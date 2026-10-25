import Foundation
import os

/// One sing-mux (h2mux) session over a single VMess/VLESS connection to
/// sp.mux.sing-box.arpa:444. Streams are opened per flow; the session is
/// shared per proxy through NCConnector's registry.
///
/// Threading (nc-sessions): the session owns a serial queue and *all* session and stream state (the streams
/// dictionary, the NCH2MuxCore, every stream's buffers/handlers) is touched only on it. Callers on any queue
/// may call in; stream entry points hop onto the session queue and deliver results back on the caller queue
/// recorded at openStream. The only state read cross-thread is the `state`/`isAlive` snapshot, which lives
/// behind a lock for the registry's benefit.
final class NCMuxSession {
    enum State { case connecting, ready, failed }

    /// Owns this session: created with the session, targeted at the shared session-queue target so sessions
    /// do not each pin a thread.
    let queue: DispatchQueue
    let key: String

    /// Lock-protected snapshot for cross-thread readers (the registry). Everything else is queue-confined.
    private let snapshot = OSAllocatedUnfairLock(initialState: (state: State.connecting, tornDown: false))
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready && !$0.tornDown } }
    private func setSnapshot(state: State? = nil, tornDown: Bool? = nil) {
        snapshot.withLock {
            if let state { $0.state = state }
            if let tornDown { $0.tornDown = tornDown }
        }
    }

    private let core = NCH2MuxCore()
    private var base: NCRelayStream?
    private var streams: [Int: NCMuxStream] = [:]
    private var tornDown = false // queue-confined mirror of the snapshot flag
    /// Readiness waiters (queue-confined): notified exactly once, each on its own caller queue, when the
    /// session attaches or fails — no polling (the old 0.25 s × 60 waiter also read `state` cross-thread).
    private var readyWaiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []

    init(key: String) {
        self.key = key
        self.queue = NCSessionQueues.make("nc.mux.\(key)")
    }

    /// Number of live streams; read by tests/diagnostics (hops onto the session queue).
    var activeStreamCount: Int {
        if NCSessionQueues.isCurrent(queue) { return streams.count }
        return queue.sync { streams.count }
    }

    /// Registers interest in readiness: ready → nil at once on `callerQueue`, failed → the failure,
    /// connecting → queued until attach/attachFailed resolves the session either way.
    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready:
                callerQueue.async { completion(nil) }
            case .failed:
                callerQueue.async { completion(NSError(domain: "NativeCore", code: 6,
                                                        userInfo: [NSLocalizedDescriptionKey: "mux session failed"])) }
            case .connecting:
                self.readyWaiters.append((callerQueue, completion))
            }
        }
    }

    private func notifyReady(_ error: Error?) {
        let waiters = readyWaiters
        readyWaiters = []
        for waiter in waiters {
            waiter.queue.async { waiter.completion(error) }
        }
    }

    /// Called by the registry once the base relay (the proxy connection
    /// to the mux destination) exists. The base was dialed on `queue`, so its callbacks arrive here.
    func attach(base: NCRelayStream) {
        ncOnSessionQueue(queue) {
            self.base = base
            self.setSnapshot(state: .ready)
            var hello = NCMux.preamble()
            hello.append(self.core.start())
            base.send(hello)
            self.pump()
            self.notifyReady(nil)
        }
    }

    func attachFailed() {
        ncOnSessionQueue(queue) {
            self.setSnapshot(state: .failed)
            self.notifyReady(NSError(domain: "NativeCore", code: 6,
                                     userInfo: [NSLocalizedDescriptionKey: "mux session failed"]))
            self.failAllStreams()
        }
    }

    /// Opens a stream for a caller living on `callerQueue`: deliveries (data / EOF / error) are handed back
    /// on that queue, so caller code does not change. The stream object returns at once; the HEADERS frame
    /// goes out on the session queue.
    func openStream(target: NCTarget, callerQueue: DispatchQueue, rawMode: Bool = false) -> NCMuxStream {
        if NCSessionQueues.isCurrent(queue) { return openStreamOnQueue(target: target, callerQueue: callerQueue, rawMode: rawMode) }
        return queue.sync { openStreamOnQueue(target: target, callerQueue: callerQueue, rawMode: rawMode) }
    }

    /// Legacy entry point for callers that have no queue of their own to hand over (the UDP sessions, which
    /// the integrator is moving to explicit caller queues): deliveries land on the session queue.
    func openStream(target: NCTarget, rawMode: Bool = false) -> NCMuxStream {
        openStream(target: target, callerQueue: queue, rawMode: rawMode)
    }

    /// nc-memory: cap on concurrently registered streams per session. Each registered stream can hold up
    /// to maxQueuedInbound + maxPendingSend (~320 KB), so the table size is a memory bound, not just a
    /// protocol one; 256 streams is far above what one pooled session carries in practice.
    static let maxStreams = 256

    private func openStreamOnQueue(target: NCTarget, callerQueue: DispatchQueue, rawMode: Bool) -> NCMuxStream {
        guard streams.count < Self.maxStreams else {
            // Refuse without touching the wire or the core's ID space: a pre-failed stream whose sends
            // drop and whose receives surface the error (streamID -1 never enters the table, so its
            // cancel/close are no-ops against the session).
            let stream = NCMuxStream(session: self, streamID: -1, target: target, callerQueue: callerQueue)
            stream.rawMode = rawMode
            stream.failFromSession()
            return stream
        }
        let (id, headersFrame) = core.openStream()
        let stream = NCMuxStream(session: self, streamID: id, target: target, callerQueue: callerQueue)
        stream.rawMode = rawMode
        streams[id] = stream
        base?.send(headersFrame)
        return stream
    }

    // MARK: stream-facing (session queue only)

    func flushStream(_ stream: NCMuxStream) {
        guard let base, !tornDown, streams[stream.streamID] === stream else { return }
        let (pending, entries) = stream.takePendingForSend()
        guard !pending.isEmpty else { return }
        let (frames, consumed) = core.makeData(streamID: stream.streamID, data: pending)
        guard !frames.isEmpty else {
            // Nothing went out (window fully shut): the bytes stay pending, completions included.
            stream.restoreUnsent(pending, entries: entries)
            return
        }
        let (done, rest) = NCPendingSends.split(entries, consumed: consumed)
        if consumed < pending.count {
            stream.restoreUnsent(Data(pending.dropFirst(consumed)), entries: rest)
        }
        // The send completion of every fully-flushed entry fires once the base stream has taken the frames
        // (the one-shot wrappers are thread-safe, so they may fire on the base stream's queue).
        base.ncSend(frames) { done.forEach { $0.call() } }
    }

    func closeStream(_ stream: NCMuxStream, reset: Bool) {
        guard streams[stream.streamID] === stream else { return } // already closed / failed
        streams[stream.streamID] = nil
        core.forgetStream(stream.streamID)
        guard let base, !tornDown else { return }
        base.send(reset ? core.rstStream(stream.streamID) : core.endStream(stream.streamID))
    }

    /// The stream's reader consumed `n` received bytes: give that much stream receive window back.
    func credit(_ stream: NCMuxStream, _ n: Int) {
        guard n > 0, let base, !tornDown, streams[stream.streamID] === stream else { return }
        base.send(core.windowUpdate(streamID: stream.streamID, n))
    }

    // MARK: pump (session queue only)

    private func pump() {
        base?.receive { [weak self] data, error in
            guard let self else { return }
            // The base was dialed on the session queue, so this normally runs inline; the hop also covers a
            // base stream whose callbacks live elsewhere (chained transports, test fakes).
            ncOnSessionQueue(self.queue) {
                guard let data else {
                    self.teardown()
                    return
                }
                let result = self.core.feed(data)
                if !result.outbound.isEmpty { self.base?.send(result.outbound) }
                for event in result.events {
                    switch event {
                    case .payload(let id, let payload):
                        self.streams[id]?.deliverFromSession(payload)
                    case .ended(let id):
                        self.streams[id]?.endFromSession()
                    case .reset(let id):
                        self.streams[id]?.resetFromSession()
                    case .windowIncreased:
                        for stream in self.streams.values { self.flushStream(stream) }
                    case .goaway:
                        self.teardown()
                        return
                    case .responseHeaders:
                        break
                    }
                }
                if !self.tornDown { self.pump() }
            }
        }
    }

    private func teardown() {
        guard !tornDown else { return }
        tornDown = true
        setSnapshot(state: .failed, tornDown: true)
        notifyReady(NSError(domain: "NativeCore", code: 6,
                            userInfo: [NSLocalizedDescriptionKey: "mux session closed"]))
        failAllStreams()
    }

    private func failAllStreams() {
        let all = streams.values
        streams.removeAll()
        for stream in all {
            core.forgetStream(stream.streamID)
            stream.failFromSession()
        }
    }
}

/// One logical stream inside an NCMuxSession. The first client bytes are
/// the StreamRequest; the first server byte is the stream status.
///
/// All mutable state lives on the session queue: `send`/`receive`/`cancel` hop onto it, and the registered
/// receive handler is invoked on the caller queue recorded at open time. The stream holds its session
/// strongly (the session holds it back in `streams` until close/fail removes it, so the cycle is bounded
/// by the stream's lifetime on the wire).
final class NCMuxStream: NCRelayStream {
    let streamID: Int
    private let session: NCMuxSession
    private let target: NCTarget
    /// Queue the owner lives on; deliveries are handed back here.
    let callerQueue: DispatchQueue
    /// Raw mode (UDP packet-addr): the caller supplies the StreamRequest
    /// bytes itself; send() must not prepend the TCP one.
    var rawMode = false
    private var pendingSend = Data()
    private var pendingEntries: [NCPendingSendEntry] = []
    private var requestWritten = false
    private var responseBuffer = Data()
    private var responseChecked = false
    private var payloadQueue: [Data] = []
    private var queuedBytes = 0
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var failure: Error?
    private var ended = false
    private var cancelled = false

    /// Memory bounds (rv2-proto). Inbound: the peer may only send a stream window (64 KB default) ahead of our
    /// reader since windows are returned on consumption; the cap only catches a peer that ignores flow control.
    /// Outbound: bytes waiting for send window; past the cap the stream is reset rather than buffering forever.
    /// Lowered from 1 MB to ~64 KB with send completion (nc-sessions): callers now wait for flush before
    /// sending more, so a healthy stream stays far below the cap and overflow means a stuck peer.
    static let maxQueuedInbound = 256 * 1024
    static let maxPendingSend = 64 * 1024

    init(session: NCMuxSession, streamID: Int, target: NCTarget, callerQueue: DispatchQueue) {
        self.session = session
        self.streamID = streamID
        self.target = target
        self.callerQueue = callerQueue
    }

    func send(_ data: Data) {
        send(data, completion: {})
    }

    /// Send with back-pressure: `completion` fires exactly once — after these bytes were flushed to the base
    /// stream and the base send completed, or when the stream/session dies trying (cancel, reset, teardown).
    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCOnceCompletion(completion)
        ncOnSessionQueue(session.queue) {
            // A failed / closed stream drops writes (they used to pile up in pendingSend after a session teardown).
            if self.failure != nil || self.cancelled { once.call(); return }
            if !self.rawMode && !self.requestWritten {
                self.requestWritten = true
                let request = NCMux.streamRequestTCP(target: self.target)
                self.pendingSend.append(request)
                self.pendingEntries.append(NCPendingSendEntry(count: request.count, once: nil))
            }
            guard self.pendingSend.count + data.count <= Self.maxPendingSend else {
                once.call()
                self.failLocal("mux stream send buffer overflow")
                return
            }
            self.pendingSend.append(data)
            self.pendingEntries.append(NCPendingSendEntry(count: data.count, once: once))
            self.session.flushStream(self)
        }
    }

    /// Send bytes verbatim (UDP mode's framed packets).
    func sendRaw(_ data: Data) { send(data) }

    func takePendingForSend() -> (data: Data, entries: [NCPendingSendEntry]) {
        defer {
            pendingSend = Data()
            pendingEntries = []
        }
        return (pendingSend, pendingEntries)
    }

    func restoreUnsent(_ data: Data, entries: [NCPendingSendEntry]) {
        pendingSend = data + pendingSend
        pendingEntries = entries + pendingEntries
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(session.queue) {
            if !self.payloadQueue.isEmpty {
                let data = self.dequeue()
                self.callerQueue.async { handler(data, nil) }
                return
            }
            if let failure = self.failure {
                self.callerQueue.async { handler(nil, failure) }
                return
            }
            if self.ended {
                self.callerQueue.async { handler(nil, nil) }
                return
            }
            self.pendingHandler = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(session.queue) {
            self.cancelled = true
            self.pendingSend = Data()
            NCPendingSends.fireAll(self.pendingEntries)
            self.pendingEntries = []
            self.session.closeStream(self, reset: !self.ended)
        }
    }

    /// Local failure (buffer overflow): reset the stream on the wire and surface the error to the reader.
    private func failLocal(_ message: String) {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 6, userInfo: [NSLocalizedDescriptionKey: message])
        }
        pendingSend = Data()
        NCPendingSends.fireAll(pendingEntries)
        pendingEntries = []
        payloadQueue.removeAll()
        queuedBytes = 0
        session.closeStream(self, reset: true)
        settle()
    }

    private func dequeue() -> Data {
        let d = payloadQueue.removeFirst()
        queuedBytes -= d.count
        session.credit(self, d.count)
        return d
    }

    // MARK: session-facing (session queue only)

    func deliverFromSession(_ payload: Data) {
        if failure != nil || cancelled { return }
        if !responseChecked {
            guard responseBuffer.count + payload.count <= Self.maxQueuedInbound else {
                failLocal("mux stream response too large")
                return
            }
            responseBuffer.append(payload)
            guard let parsed = NCMux.parseStreamResponse(responseBuffer) else { return }
            responseChecked = true
            let rest = Data(responseBuffer.dropFirst(parsed.consumed))
            session.credit(self, min(parsed.consumed, responseBuffer.count)) // status bytes are consumed here
            responseBuffer = Data()
            guard parsed.ok else {
                failure = NSError(domain: "NativeCore", code: 6,
                                  userInfo: [NSLocalizedDescriptionKey: "mux stream error: \(parsed.message ?? "?")"])
                settle()
                return
            }
            if !rest.isEmpty { emit(rest) }
            return
        }
        emit(payload)
    }

    func endFromSession() {
        ended = true
        settle()
    }

    func resetFromSession() {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 6,
                              userInfo: [NSLocalizedDescriptionKey: "mux stream reset"])
        }
        settle()
    }

    func failFromSession() {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 6,
                              userInfo: [NSLocalizedDescriptionKey: "mux session closed"])
        }
        pendingSend = Data()
        NCPendingSends.fireAll(pendingEntries)
        pendingEntries = []
        settle()
    }

    private func emit(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            session.credit(self, data.count)
            callerQueue.async { handler(data, nil) }
        } else {
            guard queuedBytes + data.count <= Self.maxQueuedInbound else {
                failLocal("mux stream receive buffer overflow (peer ignored flow control)")
                return
            }
            queuedBytes += data.count
            payloadQueue.append(data)
        }
    }

    private func settle() {
        guard let handler = pendingHandler else { return }
        pendingHandler = nil
        if !payloadQueue.isEmpty {
            let data = dequeue()
            callerQueue.async { handler(data, nil) }
        } else {
            let failure = self.failure
            callerQueue.async { handler(nil, failure) } // nil error = clean EOF
        }
    }
}
