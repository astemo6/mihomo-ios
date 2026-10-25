import Foundation
import os

/// Shared AnyTLS session: one TLS connection per proxy, streams opened
/// per flow. The auth block and the settings frame go out first; record
/// padding shaping from the scheme is not reproduced (interop-safe).
///
/// Threading (nc-sessions): like NCMuxSession, the session owns a serial queue; all session and stream
/// state is touched only on it, stream entry points hop onto it, and deliveries return on the caller queue
/// recorded at openStream. Only the `state`/`isAlive` snapshot is read cross-thread (behind a lock).
final class NCAnyTLSSession {
    enum State { case connecting, ready, failed }

    let queue: DispatchQueue
    let key: String

    private let snapshot = OSAllocatedUnfairLock(initialState: (state: State.connecting, tornDown: false))
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready && !$0.tornDown } }
    private func setSnapshot(state: State? = nil, tornDown: Bool? = nil) {
        snapshot.withLock {
            if let state { $0.state = state }
            if let tornDown { $0.tornDown = tornDown }
        }
    }

    private var tls: NCStream?
    private var parser = NCAnyTLS.FrameParser()
    private var streams: [UInt32: NCAnyTLSStream] = [:]
    private var nextStreamID: UInt32 = 1
    private var tornDown = false // queue-confined mirror of the snapshot flag
    private var readyWaiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []

    init(key: String) {
        self.key = key
        self.queue = NCSessionQueues.make("nc.anytls.\(key)")
    }

    var activeStreamCount: Int {
        if NCSessionQueues.isCurrent(queue) { return streams.count }
        return queue.sync { streams.count }
    }

    /// Same readiness contract as NCMuxSession.whenReady: no polling, one notification per waiter.
    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready:
                callerQueue.async { completion(nil) }
            case .failed:
                callerQueue.async { completion(NSError(domain: "NativeCore", code: 7,
                                                        userInfo: [NSLocalizedDescriptionKey: "anytls session failed"])) }
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

    func attach(tls: NCStream, password: String, clientMetadata: String) {
        ncOnSessionQueue(queue) {
            self.tls = tls
            self.setSnapshot(state: .ready)
            var hello = NCAnyTLS.authBlock(password: password, paddingLen: Int.random(in: 30...300))
            hello.append(NCAnyTLS.settingsFrame(clientMetadata: clientMetadata))
            tls.send(hello)
            self.pump()
            self.notifyReady(nil)
        }
    }

    func attachFailed() {
        ncOnSessionQueue(queue) {
            self.setSnapshot(state: .failed)
            self.notifyReady(NSError(domain: "NativeCore", code: 7,
                                     userInfo: [NSLocalizedDescriptionKey: "anytls session failed"]))
            self.streams.values.forEach { $0.failFromSession() }
            self.streams.removeAll()
        }
    }

    /// nc-lifecycle: deliberate close (the tunnel-stop registry drain in
    /// NCConnector.closeAllSharedSessions): fail every stream and drop the
    /// TLS connection — teardown() alone leaves the socket open. Idempotent.
    func close() {
        ncOnSessionQueue(queue) {
            self.teardown()
            self.tls?.cancel()
            self.tls = nil
        }
    }

    func openStream(target: NCTarget?, callerQueue: DispatchQueue) -> NCAnyTLSStream {
        if NCSessionQueues.isCurrent(queue) { return openStreamOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openStreamOnQueue(target: target, callerQueue: callerQueue) }
    }

    /// Legacy entry point (callers without a queue to hand over; see NCMuxSession.openStream).
    func openStream(target: NCTarget?) -> NCAnyTLSStream {
        openStream(target: target, callerQueue: queue)
    }

    /// nc-memory: cap on concurrently registered streams per session (see NCMuxSession.maxStreams —
    /// each stream can hold maxQueuedInbound + maxPendingSend, so the table size is a memory bound;
    /// here the product is 128 × ~576 KB ≈ 72 MB theoretical, all-readers-stalled).
    static let maxStreams = 128

    private func openStreamOnQueue(target: NCTarget?, callerQueue: DispatchQueue) -> NCAnyTLSStream {
        guard streams.count < Self.maxStreams else {
            // Refuse without a SYN or an ID allocation: a pre-failed stream (streamID 0 is never issued,
            // so its close is a no-op against the table) whose sends drop and receives surface the error.
            let stream = NCAnyTLSStream(session: self, streamID: 0, target: target, callerQueue: callerQueue)
            stream.failFromSession(message: "anytls session stream limit")
            return stream
        }
        let sid = nextStreamID
        nextStreamID += 1
        let stream = NCAnyTLSStream(session: self, streamID: sid, target: target, callerQueue: callerQueue)
        streams[sid] = stream
        tls?.send(NCAnyTLS.frame(cmd: NCAnyTLS.cmdSYN, streamID: sid))
        return stream
    }

    /// Frames go out on the session queue (callers are stream entry points that already hopped here).
    func sendFrame(_ frame: Data) {
        guard !tornDown else { return }
        tls?.send(frame)
    }

    /// Sends one frame and reports when the TLS connection has taken it (back-pressure for stream sends).
    func sendFrame(_ frame: Data, completion: @escaping () -> Void) {
        guard !tornDown, let tls else { completion(); return }
        tls.ncSend(frame, completion: completion)
    }

    func streamClosed(_ stream: NCAnyTLSStream) {
        guard streams[stream.streamID] === stream else { return } // already closed / failed
        streams[stream.streamID] = nil
        if !tornDown {
            tls?.send(NCAnyTLS.frame(cmd: NCAnyTLS.cmdFIN, streamID: stream.streamID))
        }
    }

    private func pump() {
        tls?.receive { [weak self] data, error in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                guard let data else { self.teardown(); return }
                for frame in self.parser.feed(data) {
                    self.handle(frame)
                }
                if !self.tornDown { self.pump() }
            }
        }
    }

    private func handle(_ frame: NCAnyTLS.Frame) {
        switch frame.cmd {
        case NCAnyTLS.cmdPSH:
            streams[frame.streamID]?.deliverFromSession(frame.data)
        case NCAnyTLS.cmdSYNACK:
            if !frame.data.isEmpty {
                streams[frame.streamID]?.failFromSession(message: String(decoding: frame.data, as: UTF8.self))
            }
        case NCAnyTLS.cmdFIN:
            streams[frame.streamID]?.endFromSession()
        case NCAnyTLS.cmdHeartRequest:
            tls?.send(NCAnyTLS.frame(cmd: NCAnyTLS.cmdHeartResponse, streamID: frame.streamID))
        case NCAnyTLS.cmdAlert:
            teardown()
        case NCAnyTLS.cmdWaste, NCAnyTLS.cmdServerSettings, NCAnyTLS.cmdUpdatePaddingScheme,
             NCAnyTLS.cmdHeartResponse, NCAnyTLS.cmdSettings:
            break // cosmetic or server-side only; nothing to do
        default:
            break
        }
    }

    private func teardown() {
        guard !tornDown else { return }
        tornDown = true
        setSnapshot(state: .failed, tornDown: true)
        notifyReady(NSError(domain: "NativeCore", code: 7,
                            userInfo: [NSLocalizedDescriptionKey: "anytls session closed"]))
        streams.values.forEach { $0.failFromSession() }
        streams.removeAll()
    }
}

/// One AnyTLS stream. The first send prepends the target address
/// (CreateProxy semantics); no separate handshake acknowledgement is
/// awaited — a SYNACK error or FIN surfaces through receive.
///
/// State lives on the session queue like the mux stream's; the session is held strongly and holds the
/// stream in its table until close/fail, bounding the reference cycle by the stream's wire lifetime.
final class NCAnyTLSStream: NCRelayStream {
    let streamID: UInt32
    private let session: NCAnyTLSSession
    private let target: NCTarget?
    let callerQueue: DispatchQueue
    private var targetWritten = false
    private var payloadQueue: [Data] = []
    private var queuedBytes = 0
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var failure: Error?
    private var ended = false
    private var cancelled = false
    /// Bytes handed to the base TLS stream whose send completion has not come back yet (back-pressure
    /// accounting for send(_:completion:)); past the cap the stream fails instead of queueing without bound.
    private var inflightBytes = 0
    private var pendingCompletions: [NCOnceCompletion] = []

    /// AnyTLS has no per-stream flow control: inbound bytes the reader has not taken yet are capped and the stream
    /// is closed past it, so one stalled flow cannot grow the shared session's memory without bound (rv2-proto).
    static let maxQueuedInbound = 512 * 1024
    /// Outbound in-flight cap, aligned with the mux stream's ~64 KB pending-send budget (nc-sessions).
    static let maxPendingSend = 64 * 1024

    init(session: NCAnyTLSSession, streamID: UInt32, target: NCTarget? = nil, callerQueue: DispatchQueue) {
        self.session = session
        self.streamID = streamID
        self.target = target
        self.callerQueue = callerQueue
    }

    func send(_ data: Data) {
        send(data, completion: {})
    }

    /// Send with back-pressure: the payload is framed at once, and `completion` fires exactly once — when
    /// the last frame has been taken by the base TLS stream, or when the stream/session dies trying.
    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCOnceCompletion(completion)
        ncOnSessionQueue(session.queue) {
            if self.failure != nil || self.cancelled { once.call(); return } // dead stream: drop, but never hang the caller
            var payload = data
            if let target = self.target, !self.targetWritten {
                self.targetWritten = true
                var first = target.atypEncoded
                first.append(data)
                payload = first
            }
            guard self.inflightBytes + payload.count <= Self.maxPendingSend else {
                once.call()
                self.failLocal("anytls stream send buffer overflow")
                return
            }
            self.inflightBytes += payload.count
            self.pendingCompletions.append(once)
            let chunkSize = 0xffff
            var rest = payload[...]
            var frames: [Data] = []
            while !rest.isEmpty {
                let chunk = Data(rest.prefix(chunkSize))
                rest = rest.dropFirst(chunk.count)
                frames.append(NCAnyTLS.frame(cmd: NCAnyTLS.cmdPSH, streamID: self.streamID, data: chunk))
            }
            // Only the last frame carries the completion: the base stream's sends complete in order.
            for (index, frame) in frames.enumerated() {
                if index == frames.count - 1 {
                    let bytes = payload.count
                    self.session.sendFrame(frame) { [weak self] in
                        guard let self else { once.call(); return }
                        ncOnSessionQueue(self.session.queue) {
                            self.inflightBytes -= bytes
                            if let i = self.pendingCompletions.firstIndex(where: { $0 === once }) {
                                self.pendingCompletions.remove(at: i)
                            }
                            once.call()
                        }
                    }
                } else {
                    self.session.sendFrame(frame)
                }
            }
            if frames.isEmpty { // empty payload: nothing to flush, complete now
                self.inflightBytes -= payload.count
                if let i = self.pendingCompletions.firstIndex(where: { $0 === once }) {
                    self.pendingCompletions.remove(at: i)
                }
                once.call()
            }
        }
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
            self.firePendingCompletions()
            self.session.streamClosed(self)
        }
    }

    private func dequeue() -> Data {
        let d = payloadQueue.removeFirst()
        queuedBytes -= d.count
        return d
    }

    private func firePendingCompletions() {
        let all = pendingCompletions
        pendingCompletions = []
        inflightBytes = 0
        all.forEach { $0.call() }
    }

    private func failLocal(_ message: String) {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 7, userInfo: [NSLocalizedDescriptionKey: message])
        }
        payloadQueue.removeAll()
        queuedBytes = 0
        firePendingCompletions()
        session.streamClosed(self)
        settle()
    }

    // MARK: session-facing (session queue only)

    func deliverFromSession(_ data: Data) {
        if failure != nil || cancelled { return }
        if let handler = pendingHandler {
            pendingHandler = nil
            callerQueue.async { handler(data, nil) }
        } else {
            guard queuedBytes + data.count <= Self.maxQueuedInbound else {
                failure = NSError(domain: "NativeCore", code: 7,
                                  userInfo: [NSLocalizedDescriptionKey: "anytls stream receive buffer overflow"])
                payloadQueue.removeAll()
                queuedBytes = 0
                firePendingCompletions()
                session.streamClosed(self)
                settle()
                return
            }
            queuedBytes += data.count
            payloadQueue.append(data)
        }
    }

    func endFromSession() {
        ended = true
        settle()
    }

    func failFromSession(message: String? = nil) {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 7,
                              userInfo: [NSLocalizedDescriptionKey: message ?? "anytls session closed"])
        }
        firePendingCompletions()
        settle()
    }

    private func settle() {
        guard let handler = pendingHandler else { return }
        pendingHandler = nil
        if !payloadQueue.isEmpty {
            let data = dequeue()
            callerQueue.async { handler(data, nil) }
        } else {
            let failure = self.failure
            callerQueue.async { handler(nil, failure) }
        }
    }
}
