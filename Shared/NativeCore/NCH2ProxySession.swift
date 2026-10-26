import Foundation
import os

/// One HTTP/2 connection to an HTTP/2 CONNECT proxy (Shadowrocket "HTTP2" / NaïveProxy over h2), carrying
/// one CONNECT stream per proxied flow — the way naiveproxy / Chrome multiplex, so N flows cost one TLS
/// session and one socket instead of N (memory first). Built on NCH2MuxCore (the multi-stream h2 core the
/// sing-mux session already uses) with feat/nc-naive-h2h3's openStream(headers:).
///
/// Threading: the NCMuxSession pattern (#116 / nc-sessions) — the session owns a serial queue; the core,
/// the stream table and every stream's buffers are touched only there; stream entry points hop in and
/// hand results back on the caller queue recorded at open. `state` / `isAlive` / `load` are a lock-held
/// snapshot for the registry.
///
/// Flow control: our SETTINGS raise the per-stream receive window to `streamWindow` and a WINDOW_UPDATE
/// raises the connection window to `connectionWindow`. Stream windows come back on consumption (a stalled
/// reader caps its own buffer at the stream window); the connection window comes back on receipt (the
/// core's behaviour), so it never throttles independent streams against each other.
final class NCH2ProxySession {
    enum State { case connecting, ready, failed }

    let queue: DispatchQueue
    let key: String

    private struct Snapshot {
        var state: State = .connecting
        var tornDown = false
        /// GOAWAY seen: no new streams; open ones run to completion.
        var draining = false
        var streams = 0
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    /// Usable for a new stream (ready, not torn down, not draining, below the stream cap).
    var isAlive: Bool { snapshot.withLock { $0.state == .ready && !$0.tornDown && !$0.draining } }
    var hasCapacity: Bool { snapshot.withLock { $0.streams < Self.maxStreams } }
    var load: Int { snapshot.withLock { $0.streams } }

    static let maxStreams = 100
    static let streamWindow = 256 * 1024
    static let connectionWindow = 2 * 1024 * 1024
    /// An idle shared session (no streams) is closed after this long; the next flow dials again.
    static var idleTimeout: TimeInterval = 90

    private let core = NCH2MuxCore()
    private var base: NCRelayStream?
    private var streams: [Int: NCH2ProxyStream] = [:]
    private var tornDown = false
    private var readyWaiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
    private var idleTimer: DispatchWorkItem?
    /// Private (chained-transport) sessions carry a single stream and close with it.
    let closeWhenIdle: Bool
    /// Registry hook: called once, on the session queue, when the session is torn down.
    var onClosed: (() -> Void)?

    init(key: String, closeWhenIdle: Bool = false) {
        self.key = key
        self.closeWhenIdle = closeWhenIdle
        self.queue = NCSessionQueues.make("nc.h2proxy.\(key)")
    }

    var activeStreamCount: Int {
        if NCSessionQueues.isCurrent(queue) { return streams.count }
        return queue.sync { streams.count }
    }

    /// Connection preface + our SETTINGS (no push, larger stream window) + connection WINDOW_UPDATE.
    static func startBytes() -> Data {
        var out = NCH2ClientCore.preface
        var settings = Data()
        settings.appendBE16(0x2); settings.appendBE32(0)                         // ENABLE_PUSH = 0
        settings.appendBE16(0x4); settings.appendBE32(UInt32(streamWindow))      // INITIAL_WINDOW_SIZE
        out.append(NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0, payload: settings))
        var inc = Data()
        inc.appendBE32(UInt32(connectionWindow - 65535))
        out.append(NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: 0, payload: inc))
        return out
    }

    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready:
                callerQueue.async { completion(self.tornDown ? Self.error("h2 proxy session closed") : nil) }
            case .failed:
                callerQueue.async { completion(Self.error("h2 proxy session failed")) }
            case .connecting:
                self.readyWaiters.append((callerQueue, completion))
            }
        }
    }

    private func notifyReady(_ error: Error?) {
        let waiters = readyWaiters
        readyWaiters = []
        for w in waiters { w.queue.async { w.completion(error) } }
    }

    /// The TLS (ALPN h2) base stream exists: speak HTTP/2 on it.
    func attach(base: NCRelayStream) {
        ncOnSessionQueue(queue) {
            guard !self.tornDown else { base.cancel(); return }
            self.base = base
            self.snapshot.withLock { $0.state = .ready }
            base.send(Self.startBytes())
            self.pump()
            self.notifyReady(nil)
            self.armIdleTimer()
        }
    }

    func attachFailed(_ error: Error?) {
        ncOnSessionQueue(queue) {
            self.snapshot.withLock { $0.state = .failed }
            self.notifyReady(error ?? Self.error("h2 proxy session failed"))
            self.teardown()
        }
    }

    func close() {
        ncOnSessionQueue(queue) {
            self.teardown()
            self.base?.cancel()
            self.base = nil
        }
    }

    /// Open one CONNECT stream. Returns at once; HEADERS go out on the session queue, the stream completes
    /// (or fails) on the caller queue via `ready`.
    func openStream(headers: [(String, String)], naive: Bool, callerQueue: DispatchQueue,
                    ready: @escaping (Error?) -> Void) -> NCH2ProxyStream {
        let stream = NCH2ProxyStream(session: self, naive: naive, callerQueue: callerQueue, ready: ready)
        ncOnSessionQueue(queue) { self.openOnQueue(stream, headers: headers) }
        return stream
    }

    private func openOnQueue(_ stream: NCH2ProxyStream, headers: [(String, String)]) {
        guard let base, !tornDown, !snapshot.withLock({ $0.draining }), streams.count < Self.maxStreams else {
            stream.failFromSession(Self.error("h2 proxy session unavailable"))
            return
        }
        idleTimer?.cancel()
        idleTimer = nil
        let (id, frame) = core.openStream(headers: headers)
        stream.streamID = id
        streams[id] = stream
        snapshot.withLock { $0.streams = streams.count }
        base.send(frame)
        stream.armResponseDeadline()
    }

    // MARK: stream-facing (session queue only)

    func flushStream(_ stream: NCH2ProxyStream) {
        guard let base, !tornDown, streams[stream.streamID] === stream else { return }
        let (pending, entries) = stream.takePendingForSend()
        guard !pending.isEmpty else { return }
        let (frames, consumed) = core.makeData(streamID: stream.streamID, data: pending)
        guard !frames.isEmpty else {
            stream.restoreUnsent(pending, entries: entries)
            return
        }
        let (done, rest) = NCPendingSends.split(entries, consumed: consumed)
        if consumed < pending.count {
            stream.restoreUnsent(Data(pending.dropFirst(consumed)), entries: rest)
        }
        base.ncSend(frames) { done.forEach { $0.call() } }
    }

    func closeStream(_ stream: NCH2ProxyStream, reset: Bool) {
        guard stream.streamID > 0, streams[stream.streamID] === stream else { return }
        streams[stream.streamID] = nil
        snapshot.withLock { $0.streams = streams.count }
        core.forgetStream(stream.streamID)
        if let base, !tornDown {
            base.send(reset ? core.rstStream(stream.streamID) : core.endStream(stream.streamID))
        }
        if streams.isEmpty {
            if closeWhenIdle { close() } else { armIdleTimer() }
        }
    }

    func credit(_ stream: NCH2ProxyStream, _ n: Int) {
        guard n > 0, let base, !tornDown, streams[stream.streamID] === stream else { return }
        base.send(core.windowUpdate(streamID: stream.streamID, n))
    }

    // MARK: internals (session queue only)

    private func armIdleTimer() {
        idleTimer?.cancel()
        guard !closeWhenIdle else { return }
        let t = DispatchWorkItem { [weak self] in
            guard let self, self.streams.isEmpty, !self.tornDown else { return }
            self.close()
        }
        idleTimer = t
        queue.asyncAfter(deadline: .now() + Self.idleTimeout, execute: t)
    }

    private func pump() {
        base?.receive { [weak self] data, _ in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                guard let data else {
                    self.teardown()
                    return
                }
                let result = self.core.feed(data)
                if !result.outbound.isEmpty { self.base?.send(result.outbound) }
                for event in result.events {
                    switch event {
                    case .responseHeaders(let id, let headers):
                        self.streams[id]?.responseFromSession(headers)
                    case .payload(let id, let payload):
                        self.streams[id]?.deliverFromSession(payload)
                    case .ended(let id):
                        self.streams[id]?.endFromSession()
                    case .reset(let id):
                        if id == 0 { self.teardown(); return }
                        self.streams[id]?.resetFromSession()
                    case .windowIncreased:
                        for s in self.streams.values { self.flushStream(s) }
                    case .goaway:
                        // No new streams; the open ones keep running until the server closes the socket.
                        self.snapshot.withLock { $0.draining = true }
                        self.onClosed?()
                        self.onClosed = nil
                    }
                }
                if !self.tornDown { self.pump() }
            }
        }
    }

    private func teardown() {
        guard !tornDown else { return }
        tornDown = true
        idleTimer?.cancel()
        idleTimer = nil
        snapshot.withLock { $0.tornDown = true; $0.state = .failed; $0.streams = 0 }
        notifyReady(Self.error("h2 proxy session closed"))
        let all = streams.values
        streams.removeAll()
        for s in all {
            core.forgetStream(s.streamID)
            s.failFromSession(Self.error("h2 proxy session closed"))
        }
        base?.cancel()
        base = nil
        onClosed?()
        onClosed = nil
    }

    static func error(_ message: String) -> NSError {
        NSError(domain: "NativeCore", code: 7, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

/// One CONNECT tunnel inside an NCH2ProxySession. Sends before the 2xx response are held (and naive
/// padding is decided by that response); afterwards the stream is a plain byte pipe, with the first
/// eight writes / reads padded when naive padding was negotiated.
final class NCH2ProxyStream: NCRelayStream {
    fileprivate(set) var streamID: Int = -1
    private let session: NCH2ProxySession
    private let naive: Bool
    let callerQueue: DispatchQueue
    private var readyCallback: ((Error?) -> Void)?

    private enum Phase { case awaiting, open, closed }
    private var phase: Phase = .awaiting
    private var padding: NCNaivePadding?
    private var held: [(Data, NCOnceCompletion)] = []
    private var heldBytes = 0
    private var pendingSend = Data()
    private var pendingEntries: [NCPendingSendEntry] = []
    private var payloadQueue: [Data] = []
    private var queuedBytes = 0
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var failure: Error?
    private var ended = false
    private var deadline: DispatchWorkItem?

    static let maxQueuedInbound = NCH2ProxySession.streamWindow
    static let maxPendingSend = 64 * 1024

    init(session: NCH2ProxySession, naive: Bool, callerQueue: DispatchQueue, ready: @escaping (Error?) -> Void) {
        self.session = session
        self.naive = naive
        self.callerQueue = callerQueue
        self.readyCallback = ready
    }

    // MARK: NCRelayStream

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCOnceCompletion(completion)
        ncOnSessionQueue(session.queue) {
            if self.failure != nil || self.phase == .closed || data.isEmpty { once.call(); return }
            if self.phase == .awaiting {
                guard self.heldBytes + data.count <= Self.maxPendingSend else {
                    once.call()
                    self.failLocal("h2 proxy stream send buffer overflow")
                    return
                }
                self.held.append((data, once))
                self.heldBytes += data.count
                return
            }
            self.enqueue(data, once)
            self.session.flushStream(self)
        }
    }

    private func enqueue(_ data: Data, _ once: NCOnceCompletion) {
        let wire = padding != nil ? padding!.encode(data) : data
        guard pendingSend.count + wire.count <= Self.maxPendingSend + 4 * 1024 else {
            once.call()
            failLocal("h2 proxy stream send buffer overflow")
            return
        }
        pendingSend.append(wire)
        pendingEntries.append(NCPendingSendEntry(count: wire.count, once: once))
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
            let wasOpen = self.phase != .closed
            self.phase = .closed
            self.deadline?.cancel()
            self.deadline = nil
            self.dropSends()
            self.finishReady(NCH2ProxySession.error("h2 proxy stream cancelled"))
            if wasOpen { self.session.closeStream(self, reset: !self.ended) }
        }
    }

    // MARK: session-facing (session queue only)

    func takePendingForSend() -> (data: Data, entries: [NCPendingSendEntry]) {
        defer { pendingSend = Data(); pendingEntries = [] }
        return (pendingSend, pendingEntries)
    }

    func restoreUnsent(_ data: Data, entries: [NCPendingSendEntry]) {
        pendingSend = data + pendingSend
        pendingEntries = entries + pendingEntries
    }

    func armResponseDeadline() {
        let t = DispatchWorkItem { [weak self] in
            guard let self, self.phase == .awaiting else { return }
            self.failLocal("h2 proxy CONNECT response timeout")
        }
        deadline = t
        session.queue.asyncAfter(deadline: .now() + NCConnector.proxyHandshakeTimeout, execute: t)
    }

    func responseFromSession(_ headers: [(String, String)]) {
        guard phase == .awaiting else { return } // trailers / informational after open: ignored
        guard let status = NCHTTPConnect.status(headers) else {
            failLocal("h2 proxy CONNECT response without :status")
            return
        }
        if (100..<200).contains(status) { return } // informational; the final response follows
        guard (200..<300).contains(status) else {
            failLocal("h2 proxy CONNECT rejected (status \(status))")
            return
        }
        deadline?.cancel()
        deadline = nil
        phase = .open
        if naive && NCNaivePadding.negotiated(responseHeaders: headers) { padding = NCNaivePadding() }
        let queued = held
        held = []
        heldBytes = 0
        for (data, once) in queued { enqueue(data, once) }
        session.flushStream(self)
        finishReady(nil)
    }

    func deliverFromSession(_ payload: Data) {
        guard failure == nil, phase == .open else {
            if phase == .awaiting { failLocal("h2 proxy DATA before the CONNECT response") }
            return
        }
        var data = payload
        if padding != nil {
            data = padding!.decode(payload)
            // Padding headers / padding bytes are consumed here: their window goes back now.
            session.credit(self, payload.count - data.count)
        }
        guard !data.isEmpty else { return }
        emit(data)
    }

    func endFromSession() {
        ended = true
        if phase == .awaiting {
            failLocal("h2 proxy stream ended before the CONNECT response")
            return
        }
        settle()
    }

    func resetFromSession() {
        if failure == nil { failure = NCH2ProxySession.error("h2 proxy stream reset") }
        phase = .closed
        deadline?.cancel()
        dropSends()
        finishReady(failure)
        settle()
    }

    func failFromSession(_ error: Error) {
        if failure == nil { failure = error }
        phase = .closed
        deadline?.cancel()
        dropSends()
        finishReady(failure)
        settle()
    }

    // MARK: internals

    private func finishReady(_ error: Error?) {
        guard let cb = readyCallback else { return }
        readyCallback = nil
        callerQueue.async { cb(error) }
    }

    private func dropSends() {
        for (_, once) in held { once.call() }
        held = []
        heldBytes = 0
        pendingSend = Data()
        NCPendingSends.fireAll(pendingEntries)
        pendingEntries = []
    }

    private func failLocal(_ message: String) {
        if failure == nil { failure = NCH2ProxySession.error(message) }
        let wasOpen = phase != .closed
        phase = .closed
        deadline?.cancel()
        deadline = nil
        dropSends()
        payloadQueue.removeAll()
        queuedBytes = 0
        finishReady(failure)
        if wasOpen { session.closeStream(self, reset: true) }
        settle()
    }

    private func dequeue() -> Data {
        let d = payloadQueue.removeFirst()
        queuedBytes -= d.count
        session.credit(self, d.count)
        return d
    }

    private func emit(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            session.credit(self, data.count)
            callerQueue.async { handler(data, nil) }
        } else {
            guard queuedBytes + data.count <= Self.maxQueuedInbound else {
                failLocal("h2 proxy stream receive buffer overflow (peer ignored flow control)")
                return
            }
            queuedBytes += data.count
            payloadQueue.append(data)
        }
    }

    private func settle() {
        guard let handler = pendingHandler else { return }
        if !payloadQueue.isEmpty {
            pendingHandler = nil
            let data = dequeue()
            callerQueue.async { handler(data, nil) }
        } else if failure != nil || ended {
            pendingHandler = nil
            let failure = self.failure
            callerQueue.async { handler(nil, failure) }
        }
    }
}
