import Foundation

/// One sing-mux (h2mux) session over a single VMess/VLESS connection to
/// sp.mux.sing-box.arpa:444. Streams are opened per flow; the session is
/// shared per proxy through NCConnector's registry.
final class NCMuxSession {
    enum State { case connecting, ready, failed }

    private(set) var state: State = .connecting
    private let core = NCH2MuxCore()
    private var base: NCRelayStream?
    private var streams: [Int: NCMuxStream] = [:]
    private var startBuffer = Data()
    private var tornDown = false

    /// Called by the registry once the base relay (the proxy connection
    /// to the mux destination) exists.
    func attach(base: NCRelayStream) {
        self.base = base
        state = .ready
        var hello = NCMux.preamble()
        hello.append(core.start())
        base.send(hello)
        pump()
    }

    func attachFailed() {
        state = .failed
        failAllStreams()
    }

    func openStream(target: NCTarget, rawMode: Bool = false) -> NCMuxStream {
        let (id, headersFrame) = core.openStream()
        let stream = NCMuxStream(session: self, streamID: id, target: target)
        stream.rawMode = rawMode
        streams[id] = stream
        base?.send(headersFrame)
        return stream
    }

    // MARK: stream-facing

    func flushStream(_ stream: NCMuxStream) {
        guard let base, !tornDown, streams[stream.streamID] === stream else { return }
        let pending = stream.takePendingForSend()
        guard !pending.isEmpty else { return }
        let (frames, consumed) = core.makeData(streamID: stream.streamID, data: pending)
        if consumed < pending.count {
            stream.restoreUnsent(Data(pending.dropFirst(consumed)))
        }
        if !frames.isEmpty { base.send(frames) }
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

    var isAlive: Bool { state == .ready && !tornDown }

    // MARK: pump

    private func pump() {
        base?.receive { [weak self] data, error in
            guard let self else { return }
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

    private func teardown() {
        guard !tornDown else { return }
        tornDown = true
        state = .failed
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
final class NCMuxStream: NCRelayStream {
    let streamID: Int
    private let session: NCMuxSession
    private let target: NCTarget
    /// Raw mode (UDP packet-addr): the caller supplies the StreamRequest
    /// bytes itself; send() must not prepend the TCP one.
    var rawMode = false
    private var pendingSend = Data()
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
    static let maxQueuedInbound = 256 * 1024
    static let maxPendingSend = 1024 * 1024

    init(session: NCMuxSession, streamID: Int, target: NCTarget) {
        self.session = session
        self.streamID = streamID
        self.target = target
    }

    func send(_ data: Data) {
        // A failed / closed stream drops writes (they used to pile up in pendingSend after a session teardown).
        if failure != nil || cancelled { pendingSend = Data(); return }
        if !rawMode && !requestWritten {
            requestWritten = true
            pendingSend.append(NCMux.streamRequestTCP(target: target))
        }
        guard pendingSend.count + data.count <= Self.maxPendingSend else {
            failLocal("mux stream send buffer overflow")
            return
        }
        pendingSend.append(data)
        session.flushStream(self)
    }

    /// Send bytes verbatim (UDP mode's framed packets).
    func sendRaw(_ data: Data) { send(data) }

    func takePendingForSend() -> Data {
        defer { pendingSend = Data() }
        return pendingSend
    }

    func restoreUnsent(_ data: Data) {
        pendingSend = data + pendingSend
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !payloadQueue.isEmpty {
            handler(dequeue(), nil)
            return
        }
        if let failure {
            handler(nil, failure)
            return
        }
        if ended {
            handler(nil, nil)
            return
        }
        pendingHandler = handler
    }

    func cancel() {
        cancelled = true
        pendingSend = Data()
        session.closeStream(self, reset: !ended)
    }

    /// Local failure (buffer overflow): reset the stream on the wire and surface the error to the reader.
    private func failLocal(_ message: String) {
        if failure == nil {
            failure = NSError(domain: "NativeCore", code: 6, userInfo: [NSLocalizedDescriptionKey: message])
        }
        pendingSend = Data()
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

    // MARK: session-facing

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
        settle()
    }

    private func emit(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            session.credit(self, data.count)
            handler(data, nil)
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
        if !payloadQueue.isEmpty {
            pendingHandler = nil
            handler(dequeue(), nil)
        } else {
            pendingHandler = nil
            handler(nil, failure) // nil error = clean EOF
        }
    }
}
