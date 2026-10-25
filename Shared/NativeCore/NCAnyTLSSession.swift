import Foundation

/// Shared AnyTLS session: one TLS connection per proxy, streams opened
/// per flow. The auth block and the settings frame go out first; record
/// padding shaping from the scheme is not reproduced (interop-safe).
final class NCAnyTLSSession {
    enum State { case connecting, ready, failed }

    private(set) var state: State = .connecting
    private var tls: NCStream?
    private var parser = NCAnyTLS.FrameParser()
    private var streams: [UInt32: NCAnyTLSStream] = [:]
    private var nextStreamID: UInt32 = 1
    private var tornDown = false

    func attach(tls: NCStream, password: String, clientMetadata: String) {
        self.tls = tls
        state = .ready
        var hello = NCAnyTLS.authBlock(password: password, paddingLen: Int.random(in: 30...300))
        hello.append(NCAnyTLS.settingsFrame(clientMetadata: clientMetadata))
        tls.send(hello)
        pump()
    }

    func attachFailed() {
        state = .failed
        streams.values.forEach { $0.failFromSession() }
        streams.removeAll()
    }

    var isAlive: Bool { state == .ready && !tornDown }

    func openStream(target: NCTarget?) -> NCAnyTLSStream {
        let sid = nextStreamID
        nextStreamID += 1
        let stream = NCAnyTLSStream(session: self, streamID: sid, target: target)
        streams[sid] = stream
        tls?.send(NCAnyTLS.frame(cmd: NCAnyTLS.cmdSYN, streamID: sid))
        return stream
    }

    func sendFrame(_ frame: Data) { tls?.send(frame) }

    func streamClosed(_ stream: NCAnyTLSStream) {
        streams[stream.streamID] = nil
        if !tornDown {
            tls?.send(NCAnyTLS.frame(cmd: NCAnyTLS.cmdFIN, streamID: stream.streamID))
        }
    }

    private func pump() {
        tls?.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else { self.teardown(); return }
            for frame in self.parser.feed(data) {
                self.handle(frame)
            }
            if !self.tornDown { self.pump() }
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
        state = .failed
        streams.values.forEach { $0.failFromSession() }
        streams.removeAll()
    }
}

/// One AnyTLS stream. The first send prepends the target address
/// (CreateProxy semantics); no separate handshake acknowledgement is
/// awaited — a SYNACK error or FIN surfaces through receive.
final class NCAnyTLSStream: NCRelayStream {
    let streamID: UInt32
    private let session: NCAnyTLSSession
    private let target: NCTarget?
    private var targetWritten = false
    private var payloadQueue: [Data] = []
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var failure: Error?
    private var ended = false

    init(session: NCAnyTLSSession, streamID: UInt32, target: NCTarget? = nil) {
        self.session = session
        self.streamID = streamID
        self.target = target
    }

    func send(_ data: Data) {
        var payload = data
        if let target, !targetWritten {
            targetWritten = true
            var first = target.atypEncoded
            first.append(data)
            payload = first
        }
        let chunkSize = 0xffff
        var rest = payload
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(chunkSize))
            rest = Data(rest.dropFirst(chunk.count))
            session.sendFrame(NCAnyTLS.frame(cmd: NCAnyTLS.cmdPSH, streamID: streamID, data: chunk))
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !payloadQueue.isEmpty {
            handler(payloadQueue.removeFirst(), nil)
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
        session.streamClosed(self)
    }

    // MARK: session-facing

    func deliverFromSession(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            handler(data, nil)
        } else {
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
        settle()
    }

    private func settle() {
        guard let handler = pendingHandler else { return }
        pendingHandler = nil
        if !payloadQueue.isEmpty {
            handler(payloadQueue.removeFirst(), nil)
        } else {
            handler(nil, failure)
        }
    }
}
