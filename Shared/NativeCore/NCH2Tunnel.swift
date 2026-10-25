import Foundation

/// HTTP/2 tunnel stream (NCH2ClientCore over a byte pipe). Used for the
/// VMess/VLESS "grpc" and "h2" transports. For gRPC, stream payloads are
/// wrapped/deframed as gRPC messages ([0][len u32][bytes]).
final class NCH2TunnelStream: NCRelayStream {
    private let raw: NCRelayStream
    private let core = NCH2ClientCore()
    private let grpc: Bool
    private var pendingSend = Data()
    /// nc-sessions-flow: send completions indexed by cumulative pendingSend offset; a completion fires
    /// once its bytes were window-accepted by the core and the resulting frames were handed to raw.
    private var sendWaiters: [(end: Int, once: NCCallOnce)] = []
    private var sendAppended = 0
    private var sendConsumed = 0
    private var payloadQueue: [Data] = []
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var grpcBuffer = Data()
    private var dead: Error?
    private var receiveStarted = false

    init(raw: NCRelayStream, grpc: Bool) {
        self.raw = raw
        self.grpc = grpc
    }

    func startHandshake(headers: [(String, String)],
                        completion: @escaping (Error?) -> Void) {
        raw.send(core.start(headers: headers))
        startReceiveLoop()
        completion(nil)
    }

    // MARK: NCRelayStream

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard dead == nil else { once.call(); return }
        if grpc {
            var msg = Data()
            msg.append(0)
            msg.appendBE32(UInt32(data.count))
            msg.append(data)
            pendingSend.append(msg)
            sendAppended += msg.count
        } else {
            pendingSend.append(data)
            sendAppended += data.count
        }
        sendWaiters.append((sendAppended, once))
        flushSend()
    }

    private func noteConsumed(_ n: Int) {
        sendConsumed += n
        let due = sendWaiters.filter { $0.end <= sendConsumed }
        sendWaiters.removeAll { $0.end <= sendConsumed }
        due.forEach { $0.once.call() }
    }

    private func drainSendWaiters() {
        let all = sendWaiters
        sendWaiters = []
        all.forEach { $0.once.call() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !payloadQueue.isEmpty {
            handler(payloadQueue.removeFirst(), nil)
            return
        }
        if let dead {
            handler(nil, dead)
            return
        }
        pendingHandler = handler
    }

    func cancel() {
        drainSendWaiters()
        raw.send(core.rstStream())
        raw.cancel()
    }

    // MARK: internals

    private func flushSend() {
        guard !pendingSend.isEmpty else { return }
        let (frames, consumed) = core.makeData(pendingSend)
        if consumed > 0 {
            pendingSend = Data(pendingSend.dropFirst(consumed))
            raw.send(frames) { [weak self] in self?.noteConsumed(consumed) }
        }
    }

    private func startReceiveLoop() {
        guard !receiveStarted else { return }
        receiveStarted = true
        pump()
    }

    private func pump() {
        raw.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                self.fail(error ?? NSError(domain: "NativeCore", code: 5,
                                           userInfo: [NSLocalizedDescriptionKey: "h2 stream closed"]))
                return
            }
            let result = self.core.feed(data)
            if !result.outbound.isEmpty { self.raw.send(result.outbound) }
            for event in result.events {
                switch event {
                case .windowIncreased:
                    self.flushSend()
                case .reset:
                    self.fail(NSError(domain: "NativeCore", code: 5,
                                      userInfo: [NSLocalizedDescriptionKey: "h2 stream reset"]))
                    return
                case .goaway, .headers:
                    break
                }
            }
            for payload in result.payloads { self.deliver(payload) }
            if self.dead == nil { self.pump() }
        }
    }

    private func deliver(_ payload: Data) {
        if grpc {
            grpcBuffer.append(payload)
            while grpcBuffer.count >= 5 {
                let len = Int(grpcBuffer[1]) << 24 | Int(grpcBuffer[2]) << 16 | Int(grpcBuffer[3]) << 8 | Int(grpcBuffer[4])
                guard grpcBuffer.count >= 5 + len else { break }
                let msg = Data(grpcBuffer[5..<(5 + len)])
                grpcBuffer = Data(grpcBuffer.dropFirst(5 + len))
                if !msg.isEmpty { emit(msg) }
            }
        } else if !payload.isEmpty {
            emit(payload)
        }
    }

    private func emit(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            handler(data, nil)
        } else {
            payloadQueue.append(data)
        }
    }

    private func fail(_ error: Error) {
        guard dead == nil else { return }
        dead = error
        drainSendWaiters()
        if let handler = pendingHandler {
            pendingHandler = nil
            handler(nil, error)
        }
    }
}
