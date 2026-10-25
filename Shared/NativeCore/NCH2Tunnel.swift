import Foundation

/// HTTP/2 tunnel stream (NCH2ClientCore over a byte pipe). Used for the
/// VMess/VLESS "grpc" and "h2" transports. For gRPC, stream payloads are
/// wrapped/deframed as gRPC messages ([0][len u32][bytes]).
///
/// Threading (nc-races, the #116 pattern): unlike the mux/anytls streams there is no session above this
/// stream — each tunnel owns a serial queue, and all of its state (the NCH2ClientCore, the pending-send
/// table, the payload queue, the receive handler) is touched only there. Entry points hop in; the
/// registered receive handler is delivered on `callerQueue`, recorded at construction, so the caller's
/// own state stays on its queue. (Before this, send/receive ran on the caller's queue while the core was
/// fed from the raw stream's queue — makeData/feed raced on the core and the waiter table.)
final class NCH2TunnelStream: NCRelayStream {
    private let raw: NCRelayStream
    private let core = NCH2ClientCore()
    private let grpc: Bool
    private let queue = NCSessionQueues.make("nc.h2.stream")
    private let callerQueue: DispatchQueue
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

    init(raw: NCRelayStream, grpc: Bool, callerQueue: DispatchQueue) {
        self.raw = raw
        self.grpc = grpc
        self.callerQueue = callerQueue
    }

    func startHandshake(headers: [(String, String)],
                        completion: @escaping (Error?) -> Void) {
        // The core's start frame must precede any DATA a pump sends right after completion, and pumps
        // hop onto `queue` behind this block: a sync hop orders the two without changing the
        // synchronous completion shape callers rely on.
        queue.sync {
            self.raw.send(self.core.start(headers: headers))
            self.startReceiveLoop()
        }
        completion(nil)
    }

    // MARK: NCRelayStream

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard self.dead == nil else { once.call(); return }
            if self.grpc {
                var msg = Data()
                msg.append(0)
                msg.appendBE32(UInt32(data.count))
                msg.append(data)
                self.pendingSend.append(msg)
                self.sendAppended += msg.count
            } else {
                self.pendingSend.append(data)
                self.sendAppended += data.count
            }
            self.sendWaiters.append((self.sendAppended, once))
            self.flushSend()
        }
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
        ncOnSessionQueue(queue) {
            if !self.payloadQueue.isEmpty {
                let data = self.payloadQueue.removeFirst()
                self.callerQueue.async { handler(data, nil) }
                return
            }
            if let dead = self.dead {
                self.callerQueue.async { handler(nil, dead) }
                return
            }
            self.pendingHandler = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            self.drainSendWaiters()
            self.raw.send(self.core.rstStream())
            self.raw.cancel()
        }
    }

    // MARK: internals

    private func flushSend() {
        guard !pendingSend.isEmpty else { return }
        let (frames, consumed) = core.makeData(pendingSend)
        if consumed > 0 {
            pendingSend = Data(pendingSend.dropFirst(consumed))
            raw.send(frames) { [weak self] in
                guard let self else { return }
                ncOnSessionQueue(self.queue) { self.noteConsumed(consumed) }
            }
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
            // The raw stream's callbacks live on its own queue; hop so the core and the tables are
            // only ever touched on this stream's queue.
            ncOnSessionQueue(self.queue) {
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
            callerQueue.async { handler(data, nil) }
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
            callerQueue.async { handler(nil, error) }
        }
    }
}
