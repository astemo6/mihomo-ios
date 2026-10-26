import Foundation

/// HTTP/2 tunnel stream (NCH2ClientCore over a byte pipe). Used for the
/// VMess/VLESS "grpc" and "h2" transports. For gRPC, stream payloads are
/// wrapped/deframed as gRPC messages ([0][len u32][body]), where the body is
/// the v2ray Gun `Hunk` protobuf message ([0x0A][varint len][payload]) — the
/// raw stream bytes are NOT the message body: a server parsing the Hunk sees
/// an empty payload in a raw body and the transport's first request comes up
/// short (sing-box trojan-grpc: "bad request size").
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
    private var queuedBytes = 0
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var grpcBuffer = Data()
    private var dead: Error?
    private var receiveStarted = false

    /// nc-memory: per-stream byte caps. The core returns DATA windows immediately (see NCH2ClientCore),
    /// so neither the send side (peer window shut) nor the receive side (reader stalled) is flow-control
    /// bounded on its own. Overflow fails the stream instead of buffering without bound.
    static let maxPendingSend = 256 * 1024
    static let maxQueuedInbound = 256 * 1024
    /// A single gRPC message larger than this is not a tunnel chunk; the length prefix is wire data.
    static let maxGRPCMessage = 1024 * 1024

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
                let body = Self.grpcHunkWrap(data)
                msg.append(0)
                msg.appendBE32(UInt32(body.count))
                msg.append(body)
                guard self.pendingSend.count + msg.count <= Self.maxPendingSend else {
                    once.call()
                    self.fail(NSError(domain: "NativeCore", code: 5,
                                      userInfo: [NSLocalizedDescriptionKey: "h2 stream send buffer overflow"]))
                    self.raw.send(self.core.rstStream())
                    self.raw.cancel()
                    return
                }
                self.pendingSend.append(msg)
                self.sendAppended += msg.count
            } else if self.pendingSend.count + data.count > Self.maxPendingSend {
                once.call()
                self.fail(NSError(domain: "NativeCore", code: 5,
                                  userInfo: [NSLocalizedDescriptionKey: "h2 stream send buffer overflow"]))
                self.raw.send(self.core.rstStream())
                self.raw.cancel()
                return
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
                self.queuedBytes -= data.count
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
            // Mark dead first (fail() alone used to set it): a send/receive issued after
            // cancel must resolve through the dead checks instead of appending to a
            // cancelled raw stream, where its waiter could hang forever — and the pending
            // receive handler must be delivered here, because fail() can no longer run
            // once dead is set. drainSendWaiters extracts before firing, so the later
            // raw-EOF fail() (guarded on dead == nil) cannot fire anything twice.
            if self.dead == nil {
                let error = NSError(domain: "NativeCore", code: 5,
                                    userInfo: [NSLocalizedDescriptionKey: "h2 stream cancelled"])
                self.dead = error
                if let handler = self.pendingHandler {
                    self.pendingHandler = nil
                    self.callerQueue.async { handler(nil, error) }
                }
            }
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
                guard len <= Self.maxGRPCMessage else {
                    fail(NSError(domain: "NativeCore", code: 5,
                                 userInfo: [NSLocalizedDescriptionKey: "grpc message too large"]))
                    raw.cancel()
                    return
                }
                guard grpcBuffer.count >= 5 + len else { break }
                let body = Data(grpcBuffer[5..<(5 + len)])
                grpcBuffer = Data(grpcBuffer.dropFirst(5 + len))
                guard let payload = Self.grpcHunkPayload(body) else {
                    fail(NSError(domain: "NativeCore", code: 5,
                                 userInfo: [NSLocalizedDescriptionKey: "grpc message decode failed"]))
                    raw.cancel()
                    return
                }
                if !payload.isEmpty { emit(payload) }
            }
        } else if !payload.isEmpty {
            emit(payload)
        }
    }

    // MARK: gRPC Hunk protobuf (v2ray Gun: message Hunk { bytes payload = 1; })

    /// Wrap stream bytes as a Hunk message body: field 1, wire type 2.
    static func grpcHunkWrap(_ data: Data) -> Data {
        var out = Data()
        out.append(0x0A)
        var n = data.count
        while true {
            var b = UInt8(n & 0x7F)
            n >>= 7
            if n > 0 { b |= 0x80; out.append(b) } else { out.append(b); break }
        }
        out.append(data)
        return out
    }

    /// Extract the payload from a Hunk message body; unknown fields are skipped per their wire
    /// type. nil on a malformed body (truncated varint / length overrun / unknown wire type).
    static func grpcHunkPayload(_ body: Data) -> Data? {
        var out = Data()
        var i = body.startIndex
        func readVarint() -> Int? {
            var result = 0
            var shift = 0
            while i < body.endIndex {
                let b = body[i]
                i = body.index(after: i)
                result |= Int(b & 0x7F) << shift
                if b & 0x80 == 0 { return result }
                shift += 7
                if shift > 63 { return nil }
            }
            return nil
        }
        while i < body.endIndex {
            guard let key = readVarint() else { return nil }
            let field = key >> 3, wire = key & 7
            switch wire {
            case 0:
                guard readVarint() != nil else { return nil }
            case 1:
                guard body.distance(from: i, to: body.endIndex) >= 8 else { return nil }
                i = body.index(i, offsetBy: 8)
            case 2:
                guard let n = readVarint(), n <= body.distance(from: i, to: body.endIndex) else { return nil }
                if field == 1 { out.append(Data(body[i..<body.index(i, offsetBy: n)])) }
                i = body.index(i, offsetBy: n)
            case 5:
                guard body.distance(from: i, to: body.endIndex) >= 4 else { return nil }
                i = body.index(i, offsetBy: 4)
            default:
                return nil
            }
        }
        return out
    }

    private func emit(_ data: Data) {
        if let handler = pendingHandler {
            pendingHandler = nil
            callerQueue.async { handler(data, nil) }
        } else {
            guard queuedBytes + data.count <= Self.maxQueuedInbound else {
                fail(NSError(domain: "NativeCore", code: 5,
                             userInfo: [NSLocalizedDescriptionKey: "h2 stream receive buffer overflow"]))
                raw.cancel()
                return
            }
            queuedBytes += data.count
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
