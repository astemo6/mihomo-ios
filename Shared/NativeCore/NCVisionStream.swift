import Foundation

/// XTLS Vision stream glue: wraps an NCTLSClientStream (REALITY or plain
/// TLS 1.3) and frames traffic with the NCVision state machines until the
/// flow ends padding (commandEnd → passthrough inside TLS) or splices
/// (commandDirect → raw socket bytes both ways, TLS layer detached).
///
/// Layering: app bytes → NCVisionWriter frames → TLS records → socket;
/// inbound reverses through NCVisionReader. The VLESS request/response heads
/// are NOT vision content: the request head goes out over the carrier unframed
/// (NCConnector's vision sites send it before this stream exists), and the
/// response head is stripped below, before the reader — a server parses the
/// request head first and only then unframes the body (Xray's inbound order;
/// feeding it the head framed is what its "invalid request version" rejects).
/// On direct: writes go straight
/// to the raw NCStream; reads first drain (a) the reader's remaining framed
/// output, (b) TLS-decrypted leftovers fed through the reader, (c) the TLS
/// layer's unparsed raw tail — inner plaintext that arrived past the last
/// record — then live raw bytes via receiveSpliced.
/// The record layer Vision frames ride on and splices out of: the hand-rolled TLS 1.3 client (REALITY / tls) or,
/// with VLESS `encryption`, the encryption conn (Clash.Meta vision.NewConn accepts *encryption.CommonConn; direct
/// bytes then go to CommonConn.Conn, i.e. through the XorConn layer when xorpub is on). feat/nc-proto3.
protocol NCVisionCarrier: AnyObject {
    func send(_ data: Data)
    func send(_ data: Data, completion: @escaping () -> Void)
    func receive(_ handler: @escaping (Data?, Error?) -> Void)
    /// Write below the record layer (after Vision switched to direct).
    func sendDirect(_ data: Data)
    func sendDirect(_ data: Data, completion: @escaping () -> Void)
    /// Detach the record layer: decrypted leftovers + raw bytes already read past the last record.
    func spliceOut() -> (plaintext: [Data], rawTail: Data)
    func receiveSpliced(_ handler: @escaping (Data?, Error?) -> Void)
    func cancel()
}

extension NCTLSClientStream: NCVisionCarrier {
    func sendDirect(_ data: Data) { rawStream.send(data) }
    func sendDirect(_ data: Data, completion: @escaping () -> Void) { rawStream.send(data, completion: completion) }
}

final class NCVisionStream: NCRelayStream {
    private let tls: NCVisionCarrier
    private let writer: NCVisionWriter
    private var reader: NCVisionReader

    private var writeDirect = false
    private var spliced = false
    private var rawTail = Data()
    private var outQueue: [Data] = []
    /// nc-perf: head offset for outQueue — pop by advancing instead of removeFirst per piece
    /// (compacted past the halfway point, same read-offset pattern as NCVisionReader).
    private var outHead = 0
    private var outBytes = 0
    private var outIsEmpty: Bool { outHead >= outQueue.count }
    private func popOut() -> Data {
        let d = outQueue[outHead]
        outBytes -= d.count
        outHead += 1
        if outHead == outQueue.count { outQueue.removeAll(); outHead = 0 }
        else if outHead > outQueue.count / 2 { outQueue.removeFirst(outHead); outHead = 0 }
        return d
    }

    /// nc-memory: the pump runs free of the reader, so the queue was unbounded. Cap aligns
    /// with the mux stream inbound cap; false = overflow (caller fails the stream).
    static let maxQueuedOut = 256 * 1024
    private func offer(_ pieces: [Data]) -> Bool {
        let total = pieces.reduce(0) { $0 + $1.count }
        guard outBytes + total <= Self.maxQueuedOut else { return false }
        outBytes += total
        outQueue.append(contentsOf: pieces)
        return true
    }
    private var readEOF = false
    private var pending: ((Data?, Error?) -> Void)?
    /// VLESS response head (version + addon length + addons), stripped before the reader.
    private var respHeadBuffer = Data()
    private var respHeadDone = false

    /// Returns the body bytes of `data` once the response head is fully consumed,
    /// nil while more head bytes are needed (an empty Data means the head ended
    /// exactly at this chunk — keep reading).
    private func stripResponseHead(_ data: Data) -> Data? {
        if respHeadDone { return data }
        respHeadBuffer.append(data)
        guard respHeadBuffer.count >= 2 else { return nil }
        let total = 2 + Int(respHeadBuffer[respHeadBuffer.startIndex + 1])
        guard respHeadBuffer.count >= total else { return nil }
        respHeadDone = true
        let rest = Data(respHeadBuffer.dropFirst(total))
        respHeadBuffer = Data()
        return rest
    }

    init(tls: NCVisionCarrier, uuid: [UInt8]) {
        self.tls = tls
        self.writer = NCVisionWriter(userUUID: uuid)
        self.reader = NCVisionReader(userUUID: uuid)
    }

    // MARK: send

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        if writeDirect {
            tls.sendDirect(data, completion: once.call)
            return
        }
        let frames = writer.process([UInt8](data)).map { Data($0) }
        if writer.isDirect { writeDirect = true }
        sendFrames(frames, once: once)
    }

    /// Vision frames go to the carrier one by one; the completion fires after the last frame's.
    private func sendFrames(_ frames: [Data], once: NCCallOnce) {
        guard let first = frames.first else { once.call(); return }
        if frames.count == 1 { tls.send(first, completion: once.call); return }
        tls.send(first) { [self] in sendFrames(Array(frames.dropFirst()), once: once) }
    }

    // MARK: receive

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !outIsEmpty {
            handler(popOut(), nil)
            return
        }
        if readEOF {
            handler(nil, nil)
            return
        }
        pending = handler
        pump()
    }

    private func deliver(_ data: Data) {
        guard let h = pending else {
            if !offer([data]) {
                deliverEOF(NSError(domain: "NativeCore", code: 4,
                                   userInfo: [NSLocalizedDescriptionKey: "vision receive buffer overflow"]))
                tls.cancel()
            }
            return
        }
        pending = nil
        h(data, nil)
    }

    private func deliverEOF(_ error: Error?) {
        readEOF = true
        guard let h = pending else { return }
        pending = nil
        h(nil, error)
    }

    private func pump() {
        if !outIsEmpty {
            deliver(popOut())
            return
        }
        guard pending != nil else { return }
        if spliced {
            if !rawTail.isEmpty {
                let out = rawTail
                rawTail = Data()
                deliver(out)
                return
            }
            tls.receiveSpliced { [weak self] data, error in
                guard let self else { return }
                if let data { self.deliver(data) }
                else { self.deliverEOF(error) }
            }
            return
        }
        tls.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                self.deliverEOF(error)
                return
            }
            guard let body = self.stripResponseHead(data), !body.isEmpty else {
                self.pump() // response head not complete yet (or ended exactly here)
                return
            }
            do {
                let outs = try self.reader.feed([UInt8](body))
                guard self.offer(outs.map { Data($0) }) else {
                    self.deliverEOF(NSError(domain: "NativeCore", code: 4,
                                            userInfo: [NSLocalizedDescriptionKey: "vision receive buffer overflow"]))
                    self.tls.cancel()
                    return
                }
            } catch {
                self.deliverEOF(error)
                return
            }
            if self.reader.directRequested, !self.spliced {
                self.performSplice()
            }
            self.pump()
        }
    }

    /// The server chose direct: detach the TLS record layer and feed its
    /// drained plaintext through the reader (which is in passthrough now)
    /// before switching the byte source to the raw socket.
    private func performSplice() {
        spliced = true
        let (plain, tail) = tls.spliceOut()
        rawTail = tail
        for chunk in plain {
            guard let body = stripResponseHead(chunk), !body.isEmpty else { continue }
            if let outs = try? reader.feed([UInt8](body)) {
                _ = offer(outs.map { Data($0) })
            }
        }
    }

    func cancel() {
        tls.cancel()
    }
}
