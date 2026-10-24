import Foundation

/// XTLS Vision stream glue: wraps an NCTLSClientStream (REALITY or plain
/// TLS 1.3) and frames traffic with the NCVision state machines until the
/// flow ends padding (commandEnd → passthrough inside TLS) or splices
/// (commandDirect → raw socket bytes both ways, TLS layer detached).
///
/// Layering: app bytes → NCVisionWriter frames → TLS records → socket;
/// inbound reverses through NCVisionReader. On direct: writes go straight
/// to the raw NCStream; reads first drain (a) the reader's remaining framed
/// output, (b) TLS-decrypted leftovers fed through the reader, (c) the TLS
/// layer's unparsed raw tail — inner plaintext that arrived past the last
/// record — then live raw bytes via receiveSpliced.
final class NCVisionStream: NCRelayStream {
    private let tls: NCTLSClientStream
    private let raw: NCRelayStream
    private let writer: NCVisionWriter
    private var reader: NCVisionReader

    private var writeDirect = false
    private var spliced = false
    private var rawTail = Data()
    private var outQueue: [Data] = []
    private var readEOF = false
    private var pending: ((Data?, Error?) -> Void)?

    init(tls: NCTLSClientStream, uuid: [UInt8]) {
        self.tls = tls
        self.raw = tls.rawStream
        self.writer = NCVisionWriter(userUUID: uuid)
        self.reader = NCVisionReader(userUUID: uuid)
    }

    // MARK: send

    func send(_ data: Data) {
        if writeDirect {
            raw.send(data)
            return
        }
        for frame in writer.process([UInt8](data)) {
            tls.send(Data(frame))
        }
        if writer.isDirect { writeDirect = true }
    }

    // MARK: receive

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !outQueue.isEmpty {
            handler(outQueue.removeFirst(), nil)
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
        guard let h = pending else { outQueue.append(data); return }
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
        if !outQueue.isEmpty {
            deliver(outQueue.removeFirst())
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
            do {
                let outs = try self.reader.feed([UInt8](data))
                self.outQueue.append(contentsOf: outs.map { Data($0) })
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
            if let outs = try? reader.feed([UInt8](chunk)) {
                outQueue.append(contentsOf: outs.map { Data($0) })
            }
        }
    }

    func cancel() {
        tls.cancel()
    }
}
