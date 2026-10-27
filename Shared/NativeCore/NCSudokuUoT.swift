import Foundation

/// Sudoku UDP (feat/nc-sudoku-udp): UDP-over-TCP inside the Sudoku tunnel, wire-compatible with the official
/// server v0.5.2.0 (its UoT session handler) and with Clash.Meta's Sudoku outbound.
///
/// After the handshake the client sends KIP StartUoT (0x12, empty payload) instead of OpenTCP. From then on both
/// directions of the tunnel carry datagram frames:
///
///     addrLen u16 BE ‖ payloadLen u16 BE ‖ address ‖ payload
///
/// `address` is the SOCKS5-style encoding (0x01 IPv4 ‖ 4 / 0x03 len ‖ domain / 0x04 IPv6 ‖ 16, then port BE16).
/// Uplink frames name the destination (a domain is resolved by the server); downlink frames name the peer that
/// sent the datagram (always an IP from the official server). addrLen 0 is a protocol error that ends the session.
/// Each frame is written with one send, so it is sealed as one AEAD record like the official writer.
enum NCSudokuUoT {
    static let headerSize = 4
    /// Type, length, a 255-byte domain and the port.
    static let maxAddressLength = 1 + 1 + 255 + 2
    static let maxPayload = 65535

    /// One uplink frame for `payload` to `target`; nil when the target cannot be encoded or the payload is too big.
    static func frame(target: NCTarget, payload: Data) -> Data? {
        guard target.isWireEncodable, payload.count <= maxPayload else { return nil }
        let addr = address(target)
        var out = Data(capacity: headerSize + addr.count + payload.count)
        out.append(UInt8(addr.count >> 8))
        out.append(UInt8(addr.count & 0xff))
        out.append(UInt8(payload.count >> 8))
        out.append(UInt8(payload.count & 0xff))
        out.append(addr)
        out.append(payload)
        return out
    }

    /// SOCKS5-style address; IPv4-mapped IPv6 literals are sent as IPv4, like the official encoder.
    static func address(_ target: NCTarget) -> Data {
        if case .v6(let b)? = target.ip, b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff {
            var out = Data([0x01])
            out.append(contentsOf: b[12..<16])
            out.append(UInt8((target.port >> 8) & 0xff))
            out.append(UInt8(target.port & 0xff))
            return out
        }
        return target.atypEncoded
    }

    enum Parsed: Equatable {
        /// A whole frame: its peer (nil when the address is undecodable — the datagram is skipped, as
        /// Clash.Meta does), the payload's byte range inside the buffer, and the bytes the frame used.
        case frame(peer: NCTarget?, payload: Range<Int>, consumed: Int)
        case incomplete
        /// addrLen 0: the official reader fails the session on it.
        case invalid
    }

    /// Parses the frame starting `offset` bytes into `buffer` without copying.
    static func parse(_ buffer: Data, at offset: Int = 0) -> Parsed {
        let base = buffer.startIndex + offset
        guard buffer.endIndex - base >= headerSize else { return .incomplete }
        let addrLen = Int(buffer[base]) << 8 | Int(buffer[base + 1])
        let payloadLen = Int(buffer[base + 2]) << 8 | Int(buffer[base + 3])
        guard addrLen > 0 else { return .invalid }
        let total = headerSize + addrLen + payloadLen
        guard buffer.endIndex - base >= total else { return .incomplete }
        let addrStart = base + headerSize
        let payloadStart = addrStart + addrLen
        let peer = decodeAddress(buffer, addrStart..<payloadStart)
        return .frame(peer: peer, payload: payloadStart..<(payloadStart + payloadLen), consumed: total)
    }

    /// Decodes a SOCKS5-style address in `range` of `buffer` (bytes past the encoding are ignored, as the
    /// reference readers treat them as padding).
    static func decodeAddress(_ buffer: Data, _ range: Range<Int>) -> NCTarget? {
        guard range.count >= 1 else { return nil }
        let s = range.lowerBound
        func port(_ at: Int) -> Int { Int(buffer[at]) << 8 | Int(buffer[at + 1]) }
        switch buffer[s] {
        case 0x01:
            guard range.count >= 7, let ip = NCIP(bytes: Array(buffer[(s + 1)..<(s + 5)])) else { return nil }
            return NCTarget(host: ip.string, port: port(s + 5))
        case 0x04:
            guard range.count >= 19, let ip = NCIP(bytes: Array(buffer[(s + 1)..<(s + 17)])) else { return nil }
            return NCTarget(host: ip.string, port: port(s + 17))
        case 0x03:
            guard range.count >= 2 else { return nil }
            let n = Int(buffer[s + 1])
            guard n > 0, range.count >= 2 + n + 2 else { return nil }
            let host = String(decoding: buffer[(s + 2)..<(s + 2 + n)], as: UTF8.self)
            return NCTarget(host: host, port: port(s + 2 + n))
        default:
            return nil
        }
    }
}

/// One UDP association through a Sudoku node (feat/nc-sudoku-udp): one tunnel opened with StartUoT per data
/// plane UDP session — the official client and Clash.Meta also open one UoT tunnel per association. Datagrams to
/// any target ride the same tunnel; replies are handed up with their peer.
///
/// Memory: no per-flow payload buffers beyond one partial downlink frame (the read buffer is released as soon as
/// it is drained); datagrams queued while the tunnel opens are capped (16 frames / 64 KiB); in-flight uplink bytes
/// are capped at 256 KiB (the official writer's pending limit) — past that datagrams are dropped, as a congested
/// UDP path would. Conforms to the tunnel's NCUDPSession in PacketTunnel/NativeCore/NCSudokuUDP.swift.
final class NCSudokuUDPSession {
    static let maxPendingFrames = 16
    static let maxPendingBytes = 64 * 1024
    static let maxInFlightBytes = 256 * 1024
    /// A legal frame is at most 4 + 65535 + 65535 bytes; more residue than that is a broken stream.
    static let maxResidue = NCSudokuUoT.headerSize + 2 * 65535

    var onReply: (Data) -> Void = { _ in }
    /// Optional: replies with the peer the server reported (tests, diagnostics).
    var onDatagram: ((NCTarget?, Data) -> Void)?
    /// Optional: the tunnel failed to open or ended.
    var onClose: ((Error?) -> Void)?

    private var stream: NCRelayStream?
    private var pending: [Data] = []
    private var pendingBytes = 0
    private var inFlight = 0
    private var buffer = Data()
    private var offset = 0
    private var dead = false
    private var cancelled = false
    private(set) var dropped = 0
    /// Bytes of a partial downlink frame held right now (0 between frames).
    var bufferedBytes: Int { buffer.count - offset }

    init(proxy: NCProxy, queue: DispatchQueue, transport: NCRelayStream? = nil) {
        NCConnector.sudokuUoTStream(proxy: proxy, queue: queue, transport: transport) { [weak self] s, err in
            guard let self, !self.cancelled else { s?.cancel(); return }
            guard let s else { self.finish(err); return }
            self.stream = s
            let queued = self.pending
            self.pending = []
            self.pendingBytes = 0
            for f in queued { self.write(f) }
            self.receiveLoop()
        }
    }

    /// Drives an already-opened UoT stream (the tunnel after StartUoT); unit tests use it with an in-memory stream.
    init(attached stream: NCRelayStream) {
        self.stream = stream
        receiveLoop()
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !dead, !cancelled else { return }
        guard let framed = NCSudokuUoT.frame(target: target, payload: data) else { dropped += 1; return }
        guard stream != nil else {
            if pending.count < Self.maxPendingFrames, pendingBytes + framed.count <= Self.maxPendingBytes {
                pending.append(framed)
                pendingBytes += framed.count
            } else {
                dropped += 1
            }
            return
        }
        write(framed)
    }

    private func write(_ framed: Data) {
        guard let stream else { return }
        guard inFlight + framed.count <= Self.maxInFlightBytes else { dropped += 1; return }
        inFlight += framed.count
        let n = framed.count
        stream.send(framed) { [weak self] in self?.inFlight -= n }
    }

    private func receiveLoop() {
        guard let stream else { return }
        stream.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data, !data.isEmpty else { self.finish(error); return }
            if self.offset == 0 && self.buffer.isEmpty {
                self.buffer = data
            } else {
                self.buffer.append(data)
            }
            while true {
                switch NCSudokuUoT.parse(self.buffer, at: self.offset) {
                case .incomplete:
                    self.compact()
                    if self.buffer.count - self.offset > Self.maxResidue { self.fail(); return }
                    self.receiveLoop()
                    return
                case .invalid:
                    self.fail()
                    return
                case .frame(let peer, let range, let consumed):
                    self.offset += consumed
                    // Undecodable peers are skipped (Clash.Meta drops those datagrams and keeps the session).
                    if let peer {
                        let payload = self.buffer.subdata(in: range)
                        self.onDatagram?(peer, payload)
                        self.onReply(payload)
                        if self.cancelled || self.dead { return }
                    }
                }
            }
        }
    }

    /// Releases the read buffer once drained; rebases it past halfway so a partial frame never pins old bytes.
    private func compact() {
        if offset == 0 { return }
        if offset >= buffer.count {
            buffer = Data()
            offset = 0
        } else if offset > buffer.count / 2 {
            buffer = buffer.subdata(in: (buffer.startIndex + offset)..<buffer.endIndex)
            offset = 0
        }
    }

    private func fail() {
        finish(NCSudokuError.protocolError("UoT 帧格式错误"))
    }

    private func finish(_ error: Error?) {
        guard !dead else { return }
        dead = true
        pending = []
        pendingBytes = 0
        buffer = Data()
        offset = 0
        stream?.cancel()
        stream = nil
        onClose?(error)
    }

    func cancel() {
        cancelled = true
        pending = []
        pendingBytes = 0
        buffer = Data()
        offset = 0
        stream?.cancel()
        stream = nil
    }
}
