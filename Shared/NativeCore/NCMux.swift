import Foundation

/// sing-mux (the mux mihomo ships) — h2mux protocol only, which is the
/// library default. Session setup: the client dials the proxy to the
/// magic destination `sp.mux.sing-box.arpa:444`, writes a 2-byte request
/// [version][protocol=2] (version 1 adds a padding flag + optional
/// padding block; we send version 0, no padding), then speaks HTTP/2:
/// each logical stream is a CONNECT request to :authority "localhost".
/// Inside every stream, the first client bytes are a StreamRequest
/// [flags u16][target atyp] and the first server byte is a status
/// (0 = ok, 1 = error followed by a length-prefixed message).
enum NCMux {
    static let destination = NCTarget(host: "sp.mux.sing-box.arpa", port: 444)

    /// Version 0 (no padding). The padding variant wraps the whole
    /// session in an extra framing layer; configs asking for it are
    /// honored only with padding off (mihomo's default) — see the
    /// connector note.
    static func preamble() -> Data { Data([0x00, 0x02]) }

    static func streamRequestTCP(target: NCTarget) -> Data {
        var out = Data(count: 2) // flags = 0
        out.append(target.atypEncoded)
        return out
    }

    static func streamRequestUDPPacketAddr() -> Data {
        var out = Data()
        out.appendBE16(0x0003) // flagUDP | flagAddr
        out.append(destination.atypEncoded)
        return out
    }

    /// Parse the stream response status byte. Returns (ok, consumedBytes)
    /// or nil when more bytes are needed (error message incomplete) or
    /// the status is an error — the caller wants the message too, so
    /// error returns the full (false, message, consumed) triple via
    /// parseStreamResponseFull.
    static func parseStreamResponse(_ data: Data) -> (ok: Bool, message: String?, consumed: Int)? {
        guard let status = data.first else { return nil }
        if status == 0 { return (true, nil, 1) }
        guard status == 1 else { return (false, "bad stream response status \(status)", 1) }
        // Error: [1][len u16][message] (rw.ReadVString = u16 BE length).
        guard data.count >= 3 else { return nil }
        let len = Int(data[1]) << 8 | Int(data[2])
        guard data.count >= 3 + len else { return nil }
        let msg = String(decoding: data[3..<(3 + len)], as: UTF8.self)
        return (false, msg, 3 + len)
    }

    /// One UDP packet frame inside a packet-addr stream:
    /// [target atyp][payloadLen u16][payload].
    static func udpPacketFrame(target: NCTarget, payload: Data) -> Data {
        var out = target.atypEncoded
        out.appendBE16(UInt16(clamping: payload.count))
        out.append(payload)
        return out
    }

    static func parseUDPPacketFrame(_ data: Data) -> (NCTarget, Data, Int)? {
        guard let (target, used) = NCSS2022.parseTarget(data) else { return nil }
        guard data.count >= used + 2 else { return nil }
        let len = Int(data[used]) << 8 | Int(data[used + 1])
        guard data.count >= used + 2 + len else { return nil }
        return (target, Data(data[(used + 2)..<(used + 2 + len)]), used + 2 + len)
    }
}

/// Multi-stream HTTP/2 session core for h2mux. Reuses the frame/HPACK
/// machinery from the tunnel core but keeps per-stream state.
final class NCH2MuxCore {
    enum Event {
        case payload(streamID: Int, Data)
        case responseHeaders(streamID: Int, [(String, String)])
        case ended(streamID: Int)
        case reset(streamID: Int)
        case windowIncreased
        case goaway
    }

    struct FeedResult {
        var outbound = Data()
        var events: [Event] = []
    }

    private var buffer = Data()
    private var decoder = NCHPACKDecoder()
    private var nextStreamID = 1
    private(set) var connSendWindow = 65535
    private var peerMaxFrame = 16384
    private var peerInitialWindow = 65535
    private var streamWindows: [Int: Int] = [:]
    private var headerBlocks: [Int: Data] = [:]

    func start() -> Data {
        var out = NCH2ClientCore.preface
        out.append(NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0, payload: Data()))
        return out
    }

    /// Open a CONNECT stream; returns its id and the HEADERS frame bytes.
    func openStream() -> (Int, Data) {
        let id = nextStreamID
        nextStreamID += 2
        streamWindows[id] = peerInitialWindow
        let headers: [(String, String)] = [(":method", "CONNECT"), (":authority", "localhost")]
        let frame = NCH2ClientCore.frame(type: 0x1, flags: 0x4, streamID: id,
                                         payload: NCHPACK.encodeHeaders(headers))
        return (id, frame)
    }

    func streamWindow(_ id: Int) -> Int { streamWindows[id] ?? 0 }

    /// Serialize stream data into DATA frames within both windows.
    func makeData(streamID: Int, data: Data) -> (frames: Data, consumed: Int) {
        var out = Data()
        var offset = 0
        while offset < data.count {
            let allowance = min(connSendWindow, streamWindows[streamID] ?? 0,
                                peerMaxFrame, data.count - offset)
            guard allowance > 0 else { break }
            let chunk = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + allowance)])
            out.append(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: streamID, payload: chunk))
            connSendWindow -= allowance
            streamWindows[streamID, default: 0] -= allowance
            offset += allowance
        }
        return (out, offset)
    }

    func endStream(_ id: Int) -> Data {
        NCH2ClientCore.frame(type: 0x0, flags: 0x1, streamID: id, payload: Data())
    }

    func rstStream(_ id: Int) -> Data {
        NCH2ClientCore.frame(type: 0x3, flags: 0, streamID: id,
                             payload: Data([0, 0, 0, 8]))
    }

    func feed(_ data: Data) -> FeedResult {
        var result = FeedResult()
        buffer.append(data)
        while buffer.count >= 9 {
            let len = Int(buffer[0]) << 16 | Int(buffer[1]) << 8 | Int(buffer[2])
            guard buffer.count >= 9 + len else { break }
            let type = buffer[3]
            let flags = buffer[4]
            let streamID = Int(buffer[5] & 0x7f) << 24 | Int(buffer[6]) << 16 | Int(buffer[7]) << 8 | Int(buffer[8])
            let payload = Data(buffer[9..<(9 + len)])
            buffer = Data(buffer.dropFirst(9 + len))
            handle(type: type, flags: flags, streamID: streamID, payload: payload, into: &result)
        }
        return result
    }

    private func handle(type: UInt8, flags: UInt8, streamID: Int, payload: Data, into result: inout FeedResult) {
        switch type {
        case 0x0: // DATA
            var body = payload
            if flags & 0x8 != 0, let pad = body.first {
                body = Data(body.dropFirst(1 + Int(pad)))
            }
            if !payload.isEmpty {
                result.outbound.append(NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: 0,
                                                            payload: be32(payload.count)))
                result.outbound.append(NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: streamID,
                                                            payload: be32(payload.count)))
            }
            if !body.isEmpty { result.events.append(.payload(streamID: streamID, body)) }
            if flags & 0x1 != 0 { result.events.append(.ended(streamID: streamID)) }
        case 0x1, 0x9: // HEADERS / CONTINUATION
            var block = headerBlocks[streamID] ?? Data()
            var frag = payload
            if type == 0x1 {
                if flags & 0x8 != 0, let pad = frag.first { frag = Data(frag.dropFirst(1 + Int(pad))) }
                if flags & 0x20 != 0 { frag = Data(frag.dropFirst(5)) }
            }
            block.append(frag)
            if flags & 0x4 != 0 {
                headerBlocks[streamID] = nil
                if let headers = decoder.decode(block) {
                    result.events.append(.responseHeaders(streamID: streamID, headers))
                }
            } else {
                headerBlocks[streamID] = block
            }
            if flags & 0x1 != 0 { result.events.append(.ended(streamID: streamID)) }
        case 0x3:
            result.events.append(.reset(streamID: streamID))
        case 0x4:
            if flags & 0x1 == 0 {
                var i = 0
                while i + 6 <= payload.count {
                    let id = Int(payload[i]) << 8 | Int(payload[i + 1])
                    let value = Int(payload[i + 2]) << 24 | Int(payload[i + 3]) << 16 | Int(payload[i + 4]) << 8 | Int(payload[i + 5])
                    if id == 0x3 {
                        let delta = value - peerInitialWindow
                        peerInitialWindow = value
                        for k in streamWindows.keys { streamWindows[k, default: 0] += delta }
                    }
                    if id == 0x5 && value > 0 { peerMaxFrame = min(value, (1 << 24) - 1) }
                    i += 6
                }
                result.outbound.append(NCH2ClientCore.frame(type: 0x4, flags: 0x1, streamID: 0, payload: Data()))
                result.events.append(.windowIncreased)
            }
        case 0x6:
            if flags & 0x1 == 0 && payload.count == 8 {
                result.outbound.append(NCH2ClientCore.frame(type: 0x6, flags: 0x1, streamID: 0, payload: payload))
            }
        case 0x7:
            result.events.append(.goaway)
        case 0x8:
            guard payload.count == 4 else { return }
            let inc = Int(payload[0] & 0x7f) << 24 | Int(payload[1]) << 16 | Int(payload[2]) << 8 | Int(payload[3])
            if streamID == 0 { connSendWindow += inc }
            else { streamWindows[streamID, default: 0] += inc }
            result.events.append(.windowIncreased)
        default:
            return
        }
    }

    private func be32(_ v: Int) -> Data {
        Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }
}
