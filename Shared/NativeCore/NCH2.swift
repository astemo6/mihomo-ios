import Foundation

/// Minimal HTTP/2 client core (RFC 7540) for tunnel transports: one
/// stream (id 1), no push, no priorities. Pure byte→byte state machine —
/// the PacketTunnel glue owns the socket. Flow control: we immediately
/// return receive windows for DATA we consume, and expose the send
/// windows so the glue never overruns the peer.
final class NCH2ClientCore {
    enum Event {
        case headers([(String, String)])
        case reset
        case goaway(lastStreamID: Int)
        case windowIncreased
    }

    static let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    private var buffer = Data()
    private var decoder = NCHPACKDecoder()
    private var headerBlock: Data?
    private(set) var connSendWindow = 65535
    private(set) var streamSendWindow = 65535
    private var peerMaxFrame = 16384
    private var peerInitialWindow = 65535
    private(set) var streamClosed = false

    /// Connection preface + empty SETTINGS + the request HEADERS frame
    /// (END_HEADERS only; the stream stays open for the tunnel).
    func start(headers: [(String, String)]) -> Data {
        var out = Self.preface
        out.append(Self.frame(type: 0x4, flags: 0, streamID: 0, payload: Data()))
        out.append(Self.frame(type: 0x1, flags: 0x4, streamID: 1,
                              payload: NCHPACK.encodeHeaders(headers)))
        return out
    }

    static func frame(type: UInt8, flags: UInt8, streamID: Int, payload: Data) -> Data {
        var out = Data()
        out.append(UInt8((payload.count >> 16) & 0xff))
        out.append(UInt8((payload.count >> 8) & 0xff))
        out.append(UInt8(payload.count & 0xff))
        out.append(type)
        out.append(flags)
        out.append(UInt8((streamID >> 24) & 0x7f))
        out.append(UInt8((streamID >> 16) & 0xff))
        out.append(UInt8((streamID >> 8) & 0xff))
        out.append(UInt8(streamID & 0xff))
        out.append(payload)
        return out
    }

    struct FeedResult {
        var outbound = Data()
        var payloads: [Data] = []
        var events: [Event] = []
    }

    /// We never send SETTINGS_MAX_FRAME_SIZE, so the peer must stay within the 2^14 default (RFC 7540 §4.2);
    /// a header block (HEADERS + CONTINUATION) is capped too. Violations end the stream (rv2-proto, memory first).
    static let maxFrameSize = 16384
    static let maxHeaderBlock = 64 * 1024

    func feed(_ data: Data) -> FeedResult {
        var result = FeedResult()
        buffer.append(data)
        var off = 0
        defer {
            if off >= buffer.count { buffer = Data() }
            else if off > 0 { buffer = Data(buffer[(buffer.startIndex + off)...]) }
        }
        while buffer.count - off >= 9 {
            let b = buffer.startIndex + off
            let len = Int(buffer[b]) << 16 | Int(buffer[b + 1]) << 8 | Int(buffer[b + 2])
            guard len <= Self.maxFrameSize else {
                protocolError(into: &result)
                off = buffer.count
                return result
            }
            guard buffer.count - off >= 9 + len else { break }
            let type = buffer[b + 3]
            let flags = buffer[b + 4]
            let streamID = Int(buffer[b + 5] & 0x7f) << 24 | Int(buffer[b + 6]) << 16 | Int(buffer[b + 7]) << 8 | Int(buffer[b + 8])
            let payload = Data(buffer[(b + 9)..<(b + 9 + len)])
            off += 9 + len
            handle(type: type, flags: flags, streamID: streamID, payload: payload, into: &result)
        }
        return result
    }

    private func protocolError(into result: inout FeedResult) {
        if !streamClosed {
            streamClosed = true
            result.outbound.append(rstStream())
            result.events.append(.reset)
        }
        headerBlock = nil
    }

    /// Strip HTTP/2 padding (RFC 7540 §6.1 / §6.2): with PADDED the first byte is the pad length and the padding
    /// sits at the END of the frame; HEADERS with PRIORITY carries 5 more bytes after the pad length.
    /// nil = malformed (padding longer than the frame).
    static func unpad(_ payload: Data, padded: Bool, priority: Bool) -> Data? {
        var start = payload.startIndex, end = payload.endIndex
        if padded {
            guard start < end else { return nil }
            let pad = Int(payload[start])
            start += 1
            guard end - start >= pad else { return nil }
            end -= pad
        }
        if priority {
            guard end - start >= 5 else { return nil }
            start += 5
        }
        return Data(payload[start..<end])
    }

    private func handle(type: UInt8, flags: UInt8, streamID: Int, payload: Data, into result: inout FeedResult) {
        switch type {
        case 0x0: // DATA
            guard streamID == 1 else { return }
            guard let body = Self.unpad(payload, padded: flags & 0x8 != 0, priority: false) else {
                protocolError(into: &result)
                return
            }
            if !payload.isEmpty { // flow control counts the whole payload, padding included
                result.outbound.append(Self.frame(type: 0x8, flags: 0, streamID: 0,
                                                  payload: be32(payload.count)))
                result.outbound.append(Self.frame(type: 0x8, flags: 0, streamID: 1,
                                                  payload: be32(payload.count)))
            }
            if !body.isEmpty { result.payloads.append(body) }
            if flags & 0x1 != 0 { streamClosed = true }
        case 0x1, 0x9: // HEADERS / CONTINUATION
            if headerBlock == nil { headerBlock = Data() }
            var block = payload
            if type == 0x1 {
                guard let frag = Self.unpad(payload, padded: flags & 0x8 != 0, priority: flags & 0x20 != 0) else {
                    protocolError(into: &result)
                    return
                }
                block = frag
            }
            guard (headerBlock?.count ?? 0) + block.count <= Self.maxHeaderBlock else {
                protocolError(into: &result)
                return
            }
            headerBlock?.append(block)
            if flags & 0x4 != 0 { // END_HEADERS
                if let block = headerBlock, let headers = decoder.decode(block) {
                    result.events.append(.headers(headers))
                }
                headerBlock = nil
            }
            if flags & 0x1 != 0 { streamClosed = true }
        case 0x3: // RST_STREAM
            if streamID == 1 { streamClosed = true; result.events.append(.reset) }
        case 0x4: // SETTINGS
            if flags & 0x1 != 0 { return } // ACK of ours
            var i = 0
            while i + 6 <= payload.count {
                let id = Int(payload[i]) << 8 | Int(payload[i + 1])
                let value = Int(payload[i + 2]) << 24 | Int(payload[i + 3]) << 16 | Int(payload[i + 4]) << 8 | Int(payload[i + 5])
                if id == 0x3 { // INITIAL_WINDOW_SIZE
                    streamSendWindow += value - peerInitialWindow
                    peerInitialWindow = value
                }
                if id == 0x5 && value > 0 { peerMaxFrame = min(value, 1 << 24 - 1) }
                i += 6
            }
            result.outbound.append(Self.frame(type: 0x4, flags: 0x1, streamID: 0, payload: Data()))
            result.events.append(.windowIncreased)
        case 0x6: // PING
            if flags & 0x1 == 0 && payload.count == 8 {
                result.outbound.append(Self.frame(type: 0x6, flags: 0x1, streamID: 0, payload: payload))
            }
        case 0x7: // GOAWAY
            if payload.count >= 4 {
                let last = Int(payload[0] & 0x7f) << 24 | Int(payload[1]) << 16 | Int(payload[2]) << 8 | Int(payload[3])
                result.events.append(.goaway(lastStreamID: last))
            }
        case 0x8: // WINDOW_UPDATE
            guard payload.count == 4 else { return }
            let inc = Int(payload[0] & 0x7f) << 24 | Int(payload[1]) << 16 | Int(payload[2]) << 8 | Int(payload[3])
            if streamID == 0 { connSendWindow += inc } else if streamID == 1 { streamSendWindow += inc }
            result.events.append(.windowIncreased)
        default:
            return
        }
    }

    /// Serialize `data` into DATA frames honoring the peer's max frame
    /// size and both send windows. Returns the frames and how many input
    /// bytes were consumed (less than the input when windows are shut).
    func makeData(_ data: Data) -> (frames: Data, consumed: Int) {
        var out = Data()
        var offset = 0
        while offset < data.count {
            let allowance = min(connSendWindow, streamSendWindow, peerMaxFrame, data.count - offset)
            guard allowance > 0 else { break }
            let chunk = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + allowance)])
            out.append(Self.frame(type: 0x0, flags: 0, streamID: 1, payload: chunk))
            connSendWindow -= allowance
            streamSendWindow -= allowance
            offset += allowance
        }
        return (out, offset)
    }

    func rstStream() -> Data {
        Self.frame(type: 0x3, flags: 0, streamID: 1, payload: be32(8)) // CANCEL
    }

    private func be32(_ v: Int) -> Data {
        Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }
}
