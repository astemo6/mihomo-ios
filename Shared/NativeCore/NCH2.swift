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
    /// A connection error was sent (GOAWAY); nothing more is parsed.
    private(set) var connectionFailed = false

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
        if connectionFailed { return result }
        buffer.append(data)
        var off = 0
        defer {
            if off >= buffer.count { buffer = Data() }
            else if off > 0 { buffer = Data(buffer[(buffer.startIndex + off)...]) }
        }
        while buffer.count - off >= 9 {
            if connectionFailed { off = buffer.count; break }
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
            // fix/nc-h2-cidr: INITIAL_WINDOW_SIZE is id 0x4 (was read from 0x3 = MAX_CONCURRENT_STREAMS, so a
            // server advertising e.g. 100 streams shrank our stream send window to 100 bytes and stalled
            // gRPC / h2 uploads). Validation + §6.9.2 delta now live in applyPeerSettings. 需同步 feat/nc-kernel.
            if let code = Self.settingsFrameError(flags: flags, streamID: streamID, payload: payload) {
                connectionError(code, into: &result)
                return
            }
            if flags & 0x1 != 0 { return } // ACK of ours
            var newWindow = streamSendWindow
            let error = Self.applyPeerSettings(payload, initialWindow: &peerInitialWindow,
                                               maxFrame: &peerMaxFrame) { delta in
                newWindow += delta
                return newWindow <= NCH2ClientCore.maxWindow
            }
            if let error {
                connectionError(error, into: &result)
                return
            }
            streamSendWindow = newWindow
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
            // RFC 9113 §6.9.1: a window above 2^31-1 is a FLOW_CONTROL_ERROR (connection / stream).
            if streamID == 0 {
                guard connSendWindow + inc <= Self.maxWindow else {
                    connectionError(Self.errFlowControl, into: &result)
                    return
                }
                connSendWindow += inc
            } else if streamID == 1 {
                guard streamSendWindow + inc <= Self.maxWindow else {
                    if !streamClosed {
                        streamClosed = true
                        result.outbound.append(rstStream(code: Self.errFlowControl))
                        result.events.append(.reset)
                    }
                    return
                }
                streamSendWindow += inc
            }
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

    func rstStream(code: Int = 8) -> Data { // default CANCEL
        Self.frame(type: 0x3, flags: 0, streamID: 1, payload: be32(code))
    }

    // MARK: Peer SETTINGS (RFC 9113 §6.5.2) — shared with NCH2MuxCore. 需同步 feat/nc-kernel.

    static let maxWindow = 0x7fff_ffff
    static let errProtocol = 0x1, errFlowControl = 0x3, errFrameSize = 0x6

    /// Frame-level SETTINGS checks (§6.5): stream 0 only, ACK carries no payload, payload is n×6 bytes.
    static func settingsFrameError(flags: UInt8, streamID: Int, payload: Data) -> Int? {
        if streamID != 0 { return errProtocol }
        if flags & 0x1 != 0 { return payload.isEmpty ? nil : errFrameSize }
        return payload.count % 6 == 0 ? nil : errFrameSize
    }

    /// Apply a peer SETTINGS payload in order. Ids:
    /// - 0x1 HEADER_TABLE_SIZE: bounds the peer's decoder table for OUR encoder; NCHPACK never indexes
    ///   (static table + literal without indexing), so any value is fine and nothing changes.
    /// - 0x2 ENABLE_PUSH: only 0/1 are valid (PROTOCOL_ERROR otherwise); we never push.
    /// - 0x3 MAX_CONCURRENT_STREAMS: no effect on windows (the tunnel core uses one stream).
    /// - 0x4 INITIAL_WINDOW_SIZE: > 2^31-1 is FLOW_CONTROL_ERROR; the change (new - old) is handed to
    ///   `adjust` so the caller moves every open stream's send window by it (§6.9.2, may go negative);
    ///   `adjust` returns false when a window would exceed 2^31-1 (FLOW_CONTROL_ERROR).
    /// - 0x5 MAX_FRAME_SIZE: must be 16384...16777215 (PROTOCOL_ERROR otherwise).
    /// - 0x6 MAX_HEADER_LIST_SIZE and unknown ids: ignored (§6.5.2).
    /// Returns the connection error code, or nil.
    static func applyPeerSettings(_ payload: Data, initialWindow: inout Int, maxFrame: inout Int,
                                  adjust: (Int) -> Bool) -> Int? {
        var i = payload.startIndex
        while i + 6 <= payload.endIndex {
            let id = Int(payload[i]) << 8 | Int(payload[i + 1])
            let value = Int(payload[i + 2]) << 24 | Int(payload[i + 3]) << 16 | Int(payload[i + 4]) << 8 | Int(payload[i + 5])
            switch id {
            case 0x2:
                if value > 1 { return errProtocol }
            case 0x4:
                guard value <= maxWindow else { return errFlowControl }
                let delta = value - initialWindow
                initialWindow = value
                if delta != 0 && !adjust(delta) { return errFlowControl }
            case 0x5:
                guard value >= 16384 && value <= 16_777_215 else { return errProtocol }
                maxFrame = value
            default:
                break
            }
            i += 6
        }
        return nil
    }

    static func goaway(lastStreamID: Int, code: Int) -> Data {
        var p = Data()
        p.append(UInt8((lastStreamID >> 24) & 0x7f)); p.append(UInt8((lastStreamID >> 16) & 0xff))
        p.append(UInt8((lastStreamID >> 8) & 0xff)); p.append(UInt8(lastStreamID & 0xff))
        p.append(UInt8((code >> 24) & 0xff)); p.append(UInt8((code >> 16) & 0xff))
        p.append(UInt8((code >> 8) & 0xff)); p.append(UInt8(code & 0xff))
        return frame(type: 0x7, flags: 0, streamID: 0, payload: p)
    }

    /// Connection error (§5.4.1): GOAWAY with the code, the stream ends (.reset → the glue fails the
    /// tunnel), and every later byte is dropped.
    private func connectionError(_ code: Int, into result: inout FeedResult) {
        guard !connectionFailed else { return }
        connectionFailed = true
        result.outbound.append(Self.goaway(lastStreamID: 0, code: code))
        if !streamClosed {
            streamClosed = true
            result.events.append(.reset)
        }
        headerBlock = nil
    }

    private func be32(_ v: Int) -> Data {
        Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }
}
