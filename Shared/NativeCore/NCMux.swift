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
        let s = data.startIndex
        let len = Int(data[s + 1]) << 8 | Int(data[s + 2])
        guard data.count >= 3 + len else { return nil }
        let msg = String(decoding: data[(s + 3)..<(s + 3 + len)], as: UTF8.self)
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
        let s = data.startIndex
        let len = Int(data[s + used]) << 8 | Int(data[s + used + 1])
        guard data.count >= used + 2 + len else { return nil }
        return (target, Data(data[(s + used + 2)..<(s + used + 2 + len)]), used + 2 + len)
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
    /// nc-memory: cap on streams with an unfinished header block (see the HEADERS branch).
    static let maxHeaderBlockStreams = 128

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

    /// Stream-level WINDOW_UPDATE for bytes the stream's consumer has taken (rv2-proto: receive windows are
    /// returned on consumption, so a slow reader caps its own buffer at the stream window instead of growing).
    func windowUpdate(streamID: Int, _ n: Int) -> Data {
        guard n > 0 else { return Data() }
        return NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: streamID, payload: be32(n))
    }

    /// Forget a closed stream's send window.
    func forgetStream(_ id: Int) {
        streamWindows[id] = nil
        headerBlocks[id] = nil
    }

    func endStream(_ id: Int) -> Data {
        NCH2ClientCore.frame(type: 0x0, flags: 0x1, streamID: id, payload: Data())
    }

    func rstStream(_ id: Int, code: Int = 8) -> Data { // default CANCEL
        NCH2ClientCore.frame(type: 0x3, flags: 0, streamID: id, payload: be32(code))
    }

    /// A connection error was sent (GOAWAY); nothing more is parsed.
    private(set) var connectionFailed = false

    /// Connection error (RFC 9113 §5.4.1): GOAWAY with the code, `.goaway` tears the session down.
    private func connectionError(_ code: Int, into result: inout FeedResult) {
        guard !connectionFailed else { return }
        connectionFailed = true
        result.outbound.append(NCH2ClientCore.goaway(lastStreamID: 0, code: code))
        result.events.append(.goaway)
        headerBlocks = [:]
    }

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
            guard len <= NCH2ClientCore.maxFrameSize else { // we never raise SETTINGS_MAX_FRAME_SIZE
                result.events.append(.goaway)
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

    private func handle(type: UInt8, flags: UInt8, streamID: Int, payload: Data, into result: inout FeedResult) {
        switch type {
        case 0x0: // DATA
            guard let body = NCH2ClientCore.unpad(payload, padded: flags & 0x8 != 0, priority: false) else {
                result.outbound.append(rstStream(streamID))
                result.events.append(.reset(streamID: streamID))
                return
            }
            if !payload.isEmpty {
                // Connection window: returned at once. Stream window: only the padding now; the body's share comes
                // back through windowUpdate(streamID:) when the stream's reader consumes it.
                result.outbound.append(NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: 0,
                                                            payload: be32(payload.count)))
                let padding = payload.count - body.count
                if padding > 0 {
                    result.outbound.append(NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: streamID,
                                                                payload: be32(padding)))
                }
            }
            if !body.isEmpty { result.events.append(.payload(streamID: streamID, body)) }
            if flags & 0x1 != 0 { result.events.append(.ended(streamID: streamID)) }
        case 0x1, 0x9: // HEADERS / CONTINUATION
            var block = headerBlocks[streamID] ?? Data()
            var frag = payload
            if type == 0x1 {
                guard let f = NCH2ClientCore.unpad(payload, padded: flags & 0x8 != 0, priority: flags & 0x20 != 0) else {
                    headerBlocks[streamID] = nil
                    result.outbound.append(rstStream(streamID))
                    result.events.append(.reset(streamID: streamID))
                    return
                }
                frag = f
            }
            // nc-memory: the per-stream block is capped (maxHeaderBlock) but the number of
            // streams with a block in flight was not; a peer opening endless HEADERS without
            // END_HEADERS pins one block per stream id.
            if headerBlocks[streamID] == nil, headerBlocks.count >= Self.maxHeaderBlockStreams {
                result.outbound.append(rstStream(streamID))
                result.events.append(.reset(streamID: streamID))
                return
            }
            guard block.count + frag.count <= NCH2ClientCore.maxHeaderBlock else {
                headerBlocks[streamID] = nil
                result.outbound.append(rstStream(streamID))
                result.events.append(.reset(streamID: streamID))
                return
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
            // fix/nc-h2-cidr: INITIAL_WINDOW_SIZE is id 0x4 (was 0x3 = MAX_CONCURRENT_STREAMS); validation and the
            // §6.9.2 per-stream delta are shared with NCH2ClientCore.applyPeerSettings. 需同步 feat/nc-kernel.
            if let code = NCH2ClientCore.settingsFrameError(flags: flags, streamID: streamID, payload: payload) {
                connectionError(code, into: &result)
                return
            }
            if flags & 0x1 == 0 {
                var windows = streamWindows
                let error = NCH2ClientCore.applyPeerSettings(payload, initialWindow: &peerInitialWindow,
                                                             maxFrame: &peerMaxFrame) { delta in
                    for k in windows.keys {
                        let w = windows[k, default: 0] + delta
                        guard w <= NCH2ClientCore.maxWindow else { return false }
                        windows[k] = w
                    }
                    return true
                }
                if let error {
                    connectionError(error, into: &result)
                    return
                }
                streamWindows = windows
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
            // RFC 9113 §6.9.1 overflow → FLOW_CONTROL_ERROR. A WINDOW_UPDATE for a stream we already forgot no
            // longer re-creates its window entry (fix/nc-h2-cidr).
            if streamID == 0 {
                guard connSendWindow + inc <= NCH2ClientCore.maxWindow else {
                    connectionError(NCH2ClientCore.errFlowControl, into: &result)
                    return
                }
                connSendWindow += inc
            } else if let w = streamWindows[streamID] {
                guard w + inc <= NCH2ClientCore.maxWindow else {
                    result.outbound.append(rstStream(streamID, code: NCH2ClientCore.errFlowControl))
                    result.events.append(.reset(streamID: streamID))
                    return
                }
                streamWindows[streamID] = w + inc
            }
            result.events.append(.windowIncreased)
        default:
            return
        }
    }

    private func be32(_ v: Int) -> Data {
        Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }
}
