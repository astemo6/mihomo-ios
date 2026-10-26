import Foundation

/// Minimal WebSocket client (RFC 6455) over an NCStream, carrying a byte
/// stream in binary messages — the v2ray/mihomo "ws" transport for VMess and
/// VLESS. Client frames are masked as required; server messages are
/// reassembled across fragmentation and surfaced as stream bytes.
final class NCWebSocketStream: NCRelayStream {
    private let raw: NCRelayStream
    private let hostHeader: String
    private let path: String
    private let extraHeaders: [String: String]
    private var handshakeDone = false
    private var buffer = Data()
    private var fragmentBuffer = Data()
    private var closed = false

    /// nc-memory: wire-declared frame lengths and fragmented messages are peer-controlled;
    /// without caps a peer can declare a 2^63 frame or fragment forever and pin the receive
    /// buffer for the connection's life. 1 MB is far above any ws-transport chunk in practice.
    static let maxFrameLength = 1024 * 1024
    static let maxMessageLength = 1024 * 1024

    init(raw: NCRelayStream, hostHeader: String, path: String, headers: [String: String]) {
        self.raw = raw
        self.hostHeader = hostHeader
        self.path = path.hasPrefix("/") ? path : "/" + path
        // fix/nc-e2e-real (E2E 40278215218: every direct xray ws node "ws upgrade refused"): ws-opts.headers usually
        // carries Host too, and it was sent as a second Host header after the one above — Go's net/http (xray /
        // v2ray ws servers) answers 400 Bad Request to that; Cloudflare-fronted nodes tolerated it. Host is sent once.
        self.extraHeaders = headers.filter { $0.key.caseInsensitiveCompare("Host") != .orderedSame }
    }

    /// Run the HTTP upgrade; completion fires once the 101 response's headers
    /// are consumed (any bytes after them are frame data, kept internally).
    func startHandshake(completion: @escaping (Error?) -> Void) {
        var keyBytes = Data()
        for _ in 0..<16 { keyBytes.append(UInt8.random(in: 0...255)) }
        let key = keyBytes.base64EncodedString()
        var req = "GET \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n"
        for (k, v) in extraHeaders { req += "\(k): \(v)\r\n" }
        req += "\r\n"
        raw.send(Data(req.utf8))
        var head = Data()
        func pump() {
            raw.receive { [weak self] data, error in
                guard let self else { completion(error); return }
                guard let data else {
                    completion(error ?? NCConnector.Failure.handshake("ws upgrade"))
                    return
                }
                head.append(data)
                if let end = head.range(of: Data("\r\n\r\n".utf8)) {
                    let headText = String(decoding: head[head.startIndex..<end.lowerBound], as: UTF8.self)
                    let status = headText.components(separatedBy: "\r\n").first ?? ""
                    guard status.contains(" 101") else {
                        completion(NCConnector.Failure.handshake("ws upgrade refused: " + String(status.prefix(64))))
                        return
                    }
                    self.buffer = Data(head[end.upperBound...])
                    self.handshakeDone = true
                    completion(nil)
                    return
                }
                if head.count > 16384 {
                    completion(NCConnector.Failure.handshake("ws upgrade overflow"))
                    return
                }
                pump()
            }
        }
        pump()
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        guard handshakeDone, !closed else { completion(); return }
        raw.send(Self.frame(opcode: 0x2, payload: data), completion: completion)
    }

    private static func frame(opcode: UInt8, payload: Data) -> Data {
        var out = Data()
        out.append(0x80 | opcode)
        var maskKey = Data()
        for _ in 0..<4 { maskKey.append(UInt8.random(in: 0...255)) }
        let len = payload.count
        if len < 126 {
            out.append(0x80 | UInt8(len))
        } else if len <= 0xffff {
            out.append(0x80 | 126)
            out.appendBE16(UInt16(len))
        } else {
            out.append(0x80 | 127)
            out.appendBE64(UInt64(len))
        }
        out.append(maskKey)
        var masked = Data()
        masked.reserveCapacity(len)
        for (idx, byte) in payload.enumerated() {
            masked.append(byte ^ maskKey[idx % 4])
        }
        out.append(masked)
        return out
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if let message = nextMessage() {
            handler(message, nil)
            return
        }
        if closed {
            handler(nil, nil)
            return
        }
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else {
                self.closed = true
                handler(nil, error)
                return
            }
            self.buffer.append(data)
            if let message = self.nextMessage() {
                handler(message, nil)
            } else if self.closed {
                handler(nil, nil)
            } else {
                self.receive(handler)
            }
        }
    }

    /// Pop one complete message's payload from the frame buffer, answering
    /// pings and noting closes along the way. Returns nil if incomplete.
    private func nextMessage() -> Data? {
        while true {
            guard buffer.count >= 2 else { return nil }
            let fin = buffer[0] & 0x80 != 0
            let opcode = buffer[0] & 0x0f
            let masked = buffer[1] & 0x80 != 0
            var len = Int(buffer[1] & 0x7f)
            var offset = 2
            if len == 126 {
                guard buffer.count >= 4 else { return nil }
                len = Int(buffer[2]) << 8 | Int(buffer[3])
                offset = 4
            } else if len == 127 {
                guard buffer.count >= 10 else { return nil }
                len = 0
                for k in 0..<8 { len = len << 8 | Int(buffer[2 + k]) }
                offset = 10
            }
            guard len <= Self.maxFrameLength else {
                // nc-memory: declared frame length over the cap — never satisfiable, close.
                closed = true
                raw.cancel()
                return nil
            }
            var maskKey: Data?
            if masked {
                guard buffer.count >= offset + 4 else { return nil }
                maskKey = Data(buffer[offset..<(offset + 4)])
                offset += 4
            }
            guard buffer.count >= offset + len else { return nil }
            var payload = Data(buffer[offset..<(offset + len)])
            if let maskKey {
                var unmasked = Data()
                for (idx, byte) in payload.enumerated() { unmasked.append(byte ^ maskKey[idx % 4]) }
                payload = unmasked
            }
            buffer = Data(buffer.dropFirst(offset + len))
            switch opcode {
            case 0x9: // ping -> pong
                raw.send(Self.frame(opcode: 0xA, payload: payload))
                continue
            case 0x8: // close
                closed = true
                return fragmentBuffer.isEmpty ? nil : fragmentBuffer
            case 0x0, 0x1, 0x2: // continuation / text / binary
                guard fragmentBuffer.count + payload.count <= Self.maxMessageLength else {
                    // nc-memory: fragmented message over the cap — close.
                    closed = true
                    raw.cancel()
                    return nil
                }
                fragmentBuffer.append(payload)
                if fin {
                    let message = fragmentBuffer
                    fragmentBuffer = Data()
                    return message
                }
                continue
            default:
                continue
            }
        }
    }

    func cancel() {
        closed = true
        raw.cancel()
    }
}

/// VLESS TCP relay: sends nothing itself (the connector sends the head), but
/// strips the 2+-byte VLESS response head (version + addon length + addons)
/// from the first inbound bytes before the stream becomes transparent.
final class NCVLESSRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private var headConsumed = false
    private var pending = Data()

    init(raw: NCRelayStream) {
        self.raw = raw
    }

    func send(_ data: Data) { raw.send(data) }

    func send(_ data: Data, completion: @escaping () -> Void) { raw.send(data, completion: completion) }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            if self.headConsumed {
                handler(data, nil)
                return
            }
            self.pending.append(data)
            if self.pending.count >= 2 {
                let addonLen = Int(self.pending[1])
                if self.pending.count >= 2 + addonLen {
                    let rest = Data(self.pending.dropFirst(2 + addonLen))
                    self.pending = Data()
                    self.headConsumed = true
                    if rest.isEmpty {
                        self.receive(handler)
                    } else {
                        handler(rest, nil)
                    }
                    return
                }
            }
            self.receive(handler)
        }
    }

    func cancel() { raw.cancel() }
}
