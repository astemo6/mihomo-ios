import Foundation

/// Shadowsocks stream plugins (simple-obfs, v2ray-plugin).
///
/// Wire formats ported from Clash.Meta v1.19.33 — the old engine the bridge
/// exposes, i.e. the behavior a real server interops with — which itself
/// ports the reference implementations:
/// - adapter/outbound/shadowsocks  plugin-opts semantics and defaults
///   (obfs: mode/host, host defaults to "bing.com"; v2ray-plugin:
///   mode/host/path/tls/mux/headers/skip-cert-verify, mux defaults to true)
/// - transport/simple-obfs/http    http mode (first packet = fake HTTP
///   GET with WebSocket upgrade headers, first SS bytes as the body)
/// - transport/simple-obfs/tls     tls mode (fake TLS ClientHello, first
///   SS bytes in the session-ticket extension, later data in TLS
///   application-data records)
/// - transport/v2ray-plugin/websocket + mux   websocket transport and
///   the v2ray mux framing over it
/// - common/convert/converter      SIP002 `plugin=` link parsing
/// Reference C sources: shadowsocks/simple-obfs (obfs_http.c / obfs_tls.c)
/// and shadowsocks/v2ray-plugin.
///
/// Plugins wrap the WHOLE Shadowsocks stream — the SS request head included —
/// and apply to TCP only; UDP never goes through them (Clash.Meta parity).
enum NCSSPlugin {

    enum Kind { case obfs, v2rayPlugin }

    /// Decoded `plugin` + `plugin-opts` of an SS node.
    struct Options {
        let kind: Kind
        /// obfs: "http" | "tls". v2ray-plugin: "websocket".
        let mode: String
        /// Camouflage host (SNI / Host header). Clash.Meta default: "bing.com".
        let host: String
        /// v2ray-plugin websocket path ("" → "/").
        let path: String
        /// v2ray-plugin: TLS to the SS server itself (wss).
        let tls: Bool
        /// v2ray-plugin: mux framing over the transport (Clash.Meta default true).
        let mux: Bool
        /// v2ray-plugin http-upgrade transport: HTTP/1.1 Upgrade handshake, then a raw stream
        /// (no websocket framing). Set by `v2ray-http-upgrade: true` or `mode: http-upgrade`.
        let httpUpgrade: Bool
        /// `v2ray-http-upgrade-fast-open`: the transport is usable before the 101 arrives.
        let httpUpgradeFastOpen: Bool
        let skipCertVerify: Bool
        let headers: [String: String]

        /// Clash.Meta adapter/outbound/shadowsocks NewShadowSocks: the plugin
        /// name must be exact, and the opts shape decides support. nil =
        /// unsupported shape (the caller turns that into an explicit
        /// unsupported reason — never a silent passthrough).
        init?(pluginName: String, opts: [String: NCJSONValue]) {
            switch pluginName {
            case "obfs":
                let mode = opts["mode"]?.string ?? ""
                guard mode == "http" || mode == "tls" else { return nil }
                self.kind = .obfs
                self.mode = mode
                self.host = NCSSPlugin.defaultHost(opts["host"]?.string)
                self.path = ""
                self.tls = false
                self.mux = false
                self.httpUpgrade = false
                self.httpUpgradeFastOpen = false
                self.skipCertVerify = false
                self.headers = [:]
            case "v2ray-plugin":
                let mode = opts["mode"]?.string ?? ""
                guard mode.isEmpty || mode == "websocket" || mode == "http-upgrade" else { return nil }
                self.httpUpgrade = opts["v2ray-http-upgrade"]?.bool == true || mode == "http-upgrade"
                self.httpUpgradeFastOpen = opts["v2ray-http-upgrade-fast-open"]?.bool ?? false
                self.kind = .v2rayPlugin
                self.mode = httpUpgrade ? "http-upgrade" : "websocket"
                self.host = NCSSPlugin.defaultHost(opts["host"]?.string)
                self.path = opts["path"]?.string ?? ""
                self.tls = opts["tls"]?.bool ?? false
                // Clash.Meta presets Mux: true before decoding plugin-opts, so a
                // config without an explicit `mux` key muxes — mirror that.
                self.mux = opts["mux"]?.bool ?? true
                self.skipCertVerify = opts["skip-cert-verify"]?.bool ?? false
                var headers: [String: String] = [:]
                if let h = opts["headers"]?.object {
                    for (k, v) in h { if let s = v.string { headers[k] = s } }
                }
                self.headers = headers
            default:
                return nil
            }
        }
    }

    /// Clash.Meta presets Host: "bing.com" for both plugins.
    private static func defaultHost(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty else { return "bing.com" }
        return raw
    }

    // MARK: simple-obfs http mode

    /// First client packet: a fake WebSocket-upgrade GET whose body is the
    /// first SS bytes. Header order mirrors the old core's http.Request.Write as used
    /// by Clash.Meta's HTTPObfs.Write (Host, User-Agent, Content-Length, then the
    /// remaining headers sorted). The server (Clash.Meta http_server / the C
    /// simple-obfs server) parses it as a normal HTTP request and reads
    /// exactly Content-Length bytes as the first payload.
    static func obfsHTTPRequest(host: String, port: String, payload: Data) -> Data {
        var head = "GET / HTTP/1.1\r\n"
        // Clash.Meta: Host carries the server port unless it is 80.
        head += "Host: \(host)\(port == "80" ? "" : ":\(port)")\r\n"
        head += "User-Agent: curl/7.\(Int.random(in: 0..<54)).\(Int.random(in: 0..<2))\r\n"
        head += "Content-Length: \(payload.count)\r\n"
        head += "Connection: Upgrade\r\n"
        head += "Sec-WebSocket-Key: \(obfsBase64URL(obfsRandom(16)))\r\n"
        head += "Upgrade: websocket\r\n"
        head += "\r\n"
        return Data(head.utf8) + payload
    }

    /// The server's fake "101 Switching Protocols" camouflage header.
    private static let httpHeaderTerminator = Data("\r\n\r\n".utf8)

    /// Strip the obfs-http camouflage header from the start of the response.
    /// The C client scans for the first \r\n\r\n (obfs_http.c
    /// deobfs_http_header); Clash.Meta's port requires it inside the first read
    /// — buffering across reads is strictly more tolerant and changes no
    /// byte on the wire.
    struct HTTPResponseStripper {
        private var buffer = Data()
        private(set) var failed = false
        private let cap = 16 * 1024

        /// Feed wire bytes; returns nil on overflow (check `failed`),
        /// empty Data while still incomplete, else the plaintext remainder.
        mutating func feed(_ data: Data) -> Data? {
            if failed { return nil }
            buffer.append(data)
            guard let range = buffer.range(of: NCSSPlugin.httpHeaderTerminator) else {
                if buffer.count > cap { failed = true; return nil }
                return Data()
            }
            let rest = Data(buffer[range.upperBound...])
            buffer = Data()
            return rest
        }
    }

    // MARK: simple-obfs tls mode

    /// First client packet: a fake TLS 1.2 ClientHello. Layout per Clash.Meta
    /// transport/simple-obfs/tls makeClientHelloMsg (itself a port of
    /// simple-obfs obfs_tls.c): fixed random/session-id/cipher-suite blocks,
    /// the first SS bytes as the session-ticket extension (0x0023) body,
    /// the camouflage host as SNI (0x0000), then the fixed extension set
    /// (ec_point_formats / supported_groups / signature_algorithms /
    /// encrypt_then_mac / extended_master_secret).
    static func obfsTLSClientHello(host: String, payload: Data) -> Data {
        // obfs-host comes from the config: u16 length fields below (UInt16(count + 5) trapped past ~64 KB). A DNS
        // name is ≤ 253 bytes; anything longer is cut to 255 so the hello stays well-formed.
        let hostBytes = Data(host.utf8.prefix(255))
        // Record: 5-byte header + 4-byte handshake header + 208 fixed bytes
        // of ClientHello body + extensions (79 + payload + host).
        var hello = Data()
        hello.append(0x16)                       // content type: handshake
        hello.append(0x03); hello.append(0x01)   // record version TLS 1.0
        hello.append(0x00); hello.append(0x00)   // record length (patched)
        hello.append(0x01)                       // handshake: ClientHello
        hello.append(0x00); hello.append(0x00); hello.append(0x00) // hs len (patched)
        hello.append(0x03); hello.append(0x03)   // client version TLS 1.2
        hello.appendBE32(UInt32(Date().timeIntervalSince1970))
        hello.append(obfsRandom(28))             // random (after unix time)
        hello.append(0x20)                       // session id len
        hello.append(obfsRandom(32))             // session id
        hello.append(0x00); hello.append(0x38)   // cipher suites len (56)
        hello.append(contentsOf: [
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
            0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
            0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
            0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
        ])
        hello.append(0x01); hello.append(0x00)   // compression: null
        let extLen = 79 + payload.count + hostBytes.count
        hello.appendBE16(UInt16(extLen))
        // Extension: session_ticket (0x0023) — body IS the first SS bytes.
        hello.append(0x00); hello.append(0x23)
        hello.appendBE16(UInt16(payload.count))
        hello.append(payload)
        // Extension: server_name (0x0000) — host_name type 0.
        hello.append(0x00); hello.append(0x00)
        hello.appendBE16(UInt16(hostBytes.count + 5))
        hello.appendBE16(UInt16(hostBytes.count + 3))
        hello.append(0x00)
        hello.appendBE16(UInt16(hostBytes.count))
        hello.append(hostBytes)
        // Extension: ec_point_formats (0x000b).
        hello.append(contentsOf: [0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02])
        // Extension: supported_groups (0x000a).
        hello.append(contentsOf: [0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18])
        // Extension: signature_algorithms (0x000d).
        hello.append(contentsOf: [
            0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
            0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
            0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
        ])
        // Extensions: encrypt_then_mac (0x0016), extended_master_secret (0x0017).
        hello.append(contentsOf: [0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00])
        // Patch the two length fields (handshake length is 3 bytes: pad + BE16).
        let recordLen = hello.count - 5
        hello[3] = UInt8((recordLen >> 8) & 0xff)
        hello[4] = UInt8(recordLen & 0xff)
        let hsLen = hello.count - 9
        hello[6] = 0x00
        hello[7] = UInt8((hsLen >> 8) & 0xff)
        hello[8] = UInt8(hsLen & 0xff)
        return hello
    }

    /// Later writes: TLS application-data records (17 03 03), each payload
    /// chunked at 16 KiB like Clash.Meta's TLSObfs.Write.
    static func obfsTLSAppDataRecords(_ payload: Data) -> [Data] {
        var out: [Data] = []
        var idx = payload.startIndex
        while idx < payload.endIndex {
            let end = payload.index(idx, offsetBy: obfsTLSMaxRecord, limitedBy: payload.endIndex) ?? payload.endIndex
            var rec = Data([0x17, 0x03, 0x03])
            rec.appendBE16(UInt16(clamping: end - idx))
            rec.append(payload[idx..<end])
            out.append(rec)
            idx = end
        }
        return out
    }

    static let obfsTLSMaxRecord = 1 << 14 // 16 KiB, Clash.Meta chunkSize

    /// Server reply parser for obfs tls mode — Clash.Meta TLSObfs.Read: the
    /// fake ServerHello record (96) + ChangeCipherSpec (6) + the first 3
    /// bytes of the encrypted-handshake record are discarded (105 total),
    /// then the stream is a sequence of records framed
    /// [len u16 BE][payload] where every record after the first restarts
    /// with its 3-byte type+version (i.e. discard 3, read len, read body).
    struct TLSResponseParser {
        private var buffer = Data()
        private enum Step { case firstDiscard, recordLen, recordHeader, recordBody }
        private var step = Step.firstDiscard
        private var pendingLen = 0
        private(set) var failed = false
        private let cap = 128 * 1024

        /// Feed wire bytes; nil = protocol error (see `failed`), empty Data
        /// = need more bytes, otherwise the plaintext became available.
        mutating func feed(_ data: Data) -> Data? {
            if failed { return nil }
            buffer.append(data)
            var out = Data()
            while true {
                switch step {
                case .firstDiscard:
                    guard buffer.count >= 105 else { return finish(&out) }
                    buffer = Data(buffer.dropFirst(105))
                    step = .recordLen
                case .recordLen:
                    guard buffer.count >= 2 else { return finish(&out) }
                    pendingLen = Int(buffer[0]) << 8 | Int(buffer[1])
                    buffer = Data(buffer.dropFirst(2))
                    step = pendingLen == 0 ? .recordHeader : .recordBody
                case .recordHeader:
                    guard buffer.count >= 3 else { return finish(&out) }
                    buffer = Data(buffer.dropFirst(3))
                    step = .recordLen
                case .recordBody:
                    guard buffer.count >= pendingLen else { return finish(&out) }
                    out.append(buffer.prefix(pendingLen))
                    buffer = Data(buffer.dropFirst(pendingLen))
                    step = .recordHeader
                }
            }
        }

        private mutating func finish(_ out: inout Data) -> Data? {
            if buffer.count > cap { failed = true; return nil }
            return out
        }
    }

    // MARK: v2ray-plugin mux framing

    /// v2ray-plugin mux framing over the websocket — Clash.Meta
    /// transport/v2ray-plugin/mux ("an mux-compatible client for
    /// v2ray-plugin"): every frame is [metalen u16][id u16][status][option],
    /// data frames add [len u16][payload]. The session create frame carries
    /// a dummy destination (Clash.Meta uses 127.0.0.1:0) — the real target
    /// travels in the SS request head inside the stream.
    enum V2RayMux {
        static let sessionStatusNew: UInt8 = 0x01
        static let sessionStatusKeep: UInt8 = 0x02
        static let sessionStatusEnd: UInt8 = 0x03
        static let sessionStatusKeepAlive: UInt8 = 0x04
        static let optionNone: UInt8 = 0x00
        static let optionData: UInt8 = 0x01

        /// Clash.Meta hard-codes the session id to {0, 0}.
        static let sessionID: (UInt8, UInt8) = (0, 0)

        static func createFrame() -> Data {
            var f = Data()
            f.append(0x00); f.append(0x0c) // metalen: 12 bytes follow
            f.append(sessionID.0); f.append(sessionID.1)
            f.append(sessionStatusNew)
            f.append(optionNone)
            f.append(0x01)                 // tcp
            f.append(0x00); f.append(0x00) // port 0
            f.append(0x01)                 // atyp ipv4
            f.append(contentsOf: [127, 0, 0, 1])
            return f
        }

        static func dataFrame(payload: Data) -> Data {
            var f = Data()
            f.append(0x00); f.append(0x04) // metalen: id+status+option
            f.append(sessionID.0); f.append(sessionID.1)
            f.append(sessionStatusKeep)
            f.append(optionData)
            f.appendBE16(UInt16(clamping: payload.count))
            f.append(payload)
            return f
        }

        static func endFrame() -> Data {
            return Data([0x00, 0x04, sessionID.0, sessionID.1, sessionStatusEnd, optionNone])
        }

        /// Inbound parser: delivers concatenated DATA payloads, skipping
        /// keepalive and non-data frames (Clash.Meta Mux.Read semantics).
        struct Parser {
            private var buffer = Data()
            private var pendingLen: Int?
            private(set) var failed = false
            private let cap = 128 * 1024

            mutating func feed(_ data: Data) -> Data? {
                if failed { return nil }
                buffer.append(data)
                var out = Data()
                while true {
                    if pendingLen == nil {
                        guard buffer.count >= 6 else { return finish(&out) }
                        let metalen = Int(buffer[0]) << 8 | Int(buffer[1])
                        if metalen > 512 { failed = true; return nil } // Clash.Meta: "invalid metalen"
                        let status = buffer[4]
                        let opt = buffer[5]
                        buffer = Data(buffer.dropFirst(6))
                        if status == V2RayMux.sessionStatusKeepAlive { continue }
                        if opt != V2RayMux.optionData { continue }
                        guard buffer.count >= 2 else { return finish(&out) }
                        let len = Int(buffer[0]) << 8 | Int(buffer[1])
                        buffer = Data(buffer.dropFirst(2))
                        pendingLen = len
                    }
                    guard let len = pendingLen, buffer.count >= len else { return finish(&out) }
                    out.append(buffer.prefix(len))
                    buffer = Data(buffer.dropFirst(len))
                    pendingLen = nil
                }
            }

            private mutating func finish(_ out: inout Data) -> Data? {
                if buffer.count > cap { failed = true; return nil }
                return out
            }
        }
    }

    // MARK: helpers

    private static func obfsRandom(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    /// base64 URL alphabet (Clash.Meta uses base64.URLEncoding for the obfs-http
    /// Sec-WebSocket-Key; padding kept, as URLEncoding does).
    private static func obfsBase64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

/// feat/nc-integrate: #101 (astemo6) refers to the options type as NCSSPluginOptions in the connector, the plugin
/// stream and NCSupport; the type lives at NCSSPlugin.Options.
typealias NCSSPluginOptions = NCSSPlugin.Options
