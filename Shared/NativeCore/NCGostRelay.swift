import Foundation

// MARK: - GOST v3 relay protocol (feat/nc-gost-relay)

/// The GOST v3 `relay` protocol as mihomo v1.19.33 speaks it (transport/gost/relay.go; adapter type
/// `gost-relay`, NOT the `relay` proxy-group, which is the chain group in NCSupport.groupTypes).
///
/// Request:  VER(0x01) ‖ CMD ‖ LEN(BE16) ‖ features…
///           CMD = CONNECT(0x01), | 0x80 for UDP.
///           feature = TYPE ‖ LEN(BE16) ‖ payload:
///             0x01 user-auth  ULEN ‖ user ‖ PLEN ‖ pass      (only when either is non-empty)
///             0x02 addr       ATYP(1 v4 / 3 domain / 4 v6) ‖ addr ‖ PORT(BE16)   (omitted in forward mode)
///             0x04 network    BE16 (0 = tcp, 1 = udp)        (always present)
/// Response: VER ‖ STATUS ‖ LEN(BE16) ‖ features (skipped). STATUS 0 = OK.
/// UDP over the stream: each datagram is LEN(BE16) ‖ payload; the association is bound to one target.
///
/// Pure wire helpers here are unit-tested against vectors produced by mihomo's own writeRelayRequest
/// (UnitTests/NativeCoreGostRelayTests.swift).
enum NCGostRelay {
    static let version: UInt8 = 0x01
    static let cmdConnect: UInt8 = 0x01
    static let flagUDP: UInt8 = 0x80

    static let featureUserAuth: UInt8 = 0x01
    static let featureAddr: UInt8 = 0x02
    static let featureNetwork: UInt8 = 0x04

    static let networkTCP: UInt16 = 0x0000
    static let networkUDP: UInt16 = 0x0001

    /// Largest response we will buffer while waiting for the header + its feature block (4 + u16 max).
    static let maxResponseHead = 4 + 0xFFFF

    /// The request header. `target == nil` is mihomo's `forward: true` (no addr feature: the server's
    /// own forward target is used). nil when a credential exceeds 255 bytes or the target cannot be encoded.
    static func request(target: NCTarget?, udp: Bool, username: String?, password: String?) -> Data? {
        var features = Data()
        let user = Array((username ?? "").utf8)
        let pass = Array((password ?? "").utf8)
        if !user.isEmpty || !pass.isEmpty {
            guard user.count <= 0xFF, pass.count <= 0xFF else { return nil }
            var auth = Data(capacity: 2 + user.count + pass.count)
            auth.append(UInt8(user.count))
            auth.append(contentsOf: user)
            auth.append(UInt8(pass.count))
            auth.append(contentsOf: pass)
            appendFeature(&features, featureUserAuth, auth)
        }
        if let target {
            guard target.isWireEncodable else { return nil }
            appendFeature(&features, featureAddr, target.atypEncoded)
        }
        let network = udp ? networkUDP : networkTCP
        appendFeature(&features, featureNetwork, Data([UInt8(network >> 8), UInt8(network & 0xFF)]))
        // auth ≤ 3+512, addr ≤ 3+259, network 5: always far below the u16 limit.
        var out = Data(capacity: 4 + features.count)
        out.append(version)
        out.append(udp ? (cmdConnect | flagUDP) : cmdConnect)
        out.append(UInt8((features.count >> 8) & 0xFF))
        out.append(UInt8(features.count & 0xFF))
        out.append(features)
        return out
    }

    private static func appendFeature(_ out: inout Data, _ type: UInt8, _ payload: Data) {
        out.append(type)
        out.append(UInt8((payload.count >> 8) & 0xFF))
        out.append(UInt8(payload.count & 0xFF))
        out.append(payload)
    }

    enum Response: Equatable {
        case needMore
        /// Header + feature block fully present; `consumed` bytes belong to it.
        case ok(consumed: Int)
        case failed(status: UInt8)
        case badVersion(UInt8)
    }

    /// Parse the response head at the start of `data` (startIndex-relative: slices are fine).
    /// mihomo readRelayConnectResponse: version checked first, then status, then the features skipped.
    static func parseResponse(_ data: Data) -> Response {
        guard data.count >= 4 else { return .needMore }
        let s = data.startIndex
        guard data[s] == version else { return .badVersion(data[s]) }
        guard data[s + 1] == 0x00 else { return .failed(status: data[s + 1]) }
        let featureLen = Int(data[s + 2]) << 8 | Int(data[s + 3])
        guard data.count >= 4 + featureLen else { return .needMore }
        return .ok(consumed: 4 + featureLen)
    }

    static func statusText(_ status: UInt8) -> String {
        switch status {
        case 0x00: return "ok"
        case 0x01: return "bad request"
        case 0x02: return "unauthorized"
        case 0x03: return "forbidden"
        case 0x04: return "timeout"
        case 0x05: return "service unavailable"
        case 0x06: return "host unreachable"
        case 0x07: return "network unreachable"
        case 0x08: return "internal server error"
        default: return "unknown"
        }
    }

    /// One UDP datagram on the relay stream; nil when it does not fit the u16 length.
    static func udpFrame(_ payload: Data) -> Data? {
        guard payload.count <= 0xFFFF else { return nil }
        var out = Data(capacity: 2 + payload.count)
        out.append(UInt8(payload.count >> 8))
        out.append(UInt8(payload.count & 0xFF))
        out.append(payload)
        return out
    }

    /// Next datagram in `buffer` starting at absolute offset `off`: (payload, bytes consumed) or nil if incomplete.
    static func nextUDPFrame(_ buffer: Data, at off: Int) -> (Data, Int)? {
        let base = buffer.startIndex + off
        guard buffer.endIndex - base >= 2 else { return nil }
        let len = Int(buffer[base]) << 8 | Int(buffer[base + 1])
        guard buffer.endIndex - base >= 2 + len else { return nil }
        return (Data(buffer[(base + 2)..<(base + 2 + len)]), 2 + len)
    }

    // MARK: Options (mihomo GostRelayOption + ws extension)

    /// The node's options, read once per dial. Field names are mihomo's (`gost-relay`):
    /// server, port, forward, udp, tls, mux, sni, username, password, skip-cert-verify, name-cert-verify,
    /// fingerprint, certificate, private-key, client-fingerprint. Tern extension (gost `relay+ws` /
    /// `relay+wss`, which mihomo's adapter lacks): `network: ws` + `ws-opts {path, headers}`.
    struct Options {
        var server: String
        var port: Int
        var forward: Bool
        var tls: Bool
        var mux: Bool
        var sni: String?
        var username: String?
        var password: String?
        var skipCertVerify: Bool
        var nameCertVerify: String?
        var pinnedSHA256: Data?
        var clientFingerprint: String?
        var ws: (path: String, headers: [String: String])?

        /// The TLS server name: sni, else (ws) the Host header, else the server (mihomo serverName()).
        var serverName: String {
            if let sni, !sni.isEmpty { return sni }
            if let host = ws?.headers.first(where: { $0.key.lowercased() == "host" })?.value, !host.isEmpty { return host }
            return server
        }

        /// The hand-rolled TLS client is needed for what NWConnection's TLS cannot do here: certificate
        /// pinning, a verify name different from the SNI, a ClientHello fingerprint.
        var needsCustomTLS: Bool {
            pinnedSHA256 != nil || !(nameCertVerify ?? "").isEmpty || !(clientFingerprint ?? "").isEmpty
        }
    }

    /// nil + reason when the node cannot be dialed (same gate NCSupport reports).
    static func options(_ proxy: NCProxy) -> (Options?, String?) {
        let f = proxy.fields
        guard let server = proxy.server, !server.isEmpty, let port = proxy.port, port > 0 else {
            return (nil, "GOST Relay 缺少 server / port")
        }
        let network = (f["network"]?.string ?? "tcp").lowercased()
        guard network.isEmpty || network == "tcp" || network == "ws" else {
            return (nil, "GOST Relay 传输 \(network) 尚未接入（支持 tcp / ws）")
        }
        let username = f["username"]?.string
        let password = proxy.password
        if (username?.utf8.count ?? 0) > 0xFF || (password?.utf8.count ?? 0) > 0xFF {
            return (nil, "GOST Relay 用户名或密码超过 255 字节")
        }
        if !(f["certificate"]?.string ?? "").isEmpty || !(f["private-key"]?.string ?? "").isEmpty {
            return (nil, "GOST Relay 客户端证书（certificate / private-key）尚未接入")
        }
        var pin: Data?
        if let fp = f["fingerprint"]?.string, !fp.isEmpty {
            let hex = fp.replacingOccurrences(of: ":", with: "").trimmingCharacters(in: .whitespaces)
            guard hex.count == 64, let bytes = hexBytes(hex) else {
                return (nil, "GOST Relay fingerprint 需为 SHA-256 证书指纹")
            }
            pin = bytes
        }
        var ws: (path: String, headers: [String: String])?
        if network == "ws" {
            let o = f["ws-opts"]?.object
            var headers: [String: String] = [:]
            for (k, v) in o?["headers"]?.object ?? [:] { if let s = v.string { headers[k] = s } }
            ws = (path: o?["path"]?.string ?? "/", headers: headers)
        }
        let sni = f["sni"]?.string ?? f["servername"]?.string
        return (Options(server: server, port: port,
                        forward: f["forward"]?.bool ?? false,
                        tls: f["tls"]?.bool ?? false,
                        mux: f["mux"]?.bool ?? false,
                        sni: sni,
                        username: username, password: password,
                        skipCertVerify: f["skip-cert-verify"]?.bool ?? false,
                        nameCertVerify: f["name-cert-verify"]?.string,
                        pinnedSHA256: pin,
                        clientFingerprint: f["client-fingerprint"]?.string,
                        ws: ws), nil)
    }

    static func hexBytes(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}

// MARK: - Relay stream

/// The relay connection after the request was written: strips the response head (failing the stream on a
/// non-OK status / bad version) and passes everything after it through. The request is sent up front
/// (gost `nodelay=true`) so server-first protocols work; the response is checked lazily on the first
/// read instead of costing a round trip before the flow starts (Surge/Trojan-style 0-RTT open).
final class NCGostRelayStream: NCFramedRelay {
    private var responded = false

    override func consume() throws -> [Data] {
        if !responded {
            switch NCGostRelay.parseResponse(inbuf) {
            case .needMore:
                if inbuf.count > NCGostRelay.maxResponseHead { throw Self.err("gost relay: oversized response") }
                return []
            case .ok(let n):
                responded = true
                inbuf = n >= inbuf.count ? Data() : Data(inbuf.dropFirst(n))
            case .failed(let status):
                let hex = (status < 0x10 ? "0" : "") + String(status, radix: 16)
                let text = NCGostRelay.statusText(status)
                throw Self.err("gost relay connect failed with status 0x\(hex) (\(text))")
            case .badVersion(let v):
                throw Self.err("gost relay bad version: \(v)")
            }
        }
        if inbuf.isEmpty { return [] }
        let d = inbuf
        inbuf = Data()
        return [d]
    }
}

// MARK: - Connector glue

extension NCConnector {
    /// Dial a `gost-relay` node toward `target` (TCP) or bind a UDP association to it (`udp: true`):
    /// socket (or chain transport) → TLS (system TLS; the hand-rolled client when pinning / name-cert-verify /
    /// client-fingerprint or a chain transport needs it) → websocket (network: ws) → smux v1 single stream
    /// (mux: true, mihomo: one session per connection, keep-alive off) → relay request.
    /// Completion fires exactly once.
    static func gostRelayStream(proxy: NCProxy, target: NCTarget, udp: Bool, queue: DispatchQueue,
                                transport: NCRelayStream?,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let (optsOrNil, why) = NCGostRelay.options(proxy)
        guard let o = optsOrNil else {
            queue.async { completion(nil, Failure.unsupported(why ?? "gost-relay")) }
            return
        }
        guard let head = NCGostRelay.request(target: o.forward ? nil : target, udp: udp,
                                             username: o.username, password: o.password) else {
            queue.async { completion(nil, Failure.handshake("gost relay: request cannot be encoded")) }
            return
        }
        func finish(_ base: NCRelayStream) {
            var pipe = base
            if o.mux {
                let m = NCGostSmuxStream(raw: base)
                m.open()
                pipe = m
            }
            pipe.send(head)
            completion(NCGostRelayStream(raw: pipe), nil)
        }
        func plainRaw(_ done: @escaping (NCRelayStream?, Error?) -> Void) {
            if let transport { done(transport, nil); return }
            let s = NCStream(to: o.server, port: o.port, queue: queue)
            s.start { err in done(err == nil ? s : nil, err) }
        }
        func overWS(_ base: NCRelayStream) {
            guard let ws = o.ws else { finish(base); return }
            let hostHeader = ws.headers.first(where: { $0.key.lowercased() == "host" })?.value
                ?? (o.sni.flatMap { $0.isEmpty ? nil : $0 } ?? o.server)
            let stream = NCWebSocketStream(raw: base, hostHeader: hostHeader, path: ws.path.isEmpty ? "/" : ws.path,
                                           headers: ws.headers.filter { $0.key.lowercased() != "host" })
            stream.startHandshake { err in
                if let err { stream.cancel(); completion(nil, err) } else { finish(stream) }
            }
        }
        if !o.tls {
            plainRaw { raw, err in
                guard let raw else { completion(nil, err); return }
                overWS(raw)
            }
            return
        }
        if transport == nil && !o.needsCustomTLS {
            // Common case: system TLS on the NWConnection (no extra Swift record layer in memory).
            let s = NCStream(to: o.server, port: o.port, tlsServerName: o.serverName,
                             allowInsecure: o.skipCertVerify, queue: queue)
            s.start { err in
                if let err { completion(nil, err) } else { overWS(s) }
            }
            return
        }
        plainRaw { raw, err in
            guard let raw else { completion(nil, err); return }
            var cfg = NCTLSClientStream.Config(serverName: o.serverName)
            cfg.alpn = ["http/1.1"]
            cfg.allowInsecure = o.skipCertVerify
            cfg.pinnedCertSHA256 = o.pinnedSHA256
            if let ncv = o.nameCertVerify, !ncv.isEmpty { cfg.certVerifyName = ncv }
            cfg.profile = NCClientHelloProfile.named(o.clientFingerprint)
            let t = NCTLSClientStream(raw: raw, config: cfg, queue: queue)
            t.startHandshake { err in
                if let err { t.cancel(); completion(nil, err) } else { overWS(t) }
            }
        }
    }
}

// MARK: - Import (share links / conf lines)

extension NCGostRelay {
    /// gost URL scheme modifiers: relay+tls / +mtls / +ws / +mws / +wss / +mwss (gost v2/v3 transports).
    /// Returns (tls, ws, mux) or nil for a transport this client does not speak (kcp, quic, h2, …).
    static func schemeTransport(_ scheme: String) -> (tls: Bool, ws: Bool, mux: Bool)? {
        let parts = scheme.lowercased().split(separator: "+", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return (false, false, false) }
        switch parts[1] {
        case "tcp", "": return (false, false, false)
        case "tls": return (true, false, false)
        case "mtls": return (true, false, true)
        case "ws": return (false, true, false)
        case "mws": return (false, true, true)
        case "wss": return (true, true, false)
        case "mwss": return (true, true, true)
        default: return nil
        }
    }

    /// Map Shadowrocket- / gost-style parameters (keys lower-cased) onto mihomo `gost-relay` fields.
    /// Shadowrocket spells SNI `peer`, skip-verify `allowInsecure`, the ws transport `obfs=websocket`
    /// with the Host in `obfsParam`, and the uTLS profile `fingerprint` (a 64-hex value is a cert pin).
    /// Returns the keys it consumed.
    @discardableResult
    static func applyParams(_ q: [String: String], into f: inout [String: NCJSONValue]) -> Set<String> {
        var used: Set<String> = []
        func take(_ keys: String...) -> String? {
            for k in keys { if let v = q[k] { used.insert(k); return v } }
            return nil
        }
        func flag(_ v: String?) -> Bool? { NCConfImport.boolValue(v) }
        if let u = take("username", "user"), !u.isEmpty { f["username"] = .string(u) }
        if let p = take("password", "pass"), !p.isEmpty { f["password"] = .string(p) }
        if let b = flag(take("tls", "over-tls")) { f["tls"] = .bool(b) }
        if let s = take("peer", "sni", "servername", "tls-name", "tls-host"), !s.isEmpty { f["sni"] = .string(s) }
        if let b = flag(take("allowinsecure", "insecure", "skip-cert-verify")) { f["skip-cert-verify"] = .bool(b) }
        if let b = flag(take("mux", "smux")) { f["mux"] = .bool(b) }
        if let b = flag(take("udp", "udp-relay")) { f["udp"] = .bool(b) }
        if let b = flag(take("forward")) { f["forward"] = .bool(b) }
        if let t = take("obfs", "transport", "network", "type")?.lowercased() {
            switch t {
            case "websocket", "ws": f["network"] = .string("ws")
            case "wss": f["network"] = .string("ws"); f["tls"] = .bool(true)
            case "none", "tcp", "": break
            default: f["network"] = .string(t) // kept so NCSupport names it instead of dropping it silently
            }
        }
        if let w = take("ws"), flag(w) == true { f["network"] = .string("ws") }
        if f["network"]?.string == "ws" {
            var opts = f["ws-opts"]?.object ?? [:]
            if let p = take("path", "ws-path", "obfs-uri"), !p.isEmpty { opts["path"] = .string(p) }
            var headers = opts["headers"]?.object ?? [:]
            if let wh = take("ws-headers") {
                for (k, v) in NCConfImport.parseWSHeaders(wh) { headers[k] = .string(v) }
            }
            if headers["Host"] == nil, let h = take("obfsparam", "obfs-host", "host"), !h.isEmpty { headers["Host"] = .string(h) }
            if !headers.isEmpty { opts["headers"] = .object(headers) }
            if !opts.isEmpty { f["ws-opts"] = .object(opts) }
        }
        if let fp = take("client-fingerprint", "fp"), !fp.isEmpty { f["client-fingerprint"] = .string(fp) }
        if let fp = take("fingerprint", "hpkp"), !fp.isEmpty {
            let hex = fp.replacingOccurrences(of: ":", with: "")
            if hex.count == 64, hexBytes(hex) != nil { f["fingerprint"] = .string(fp) }
            else if f["client-fingerprint"] == nil { f["client-fingerprint"] = .string(fp.lowercased()) }
        }
        if let n = take("name-cert-verify"), !n.isEmpty { f["name-cert-verify"] = .string(n) }
        return used
    }
}
