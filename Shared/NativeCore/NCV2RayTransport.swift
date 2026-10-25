import Foundation

// fix/nc-silent-fail: the stream-transport options NCConnector.transportStream used to read only partly, so the
// node looked usable and connected wrongly. Ported from mihomo v1.19.33:
// - transport/vmess/websocket.go   ws-opts: path `?ed=`, max-early-data / early-data-header-name (0-RTT
//                                  WebSocket), v2ray-http-upgrade (+ fast-open): HTTP Upgrade, no ws framing
// - transport/vmess/http.go        http-opts: HTTP/1.1 request disguise (method, random path, random headers)
// Snell obfs-opts (simple-obfs http / tls) reuses NCSSPluginStream (adapter/outbound/snell.go streamConnContext).
// Pure Swift, no extra buffering beyond one queued receive and the sends issued while a deferred ws dial runs.

// MARK: - ws-opts

/// Decoded `ws-opts` of a VMess / VLESS / Trojan node (mihomo WebsocketConfig as the outbound fills it).
struct NCWSTransportOptions: Equatable {
    /// Request path including any query, `ed` already removed (mihomo StreamWebsocketConn).
    var path: String
    /// Host header (and the ws URI host): ws-opts.headers.Host, else the outbound's default host.
    var hostHeader: String
    /// Extra request headers, Host excluded (it is `hostHeader`).
    var headers: [String: String]
    /// Bytes of the first write carried in the upgrade request (0 = no early data).
    var maxEarlyData: Int
    /// Header the base64url early data rides in; empty = appended to the path.
    var earlyDataHeaderName: String
    /// `v2ray-http-upgrade`: same GET, no Sec-WebSocket-* headers, raw stream after the 101.
    var httpUpgrade: Bool
    /// `v2ray-http-upgrade-fast-open`: usable before the 101 arrives (validated on the first reads).
    var httpUpgradeFastOpen: Bool

    /// `defaultHost`: mihomo uses the server address for VMess / VLESS, and `sni` (if set) for Trojan.
    static func parse(_ proxy: NCProxy, defaultHost: String) -> NCWSTransportOptions {
        let o = proxy.fields["ws-opts"]?.object ?? [:]
        var headers: [String: String] = [:]
        var host: String?
        for (k, v) in o["headers"]?.object ?? [:] {
            guard let s = v.string ?? v.array?.first?.string else { continue }
            if k.lowercased() == "host" { if !s.isEmpty { host = s } } else { headers[k] = s }
        }
        var opts = NCWSTransportOptions(
            path: o["path"]?.string ?? "/",
            hostHeader: host ?? defaultHost,
            headers: headers,
            maxEarlyData: max(0, o["max-early-data"]?.int ?? 0),
            earlyDataHeaderName: o["early-data-header-name"]?.string ?? "",
            httpUpgrade: o["v2ray-http-upgrade"]?.bool ?? false,
            httpUpgradeFastOpen: o["v2ray-http-upgrade-fast-open"]?.bool ?? false)
        // mihomo: `?ed=N` in the path overrides both early-data options (Xray share-link convention) and is
        // removed from the path that goes on the wire.
        if let (stripped, ed) = Self.extractED(opts.path) {
            opts.path = stripped
            opts.maxEarlyData = max(0, ed)
            opts.earlyDataHeaderName = "Sec-WebSocket-Protocol"
        }
        if opts.path.isEmpty { opts.path = "/" }
        return opts
    }

    /// `/p?ed=2048&x=1` → ("/p?x=1", 2048). nil when there is no integer `ed` parameter.
    static func extractED(_ path: String) -> (String, Int)? {
        guard let q = path.firstIndex(of: "?") else { return nil }
        let base = String(path[..<q])
        var query = String(path[path.index(after: q)...])
        var fragment = ""
        if let h = query.firstIndex(of: "#") {
            fragment = String(query[h...])
            query = String(query[..<h])
        }
        var ed: Int?
        var kept: [Substring] = []
        for item in query.split(separator: "&", omittingEmptySubsequences: false) {
            let kv = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if kv.first == "ed" {
                let v = kv.count > 1 ? String(kv[1]) : ""
                if !v.isEmpty, let n = Int(v.removingPercentEncoding ?? v) {
                    if ed == nil { ed = n }
                    continue
                }
            }
            kept.append(item)
        }
        guard let ed else { return nil }
        let rest = kept.filter { !$0.isEmpty }.joined(separator: "&")
        return (base + (rest.isEmpty ? "" : "?" + rest) + fragment, ed)
    }

    /// Path and extra headers for one upgrade request, given the base64url early data (if any).
    /// mihomo: no header name → `uri.Path += early` (before the query).
    func request(earlyData: String?) -> (path: String, headers: [String: String]) {
        guard let earlyData, !earlyData.isEmpty else { return (path, headers) }
        if earlyDataHeaderName.isEmpty {
            if let q = path.firstIndex(of: "?") {
                return (String(path[..<q]) + earlyData + String(path[q...]), headers)
            }
            return (path + earlyData, headers)
        }
        var h = headers
        h[earlyDataHeaderName] = earlyData
        return (path, h)
    }

    /// RFC 4648 §5 base64url without padding (Go base64.RawURLEncoding).
    static func base64URLRaw(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }
}

/// The VMess / VLESS / Trojan "ws" transport with every ws-opts mode: WebSocket (NCWebSocketStream) or v2ray
/// http-upgrade (NCV2RayUpgradeStream), each optionally with early data — then the upgrade request is deferred to
/// the first send, whose first `maxEarlyData` bytes ride in it (mihomo websocketWithEarlyDataConn): the CDN
/// node answers without the extra round trip. Reads issued before that dial wait for it.
final class NCV2RayWSStream: NCRelayStream {
    private let raw: NCRelayStream
    let options: NCWSTransportOptions
    private var inner: NCRelayStream?
    private var dialing = false
    private var failure: Error?
    private var closed = false
    private var queuedSends: [(Data, NCCallOnce)] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?

    init(raw: NCRelayStream, options: NCWSTransportOptions) {
        self.raw = raw
        self.options = options
    }

    /// Without early data the upgrade runs now (completion after the 101, or at once with fast-open); with early
    /// data the completion fires immediately and the upgrade goes out with the first send.
    func start(completion: @escaping (Error?) -> Void) {
        if options.maxEarlyData > 0 {
            completion(nil)
            return
        }
        dialing = true
        dial(earlyData: nil, completion: completion)
    }

    private func dial(earlyData: String?, completion: @escaping (Error?) -> Void) {
        let (path, headers) = options.request(earlyData: earlyData)
        let finish: (NCRelayStream, Error?) -> Void = { [weak self] stream, err in
            guard let self else { completion(err); return }
            self.dialing = false
            if let err {
                self.fail(err)
            } else if !self.closed {
                self.inner = stream
                self.drain()
            }
            completion(err)
        }
        if options.httpUpgrade {
            let up = NCV2RayUpgradeStream(raw: raw, hostHeader: options.hostHeader, path: path,
                                          headers: headers, fastOpen: options.httpUpgradeFastOpen)
            up.startHandshake { err in finish(up, err) }
        } else {
            let ws = NCWebSocketStream(raw: raw, hostHeader: options.hostHeader, path: path, headers: headers)
            ws.startHandshake { err in finish(ws, err) }
        }
    }

    private func fail(_ error: Error) {
        failure = error
        let sends = queuedSends
        queuedSends = []
        for (_, once) in sends { once.call() }
        if let r = pendingReceive {
            pendingReceive = nil
            r(nil, error)
        }
        raw.cancel()
    }

    /// After the deferred dial: queued sends in order, then the waiting read.
    private func drain() {
        guard let inner else { return }
        let sends = queuedSends
        queuedSends = []
        for (d, once) in sends { inner.send(d, completion: once.call) }
        if let r = pendingReceive {
            pendingReceive = nil
            inner.receive(r)
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        if closed || failure != nil { once.call(); return }
        if let inner { inner.send(data, completion: once.call); return }
        if dialing || data.isEmpty { queuedSends.append((data, once)); return }
        // First write with early data: its head rides in the upgrade request, the rest follows the 101.
        dialing = true
        let n = min(options.maxEarlyData, data.count)
        let early = NCWSTransportOptions.base64URLRaw(Data(data.prefix(n)))
        let rest = Data(data.dropFirst(n))
        if !rest.isEmpty { queuedSends.insert((rest, once), at: 0) }
        dial(earlyData: early) { _ in
            // A non-empty rest carries `once` through the queue (sent by drain(), or fired by fail() / cancel());
            // otherwise the whole write rode in the upgrade request and is done either way.
            if rest.isEmpty { once.call() }
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if let inner { inner.receive(handler); return }
        if let failure { handler(nil, failure); return }
        if closed { handler(nil, nil); return }
        pendingReceive = handler
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        let sends = queuedSends
        queuedSends = []
        for (_, once) in sends { once.call() }
        if let r = pendingReceive {
            pendingReceive = nil
            r(nil, nil)
        }
        if let inner { inner.cancel() } else { raw.cancel() }
    }
}

// MARK: - http-opts (HTTP/1.1 obfuscation)

/// Decoded `http-opts` (mihomo HTTPOptions / vmess.HTTPConfig): method (default GET), path list (one picked at
/// random per connection, default "/"), headers name → value list (one value picked at random per connection; a
/// Host header replaces the server address). Scalars are accepted where mihomo wants a list (weakly typed decode).
struct NCHTTPObfsOptions: Equatable {
    var method: String
    var paths: [String]
    var headers: [String: [String]]
    var host: String

    static func parse(_ proxy: NCProxy, server: String) -> NCHTTPObfsOptions {
        let o = proxy.fields["http-opts"]?.object ?? [:]
        func list(_ v: NCJSONValue?) -> [String] {
            if let a = v?.array { return a.compactMap { $0.string } }
            if let s = v?.string { return [s] }
            return []
        }
        var headers: [String: [String]] = [:]
        for (k, v) in o["headers"]?.object ?? [:] { headers[k] = list(v) }
        let method = o["method"]?.string ?? ""
        return NCHTTPObfsOptions(method: method.isEmpty ? "GET" : method.uppercased(),
                                 paths: list(o["path"]), headers: headers, host: server)
    }

    /// The request head + body Go's http.Request.Write produces for mihomo httpConn's first Write: request line,
    /// Host, User-Agent (Go default unless configured), Content-Length, the other headers sorted by canonical
    /// name, blank line, then the payload as the body.
    func requestHead(payload: Data, pick: (Int) -> Int = { Int.random(in: 0..<$0) }) -> Data {
        var path = "/"
        if !paths.isEmpty { path = paths[pick(paths.count)] }
        if path.isEmpty { path = "/" }
        var hostValue = host
        var fields: [String: String] = [:]
        for (k, list) in headers.sorted(by: { $0.key < $1.key }) where !list.isEmpty {
            let v = list[pick(list.count)]
            let canon = Self.canonicalKey(k)
            if canon == "Host" { hostValue = v; continue }
            fields[canon] = v
        }
        var out = "\(method) \(path) HTTP/1.1\r\nHost: \(hostValue)\r\n"
        let userAgent = fields.removeValue(forKey: "User-Agent") ?? "Go-http-client/1.1"
        out += "User-Agent: \(userAgent)\r\n"
        fields.removeValue(forKey: "Content-Length")
        fields.removeValue(forKey: "Transfer-Encoding")
        if !payload.isEmpty { out += "Content-Length: \(payload.count)\r\n" }
        for k in fields.keys.sorted() { out += "\(k): \(fields[k]!)\r\n" }
        out += "\r\n"
        var d = Data(out.utf8)
        d.append(payload)
        return d
    }

    /// Go textproto.CanonicalMIMEHeaderKey for plain ASCII tokens: "content-type" → "Content-Type".
    static func canonicalKey(_ k: String) -> String {
        var out = ""
        var upper = true
        for ch in k {
            if upper { out += ch.uppercased() } else { out += ch.lowercased() }
            upper = ch == "-"
        }
        return out
    }
}

/// mihomo vmess httpConn: the first send becomes an HTTP/1.1 request carrying it as the body, later sends go
/// out raw; inbound, the server's HTTP response head is skipped once and the rest is the stream.
final class NCHTTPObfsStream: NCRelayStream {
    private let raw: NCRelayStream
    private let options: NCHTTPObfsOptions
    private var wroteHead = false
    private var headDone = false
    private var head = Data()
    /// The server's response head is attacker-sized; mihomo's textproto reader has no cap, 16 KB is plenty.
    static let maxResponseHead = 16 * 1024

    init(raw: NCRelayStream, options: NCHTTPObfsOptions) {
        self.raw = raw
        self.options = options
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        if wroteHead {
            raw.send(data, completion: completion)
            return
        }
        guard !data.isEmpty else { completion(); return }
        wroteHead = true
        raw.send(options.requestHead(payload: data), completion: completion)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if headDone { raw.receive(handler); return }
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            switch Self.stripResponseHead(&self.head, appending: data) {
            case .needMore:
                if self.head.count > Self.maxResponseHead {
                    self.raw.cancel()
                    handler(nil, NCConnector.Failure.handshake("http obfs: response header too large"))
                } else {
                    self.receive(handler)
                }
            case .done(let rest):
                self.headDone = true
                if rest.isEmpty { self.receive(handler) } else { handler(rest, nil) }
            }
        }
    }

    enum StripResult: Equatable { case needMore, done(Data) }

    /// Accumulate into `head` until the blank line ending the HTTP response head; then everything after it.
    static func stripResponseHead(_ head: inout Data, appending data: Data) -> StripResult {
        head.append(data)
        guard let r = head.range(of: Data("\r\n\r\n".utf8)) else { return .needMore }
        let rest = Data(head[r.upperBound...])
        head = Data()
        return .done(rest)
    }

    func cancel() { raw.cancel() }
}

// MARK: - Connector helpers

extension NCConnector {
    /// uTLS ClientHello shape for the hand-rolled TLS paths (Vision / REALITY): `client-fingerprint` (mihomo).
    /// `fingerprint` is the certificate SHA-256 pin; only a legacy config that put a browser name there (the old
    /// NativeCore reading) still gets that browser, when no client-fingerprint is given.
    static func utlsProfile(_ proxy: NCProxy) -> NCClientHelloProfile {
        if let cf = proxy.fields["client-fingerprint"]?.string, !cf.isEmpty {
            return NCClientHelloProfile.named(cf)
        }
        if let fp = proxy.fields["fingerprint"]?.string, browserFingerprintNames.contains(fp.lowercased()) {
            return NCClientHelloProfile.named(fp)
        }
        return NCClientHelloProfile.named(nil)
    }

    static let browserFingerprintNames: Set<String> = ["chrome", "firefox", "safari", "ios", "android", "edge",
                                                       "360", "qq", "random", "randomized"]

    /// `fingerprint` as a certificate pin (mihomo ca.NewFingerprintVerifier: hex SHA-256, colons allowed).
    /// .absent = no pin (absent, or a legacy browser name); .invalid = present but not a SHA-256.
    enum CertPin: Equatable { case absent, pin(Data), invalid }

    static func certPin(_ proxy: NCProxy) -> CertPin {
        guard let fp = proxy.fields["fingerprint"]?.string?.trimmingCharacters(in: .whitespaces), !fp.isEmpty
        else { return .absent }
        if browserFingerprintNames.contains(fp.lowercased()) { return .absent }
        let hex = fp.replacingOccurrences(of: ":", with: "")
        guard hex.count == 64 else { return .invalid }
        var out = Data(capacity: 32)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return .invalid }
            out.append(b)
            i = j
        }
        return .pin(out)
    }

    /// Trojan stream transports routed through transportStream (mihomo trojan: ws / grpc; h2 as Xray does).
    /// Anything else (tcp, or a value mihomo's trojan ignores such as "http") stays plain Trojan-over-TLS.
    static func trojanUsesTransport(_ proxy: NCProxy) -> Bool {
        ["ws", "grpc", "h2"].contains(proxy.fields["network"]?.string ?? "tcp")
    }

    /// Trojan over a stream transport: TLS (or REALITY) to the server, then ws / grpc / h2, then the caller's
    /// Trojan head. Shared by TCP (connectViaProxy) and the UDP session.
    static func trojanTransportBase(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                                    completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let wrap: (NCRelayStream?, Error?) -> Void = { base, err in
            guard let base else { completion(nil, err); return }
            transportStream(raw: base, proxy: proxy, server: server, queue: queue, completion: completion)
        }
        if realityParams(proxy) != nil {
            dialReality(proxy: proxy, server: server, port: port, queue: queue, completion: wrap)
            return
        }
        let raw = NCStream(to: server, port: port,
                           tlsServerName: proxy.fields["sni"]?.string ?? server,
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        raw.start { err in wrap(err == nil ? raw : nil, err) }
    }

    /// sing-mux over VMess / VLESS is implemented for h2mux only. smux / yamux sessions are optional on the
    /// server side (sing-mux accepts plain connections too), so those nodes dial without multiplexing instead
    /// of failing every connection.
    static func smuxUsable(_ proxy: NCProxy) -> Bool {
        smuxEnabled(proxy) && smuxProtocol(proxy) == "h2mux"
    }

    /// Snell `obfs-opts` as a simple-obfs plugin (mihomo NewSnell: Host defaults to bing.com; mode "" = none).
    static func snellObfsOptions(_ proxy: NCProxy) -> NCSSPluginOptions? {
        let o = proxy.fields["obfs-opts"]?.object ?? [:]
        let mode = o["mode"]?.string ?? ""
        guard mode == "http" || mode == "tls" else { return nil }
        var opts: [String: NCJSONValue] = ["mode": .string(mode)]
        if let h = o["host"]?.string { opts["host"] = .string(h) }
        return NCSSPluginOptions(pluginName: "obfs", opts: opts)
    }
}
