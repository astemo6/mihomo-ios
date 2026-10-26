import Foundation
import Network

/// Gap D1 (feat/nc-modes, on astemo6/Muse's NativeCore): the local mixed port (mihomo `mixed-port` semantics) for
/// 仅代理 and VPN 混合. One loopback listener on CoreOverrides.mixedPort answers, by the first byte of a connection:
///   - SOCKS5 (0x05): no-auth, CONNECT only (UDP ASSOCIATE / BIND answer 0x07 "command not supported");
///   - HTTP: `CONNECT host:port` (HTTPS tunnels — what NEProxySettings' httpsServer sends) and absolute-form plain
///     requests (`GET http://host/path`, NEProxySettings' httpServer), forwarded in origin form with
///     `Connection: close` (one request per proxied connection: the next request opens a new one).
/// Every connection is routed exactly like a TUN connection: fake-IP deref, rules → policy → group engine
/// (NativeCoreEngine.route), NCConnector for the outbound, and the native MitM front for MitM hosts on CONNECT /
/// SOCKS (the ClientHello is sniffed for ALPN first, as NCDataPlane does). Connections show in the controller's
/// /connections (ids "lp<N>") and count in the traffic totals.
///
/// feat/nc-lan-share (需同步 feat/nc-kernel): 局域网共享. The listener follows NCLanShare (mihomo allow-lan /
/// bind-address / authentication / skip-auth-prefixes / lan-allowed-ips / lan-disallowed-ips, from the runtime config
/// the app builds out of 更多 → 连接方式 → 局域网共享): allow-lan off → loopback only (as before); on → every interface
/// (bind-address "*") or the one address given. Clients outside lan-allowed-ips are dropped at accept; with
/// `authentication` set, a client outside skip-auth-prefixes (the app always skips 127.0.0.0/8 and ::1, so the
/// device's own system proxy never prompts) must send `Proxy-Authorization: Basic …` (else 407) or use SOCKS5
/// username/password (RFC 1929; a client offering only no-auth gets 0xFF). `reconfigure` re-applies a reloaded
/// config: same port + bind → only the policy changes (open connections stay); otherwise the listener is re-bound.
///
/// Not done yet: SOCKS5 UDP, SOCKS4, keep-alive across requests of a plain-HTTP proxy connection.
final class NCLocalProxy {
    static let idPrefix = "lp"
    static func ownsConnectionID(_ id: String) -> Bool { id.hasPrefix(idPrefix) }

    /// Owned by `queue` once started (reconfigure may re-bind it).
    private(set) var port: UInt16
    private var lan: NCLanShare
    private var bind: NCLanShare.Bind
    private let engine: NativeCoreEngine
    private let stats: NCDataPlaneStats
    let queue = DispatchQueue(label: "nc.localproxy", qos: .userInitiated)
    private var listener: NWListener?
    private var conns: [Int: Conn] = [:]
    private var nextID = 1
    private var timer: DispatchSourceTimer?
    private var totalUp: Int64 = 0, totalDown: Int64 = 0, totalProxyUp: Int64 = 0, totalProxyDown: Int64 = 0
    private static let maxConnections = 512
    private static let maxHead = 64 * 1024
    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    init(engine: NativeCoreEngine, port: Int, stats: NCDataPlaneStats, lan: NCLanShare? = nil) {
        self.engine = engine
        self.port = UInt16(clamping: port)
        self.stats = stats
        let l = lan ?? NCLanShare(skipAuth: NCLanShare.loopbackPrefixes.compactMap { NCCIDR($0) })
        self.lan = l
        bind = l.bind
    }

    /// "127.0.0.1:7890" / "0.0.0.0:7890" / "192.168.1.2:7890" for logs.
    static func describe(_ bind: NCLanShare.Bind, _ port: UInt16) -> String {
        switch bind {
        case .loopback: return "127.0.0.1:\(port)"
        case .any: return "0.0.0.0:\(port)"
        case .address(let a): return a.contains(":") ? "[\(a)]:\(port)" : "\(a):\(port)"
        }
    }

    final class Conn {
        let id: Int
        let client: NWConnection
        var buf = Data()
        var relay: NCRelayStream?
        var closed = false
        var kind = "HTTP"
        var target = NCTarget(host: "", port: 0)
        var ruleDomain: String?
        var chain = ""
        var rule = ""
        var up: Int64 = 0
        var down: Int64 = 0
        let start = Date()
        var sourcePort = ""
        var sourceIP = "127.0.0.1"
        var needsAuth = false
        /// fix/nc-tails: /app/stats (host / policy / rule / bytes / closed record), like a TUN connection.
        var flow = NCListenerFlowStats()
        init(id: Int, client: NWConnection) { self.id = id; self.client = client }
    }

    // MARK: lifecycle

    /// Starts listening (loopback, or the LAN bind NCLanShare asks for); waits up to `timeout` for the listener.
    /// nil = listening, else the reason (port in use, …).
    func start(timeout: TimeInterval = 3) -> String? {
        let (p, b) = queue.sync { (port, bind) }
        let made = Self.makeListener(port: p, bind: b, queue: queue, timeout: timeout) { [weak self] nw in self?.accept(nw) }
        guard let listener = made.listener else { return made.error }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.refreshStats() }
        t.resume()
        queue.sync {
            self.listener = listener
            timer = t
        }
        return nil
    }

    /// Applies a reloaded LAN policy / port. Same port and bind: the policy is swapped in place (new connections use
    /// it; open ones stay). Otherwise the listener is re-bound; if the new one cannot listen the previous one is
    /// restored and the reason returned.
    func reconfigure(port newPort: Int, lan newLan: NCLanShare, timeout: TimeInterval = 3) -> String? {
        let p = UInt16(clamping: newPort)
        let newBind = newLan.bind
        let (oldPort, oldBind) = queue.sync { (port, bind) }
        if p == oldPort && newBind == oldBind {
            queue.sync { lan = newLan }
            return nil
        }
        queue.sync {
            listener?.newConnectionHandler = nil
            listener?.cancel()
            listener = nil
        }
        let accept: (NWConnection) -> Void = { [weak self] nw in self?.accept(nw) }
        let made = Self.makeListener(port: p, bind: newBind, queue: queue, timeout: timeout, onConnection: accept)
        if let l = made.listener {
            queue.sync {
                listener = l
                port = p
                bind = newBind
                lan = newLan
            }
            return nil
        }
        let back = Self.makeListener(port: oldPort, bind: oldBind, queue: queue, timeout: timeout, onConnection: accept)
        queue.sync { listener = back.listener }
        if back.listener == nil { StartupLog.write("local proxy: could not restore \(Self.describe(oldBind, oldPort)): \(back.error ?? "?")") }
        return made.error
    }

    /// One NWListener for `bind`:`port`, started on `queue`; waits until it is ready or failed.
    private static func makeListener(port: UInt16, bind: NCLanShare.Bind, queue: DispatchQueue, timeout: TimeInterval,
                                     onConnection: @escaping (NWConnection) -> Void) -> (listener: NWListener?, error: String?) {
        guard port > 0, let nwPort = NWEndpoint.Port(rawValue: port) else { return (nil, "端口无效（\(port)）") }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        let listener: NWListener
        do {
            switch bind {
            case .loopback:
                params.requiredInterfaceType = .loopback
                listener = try NWListener(using: params, on: nwPort)
            case .any:
                // Every interface (Wi-Fi, 个人热点 bridge, …), IPv4 + IPv6.
                listener = try NWListener(using: params, on: nwPort)
            case .address(let a):
                params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(a), port: nwPort)
                listener = try NWListener(using: params)
            }
        } catch {
            return (nil, error.localizedDescription)
        }
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String?? // nil = no answer yet
        listener.stateUpdateHandler = { state in
            var answer: String??
            switch state {
            case .ready: answer = .some(nil)
            case .failed(let e): answer = .some(e.localizedDescription)
            case .waiting(let e): answer = .some(e.localizedDescription)
            default: break
            }
            guard let answer else { return }
            lock.lock()
            let first = result == nil
            if first { result = answer }
            lock.unlock()
            if first { sem.signal() }
            else if case .failed(let e) = state { StartupLog.write("local proxy: listener failed: \(e.localizedDescription)") }
        }
        listener.newConnectionHandler = onConnection
        listener.start(queue: queue)
        _ = sem.wait(timeout: .now() + timeout)
        lock.lock()
        let outcome = result
        lock.unlock()
        switch outcome {
        case .some(.none):
            return (listener, nil)
        case .some(.some(let why)):
            listener.cancel()
            return (nil, why)
        case .none:
            listener.cancel()
            return (nil, "监听超时")
        }
    }

    func stop() {
        queue.sync {
            // rv2-life: the listener is touched on `queue` only (was cancelled from the caller's thread)
            listener?.newConnectionHandler = nil
            listener?.cancel()
            listener = nil
            timer?.cancel()
            timer = nil
            for c in Array(conns.values) { close(c) }
            conns.removeAll()
            stats.updateLocal(connections: [], up: totalUp, down: totalDown, proxyUp: totalProxyUp, proxyDown: totalProxyDown)
        }
    }

    func closeConnection(id: String) {
        guard let n = Int(id.dropFirst(Self.idPrefix.count)) else { return }
        queue.async { [weak self] in
            guard let self, let c = conns[n] else { return }
            close(c)
        }
    }

    func closeAllConnections() {
        queue.async { [weak self] in
            guard let self else { return }
            for c in Array(conns.values) { close(c) }
        }
    }

    // MARK: accept / first bytes

    private func accept(_ nw: NWConnection) {
        guard conns.count < Self.maxConnections else {
            nw.cancel()
            return
        }
        var source: NCIP?
        var sourceText = ""
        if case .hostPort(let h, _) = nw.endpoint {
            switch h {
            case .ipv4(let a): sourceText = "\(a)"
            case .ipv6(let a): sourceText = "\(a)"
            case .name(let n, _): sourceText = n
            @unknown default: break
            }
            source = NCLanShare.sourceIP(sourceText)
        }
        // 局域网共享: lan-allowed-ips / lan-disallowed-ips (loopback always in).
        guard lan.admits(source) else {
            nw.cancel()
            return
        }
        let c = Conn(id: nextID, client: nw)
        nextID &+= 1
        if case .hostPort(_, let p) = nw.endpoint { c.sourcePort = String(p.rawValue) }
        if let source { c.sourceIP = source.string } else if !sourceText.isEmpty { c.sourceIP = sourceText }
        c.needsAuth = lan.needsAuth(source)
        conns[c.id] = c
        nw.stateUpdateHandler = { [weak self, weak c] state in
            guard let self, let c else { return }
            switch state {
            case .failed, .cancelled: self.close(c)
            default: break
            }
        }
        nw.start(queue: queue)
        // A client that never sends its request head is dropped after 30 s.
        queue.asyncAfter(deadline: .now() + 30) { [weak self, weak c] in
            guard let self, let c, !c.closed, c.relay == nil, c.chain.isEmpty else { return }
            self.close(c)
        }
        readHead(c)
    }

    private func readHead(_ c: Conn) {
        c.client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak c] data, _, isComplete, error in
            guard let self, let c, !c.closed else { return }
            if let data { c.buf.append(data) }
            if data == nil || data!.isEmpty, isComplete || error != nil {
                self.close(c)
                return
            }
            self.parseHead(c)
        }
    }

    private func parseHead(_ c: Conn) {
        guard let first = c.buf.first else { return readHead(c) }
        if first == 0x05 {
            c.kind = "Socks5"
            socks(c)
            return
        }
        guard let end = c.buf.range(of: Data("\r\n\r\n".utf8)) else {
            if c.buf.count > Self.maxHead { close(c) } else { readHead(c) }
            return
        }
        http(c, headEnd: end)
    }

    // MARK: SOCKS5

    private enum SocksStage { case greeting, auth, request }
    private var socksStage: [Int: SocksStage] = [:]

    private func socks(_ c: Conn) {
        let b = [UInt8](c.buf)
        switch socksStage[c.id] ?? .greeting {
        case .greeting:
            guard b.count >= 2 else { return readHead(c) }
            let n = Int(b[1])
            guard b.count >= 2 + n else { return readHead(c) }
            let methods = b[2..<(2 + n)]
            c.buf = Data(b[(2 + n)...])
            // 局域网共享 authentication: username/password (0x02) is the only method accepted then.
            let method: UInt8 = c.needsAuth ? 0x02 : 0x00
            guard methods.contains(method) else {
                c.client.send(content: Data([0x05, 0xff]), completion: .contentProcessed { [weak self] _ in
                    self?.queue.async { self?.close(c) }
                })
                return
            }
            c.client.send(content: Data([0x05, method]), completion: .idempotent)
            socksStage[c.id] = c.needsAuth ? .auth : .request
            if c.buf.isEmpty { readHead(c) } else { socks(c) }
        case .auth:
            switch NCLanShare.parseSocksUserPass(b) {
            case .needMore:
                return readHead(c)
            case .invalid:
                return close(c)
            case .ok(let consumed, let user, let password):
                c.buf = Data(b[consumed...])
                guard lan.verify(user: user, password: password) else {
                    c.client.send(content: Data([0x01, 0x01]), completion: .contentProcessed { [weak self] _ in
                        self?.queue.async { self?.close(c) }
                    })
                    return
                }
                c.client.send(content: Data([0x01, 0x00]), completion: .idempotent)
                socksStage[c.id] = .request
                if c.buf.isEmpty { readHead(c) } else { socks(c) }
            }
        case .request:
            guard b.count >= 5 else { return readHead(c) }
            guard b[0] == 0x05 else { return close(c) }
            let cmd = b[1], atyp = b[3]
            var host = ""
            var off = 4
            switch atyp {
            case 0x01:
                guard b.count >= off + 4 + 2 else { return readHead(c) }
                host = b[off..<(off + 4)].map { String($0) }.joined(separator: ".")
                off += 4
            case 0x03:
                let len = Int(b[4])
                guard b.count >= 5 + len + 2 else { return readHead(c) }
                host = String(decoding: b[5..<(5 + len)], as: UTF8.self)
                off = 5 + len
            case 0x04:
                guard b.count >= off + 16 + 2 else { return readHead(c) }
                host = IPv6Address(Data(b[off..<(off + 16)])).map { "\($0)" } ?? ""
                off += 16
            default:
                return socksReply(c, 0x08, thenClose: true)
            }
            let port = Int(b[off]) << 8 | Int(b[off + 1])
            off += 2
            c.buf = Data(b[off...])
            socksStage.removeValue(forKey: c.id)
            guard cmd == 0x01 else { return socksReply(c, 0x07, thenClose: true) }
            guard !host.isEmpty, port > 0 else { return socksReply(c, 0x01, thenClose: true) }
            connect(c, host: host, port: port) { [weak self] ok, rep in
                self?.socksReply(c, ok ? 0x00 : rep, thenClose: !ok)
            }
        }
    }

    private func socksReply(_ c: Conn, _ rep: UInt8, thenClose: Bool) {
        let reply = Data([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        c.client.send(content: reply, completion: .contentProcessed { [weak self] _ in
            if thenClose { self?.queue.async { self?.close(c) } }
        })
    }

    // MARK: HTTP

    private func http(_ c: Conn, headEnd: Range<Data.Index>) {
        let headData = c.buf[c.buf.startIndex..<headEnd.lowerBound]
        let rest = Data(c.buf[headEnd.upperBound...])
        let head = String(decoding: headData, as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return close(c) }
        let parts = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count == 3 else { return httpError(c, 400, "Bad Request") }
        let (method, uri, version) = (parts[0], parts[1], parts[2])
        // 局域网共享 authentication (Proxy-Authorization: Basic); mihomo answers 407 + Proxy-Authenticate.
        if c.needsAuth && !lan.verifyHTTP(headerLines: lines) {
            return httpError(c, 407, "Proxy Authentication Required", extra: "Proxy-Authenticate: Basic realm=\"Tern\"\r\n")
        }
        if method.uppercased() == "CONNECT" {
            c.kind = "HTTPS"
            guard let hp = Self.splitAuthority(uri, defaultPort: 443) else { return httpError(c, 400, "Bad Request") }
            c.buf = rest
            connect(c, host: hp.0, port: hp.1) { [weak self] ok, rep in
                guard let self else { return }
                if ok {
                    c.client.send(content: Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8), completion: .idempotent)
                } else {
                    self.httpError(c, rep == 0x02 ? 403 : 502, rep == 0x02 ? "Forbidden" : "Bad Gateway")
                }
            }
            return
        }
        // Absolute-form request (a client using us as its HTTP proxy).
        c.kind = "HTTP"
        guard let url = URLComponents(string: uri), let scheme = url.scheme?.lowercased(), scheme == "http",
              let host = url.host, !host.isEmpty else {
            return httpError(c, 400, "Bad Request")
        }
        let port = url.port ?? 80
        var path = url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath
        if let q = url.percentEncodedQuery { path += "?" + q }
        var out = "\(method) \(path) \(version)\r\n"
        var hasHost = false
        for line in lines where !line.isEmpty {
            let name = line.split(separator: ":", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            if ["proxy-connection", "proxy-authorization", "connection", "keep-alive"].contains(name) { continue }
            if name == "host" { hasHost = true }
            out += line + "\r\n"
        }
        if !hasHost { out += "Host: \(port == 80 ? host : "\(host):\(port)")\r\n" }
        out += "Connection: close\r\n\r\n"
        c.buf = Data(out.utf8) + rest
        connect(c, host: host.hasPrefix("[") ? String(host.dropFirst().dropLast()) : host, port: port) { [weak self] ok, rep in
            if !ok { self?.httpError(c, rep == 0x02 ? 403 : 502, rep == 0x02 ? "Forbidden" : "Bad Gateway") }
        }
    }

    private func httpError(_ c: Conn, _ code: Int, _ text: String, extra: String = "") {
        let body = "\(code) \(text)\n"
        let resp = "HTTP/1.1 \(code) \(text)\r\n\(extra)Content-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        c.client.send(content: Data(resp.utf8), completion: .contentProcessed { [weak self] _ in
            self?.queue.async { self?.close(c) }
        })
    }

    /// host:port, [v6]:port, or a bare host (default port).
    static func splitAuthority(_ s: String, defaultPort: Int) -> (String, Int)? {
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            if rest.isEmpty { return (host, defaultPort) }
            guard rest.hasPrefix(":"), let p = Int(rest.dropFirst()), (1...65535).contains(p) else { return nil }
            return (host, p)
        }
        let parts = s.split(separator: ":")
        if parts.count == 1 { return (String(parts[0]), defaultPort) }
        guard parts.count == 2, let p = Int(parts[1]), (1...65535).contains(p), !parts[0].isEmpty else { return nil }
        return (String(parts[0]), p)
    }

    // MARK: routing

    /// Routes host:port like a TUN connection and opens the outbound. `done(ok, socksReplyCode)` runs on `queue`
    /// before any relayed byte reaches the client; on success the pumps start right after it.
    private func connect(_ c: Conn, host rawHost: String, port: Int, done: @escaping (Bool, UInt8) -> Void) {
        // Our own port through ourselves would loop forever.
        if NCOutboundBinding.isLoopback(rawHost), port == Int(self.port) {
            c.chain = "REJECT"
            return done(false, 0x02)
        }
        let target = engine.derefFakeIP(NCTarget(host: rawHost.lowercased(), port: port))
        c.target = target
        c.ruleDomain = target.ip == nil ? target.host : nil
        // MitM hosts: the ClientHello comes after our success reply; sniff it, then hand over to the native front.
        if c.kind != "HTTP", let domain = c.ruleDomain, engine.isMitm(host: domain, port: port) {
            c.chain = "MITM"
            done(true, 0)
            awaitClientHello(c, host: domain)
            return
        }
        open(c, done: done)
    }

    private func open(_ c: Conn, done: @escaping (Bool, UInt8) -> Void) {
        let ctx = engine.matchContext(domain: c.ruleDomain, ip: c.target.ip, dstPort: c.target.port, network: "tcp")
        // rv2-rules: IP rules on a domain target resolve it first (no-resolve skips), same as the TUN data plane.
        engine.routeAsync(ctx, queue: queue) { [weak self, weak c] policy, rule, resolution in
            guard let self, let c, !c.closed else { return }
            self.dial(c, policy: policy, rule: rule, resolution: resolution, done: done)
        }
    }

    private func dial(_ c: Conn, policy: String, rule: String?, resolution: NCGroupEngine.Resolution,
                      done: @escaping (Bool, UInt8) -> Void) {
        c.rule = rule ?? ""
        c.chain = NCListenerFlowStats.chainName(resolution)
        c.flow.open(rule: c.rule, policy: policy, chain: c.chain, host: Self.statsHost(c))
        if case .reject = resolution { return done(false, 0x02) }
        NCConnector.connect(target: c.target, resolution: resolution, queue: queue) { [weak self, weak c] relay, _ in
            guard let self, let c, !c.closed else {
                relay?.cancel()
                return
            }
            guard let relay else {
                done(false, 0x05)
                return
            }
            c.relay = relay
            done(true, 0)
            self.startPumps(c)
        }
    }

    private func awaitClientHello(_ c: Conn, host: String) {
        guard c.buf.isEmpty || c.buf.first == 0x16, c.buf.count < 5 || !Self.helloComplete(c.buf) else {
            return mitm(c, host: host)
        }
        c.client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak c] data, _, isComplete, error in
            guard let self, let c, !c.closed else { return }
            if let data, !data.isEmpty {
                c.buf.append(data)
                if c.buf.first != 0x16 || Self.helloComplete(c.buf) || c.buf.count > 16 * 1024 {
                    self.mitm(c, host: host)
                } else {
                    self.awaitClientHello(c, host: host)
                }
            } else if isComplete || error != nil {
                self.close(c)
            } else {
                self.awaitClientHello(c, host: host)
            }
        }
    }

    /// The first TLS record is in (its length field is satisfied).
    private static func helloComplete(_ d: Data) -> Bool {
        let b = [UInt8](d.prefix(5))
        guard b.count == 5 else { return false }
        return d.count >= 5 + (Int(b[3]) << 8 | Int(b[4]))
    }

    private func mitm(_ c: Conn, host: String) {
        var alpn = ""
        if case .tls(_, let a) = NCSniffer.detect(c.buf) { alpn = a.joined(separator: ",") }
        let mitmPort = c.buf.first == 0x16 ? MitmTLSFront.shared.listen(host: host, alpn: alpn) : 0
        guard mitmPort > 0 else {
            // Front declined (budget, no CA, not TLS): route the connection normally; the success reply is out.
            open(c) { [weak self] ok, _ in if !ok { self?.close(c) } }
            return
        }
        c.chain = "MITM"
        c.rule = "MITM"
        c.flow.open(rule: "MITM", policy: NCStatsRecorder.engineOutbound, chain: "MITM", host: host)
        let stream = NCStream(to: "127.0.0.1", port: Int(mitmPort), queue: queue)
        stream.start { [weak self, weak c] err in
            guard let self, let c, !c.closed else {
                stream.cancel()
                return
            }
            if err != nil { return self.close(c) }
            c.relay = stream
            self.startPumps(c)
        }
    }

    // MARK: relay

    private func startPumps(_ c: Conn) {
        if !c.buf.isEmpty {
            count(c, up: c.buf.count)
            c.relay?.send(c.buf)
            c.buf = Data()
        }
        pumpUp(c)
        pumpDown(c)
    }

    private func pumpUp(_ c: Conn) {
        c.client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak c] data, _, isComplete, error in
            guard let self, let c, !c.closed else { return }
            let finished = isComplete || error != nil
            if let data, !data.isEmpty, let relay = c.relay {
                self.count(c, up: data.count)
                // rv2-life: back-pressure, symmetric with pumpDown — the next client read waits until the
                // relay's send completion fires for this chunk (nc-sessions-flow: every NCRelayStream has one).
                NCRelayFlow.send(relay, data, queue: self.queue) { [weak self, weak c] in
                    guard let self, let c, !c.closed else { return }
                    if finished { self.close(c) } else { self.pumpUp(c) }
                }
                return
            }
            if finished {
                self.close(c)
                return
            }
            self.pumpUp(c)
        }
    }

    private func pumpDown(_ c: Conn) {
        c.relay?.receive { [weak self, weak c] data, _ in
            guard let self, let c, !c.closed else { return }
            guard let data, !data.isEmpty else {
                // Upstream EOF / error: finish the client side after what was already queued.
                c.client.send(content: nil, contentContext: .finalMessage, isComplete: true,
                              completion: .contentProcessed { [weak self] _ in self?.queue.async { self?.close(c) } })
                return
            }
            self.count(c, down: data.count)
            // Back-pressure: next upstream read once the client took this chunk.
            c.client.send(content: data, completion: .contentProcessed { [weak self, weak c] err in
                guard let self, let c else { return }
                self.queue.async {
                    if err != nil { self.close(c) } else if !c.closed { self.pumpDown(c) }
                }
            })
        }
    }

    private func count(_ c: Conn, up: Int = 0, down: Int = 0) {
        c.up += Int64(up)
        c.down += Int64(down)
        c.flow.count(up: up, down: down)
        totalUp += Int64(up)
        totalDown += Int64(down)
        if c.chain != "DIRECT" {
            totalProxyUp += Int64(up)
            totalProxyDown += Int64(down)
        }
    }

    private func close(_ c: Conn) {
        guard !c.closed else { return }
        c.closed = true
        conns.removeValue(forKey: c.id)
        socksStage.removeValue(forKey: c.id)
        c.flow.close(id: Self.idPrefix + String(c.id), type: c.kind, srcIP: c.sourceIP, srcPort: Int(c.sourcePort) ?? 0,
                     dstIP: c.target.ip != nil ? c.target.host : "", dstPort: c.target.port, remote: c.target.host,
                     start: c.start)
        c.relay?.cancel()
        c.relay = nil
        c.client.stateUpdateHandler = nil
        c.client.cancel()
    }

    // MARK: stats

    /// The App's ConnectionAnalytics.hostName: the requested domain, else the destination IP.
    private static func statsHost(_ c: Conn) -> String {
        if let d = c.ruleDomain, !d.isEmpty { return d }
        return c.target.host
    }

    private func refreshStats() {
        // fix/nc-tails: per-host / per-policy growth since the last tick (totals already reach the speed series
        // through stats.updateLocal → NCDataPlaneStats.snapshot).
        var batch: [(policy: String, host: String, up: Int64, down: Int64)] = []
        for c in conns.values { if let p = c.flow.takePending() { batch.append(p) } }
        NCStatsRecorder.shared.bytesBatch(batch)
        let fmt = Self.isoFormatter
        let list: [[String: Any]] = conns.values.filter { !$0.chain.isEmpty }.map { c in
            [
                "id": Self.idPrefix + String(c.id),
                "metadata": [
                    "network": "tcp",
                    "type": c.kind,
                    "sourceIP": c.sourceIP,
                    "sourcePort": c.sourcePort,
                    "destinationIP": c.target.ip != nil ? c.target.host : "",
                    "destinationPort": String(c.target.port),
                    "host": c.ruleDomain ?? "",
                    "sniffHost": "",
                    "process": "",
                    "remoteDestination": c.target.host,
                ],
                "upload": c.up,
                "download": c.down,
                "start": fmt.string(from: c.start),
                "chains": [c.chain],
                "rule": c.rule,
                "rulePayload": "",
            ]
        }
        stats.updateLocal(connections: list, up: totalUp, down: totalDown, proxyUp: totalProxyUp, proxyDown: totalProxyDown)
    }
}
