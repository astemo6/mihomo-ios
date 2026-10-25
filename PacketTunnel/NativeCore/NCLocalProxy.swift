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
/// Not done yet: LAN sharing (allow-lan / lanAuth / lanUsers — the listener is loopback-only, so the 局域网共享
/// switch has no effect on NativeCore), SOCKS5 UDP, SOCKS4, HTTP proxy authentication, keep-alive across requests of a
/// plain-HTTP proxy connection.
final class NCLocalProxy {
    static let idPrefix = "lp"
    static func ownsConnectionID(_ id: String) -> Bool { id.hasPrefix(idPrefix) }

    let port: UInt16
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

    init(engine: NativeCoreEngine, port: Int, stats: NCDataPlaneStats) {
        self.engine = engine
        self.port = UInt16(clamping: port)
        self.stats = stats
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
        init(id: Int, client: NWConnection) { self.id = id; self.client = client }
    }

    // MARK: lifecycle

    /// Starts listening on the loopback interface; waits up to `timeout` for the listener. nil = listening, else the
    /// reason (port in use, …).
    func start(timeout: TimeInterval = 3) -> String? {
        guard port > 0, let nwPort = NWEndpoint.Port(rawValue: port) else { return "端口无效（\(port)）" }
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        params.allowLocalEndpointReuse = true
        let listener: NWListener
        do {
            listener = try NWListener(using: params, on: nwPort)
        } catch {
            return error.localizedDescription
        }
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String?? // nil = no answer yet
        listener.stateUpdateHandler = { [weak self] state in
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
            _ = self
        }
        listener.newConnectionHandler = { [weak self] nw in self?.accept(nw) }
        listener.start(queue: queue)
        _ = sem.wait(timeout: .now() + timeout)
        lock.lock()
        let outcome = result
        lock.unlock()
        switch outcome {
        case .some(.none):
            self.listener = listener
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + 1, repeating: 1)
            t.setEventHandler { [weak self] in self?.refreshStats() }
            t.resume()
            queue.sync { timer = t }
            return nil
        case .some(.some(let why)):
            listener.cancel()
            return why
        case .none:
            listener.cancel()
            return "监听超时"
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        queue.sync {
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
        let c = Conn(id: nextID, client: nw)
        nextID &+= 1
        if case .hostPort(_, let p) = nw.endpoint { c.sourcePort = String(p.rawValue) }
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

    private enum SocksStage { case greeting, request }
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
            guard methods.contains(0x00) else {
                c.client.send(content: Data([0x05, 0xff]), completion: .contentProcessed { [weak self] _ in self?.close(c) })
                return
            }
            c.client.send(content: Data([0x05, 0x00]), completion: .idempotent)
            socksStage[c.id] = .request
            if c.buf.isEmpty { readHead(c) } else { socks(c) }
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

    private func httpError(_ c: Conn, _ code: Int, _ text: String) {
        let body = "\(code) \(text)\n"
        let resp = "HTTP/1.1 \(code) \(text)\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
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
        let (_, rule, resolution) = engine.route(ctx)
        c.rule = rule ?? ""
        c.chain = switch resolution {
        case .direct: "DIRECT"
        case .reject: "REJECT"
        case .proxy(let p): p.name
        case .chain(let ps): ps.map { $0.name }.joined(separator: " -> ")
        case .unknown(let n): n
        }
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
            if let data, !data.isEmpty {
                self.count(c, up: data.count)
                c.relay?.send(data)
            }
            if isComplete || error != nil {
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
        c.relay?.cancel()
        c.relay = nil
        c.client.stateUpdateHandler = nil
        c.client.cancel()
    }

    // MARK: stats

    private func refreshStats() {
        let fmt = Self.isoFormatter
        let list: [[String: Any]] = conns.values.filter { !$0.chain.isEmpty }.map { c in
            [
                "id": Self.idPrefix + String(c.id),
                "metadata": [
                    "network": "tcp",
                    "type": c.kind,
                    "sourceIP": "127.0.0.1",
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
