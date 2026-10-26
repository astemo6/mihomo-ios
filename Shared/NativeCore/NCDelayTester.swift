import Foundation
import Network
import Security

/// Pure-Swift latency and connectivity tester for outbounds and proxy nodes.
/// Replaces the Go bridge functions (LibmihomoNodeTestDelayIn, LibmihomoNodeTCPDelayIn,
/// LibmihomoTestDelay, LibmihomoTestTCPDelay, LibmihomoTestDelayByName, LibmihomoTCPDelayByName)
/// so latency tests can be performed directly in the app process without Go or tunnel dependency.
enum NCDelayTester {

    // MARK: - Physical Interface Configuration

    private static let lock = NSLock()
    private static var _offlineInterfaceName: String?

    static var offlineInterfaceName: String? {
        get { lock.lock(); defer { lock.unlock() }; return _offlineInterfaceName }
        set { lock.lock(); defer { lock.unlock() }; _offlineInterfaceName = newValue }
    }

    /// Records the physical interface (en0 / pdp_ip0) to bind sockets to for offline tests,
    /// preventing test traffic from routing into another app's active VPN tunnel.
    static func setOfflineInterface(_ iface: String) {
        offlineInterfaceName = iface.isEmpty ? nil : iface
    }

    // MARK: - Synchronous API (for BlockingWork.run / background GCD workers)

    /// HTTP delay test on a raw proxy spec JSON (returns ms, or -1 on error/timeout).
    static func testDelay(proxyJSON: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            testDelayAsync(proxyJSON: proxyJSON, url: url, timeoutMs: timeoutMs, completion: done)
        }
    }

    /// TCP handshake delay test on a raw proxy spec JSON (returns ms, or -1 on error/timeout).
    static func testTCPDelay(proxyJSON: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            testTCPDelayAsync(proxyJSON: proxyJSON, url: url, timeoutMs: timeoutMs, completion: done)
        }
    }

    /// HTTP delay test for a node in a specific provider/source (returns ms, or -1 on error/timeout).
    static func nodeTestDelayIn(homeDir: String, profilePath: String, provider: String, name: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            nodeDelayInAsync(homeDir: homeDir, profilePath: profilePath, provider: provider, name: name, url: url, timeoutMs: timeoutMs, tcp: false, completion: done)
        }
    }

    /// TCP handshake delay test for a node in a specific provider/source (returns ms, or -1 on error/timeout).
    static func nodeTCPDelayIn(homeDir: String, profilePath: String, provider: String, name: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            nodeDelayInAsync(homeDir: homeDir, profilePath: profilePath, provider: provider, name: name, url: url, timeoutMs: timeoutMs, tcp: true, completion: done)
        }
    }

    /// HTTP delay test for a node by name across profile and providers (returns ms, or -1 on error/timeout).
    static func testDelayByName(homeDir: String, profilePath: String, name: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            delayByNameAsync(homeDir: homeDir, profilePath: profilePath, name: name, url: url, timeoutMs: timeoutMs, tcp: false, completion: done)
        }
    }

    /// TCP handshake delay test for a node by name across profile and providers (returns ms, or -1 on error/timeout).
    static func tcpDelayByName(homeDir: String, profilePath: String, name: String, url: String, timeoutMs: Int) -> Int {
        runSync(timeoutMs: timeoutMs) { done in
            delayByNameAsync(homeDir: homeDir, profilePath: profilePath, name: name, url: url, timeoutMs: timeoutMs, tcp: true, completion: done)
        }
    }

    // MARK: - Async API (Swift Concurrency)

    static func testDelayAsync(proxyJSON: String, url: String, timeoutMs: Int) async -> Int {
        await withCheckedContinuation { cont in
            testDelayAsync(proxyJSON: proxyJSON, url: url, timeoutMs: timeoutMs) { cont.resume(returning: $0) }
        }
    }

    static func testTCPDelayAsync(proxyJSON: String, url: String, timeoutMs: Int) async -> Int {
        await withCheckedContinuation { cont in
            testTCPDelayAsync(proxyJSON: proxyJSON, url: url, timeoutMs: timeoutMs) { cont.resume(returning: $0) }
        }
    }

    static func delayByNameAsync(homeDir: String, profilePath: String, name: String, url: String, timeoutMs: Int, tcp: Bool) async -> Int {
        await withCheckedContinuation { cont in
            delayByNameAsync(homeDir: homeDir, profilePath: profilePath, name: name, url: url, timeoutMs: timeoutMs, tcp: tcp) { cont.resume(returning: $0) }
        }
    }

    /// Batch delay test for a group of node names (with concurrency limit).
    static func measureGroupDelay(members: [String], homeDir: String, profilePath: String, url: String, timeoutMs: Int, tcp: Bool, limit: Int = 8) async -> [String: Int] {
        guard !members.isEmpty else { return [:] }
        var results: [String: Int] = [:]
        var idx = 0
        while idx < members.count {
            let batch = Array(members[idx..<min(idx + limit, members.count)])
            idx += batch.count
            let got = await withTaskGroup(of: (String, Int).self, returning: [(String, Int)].self) { tg in
                for m in batch {
                    tg.addTask {
                        let ms = await delayByNameAsync(homeDir: homeDir, profilePath: profilePath, name: m, url: url, timeoutMs: timeoutMs, tcp: tcp)
                        return (m, ms)
                    }
                }
                var out: [(String, Int)] = []
                for await pair in tg { out.append(pair) }
                return out
            }
            for (m, ms) in got { results[m] = ms }
        }
        return results
    }

    // MARK: - Core Test Dispatchers

    private static func runSync(timeoutMs: Int, work: @escaping (@escaping (Int) -> Void) -> Void) -> Int {
        let sem = DispatchSemaphore(value: 0)
        var result = -1
        work { ms in
            result = ms
            sem.signal()
        }
        // fix/nc-delay-2: a URL test may take the cold budget plus the warm request (unified-delay).
        let t = NCTunnelDelayTester.probeWindowMs(timeoutMs: max(timeoutMs, 1000), unified: true) + 500
        _ = sem.wait(timeout: .now() + .milliseconds(t))
        return result
    }

    static func testDelayAsync(proxyJSON: String, url: String, timeoutMs: Int, completion: @escaping (Int) -> Void) {
        guard let proxy = parseProxy(jsonString: proxyJSON) else {
            completion(-1)
            return
        }
        measureHttpDelay(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
    }

    static func testTCPDelayAsync(proxyJSON: String, url: String, timeoutMs: Int, completion: @escaping (Int) -> Void) {
        guard let proxy = parseProxy(jsonString: proxyJSON) else {
            completion(-1)
            return
        }
        measureTCPOrFallback(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
    }

    private static func nodeDelayInAsync(homeDir: String, profilePath: String, provider: String, name: String, url: String, timeoutMs: Int, tcp: Bool, completion: @escaping (Int) -> Void) {
        guard let proxy = NCNodeResolver.shared.resolve(homeDir: homeDir, profilePath: profilePath, provider: provider, name: name) else {
            completion(-1)
            return
        }
        if tcp {
            measureTCPOrFallback(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
        } else {
            measureHttpDelay(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
        }
    }

    private static func delayByNameAsync(homeDir: String, profilePath: String, name: String, url: String, timeoutMs: Int, tcp: Bool, completion: @escaping (Int) -> Void) {
        guard let proxy = NCNodeResolver.shared.resolveByName(homeDir: homeDir, profilePath: profilePath, name: name) else {
            completion(-1)
            return
        }
        if tcp {
            measureTCPOrFallback(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
        } else {
            measureHttpDelay(proxy: proxy, url: url, timeoutMs: timeoutMs, completion: completion)
        }
    }

    // MARK: - HTTP Probing

    private static func measureHttpDelay(proxy: NCProxy, url: String, timeoutMs: Int, completion: @escaping (Int) -> Void) {
        let timeout = timeoutMs <= 0 ? 5000 : timeoutMs
        // Tailscale nodes cannot be dialed offline in app process
        if proxy.type == "tailscale" {
            completion(-1)
            return
        }
        guard let target = httpTarget(url) else {
            completion(-1)
            return
        }

        let workQueue = DispatchQueue(label: "nc.delay.http", qos: .userInitiated)
        let start = DispatchTime.now()
        var finished = false
        var activeStream: NCRelayStream?

        let finish: (Int) -> Void = { ms in
            workQueue.async {
                guard !finished else { return }
                finished = true
                activeStream?.cancel()
                activeStream = nil
                completion(ms)
            }
        }

        // fix/nc-delay-2: same accounting as the tunnel's probe (NCTunnelDelayTester, mihomo unified-delay, which
        // Tern always sets): the cold phase (dial + inner TLS + first request) gets max(timeout, 5000); the reported
        // value is the second request on the warm connection, bounded by `timeout`. Offline tests used to time the
        // cold dial against `timeout` alone, so a CDN node on a high-RTT network always showed 超时.
        let coldTimer = DispatchWorkItem { finish(-1) }
        workQueue.asyncAfter(deadline: .now() + .milliseconds(NCTunnelDelayTester.coldBudgetMs(timeoutMs: timeout, unified: true)),
                             execute: coldTimer)
        let probeHttp: (NCRelayStream, (host: String, port: Int, tls: Bool, path: String), DispatchTime, @escaping (Int) -> Void) -> Void = { stream, target, start, finish in
            let ex = NCTunnelDelayTester.HTTPExchange(relay: stream, target: target, unified: true, trace: nil, start: start) { ms, _ in
                finish(ms.map { max(1, $0) } ?? -1)
            }
            ex.warmTimeoutMs = timeout
            ex.timerQueue = workQueue
            ex.onWarmStart = { coldTimer.cancel() }
            ex.run()
        }

        if proxy.type == "direct" {
            let stream = target.tls
                ? NCStream(to: target.host, port: target.port, tlsServerName: target.host, allowInsecure: false, queue: workQueue)
                : NCStream(to: target.host, port: target.port, queue: workQueue)
            activeStream = stream
            stream.start { err in
                if err != nil { finish(-1); return }
                probeHttp(stream, target, start, finish)
            }
            return
        }

        if proxy.type == "reject" || proxy.type == "reject-drop" {
            finish(-1)
            return
        }

        let targetDesc = NCTarget(host: target.host, port: target.port)
        NCConnector.connect(target: targetDesc, proxy: proxy, queue: workQueue) { relay, error in
            guard let relay, error == nil else {
                finish(-1)
                return
            }
            activeStream = relay
            if target.tls {
                let tls = NCTLSClientStream(raw: relay, config: .init(serverName: target.host, alpn: ["http/1.1"]), queue: workQueue)
                activeStream = tls
                tls.startHandshake { err in
                    if err != nil { finish(-1); return }
                    probeHttp(tls, target, start, finish)
                }
            } else {
                probeHttp(relay, target, start, finish)
            }
        }
    }

    // MARK: - TCP Handshake Probing

    private static func measureTCPOrFallback(proxy: NCProxy, url: String, timeoutMs: Int, completion: @escaping (Int) -> Void) {
        let timeout = timeoutMs <= 0 ? 5000 : timeoutMs
        // If not a TCP transport protocol, or behind a dialer-proxy chain, fall back to URL test
        if !isTCPTransport(proxy.type) || (proxy.fields["dialer-proxy"]?.string?.isEmpty == false) {
            measureHttpDelay(proxy: proxy, url: url, timeoutMs: timeout, completion: completion)
            return
        }

        guard let server = proxy.server, !server.isEmpty,
              let port = proxy.port, port > 0, port <= 65535 else {
            completion(-1)
            return
        }

        let workQueue = DispatchQueue(label: "nc.delay.tcp", qos: .userInitiated)
        var finished = false
        var activeConn: NWConnection?

        let finish: (Int) -> Void = { ms in
            workQueue.async {
                guard !finished else { return }
                finished = true
                activeConn?.cancel()
                activeConn = nil
                completion(ms)
            }
        }

        workQueue.asyncAfter(deadline: .now() + .milliseconds(timeout)) {
            finish(-1)
        }

        workQueue.async {
            // DNS resolution is performed before starting the connection timer (mirrors Go tcpHandshake)
            let ip = resolveIP(server) ?? server
            let start = Date()

            let endpoint = NCStream.endpoint(ip, port: port)
            let tcpOptions = NWProtocolTCP.Options()
            let params = NWParameters(tls: nil, tcp: tcpOptions)
            params.prohibitedInterfaceTypes = [.other, .loopback]

            let conn = NWConnection(to: endpoint, using: params)
            activeConn = conn

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let ms = max(1, Int(Date().timeIntervalSince(start) * 1000))
                    finish(ms)
                case .failed, .cancelled:
                    finish(-1)
                default:
                    break
                }
            }
            conn.start(queue: workQueue)
        }
    }

    // MARK: - Helpers

    static func isTCPTransport(_ type: String) -> Bool {
        switch type.lowercased().trimmingCharacters(in: .whitespaces) {
        case "ss", "shadowsocks", "ssr", "shadowsocksr", "snell", "socks5", "socks", "http", "vmess", "vless", "trojan", "ssh", "anytls":
            return true
        default:
            return false
        }
    }

    static func httpTarget(_ urlString: String) -> (host: String, port: Int, tls: Bool, path: String)? {
        guard let url = URL(string: urlString), let host = url.host else { return nil }
        let tls = url.scheme?.lowercased() == "https"
        let port = url.port ?? (tls ? 443 : 80)
        var path = url.path.isEmpty ? "/" : url.path
        if let q = url.query, !q.isEmpty { path += "?" + q }
        return (host, port, tls, path)
    }

    static func parseProxy(jsonString: String) -> NCProxy? {
        guard let data = jsonString.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return nil
        }
        return parseProxy(dict: obj)
    }

    static func parseProxy(dict: [String: Any]) -> NCProxy? {
        guard let type = (dict["type"] as? String)?.lowercased() else { return nil }
        let name = (dict["name"] as? String) ?? (dict["name"] as? NSNumber)?.stringValue ?? "node"
        let fields = dict.mapValues(NCJSONValue.init)
        return NCProxy(name: name, type: type, fields: fields)
    }

    private static func resolveIP(_ host: String) -> String? {
        if IPv4Address(host) != nil || IPv6Address(host) != nil { return host }
        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        if getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
            return String(cString: buf)
        }
        return nil
    }
}

// MARK: - Node Resolver & Profile Cache

final class NCNodeResolver {
    static let shared = NCNodeResolver()
    private let lock = NSLock()

    struct CachedProfile {
        var mtime: Date
        /// mtime of the manual-nodes store (a manual node added / edited must not resolve from a stale cache).
        var manualMtime: Date = .distantPast
        var profileProxies: [String: NCProxy]
        var providers: [String: [String: NCProxy]]
        var allNamedProxies: [String: NCProxy]
    }

    private var cache: [String: CachedProfile] = [:]

    func resolve(homeDir: String, profilePath: String, provider: String, name: String) -> NCProxy? {
        lock.lock()
        defer { lock.unlock() }
        let cp = cachedProfile(homeDir: homeDir, profilePath: profilePath)
        if provider.isEmpty {
            return cp.profileProxies[name]
        }
        return cp.providers[provider]?[name]
    }

    func resolveByName(homeDir: String, profilePath: String, name: String) -> NCProxy? {
        lock.lock()
        defer { lock.unlock() }
        let cp = cachedProfile(homeDir: homeDir, profilePath: profilePath)
        if let p = cp.profileProxies[name] {
            return p
        }
        return cp.allNamedProxies[name]
    }

    private func cachedProfile(homeDir: String, profilePath: String) -> CachedProfile {
        let fm = FileManager.default
        let attrs = (try? fm.attributesOfItem(atPath: profilePath)) ?? [:]
        let mtime = (attrs[.modificationDate] as? Date) ?? Date.distantPast

        let manualPath = Self.manualNodesPath(home: homeDir)
        let manualMtime = ((try? fm.attributesOfItem(atPath: manualPath))?[.modificationDate] as? Date) ?? Date.distantPast

        if let existing = cache[profilePath], existing.mtime == mtime, existing.manualMtime == manualMtime {
            return existing
        }

        var profileProxies: [String: NCProxy] = [:]
        var providers: [String: [String: NCProxy]] = [:]
        var allNamedProxies: [String: NCProxy] = [:]

        // 1. Profile YAML
        if let text = try? String(contentsOfFile: profilePath, encoding: .utf8),
           let root = NCYAML.parse(text)?.object {

            if let list = root["proxies"]?.array {
                for item in list {
                    if let p = makeProxy(from: item) {
                        profileProxies[p.name] = p
                        allNamedProxies[p.name] = p
                    }
                }
            }

            if let provObj = root["proxy-providers"]?.object {
                for (pvName, pvVal) in provObj {
                    guard let pv = pvVal.object else { continue }
                    var pvNodes: [String: NCProxy] = [:]
                    let type = pv["type"]?.string?.lowercased() ?? ""

                    if type == "inline" {
                        if let pl = pv["payload"]?.array ?? pv["payload"]?.object?["proxies"]?.array {
                            for item in pl {
                                if let p = makeProxy(from: item) {
                                    pvNodes[p.name] = p
                                    allNamedProxies[p.name] = allNamedProxies[p.name] ?? p
                                }
                            }
                        }
                    } else if let path = pv["path"]?.string {
                        let full = path.hasPrefix("/") ? path : (homeDir as NSString).appendingPathComponent(path)
                        pvNodes = loadNodesFromFile(full)
                        for (k, v) in pvNodes {
                            allNamedProxies[k] = allNamedProxies[k] ?? v
                        }
                    }
                    providers[pvName] = pvNodes
                }
            }
        }

        // 2. Node subscriptions from <home>/node-subscriptions.json
        let subsURL = URL(fileURLWithPath: homeDir).appendingPathComponent("node-subscriptions.json")
        if let data = try? Data(contentsOf: subsURL),
           let subs = try? JSONDecoder().decode([NodeSubInfo].self, from: data) {
            for sub in subs where sub.enabled {
                let cacheURL = URL(fileURLWithPath: homeDir).appendingPathComponent("nodesubs/\(sub.id).yaml")
                let subNodes = loadNodesFromFile(cacheURL.path)
                providers[sub.name] = subNodes
                providers[sub.id] = subNodes
                for (k, v) in subNodes {
                    allNamedProxies[k] = allNamedProxies[k] ?? v
                }
            }
        }

        // 3. Manual nodes. rv2: the App keeps them in the manual profile <container>/profiles/manual-nodes.yaml
        // (NCManualNodes / AppShared.profileURL(id: "manual-nodes"), bridge runtimeinputs.go manualNodesPath) —
        // nothing ever wrote the <home>/manual-nodes.json this used to read, so manual nodes never resolved here.
        if !manualPath.isEmpty, manualPath != profilePath {
            for (_, p) in loadNodesFromFile(manualPath).sorted(by: { $0.key < $1.key }) {
                if profileProxies[p.name] == nil {
                    profileProxies[p.name] = p
                }
                allNamedProxies[p.name] = allNamedProxies[p.name] ?? p
            }
        }

        // 4. Cached provider files in <home>/proxies/
        let proxiesDir = URL(fileURLWithPath: homeDir).appendingPathComponent("proxies")
        if let files = try? fm.contentsOfDirectory(at: proxiesDir, includingPropertiesForKeys: nil) {
            for file in files {
                let nodes = loadNodesFromFile(file.path)
                if !nodes.isEmpty {
                    let key = file.deletingPathExtension().lastPathComponent
                    if providers[key] == nil {
                        providers[key] = nodes
                    }
                    for (k, v) in nodes {
                        allNamedProxies[k] = allNamedProxies[k] ?? v
                    }
                }
            }
        }

        let cp = CachedProfile(mtime: mtime,
                               manualMtime: manualMtime,
                               profileProxies: profileProxies,
                               providers: providers,
                               allNamedProxies: allNamedProxies)
        cache[profilePath] = cp
        return cp
    }

    private struct NodeSubInfo: Decodable {
        var id: String
        var name: String
        var enabled: Bool
    }

    private func makeProxy(from val: NCJSONValue) -> NCProxy? {
        guard let obj = val.object,
              let name = obj["name"]?.string,
              let type = obj["type"]?.string?.lowercased() else {
            return nil
        }
        return NCProxy(name: name, type: type, fields: obj)
    }

    /// Same path as the App's NCRuntimeOverrides.manualNodesPath (bridge runtimeinputs.go):
    /// filepath.Join(filepath.Dir(home), "profiles", "manual-nodes.yaml"). Duplicated here because NCDelayTester is
    /// Shared and NCRuntimeOverrides is App-only; keep the two in step.
    static func manualNodesPath(home: String) -> String {
        if home.isEmpty { return "" }
        let dir: String
        if let r = home.range(of: "/", options: .backwards) {
            let head = String(home[home.startIndex..<r.lowerBound])
            dir = head.isEmpty ? "/" : head
        } else {
            dir = "."
        }
        if dir == "." { return "profiles/manual-nodes.yaml" }
        return ((dir as NSString).appendingPathComponent("profiles") as NSString)
            .appendingPathComponent("manual-nodes.yaml")
    }

    private func loadNodesFromFile(_ path: String) -> [String: NCProxy] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [:] }
        let proxies = NCSubscriptionParser.parse(text)
        var map: [String: NCProxy] = [:]
        for p in proxies {
            map[p.name] = p
        }
        return map
    }
}
