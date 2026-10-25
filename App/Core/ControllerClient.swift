import Foundation

/// Talks to mihomo's external-controller (127.0.0.1:<port>, Bearer secret) inside the tunnel.
final class ControllerClient {
    static let shared = ControllerClient()

    private let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 8
        c.connectionProxyDictionary = [:]
        return URLSession(configuration: c)
    }()

    /// v0.19.2: port + secret, re-read at most every 3 s. Every request used to call CoreOverrides.load() twice
    /// (two Keychain reads and a file read, sometimes a write) — dozens of times a second with the 1 s polls of
    /// 请求 / 日志 / 首页 open.
    private struct Credentials { var port: Int; var secret: String; var at: Date }
    private let credLock = NSLock()
    private var cached: Credentials?
    private var credentials: Credentials {
        credLock.lock(); defer { credLock.unlock() }
        if let c = cached, Date().timeIntervalSince(c.at) < 3 { return c }
        let o = CoreOverrides.load()
        let c = Credentials(port: o.controllerPort, secret: o.secret, at: Date())
        cached = c
        return c
    }
    /// Drops the cached port / secret (after the controller settings changed).
    func invalidateCredentials() { credLock.lock(); cached = nil; credLock.unlock() }

    var base: String { "http://127.0.0.1:\(credentials.port)" }

    enum APIError: LocalizedError {
        case http(Int, String)
        case badURL
        case unreachable
        case timedOut
        /// v0.11: readable Chinese messages instead of "HTTP 404 {…}".
        var errorDescription: String? {
            switch self {
            case let .http(c, m):
                let detail = Self.detail(m)
                switch c {
                case 401, 403: return String(localized: "内核拒绝了请求（密钥不匹配）。断开后重新连接一次。")
                case 404:
                    // v0.19.8: mihomo answers {"message":"resource not found"} when the NAME (node, group,
                    // provider) is not in the running config; only a missing route is an old extension.
                    if Self.isResourceNotFound(m) {
                        return String(localized: "内核里找不到这个节点或策略组，配置可能已变更，重新加载后再试。")
                    }
                    return detail.isEmpty || detail.lowercased().contains("not found")
                        ? String(localized: "内核没有这个接口：扩展可能还在运行旧版本，断开后重新连接一次。") : detail
                case 503: return detail.lowercased().contains("engine not running")
                    ? String(localized: "脚本引擎未运行：先在「工具 → 重写」开启重写与脚本，再重新连接。") : String(localized: "内核暂时不可用：\(detail)")
                case 408, 504: return String(localized: "请求超时：\(detail)")
                default: return detail.isEmpty ? "HTTP \(c)" : String(localized: "内核返回错误（HTTP \(c)）：\(detail)")
                }
            case .badURL: return String(localized: "控制器地址无效")
            case .unreachable: return String(localized: "连不上内核：VPN 未连接，或扩展刚刚退出。")
            case .timedOut: return String(localized: "内核没有及时响应，请稍后再试。")
            }
        }

        /// mihomo's ErrNotFound ({"message":"resource not found"}): the route exists, the name does not.
        static func isResourceNotFound(_ body: String) -> Bool {
            detail(body).lowercased() == "resource not found"
        }

        /// mihomo answers {"message": "…"}; plain text otherwise (trimmed).
        static func detail(_ body: String) -> String {
            if let d = body.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let m = (o["message"] ?? o["error"]) as? String {
                return m
            }
            let t = body.trimmingCharacters(in: .whitespacesAndNewlines)
            return t.count > 200 ? String(t.prefix(200)) + "…" : t
        }
    }

    private func request(_ path: String, method: String = "GET", query: [URLQueryItem] = [], body: Any? = nil, timeout: TimeInterval = 8) throws -> URLRequest {
        guard var comps = URLComponents(string: base) else { throw APIError.badURL }
        comps.percentEncodedPath = path
        if !query.isEmpty { comps.percentEncodedQuery = Self.query(query.map { ($0.name, $0.value ?? "") }) }
        guard let url = comps.url else { throw APIError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = timeout
        req.setValue("Bearer \(credentials.secret)", forHTTPHeaderField: "Authorization")
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    @discardableResult
    func send(_ path: String, method: String = "GET", query: [URLQueryItem] = [], body: Any? = nil, timeout: TimeInterval = 8) async throws -> Data {
        let req = try request(path, method: method, query: query, body: body, timeout: timeout)
        let data: Data, resp: URLResponse
        do {
            (data, resp) = try await session.data(for: req)
        } catch let e as URLError {
            switch e.code {
            case .cannotConnectToHost, .networkConnectionLost, .notConnectedToInternet, .cannotFindHost: throw APIError.unreachable
            case .timedOut: throw APIError.timedOut
            default: throw e
            }
        }
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw APIError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }

    /// Streams a response body line by line (NDJSON endpoints such as /tools/speed).
    func lines(_ path: String, query: [URLQueryItem] = [], timeout: TimeInterval = 120) async throws -> AsyncLineSequence<URLSession.AsyncBytes> {
        let req = try request(path, query: query, timeout: timeout)
        let (bytes, resp) = try await session.bytes(for: req)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw APIError.http(http.statusCode, "")
        }
        return bytes.lines
    }

    func get<T: Decodable>(_ type: T.Type, _ path: String, query: [URLQueryItem] = [], timeout: TimeInterval = 8) async throws -> T {
        let data = try await send(path, query: query, timeout: timeout)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// RFC 3986 unreserved characters only; everything else (emoji, spaces, "/", "+", "&", "%" …) is
    /// percent-encoded as UTF-8. The core unescapes path parameters with url.PathUnescape.
    static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
    }

    /// Query string with every value strictly encoded (URLQueryItem leaves "&", "+" and "=" alone).
    static func query(_ items: [(String, String)]) -> String {
        items.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&")
    }

    // MARK: API

    func version() async throws -> String {
        let data = try await send("/version")
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return obj?["version"] as? String ?? "?"
    }

    func proxies() async throws -> [String: ProxyItem] {
        var p = try await get(ProxiesResponse.self, "/proxies").proxies
        // Hide the internal MitM engine outbound and the v0.8 节点探测 group.
        let hiddenNames: Set<String> = ["__MITM__", PolicyProbe.group]
        for n in hiddenNames { p.removeValue(forKey: n) }
        for (k, v) in p where v.all?.contains(where: { hiddenNames.contains($0) }) == true {
            var v2 = v
            v2.all = v.all?.filter { !hiddenNames.contains($0) }
            p[k] = v2
        }
        return p
    }

    // MARK: MitM engine (/mitm on the same controller)

    func mitmStatus() async throws -> MitMStatus { try await get(MitMStatus.self, "/mitm/status") }
    // NativeCore gap C4 (astemo6/Muse NativeCore): the tunnel also keeps finished MitM requests in the App Group ring
    // (NativeRequestLogFile); read it when the controller is not reachable (tunnel off / restarting).
    func mitmRequests(since: Int64 = 0) async throws -> [HTTPRequestSummary] {
        do {
            return try await get([HTTPRequestSummary].self, "/mitm/requests", query: [URLQueryItem(name: "since", value: String(since))])
        } catch {
            let local: [HTTPRequestSummary] = Self.fileRecords(since: since)
            if local.isEmpty { throw error }
            return local
        }
    }
    func mitmRequest(_ id: Int64) async throws -> HTTPRequestDetail {
        do {
            return try await get(HTTPRequestDetail.self, "/mitm/requests/\(id)")
        } catch {
            guard let e = NativeRequestLogFile.entry(id: id), let d = try? JSONEncoder().encode(e),
                  let detail = try? JSONDecoder().decode(HTTPRequestDetail.self, from: d) else { throw error }
            return detail
        }
    }
    func mitmClearRequests() async throws {
        NativeRequestLogFile.clear()
        try await send("/mitm/requests", method: "DELETE")
    }
    private static func fileRecords<T: Decodable>(since: Int64) -> [T] {
        let dec = JSONDecoder()
        return NativeRequestLogFile.entries(since: since).compactMap { e in
            (try? JSONEncoder().encode(e)).flatMap { try? dec.decode(T.self, from: $0) }
        }
    }
    func mitmHosts() async throws -> [String: [String]] { try await get([String: [String]].self, "/mitm/hosts") }
    func mitmLogs(since: Int64 = 0) async throws -> [ScriptLogLine] {
        try await get([ScriptLogLine].self, "/mitm/logs", query: [URLQueryItem(name: "since", value: String(since))])
    }
    func mitmClearLogs() async throws { try await send("/mitm/logs", method: "DELETE") }

    // MARK: v0.19.8 log history (/hark/logs, bridge/logring.go)

    /// The extension keeps the general log and the DNS queries from tunnel start; the pages read this first and
    /// then attach the live /logs stream.
    func harkLogs(kind: String, since: UInt64 = 0, level: String? = nil) async throws -> HarkLogHistory {
        var q = [URLQueryItem(name: "kind", value: kind), URLQueryItem(name: "since", value: String(since))]
        if let level { q.append(URLQueryItem(name: "level", value: level)) }
        return try await get(HarkLogHistory.self, "/hark/logs", query: q)
    }
    func harkClearLogs(kind: String) async throws {
        try await send("/hark/logs", method: "DELETE", query: [URLQueryItem(name: "kind", value: kind)])
    }
    func mitmRefresh(url: String) async throws { try await send("/mitm/refresh", method: "POST", body: ["url": url], timeout: 40) }

    func select(group: String, node: String) async throws {
        try await send("/proxies/\(Self.enc(group))", method: "PUT", body: ["name": node])
    }

    /// v0.19 切换节点或模式时断开所有连接 (更多 → 内核设置, on by default): open connections keep the node
    /// they were made with, so a user switch closes them and apps reconnect through the new choice.
    /// v0.19.3: stored in the App Group defaults (was UserDefaults.standard), so the widget / Control
    /// Center mode switch follows the same setting instead of always closing every connection.
    static let closeOnSwitchKey = "switch.closeConnections"
    static var closeOnSwitch: Bool { AppShared.defaults.object(forKey: closeOnSwitchKey) as? Bool ?? true }

    /// Moves a value saved by v0.19.0–v0.19.2 (standard defaults) into the App Group once.
    static func migrateCloseOnSwitch() {
        guard AppShared.defaults.object(forKey: closeOnSwitchKey) == nil,
              let old = UserDefaults.standard.object(forKey: closeOnSwitchKey) as? Bool else { return }
        AppShared.defaults.set(old, forKey: closeOnSwitchKey)
        UserDefaults.standard.removeObject(forKey: closeOnSwitchKey)
    }

    /// A node / mode change the user made: closes every connection when that setting is on.
    func afterUserSwitch() async {
        if Self.closeOnSwitch { try? await closeAllConnections() }
    }

    /// 固定 (v0.8): url-test / fallback groups accept PUT /proxies/{group} too; the core then uses that member
    /// until DELETE /proxies/{group} (解除固定). Stored by the core's cache file, so it survives a reconnect.
    func pin(group: String, node: String) async throws {
        try await send("/proxies/\(Self.enc(group))", method: "PUT", body: ["name": node])
    }

    func unpin(group: String) async throws {
        try await send("/proxies/\(Self.enc(group))", method: "DELETE")
    }

    static let testURL = CoreOverrides.defaultTestURL

    /// 测速 settings (更多 → 测速). Group testUrl from /proxies is NOT used: the core reports "" for
    /// groups on the default URL, and an empty url makes every node fail (the v0.6.0 device bug).
    static var testSettings: (url: String, timeoutMs: Int) {
        let o = CoreOverrides.load()
        let url = CoreOverrides.isValidTestURL(o.testURL) ? o.testURL.trimmingCharacters(in: .whitespaces) : CoreOverrides.defaultTestURL
        return (url, min(max(o.testTimeoutMs, 1000), 30000))
    }

    /// 测速设置 → 直连测试地址: the URL a test of DIRECT uses; nil = 测速地址.
    static var directTestURL: String? {
        let u = CoreOverrides.load().directTestURL.trimmingCharacters(in: .whitespaces)
        return !u.isEmpty && CoreOverrides.isValidTestURL(u) ? u : nil
    }

    /// 测速设置 → TCP 握手延迟: TCP nodes report the TCP connect time to their server (bridge netextras.go).
    static var tcpHandshake: Bool { CoreOverrides.load().tcpHandshakeDelay }

    enum DelayResult {
        /// name → ms for members that answered; members missing from the map timed out.
        case measured([String: Int])
        /// The core answered 504: every member timed out.
        case allTimedOut
    }

    /// GET /group/{name}/delay. Tests every member in parallel inside the core (through each node).
    func groupDelay(_ group: String, url: String? = nil, timeoutMs: Int? = nil) async throws -> DelayResult {
        let st = Self.testSettings
        let ms = timeoutMs ?? st.timeoutMs
        do {
            let data = try await send("/group/\(Self.enc(group))/delay", query: [
                URLQueryItem(name: "url", value: url ?? st.url), URLQueryItem(name: "timeout", value: String(ms)),
            ], timeout: TimeInterval(ms) / 1000 + 10)
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            return .measured(obj.compactMapValues { ($0 as? NSNumber)?.intValue })
        } catch APIError.http(504, _) {
            return .allTimedOut
        }
    }

    /// v0.15.2: tests the given members with at most `limit` (10) running at once (GET /proxies/{name}/delay
    /// each) instead of GET /group/{name}/delay, which starts every member at the same moment inside the
    /// memory-limited extension (CPU / GC contention inflates the measured round trip) and also clears
    /// the 固定 node of a url-test / fallback group. Returns name → ms, 0 = timeout / failure.
    func membersDelay(_ members: [String], limit: Int = 10, url: String? = nil, timeoutMs: Int? = nil) async throws -> [String: Int] {
        var out: [String: Int] = [:]
        var firstError: Error?
        var errors = 0
        var notFound: [String] = []
        let width = max(1, limit)
        // v0.19.8: nodes of proxy-providers (node subscriptions, 配置里的订阅) are not in GET /proxies/{name}
        // (mihomo's route only looks at the config's own proxies and groups) — every one of them answered 404 and
        // the whole test failed. They are tested through /providers/proxies/{provider}/{name}/healthcheck.
        let providerOf = await providerIndex()
        let run: (String) async -> (String, Int, Error?) = { name in
            // v0.17: a node's own test URL (按节点设置) wins unless the caller fixed one.
            do {
                let u = url ?? NodeSettingsStore.testURL(for: name)
                return (name, try await self.proxyDelay(name, url: u, timeoutMs: timeoutMs, provider: providerOf[name], resolved: true), nil)
            } catch { return (name, 0, error) }
        }
        // Sliding window: a new member starts as soon as one finishes, never more than `width` at once.
        await withTaskGroup(of: (String, Int, Error?).self) { tg in
            var next = 0
            while next < min(width, members.count) {
                let name = members[next]
                next += 1
                tg.addTask { await run(name) }
            }
            while let r = await tg.next() {
                let (name, ms, err) = r
                out[name] = ms
                if let err {
                    errors += 1
                    if case APIError.http(404, let body) = err, APIError.isResourceNotFound(body) { notFound.append(name) }
                    if firstError == nil { firstError = err }
                }
                if next < members.count {
                    let n2 = members[next]
                    next += 1
                    tg.addTask { await run(n2) }
                }
            }
        }
        // Every request failed at the HTTP level (not a node timeout): the controller is unreachable.
        // selftest: before, one failed request (e.g. a node renamed since the list loaded) plus timeouts for
        // the rest threw away every result and showed an error instead of the timeouts.
        if let firstError, errors == members.count {
            // A member the core does not know counts as a failed member; only when nothing could be tested say why.
            if notFound.count == members.count, let first = members.first { throw DelayError.nodeNotFound(first) }
            throw firstError
        }
        return out
    }

    enum DelayError: LocalizedError {
        case nodeNotFound(String)
        var errorDescription: String? {
            switch self {
            case .nodeNotFound(let n): return String(localized: "内核里找不到节点「\(n)」，配置可能已变更，重新加载后再试")
            }
        }
    }

    /// Node name → the proxy-provider that holds it (first one wins), from GET /providers/proxies.
    /// Cached 5 s (a 全部测速 in 节点管理 tests node by node).
    func providerIndex() async -> [String: String] {
        credLock.lock()
        let c = providerIndexCache
        credLock.unlock()
        if let c, Date().timeIntervalSince(c.at) < 5 { return c.map }
        guard let list = try? await proxyProviders() else { return [:] }
        var m: [String: String] = [:]
        for pv in list { for p in pv.proxies ?? [] where m[p.name] == nil { m[p.name] = pv.name } }
        credLock.lock(); providerIndexCache = (Date(), m); credLock.unlock()
        return m
    }

    private var providerIndexCache: (at: Date, map: [String: String])?

    /// GET /proxies/{name}/delay for one node; 0 = timeout / failure.
    /// `resolved`: the caller already looked the provider up (nil provider = a config proxy / group).
    func proxyDelay(_ name: String, url: String? = nil, timeoutMs: Int? = nil, provider: String? = nil, resolved: Bool = false) async throws -> Int {
        let st = Self.testSettings
        let ms = timeoutMs ?? st.timeoutMs
        // v0.19.8: a provider node is only reachable under its provider (see membersDelay). Without a known provider,
        // a 404 "resource not found" from /proxies is retried there once.
        var prov = provider
        if prov == nil, !resolved { prov = await providerIndex()[name] }
        let testURL = url ?? NodeSettingsStore.testURL(for: name)
        var path = prov.map { "/providers/proxies/\(Self.enc($0))/\(Self.enc(name))/healthcheck" } ?? "/proxies/\(Self.enc(name))/delay"
        var query = [URLQueryItem(name: "url", value: testURL), URLQueryItem(name: "timeout", value: String(ms))]
        if Self.tcpHandshake {
            // TCP 握手延迟: groups, DIRECT and UDP-based nodes still get the URL test from the same endpoint.
            path = "/tern/node-tcp-delay"
            query.append(URLQueryItem(name: "name", value: name))
            if let prov { query.append(URLQueryItem(name: "provider", value: prov)) }
        }
        do {
            let data = try await send(path, query: query, timeout: TimeInterval(ms) / 1000 + 5)
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return (obj?["delay"] as? NSNumber)?.intValue ?? 0
        } catch APIError.http(let code, _) where code == 504 || code == 503 || code == 408 {
            return 0
        }
    }

    func connections() async throws -> ConnectionsResponse {
        try await get(ConnectionsResponse.self, "/connections")
    }

    func closeConnection(_ id: String) async throws { try await send("/connections/\(id)", method: "DELETE") }
    func closeAllConnections() async throws { try await send("/connections", method: "DELETE") }

    func rules() async throws -> [RuleItem] { try await get(RulesResponse.self, "/rules").rules }

    func proxyProviders() async throws -> [ProviderItem] {
        let r = try await get(ProvidersResponse.self, "/providers/proxies")
        // "default" is the built-in provider wrapping inline proxies; hide it.
        // 代理链 copies (tern.chain/…) are part of their chain group, not node sources.
        return r.providers.values.filter { $0.vehicleType != "Compatible" && !ProxyChainStore.isGenerated($0.name) }.sorted { $0.name < $1.name }
    }

    func ruleProviders() async throws -> [ProviderItem] {
        try await get(ProvidersResponse.self, "/providers/rules").providers.values.sorted { $0.name < $1.name }
    }

    func updateProxyProvider(_ name: String) async throws {
        try await send("/providers/proxies/\(Self.enc(name))", method: "PUT", timeout: 30)
    }

    func updateRuleProvider(_ name: String) async throws {
        try await send("/providers/rules/\(Self.enc(name))", method: "PUT", timeout: 30)
    }

    func setMode(_ mode: String) async throws {
        try await send("/configs", method: "PATCH", body: ["mode": mode])
    }

    func configs() async throws -> [String: Any] {
        let data = try await send("/configs")
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    // MARK: WebSocket streams

    /// Streams JSON frames from a websocket endpoint (/traffic, /memory, /logs ...).
    func stream<T: Decodable>(_ path: String, query: [URLQueryItem] = [], as type: T.Type) -> AsyncStream<T> {
        AsyncStream { continuation in
            guard var comps = URLComponents(string: base.replacingOccurrences(of: "http://", with: "ws://")) else {
                continuation.finish()
                return
            }
            comps.percentEncodedPath = path
            comps.queryItems = query + [URLQueryItem(name: "token", value: credentials.secret)]
            guard let wsURL = comps.url else {
                continuation.finish()
                return
            }
            let task = session.webSocketTask(with: wsURL)
            task.resume()
            func receive() {
                task.receive { result in
                    switch result {
                    case .success(let msg):
                        var data: Data?
                        switch msg {
                        case .string(let s): data = s.data(using: .utf8)
                        case .data(let d): data = d
                        @unknown default: data = nil
                        }
                        if let data, let v = try? JSONDecoder().decode(T.self, from: data) {
                            continuation.yield(v)
                        }
                        receive()
                    case .failure:
                        continuation.finish()
                    }
                }
            }
            receive()
            continuation.onTermination = { _ in task.cancel(with: .goingAway, reason: nil) }
        }
    }
}
