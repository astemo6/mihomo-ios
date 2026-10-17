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

    var overrides: CoreOverrides { CoreOverrides.load() }
    var base: String { "http://127.0.0.1:\(overrides.controllerPort)" }

    enum APIError: LocalizedError {
        case http(Int, String)
        case badURL
        var errorDescription: String? {
            switch self {
            case let .http(c, m): return "HTTP \(c) \(m)"
            case .badURL: return String(localized: "控制器地址无效")
            }
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
        req.setValue("Bearer \(overrides.secret)", forHTTPHeaderField: "Authorization")
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    @discardableResult
    func send(_ path: String, method: String = "GET", query: [URLQueryItem] = [], body: Any? = nil, timeout: TimeInterval = 8) async throws -> Data {
        let req = try request(path, method: method, query: query, body: body, timeout: timeout)
        let (data, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw APIError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        return data
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
        let internal: Set<String> = ["__MITM__", PolicyProbe.group]
        for n in internal { p.removeValue(forKey: n) }
        for (k, v) in p where v.all?.contains(where: { internal.contains($0) }) == true {
            var v2 = v
            v2.all = v.all?.filter { !internal.contains($0) }
            p[k] = v2
        }
        return p
    }

    // MARK: MitM engine (/mitm on the same controller)

    func mitmStatus() async throws -> MitMStatus { try await get(MitMStatus.self, "/mitm/status") }
    func mitmRequests(since: Int64 = 0) async throws -> [HTTPRequestSummary] {
        try await get([HTTPRequestSummary].self, "/mitm/requests", query: [URLQueryItem(name: "since", value: String(since))])
    }
    func mitmRequest(_ id: Int64) async throws -> HTTPRequestDetail { try await get(HTTPRequestDetail.self, "/mitm/requests/\(id)") }
    func mitmClearRequests() async throws { try await send("/mitm/requests", method: "DELETE") }
    func mitmHosts() async throws -> [String: [String]] { try await get([String: [String]].self, "/mitm/hosts") }
    func mitmLogs(since: Int64 = 0) async throws -> [ScriptLogLine] {
        try await get([ScriptLogLine].self, "/mitm/logs", query: [URLQueryItem(name: "since", value: String(since))])
    }
    func mitmClearLogs() async throws { try await send("/mitm/logs", method: "DELETE") }
    func mitmRefresh(url: String) async throws { try await send("/mitm/refresh", method: "POST", body: ["url": url], timeout: 40) }

    func select(group: String, node: String) async throws {
        try await send("/proxies/\(Self.enc(group))", method: "PUT", body: ["name": node])
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

    /// GET /proxies/{name}/delay for one node; 0 = timeout / failure.
    func proxyDelay(_ name: String, url: String? = nil, timeoutMs: Int? = nil) async throws -> Int {
        let st = Self.testSettings
        let ms = timeoutMs ?? st.timeoutMs
        do {
            let data = try await send("/proxies/\(Self.enc(name))/delay", query: [
                URLQueryItem(name: "url", value: url ?? st.url), URLQueryItem(name: "timeout", value: String(ms)),
            ], timeout: TimeInterval(ms) / 1000 + 5)
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
        return r.providers.values.filter { $0.vehicleType != "Compatible" }.sorted { $0.name < $1.name }
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
            comps.queryItems = query + [URLQueryItem(name: "token", value: overrides.secret)]
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
