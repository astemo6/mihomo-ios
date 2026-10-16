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
        var errorDescription: String? {
            switch self { case let .http(c, m): return "HTTP \(c) \(m)" }
        }
    }

    private func request(_ path: String, method: String = "GET", query: [URLQueryItem] = [], body: Any? = nil, timeout: TimeInterval = 8) throws -> URLRequest {
        var comps = URLComponents(string: base)!
        comps.percentEncodedPath = path
        if !query.isEmpty { comps.queryItems = query }
        var req = URLRequest(url: comps.url!)
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

    static func enc(_ s: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/?#%")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    // MARK: API

    func version() async throws -> String {
        let data = try await send("/version")
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return obj?["version"] as? String ?? "?"
    }

    func proxies() async throws -> [String: ProxyItem] {
        try await get(ProxiesResponse.self, "/proxies").proxies
    }

    func select(group: String, node: String) async throws {
        try await send("/proxies/\(Self.enc(group))", method: "PUT", body: ["name": node])
    }

    static let testURL = "https://www.gstatic.com/generate_204"

    func groupDelay(_ group: String, url: String = testURL) async throws -> [String: Int] {
        let data = try await send("/group/\(Self.enc(group))/delay", query: [
            URLQueryItem(name: "url", value: url), URLQueryItem(name: "timeout", value: "5000"),
        ], timeout: 20)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        return obj.compactMapValues { ($0 as? NSNumber)?.intValue }
    }

    func proxyDelay(_ name: String, url: String = testURL) async throws -> Int {
        let data = try await send("/proxies/\(Self.enc(name))/delay", query: [
            URLQueryItem(name: "url", value: url), URLQueryItem(name: "timeout", value: "5000"),
        ], timeout: 10)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (obj?["delay"] as? NSNumber)?.intValue ?? 0
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
            var comps = URLComponents(string: base.replacingOccurrences(of: "http://", with: "ws://"))!
            comps.percentEncodedPath = path
            comps.queryItems = query + [URLQueryItem(name: "token", value: overrides.secret)]
            let task = session.webSocketTask(with: comps.url!)
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
