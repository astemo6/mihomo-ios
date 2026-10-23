import Foundation
import Libmihomo

/// 出口信息查询 (v0.12, QX geo_location_checker). Settings live in the App Group under the same keys as
/// qx/rebuild's 出口位置查询 (IPInfoFetcher.checkerKey / checkerURLKey: "" auto, an endpoint name = preferred,
/// "custom" = the user's JSON API, "disabled" = no lookup). Main adds one optional key on top: a QX
/// geo_location_checker script for the custom API, which turns the API reply into {title, subtitle}
/// (run in the Go script engine, app process).
enum GeoChecker {
    static let scriptKey = "geo.checkerScript"
    static var script: String { AppShared.defaults.string(forKey: scriptKey) ?? "" }
    static var usesScript: Bool {
        IPInfoFetcher.checker == "custom" && !IPInfoFetcher.checkerURL.isEmpty && !script.trimmingCharacters(in: .whitespaces).isEmpty
    }
    static var scriptCache: URL { AppShared.homeURL.appendingPathComponent("geo-checker.js") }

    /// Stores the choice (and clears the cached script when it changed).
    static func save(checker: String, url: String, script newScript: String) {
        let d = AppShared.defaults
        if newScript.trimmingCharacters(in: .whitespaces) != script { try? FileManager.default.removeItem(at: scriptCache) }
        d.set(checker, forKey: IPInfoFetcher.checkerKey)
        d.set(url.trimmingCharacters(in: .whitespacesAndNewlines), forKey: IPInfoFetcher.checkerURLKey)
        d.set(newScript.trimmingCharacters(in: .whitespacesAndNewlines), forKey: scriptKey)
    }

    struct ScriptResult: Decodable { var title: String?; var subtitle: String?; var ip: String?; var error: String? }

    /// Result of the last lookup for the settings page ("" = fine).
    @MainActor static var lastError = ""

    /// Custom API + script; falls back to the built-in endpoints when the custom API gives nothing.
    static func fetchWithScript(timeout: TimeInterval = 8) async -> IPInfo? {
        if let info = await fetchCustom(timeout: timeout) { return info }
        return await IPInfoFetcher.fetch()
    }

    static func fetchCustom(timeout: TimeInterval = 8) async -> IPInfo? {
        let api = IPInfoFetcher.checkerURL
        guard let url = URL(string: api), url.scheme?.hasPrefix("http") == true else { await setError(String(localized: "查询地址无效")); return nil }
        let session = URLSession(configuration: IPInfoFetcher.sessionConfiguration(timeout: timeout))
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: url)
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", forHTTPHeaderField: "User-Agent")
        let result: (Data, URLResponse)
        do {
            result = try await session.data(for: req)
        } catch {
            // Say why (timeout, offline, TLS, host not found) instead of a bare 没有响应 that looks like nothing happened.
            let reason = (error as? URLError).map { e -> String in
                switch e.code {
                case .timedOut: return String(localized: "连接超时")
                case .notConnectedToInternet, .networkConnectionLost: return String(localized: "网络不可用")
                case .cannotFindHost, .dnsLookupFailed: return String(localized: "无法解析域名")
                case .cannotConnectToHost: return String(localized: "无法连接到服务器")
                case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
                     .serverCertificateNotYetValid, .serverCertificateHasUnknownRoot: return String(localized: "TLS 连接失败")
                default: return e.localizedDescription
                }
            } ?? error.localizedDescription
            await setError(String(localized: "查询地址没有响应：\(reason)"))
            return nil
        }
        guard let http = result.1 as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (result.1 as? HTTPURLResponse)?.statusCode ?? 0
            await setError(code == 429 ? String(localized: "查询地址拒绝请求：请求过于频繁（HTTP 429），请稍后再试")
                                       : String(localized: "查询地址返回错误：HTTP \(code)"))
            return nil
        }
        let data = result.0
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        var info = IPInfoFetcher.genericParse(obj, source: url.host ?? "custom")
        if info != nil, info?.timezone == nil { info?.timezone = IPInfoFetcher.str(obj, "timezone", "time_zone") }
        let ref = script.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else {
            await setError(info == nil ? String(localized: "无法识别查询结果，请填写脚本") : "")
            return info
        }
        guard let code = await loadScript(ref, session: session) else {
            await setError(String(localized: "脚本下载失败"))
            return info
        }
        let body = String(decoding: data, as: UTF8.self)
        let home = AppShared.homeURL.path
        let json = await Task.detached { LibmihomoGeoLocationRun(home, code, url.absoluteString, body) }.value
        guard let r = try? JSONDecoder().decode(ScriptResult.self, from: Data(json.utf8)) else { return info }
        if let e = r.error, !e.isEmpty { await setError(e); return info }
        if info == nil, let ip = r.ip, !ip.isEmpty { info = IPInfo(ip: ip, source: url.host) }
        info?.customTitle = r.title
        if let sub = r.subtitle, !sub.isEmpty { info?.org = sub; info?.asn = nil; info?.customSubtitle = sub }
        await setError("")
        return info
    }

    /// Script source: cached copy (≤ 1 day), else downloaded; local file names under Scripts are accepted too.
    private static func loadScript(_ ref: String, session: URLSession) async -> String? {
        if !ref.hasPrefix("http") {
            let s = LibmihomoScriptSource(AppShared.homeURL.path, ref)
            return s.isEmpty ? nil : s
        }
        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: scriptCache.path), let m = attrs[.modificationDate] as? Date,
           Date().timeIntervalSince(m) < 86400, let s = try? String(contentsOf: scriptCache, encoding: .utf8) {
            return s
        }
        guard let u = URL(string: ref), let got = try? await session.data(from: u),
              let h = got.1 as? HTTPURLResponse, (200..<300).contains(h.statusCode), !got.0.isEmpty else {
            return try? String(contentsOf: scriptCache, encoding: .utf8)
        }
        try? got.0.write(to: scriptCache, options: .atomic)
        return String(decoding: got.0, as: UTF8.self)
    }

    @MainActor private static func setError(_ e: String) { lastError = e }
}

/// 资源解析器 (v0.12, QX resource_parser_url): kept as an optional advanced field. Mihomo parses node,
/// rule and rewrite resources natively, so the URL is only stored (and shown) — never downloaded or run.
enum ResourceParserSetting {
    private static let key = "qx.resourceParserURL"
    static var url: String {
        get { UserDefaults.standard.string(forKey: key) ?? "" }
        set { UserDefaults.standard.set(newValue.trimmingCharacters(in: .whitespaces), forKey: key) }
    }
}
