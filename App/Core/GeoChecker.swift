import Foundation
import Libmihomo

/// 出口信息查询 (v0.12, QX geo_location_checker): an optional custom exit-IP lookup for the Home header.
/// api = any JSON IP API (parsed with the built-in readers); script = a QX geo_location_checker script that
/// turns the API reply into {title, subtitle} (run in the Go script engine, app process). disabled = no
/// exit lookup at all. Empty api = the built-in endpoints (default).
struct GeoCheckerSettings: Codable, Equatable {
    var api: String = ""
    var script: String = ""
    var disabled: Bool = false

    private static let key = "geo.checker"

    static func load() -> GeoCheckerSettings {
        guard let d = UserDefaults.standard.data(forKey: key), let s = try? JSONDecoder().decode(GeoCheckerSettings.self, from: d) else { return GeoCheckerSettings() }
        return s
    }

    func save() {
        if let d = try? JSONEncoder().encode(self) { UserDefaults.standard.set(d, forKey: Self.key) }
        try? FileManager.default.removeItem(at: GeoChecker.scriptCache)
    }

    var isCustom: Bool { !api.trimmingCharacters(in: .whitespaces).isEmpty }
}

enum GeoChecker {
    static var scriptCache: URL { AppShared.homeURL.appendingPathComponent("geo-checker.js") }

    struct ScriptResult: Decodable { var title: String?; var subtitle: String?; var ip: String?; var error: String? }

    /// Result of the last lookup for the settings page ("" = fine).
    @MainActor static var lastError = ""

    /// Fetches the custom API (through the tunnel when connected) and applies the script when one is set.
    static func fetch(_ s: GeoCheckerSettings, timeout: TimeInterval = 8) async -> IPInfo? {
        guard let url = URL(string: s.api.trimmingCharacters(in: .whitespaces)) else { await setError(String(localized: "查询地址无效")); return nil }
        let session = URLSession(configuration: IPInfoFetcher.sessionConfiguration(timeout: timeout))
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: url)
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", forHTTPHeaderField: "User-Agent")
        guard let result = try? await session.data(for: req),
              let http = result.1 as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            await setError(String(localized: "查询地址没有响应"))
            return nil
        }
        let data = result.0
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        var info = IPInfoFetcher.endpoints.lazy.compactMap { $0.parse(obj) }.first
        if info != nil {
            info?.source = url.host
            if info?.timezone == nil { info?.timezone = IPInfoFetcher.str(obj, "timezone", "time_zone") }
        }
        let script = s.script.trimmingCharacters(in: .whitespaces)
        if !script.isEmpty, let code = await loadScript(script, session: session) {
            let body = String(decoding: data, as: UTF8.self)
            let home = AppShared.homeURL.path
            let json = await Task.detached { LibmihomoGeoLocationRun(home, code, url.absoluteString, body) }.value
            if let r = try? JSONDecoder().decode(ScriptResult.self, from: Data(json.utf8)) {
                if let e = r.error, !e.isEmpty {
                    await setError(e)
                } else {
                    if info == nil, let ip = r.ip, !ip.isEmpty { info = IPInfo(ip: ip, source: url.host) }
                    info?.customTitle = r.title
                    if let sub = r.subtitle, !sub.isEmpty { info?.org = sub; info?.asn = nil }
                    await setError("")
                    return info
                }
            }
        } else if !script.isEmpty {
            await setError(String(localized: "脚本下载失败"))
        } else {
            await setError(info == nil ? String(localized: "无法识别查询结果，请填写脚本") : "")
        }
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
        let d = got.0
        try? d.write(to: scriptCache, options: .atomic)
        return String(decoding: d, as: UTF8.self)
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
