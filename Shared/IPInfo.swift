import Foundation

/// Exit / direct IP information (IP + geo + ASN), parsed tolerantly from several free endpoints.
struct IPInfo: Codable, Equatable {
    var ip: String
    var countryCode: String?
    var country: String?
    var region: String?
    var city: String?
    var asn: String?      // "AS13335"
    var org: String?      // "Cloudflare, Inc."
    var source: String?
    var timezone: String? = nil   // "Asia/Tokyo" (v0.7 Home header)
    var customTitle: String? = nil   // v0.12 geo_location_checker script title (replaces the place text)
    var customSubtitle: String? = nil   // geo_location_checker script subtitle (replaces the whole detail line)

    var flag: String { CountryFlag.emoji(countryCode) ?? "🌐" }

    /// Country name in the app's display language (was always zh_CN, so English / Japanese / … UIs showed
    /// 「日本」; found by the v0.19 en UI scan of the 出口 IP card).
    var countryName: String? {
        let lang = Bundle.main.preferredLocalizations.first ?? Locale.current.identifier
        if let cc = countryCode, let n = Locale(identifier: lang).localizedString(forRegionCode: cc) { return n }
        return country
    }

    /// A geo_location_checker script title conventionally starts with the flag emoji
    /// ("🇯🇵 Japan Tokyo") because QX shows the title alone; every Tern surface renders
    /// `flag` next to the place text, so the title's own flag would double up
    /// (device screenshot 2026-10-28). Strip one leading flag (a regional-indicator pair)
    /// plus following spaces when the title is used as the place text.
    static func stripLeadingFlag(_ s: String) -> String {
        guard let first = s.first, first.unicodeScalars.count == 2,
              first.unicodeScalars.allSatisfy({ (0x1F1E6...0x1F1FF).contains($0.value) }) else { return s }
        let rest = String(s.dropFirst()).trimmingCharacters(in: .whitespaces)
        return rest.isEmpty ? s : rest
    }

    var locationText: String {
        if let t = customTitle, !t.isEmpty { return Self.stripLeadingFlag(t) }
        var parts: [String] = []
        if let c = countryName, !c.isEmpty { parts.append(c) }
        if let city = city, !city.isEmpty, city != parts.first { parts.append(city) }
        else if let r = region, !r.isEmpty, r != parts.first { parts.append(r) }
        return parts.isEmpty ? String(localized: "未知位置") : parts.joined(separator: " · ")
    }

    var asnText: String {
        let a = asn ?? ""
        let o = org ?? ""
        if a.isEmpty && o.isEmpty { return String(localized: "ASN 未知") }
        return [a, o].filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// Header title: "日本 东京" (country + city, no separator dot).
    var placeText: String {
        if let t = customTitle, !t.isEmpty { return Self.stripLeadingFlag(t) }
        var parts: [String] = []
        if let c = countryName, !c.isEmpty { parts.append(c) }
        if let city = city, !city.isEmpty, city != parts.first { parts.append(city) }
        else if let r = region, !r.isEmpty, r != parts.first { parts.append(r) }
        return parts.isEmpty ? String(localized: "未知位置") : parts.joined(separator: " ")
    }

    /// Header detail line in the user's choice (首页副标题显示, default 运营商 · ASN · IP).
    var detailText: String { detailText(fields: ExitDetailField.stored) }

    /// The detail line for the given items, always in the fixed order 运营商 · ASN · 时区 · IP. A QX
    /// geo_location_checker script subtitle wins over the choice. 运营商 unknown → the time zone takes its
    /// place, unless 时区 is chosen anyway. Never invents a value: unknown items are left out.
    func detailText(fields: Set<ExitDetailField>) -> String {
        if let s = customSubtitle?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty { return s }
        let tz = timezone?.trimmingCharacters(in: .whitespaces) ?? ""
        var parts: [String] = []
        for f in ExitDetailField.allCases where fields.contains(f) {
            switch f {
            case .isp:
                if let o = Self.shortOrg(org) { parts.append(o) }
                else if !fields.contains(.timezone), !tz.isEmpty { parts.append(tz) }
            case .asn:
                if let a = asn?.trimmingCharacters(in: .whitespaces), !a.isEmpty { parts.append(a) }
            case .timezone:
                if !tz.isEmpty { parts.append(tz) }
            case .ip:
                if !ip.isEmpty { parts.append(ip) }
            }
        }
        return parts.joined(separator: " · ")
    }

    /// "xTom Japan Corporation" → "xTom Japan", "Cloudflare, Inc." → "Cloudflare"; longer than `max`
    /// characters → middle truncated ("Hong Kong Te…ture Limited"). nil when empty.
    static func shortOrg(_ s: String?, max: Int = 24) -> String? {
        guard let raw = s?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        let suffixes = ["co., ltd.", "co.,ltd.", "co., ltd", "co.,ltd", "co. ltd.", "co. ltd", "co ltd", "pty. ltd.", "pty ltd",
                        "pte. ltd.", "pte ltd", "sdn. bhd.", "sdn bhd", "gmbh & co. kg", "gmbh", "mbh", "l.l.c.", "llc", "ltd.", "ltd",
                        "limited", "inc.", "inc", "incorporated", "corporation", "corp.", "corp", "s.a.", "s.a", "s.r.l.", "srl",
                        "sas", "b.v.", "bv", "ag", "oy", "ab", "k.k.", "plc", "company", "co."]
        var t = raw
        var changed = true
        while changed {
            changed = false
            t = t.trimmingCharacters(in: CharacterSet(charactersIn: " ,"))
            let low = t.lowercased()
            for suf in suffixes {
                for sep in [" ", ","] where low.hasSuffix(sep + suf) {
                    t = String(t.dropLast(sep.count + suf.count))
                    changed = true
                    break
                }
                if changed { break }
            }
        }
        t = t.trimmingCharacters(in: CharacterSet(charactersIn: " ,"))
        if t.count < 2 { t = raw }
        if t.count > max, max > 4 {
            let keep = max - 1
            t = String(t.prefix((keep + 1) / 2)).trimmingCharacters(in: .whitespaces) + "…" + String(t.suffix(keep / 2)).trimmingCharacters(in: .whitespaces)
        }
        return t
    }

    var copyText: String {
        "\(ip)  \(flag) \(locationText)  \(asnText)"
    }
}

/// The one country code → flag emoji helper (Home header, 出口 IP card, 解锁检测 regions …).
/// TW is drawn as 🇨🇳: China-region iOS renders 🇹🇼 blank (user 2026-10-21 「台湾的emoji…改成cn的」). Only the
/// glyph changes; place text and node names stay as returned.
enum CountryFlag {
    static let substitutes: [String: String] = ["TW": "CN"]

    static func emoji(_ code: String?) -> String? {
        guard var cc = code?.trimmingCharacters(in: .whitespaces).uppercased(), cc.count == 2,
              cc.unicodeScalars.allSatisfy({ (65...90).contains($0.value) }) else { return nil }
        cc = substitutes[cc] ?? cc
        var s = ""
        for u in cc.unicodeScalars {
            guard let v = UnicodeScalar(127397 + u.value) else { return nil }
            s.unicodeScalars.append(v)
        }
        return s
    }
}

/// Items of the Home header's small line (更多 → 高级设置 → 出口信息来源 → 首页副标题显示). Toggles only; the line
/// always uses this order. Stored in the App Group as a comma list (key `home.exitDetail`).
enum ExitDetailField: String, CaseIterable, Identifiable {
    case isp, asn, timezone, ip
    var id: String { rawValue }

    static let storageKey = "home.exitDetail"
    static let defaultValue = "isp,asn,ip"
    static let legacy: Set<ExitDetailField> = [.timezone, .asn, .ip]

    static func parse(_ s: String?) -> Set<ExitDetailField> {
        guard let s else { return parse(defaultValue) }
        return Set(s.split(separator: ",").compactMap { ExitDetailField(rawValue: $0.trimmingCharacters(in: .whitespaces)) })
    }

    static func encode(_ set: Set<ExitDetailField>) -> String {
        allCases.filter { set.contains($0) }.map(\.rawValue).joined(separator: ",")
    }

    static var stored: Set<ExitDetailField> { parse(AppShared.defaults.string(forKey: storageKey)) }
}

enum IPInfoFetcher {
    struct Endpoint {
        let name: String
        let url: String
        let parse: ([String: Any]) -> IPInfo?
    }

    static func str(_ d: [String: Any], _ keys: String...) -> String? {
        for k in keys {
            if let v = d[k] as? String, !v.trimmingCharacters(in: .whitespaces).isEmpty { return v }
            if let v = d[k] as? NSNumber { return v.stringValue }
        }
        return nil
    }

    /// Splits "AS13335 Cloudflare, Inc." into ("AS13335", "Cloudflare, Inc.").
    static func splitASOrg(_ s: String?) -> (String?, String?) {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return (nil, nil) }
        if s.uppercased().hasPrefix("AS"), let sp = s.firstIndex(of: " ") {
            let a = String(s[..<sp]).uppercased()
            if a.dropFirst(2).allSatisfy(\.isNumber) {
                return (a, String(s[s.index(after: sp)...]).trimmingCharacters(in: .whitespaces))
            }
        }
        if s.uppercased().hasPrefix("AS"), s.dropFirst(2).allSatisfy(\.isNumber) { return (s.uppercased(), nil) }
        return (nil, s)
    }

    static func normASN(_ v: String?) -> String? {
        guard var v = v?.trimmingCharacters(in: .whitespaces), !v.isEmpty else { return nil }
        if let sp = v.firstIndex(of: " ") { v = String(v[..<sp]) }
        if v.allSatisfy(\.isNumber) { return "AS" + v }
        return v.uppercased()
    }

    static let endpoints: [Endpoint] = [
        Endpoint(name: "ipinfo.io", url: "https://ipinfo.io/json") { d in
            guard let ip = IPInfoFetcher.str(d, "ip") else { return nil }
            let (a, o) = IPInfoFetcher.splitASOrg(IPInfoFetcher.str(d, "org"))
            return IPInfo(ip: ip, countryCode: IPInfoFetcher.str(d, "country"), country: nil, region: IPInfoFetcher.str(d, "region"),
                          city: IPInfoFetcher.str(d, "city"), asn: a, org: o, source: "ipinfo.io")
        },
        Endpoint(name: "ip-api.com", url: "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,timezone,isp,org,as,asname&lang=en") { d in
            guard let ip = IPInfoFetcher.str(d, "query") else { return nil }
            let (a, o) = IPInfoFetcher.splitASOrg(IPInfoFetcher.str(d, "as"))
            return IPInfo(ip: ip, countryCode: IPInfoFetcher.str(d, "countryCode"), country: IPInfoFetcher.str(d, "country"),
                          region: IPInfoFetcher.str(d, "regionName"), city: IPInfoFetcher.str(d, "city"),
                          asn: a, org: IPInfoFetcher.str(d, "isp", "asname", "org") ?? o, source: "ip-api.com")
        },
        Endpoint(name: "ip.sb", url: "https://api.ip.sb/geoip") { d in
            guard let ip = IPInfoFetcher.str(d, "ip") else { return nil }
            return IPInfo(ip: ip, countryCode: IPInfoFetcher.str(d, "country_code"), country: IPInfoFetcher.str(d, "country"),
                          region: IPInfoFetcher.str(d, "region"), city: IPInfoFetcher.str(d, "city"),
                          asn: IPInfoFetcher.normASN(IPInfoFetcher.str(d, "asn")), org: IPInfoFetcher.str(d, "asn_organization", "isp", "organization"), source: "ip.sb")
        },
        Endpoint(name: "ipapi.co", url: "https://ipapi.co/json/") { d in
            guard let ip = IPInfoFetcher.str(d, "ip") else { return nil }
            return IPInfo(ip: ip, countryCode: IPInfoFetcher.str(d, "country_code", "country"), country: IPInfoFetcher.str(d, "country_name"),
                          region: IPInfoFetcher.str(d, "region"), city: IPInfoFetcher.str(d, "city"),
                          asn: IPInfoFetcher.normASN(IPInfoFetcher.str(d, "asn")), org: IPInfoFetcher.str(d, "org"), source: "ipapi.co")
        },
        Endpoint(name: "ipwho.is", url: "https://ipwho.is/") { d in
            guard let ip = IPInfoFetcher.str(d, "ip") else { return nil }
            let conn = d["connection"] as? [String: Any] ?? [:]
            return IPInfo(ip: ip, countryCode: IPInfoFetcher.str(d, "country_code"), country: IPInfoFetcher.str(d, "country"),
                          region: IPInfoFetcher.str(d, "region"), city: IPInfoFetcher.str(d, "city"),
                          asn: IPInfoFetcher.normASN(IPInfoFetcher.str(conn, "asn")), org: IPInfoFetcher.str(conn, "org", "isp"), source: "ipwho.is")
        },
    ]

    // MARK: QX geo_location_checker (QX-4)

    /// "" = automatic (built-in order), an endpoint name = try it first, "custom" = the user's API first,
    /// "disabled" = no lookup at all (QX `geo_location_checker = disabled`). Stored in the App Group.
    static let checkerKey = "geo.checker"
    static let checkerURLKey = "geo.checkerURL"
    static var checker: String { AppShared.defaults.string(forKey: checkerKey) ?? "" }
    static var checkerURL: String { AppShared.defaults.string(forKey: checkerURLKey) ?? "" }
    static var disabled: Bool { checker == "disabled" }

    /// Reads the common field names of IP APIs (ipinfo / ip-api / ip.sb / ipapi / ipwho / ifconfig.co …).
    static func genericParse(_ d: [String: Any], source: String) -> IPInfo? {
        guard let ip = str(d, "ip", "query", "ip_addr", "address") else { return nil }
        let conn = d["connection"] as? [String: Any] ?? [:]
        let asRaw = str(d, "asn", "as", "as_number") ?? str(conn, "asn")
        let (a, o) = splitASOrg(asRaw)
        return IPInfo(ip: ip, countryCode: str(d, "country_code", "countryCode", "country_iso", "cc") ?? (str(d, "country").flatMap { $0.count == 2 ? $0 : nil }),
                      country: str(d, "country_name", "country"), region: str(d, "region", "regionName", "region_name"),
                      city: str(d, "city"), asn: a ?? normASN(asRaw), org: str(d, "org", "isp", "asn_organization", "asname", "organization") ?? o ?? str(conn, "org", "isp"),
                      source: source)
    }

    /// Endpoints in the order the user's choice asks for.
    static var orderedEndpoints: [Endpoint] {
        var list = endpoints
        let c = checker
        if c == "custom", let u = URL(string: checkerURL), let host = u.host, u.scheme?.hasPrefix("http") == true {
            list.insert(Endpoint(name: host, url: checkerURL) { d in IPInfoFetcher.genericParse(d, source: host) }, at: 0)
        } else if let i = list.firstIndex(where: { $0.name == c }) {
            let e = list.remove(at: i)
            list.insert(e, at: 0)
        }
        return list
    }

    /// GeoIP of an arbitrary address (网络活动 detail): ipinfo.io, then ip-api.com.
    static func lookup(ip: String, timeout: TimeInterval = 6) async -> IPInfo? {
        let session = URLSession(configuration: sessionConfiguration(timeout: timeout))
        defer { session.invalidateAndCancel() }
        let enc = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip
        let tries: [(String, String)] = [
            ("ipinfo.io", "https://ipinfo.io/\(enc)/json"),
            ("ip-api.com", "http://ip-api.com/json/\(enc)?fields=status,query,country,countryCode,regionName,city,timezone,isp,org,as&lang=en"),
        ]
        for (name, u) in tries {
            guard let url = URL(string: u) else { continue }
            var req = URLRequest(url: url)
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            guard let r = try? await session.data(for: req),
                  let http = r.1 as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let obj = try? JSONSerialization.jsonObject(with: r.0) as? [String: Any] else { continue }
            if let status = obj["status"] as? String, status.lowercased() == "fail" { continue }
            if obj["bogon"] as? Bool == true { continue }
            if var info = genericParse(obj, source: name) {
                info.timezone = str(obj, "timezone")
                return info
            }
        }
        return nil
    }

    /// Fetches with a brand-new ephemeral session each time so a connection opened
    /// before the tunnel came up is never reused (that would report the old IP).
    static func fetch(timeout: TimeInterval = 6) async -> IPInfo? {
        let session = URLSession(configuration: sessionConfiguration(timeout: timeout))
        defer { session.invalidateAndCancel() }
        return await fetch(using: session)
    }

    static func sessionConfiguration(timeout: TimeInterval) -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout + 2
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.urlCache = nil
        cfg.httpShouldUsePipelining = false
        cfg.httpMaximumConnectionsPerHost = 1
        return cfg
    }

    /// Tries the endpoints with the given session (v0.8: also a session through 节点探测).
    /// fix/nc-diag-439 (D): a staggered race instead of one endpoint after another (6 s timeout each — one slow or
    /// refused endpoint kept Home on 「查询中」 up to the 18 s cap). Endpoint i starts after i × `stagger` seconds, or
    /// at once when every endpoint before it has failed; the first usable answer wins and the rest are cancelled.
    static let stagger: TimeInterval = 1.2

    static func fetch(using session: URLSession) async -> IPInfo? {
        if disabled { return nil }
        let eps = orderedEndpoints
        guard !eps.isEmpty else { return nil }
        let gate = RaceGate(count: eps.count)
        let started = Date()
        let (info, why): (IPInfo?, [String]) = await withTaskGroup(of: (Int, IPInfo?, String?).self, returning: (IPInfo?, [String]).self) { tg in
            for (i, ep) in eps.enumerated() {
                tg.addTask {
                    while Date().timeIntervalSince(started) < Double(i) * stagger, await !gate.allFailed(before: i) {
                        if Task.isCancelled { return (i, nil, nil) }
                        try? await Task.sleep(nanoseconds: 100_000_000)
                    }
                    if Task.isCancelled { return (i, nil, nil) }
                    let (info, why) = await attempt(ep, session: session)
                    if info == nil { await gate.failed(i) }
                    return (i, info, why)
                }
            }
            var why: [String] = []
            for await (_, info, w) in tg {
                if let info { tg.cancelAll(); return (info, []) }
                if let w { why.append(w) }
            }
            return (nil, why)
        }
        // fix/nc-delay-2: Home's 出口 line sat on 「正在查询…」 with no trace of why; one line per failed lookup.
        if info == nil, !why.isEmpty {
            StartupLog.write("exit-ip lookup: " + why.joined(separator: "; "), tag: "app")
        }
        return info
    }

    private actor RaceGate {
        private var failed: Set<Int> = []
        init(count: Int) {}
        func failed(_ i: Int) { failed.insert(i) }
        func allFailed(before i: Int) -> Bool { (0..<i).allSatisfy { failed.contains($0) } }
    }

    /// One endpoint: the parsed answer, or why it gave none.
    private static func attempt(_ ep: Endpoint, session: URLSession) async -> (IPInfo?, String?) {
        guard let url = URL(string: ep.url) else { return (nil, "\(ep.name) bad URL") }
        var req = URLRequest(url: url)
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        do {
            let t0 = Date()
            let (data, resp) = try await session.data(for: req)
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return (nil, "\(ep.name) HTTP \((resp as? HTTPURLResponse)?.statusCode ?? -1) in \(ms) ms")
            }
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return (nil, "\(ep.name) not JSON") }
            if let status = obj["status"] as? String, status.lowercased() == "fail" { return (nil, "\(ep.name) status fail") }
            if let success = obj["success"] as? Bool, success == false { return (nil, "\(ep.name) success false") }
            guard var info = ep.parse(obj) else { return (nil, "\(ep.name) no IP field") }
            info.source = ep.name
            if info.timezone == nil {
                info.timezone = str(obj, "timezone", "time_zone") ?? (obj["timezone"] as? [String: Any]).flatMap { str($0, "id") }
            }
            return (info, nil)
        } catch {
            if Task.isCancelled { return (nil, nil) }
            let ns = error as NSError
            return (nil, "\(ep.name) \(ns.domain) \(ns.code)")
        }
    }
}
