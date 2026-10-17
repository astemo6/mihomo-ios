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

    var flag: String {
        guard let cc = countryCode?.uppercased(), cc.count == 2 else { return "🌐" }
        var s = ""
        for u in cc.unicodeScalars {
            guard let v = UnicodeScalar(127397 + u.value) else { return "🌐" }
            s.unicodeScalars.append(v)
        }
        return s
    }

    /// Chinese country name when possible.
    var countryName: String? {
        if let cc = countryCode, let n = Locale(identifier: "zh_CN").localizedString(forRegionCode: cc) { return n }
        return country
    }

    var locationText: String {
        var parts: [String] = []
        if let c = countryName, !c.isEmpty { parts.append(c) }
        if let city = city, !city.isEmpty, city != parts.first { parts.append(city) }
        else if let r = region, !r.isEmpty, r != parts.first { parts.append(r) }
        return parts.isEmpty ? "未知位置" : parts.joined(separator: " · ")
    }

    var asnText: String {
        let a = asn ?? ""
        let o = org ?? ""
        if a.isEmpty && o.isEmpty { return String(localized: "ASN 未知") }
        return [a, o].filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// Header title: "日本 东京" (country + city, no separator dot).
    var placeText: String {
        var parts: [String] = []
        if let c = countryName, !c.isEmpty { parts.append(c) }
        if let city = city, !city.isEmpty, city != parts.first { parts.append(city) }
        else if let r = region, !r.isEmpty, r != parts.first { parts.append(r) }
        return parts.isEmpty ? String(localized: "未知位置") : parts.joined(separator: " ")
    }

    /// Header detail line: time zone · ASN · IP.
    var detailText: String {
        [timezone, asn, ip].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }

    var copyText: String {
        "\(ip)  \(flag) \(locationText)  \(asnText)"
    }
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

    /// Tries the endpoints in order with the given session (v0.8: also a session through 节点探测).
    static func fetch(using session: URLSession) async -> IPInfo? {
        for ep in endpoints {
            guard let url = URL(string: ep.url) else { continue }
            var req = URLRequest(url: url)
            req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", forHTTPHeaderField: "User-Agent")
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            do {
                let (data, resp) = try await session.data(for: req)
                guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { continue }
                guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                if let status = obj["status"] as? String, status.lowercased() == "fail" { continue }
                if let success = obj["success"] as? Bool, success == false { continue }
                if var info = ep.parse(obj) {
                    info.source = ep.name
                    if info.timezone == nil {
                        info.timezone = str(obj, "timezone", "time_zone") ?? (obj["timezone"] as? [String: Any]).flatMap { str($0, "id") }
                    }
                    return info
                }
            } catch {
                continue
            }
        }
        return nil
    }
}
