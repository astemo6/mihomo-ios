import Foundation

/// Node-subscription content parsing + filtering + cached store.
///
/// Every subscription format in the wild reduces to one of:
/// - a Clash/mihomo YAML document with `proxies:`
/// - a base64 blob of newline-separated share URIs (ss/vmess/vless/trojan/
///   hysteria2/tuic) — the "airport" format QX/Loon/Surge all consume
/// - the same URI list in plain text
///
/// Parsed nodes use the canonical parameter-bag shape (NCProxy) with the
/// field names the connector reads. Name collisions get " 2", " 3", …
/// suffixes, like the reference apps do.
enum NCSubscriptionParser {
    static func parse(_ text: String) -> [NCProxy] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("proxies:") || trimmed.contains("\nproxies:") {
            if let nodes = parseClashYAML(trimmed) { return dedup(nodes) }
        }
        var body = trimmed
        if !body.contains("://"), let decoded = base64Decode(body),
           let s = String(data: decoded, encoding: .utf8) {
            body = s
        }
        var nodes: [NCProxy] = []
        for line in body.components(separatedBy: .newlines) {
            let l = line.trimmingCharacters(in: .whitespaces)
            guard l.contains("://") else { continue }
            if let n = parseURI(l) { nodes.append(n) }
        }
        return dedup(nodes)
    }

    // MARK: Clash YAML

    static func parseClashYAML(_ text: String) -> [NCProxy]? {
        guard let root = NCYAML.parse(text) else { return nil }
        let cfg = NCConfig.decode(root: root.object ?? [:])
        return cfg.proxies.isEmpty ? nil : cfg.proxies
    }

    // MARK: URI schemes

    static func parseURI(_ uri: String) -> NCProxy? {
        guard let sep = uri.range(of: "://") else { return nil }
        let scheme = uri[..<sep.lowerBound].lowercased()
        let rest = String(uri[sep.upperBound...])
        switch scheme {
        case "ss": return parseSS(rest)
        case "vmess": return parseVMess(rest)
        case "vless": return parseVLESS(rest)
        case "trojan": return parseTrojan(rest)
        case "hysteria2", "hy2": return parseHysteria2(rest)
        case "tuic": return parseTUIC(rest)
        default: return nil
        }
    }

    /// Split `userinfo@host:port?query#name` (query/name optional).
    private struct Parts {
        var userinfo: String = ""
        var host: String = ""
        var port: Int = 0
        var query: [String: String] = [:]
        var name: String = ""
    }

    private static func splitParts(_ rest: String) -> Parts {
        var p = Parts()
        var s = rest
        if let hash = s.firstIndex(of: "#") {
            p.name = String(s[s.index(after: hash)...]).removingPercentEncoding ?? ""
            s = String(s[..<hash])
        }
        if let q = s.firstIndex(of: "?") {
            let qs = s[s.index(after: q)...]
            s = String(s[..<q])
            for pair in qs.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 {
                    p.query[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
                }
            }
        }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) } // stray path
        if let at = s.lastIndex(of: "@") {
            p.userinfo = String(s[..<at])
            s = String(s[s.index(after: at)...])
        }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            p.host = String(s[s.index(after: s.startIndex)..<close])
            let tail = s[s.index(after: close)...]
            if tail.hasPrefix(":") { p.port = Int(tail.dropFirst()) ?? 0 }
        } else if let colon = s.lastIndex(of: ":") {
            p.host = String(s[..<colon])
            p.port = Int(s[s.index(after: colon)...]) ?? 0
        } else {
            p.host = s
        }
        return p
    }

    private static func base64Decode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }

    private static func fields(_ pairs: [(String, NCJSONValue?)]) -> [String: NCJSONValue] {
        var out: [String: NCJSONValue] = [:]
        for (k, v) in pairs { if let v { out[k] = v } }
        return out
    }

    private static func str(_ v: String?) -> NCJSONValue? {
        guard let v, !v.isEmpty else { return nil }
        return .string(v)
    }

    // ss://base64(method:password)@host:port#name | ss://method:pass@… | legacy whole-base64
    private static func parseSS(_ rest: String) -> NCProxy? {
        // Legacy: the entire rest (minus #name) is one base64 blob.
        var body = rest
        var frag = ""
        if let hash = body.firstIndex(of: "#") {
            frag = String(body[body.index(after: hash)...]).removingPercentEncoding ?? ""
            body = String(body[..<hash])
        }
        if !body.contains("@"), let decoded = base64Decode(body),
           let s = String(data: decoded, encoding: .utf8), s.contains("@") {
            var p = splitParts(s)
            p.name = frag
            return ssNode(p, userinfo: p.userinfo)
        }
        let p = splitParts(rest)
        return ssNode(p, userinfo: p.userinfo.removingPercentEncoding ?? p.userinfo)
    }

    private static func ssNode(_ p: Parts, userinfo: String) -> NCProxy? {
        var ui = userinfo
        if !ui.contains(":"), let decoded = base64Decode(ui), let s = String(data: decoded, encoding: .utf8) {
            ui = s
        }
        let kv = ui.split(separator: ":", maxSplits: 1)
        guard kv.count == 2, !p.host.isEmpty, p.port > 0 else { return nil }
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("cipher", str(String(kv[0]))), ("password", str(String(kv[1]))),
            ("udp", .bool(true)),
        ])
        if let plugin = p.query["plugin"] {
            let parts = plugin.split(separator: ";")
            if let mode = parts.first {
                f["plugin"] = .string(String(mode))
                var opts: [String: NCJSONValue] = ["mode": .string(String(mode))]
                for kvp in parts.dropFirst() {
                    let e = kvp.split(separator: "=", maxSplits: 1)
                    if e.count == 2 { opts[String(e[0])] = .string(String(e[1])) }
                }
                f["plugin-opts"] = .object(opts)
            }
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "ss", fields: f)
    }

    // vmess://base64(JSON)
    private static func parseVMess(_ rest: String) -> NCProxy? {
        var body = rest
        if let hash = body.firstIndex(of: "#") { body = String(body[..<hash]) }
        guard let data = base64Decode(body),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        func s(_ k: String) -> String {
            if let v = obj[k] as? String { return v }
            if let v = obj[k] as? NSNumber { return v.stringValue }
            return ""
        }
        let port = Int(s("port")) ?? 0
        guard !s("add").isEmpty, port > 0, !s("id").isEmpty else { return nil }
        var f = fields([
            ("server", str(s("add"))), ("port", .number(Double(port))),
            ("uuid", str(s("id"))),
            ("alterId", .number(Double(Int(s("aid")) ?? 0))),
            ("cipher", str(s("scy").isEmpty ? "auto" : s("scy"))),
            ("udp", .bool(true)),
        ])
        let net = s("net")
        if !net.isEmpty, net != "tcp" { f["network"] = .string(net) }
        if s("tls") == "tls" {
            f["tls"] = .bool(true)
            if !s("sni").isEmpty { f["servername"] = .string(s("sni")) }
        }
        if net == "ws" {
            var opts: [String: NCJSONValue] = [:]
            if !s("path").isEmpty { opts["path"] = .string(s("path")) }
            if !s("host").isEmpty { opts["headers"] = .object(["Host": .string(s("host"))]) }
            f["ws-opts"] = .object(opts)
        }
        if net == "grpc", !s("path").isEmpty {
            f["grpc-opts"] = .object(["grpc-service-name": .string(s("path"))])
        }
        let name = s("ps").isEmpty ? "\(s("add")):\(port)" : s("ps")
        return NCProxy(name: name, type: "vmess", fields: f)
    }

    private static func parseVLESS(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0, !p.userinfo.isEmpty else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("uuid", str(p.userinfo)), ("udp", .bool(true)),
        ])
        if let flow = q["flow"] { f["flow"] = .string(flow) }
        let security = q["security"] ?? ""
        if security == "tls" || security == "reality" { f["tls"] = .bool(true) }
        if let sni = q["sni"] ?? q["peer"] { f["servername"] = .string(sni) }
        if security == "reality" {
            var opts: [String: NCJSONValue] = [:]
            if let pbk = q["pbk"] { opts["public-key"] = .string(pbk) }
            if let sid = q["sid"] { opts["short-id"] = .string(sid) }
            f["reality-opts"] = .object(opts)
        }
        let net = q["type"] ?? "tcp"
        if net != "tcp" { f["network"] = .string(net) }
        if net == "ws" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["headers"] = .object(["Host": .string(host)]) }
            f["ws-opts"] = .object(opts)
        }
        if net == "grpc", let svc = q["serviceName"] {
            f["grpc-opts"] = .object(["grpc-service-name": .string(svc)])
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "vless", fields: f)
    }

    private static func parseTrojan(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("password", str(p.userinfo.removingPercentEncoding ?? p.userinfo)),
            ("udp", .bool(true)),
        ])
        if let sni = q["sni"] ?? q["peer"] { f["sni"] = .string(sni) }
        if q["allowInsecure"] == "1" || q["allowInsecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        let net = q["type"] ?? "tcp"
        if net != "tcp" { f["network"] = .string(net) }
        if net == "ws" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["headers"] = .object(["Host": .string(host)]) }
            f["ws-opts"] = .object(opts)
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "trojan", fields: f)
    }

    private static func parseHysteria2(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("password", str(p.userinfo.removingPercentEncoding ?? p.userinfo)),
        ])
        if let sni = q["sni"] { f["sni"] = .string(sni) }
        if q["insecure"] == "1" || q["insecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        if let obfs = q["obfs"] { f["obfs"] = .string(obfs) }
        if let obfsPwd = q["obfs-password"] { f["obfs-password"] = .string(obfsPwd) }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "hysteria2", fields: f)
    }

    private static func parseTUIC(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        let creds = p.userinfo.split(separator: ":", maxSplits: 1)
        guard !p.host.isEmpty, p.port > 0, creds.count == 2 else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("uuid", str(String(creds[0]))),
            ("password", str(String(creds[1]).removingPercentEncoding ?? String(creds[1]))),
        ])
        if let sni = q["sni"] { f["sni"] = .string(sni) }
        if let cc = q["congestion_control"] { f["congestion-controller"] = .string(cc) }
        if let alpn = q["alpn"] { f["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0)) }) }
        if q["allow_insecure"] == "1" || q["allowInsecure"] == "1" { f["skip-cert-verify"] = .bool(true) }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "tuic", fields: f)
    }

    private static func dedup(_ nodes: [NCProxy]) -> [NCProxy] {
        var seen: [String: Int] = [:]
        return nodes.map { node in
            let count = (seen[node.name] ?? 0) + 1
            seen[node.name] = count
            guard count > 1 else { return node }
            return NCProxy(name: "\(node.name) \(count)", type: node.type, fields: node.fields)
        }
    }
}

/// Regex include/exclude node filtering (QX server_remote filters, Loon
/// remote filters, mihomo group filter/exclude-filter over providers).
enum NCNodeFilter {
    static func matches(_ name: String, include: String?, exclude: String?) -> Bool {
        if let include, !include.isEmpty,
           (try? NSRegularExpression(pattern: include))?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) == nil {
            return false
        }
        if let exclude, !exclude.isEmpty,
           (try? NSRegularExpression(pattern: exclude))?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil {
            return false
        }
        return true
    }

    static func apply(_ nodes: [NCProxy], include: String?, exclude: String?) -> [NCProxy] {
        nodes.filter { matches($0.name, include: include, exclude: exclude) }
    }
}

/// Cached store for node subscriptions, mirroring the rule-provider
/// store's freshness model: cache-first, refresh failures keep old nodes.
final class NCNodeSubscriptionStore {
    private let dir: URL
    private let lock = NSLock()
    private var nodesBySub: [String: [NCProxy]] = [:]
    private var fetchedAt: [String: TimeInterval] = [:]

    var fetcher: (String, @escaping (Data?) -> Void) -> Void = { urlString, done in
        guard let url = URL(string: urlString) else { done(nil); return }
        var req = URLRequest(url: url)
        req.setValue("clash-verge/v2.0", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: req) { data, _, _ in done(data) }.resume()
    }

    init(dir: URL) {
        self.dir = dir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? Data(contentsOf: dir.appendingPathComponent("meta.json")),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Double] {
            fetchedAt = obj
        }
    }

    private func cacheFile(for name: String) -> URL {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in name.utf8 { hash = (hash ^ UInt64(b)) &* 0x100000001b3 }
        return dir.appendingPathComponent(String(format: "sub-%016llx.txt", hash))
    }

    /// Load cached nodes for all subscriptions; returns those needing a
    /// network refresh (stale or never fetched).
    @discardableResult
    func loadCached(_ subs: [NCNodeSubscription]) -> [NCNodeSubscription] {
        var stale: [NCNodeSubscription] = []
        for sub in subs {
            if let text = try? String(contentsOf: cacheFile(for: sub.name), encoding: .utf8) {
                let nodes = NCSubscriptionParser.parse(text)
                if !nodes.isEmpty {
                    lock.lock(); nodesBySub[sub.name] = nodes; lock.unlock()
                }
            }
            lock.lock(); let at = fetchedAt[sub.name]; lock.unlock()
            if at == nil || Date().timeIntervalSince1970 - at! > Double(max(sub.interval, 60)) {
                stale.append(sub)
            }
        }
        return stale
    }

    func refresh(_ sub: NCNodeSubscription, completion: (() -> Void)? = nil) {
        fetcher(sub.url) { [weak self] data in
            guard let self, let data, let text = String(data: data, encoding: .utf8) else {
                completion?()
                return
            }
            let nodes = NCSubscriptionParser.parse(text)
            guard !nodes.isEmpty else { completion?(); return }
            try? data.write(to: self.cacheFile(for: sub.name), options: .atomic)
            self.lock.lock()
            self.nodesBySub[sub.name] = nodes
            self.fetchedAt[sub.name] = Date().timeIntervalSince1970
            let meta = self.fetchedAt
            self.lock.unlock()
            if let mdata = try? JSONSerialization.data(withJSONObject: meta) {
                try? mdata.write(to: self.dir.appendingPathComponent("meta.json"), options: .atomic)
            }
            completion?()
        }
    }

    /// Nodes of one subscription with its own include/exclude filter applied.
    func nodes(for sub: NCNodeSubscription) -> [NCProxy] {
        lock.lock(); let raw = nodesBySub[sub.name] ?? []; lock.unlock()
        return NCNodeFilter.apply(raw, include: sub.includeRegex, exclude: sub.excludeRegex)
    }

    func allNodes() -> [String: [NCProxy]] {
        lock.lock(); defer { lock.unlock() }
        return nodesBySub
    }
}
