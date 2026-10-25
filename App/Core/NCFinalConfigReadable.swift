import Foundation

/// B1 (Go-zero): 「导出最终配置（含覆写）」 — Swift port of bridge/exportreadable.go FinalConfigReadable (+ the
/// portable-export clean-up of exportconfig.go portableProviders / stripAuthHeader / inlineFileProvider and
/// stripAppInternalsNode). The runtime config (NCRuntimeBuilder.build, as a connect builds it) rendered for
/// people: block YAML in mihomo's conventional order — general keys, cache / GEO data, sniffer, tun, dns, hosts,
/// proxies, proxy-providers, proxy-groups, rule-providers, rules, then everything else alphabetically — with a
/// short header and one Chinese comment per section; known objects use mihomo's documented key order.
///
/// DIVERGENCE: Go walked a yaml.v3 node tree, so keys outside the documented lists kept the runtime order
/// (notably dns.nameserver-policy). NCJSONValue objects are unordered, so those keys are written alphabetically
/// (the tunnel's nativecore-runtime.json sorts that map too, see NCRuntimeDNS). Quoting follows our own emitter
/// (strings that would read as another type are double-quoted; YAML 1.1 booleans y/n/yes/no/on/off quoted, as Go).
enum NCFinalConfigReadable {

    struct ExportError: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// bridge FinalConfigReadable(homeDir, path, profileName, appVersion).
    static func render(home: String, path: String, profileName: String, appVersion: String) throws -> String {
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: path)
        guard let profile = NCRuntimeFiles.readRuntimeProfile(home: home, path: path, safe: false) else {
            var detail = "配置文件不可读"
            do { _ = try Data(contentsOf: URL(fileURLWithPath: path)) } catch { detail = error.localizedDescription }
            throw ExportError(message: "读取配置失败: " + detail)
        }
        let built: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])
        do {
            built = try NCRuntimeBuilder.build(profile: profile, req: req, fd: 0)
        } catch let e as NCRuntimeBuilder.BuildError {
            throw ExportError(message: e.message)
        }
        return renderReadable(built.raw, home: home, secret: req.settings.core.secret,
                              profile: profileName, version: appVersion, time: Date())
    }

    static let flowThreshold = 50        // from this many nodes on, one node per line (flow style)
    static let groupFlowMembers = 20     // a group's member list longer than this is written on one line

    static let generalKeys = [
        "port", "socks-port", "redir-port", "tproxy-port", "mixed-port", "allow-lan", "bind-address", "lan-allowed-ips",
        "lan-disallowed-ips", "authentication", "skip-auth-prefixes", "mode", "log-level", "ipv6", "unified-delay",
        "tcp-concurrent", "find-process-mode", "global-client-fingerprint", "keep-alive-interval", "keep-alive-idle",
        "disable-keep-alive", "interface-name", "routing-mark", "external-controller", "external-controller-tls",
        "external-controller-unix", "external-controller-cors", "external-ui", "external-ui-name", "external-ui-url",
        "secret", "global-ua", "etag-support",
    ]
    static let geoKeys = ["profile", "geodata-mode", "geodata-loader", "geosite-matcher", "geo-auto-update",
                          "geo-update-interval", "geox-url"]

    static func count(_ v: NCJSONValue?) -> Int {
        switch v {
        case .array(let a)?: return a.count
        case .object(let o)?: return o.count
        default: return 0
        }
    }

    static let sections: [([String], (NCJSONValue?) -> String)] = [
        (generalKeys, { _ in "通用设置" }),
        (geoKeys, { _ in "缓存与 GEO 数据库" }),
        (["sniffer"], { _ in "域名嗅探" }),
        (["tun"], { _ in "TUN" }),
        (["dns"], { _ in "DNS 设置" }),
        (["hosts"], { _ in "Hosts" }),
        (["proxies"], { "节点（共 \(count($0)) 个）" }),
        (["proxy-providers"], { "节点集（共 \(count($0)) 个）" }),
        (["proxy-groups"], { "策略组（共 \(count($0)) 个）" }),
        (["rule-providers"], { "规则集（共 \(count($0)) 个）" }),
        (["rules"], { "规则（共 \(count($0)) 条，按顺序匹配，越靠前优先级越高）" }),
    ]

    static let orderProxy = ["name", "type", "server", "port", "ports", "cipher", "password", "username", "uuid", "alterId",
        "auth-str", "auth", "obfs", "obfs-password", "obfs-param", "protocol", "protocol-param", "plugin", "plugin-opts",
        "flow", "network", "tls", "udp", "udp-over-tcp", "sni", "servername", "skip-cert-verify", "fingerprint",
        "client-fingerprint", "alpn", "up", "down", "reality-opts", "ws-opts", "h2-opts", "http-opts", "grpc-opts",
        "smux", "dialer-proxy", "interface-name", "routing-mark", "ip-version", "tfo", "mptcp"]
    static let orderGroup = ["name", "type", "proxies", "use", "url", "interval", "tolerance", "lazy", "timeout",
        "max-failed-times", "strategy", "disable-udp", "interface-name", "routing-mark", "include-all",
        "include-all-proxies", "include-all-providers", "filter", "exclude-filter", "exclude-type", "expected-status",
        "hidden", "icon"]
    static let orderProxyProvider = ["type", "url", "path", "interval", "proxy", "size-limit", "header", "health-check",
        "override", "filter", "exclude-filter", "exclude-type", "payload"]
    static let orderHealthCheck = ["enable", "url", "interval", "timeout", "lazy", "expected-status"]
    static let orderRuleProvider = ["type", "behavior", "format", "url", "path", "interval", "proxy", "size-limit", "payload"]
    static let orderDNS = ["enable", "cache-algorithm", "prefer-h3", "listen", "ipv6", "ipv6-timeout", "use-hosts",
        "use-system-hosts", "respect-rules", "enhanced-mode", "fake-ip-range", "fake-ip-range6", "fake-ip-filter-mode",
        "fake-ip-filter", "fake-ip-ttl", "default-nameserver", "nameserver-policy", "nameserver",
        "proxy-server-nameserver", "proxy-server-nameserver-policy", "direct-nameserver",
        "direct-nameserver-follow-policy", "fallback", "fallback-filter"]
    static let orderFallbackFilter = ["geoip", "geoip-code", "geosite", "ipcidr", "domain"]
    static let orderTun = ["enable", "stack", "device", "dns-mode", "dns-hijack", "auto-route", "auto-redirect",
        "auto-detect-interface", "strict-route", "mtu", "gso", "gso-max-size", "udp-timeout", "file-descriptor",
        "inet4-address", "inet6-address", "route-address", "route-exclude-address", "route-address-set",
        "route-exclude-address-set", "include-interface", "exclude-interface", "endpoint-independent-nat"]
    static let orderSniffer = ["enable", "force-dns-mapping", "parse-pure-ip", "override-destination", "sniff",
        "force-domain", "skip-domain", "skip-src-address", "skip-dst-address"]
    static let orderProfile = ["store-selected", "store-fake-ip"]
    static let orderGeoxURL = ["geoip", "geosite", "mmdb", "asn"]

    /// Key order for an object at `path` (top-level key, then nested keys; "*" = any item / value).
    static func order(for path: [String]) -> [String] {
        switch path {
        case ["proxies", "*"], ["proxy-providers", "*", "payload", "*"]: return orderProxy
        case ["proxies", "*", "ws-opts"], ["proxy-providers", "*", "payload", "*", "ws-opts"]:
            return ["path", "headers", "max-early-data", "early-data-header-name"]
        case ["proxies", "*", "reality-opts"], ["proxy-providers", "*", "payload", "*", "reality-opts"]:
            return ["public-key", "short-id"]
        case ["proxy-groups", "*"]: return orderGroup
        case ["proxy-providers", "*"]: return orderProxyProvider
        case ["proxy-providers", "*", "health-check"]: return orderHealthCheck
        case ["rule-providers", "*"]: return orderRuleProvider
        case ["dns"]: return orderDNS
        case ["dns", "fallback-filter"]: return orderFallbackFilter
        case ["tun"]: return orderTun
        case ["sniffer"]: return orderSniffer
        case ["profile"]: return orderProfile
        case ["geox-url"]: return orderGeoxURL
        default: return []
        }
    }

    static func orderedKeys(_ o: [String: NCJSONValue], path: [String]) -> [String] {
        let pref = order(for: path)
        let rank = Dictionary(pref.enumerated().map { ($0.element, $0.offset) }, uniquingKeysWith: { a, _ in a })
        return o.keys.sorted { a, b in
            let ra = rank[a] ?? pref.count, rb = rank[b] ?? pref.count
            return ra != rb ? ra < rb : a < b
        }
    }

    // MARK: - render

    static func renderReadable(_ raw0: [String: NCJSONValue], home: String, secret: String,
                               profile: String, version: String, time: Date) -> String {
        var raw = raw0
        let notes = stripAppInternals(&raw, home: home, secret: secret)
        var out = ""
        writeHeader(&out, profile: profile, version: version, time: time, notes: notes)
        var done = Set<String>()
        for (keys, comment) in sections {
            let present = keys.filter { raw[$0] != nil && !done.contains($0) }
            guard let first = present.first else { continue }
            writeSectionComment(&out, comment(raw[first]))
            for k in present {
                done.insert(k)
                writePair(&out, key: k, value: raw[k]!)
            }
        }
        let rest = raw.keys.filter { !done.contains($0) }.sorted()
        if !rest.isEmpty {
            writeSectionComment(&out, "其他设置")
            for k in rest { writePair(&out, key: k, value: raw[k]!) }
        }
        if !secret.isEmpty && out.contains(secret) {
            out = out.replacingOccurrences(of: secret, with: "<redacted>")
        }
        return out
    }

    static func writeSectionComment(_ out: inout String, _ title: String) {
        out += "\n# ===== " + title + (title.hasSuffix("）") ? "" : " ") + "=====\n"
    }

    static func oneLine(_ s: String) -> String {
        s.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
            .split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    static func writeHeader(_ out: inout String, profile: String, version: String, time: Date, notes: [String]) {
        out += "# Tern 导出的最终配置（mihomo 格式）\n"
        let v = oneLine(version)
        if !v.isEmpty { out += "# Tern 版本：" + v + "\n" }
        let p = oneLine(profile)
        if !p.isEmpty { out += "# 配置：" + p + "\n" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss xxx"
        out += "# 导出时间：" + f.string(from: time) + "\n"
        out += "# 内容即内核运行的配置：已包含覆写脚本、节点处理、节点订阅、对节点的修改和 App 内的内核设置；\n"
        out += "# 不含模块 / MitM，App 内部使用的控制器地址、密钥和探测用策略组已移除。节点凭据与原配置相同，请勿随意分享。\n"
        out += "# 以 # 开头的注释只为方便阅读，内核不读取。\n"
        if !notes.isEmpty {
            out += "#\n# 导出说明 / Export notes:\n"
            for n in notes { out += "#   - " + oneLine(n) + "\n" }
        }
    }

    /// One top-level `key: value`.
    static func writePair(_ out: inout String, key: String, value: NCJSONValue) {
        let flowItems = key == "proxies" && count(value) >= flowThreshold
        out += scalarText(.string(key)) + ":"
        writeBlock(&out, value, indent: 0, path: [key], flowItems: flowItems)
    }

    // MARK: - YAML writer

    /// Writes a value after "key:" (block style; nested under `indent`).
    static func writeBlock(_ out: inout String, _ v: NCJSONValue, indent: Int, path: [String], flowItems: Bool = false) {
        let pad = String(repeating: " ", count: indent + 2)
        switch v {
        case .object(let o) where !o.isEmpty:
            out += "\n"
            for k in orderedKeys(o, path: path) {
                out += pad + scalarText(.string(k)) + ":"
                writeBlock(&out, o[k]!, indent: indent + 2, path: path + [path.count == 1 && isMapOfItems(path[0]) ? "*" : k])
            }
        case .array(let a) where !a.isEmpty:
            if path.count >= 2, path.first == "proxy-groups", path.last == "proxies" || path.last == "use", a.count > groupFlowMembers {
                out += " " + flow(v, path: path) + "\n"
                return
            }
            out += "\n"
            let itemPath = path + ["*"]
            let itemFlow = flowItems || (path.count == 3 && path[0] == "proxy-providers" && path[2] == "payload")
            for item in a {
                out += pad + "- "
                switch item {
                case .object(let o) where !o.isEmpty:
                    if itemFlow { out += flow(item, path: itemPath) + "\n"; continue }
                    var first = true
                    for k in orderedKeys(o, path: itemPath) {
                        if !first { out += pad + "  " }
                        first = false
                        out += scalarText(.string(k)) + ":"
                        writeBlock(&out, o[k]!, indent: indent + 4, path: itemPath + [k])
                    }
                case .array(let sub) where !sub.isEmpty:
                    out += flow(item, path: itemPath) + "\n"
                default:
                    out += scalarText(item) + "\n"
                }
            }
        default:
            if case .string(let s) = v, s.contains("\n") {
                // literal block for multi-line strings, as yaml.v3 picks
                out += " |" + (s.hasSuffix("\n") ? "" : "-") + "\n"
                for l in s.split(separator: "\n", omittingEmptySubsequences: false).dropLast(s.hasSuffix("\n") ? 1 : 0) {
                    out += (l.isEmpty ? "" : pad + l) + "\n"
                }
                return
            }
            out += " " + scalarText(v) + "\n"
        }
    }

    /// Top-level keys whose value is a map of named items (provider name -> object).
    static func isMapOfItems(_ k: String) -> Bool { k == "proxy-providers" || k == "rule-providers" }

    static func flow(_ v: NCJSONValue, path: [String]) -> String {
        switch v {
        case .object(let o):
            if o.isEmpty { return "{}" }
            return "{" + orderedKeys(o, path: path).map { k in
                scalarText(.string(k), flow: true) + ": " + flow(o[k]!, path: path + [k])
            }.joined(separator: ", ") + "}"
        case .array(let a):
            if a.isEmpty { return "[]" }
            return "[" + a.map { flow($0, path: path + ["*"]) }.joined(separator: ", ") + "]"
        default:
            return scalarText(v, flow: true)
        }
    }

    static let yaml11Bools: Set<String> = ["y", "n", "yes", "no", "on", "off"]

    static func scalarText(_ v: NCJSONValue, flow: Bool = false) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let d):
            if d.isFinite, d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
            return String(d)
        case .string(let s):
            return needsQuotes(s, flow: flow) ? quote(s) : s
        case .array(let a): return a.isEmpty ? "[]" : self.flow(v, path: [])
        case .object(let o): return o.isEmpty ? "{}" : self.flow(v, path: [])
        }
    }

    static func needsQuotes(_ s: String, flow: Bool) -> Bool {
        if s.isEmpty { return true }
        if s.trimmingCharacters(in: .whitespaces) != s { return true }
        let lower = s.lowercased()
        if yaml11Bools.contains(lower) || ["true", "false", "null", "~"].contains(lower) { return true }
        if Double(s) != nil || lower.hasPrefix("0x") || lower.hasPrefix("0o") || lower.hasPrefix("0b") { return true }
        if s.contains("\n") || s.contains("\r") || s.contains("\t") || s.contains(": ") || s.contains(" #") || s.hasSuffix(":") {
            return true
        }
        if flow && s.contains(where: { ",[]{}".contains($0) }) { return true }
        if let f = s.first, "-?:,[]{}#&*!|>'\"%@`".contains(f) { return true }
        return false
    }

    static func quote(_ s: String) -> String {
        var e = ""
        for ch in s {
            switch ch {
            case "\\": e += "\\\\"
            case "\"": e += "\\\""
            case "\n": e += "\\n"
            case "\r": e += "\\r"
            case "\t": e += "\\t"
            default: e.append(ch)
            }
        }
        return "\"" + e + "\""
    }

    // MARK: - stripAppInternalsNode + portableProviders

    static let privateProviderKeys = ["x-source", "x-convert", "x-own-policy"]

    static func isLoopbackConvert(_ u: String) -> Bool {
        guard let c = URLComponents(string: u), let h = c.host else { return false }
        let host = h.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return (host == "127.0.0.1" || host == "localhost" || host == "::1") && c.path.hasSuffix("/convert")
    }

    /// bridge providerSourceURL.
    static func providerSourceURL(_ m: [String: NCJSONValue]) -> String {
        let u = m["url"]?.string ?? ""
        if let c = URLComponents(string: u), c.host == "127.0.0.1", c.path.hasSuffix("/convert"),
           let q = c.queryItems?.first(where: { $0.name == "url" })?.value, !q.isEmpty {
            return q
        }
        let xs = m["x-source"]?.string ?? ""
        return xs.isEmpty ? u : xs
    }

    static func stripAppInternals(_ root: inout [String: NCJSONValue], home: String, secret: String) -> [String] {
        root["secret"] = nil
        root["external-controller"] = nil
        func dropNamed(_ key: String, _ name: String) {
            guard case .array(let a)? = root[key] else { return }
            root[key] = .array(a.filter { $0["name"]?.string != name })
        }
        dropNamed("proxy-groups", NCProfileCheck.probeGroup)
        if root["listeners"] != nil {
            dropNamed("listeners", "mihomo-ios-probe")
            if case .array(let a)? = root["listeners"], a.isEmpty { root["listeners"] = nil }
        }
        var notes: [String] = []
        for key in ["proxy-providers", "rule-providers"] {
            guard case .object(var pv)? = root[key] else { continue }
            let label = key == "rule-providers" ? "规则集" : "节点集"
            for name in pv.keys.sorted() {
                guard case .object(var m)? = pv[name] else { continue }
                let u = m["url"]?.string ?? ""
                if isLoopbackConvert(u) {
                    let src = providerSourceURL(m)
                    var kind = URLComponents(string: u)?.queryItems?.first(where: { $0.name == "kind" })?.value ?? ""
                    if !src.isEmpty && !isLoopbackConvert(src) {
                        m["url"] = .string(src)
                        if kind.isEmpty { kind = "nodes" }
                        notes.append("\(label)「\(name)」的原始链接是需要转换的格式（\(kind)），本 App 在本机转换后加载；其他客户端可能无法直接读取")
                    } else {
                        pv[name] = nil
                        notes.append("\(label)「\(name)」只有本机转换地址，已从导出中移除")
                        continue
                    }
                }
                stripAuthHeader(&m, secret: secret)
                for k in privateProviderKeys { m[k] = nil }
                if (m["type"]?.string ?? "").lowercased() == "file",
                   let n = inlineFileProvider(key: key, name: name, &m, home: home) {
                    notes.append(n)
                }
                pv[name] = .object(m)
            }
            root[key] = .object(pv)
        }
        return notes
    }

    static func stripAuthHeader(_ m: inout [String: NCJSONValue], secret: String) {
        guard case .object(var h)? = m["header"] else { return }
        for (k, v) in h where k.lowercased() == "authorization" {
            let s: String
            switch v {
            case .array(let a): s = "[" + a.compactMap { NCConfigValidator.scalar($0) }.joined(separator: " ") + "]"
            default: s = NCConfigValidator.scalar(v) ?? ""
            }
            if secret.isEmpty || s.contains(secret) { h[k] = nil }
        }
        m["header"] = h.isEmpty ? nil : .object(h)
    }

    /// bridge inlineFileProvider: a device-local file provider becomes `type: inline` with the file's content;
    /// returns a note when it stays a file.
    static func inlineFileProvider(key: String, name: String, _ m: inout [String: NCJSONValue], home: String) -> String? {
        let p = m["path"]?.string ?? ""
        let label = key == "rule-providers" ? "规则集" : "节点集"
        if p.isEmpty { return "\(label)「\(name)」是本机文件，导出中无法携带" }
        var full = p
        if !p.hasPrefix("/") && !home.isEmpty { full = (home as NSString).appendingPathComponent(p) }
        func keep(_ why: String) -> String {
            if p.hasPrefix("/") { m["path"] = .string("./" + (p as NSString).lastPathComponent) }
            return "\(label)「\(name)」是本机文件（\(why)），请在目标客户端里提供 \(m["path"]?.string ?? "")"
        }
        guard let b = FileManager.default.contents(atPath: full) else { return keep("未找到") }
        let text = String(decoding: b, as: UTF8.self)
        if key == "proxy-providers" {
            guard case .array(let ps)? = NCYAML.parse(text)?["proxies"], !ps.isEmpty else { return keep("内容无法内联") }
            m["payload"] = .array(ps)
        } else {
            let format = (m["format"]?.string ?? "").lowercased()
            var payload: [NCJSONValue] = []
            switch format {
            case "mrs":
                return keep("二进制 mrs 格式")
            case "yaml", "":
                if let pl = NCYAML.parse(text)?["payload"], pl != .null {
                    payload = pl.array ?? []
                    break
                }
                if format == "yaml" { return keep("内容无法内联") }
                payload = textLines(text)
            default:
                payload = textLines(text)
            }
            m["payload"] = .array(payload)
            m["format"] = nil
        }
        m["type"] = .string("inline")
        m["path"] = nil
        m["interval"] = nil
        return nil
    }

    private static func textLines(_ text: String) -> [NCJSONValue] {
        text.components(separatedBy: "\n").compactMap { l0 in
            let l = l0.trimmingCharacters(in: .whitespacesAndNewlines)
            if l.isEmpty || l.hasPrefix("#") || l.hasPrefix("//") { return nil }
            return .string(l)
        }
    }
}
