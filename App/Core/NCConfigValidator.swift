import Foundation
import CryptoKit

/// B1 (Go-zero): the full config check — Swift port of bridge ValidateConfigIn / validateBytes (bridge.go) +
/// parseRuntimeCached (validatecache.go), with mihomo v1.19.33's `executor.ParseWithBytes` → config.ParseRawConfig
/// replaced by `parse(_:)` below. Ported from the mihomo sources the bridge linked (config/config.go parseProxies /
/// parseRuleProviders / parseSubRules / parseRules / parseHosts / parseDNS / tunnels, config/utils.go
/// proxyGroupsDagSort / validateDialerProxies, adapter/parser.go, adapter/outboundgroup/parser.go,
/// adapter/provider/parser.go, rules/provider/parse.go, rules/parser.go, rules/logic/logic.go,
/// rules/common/base.go ParseRulePayload, common/utils/ranges.go). Error texts are mihomo's, so ProfileCheck's
/// locate patterns and FriendlyError hints keep matching.
///
/// Used by every caller that had the Go parse: ProfileStore.validate (import / save), TestBridge.validate,
/// ProfileCheck (editor), NCProfileNodes / NCProfileRefRename commit (node edit, rename) and NCOverrideOutput
/// (覆写脚本 output).
///
/// DIVERGENCES (declared): mihomo also *constructs* every adapter (cipher tables, TLS configs, transport options)
/// and loads geodata for GEOSITE / GEOIP rules. Here a node is checked for its type, a string `type`, numeric
/// `port`, unique name and its dialer-proxy chain; protocol parameters are NativeCore's business (NCSupport marks
/// what it cannot dial; mihomo would accept those nodes too). Geo databases are not opened (the tunnel downloads
/// them; Go only failed when they were missing *and* undownloadable). DOMAIN-REGEX compiles with
/// NSRegularExpression instead of regexp2. Listener / TUIC-server / tun sections are not parsed (the app never
/// writes them; tun is NativeCore's own).
enum NCConfigValidator {

    struct Parsed {
        /// len(cfg.Rules).
        var rules = 0
        /// len(cfg.Providers): proxy providers + one compatible provider per group with `proxies` + "default".
        var providers = 0
    }

    struct ParseError: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    // MARK: - bridge entry points

    /// bridge ValidateConfigIn: "" when the profile at `path` (its 覆写脚本 output, subscription rules, provider /
    /// node overrides and the app's core settings applied) parses, else the error text.
    static func validateConfigIn(home: String, path: String) -> String {
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: path)
        guard let profile = NCRuntimeFiles.readRuntimeProfile(home: home, path: path, safe: false) else {
            var detail = "配置文件不可读"
            do { _ = try Data(contentsOf: URL(fileURLWithPath: path)) } catch { detail = error.localizedDescription }
            return detail
        }
        return check(home: home, profile: profile, req: req) ?? ""
    }

    /// validateBytes for `profile` as the content of the profile at `path` (node edit / rename / script output):
    /// nil when it builds and parses, else the error.
    static func validate(home: String, path: String, profile: Data) -> String? {
        check(home: home, profile: profile, req: NCRuntimeBuilder.Request.load(home: home, profilePath: path))
    }

    private static func check(home: String, profile: Data, req: NCRuntimeBuilder.Request) -> String? {
        let built: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])
        do {
            built = try NCRuntimeBuilder.build(profile: profile, req: req, fd: 0)
        } catch let e as NCRuntimeBuilder.BuildError {
            return e.message
        } catch {
            return error.localizedDescription
        }
        let msg = parseCached(home: home, runtime: built.data, raw: built.raw)
        return msg.isEmpty ? nil : msg
    }

    // MARK: - parseRuntimeCached (validatecache.go)

    private static let cacheMax = 8
    private static let okTTL: TimeInterval = 600
    private static let errTTL: TimeInterval = 30
    private static let cacheLock = NSLock()
    private static var cache: [Data: (err: String, at: Date)] = [:]

    /// "" when the runtime parses, else mihomo's error text; remembered by the exact runtime bytes + home
    /// (successes 10 min, failures 30 s, 8 entries).
    static func parseCached(home: String, runtime: Data, raw: [String: NCJSONValue]) -> String {
        var h = SHA256()
        h.update(data: Data(home.utf8))
        h.update(data: Data([0]))
        h.update(data: runtime)
        let key = Data(h.finalize())
        let now = Date()
        cacheLock.lock()
        if let e = cache[key] {
            let ttl = e.err.isEmpty ? okTTL : errTTL
            if now.timeIntervalSince(e.at) < ttl {
                cacheLock.unlock()
                return e.err
            }
            cache[key] = nil
        }
        cacheLock.unlock()
        var msg = ""
        do { _ = try parse(raw) } catch let e as ParseError { msg = e.message } catch { msg = error.localizedDescription }
        cacheLock.lock()
        if cache.count >= cacheMax, let oldest = cache.min(by: { $0.value.at < $1.value.at })?.key {
            cache[oldest] = nil
        }
        cache[key] = (msg, now)
        cacheLock.unlock()
        return msg
    }

    // MARK: - config.ParseRawConfig

    static let builtinProxies = ["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE"]

    /// adapter/parser.go ParseProxy's switch.
    static let proxyTypes: Set<String> = [
        "ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan", "hysteria", "hysteria2", "wireguard",
        "tuic", "juicity", "shadowquic", "gost-relay", "direct", "dns", "reject", "rematch", "ssh", "mieru", "anytls", "sudoku",
        "masque", "trusttunnel", "openvpn", "tailscale", "zerotier", "easytier",
    ]

    /// config.ParseRawConfig on the runtime tree (the order of the checks is mihomo's).
    @discardableResult
    static func parse(_ raw: [String: NCJSONValue]) throws -> Parsed {
        try parseGeneral(raw)
        let px = try parseProxies(raw)
        let ruleProviders = try parseRuleProviders(raw)
        let subRules = try parseSubRules(raw, proxies: px.names, ruleProviders: ruleProviders)
        let rules = try parseRules(list(raw["rules"]), proxies: px.names, ruleProviders: ruleProviders,
                                   subRules: Set(subRules.keys), format: "rules")
        try parseHosts(raw)
        try parseDNS(raw)
        // tunnels: a named proxy must exist.
        for t in list(raw["tunnels"]) {
            if let p = t["proxy"]?.string, !p.isEmpty, !px.names.contains(p) {
                throw ParseError(message: "tunnel proxy \(p) not found")
            }
        }
        return Parsed(rules: rules.count, providers: px.providerCount)
    }

    // MARK: general

    /// parseGeneral's typed fields that can fail to unmarshal: mode (T.TunnelMode) and log-level (log.LogLevel).
    static func parseGeneral(_ raw: [String: NCJSONValue]) throws {
        if let m = raw["mode"]?.string, !["global", "rule", "direct"].contains(m.lowercased()) {
            throw ParseError(message: "invalid mode: \(m)")
        }
        if let l = raw["log-level"]?.string, !["debug", "info", "warning", "error", "silent"].contains(l.lowercased()) {
            throw ParseError(message: "invalid log-level: \(l)")
        }
    }

    // MARK: proxies / groups / providers

    struct ProxyResult {
        var names: Set<String>
        var providerCount: Int
    }

    static func parseProxies(_ raw: [String: NCJSONValue]) throws -> ProxyResult {
        var proxies = Set(builtinProxies)
        var allProxies: [String] = []
        var dialers: [String: String] = [:] // proxy name -> dialer-proxy
        var hasGlobal = false

        for (idx, item) in list(raw["proxies"]).enumerated() {
            guard case .object(let m) = item else {
                throw ParseError(message: "proxy \(idx): missing type")
            }
            guard let typ = m["type"]?.string else { throw ParseError(message: "proxy \(idx): missing type") }
            guard proxyTypes.contains(typ) else { throw ParseError(message: "proxy \(idx): unsupport proxy type: \(typ)") }
            if let p = m["port"] {
                switch p {
                case .number, .null: break
                case .string(let s):
                    if goParseInt(s) == nil {
                        throw ParseError(message: "proxy \(idx): cannot parse 'port' as int: strconv.ParseInt: parsing \"\(s)\": invalid syntax")
                    }
                case .bool: throw ParseError(message: "proxy \(idx): 'port' expected type 'int', got unconvertible type 'bool'")
                default: throw ParseError(message: "proxy \(idx): 'port' expected type 'int', got unconvertible type 'map'")
                }
            }
            let name = scalar(m["name"]) ?? ""
            if proxies.contains(name) { throw ParseError(message: "proxy \(name) is the duplicate name") }
            proxies.insert(name)
            allProxies.append(name)
            if let d = scalar(m["dialer-proxy"]), !d.isEmpty { dialers[name] = d }
        }

        let groups = list(raw["proxy-groups"])
        for (idx, g) in groups.enumerated() {
            guard let name = g["name"]?.string else { throw ParseError(message: "proxy group \(idx): missing name") }
            if name == "GLOBAL" { hasGlobal = true }
        }
        try proxyGroupsDagSort(groups)

        // proxy-providers (Go ranges over a map: order is random there; sorted here for a stable first error)
        var providerKinds: [String: Bool] = [:] // name -> isCompatible (a group's)
        let pp = raw["proxy-providers"]?.object ?? [:]
        for name in pp.keys.sorted() {
            if name == "default" { throw ParseError(message: "can not defined a provider called `default`") }
            if let e = proxyProviderError(pp[name] ?? .null) {
                throw ParseError(message: "parse proxy provider \(name) error: \(e)")
            }
            providerKinds[name] = false
        }
        let allProviders = pp.keys.sorted()
        let sortedAll = allProxies.sorted()

        // groups in dependency order (members before the groups using them), as after proxyGroupsDagSort
        var compatibleCount = 0
        for (idx, g) in dagOrder(groups) {
            guard case .object(let m) = g else { throw ParseError(message: "proxy group[\(idx)]: format error") }
            let typ = m["type"]?.string ?? ""
            let name = m["name"]?.string ?? ""
            if typ.isEmpty || name.isEmpty { throw ParseError(message: "proxy group[\(idx)]: format error") }
            let emptyFallback = scalar(m["empty-fallback"]).flatMap { $0.isEmpty ? nil : $0 } ?? "COMPATIBLE"
            // only real proxies (no groups) may be the empty fallback
            if !(builtinProxies.contains(emptyFallback) || allProxies.contains(emptyFallback)) {
                throw ParseError(message: "proxy group[\(idx)]: \(name): empty fallback proxy '\(emptyFallback)' not found")
            }
            var members = list(m["proxies"]).compactMap { scalar($0) }
            var use = list(m["use"]).compactMap { scalar($0) }
            let includeAll = m["include-all"]?.bool ?? false
            let includeProviders = includeAll || (m["include-all-providers"]?.bool ?? false)
            let includeProxies = includeAll || (m["include-all-proxies"]?.bool ?? false)
            if includeProviders { use = allProviders }
            if includeProxies {
                let filter = scalar(m["filter"]) ?? ""
                if !filter.isEmpty {
                    let regs = filter.components(separatedBy: "`").map { try? NSRegularExpression(pattern: $0) }
                    for p in sortedAll {
                        for r in regs {
                            if let r, r.firstMatch(in: p, range: NSRange(p.startIndex..., in: p)) != nil { members.append(p) }
                        }
                    }
                } else {
                    members.append(contentsOf: sortedAll)
                }
                if members.isEmpty && use.isEmpty { members = [emptyFallback] }
            }
            if members.isEmpty && use.isEmpty {
                throw ParseError(message: "proxy group[\(idx)]: \(name): `use` or `proxies` missing")
            }
            if let es = scalar(m["expected-status"]), let e = unsignedRangesError(es, max: 65535) {
                throw ParseError(message: "proxy group[\(idx)]: \(name): \(e)")
            }
            for u in use {
                guard let compatible = providerKinds[u] else {
                    throw ParseError(message: "proxy group[\(idx)]: \(name): '\(u)' not found")
                }
                if compatible {
                    throw ParseError(message: "proxy group[\(idx)]: \(name): proxy group \(u) can't contains in `use`")
                }
            }
            if !members.isEmpty {
                for p in members where !proxies.contains(p) {
                    throw ParseError(message: "proxy group[\(idx)]: \(name): '\(p)' not found")
                }
                if providerKinds[name] != nil {
                    throw ParseError(message: "proxy group[\(idx)]: \(name): duplicate provider name")
                }
                providerKinds[name] = true
                compatibleCount += 1
            }
            switch typ {
            case "url-test", "select", "fallback", "load-balance": break
            case "relay":
                throw ParseError(message: "proxy group[\(idx)]: unsupported type: The group [\(name)] with relay type was removed, please using dialer-proxy instead")
            default:
                throw ParseError(message: "proxy group[\(idx)]: unsupported type: \(typ)")
            }
            if proxies.contains(name) { throw ParseError(message: "proxy group \(name): the duplicate name") }
            proxies.insert(name)
        }
        if !hasGlobal { proxies.insert("GLOBAL") }

        // validateDialerProxies
        for name in dialers.keys.sorted() {
            let d = dialers[name]!
            if !proxies.contains(d) { throw ParseError(message: "proxy [\(name)] dialer-proxy [\(d)] not found") }
        }
        var state: [String: UInt8] = [:] // 1 on path, 2 acyclic
        for name in dialers.keys.sorted() {
            var path: [String] = []
            var cur: String? = name
            while let c = cur, state[c] != 2 {
                if state[c] == 1 { throw ParseError(message: "proxy [\(name)] has circular dialer-proxy dependency") }
                state[c] = 1
                path.append(c)
                cur = dialers[c]
            }
            for p in path { state[p] = 2 }
        }

        return ProxyResult(names: proxies, providerCount: pp.count + compatibleCount + 1)
    }

    /// adapter/provider/parser.go ParseProxyProvider's failure paths (vehicle type, safe path).
    static func proxyProviderError(_ v: NCJSONValue) -> String? {
        guard case .object(let m) = v else { return "unsupport vehicle type: " }
        let typ = scalar(m["type"]) ?? ""
        switch typ {
        case "file":
            return unsafePath(scalar(m["path"]) ?? "")
        case "http":
            if let p = scalar(m["path"]), !p.isEmpty { return unsafePath(p) }
            return nil
        case "inline":
            return nil
        default:
            return "unsupport vehicle type: \(typ)"
        }
    }

    /// C.Path.IsSafePath: relative paths resolve under home; absolute ones must lie inside it.
    static func unsafePath(_ p: String) -> String? {
        let home = AppShared.homeURL.standardizedFileURL.path
        let full = p.hasPrefix("/") ? (p as NSString).standardizingPath
            : ((home as NSString).appendingPathComponent(p) as NSString).standardizingPath
        if full == home || full.hasPrefix(home + "/") { return nil }
        return "path is not subpath of home directory or SAFE_PATHS: \(full) \n allowed paths: [\(home)]"
    }

    /// config/utils.go proxyGroupsDagSort: duplicate group names and member loops.
    static func proxyGroupsDagSort(_ groups: [NCJSONValue]) throws {
        var options: [String: [String]] = [:]
        var indegree: [String: Int] = [:]
        var isGroup: Set<String> = []
        for g in groups {
            let name = scalar(g["name"]) ?? ""
            if isGroup.contains(name) { throw ParseError(message: "ProxyGroup \(name): duplicate group name") }
            isGroup.insert(name)
            let members = list(g["proxies"]).compactMap { scalar($0) }
            options[name] = members
            if indegree[name] == nil { indegree[name] = 0 }
            for p in members { indegree[p, default: 0] += 1 }
        }
        var queue = indegree.filter { $0.value == 0 }.map(\.key)
        var remaining = indegree
        while let name = queue.first {
            queue.removeFirst()
            if isGroup.contains(name) {
                for p in options[name] ?? [] {
                    remaining[p, default: 0] -= 1
                    if remaining[p] == 0 { queue.append(p) }
                }
            }
            remaining[name] = nil
        }
        guard !remaining.isEmpty else { return }
        // locate the loop: drop nodes whose outdegree (inside the remaining graph) reaches 0
        var out: [String: Int] = [:]
        var from: [String: [String]] = [:]
        for name in remaining.keys where isGroup.contains(name) {
            for p in options[name] ?? [] {
                out[name, default: 0] += 1
                from[p, default: []].append(name)
            }
        }
        var q = remaining.keys.filter { (out[$0] ?? 0) == 0 }
        var left = Set(remaining.keys)
        while let n = q.first {
            q.removeFirst()
            for f in from[n] ?? [] {
                out[f, default: 0] -= 1
                if out[f] == 0 { q.append(f) }
            }
            left.remove(n)
        }
        throw ParseError(message: "loop is detected in ProxyGroup, please check following ProxyGroups: [\(left.sorted().joined(separator: " "))]")
    }

    /// Groups ordered members-first (the order ParseProxyGroup sees them after the DAG sort), with their index in
    /// the sorted list as mihomo reports it.
    static func dagOrder(_ groups: [NCJSONValue]) -> [(Int, NCJSONValue)] {
        var byName: [String: NCJSONValue] = [:]
        var order: [String] = []
        for g in groups {
            let n = scalar(g["name"]) ?? ""
            byName[n] = g
            order.append(n)
        }
        var done: Set<String> = []
        var out: [NCJSONValue] = []
        func visit(_ n: String) {
            guard !done.contains(n), let g = byName[n] else { return }
            done.insert(n)
            for p in list(g["proxies"]).compactMap({ scalar($0) }) { visit(p) }
            out.append(g)
        }
        for n in order { visit(n) }
        return out.enumerated().map { ($0.offset, $0.element) }
    }

    // MARK: rule providers / rules

    static func parseRuleProviders(_ raw: [String: NCJSONValue]) throws -> Set<String> {
        let rp = raw["rule-providers"]?.object ?? [:]
        for name in rp.keys.sorted() {
            guard case .object(let m)? = rp[name] else {
                throw ParseError(message: "unsupported behavior type: ")
            }
            let behavior = scalar(m["behavior"]) ?? ""
            guard ["domain", "ipcidr", "classical"].contains(behavior) else {
                throw ParseError(message: "unsupported behavior type: \(behavior)")
            }
            let format = scalar(m["format"]) ?? ""
            guard ["", "yaml", "text", "mrs"].contains(format) else {
                throw ParseError(message: "unsupported format type: \(format)")
            }
            let typ = scalar(m["type"]) ?? ""
            switch typ {
            case "file":
                if let e = unsafePath(scalar(m["path"]) ?? "") { throw ParseError(message: e) }
            case "http":
                if let p = scalar(m["path"]), !p.isEmpty, let e = unsafePath(p) { throw ParseError(message: e) }
            case "inline": break
            default: throw ParseError(message: "unsupported vehicle type: \(typ)")
            }
        }
        return Set(rp.keys)
    }

    static func parseSubRules(_ raw: [String: NCJSONValue], proxies: Set<String>, ruleProviders: Set<String>) throws -> [String: [String]] {
        let sr = raw["sub-rules"]?.object ?? [:]
        let names = Set(sr.keys)
        var parsed: [String: [String]] = [:] // name -> SUB-RULE targets in order
        for name in sr.keys.sorted() {
            if name.isEmpty { throw ParseError(message: "sub-rule name is empty") }
            let lines = list(sr[name])
            let rules = try parseRules(lines, proxies: proxies, ruleProviders: ruleProviders, subRules: names,
                                       format: "sub-rules[\(name)]")
            parsed[name] = rules.compactMap { $0.type == "SUB-RULE" ? $0.target : nil }
        }
        // verifySubRuleCircularReferences
        func verify(_ n: String, _ arr0: [String]) throws {
            var arr = arr0
            arr.append(n)
            for (i, t) in (parsed[n] ?? []).enumerated() {
                guard parsed[t] != nil else { throw ParseError(message: "sub-rule[\(i):\(n)] error: [\(t)] not found") }
                if arr.contains(t) {
                    throw ParseError(message: "sub-rule error: circular references [\((arr + [t]).joined(separator: "->"))]")
                }
                try verify(t, arr)
            }
        }
        for n in parsed.keys.sorted() { try verify(n, []) }
        return parsed
    }

    struct ParsedRule {
        var type: String
        var target: String
    }

    static func parseRules(_ lines: [NCJSONValue], proxies: Set<String>, ruleProviders: Set<String>,
                           subRules: Set<String>, format: String) throws -> [ParsedRule] {
        var out: [ParsedRule] = []
        for (idx, v) in lines.enumerated() {
            let line = scalar(v) ?? ""
            let (tp, payload, target, params) = parseRulePayload(line, needTarget: true)
            if target.isEmpty { throw ParseError(message: "\(format)[\(idx)] [\(line)] error: format invalid") }
            if !proxies.contains(target) {
                if tp != "SUB-RULE" {
                    throw ParseError(message: "\(format)[\(idx)] [\(line)] error: proxy [\(target)] not found")
                } else if !subRules.contains(target) {
                    throw ParseError(message: "\(format)[\(idx)] [\(line)] error: sub-rule [\(target)] not found")
                }
            }
            var providers: [String] = []
            if let e = parseRuleError(tp, payload, params, subRules: subRules, providers: &providers) {
                throw ParseError(message: "\(format)[\(idx)] [\(line)] error: \(e)")
            }
            for n in providers where !ruleProviders.contains(n) {
                throw ParseError(message: "\(format)[\(idx)] [\(line)] error: rule set [\(n)] not found")
            }
            out.append(ParsedRule(type: tp, target: target))
        }
        return out
    }

    /// rules/common/base.go ParseRulePayload.
    static func parseRulePayload(_ ruleRaw: String, needTarget: Bool) -> (tp: String, payload: String, target: String, params: [String]) {
        var item = ruleRaw.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let tp = item[0].uppercased()
        var payload = "", target = ""
        var params: [String] = []
        if item.count > 1 {
            switch tp {
            case "MATCH":
                target = item[1]
            case "NOT", "OR", "AND", "SUB-RULE", "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
                if needTarget {
                    target = item[item.count - 1]
                    item.removeLast()
                }
                payload = item[1...].joined(separator: ",")
            default:
                payload = item[1]
                if item.count > 2 {
                    if needTarget {
                        target = item[2]
                        if item.count > 3 { params = Array(item[3...]) }
                    } else {
                        params = Array(item[2...])
                    }
                }
            }
        }
        return (tp, payload, target, params)
    }

    static let inTypes: Set<String> = ["HTTP", "HTTPS", "SOCKS4", "SOCKS5", "SOCKS", "SHADOWSOCKS", "VMESS", "VLESS",
        "REDIR", "TPROXY", "TROJAN", "TUNNEL", "TUN", "TUIC", "HYSTERIA2", "ANYTLS", "MIERU", "SUDOKU", "INNER"]

    /// rules/parser.go ParseRule: nil = parses; providers collects RULE-SET names (nested in logic rules too).
    static func parseRuleError(_ tp: String, _ payload: String, _ params: [String], subRules: Set<String>?,
                               providers: inout [String]) -> String? {
        if tp != "MATCH" && payload.isEmpty { return "missing subsequent parameters: \(tp)" }
        switch tp {
        case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "GEOSITE", "GEOIP", "SRC-GEOIP",
             "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD", "IN-USER", "IN-NAME",
             "REMATCH-NAME", "MATCH":
            return nil
        case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
            do { _ = try NSRegularExpression(pattern: payload, options: [.caseInsensitive]) } catch {
                return "error parsing regexp: \(payload)"
            }
            return nil
        case "IP-ASN", "SRC-IP-ASN":
            return payload.split(separator: "/").allSatisfy({ UInt32($0) != nil }) ? nil : "payloadRule error"
        case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
            return isPrefix(payload) ? nil : "payloadRule error"
        case "IP-SUFFIX", "SRC-IP-SUFFIX":
            return isPrefix(payload) ? nil : "payloadRule error"
        case "SRC-PORT", "DST-PORT", "IN-PORT":
            if let e = unsignedRangesError(payload, max: 65535) { return "payloadRule error, \(e)" }
            return payload.trimmingCharacters(in: .whitespaces) == "*" ? "payloadRule error" : nil
        case "DSCP":
            return unsignedRangesError(payload, max: 63).map { "payloadRule error, \($0)" }
        case "NETWORK":
            return ["TCP", "UDP"].contains(payload.uppercased()) ? nil : "unsupported network type, only TCP/UDP"
        case "UID":
            return unsignedRangesError(payload, max: Int(UInt32.max)).map { "payloadRule error, \($0)" }
        case "IN-TYPE":
            for t in payload.components(separatedBy: "/") {
                let s = t.trimmingCharacters(in: .whitespaces)
                if s.isEmpty { return "in type couldn't be empty" }
                if !inTypes.contains(s.uppercased()) { return "unsupported type: \(s)" }
            }
            return nil
        case "SUB-RULE":
            return logicError("(\(payload))", sub: true, providers: &providers)
        case "AND", "OR":
            return logicError(payload, sub: false, providers: &providers)
        case "NOT":
            var n = 0
            if let e = logicError(payload, sub: false, providers: &providers, count: &n) { return e }
            return n == 1 ? nil : "not rule must contain one rule"
        case "RULE-SET":
            providers.append(payload)
            return nil
        default:
            return "unsupported rule type: \(tp)"
        }
    }

    private static func logicError(_ payload: String, sub: Bool, providers: inout [String]) -> String? {
        var n = 0
        if let e = logicError(payload, sub: sub, providers: &providers, count: &n) { return e }
        if sub && n != 1 { return "Sub-Rule rule must contain one rule" }
        return nil
    }

    /// rules/logic/logic.go parsePayload + payloadToRule.
    private static func logicError(_ payload: String, sub: Bool, providers: inout [String], count: inout Int) -> String? {
        guard payload.hasPrefix("("), payload.hasSuffix(")") else { return "payload format error" }
        let chars = Array(payload.utf8)
        var stack: [Int] = []
        var ranges: [(Int, Int)] = []
        for (i, c) in chars.enumerated() {
            if c == UInt8(ascii: "(") { stack.append(i) }
            else if c == UInt8(ascii: ")") {
                guard let s = stack.popLast() else { return "missing '('" }
                ranges.append((s, i))
            }
        }
        if !stack.isEmpty { return "format error is missing )" }
        ranges.sort { $0.0 < $1.0 }
        var subRanges: [(Int, Int)] = []
        for rr in ranges {
            if rr.0 == 0 && rr.1 == chars.count - 1 { continue }
            if subRanges.contains(where: { rr.0 > $0.0 && rr.1 < $0.1 }) { continue }
            subRanges.append(rr)
        }
        for r in subRanges {
            let sp = String(decoding: chars[(r.0 + 1)..<r.1], as: UTF8.self)
            let (tp, pl, _, params) = parseRulePayload(sp, needTarget: false)
            switch tp {
            case "MATCH", "SUB-RULE": return "unsupported rule type [\(tp)] on logic rule"
            case "": return "[\(sp)] format is error"
            default: break
            }
            if let e = parseRuleError(tp, pl, params, subRules: nil, providers: &providers) { return e }
            count += 1
        }
        return nil
    }

    // MARK: hosts / dns

    static func parseHosts(_ raw: [String: NCJSONValue]) throws {
        guard let hosts = raw["hosts"]?.object else { return }
        var domainMap: [String: String] = [:]
        for domain in hosts.keys.sorted() {
            let v = hosts[domain]!
            let values: [String]
            switch v {
            case .array(let a): values = a.compactMap { scalar($0) }
            default: values = scalar(v).map { [$0] } ?? []
            }
            if values == ["lan"] { continue }
            let ips = values.filter { isIP($0) }
            if values.isEmpty || (ips.count != values.count && values.count > 1) {
                throw ParseError(message: "\(values) is not a valid value")
            }
            if ips.isEmpty, let target = values.first {
                var t: String? = target
                while let cur = t {
                    if cur == domain { throw ParseError(message: "\(domain), there is a cycle in domain name mapping") }
                    t = domainMap[cur]
                }
                domainMap[domain] = target
            }
        }
    }

    static let nameserverSchemes: Set<String> = ["udp", "tcp", "tls", "http", "https", "quic", "system", "ts",
                                                 "tailscale", "et", "easytier", "dhcp", "rcode"]

    static func parseDNS(_ raw: [String: NCJSONValue]) throws {
        guard let dns = raw["dns"]?.object else { return }
        let ns = list(dns["nameserver"]).compactMap { scalar($0) }
        if dns["enable"]?.bool == true && ns.isEmpty {
            throw ParseError(message: "if DNS configuration is turned on, NameServer cannot be empty")
        }
        let psn = list(dns["proxy-server-nameserver"]).compactMap { scalar($0) }
        if dns["respect-rules"]?.bool == true && psn.isEmpty {
            throw ParseError(message: "if “respect-rules” is turned on, “proxy-server-nameserver” cannot be empty")
        }
        try parseNameServer(ns)
        try parseNameServer(list(dns["fallback"]).compactMap { scalar($0) })
        for (k, v) in (dns["nameserver-policy"]?.object ?? [:]).sorted(by: { $0.key < $1.key }) {
            _ = k
            try parseNameServer(serverList(v))
        }
        try parseNameServer(psn)
        let psp = dns["proxy-server-nameserver-policy"]?.object ?? [:]
        for (_, v) in psp.sorted(by: { $0.key < $1.key }) { try parseNameServer(serverList(v)) }
        if !psp.isEmpty && psn.isEmpty {
            throw ParseError(message: "disallow empty `proxy-server-nameserver` when `proxy-server-nameserver-policy` is set")
        }
        try parseNameServer(list(dns["direct-nameserver"]).compactMap { scalar($0) })
        if let d = dns["default-nameserver"] {
            let dl = list(d).compactMap { scalar($0) }
            if dl.isEmpty { throw ParseError(message: "default nameserver should have at least one nameserver") }
            try parseNameServer(dl)
        }
    }

    private static func serverList(_ v: NCJSONValue) -> [String] {
        if case .array(let a) = v { return a.compactMap { scalar($0) } }
        return (scalar(v) ?? "").components(separatedBy: ";").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// config.go parseNameServer's scheme check (after parsePureDNSServer).
    static func parseNameServer(_ servers: [String]) throws {
        for (idx, s0) in servers.enumerated() {
            var s = s0
            if s == "system" { s = "system://" }
            else if isIP(s) { s = s.contains(":") ? "udp://[\(s)]" : "udp://" + s }
            else if !s.contains("://") { s = "udp://" + s }
            guard let r = s.range(of: "://") else { continue }
            let scheme = String(s[..<r.lowerBound]).lowercased()
            if !nameserverSchemes.contains(scheme) {
                throw ParseError(message: "DNS NameServer[\(idx)] unsupport scheme: \(scheme)")
            }
            if scheme == "rcode" {
                let code = String(s[r.upperBound...]).components(separatedBy: "#")[0]
                if !["success", "format_error", "server_failure", "name_error", "not_implemented", "refused"].contains(code) {
                    throw ParseError(message: "DNS NameServer[\(idx)] format error: unsupported RCode type: \(code)")
                }
            }
        }
    }

    // MARK: helpers

    static func list(_ v: NCJSONValue?) -> [NCJSONValue] { v?.array ?? [] }

    /// A scalar as yaml.v3 would hand it to a string field (numbers and bools stringified).
    static func scalar(_ v: NCJSONValue?) -> String? {
        guard let v else { return nil }
        switch v {
        case .string(let s): return s
        case .bool(let b): return b ? "true" : "false"
        case .number(let d):
            if d.isFinite, d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
            return String(d)
        default: return nil
        }
    }

    /// strconv.ParseInt(s, 0, 64): decimal, 0x / 0o / 0b prefixes, optional sign and underscores after a prefix.
    static func goParseInt(_ s: String) -> Int64? {
        var t = s
        var neg = false
        if t.hasPrefix("+") || t.hasPrefix("-") { neg = t.hasPrefix("-"); t.removeFirst() }
        var radix = 10
        let low = t.lowercased()
        if low.hasPrefix("0x") { radix = 16; t = String(t.dropFirst(2)) }
        else if low.hasPrefix("0o") { radix = 8; t = String(t.dropFirst(2)) }
        else if low.hasPrefix("0b") { radix = 2; t = String(t.dropFirst(2)) }
        else if t.count > 1 && t.hasPrefix("0") { radix = 8; t = String(t.dropFirst()) }
        if radix != 10 { t = t.replacingOccurrences(of: "_", with: "") }
        guard !t.isEmpty, let v = Int64(t, radix: radix) else { return nil }
        return neg ? -v : v
    }

    /// utils.NewUnsignedRanges: "" / "*" = any; "a", "a-b" joined by "/" or ","; at most 28 ranges.
    static func unsignedRangesError(_ s0: String, max: Int) -> String? {
        let s = s0.trimmingCharacters(in: .whitespaces)
        if s.isEmpty || s == "*" { return nil }
        let parts = s.replacingOccurrences(of: ",", with: "/").components(separatedBy: "/")
        if parts.count > 28 { return "intRanges error, too many ranges to use, maximum support 28 ranges" }
        for p in parts where !p.isEmpty {
            let ends = p.components(separatedBy: "-")
            guard ends.count <= 2 else { return "intRanges error, \(p)" }
            for e in ends {
                guard let v = UInt64(e.trimmingCharacters(in: .whitespaces)), v <= UInt64(max) else {
                    return "intRanges error, \(p)"
                }
            }
            if ends.count == 2, let a = UInt64(ends[0].trimmingCharacters(in: .whitespaces)),
               let b = UInt64(ends[1].trimmingCharacters(in: .whitespaces)), a > b {
                return "intRanges error, \(p)"
            }
        }
        return nil
    }

    static func isIP(_ s: String) -> Bool {
        var a4 = in_addr(), a6 = in6_addr()
        return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
    }

    /// netip.ParsePrefix.
    static func isPrefix(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]), !parts[1].hasPrefix("+") else { return false }
        let ip = String(parts[0])
        var a4 = in_addr(), a6 = in6_addr()
        if inet_pton(AF_INET, ip, &a4) == 1 { return (0...32).contains(bits) }
        if inet_pton(AF_INET6, ip, &a6) == 1 { return (0...128).contains(bits) }
        return false
    }
}
