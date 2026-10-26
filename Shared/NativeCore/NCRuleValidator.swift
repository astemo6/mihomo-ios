import Foundation
import CryptoKit

// MARK: - Models

/// One entry of <home>/rules.json.
struct CustomRule: Codable, Identifiable, Hashable {
    var id: String
    var line: String
    var enabled: Bool
    var interval: Int?

    init(id: String = UUID().uuidString, line: String, enabled: Bool = true, interval: Int? = nil) {
        self.id = id
        self.line = line
        self.enabled = enabled
        self.interval = interval
    }
}

/// Result of custom rule validation (mirrors Go's ruleCheck in bridge/customrules.go).
struct RuleCheck: Codable, Hashable {
    var id: String?
    var line: String?
    var enabled: Bool?
    var rule: String?
    var policy: String?
    var error: String?
    var note: String?
    var unresolved: String?

    init(
        id: String? = nil,
        line: String? = nil,
        enabled: Bool? = nil,
        rule: String? = nil,
        policy: String? = nil,
        error: String? = nil,
        note: String? = nil,
        unresolved: String? = nil
    ) {
        self.id = id
        self.line = line
        self.enabled = enabled
        self.rule = rule
        self.policy = policy
        self.error = error
        self.note = note
        self.unresolved = unresolved
    }
}

// MARK: - Validation Errors

enum RuleValidationError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let msg):
            return msg
        }
    }
}

// MARK: - NCRuleValidator

/// Pure Swift rule validator replacing bridge/customrules.go (CheckRuleLine, CheckCustomRules).
enum NCRuleValidator {

    // MARK: - Type Maps & Tables

    static let surgeTypeMap: [String: String] = [
        "DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD", "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
        "DOMAIN-REGEX": "DOMAIN-REGEX", "IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP-CIDR6", "IP6-CIDR": "IP-CIDR6", "GEOIP": "GEOIP",
        "IP-ASN": "IP-ASN", "GEOSITE": "GEOSITE", "DEST-PORT": "DST-PORT", "DST-PORT": "DST-PORT", "SRC-PORT": "SRC-PORT",
        "IN-PORT": "IN-PORT", "SRC-IP": "SRC-IP-CIDR", "SRC-IP-CIDR": "SRC-IP-CIDR", "PROCESS-NAME": "PROCESS-NAME",
        "PROCESS-PATH": "PROCESS-PATH", "NETWORK": "NETWORK", "IP-SUFFIX": "IP-SUFFIX", "SRC-GEOIP": "SRC-GEOIP",
        "SRC-IP-ASN": "SRC-IP-ASN", "DSCP": "DSCP", "UID": "UID", "IN-TYPE": "IN-TYPE", "IN-NAME": "IN-NAME",
        // Quantumult X filter types
        "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "HOST-WILDCARD": "DOMAIN-WILDCARD",
        "IP6-CIDR6": "IP-CIDR6"
    ]

    static let unsupportedTypes: [String: String] = [
        "USER-AGENT": "mihomo 不支持 USER-AGENT 规则（可用 MitM 重写代替）",
        "URL-REGEX": "mihomo 规则不匹配 URL；REJECT 类策略会转为 MitM URL 重写",
        "CELLULAR-RADIO": "iOS 扩展内无法获取蜂窝制式",
        "DEVICE-NAME": "不支持",
        "SUBNET": "不支持（Surge 网络条件规则）",
        "SCRIPT": "不支持脚本规则",
        "HOSTNAME-TYPE": "不支持"
    ]

    // MARK: - Profile Context

    struct ProfileContext {
        var groups: [String] = []
        var proxies: [String] = []
        var firstSelect: String? = nil
        var ruleProvidersByPath: [String: String] = [:]
        var ruleProviderNames: Set<String> = []

        mutating func addRemoteProvider(sp: RemoteSpec) -> String {
            let path = "./ruleset/" + NCRuleValidator.providerNameFor(url: sp.url, kind: sp.kind) + ".txt"
            if let existing = ruleProvidersByPath[path] {
                return "RULE-SET," + existing
            }
            let base = NCRuleValidator.prettyProviderName(u: sp.url, tag: sp.tag)
            let name = NCRuleValidator.uniqueProviderName(base: base, taken: { self.ruleProviderNames.contains($0) })
            ruleProviderNames.insert(name)
            ruleProvidersByPath[path] = name
            return "RULE-SET," + name
        }
    }

    static func loadProfileContext(homeDir: String, profilePath: String) -> ProfileContext {
        var ctx = ProfileContext()
        if !profilePath.isEmpty, let text = try? String(contentsOfFile: profilePath, encoding: .utf8) {
            extractFromText(text: text, into: &ctx)
        }
        if ctx.groups.isEmpty, !homeDir.isEmpty {
            let rtPath = (homeDir as NSString).appendingPathComponent("runtime.yaml")
            if let rtText = try? String(contentsOfFile: rtPath, encoding: .utf8) {
                extractFromText(text: rtText, into: &ctx)
            }
        }
        return ctx
    }

    private static func extractFromText(text: String, into ctx: inout ProfileContext) {
        if let root = NCYAML.parse(text) {
            if let gl = root["proxy-groups"]?.array {
                for item in gl {
                    if let m = item.object, let n = m["name"]?.string, !n.isEmpty, n != "__MITM__" {
                        ctx.groups.append(n)
                        if ctx.firstSelect == nil, m["type"]?.string?.caseInsensitiveCompare("select") == .orderedSame {
                            ctx.firstSelect = n
                        }
                    }
                }
            }
            if let pl = root["proxies"]?.array {
                for item in pl {
                    if let m = item.object, let n = m["name"]?.string, !n.isEmpty, n != "__MITM__" {
                        ctx.proxies.append(n)
                    }
                }
            }
            if let rp = root["rule-providers"]?.object {
                for (name, val) in rp {
                    ctx.ruleProviderNames.insert(name)
                    if let p = val["path"]?.string {
                        ctx.ruleProvidersByPath[p] = name
                    }
                }
            }
        }
        if ctx.groups.isEmpty && ctx.proxies.isEmpty {
            // INI / .conf format fallback
            let sections = NCConfImport.splitSections(text)
            let map = NCConfImport.sectionMap(sections)
            for line in map["proxy group", default: []] {
                guard let eq = line.firstIndex(of: "=") else { continue }
                let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty, name != "__MITM__" else { continue }
                ctx.groups.append(name)
                let rest = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                let toks = rest.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                if ctx.firstSelect == nil, let t = toks.first, t.caseInsensitiveCompare("select") == .orderedSame {
                    ctx.firstSelect = name
                }
            }
            for line in map["proxy", default: []] {
                if let tagRange = line.range(of: "tag=", options: .caseInsensitive) {
                    let afterTag = line[tagRange.upperBound...]
                    let name = afterTag.prefix { $0 != "," }.trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty, name != "__MITM__" {
                        ctx.proxies.append(name)
                    }
                } else if let eq = line.firstIndex(of: "=") {
                    let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty, name != "__MITM__" {
                        ctx.proxies.append(name)
                    }
                }
            }
            for line in (map["rule-provider", default: []] + map["rule-set", default: []]) {
                if let eq = line.firstIndex(of: "=") {
                    let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty { ctx.ruleProviderNames.insert(name) }
                }
            }
        }
    }

    // MARK: - Rule Conversion & Diagnostics

    struct RuleConv {
        var rule: String = ""
        var type: String = ""
        var policy: String = ""
        var options: String = ""
        var remoteURL: String = ""
        var remoteKind: String = ""
        var tag: String = ""
        var unsupported: String = ""
        var note: String = ""

        func format(_ pol: String) -> String {
            if type == "MATCH" {
                return "MATCH," + pol
            }
            return rule + "," + pol + options
        }
    }

    struct RemoteSpec {
        var url: String
        var kind: String = "list"
        var policy: String = "proxy"
        var interval: Int = 86400
        var tag: String = ""
    }

    static func fixValue(_ t: String, _ v0: String) -> String {
        let v = v0.trimmingCharacters(in: .whitespaces)
        switch t {
        case "SRC-IP-CIDR", "IP-CIDR", "IP-CIDR6":
            if !v.contains("/") {
                if let ip = NCIP(v) {
                    if case .v4 = ip {
                        return v + "/32"
                    } else {
                        return v + "/128"
                    }
                }
            }
        case "IP-ASN", "SRC-IP-ASN":
            let u = v.uppercased()
            if u.hasPrefix("AS") {
                return String(u.dropFirst(2))
            }
            return u
        default:
            break
        }
        return v
    }

    static func noResolve(_ opts: [String]) -> String {
        for o in opts {
            if o.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare("no-resolve") == .orderedSame {
                return ",no-resolve"
            }
        }
        return ""
    }

    static func convertLogicBody(_ body0: String) throws -> String {
        let body = body0.trimmingCharacters(in: .whitespaces)
        guard body.hasPrefix("("), body.hasSuffix(")") else {
            throw RuleValidationError.message("逻辑规则格式错误")
        }
        let inner = String(body.dropFirst().dropLast())
        var parts: [String] = []
        for sub0 in NCRule.splitTopLevel(inner) {
            let sub = sub0.trimmingCharacters(in: .whitespaces)
            guard sub.hasPrefix("("), sub.hasSuffix(")") else {
                throw RuleValidationError.message("逻辑规则子项格式错误：\(sub)")
            }
            let subInner = String(sub.dropFirst().dropLast())
            let fields = NCRule.splitTopLevel(subInner)
            guard !fields.isEmpty, !fields[0].isEmpty else {
                throw RuleValidationError.message("逻辑规则缺少条件")
            }
            let t = fields[0].uppercased()
            if t == "AND" || t == "OR" || t == "NOT" {
                guard fields.count >= 2 else {
                    throw RuleValidationError.message("逻辑规则缺少条件")
                }
                let nb = try convertLogicBody(fields.dropFirst().joined(separator: ","))
                parts.append("(\(t),\(nb))")
                continue
            }
            if t == "PROTOCOL", fields.count > 1 {
                let p = fields[1].uppercased()
                if p == "UDP" || p == "QUIC" {
                    parts.append("(NETWORK,UDP)")
                } else {
                    parts.append("(NETWORK,TCP)")
                }
                continue
            }
            if let why = unsupportedTypes[t] {
                throw RuleValidationError.message("\(t)：\(why)")
            }
            guard let mt = surgeTypeMap[t] else {
                throw RuleValidationError.message("不支持的规则类型 \(t)")
            }
            guard fields.count >= 2 else {
                throw RuleValidationError.message("\(t) 缺少内容")
            }
            parts.append("(\(mt),\(fixValue(mt, fields[1])))")
        }
        return "(" + parts.joined(separator: ",") + ")"
    }

    static func parseQXRemote(_ line: String) -> (RemoteSpec, Bool)? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map { String($0) }
        guard let first = parts.first else { return nil }
        let u = first.trimmingCharacters(in: .whitespaces)
        guard u.hasPrefix("http://") || u.hasPrefix("https://") else {
            return nil
        }
        var sp = RemoteSpec(url: u)
        for p in parts.dropFirst() {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch k {
            case "tag":
                sp.tag = v
            case "force-policy":
                sp.policy = v
            case "update-interval":
                if let n = Int(v), n > 0 {
                    sp.interval = n
                }
            case "enabled":
                let lower = v.lowercased()
                if !(lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
                    return nil
                }
            default:
                break
            }
        }
        return (sp, true)
    }

    static func convertRuleLine(_ rawLine: String) throws -> RuleConv? {
        var line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
            return nil
        }
        if line.hasPrefix("- ") {
            line = String(line.dropFirst(2)).trimmingCharacters(in: .whitespaces)
        } else if line.hasPrefix("-") {
            line = String(line.dropFirst(1)).trimmingCharacters(in: .whitespaces)
        }
        let parts = NCRule.splitTopLevel(line)
        guard !parts.isEmpty, !parts[0].isEmpty else {
            return nil
        }
        let t = parts[0].uppercased()
        switch t {
        case "FINAL", "MATCH":
            let pol = parts.count > 1 ? parts[1] : "DIRECT"
            return RuleConv(rule: "MATCH", type: "MATCH", policy: pol)
        case "AND", "OR", "NOT":
            guard parts.count >= 3 else {
                throw RuleValidationError.message("逻辑规则缺少策略")
            }
            let body = try convertLogicBody(parts[1])
            return RuleConv(rule: "\(t),\(body)", type: t, policy: parts[2])
        case "RULE-SET", "DOMAIN-SET":
            guard parts.count >= 3 else {
                throw RuleValidationError.message("\(t) 缺少策略")
            }
            let src = parts[1]
            let kind = (t == "DOMAIN-SET") ? "domainset" : "list"
            if src.contains("://") {
                let opts = noResolve(Array(parts.dropFirst(3)))
                return RuleConv(type: "RULE-SET", policy: parts[2], options: opts, remoteURL: src, remoteKind: kind)
            }
            if src.caseInsensitiveCompare("SYSTEM") == .orderedSame || src.caseInsensitiveCompare("LAN") == .orderedSame {
                return RuleConv(rule: "GEOIP,private", type: "GEOIP", policy: parts[2], options: ",no-resolve", note: "Surge 内置 LAN/SYSTEM 规则集按 GEOIP,private 处理")
            }
            let opts = noResolve(Array(parts.dropFirst(3)))
            return RuleConv(rule: "RULE-SET,\(src)", type: "RULE-SET", policy: parts[2], options: opts)
        case "PROTOCOL":
            guard parts.count >= 3 else {
                throw RuleValidationError.message("PROTOCOL 缺少策略")
            }
            let p = parts[1].uppercased()
            let n = (p == "UDP" || p == "QUIC") ? "UDP" : "TCP"
            return RuleConv(rule: "NETWORK,\(n)", type: "NETWORK", policy: parts[2], note: "PROTOCOL 近似为 NETWORK")
        default:
            break
        }

        if let why = unsupportedTypes[t] {
            throw RuleValidationError.message("\(t)：\(why)")
        }
        guard let mt = surgeTypeMap[t] else {
            throw RuleValidationError.message("不支持的规则类型 \(parts[0])")
        }
        guard parts.count >= 3 else {
            throw RuleValidationError.message("\(t) 缺少策略")
        }
        let opts = noResolve(Array(parts.dropFirst(3)))
        var c = RuleConv(rule: "\(mt),\(fixValue(mt, parts[1]))", type: mt, policy: parts[2], options: opts)
        if mt == "PROCESS-NAME" || mt == "PROCESS-PATH" || mt == "UID" {
            c.note = "iOS 上无法识别进程，该规则不会命中"
        }
        return c
    }

    static func resolvePolicy(_ name: String, groups: [String], proxies: [String], firstSelect: String?) -> (policy: String, ok: Bool) {
        let n = name.trimmingCharacters(in: .whitespaces)
        let u = n.uppercased()
        switch u {
        case "DIRECT":
            return ("DIRECT", true)
        case "REJECT-DROP":
            return ("REJECT-DROP", true)
        case _ where u.hasPrefix("REJECT"):
            return ("REJECT", true)
        case "PASS":
            return ("PASS", true)
        default:
            break
        }
        for g in groups {
            if g == n {
                return (g, true)
            }
        }
        for g in groups {
            if g.caseInsensitiveCompare(n) == .orderedSame {
                return (g, true)
            }
        }
        for p in proxies {
            if p.caseInsensitiveCompare(n) == .orderedSame {
                return (p, true)
            }
        }
        if (u == "PROXY" || u == "PROXIES"), let fs = firstSelect, !fs.isEmpty {
            return (fs, true)
        }
        return ("", false)
    }

    // MARK: - Provider Helpers

    static func providerNameFor(url: String, kind: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((kind + "|" + url).utf8))
        let hex = digest.prefix(4).ncHex
        return "custom-" + hex
    }

    static func prettyProviderName(u: String, tag: String) -> String {
        var n = tag.trimmingCharacters(in: .whitespaces)
        if n.isEmpty {
            if let pu = URL(string: u) {
                let path = pu.path
                var b = (path as NSString).lastPathComponent
                if let dot = b.lastIndex(of: "."), dot != b.startIndex {
                    b = String(b[..<dot])
                }
                if b != "/" && b != "." && !b.isEmpty {
                    n = b
                }
                if n.isEmpty {
                    n = pu.host ?? ""
                }
            }
        }
        let badChars: Set<Character> = [",", "\n", "\r", "\t", "/", "(", ")"]
        let mapped = n.map { badChars.contains($0) ? "-" : $0 }
        n = String(mapped).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        if n.isEmpty {
            n = "ruleset"
        }
        return n
    }

    static func uniqueProviderName(base: String, taken: (String) -> Bool) -> String {
        if !taken(base) {
            return base
        }
        var i = 2
        while true {
            let c = "\(base)-\(i)"
            if !taken(c) {
                return c
            }
            i += 1
        }
    }

    // MARK: - Core Conversion

    static func convertCustom(rules: [CustomRule], context: inout ProfileContext) -> [RuleCheck] {
        var checks: [RuleCheck] = []
        for r in rules {
            var ck = RuleCheck(id: r.id, line: r.line, enabled: r.enabled)
            let line = r.line.trimmingCharacters(in: .whitespaces)
            var conv: RuleConv?
            var parseErr: Error?
            var interval = r.interval ?? 0

            if let (sp, ok) = parseQXRemote(line), ok {
                conv = RuleConv(rule: "", type: "RULE-SET", policy: sp.policy, options: "", remoteURL: sp.url, remoteKind: "list", tag: sp.tag, unsupported: "", note: "")
                if interval == 0 {
                    interval = sp.interval
                }
                if !line.lowercased().contains("force-policy") {
                    ck.note = "QX 远程列表未指定 force-policy：整份列表使用 proxy（第一个手动选择组），列表内各行的策略被忽略"
                }
            } else {
                do {
                    conv = try convertRuleLine(line)
                } catch {
                    parseErr = error
                }
            }

            if let err = parseErr {
                ck.error = err.localizedDescription
                checks.append(ck)
                continue
            }

            guard let conv = conv else {
                checks.append(ck)
                continue
            }

            if conv.rule.isEmpty && conv.remoteURL.isEmpty {
                checks.append(ck)
                continue
            }

            if ck.note == nil || ck.note?.isEmpty == true {
                if !conv.note.isEmpty {
                    ck.note = conv.note
                }
            }

            let (pol, ok) = resolvePolicy(conv.policy, groups: context.groups, proxies: context.proxies, firstSelect: context.firstSelect)
            if !ok {
                ck.error = "策略「\(conv.policy)」在当前配置中不存在"
                ck.unresolved = conv.policy
                checks.append(ck)
                continue
            }
            ck.policy = pol

            let rule: String
            if !conv.remoteURL.isEmpty {
                if !r.enabled {
                    ck.rule = "RULE-SET,<\(conv.remoteURL)>,\(pol)"
                    checks.append(ck)
                    continue
                }
                let sp = RemoteSpec(url: conv.remoteURL, kind: conv.remoteKind, policy: pol, interval: interval, tag: conv.tag)
                rule = context.addRemoteProvider(sp: sp) + "," + pol + conv.options
            } else {
                rule = conv.format(pol)
            }
            if NCRule.parse(rule) == nil {
                ck.error = "规则语法解析失败"
            } else {
                ck.rule = rule
            }
            checks.append(ck)
        }
        return checks
    }

    static func readCustomRules(homeDir: String) -> [CustomRule] {
        guard !homeDir.isEmpty else { return [] }
        let path = (homeDir as NSString).appendingPathComponent("rules.json")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return [] }
        struct CustomRulesFile: Codable {
            var rules: [CustomRule] = []
        }
        return (try? JSONDecoder().decode(CustomRulesFile.self, from: data))?.rules ?? []
    }

    // MARK: - Public API (Replacing Libmihomo)

    /// Check one rule line in the editor against the active profile.
    static func checkRuleLine(homeDir: String, profilePath: String, line: String) -> RuleCheck {
        var context = loadProfileContext(homeDir: homeDir, profilePath: profilePath)
        let checks = convertCustom(rules: [CustomRule(id: "1", line: line, enabled: true)], context: &context)
        return checks.first ?? RuleCheck(id: "1", line: line, enabled: true)
    }

    /// Check all rules in <home>/rules.json against the profile.
    static func checkCustomRules(homeDir: String, profilePath: String) -> [RuleCheck] {
        var context = loadProfileContext(homeDir: homeDir, profilePath: profilePath)
        let rules = readCustomRules(homeDir: homeDir)
        return convertCustom(rules: rules, context: &context)
    }

}
