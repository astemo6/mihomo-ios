import Foundation
import CommonCrypto

/// Pure Swift port of the bridge's module / rewrite text parser
/// (bridge/mitm/parse.go + rules.go + tasks.go, driven by
/// bridge/engine.go's EngineParseText / EngineParseLine). Produces the
/// same ParsedEngineText the app consumed from the Go JSON.
///
/// Covered: Surge / Loon / QX INI-family modules and snippets (script,
/// URL / header / body rewrites, map local, jq / JSON ops, MITM
/// hostnames, [Rule] core rules, [Panel], cron / event / generic tasks,
/// QX task-gallery JSON), Surge #!arguments and Loon [Argument]
/// substitution, format detection identical to ParseText's, and
/// Egern / Stash YAML detection with metadata / hostname / rule
/// extraction.
/// Not covered (recorded in `unsupported` or noted where they land):
/// Loon's .lpx expression syntax and plugin-object arguments, Egern's
/// script-provider machinery beyond name extraction, and regex error
/// strings (NSRegularExpression messages differ from Go's regexp2; the
/// error channel and drop behavior are the same).
enum NCEngineParser {

    static func parseText(_ text: String, argsJSON: String) -> ParsedEngineText {
        var args: [String: String] = [:]
        if let d = argsJSON.data(using: .utf8),
           let m = try? JSONSerialization.jsonObject(with: d) as? [String: String] {
            args = m
        }
        let rs = NCEngineRuleset()
        rs.parseText(text, source: "模块", args: args)
        return rs.projected()
    }

    static func parseLine(_ line: String, section: String) -> ParsedEngineText {
        let rs = NCEngineRuleset()
        rs.parseLine(line, section: section, source: "用户")
        return rs.projected()
    }
}

// MARK: - Internal model (mirrors mitm.Rule / Script / Task / Panel)

struct NCEngineScript {
    var name = ""
    var type = ""
    var path = ""
    var argument = ""
    var hasArgument = false
    var argObject = false
    var requiresBody = false
    var binaryBody = false
    var maxSize = 0
    var timeout = 0
    var updateInterval = 0
    var echo = false
    var cron = ""
    var env: [String: String] = [:]
    var source: Data? = nil
}

struct NCEngineRule {
    var kind = ""
    var phase = ""
    var pattern = ""
    var action = ""
    var target = ""
    var headers: [(op: String, name: String, value: String, regex: String)] = []
    var body: [(regex: String, repl: String)] = []
    var jq = ""
    var jsonCount = 0
    var jsonOps: [(op: String, path: String, value: String)] = []
    var data = ""
    var dataType = ""
    var respHeaders: [String: String] = [:]
    var status = 0
    var script: NCEngineScript? = nil
    var headerPattern = ""
    var line = ""
    var desc = ""
}

struct NCEngineTask {
    var id = ""
    var kind = ""
    var name = ""
    var cron: String? = nil
    var event: String? = nil
    var path = ""
    var format = ""
    var line = ""
    var source = ""
    var icon = ""
    var disabledByLine = false
    var script: NCEngineScript? = nil
}

struct NCEnginePanel: Codable {
    var id: String = ""
    var name: String = ""
    var title: String = ""
    var content: String? = nil
    var style: String? = nil
    var icon: String? = nil
    var iconColor: String? = nil
    var script: String? = nil
    var interval: Int? = nil
    var source: String = ""
    var format: String = ""
    var taskId: String? = nil
    var defaultInterval: Int? = nil
    var intervalOverridden: Bool? = nil

    enum CodingKeys: String, CodingKey {
        case id, name, title, content, style, icon, iconColor, script, interval, source, format, taskId, defaultInterval, intervalOverridden
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        if !title.isEmpty { try container.encode(title, forKey: .title) }
        if let content, !content.isEmpty { try container.encode(content, forKey: .content) }
        if let style, !style.isEmpty { try container.encode(style, forKey: .style) }
        if let icon, !icon.isEmpty { try container.encode(icon, forKey: .icon) }
        if let iconColor, !iconColor.isEmpty { try container.encode(iconColor, forKey: .iconColor) }
        if let script, !script.isEmpty { try container.encode(script, forKey: .script) }
        if let interval, interval > 0 { try container.encode(interval, forKey: .interval) }
        try container.encode(source, forKey: .source)
        try container.encode(format, forKey: .format)
        if let taskId, !taskId.isEmpty { try container.encode(taskId, forKey: .taskId) }
        if let defaultInterval, defaultInterval > 0 { try container.encode(defaultInterval, forKey: .defaultInterval) }
        if let intervalOverridden, intervalOverridden { try container.encode(intervalOverridden, forKey: .intervalOverridden) }
    }
}

// MARK: - Ruleset builder

final class NCEngineRuleset {
    var rules: [NCEngineRule] = []
    var hostnames: [String] = []
    var coreRules: [String] = []
    var errors: [String] = []
    var unsupported: [String] = []
    var name = ""
    var desc = ""
    var author = ""
    var category = ""
    var arguments: [ParsedEngineText.Arg] = []
    var format = ""
    var tasks: [NCEngineTask] = []
    var panels: [NCEnginePanel] = []

    /// bridge/engine.go toParsed, field for field.
    func projected() -> ParsedEngineText {
        ParsedEngineText(
            name: name, desc: desc, author: author.isEmpty ? nil : author,
            category: category.isEmpty ? nil : category, format: format,
            rules: rules.map {
                ParsedEngineText.Rule(kind: $0.kind, phase: $0.phase, pattern: $0.pattern,
                                      desc: $0.desc, line: $0.line,
                                      script: $0.script?.name, path: $0.script?.path)
            },
            hostnames: hostnames, coreRules: coreRules, errors: errors,
            unsupported: unsupported, arguments: arguments,
            tasks: tasks.map { t in
                let d: String
                switch t.kind {
                case "cron": d = "定时脚本：" + (t.cron ?? "")
                case "event": d = "事件脚本：网络变化"
                default: d = "通用脚本（手动运行 / 面板）"
                }
                return ParsedEngineText.Task(kind: t.kind, name: t.name, cron: t.cron,
                                             event: t.event, path: t.path,
                                             format: t.format.isEmpty ? nil : t.format,
                                             desc: d, line: t.line)
            },
            panels: panels.map {
                ParsedEngineText.Panel(name: $0.name, title: $0.title, script: $0.script, format: $0.format)
            })
    }

    enum AddError {
        case unsupported
        case message(String)
    }

    /// mitm addRule: validate regexes, describe, append; errors and
    /// unsupported lines are reported against the source line.
    func addRule(line: String, _ r: NCEngineRule?, _ err: AddError?) {
        if case .unsupported? = err {
            unsupported.append(line)
            return
        }
        if case .message(let m)? = err {
            errors.append("\(m)：\(Self.clip(line, 120))")
            return
        }
        guard var r else { return }
        if !r.pattern.isEmpty, !Self.regexValid(r.pattern) {
            errors.append("正则无效：\(Self.clip(line, 120))")
            return
        }
        if !r.headerPattern.isEmpty, !Self.regexValid(r.headerPattern) {
            errors.append("正则无效：\(Self.clip(line, 120))")
            return
        }
        for h in r.headers where !h.regex.isEmpty {
            if !Self.regexValid(h.regex) {
                errors.append("正则无效：\(Self.clip(line, 120))")
                return
            }
        }
        for b in r.body {
            if !Self.regexValid(b.regex) {
                errors.append("正则无效：\(Self.clip(line, 120))")
                return
            }
        }
        r.line = line
        r.desc = Self.describe(r)
        rules.append(r)
    }

    static func regexValid(_ p: String) -> Bool {
        (try? NSRegularExpression(pattern: p)) != nil
    }

    static func clip(_ s: String, _ n: Int) -> String {
        s.count > n ? String(s.prefix(n)) + "…" : s
    }

    /// mitm describe(): the short Chinese UI description of a rule.
    static func describe(_ r: NCEngineRule) -> String {
        switch r.kind {
        case "url":
            switch r.action {
            case "reject": return "拒绝（404）"
            case "reject-200": return "拒绝（空 200）"
            case "reject-img": return "拒绝（1×1 GIF）"
            case "reject-dict": return "拒绝（{}）"
            case "reject-array": return "拒绝（[]）"
            case "reject-drop": return "拒绝（断开）"
            case "302", "307": return r.action + " 重定向 → " + r.target
            case "header": return "改写 URL → " + r.target
            default: break
            }
        case "header":
            let ph = r.phase == "response" ? "响应头" : "请求头"
            guard let h = r.headers.first else { break }
            switch h.op {
            case "add": return ph + "添加 " + h.name
            case "del": return ph + "删除 " + h.name
            case "replace": return ph + "替换 " + h.name
            case "replace-regex": return ph + "正则替换 " + h.name
            case "raw": return ph + "正则改写"
            default: break
            }
        case "body":
            return r.phase == "response" ? "响应体替换（\(r.body.count) 组）" : "请求体替换（\(r.body.count) 组）"
        case "jq":
            return r.phase == "response" ? "响应体 jq" : "请求体 jq"
        case "json":
            return "JSON 改写（\(r.jsonCount) 项）"
        case "maplocal":
            return "本地映射（" + r.dataType + "）"
        case "script":
            var t = r.phase == "response" ? "响应脚本" : "请求脚本"
            if r.script?.requiresBody == true { t += " · 含 body" }
            return t + " · " + (r.script?.name ?? "")
        default:
            break
        }
        return r.kind
    }
}

// MARK: - Lexical helpers (ports of mitm tokenize / splitParams / …)

extension NCEngineRuleset {
    /// mitm tokenize: whitespace split; a token starting with a quote whose
    /// closing quote is followed by whitespace/EOL is taken verbatim.
    static func tokenize(_ s: String) -> [String] {
        let c = Array(s)
        var out: [String] = []
        var i = 0
        while i < c.count {
            while i < c.count && (c[i] == " " || c[i] == "\t") { i += 1 }
            if i >= c.count { break }
            if c[i] == "\"" || c[i] == "'" {
                let q = c[i]
                var found = -1
                var j = i + 1
                while j < c.count {
                    if c[j] == "\\" && q == "\"" { j += 2; continue }
                    if c[j] == q {
                        if j + 1 == c.count || c[j + 1] == " " || c[j + 1] == "\t" { found = j }
                        break
                    }
                    j += 1
                }
                if found > 0 {
                    var tok = String(c[(i + 1)..<found])
                    if q == "\"" { tok = tok.replacingOccurrences(of: "\\\"", with: "\"") }
                    out.append(tok)
                    i = found + 1
                    continue
                }
            }
            var j = i
            while j < c.count && c[j] != " " && c[j] != "\t" { j += 1 }
            out.append(String(c[i..<j]))
            i = j
        }
        return out
    }

    /// mitm tokenizeKV: splits `a="x y" b=z` keeping quoted spans.
    static func tokenizeKV(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inQ = false
        let c = Array(s)
        var i = 0
        while i < c.count {
            let ch = c[i]
            if ch == "\\" && inQ && i + 1 < c.count && c[i + 1] == "\"" {
                cur += "\\\""
                i += 2
                continue
            }
            if ch == "\"" { inQ.toggle() }
            if (ch == " " || ch == "\t" || ch == ",") && !inQ {
                if !cur.isEmpty { out.append(cur); cur = "" }
                i += 1
                continue
            }
            cur.append(ch)
            i += 1
        }
        if !cur.isEmpty { out.append(cur) }
        return out
    }

    static func unquote(_ s0: String) -> String {
        let s = s0.trimmingCharacters(in: .whitespaces)
        if s.count >= 2, let f = s.first, let l = s.last,
           (f == "\"" && l == "\"") || (f == "'" && l == "'") {
            return String(s.dropFirst().dropLast())
        }
        return s
    }

    static let scriptKeys: Set<String> = ["type", "pattern", "requires-body", "max-size", "binary-body-mode",
                                          "script-path", "argument", "timeout", "script-update-interval", "debug",
                                          "engine", "cronexp", "cron", "wake-system", "ability", "tag", "enable",
                                          "img-url", "event-name", "enabled", "binary-mode", "requires-header"]

    /// mitm splitParams: split on commas that start a known key.
    static func splitParams(_ s: String, keys: Set<String>) -> [String: String] {
        var parts: [String] = []
        var start = s.startIndex
        var inQ = false
        var i = s.startIndex
        while i < s.endIndex {
            let ch = s[i]
            if ch == "\"" { inQ.toggle() }
            if ch == "," && !inQ {
                let rest = s[s.index(after: i)...]
                if let m = keyStartMatch(rest), keys.contains(m.lowercased()) {
                    parts.append(String(s[start..<i]))
                    start = s.index(after: i)
                }
            }
            i = s.index(after: i)
        }
        parts.append(String(s[start...]))
        var out: [String: String] = [:]
        for p in parts {
            guard let eq = p.firstIndex(of: "=") else { continue }
            let k = String(p[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            out[k] = unquote(String(p[p.index(after: eq)...]))
        }
        return out
    }

    /// ^\s*([a-zA-Z-]+)\s*= — returns the key when the text starts with one.
    static func keyStartMatch(_ s: Substring) -> String? {
        var i = s.startIndex
        while i < s.endIndex && (s[i] == " " || s[i] == "\t") { i = s.index(after: i) }
        var key = ""
        while i < s.endIndex && (s[i].isLetter || s[i] == "-") {
            key.append(s[i])
            i = s.index(after: i)
        }
        guard !key.isEmpty else { return nil }
        while i < s.endIndex && (s[i] == " " || s[i] == "\t") { i = s.index(after: i) }
        return i < s.endIndex && s[i] == "=" ? key : nil
    }

    /// mitm splitTop: split on commas outside parentheses.
    static func splitTop(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var start = s.startIndex
        var i = s.startIndex
        while i < s.endIndex {
            switch s[i] {
            case "(": depth += 1
            case ")": depth -= 1
            case "," where depth == 0:
                out.append(String(s[start..<i]).trimmingCharacters(in: .whitespaces))
                start = s.index(after: i)
            default: break
            }
            i = s.index(after: i)
        }
        out.append(String(s[start...]).trimmingCharacters(in: .whitespaces))
        return out
    }

    /// mitm splitArgList: split on commas outside double quotes.
    static func splitArgList(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inQ = false
        for ch in s {
            if ch == "\"" { inQ.toggle() }
            if ch == "," && !inQ {
                out.append(cur)
                cur = ""
                continue
            }
            cur.append(ch)
        }
        if !cur.isEmpty { out.append(cur) }
        return out
    }

    static func truthy(_ s: String) -> Bool {
        ["1", "true", "yes", "on"].contains(s.trimmingCharacters(in: .whitespaces).lowercased())
    }

    static func atoiDef(_ s: String, _ d: Int) -> Int {
        Int(s.trimmingCharacters(in: .whitespaces)) ?? d
    }
}

// MARK: - Core rule translation (mitm rules.go)

extension NCEngineRuleset {
    static let surgeTypeMap: [String: String] = [
        "DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD": "DOMAIN-WILDCARD", "DOMAIN-REGEX": "DOMAIN-REGEX", "IP-CIDR": "IP-CIDR",
        "IP-CIDR6": "IP-CIDR6", "IP6-CIDR": "IP-CIDR6", "GEOIP": "GEOIP", "IP-ASN": "IP-ASN",
        "GEOSITE": "GEOSITE", "DEST-PORT": "DST-PORT", "DST-PORT": "DST-PORT", "SRC-PORT": "SRC-PORT",
        "IN-PORT": "IN-PORT", "SRC-IP": "SRC-IP-CIDR", "SRC-IP-CIDR": "SRC-IP-CIDR",
        "PROCESS-NAME": "PROCESS-NAME", "PROCESS-PATH": "PROCESS-PATH", "NETWORK": "NETWORK",
        "IP-SUFFIX": "IP-SUFFIX", "SRC-GEOIP": "SRC-GEOIP", "SRC-IP-ASN": "SRC-IP-ASN",
        "DSCP": "DSCP", "UID": "UID", "IN-TYPE": "IN-TYPE", "IN-NAME": "IN-NAME",
        "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD",
        "HOST-WILDCARD": "DOMAIN-WILDCARD", "IP6-CIDR6": "IP-CIDR6",
    ]

    static let unsupportedTypes: [String: String] = [
        "USER-AGENT": "mihomo 不支持 USER-AGENT 规则（可用 MitM 重写代替）",
        "URL-REGEX": "mihomo 规则不匹配 URL；REJECT 类策略会转为 MitM URL 重写",
        "CELLULAR-RADIO": "iOS 扩展内无法获取蜂窝制式",
        "DEVICE-NAME": "不支持",
        "SUBNET": "不支持（Surge 网络条件规则）",
        "SCRIPT": "不支持脚本规则",
        "HOSTNAME-TYPE": "不支持",
    ]

    struct RuleConv {
        var rule = ""
        var type = ""
        var policy = ""
        var options = ""
        var remoteURL = ""
        var remoteKind = ""
        var unsupported = ""
        func format(_ policy: String) -> String {
            if type == "MATCH" { return "MATCH," + policy }
            return rule + "," + policy + options
        }
    }

    static func fixValue(_ t: String, _ v0: String) -> String {
        let v = v0.trimmingCharacters(in: .whitespaces)
        switch t {
        case "SRC-IP-CIDR", "IP-CIDR", "IP-CIDR6":
            if !v.contains("/") {
                if let ip = NCIP(v) { return v + (ip.isV4 ? "/32" : "/128") }
            }
        case "IP-ASN", "SRC-IP-ASN":
            var u = v.uppercased()
            if u.hasPrefix("AS") { u = String(u.dropFirst(2)) }
            return u
        default:
            break
        }
        return v
    }

    static func noResolve(_ opts: [String]) -> String {
        opts.contains { $0.trimmingCharacters(in: .whitespaces).lowercased() == "no-resolve" } ? ",no-resolve" : ""
    }

    /// mitm convertLogicBody (throws the Go error strings).
    static func convertLogicBody(_ body0: String) throws -> String {
        let body = body0.trimmingCharacters(in: .whitespaces)
        guard body.hasPrefix("(") && body.hasSuffix(")") else {
            throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "逻辑规则格式错误"])
        }
        let inner = String(body.dropFirst().dropLast())
        var parts: [String] = []
        for sub0 in splitTop(inner) {
            let sub = sub0.trimmingCharacters(in: .whitespaces)
            guard sub.hasPrefix("(") && sub.hasSuffix(")") else {
                throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "逻辑规则子项格式错误：\(sub)"])
            }
            let fields = splitTop(String(sub.dropFirst().dropLast()))
            let t = (fields.first ?? "").uppercased()
            if t == "AND" || t == "OR" || t == "NOT" {
                guard fields.count >= 2 else {
                    throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "逻辑规则缺少条件"])
                }
                let nb = try convertLogicBody(fields.dropFirst().joined(separator: ","))
                parts.append("(\(t),\(nb))")
                continue
            }
            if t == "PROTOCOL" && fields.count > 1 {
                let p = fields[1].uppercased()
                parts.append(p == "UDP" || p == "QUIC" ? "(NETWORK,UDP)" : "(NETWORK,TCP)")
                continue
            }
            guard let mt = surgeTypeMap[t] else {
                if let why = unsupportedTypes[t] {
                    throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(t)：\(why)"])
                }
                throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "不支持的规则类型 \(t)"])
            }
            guard fields.count >= 2 else {
                throw NSError(domain: "engine", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(t) 缺少内容"])
            }
            parts.append("(\(mt),\(fixValue(mt, fields[1])))")
        }
        return "(" + parts.joined(separator: ",") + ")"
    }

    /// mitm ConvertRuleLine: (conv, error message?) — error also fills
    /// conv.unsupported for the "unsupported type" cases, like Go.
    static func convertRuleLine(_ line0: String) -> (RuleConv, String?) {
        var line = line0.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
            return (RuleConv(), nil)
        }
        if line.hasPrefix("- ") { line = String(line.dropFirst(2)) }
        else if line.hasPrefix("-") { line = String(line.dropFirst()) }
        line = line.trimmingCharacters(in: .whitespaces)
        let parts = splitTop(line)
        let t = (parts.first ?? "").uppercased()
        switch t {
        case "FINAL", "MATCH":
            return (RuleConv(rule: "MATCH", type: "MATCH", policy: parts.count > 1 ? parts[1] : "DIRECT"), nil)
        case "AND", "OR", "NOT":
            guard parts.count >= 3 else { return (RuleConv(), "逻辑规则缺少策略") }
            do {
                let body = try convertLogicBody(parts[1])
                return (RuleConv(rule: t + "," + body, type: t, policy: parts[2]), nil)
            } catch let e as NSError {
                return (RuleConv(unsupported: e.localizedDescription), e.localizedDescription)
            }
        case "RULE-SET", "DOMAIN-SET":
            guard parts.count >= 3 else { return (RuleConv(), "\(t) 缺少策略") }
            let src = parts[1]
            let kind = t == "DOMAIN-SET" ? "domainset" : "list"
            if src.contains("://") {
                return (RuleConv(type: "RULE-SET", policy: parts[2], options: noResolve(Array(parts.dropFirst(3))),
                                 remoteURL: src, remoteKind: kind), nil)
            }
            if src.uppercased() == "SYSTEM" || src.uppercased() == "LAN" {
                return (RuleConv(rule: "GEOIP,private", type: "GEOIP", policy: parts[2], options: ",no-resolve"), nil)
            }
            return (RuleConv(rule: "RULE-SET," + src, type: "RULE-SET", policy: parts[2],
                             options: noResolve(Array(parts.dropFirst(3)))), nil)
        case "PROTOCOL":
            guard parts.count >= 3 else { return (RuleConv(), "PROTOCOL 缺少策略") }
            let p = parts[1].uppercased()
            return (RuleConv(rule: "NETWORK," + (p == "UDP" || p == "QUIC" ? "UDP" : "TCP"),
                             type: "NETWORK", policy: parts[2]), nil)
        default:
            break
        }
        if let why = unsupportedTypes[t] {
            return (RuleConv(type: t, policy: parts.count > 2 ? parts[2] : "", unsupported: why), "\(t)：\(why)")
        }
        guard let mt = surgeTypeMap[t] else {
            return (RuleConv(type: t, unsupported: "不支持的规则类型 \(parts.first ?? "")"),
                    "不支持的规则类型 \(parts.first ?? "")")
        }
        guard parts.count >= 3 else { return (RuleConv(), "\(t) 缺少策略") }
        return (RuleConv(rule: mt + "," + fixValue(mt, parts[1]), type: mt, policy: parts[2],
                         options: noResolve(Array(parts.dropFirst(3)))), nil)
    }

    /// mitm parseCoreRule.
    func parseCoreRule(_ line: String) {
        let parts = Self.splitTop(line)
        if (parts.first ?? "").uppercased() == "URL-REGEX" && parts.count >= 3 {
            let policy = parts[2].uppercased()
            if policy.hasPrefix("REJECT") {
                var act = "reject"
                if policy == "REJECT-TINYGIF" { act = "reject-img" }
                else if policy == "REJECT-DROP" { act = "reject-drop" }
                else if policy == "REJECT-200" { act = "reject-200" }
                addRule(line: line, NCEngineRule(kind: "url", phase: "request", pattern: parts[1], action: act), nil)
                return
            }
        }
        let (c, err) = Self.convertRuleLine(line)
        if err != nil || (c.rule.isEmpty && c.remoteURL.isEmpty) {
            unsupported.append(line)
            return
        }
        if !c.remoteURL.isEmpty {
            coreRules.append("\((parts.first ?? "").uppercased()),\(c.remoteURL),\(c.policy)\(c.options)")
            return
        }
        coreRules.append(c.format(c.policy))
    }

    func addHosts(_ v: String) {
        for h0 in v.split(separator: ",") {
            var h = h0.trimmingCharacters(in: .whitespaces)
            if h.hasPrefix("%APPEND%") { h = String(h.dropFirst(8)) }
            if h.hasPrefix("%INSERT%") { h = String(h.dropFirst(8)) }
            h = h.trimmingCharacters(in: .whitespaces)
            if h.isEmpty || h.hasPrefix("%") { continue }
            hostnames.append(h.lowercased())
        }
    }
}

// MARK: - Script / header / map-local / QX line parsers

extension NCEngineRuleset {
    static func normScriptType(_ t0: String) -> String {
        switch t0.lowercased().trimmingCharacters(in: .whitespaces) {
        case "request", "http-request": return "http-request"
        case "response", "http-response": return "http-response"
        default: return t0.lowercased().trimmingCharacters(in: .whitespaces)
        }
    }

    static func scriptNameFromPath(_ p0: String) -> String {
        var p = p0
        if p.hasSuffix("/") { p = String(p.dropLast()) }
        if let i = p.lastIndex(where: { $0 == "/" || $0 == "\\" }) { p = String(p[p.index(after: i)...]) }
        if let i = p.firstIndex(where: { $0 == "?" || $0 == "#" }) { p = String(p[..<i]) }
        if p.hasSuffix(".js") { p = String(p.dropLast(3)) }
        return p
    }

    static func setScriptArgument(_ sc: inout NCEngineScript, _ a: String) {
        sc.argument = a
        sc.hasArgument = true
        let t = a.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("__tern_loon_obj__:") {
            let enc = String(t.dropFirst("__tern_loon_obj__:".count))
            var b64 = enc.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            let rem = b64.count % 4
            if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }
            if let d = Data(base64Encoded: b64), (try? JSONSerialization.jsonObject(with: d)) != nil,
               let s = String(data: d, encoding: .utf8) {
                sc.argument = s
                sc.argObject = true
            }
        }
    }

    /// mitm newScriptRule: (rule, error).
    static func newScriptRule(name: String, type typ0: String, pattern: String,
                              p: [String: String]) -> (NCEngineRule?, AddError?) {
        let typ = normScriptType(typ0)
        var sc = NCEngineScript()
        sc.name = name.trimmingCharacters(in: .whitespaces)
        sc.type = typ
        sc.path = p["script-path"] ?? ""
        sc.timeout = atoiDef(p["timeout"] ?? "", 10)
        sc.maxSize = atoiDef(p["max-size"] ?? "", 0)
        sc.updateInterval = atoiDef(p["script-update-interval"] ?? "", 86400)
        sc.requiresBody = truthy(p["requires-body"] ?? "")
        sc.binaryBody = truthy(p["binary-body-mode"] ?? "") || truthy(p["binary-mode"] ?? "")
        if let a = p["argument"] { setScriptArgument(&sc, a) }
        if let c = p["cronexp"], !c.isEmpty { sc.cron = c }
        else if let c = p["cron"], !c.isEmpty { sc.cron = c }
        if sc.name.isEmpty { sc.name = p["tag"] ?? "" }
        if sc.name.isEmpty { sc.name = scriptNameFromPath(sc.path) }
        if sc.path.isEmpty { return (nil, .message("脚本缺少 script-path")) }
        var r = NCEngineRule(kind: "script", pattern: pattern, script: sc)
        switch typ {
        case "http-request": r.phase = "request"
        case "http-response": r.phase = "response"
        default: return (r, .unsupported)
        }
        return (r, nil)
    }

    static func scriptFromParams(name: String, p: [String: String]) -> NCEngineScript {
        var sc = NCEngineScript()
        sc.name = name.trimmingCharacters(in: .whitespaces)
        sc.path = p["script-path"] ?? ""
        sc.timeout = atoiDef(p["timeout"] ?? "", 0)
        sc.updateInterval = atoiDef(p["script-update-interval"] ?? "", 86400)
        if let a = p["argument"] { setScriptArgument(&sc, a) }
        if sc.name.isEmpty { sc.name = p["tag"] ?? "" }
        if sc.name.isEmpty { sc.name = scriptNameFromPath(sc.path) }
        return sc
    }

    static let urlActions: Set<String> = ["reject", "reject-200", "reject-img", "reject-dict", "reject-array",
                                          "reject-drop", "reject-no-drop", "reject-tinygif", "reject-video",
                                          "302", "307", "301", "header"]

    static func normURLAction(_ a0: String) -> String {
        switch a0.lowercased() {
        case "reject-tinygif": return "reject-img"
        case "reject-no-drop": return "reject"
        case "reject-video": return "reject-200"
        case "301": return "302"
        default: return a0.lowercased()
        }
    }

    static let headerOps: [String: String] = [
        "header-add": "add", "header-del": "del", "header-replace": "replace",
        "header-replace-regex": "replace-regex",
        "request-add": "add", "request-del": "del", "request-replace": "replace",
        "request-replace-regex": "replace-regex",
        "response-add": "add", "response-del": "del", "response-replace": "replace",
        "response-replace-regex": "replace-regex",
    ]

    /// mitm parseHeaderOp.
    static func parseHeaderOp(_ op: String, _ args: [String]) -> (op: String, name: String, value: String, regex: String, err: AddError?) {
        let o = headerOps[op] ?? ""
        switch o {
        case "del":
            if args.isEmpty { return (o, "", "", "", .message("\(op) 需要头名")) }
            return (o, args[0], "", "", nil)
        case "add", "replace":
            if args.isEmpty { return (o, "", "", "", .message("\(op) 需要头名和值")) }
            return (o, args[0], args.dropFirst().joined(separator: " "), "", nil)
        case "replace-regex":
            if args.count < 3 { return (o, "", "", "", .message("\(op) 需要头名、正则和替换值")) }
            return (o, args[0], args.dropFirst(2).joined(separator: " "), args[1], nil)
        default:
            return (o, "", "", "", .unsupported)
        }
    }

    /// mitm parseMapLocal.
    static func parseMapLocal(pattern: String, rest: String) -> NCEngineRule {
        var r = NCEngineRule(kind: "maplocal", phase: "request", pattern: pattern, status: 200)
        for tok in tokenizeKV(rest) {
            guard let eq = tok.firstIndex(of: "=") else { continue }
            let k = String(tok[..<eq]).lowercased()
            let v = unquote(String(tok[tok.index(after: eq)...])).replacingOccurrences(of: "\\\"", with: "\"")
            switch k {
            case "data": r.data = v
            case "data-type": r.dataType = v.lowercased()
            case "status-code": r.status = atoiDef(v, 200)
            case "header":
                for kv in v.split(separator: "|") {
                    if let colon = kv.firstIndex(of: ":") {
                        r.respHeaders[String(kv[..<colon]).trimmingCharacters(in: .whitespaces)] =
                            String(kv[kv.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                    }
                }
            default: break
            }
        }
        if r.dataType.isEmpty { r.dataType = r.data.isEmpty ? "text" : "file" }
        return r
    }

    /// mitm parseLoonJSON. op shape: <phase>-body-json-<verb>.
    static func parseLoonJSON(pattern: String, op: String, args: [String]) -> (NCEngineRule?, AddError?) {
        let phase = op.hasPrefix("response") ? "response" : "request"
        let verb = op.components(separatedBy: "-body-json-").last ?? ""
        var r = NCEngineRule(kind: "json", phase: phase, pattern: pattern)
        var count = 0
        if verb == "del" {
            for a in args {
                r.jsonOps.append((op: "del", path: a, value: ""))
            }
            count = args.count
        } else {
            var i = 0
            while i + 1 < args.count {
                r.jsonOps.append((op: verb, path: args[i], value: args[i + 1]))
                count += 1
                i += 2
            }
        }
        r.jsonCount = count
        if count == 0 { return (nil, .message("JSON 操作缺少参数")) }
        return (r, nil)
    }

    /// mitm qxRawPair: split `… url ACT REGEX ACT REPLACEMENT` on the
    /// repeated keyword, keeping spaces inside the pair.
    static func qxRawPair(line: String, act: String) -> (String, String)? {
        let lower = line.lowercased()
        let key = " " + act + " "
        guard let first = lower.range(of: " url" + key) else { return nil }
        let rest = line[first.upperBound...]
        guard let second = rest.lowercased().range(of: key) else { return nil }
        let re = String(rest[..<second.lowerBound]).trimmingCharacters(in: .whitespaces)
        var repl = String(rest[second.upperBound...])
        repl = String(repl.drop(while: { $0 == " " }))
        repl = repl.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r"))
        if re.isEmpty { return nil }
        return (re, unquoteQXPair(repl))
    }

    static func unquoteQXPair(_ s: String) -> String {
        if s.count >= 2, let f = s.first, let l = s.last,
           (f == "\"" && l == "\"") || (f == "'" && l == "'") {
            let inner = String(s.dropFirst().dropLast())
            if !inner.contains("\"") && !inner.contains("'") { return inner }
        }
        return s
    }

    static func parseQXBodyTokens(pattern: String, act: String, args: [String]) -> (NCEngineRule?, AddError?) {
        let phase = act.replacingOccurrences(of: "-body", with: "")
        var r = NCEngineRule(kind: "body", phase: phase, pattern: pattern)
        if args.count >= 3 && args[1].lowercased() == act {
            r.body = [(args[0], args[2])]
            return (r, nil)
        }
        if args.count >= 2 {
            r.body = [(args[0], args[1])]
            return (r, nil)
        }
        return (nil, .message("参数不足"))
    }

    /// mitm parseQX (`regex url <action> …`).
    static func parseQX(toks: [String], line: String) -> (NCEngineRule?, AddError?) {
        let pattern = toks[0]
        let act = toks[2].lowercased()
        let args = Array(toks.dropFirst(3))
        func arg(_ i: Int) -> String { i < args.count ? args[i] : "" }
        switch act {
        case "reject", "reject-200", "reject-img", "reject-dict", "reject-array",
             "reject-video", "reject-drop", "reject-no-drop":
            return (NCEngineRule(kind: "url", phase: "request", pattern: pattern, action: normURLAction(act)), nil)
        case "302", "307":
            if arg(0).isEmpty { return (nil, .message("\(act) 缺少目标地址")) }
            return (NCEngineRule(kind: "url", phase: "request", pattern: pattern, action: act, target: arg(0)), nil)
        case "request-header", "response-header", "request-body", "response-body":
            if let (re, repl) = qxRawPair(line: line, act: act) {
                if act.hasSuffix("-header") {
                    var r = NCEngineRule(kind: "header", phase: act.replacingOccurrences(of: "-header", with: ""), pattern: pattern)
                    r.headers = [(op: "raw", name: "", value: repl, regex: re)]
                    return (r, nil)
                }
                var r = NCEngineRule(kind: "body", phase: act.replacingOccurrences(of: "-body", with: ""), pattern: pattern)
                r.body = [(re, repl)]
                return (r, nil)
            }
            if act.hasSuffix("-body") { return parseQXBodyTokens(pattern: pattern, act: act, args: args) }
            let phase = act.replacingOccurrences(of: "-header", with: "")
            var r = NCEngineRule(kind: "header", phase: phase, pattern: pattern)
            if args.count >= 3 && args[1].lowercased() == act {
                r.headers = [(op: "raw", name: "", value: args[2], regex: args[0])]
                return (r, nil)
            }
            if args.count >= 2 {
                r.headers = [(op: "raw", name: "", value: args[1], regex: args[0])]
                return (r, nil)
            }
            return (nil, .message("参数不足"))
        case "script-response-body", "script-request-body", "script-response-header",
             "script-request-header", "script-echo-response", "script-analyze-echo-response":
            if arg(0).isEmpty { return (nil, .message("缺少脚本路径")) }
            var sc = NCEngineScript()
            sc.path = arg(0)
            sc.name = scriptNameFromPath(arg(0))
            sc.timeout = 10
            sc.updateInterval = 86400
            var r = NCEngineRule(kind: "script", pattern: pattern)
            switch act {
            case "script-response-body":
                sc.type = "http-response"; sc.requiresBody = true; r.phase = "response"
            case "script-response-header":
                sc.type = "http-response"; r.phase = "response"
            case "script-request-body":
                sc.type = "http-request"; sc.requiresBody = true; r.phase = "request"
            case "script-request-header":
                sc.type = "http-request"; r.phase = "request"
            default:
                sc.type = "http-request"; sc.echo = true; r.phase = "request"
                sc.requiresBody = act == "script-analyze-echo-response"
            }
            r.script = sc
            return (r, nil)
        case "jsonjq-response-body", "jsonjq-request-body":
            let phase = act.replacingOccurrences(of: "jsonjq-", with: "").replacingOccurrences(of: "-body", with: "")
            var rest = ""
            if let range = line.lowercased().range(of: act) {
                rest = String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
            }
            if rest.isEmpty { return (nil, .message("\(act) 缺少 jq 表达式")) }
            var r = NCEngineRule(kind: "jq", phase: phase, pattern: pattern)
            if rest.hasPrefix("jq-path=") {
                r.data = unquote(String(rest.dropFirst("jq-path=".count)))
            } else {
                r.jq = unquote(rest)
            }
            return (r, nil)
        case "echo-response":
            let ct = arg(0)
            var data = arg(2)
            if data.isEmpty { data = arg(1) }
            var r = NCEngineRule(kind: "maplocal", phase: "request", pattern: pattern, status: 200)
            r.dataType = "file"
            r.data = data
            r.respHeaders = ["Content-Type": ct]
            return (r, nil)
        default:
            return (nil, .unsupported)
        }
    }
}

// MARK: - Tasks & panels (mitm tasks.go)

extension NCEngineRuleset {
    static func regex(_ pattern: String, options: NSRegularExpression.Options = []) -> NSRegularExpression? {
        try? NSRegularExpression(pattern: pattern, options: options)
    }

    static func firstMatch(_ re: NSRegularExpression?, _ s: String) -> [String]? {
        guard let re, let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return (0..<m.numberOfRanges).map { i in
            guard let r = Range(m.range(at: i), in: s) else { return "" }
            return String(s[r])
        }
    }

    static let cronFieldOnlyRe = regex(#"^[0-9*?/,\-]+$"#)

    /// ParseCron substitute: 5- or 6-field cron, each field a comma list of
    /// values / ranges / `*` / `?` with optional steps; month and weekday
    /// names allowed in their fields. (Go re-renders the parsed schedule;
    /// the stored form here is the whitespace-collapsed original.)
    static func cronValid(_ expr: String) -> Bool {
        let f = expr.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard f.count == 5 || f.count == 6 else { return false }
        if f.count == 6 {
            // Loon's optional 6th field is a year; Surge's is seconds.
            // Accept when either reading validates.
            if cronValid(f.dropLast().joined(separator: " ")) && yearFieldValid(f[5]) { return true }
        }
        let bounds5 = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
        let bounds = f.count == 5 ? bounds5 : [(0, 59)] + bounds5
        let monthNames = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
        let dowNames = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
        for (idx, field) in f.enumerated() {
            let (lo, hi) = bounds[idx]
            let isMonth = (f.count == 5 && idx == 3) || (f.count == 6 && idx == 4)
            let isDow = (f.count == 5 && idx == 4) || (f.count == 6 && idx == 5)
            for item in field.split(separator: ",", omittingEmptySubsequences: false) {
                var base = String(item)
                if let slash = base.firstIndex(of: "/") {
                    let step = String(base[base.index(after: slash)...])
                    guard let n = Int(step), n > 0 else { return false }
                    base = String(base[..<slash])
                }
                if base == "*" || base == "?" { continue }
                let ends = base.split(separator: "-", omittingEmptySubsequences: false)
                if ends.count > 2 { return false }
                for e in ends {
                    let v = String(e).uppercased()
                    if let n = Int(v) {
                        if n < lo || n > hi { return false }
                    } else if isMonth && monthNames.contains(v) {
                        continue
                    } else if isDow && dowNames.contains(v) {
                        continue
                    } else {
                        return false
                    }
                }
            }
        }
        return true
    }

    static func yearFieldValid(_ field: String) -> Bool {
        if field == "*" || field == "?" { return true }
        return field.split(separator: ",").allSatisfy { part in
            let base = part.split(separator: "/").first.map(String.init) ?? ""
            return base.split(separator: "-").allSatisfy { v in
                v == "*" || (Int(v).map { (1970...2099).contains($0) } ?? false)
            }
        }
    }

    static func cronLooksValid(_ expr: String) -> Bool {
        let f = expr.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard f.count >= 5 && f.count <= 6 else { return false }
        guard firstMatch(cronFieldOnlyRe, String(f[0])) != nil else { return false }
        return cronValid(expr)
    }

    static func stableID(_ parts: [String]) -> String {
        let joined = parts.joined(separator: "\0")
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        let bytes = Array(joined.utf8)
        CC_SHA1(bytes, CC_LONG(bytes.count), &digest)
        return digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    static func disabledByParam(_ p: [String: String]) -> Bool {
        for k in ["enable", "enabled"] {
            if let v = p[k], !truthy(v) {
                return true
            }
        }
        return false
    }

    static func withLineOpts(_ t: inout NCEngineTask, p: [String: String]) {
        if let ic = p["img-url"], ic.hasPrefix("http://") || ic.hasPrefix("https://") {
            t.icon = ic
        }
        t.disabledByLine = disabledByParam(p)
    }

    /// mitm addTask (projection-relevant parts).
    @discardableResult
    func addTask(kind: String, cron cron0: String, event: String, sc: NCEngineScript,
                 source: String = "", line: String, format: String,
                 params: [String: String]? = nil) -> Int? {
        // mitm ParseCron's expression (nc-dego-rest): quotes trimmed, @macros expanded, fields joined by one space.
        let cron = kind == "cron" ? Self.normCron(cron0) : cron0
        if sc.path.isEmpty {
            errors.append("脚本缺少 script-path：" + Self.clip(line, 120))
            return nil
        }
        var mutSc = sc
        var t = NCEngineTask()
        t.kind = kind
        t.name = mutSc.name
        t.path = mutSc.path
        t.format = format
        t.line = line
        t.source = source
        switch kind {
        case "cron":
            guard Self.cronValid(cron) else {
                errors.append("cron 表达式无效：" + Self.clip(line, 120))
                return nil
            }
            let normalized = cron.split(whereSeparator: { $0 == " " || $0 == "\t" }).joined(separator: " ")
            t.cron = normalized
            mutSc.type = "cron"
            if mutSc.cron.isEmpty {
                mutSc.cron = normalized
            }
        case "event":
            let ev = event.isEmpty ? "network-changed" : event
            guard ev == "network-changed" else {
                unsupported.append(line)
                return nil
            }
            t.event = ev
            mutSc.type = "event"
        case "interaction":
            t.event = "interaction"
            mutSc.type = "generic"
        default:
            mutSc.type = "generic"
        }
        if mutSc.timeout <= 0 {
            mutSc.timeout = 30
        }
        t.script = mutSc
        t.id = Self.stableID([source, kind, mutSc.name, mutSc.path, t.cron ?? ""])
        if let params {
            Self.withLineOpts(&t, p: params)
        }
        if let existingIdx = tasks.firstIndex(where: { $0.id == t.id }) {
            if let params {
                Self.withLineOpts(&tasks[existingIdx], p: params)
            }
            return existingIdx
        }
        let idx = tasks.count
        tasks.append(t)
        return idx
    }

    static let cronMacros: [String: String] = [
        "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
        "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
    ]

    /// mitm ParseCron's normalisation (Cron.String()).
    static func normCron(_ expr: String) -> String {
        var e = expr.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let m = cronMacros[e.lowercased()] { e = m }
        return e.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    static let loonCronRe = regex(#"^cron\s+"([^"]+)"\s+(script-path\s*=.*)$"#, options: [.caseInsensitive])
    static let loonCronBareRe = regex(#"^cron\s+((?:\S+\s+){4,5}\S+?)\s+(script-path\s*=.*)$"#, options: [.caseInsensitive])
    static let loonEventRe = regex(#"^(network-changed|generic)\s+(script-path\s*=.*)$"#, options: [.caseInsensitive])
    static let qxEventRe = regex(#"^event-(network|interaction)\s+(\S+?)\s*(,.*)?$"#, options: [.caseInsensitive])
    static let qxCronRe = regex(#"^((?:[0-9*?/,\-A-Za-z]+\s+){4,5}[0-9*?/,\-A-Za-z]+)\s+(\S+?)\s*(,.*)?$"#)
    static let surgeScriptRe = regex(#"^([^=]+?)\s*=\s*(type\s*=.*)$"#)
    static let loonScriptRe = regex(#"^(http-request|http-response)\s+(\S+)\s+(script-path\s*=.*)$"#)
    static let coreLineRe = regex(#"^(url-regex|domain|domain-suffix|domain-keyword|domain-wildcard|domain-regex|ip-cidr6?|geoip|ip-asn|dst-port|host|host-suffix|host-keyword|host-wildcard|ip6-cidr)\s*,[^,]+,"#, options: [.caseInsensitive])

    /// mitm parseTaskLine: returns true when the line was consumed.
    func parseTaskLine(_ line: String, section: String, source: String = "") -> Bool {
        if let m = Self.firstMatch(Self.surgeScriptRe, line) {
            let p = Self.splitParams(m[2], keys: Self.scriptKeys)
            let typ = (p["type"] ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            switch typ {
            case "cron", "event", "generic":
                break
            case "dns", "rule":
                unsupported.append(line)
                return true
            default:
                return false
            }
            let sc = Self.scriptFromParams(name: m[1], p: p)
            let cron = !(p["cronexp"] ?? "").isEmpty ? p["cronexp"]! : (p["cron"] ?? "")
            addTask(kind: typ, cron: cron, event: p["event-name"] ?? "", sc: sc, source: source, line: line, format: "surge", params: p)
            return true
        }
        var lm = Self.firstMatch(Self.loonCronRe, line)
        if lm == nil, let b = Self.firstMatch(Self.loonCronBareRe, line), Self.cronLooksValid(b[1]) {
            lm = b
        }
        if let m = lm {
            let p = Self.splitParams(m[2], keys: Self.scriptKeys)
            addTask(kind: "cron", cron: m[1], event: "", sc: Self.scriptFromParams(name: p["tag"] ?? "", p: p),
                    source: source, line: line, format: "loon", params: p)
            return true
        }
        if let m = Self.firstMatch(Self.loonEventRe, line) {
            let p = Self.splitParams(m[2], keys: Self.scriptKeys)
            let kind = m[1].lowercased() == "network-changed" ? "event" : "generic"
            addTask(kind: kind, cron: "", event: "network-changed", sc: Self.scriptFromParams(name: p["tag"] ?? "", p: p),
                    source: source, line: line, format: "loon", params: p)
            return true
        }
        if let m = Self.firstMatch(Self.qxEventRe, line) {
            var p = Self.splitParams(String(m[3].dropFirst(m[3].hasPrefix(",") ? 1 : 0)), keys: Self.scriptKeys)
            p["script-path"] = m[2]
            let kind = m[1].lowercased() == "network" ? "event" : "interaction"
            addTask(kind: kind, cron: "", event: "network-changed", sc: Self.scriptFromParams(name: p["tag"] ?? "", p: p),
                    source: source, line: line, format: "qx", params: p)
            return true
        }
        let low = line.lowercased()
        if section == "task_local" || low.hasPrefix("0") || low.hasPrefix("*")
            || (low.first?.isNumber ?? false) {
            if let m = Self.firstMatch(Self.qxCronRe, line), Self.cronLooksValid(m[1]),
               m[2].contains(".js") || m[2].contains("://") || section == "task_local" {
                var p = Self.splitParams(String(m[3].dropFirst(m[3].hasPrefix(",") ? 1 : 0)), keys: Self.scriptKeys)
                p["script-path"] = m[2]
                addTask(kind: "cron", cron: m[1], event: "", sc: Self.scriptFromParams(name: p["tag"] ?? "", p: p),
                        source: source, line: line, format: "qx", params: p)
                return true
            }
        }
        return false
    }

    /// mitm parsePanelLine.
    func parsePanelLine(_ line: String, source: String = "") {
        guard let eq = line.firstIndex(of: "=") else { return }
        let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
        let rest = String(line[line.index(after: eq)...])
        let p = Self.splitParams(rest, keys: ["script-name", "update-interval", "title", "content", "style", "icon", "icon-color"])
        var pn = NCEnginePanel()
        pn.name = name
        let title = p["title"] ?? ""
        pn.title = title.isEmpty ? name : title
        if let content = p["content"], !content.isEmpty {
            pn.content = content.replacingOccurrences(of: "\\n", with: "\n")
        }
        if let style = p["style"], !style.isEmpty {
            pn.style = style
        }
        if let icon = p["icon"], !icon.isEmpty {
            pn.icon = icon
        }
        if let iconColor = p["icon-color"], !iconColor.isEmpty {
            pn.iconColor = iconColor
        }
        pn.script = (p["script-name"] ?? "").isEmpty ? nil : p["script-name"]
        let iv = Self.atoiDef(p["update-interval"] ?? "", 0)
        if iv > 0 {
            pn.interval = iv
        }
        pn.source = source
        pn.format = "surge"
        pn.id = Self.stableID([source, "panel", pn.name])
        panels.append(pn)
    }
}

// MARK: - ParseLine (mitm Ruleset.ParseLine)

extension NCEngineRuleset {
    func parseLine(_ line0: String, section: String, source: String) {
        let line = line0.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { return }
        let add: (NCEngineRule?, AddError?) -> Void = { [self] r, e in addRule(line: line, r, e) }

        // MITM section / QX hostname line and assorted key=value switches.
        if let eq = line.firstIndex(of: "=") {
            let key = String(line[..<eq]).lowercased().trimmingCharacters(in: .whitespaces)
            let v = String(line[line.index(after: eq)...])
            switch key {
            case "hostname":
                addHosts(v)
                return
            case "hostname-disabled", "skip-server-cert-verify", "skip-cert-verify",
                 "skip_validating_cert", "h2", "tcp-connection", "ca-passphrase", "ca-p12",
                 "passphrase", "p12", "client-source-address", "auto-quic-block",
                 "skip_src_ip", "skip_dst_ip":
                return
            default:
                break
            }
        }
        if section == "mitm" { return }
        if section == "rule" || section == "filter_local" || section == "filter_remote" {
            parseCoreRule(line)
            return
        }
        if section == "panel" {
            parsePanelLine(line, source: source)
            return
        }
        if section == "general" || section == "host" || section == "proxy" || section == "proxy group" { return }
        // Loon .lpx expression lines are not ported; they fall through and
        // normally land in unsupported below.
        if parseTaskLine(line, section: section, source: source) { return }
        // Surge script line: name = type=..., pattern=...
        if let m = Self.firstMatch(Self.surgeScriptRe, line), !m[1].contains(" url ") {
            let p = Self.splitParams(m[2], keys: Self.scriptKeys)
            let (r, e) = Self.newScriptRule(name: m[1], type: p["type"] ?? "", pattern: p["pattern"] ?? "", p: p)
            add(r, e)
            return
        }
        // Loon script line: http-response ^url script-path=..., tag=x
        if let m = Self.firstMatch(Self.loonScriptRe, line) {
            let p = Self.splitParams(m[3], keys: Self.scriptKeys)
            let (r, e) = Self.newScriptRule(name: p["tag"] ?? "", type: m[1], pattern: m[2], p: p)
            add(r, e)
            return
        }
        let toks = Self.tokenize(line)
        if toks.isEmpty { return }
        // Core rule lines appearing outside [Rule].
        if Self.firstMatch(Self.coreLineRe, line) != nil {
            parseCoreRule(line)
            return
        }
        // Prefixed phase lines: http-request / http-response (+ -jq).
        let t0 = toks[0].lowercased()
        if ["http-request", "http-response", "http-request-jq", "http-response-jq",
            "request", "response", "response-jq", "request-jq"].contains(t0) {
            if toks.count < 3 {
                add(nil, .message("参数不足"))
                return
            }
            let phase = t0.contains("response") ? "response" : "request"
            let pattern = toks[1]
            if t0.hasSuffix("-jq") {
                var r = NCEngineRule(kind: "jq", phase: phase, pattern: pattern)
                let rest: String
                if let idx = line.range(of: pattern) {
                    rest = String(line[idx.upperBound...]).trimmingCharacters(in: .whitespaces)
                } else {
                    rest = ""
                }
                if rest.hasPrefix("jq-path=") {
                    r.data = Self.unquote(String(rest.dropFirst("jq-path=".count)))
                } else {
                    r.jq = Self.unquote(rest)
                }
                add(r, nil)
                return
            }
            if Self.headerOps[toks[2].lowercased()] != nil {
                let h = Self.parseHeaderOp(toks[2].lowercased(), Array(toks.dropFirst(3)))
                var r = NCEngineRule(kind: "header", phase: phase, pattern: pattern)
                if let e = h.err { add(nil, e) } else {
                    r.headers = [(op: h.op, name: h.name, value: h.value, regex: h.regex)]
                    add(r, nil)
                }
                return
            }
            var r = NCEngineRule(kind: "body", phase: phase, pattern: pattern)
            var rest = Array(toks.dropFirst(2))
            if rest.count % 2 != 0 { rest.append("") }
            var i = 0
            while i + 1 < rest.count {
                r.body.append((rest[i], rest[i + 1]))
                i += 2
            }
            add(r, nil)
            return
        }
        // Quantumult X: <regex> <header-regex> url-and-header <action> [args]
        if toks.count >= 4 && toks[2].lowercased() == "url-and-header" {
            let qt = [toks[0], "url"] + Array(toks.dropFirst(3))
            var (r, e) = Self.parseQX(toks: qt, line: line)
            if r != nil { r!.headerPattern = toks[1] }
            add(r, e)
            return
        }
        // Quantumult X: <regex> url <action> [args]
        if toks.count >= 3 && toks[1].lowercased() == "url" {
            let (r, e) = Self.parseQX(toks: toks, line: line)
            add(r, e)
            return
        }
        let pattern = toks[0]
        if toks.count >= 2 {
            let t1 = toks[1].lowercased()
            // Map Local (Surge)
            if section == "map local" || t1.hasPrefix("data=") || t1.hasPrefix("data-type=")
                || line.contains(" data=\"") {
                let rest = String(line.dropFirst(toks[0].count)).trimmingCharacters(in: .whitespaces)
                add(Self.parseMapLocal(pattern: pattern, rest: rest), nil)
                return
            }
            // Header Rewrite (old Surge syntax, request phase)
            if Self.headerOps[t1] != nil {
                let h = Self.parseHeaderOp(t1, Array(toks.dropFirst(2)))
                var r = NCEngineRule(kind: "header", pattern: pattern)
                r.phase = t1.hasPrefix("response-") ? "response" : "request"
                if let e = h.err { add(nil, e) } else {
                    r.headers = [(op: h.op, name: h.name, value: h.value, regex: h.regex)]
                    add(r, nil)
                }
                return
            }
            // Loon: <regex> <action> [target]
            if Self.urlActions.contains(t1) {
                var r = NCEngineRule(kind: "url", phase: "request", pattern: pattern, action: Self.normURLAction(t1))
                if toks.count >= 3 { r.target = toks[2] }
                if (r.action == "302" || r.action == "307" || r.action == "header") && r.target.isEmpty {
                    add(nil, .message("\(r.action) 缺少目标地址"))
                    return
                }
                add(r, nil)
                return
            }
            switch t1 {
            case "response-body-json-del", "response-body-json-replace", "response-body-json-add",
                 "request-body-json-del", "request-body-json-replace", "request-body-json-add":
                let (r, e) = Self.parseLoonJSON(pattern: pattern, op: t1, args: Array(toks.dropFirst(2)))
                add(r, e)
                return
            case "response-body-replace-regex", "request-body-replace-regex":
                var r = NCEngineRule(kind: "body", phase: t1.split(separator: "-").first.map(String.init) ?? "request",
                                     pattern: pattern)
                var rest = Array(toks.dropFirst(2))
                if rest.count % 2 != 0 { rest.append("") }
                var i = 0
                while i + 1 < rest.count {
                    r.body.append((rest[i], rest[i + 1]))
                    i += 2
                }
                add(r, nil)
                return
            case "mock-response-body":
                let afterTwo = line.dropFirst(toks[0].count + toks[1].count + 1)
                add(Self.parseMapLocal(pattern: pattern, rest: afterTwo.trimmingCharacters(in: .whitespaces)), nil)
                return
            case "response-header-add", "response-header-del", "response-header-replace", "response-header-replace-regex",
                 "request-header-add", "request-header-del", "request-header-replace", "request-header-replace-regex":
                let halves = t1.split(separator: "-", maxSplits: 1).map(String.init)
                let phase = halves[0]
                let op = "header-" + String(t1.dropFirst(phase.count + "-header-".count))
                let h = Self.parseHeaderOp(op, Array(toks.dropFirst(2)))
                var r = NCEngineRule(kind: "header", phase: phase, pattern: pattern)
                if let e = h.err { add(nil, e) } else {
                    r.headers = [(op: h.op, name: h.name, value: h.value, regex: h.regex)]
                    add(r, nil)
                }
                return
            default:
                break
            }
        }
        // Surge URL Rewrite: <regex> <replacement> <type>
        if toks.count >= 3 {
            let a = toks[toks.count - 1].lowercased()
            if Self.urlActions.contains(a) {
                add(NCEngineRule(kind: "url", phase: "request", pattern: pattern,
                                 action: Self.normURLAction(a), target: toks[1]), nil)
                return
            }
        }
        if toks.count == 2 && Self.urlActions.contains(toks[1].lowercased()) {
            add(NCEngineRule(kind: "url", phase: "request", pattern: pattern,
                             action: Self.normURLAction(toks[1])), nil)
            return
        }
        // Surge [URL Rewrite] with the type omitted: <regex> <replacement>. Surge uses
        // `header` then — a transparent rewrite of the upstream request, not a redirect
        // (manual.nssurge.com/http/url-rewrite.html). Review M1: the tunnel's .conf path
        // (NCConfImport.applyURLRewrite) reads the same line the same way. Other
        // sections (Loon [Rewrite], QX, Egern) keep the generic behaviour above.
        if toks.count == 2 && section == "url rewrite" {
            add(NCEngineRule(kind: "url", phase: "request", pattern: pattern,
                             action: "header", target: toks[1]), nil)
            return
        }
        unsupported.append(line)
    }
}

// MARK: - Module arguments (Surge #!arguments, Loon [Argument])

extension NCEngineRuleset {
    struct ModArg {
        var key = ""
        var def = ""
        var desc: String? = nil
        var type: String? = nil
        var options: [String]? = nil
    }

    /// mitm ParseModuleArgs.
    static func parseModuleArgs(_ text: String) -> [ModArg] {
        guard let re = regex(#"^#!arguments\s*=\s*(.*)$"#, options: [.anchorsMatchLines]),
              let m = firstMatch(re, text) else { return [] }
        var out: [ModArg] = []
        for kv in splitArgList(m[1]) {
            guard let colon = kv.firstIndex(of: ":") else {
                let k = kv.trimmingCharacters(in: .whitespaces)
                if !k.isEmpty { out.append(ModArg(key: k, def: "")) }
                continue
            }
            let k = String(kv[..<colon]).trimmingCharacters(in: .whitespaces)
            if k.isEmpty { continue }
            out.append(ModArg(key: k, def: unquote(String(kv[kv.index(after: colon)...]))))
        }
        if let dre = regex(#"^#!arguments-desc\s*=\s*(.*)$"#, options: [.anchorsMatchLines]),
           let dm = firstMatch(dre, text), !out.isEmpty {
            let descText = dm[1].replacingOccurrences(of: "\\n", with: "\n")
            for i in out.indices {
                for l in descText.split(separator: "\n") {
                    if String(l).trimmingCharacters(in: .whitespaces).hasPrefix(out[i].key) {
                        out[i].desc = String(l).trimmingCharacters(in: .whitespaces)
                    }
                }
            }
        }
        return out
    }

    /// mitm ApplyModuleArgs.
    static func applyModuleArgs(_ text0: String, user: [String: String]) -> String {
        var text = text0
        for a in parseModuleArgs(text0) {
            let v = user[a.key] ?? a.def
            text = text.replacingOccurrences(of: "{{{\(a.key)}}}", with: v)
        }
        return text
    }

    static let loonArgKeyValid: (String) -> Bool = { k in
        guard let f = k.first, f.isLetter || f == "_" else { return false }
        return k.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }
    }

    /// mitm parseLoonArguments ([Argument] section).
    static func parseLoonArguments(_ text: String) -> [ModArg] {
        var out: [ModArg] = []
        var inSection = false
        let sectionRe = regex(#"^\[([^\]]+)\]\s*$"#)
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = String(raw).trimmingCharacters(in: .whitespaces)
            if let m = firstMatch(sectionRe, t) {
                inSection = m[1].trimmingCharacters(in: .whitespaces).lowercased() == "argument"
                continue
            }
            if !inSection || t.isEmpty || t.hasPrefix("#") || t.hasPrefix(";") { continue }
            guard let eq = t.firstIndex(of: "=") else { continue }
            let k = String(t[..<eq]).trimmingCharacters(in: .whitespaces)
            guard loonArgKeyValid(k) else { continue }
            let parts = splitArgList(String(t[t.index(after: eq)...]).trimmingCharacters(in: .whitespaces))
            if parts.isEmpty { continue }
            var a = ModArg(key: k, type: parts[0].trimmingCharacters(in: .whitespaces).lowercased())
            var vals: [String] = []
            for p0 in parts.dropFirst() {
                let p = p0.trimmingCharacters(in: .whitespaces)
                if let e = p.firstIndex(of: "="), !p.hasPrefix("\"") {
                    let kk = String(p[..<e]).trimmingCharacters(in: .whitespaces).lowercased()
                    let vv = String(p[p.index(after: e)...])
                    switch kk {
                    case "tag":
                        a.desc = (a.desc?.isEmpty ?? true) ? unquote(vv) : unquote(vv) + " · " + (a.desc ?? "")
                    case "desc":
                        a.desc = (a.desc?.isEmpty ?? true) ? unquote(vv) : (a.desc ?? "") + " · " + unquote(vv)
                    case "type":
                        break // ValueType: not carried by ParsedEngineText.Arg
                    default:
                        vals.append(unquote(p))
                    }
                    continue
                }
                vals.append(unquote(p))
            }
            switch a.type {
            case "switch":
                a.def = vals.isEmpty ? "false" : vals[0].lowercased()
                a.options = ["true", "false"]
            case "select":
                a.options = vals
                a.def = vals.first ?? ""
            default:
                a.def = vals.first ?? ""
            }
            out.append(a)
        }
        return out
    }

    /// mitm applyLoonArgs (classic lines only; the .lpx expression and
    /// plugin-object machinery is not ported): substitute {key} (and
    /// Surge-style {{{key}}} first), then drop enable=false lines and
    /// strip resolved enable= options.
    static func applyLoonArgs(_ text0: String, args: [ModArg], user: [String: String]) -> String {
        if args.isEmpty { return text0 }
        var text = text0
        for a in args {
            let v = user[a.key] ?? a.def
            text = text.replacingOccurrences(of: "{{{\(a.key)}}}", with: v)
            text = text.replacingOccurrences(of: "{\(a.key)}", with: v)
        }
        let enableRe = regex(#"(^|[,\s])enable\s*=\s*"?([^,\s"]*)"?"#, options: [.caseInsensitive])
        var out: [String] = []
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var l = String(raw)
            if let re = enableRe,
               let m = re.firstMatch(in: l, range: NSRange(l.startIndex..., in: l)),
               let full = Range(m.range, in: l), let g1 = Range(m.range(at: 1), in: l),
               let g2 = Range(m.range(at: 2), in: l) {
                let val = String(l[g2]).lowercased()
                if val == "false" || val == "0" { continue }
                var start = full.lowerBound
                if String(l[g1]) == "," { start = g1.lowerBound }
                l = String(l[..<start]) + String(l[full.upperBound...])
                l = l.trimmingCharacters(in: CharacterSet(charactersIn: " ,"))
                if l.trimmingCharacters(in: .whitespaces).hasPrefix(",") {
                    l = l.trimmingCharacters(in: .whitespaces)
                    if l.hasPrefix(",") { l = String(l.dropFirst()).trimmingCharacters(in: .whitespaces) }
                }
            }
            out.append(l)
        }
        return out.joined(separator: "\n")
    }
}

// MARK: - ParseText (mitm Ruleset.ParseText)

extension NCEngineRuleset {
    static let sectionRe = regex(#"^\[([^\]]+)\]\s*$"#)
    static let metaRe = regex(#"^#!(name|desc|author|category|tag)\s*=\s*(.*)$"#, options: [.anchorsMatchLines])
    static let loonScriptLineRe = regex(#"^[ \t]*(?:(?:http-request|http-response)[ \t]|cron[ \t]+["0-9*$]|(?:request|response)[ \t]+if[ \t]|(?:generic|network-changed)[ \t]+then[ \t])"#)

    static func isCommentDecoration(_ t: String) -> Bool {
        if t.isEmpty { return true }
        return t.trimmingCharacters(in: CharacterSet(charactersIn: "*-=_~ \t")).isEmpty
    }

    static func hasLoonScriptLine(_ text: String) -> Bool {
        var section = ""
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let l = String(raw)
            let t = l.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("[") && t.hasSuffix("]") {
                section = String(t.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces).lowercased()
                continue
            }
            if section == "script" && firstMatch(loonScriptLineRe, l) != nil { return true }
        }
        return false
    }

    /// mitm parseQXTaskGallery.
    func parseQXTaskGallery(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard t.hasPrefix("{"), t.contains("\"task\""),
              let d = t.data(using: .utf8),
              let g = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let taskLines = g["task"] as? [String], !taskLines.isEmpty else { return false }
        format = "qx"
        name = (g["name"] as? String ?? "").trimmingCharacters(in: .whitespaces)
        desc = (g["description"] as? String ?? "").trimmingCharacters(in: .whitespaces)
        for line in taskLines {
            parseLine(line.trimmingCharacters(in: .whitespaces), section: "task_local", source: "模块")
        }
        return true
    }

    func parseText(_ text0: String, source: String, args: [String: String]) {
        var text = text0
        if text.hasPrefix("\u{FEFF}") { text = String(text.dropFirst()) }
        text = text.replacingOccurrences(of: "\r\n", with: "\n")
        if Self.isEgern(text) {
            parseEgern(text)
            return
        }
        if parseQXTaskGallery(text) { return }
        var surgeArgs = Self.parseModuleArgs(text)
        if !surgeArgs.isEmpty {
            text = Self.applyModuleArgs(text, user: args)
        }
        let loonArgs = Self.parseLoonArguments(text)
        if !loonArgs.isEmpty {
            surgeArgs += loonArgs
            text = Self.applyLoonArgs(text, args: loonArgs, user: args)
            format = "loon"
        }
        arguments = surgeArgs.map {
            ParsedEngineText.Arg(key: $0.key, default: $0.def, desc: $0.desc, type: $0.type, options: $0.options)
        }
        // Metadata (#!name / desc / author / category / tag), in file order.
        if let re = Self.metaRe {
            var idx = text.startIndex
            while let m = re.firstMatch(in: text, range: NSRange(idx..., in: text)),
                  let kr = Range(m.range(at: 1), in: text), let vr = Range(m.range(at: 2), in: text),
                  let full = Range(m.range, in: text) {
                let key = String(text[kr])
                let val = String(text[vr]).trimmingCharacters(in: .whitespaces)
                switch key {
                case "name": if name.isEmpty { name = val }
                case "desc": if desc.isEmpty { desc = val }
                case "author": if author.isEmpty { author = val }
                case "category": category = val
                case "tag": if category.isEmpty { category = val }
                default: break
                }
                idx = full.upperBound
            }
        }
        if Self.isStash(text) {
            format = "stash"
            parseStash(text)
            return
        }
        var section = ""
        var sawSection = false
        var inComment = false, commentHadSection = false, jsBody = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = String(raw).trimmingCharacters(in: .whitespaces)
            if !inComment && t.hasPrefix("/*") && !t.dropFirst(2).contains("*/") {
                inComment = true
                commentHadSection = false
                continue
            }
            if inComment && t.hasSuffix("*/") && !t.hasPrefix("^") {
                inComment = false
                if commentHadSection { jsBody = true }
                continue
            }
            if jsBody { continue }
            if inComment && Self.isCommentDecoration(t) { continue }
            if let m = Self.firstMatch(Self.sectionRe, t) {
                if inComment { commentHadSection = true }
                section = m[1].trimmingCharacters(in: .whitespaces).lowercased()
                sawSection = true
                switch section {
                case "rewrite_local", "filter_local", "rewrite_remote":
                    format = "qx"
                case "mitm":
                    if m[1].trimmingCharacters(in: .whitespaces) == "mitm" && format.isEmpty { format = "qx" }
                case "rewrite", "plugin":
                    if format.isEmpty { format = "loon" }
                case "url rewrite", "header rewrite", "body rewrite", "map local", "script":
                    if format.isEmpty { format = "surge" }
                default:
                    break
                }
                continue
            }
            if ["rewrite_remote", "server_local", "server_remote", "policy", "dns", "argument"].contains(section) {
                continue
            }
            if inComment && section.isEmpty { continue }
            parseLine(t, section: section, source: source)
        }
        if !sawSection && format.isEmpty { format = "list" }
        if format == "surge" && Self.hasLoonScriptLine(text) { format = "loon" }
    }
}

// MARK: - Egern / Stash YAML (detection + extraction slice)

extension NCEngineRuleset {
    static let egernTopKeys = ["scriptings:", "url_rewrites:", "header_rewrites:", "body_rewrites:", "map_locals:",
                               "compat_arguments:", "widgets:", "http_captures:", "real_ip_domains:",
                               "bypass_tunnel_proxy:", "env_schema:"]
    static let egernRuleItemRe = regex(#"^\s*-\s+(domain|domain_suffix|domain_keyword|domain_regex|domain_wildcard|ip_cidr|ip_cidr6|geoip|asn|url_regex|user_agent|dest_port|protocol|rule_set|and|or|not|default|ssid)\s*:\s*$"#)
    static let stashRuleItemRe = regex(#"^\s*-\s+['"]?[A-Za-z][A-Za-z0-9\-]*,"#)

    /// mitm IsEgern.
    static func isEgern(_ text: String) -> Bool {
        var hasRulesKey = false
        var rulesKey = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = String(raw).trimmingCharacters(in: CharacterSet(charactersIn: " \t\r"))
            if t.isEmpty || t.hasPrefix("#") { continue }
            if t == "http:" || t.hasPrefix("script-providers:") || t == "tiles:" { return false } // Stash
            if !t.hasPrefix(" ") && !t.hasPrefix("-") {
                for k in egernTopKeys where t.hasPrefix(k) { return true }
                if t == "rules:" { hasRulesKey = true }
            }
            if hasRulesKey && firstMatch(egernRuleItemRe, t) != nil { return true }
            if t.hasPrefix("  hostnames:") || t.hasPrefix("    includes:") { return true }
            if t == "rules:" { rulesKey = true }
            else if rulesKey && firstMatch(stashRuleItemRe, t) != nil { return true }
        }
        return false
    }

    /// Stash override detection (structural slice of mitm isStash): an
    /// `http:` map carrying mitm / rewrite keys, or a named doc with
    /// rules. Merge markers (`rules#!replace:`) are normalized first.
    static func isStash(_ text: String) -> Bool {
        let normalized = normalizeStashKeys(text)
        guard let root = NCYAML.parse(normalized)?.object else { return false }
        if let http = root["http"]?.object {
            if http["mitm"] != nil || http["rewrite"] != nil || http["url-rewrite"] != nil
                || http["script-providers"] != nil {
                return true
            }
        }
        if root["name"]?.string != nil && (root["rules"] != nil || root["http"] != nil) { return true }
        return false
    }

    /// mitm normalizeStashKeys: drop `#!<word>` merge markers from keys.
    static func normalizeStashKeys(_ text: String) -> String {
        guard let re = regex(#"^(\s*[A-Za-z][A-Za-z0-9_\-]*)#![A-Za-z]*\s*:"#, options: [.anchorsMatchLines]) else { return text }
        return re.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "$1:")
    }

    /// Egern YAML extraction: metadata, MITM hostnames, and the
    /// domain/IP-family rules (as core rules). Scriptings and the
    /// rewrite families need Egern's per-entry object mapping; their
    /// entries are surfaced in `unsupported` rather than dropped.
    func parseEgern(_ text: String) {
        format = "egern"
        guard let root = NCYAML.parse(text)?.object else { return }
        if let n = root["name"]?.string { name = n }
        if let d = root["desc"]?.string ?? root["description"]?.string { desc = d }
        if let hosts = root["mitm"]?.object?["hostnames"]?.array {
            for h in hosts {
                if let s = h.string { addHosts(s) }
            }
        }
        let typeMap: [String: String] = ["domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX",
                                         "domain_keyword": "DOMAIN-KEYWORD", "domain_regex": "DOMAIN-REGEX",
                                         "domain_wildcard": "DOMAIN-WILDCARD", "ip_cidr": "IP-CIDR",
                                         "ip_cidr6": "IP-CIDR6", "geoip": "GEOIP", "asn": "IP-ASN",
                                         "dest_port": "DST-PORT"]
        if let rules = root["rules"]?.array {
            for item in rules {
                guard let obj = item.object,
                      let key = obj.keys.first(where: { typeMap[$0.lowercased()] != nil }),
                      let mt = typeMap[key.lowercased()] else {
                    unsupported.append("egern rule: \(item)")
                    continue
                }
                let value = obj[key]?.string ?? obj[key]?.number.map { String(Int($0)) } ?? ""
                let policy = obj["policy"]?.string ?? obj["policies"]?.string ?? ""
                if policy.isEmpty {
                    unsupported.append("egern rule: \(item)")
                    continue
                }
                parseCoreRule("\(mt),\(value),\(policy)")
            }
        }
        for key in ["scriptings", "url_rewrites", "header_rewrites", "body_rewrites", "map_locals"] {
            if let arr = root[key]?.array {
                for item in arr { unsupported.append("egern \(key): \(item)") }
            }
        }
    }

    /// Stash YAML extraction: metadata, http.mitm hostnames, http
    /// rewrite lines (Surge-style strings, parsed as lines), and rules
    /// (parsed as core rules).
    func parseStash(_ text: String) {
        let normalized = Self.normalizeStashKeys(text)
        guard let root = NCYAML.parse(normalized)?.object else { return }
        if let n = root["name"]?.string, name.isEmpty { name = n }
        if let d = root["desc"]?.string, desc.isEmpty { desc = d }
        if let http = root["http"]?.object {
            if let mitm = http["mitm"]?.array {
                for h in mitm {
                    if let s = h.string { addHosts(s) }
                }
            }
            for key in ["rewrite", "url-rewrite"] {
                if let lines = http[key]?.array {
                    for l in lines {
                        if let s = l.string { parseLine(s, section: "", source: "模块") }
                    }
                }
            }
            if let providers = http["script-providers"]?.array {
                for p in providers { unsupported.append("stash script-provider: \(p)") }
            }
        }
        if let rules = root["rules"]?.array {
            for r in rules {
                if let s = r.string { parseCoreRule(s) }
            }
        }
    }
}

// MARK: - Rewrite form conversion (mitm rewriteform.go)

/// Pure Swift port of mitm.LineFromForm / FormFromLine (driven through
/// this file's ParseLine port): the visual rewrite editor's form model
/// <-> one canonical Surge-syntax line, replacing the Go bridge's
/// LibmihomoRewriteLineFromForm / LibmihomoRewriteFormFromLine.
enum NCRewriteFormConverter {
    static let rejectActions: Set<String> = ["reject", "reject-200", "reject-img", "reject-dict",
                                             "reject-array", "reject-drop"]

    /// mitm quoteTok.
    static func quoteTok(_ s: String) -> String {
        if !s.isEmpty && !s.contains(" ") && !s.contains("\t") && s.first != "\"" && s.first != "'" {
            return s
        }
        return "\"" + s.replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// mitm quoteKV.
    static func quoteKV(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    private static func opt(_ s: String) -> String? { s.isEmpty ? nil : s }

    /// mitm LineFromForm: build the canonical line, then validate it with
    /// the parser (errors / description land back on the form).
    static func line(fromForm f0: RewriteForm) -> RewriteForm {
        var f = f0
        f.error = nil
        f.desc = nil
        let p = f.pattern.trimmingCharacters(in: .whitespaces)
        if f.type != "raw" && p.isEmpty {
            f.error = "请填写 URL 正则"
            return f
        }
        if p.contains(" ") || p.contains("\t") {
            f.error = "URL 正则不能包含空格（用 \\s 或 %20）"
            return f
        }
        let phase = f.phase == "response" ? "response" : "request"
        switch f.type {
        case "reject":
            var a = (f.action ?? "").lowercased()
            if !rejectActions.contains(a) { a = "reject" }
            f.line = p + " - " + a
        case "redirect":
            let a = f.action == "307" ? "307" : "302"
            let t = (f.target ?? "").trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.contains(" ") || t.contains("\t") {
                f.error = "请填写跳转地址（不能有空格，可用 $1 引用分组）"
                return f
            }
            f.line = p + " " + t + " " + a
        case "header":
            let name = (f.headerName ?? "").trimmingCharacters(in: .whitespaces)
            if name.isEmpty || name.contains(" ") || name.contains("\t") || name.contains(":") {
                f.error = "请填写头名（不含空格和冒号）"
                return f
            }
            switch f.headerOp ?? "" {
            case "del":
                f.line = "http-\(phase) \(p) header-del \(name)"
            case "replace", "add":
                f.line = "http-\(phase) \(p) header-\(f.headerOp ?? "") \(name) \(f.headerValue ?? "")"
            case "replace-regex":
                if (f.headerRegex ?? "").isEmpty {
                    f.error = "请填写要替换的正则"
                    return f
                }
                f.line = "http-\(phase) \(p) header-replace-regex \(name) \(quoteTok(f.headerRegex ?? "")) \(f.headerValue ?? "")"
            default:
                f.error = "未知的头部操作"
                return f
            }
            f.line = f.line?.trimmingCharacters(in: CharacterSet(charactersIn: " "))
        case "body":
            if (f.regex ?? "").isEmpty {
                f.error = "请填写要替换的正则"
                return f
            }
            f.line = "http-\(phase) \(p) \(quoteTok(f.regex ?? "")) \(quoteTok(f.replacement ?? ""))"
        case "maplocal":
            var b = p
            let dt = f.dataType ?? ""
            switch dt {
            case "tiny-gif":
                b += " data-type=tiny-gif"
            case "file":
                if (f.data ?? "").trimmingCharacters(in: .whitespaces).isEmpty {
                    f.error = "请填写文件路径或 URL"
                    return f
                }
                b += " data=" + quoteKV(f.data ?? "") + " data-type=file"
            case "base64":
                b += " data=" + quoteKV(f.data ?? "") + " data-type=base64"
            default:
                b += " data=" + quoteKV(f.data ?? "") + " data-type=text"
            }
            if let st = f.status, st > 0 && st != 200 {
                b += " status-code=\(st)"
            }
            var hs: [String] = []
            if let ct = f.contentType?.trimmingCharacters(in: .whitespaces), !ct.isEmpty {
                hs.append("Content-Type:" + ct)
            }
            for h0 in (f.headers ?? "").split(separator: "|") {
                let h = String(h0).trimmingCharacters(in: .whitespaces)
                if !h.isEmpty && h.contains(":") { hs.append(h) }
            }
            if !hs.isEmpty {
                b += " header=" + quoteKV(hs.joined(separator: "|"))
            }
            f.line = b
        case "raw":
            f.line = (f.line ?? "").trimmingCharacters(in: .whitespaces)
            if (f.line ?? "").isEmpty {
                f.error = "规则为空"
                return f
            }
        default:
            f.error = "未知类型"
            return f
        }
        let rs = NCEngineRuleset()
        rs.parseLine(f.line ?? "", section: "", source: "用户")
        if let e = rs.errors.first {
            f.error = e
        } else if rs.rules.count == 1 {
            f.desc = rs.rules[0].desc
        } else if !rs.hostnames.isEmpty && f.type == "raw" {
            f.desc = "MitM 主机名"
        } else if !rs.coreRules.isEmpty && f.type == "raw" {
            f.desc = "内核规则：" + rs.coreRules[0]
        } else if !rs.tasks.isEmpty && f.type == "raw" {
            f.desc = "脚本任务"
        } else {
            f.error = "无法识别这条规则"
        }
        return f
    }

    /// mitm FormFromLine: map a stored line onto the form ("raw" when the
    /// rule does not fit one).
    static func form(fromLine line: String) -> RewriteForm {
        var raw = RewriteForm(type: "raw", line: line.trimmingCharacters(in: .whitespaces))
        let rs = NCEngineRuleset()
        rs.parseLine(line, section: "", source: "用户")
        if let e = rs.errors.first {
            raw.error = e
            return raw
        }
        guard rs.rules.count == 1 else { return raw }
        let r = rs.rules[0]
        raw.desc = r.desc
        var f = RewriteForm()
        f.pattern = r.pattern
        f.phase = r.phase
        f.desc = r.desc
        switch r.kind {
        case "url":
            if rejectActions.contains(r.action) {
                f.type = "reject"
                f.action = r.action
            } else if r.action == "302" || r.action == "307" {
                f.type = "redirect"
                f.action = r.action
                f.target = r.target
            } else {
                return raw
            }
        case "header":
            guard r.headers.count == 1 else { return raw }
            let h = r.headers[0]
            f.type = "header"
            f.headerOp = h.op
            f.headerName = opt(h.name)
            f.headerValue = opt(h.value)
            f.headerRegex = opt(h.regex)
        case "body":
            guard r.body.count == 1 else { return raw }
            f.type = "body"
            f.regex = r.body[0].regex
            f.replacement = r.body[0].repl
        case "maplocal":
            f.type = "maplocal"
            f.data = opt(r.data)
            f.dataType = r.dataType
            f.status = r.status
            switch r.dataType {
            case "text", "base64", "file", "tiny-gif":
                break
            default:
                return raw
            }
            var extra: [String] = []
            for k in r.respHeaders.keys.sorted() {
                if k.lowercased() == "content-type" {
                    f.contentType = r.respHeaders[k]
                } else {
                    extra.append(k + ":" + (r.respHeaders[k] ?? ""))
                }
            }
            f.headers = opt(extra.joined(separator: "|"))
        default:
            return raw
        }
        f.line = line.trimmingCharacters(in: .whitespaces)
        return f
    }
}
