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
/// nc-compat additions: Loon .lpx expression script lines and
/// plugin-object arguments (parseLoonExpressionLine /
/// loonObjectEnvelope), [Plugin] reference lines split into url +
/// parameters, the full `#!` metadata set (not just the five classic
/// keys), Surge type=dns / type=rule script registration (execution
/// contract: PacketTunnel/NativeCore/NCScriptHookRunner.swift), and Egern `scriptings:` import.
/// Not covered (recorded in `unsupported` or noted where they land):
/// Loon *rewrite* expression actions (response.json.replace …),
/// Egern's rewrite families (url_rewrites / header_rewrites /
/// body_rewrites / map_locals object mapping), Stash
/// script-providers, and regex error strings (NSRegularExpression
/// messages differ from Go's regexp2; the error channel and drop
/// behavior are the same).
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
    /// mitm Rule.Source ("用户" or the module name), set by addRule.
    var source = ""
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

/// One Loon [Plugin] reference line (url + parameters + original line).
struct NCEnginePluginRef {
    var url = ""
    var params: [String: String] = [:]
    var line = ""
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
    /// mitm Ruleset.SkipCertVerify / H2: set by [MITM] key lines
    /// (skip-server-cert-verify / skip-cert-verify / skip_validating_cert,
    /// h2) and by Stash YAML http.skip-cert-verify. Build merges a
    /// module's skipCertVerify into the parent ruleset (only-true).
    var skipCertVerify: Bool? = nil
    var h2: Bool? = nil
    /// Source label of the text currently being parsed; addRule stamps
    /// it onto each rule (mitm addRule's source parameter).
    var parseSource = ""
    var name = ""
    var desc = ""
    var author = ""
    var category = ""
    var arguments: [ParsedEngineText.Arg] = []
    var format = ""
    var tasks: [NCEngineTask] = []
    var panels: [NCEnginePanel] = []
    /// Loon [Plugin] reference lines, in file order (nc-compat).
    var plugins: [NCEnginePluginRef] = []
    /// Every `#!key = value` header field, first occurrence wins
    /// (nc-compat); name / desc / author / category keep their dedicated
    /// fields above, the rest (homepage, icon, system, …) lives only here.
    var metadata: [String: String] = [:]
    /// Resolved Loon [Argument] values for expression-line evaluation:
    /// user-supplied value when present, else the declared default, plus
    /// the declared value type (string / number / boolean) and the
    /// declared widget type (switch / select / …) used to type
    /// plugin-object arguments. Filled by parseText.
    var loonArgContext: [String: (value: String, valueType: String?, type: String?)] = [:]

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
            },
            plugins: plugins.isEmpty ? nil : plugins.map {
                ParsedEngineText.PluginRef(url: $0.url, params: $0.params, line: $0.line)
            },
            metadata: metadata.isEmpty ? nil : metadata)
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
        r.source = parseSource
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
            if r.phase == "dns" { return "DNS 脚本 · " + (r.script?.name ?? "") }
            if r.phase == "rule" { return "规则脚本 · " + (r.script?.name ?? "") }
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
    /// `underscore` (nc-compat, Loon `with` lists only) additionally
    /// allows `_` / digits in the key charset so requires_body splits;
    /// the classic default keeps the Go key charset exactly.
    static func splitParams(_ s: String, keys: Set<String>, underscore: Bool = false) -> [String: String] {
        var parts: [String] = []
        var start = s.startIndex
        var inQ = false
        var i = s.startIndex
        while i < s.endIndex {
            let ch = s[i]
            if ch == "\"" { inQ.toggle() }
            if ch == "," && !inQ {
                let rest = s[s.index(after: i)...]
                if let m = keyStartMatch(rest, underscore: underscore), keys.contains(m.lowercased()) {
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
    static func keyStartMatch(_ s: Substring, underscore: Bool = false) -> String? {
        var i = s.startIndex
        while i < s.endIndex && (s[i] == " " || s[i] == "\t") { i = s.index(after: i) }
        var key = ""
        while i < s.endIndex && (s[i].isLetter || s[i] == "-" || (underscore && (s[i] == "_" || s[i].isNumber))) {
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
        // mitm ConvertRuleLine: two sequential TrimPrefix calls, so a
        // YAML list item "- - DOMAIN,…" also converts.
        if line.hasPrefix("- ") { line = String(line.dropFirst(2)) }
        if line.hasPrefix("-") { line = String(line.dropFirst()) }
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
        case "dns": r.phase = "dns" // Surge type=dns (nc-compat; NCScriptHookRunner.swift)
        case "rule": r.phase = "rule" // Surge type=rule (nc-compat; NCScriptHookRunner.swift)
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
        // Search the original string case-insensitively: indices from a lowercased copy (or from
        // `rest.lowercased()`, which restarts at offset 0) are not valid in `line` / `rest` and trapped on launch.
        let key = " " + act + " "
        guard let first = line.range(of: " url" + key, options: .caseInsensitive) else { return nil }
        let rest = line[first.upperBound...]
        guard let second = rest.range(of: key, options: .caseInsensitive) else { return nil }
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
            if let range = line.range(of: act, options: .caseInsensitive) {
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
        // mitm cron.go ParseCron: 5 fields, or 6 with leading seconds —
        // the 6th field is never a year. Ranges must satisfy a <= b
        // (parseField errors on a > b); values resolve through the
        // month / weekday name tables before bounds-checking.
        let f = expr.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard f.count == 5 || f.count == 6 else { return false }
        let bounds5 = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
        let bounds = f.count == 5 ? bounds5 : [(0, 59)] + bounds5
        let monthNames = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
        let dowNames = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
        for (idx, field) in f.enumerated() {
            let (lo, hi) = bounds[idx]
            let isMonth = (f.count == 5 && idx == 3) || (f.count == 6 && idx == 4)
            let isDow = (f.count == 5 && idx == 4) || (f.count == 6 && idx == 5)
            func resolve(_ e: Substring) -> Int? {
                let v = String(e).uppercased()
                if let n = Int(v) { return n }
                if isMonth, let i = monthNames.firstIndex(of: v) { return i + 1 }
                if isDow, let i = dowNames.firstIndex(of: v) { return i }
                return nil
            }
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
                var resolved: [Int] = []
                for e in ends {
                    guard let n = resolve(e) else { return false }
                    if n < lo || n > hi { return false }
                    resolved.append(n)
                }
                if resolved.count == 2 && resolved[0] > resolved[1] { return false }
            }
        }
        return true
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
        return digest.prefix(6).ncHex
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
        // mitm addTask constructs the Task with the event parameter
        // up front (the switch below only validates / defaults it), so
        // a generic task called with event="network-changed" (the Loon
        // generic form) keeps it.
        if !event.isEmpty { t.event = event }
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
                // Go backfills sc.Cron with the ORIGINAL cron string;
                // only t.Cron carries the normalized form.
                mutSc.cron = cron0
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
                // nc-compat: Surge DNS / rule scripts register as script
                // rules (phase "dns" / "rule") so they flow into the
                // script manifest like every other script instead of
                // being dropped here. How the kernel must invoke them is
                // defined in PacketTunnel/NativeCore/NCScriptHookRunner.swift.
                let (r, e) = Self.newScriptRule(name: m[1], type: typ, pattern: p["pattern"] ?? "", p: p)
                addRule(line: line, r, e)
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
    // MARK: Loon plugin references + .lpx expression lines (nc-compat)

    /// [Plugin] reference line: `<url>[, key=value, …]`. The url and
    /// every parameter are kept on the model (projected as
    /// ParsedEngineText.plugins, original line retained for exact
    /// write-back). Lines that do not look like a plugin reference stay
    /// in `unsupported`, as before.
    func parsePluginRefLine(_ line: String) {
        var url = line
        var rest = ""
        var inQ = false
        var i = line.startIndex
        while i < line.endIndex {
            let ch = line[i]
            if ch == "\"" { inQ.toggle() }
            if ch == "," && !inQ {
                url = String(line[..<i])
                rest = String(line[line.index(after: i)...])
                break
            }
            i = line.index(after: i)
        }
        let u = url.trimmingCharacters(in: .whitespaces)
        guard u.contains("://") || u.hasSuffix(".lpx") || u.hasSuffix(".plugin") else {
            unsupported.append(line)
            return
        }
        var params: [String: String] = [:]
        for piece in Self.splitArgList(rest) {
            let t = piece.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if let eq = t.firstIndex(of: "=") {
                let k = String(t[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                params[k] = Self.unquote(String(t[t.index(after: eq)...]))
            } else {
                params[t] = "" // bare token: kept, not dropped
            }
        }
        plugins.append(NCEnginePluginRef(url: u, params: params, line: line))
    }

    static let loonPlaceholderRe = regex(#"\$\{([A-Za-z0-9_.\-]+)\}"#)
    static let loonExprIfRe = regex(#"^(http-request|http-response|request|response)[ \t]+if[ \t]+(.+?)[ \t]+then[ \t]+script\([ \t]*"([^"]*)"[ \t]*(?:,[ \t]*(\{.*\}))?[ \t]*\)(?:[ \t]+with[ \t]+(.+))?$"#, options: [.caseInsensitive])
    static let loonExprCronRe = regex(#"^cron[ \t]+(.+?)[ \t]+then[ \t]+script\([ \t]*"([^"]*)"[ \t]*(?:,[ \t]*(\{.*\}))?[ \t]*\)(?:[ \t]+with[ \t]+(.+))?$"#, options: [.caseInsensitive])
    static let loonExprBareRe = regex(#"^(generic|network-changed)[ \t]+then[ \t]+script\([ \t]*"([^"]*)"[ \t]*(?:,[ \t]*(\{.*\}))?[ \t]*\)(?:[ \t]+with[ \t]+(.+))?$"#, options: [.caseInsensitive])
    static let loonURLTermRe = regex(#"^\$\{url\}[ \t]*(==|!=|~=)[ \t]*/(.*)/$"#)
    static let loonArgTermRe = regex(#"^\$\{([A-Za-z0-9_.\-]+)\}[ \t]*(==|!=|~=)[ \t]*(.+)$"#)
    static let loonBareTermRe = regex(#"^\$\{([A-Za-z0-9_.\-]+)\}$"#)

    /// Replaces every ${name} with the declared argument's resolved
    /// value. Returns nil when any placeholder names an undeclared
    /// argument — callers then leave the source line in `unsupported`
    /// rather than guess.
    func resolveAllPlaceholders(_ s: String) -> String? {
        guard let re = Self.loonPlaceholderRe else { return s }
        let matches = re.matches(in: s, range: NSRange(s.startIndex..., in: s))
        if matches.isEmpty { return s }
        var out = ""
        var idx = s.startIndex
        for m in matches {
            guard let full = Range(m.range, in: s), let g = Range(m.range(at: 1), in: s),
                  let v = loonArgContext[String(s[g])]?.value else { return nil }
            out += String(s[idx..<full.lowerBound])
            out += v
            idx = full.upperBound
        }
        out += String(s[idx...])
        return out
    }

    /// Best-effort variant: declared placeholders are substituted,
    /// undeclared ones (runtime variables) stay as written.
    func substituteDeclaredPlaceholders(_ s: String) -> String {
        guard let re = Self.loonPlaceholderRe else { return s }
        let matches = re.matches(in: s, range: NSRange(s.startIndex..., in: s))
        if matches.isEmpty { return s }
        var out = ""
        var idx = s.startIndex
        for m in matches {
            guard let full = Range(m.range, in: s), let g = Range(m.range(at: 1), in: s) else { continue }
            out += String(s[idx..<full.lowerBound])
            out += loonArgContext[String(s[g])]?.value ?? String(s[full])
            idx = full.upperBound
        }
        out += String(s[idx...])
        return out
    }

    static func loonScalarEqual(_ a: String, _ b: String) -> Bool {
        let x = unquote(a).trimmingCharacters(in: .whitespaces)
        let y = unquote(b).trimmingCharacters(in: .whitespaces)
        if x == y { return true }
        if let dx = Double(x), let dy = Double(y) { return dx == dy }
        let bx = ["true", "false"].contains(x.lowercased())
        let by = ["true", "false"].contains(y.lowercased())
        return bx && by && x.lowercased() == y.lowercased()
    }

    static func jsonEscaped(_ s: String) -> String {
        var out = "\""
        for ch in s {
            switch ch {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if ch.unicodeScalars.count == 1, let sc = ch.unicodeScalars.first, sc.value < 0x20 {
                    out += String(format: "\\u%04x", sc.value)
                } else {
                    out.append(ch)
                }
            }
        }
        return out + "\""
    }

    /// Builds the "__tern_loon_obj__:" envelope setScriptArgument
    /// decodes into a typed object argument, from a script("…", {…})
    /// second argument. Two accepted shapes: an already-JSON object
    /// (used verbatim), or the {${a}, ${b}, …} selector list of plugin
    /// argument names, expanded with each argument's resolved value
    /// typed by its declared [Argument] type= (string / number /
    /// boolean — the value Loon would hand the script as $argument).
    /// Returns nil for anything else; the line then stays in
    /// `unsupported`.
    func loonObjectEnvelope(_ braces: String, line: String) -> String? {
        let t = braces.trimmingCharacters(in: .whitespaces)
        guard t.hasPrefix("{"), t.hasSuffix("}") else { return nil }
        let json: String
        var isJSONObject = false
        if let d = t.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: d) {
            isJSONObject = obj is [String: Any]
        }
        if isJSONObject {
            json = t
        } else {
            let inner = String(t.dropFirst().dropLast())
            var pairs: [String] = []
            for piece in inner.split(separator: ",", omittingEmptySubsequences: false) {
                let name = piece.trimmingCharacters(in: .whitespaces)
                if name.isEmpty { continue }
                guard let m = Self.firstMatch(Self.loonBareTermRe, name) else { return nil }
                let key = m[1]
                guard let ctx = loonArgContext[key] else {
                    errors.append("插件参数未声明：\(key)：\(Self.clip(line, 120))")
                    pairs.append("\(Self.jsonEscaped(key)):\"\"")
                    continue
                }
                let v = ctx.value
                // mitm loonObjectArgs typing: a switch argument is a
                // Boolean before the type= value type is consulted.
                if ctx.type == "switch" {
                    pairs.append("\(Self.jsonEscaped(key)):\(Self.truthy(v) ? "true" : "false")")
                    continue
                }
                switch ctx.valueType {
                case "number":
                    pairs.append("\(Self.jsonEscaped(key)):\(Double(v) != nil ? v : Self.jsonEscaped(v))")
                case "boolean":
                    pairs.append("\(Self.jsonEscaped(key)):\(v.lowercased() == "true" ? "true" : "false")")
                default:
                    pairs.append("\(Self.jsonEscaped(key)):\(Self.jsonEscaped(v))")
                }
            }
            json = "{" + pairs.joined(separator: ",") + "}"
        }
        var b64 = Data(json.utf8).base64EncodedString()
        b64 = b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while b64.hasSuffix("=") { b64.removeLast() }
        return "__tern_loon_obj__:" + b64
    }

    /// Shared tail of the Loon expression forms: the script() path, the
    /// optional {…} object and the `with` parameter list become the
    /// classic key=value map newScriptRule / scriptFromParams consume
    /// (`with` keys use underscores in Loon — requires_body is mapped
    /// to the classic requires-body). Returns nil when a piece cannot
    /// be represented faithfully; the caller then leaves the line in
    /// `unsupported`.
    func loonScriptParams(path: String, braces: String, with: String, line: String) -> [String: String]? {
        var p: [String: String] = ["script-path": path]
        if !with.isEmpty {
            var wp = Self.splitParams(with, keys: Self.scriptKeys.union(["requires_body"]), underscore: true)
            if let v = wp.removeValue(forKey: "requires_body") { wp["requires-body"] = v }
            for (k, v) in wp {
                if k == "enable" || k == "enabled" {
                    guard let r = resolveAllPlaceholders(v) else { return nil }
                    p[k] = r
                } else {
                    p[k] = substituteDeclaredPlaceholders(v)
                }
            }
        }
        if !braces.isEmpty {
            guard let env = loonObjectEnvelope(braces, line: line) else { return nil }
            p["argument"] = env
        }
        return p
    }

    enum LoonIfOutcome {
        case pattern(String)
        case disabled
        case unparseable
    }

    /// Evaluates an `if` condition of a Loon expression script line at
    /// import time. The `${url} ~= /…/ ` term becomes the rule pattern;
    /// argument terms (${arg} == / != / ~= literal) are decided with the
    /// resolved argument values — a false term disables the script
    /// (Loon semantics: the condition can never hold for this install).
    /// Anything richer (||, ordering comparisons, a second url term, an
    /// undeclared argument) is .unparseable and the line is kept
    /// verbatim in `unsupported`.
    func evalLoonIfExpression(_ expr0: String) -> LoonIfOutcome {
        let expr = expr0.trimmingCharacters(in: .whitespaces)
        if expr.contains("||") { return .unparseable }
        var pattern: String? = nil
        for rawTerm in expr.components(separatedBy: "&&") {
            let term = rawTerm.trimmingCharacters(in: .whitespaces)
            if term.isEmpty { return .unparseable }
            if let m = Self.firstMatch(Self.loonURLTermRe, term) {
                guard m[1] == "~=", pattern == nil else { return .unparseable }
                pattern = m[2].replacingOccurrences(of: "\\/", with: "/")
                continue
            }
            if let m = Self.firstMatch(Self.loonArgTermRe, term) {
                guard let lhs = loonArgContext[m[1]]?.value else { return .unparseable }
                var rhs = m[3].trimmingCharacters(in: .whitespaces)
                if rhs.hasPrefix("${"), rhs.hasSuffix("}") {
                    guard let v = loonArgContext[String(rhs.dropFirst(2).dropLast())]?.value else { return .unparseable }
                    rhs = v
                } else if rhs.hasPrefix("/"), rhs.hasSuffix("/"), rhs.count >= 2 {
                    guard m[2] == "~=" else { return .unparseable }
                    let pat = String(rhs.dropFirst().dropLast())
                    guard let re = Self.regex(pat) else { return .unparseable }
                    if re.firstMatch(in: lhs, range: NSRange(lhs.startIndex..., in: lhs)) == nil { return .disabled }
                    continue
                } else {
                    rhs = Self.unquote(rhs)
                }
                switch m[2] {
                case "==":
                    if !Self.loonScalarEqual(lhs, rhs) { return .disabled }
                case "!=":
                    if Self.loonScalarEqual(lhs, rhs) { return .disabled }
                case "~=":
                    guard let re = Self.regex(rhs) else { return .unparseable }
                    if re.firstMatch(in: lhs, range: NSRange(lhs.startIndex..., in: lhs)) == nil { return .disabled }
                default:
                    return .unparseable
                }
                continue
            }
            if let m = Self.firstMatch(Self.loonBareTermRe, term) {
                guard let v = loonArgContext[m[1]]?.value else { return .unparseable }
                if !Self.truthy(v) { return .disabled }
                continue
            }
            return .unparseable
        }
        return .pattern(pattern ?? "")
    }

    /// Loon .lpx expression script lines (Loon 3.5.1+ syntax):
    ///   request|response if <cond> then script("<path>"[, {<args>}]) [with <params>]
    ///   cron <expr> then script("<path>"[, {<args>}]) [with <params>]
    ///   generic|network-changed then script("<path>"[, {<args>}]) [with <params>]
    /// Returns true when the line was consumed. Lines whose condition
    /// or object cannot be mapped return false and land in
    /// `unsupported` verbatim further down parseLine.
    func parseLoonExpressionLine(_ line: String, source: String) -> Bool {
        if let m = Self.firstMatch(Self.loonExprIfRe, line) {
            switch evalLoonIfExpression(m[2]) {
            case .unparseable:
                return false
            case .disabled:
                return true // condition false for this install: Loon never runs it
            case .pattern(let pattern):
                guard let p = loonScriptParams(path: m[3], braces: m[4], with: m[5], line: line) else { return false }
                if Self.disabledByParam(p) { return true }
                let isResponse = m[1].lowercased() == "response" || m[1].lowercased() == "http-response"
                let (r, e) = Self.newScriptRule(name: p["tag"] ?? "", type: isResponse ? "http-response" : "http-request",
                                                pattern: pattern, p: p)
                addRule(line: line, r, e)
                return true
            }
        }
        if let m = Self.firstMatch(Self.loonExprCronRe, line) {
            let rawExpr = Self.unquote(m[1].trimmingCharacters(in: .whitespaces))
            guard let cronExpr = resolveAllPlaceholders(rawExpr) else { return false }
            guard let p = loonScriptParams(path: m[2], braces: m[3], with: m[4], line: line) else { return false }
            if Self.disabledByParam(p) { return true }
            let sc = Self.scriptFromParams(name: p["tag"] ?? "", p: p)
            addTask(kind: "cron", cron: cronExpr, event: "", sc: sc, source: source, line: line, format: "loon", params: p)
            return true
        }
        if let m = Self.firstMatch(Self.loonExprBareRe, line) {
            guard let p = loonScriptParams(path: m[2], braces: m[3], with: m[4], line: line) else { return false }
            if Self.disabledByParam(p) { return true }
            let isEvent = m[1].lowercased() == "network-changed"
            let sc = Self.scriptFromParams(name: p["tag"] ?? "", p: p)
            // mitm parse.go passes event="network-changed" for BOTH the
            // network-changed and generic forms; addTask keeps it on the
            // task (see addTask's up-front event assignment).
            addTask(kind: isEvent ? "event" : "generic", cron: "", event: "network-changed",
                    sc: sc, source: source, line: line, format: "loon", params: p)
            return true
        }
        return false
    }

    func parseLine(_ line0: String, section: String, source: String) {
        parseSource = source
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
            case "skip-server-cert-verify", "skip-cert-verify", "skip_validating_cert":
                // mitm parse.go: rs.SkipCertVerify = truthy(v) — the flag
                // used to be discarded with the other ignored keys, so a
                // module asking to skip verification never took effect.
                skipCertVerify = Self.truthy(v)
                return
            case "h2":
                h2 = Self.truthy(v)
                return
            case "hostname-disabled", "tcp-connection", "ca-passphrase", "ca-p12",
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
        // Loon [Plugin] reference lines and .lpx expression lines
        // (nc-compat). Anything these two do not consume keeps falling
        // through and lands in unsupported below — never silently dropped.
        if section == "plugin" {
            parsePluginRefLine(line)
            return
        }
        if parseLoonExpressionLine(line, source: source) { return }
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
                // fix/nc-jq-full: the filter is everything after the pattern token (searched after the first token:
                // the pattern text can also occur inside "http-response-jq"); a stray repeated phase token
                // ("http-response-jq http-response ^regex '…'", seen in published modules) is skipped.
                var pat = pattern
                var after = line.range(of: toks[0])?.upperBound ?? line.startIndex
                if ["http-response", "http-request"].contains(pattern.lowercased()), toks.count >= 4,
                   let stray = line.range(of: pattern, range: after..<line.endIndex) {
                    after = stray.upperBound
                    pat = toks[2]
                }
                var r = NCEngineRule(kind: "jq", phase: phase, pattern: pat)
                let rest: String
                if let idx = line.range(of: pat, range: after..<line.endIndex) {
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
            case "response-body-json-jq", "request-body-json-jq":
                // fix/nc-jq-full: Loon <regex> response-body-json-jq '<filter>' | jq-path="<url>"
                var r = NCEngineRule(kind: "jq", phase: t1.hasPrefix("response") ? "response" : "request", pattern: pattern)
                var rest = ""
                if let range = line.range(of: toks[1]) {
                    rest = String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
                }
                if rest.isEmpty {
                    add(nil, .message("\(t1) 缺少 jq 表达式"))
                    return
                }
                if rest.hasPrefix("jq-path=") {
                    r.data = Self.unquote(String(rest.dropFirst("jq-path=".count)))
                } else {
                    r.jq = Self.unquote(rest)
                }
                add(r, nil)
                return
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
        /// The [Argument] `type=` value type (string / number / boolean),
        /// lowercased. Not part of ParsedEngineText.Arg; the parser itself
        /// needs it to type plugin-object arguments in Loon expression
        /// lines (nc-compat).
        var valueType: String? = nil
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
                        a.valueType = unquote(vv).lowercased()
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

    /// One Loon .lpx expression script line (nc-compat): `request /
    /// response if … then script(…)`, `cron … then script(…)` or
    /// `generic / network-changed then script(…)`. Such lines resolve
    /// their own ${…} placeholders and `with enable=` at parse time
    /// (parseLoonExpressionLine); the textual substitution in
    /// applyLoonArgs must not touch them — replacing {key} inside the
    /// script("…", {${a}, ${b}}) selector list would corrupt it.
    static let loonExprLineRe = regex(#"^(?:(?:http-request|http-response|request|response)[ \t]+if[ \t]|cron[ \t]+\S.*[ \t]then[ \t]+script\(|(?:generic|network-changed)[ \t]+then[ \t]+script\()"#, options: [.caseInsensitive])

    /// mitm loonArgListRe: Loon's plugin-object argument list.
    static let loonArgListRe = regex(#"\bargument\s*=\s*"?\[\s*(\{[^{}\[\],"]+\}(?:\s*,\s*\{[^{}\[\],"]+\})*)\s*\]"?"#, options: [.caseInsensitive])

    /// mitm loonObjectArgs: turn `argument=[{a},{b}]` into the typed
    /// object envelope (`argument=__tern_loon_obj__:<base64url JSON>`)
    /// BEFORE any {key} substitution — substituting first used to hand
    /// the script the string "[v1,v2]" and setScriptArgument's envelope
    /// decode never triggered. Typing: switch → Boolean (truthy),
    /// type=number → Number when parseable, otherwise String. A list
    /// naming an undeclared argument is left as written.
    static func loonObjectArgs(_ text: String, args: [ModArg], user: [String: String]) -> String {
        guard let re = loonArgListRe else { return text }
        let byKey = Dictionary(args.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        let ns = text as NSString
        var result = ""
        var last = 0
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            guard m.numberOfRanges > 1 else { continue }
            let list = ns.substring(with: m.range(at: 1))
            var pairs: [String] = []
            var ok = true
            for part in list.split(separator: ",") {
                var k = String(part).trimmingCharacters(in: .whitespaces)
                if k.hasPrefix("{") { k.removeFirst() }
                if k.hasSuffix("}") { k.removeLast() }
                k = k.trimmingCharacters(in: .whitespaces)
                if k.hasPrefix("$") { k.removeFirst() }
                if k.hasPrefix("{") { k.removeFirst() }
                if k.hasSuffix("}") { k.removeLast() }
                k = k.trimmingCharacters(in: .whitespaces)
                guard let a = byKey[k] else { ok = false; break }
                let v = user[k] ?? a.def
                if a.type == "switch" {
                    pairs.append("\(jsonEscaped(k)):\(truthy(v) ? "true" : "false")")
                } else if a.valueType == "number",
                          Double(v.trimmingCharacters(in: .whitespaces)) != nil {
                    pairs.append("\(jsonEscaped(k)):\(v.trimmingCharacters(in: .whitespaces))")
                } else {
                    pairs.append("\(jsonEscaped(k)):\(jsonEscaped(v))")
                }
            }
            guard ok else { continue }
            let json = "{" + pairs.joined(separator: ",") + "}"
            var b64 = Data(json.utf8).base64EncodedString()
            b64 = b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            while b64.hasSuffix("=") { b64.removeLast() }
            result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            result += "argument=__tern_loon_obj__:" + b64
            last = m.range.location + m.range.length
        }
        result += ns.substring(from: last)
        return result
    }

    /// mitm applyLoonArgs: encode plugin-object arguments, substitute
    /// {{{key}}} then {key} (NOT ${key} — the expression syntax binds
    /// that itself), then drop enable=false lines and strip resolved
    /// enable= options. Substitution is per line so .lpx expression
    /// lines can be skipped (they are resolved by parseLoonExpressionLine).
    static func applyLoonArgs(_ text0: String, args: [ModArg], user: [String: String]) -> String {
        if args.isEmpty { return text0 }
        let enableRe = regex(#"(^|[,\s])enable\s*=\s*"?([^,\s"]*)"?"#, options: [.caseInsensitive])
        var out: [String] = []
        for raw in text0.split(separator: "\n", omittingEmptySubsequences: false) {
            var l = String(raw)
            if firstMatch(loonExprLineRe, l.trimmingCharacters(in: .whitespaces)) != nil {
                out.append(l)
                continue
            }
            l = loonObjectArgs(l, args: args, user: user)
            for a in args {
                let v = user[a.key] ?? a.def
                l = l.replacingOccurrences(of: "{{{\(a.key)}}}", with: v)
                l = l.replacingOccurrences(of: "{\(a.key)}", with: v)
            }
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
    /// Every `#!key = value` header line (nc-compat: previously only
    /// name / desc / author / category / tag were even looked at; the
    /// rest of the plugin's metadata — homepage, icon, system,
    /// system_version, loon_version, date, type, … — was dropped).
    static let metaRe = regex(#"^#!([A-Za-z0-9_-]+)\s*=\s*(.*)$"#, options: [.anchorsMatchLines])
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
        parseSource = source
        var text = text0
        if text.hasPrefix("\u{FEFF}") { text = String(text.dropFirst()) }
        text = text.replacingOccurrences(of: "\r\n", with: "\n")
        if Self.isEgern(text) {
            parseEgern(text, user: args)
            return
        }
        if parseQXTaskGallery(text) { return }
        var surgeArgs = Self.parseModuleArgs(text)
        if !surgeArgs.isEmpty {
            text = Self.applyModuleArgs(text, user: args)
        }
        let loonArgs = Self.parseLoonArguments(text)
        for a in loonArgs {
            loonArgContext[a.key] = (value: args[a.key] ?? a.def, valueType: a.valueType, type: a.type)
        }
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
                if metadata[key] == nil { metadata[key] = val }
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

    /// mitm IsEgern. (A Stash document — `rules:` plus `- DOMAIN,…`
    /// items — must NOT match here: Go's IsEgern has no such branch,
    /// and with it those files were routed away from parseStash.)
    static func isEgern(_ text: String) -> Bool {
        var hasRulesKey = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            // Go strings.TrimRight(l, " \t\r"): leading indentation is
            // KEPT — the top-level test below and the "  hostnames:" /
            // "    includes:" markers depend on it. Trimming both sides made
            // nested keys look top-level and a mitm-only Egern module
            // (mitm: / hostnames: / includes:) never matched.
            var tail = Substring(raw)
            while let c = tail.last, c == " " || c == "\t" || c == "\r" { tail = tail.dropLast() }
            let t = String(tail)
            if t.isEmpty || t.hasPrefix("#") { continue }
            if t == "http:" || t.hasPrefix("script-providers:") || t == "tiles:" { return false } // Stash
            if !t.hasPrefix(" ") && !t.hasPrefix("-") {
                for k in egernTopKeys where t.hasPrefix(k) { return true }
                if t == "rules:" { hasRulesKey = true }
            }
            if hasRulesKey && firstMatch(egernRuleItemRe, t) != nil { return true }
            if t.hasPrefix("  hostnames:") || t.hasPrefix("    includes:") { return true }
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

    // MARK: Egern helpers (mitm_egern.go egernStr / egernBool / egernEmpty)

    static func egernStr(_ v: NCJSONValue?) -> String {
        guard let v else { return "" }
        if let s = v.string { return s }
        if let b = v.bool { return b ? "true" : "false" }
        if let n = v.number { return n == n.rounded() && abs(n) < 9.0e15 ? String(Int(n)) : String(n) }
        return ""
    }

    static func egernBool(_ v: NCJSONValue?) -> Bool {
        guard let v else { return false }
        if let b = v.bool { return b }
        if let s = v.string { return truthy(s) }
        if let n = v.number { return n != 0 }
        return false
    }

    static func egernEmpty(_ v: NCJSONValue?) -> Bool {
        guard let v else { return true }
        if let o = v.object { return o.isEmpty }
        if let a = v.array { return a.isEmpty }
        if let s = v.string { return s.trimmingCharacters(in: .whitespaces).isEmpty }
        if case .null = v { return true }
        return false
    }

    static let egernCondTypes: [String: String] = [
        "domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "domain_keyword": "DOMAIN-KEYWORD",
        "domain_regex": "DOMAIN-REGEX", "domain_wildcard": "DOMAIN-WILDCARD", "ip_cidr": "IP-CIDR",
        "ip_cidr6": "IP-CIDR6", "geoip": "GEOIP", "asn": "IP-ASN", "url_regex": "URL-REGEX",
        "dest_port": "DST-PORT", "protocol": "PROTOCOL", "rule_set": "RULE-SET",
    ]

    /// mitm egernCond: a rule entry is a single-key object
    /// `{type: {match: …, policy: …}}`; logic keys recurse. Returns the
    /// Surge condition (no policy) or the Go error text.
    static func egernCond(_ item: NCJSONValue) -> (cond: String?, error: String?) {
        guard let obj = item.object, obj.count == 1, let (k, v) = obj.first else {
            return (nil, "无法识别的 Egern 规则")
        }
        let body = v.object ?? [:]
        if k == "and" || k == "or" || k == "not" {
            var items: [NCJSONValue] = []
            if let m = body["match"] {
                if let arr = m.array { items = arr } else { items = [m] }
            }
            var subs: [String] = []
            for s in items {
                let (c, e) = egernCond(s)
                if let e { return (nil, e) }
                if let c { subs.append("(" + c + ")") }
            }
            if subs.isEmpty { return (nil, "逻辑规则缺少条件") }
            return (k.uppercased() + ",(" + subs.joined(separator: ",") + ")", nil)
        }
        guard let t = egernCondTypes[k] else {
            return (nil, "Egern 规则类型 \(k) 暂不支持")
        }
        var match = egernStr(body["match"]).trimmingCharacters(in: .whitespaces)
        if match.isEmpty { return (nil, "\(k) 缺少 match") }
        switch k {
        case "asn":
            let up = match.uppercased()
            match = up.hasPrefix("AS") ? String(up.dropFirst(2)) : up
        case "dest_port":
            match = match.replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: ",", with: "/")
        case "protocol":
            match = match.uppercased()
        default:
            break
        }
        var c = t + "," + match
        if egernBool(body["no_resolve"]) { c += ",no-resolve" }
        return (c, nil)
    }

    /// mitm egernRule.
    func egernRule(_ item: NCJSONValue) {
        guard let obj = item.object, obj.count == 1, let (k, v) = obj.first else {
            unsupported.append("rules: \(item)")
            return
        }
        if k == "default" {
            unsupported.append("default（模块里的兜底规则不导入）")
            return
        }
        let body = v.object ?? [:]
        let policy = Self.egernStr(body["policy"]).trimmingCharacters(in: .whitespaces)
        let (cond, err) = Self.egernCond(item)
        if let err {
            unsupported.append(err)
            return
        }
        guard let cond else { return }
        if policy.isEmpty {
            unsupported.append("规则缺少 policy：" + cond)
            return
        }
        var line = cond + "," + policy
        if cond.hasSuffix(",no-resolve"), k != "and", k != "or", k != "not" {
            line = String(cond.dropLast(",no-resolve".count)) + "," + policy + ",no-resolve"
        }
        parseCoreRule(line)
    }

    static let egernPlaceholderRe = regex(#"\{\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}\}"#)

    /// mitm egernPlaceholderRe substitution: declared keys take their
    /// (user-overridden) value; undeclared placeholders stay as written.
    static func egernSubstitute(_ text: String, vals: [String: String]) -> String {
        guard let re = egernPlaceholderRe else { return text }
        let ns = text as NSString
        var result = ""
        var last = 0
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            let key = ns.substring(with: m.range(at: 1))
            result += vals[key] ?? ns.substring(with: m.range)
            last = m.range.location + m.range.length
        }
        result += ns.substring(from: last)
        return result
    }

    /// mitm egernArgs: compat_arguments defaults (bool value → switch),
    /// ordered by first appearance in the text; the description comes
    /// from the compat_arguments_desc line starting with the key.
    static func egernCompatArgs(_ text: String) -> [ModArg] {
        // Neutralise placeholders so the YAML parses (Go does the same
        // with a regex replace to a constant token).
        guard let re = egernPlaceholderRe else { return [] }
        let neutralized = re.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "__egern_arg__")
        guard let root = NCYAML.parse(neutralized)?.object,
              let defs = root["compat_arguments"]?.object else { return [] }
        let descText = egernStr(root["compat_arguments_desc"])
        let keys = defs.keys.sorted { a, b in
            let ia = text.range(of: a + ":")?.lowerBound ?? text.endIndex
            let ib = text.range(of: b + ":")?.lowerBound ?? text.endIndex
            return ia < ib
        }
        var out: [ModArg] = []
        for k in keys {
            let v = defs[k]
            var a = ModArg(key: k, def: egernStr(v))
            if v?.bool != nil { a.type = "switch" }
            for l in descText.split(separator: "\n") {
                let t = String(l).trimmingCharacters(in: .whitespaces)
                if t.hasPrefix(k) && t.count > k.count {
                    a.desc = t
                    break
                }
            }
            out.append(a)
        }
        return out
    }

    static let egernKnownKeys: Set<String> = ["name", "description", "author", "homepage", "manual",
                                              "icon", "open_url", "compat_arguments", "compat_arguments_desc", "env_schema", "dns",
                                              "rules", "url_rewrites", "header_rewrites", "body_rewrites", "map_locals", "scriptings",
                                              "mitm", "http_captures", "widgets", "bypass_tunnel_proxy", "real_ip_domains",
                                              "proxies", "policy_groups", "category", "version", "date", "env"]

    /// Egern YAML extraction (mitm parseEgern): metadata + author,
    /// compat_arguments (with {{{key}}} substitution), MITM hostnames
    /// (list or includes/excludes map) + skip_server_cert_verify,
    /// nested rules via egernCond, scriptings, widgets → panels, and
    /// unsupported notes for the sections Swift does not carry and for
    /// unknown top-level keys. The rewrite families (url_rewrites /
    /// header_rewrites / body_rewrites / map_locals) are still
    /// surfaced in `unsupported` rather than converted — Go converts
    /// them; that port is outstanding.
    func parseEgern(_ text0: String, user: [String: String] = [:]) {
        format = "egern"
        var text = text0
        let compatArgs = Self.egernCompatArgs(text)
        if !compatArgs.isEmpty {
            arguments.append(contentsOf: compatArgs.map {
                ParsedEngineText.Arg(key: $0.key, default: $0.def, desc: $0.desc, type: $0.type, options: $0.options)
            })
            var vals: [String: String] = [:]
            for a in compatArgs { vals[a.key] = user[a.key] ?? a.def }
            text = Self.egernSubstitute(text, vals: vals)
        }
        guard let root = NCYAML.parse(text)?.object else {
            errors.append("Egern 模块 YAML 解析失败")
            return
        }
        if let n = root["name"]?.string, name.isEmpty { name = n }
        if let d = root["desc"]?.string ?? root["description"]?.string, desc.isEmpty { desc = d }
        if let a = root["author"]?.string, author.isEmpty { author = a }
        for k in ["dns", "http_captures", "bypass_tunnel_proxy", "real_ip_domains", "proxies", "policy_groups"] {
            if let v = root[k], !Self.egernEmpty(v) {
                unsupported.append("\(k)（Egern 模块，暂不支持）")
            }
        }
        for k in root.keys.sorted() where !Self.egernKnownKeys.contains(k) {
            unsupported.append("\(k)（不是 Egern 模块文档里的字段，已忽略）")
        }
        // mitm egernMitM.
        if let mitm = root["mitm"]?.object {
            if let hosts = mitm["hostnames"] {
                if let arr = hosts.array {
                    for h in arr {
                        if let s = h.string { addHosts(s) }
                    }
                } else if let hm = hosts.object {
                    for x in hm["includes"]?.array ?? [] {
                        if let s = x.string { addHosts(s) }
                    }
                    for x in hm["excludes"]?.array ?? [] {
                        guard let s0 = x.string else { continue }
                        let s = s0.trimmingCharacters(in: .whitespaces)
                        if !s.isEmpty {
                            addHosts("-" + (s.hasPrefix("-") ? String(s.dropFirst()) : s))
                        }
                    }
                }
            }
            if let b = mitm["skip_server_cert_verify"]?.bool { skipCertVerify = b }
        }
        if let rules = root["rules"]?.array {
            for item in rules { egernRule(item) }
        }
        if let arr = root["scriptings"]?.array {
            for item in arr { parseEgernScripting(item) }
        }
        if let arr = root["widgets"]?.array {
            for item in arr {
                guard let w = item.object else { continue }
                let wname = Self.egernStr(w["name"])
                if wname.isEmpty { continue }
                var script = Self.egernStr(w["script_name"])
                if script.isEmpty { script = wname }
                var p = NCEnginePanel()
                p.id = Self.stableID([parseSource, "panel", wname])
                p.name = wname
                p.title = wname
                p.script = script
                p.source = parseSource
                p.format = "egern"
                panels.append(p)
            }
        }
        // fix/nc-jq-full: body_rewrites request_jq / response_jq → jq rules (filter inline, or a URL of a .jq file)
        if let arr = root["body_rewrites"]?.array {
            for item in arr { parseEgernBodyRewrite(item) }
        }
        for key in ["url_rewrites", "header_rewrites", "map_locals"] {
            if let arr = root[key]?.array {
                for item in arr { unsupported.append("egern \(key): \(item)") }
            }
        }
        // env_schema: user-set values merge into every script env of
        // this module (Go's deferred put; module env wins). The
        // Arguments projection has no env marker in Swift, so the
        // schema entries themselves are not surfaced as arguments.
        if let schema = root["env_schema"]?.object {
            var userEnv: [String: String] = [:]
            for k in schema.keys {
                if let v = user[k], !v.isEmpty { userEnv[k] = v }
            }
            if !userEnv.isEmpty {
                for i in rules.indices where rules[i].script?.source == nil {
                    rules[i].script?.env.merge(userEnv) { _, new in new }
                }
                for i in tasks.indices {
                    tasks[i].script?.env.merge(userEnv) { _, new in new }
                }
            }
        }
    }

    /// Egern `body_rewrites` item: `- response_jq: {match, filter}` / `- request_jq: …`. Other body rewrite kinds stay
    /// in `unsupported`.
    func parseEgernBodyRewrite(_ item: NCJSONValue) {
        guard let o = item.object else {
            unsupported.append("egern body_rewrites: \(item)")
            return
        }
        var handled = false
        for (key, phase) in [("response_jq", "response"), ("request_jq", "request")] {
            guard let spec = o[key]?.object else { continue }
            handled = true
            let filter = Self.egernStr(spec["filter"]).trimmingCharacters(in: .whitespacesAndNewlines)
            let pats = Self.egernPatterns(spec["match"] ?? .null)
            if filter.isEmpty || pats.isEmpty {
                unsupported.append("egern body_rewrites \(key): match / filter missing")
                continue
            }
            for pat in pats {
                var r = NCEngineRule(kind: "jq", phase: phase, pattern: pat)
                if filter.hasPrefix("http://") || filter.hasPrefix("https://") { r.data = filter } else { r.jq = filter }
                addRule(line: "egern body_rewrites \(key): \(pat)", r, nil)
            }
        }
        if !handled { unsupported.append("egern body_rewrites: \(item)") }
    }

    static func egernPatterns(_ v: NCJSONValue) -> [String] {
        if let s = v.string { return [s] }
        if let arr = v.array { return arr.compactMap { $0.string } }
        if let o = v.object {
            if let arr = o["patterns"]?.array { return arr.compactMap { $0.string } }
            if let s = o["pattern"]?.string { return [s] }
            if let arr = o["match"]?.array { return arr.compactMap { $0.string } }
        }
        return []
    }

    static func egernCrons(_ v: NCJSONValue) -> [String] {
        if let s = v.string { return [s] }
        if let arr = v.array { return arr.compactMap { $0.string } }
        if let o = v.object {
            if let arr = o["crons"]?.array { return arr.compactMap { $0.string } }
            if let s = o["cron"]?.string ?? o["crons"]?.string { return [s] }
        }
        return []
    }

    static func jsonAny(_ v: NCJSONValue) -> Any {
        switch v {
        case .null: return NSNull()
        case .bool(let b): return b
        case .number(let n): return n
        case .string(let s): return s
        case .array(let a): return a.map { jsonAny($0) }
        case .object(let o): return o.mapValues { jsonAny($0) }
        }
    }

    /// JSON text for an Egern `argument` object / array value.
    static func jsonString(of v: NCJSONValue) -> String? {
        let any = jsonAny(v)
        guard JSONSerialization.isValidJSONObject(any),
              let d = try? JSONSerialization.data(withJSONObject: any, options: [.sortedKeys]) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    /// One Egern `scriptings:` entry (nc-compat). Config-level fields
    /// map onto the internal script model as follows:
    ///   name            -> NCEngineScript.name (ctx.script.name)
    ///   url (path/script accepted too)
    ///                   -> NCEngineScript.path; the script source is
    ///                      fetched / cached by NCResources at manifest
    ///                      build, like every other script
    ///   env (map)       -> NCEngineScript.env, exported as the setup's
    ///                      egernEnv (ctx.env inside the script)
    ///   argument        -> NCEngineScript.argument; an object / array
    ///                      becomes a JSON object argument (argObject)
    ///   timeout         -> NCEngineScript.timeout (seconds)
    ///   http_request    -> script rule, phase "request", one rule per
    ///                      pattern (requires_body -> requiresBody)
    ///   http_response   -> script rule, phase "response", likewise
    ///   schedule / cron -> cron task(s), one per cron expression
    ///                      (ctx.cron inside the script)
    ///   network_changed -> event task
    ///   widget          -> generic task (the panel / widget channel)
    ///   dns / rule      -> script rule phase "dns" / "rule": the
    ///                      NCScriptHookRunner.swift contract applies
    /// The ctx object itself is built at run time by the existing
    /// Egern adapter (NCScriptManifest.egernPrelude) from the host
    /// globals: ctx.request <- $request (method / url / headers /
    /// body + text() / json() / arrayBuffer() / bytes()),
    /// ctx.response <- $response, ctx.http <- $httpClient,
    /// ctx.storage <- $persistentStore, ctx.notify <- $notification,
    /// ctx.lookupIP <- $utils, ctx.device <- $network; the script's
    /// return value / ctx.respond() / ctx.abort() is its result
    /// channel, and export-default (ctx) scripts are adapted by
    /// NCScriptManifest.scriptCode at export. ctx.ssh.connect is the
    /// one ctx member the existing adapter explicitly does not
    /// support (it rejects); there is no config-level equivalent.
    /// Fields of an entry that have no equivalent above are NOT
    /// dropped: each is surfaced in `unsupported` with its original
    /// value, and an entry with no mappable trigger at all stays in
    /// `unsupported` whole, as before.
    func parseEgernScripting(_ item: NCJSONValue) {
        guard let obj = item.object else {
            unsupported.append("egern scripting: \(item)")
            return
        }
        let name = obj["name"]?.string ?? ""
        let path = obj["url"]?.string ?? obj["path"]?.string ?? obj["script"]?.string ?? ""
        guard !path.isEmpty else {
            unsupported.append("egern scripting: \(item)")
            return
        }
        var sc = NCEngineScript()
        sc.name = name
        sc.path = path
        if let t = obj["timeout"]?.int { sc.timeout = t }
        if let envObj = obj["env"]?.object {
            for (k, v) in envObj {
                if let s = v.string { sc.env[k] = s }
                else if let n = v.number { sc.env[k] = n == n.rounded() && abs(n) < 1e15 ? String(Int(n)) : String(n) }
                else if let b = v.bool { sc.env[k] = b ? "true" : "false" }
            }
        }
        if let a = obj["argument"] {
            switch a {
            case .string(let s):
                Self.setScriptArgument(&sc, s)
            case .object, .array:
                if let json = Self.jsonString(of: a) {
                    sc.argument = json
                    sc.hasArgument = true
                    sc.argObject = true
                }
            default:
                break
            }
        }
        var consumed: Set<String> = ["name", "url", "path", "script", "timeout", "env", "argument"]
        var imported = false
        let line = "egern scripting: \(name)"
        for (key, phase, type) in [("http_request", "request", "http-request"),
                                   ("http-request", "request", "http-request"),
                                   ("http_response", "response", "http-response"),
                                   ("http-response", "response", "http-response")] {
            guard let trig = obj[key] else { continue }
            consumed.insert(key)
            var s2 = sc
            s2.type = type
            if let rb = trig.object?["requires_body"]?.bool ?? trig.object?["requires-body"]?.bool {
                s2.requiresBody = rb
            }
            let patterns = Self.egernPatterns(trig)
            if patterns.isEmpty {
                unsupported.append("egern scripting \(name): \(key) without patterns: \(trig)")
                continue
            }
            for pat in patterns {
                addRule(line: line, NCEngineRule(kind: "script", phase: phase, pattern: pat, script: s2), nil)
            }
            imported = true
        }
        for key in ["schedule", "cron"] {
            guard let trig = obj[key] else { continue }
            consumed.insert(key)
            let crons = Self.egernCrons(trig)
            if crons.isEmpty {
                unsupported.append("egern scripting \(name): \(key) without crons: \(trig)")
                continue
            }
            for c in crons {
                addTask(kind: "cron", cron: c, event: "", sc: sc, source: "", line: line, format: "egern", params: nil)
            }
            imported = true
        }
        for key in ["network_changed", "network-changed"] {
            guard let trig = obj[key] else { continue }
            consumed.insert(key)
            if trig.bool == false { continue }
            addTask(kind: "event", cron: "", event: "network-changed", sc: sc, source: "", line: line, format: "egern", params: nil)
            imported = true
        }
        if let trig = obj["widget"] {
            consumed.insert("widget")
            if trig.bool != false {
                addTask(kind: "generic", cron: "", event: "", sc: sc, source: "", line: line, format: "egern", params: nil)
                imported = true
            }
        }
        for (key, phase) in [("dns", "dns"), ("rule", "rule")] {
            guard obj[key] != nil else { continue }
            consumed.insert(key)
            var s2 = sc
            s2.type = phase
            let pat = Self.egernPatterns(obj[key]!).first ?? ""
            addRule(line: line, NCEngineRule(kind: "script", phase: phase, pattern: pat, script: s2), nil)
            imported = true
        }
        if !imported {
            unsupported.append("egern scripting: \(item)")
            return
        }
        for k in obj.keys.sorted() where !consumed.contains(k) {
            if let v = obj[k] {
                unsupported.append("egern scripting \(name): unparsed \(k): \(v)")
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
            // mitm parse.go parseStash: http.skip-cert-verify lands on the
            // ruleset, and header-rewrite lines parse after rewrite lines.
            if let scv = http["skip-cert-verify"]?.bool { skipCertVerify = scv }
            for key in ["rewrite", "url-rewrite", "header-rewrite"] {
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
