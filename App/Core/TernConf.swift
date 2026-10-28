import Foundation

// feat/nc-conf-native (user decision 2026-10-28 10:14): Tern's own user-facing profile format is a Quantumult X-style
// .conf. This file is the ONE canonical serializer / parser pair:
//
//   internal profile (the YAML the runtime reads, as an NCJSONValue tree) ──serializeProfile──▶ .conf text
//   .conf text ──parse──▶ internal profile (+ the shared rewrite / script / MitM part, see EngineSection)
//
// Contract: parse(serialize(x)) == x for every profile (NCJSONValue equality; YAML comments / key order are not part of
// the profile). The serializer guarantees it by construction: every item is written in its QX form when that form reads
// back to the same value, else in its QX form plus `tern-` correction keys, else in a lossless Tern extension form —
// each step is verified with the parser before it is used. Grammar: docs/tern-conf.md.
//
// Sections (profile-owned): [general] [dns] [policy] [server_local] [server_remote] [filter_remote] [filter_local]
// Sections (shared by every profile, from engine.json): [rewrite_remote] [rewrite_local] [task_local]
//                                                      [script_resource] [mitm]
// Hand-written / imported Quantumult X lines are read with QX semantics (node lines through the same QX node parser the
// importer uses, `filter_remote … force-policy=` as a rule set plus its RULE-SET rule, `host-suffix, a.com, direct` …).
enum TernConf {

    // MARK: - Errors

    struct ParseError: Error, LocalizedError, Equatable {
        var line: Int
        var message: String
        var errorDescription: String? { String(localized: "第 \(line) 行：\(message)") }
    }

    // MARK: - Section names

    static let profileSections = ["general", "dns", "policy", "server_local", "server_remote", "filter_remote", "filter_local"]
    static let engineSections = ["rewrite_remote", "rewrite_local", "task_local", "script_resource", "mitm"]

    /// Top-level profile keys that own a section (everything else goes to [general]).
    static let sectionKeys: [String: String] = ["proxies": "server_local", "proxy-groups": "policy",
                                                "proxy-providers": "server_remote", "rule-providers": "filter_remote",
                                                "rules": "filter_local", "dns": "dns"]

    // MARK: - Value grammar

    /// Number text that reads back to the same Double.
    static func formatNumber(_ d: Double) -> String {
        if d.isFinite, d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
        return "\(d)"
    }

    static func isNumeric(_ t: String) -> Bool {
        guard !t.isEmpty else { return false }
        var digit = false
        for u in t.unicodeScalars {
            if u >= "0" && u <= "9" { digit = true; continue }
            if u == "+" || u == "-" || u == "." || u == "e" || u == "E" { continue }
            return false
        }
        return digit
    }

    /// Typed value: true / false / null, numbers, JSON strings / arrays / objects, else the plain text.
    static func decodeValue(_ raw: String) -> NCJSONValue {
        let t = raw.trimmingCharacters(in: .whitespaces)
        switch t {
        case "true": return .bool(true)
        case "false": return .bool(false)
        case "null": return .null
        default: break
        }
        if let f = t.first, f == "\"" || f == "[" || f == "{" {
            if let d = t.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]) {
                return NCJSONValue(o)
            }
            return .string(t)
        }
        if isNumeric(t), let d = Double(t), d.isFinite { return .number(d) }
        return .string(t)
    }

    /// The text decodeValue reads back as `v`.
    static func encodeValue(_ v: NCJSONValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let d): return formatNumber(d)
        case .string(let s):
            let plain = !s.isEmpty && s == s.trimmingCharacters(in: .whitespaces)
                && !s.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
                && decodeValue(s) == .string(s)
            return plain ? s : jsonString(s)
        case .array, .object: return json(v)
        }
    }

    static func json(_ v: NCJSONValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let d): return formatNumber(d)
        case .string(let s): return jsonString(s)
        case .array(let a): return "[" + a.map(json).joined(separator: ",") + "]"
        case .object(let o): return "{" + o.keys.sorted().map { jsonString($0) + ":" + json(o[$0] ?? .null) }.joined(separator: ",") + "}"
        }
    }

    static func jsonString(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if u.value < 0x20 || u.value == 0x7F || u.value == 0x2028 || u.value == 0x2029 {
                    out += String(format: "\\u%04x", u.value)
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        return out + "\""
    }

    // MARK: - Field escaping (comma lines)

    /// A field of a `a, b, k=v` line: % , " (and = for positional fields), line breaks, edge spaces and a leading
    /// [ { are percent-escaped, everything else (CJK, emoji, URLs) stays readable.
    static func escField(_ s: String, positional: Bool = false) -> String {
        let scalars = Array(s.unicodeScalars)
        var out = ""
        for (i, c) in scalars.enumerated() {
            switch c {
            case "%": out += "%25"
            case ",": out += "%2C"
            case "\"": out += "%22"
            case "[" where i == 0: out += "%5B"
            case "{" where i == 0: out += "%7B"
            case "=" where positional: out += "%3D"
            case "\n": out += "%0A"
            case "\r": out += "%0D"
            case " " where i == 0 || i == scalars.count - 1: out += "%20"
            default: out.unicodeScalars.append(c)
            }
        }
        return out
    }

    static func unescField(_ s: String) -> String {
        guard s.contains("%") else { return s }
        return s.removingPercentEncoding ?? s
    }

    /// URL fields keep their own percent-encoding: only % , and " are escaped (hand-written `%20` stays as written).
    static func escURL(_ s: String) -> String {
        s.replacingOccurrences(of: "%", with: "%25").replacingOccurrences(of: ",", with: "%2C").replacingOccurrences(of: "\"", with: "%22")
            .replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
    }
    static func unescURL(_ s: String) -> String {
        s.replacingOccurrences(of: "%2C", with: ",").replacingOccurrences(of: "%2c", with: ",")
            .replacingOccurrences(of: "%22", with: "\"").replacingOccurrences(of: "%25", with: "%")
    }

    /// Typed value of a `k=v` field: JSON (strings that need quoting, lists, mappings) is written as is (only % is
    /// escaped — the field splitter keeps quoted / bracketed values whole), plain text is escaped with escField.
    static func fieldValue(_ v: NCJSONValue) -> String {
        let t = encodeValue(v)
        switch v {
        case .array, .object: return jsonField(t)
        case .string(let s): return t == s ? escField(s) : jsonField(t)
        default: return t
        }
    }
    static func jsonField(_ json: String) -> String { json.replacingOccurrences(of: "%", with: "%25") }
    static func readFieldValue(_ s: String) -> NCJSONValue { decodeValue(unescField(s)) }

    /// Splits a comma line into fields (each trimmed, empty tail dropped). A field or `key=` value that starts with
    /// a double quote runs to the closing quote (QX `tag="a,b"`; JSON escapes honoured), one that starts with [ or {
    /// runs to its matching bracket (JSON lists / mappings), so commas inside them do not split.
    static func splitFields(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inQ = false, esc = false
        var depth = 0
        var valueStart = true   // at the start of the field, or right after its first '='
        var sawEq = false
        for ch in s {
            if inQ {
                cur.append(ch)
                if esc { esc = false } else if ch == "\\" { esc = true } else if ch == "\"" { inQ = false }
                continue
            }
            if depth > 0 {
                cur.append(ch)
                if ch == "\"" { inQ = true } else if ch == "[" || ch == "{" { depth += 1 } else if ch == "]" || ch == "}" { depth -= 1 }
                continue
            }
            if ch == "," {
                out.append(cur.trimmingCharacters(in: .whitespaces))
                cur = ""
                valueStart = true
                sawEq = false
                continue
            }
            cur.append(ch)
            if ch == " " || ch == "\t" { continue }
            if valueStart {
                valueStart = false
                if ch == "\"" { inQ = true; continue }
                if ch == "[" || ch == "{" { depth = 1; continue }
            }
            if ch == "=" && !sawEq { sawEq = true; valueStart = true }
        }
        let last = cur.trimmingCharacters(in: .whitespaces)
        if !last.isEmpty { out.append(last) }
        return out
    }

    /// `key=value` field → (key, raw value) when the key is a plain identifier.
    static func kvField(_ f: String) -> (String, String)? {
        guard let eq = f.firstIndex(of: "="), eq > f.startIndex else { return nil }
        let k = f[..<eq].trimmingCharacters(in: .whitespaces)
        guard !k.isEmpty, k.unicodeScalars.allSatisfy({ ($0.isASCII && (CharacterSet.alphanumerics.contains($0))) || $0 == "-" || $0 == "_" || $0 == "." }) else { return nil }
        return (k, f[f.index(after: eq)...].trimmingCharacters(in: .whitespaces))
    }

    static func isSimpleKey(_ k: String) -> Bool {
        !k.isEmpty && k.unicodeScalars.allSatisfy { ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || $0 == "-" || $0 == "_" }
    }

    // MARK: - Policy names (direct / reject)

    static let builtinLower: [String: String] = ["DIRECT": "direct", "REJECT": "reject", "REJECT-DROP": "reject-drop"]
    static let builtinUpper: [String: String] = ["direct": "DIRECT", "reject": "REJECT", "reject-drop": "REJECT-DROP"]

    static func writePolicy(_ p: String, names: Set<String>) -> String {
        if let l = builtinLower[p], !names.contains(l) { return l }
        return p
    }

    static func readPolicy(_ p: String, names: Set<String>) -> String {
        if let u = builtinUpper[p.lowercased()], !names.contains(p) { return u }
        return p
    }

    // MARK: - Line splitting

    struct SourceLine {
        var number: Int      // 1-based
        var text: String     // trimmed
    }

    struct Sections {
        /// Lowercased section name → its lines in order (comments included; a repeated section continues the first).
        var lines: [String: [SourceLine]] = [:]
        var order: [String] = []
        var headerLine: [String: Int] = [:]
    }

    static func sectionName(_ trimmed: String) -> String? {
        guard trimmed.count >= 3, trimmed.hasPrefix("["), trimmed.hasSuffix("]") else { return nil }
        let name = trimmed.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == " ") }) else { return nil }
        return name.lowercased()
    }

    static func splitSections(_ text: String) -> Sections {
        var s = Sections()
        var cur: String? = nil
        var t0 = text
        if t0.hasPrefix("\u{FEFF}") { t0.removeFirst() }
        var n = 0
        for raw in t0.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false) {
            n += 1
            let t = raw.trimmingCharacters(in: .whitespaces)
            if let name = sectionName(t) {
                cur = name
                if s.lines[name] == nil { s.lines[name] = []; s.order.append(name); s.headerLine[name] = n }
                continue
            }
            guard let c = cur, !t.isEmpty else { continue }
            s.lines[c, default: []].append(SourceLine(number: n, text: t))
        }
        return s
    }

    static func isComment(_ t: String) -> Bool { t.hasPrefix("#") || t.hasPrefix(";") || t.hasPrefix("//") }

    /// The text split in two: the profile-owned part (everything outside the shared sections, header comments
    /// included) and the shared part. Used to store a profile's .conf without the shared sections.
    static func splitText(_ text: String) -> (profile: String, shared: String) {
        var prof: [Substring] = []
        var shared: [Substring] = []
        var inShared = false
        for raw in text.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false) {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if let name = sectionName(t) { inShared = engineSections.contains(name) }
            if inShared { shared.append(raw) } else { prof.append(raw) }
        }
        // A comment block written right above a shared section belongs to it (the shared-part banner).
        while let last = prof.last, last.trimmingCharacters(in: .whitespaces).isEmpty || isComment(last.trimmingCharacters(in: .whitespaces)) {
            if last.trimmingCharacters(in: .whitespaces).isEmpty { prof.removeLast(); continue }
            if shared.isEmpty { break }
            shared.insert(prof.removeLast(), at: 0)
        }
        var p = prof.joined(separator: "\n")
        if !p.isEmpty { p += "\n" }
        var s = shared.joined(separator: "\n")
        if !s.isEmpty && !s.hasSuffix("\n") { s += "\n" }
        return (p, s)
    }

    // MARK: - Serialize: profile

    static let header = "# Tern profile\n"

    /// The profile part of the canonical .conf for `profile` (top-level YAML mapping).
    static func serializeProfile(_ profile: [String: NCJSONValue]) -> String {
        var out = header
        var general = profile
        var names = Set<String>()
        for p in profile["proxies"]?.array ?? [] { if let n = p["name"]?.string { names.insert(n) } }
        for g in profile["proxy-groups"]?.array ?? [] { if let n = g["name"]?.string { names.insert(n) } }

        // Which keys get their own section (right container type), the rest stays in [general].
        var owned: [String: NCJSONValue] = [:]
        for (k, _) in sectionKeys {
            guard let v = profile[k] else { continue }
            switch (k, v) {
            case ("proxies", .array), ("proxy-groups", .array), ("rules", .array),
                 ("proxy-providers", .object), ("rule-providers", .object), ("dns", .object):
                owned[k] = v
                general.removeValue(forKey: k)
            default: break
            }
        }
        // hosts: QX `address=/domain/ip` lines in [dns] when the profile has a dns mapping and every entry fits.
        var hostsInDNS: [String: NCJSONValue]? = nil
        if owned["dns"] != nil, case .object(let h)? = profile["hosts"], hostsFit(h) {
            hostsInDNS = h
            general.removeValue(forKey: "hosts")
        }

        out += "\n[general]\n"
        out += serializeKeyValues(general)

        if case .object(let d)? = owned["dns"] {
            out += "\n[dns]\n"
            out += serializeDNS(d, hosts: hostsInDNS)
        }
        if case .array(let groups)? = owned["proxy-groups"] {
            out += "\n[policy]\n"
            for g in groups { out += serializeGroup(g, names: names) + "\n" }
        }
        if case .array(let nodes)? = owned["proxies"] {
            out += "\n[server_local]\n"
            for p in nodes { out += serializeNode(p) + "\n" }
        }
        if case .object(let provs)? = owned["proxy-providers"] {
            out += "\n[server_remote]\n"
            for k in provs.keys.sorted() { out += serializeProvider(name: k, provs[k] ?? .null, ruleSet: false) + "\n" }
        }
        if case .object(let provs)? = owned["rule-providers"] {
            out += "\n[filter_remote]\n"
            for k in provs.keys.sorted() { out += serializeProvider(name: k, provs[k] ?? .null, ruleSet: true) + "\n" }
        }
        if case .array(let rules)? = owned["rules"] {
            out += "\n[filter_local]\n"
            for r in rules { out += serializeRule(r, names: names) + "\n" }
        }
        return out
    }

    // MARK: [general] key = value (nested mappings flattened to dotted keys)

    static func serializeKeyValues(_ m: [String: NCJSONValue]) -> String {
        var out = ""
        func emit(_ prefix: String, _ v: NCJSONValue) {
            if case .object(let o) = v, !o.isEmpty, o.keys.allSatisfy(isSimpleKey) {
                for k in o.keys.sorted() { emit(prefix + "." + k, o[k] ?? .null) }
                return
            }
            out += prefix + " = " + encodeValue(v) + "\n"
        }
        for k in m.keys.sorted() {
            let v = m[k] ?? .null
            if isSimpleKey(k) { emit(k, v) } else { out += jsonString(k) + " = " + encodeValue(v) + "\n" }
        }
        return out
    }

    /// `key = value` line → (path, value). A JSON-quoted key is one path element.
    static func readKeyValue(_ t: String) -> ([String], NCJSONValue)? {
        if t.hasPrefix("\"") {
            // "key" = value
            var idx = t.index(after: t.startIndex)
            var esc = false
            while idx < t.endIndex {
                let c = t[idx]
                if esc { esc = false } else if c == "\\" { esc = true } else if c == "\"" { break }
                idx = t.index(after: idx)
            }
            guard idx < t.endIndex else { return nil }
            let keyJSON = String(t[...idx])
            guard case .string(let k) = decodeValue(keyJSON) else { return nil }
            let rest = t[t.index(after: idx)...].trimmingCharacters(in: .whitespaces)
            guard rest.hasPrefix("=") else { return nil }
            return ([k], decodeValue(String(rest.dropFirst())))
        }
        guard let eq = t.firstIndex(of: "=") else { return nil }
        let k = t[..<eq].trimmingCharacters(in: .whitespaces)
        guard !k.isEmpty else { return nil }
        let path = k.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard path.allSatisfy({ !$0.isEmpty }) else { return nil }
        return (path, decodeValue(String(t[t.index(after: eq)...])))
    }

    /// Sets `v` at `path` in `m`. False on a conflict (a value where a mapping is needed or the reverse).
    static func set(_ m: inout [String: NCJSONValue], _ path: [String], _ v: NCJSONValue) -> Bool {
        guard let first = path.first else { return false }
        if path.count == 1 {
            if case .object? = m[first], case .object = v { return false }
            if case .object? = m[first] { return false }
            m[first] = v
            return true
        }
        var child: [String: NCJSONValue]
        switch m[first] {
        case nil: child = [:]
        case .object(let o)?: child = o
        default: return false
        }
        guard set(&child, Array(path.dropFirst()), v) else { return false }
        m[first] = .object(child)
        return true
    }

    // MARK: [dns]

    static func hostsFit(_ h: [String: NCJSONValue]) -> Bool {
        h.allSatisfy { k, v in
            guard case .string(let s) = v else { return false }
            return !k.isEmpty && !k.contains("/") && !k.contains(",") && !s.isEmpty && !s.contains(",") && s == s.trimmingCharacters(in: .whitespaces)
                && k == k.trimmingCharacters(in: .whitespaces)
        }
    }

    static func serializeDNS(_ d: [String: NCJSONValue], hosts: [String: NCJSONValue]?) -> String {
        let qx = serializeDNSQX(d, hosts: hosts)
        // Verify the QX form; fall back to plain key = value lines (always exact).
        if let back = try? parseDNS(qx.split(separator: "\n").enumerated().map { SourceLine(number: $0.offset + 1, text: String($0.element)) }),
           back.dns == d, back.hosts == hosts {
            return qx
        }
        var out = serializeKeyValues(d)
        if let hosts { for k in hosts.keys.sorted() { out += "address=/\(k)/\(hosts[k]?.string ?? "")\n" } }
        return out
    }

    private static func serializeDNSQX(_ d: [String: NCJSONValue], hosts: [String: NCJSONValue]?) -> String {
        var rest = d
        var out = ""
        if case .bool(false)? = d["ipv6"] { out += "no-ipv6\n"; rest.removeValue(forKey: "ipv6") }
        if case .array(let ns)? = d["nameserver"], !ns.isEmpty,
           ns.allSatisfy({ ($0.string.map { !$0.isEmpty && !$0.contains(",") && !$0.hasPrefix("/") && $0 == $0.trimmingCharacters(in: .whitespaces) }) ?? false }) {
            for s in ns.compactMap({ $0.string }) {
                out += (s.lowercased().hasPrefix("https://") ? "doh-server=" : "server=") + s + "\n"
            }
            rest.removeValue(forKey: "nameserver")
        }
        if case .object(let pol)? = d["nameserver-policy"], !pol.isEmpty,
           pol.allSatisfy({ k, v in !k.contains("/") && !k.isEmpty && (v.string.map { !$0.isEmpty && !$0.contains(",") && $0 == $0.trimmingCharacters(in: .whitespaces) } ?? false) }) {
            for k in pol.keys.sorted() { out += "server=/\(k)/\(pol[k]?.string ?? "")\n" }
            rest.removeValue(forKey: "nameserver-policy")
        }
        out += serializeKeyValues(rest)
        if let hosts { for k in hosts.keys.sorted() { out += "address=/\(k)/\(hosts[k]?.string ?? "")\n" } }
        return out
    }

    static func parseDNS(_ lines: [SourceLine]) throws -> (dns: [String: NCJSONValue], hosts: [String: NCJSONValue]?) {
        var d: [String: NCJSONValue] = [:]
        var hosts: [String: NCJSONValue]? = nil
        var ns: [NCJSONValue] = []
        var pol: [String: NCJSONValue] = [:]
        var sawNS = false, sawPol = false
        for l in lines where !isComment(l.text) {
            let t = l.text
            let lower = t.lowercased()
            if lower == "no-ipv6" { d["ipv6"] = .bool(false); continue }
            if lower == "no-system" || lower == "prefer-doh3" || lower == "circumvent-ipv4-answer" || lower == "circumvent-ipv6-answer" {
                continue // QX-only switches with no internal equivalent
            }
            if let eq = t.firstIndex(of: "=") {
                let k = t[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
                let v = t[t.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                switch k {
                case "server", "doh-server", "doq-server":
                    if v.hasPrefix("/") {
                        // server=/domain/value
                        let body = v.dropFirst()
                        guard let slash = body.firstIndex(of: "/") else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
                        let dom = String(body[..<slash]), val = String(body[body.index(after: slash)...])
                        guard !dom.isEmpty, !val.isEmpty else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
                        pol[dom] = .string(val)
                        sawPol = true
                    } else {
                        for s in v.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !s.isEmpty {
                            ns.append(.string(s))
                        }
                        sawNS = true
                    }
                    continue
                case "address":
                    guard v.hasPrefix("/") else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
                    let body = v.dropFirst()
                    guard let slash = body.firstIndex(of: "/") else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
                    let dom = String(body[..<slash]), val = String(body[body.index(after: slash)...])
                    guard !dom.isEmpty, !val.isEmpty else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
                    if hosts == nil { hosts = [:] }
                    hosts?[dom] = .string(val)
                    continue
                default: break
                }
            }
            guard case let (path, v)? = readKeyValue(t) else { throw ParseError(line: l.number, message: String(localized: "无法识别的 DNS 行")) }
            guard set(&d, path, v) else { throw ParseError(line: l.number, message: String(localized: "键重复或冲突：\(path.joined(separator: "."))")) }
        }
        if sawNS {
            if case .array(let a)? = d["nameserver"] { d["nameserver"] = .array(ns + a) } else { d["nameserver"] = .array(ns) }
        }
        if sawPol {
            if case .object(let o)? = d["nameserver-policy"] { d["nameserver-policy"] = .object(pol.merging(o) { a, _ in a }) }
            else { d["nameserver-policy"] = .object(pol) }
        }
        return (d, hosts)
    }

    // MARK: [server_local] nodes

    /// Internal type → QX line key (types QX itself has).
    static let qxNodeTypes: [String: String] = ["ss": "shadowsocks", "ssr": "shadowsocks", "vmess": "vmess", "vless": "vless",
                                                "trojan": "trojan", "http": "http", "socks5": "socks5", "anytls": "anytls"]
    static let qxNodeKeys: Set<String> = ["shadowsocks", "vmess", "vless", "trojan", "http", "socks5", "anytls"]

    static func hostPort(_ p: [String: NCJSONValue]) -> String? {
        guard case .string(let h)? = p["server"], !h.isEmpty, !h.contains(","), !h.contains(" "),
              case .number(let n)? = p["port"], n == n.rounded(), n >= 1, n <= 65535 else { return nil }
        let port = Int(n)
        return (h.contains(":") ? "[\(h)]" : h) + ":" + String(port)
    }

    /// A raw QX value is usable when the QX node parser reads it back unchanged.
    private static func qxSafe(_ s: String) -> Bool {
        !s.isEmpty && !s.contains(",") && !s.contains("\"") && s == s.trimmingCharacters(in: .whitespaces) && !s.contains("\n")
            && !s.hasPrefix("[") && !s.hasPrefix("{")
    }

    static func serializeNode(_ v: NCJSONValue) -> String {
        if case .object(let p) = v, case .string(let type)? = p["type"] {
            if let key = qxNodeTypes[type], let line = qxNodeLine(p, key: key, type: type), (try? parseNode(line, line: 0)) == v {
                return line
            }
            if qxNodeTypes[type] == nil, !qxNodeKeys.contains(type), type != "tern-node", isSimpleKey(type) {
                let line = genericNodeLine(p, type: type)
                if (try? parseNode(line, line: 0)) == v { return line }
            }
        }
        return "tern-node=-, json=" + jsonField(json(v))
    }

    /// QX form + `tern-` corrections, or nil when the node has no QX address.
    private static func qxNodeLine(_ p: [String: NCJSONValue], key: String, type: String) -> String? {
        guard let hp = hostPort(p) else { return nil }
        var f: [String] = []
        func add(_ k: String, _ v: String?) { if let v, qxSafe(v) { f.append("\(k)=\(v)") } }
        func str(_ k: String) -> String? { p[k]?.string }
        func bool(_ k: String) -> Bool? { p[k]?.bool }
        let ws = str("network") == "ws"
        let wsOpts = p["ws-opts"]?.object
        let wsPath = wsOpts?["path"]?.string
        let wsHost = wsOpts?["headers"]?.object?["Host"]?.string
        let tls = bool("tls") == true
        switch type {
        case "ss":
            add("method", str("cipher"))
            add("password", str("password"))
            if let po = p["plugin-opts"]?.object {
                if str("plugin") == "obfs" { add("obfs", po["mode"]?.string); add("obfs-host", po["host"]?.string) }
                if str("plugin") == "v2ray-plugin", po["mode"]?.string == "websocket" {
                    f.append(po["tls"]?.bool == true ? "obfs=wss" : "obfs=ws")
                    add("obfs-host", po["host"]?.string)
                    add("obfs-uri", po["path"]?.string)
                }
            }
            if let u = bool("udp") { f.append("udp-relay=\(u)") }
        case "ssr":
            add("method", str("cipher"))
            add("password", str("password"))
            add("ssr-protocol", str("protocol"))
            add("ssr-protocol-param", str("protocol-param"))
            add("obfs", str("obfs"))
            add("obfs-host", str("obfs-param"))
            if let u = bool("udp") { f.append("udp-relay=\(u)") }
        case "vmess", "vless":
            if type == "vmess" { add("method", str("cipher")) }
            add("password", str("uuid"))
            if type == "vless" { add("vless-flow", str("flow")) }
            if ws {
                f.append(tls ? "obfs=wss" : "obfs=ws")
                add("obfs-host", wsHost)
                add("obfs-uri", wsPath)
            } else if tls {
                f.append("over-tls=true")
            }
            if tls { add("tls-host", str("servername")) }
            if let ro = p["reality-opts"]?.object {
                add("reality-base64-pubkey", ro["public-key"]?.string)
                add("reality-hex-shortid", ro["short-id"]?.string)
            }
        case "trojan":
            add("password", str("password"))
            if ws {
                f.append("obfs=wss")
                add("obfs-host", wsHost)
                add("obfs-uri", wsPath)
            } else {
                f.append("over-tls=true")
            }
            add("tls-host", str("sni"))
            if let u = bool("udp") { f.append("udp-relay=\(u)") }
        case "http", "socks5":
            add("username", str("username"))
            add("password", str("password"))
            if tls { f.append("over-tls=true"); add("tls-host", str("sni")) }
            if type == "socks5", let u = bool("udp") { f.append("udp-relay=\(u)") }
        case "anytls":
            add("password", str("password"))
            add("tls-host", str("sni"))
        default: return nil
        }
        if bool("skip-cert-verify") == true { f.append("tls-verification=false") }
        if bool("tfo") == true { f.append("fast-open=true") }
        if bool("udp-over-tcp") == true { f.append("udp-over-tcp=true") }
        if let fp = str("fingerprint"), fp.count == 64 { add("tls-cert-sha256", fp) }
        if case .array(let a)? = p["alpn"], !a.isEmpty, a.allSatisfy({ ($0.string.map { qxSafe($0) && !$0.contains("|") }) ?? false }) {
            f.append("tls-alpn=" + a.compactMap { $0.string }.joined(separator: "|"))
        }
        if let n = str("name") {
            if qxSafe(n) { f.append("tag=\(n)") } else if !n.contains("\"") && !n.contains("\\") && !n.contains("\n") && !n.isEmpty { f.append("tag=\"\(n)\"") }
        }
        var line = key + "=" + ([hp] + f).joined(separator: ", ")
        // Corrections: whatever the QX reading gets wrong or adds.
        guard let baseAny = try? NCConfImportPort.parseQXLine(line), case .object(let base) = NCJSONValue(baseAny) else { return nil }
        var fixes: [String] = []
        for k in p.keys.sorted() where base[k] != p[k] {
            guard isSimpleKey(k) else { return nil }
            fixes.append("tern-\(k)=" + fieldValue(p[k] ?? .null))
        }
        let extra = base.keys.filter { p[$0] == nil }.sorted()
        guard extra.allSatisfy(isSimpleKey) else { return nil }
        if !extra.isEmpty { fixes.append("tern-unset=" + extra.joined(separator: "|")) }
        if !fixes.isEmpty { line += ", " + fixes.joined(separator: ", ") }
        return line
    }

    /// Tern extension node line for types QX does not have: `type=host:port, key=value…, tag=name`.
    private static func genericNodeLine(_ p: [String: NCJSONValue], type: String) -> String {
        var rest = p
        rest.removeValue(forKey: "type")
        var first = "-"
        if let hp = hostPort(p) { first = hp; rest.removeValue(forKey: "server"); rest.removeValue(forKey: "port") }
        let name = rest.removeValue(forKey: "name")
        var f = [first]
        for k in rest.keys.sorted() { f.append(escField(k, positional: true) + "=" + fieldValue(rest[k] ?? .null)) }
        if let name { f.append("tag=" + fieldValue(name)) }
        return type + "=" + f.joined(separator: ", ")
    }

    static func parseNode(_ t: String, line: Int) throws -> NCJSONValue {
        guard let eq = t.firstIndex(of: "=") else { throw ParseError(line: line, message: String(localized: "无法识别的节点行")) }
        let key = t[..<eq].trimmingCharacters(in: .whitespaces)
        let body = String(t[t.index(after: eq)...])
        let fields = splitFields(body)
        guard let first = fields.first else { throw ParseError(line: line, message: String(localized: "无法识别的节点行")) }
        let lkey = key.lowercased()
        if lkey == "tern-node" {
            for f in fields.dropFirst() {
                if case let (k, v)? = kvField(f), k == "json" { return decodeValue(unescField(v)) }
            }
            throw ParseError(line: line, message: String(localized: "无法识别的节点行"))
        }
        if qxNodeKeys.contains(lkey) && first != "-" {
            // QX node line (+ tern- corrections).
            var qx: [String] = [first]
            var fixes: [(String, NCJSONValue)] = []
            var unset: [String] = []
            for f in fields.dropFirst() {
                if case let (k, v)? = kvField(f), k.lowercased().hasPrefix("tern-") {
                    let name = String(k.dropFirst(5))
                    if name.lowercased() == "unset" {
                        unset += v.split(separator: "|").map { String($0).trimmingCharacters(in: .whitespaces) }
                    } else {
                        fixes.append((name, readFieldValue(v)))
                    }
                } else {
                    qx.append(f)
                }
            }
            let any: [String: Any]
            do { any = try NCConfImportPort.parseQXLine(lkey + "=" + qx.joined(separator: ", ")) } catch {
                throw ParseError(line: line, message: String(localized: "节点行无效：\(error.localizedDescription)"))
            }
            guard case .object(var p) = NCJSONValue(any) else { throw ParseError(line: line, message: String(localized: "无法识别的节点行")) }
            for (k, v) in fixes { p[k] = v }
            for k in unset { p.removeValue(forKey: k) }
            return .object(p)
        }
        // Tern extension line: type=host:port|-, key=value…, tag=name.
        var p: [String: NCJSONValue] = ["type": .string(lkey == "shadowsocks" ? "ss" : key)]
        if first != "-" {
            let (h, port, ok) = NCConfImportPort.splitHostPort(first)
            guard ok else { throw ParseError(line: line, message: String(localized: "节点地址无效：\(first)")) }
            p["server"] = .string(h)
            p["port"] = .number(Double(port))
        }
        for f in fields.dropFirst() {
            guard case let (k, v)? = kvField(f) else { throw ParseError(line: line, message: String(localized: "无法识别的字段：\(f)")) }
            p[k == "tag" ? "name" : unescField(k)] = readFieldValue(v)
        }
        return .object(p)
    }

    // MARK: [policy] groups

    static let qxGroupType: [String: String] = ["select": "static", "url-test": "url-latency-benchmark", "fallback": "available",
                                                "load-balance": "round-robin"]
    static let groupTypeFromQX: [String: String] = ["static": "select", "url-latency-benchmark": "url-test", "available": "fallback",
                                                    "round-robin": "load-balance"]
    /// Internal key → QX key on a policy line.
    static let qxGroupKey: [String: String] = ["interval": "check-interval", "icon": "img-url", "filter": "server-tag-regex"]
    static let groupKeyFromQX: [String: String] = ["check-interval": "interval", "img-url": "icon", "server-tag-regex": "filter"]

    static func serializeGroup(_ v: NCJSONValue, names: Set<String>) -> String {
        if case .object(let g) = v, case .string(let name)? = g["name"], case .string(let type)? = g["type"],
           isSimpleKey(type), type != "tern-group" {
            var rest = g
            rest.removeValue(forKey: "name")
            rest.removeValue(forKey: "type")
            var f = [escField(name, positional: true)]
            if case .array(let members)? = g["proxies"], !members.isEmpty, members.allSatisfy({ $0.string.map { !$0.isEmpty } ?? false }) {
                for m in members.compactMap({ $0.string }) { f.append(escField(writePolicy(m, names: names), positional: true)) }
                rest.removeValue(forKey: "proxies")
            }
            for k in rest.keys.sorted() {
                let qk = qxGroupKey[k] ?? k
                f.append(escField(qk, positional: true) + "=" + fieldValue(rest[k] ?? .null))
            }
            let line = (qxGroupType[type] ?? type) + "=" + f.joined(separator: ", ")
            if (try? parseGroup(line, line: 0, names: names)) == v { return line }
        }
        return "tern-group=-, json=" + jsonField(json(v))
    }

    static func parseGroup(_ t: String, line: Int, names: Set<String>) throws -> NCJSONValue {
        guard let eq = t.firstIndex(of: "=") else { throw ParseError(line: line, message: String(localized: "无法识别的策略组行")) }
        let key = t[..<eq].trimmingCharacters(in: .whitespaces)
        let fields = splitFields(String(t[t.index(after: eq)...]))
        guard let first = fields.first, !first.isEmpty else { throw ParseError(line: line, message: String(localized: "策略组缺少名称")) }
        if key.lowercased() == "tern-group" {
            for f in fields.dropFirst() {
                if case let (k, v)? = kvField(f), k == "json" { return decodeValue(unescField(v)) }
            }
            throw ParseError(line: line, message: String(localized: "无法识别的策略组行"))
        }
        let lkey = key.lowercased()
        var g: [String: NCJSONValue] = ["name": .string(unescField(first).trimmingCharacters(in: CharacterSet(charactersIn: "\"")))]
        if lkey == "dest-hash" {
            g["type"] = .string("load-balance")
            g["strategy"] = .string("consistent-hashing")
        } else {
            g["type"] = .string(groupTypeFromQX[lkey] ?? key)
        }
        var members: [NCJSONValue] = []
        for f in fields.dropFirst() {
            if case let (k, v)? = kvField(f) {
                let ik = groupKeyFromQX[k.lowercased()] ?? unescField(k)
                g[ik] = readFieldValue(v)
            } else {
                let m = unescField(f).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                members.append(.string(readPolicy(m, names: names)))
            }
        }
        if !members.isEmpty { g["proxies"] = .array(members) }
        return .object(g)
    }

    // MARK: [server_remote] / [filter_remote] providers

    static func serializeProvider(name: String, _ v: NCJSONValue, ruleSet: Bool) -> String {
        if case .object(let p) = v {
            var rest = p
            var first = "-"
            if case .string(let u)? = p["url"], !u.isEmpty, u != "-", u == u.trimmingCharacters(in: .whitespaces), !u.contains("\n") {
                first = escURL(u)
                rest.removeValue(forKey: "url")
            }
            if first != "-", p["type"]?.string == "http" { rest.removeValue(forKey: "type") }
            var f = [first, "tag=" + escField(name)]
            if let i = rest.removeValue(forKey: "interval") { f.append("update-interval=" + fieldValue(i)) }
            for k in rest.keys.sorted() {
                guard k != "tag", k != "update-interval", k != "force-policy", k != "json" else { f = []; break }
                f.append(escField(k, positional: true) + "=" + fieldValue(rest[k] ?? .null))
            }
            if !f.isEmpty {
                let line = f.joined(separator: ", ")
                if let back = try? parseProvider(line, line: 0, ruleSet: ruleSet), back.name == name, back.value == v, back.rule == nil {
                    return line
                }
            }
        }
        return "-, tag=" + escField(name) + ", json=" + jsonField(json(v))
    }

    struct ProviderLine {
        var name: String
        var value: NCJSONValue
        /// QX `force-policy=`: the RULE-SET rule the line also stands for.
        var rule: String?
        /// QX `enabled=false` on a force-policy line: the line is skipped.
        var skip = false
    }

    static func parseProvider(_ t: String, line: Int, ruleSet: Bool) throws -> ProviderLine {
        let fields = splitFields(t)
        guard let first = fields.first, !first.isEmpty else { throw ParseError(line: line, message: String(localized: "无法识别的远程资源行")) }
        var kv: [(String, String)] = []
        for f in fields.dropFirst() {
            guard let pair = kvField(f) else { throw ParseError(line: line, message: String(localized: "无法识别的字段：\(f)")) }
            kv.append(pair)
        }
        var tag = ""
        var json: String?
        var force: String?
        var enabled: String?
        var p: [String: NCJSONValue] = [:]
        for (k, v) in kv {
            switch k.lowercased() {
            case "tag": tag = unescField(v)
            case "json": json = v
            case "force-policy": force = unescField(v)
            case "update-interval": p["interval"] = readFieldValue(v)
            case "enabled" where force != nil || ruleSet: enabled = v
            case "opt-parser", "as-policy": continue
            default: p[unescField(k)] = readFieldValue(v)
            }
        }
        let url = first == "-" ? nil : unescURL(first)
        if let json {
            guard !tag.isEmpty else { throw ParseError(line: line, message: String(localized: "远程资源缺少 tag")) }
            return ProviderLine(name: tag, value: decodeValue(unescField(json)))
        }
        if let force, ruleSet, let url {
            // Quantumult X filter list: a rule set read as QX list lines, plus its RULE-SET rule.
            let name = tag.isEmpty ? NCRuleValidator.prettyProviderName(u: url, tag: "") : tag
            var m: [String: NCJSONValue] = ["type": .string("http"), "behavior": .string("classical"), "format": .string("text"),
                                            "url": .string(url), "x-convert": .string("list"),
                                            "path": .string("./ruleset/" + NCRuleValidator.providerNameFor(url: url, kind: "list") + ".txt"),
                                            "interval": .number(86400)]
            for (k, v) in p { m[k] = v }
            m.removeValue(forKey: "enabled")
            let off = enabled.map { !NCConfImportPort.truthy($0) } ?? false
            return ProviderLine(name: name, value: .object(m), rule: off ? nil : "RULE-SET,\(name),\(force)", skip: off)
        }
        if let e = enabled { p["enabled"] = decodeValue(unescField(e)) }
        if let url {
            p["url"] = .string(url)
            if p["type"] == nil { p["type"] = .string("http") }
        }
        let name = tag.isEmpty ? (url.map { NCRuleValidator.prettyProviderName(u: $0, tag: "") } ?? "") : tag
        guard !name.isEmpty else { throw ParseError(line: line, message: String(localized: "远程资源缺少 tag")) }
        return ProviderLine(name: name, value: .object(p))
    }

    // MARK: [filter_local] rules

    static let qxRuleType: [String: String] = ["DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword",
                                               "DOMAIN-WILDCARD": "host-wildcard", "IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr",
                                               "GEOIP": "geoip", "MATCH": "final", "USER-AGENT": "user-agent", "IP-ASN": "ip-asn"]
    static let ruleTypeFromQX: [String: String] = ["host": "DOMAIN", "host-suffix": "DOMAIN-SUFFIX", "host-keyword": "DOMAIN-KEYWORD",
                                                   "host-wildcard": "DOMAIN-WILDCARD", "ip-cidr": "IP-CIDR", "ip6-cidr": "IP-CIDR6",
                                                   "geoip": "GEOIP", "final": "MATCH", "user-agent": "USER-AGENT", "ip-asn": "IP-ASN"]

    /// Splits a rule on commas outside parentheses (logical rules), parts kept as written.
    static func splitRule(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var depth = 0
        for ch in s {
            if ch == "(" { depth += 1 } else if ch == ")" { depth = max(0, depth - 1) } else if ch == "," && depth == 0 {
                out.append(cur)
                cur = ""
                continue
            }
            cur.append(ch)
        }
        out.append(cur)
        return out
    }

    static func policyIndex(_ type: String, count: Int) -> Int? {
        switch type {
        case "MATCH": return count >= 2 ? 1 : nil
        case "SUB-RULE": return nil
        default: return count >= 3 ? 2 : nil
        }
    }

    static func serializeRule(_ v: NCJSONValue, names: Set<String>) -> String {
        guard case .string(let r) = v else { return "tern-raw-json, " + escField(json(v)) }
        var parts = splitRule(r)
        if parts.count >= 2, let t = parts.first, t == t.uppercased(), !t.isEmpty,
           parts.allSatisfy({ $0 == $0.trimmingCharacters(in: .whitespaces) && !$0.isEmpty }) {
            if let i = policyIndex(t, count: parts.count) { parts[i] = writePolicy(parts[i], names: names) }
            if t == "GEOIP", parts.count >= 2, parts[1].count == 2, parts[1].allSatisfy({ $0.isASCII && $0.isUppercase }) {
                parts[1] = parts[1].lowercased()
            }
            parts[0] = qxRuleType[t] ?? t.lowercased()
            let line = parts.joined(separator: ", ")
            if (try? parseRule(line, line: 0, names: names)) == r { return line }
        }
        return "tern-raw, " + escField(r)
    }

    static func parseRule(_ t: String, line: Int, names: Set<String>) throws -> String {
        let lower = t.lowercased()
        if lower.hasPrefix("tern-raw-json,") {
            throw ParseError(line: line, message: "json") // handled by parseRuleValue
        }
        if lower.hasPrefix("tern-raw,") {
            return unescField(String(t.dropFirst("tern-raw,".count)).trimmingCharacters(in: .whitespaces))
        }
        var parts = splitRule(t).map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2, !parts[0].isEmpty else { throw ParseError(line: line, message: String(localized: "无法识别的规则：\(t)")) }
        let type = ruleTypeFromQX[parts[0].lowercased()] ?? parts[0].uppercased()
        parts[0] = type
        if type == "GEOIP", parts[1].count == 2, parts[1].allSatisfy({ $0.isASCII && $0.isLowercase }) { parts[1] = parts[1].uppercased() }
        if let i = policyIndex(type, count: parts.count) { parts[i] = readPolicy(parts[i], names: names) }
        return parts.joined(separator: ",")
    }

    static func parseRuleValue(_ t: String, line: Int, names: Set<String>) throws -> NCJSONValue {
        if t.lowercased().hasPrefix("tern-raw-json,") {
            return decodeValue(unescField(String(t.dropFirst("tern-raw-json,".count)).trimmingCharacters(in: .whitespaces)))
        }
        return .string(try parseRule(t, line: line, names: names))
    }

    // MARK: - Parse

    struct Parsed {
        var profile: [String: NCJSONValue]
        /// nil when the text has none of the shared sections.
        var engine: EngineSection?
    }

    /// Parses a .conf (canonical or hand-written Quantumult X) into the internal profile and the shared part.
    static func parse(_ text: String) throws -> Parsed {
        let s = splitSections(text)
        var profile: [String: NCJSONValue] = [:]

        // [general]
        for l in s.lines["general"] ?? [] where !isComment(l.text) {
            guard case let (path, v)? = readKeyValue(l.text) else { throw ParseError(line: l.number, message: String(localized: "无法识别的行")) }
            guard set(&profile, path, v) else { throw ParseError(line: l.number, message: String(localized: "键重复或冲突：\(path.joined(separator: "."))")) }
        }

        // Names first: rule / member policies need them to tell `direct` the built-in from a group called "direct".
        var nodes: [NCJSONValue] = []
        for l in s.lines["server_local"] ?? [] where !isComment(l.text) { nodes.append(try parseNode(l.text, line: l.number)) }
        var names = Set<String>()
        for n in nodes { if let x = n["name"]?.string { names.insert(x) } }
        for l in s.lines["policy"] ?? [] where !isComment(l.text) {
            if let eq = l.text.firstIndex(of: "=") {
                let rest = l.text[l.text.index(after: eq)...]
                if let first = splitFields(String(rest)).first { names.insert(unescField(first).trimmingCharacters(in: CharacterSet(charactersIn: "\""))) }
            }
        }
        var groups: [NCJSONValue] = []
        for l in s.lines["policy"] ?? [] where !isComment(l.text) { groups.append(try parseGroup(l.text, line: l.number, names: names)) }
        for g in groups { if let x = g["name"]?.string { names.insert(x) } }

        if s.lines["server_local"] != nil { profile["proxies"] = .array(nodes) }
        if s.lines["policy"] != nil { profile["proxy-groups"] = .array(groups) }

        if let lines = s.lines["dns"] {
            let (d, hosts) = try parseDNS(lines)
            profile["dns"] = .object(d)
            if let hosts {
                if case .object(let h)? = profile["hosts"] { profile["hosts"] = .object(hosts.merging(h) { a, _ in a }) }
                else { profile["hosts"] = .object(hosts) }
            }
        }
        if let lines = s.lines["server_remote"] {
            var m: [String: NCJSONValue] = [:]
            for l in lines where !isComment(l.text) {
                let p = try parseProvider(l.text, line: l.number, ruleSet: false)
                m[p.name] = p.value
            }
            profile["proxy-providers"] = .object(m)
        }
        var forced: [String] = []
        if let lines = s.lines["filter_remote"] {
            var m: [String: NCJSONValue] = [:]
            for l in lines where !isComment(l.text) {
                let p = try parseProvider(l.text, line: l.number, ruleSet: true)
                if p.skip { continue }
                m[p.name] = p.value
                if let r = p.rule { forced.append(r) }
            }
            profile["rule-providers"] = .object(m)
        }
        if s.lines["filter_local"] != nil || !forced.isEmpty {
            var rules: [NCJSONValue] = forced.map { r in
                var parts = splitRule(r)
                if parts.count >= 3 { parts[2] = readPolicy(parts[2], names: names) }
                return NCJSONValue.string(parts.joined(separator: ","))
            }
            for l in s.lines["filter_local"] ?? [] where !isComment(l.text) {
                rules.append(try parseRuleValue(l.text, line: l.number, names: names))
            }
            profile["rules"] = .array(rules)
        }

        var engine: EngineSection? = nil
        if engineSections.contains(where: { s.lines[$0] != nil }) { engine = try parseEngine(s) }
        return Parsed(profile: profile, engine: engine)
    }

    // MARK: - Shared part (engine.json): rewrites, scripts, modules, MitM

    struct CAFile: Equatable {
        var passphrase: String
        var p12: Data
    }

    struct EngineSection: Equatable {
        var rewriteEnabled: Bool? = nil
        var scriptsEnabled: Bool? = nil
        var mitm: Bool? = nil
        var skipCertVerify: Bool? = nil
        var h2: Bool? = nil
        var captureBodies: Bool? = nil
        var hostnames: [String] = []
        var quic: String? = nil
        var quicAllow: [String]? = nil
        var rules: [EngineItem] = []
        var scripts: [EngineItem] = []
        var modules: [EngineModule] = []
        var scriptResources: [String: ScriptResourceSetting] = [:]
        var ca: CAFile? = nil

        init() {}

        init(_ c: EngineConfig) {
            rewriteEnabled = c.enabled
            scriptsEnabled = c.scriptsEnabled
            mitm = c.mitm
            skipCertVerify = c.skipCertVerify
            h2 = c.h2
            captureBodies = c.captureBodies
            hostnames = c.hostnames
            quic = c.quic
            quicAllow = c.quicAllow
            rules = c.rules
            scripts = c.scripts
            modules = c.modules
            scriptResources = c.scriptResources ?? [:]
        }

        /// `base` with this section applied: items keep the id of the entry with the same line, modules match by id
        /// then url. Values the text does not state keep the current setting.
        func applied(to base: EngineConfig) -> EngineConfig {
            var c = base
            if let v = rewriteEnabled { c.enabled = v }
            if let v = scriptsEnabled { c.scriptsEnabled = v }
            if let v = mitm { c.mitm = v }
            if let v = skipCertVerify { c.skipCertVerify = v }
            if h2 != nil { c.h2 = h2 }
            if captureBodies != nil { c.captureBodies = captureBodies }
            c.hostnames = hostnames
            c.quic = quic
            c.quicAllow = quicAllow
            func keepIDs(_ new: [EngineItem], _ old: [EngineItem]) -> [EngineItem] {
                var pool = old
                return new.map { it in
                    var it = it
                    if let i = pool.firstIndex(where: { $0.line == it.line }) { it.id = pool[i].id; pool.remove(at: i) }
                    return it
                }
            }
            c.rules = keepIDs(rules, base.rules)
            c.scripts = keepIDs(scripts, base.scripts)
            c.modules = modules.map { m in
                var m = m
                if let old = base.modules.first(where: { $0.id == m.id }) ?? base.modules.first(where: { !m.url.isEmpty && $0.url == m.url }) {
                    m.id = old.id
                    if m.updatedAt == nil { m.updatedAt = old.updatedAt }
                }
                return m
            }
            c.scriptResources = scriptResources.isEmpty ? nil : scriptResources
            return c
        }

        /// Equality that ignores item / module ids and the cron-vs-script interleaving (see docs/tern-conf.md).
        func sameContent(_ o: EngineSection) -> Bool {
            func items(_ l: [EngineItem]) -> [String] { l.map { "\($0.enabled)|\($0.note ?? "\u{1}")|\($0.line)" } }
            func scriptsKey(_ l: [EngineItem]) -> [String] {
                let t = l.filter { TernConf.isTask($0.line) }, s = l.filter { !TernConf.isTask($0.line) }
                return items(s) + items(t)
            }
            func mods(_ l: [EngineModule]) -> [EngineModule] { l }
            return rewriteEnabled == o.rewriteEnabled && scriptsEnabled == o.scriptsEnabled && mitm == o.mitm
                && skipCertVerify == o.skipCertVerify && h2 == o.h2 && captureBodies == o.captureBodies
                && hostnames == o.hostnames && quic == o.quic && quicAllow == o.quicAllow
                && items(rules) == items(o.rules) && scriptsKey(scripts) == scriptsKey(o.scripts)
                && mods(modules) == mods(o.modules) && scriptResources == o.scriptResources && ca == o.ca
        }
    }

    /// Cron / event task line (QX [task_local], Surge type=cron / event, Loon [Script] cron).
    static func isTask(_ line: String) -> Bool {
        let p = NCEngineParser.parseLine(line, section: "")
        return !(p.tasks ?? []).isEmpty
    }

    /// The list a line lands in when no `#!list` pragma says otherwise.
    static func defaultIsScript(_ line: String) -> Bool {
        let p = NCEngineParser.parseLine(line, section: "")
        if !(p.tasks ?? []).isEmpty { return true }
        return p.rules.first?.kind == "script"
    }

    /// A line the engine reads as an entry (a commented-out one is then a disabled entry, not prose).
    static func isEntry(_ line: String) -> Bool {
        let p = NCEngineParser.parseLine(line, section: "")
        return p.errors.isEmpty && (!p.rules.isEmpty || !(p.tasks ?? []).isEmpty || !p.coreRules.isEmpty)
    }

    static let sharedBanner = """
    # —— 以下各段为所有配置共用（重写、脚本、MitM）。Sections below are shared by every profile (rewrite, scripts, MitM).
    """

    /// The shared sections for `e` (the editor appends them below the profile part).
    static func serializeEngine(_ e: EngineSection) -> String {
        var out = "\n" + sharedBanner + "\n"
        out += "\n[rewrite_remote]\n"
        for m in e.modules {
            var f = [m.url.isEmpty ? "tern-local" : escURL(m.url)]
            f.append("tag=" + escField(m.name))
            if let i = m.interval { f.append("update-interval=\(i)") }
            f.append("opt-parser=false")
            f.append("enabled=\(m.enabled)")
            f.append("tern-id=" + escField(m.id))
            if m.customName == true { f.append("tern-custom-name=true") }
            if let u = m.updatedAt { f.append("tern-updated=" + formatNumber(u)) }
            if let a = m.args { f.append("tern-argument=" + fieldValue(NCJSONValue.object(a.mapValues { NCJSONValue.string($0) }))) }
            if let p = m.policies { f.append("tern-policy=" + fieldValue(NCJSONValue.object(p.mapValues { NCJSONValue.string($0) }))) }
            out += f.joined(separator: ", ") + "\n"
        }

        out += "\n[rewrite_local]\n"
        if let v = e.rewriteEnabled { out += "#!rewrite = \(v)\n" }
        if let v = e.scriptsEnabled { out += "#!script = \(v)\n" }
        for it in e.rules { out += item(it, script: false) }
        for it in e.scripts where !isTask(it.line) { out += item(it, script: true) }

        out += "\n[task_local]\n"
        for it in e.scripts where isTask(it.line) { out += item(it, script: true, inTasks: true) }

        if !e.scriptResources.isEmpty {
            out += "\n[script_resource]\n"
            for (k, v) in e.scriptResources.sorted(by: { $0.key < $1.key }) {
                var f = [escField(k)]
                if let d = v.disabled { f.append("disabled=\(d)") }
                if let i = v.interval { f.append("interval=\(i)") }
                out += f.joined(separator: ", ") + "\n"
            }
        }

        out += "\n[mitm]\n"
        out += "hostname = " + e.hostnames.map { $0.replacingOccurrences(of: "\n", with: " ") }.joined(separator: ", ") + "\n"
        if let v = e.mitm { out += "enable = \(v)\n" }
        if let v = e.skipCertVerify { out += "skip_validating_cert = \(v)\n" }
        if let v = e.h2 { out += "h2 = \(v)\n" }
        if let v = e.captureBodies { out += "capture-bodies = \(v)\n" }
        if let v = e.quic { out += "quic = \(v)\n" }
        if let v = e.quicAllow { out += "quic-allow = " + v.joined(separator: ", ") + "\n" }
        if let ca = e.ca {
            out += "passphrase = \(ca.passphrase)\n"
            out += "p12 = \(ca.p12.base64EncodedString())\n"
        }
        return out
    }

    /// One local rewrite / script line: verbatim when it reads back as the same entry, else `#!item = <base64 JSON>`.
    private static func item(_ it: EngineItem, script: Bool, inTasks: Bool = false) -> String {
        let l = it.line
        var verbatim = !l.isEmpty && l == l.trimmingCharacters(in: .whitespacesAndNewlines) && !l.contains("\n") && !l.contains("\r")
            && !isComment(l) && !l.hasPrefix("[") && !l.hasPrefix("!")
        if verbatim && !it.enabled && !isEntry(l) { verbatim = false }
        var out = ""
        if verbatim {
            if let n = it.note { out += "#!note = " + escField(n) + "\n" }
            if !inTasks && defaultIsScript(l) != script { out += "#!list = " + (script ? "script" : "rewrite") + "\n" }
            if inTasks && !script { out += "#!list = rewrite\n" }
            out += (it.enabled ? "" : "#") + l + "\n"
        } else {
            var obj: [String: Any] = ["line": l, "enabled": it.enabled, "script": script]
            if let n = it.note { obj["note"] = n }
            let d = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
            out += "#!item = " + d.base64EncodedString() + "\n"
        }
        return out
    }

    static func parseEngine(_ s: Sections) throws -> EngineSection {
        var e = EngineSection()
        // [rewrite_remote]
        var usedIDs = Set<String>()
        for l in s.lines["rewrite_remote"] ?? [] where !isComment(l.text) {
            let fields = splitFields(l.text)
            guard let first = fields.first, !first.isEmpty else { continue }
            let url = first == "tern-local" ? "" : unescURL(first)
            var o: [String: String] = [:]
            for f in fields.dropFirst() { if case let (k, v)? = kvField(f) { o[k.lowercased()] = v } }
            let name = unescField(o["tag"] ?? "")
            var m = EngineModule(name: name.isEmpty ? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? url) : name, url: url)
            if let id = o["tern-id"].map(unescField), !id.isEmpty {
                guard TernFullExport.isModuleID(id) else { throw ParseError(line: l.number, message: String(localized: "无效的模块 id：\(id)")) }
                m.id = id
            }
            guard !usedIDs.contains(m.id) else { throw ParseError(line: l.number, message: String(localized: "模块 id 重复：\(m.id)")) }
            usedIDs.insert(m.id)
            m.enabled = o["enabled"].map { NCConfImportPort.truthy($0) } ?? true
            if let s = o["update-interval"] { m.interval = Int(s) }
            if let s = o["tern-updated"] { m.updatedAt = Double(s) }
            if o["tern-custom-name"].map({ NCConfImportPort.truthy($0) }) == true { m.customName = true }
            if let s = o["tern-argument"] {
                guard case .object(let a) = readFieldValue(s) else { throw ParseError(line: l.number, message: String(localized: "模块参数无法解析")) }
                m.args = a.mapValues { $0.string ?? TernConf.encodeValue($0) }
            }
            if let s = o["tern-policy"] {
                guard case .object(let a) = readFieldValue(s) else { throw ParseError(line: l.number, message: String(localized: "模块参数无法解析")) }
                m.policies = a.mapValues { $0.string ?? TernConf.encodeValue($0) }
            }
            if url.isEmpty && o["tern-id"] == nil { continue } // a local module needs its id (its text lives on this device)
            e.modules.append(m)
        }
        // [rewrite_local] + [task_local]
        func items(_ lines: [SourceLine], tasks: Bool) throws {
            var note: String?
            var list: String?
            for l in lines {
                let t = l.text
                if t.hasPrefix("#!") {
                    guard let eq = t.firstIndex(of: "=") else { continue }
                    let k = t[t.index(t.startIndex, offsetBy: 2)..<eq].trimmingCharacters(in: .whitespaces).lowercased()
                    let v = t[t.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                    switch k {
                    case "note": note = unescField(v)
                    case "list": list = v.lowercased()
                    case "rewrite": e.rewriteEnabled = NCConfImportPort.truthy(v)
                    case "script": e.scriptsEnabled = NCConfImportPort.truthy(v)
                    case "item":
                        guard let d = Data(base64Encoded: v), let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
                              let line = obj["line"] as? String else { throw ParseError(line: l.number, message: String(localized: "base64 内容无效")) }
                        var it = EngineItem(line: line)
                        it.enabled = (obj["enabled"] as? Bool) ?? true
                        it.note = obj["note"] as? String
                        if (obj["script"] as? Bool) ?? defaultIsScript(line) { e.scripts.append(it) } else { e.rules.append(it) }
                        note = nil; list = nil
                    default: break
                    }
                    continue
                }
                var it: EngineItem
                if isComment(t) {
                    if t.hasPrefix("//") { note = nil; list = nil; continue }
                    let body = t.drop(while: { $0 == "#" || $0 == ";" }).trimmingCharacters(in: .whitespaces)
                    guard !body.isEmpty, isEntry(body) else { note = nil; list = nil; continue }
                    it = EngineItem(line: body)
                    it.enabled = false
                } else {
                    it = EngineItem(line: t)
                }
                // Lines that belong to [mitm] in other clients.
                if !isComment(t), t.lowercased().hasPrefix("hostname"), let eq = t.firstIndex(of: "=") {
                    for h in t[t.index(after: eq)...].split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !h.isEmpty && !e.hostnames.contains(h) {
                        e.hostnames.append(h)
                    }
                    continue
                }
                it.note = note
                let script: Bool
                switch list {
                case "script": script = true
                case "rewrite": script = false
                default: script = tasks || defaultIsScript(it.line)
                }
                if script { e.scripts.append(it) } else { e.rules.append(it) }
                note = nil; list = nil
            }
        }
        try items(s.lines["rewrite_local"] ?? [], tasks: false)
        try items(s.lines["task_local"] ?? [], tasks: true)
        // [script_resource]
        for l in s.lines["script_resource"] ?? [] where !isComment(l.text) {
            let fields = splitFields(l.text)
            guard let k = fields.first.map({ unescField($0) }), !k.isEmpty else { continue }
            var r = ScriptResourceSetting()
            for f in fields.dropFirst() {
                guard case let (fk, v)? = kvField(f) else { continue }
                if fk == "disabled" { r.disabled = NCConfImportPort.truthy(v) }
                if fk == "interval" { r.interval = Int(v) }
            }
            e.scriptResources[k] = r
        }
        // [mitm]
        var pass: String?
        var p12: String?
        var p12Line = 0
        for l in s.lines["mitm"] ?? [] where !isComment(l.text) {
            guard let eq = l.text.firstIndex(of: "=") else { throw ParseError(line: l.number, message: String(localized: "无法识别的行")) }
            let k = l.text[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let v = l.text[l.text.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            func list() -> [String] { v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
            switch k {
            case "hostname": for h in list() where !e.hostnames.contains(h) { e.hostnames.append(h) }
            case "enable": e.mitm = NCConfImportPort.truthy(v)
            case "skip_validating_cert", "skip-server-cert-verify": e.skipCertVerify = NCConfImportPort.truthy(v)
            case "h2": e.h2 = NCConfImportPort.truthy(v)
            case "capture-bodies": e.captureBodies = NCConfImportPort.truthy(v)
            case "quic": e.quic = v.isEmpty ? nil : v
            case "quic-allow": e.quicAllow = list()
            case "passphrase": pass = v
            case "p12": p12 = v; p12Line = l.number
            default: break
            }
        }
        if let p12, !p12.isEmpty {
            guard let d = Data(base64Encoded: p12) else { throw ParseError(line: p12Line, message: String(localized: "base64 内容无效")) }
            guard let pass, !pass.isEmpty else { throw ParseError(line: p12Line, message: String(localized: "p12 缺少 passphrase")) }
            e.ca = CAFile(passphrase: pass, p12: d)
        }
        return e
    }
}
