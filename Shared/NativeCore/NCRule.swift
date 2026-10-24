import Foundation

/// One parsed rule. Mirrors mihomo's rule semantics (the Go core is the spec):
/// `TYPE,payload,POLICY[,options]`; logic rules carry sub-rules without policies:
/// `AND,((DOMAIN,a.com),(IP-CIDR,10.0.0.0/8)),POLICY`.
struct NCRule: Equatable {
    let raw: String
    let kind: String // uppercased type
    let payload: String
    let policy: String // "" for sub-rules inside a logic rule
    let noResolve: Bool
    let subRules: [NCRule]

    var isLogic: Bool { kind == "AND" || kind == "OR" || kind == "NOT" }

    static func parse(_ line: String) -> NCRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        let fields = splitTopLevel(trimmed)
        guard fields.count >= 2 else { return nil }
        let kind = fields[0].uppercased()
        if kind == "MATCH" || kind == "FINAL" {
            return NCRule(raw: line, kind: "MATCH", payload: "", policy: fields[1], noResolve: false, subRules: [])
        }
        guard fields.count >= 3 else { return nil }
        let options = Array(fields.dropFirst(3))
        let noResolve = options.contains { $0.lowercased() == "no-resolve" }
        if ["AND", "OR", "NOT"].contains(kind) {
            let subs = parseLogicPayload(fields[1])
            return NCRule(raw: line, kind: kind, payload: fields[1], policy: fields[2], noResolve: noResolve, subRules: subs)
        }
        return NCRule(raw: line, kind: kind, payload: fields[1], policy: fields[2], noResolve: noResolve, subRules: [])
    }

    /// Payload of a logic rule: `((rule),(rule),...)`; each chunk is itself a rule
    /// (possibly a nested logic rule) without a policy.
    static func parseLogicPayload(_ payload: String) -> [NCRule] {
        var s = payload.trimmingCharacters(in: .whitespaces)
        guard s.hasPrefix("("), s.hasSuffix(")") else { return [] }
        s = String(s.dropFirst().dropLast())
        var out: [NCRule] = []
        var depth = 0
        var start: String.Index?
        var i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c == "(" {
                if depth == 0 { start = s.index(after: i) }
                depth += 1
            } else if c == ")" {
                depth -= 1
                if depth == 0, let st = start {
                    let inner = String(s[st..<i])
                    if let r = parseSubRule(inner) { out.append(r) }
                    start = nil
                }
            }
            i = s.index(after: i)
        }
        return out
    }

    private static func parseSubRule(_ inner: String) -> NCRule? {
        let fields = splitTopLevel(inner)
        guard fields.count >= 2 else { return nil }
        let kind = fields[0].uppercased()
        if ["AND", "OR", "NOT"].contains(kind), fields.count >= 2 {
            return NCRule(raw: inner, kind: kind, payload: fields[1], policy: "",
                          noResolve: false, subRules: parseLogicPayload(fields[1]))
        }
        let options = Array(fields.dropFirst(2))
        return NCRule(raw: inner, kind: kind, payload: fields[1], policy: "",
                      noResolve: options.contains { $0.lowercased() == "no-resolve" }, subRules: [])
    }

    /// Split on commas that are not inside parentheses.
    static func splitTopLevel(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var cur = ""
        for c in s {
            if c == "(" { depth += 1; cur.append(c) }
            else if c == ")" { depth -= 1; cur.append(c) }
            else if c == ",", depth == 0 { out.append(cur.trimmingCharacters(in: .whitespaces)); cur = "" }
            else { cur.append(c) }
        }
        out.append(cur.trimmingCharacters(in: .whitespaces))
        return out
    }
}

/// What a rule matches against. `ip` is the destination IP when known (already
/// resolved, sniffed, or a fake-IP reverse lookup); IP rules with no ip simply
/// do not match — the engine handles resolution and no-resolve upstream.
struct NCMatchContext {
    var domain: String? = nil
    var ip: NCIP? = nil
    var srcIP: NCIP? = nil
    var dstPort: Int? = nil
    var srcPort: Int? = nil
    var network: String? = nil // "tcp" | "udp"
    var processName: String? = nil
    /// Injected lookups (engine supplies GeoIP mmdb / rule providers later).
    var countryOf: (NCIP) -> String? = { _ in nil }
    var asnOf: (NCIP) -> Int? = { _ in nil }
    var ruleSetContains: (String, NCMatchContext) -> Bool = { _, _ in false }
}

struct NCRuleMatcher {
    static func matches(_ rule: NCRule, _ ctx: NCMatchContext) -> Bool {
        switch rule.kind {
        case "MATCH":
            return true
        case "AND":
            return !rule.subRules.isEmpty && rule.subRules.allSatisfy { matches($0, ctx) }
        case "OR":
            return rule.subRules.contains { matches($0, ctx) }
        case "NOT":
            return rule.subRules.first.map { !matches($0, ctx) } ?? false
        case "DOMAIN":
            return ctx.domain.map { $0.lowercased() == rule.payload.lowercased() } ?? false
        case "DOMAIN-SUFFIX":
            guard let d = ctx.domain?.lowercased() else { return false }
            let p = rule.payload.lowercased()
            return d == p || d.hasSuffix("." + p)
        case "DOMAIN-KEYWORD":
            return ctx.domain?.lowercased().contains(rule.payload.lowercased()) ?? false
        case "DOMAIN-WILDCARD":
            return ctx.domain.map { globMatch(pattern: rule.payload.lowercased(), $0.lowercased()) } ?? false
        case "DOMAIN-REGEX":
            guard let d = ctx.domain,
                  let re = try? NSRegularExpression(pattern: rule.payload) else { return false }
            return re.firstMatch(in: d, range: NSRange(d.startIndex..., in: d)) != nil
        case "IP-CIDR", "IP-CIDR6":
            guard let ip = ctx.ip, let cidr = NCCIDR(rule.payload) else { return false }
            return cidr.contains(ip)
        case "SRC-IP-CIDR":
            guard let ip = ctx.srcIP, let cidr = NCCIDR(rule.payload) else { return false }
            return cidr.contains(ip)
        case "GEOIP":
            guard let ip = ctx.ip, let c = ctx.countryOf(ip) else { return false }
            return c.uppercased() == rule.payload.uppercased()
        case "IP-ASN":
            guard let ip = ctx.ip, let asn = ctx.asnOf(ip) else { return false }
            return asn == Int(rule.payload)
        case "DST-PORT":
            return ctx.dstPort.map { portMatches(rule.payload, $0) } ?? false
        case "SRC-PORT":
            return ctx.srcPort.map { portMatches(rule.payload, $0) } ?? false
        case "NETWORK":
            return ctx.network?.lowercased() == rule.payload.lowercased()
        case "PROCESS-NAME", "PROCESS-PATH":
            return ctx.processName.map { $0.lowercased() == rule.payload.lowercased() } ?? false
        case "RULE-SET":
            return ctx.ruleSetContains(rule.payload, ctx)
        default:
            return false
        }
    }

    /// First matching rule wins (mihomo/clash semantics). Returns its policy.
    static func firstMatch(_ rules: [NCRule], _ ctx: NCMatchContext) -> NCRule? {
        for r in rules where matches(r, ctx) { return r }
        return nil
    }

    static func evaluate(_ rules: [NCRule], _ ctx: NCMatchContext) -> String? {
        for r in rules where matches(r, ctx) { return r.policy }
        return nil
    }

    static func portMatches(_ payload: String, _ port: Int) -> Bool {
        for part in payload.split(whereSeparator: { $0 == "/" || $0 == "," }) {
            if let single = Int(part) {
                if single == port { return true }
            } else if part.contains("-") {
                let b = part.split(separator: "-")
                if b.count == 2, let lo = Int(b[0]), let hi = Int(b[1]), port >= lo, port <= hi { return true }
            }
        }
        return false
    }

    static func globMatch(pattern: String, _ value: String) -> Bool {
        let p = Array(pattern), v = Array(value)
        var pi = 0, vi = 0, starP = -1, starV = 0
        while vi < v.count {
            if pi < p.count, p[pi] == "?" || p[pi] == v[vi] {
                pi += 1; vi += 1
            } else if pi < p.count, p[pi] == "*" {
                starP = pi; starV = vi; pi += 1
            } else if starP >= 0 {
                pi = starP + 1; starV += 1; vi = starV
            } else { return false }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}
