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
        if kind == "SUB-RULE" {
            // mihomo: `SUB-RULE,(<one condition rule>),<sub-rule set name>` —
            // the third field names the set (it is not a policy), and the
            // payload is a single parenthesised rule without a policy.
            let cond = parseSubRuleCondition(fields[1])
            return NCRule(raw: line, kind: kind, payload: fields[1], policy: fields[2],
                          noResolve: noResolve, subRules: cond.map { [$0] } ?? [])
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

    /// The condition of a SUB-RULE: payload `(DOMAIN-SUFFIX,example.com)` —
    /// strip exactly one parenthesis level and parse the rule inside.
    static func parseSubRuleCondition(_ payload: String) -> NCRule? {
        let s = payload.trimmingCharacters(in: .whitespaces)
        guard s.hasPrefix("("), s.hasSuffix(")"), s.count > 2 else { return nil }
        return parseSubRule(String(s.dropFirst().dropLast()))
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
    /// Full request URL / User-Agent when the flow carries HTTP metadata
    /// (MitM lane). Nil on plain TUN flows — URL-REGEX / USER-AGENT rules
    /// then simply do not match, like IP rules without an IP.
    var url: String? = nil
    var userAgent: String? = nil
    /// Inbound side: the port the connection arrived on (nil for TUN —
    /// there is no listener) and the inbound type ("TUN" here; mihomo also
    /// has HTTP / SOCKS / REDIR / INNER for its other inbounds).
    var inPort: Int? = nil
    var inType: String? = nil
    /// Named sub-rule sets from the config's `sub-rules:` section, for
    /// SUB-RULE evaluation (mihomo semantics: the SUB-RULE line's third
    /// field is the set name; the winning sub-rule supplies the policy).
    var subRules: [String: [NCRule]] = [:]
    /// Injected lookups (engine supplies GeoIP mmdb / rule providers later).
    var countryOf: (NCIP) -> String? = { _ in nil }
    var asnOf: (NCIP) -> Int? = { _ in nil }
    var ruleSetContains: (String, NCMatchContext) -> Bool = { _, _ in false }
    /// GEOSITE lookup: (rule payload incl. any @attrs, domain) -> match.
    var geositeMatches: (String, String) -> Bool = { _, _ in false }
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
        case "SRC-GEOIP":
            guard let ip = ctx.srcIP, let c = ctx.countryOf(ip) else { return false }
            return c.uppercased() == rule.payload.uppercased()
        case "GEOSITE":
            guard let d = ctx.domain else { return false }
            return ctx.geositeMatches(rule.payload, d)
        case "IP-ASN":
            guard let ip = ctx.ip, let asn = ctx.asnOf(ip) else { return false }
            return asn == Int(rule.payload)
        case "DST-PORT", "DEST-PORT":
            return ctx.dstPort.map { portMatches(rule.payload, $0) } ?? false
        case "SRC-PORT":
            return ctx.srcPort.map { portMatches(rule.payload, $0) } ?? false
        case "IN-PORT":
            return ctx.inPort.map { portMatches(rule.payload, $0) } ?? false
        case "IN-TYPE":
            guard let t = ctx.inType else { return false }
            return rule.payload.split(separator: "/").contains {
                $0.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(t) == .orderedSame
            }
        case "NETWORK":
            return ctx.network?.lowercased() == rule.payload.lowercased()
        case "PROCESS-NAME", "PROCESS-PATH":
            return ctx.processName.map { $0.lowercased() == rule.payload.lowercased() } ?? false
        case "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
            guard let p = ctx.processName,
                  let re = try? NSRegularExpression(pattern: rule.payload) else { return false }
            return re.firstMatch(in: p, range: NSRange(p.startIndex..., in: p)) != nil
        case "URL-REGEX":
            guard let u = ctx.url,
                  let re = try? NSRegularExpression(pattern: rule.payload) else { return false }
            return re.firstMatch(in: u, range: NSRange(u.startIndex..., in: u)) != nil
        case "USER-AGENT":
            guard let ua = ctx.userAgent else { return false }
            return globMatch(pattern: rule.payload.lowercased(), ua.lowercased())
        case "SUB-RULE":
            return subRulePolicy(rule, ctx) != nil
        case "RULE-SET":
            return ctx.ruleSetContains(rule.payload, ctx)
        default:
            return false
        }
    }

    /// The policy a matched SUB-RULE yields, per mihomo's matchSubRules:
    /// the line's condition must match, then the named set is scanned in
    /// order — the first matching sub-rule supplies the policy, except a
    /// sub-rule whose policy is PASS-RULE, which passes control to the
    /// next sub-rule instead. Nested SUB-RULEs recurse (depth-capped).
    static func subRulePolicy(_ rule: NCRule, _ ctx: NCMatchContext, depth: Int = 0) -> String? {
        guard rule.kind == "SUB-RULE", depth < 16,
              let cond = rule.subRules.first, matches(cond, ctx),
              let list = ctx.subRules[rule.policy] else { return nil }
        for sub in list {
            if sub.kind == "SUB-RULE" {
                if let p = subRulePolicy(sub, ctx, depth: depth + 1), p != "PASS-RULE" { return p }
                continue
            }
            guard matches(sub, ctx) else { continue }
            if sub.policy == "PASS-RULE" { continue }
            return sub.policy
        }
        return nil
    }

    /// First matching rule wins (mihomo/clash semantics). Returns its policy.
    static func firstMatch(_ rules: [NCRule], _ ctx: NCMatchContext) -> NCRule? {
        for r in rules where matches(r, ctx) { return r }
        return nil
    }

    static func evaluate(_ rules: [NCRule], _ ctx: NCMatchContext) -> String? {
        firstMatchWithPolicy(rules, ctx)?.policy
    }

    /// First matching rule together with the policy it actually yields.
    /// Differs from `firstMatch` for SUB-RULE (the winning sub-rule's
    /// policy, not the set name in the line's policy slot) and for rules
    /// whose policy is PASS-RULE (mihomo: keep scanning subsequent rules).
    static func firstMatchWithPolicy(_ rules: [NCRule], _ ctx: NCMatchContext) -> (rule: NCRule, policy: String)? {
        for r in rules where matches(r, ctx) {
            if r.kind == "SUB-RULE" {
                if let p = subRulePolicy(r, ctx) { return (r, p) }
                continue
            }
            if r.policy == "PASS-RULE" { continue }
            return (r, r.policy)
        }
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
