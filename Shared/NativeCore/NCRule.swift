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
    /// Application protocol learned from the first bytes (sniffer): "http",
    /// "tls" or "quic". Nil when not sniffed — PROTOCOL rules then fall back
    /// to the well-known port (HTTP 80, HTTPS / QUIC 443), Surge-style.
    var protocolHint: String? = nil
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
    /// fix/nc-diag-439 (A): every code of the IP (Meta-geoip0 multi-code records). When set, GEOIP / SRC-GEOIP match
    /// any of them (mihomo MetaV0); nil → `countryOf` alone, as before.
    var countryCodesOf: ((NCIP) -> [String])? = nil
    var asnOf: (NCIP) -> Int? = { _ in nil }
    var ruleSetContains: (String, NCMatchContext) -> Bool = { _, _ in false }
    /// Whether the named rule set holds IP entries (ipcidr behavior, or a
    /// classical list with IP-CIDR / GEOIP / IP-ASN lines) — mihomo's
    /// RuleSet.ShouldResolveIP: a RULE-SET without no-resolve reached by a
    /// domain flow then triggers the one-shot resolve.
    var ruleSetNeedsIP: (String) -> Bool = { _ in false }
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
            guard let d = ctx.domain, let re = NCRegexCache.shared.regex(rule.payload) else { return false }
            return re.firstMatch(in: d, range: NSRange(d.startIndex..., in: d)) != nil
        case "IP-CIDR", "IP-CIDR6":
            guard let ip = ctx.ip, let cidr = NCCIDR(rule.payload) else { return false }
            return cidr.contains(ip)
        case "SRC-IP-CIDR":
            guard let ip = ctx.srcIP, let cidr = NCCIDR(rule.payload) else { return false }
            return cidr.contains(ip)
        case "GEOIP":
            guard let ip = ctx.ip else { return false }
            return geoIPMatches(rule.payload, ip, ctx)
        case "SRC-GEOIP":
            guard let ip = ctx.srcIP else { return false }
            return geoIPMatches(rule.payload, ip, ctx)
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
            guard let p = ctx.processName, let re = NCRegexCache.shared.regex(rule.payload) else { return false }
            return re.firstMatch(in: p, range: NSRange(p.startIndex..., in: p)) != nil
        case "URL-REGEX":
            guard let u = ctx.url, let re = NCRegexCache.shared.regex(rule.payload) else { return false }
            return re.firstMatch(in: u, range: NSRange(u.startIndex..., in: u)) != nil
        case "PROTOCOL":
            return protocolMatches(rule.payload, ctx)
        case "USER-AGENT":
            guard let ua = ctx.userAgent else { return false }
            return globMatch(pattern: rule.payload.lowercased(), ua.lowercased())
        case "SUB-RULE":
            return subRulePolicy(rule, ctx) != nil
        case "RULE-SET", "DOMAIN-SET":
            // DOMAIN-SET (Surge / Loon) is a rule set of behavior domain;
            // the provider store registers it under the same key.
            return ctx.ruleSetContains(rule.payload, ctx)
        default:
            return false
        }
    }

    /// GEOIP payload against the IP's code(s), case-insensitive (fix/nc-diag-439: any code of a multi-code record).
    static func geoIPMatches(_ payload: String, _ ip: NCIP, _ ctx: NCMatchContext) -> Bool {
        let want = payload.trimmingCharacters(in: .whitespaces)
        if let all = ctx.countryCodesOf {
            return all(ip).contains { $0.caseInsensitiveCompare(want) == .orderedSame }
        }
        guard let c = ctx.countryOf(ip) else { return false }
        return c.caseInsensitiveCompare(want) == .orderedSame
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
        if case .hit(_, let r, let p) = scan(rules, ctx, from: 0, mayResolve: false) { return (r, p) }
        return nil
    }

    /// Outcome of one pass over the rule list (see `scan`).
    enum Scan {
        case hit(index: Int, rule: NCRule, policy: String)
        /// Rule `index` needs the destination IP, the flow only has a domain
        /// and the rule lacks no-resolve: resolve the domain once, set
        /// `ctx.ip`, then call `scan(from: index, mayResolve: false)`.
        case needsResolve(index: Int)
        case miss
    }

    /// mihomo tunnel.match semantics: rules are walked in order; the first
    /// rule that wants an IP (IP-CIDR / GEOIP / IP-ASN / an IP-bearing
    /// RULE-SET / a logic rule containing one), reached while the flow has a
    /// domain but no IP and without no-resolve, triggers ONE resolution of
    /// the domain; matching then resumes at that same rule with the IP set
    /// (earlier rules already failed without it). `mayResolve: false` means
    /// the resolution was already attempted (or is not possible here): IP
    /// rules then simply do not match an IP-less flow.
    static func scan(_ rules: [NCRule], _ ctx: NCMatchContext, from start: Int, mayResolve: Bool) -> Scan {
        let wantsResolve = mayResolve && ctx.ip == nil && !(ctx.domain ?? "").isEmpty
        var i = max(0, start)
        while i < rules.count {
            let r = rules[i]
            if wantsResolve, shouldResolveIP(r, ctx) { return .needsResolve(index: i) }
            if matches(r, ctx) {
                if r.kind == "SUB-RULE" {
                    if let p = subRulePolicy(r, ctx) { return .hit(index: i, rule: r, policy: p) }
                } else if r.policy != "PASS-RULE" {
                    return .hit(index: i, rule: r, policy: r.policy)
                }
            }
            i += 1
        }
        return .miss
    }

    /// Rule kinds whose match reads the destination IP.
    static let ipKinds: Set<String> = ["IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"]

    /// mihomo Rule.ShouldResolveIP: true for IP rules without no-resolve,
    /// RULE-SETs over IP data, and logic / SUB-RULE rules containing one.
    static func shouldResolveIP(_ rule: NCRule, _ ctx: NCMatchContext, depth: Int = 0) -> Bool {
        guard !rule.noResolve, depth < 8 else { return false }
        switch rule.kind {
        case "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN":
            return true
        case "RULE-SET":
            return ctx.ruleSetNeedsIP(rule.payload)
        case "AND", "OR", "NOT":
            return rule.subRules.contains { shouldResolveIP($0, ctx, depth: depth + 1) }
        case "SUB-RULE":
            if let cond = rule.subRules.first, shouldResolveIP(cond, ctx, depth: depth + 1) { return true }
            return (ctx.subRules[rule.policy] ?? []).contains { shouldResolveIP($0, ctx, depth: depth + 1) }
        default:
            return false
        }
    }

    /// Surge PROTOCOL rule (QX `protocol` maps here): TCP / UDP by transport;
    /// HTTP / HTTPS / QUIC by the sniffed protocol when known, else by the
    /// well-known port. DOH / DOH3 / DOQ / STUN are not identified natively
    /// and never match (reported once at load by the engine).
    static func protocolMatches(_ payload: String, _ ctx: NCMatchContext) -> Bool {
        let net = ctx.network?.lowercased()
        let hint = ctx.protocolHint?.lowercased()
        switch payload.trimmingCharacters(in: .whitespaces).uppercased() {
        case "TCP": return net == "tcp"
        case "UDP": return net == "udp"
        case "QUIC": return net == "udp" && (hint == "quic" || (hint == nil && ctx.dstPort == 443))
        case "HTTPS", "TLS": return net == "tcp" && (hint == "tls" || (hint == nil && ctx.dstPort == 443))
        case "HTTP": return net == "tcp" && (hint == "http" || (hint == nil && ctx.dstPort == 80))
        default: return false
        }
    }

    /// PROTOCOL payloads the matcher can identify (diagnostics).
    static let supportedProtocols: Set<String> = ["TCP", "UDP", "QUIC", "HTTPS", "TLS", "HTTP"]

    /// Rule kinds this matcher evaluates; anything else never matches
    /// (diagnosed once at load).
    static let knownKinds: Set<String> = [
        "MATCH", "AND", "OR", "NOT", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
        "DOMAIN-REGEX", "DOMAIN-SET", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "GEOIP", "SRC-GEOIP", "GEOSITE",
        "IP-ASN", "DST-PORT", "DEST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "NETWORK", "PROTOCOL",
        "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "URL-REGEX",
        "USER-AGENT", "SUB-RULE", "RULE-SET",
    ]

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

/// Compiled-regex cache shared by every regex rule kind (DOMAIN-REGEX,
/// PROCESS-*-REGEX, URL-REGEX, DNS `regexp:` keys): compiled once per pattern
/// instead of per connection. Invalid patterns are cached as failures so they
/// are not recompiled either. Bounded: past `cap` patterns the cache is
/// cleared (patterns come from the config, so this only bites pathological
/// configs).
final class NCRegexCache {
    static let shared = NCRegexCache()
    private let lock = NSLock()
    private var compiled: [String: NSRegularExpression] = [:]
    private var invalid: Set<String> = []
    private let cap = 1024

    func regex(_ pattern: String) -> NSRegularExpression? {
        lock.lock(); defer { lock.unlock() }
        if let re = compiled[pattern] { return re }
        if invalid.contains(pattern) { return nil }
        if compiled.count + invalid.count >= cap {
            compiled.removeAll(keepingCapacity: true)
            invalid.removeAll(keepingCapacity: true)
        }
        guard let re = try? NSRegularExpression(pattern: pattern) else {
            invalid.insert(pattern)
            return nil
        }
        compiled[pattern] = re
        return re
    }

    /// Load-time validation (diagnostics): true when the pattern compiles.
    func isValid(_ pattern: String) -> Bool { regex(pattern) != nil }
}
