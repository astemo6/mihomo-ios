import Foundation

/// fix/rule-labels (device report 2026-10-22, Home 规则 card: a ring read 「((Netw…ort,80))」 · AND · __MITM__): how a
/// matched rule and its policy are shown to a person, Egern-style — the payload first (a rule set's name, a domain, a
/// readable summary of a logical rule), a human rule-type name under it, then the policy. One place for the Home 规则
/// card, 规则命中, the 连接 list and its filter sheet, and the connection detail.
///
/// Input is what Clash.Meta's /connections (and the tunnel's stats) carry: `rule` = the old core type name (constant/rule.go
/// RuleType.String(): Domain, DomainSuffix, RuleSet, GeoIP, IPCIDR, Match, AND, ProcessName…), `rulePayload` = the
/// rule's Payload(); logical rules log their sub-rules as `((Network,tcp) && (DstPort,80))`, `(… || …)` and NOT as
/// `(!(Type,payload))` (rules/logic/logic.go). The combined `Type(payload)` form is ConnectionItem.ruleText, the key the
/// session stats count hits by. Filtering always keeps using those raw values; only the text shown changes.
///
/// App-injected rules never show their internals: the engine's outbound `__MITM__`
/// is 「重写引擎」, its `AND,((NETWORK,TCP),(NOT,((IN-TYPE,INNER))),(DST-PORT,80))` rule is 「HTTP 明文（端口 80）」 · 重写,
/// the MitM-hosts TCP rule 「HTTPS 解密（MitM）」 · 重写, and the QUIC refusals 「UDP 443（QUIC）」 · 阻止 QUIC.
/// Pure and nonisolated: the 连接 page calls it off the main thread while filtering.
enum RuleDisplay {
    /// The engine outbound the app injects. Never shown by this name.
    static let engineOutbound = "__MITM__"

    struct Parts: Equatable {
        /// First line: payload (rule-set name, domain, 「TCP · 端口 80」…), or the type name when the rule has none (MATCH).
        let primary: String
        /// Human rule-type name (「规则集」「域名后缀」「逻辑与」「重写」); empty when `primary` already is the type.
        let type: String
        /// Profile spelling of the raw type (RULE-SET, DOMAIN-SUFFIX, AND) — colour key and accessibility id of the tag.
        let key: String
    }

    // MARK: rules

    /// From ConnectionItem.ruleText / a stats rule key: 「RuleSet(Facebook)」, 「AND(((Network,tcp) && (DstPort,80)))」, 「Match」, 「—」.
    static func describe(_ ruleText: String, policy: String? = nil) -> Parts {
        let (type, payload) = split(ruleText)
        return describe(type: type, payload: payload, policy: policy)
    }

    /// From the separate /connections fields.
    static func describe(type rawType: String?, payload rawPayload: String?, policy: String? = nil) -> Parts {
        let type = (rawType ?? "").trimmingCharacters(in: .whitespaces)
        let payload = (rawPayload ?? "").trimmingCharacters(in: .whitespaces)
        if type.isEmpty || type == "—" { return Parts(primary: "—", type: "", key: "") }
        let key = Theme.ruleTypeName(type)
        let t = norm(type)

        if t == "AND" || t == "OR" || t == "NOT" {
            let text = "\(type)(\(payload))"
            let n = payload.uppercased().replacingOccurrences(of: " ", with: "")
            let engine = n.contains("(INTYPE,INNER)") || n.contains("RULESET,__MITM_")
            let rejecting = policy.map { $0.uppercased().hasPrefix("REJECT") } ?? true
            if rejecting, RejectClassifier.isQUIC(rule: text) {
                let p = RejectClassifier.isMitMQUIC(rule: text) ? String(localized: "UDP 443（QUIC）· MitM 主机") : String(localized: "UDP 443（QUIC）")
                return Parts(primary: p, type: String(localized: "阻止 QUIC"), key: key)
            }
            if engine || policy == engineOutbound {
                if n.contains("RULESET,__MITM_HOSTS") { return Parts(primary: String(localized: "HTTPS 解密（MitM）"), type: String(localized: "重写"), key: key) }
                if n.contains("(DSTPORT,80)") { return Parts(primary: String(localized: "HTTP 明文（端口 80）"), type: String(localized: "重写"), key: key) }
                let s = logicSummary(t, payload, dropEngineTerms: true)
                return Parts(primary: s.isEmpty ? String(localized: "重写") : s, type: String(localized: "重写"), key: key)
            }
            let s = logicSummary(t, payload, dropEngineTerms: false)
            return Parts(primary: s.isEmpty ? payload : s, type: typeName(type), key: key)
        }

        let name = typeName(type)
        if payload.isEmpty { return Parts(primary: name, type: "", key: key) }
        // A plain rule's first line is its payload alone (Egern: 「CN」 over 「GeoIP」); the type is the second line.
        let primary: String
        switch t {
        case "NETWORK": primary = payload.uppercased()
        case "RULESET": primary = termValue(t, payload)
        default: primary = payload
        }
        return Parts(primary: primary, type: name, key: key)
    }

    /// 「DomainKeyword(example)」 → ("DomainKeyword", "example"); a rule without a payload keeps its name.
    static func split(_ rule: String) -> (type: String, payload: String) {
        let r = rule.trimmingCharacters(in: .whitespaces)
        guard r.hasSuffix(")"), let open = r.firstIndex(of: "("), open > r.startIndex else { return (r, "") }
        return (String(r[..<open]), String(r[r.index(after: open)..<r.index(before: r.endIndex)]))
    }

    /// Human name of a Clash.Meta rule type (the old core spelling or profile spelling).
    static func typeName(_ raw: String) -> String {
        switch norm(raw) {
        case "DOMAIN": return String(localized: "域名")
        case "DOMAINSUFFIX": return String(localized: "域名后缀")
        case "DOMAINKEYWORD": return String(localized: "域名关键词")
        case "DOMAINREGEX": return String(localized: "域名正则")
        case "DOMAINWILDCARD": return String(localized: "域名通配")
        case "GEOSITE": return "GeoSite"
        case "GEOIP": return "GeoIP"
        case "SRCGEOIP": return String(localized: "来源 GeoIP")
        case "IPASN": return "ASN"
        case "SRCIPASN": return String(localized: "来源 ASN")
        case "IPCIDR", "IPCIDR6", "IPSUFFIX": return String(localized: "IP 段")
        case "SRCIPCIDR", "SRCIPSUFFIX": return String(localized: "来源 IP 段")
        case "DSTPORT": return String(localized: "目标端口")
        case "SRCPORT": return String(localized: "来源端口")
        case "INPORT": return String(localized: "入站端口")
        case "INUSER": return String(localized: "入站用户")
        case "INNAME": return String(localized: "入站名称")
        case "INTYPE": return String(localized: "入站类型")
        case "PROCESSNAME", "PROCESSNAMEREGEX", "PROCESSNAMEWILDCARD": return String(localized: "进程")
        case "PROCESSPATH", "PROCESSPATHREGEX", "PROCESSPATHWILDCARD": return String(localized: "进程路径")
        // 「规则集」 alone is the plural page title (en 「Rule Sets」); the rule type gets its own entry.
        case "RULESET": return String(localized: "rule.type.ruleset", defaultValue: "规则集")
        case "NETWORK": return String(localized: "网络")
        case "SUBRULES", "SUBRULE": return String(localized: "子规则")
        case "MATCH", "FINAL": return String(localized: "兜底规则")
        case "AND": return String(localized: "逻辑与")
        case "OR": return String(localized: "逻辑或")
        case "NOT": return String(localized: "逻辑非")
        case "UID": return "UID"
        case "DSCP": return "DSCP"
        default: return Theme.ruleTypeName(raw)
        }
    }

    // MARK: policies

    /// A policy / outbound name as shown: the engine outbound becomes 「重写引擎」, everything else is the user's own name.
    static func policyName(_ name: String) -> String {
        name == engineOutbound ? String(localized: "重写引擎") : name
    }

    /// ConnectionItem.chainText with every hop shown by policyName (rule's group first, final node last).
    static func chainText(_ chains: [String]?) -> String {
        (chains ?? []).reversed().map(policyName).joined(separator: " → ")
    }

    // MARK: logical rules

    /// 「((Network,tcp) && (DstPort,80))」 → 「TCP · 端口 80」; OR terms joined by 「 / 」, NOT as 「非 …」.
    static func logicSummary(_ op: String, _ payload: String, dropEngineTerms: Bool) -> String {
        if op == "NOT" {
            guard let inner = notOperand(payload) else { return "" }
            let s = term(inner, dropEngineTerms: dropEngineTerms)
            return s.isEmpty ? "" : String(localized: "非 \(s)")
        }
        let sep = op == "OR" ? "||" : "&&"
        let parts = splitTop(unwrap(payload), sep).map { term($0, dropEngineTerms: dropEngineTerms) }.filter { !$0.isEmpty }
        return parts.joined(separator: op == "OR" ? " / " : " · ")
    }

    /// One `(Type,payload)` operand.
    private static func term(_ raw: String, dropEngineTerms: Bool) -> String {
        let body = unwrap(raw.trimmingCharacters(in: .whitespaces))
        guard let comma = body.firstIndex(of: ",") else { return body }
        let type = String(body[..<comma]).trimmingCharacters(in: .whitespaces)
        let payload = String(body[body.index(after: comma)...]).trimmingCharacters(in: .whitespaces)
        let t = norm(type)
        switch t {
        case "AND", "OR":
            let s = logicSummary(t, payload, dropEngineTerms: dropEngineTerms)
            return s.isEmpty ? "" : "(\(s))"
        case "NOT":
            if dropEngineTerms, let inner = notOperand(payload), isEngineTerm(inner) { return "" }
            return logicSummary("NOT", payload, dropEngineTerms: dropEngineTerms)
        default:
            if dropEngineTerms && isEngineTerm(raw) { return "" }
            return termValue(t, payload)
        }
    }

    /// The readable value of a single (non-logical) condition: 「TCP」「端口 80」「GeoIP CN」「example.com」.
    private static func termValue(_ t: String, _ p: String) -> String {
        switch t {
        case "NETWORK": return p.uppercased()
        case "DSTPORT": return String(localized: "端口 \(p)")
        case "SRCPORT": return String(localized: "来源端口 \(p)")
        case "INPORT": return String(localized: "入站端口 \(p)")
        case "RULESET": return p.lowercased() == "__mitm_hosts" ? String(localized: "MitM 主机") : p
        case "DOMAIN", "DOMAINSUFFIX", "DOMAINKEYWORD", "DOMAINREGEX", "DOMAINWILDCARD", "IPCIDR", "IPCIDR6", "IPSUFFIX",
             "PROCESSNAME", "PROCESSNAMEREGEX", "PROCESSNAMEWILDCARD", "PROCESSPATH", "PROCESSPATHREGEX", "PROCESSPATHWILDCARD",
             "SUBRULES", "SUBRULE":
            return p
        default: return "\(typeName(t)) \(p)"
        }
    }

    /// Conditions only the engine's own rules carry: (InType,INNER) and the internal rule sets.
    private static func isEngineTerm(_ raw: String) -> Bool {
        let n = raw.uppercased().replacingOccurrences(of: " ", with: "")
        return n.contains("INTYPE,INNER") || n.contains("RULESET,__MITM_") || n.contains("RULESET,__QUIC_")
    }

    /// NOT payload 「(!(InType,INNER))」 → 「(InType,INNER)」.
    private static func notOperand(_ payload: String) -> String? {
        var s = unwrap(payload.trimmingCharacters(in: .whitespaces))
        guard s.hasPrefix("!") else { return s.isEmpty ? nil : s }
        s.removeFirst()
        return s
    }

    /// Drops one pair of parentheses when they enclose the whole string.
    private static func unwrap(_ s: String) -> String {
        guard s.hasPrefix("("), s.hasSuffix(")") else { return s }
        var depth = 0
        let lastIndex = s.count - 1
        for (i, ch) in s.enumerated() {
            if ch == "(" { depth += 1 } else if ch == ")" { depth -= 1 }
            if depth == 0 && i < lastIndex { return s } // the first "(" closes early: not one enclosing pair
        }
        return String(s.dropFirst().dropLast())
    }

    /// Splits at `sep` ("&&" / "||") outside parentheses.
    private static func splitTop(_ s: String, _ sep: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var depth = 0
        let chars = Array(s)
        let sepChars = Array(sep)
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            if ch == "(" { depth += 1 } else if ch == ")" { depth -= 1 }
            if depth == 0, i + sepChars.count <= chars.count, Array(chars[i..<i + sepChars.count]) == sepChars {
                out.append(cur.trimmingCharacters(in: .whitespaces))
                cur = ""
                i += sepChars.count
                continue
            }
            cur.append(ch)
            i += 1
        }
        let last = cur.trimmingCharacters(in: .whitespaces)
        if !last.isEmpty { out.append(last) }
        return out
    }

    private static func norm(_ s: String) -> String {
        s.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
    }
}
