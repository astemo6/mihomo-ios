import Foundation

/// Rule-set (remote rule list) parsing + matching index.
///
/// One parser normalizes the four ecosystems' list dialects into the same
/// buckets, per the user's direction to benchmark rule subscriptions
/// against Quantumult X / Loon / Surge rather than only mihomo:
///
/// - mihomo classical provider payload: `DOMAIN-SUFFIX,google.com[,policy]`
///   lines, or a YAML document with a `payload:` list of such strings
///   (behavior "classical" / "domain" / "ipcidr" texts all reduce to lines)
/// - Surge RULE-SET lists: same classical lines; DOMAIN-SET lists: bare
///   domains, one per line (see suffix semantics below)
/// - Loon remote rules: classical lines
/// - QX filter files: lowercase dialect (`host-suffix,google.com,Policy`)
///
/// A rule SET is an OR of its entries (they all route to the policy the
/// referencing RULE-SET rule names), so the index answers one question:
/// "does this context hit any entry?" — exposed via `contains(_ ctx:)`,
/// which the engine injects as `NCMatchContext.ruleSetContains`.
///
/// DOMAIN-SET suffix semantics (Surge-compatible): a bare entry matches
/// itself and its subdomains; a leading-dot entry matches subdomains only.
/// Both live in a reversed-label trie, so a 50k-entry list costs one walk
/// of the queried hostname's labels, not a linear scan.

enum NCRuleSetFlavor {
    case classical   // TYPE,payload[,policy] lines (mihomo / Surge RULE-SET / Loon)
    case qx          // lowercase QX dialect lines
    case domainSet   // bare domains per line (Surge DOMAIN-SET)
    case auto        // per-line detection (mixed sources)
}

struct NCRuleSetIndex {
    private(set) var exactDomains: Set<String> = []
    private var suffixRoot = NCSuffixTrieNode()
    private(set) var mrsDomainSet: NCMRSDomainSet? = nil
    private(set) var mrsIPCIDRSet: NCMRSIPCIDRSet? = nil
    private(set) var others: [NCRule] = [] // keywords, wildcards, regex, CIDRs, GEOIP, ASN, ports…
    private(set) var entryCount = 0

    // MARK: building

    mutating func addLine(_ rawLine: String, flavor: NCRuleSetFlavor) {
        var line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { return }
        // Trailing comments in published lists are separated by " #"/" //".
        if let r = line.range(of: " #") { line = String(line[..<r.lowerBound]).trimmingCharacters(in: .whitespaces) }
        if line.isEmpty { return }

        switch flavor {
        case .domainSet:
            addDomainSetEntry(line)
        case .qx:
            addClassicalLine(line, dialect: .qx)
        case .classical:
            addClassicalLine(line, dialect: .standard)
        case .auto:
            if line.contains(",") {
                let head = line.prefix { $0 != "," }
                // QX dialect type tokens are all-lowercase; classical lists
                // spell types UPPERCASE.
                let isQX = !head.isEmpty && head == head.lowercased() && head != head.uppercased()
                addClassicalLine(line, dialect: isQX ? .qx : .standard)
            } else {
                addDomainSetEntry(line)
            }
        }
    }

    mutating func addText(_ text: String, flavor: NCRuleSetFlavor) {
        // mihomo YAML provider document: `payload: [ "line", … ]`.
        if flavor == .classical || flavor == .auto,
           let root = NCYAML.parse(text), let payload = root["payload"]?.array {
            for item in payload {
                if let s = item.string { addLine(s, flavor: .classical) }
            }
            if entryCount > 0 { return }
        }
        for line in text.components(separatedBy: .newlines) { addLine(line, flavor: flavor) }
    }

    private enum Dialect { case standard, qx }

    private mutating func addClassicalLine(_ line: String, dialect: Dialect) {
        let fields = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard fields.count >= 2 else { return }
        var kind = fields[0].uppercased()
        let payload = fields[1]
        if dialect == .qx {
            kind = [
                "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD",
                "HOST-WILDCARD": "DOMAIN-WILDCARD", "IP6-CIDR": "IP-CIDR", "USER-AGENT": "USER-AGENT",
            ][kind] ?? kind
        }
        switch kind {
        case "DOMAIN":
            exactDomains.insert(payload.lowercased()); entryCount += 1
        case "DOMAIN-SUFFIX":
            suffixRoot.insert(domain: payload.lowercased(), matchSelf: true, subOnly: false); entryCount += 1
        default:
            // Everything else (keywords, CIDRs, GEOIP, ports, regex…) reuses
            // the single-rule matcher, evaluated linearly — those buckets
            // are small in real lists; domains dominate and are indexed.
            let policy = fields.count >= 3 ? fields[2] : ""
            let opts = fields.dropFirst(3)
            others.append(NCRule(raw: line, kind: kind, payload: payload, policy: policy,
                                 noResolve: opts.contains { $0.lowercased() == "no-resolve" }, subRules: []))
            entryCount += 1
        }
    }

    private mutating func addDomainSetEntry(_ line0: String) {
        var line = line0
        if line.hasPrefix("+.") { line = String(line.dropFirst(2)) } // clash-style suffix marker
        var subOnly = false
        if line.hasPrefix(".") { subOnly = true; line = String(line.dropFirst()) }
        // DOMAIN-SET files sometimes carry full URLs; keep just the host.
        if let scheme = line.range(of: "://") { line = String(line[scheme.upperBound...]) }
        if let slash = line.firstIndex(of: "/") { line = String(line[..<slash]) }
        let host = line.lowercased()
        guard !host.isEmpty, host.contains(".") || subOnly else { return }
        suffixRoot.insert(domain: host, matchSelf: !subOnly, subOnly: subOnly)
        entryCount += 1
    }

    mutating func addMRSDomain(_ domainSet: NCMRSDomainSet) {
        mrsDomainSet = domainSet
        entryCount += domainSet.ruleCount
    }

    mutating func addMRSIPCIDR(_ ipcidrSet: NCMRSIPCIDRSet) {
        mrsIPCIDRSet = ipcidrSet
        entryCount += ipcidrSet.ruleCount
    }

    mutating func addMRS(data: Data, behavior: String? = nil) throws {
        let payload = try NCMRS.decode(data: data, expectedBehavior: behavior)
        switch payload {
        case .domain(let d):
            addMRSDomain(d)
        case .ipcidr(let i):
            addMRSIPCIDR(i)
        }
    }

    // MARK: matching

    func contains(_ ctx: NCMatchContext) -> Bool {
        if let d = ctx.domain?.lowercased() {
            if exactDomains.contains(d) { return true }
            if suffixRoot.matches(host: d) { return true }
            if let ds = mrsDomainSet, ds.has(d) { return true }
        }
        if let ip = ctx.ip {
            if let iset = mrsIPCIDRSet, iset.contains(ip) { return true }
        }
        if others.isEmpty { return false }
        // Rule-set entries must not recurse into other rule sets.
        var sub = ctx
        sub.ruleSetContains = { _, _ in false }
        return others.contains { NCRuleMatcher.matches($0, sub) }
    }
}

/// Reversed-label suffix trie for domain sets.
final class NCSuffixTrieNode {
    var children: [String: NCSuffixTrieNode] = [:]
    var matchSelf = false // an entry ends here and includes the exact host
    var subOnly = false   // an entry ends here covering subdomains only

    func insert(domain: String, matchSelf: Bool, subOnly: Bool) {
        var node = self
        for label in domain.split(separator: ".").reversed() {
            let key = String(label)
            if let next = node.children[key] { node = next }
            else { let n = NCSuffixTrieNode(); node.children[key] = n; node = n }
        }
        node.matchSelf = node.matchSelf || matchSelf
        node.subOnly = node.subOnly || subOnly
    }

    /// Walk the host's labels right-to-left; a hit is any node on the path
    /// flagged matchSelf (covers the host itself when the walk is complete,
    /// or an ancestor domain), or flagged subOnly once at least one label
    /// has been consumed below it (a true subdomain relationship).
    func matches(host: String) -> Bool {
        let labels = host.split(separator: ".").reversed().map(String.init)
        var node = self
        for (i, label) in labels.enumerated() {
            guard let next = node.children[label] else { return false }
            node = next
            if node.matchSelf { return true }
            // subOnly hits only when labels remain below the entry (a true
            // subdomain); host == entry exactly is excluded by definition.
            if node.subOnly, i < labels.count - 1 { return true }
        }
        return false
    }
}
