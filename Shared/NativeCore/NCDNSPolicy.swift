import Foundation

/// DNS policy layer (pure logic): hosts-table answers and per-domain
/// upstream selection, benchmarked against Surge / Loon / Quantumult X
/// rather than mihomo alone:
///
/// - [Host] entries answer A/AAAA directly (exact name, `*` globs, aliases
///   chased within the table); an address entry whose family doesn't match
///   the qtype yields NOERROR/no-data, never an upstream leak. Entries of
///   the form `name = server:<addr>` assign that domain a DNS server.
/// - Per-domain upstreams (QX `server=/domain/…`, mihomo nameserver-policy,
///   Loon/Surge host-server entries) pick the longest matching suffix;
///   `+.d` and bare `d` both mean "d and its subdomains" (dnsmasq semantics,
///   what QX users expect).
/// - always-real-ip / fake-ip-filter is handled by the fake-IP pool's
///   `shouldFake` upstream of this layer (filtered names decline the fake
///   answer and land here for forwarding).
struct NCDNSPolicy {
    let model: NCDNSModel
    let hosts: [NCHostEntry]

    /// GEOSITE category matcher (category incl. @attrs, domain) -> Bool,
    /// injected by the engine from its GeoSite.dat store. Used by
    /// nameserver-policy `geosite:` keys and fallback-filter `geosite`.
    /// Nil (no database) = those entries never match; the engine reports
    /// that once at load.
    var geositeContains: ((String, String) -> Bool)? = nil
    /// Rule-provider domain membership (provider name, domain) -> Bool, for
    /// nameserver-policy `rule-set:` keys (mihomo matches only the
    /// provider's domain entries there).
    var ruleSetContainsDomain: ((String, String) -> Bool)? = nil

    enum MatcherKind: Equatable { case geosite, ruleSet, regexp }
    /// nameserver-policy, precompiled: plain domain keys (longest suffix
    /// wins among them) and matcher keys (evaluated in order after the
    /// domain keys — a specific domain beats a whole category).
    private let domainKeys: [(key: String, servers: [NCDNSServerRef])]
    private let matcherKeys: [(kind: MatcherKind, arg: String, servers: [NCDNSServerRef])]
    /// Keys that cannot take effect (unknown prefix, invalid regexp),
    /// listed once in the startup log by the engine.
    let diagnostics: [String]

    init(model: NCDNSModel, hosts: [NCHostEntry]) {
        self.model = model
        self.hosts = hosts
        var dk: [(key: String, servers: [NCDNSServerRef])] = []
        var mk: [(kind: MatcherKind, arg: String, servers: [NCDNSServerRef])] = []
        var diag: [String] = []
        for item in model.domainServers {
            for sub in Self.expandPolicyKey(item.key) {
                let lower = sub.lowercased()
                if lower.hasPrefix("geosite:") {
                    let arg = String(sub.dropFirst(8)).trimmingCharacters(in: .whitespaces)
                    if !arg.isEmpty { mk.append((kind: .geosite, arg: arg, servers: item.servers)) }
                } else if lower.hasPrefix("rule-set:") {
                    let arg = String(sub.dropFirst(9)).trimmingCharacters(in: .whitespaces)
                    if !arg.isEmpty { mk.append((kind: .ruleSet, arg: arg, servers: item.servers)) }
                } else if lower.hasPrefix("regexp:") || lower.hasPrefix("regex:") {
                    let arg = String(sub[sub.index(after: sub.firstIndex(of: ":")!)...])
                    if NCRegexCache.shared.isValid(arg) {
                        mk.append((kind: .regexp, arg: arg, servers: item.servers))
                    } else {
                        diag.append("DNS 分流 \(sub)：正则无效，已忽略")
                    }
                } else if let colon = lower.firstIndex(of: ":"), !lower[..<colon].contains(".") {
                    // geoip: / domain: / keyword: … — not a domain and not a
                    // kind this kernel evaluates.
                    diag.append("DNS 分流键 \(sub) 暂不支持，已忽略")
                } else {
                    var key = lower.trimmingCharacters(in: .whitespaces)
                    if key.hasSuffix(".") { key.removeLast() }
                    for prefix in ["+.", "*.", "."] where key.hasPrefix(prefix) {
                        key = String(key.dropFirst(prefix.count))
                        break
                    }
                    if !key.isEmpty { dk.append((key: key, servers: item.servers)) }
                }
            }
        }
        domainKeys = dk
        matcherKeys = mk
        diagnostics = diag
    }

    /// mihomo parseNameServerPolicy key splitting: `geosite:cn,private` →
    /// geosite:cn + geosite:private; `rule-set:a,b` likewise; any other
    /// comma list is a list of domains.
    static func expandPolicyKey(_ key0: String) -> [String] {
        let key = key0.trimmingCharacters(in: .whitespaces)
        guard key.contains(",") else { return [key] }
        let lower = key.lowercased()
        for prefix in ["geosite:", "rule-set:"] where lower.hasPrefix(prefix) {
            return key.dropFirst(prefix.count).split(separator: ",")
                .map { prefix + $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.count > prefix.count }
        }
        if lower.hasPrefix("regexp:") || lower.hasPrefix("regex:") { return [key] } // commas belong to the regex
        return key.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// Kinds of matcher keys present (diagnostics: geosite keys without a
    /// database, rule-set keys naming an unknown provider).
    var matcherKeyArgs: [(kind: MatcherKind, arg: String)] { matcherKeys.map { (kind: $0.kind, arg: $0.arg) } }

    private func normalize(_ name: String) -> String {
        var n = name.lowercased()
        if n.hasSuffix(".") { n = String(n.dropLast()) }
        return n
    }

    // MARK: hosts

    /// Find the hosts entry governing `name`, chasing aliases (≤5 hops).
    /// Exact matches beat globs; earlier entries win within a class.
    func hostsEntry(for name0: String) -> NCHostEntry? {
        var name = normalize(name0)
        for _ in 0..<6 {
            if let hit = matchHosts(name) {
                if hit.kind == .alias {
                    name = normalize(hit.value)
                    continue
                }
                return hit
            }
            return nil
        }
        return nil
    }

    private func matchHosts(_ name: String) -> NCHostEntry? {
        for e in hosts where !e.pattern.contains("*") {
            if normalize(e.pattern) == name { return e }
        }
        for e in hosts where e.pattern.contains("*") {
            if NCRuleMatcher.globMatch(pattern: e.pattern.lowercased(), name) { return e }
        }
        return nil
    }

    /// A wire response when a hosts address entry answers this query;
    /// nil when the hosts table has nothing to say (caller forwards).
    func hostsReply(queryData: Data) -> Data? {
        guard let query = NCDNSMessage.parse(queryData), query.questions.count == 1 else { return nil }
        let q = query.questions[0]
        guard q.klass == NCDNSMessage.classIN,
              q.type == NCDNSMessage.typeA || q.type == NCDNSMessage.typeAAAA,
              let entry = hostsEntry(for: q.name), entry.kind == .address else { return nil }
        let ips = entry.addresses
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        // Every address of the queried family (dual-stack entries answer
        // both A and AAAA); none of that family -> NOERROR / no data.
        let wantV4 = q.type == NCDNSMessage.typeA
        resp.answers = ips.filter { $0.isV4 == wantV4 }.map {
            NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: 60, rdata: Data($0.bytes))
        }
        return resp.serialized()
    }

    // MARK: per-domain upstreams

    /// The upstream servers assigned to this name, most specific first
    /// source wins: hosts `server:` entries, then the domain-server policy
    /// table (longest suffix). Empty = use the default servers.
    func servers(for name0: String) -> [NCDNSServerRef] {
        let name = normalize(name0)
        if let entry = hostsEntry(for: name), entry.kind == .dnsServer, let srv = entry.dnsServer {
            return [srv]
        }
        var best: (len: Int, servers: [NCDNSServerRef])? = nil
        for item in domainKeys where name == item.key || name.hasSuffix("." + item.key) {
            if best == nil || item.key.count > best!.len { best = (len: item.key.count, servers: item.servers) }
        }
        if let best { return best.servers }
        for item in matcherKeys {
            switch item.kind {
            case .geosite:
                if let geositeContains, geositeContains(item.arg, name) { return item.servers }
            case .ruleSet:
                if let ruleSetContainsDomain, ruleSetContainsDomain(item.arg, name) { return item.servers }
            case .regexp:
                if let re = NCRegexCache.shared.regex(item.arg),
                   re.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil { return item.servers }
            }
        }
        return []
    }

    // MARK: fallback (mihomo dns.fallback + fallback-filter)

    /// The configured fallback servers, in preference order.
    var fallbackServers: [NCDNSServerRef] { model.fallback }

    var hasFallback: Bool { !model.fallback.isEmpty }

    /// Domain-side fallback trigger (mihomo checks the query name against
    /// fallback-filter's geosite/domain lists first): when true, the query
    /// goes to the fallback servers directly instead of trusting the
    /// primary answer for a name expected to be polluted / hijacked.
    func useFallbackFirst(forDomain name0: String) -> Bool {
        guard hasFallback else { return false }
        let name = normalize(name0)
        for raw in model.fallbackFilter.domain {
            var key = normalize(raw)
            if key.hasPrefix("+.") { key = String(key.dropFirst(2)) }
            if name == key || name.hasSuffix("." + key) { return true }
        }
        if let geositeContains {
            for cat in model.fallbackFilter.geosite where geositeContains(cat, name) { return true }
        }
        return false
    }

    /// Answer-side fallback trigger: any A/AAAA in the primary's response
    /// falls inside fallback-filter's ipcidr ranges, so the answer is
    /// treated as polluted and the fallback servers get asked instead.
    func answerTriggersFallback(_ response: Data) -> Bool {
        guard hasFallback, !model.fallbackFilter.ipcidr.isEmpty,
              let msg = NCDNSMessage.parse(response) else { return false }
        let nets = model.fallbackFilter.ipcidr.compactMap { NCCIDR($0) }
        guard !nets.isEmpty else { return false }
        for (ip, _) in msg.addressAnswers {
            if nets.contains(where: { $0.contains(ip) }) { return true }
        }
        return false
    }
}
