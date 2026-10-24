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

    init(model: NCDNSModel, hosts: [NCHostEntry]) {
        self.model = model
        self.hosts = hosts
    }

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
              let entry = hostsEntry(for: q.name), entry.kind == .address,
              let ip = NCIP(entry.value) else { return nil }
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        let familyOK = (q.type == NCDNSMessage.typeA && ip.isV4)
            || (q.type == NCDNSMessage.typeAAAA && !ip.isV4)
        if familyOK {
            resp.answers = [NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: 60,
                                        rdata: Data(ip.bytes))]
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
        var best: (key: String, servers: [NCDNSServerRef])? = nil
        for item in model.domainServers {
            var key = normalize(item.key)
            if key.hasPrefix("+.") { key = String(key.dropFirst(2)) }
            if key.hasPrefix("geosite:") || key.hasPrefix("rule-set:") || key.hasPrefix("regexp:") { continue }
            if name == key || name.hasSuffix("." + key) {
                if best == nil || key.count > best!.key.count { best = (key, item.servers) }
            }
        }
        return best?.servers ?? []
    }
}
