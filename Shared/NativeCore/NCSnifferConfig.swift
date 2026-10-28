import Foundation

/// Parsed `sniffer:` section of the runtime config (Clash.Meta semantics; the
/// app's runtime builder, the retired bridge, sets `enable` from the user's
/// 域名嗅探 toggle and injects the default sniff table below when the
/// profile doesn't carry one — this parser mirrors that injection so the
/// native core behaves exactly like the old core on the same runtime.yaml).
///
/// Defaults follow Clash.Meta: disabled unless enabled, override-destination
/// on. parse-pure-ip defaults ON when the field is absent (an explicit false
/// is honored): QX-style configs carry no such switch and QX always evaluates
/// its filters with the SNI domain, and with the gate off every DOMAIN rule in
/// every rule-set is silently dead for bare-IP flows (HTTPDNS apps — device
/// 2026-10-28: Baidu Maps ads matched only the ad list's 28 IP-CIDR lines,
/// its 2700+ host rules never saw a domain). force-domain / skip-domain use
/// domain-trie semantics (`+.d` or bare `d` = d and its subdomains; `*` globs
/// allowed).
struct NCSnifferConfig: Equatable {
    var enable = false
    var overrideDestination = true
    var parsePureIP = true
    var forceDNSMapping = false // parsed for completeness; the native DNS path always records mappings in fake-ip mode and in redir-host mode
    var forceDomain: [String] = []
    var skipDomain: [String] = []
    var httpPorts: [ClosedRange<Int>] = []
    var httpOverrideDestination: Bool? = nil
    var tlsPorts: [ClosedRange<Int>] = []
    var quicPorts: [ClosedRange<Int>] = []

    init(fields: [String: NCJSONValue]) {
        enable = fields["enable"]?.bool ?? false
        overrideDestination = fields["override-destination"]?.bool ?? true
        parsePureIP = fields["parse-pure-ip"]?.bool ?? true
        forceDNSMapping = fields["force-dns-mapping"]?.bool ?? false
        forceDomain = fields["force-domain"]?.array?.compactMap { $0.string } ?? []
        skipDomain = fields["skip-domain"]?.array?.compactMap { $0.string } ?? []
        if let sniff = fields["sniff"]?.object {
            // Case-insensitive protocol keys (the injected table is uppercase,
            // hand-written profiles vary).
            var byProto: [String: [String: NCJSONValue]] = [:]
            for (k, v) in sniff {
                if let o = v.object { byProto[k.uppercased()] = o }
            }
            if let http = byProto["HTTP"] {
                httpPorts = Self.parsePorts(http["ports"])
                httpOverrideDestination = http["override-destination"]?.bool
            }
            if let tls = byProto["TLS"] { tlsPorts = Self.parsePorts(tls["ports"]) }
            if let quic = byProto["QUIC"] { quicPorts = Self.parsePorts(quic["ports"]) }
        } else if enable {
            // bridge's injected default table, verbatim.
            httpPorts = [80...80, 8080...8880]
            httpOverrideDestination = true
            tlsPorts = [443...443, 8443...8443]
            quicPorts = [443...443, 8443...8443]
        }
    }

    /// Port list entries are numbers or strings, a string being either a
    /// single port or an "a-b" range.
    static func parsePorts(_ v: NCJSONValue?) -> [ClosedRange<Int>] {
        guard let arr = v?.array else { return [] }
        var out: [ClosedRange<Int>] = []
        for item in arr {
            if let n = item.number {
                // A non-port number (NaN, 1e30, -1, 70000) is skipped: Int(Double) would trap past 2^63.
                if n.isFinite, n >= 0, n <= 65535 { out.append(Int(n)...Int(n)) }
            } else if let s = item.string?.trimmingCharacters(in: .whitespaces) {
                if let dash = s.firstIndex(of: "-"),
                   let lo = Int(s[..<dash]), let hi = Int(s[s.index(after: dash)...]), lo <= hi {
                    out.append(lo...hi)
                } else if let n = Int(s) {
                    out.append(n...n)
                }
            }
        }
        return out
    }

    func sniffHTTP(port: Int) -> Bool { enable && httpPorts.contains { $0.contains(port) } }
    func sniffTLS(port: Int) -> Bool { enable && tlsPorts.contains { $0.contains(port) } }
    func sniffQUIC(port: Int) -> Bool { enable && quicPorts.contains { $0.contains(port) } }

    /// Whether the sniffed host replaces the dial target for a protocol
    /// ("http" / "tls" / "quic"): per-protocol value wins, else global.
    func overridesDestination(proto: String) -> Bool {
        if proto == "http", let o = httpOverrideDestination { return o }
        return overrideDestination
    }

    func matchesForceDomain(_ domain: String?) -> Bool {
        guard let domain else { return false }
        return Self.domainList(forceDomain, matches: domain)
    }

    func matchesSkipDomain(_ domain: String?) -> Bool {
        guard let domain else { return false }
        return Self.domainList(skipDomain, matches: domain)
    }

    /// Domain-trie list semantics: `+.d` / bare `d` match d and any
    /// subdomain; entries containing `*` are globs.
    static func domainList(_ list: [String], matches domain0: String) -> Bool {
        var domain = domain0.lowercased()
        if domain.hasSuffix(".") { domain = String(domain.dropLast()) }
        for raw in list {
            var p = raw.lowercased()
            if p.hasSuffix(".") { p = String(p.dropLast()) }
            if p.contains("*") {
                if NCRuleMatcher.globMatch(pattern: p, domain) { return true }
                continue
            }
            if p.hasPrefix("+.") { p = String(p.dropFirst(2)) }
            if domain == p || domain.hasSuffix("." + p) { return true }
        }
        return false
    }
}
