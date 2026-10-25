import Foundation

// MARK: - MagicDNS name table (phase 3)
//
// Derived from each netmap snapshot: every node (self + peers) contributes
// its DNS name (`Node.Name`, an FQDN like `host.<tailnet>.ts.net`) and its
// short hostname (first label), mapped to the node's tailnet addresses.
// Lookups serve two consumers:
// - the Tailscale client's own dial path (name -> tailnet IPs without a
//   DNS round-trip), and
// - the tunnel-wide DNS policy, via `NCDNSPolicy.tailscaleHostsProvider`,
//   so apps resolving `*.ts.net` names or short peer names get local
//   answers while the client is running.
//
// Split DNS (DNSConfig.Routes custom resolvers) is intentionally not
// implemented here; only locally-known names are answered.

public final class NCTailscaleMagicDNS {
    private let lock = NSLock()
    private var byFQDN: [String: [NCIP]] = [:]
    private var byShort: [String: [NCIP]] = [:]
    public private(set) var suffixes: [String] = []

    public init() {}

    public func rebuild(snapshot: NCTailscaleNetmapSnapshot) {
        var fqdn: [String: [NCIP]] = [:]
        var short: [String: [NCIP]] = [:]

        func add(node: NCTailscaleNode?) {
            guard let node, let rawName = node.Name else { return }
            let name = Self.normalize(rawName)
            guard !name.isEmpty else { return }
            let ips = node.Addresses.compactMap { NCIP(Self.hostPart($0)) }
            guard !ips.isEmpty else { return }
            fqdn[name] = ips
            let first = name.split(separator: ".").first.map(String.init) ?? name
            // Short-name collisions: first node wins (matches upstream's
            // "one name, one owner" expectation closely enough for a
            // single-user tailnet); FQDNs stay unambiguous.
            if short[first] == nil { short[first] = ips }
        }

        add(node: snapshot.selfNode)
        for peer in snapshot.peers.values { add(node: peer) }

        var suffixSet = Set<String>()
        if let domains = snapshot.dnsConfig?.Domains {
            for d in domains {
                let s = Self.normalize(d)
                if !s.isEmpty { suffixSet.insert(s) }
            }
        }
        if let selfName = snapshot.selfNode?.Name {
            let parts = Self.normalize(selfName).split(separator: ".")
            if parts.count > 1 {
                suffixSet.insert(parts.dropFirst().joined(separator: "."))
            }
        }

        lock.lock()
        byFQDN = fqdn
        byShort = short
        suffixes = Array(suffixSet).sorted()
        lock.unlock()
    }

    /// Tailnet IPs for a name (FQDN or short hostname), [] when unknown.
    public func lookup(_ host: String) -> [NCIP] {
        let name = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        if let hit = byFQDN[name] { return hit }
        if !name.contains("."), let hit = byShort[name] { return hit }
        return []
    }

    /// Whether the name belongs to the tailnet (known suffix or known node).
    public func isTailnetName(_ host: String) -> Bool {
        let name = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        if byFQDN[name] != nil { return true }
        return suffixes.contains { name == $0 || name.hasSuffix("." + $0) }
    }

    public static func normalize(_ name: String) -> String {
        var n = name.lowercased().trimmingCharacters(in: .whitespaces)
        if n.hasSuffix(".") { n = String(n.dropLast()) }
        return n
    }

    private static func hostPart(_ addr: String) -> String {
        let t = addr.trimmingCharacters(in: .whitespaces)
        if let slash = t.firstIndex(of: "/") {
            return String(t[..<slash])
        }
        return t
    }
}
