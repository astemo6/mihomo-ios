import Foundation

/// Fake-IP pool (mihomo semantics): each queried host gets a stable address from
/// the fake-ip range (default 198.18.0.1/16); the tunnel later maps the address
/// back to the host. Hosts matching the filter list (glob, case-insensitive,
/// `*.` treated as suffix) never get fake addresses. Mappings persist to a file
/// so restarts keep them, like mihomo's fake-ip cache.
final class NCFakeIPPool {
    private let base: UInt32
    private let count: UInt32
    private var hostToIP: [String: UInt32] = [:]
    private var ipToHost: [UInt32: String] = [:]
    private var nextOffset: UInt32 = 1 // .0 is the network address; mihomo starts at .1 of the range host part
    private let lock = NSLock()
    let filter: [String]

    init(range: String = "198.18.0.1/16", filter: [String] = []) {
        let cidr = NCCIDR(range) ?? NCCIDR("198.18.0.1/16")!
        switch cidr.network {
        case .v4(let v):
            let hostBits = 32 - cidr.bits
            count = hostBits >= 31 ? UInt32.max : (UInt32(1) << hostBits)
            base = hostBits == 0 ? v : (v >> hostBits) << hostBits
        case .v6:
            base = 0xc612_0001; count = 0x1_0000 // v6 fake ranges are not used in practice; fall back to the v4 default
        }
        self.filter = filter
    }

    func shouldFake(_ host: String) -> Bool {
        let h = host.lowercased()
        for pat in filter {
            let p = pat.lowercased()
            if p.hasPrefix("*.") {
                let suffix = String(p.dropFirst(1)) // ".example.com"
                if h.hasSuffix(suffix) || h == String(p.dropFirst(2)) { return false }
            } else if NCRuleMatcher.globMatch(pattern: p, h) {
                return false
            }
        }
        return true
    }

    /// Stable fake address for a host (allocates on first sight).
    func address(for host: String) -> NCIP {
        lock.lock(); defer { lock.unlock() }
        let h = host.lowercased()
        if let existing = hostToIP[h] { return .v4(existing) }
        // Linear probe from the cursor; wraps around the pool.
        for _ in 0..<count {
            let candidate = base + nextOffset
            nextOffset = (nextOffset + 1) % count
            if ipToHost[candidate] == nil {
                hostToIP[h] = candidate
                ipToHost[candidate] = h
                return .v4(candidate)
            }
        }
        // Pool exhausted: reuse the oldest-style slot deterministically (first).
        let fallback = base + 1
        return .v4(fallback)
    }

    func host(for ip: NCIP) -> String? {
        guard case .v4(let v) = ip else { return nil }
        lock.lock(); defer { lock.unlock() }
        return ipToHost[v]
    }

    var size: Int { lock.lock(); defer { lock.unlock() }; return hostToIP.count }

    // MARK: Persistence (host -> offset pairs, compact and stable across versions)

    private struct Snapshot: Codable {
        var base: UInt32
        var pairs: [String: UInt32]
    }

    func snapshotData() -> Data? {
        lock.lock(); defer { lock.unlock() }
        let snap = Snapshot(base: base, pairs: hostToIP)
        return try? JSONEncoder().encode(snap)
    }

    func restore(data: Data) {
        guard let snap = try? JSONDecoder().decode(Snapshot.self, from: data), snap.base == base else { return }
        lock.lock(); defer { lock.unlock() }
        hostToIP = snap.pairs
        ipToHost = Dictionary(uniqueKeysWithValues: snap.pairs.map { ($0.value, $0.key) })
        if let maxUsed = snap.pairs.values.max() {
            nextOffset = (maxUsed - base + 1) % count
        }
    }
}
