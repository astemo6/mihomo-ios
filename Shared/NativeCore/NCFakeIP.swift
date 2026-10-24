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

    // IPv6 fake pool (fake-ip-range6): offsets live in the low 64 bits of
    // the range; hosts map independently of the v4 pool.
    private let base6: [UInt8]?
    private var prefix6: Int = 0
    private let count6: UInt64
    private var hostToIP6: [String: UInt64] = [:]
    private var ipToHost6: [Data: String] = [:]
    private var nextOffset6: UInt64 = 1

    init(range: String = "198.18.0.1/16", range6: String? = nil, filter: [String] = []) {
        let cidr = NCCIDR(range) ?? NCCIDR("198.18.0.1/16")!
        switch cidr.network {
        case .v4(let v):
            let hostBits = 32 - cidr.bits
            count = hostBits >= 31 ? UInt32.max : (UInt32(1) << hostBits)
            base = hostBits == 0 ? v : (v >> hostBits) << hostBits
        case .v6:
            base = 0xc612_0001; count = 0x1_0000 // v6 fake ranges are not used in practice; fall back to the v4 default
        }
        if let range6, let cidr6 = NCCIDR(range6), case .v6(let bytes) = cidr6.network {
            prefix6 = cidr6.bits
            let hostBits = 128 - cidr6.bits
            count6 = hostBits >= 64 ? UInt64.max : (UInt64(1) << hostBits)
            // Zero the host bits of the base address.
            var b = bytes
            for i in 0..<16 {
                let bitPos = i * 8
                if bitPos + 8 <= cidr6.bits { continue }
                if bitPos >= cidr6.bits { b[i] = 0 } else {
                    let keep = cidr6.bits - bitPos
                    b[i] = b[i] & (0xff << (8 - keep))
                }
            }
            base6 = b
        } else {
            base6 = nil
            count6 = 0
        }
        self.filter = filter
    }

    var hasRange6: Bool { base6 != nil }

    private func address6Bytes(forOffset offset: UInt64) -> [UInt8] {
        var b = base6!
        var v = offset
        var i = 15
        while v > 0, i >= 0 {
            b[i] = b[i] | UInt8(v & 0xff)
            v >>= 8
            i -= 1
        }
        return b
    }

    /// Stable fake IPv6 address for a host when range6 is configured.
    func address6(for host: String) -> NCIP? {
        guard base6 != nil else { return nil }
        lock.lock(); defer { lock.unlock() }
        let h = host.lowercased()
        if let existing = hostToIP6[h] { return .v6(address6Bytes(forOffset: existing)) }
        for _ in 0..<min(count6, 1 << 20) {
            let candidate = nextOffset6
            nextOffset6 = (nextOffset6 + 1) % count6
            if nextOffset6 == 0 { nextOffset6 = 1 }
            let bytes = address6Bytes(forOffset: candidate)
            if ipToHost6[Data(bytes)] == nil {
                hostToIP6[h] = candidate
                ipToHost6[Data(bytes)] = h
                return .v6(bytes)
            }
        }
        return nil
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
        lock.lock(); defer { lock.unlock() }
        switch ip {
        case .v4(let v):
            return ipToHost[v]
        case .v6(let bytes):
            return ipToHost6[Data(bytes)]
        }
    }

    /// Whether an address sits inside either fake range (regardless of
    /// whether this pool handed it out — e.g. after a restart).
    func isFakeAddress(_ ip: NCIP) -> Bool {
        switch ip {
        case .v4(let v):
            return v >= base && v - base < count
        case .v6(let bytes):
            guard let base6 else { return false }
            let fullBytes = prefix6 / 8
            for i in 0..<fullBytes where bytes[i] != base6[i] { return false }
            let remBits = prefix6 % 8
            if remBits > 0, fullBytes < 16 {
                let mask = UInt8(0xff << (8 - remBits))
                if bytes[fullBytes] & mask != base6[fullBytes] & mask { return false }
            }
            return true
        }
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
