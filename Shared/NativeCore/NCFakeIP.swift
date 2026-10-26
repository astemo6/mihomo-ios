import Foundation

/// Fake-IP pool (Clash.Meta semantics): each queried host gets a stable address from
/// the fake-ip range (default 198.18.0.1/16); the tunnel later maps the address
/// back to the host. Mappings persist to a file so restarts keep them, like
/// Clash.Meta's fake-ip cache.
///
/// Filter (`fake-ip-filter`, Surge always-real-ip): glob patterns, `*.d` = d and
/// its subdomains (kept from earlier releases), `+.d` = d and subdomains, `.d` =
/// subdomains only, plus `geosite:` / `rule-set:` entries evaluated through the
/// engine-injected `externalMatcher`. `fake-ip-filter-mode: blacklist` (default)
/// gives listed names real IPs; `whitelist` gives ONLY listed names fake IPs.
///
/// Address allocation (rv2): offsets start at .4 like Clash.Meta (.0 network, .1
/// gateway / tunnel address, .2 / .3 reserved) and the broadcast address is never
/// handed out. The number of live mappings is capped (`maxEntries`); past the cap
/// the least-recently-used mapping is recycled (second-chance / clock over the
/// allocation order: a mapping looked up since the last sweep — by a DNS re-query
/// or a connection deref — survives one more round). The pool never returns an
/// address that is not registered to the requested host.
final class NCFakeIPPool {
    private let base: UInt32
    private let count: UInt32
    private let firstOff: UInt32
    private let lastOff: UInt32
    private var hostToIP: [String: UInt32] = [:]   // absolute v4 address
    private var ipToHost: [UInt32: String] = [:]
    private var cursor: UInt32                      // next offset to probe
    private let capacity: Int
    /// Allocation order (absolute addresses) for recycling; entries already
    /// removed are skipped lazily. `ringHead` is the logical front.
    private var ring: [UInt32] = []
    private var ringHead = 0
    private var referenced: Set<UInt32> = []
    private let lock = NSLock()
    let filter: [String]
    let whitelist: Bool
    /// Plain filter patterns (lowercased) and the geosite: / rule-set:
    /// entries (one per category / provider, comma lists expanded).
    private let patterns: [String]
    let externalEntries: [String]
    /// Engine-injected matcher for `externalEntries` (host -> listed).
    /// Set once at load, before the pool answers queries.
    var externalMatcher: ((String) -> Bool)?

    // IPv6 fake pool (fake-ip-range6): offsets live in the low 64 bits of
    // the range; hosts map independently of the v4 pool. Same cap / clock.
    private let base6: [UInt8]?
    private var prefix6: Int = 0
    private let count6: UInt64
    private var hostToIP6: [String: UInt64] = [:]
    private var ipToHost6: [Data: String] = [:]
    private var nextOffset6: UInt64 = 1
    private var ring6: [UInt64] = []
    private var ring6Head = 0
    private var referenced6: Set<UInt64> = []

    init(range: String = "198.18.0.1/16", range6: String? = nil, filter: [String] = [],
         whitelist: Bool = false, maxEntries: Int = 8192) {
        let cidr = NCCIDR(range) ?? NCCIDR("198.18.0.1/16")!
        var b4: UInt32 = 0xc612_0000
        var n4: UInt32 = 0x1_0000 // v6 fake-ip-range here is invalid; fall back to the v4 default size
        if case .v4(let v) = cidr.network {
            let hostBits = 32 - cidr.bits
            n4 = hostBits >= 31 ? UInt32(1) << 31 : (UInt32(1) << hostBits)
            b4 = hostBits == 0 ? v : (v >> hostBits) << hostBits
        }
        var fOff: UInt32 = 0, lOff: UInt32 = n4 - 1
        if n4 >= 16 {
            fOff = 4          // Clash.Meta: first = gateway + 3 (198.18.0.4)
            lOff = n4 - 2     // broadcast excluded
        } else if n4 >= 4 {
            fOff = 1
            lOff = n4 - 2
        }
        base = b4
        count = n4
        firstOff = fOff
        lastOff = lOff
        cursor = fOff
        capacity = max(1, min(Int(lOff - fOff) + 1, maxEntries))
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
                    b[i] = b[i] & (UInt8(0xff) << UInt8(8 - keep)) // UInt8 shift: never traps
                }
            }
            base6 = b
        } else {
            base6 = nil
            count6 = 0
        }
        self.filter = filter
        self.whitelist = whitelist
        var plain: [String] = []
        var external: [String] = []
        for raw in filter {
            let item = raw.trimmingCharacters(in: .whitespaces)
            let lower = item.lowercased()
            if lower.hasPrefix("geosite:") || lower.hasPrefix("rule-set:") {
                // Clash.Meta parseDomain: `geosite:cn,private` = two categories.
                let prefix = lower.hasPrefix("geosite:") ? "geosite:" : "rule-set:"
                for part in item.dropFirst(prefix.count).split(separator: ",") {
                    let arg = part.trimmingCharacters(in: .whitespaces)
                    if !arg.isEmpty { external.append(prefix + arg) }
                }
            } else if !lower.isEmpty {
                plain.append(lower)
            }
        }
        patterns = plain
        externalEntries = external
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
        guard base6 != nil, count6 > 2 else { return nil }
        lock.lock(); defer { lock.unlock() }
        let h = host.lowercased()
        if let existing = hostToIP6[h] {
            referenced6.insert(existing)
            return .v6(address6Bytes(forOffset: existing))
        }
        if hostToIP6.count >= capacity { evictOne6() }
        for _ in 0..<min(count6, 1 << 20) {
            let candidate = nextOffset6
            nextOffset6 = nextOffset6 &+ 1
            if nextOffset6 >= count6 - 1 || nextOffset6 == 0 { nextOffset6 = 1 }
            let key = Data(address6Bytes(forOffset: candidate))
            if ipToHost6[key] == nil {
                hostToIP6[h] = candidate
                ipToHost6[key] = h
                ring6.append(candidate)
                mutationCount &+= 1
                return .v6([UInt8](key))
            }
        }
        return nil
    }

    private func evictOne6() {
        while ring6Head < ring6.count {
            let off = ring6[ring6Head]
            ring6Head += 1
            let key = Data(address6Bytes(forOffset: off))
            guard let host = ipToHost6[key], hostToIP6[host] == off else { continue }
            if referenced6.remove(off) != nil { ring6.append(off); continue }
            ipToHost6.removeValue(forKey: key)
            hostToIP6.removeValue(forKey: host)
            break
        }
        if ring6Head > 1024, ring6Head * 2 > ring6.count {
            ring6.removeFirst(ring6Head)
            ring6Head = 0
        }
    }

    /// Whether the name is listed in fake-ip-filter.
    func filterLists(_ host: String) -> Bool {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        for p in patterns {
            if p.hasPrefix("*.") {
                let suffix = String(p.dropFirst(1)) // ".example.com"
                if h.hasSuffix(suffix) || h == String(p.dropFirst(2)) { return true }
            } else if p.hasPrefix("+.") {
                let d = String(p.dropFirst(2))
                if h == d || h.hasSuffix("." + d) { return true }
            } else if p.hasPrefix(".") {
                if h.hasSuffix(p) { return true }
            } else if NCRuleMatcher.globMatch(pattern: p, h) {
                return true
            }
        }
        if !externalEntries.isEmpty, let externalMatcher, externalMatcher(h) { return true }
        return false
    }

    /// blacklist: fake unless listed; whitelist: fake only when listed.
    func shouldFake(_ host: String) -> Bool {
        let listed = filterLists(host)
        return whitelist ? listed : !listed
    }

    /// Stable fake address for a host (allocates on first sight, recycling
    /// the least-recently-used mapping once the pool is at capacity).
    func address(for host: String) -> NCIP {
        lock.lock(); defer { lock.unlock() }
        let h = host.lowercased()
        if let existing = hostToIP[h] {
            referenced.insert(existing)
            return .v4(existing)
        }
        if hostToIP.count >= capacity { evictOne() }
        let usable = lastOff - firstOff + 1
        var probes: UInt32 = 0
        while probes < usable {
            let off = cursor
            cursor = cursor >= lastOff ? firstOff : cursor + 1
            probes += 1
            let candidate = base &+ off
            if ipToHost[candidate] == nil {
                hostToIP[h] = candidate
                ipToHost[candidate] = h
                ring.append(candidate)
                mutationCount &+= 1
                return .v4(candidate)
            }
        }
        // Every usable address is taken (capacity == usable and the evictor
        // found nothing — cannot happen with a consistent ring): force-recycle
        // the slot under the cursor so the answer is still registered to `h`.
        let candidate = base &+ cursor
        cursor = cursor >= lastOff ? firstOff : cursor + 1
        if let old = ipToHost[candidate] { hostToIP.removeValue(forKey: old) }
        referenced.remove(candidate)
        hostToIP[h] = candidate
        ipToHost[candidate] = h
        ring.append(candidate)
        mutationCount &+= 1
        return .v4(candidate)
    }

    /// Clock sweep over the allocation order: referenced mappings get a
    /// second chance (moved to the back), the first unreferenced one is freed.
    private func evictOne() {
        while ringHead < ring.count {
            let a = ring[ringHead]
            ringHead += 1
            guard let host = ipToHost[a], hostToIP[host] == a else { continue } // stale ring entry
            if referenced.remove(a) != nil { ring.append(a); continue }
            ipToHost.removeValue(forKey: a)
            hostToIP.removeValue(forKey: host)
            break
        }
        if ringHead > 1024, ringHead * 2 > ring.count {
            ring.removeFirst(ringHead)
            ringHead = 0
        }
    }

    /// fix/nc-e2e-real: POST /cache/fakeip/flush (DNS 页「清空 Fake-IP 缓存」 answered 404 on the native core). Drops
    /// every mapping (v4 and v6); the next query for a host allocates afresh, like Clash.Meta's FlushFakeIP.
    func flush() {
        lock.lock(); defer { lock.unlock() }
        hostToIP.removeAll(); ipToHost.removeAll(); ring.removeAll(); ringHead = 0; referenced.removeAll()
        cursor = firstOff
        hostToIP6.removeAll(); ipToHost6.removeAll(); ring6.removeAll(); ring6Head = 0; referenced6.removeAll()
        nextOffset6 = 1
        mutationCount &+= 1
    }

    func host(for ip: NCIP) -> String? {
        lock.lock(); defer { lock.unlock() }
        switch ip {
        case .v4(let v):
            guard let h = ipToHost[v] else { return nil }
            referenced.insert(v)
            return h
        case .v6(let bytes):
            guard let h = ipToHost6[Data(bytes)] else { return nil }
            if let off = hostToIP6[h] { referenced6.insert(off) }
            return h
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
                // fix/nc-h2-cidr: was UInt8(0xff << n) on Int, which traps for any fake-ip-range6 prefix not a
                // multiple of 8 (/60, /7, /10) — same bug as NCCIDR (5d058fc). 需同步 feat/nc-kernel.
                let mask = UInt8(0xff) << UInt8(8 - remBits)
                if bytes[fullBytes] & mask != base6[fullBytes] & mask { return false }
            }
            return true
        }
    }

    var size: Int { lock.lock(); defer { lock.unlock() }; return hostToIP.count }

    /// fix/nc-mitm-live: bumped by every new mapping (v4 / v6). The engine persists the pool periodically when this
    /// moved since the last write, so mappings survive an extension that dies without stopTunnel (jetsam / crash /
    /// iOS kill) — apps keep fake IPs in their own DNS caches across tunnel restarts.
    private var mutationCount: UInt64 = 0
    var mutations: UInt64 { lock.lock(); defer { lock.unlock() }; return mutationCount }

    // MARK: Persistence (host -> address pairs, compact and stable across versions)

    /// On-disk format version. Files with any other version (including the pre-version
    /// v1 layout) fail the version check in restore() and are silently rebuilt — a bad or
    /// stale cache must never keep the tunnel from starting. Entry counts are bounded by
    /// the pool's own `capacity` on both the write and the read side, and only mappings
    /// still live in the pool are written (the clock/LRU state is the expiry policy).
    private static let snapshotVersion = 2

    private struct Snapshot: Codable {
        var version: Int
        var base: UInt32
        var pairs: [String: UInt32]
        var pairs6: [String: UInt64] // host -> v6 offset (validated against base6 on restore)
    }

    func snapshotData() -> Data? {
        lock.lock(); defer { lock.unlock() }
        let snap = Snapshot(version: Self.snapshotVersion, base: base, pairs: hostToIP, pairs6: hostToIP6)
        return try? JSONEncoder().encode(snap)
    }

    /// Atomically persist the live mappings (the engine calls this before a reload swaps
    /// the pool out, and on stop). Write failures are ignored by design: persistence is
    /// an optimisation for mapping stability, never a reason to fail a load.
    func persist(to url: URL) {
        guard let data = snapshotData() else { return }
        try? data.write(to: url, options: .atomic)
    }

    func restore(data: Data) {
        guard let snap = try? JSONDecoder().decode(Snapshot.self, from: data),
              snap.version == Self.snapshotVersion, snap.base == base else { return }
        lock.lock(); defer { lock.unlock() }
        // Only addresses this pool may hand out (older builds could persist
        // the network address / .1-.3), at most `capacity`, in address order.
        let lo = base &+ firstOff, hi = base &+ lastOff
        var seen = Set<UInt32>()
        var kept: [(String, UInt32)] = []
        for (h, a) in snap.pairs.sorted(by: { $0.value < $1.value }) where a >= lo && a <= hi {
            guard seen.insert(a).inserted else { continue }
            kept.append((h, a))
            if kept.count >= capacity { break }
        }
        hostToIP = [:]
        ipToHost = [:]
        ring = []
        ringHead = 0
        referenced = []
        for (h, a) in kept {
            hostToIP[h] = a
            ipToHost[a] = h
            ring.append(a)
        }
        if let maxUsed = kept.last?.1 {
            let off = maxUsed &- base
            cursor = off >= lastOff ? firstOff : off + 1
        }
        // v6 mappings: offsets valid for this pool's range6 only, deduped, capped.
        if base6 != nil, count6 > 2 {
            hostToIP6 = [:]
            ipToHost6 = [:]
            ring6 = []
            ring6Head = 0
            referenced6 = []
            var seen6 = Set<Data>()
            var maxOff6: UInt64 = 0
            for (h, off) in snap.pairs6.sorted(by: { $0.value < $1.value }) where off >= 1 && off < count6 - 1 {
                let key = Data(address6Bytes(forOffset: off))
                guard seen6.insert(key).inserted else { continue }
                hostToIP6[h] = off
                ipToHost6[key] = h
                ring6.append(off)
                maxOff6 = off
                if hostToIP6.count >= capacity { break }
            }
            if maxOff6 > 0 {
                nextOffset6 = maxOff6 &+ 1
                if nextOffset6 >= count6 - 1 || nextOffset6 == 0 { nextOffset6 = 1 }
            }
        }
    }
}
