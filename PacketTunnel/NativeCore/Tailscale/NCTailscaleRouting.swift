import Foundation

// MARK: - Tailscale routing policy (phase 3: exit node + subnet routes)
//
// Turns one netmap snapshot plus the node's `accept-routes` / `exit-node` /
// `exit-node-allow-lan-access` options into the *effective* AllowedIPs that
// get programmed into the WireGuard device. The device sorts its routes by
// prefix length (longest first), so adding a default route to the exit peer
// is safe: peer /32s and accepted subnet routes always win over it.
//
// Policy, mirroring upstream Tailscale semantics:
// - A peer's own addresses (from `Node.Addresses`) are always routable.
// - Advertised subnet routes (the rest of `Node.AllowedIPs`) only enter the
//   table when `accept-routes` is true. Advertised default routes never
//   enter through this path — they only mark exit-node capability.
// - The configured exit node additionally receives the default routes.
//   With `exit-node-allow-lan-access`, private / link-local / loopback and
//   the tailnet's own ranges are carved out of the default routes, so LAN
//   traffic is not forced through the exit node.

public struct NCTailscaleRouteConfig: Equatable {
    public var acceptRoutes: Bool
    public var exitNodeQuery: String?
    public var allowLanAccess: Bool

    public init(proxy: NCProxy) {
        acceptRoutes = proxy.fields["accept-routes"]?.bool ?? false
        let rawExit = proxy.fields["exit-node"]?.string?.trimmingCharacters(in: .whitespaces) ?? ""
        exitNodeQuery = rawExit.isEmpty ? nil : rawExit
        allowLanAccess = proxy.fields["exit-node-allow-lan-access"]?.bool ?? false
    }
}

public enum NCTailscaleRouting {
    // MARK: Exit node resolution

    /// Resolves the configured exit-node value against the netmap peers.
    /// Accepts a tailnet IP, a node name (FQDN or short name), a Hostinfo
    /// hostname, or `auto` / `auto:any` (first peer advertising a default
    /// route, i.e. offering itself as an exit node).
    public static func resolveExitNode(query: String, peers: [NCTailscaleNode]) -> NCTailscaleNode? {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        if q == "auto" || q == "auto:any" {
            return peers.first { peer in
                peer.AllowedIPs.contains { isDefaultRoute($0) }
            }
        }
        if let ip = NCIP(q) {
            return peers.first { peer in
                peer.Addresses.contains { hostPart($0) == ip.string.lowercased() }
            }
        }
        return peers.first { peer in
            if let name = peer.Name?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) {
                if name == q || name.split(separator: ".").first.map(String.init) == q {
                    return true
                }
            }
            if let host = peer.Hostinfo?.Hostname.lowercased(), host == q {
                return true
            }
            return false
        }
    }

    // MARK: Effective AllowedIPs

    public static func effectiveAllowedIPs(
        for peer: NCTailscaleNode,
        isExitNode: Bool,
        config: NCTailscaleRouteConfig
    ) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        func add(_ cidr: String) {
            let key = cidr.trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, seen.insert(key).inserted else { return }
            out.append(key)
        }

        for addr in peer.Addresses { add(addr) }

        if config.acceptRoutes {
            for route in peer.AllowedIPs where !isDefaultRoute(route) {
                add(route)
            }
        }

        if isExitNode {
            for cidr in exitDefaultRoutes(allowLanAccess: config.allowLanAccess) {
                add(cidr)
            }
        }
        return out
    }

    /// Default routes granted to the exit peer, optionally with LAN carved out.
    public static func exitDefaultRoutes(allowLanAccess: Bool) -> [String] {
        guard allowLanAccess else { return ["0.0.0.0/0", "::/0"] }
        var routes = complementV4(excluding: lanExclusionsV4)
        routes += complementV6(excluding: lanExclusionsV6)
        return routes
    }

    // MARK: LAN classification (for dial errors and default-route carving)

    public static let lanExclusionsV4: [String] = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "127.0.0.0/8",
        "100.64.0.0/10", // tailnet CGNAT range: never force via exit node
    ]

    public static let lanExclusionsV6: [String] = [
        "::1/128", "fe80::/10",
        "fd7a:115c:a1e0::/48", // tailnet ULA range
    ]

    public static func isLANOrTailnet(_ ip: NCIP) -> Bool {
        switch ip {
        case .v4:
            return lanExclusionsV4.contains { NCCIDR($0)?.contains(ip) == true }
        case .v6:
            return lanExclusionsV6.contains { NCCIDR($0)?.contains(ip) == true }
        }
    }

    // MARK: Helpers

    public static func isDefaultRoute(_ cidr: String) -> Bool {
        let t = cidr.trimmingCharacters(in: .whitespaces)
        return t == "0.0.0.0/0" || t == "::/0"
    }

    /// "100.64.0.5/32" -> "100.64.0.5" (lowercased); plain IPs pass through.
    private static func hostPart(_ addr: String) -> String {
        let t = addr.trimmingCharacters(in: .whitespaces)
        if let slash = t.firstIndex(of: "/") {
            return String(t[..<slash]).lowercased()
        }
        return t.lowercased()
    }

    // MARK: CIDR complement (0.0.0.0/0 or ::/0 minus exclusion intervals)

    /// IPv4 complement via interval subtraction + largest-block decomposition.
    public static func complementV4(excluding: [String]) -> [String] {
        var intervals: [(UInt64, UInt64)] = []
        for s in excluding {
            guard let c = NCCIDR(s), case .v4(let base) = c.network else { continue }
            let bits = c.bits
            let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
            let lo = UInt64(base & mask)
            let hi = lo + (bits == 0 ? UInt64(UInt32.max) : UInt64(UInt32.max >> bits))
            intervals.append((lo, min(hi, UInt64(UInt32.max))))
        }
        return complement(totalBits: 32, intervals: intervals).map { (lo, bits) in
            let ip = NCIP.v4(UInt32(lo))
            return "\(ip.string)/\(bits)"
        }
    }

    /// IPv6 complement; intervals are handled in 128-bit (hi, lo) space.
    public static func complementV6(excluding: [String]) -> [String] {
        var intervals: [(U128, U128)] = []
        for s in excluding {
            guard let c = NCCIDR(s), case .v6(let bytes) = c.network, bytes.count == 16 else { continue }
            let bits = c.bits
            var base = U128(bytes: bytes)
            base = base.masked(prefixBits: bits, totalBits: 128)
            let size = U128.powerOfTwo(128 - bits) // count of addresses
            let hi = base.adding(size).subtracting(U128(1))
            intervals.append((base, hi))
        }
        return complement128(intervals: intervals).map { (lo, bits) in
            let ip = NCIP.v6(lo.bytes)
            return "\(ip.string)/\(bits)"
        }
    }

    /// Emits the gaps between sorted exclusion intervals inside [0, 2^32)
    /// as the minimal list of (network address, prefix bits) blocks.
    private static func complement(totalBits: Int, intervals: [(UInt64, UInt64)]) -> [(UInt64, Int)] {
        let sorted = intervals.sorted { $0.0 < $1.0 }
        var out: [(UInt64, Int)] = []
        var cursor: UInt64 = 0
        let limit = UInt64(1) << totalBits // exclusive end (2^32 fits in UInt64)
        func emit(from a: UInt64, toExclusive b: UInt64) {
            var start = a
            while start < b {
                let remaining = b - start
                // largest aligned block at `start`
                var block = start == 0 ? limit : start & (~start &+ 1)
                while block > remaining { block >>= 1 }
                let bits = totalBits - (63 - (block.leadingZeroBitCount)) // log2(block)
                out.append((start, bits))
                start += block
            }
        }
        for (lo, hi) in sorted {
            if lo > cursor { emit(from: cursor, toExclusive: lo) }
            cursor = max(cursor, hi &+ 1)
            if cursor >= limit { return out }
        }
        if cursor < limit { emit(from: cursor, toExclusive: limit) }
        return out
    }

    /// 128-bit variant of the gap decomposition.
    private static func complement128(intervals: [(U128, U128)]) -> [(U128, Int)] {
        let sorted = intervals.sorted { $0.0 < $1.0 }
        var out: [(U128, Int)] = []
        var cursor = U128(0)
        let limit = U128.powerOfTwo(128) // exclusive end == 2^128, represented as overflow sentinel
        func emit(from a: U128, toExclusive b: U128) {
            var start = a
            while start < b {
                if start.isZero && b.isOverflowSentinel {
                    // the whole remaining space is one ::/0-sized block
                    out.append((start, 0))
                    return
                }
                // when b is the 2^128 sentinel, wrapped subtraction still
                // yields the true remaining count (2^128 - start)
                let remaining = b.subtracting(start)
                // at address 0 the largest aligned block is the whole space;
                // start from 2^127 and let the halving loop cap it (the full
                // 2^128 case returned early above)
                var block = start.isZero ? U128.powerOfTwo(127) : start.lowestSetBitValue
                while block > remaining { block = block.shiftedRight(1) }
                let bits = 128 - block.log2
                out.append((start, bits))
                start = start.adding(block)
            }
        }
        for (lo, hi) in sorted {
            if lo > cursor { emit(from: cursor, toExclusive: lo) }
            let next = hi.adding(U128(1))
            if next > cursor { cursor = next }
            if cursor.isOverflowSentinel { return out }
        }
        if !cursor.isOverflowSentinel { emit(from: cursor, toExclusive: limit) }
        return out
    }
}

// MARK: - Minimal 128-bit unsigned value for IPv6 interval math

public struct U128: Comparable, Equatable {
    public var hi: UInt64
    public var lo: UInt64

    public init(_ v: UInt64) { hi = 0; lo = v }

    public init(bytes: [UInt8]) {
        var h: UInt64 = 0
        var l: UInt64 = 0
        for i in 0..<8 { h = h << 8 | UInt64(bytes[i]) }
        for i in 8..<16 { l = l << 8 | UInt64(bytes[i]) }
        hi = h
        lo = l
    }

    public var bytes: [UInt8] {
        var out: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((hi >> shift) & 0xff)) }
        for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((lo >> shift) & 0xff)) }
        return out
    }

    public static func < (a: U128, b: U128) -> Bool {
        a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo
    }

    public func adding(_ o: U128) -> U128 {
        let (l, carry) = lo.addingReportingOverflow(o.lo)
        return U128(hi: hi &+ o.hi &+ (carry ? 1 : 0), lo: l)
    }

    public func subtracting(_ o: U128) -> U128 {
        let (l, borrow) = lo.subtractingReportingOverflow(o.lo)
        return U128(hi: hi &- o.hi &- (borrow ? 1 : 0), lo: l)
    }

    private init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }

    public var isZero: Bool { hi == 0 && lo == 0 }

    /// True when this value represents 2^128 (wrapped to zero by overflow).
    /// Only produced by `powerOfTwo(128)` / adding past the top; used as an
    /// exclusive-end sentinel in complement decomposition.
    public var isOverflowSentinel: Bool { isZero }

    public static func powerOfTwo(_ n: Int) -> U128 {
        if n >= 128 { return U128(hi: 0, lo: 0) } // sentinel for 2^128
        if n >= 64 { return U128(hi: UInt64(1) << (n - 64), lo: 0) }
        return U128(hi: 0, lo: UInt64(1) << n)
    }

    public func masked(prefixBits: Int, totalBits: Int) -> U128 {
        if prefixBits <= 0 { return U128(0) }
        if prefixBits >= totalBits { return self }
        if prefixBits >= 64 {
            // keep top (prefixBits-64) bits of lo, all of hi
            let loBits = prefixBits - 64
            let loMask = UInt64.max << (64 - loBits)
            return U128(hi: hi, lo: lo & loMask)
        } else {
            let hiMask = UInt64.max << (64 - prefixBits)
            return U128(hi: hi & hiMask, lo: 0)
        }
    }

    /// Value of the lowest set bit (as a power of two); zero when self is zero.
    public var lowestSetBitValue: U128 {
        if lo != 0 { return U128(hi: 0, lo: lo & (~lo &+ 1)) }
        return U128(hi: hi & (~hi &+ 1), lo: 0)
    }

    public func shiftedRight(_ n: Int) -> U128 {
        if n >= 128 { return U128(0) }
        if n >= 64 { return U128(hi: 0, lo: hi >> (n - 64)) }
        if n == 0 { return self }
        return U128(hi: hi >> n, lo: (lo >> n) | (hi << (64 - n)))
    }

    /// log2 for power-of-two values (used only on such values).
    public var log2: Int {
        if hi != 0 { return 64 + (63 - hi.leadingZeroBitCount) }
        if lo != 0 { return 63 - lo.leadingZeroBitCount }
        return 128 // overflow sentinel (2^128)
    }
}
