import Foundation

/// 本机隧道 — a LocalDevVPN / StosVPN compatible loopback ("local device") tunnel, provided by Tern's own VPN so
/// sideload tools (wloc 标准版, StikDebug, SideStore, SideInstaller …) can reach the device's own services
/// (lockdownd / RemotePairing over the developer pairing file) while Tern holds the single VPN slot.
///
/// How LocalDevVPN does it (TunnelProv/PacketTunnelProvider.swift, jkcoxson/LocalDevVPN and SideStore/StosVPN):
/// the tunnel routes one "peer" address (default 10.7.0.1/32) into the TUN; every IPv4 packet read from the TUN has
/// its source and destination addresses swapped and is written straight back. iOS then sees a packet *from*
/// 10.7.0.1 *to* its own tunnel address and delivers it locally, so a connection to 10.7.0.1:<port> lands on the
/// device's own listener on <port>; the replies go to 10.7.0.1 again and are reflected back the same way.
/// Ports are not touched.
///
/// Checksums: the IPv4 header checksum and the TCP / UDP checksums (pseudo-header) are one's-complement sums over
/// 16-bit words in which src and dst appear once each — swapping them leaves every sum unchanged, so no checksum
/// is recomputed (UnitTests/NativeCoreLocalDeviceTunnelTests verifies this).
///
/// Tern differences: the tunnel address is Tern's (198.18.0.1) instead of 10.7.0.0 / 10.7.1.1 — the tools only
/// dial the peer (StikDebug `DeviceConnectionContext.defaultTargetIPAddress = "10.7.0.1"`), and the reflected
/// packet's destination is whatever source iOS chose, so it always comes back to a local address. Only packets
/// whose destination is the peer are reflected (LocalDevVPN reflects everything because only the peer is routed
/// to it); everything else goes to lwIP / the rules as before. Reflected packets never reach the rules, the
/// connection list, the packet trace or the traffic counters.
struct NCLocalDeviceTunnel: Equatable {
    /// LocalDevVPN's default peer (TunnelConstants.defaultPeerIP = "10.7.0.1/32"); wloc / StikDebug / SideStore dial it.
    static let defaultPeer = "10.7.0.1"

    /// The peer address in network byte order, as 4 bytes (compared against IPv4 header bytes 16…19).
    let b0: UInt8, b1: UInt8, b2: UInt8, b3: UInt8

    /// Host-order value of the peer.
    var peer: UInt32 { UInt32(b0) << 24 | UInt32(b1) << 16 | UInt32(b2) << 8 | UInt32(b3) }
    var peerString: String { "\(b0).\(b1).\(b2).\(b3)" }

    /// A strict dotted IPv4 address ("10.7.0.1", optionally "/32"). Refuses addresses that cannot work as a peer:
    /// 0.0.0.0/8, loopback, link-local, multicast / reserved, broadcast and Tern's own 198.18.0.0/15 (tunnel
    /// address, tunnel DNS and the Fake-IP range).
    init?(peer text: String) {
        var t = text.trimmingCharacters(in: .whitespaces)
        if t.hasSuffix("/32") { t.removeLast(3) }
        let parts = t.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var o = [UInt8]()
        o.reserveCapacity(4)
        for p in parts {
            guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0 >= "0" && $0 <= "9" }), let v = UInt8(p) else { return nil }
            o.append(v)
        }
        let v = UInt32(o[0]) << 24 | UInt32(o[1]) << 16 | UInt32(o[2]) << 8 | UInt32(o[3])
        if o[0] == 0 || o[0] == 127 || o[0] >= 224 { return nil }
        if o[0] == 169 && o[1] == 254 { return nil }
        if v & 0xFFFE_0000 == 0xC612_0000 { return nil } // 198.18.0.0/15
        b0 = o[0]; b1 = o[1]; b2 = o[2]; b3 = o[3]
    }

    /// The tunnel to run for these settings, nil when 本机隧道 is off or the address is invalid.
    static func from(enabled: Bool, peer: String) -> NCLocalDeviceTunnel? {
        enabled ? NCLocalDeviceTunnel(peer: peer.isEmpty ? defaultPeer : peer) : nil
    }

    /// The settings validator for the address field (empty = default).
    static func isValidPeer(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespaces).isEmpty || NCLocalDeviceTunnel(peer: text) != nil
    }

    // MARK: Packet path (no allocation: a 4-byte compare per packet)

    /// True when `packet` is IPv4, at least a full minimal header, addressed to the peer, and not from it.
    @inline(__always)
    func matches(_ packet: Data) -> Bool {
        packet.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            guard raw.count >= 20, raw[0] >> 4 == 4, (raw[0] & 0x0f) >= 5 else { return false }
            guard raw[16] == b0, raw[17] == b1, raw[18] == b2, raw[19] == b3 else { return false }
            // src == dst == peer would bounce forever; iOS never sends it, but never loop on it either.
            return !(raw[12] == b0 && raw[13] == b1 && raw[14] == b2 && raw[15] == b3)
        }
    }

    /// Swap the IPv4 source and destination addresses in place. Checksums stay valid (see the type comment).
    @inline(__always)
    static func reflect(_ packet: inout Data) {
        packet.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            guard raw.count >= 20 else { return }
            for i in 12..<16 { raw.swapAt(i, i + 4) }
        }
    }

    /// The reflected copy of `packet` if it is for the peer, else nil.
    @inline(__always)
    func reflected(_ packet: Data) -> Data? {
        guard matches(packet) else { return nil }
        var p = packet
        Self.reflect(&p)
        return p
    }

    // MARK: Routes

    /// The tunnel's excluded IPv4 routes with the peer carved out: an excluded CIDR that contains the peer (the
    /// default 排除的路由 has 10.0.0.0/8) is replaced by the CIDRs that cover it minus the peer /32, so the peer is
    /// routed into the tunnel whatever precedence iOS gives included vs excluded routes. IPv6 entries, invalid
    /// lines and CIDRs that do not contain the peer pass through unchanged.
    func carve(excluded: [String]) -> [String] {
        var out: [String] = []
        out.reserveCapacity(excluded.count)
        let p = peer
        for line in excluded {
            guard let (net, len) = Self.parseV4CIDR(line) else { out.append(line); continue }
            let mask: UInt32 = len == 0 ? 0 : UInt32.max << UInt32(32 - len)
            guard p & mask == net & mask else { out.append(line); continue }
            // Siblings along the path from /len+1 down to /32, each the half that does not hold the peer.
            if len < 32 {
                for l in (len + 1)...32 {
                    let m: UInt32 = UInt32.max << UInt32(32 - l)
                    let sib = (p ^ (1 << UInt32(32 - l))) & m
                    out.append("\(Self.dotted(sib))/\(l)")
                }
            }
        }
        return out
    }

    static func dotted(_ v: UInt32) -> String { "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)" }

    private static func parseV4CIDR(_ text: String) -> (UInt32, Int)? {
        let t = text.trimmingCharacters(in: .whitespaces)
        let parts = t.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let a = parts.first else { return nil }
        let q = a.split(separator: ".", omittingEmptySubsequences: false)
        guard q.count == 4 else { return nil }
        var v: UInt32 = 0
        for x in q {
            guard !x.isEmpty, x.count <= 3, x.allSatisfy({ $0 >= "0" && $0 <= "9" }), let b = UInt8(x) else { return nil }
            v = v << 8 | UInt32(b)
        }
        var len = 32
        if parts.count == 2 {
            guard let l = Int(parts[1]), (0...32).contains(l) else { return nil }
            len = l
        }
        return (v, len)
    }
}

/// The tunnel the extension runs this session. Set by PacketTunnelProvider before the data plane starts; the data
/// plane copies it once at start (no per-packet global read).
enum NCLocalDeviceTunnelState {
    static var active: NCLocalDeviceTunnel?
}
