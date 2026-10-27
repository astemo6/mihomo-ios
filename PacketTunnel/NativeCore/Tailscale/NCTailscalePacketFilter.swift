import Foundation

// MARK: - Tailscale PacketFilter enforcement (phase 3)
//
// Evaluates the control-delivered tailcfg.PacketFilter rules against
// inbound packets (peer -> us, after WireGuard decryption, before the
// packet enters lwIP). This runs *after* the phase-1 cryptokey check
// (source must be inside the sending peer's AllowedIPs) and adds the
// ACL layer on top:
//
// - No rules (nil/empty) -> allow; phase-1 behavior is unchanged.
// - Rules present -> default deny; the packet must match one rule.
// - A rule matches when the source is in SrcIPs/SrcBits, the IP protocol
//   is in IPProto (empty or 0 = any), and some DstPorts entry covers the
//   destination IP + port. Rules carrying only CapGrant entries are
//   capability grants, not plain allows, and never match here
//   (capability enforcement is out of scope, noted in the phase report).
//
// Protocol numbers follow tailcfg: 1 ICMPv4, 6 TCP, 17 UDP, 58 ICMPv6.
// IPv6 extension headers are not walked: the next-header byte is taken
// at face value (noted limitation).

enum NCTailscalePacketFilter {
    struct PacketInfo {
        var src: NCIP
        var dst: NCIP
        var proto: Int
        var dstPort: UInt16?
    }

    /// Parses the inner IP packet header. Returns nil for truncated or
    /// non-IP payloads (caller drops those when rules are enforced).
    static func parse(_ pkt: [UInt8]) -> PacketInfo? {
        guard let first = pkt.first else { return nil }
        switch first >> 4 {
        case 4:
            guard pkt.count >= 20 else { return nil }
            let ihl = Int(first & 0x0f) * 4
            guard ihl >= 20, pkt.count >= ihl else { return nil }
            guard let src = NCIP(bytes: Array(pkt[12..<16])),
                  let dst = NCIP(bytes: Array(pkt[16..<20])) else { return nil }
            let proto = Int(pkt[9])
            var port: UInt16?
            if (proto == 6 || proto == 17), pkt.count >= ihl + 4 {
                port = UInt16(pkt[ihl + 2]) << 8 | UInt16(pkt[ihl + 3])
            }
            return PacketInfo(src: src, dst: dst, proto: proto, dstPort: port)
        case 6:
            guard pkt.count >= 40 else { return nil }
            guard let src = NCIP(bytes: Array(pkt[8..<24])),
                  let dst = NCIP(bytes: Array(pkt[24..<40])) else { return nil }
            let proto = Int(pkt[6])
            var port: UInt16?
            if (proto == 6 || proto == 17), pkt.count >= 44 {
                port = UInt16(pkt[42]) << 8 | UInt16(pkt[43])
            }
            return PacketInfo(src: src, dst: dst, proto: proto, dstPort: port)
        default:
            return nil
        }
    }

    static func allows(packet pkt: [UInt8], rules: [NCTailscalePacketFilterRule]?) -> Bool {
        guard let rules, !rules.isEmpty else { return true }
        guard let info = parse(pkt) else { return false }
        return rules.contains { ruleMatches($0, info) }
    }

    private static func ruleMatches(_ rule: NCTailscalePacketFilterRule, _ info: PacketInfo) -> Bool {
        // Capability-grant-only rules are not plain allows.
        if let grants = rule.CapGrant, !grants.isEmpty,
           (rule.DstPorts ?? []).isEmpty, (rule.IPProto ?? []).isEmpty {
            return false
        }

        // Source: upstream semantics — an empty source list matches nothing.
        let srcMatchers = (rule.SrcIPs ?? []) + (rule.SrcBits ?? [])
        guard !srcMatchers.isEmpty else { return false }
        guard srcMatchers.contains(where: { cidrOrIP($0)?.contains(info.src) == true }) else {
            return false
        }

        // Protocol: empty or containing 0 is the wildcard.
        if let protos = rule.IPProto, !protos.isEmpty, !protos.contains(0) {
            guard protos.contains(info.proto) else { return false }
        }

        // Destination: no DstPorts entries means any destination/port.
        guard let dsts = rule.DstPorts, !dsts.isEmpty else { return true }
        return dsts.contains { entry in
            let dstOK: Bool
            if let bits = entry.Bits, !bits.isEmpty {
                dstOK = NCCIDR(bits)?.contains(info.dst) == true
            } else if entry.IP == "*" {
                dstOK = true
            } else {
                dstOK = cidrOrIP(entry.IP)?.contains(info.dst) == true
            }
            guard dstOK else { return false }
            // Non-TCP/UDP packets have no port; a port-ranged entry can
            // only match them when the range is the full range.
            guard let port = info.dstPort else {
                return entry.Ports.First == 0 && entry.Ports.Last == 65535
            }
            return port >= entry.Ports.First && port <= entry.Ports.Last
        }
    }

    /// Accepts "1.2.3.4", "1.2.3.4/32" and CIDR strings uniformly.
    private static func cidrOrIP(_ s: String) -> NCCIDR? {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.contains("/") { return NCCIDR(t) }
        guard let ip = NCIP(t) else { return nil }
        return NCCIDR(ip.isV4 ? "\(t)/32" : "\(t)/128")
    }
}
