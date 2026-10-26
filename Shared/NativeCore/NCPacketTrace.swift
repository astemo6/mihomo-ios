import Foundation

/// fix/nc-tcp0: one-line summaries of raw TUN packets for 诊断 — the first N packets in each direction go to the
/// startup log, so a device report shows what iOS actually routed into the tunnel (v4 / v6, protocol, destination,
/// TCP flags) and whether what the core sent back carries valid checksums. Pure logic (unit-tested); the data plane
/// owns the limits and the queue.
enum NCPacketTrace {
    /// "v4 tcp 198.18.0.1:50000 → 93.184.216.34:443 [S] 64 B" / "v6 udp [fdfe:…]:5353 → [2404:…]:443 1200 B".
    /// `checksums` adds "csum ok" / "csum BAD (ip|l4)" — used for packets the core emits.
    static func summary(_ p: Data, checksums: Bool = false) -> String {
        let a = [UInt8](p)
        guard let b0 = a.first else { return "empty" }
        let v = b0 >> 4
        var proto: UInt8 = 0
        var l4 = 0
        var src = "", dst = ""
        if v == 4, a.count >= 20 {
            let ihl = Int(b0 & 0x0f) * 4
            guard ihl >= 20, a.count >= ihl else { return "v4 bad header, \(a.count) B" }
            proto = a[9]
            l4 = ihl
            src = "\(a[12]).\(a[13]).\(a[14]).\(a[15])"
            dst = "\(a[16]).\(a[17]).\(a[18]).\(a[19])"
        } else if v == 6, a.count >= 40 {
            proto = a[6]
            l4 = 40
            src = "[" + NCIP.v6(Array(a[8..<24])).string + "]"
            dst = "[" + NCIP.v6(Array(a[24..<40])).string + "]"
        } else {
            return "version \(v), \(a.count) B"
        }
        let name: String
        switch proto {
        case 6: name = "tcp"
        case 17: name = "udp"
        case 1: name = "icmp"
        case 58: name = "icmp6"
        default: name = "proto \(proto)"
        }
        var line = "v\(v) \(name) "
        if (proto == 6 || proto == 17), a.count >= l4 + 4 {
            let sp = Int(a[l4]) << 8 | Int(a[l4 + 1])
            let dp = Int(a[l4 + 2]) << 8 | Int(a[l4 + 3])
            line += "\(src):\(sp) → \(dst):\(dp)"
            if proto == 6, a.count >= l4 + 14 {
                line += " [" + flags(a[l4 + 13]) + "]"
            }
        } else {
            line += "\(src) → \(dst)"
        }
        line += " \(a.count) B"
        if checksums { line += " " + checksumVerdict(a) }
        return line
    }

    static func flags(_ f: UInt8) -> String {
        var s = ""
        if f & 0x02 != 0 { s += "S" }
        if f & 0x10 != 0 { s += "A" }
        if f & 0x01 != 0 { s += "F" }
        if f & 0x04 != 0 { s += "R" }
        if f & 0x08 != 0 { s += "P" }
        return s.isEmpty ? "-" : s
    }

    /// RFC 1071 check of the IPv4 header and the TCP / UDP checksum (v4 and v6, no extension headers).
    static func checksumVerdict(_ a: [UInt8]) -> String {
        guard let b0 = a.first else { return "csum ?" }
        let v = b0 >> 4
        var bad: [String] = []
        var proto: UInt8 = 0
        var l4 = 0
        var pseudo: UInt32 = 0
        if v == 4, a.count >= 20 {
            let ihl = Int(b0 & 0x0f) * 4
            guard a.count >= ihl else { return "csum ?" }
            if fold(sum(a, 0, ihl, 0)) != 0xffff { bad.append("ip") }
            proto = a[9]
            l4 = ihl
            let total = min(a.count, Int(a[2]) << 8 | Int(a[3]))
            pseudo = sum(a, 12, 8, 0) + UInt32(proto) + UInt32(max(0, total - ihl))
            if proto == 6 || proto == 17 {
                if proto == 17, a.count >= l4 + 8, a[l4 + 6] == 0, a[l4 + 7] == 0 {
                    // v4 UDP without checksum is legal
                } else if fold(sum(a, l4, total - l4, pseudo)) != 0xffff {
                    bad.append(proto == 6 ? "tcp" : "udp")
                }
            }
        } else if v == 6, a.count >= 40 {
            proto = a[6]
            l4 = 40
            let plen = min(a.count - 40, Int(a[4]) << 8 | Int(a[5]))
            pseudo = sum(a, 8, 32, 0) + UInt32(proto) + UInt32(plen)
            if proto == 6 || proto == 17 || proto == 58, fold(sum(a, l4, plen, pseudo)) != 0xffff {
                bad.append(proto == 6 ? "tcp" : proto == 17 ? "udp" : "icmp6")
            }
        } else {
            return "csum ?"
        }
        return bad.isEmpty ? "csum ok" : "csum BAD (" + bad.joined(separator: ",") + ")"
    }

    private static func sum(_ a: [UInt8], _ off: Int, _ n: Int, _ acc0: UInt32) -> UInt32 {
        var acc = acc0
        var i = off
        let end = min(a.count, off + max(0, n))
        while i + 1 < end {
            acc &+= UInt32(a[i]) << 8 | UInt32(a[i + 1])
            i += 2
        }
        if i < end { acc &+= UInt32(a[i]) << 8 }
        return acc
    }

    private static func fold(_ x: UInt32) -> UInt32 {
        var acc = x
        while acc >> 16 != 0 { acc = (acc & 0xffff) + (acc >> 16) }
        return acc
    }

    /// A SERVFAIL answer to `query` (same id / question, QR + RA set, RD copied, no records): what the tunnel resolver
    /// sends when every upstream failed, like mihomo's DNS server — a silent drop made iOS's resolver wait, retry and
    /// eventually stop asking the tunnel DNS at all. nil when the query is not a parseable DNS question.
    static func dnsServfail(for query: Data) -> Data? {
        let q = [UInt8](query)
        guard q.count >= 12, q[2] & 0x80 == 0 else { return nil }
        let qd = Int(q[4]) << 8 | Int(q[5])
        var off = 12
        if qd > 0 {
            // skip the first question's name (uncompressed in queries) + type / class
            while off < q.count {
                let len = Int(q[off])
                if len == 0 { off += 1; break }
                if len & 0xc0 != 0 { return nil }
                off += 1 + len
            }
            off += 4
            guard off <= q.count else { return nil }
        }
        var out = Array(q[0..<off])
        out[2] = 0x80 | (q[2] & 0x79) // QR, opcode + RD copied (AA / TC cleared)
        out[3] = 0x80 | 0x02          // RA, RCODE = SERVFAIL
        out[4] = 0; out[5] = qd > 0 ? 1 : 0
        for i in 6..<12 { out[i] = 0 }
        return Data(out)
    }
}
