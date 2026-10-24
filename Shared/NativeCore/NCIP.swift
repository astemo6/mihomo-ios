import Foundation

/// IP address + CIDR helpers for the native core (docs/native-core-design.md).
/// Pure value types, no networking: parsing, masking, containment, and the
/// SOCKS/Shadowsocks address (ATYP) encodings shared by rules and outbounds.

enum NCIP: Equatable, Hashable {
    case v4(UInt32)
    case v6([UInt8]) // always 16 bytes

    init?(_ string: String) {
        if let v4 = NCIP.parseV4(string) { self = .v4(v4); return }
        if let v6 = NCIP.parseV6(string) { self = .v6(v6); return }
        return nil
    }

    static func parseV4(_ string: String) -> UInt32? {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: UInt32 = 0
        for p in parts {
            guard let n = UInt32(p), n <= 255, String(n) == String(p) || p == "0" || !p.hasPrefix("0") else { return nil }
            out = (out << 8) | n
        }
        return out
    }

    static func parseV6(_ string: String) -> [UInt8]? {
        var s = string
        // Embedded IPv4 tail (::ffff:1.2.3.4)
        var v4Tail: [UInt8] = []
        if let dot = s.lastIndex(of: ".") {
            var colon = dot
            while colon > s.startIndex, s[s.index(before: colon)] != ":" { colon = s.index(before: colon) }
            guard let v4 = parseV4(String(s[s.index(after: colon)...])) else { return nil }
            v4Tail = [UInt8((v4 >> 24) & 0xff), UInt8((v4 >> 16) & 0xff), UInt8((v4 >> 8) & 0xff), UInt8(v4 & 0xff)]
            s = String(s[...colon]) + "0:0"
        }
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ part: String) -> [UInt16]? {
            if part.isEmpty { return [] }
            var out: [UInt16] = []
            for g in part.split(separator: ":", omittingEmptySubsequences: false) {
                guard let v = UInt16(g, radix: 16), v <= 0xffff else { return nil }
                out.append(v)
            }
            return out
        }
        guard let head = groups(halves[0]) else { return nil }
        var tail: [UInt16] = []
        if halves.count == 2 {
            guard let t = groups(halves[1]) else { return nil }
            tail = t
        }
        let totalGroups = 8 - v4Tail.count / 2
        var all: [UInt16]
        if halves.count == 2 {
            let missing = totalGroups - head.count - tail.count
            guard missing >= 0 else { return nil }
            all = head + Array(repeating: 0, count: missing) + tail
        } else {
            guard head.count == totalGroups else { return nil }
            all = head
        }
        var bytes: [UInt8] = []
        for g in all { bytes.append(UInt8(g >> 8)); bytes.append(UInt8(g & 0xff)) }
        bytes.append(contentsOf: v4Tail)
        guard bytes.count == 16 else { return nil }
        return bytes
    }

    var isV4: Bool { if case .v4 = self { return true }; return false }

    var bytes: [UInt8] {
        switch self {
        case .v4(let v): return [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        case .v6(let b): return b
        }
    }

    /// Dotted/colon text form (for logs and fake-IP reverse lookups).
    var string: String {
        switch self {
        case .v4(let v):
            return "\((v >> 24) & 0xff).\((v >> 16) & 0xff).\((v >> 8) & 0xff).\(v & 0xff)"
        case .v6(let b):
            // IPv4-mapped addresses print as plain IPv4, matching mihomo's display.
            if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff {
                return "\(b[12]).\(b[13]).\(b[14]).\(b[15])"
            }
            var groups: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                groups.append(String((UInt16(b[i]) << 8) | UInt16(b[i + 1]), radix: 16))
            }
            return groups.joined(separator: ":")
        }
    }
}

struct NCCIDR: Equatable {
    let network: NCIP
    let bits: Int

    init?(_ string: String) {
        let parts = string.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2, let ip = NCIP(String(parts[0])) else { return nil }
        let maxBits = ip.isV4 ? 32 : 128
        if parts.count == 2 {
            guard let b = Int(parts[1]), b >= 0, b <= maxBits else { return nil }
            bits = b
        } else { bits = maxBits }
        network = ip
    }

    func contains(_ ip: NCIP) -> Bool {
        switch (network, ip) {
        case (.v4(let n), .v4(let a)):
            if bits == 0 { return true }
            let mask: UInt32 = bits == 32 ? 0xffff_ffff : (0xffff_ffff << (32 - bits))
            return (n & mask) == (a & mask)
        case (.v6(let n), .v6(let a)):
            var remaining = bits
            for i in 0..<16 {
                if remaining <= 0 { return true }
                if remaining >= 8 {
                    if n[i] != a[i] { return false }
                    remaining -= 8
                } else {
                    let mask = UInt8(0xff << (8 - remaining))
                    return (n[i] & mask) == (a[i] & mask)
                }
            }
            return true
        case (.v6(let n), .v4):
            // A v6 CIDR only matches a v4 address when it is the mapped form; callers
            // normally normalize first (see NCIP normalizing in the rule matcher).
            return contains(.v6(NCIP.v4Mapped(ip)))
        case (.v4, .v6(let b)):
            if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff {
                return contains(.v4((UInt32(b[12]) << 24) | (UInt32(b[13]) << 16) | (UInt32(b[14]) << 8) | UInt32(b[15])))
            }
            return false
        }
    }
}

extension NCIP {
    static func v4Mapped(_ ip: NCIP) -> [UInt8] {
        switch ip {
        case .v4(let v):
            return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                    UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        case .v6(let b): return b
        }
    }
}
