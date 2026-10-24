import Foundation

/// ICMP echo handling for the tunnel: lwIP answers echo requests for its
/// own addresses, but fake-IP destinations aren't stack addresses, so the
/// data plane answers those itself (an echo reply built by swapping the
/// request). Proxying ICMP through outbounds isn't a thing the common
/// protocols support; destination-unreachable etc. are not synthesized.
enum NCICMPEcho {
    /// The destination address if the packet is an ICMP(v6) echo request.
    static func echoRequestDestination(_ packet: Data) -> NCIP? {
        guard let first = packet.first else { return nil }
        switch first >> 4 {
        case 4:
            guard packet.count >= 20 else { return nil }
            let ihl = Int(packet[0] & 0x0f) * 4
            guard ihl >= 20, packet.count >= ihl + 8, packet[9] == 1 else { return nil }
            guard packet[ihl] == 8, packet[ihl + 1] == 0 else { return nil } // echo request
            let dst = UInt32(packet[16]) << 24 | UInt32(packet[17]) << 16 | UInt32(packet[18]) << 8 | UInt32(packet[19])
            return .v4(dst)
        case 6:
            guard packet.count >= 48, packet[6] == 58 else { return nil }
            guard packet[40] == 128, packet[41] == 0 else { return nil } // echo request
            return .v6([UInt8](packet[24..<40]))
        default:
            return nil
        }
    }

    /// Build the echo reply for an echo-request packet (nil if not one).
    static func reply(for packet: Data) -> Data? {
        guard let first = packet.first else { return nil }
        switch first >> 4 {
        case 4: return replyV4(packet)
        case 6: return replyV6(packet)
        default: return nil
        }
    }

    private static func replyV4(_ packet: Data) -> Data? {
        guard echoRequestDestination(packet) != nil else { return nil }
        let ihl = Int(packet[0] & 0x0f) * 4
        let total = Int(packet[2]) << 8 | Int(packet[3])
        guard total >= ihl + 8, packet.count >= total else { return nil }
        var out = [UInt8](packet.prefix(total))
        // Swap addresses, fresh TTL, ICMP type -> reply.
        for i in 0..<4 {
            (out[12 + i], out[16 + i]) = (out[16 + i], out[12 + i])
        }
        out[8] = 64 // TTL
        out[ihl] = 0 // echo reply
        // IP header checksum.
        out[10] = 0; out[11] = 0
        let hc = checksum(Data(out[0..<ihl]))
        out[10] = UInt8(hc >> 8); out[11] = UInt8(hc & 0xff)
        // ICMP checksum.
        out[ihl + 2] = 0; out[ihl + 3] = 0
        let ic = checksum(Data(out[ihl...]))
        out[ihl + 2] = UInt8(ic >> 8); out[ihl + 3] = UInt8(ic & 0xff)
        return Data(out)
    }

    private static func replyV6(_ packet: Data) -> Data? {
        guard echoRequestDestination(packet) != nil else { return nil }
        let payloadLen = Int(packet[4]) << 8 | Int(packet[5])
        guard payloadLen >= 8, packet.count >= 40 + payloadLen else { return nil }
        var out = [UInt8](packet.prefix(40 + payloadLen))
        for i in 0..<16 {
            (out[8 + i], out[24 + i]) = (out[24 + i], out[8 + i])
        }
        out[7] = 64 // hop limit
        out[40] = 129 // echo reply
        out[42] = 0; out[43] = 0
        // Checksum over pseudo-header + ICMPv6 message (post-swap).
        var pseudo = Data()
        pseudo.append(contentsOf: out[8..<24]) // source (post-swap)
        pseudo.append(contentsOf: out[24..<40]) // destination
        pseudo.appendBE32(UInt32(payloadLen))
        pseudo.append(contentsOf: [0, 0, 0, 58])
        pseudo.append(contentsOf: out[40...])
        let ic = checksum(pseudo)
        out[42] = UInt8(ic >> 8); out[43] = UInt8(ic & 0xff)
        return Data(out)
    }

    /// Internet checksum (RFC 1071).
    static func checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        let bytes = [UInt8](data)
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return UInt16(~sum & 0xffff)
    }
}
