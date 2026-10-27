import Foundation
import Security

// MARK: - STUN binding codec (RFC 5389, subset)
//
// Just enough STUN to discover our reflexive (public) endpoint from the
// DERP map's STUN servers: build a Binding Request, parse a Binding
// Success Response's XOR-MAPPED-ADDRESS (falling back to MAPPED-ADDRESS).

enum NCTailscaleSTUN {
    static let magicCookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
    static let defaultPort = 3478

    static func isSTUNResponse(_ data: [UInt8]) -> Bool {
        data.count >= 20 && data[0] == 0x01 && data[1] == 0x01
            && Array(data[4..<8]) == magicCookie
    }

    /// Builds a Binding Request; returns (packet, transactionID).
    static func makeBindingRequest() -> ([UInt8], [UInt8]) {
        var txid = [UInt8](repeating: 0, count: 12)
        NCTailscaleDiscoRandom.fill(&txid)
        var pkt: [UInt8] = [0x00, 0x01, 0x00, 0x00]
        pkt += magicCookie
        pkt += txid
        return (pkt, txid)
    }

    /// Extracts the reflexive endpoint "ip:port" from a success response
    /// whose transaction ID matches `txid`.
    static func parseBindingResponse(_ data: [UInt8], txid: [UInt8]) -> String? {
        guard isSTUNResponse(data), data.count >= 20 else { return nil }
        guard Array(data[8..<20]) == txid else { return nil }
        var off = 20
        let end = data.count
        while off + 4 <= end {
            let type = Int(data[off]) << 8 | Int(data[off + 1])
            let len = Int(data[off + 2]) << 8 | Int(data[off + 3])
            let valueStart = off + 4
            guard valueStart + len <= end else { return nil }
            let value = Array(data[valueStart..<(valueStart + len)])
            if type == 0x0020, let ep = decodeAddress(value, xored: true, txid: txid) {
                return ep
            }
            if type == 0x0001, let ep = decodeAddress(value, xored: false, txid: txid) {
                return ep
            }
            off = valueStart + ((len + 3) & ~3)
        }
        return nil
    }

    private static func decodeAddress(_ v: [UInt8], xored: Bool, txid: [UInt8]) -> String? {
        guard v.count >= 4 else { return nil }
        let family = v[1]
        var port = Int(v[2]) << 8 | Int(v[3])
        if xored { port ^= 0x2112 }
        switch family {
        case 0x01:
            guard v.count >= 8 else { return nil }
            var ip = Array(v[4..<8])
            if xored {
                for i in 0..<4 { ip[i] ^= magicCookie[i] }
            }
            guard let addr = NCIP(bytes: ip) else { return nil }
            return "\(addr.string):\(port)"
        case 0x02:
            guard v.count >= 20 else { return nil }
            var ip = Array(v[4..<20])
            if xored {
                let key = magicCookie + txid
                for i in 0..<16 { ip[i] ^= key[i] }
            }
            guard let addr = NCIP(bytes: ip) else { return nil }
            return "[\(addr.string)]:\(port)"
        default:
            return nil
        }
    }
}

/// Shared randomness helper (SecRandomCopyBytes with a stdlib fallback).
enum NCTailscaleDiscoRandom {
    static func fill(_ bytes: inout [UInt8]) {
        let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if rc != errSecSuccess {
            var rng = SystemRandomNumberGenerator()
            for i in bytes.indices { bytes[i] = UInt8.random(in: .min ... .max, using: &rng) }
        }
    }

    static func data(count: Int) -> Data {
        var b = [UInt8](repeating: 0, count: count)
        fill(&b)
        return Data(b)
    }
}
