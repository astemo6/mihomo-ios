import CryptoKit
import Foundation

/// QUIC Initial-packet SNI sniffing (RFC 9000/9001): derive the client
/// initial keys from the destination connection ID, remove header
/// protection, AES-GCM-open the payload, reassemble CRYPTO frames and
/// read the TLS ClientHello's SNI. Pure function of the first datagram;
/// any failure (not QUIC, not Initial, wrong version, coalesced weirdness)
/// returns nil and the flow falls back to IP rules.
enum NCQUICSniffer {
    private static let saltV1: [UInt8] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
                                          0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
                                          0xcc, 0xbb, 0x7f, 0x0a]
    private static let saltV2: [UInt8] = [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
                                          0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
                                          0xf9, 0xbd, 0x57, 0x95]

    static func sni(from packet: Data) -> String? {
        guard let payload = decryptInitial(packet) else { return nil }
        return sni(fromPayload: payload)
    }

    /// Parse + header-protection removal + AEAD open of a QUIC Initial;
    /// internal so tests can bisect key derivation vs frame parsing.
    static func decryptInitial(_ packet: Data) -> Data? {
        let bytes = [UInt8](packet)
        guard bytes.count >= 20, bytes[0] & 0x80 != 0 else { return nil }
        let version = UInt32(bytes[1]) << 24 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 8 | UInt32(bytes[4])
        let salt: [UInt8]
        switch version {
        case 0x0000_0001: salt = saltV1
        case 0x6b33_43cf: salt = saltV2
        default: return nil
        }
        var pos = 5
        guard pos < bytes.count else { return nil }
        let dcidLen = Int(bytes[pos]); pos += 1
        guard dcidLen <= 20, pos + dcidLen <= bytes.count else { return nil }
        let dcid = Data(bytes[pos..<(pos + dcidLen)]); pos += dcidLen
        guard pos < bytes.count else { return nil }
        let scidLen = Int(bytes[pos]); pos += 1 + scidLen
        // Token: varint length + bytes.
        guard let (tokenLen, n1) = varint(bytes, pos) else { return nil }
        pos += n1 + Int(tokenLen)
        guard let (length, n2) = varint(bytes, pos) else { return nil }
        pos += n2
        let pnOffset = pos
        let packetEnd = pnOffset + Int(length)
        guard length >= 20, packetEnd <= bytes.count, pnOffset + 20 <= bytes.count else { return nil }

        // Initial keys (RFC 9001 §5.2).
        let initialSecret = NCTLS13.hkdfExtract(.sha256, salt: Data(salt), ikm: dcid)
        let clientSecret = NCTLS13.expandLabel(.sha256, secret: initialSecret, label: "client in", context: Data(), length: 32)
        let key = NCTLS13.expandLabel(.sha256, secret: clientSecret, label: "quic key", context: Data(), length: 16)
        let iv = NCTLS13.expandLabel(.sha256, secret: clientSecret, label: "quic iv", context: Data(), length: 12)
        let hp = NCTLS13.expandLabel(.sha256, secret: clientSecret, label: "quic hp", context: Data(), length: 16)

        // Header protection removal (RFC 9001 §5.4).
        let sample = Data(bytes[(pnOffset + 4)..<(pnOffset + 20)])
        guard let hpAES = NCAES(key: hp) else { return nil }
        let mask = [UInt8](hpAES.encryptBlock(sample))
        let firstUnprotected = bytes[0] ^ (mask[0] & 0x0f)
        let pnLength = Int(firstUnprotected & 0x03) + 1
        guard pnOffset + pnLength <= packetEnd else { return nil }
        var pn: UInt64 = 0
        var header = [UInt8](bytes[0..<pnOffset])
        header[0] = firstUnprotected
        for i in 0..<pnLength {
            let b = bytes[pnOffset + i] ^ mask[1 + i]
            header.append(b)
            pn = (pn << 8) | UInt64(b)
        }
        var nonce = [UInt8](iv)
        for i in 0..<8 {
            nonce[11 - i] ^= UInt8((pn >> UInt64(8 * i)) & 0xff)
        }
        let ciphertext = Data(bytes[(pnOffset + pnLength)..<packetEnd])
        guard ciphertext.count > 16,
              let sealed = try? AES.GCM.SealedBox(combined: Data(nonce) + ciphertext),
              let payload = try? AES.GCM.open(sealed, using: SymmetricKey(data: key)) else { return nil }
        return payload
    }

    /// Frame walk over a decrypted Initial payload + ClientHello SNI.
    static func sni(fromPayload payload: Data) -> String? {
        // Frame walk: collect CRYPTO segments.
        var segments: [(offset: Int, data: Data)] = []
        var p = 0
        let pl = [UInt8](payload)
        while p < pl.count {
            guard let (frameType, fn) = varint(pl, p) else { break }
            p += fn
            switch frameType {
            case 0x00: // PADDING
                continue
            case 0x01: // PING
                continue
            case 0x06: // CRYPTO
                guard let (off, on) = varint(pl, p) else { return nil }
                p += on
                guard let (len, ln) = varint(pl, p) else { return nil }
                p += ln
                guard p + Int(len) <= pl.count else { return nil }
                segments.append((Int(off), Data(pl[p..<(p + Int(len))])))
                p += Int(len)
            default:
                // ACK and anything else: stop; CRYPTO virtually always
                // leads the first Initial's payload.
                p = pl.count
            }
        }
        guard let firstSeg = segments.first(where: { $0.offset == 0 }) else { return nil }
        var stream = Data()
        var expected = 0
        for seg in segments.sorted(by: { $0.offset < $1.offset }) where seg.offset == expected {
            stream.append(seg.data)
            expected += seg.data.count
        }
        _ = firstSeg
        guard !stream.isEmpty else { return nil }
        if case .tls(let sni, _) = NCSniffer.parseHandshake(stream) {
            return sni
        }
        return nil
    }

    /// QUIC variable-length integer (RFC 9000 §16). Returns (value, bytes used).
    private static func varint(_ bytes: [UInt8], _ pos: Int) -> (UInt64, Int)? {
        guard pos < bytes.count else { return nil }
        let first = bytes[pos]
        let prefix = first >> 6
        switch prefix {
        case 0:
            return (UInt64(first & 0x3f), 1)
        case 1:
            guard pos + 2 <= bytes.count else { return nil }
            return (UInt64(first & 0x3f) << 8 | UInt64(bytes[pos + 1]), 2)
        case 2:
            guard pos + 4 <= bytes.count else { return nil }
            var v: UInt64 = UInt64(first & 0x3f)
            for i in 1..<4 { v = (v << 8) | UInt64(bytes[pos + i]) }
            return (v, 4)
        default:
            guard pos + 8 <= bytes.count else { return nil }
            var v: UInt64 = UInt64(first & 0x3f)
            for i in 1..<8 { v = (v << 8) | UInt64(bytes[pos + i]) }
            return (v, 8)
        }
    }
}
