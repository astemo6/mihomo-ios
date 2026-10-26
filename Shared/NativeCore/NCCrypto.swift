import Foundation

/* Small crypto primitives CryptoKit does not ship: MD5 (VMess cmdKey / legacy
   hashes), a raw AES block cipher (VMess authID uses AES-128-ECB; body ciphers
   use CryptoKit's GCM instead), CRC-32 (authID checksum) and FNV-1a (VMess
   header checksum). Tables were generated programmatically and are covered by
   FIPS/RFC test vectors in the unit tests. */

enum NCMD5 {
    private static let s: [UInt32] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]
    private static let k: [UInt32] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    static func hash(_ data: Data) -> Data {
        var msg = [UInt8](data)
        let bitLen = UInt64(msg.count) * 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in 0..<8 { msg.append(UInt8((bitLen >> (8 * UInt64(i))) & 0xff)) }

        var a0: UInt32 = 0x67452301
        var b0: UInt32 = 0xefcdab89
        var c0: UInt32 = 0x98badcfe
        var d0: UInt32 = 0x10325476

        for chunkStart in stride(from: 0, to: msg.count, by: 64) {
            var m = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                let o = chunkStart + i * 4
                m[i] = UInt32(msg[o]) | UInt32(msg[o + 1]) << 8 | UInt32(msg[o + 2]) << 16 | UInt32(msg[o + 3]) << 24
            }
            var (a, b, c, d) = (a0, b0, c0, d0)
            for i in 0..<64 {
                let f: UInt32
                let g: Int
                switch i / 16 {
                case 0:
                    f = (b & c) | (~b & d)
                    g = i
                case 1:
                    f = (d & b) | (~d & c)
                    g = (5 * i + 1) % 16
                case 2:
                    f = b ^ c ^ d
                    g = (3 * i + 5) % 16
                default:
                    f = c ^ (b | ~d)
                    g = (7 * i) % 16
                }
                let tmp = f &+ a &+ k[i] &+ m[g]
                a = d
                d = c
                c = b
                b = b &+ (tmp <<< s[i])
            }
            a0 &+= a
            b0 &+= b
            c0 &+= c
            d0 &+= d
        }
        var out = Data()
        for v in [a0, b0, c0, d0] {
            out.append(UInt8(v & 0xff))
            out.append(UInt8((v >> 8) & 0xff))
            out.append(UInt8((v >> 16) & 0xff))
            out.append(UInt8((v >> 24) & 0xff))
        }
        return out
    }
}

infix operator <<< : BitwiseShiftPrecedence
func <<< (lhs: UInt32, rhs: UInt32) -> UInt32 { (lhs << rhs) | (lhs >> (32 - rhs)) }

enum NCCRC32 {
    private static let table: [UInt32] = (0...255).map { n in
        var c = UInt32(n)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xffffffff
        for b in data {
            crc = table[Int((crc ^ UInt32(b)) & 0xff)] ^ (crc >> 8)
        }
        return crc ^ 0xffffffff
    }
}

enum NCFNV1a {
    static func hash32(_ data: Data) -> UInt32 {
        var h: UInt32 = 2166136261
        for b in data {
            h ^= UInt32(b)
            h &*= 16777619
        }
        return h
    }
}

/// SHA-1 (FIPS 180-1). Only used for the UUIDv5 fallback when a VMess/VLESS
/// config carries a non-UUID user string (Clash.Meta's UUIDMap behavior).
enum NCSHA1 {
    static func hash(_ data: Data) -> Data {
        var msg = [UInt8](data)
        let bitLen = UInt64(msg.count) * 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in stride(from: 56, through: 0, by: -8) { msg.append(UInt8((bitLen >> UInt64(i)) & 0xff)) }
        var h: [UInt32] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
        for chunkStart in stride(from: 0, to: msg.count, by: 64) {
            var w = [UInt32](repeating: 0, count: 80)
            for i in 0..<16 {
                let o = chunkStart + i * 4
                w[i] = UInt32(msg[o]) << 24 | UInt32(msg[o + 1]) << 16 | UInt32(msg[o + 2]) << 8 | UInt32(msg[o + 3])
            }
            for i in 16..<80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) <<< 1
            }
            var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
            for i in 0..<80 {
                let f: UInt32
                let k: UInt32
                switch i / 20 {
                case 0: f = (b & c) | (~b & d); k = 0x5a827999
                case 1: f = b ^ c ^ d; k = 0x6ed9eba1
                case 2: f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc
                default: f = b ^ c ^ d; k = 0xca62c1d6
                }
                let tmp = (a <<< 5) &+ f &+ e &+ k &+ w[i]
                e = d; d = c; c = b <<< 30; b = a; a = tmp
            }
            h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d; h[4] &+= e
        }
        var out = Data()
        for v in h { out.appendBE32(v) }
        return out
    }

    /// RFC 4122 UUIDv5 with the nil namespace (Clash.Meta's UUIDMap fallback for
    /// non-UUID strings).
    static func uuidV5NilNamespace(_ string: String) -> Data {
        var digest = [UInt8](hash(NCVMess.cat(Data(repeating: 0, count: 16), Data(string.utf8))).prefix(16))
        digest[6] = (digest[6] & 0x0f) | 0x50
        digest[8] = (digest[8] & 0x3f) | 0x80
        return Data(digest)
    }
}
