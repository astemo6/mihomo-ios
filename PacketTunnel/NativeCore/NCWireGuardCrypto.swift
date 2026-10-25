import CryptoKit
import Foundation

// feat/nc-wg (based on astemo6/Muse NativeCore): WireGuard primitives in pure Swift + CryptoKit.
// BLAKE2s (RFC 7693) with keyed MAC and HMAC-BLAKE2s, the Noise KDF, ChaCha20-Poly1305 with WireGuard's
// 64-bit counter nonce, XChaCha20-Poly1305 open (cookie replies), X25519 and TAI64N.

/// BLAKE2s, RFC 7693. `outLen` 1...32, optional key up to 32 bytes.
struct NCBlake2s {
    private static let iv: [UInt32] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt32]
    private var t: UInt64 = 0
    private var buf: [UInt8] = []
    private let outLen: Int

    init(outLen: Int = 32, key: [UInt8] = []) {
        precondition(outLen >= 1 && outLen <= 32 && key.count <= 32)
        self.outLen = outLen
        h = NCBlake2s.iv
        h[0] ^= 0x0101_0000 ^ (UInt32(key.count) << 8) ^ UInt32(outLen)
        buf.reserveCapacity(64)
        if !key.isEmpty {
            buf = key + [UInt8](repeating: 0, count: 64 - key.count)
        }
    }

    mutating func update(_ data: [UInt8]) {
        var i = 0
        while i < data.count {
            if buf.count == 64 {
                t &+= 64
                compress(last: false)
                buf.removeAll(keepingCapacity: true)
            }
            let n = min(64 - buf.count, data.count - i)
            buf.append(contentsOf: data[i..<(i + n)])
            i += n
        }
    }

    mutating func finalize() -> [UInt8] {
        t &+= UInt64(buf.count)
        if buf.count < 64 { buf.append(contentsOf: [UInt8](repeating: 0, count: 64 - buf.count)) }
        compress(last: true)
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for w in h {
            out.append(UInt8(w & 0xff)); out.append(UInt8((w >> 8) & 0xff))
            out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
        }
        return Array(out.prefix(outLen))
    }

    private mutating func compress(last: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(buf[i * 4]) | UInt32(buf[i * 4 + 1]) << 8 | UInt32(buf[i * 4 + 2]) << 16
                | UInt32(buf[i * 4 + 3]) << 24
        }
        var v = h + NCBlake2s.iv
        v[12] ^= UInt32(truncatingIfNeeded: t)
        v[13] ^= UInt32(truncatingIfNeeded: t >> 32)
        if last { v[14] = ~v[14] }
        @inline(__always) func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x; v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]; v[b] = rotr(v[b] ^ v[c], 12)
            v[a] = v[a] &+ v[b] &+ y; v[d] = rotr(v[d] ^ v[a], 8)
            v[c] = v[c] &+ v[d]; v[b] = rotr(v[b] ^ v[c], 7)
        }
        for r in 0..<10 {
            let s = NCBlake2s.sigma[r]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    static func hash(_ parts: [UInt8]...) -> [UInt8] {
        var b = NCBlake2s()
        for p in parts { b.update(p) }
        return b.finalize()
    }

    /// WireGuard MAC(key, input): keyed BLAKE2s with a 16-byte output.
    static func mac(key: [UInt8], _ input: [UInt8]) -> [UInt8] {
        var b = NCBlake2s(outLen: 16, key: key)
        b.update(input)
        return b.finalize()
    }

    /// HMAC-BLAKE2s-256 (RFC 2104, block 64).
    static func hmac(key: [UInt8], _ input: [UInt8]) -> [UInt8] {
        var k = key.count > 64 ? hash(key) : key
        k += [UInt8](repeating: 0, count: 64 - k.count)
        var inner = NCBlake2s()
        inner.update(k.map { $0 ^ 0x36 })
        inner.update(input)
        let ih = inner.finalize()
        var outer = NCBlake2s()
        outer.update(k.map { $0 ^ 0x5c })
        outer.update(ih)
        return outer.finalize()
    }
}

enum NCWGCrypto {
    static let construction = Array("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8)
    static let identifier = Array("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8)
    static let labelMAC1 = Array("mac1----".utf8)
    static let labelCookie = Array("cookie--".utf8)

    /// Noise KDF_n over HMAC-BLAKE2s: returns n 32-byte keys.
    static func kdf(_ n: Int, key: [UInt8], input: [UInt8]) -> [[UInt8]] {
        let t0 = NCBlake2s.hmac(key: key, input)
        var out: [[UInt8]] = []
        var prev: [UInt8] = []
        for i in 1...n {
            prev = NCBlake2s.hmac(key: t0, prev + [UInt8(i)])
            out.append(prev)
        }
        return out
    }

    static func nonce(_ counter: UInt64) -> ChaChaPoly.Nonce {
        var n = [UInt8](repeating: 0, count: 12)
        for i in 0..<8 { n[4 + i] = UInt8((counter >> (8 * UInt64(i))) & 0xff) }
        return try! ChaChaPoly.Nonce(data: n)
    }

    static func seal(key: SymmetricKey, counter: UInt64, _ plain: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard let box = try? ChaChaPoly.seal(plain, using: key, nonce: nonce(counter), authenticating: aad) else {
            return nil
        }
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    static func open(key: SymmetricKey, counter: UInt64, _ sealed: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard sealed.count >= 16,
              let box = try? ChaChaPoly.SealedBox(nonce: nonce(counter), ciphertext: sealed.prefix(sealed.count - 16),
                                                  tag: sealed.suffix(16)),
              let plain = try? ChaChaPoly.open(box, using: key, authenticating: aad) else { return nil }
        return [UInt8](plain)
    }

    /// XChaCha20-Poly1305 open with additional data (cookie reply: aad = the mac1 we sent).
    static func xopen(key: [UInt8], nonce24: [UInt8], _ sealed: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard nonce24.count == 24, sealed.count >= 16 else { return nil }
        let sub = NCChaCha.hchacha20(key: Data(key), nonce: Data(nonce24.prefix(16)))
        var n12 = [UInt8](repeating: 0, count: 4)
        n12 += nonce24.suffix(8)
        guard let n = try? ChaChaPoly.Nonce(data: n12),
              let box = try? ChaChaPoly.SealedBox(nonce: n, ciphertext: sealed.prefix(sealed.count - 16),
                                                  tag: sealed.suffix(16)),
              let plain = try? ChaChaPoly.open(box, using: SymmetricKey(data: sub), authenticating: aad) else {
            return nil
        }
        return [UInt8](plain)
    }

    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: [UInt8]) -> [UInt8]? {
        guard let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub),
              let s = try? priv.sharedSecretFromKeyAgreement(with: p) else { return nil }
        let out = s.withUnsafeBytes { [UInt8]($0) }
        // An all-zero result means a low-order point: refuse like wireguard-go.
        return out.allSatisfy({ $0 == 0 }) ? nil : out
    }

    /// TAI64N (12 bytes, big-endian), nanoseconds whitened to 2^24 ns like wireguard-go.
    static func tai64n(_ date: Date = Date()) -> [UInt8] {
        let t = date.timeIntervalSince1970
        let secs = UInt64(t) &+ 0x4000_0000_0000_000A
        var nanos = UInt32((t - floor(t)) * 1_000_000_000)
        nanos &= ~UInt32(0xFF_FFFF)
        var out = [UInt8](repeating: 0, count: 12)
        for i in 0..<8 { out[i] = UInt8((secs >> (56 - 8 * UInt64(i))) & 0xff) }
        for i in 0..<4 { out[8 + i] = UInt8((nanos >> (24 - 8 * UInt32(i))) & 0xff) }
        return out
    }

    /// A key from config: base64 (WireGuard's form) or 64 hex digits.
    static func key(_ s: String?) -> [UInt8]? {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        if s.count == 64, s.allSatisfy({ $0.isHexDigit }) {
            var out: [UInt8] = []
            var i = s.startIndex
            while i < s.endIndex {
                let j = s.index(i, offsetBy: 2)
                guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
                out.append(b)
                i = j
            }
            return out
        }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        guard let d = Data(base64Encoded: b64), d.count == 32 else { return nil }
        return [UInt8](d)
    }
}

/// 2048-bit sliding replay window (RFC 6479 style), as wireguard-go's.
struct NCWGReplayWindow {
    private static let bits = 2048
    private var bitmap = [UInt64](repeating: 0, count: 2048 / 64)
    private var last: UInt64 = 0
    private var any = false

    /// True (and records it) when `counter` is new and inside the window.
    mutating func accept(_ counter: UInt64) -> Bool {
        let words = UInt64(bitmap.count)
        if !any || counter > last {
            // Clear the words skipped over.
            let fromBlock = any ? last / 64 : 0
            let toBlock = counter / 64
            if !any || toBlock - fromBlock >= words {
                for i in 0..<bitmap.count { bitmap[i] = 0 }
            } else {
                var b = fromBlock + 1
                while b <= toBlock { bitmap[Int(b % words)] = 0; b += 1 }
            }
            last = counter
            any = true
        } else if last - counter >= UInt64(NCWGReplayWindow.bits) - 64 {
            return false
        }
        let idx = Int((counter / 64) % words)
        let bit = UInt64(1) << (counter % 64)
        if bitmap[idx] & bit != 0 { return false }
        bitmap[idx] |= bit
        return true
    }
}
