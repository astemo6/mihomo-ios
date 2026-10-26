import Foundation

// ML-KEM-768 (FIPS 203) in pure Swift for VLESS encryption (feat/nc-proto A6, based on astemo6/Muse NativeCore).
// Straight transcription of the FIPS 203 algorithms (KeyGen / Encaps / Decaps with implicit rejection); the
// arithmetic uses plain Int32 reductions mod q — not constant-time beyond what the tunnel needs (keys are
// ephemeral per connection). Memory: a handful of 256-coefficient polynomials per operation.

/// Keccak-f[1600] sponge (SHA3-256/512, SHAKE128/256).
struct NCKeccak {
    private var s = [UInt64](repeating: 0, count: 25)
    private let rate: Int
    private let suffix: UInt8
    private var buf: [UInt8] = []
    private var squeezing = false
    private var out: [UInt8] = []
    private var outPos = 0

    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rho: [UInt64] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
                                        41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
    private static let pi: [Int] = (0..<25).map { i in (i / 5) + 5 * ((2 * (i % 5) + 3 * (i / 5)) % 5) }

    init(rate: Int, suffix: UInt8) { self.rate = rate; self.suffix = suffix }
    static func sha3_256() -> NCKeccak { NCKeccak(rate: 136, suffix: 0x06) }
    static func sha3_512() -> NCKeccak { NCKeccak(rate: 72, suffix: 0x06) }
    static func shake128() -> NCKeccak { NCKeccak(rate: 168, suffix: 0x1f) }
    static func shake256() -> NCKeccak { NCKeccak(rate: 136, suffix: 0x1f) }

    private mutating func permute() {
        var a = s
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotatedLeft(1)
                for y in 0..<5 { a[x + 5 * y] ^= d }
            }
            for i in 0..<25 { b[Self.pi[i]] = a[i].rotatedLeft(Self.rho[i]) }
            for y in 0..<5 {
                for x in 0..<5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                }
            }
            a[0] ^= Self.rc[round]
        }
        s = a
    }

    private mutating func xorBlock(_ blk: [UInt8]) {
        for lane in 0..<(rate / 8) {
            var v: UInt64 = 0
            for j in 0..<8 { v |= UInt64(blk[lane * 8 + j]) << (8 * UInt64(j)) }
            s[lane] ^= v
        }
        permute()
    }

    mutating func absorb(_ data: [UInt8]) {
        precondition(!squeezing)
        buf.append(contentsOf: data)
        while buf.count >= rate {
            xorBlock(Array(buf[0..<rate]))
            buf.removeFirst(rate)
        }
    }

    private mutating func finish() {
        var blk = buf
        blk.append(suffix)
        while blk.count < rate { blk.append(0) }
        blk[rate - 1] |= 0x80
        xorBlock(blk)
        buf = []
        squeezing = true
        fill()
    }

    private mutating func fill() {
        out = []
        out.reserveCapacity(rate)
        for lane in 0..<(rate / 8) {
            for j in 0..<8 { out.append(UInt8(truncatingIfNeeded: s[lane] >> (8 * UInt64(j)))) }
        }
        outPos = 0
    }

    mutating func squeeze(_ n: Int) -> [UInt8] {
        if !squeezing { finish() }
        var r: [UInt8] = []
        r.reserveCapacity(n)
        while r.count < n {
            if outPos == out.count { permute(); fill() }
            let take = min(n - r.count, out.count - outPos)
            r.append(contentsOf: out[outPos..<(outPos + take)])
            outPos += take
        }
        return r
    }

    static func digest(_ k: NCKeccak, _ data: [UInt8], _ n: Int) -> [UInt8] {
        var h = k
        h.absorb(data)
        return h.squeeze(n)
    }
}

enum NCMLKEM768 {
    static let n = 256, q: Int32 = 3329, k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4
    static let encapsulationKeySize = 1184
    static let ciphertextSize = 1088
    typealias Poly = [Int32]

    // zetas[i] = 17^BitRev7(i) mod q
    static let zetas: [Int32] = (0..<128).map { i in pow17(bitrev7(i)) }
    // gammas[i] = 17^(2·BitRev7(i)+1) mod q
    static let gammas: [Int32] = (0..<128).map { i in pow17(2 * bitrev7(i) + 1) }

    private static func bitrev7(_ x: Int) -> Int {
        var r = 0
        for b in 0..<7 where x & (1 << b) != 0 { r |= 1 << (6 - b) }
        return r
    }
    private static func pow17(_ e: Int) -> Int32 {
        var r: Int64 = 1, base: Int64 = 17, x = e
        while x > 0 { if x & 1 == 1 { r = r * base % 3329 }; base = base * base % 3329; x >>= 1 }
        return Int32(r)
    }
    @inline(__always) static func modq(_ x: Int32) -> Int32 { let r = x % q; return r < 0 ? r + q : r }

    static func ntt(_ f: inout Poly) {
        var i = 1
        var len = 128
        while len >= 2 {
            var start = 0
            while start < 256 {
                let z = zetas[i]; i += 1
                for j in start..<(start + len) {
                    let t = Int32((Int64(z) * Int64(f[j + len])) % 3329)
                    f[j + len] = modq(f[j] - t)
                    f[j] = modq(f[j] + t)
                }
                start += 2 * len
            }
            len >>= 1
        }
    }

    static func invNTT(_ f: inout Poly) {
        var i = 127
        var len = 2
        while len <= 128 {
            var start = 0
            while start < 256 {
                let z = zetas[i]; i -= 1
                for j in start..<(start + len) {
                    let t = f[j]
                    f[j] = modq(t + f[j + len])
                    f[j + len] = Int32((Int64(z) * Int64(modq(f[j + len] - t))) % 3329)
                }
                start += 2 * len
            }
            len <<= 1
        }
        for j in 0..<256 { f[j] = Int32((Int64(f[j]) * 3303) % 3329) }
    }

    static func mulNTT(_ f: Poly, _ g: Poly) -> Poly {
        var h = Poly(repeating: 0, count: 256)
        for i in 0..<128 {
            let a0 = Int64(f[2 * i]), a1 = Int64(f[2 * i + 1]), b0 = Int64(g[2 * i]), b1 = Int64(g[2 * i + 1])
            let gm = Int64(gammas[i])
            h[2 * i] = Int32((a0 * b0 + (a1 * b1 % 3329) * gm) % 3329)
            h[2 * i + 1] = Int32((a0 * b1 + a1 * b0) % 3329)
        }
        return h
    }

    static func add(_ a: Poly, _ b: Poly) -> Poly { (0..<256).map { modq(a[$0] + b[$0]) } }
    static func sub(_ a: Poly, _ b: Poly) -> Poly { (0..<256).map { modq(a[$0] - b[$0]) } }

    static func sampleNTT(_ seed: [UInt8]) -> Poly {
        var x = NCKeccak.shake128()
        x.absorb(seed)
        var a = Poly()
        a.reserveCapacity(256)
        while a.count < 256 {
            let c = x.squeeze(3)
            let d1 = Int32(c[0]) + 256 * (Int32(c[1]) & 15)
            let d2 = (Int32(c[1]) >> 4) + 16 * Int32(c[2])
            if d1 < q { a.append(d1) }
            if d2 < q && a.count < 256 { a.append(d2) }
        }
        return a
    }

    static func cbd(_ b: [UInt8], eta: Int) -> Poly {
        func bit(_ i: Int) -> Int32 { Int32((b[i >> 3] >> (i & 7)) & 1) }
        return (0..<256).map { i in
            var x: Int32 = 0, y: Int32 = 0
            for j in 0..<eta { x += bit(2 * i * eta + j); y += bit(2 * i * eta + eta + j) }
            return modq(x - y)
        }
    }

    static func prf(_ s: [UInt8], _ b: UInt8, eta: Int) -> [UInt8] {
        NCKeccak.digest(.shake256(), s + [b], 64 * eta)
    }

    static func byteEncode(_ f: Poly, d: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32 * d)
        var bitPos = 0
        for c in f {
            var v = Int(c)
            for _ in 0..<d {
                if v & 1 == 1 { out[bitPos >> 3] |= UInt8(1 << (bitPos & 7)) }
                v >>= 1
                bitPos += 1
            }
        }
        return out
    }

    static func byteDecode(_ b: [UInt8], d: Int) -> Poly {
        var f = Poly(repeating: 0, count: 256)
        var bitPos = 0
        for i in 0..<256 {
            var v: Int32 = 0
            for j in 0..<d {
                if (b[bitPos >> 3] >> (bitPos & 7)) & 1 == 1 { v |= 1 << j }
                bitPos += 1
            }
            f[i] = d == 12 ? v % q : v
        }
        return f
    }

    static func compress(_ x: Int32, d: Int) -> Int32 {
        Int32(((Int64(x) << d) + 1664) / 3329) & ((1 << d) - 1)
    }
    static func decompress(_ y: Int32, d: Int) -> Int32 {
        Int32((Int64(y) * 3329 + (1 << (d - 1))) >> d)
    }

    // MARK: K-PKE

    static func matrix(_ rho: [UInt8]) -> [[Poly]] {
        (0..<k).map { i in (0..<k).map { j in sampleNTT(rho + [UInt8(j), UInt8(i)]) } }
    }

    static func pkeKeyGen(_ d: [UInt8]) -> (ek: [UInt8], dk: [UInt8]) {
        let g = NCKeccak.digest(.sha3_512(), d + [UInt8(k)], 64)
        let rho = Array(g[0..<32]), sigma = Array(g[32..<64])
        let a = matrix(rho)
        var nCtr: UInt8 = 0
        var s: [Poly] = [], e: [Poly] = []
        for _ in 0..<k { s.append(cbd(prf(sigma, nCtr, eta: eta1), eta: eta1)); nCtr += 1 }
        for _ in 0..<k { e.append(cbd(prf(sigma, nCtr, eta: eta1), eta: eta1)); nCtr += 1 }
        for i in 0..<k { ntt(&s[i]); ntt(&e[i]) }
        var ek: [UInt8] = []
        var dk: [UInt8] = []
        for i in 0..<k {
            var t = e[i]
            for j in 0..<k { t = add(t, mulNTT(a[i][j], s[j])) }
            ek += byteEncode(t, d: 12)
        }
        ek += rho
        for i in 0..<k { dk += byteEncode(s[i], d: 12) }
        return (ek, dk)
    }

    static func pkeEncrypt(_ ek: [UInt8], _ m: [UInt8], _ r: [UInt8]) -> [UInt8] {
        let t: [Poly] = (0..<k).map { byteDecode(Array(ek[(384 * $0)..<(384 * $0 + 384)]), d: 12) }
        let rho = Array(ek[1152..<1184])
        let a = matrix(rho)
        var nCtr: UInt8 = 0
        var y: [Poly] = [], e1: [Poly] = []
        for _ in 0..<k { y.append(cbd(prf(r, nCtr, eta: eta1), eta: eta1)); nCtr += 1 }
        for _ in 0..<k { e1.append(cbd(prf(r, nCtr, eta: eta2), eta: eta2)); nCtr += 1 }
        let e2 = cbd(prf(r, nCtr, eta: eta2), eta: eta2)
        for i in 0..<k { ntt(&y[i]) }
        var c: [UInt8] = []
        for i in 0..<k {
            var u = Poly(repeating: 0, count: 256)
            for j in 0..<k { u = add(u, mulNTT(a[j][i], y[j])) } // Âᵀ
            invNTT(&u)
            u = add(u, e1[i])
            c += byteEncode(u.map { compress($0, d: du) }, d: du)
        }
        var v = Poly(repeating: 0, count: 256)
        for i in 0..<k { v = add(v, mulNTT(t[i], y[i])) }
        invNTT(&v)
        let mu = byteDecode(m, d: 1).map { decompress($0, d: 1) }
        v = add(add(v, e2), mu)
        c += byteEncode(v.map { compress($0, d: dv) }, d: dv)
        return c
    }

    static func pkeDecrypt(_ dk: [UInt8], _ c: [UInt8]) -> [UInt8] {
        var w = byteDecode(Array(c[960..<1088]), d: dv).map { decompress($0, d: dv) }
        var acc = Poly(repeating: 0, count: 256)
        for i in 0..<k {
            var u = byteDecode(Array(c[(320 * i)..<(320 * i + 320)]), d: du).map { decompress($0, d: du) }
            ntt(&u)
            let s = byteDecode(Array(dk[(384 * i)..<(384 * i + 384)]), d: 12)
            acc = add(acc, mulNTT(s, u))
        }
        invNTT(&acc)
        w = sub(w, acc)
        return byteEncode(w.map { compress($0, d: 1) }, d: 1)
    }

    // MARK: ML-KEM

    struct DecapsulationKey {
        let dkPKE: [UInt8]
        let ek: [UInt8]
        let h: [UInt8]
        let z: [UInt8]
    }

    static func generateKey() -> DecapsulationKey {
        let d = [UInt8](NCConnector.randomData(32)), z = [UInt8](NCConnector.randomData(32))
        let (ek, dk) = pkeKeyGen(d)
        return DecapsulationKey(dkPKE: dk, ek: ek, h: NCKeccak.digest(.sha3_256(), ek, 32), z: z)
    }

    /// (shared key, ciphertext) — the order the old core's mlkem Encapsulate returns.
    static func encapsulate(ek: [UInt8]) -> (key: [UInt8], ciphertext: [UInt8])? {
        guard ek.count == encapsulationKeySize else { return nil }
        // FIPS 203 modulus check: every 12-bit coefficient must already be < q.
        for i in 0..<(k * 128) {
            let b0 = Int32(ek[3 * i]), b1 = Int32(ek[3 * i + 1]), b2 = Int32(ek[3 * i + 2])
            if b0 | ((b1 & 15) << 8) >= q || ((b1 >> 4) | (b2 << 4)) >= q { return nil }
        }
        let m = [UInt8](NCConnector.randomData(32))
        let g = NCKeccak.digest(.sha3_512(), m + NCKeccak.digest(.sha3_256(), ek, 32), 64)
        let c = pkeEncrypt(ek, m, Array(g[32..<64]))
        return (Array(g[0..<32]), c)
    }

    static func decapsulate(_ dk: DecapsulationKey, ciphertext c: [UInt8]) -> [UInt8]? {
        guard c.count == ciphertextSize else { return nil }
        let m2 = pkeDecrypt(dk.dkPKE, c)
        let g = NCKeccak.digest(.sha3_512(), m2 + dk.h, 64)
        let kBar = NCKeccak.digest(.shake256(), dk.z + c, 32)
        let c2 = pkeEncrypt(dk.ek, m2, Array(g[32..<64]))
        var diff: UInt8 = 0
        for i in 0..<c.count { diff |= c[i] ^ c2[i] }
        return diff == 0 ? Array(g[0..<32]) : kBar
    }
}
