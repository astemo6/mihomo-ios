import Foundation

/// BLAKE2b (RFC 7693) one-shot hashing — the missing primitive under
/// Argon2. Supports variable output length and an optional key.
enum NCBlake2b {
    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
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
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    /// Unkeyed only (all Argon2 needs).
    static func hash(_ data: Data, outputLength: Int) -> Data {
        precondition(outputLength >= 1 && outputLength <= 64)
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(outputLength)
        let total = data.count
        var offset = 0
        var counter: UInt64 = 0
        // All blocks but the last are full 128-byte blocks; an empty input
        // still compresses one zero-padded block.
        while true {
            let remaining = total - offset
            let take = min(remaining, 128)
            var block = [UInt8](repeating: 0, count: 128)
            if take > 0 {
                block.replaceSubrange(0..<take, with: data[offset..<(offset + take)])
            }
            let isLast = remaining <= 128
            counter = isLast ? UInt64(total) : counter + 128
            compress(&h, block: block, count: counter, last: isLast)
            if isLast { break }
            offset += 128
        }
        var out = Data()
        for w in h {
            for i in 0..<8 { out.append(UInt8((w >> UInt64(8 * i)) & 0xff)) }
        }
        return Data(out.prefix(outputLength))
    }

    private static func compress(_ h: inout [UInt64], block: [UInt8], count: UInt64, last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            var w: UInt64 = 0
            for j in 0..<8 { w |= UInt64(block[i * 8 + j]) << UInt64(8 * j) }
            m[i] = w
        }
        var v = h + iv
        // RFC 7693 §3.2: the offset counter goes into v[12] (low word; v[13] high word is 0 for < 2^64 bytes)
        // and the final-block flag inverts v[14].
        v[12] ^= count
        if last { v[14] = ~v[14] }
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = (v[d] ^ v[a]).rotated(right: 32)
            v[c] = v[c] &+ v[d]
            v[b] = (v[b] ^ v[c]).rotated(right: 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = (v[d] ^ v[a]).rotated(right: 16)
            v[c] = v[c] &+ v[d]
            v[b] = (v[b] ^ v[c]).rotated(right: 63)
        }
        for r in 0..<12 {
            let s = sigma[r]
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
}

/// Argon2id (RFC 9106 / x/crypto/argon2 semantics): the KDF Snell uses.
/// Single implementation, lanes supported; verified against Go vectors.
enum NCArgon2 {
    /// H' — BLAKE2b long-output hash used for block seeding/extraction.
    static func blake2bLong(outputLength: Int, input: Data) -> Data {
        var le = Data(count: 4)
        for i in 0..<4 { le[i] = UInt8((outputLength >> (8 * i)) & 0xff) }
        var seeded = le
        seeded.append(input)
        if outputLength <= 64 {
            return NCBlake2b.hash(seeded, outputLength: outputLength)
        }
        var v = NCBlake2b.hash(seeded, outputLength: 64)
        var out = Data(v.prefix(32))
        var remaining = outputLength - 32
        while remaining > 64 {
            v = NCBlake2b.hash(v, outputLength: 64)
            out.append(v.prefix(32))
            remaining -= 32
        }
        out.append(NCBlake2b.hash(v, outputLength: remaining))
        return out
    }

    static func idKey(password: Data, salt: Data, iterations: Int, memoryKB: Int,
                      lanes: Int, keyLength: Int) -> Data {
        let syncPoints = 4
        // H0
        var params = Data()
        func le32(_ v: UInt32) {
            for i in 0..<4 { params.append(UInt8((v >> UInt32(8 * i)) & 0xff)) }
        }
        le32(UInt32(lanes)); le32(UInt32(keyLength)); le32(UInt32(memoryKB))
        le32(UInt32(iterations)); le32(0x13); le32(2) // version, type=id
        le32(UInt32(password.count)); params.append(password)
        le32(UInt32(salt.count)); params.append(salt)
        le32(0); le32(0) // secret, AD
        var h0 = NCBlake2b.hash(params, outputLength: 64)
        h0.append(Data(count: 8)) // block index + lane patched per block

        var memory = memoryKB / (syncPoints * lanes) * (syncPoints * lanes)
        if memory < 2 * syncPoints * lanes { memory = 2 * syncPoints * lanes }
        let laneLength = memory / lanes
        let segmentLength = laneLength / syncPoints

        // Initial blocks.
        var blocks = [[UInt64]](repeating: [UInt64](repeating: 0, count: 128), count: memory)
        func words(_ d: Data) -> [UInt64] {
            (0..<128).map { i in
                var w: UInt64 = 0
                for j in 0..<8 { w |= UInt64(d[i * 8 + j]) << UInt64(8 * j) }
                return w
            }
        }
        for lane in 0..<lanes {
            let base = lane * laneLength
            var seed = h0
            for i in 0..<4 { seed[64 + i] = UInt8((0 >> (8 * i)) & 0xff) } // block idx 0
            for i in 0..<4 { seed[68 + i] = UInt8((lane >> (8 * i)) & 0xff) }
            blocks[base] = words(blake2bLong(outputLength: 1024, input: seed))
            for i in 0..<4 { seed[64 + i] = UInt8((1 >> (8 * i)) & 0xff) }
            blocks[base + 1] = words(blake2bLong(outputLength: 1024, input: seed))
        }

        // Fill.
        for pass in 0..<iterations {
            for slice in 0..<syncPoints {
                for lane in 0..<lanes {
                    fillSegment(blocks: &blocks, pass: pass, slice: slice, lane: lane,
                                segmentLength: segmentLength, laneLength: laneLength,
                                memory: memory, iterations: iterations)
                }
            }
        }

        // Extract: XOR of lane-final blocks (lanes == 1 → the last block).
        var final = blocks[laneLength - 1]
        for lane in 1..<lanes {
            let b = blocks[lane * laneLength + laneLength - 1]
            for i in 0..<128 { final[i] ^= b[i] }
        }
        var finalBytes = Data()
        for w in final { for i in 0..<8 { finalBytes.append(UInt8((w >> UInt64(8 * i)) & 0xff)) } }
        return blake2bLong(outputLength: keyLength, input: finalBytes)
    }

    private static func fillSegment(blocks: inout [[UInt64]], pass: Int, slice: Int, lane: Int,
                                    segmentLength: Int, laneLength: Int,
                                    memory: Int, iterations: Int) {
        let syncPoints = 4
        let type = 2 // argon2id
        let dataIndependent = pass == 0 && slice < syncPoints / 2
        var input = [UInt64](repeating: 0, count: 128)
        if dataIndependent {
            input[0] = UInt64(pass); input[1] = UInt64(lane); input[2] = UInt64(slice)
            input[3] = UInt64(memory); input[4] = UInt64(iterations); input[5] = UInt64(type)
        }
        var index = 0
        var addresses = [UInt64](repeating: 0, count: 128)
        let zero = [UInt64](repeating: 0, count: 128)
        if pass == 0 && slice == 0 {
            index = 2
            if dataIndependent {
                input[6] += 1
                addresses = processBlock(input, zero, xorInto: nil)
                addresses = processBlock(addresses, zero, xorInto: nil)
            }
        }
        var offset = lane * laneLength + slice * segmentLength + index
        while index < segmentLength {
            var prev = offset - 1
            if index == 0 && slice == 0 { prev += laneLength }
            let random: UInt64
            if dataIndependent {
                if index % 128 == 0 {
                    input[6] += 1
                    addresses = processBlock(input, zero, xorInto: nil)
                    addresses = processBlock(addresses, zero, xorInto: nil)
                }
                random = addresses[index % 128]
            } else {
                random = blocks[prev][0]
            }
            let ref = indexAlpha(random: random, segmentLength: segmentLength,
                                 lanes: laneLength, pass: pass, slice: slice,
                                 lane: lane, index: index, lanesCount: blocks.count / laneLength)
            blocks[offset] = processBlock(blocks[prev], blocks[ref], xorInto: blocks[offset])
            index += 1
            offset += 1
        }
    }

    /// Port of x/crypto/argon2's indexAlpha + phi (lanes = memory lanes).
    private static func indexAlpha(random: UInt64, segmentLength: Int, lanes laneLength: Int,
                                   pass: Int, slice: Int, lane: Int, index: Int,
                                   lanesCount: Int) -> Int {
        var refLane = Int((random >> 32) % UInt64(lanesCount))
        if pass == 0 && slice == 0 { refLane = lane }
        var m = 3 * segmentLength
        var s = ((slice + 1) % 4) * segmentLength
        if lane == refLane { m += index }
        if pass == 0 {
            m = slice * segmentLength
            s = 0
            if slice == 0 || lane == refLane { m += index }
        }
        if index == 0 || lane == refLane { m -= 1 }
        // phi
        var p = random & 0xffffffff
        p = (p * p) >> 32
        p = (p * UInt64(m)) >> 32
        let rel = (UInt64(s) + UInt64(m) - (p + 1)) % UInt64(laneLength)
        return refLane * laneLength + Int(rel)
    }

    /// The Argon2 compression function G: P(a⊕b) ⊕ a ⊕ b, additionally
    /// XORed with `old` when given (Argon2 v1.3 later-pass semantics;
    /// x/crypto always fills with the XOR variant, and fresh memory is
    /// zero, so pass 0 comes out identical).
    static func processBlock(_ a: [UInt64], _ b: [UInt64], xorInto old: [UInt64]?) -> [UInt64] {
        var t = [UInt64](repeating: 0, count: 128)
        for i in 0..<128 { t[i] = a[i] ^ b[i] }
        let r = t
        // Rows.
        for i in stride(from: 0, to: 128, by: 16) {
            blamkaRound(&t, [i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
                             i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15])
        }
        // Columns.
        for i in stride(from: 0, to: 16, by: 2) {
            blamkaRound(&t, [i, i + 1, 16 + i, 16 + i + 1, 32 + i, 32 + i + 1, 48 + i, 48 + i + 1,
                             64 + i, 64 + i + 1, 80 + i, 80 + i + 1, 96 + i, 96 + i + 1, 112 + i, 112 + i + 1])
        }
        var out = [UInt64](repeating: 0, count: 128)
        for i in 0..<128 {
            var v = r[i] ^ t[i]
            if let old { v ^= old[i] }
            out[i] = v
        }
        return out
    }

    /// One BlaMka round over 16 words of `t` at the given indices.
    private static func blamkaRound(_ t: inout [UInt64], _ idx: [Int]) {
        var v = idx.map { t[$0] }
        // fBlaMka: x + y + 2·lo32(x)·lo32(y) mod 2^64 — the doubled product can exceed 2^64, so wrapping ops
        // (a checked `*` traps on every real Argon2 run).
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            v[a] = v[a] &+ v[b] &+ 2 &* UInt64(UInt32(truncatingIfNeeded: v[a])) &* UInt64(UInt32(truncatingIfNeeded: v[b]))
            v[d] = (v[d] ^ v[a]).rotated(right: 32)
            v[c] = v[c] &+ v[d] &+ 2 &* UInt64(UInt32(truncatingIfNeeded: v[c])) &* UInt64(UInt32(truncatingIfNeeded: v[d]))
            v[b] = (v[b] ^ v[c]).rotated(right: 24)
            v[a] = v[a] &+ v[b] &+ 2 &* UInt64(UInt32(truncatingIfNeeded: v[a])) &* UInt64(UInt32(truncatingIfNeeded: v[b]))
            v[d] = (v[d] ^ v[a]).rotated(right: 16)
            v[c] = v[c] &+ v[d] &+ 2 &* UInt64(UInt32(truncatingIfNeeded: v[c])) &* UInt64(UInt32(truncatingIfNeeded: v[d]))
            v[b] = (v[b] ^ v[c]).rotated(right: 63)
        }
        g(0, 4, 8, 12); g(1, 5, 9, 13); g(2, 6, 10, 14); g(3, 7, 11, 15)
        g(0, 5, 10, 15); g(1, 6, 11, 12); g(2, 7, 8, 13); g(3, 4, 9, 14)
        for (k, i) in idx.enumerated() { t[i] = v[k] }
    }
}
