import Foundation

/// SHAKE128 extendable-output function (FIPS 202), used by VMess for chunk
/// length masking. Absorbs a seed once, then squeezes a byte stream.
final class NCShake128 {
    private var state = [UInt64](repeating: 0, count: 25)
    private var block = Data()
    private var blockPos = 0
    private static let rate = 168 // bytes for SHAKE128

    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    /// Rotation offsets by lane index x + 5*y.
    private static let rho: [UInt64] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]
    /// Pi target lane index for source lane x + 5*y: (y) + 5*((2x + 3y) % 5).
    private static let pi: [Int] = (0..<25).map { i in
        let x = i % 5, y = i / 5
        return y + 5 * ((2 * x + 3 * y) % 5)
    }

    init(seed: Data) {
        absorb(seed)
        finishAbsorb()
        squeezeBlock()
    }

    private init(unseeded: Bool) {
        _ = unseeded
    }

    /// Snapshot for consumers that must peek the stream before committing to
    /// it (the VMess chunk decoder reads a length before the record arrives).
    func clone() -> NCShake128 {
        let c = NCShake128(unseeded: true)
        c.state = state
        c.block = block
        c.blockPos = blockPos
        c.pending = pending
        return c
    }

    /* The absorb path: full rate-sized blocks are XORed and permuted directly;
       the trailing partial block is finished with the SHAKE suffix. */
    private var pending = Data()

    private func absorb(_ data: Data) {
        var offset = 0
        while data.count - offset >= Self.rate {
            xorBlock(Data(data[offset..<(offset + Self.rate)]))
            permute()
            offset += Self.rate
        }
        pending = Data(data[offset...])
    }

    private func finishAbsorb() {
        var block = [UInt8](pending)
        block.append(0x1f)
        while block.count < Self.rate { block.append(0) }
        block[Self.rate - 1] |= 0x80
        xorBlock(Data(block))
        permute()
    }

    private func xorBlock(_ blockData: Data) {
        for lane in 0..<(Self.rate / 8) {
            var v: UInt64 = 0
            for j in 0..<8 {
                v |= UInt64(blockData[lane * 8 + j]) << (8 * UInt64(j))
            }
            state[lane] ^= v
        }
    }

    private func squeezeBlock() {
        var out = Data()
        for lane in 0..<(Self.rate / 8) {
            for j in 0..<8 {
                out.append(UInt8((state[lane] >> (8 * UInt64(j))) & 0xff))
            }
        }
        block = out
        blockPos = 0
    }

    func read(_ count: Int) -> Data {
        var out = Data()
        while out.count < count {
            if blockPos == block.count {
                permute()
                squeezeBlock()
            }
            let take = min(count - out.count, block.count - blockPos)
            out.append(block[blockPos..<(blockPos + take)])
            blockPos += take
        }
        return out
    }

    func nextUInt16() -> UInt16 {
        let b = read(2)
        return UInt16(b[0]) << 8 | UInt16(b[1])
    }

    private func permute() {
        var a = state
        for round in 0..<24 {
            // theta
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotatedLeft(1)
                for y in 0..<5 { a[x + 5 * y] ^= d }
            }
            // rho + pi
            var b = [UInt64](repeating: 0, count: 25)
            for i in 0..<25 {
                b[Self.pi[i]] = a[i].rotatedLeft(Self.rho[i])
            }
            // chi
            for y in 0..<5 {
                for x in 0..<5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                }
            }
            // iota
            a[0] ^= Self.rc[round]
        }
        state = a
    }
}

extension UInt64 {
    func rotatedLeft(_ n: UInt64) -> UInt64 {
        n == 0 ? self : (self << n) | (self >> (64 - n))
    }
}
