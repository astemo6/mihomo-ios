import Foundation

/// BLAKE3 (one-shot, 32-byte outputs) — needed by TUIC v4 token derivation
/// and the Shadowsocks 2022 key schedule. Implements hash / keyed-hash /
/// derive-key modes per the BLAKE3 paper's reference structure: 1024-byte
/// chunks, ChaCha-derived compression with 7 rounds, CV-stack tree fold.
/// Test vectors were generated with the same Go library mihomo uses
/// (metacubex/blake3) — see NativeCoreBlake3Tests.
enum NCBlake3 {
    private static let iv: [UInt32] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    private static let perm: [Int] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

    private static let flagChunkStart: UInt32 = 1 << 0
    private static let flagChunkEnd: UInt32 = 1 << 1
    private static let flagParent: UInt32 = 1 << 2
    private static let flagRoot: UInt32 = 1 << 3
    private static let flagKeyed: UInt32 = 1 << 4
    private static let flagDeriveContext: UInt32 = 1 << 5
    private static let flagDeriveMaterial: UInt32 = 1 << 6

    // MARK: public

    static func hash(_ data: [UInt8]) -> [UInt8] {
        finalize(keyWords: iv, flags: 0, data: data)
    }

    static func keyedHash(key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        precondition(key.count == 32)
        return finalize(keyWords: words(from: key), flags: flagKeyed, data: data)
    }

    static func deriveKey(context: String, material: [UInt8]) -> [UInt8] {
        let contextKey = chainingValue(keyWords: iv, flags: flagDeriveContext,
                                       data: [UInt8](context.utf8))
        return finalize(keyWords: contextKey, flags: flagDeriveMaterial, data: material)
    }

    // MARK: tree driver

    /// Root output bytes (32) for keyed/context modes.
    private static func finalize(keyWords: [UInt32], flags: UInt32, data: [UInt8]) -> [UInt8] {
        let root = rootOutput(keyWords: keyWords, flags: flags, data: data)
        let words = compress(cv: root.inputCV, block: root.blockWords, counter: 0,
                             blockLen: root.blockLen, flags: root.flags | flagRoot)
        return wordsToBytes(words)[0..<32].map { $0 }
    }

    /// The chaining value (non-root) — used for the derive-key context key.
    private static func chainingValue(keyWords: [UInt32], flags: UInt32, data: [UInt8]) -> [UInt32] {
        let root = rootOutput(keyWords: keyWords, flags: flags, data: data)
        let words = compress(cv: root.inputCV, block: root.blockWords, counter: root.counter,
                             blockLen: root.blockLen, flags: root.flags)
        return Array(words[0..<8])
    }

    private struct Output {
        var inputCV: [UInt32]
        var blockWords: [UInt32]
        var counter: UInt64
        var blockLen: UInt32
        var flags: UInt32
        var chainingValue: [UInt32] {
            let w = compress(cv: inputCV, block: blockWords, counter: counter,
                             blockLen: blockLen, flags: flags)
            return Array(w[0..<8])
        }
    }

    /// Walk chunks left to right, folding completed chunk CVs into a stack,
    /// and return the root Output node (whose block/counter describe the
    /// final, not-yet-compressed chunk or parent).
    private static func rootOutput(keyWords: [UInt32], flags: UInt32, data: [UInt8]) -> Output {
        let chunkLen = 1024
        var cvStack: [[UInt32]] = []
        var offset = 0
        var chunkCounter: UInt64 = 0
        while true {
            let remaining = data.count - offset
            let take = min(chunkLen, remaining)
            let chunk = Array(data[offset..<(offset + take)])
            let isLastChunk = offset + take >= data.count
            let out = chunkOutput(keyWords: keyWords, flags: flags, chunk: chunk, counter: chunkCounter)
            if isLastChunk {
                // Fold the stack into this output, bottom-up. (A chunk
                // ending exactly at the data end IS the last chunk, so a
                // non-final iteration always has more data after it.)
                var root = out
                while let left = cvStack.popLast() {
                    root = parentOutput(keyWords: keyWords, flags: flags,
                                        left: left, right: root.chainingValue)
                }
                return root
            }
            // Complete non-final chunk: push its CV, merging parents while
            // the (incremented) chunk counter is even.
            var cv = out.chainingValue
            chunkCounter += 1
            var n = chunkCounter
            while n & 1 == 0 {
                let left = cvStack.removeLast()
                cv = parentOutput(keyWords: keyWords, flags: flags, left: left, right: cv).chainingValue
                n >>= 1
            }
            cvStack.append(cv)
            offset += take
        }
    }

    /// Output node for one 1024-byte (or shorter) chunk: every block but the
    /// last is compressed into the running CV; the last block stays as the
    /// output's block (it carries CHUNK_END, and ROOT when applicable).
    private static func chunkOutput(keyWords: [UInt32], flags: UInt32, chunk: [UInt8], counter: UInt64) -> Output {
        var cv = keyWords
        if chunk.isEmpty {
            return Output(inputCV: cv, blockWords: [UInt32](repeating: 0, count: 16),
                          counter: counter, blockLen: 0, flags: flags | flagChunkStart | flagChunkEnd)
        }
        var blockIndex = 0
        var pos = 0
        while true {
            let remaining = chunk.count - pos
            let blockBytes = Array(chunk[pos..<(pos + min(64, remaining))])
            let isLastBlock = pos + 64 >= chunk.count
            var blockFlags = flags
            if blockIndex == 0 { blockFlags |= flagChunkStart }
            if isLastBlock {
                blockFlags |= flagChunkEnd
                return Output(inputCV: cv, blockWords: words(from: padded(blockBytes)),
                              counter: counter, blockLen: UInt32(blockBytes.count), flags: blockFlags)
            }
            let w = compress(cv: cv, block: words(from: blockBytes), counter: counter,
                             blockLen: 64, flags: blockFlags)
            cv = Array(w[0..<8])
            pos += 64
            blockIndex += 1
        }
    }

    private static func parentOutput(keyWords: [UInt32], flags: UInt32,
                                     left: [UInt32], right: [UInt32]) -> Output {
        Output(inputCV: keyWords, blockWords: left + right, counter: 0,
               blockLen: 64, flags: flags | flagParent)
    }

    // MARK: compression

    private static func words(from bytes: [UInt8]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: bytes.count / 4)
        for i in out.indices {
            out[i] = UInt32(bytes[i * 4]) | UInt32(bytes[i * 4 + 1]) << 8
                | UInt32(bytes[i * 4 + 2]) << 16 | UInt32(bytes[i * 4 + 3]) << 24
        }
        return out
    }

    private static func padded(_ block: [UInt8]) -> [UInt8] {
        var b = block
        while b.count < 64 { b.append(0) }
        return b
    }

    private static func wordsToBytes(_ words: [UInt32]) -> [UInt8] {
        var out: [UInt8] = []
        for w in words {
            out.append(UInt8(w & 0xff)); out.append(UInt8((w >> 8) & 0xff))
            out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
        }
        return out
    }

    private static func compress(cv: [UInt32], block: [UInt32], counter: UInt64,
                                 blockLen: UInt32, flags: UInt32) -> [UInt32] {
        var v: [UInt32] = cv + [iv[0], iv[1], iv[2], iv[3],
                                UInt32(counter & 0xffff_ffff), UInt32(counter >> 32),
                                blockLen, flags]
        var m = block
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = (v[d] ^ v[a]).rotated(right: 16)
            v[c] = v[c] &+ v[d]
            v[b] = (v[b] ^ v[c]).rotated(right: 12)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = (v[d] ^ v[a]).rotated(right: 8)
            v[c] = v[c] &+ v[d]
            v[b] = (v[b] ^ v[c]).rotated(right: 7)
        }
        for _ in 0..<7 {
            g(0, 4, 8, 12, m[0], m[1]); g(1, 5, 9, 13, m[2], m[3])
            g(2, 6, 10, 14, m[4], m[5]); g(3, 7, 11, 15, m[6], m[7])
            g(0, 5, 10, 15, m[8], m[9]); g(1, 6, 11, 12, m[10], m[11])
            g(2, 7, 8, 13, m[12], m[13]); g(3, 4, 9, 14, m[14], m[15])
            m = perm.map { m[$0] }
        }
        var out = [UInt32](repeating: 0, count: 16)
        for i in 0..<8 {
            out[i] = v[i + 8] ^ v[i]
            out[i + 8] = v[i + 8] ^ cv[i]
        }
        return out
    }
}

private extension UInt32 {
    func rotated(right n: UInt32) -> UInt32 { (self >> n) | (self << (32 - n)) }
}
