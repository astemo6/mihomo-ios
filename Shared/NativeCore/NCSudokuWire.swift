import Foundation

// fix/nc-sudoku-interop: the Sudoku obfuscation layer, wire-compatible with the official server
// (SUDOKU-ASCII/sudoku v0.5.2). Pure Swift, no CryptoKit (callers pass SHA-256 derived seeds), so the
// table / codec / key math is checked byte-for-byte against vectors produced by the official Go code.
// Re-implemented from the documented algorithms (Go math/rand v1, 4x4 grid enumeration, hint layouts,
// Ed25519 scalar-base multiplication); the official Go source was read as reference only.

// MARK: - Go math/rand v1 (rngSource + Rand.Shuffle)

/// Go `math/rand` v1 `rngSource` (additive lagged Fibonacci, len 607 / tap 273) seeded exactly like
/// `rand.NewSource(seed)`, with the `Rand.Uint32` / `Rand.int31n` / `Rand.Shuffle` paths the Sudoku table
/// shuffle uses. Only lives while a table is built.
struct NCGoRandV1 {
    private static let len = 607
    private static let tapLen = 273
    private static let int32max: Int64 = 2147483647
    private var vec: [Int64]
    private var tap = 0
    private var feed = NCGoRandV1.len - NCGoRandV1.tapLen

    init(seed: Int64) {
        var s = seed % Self.int32max // truncated remainder, like Go
        if s < 0 { s += Self.int32max }
        if s == 0 { s = 89482311 }
        var x = Int32(truncatingIfNeeded: s)
        var v = [Int64](repeating: 0, count: Self.len)
        let cooked = NCGoRandCooked.values
        for i in -20..<Self.len {
            x = Self.seedrand(x)
            if i >= 0 {
                var u = Int64(x) << 40
                x = Self.seedrand(x)
                u ^= Int64(x) << 20
                x = Self.seedrand(x)
                u ^= Int64(x)
                u ^= cooked[i]
                v[i] = u
            }
        }
        vec = v
    }

    /// x[n+1] = 48271 * x[n] mod (2**31 - 1), Schrage's method (Go `seedrand`).
    private static func seedrand(_ x: Int32) -> Int32 {
        let hi = x / 44488
        let lo = x % 44488
        var r = 48271 &* lo &- 3399 &* hi
        if r < 0 { r &+= 2147483647 }
        return r
    }

    mutating func uint64() -> UInt64 {
        tap -= 1
        if tap < 0 { tap += Self.len }
        feed -= 1
        if feed < 0 { feed += Self.len }
        let x = vec[feed] &+ vec[tap]
        vec[feed] = x
        return UInt64(bitPattern: x)
    }

    mutating func int63() -> Int64 { Int64(bitPattern: uint64() & 0x7fff_ffff_ffff_ffff) }

    mutating func uint32() -> UInt32 { UInt32(truncatingIfNeeded: int63() >> 31) }

    /// Go's unexported `Rand.int31n` (Lemire's multiply-shift with rejection), used by `Shuffle`.
    mutating func int31n(_ n: Int32) -> Int32 {
        let un = UInt32(n)
        var prod = UInt64(uint32()) &* UInt64(un)
        var low = UInt32(truncatingIfNeeded: prod)
        if low < un {
            let thresh = (0 &- un) % un
            while low < thresh {
                prod = UInt64(uint32()) &* UInt64(un)
                low = UInt32(truncatingIfNeeded: prod)
            }
        }
        return Int32(truncatingIfNeeded: prod >> 32)
    }

    /// `Rand.Shuffle` for n < 2^31 (Fisher-Yates from the top).
    mutating func shuffle(_ n: Int, swap: (Int, Int) -> Void) {
        var i = n - 1
        while i > 0 {
            let j = Int(int31n(Int32(i + 1)))
            swap(i, j)
            i -= 1
        }
    }
}

// MARK: - wyrand (encoder randomness; never part of the wire contract)

struct NCSudokuWyRand {
    var state: UInt64

    init() {
        var g = SystemRandomNumberGenerator()
        state = g.next()
    }

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0xa076_1d64_78bd_642f
        let r = state.multipliedFullWidth(by: state ^ 0xe703_7ed1_a0b4_28db)
        return r.high ^ r.low
    }

    /// Uniform in 0..<n from the high 32 bits (multiply-shift).
    @inline(__always) static func pick(_ draw32: UInt64, _ n: Int) -> Int {
        Int((draw32 &* UInt64(n)) >> 32)
    }
}

// MARK: - Grids

enum NCSudokuGrids {
    /// Every valid 4x4 sudoku grid (288), row-major values 1...4, in the fixed backtracking order the
    /// official table seeding depends on.
    static func all() -> [[UInt8]] {
        var out = [[UInt8]]()
        out.reserveCapacity(288)
        var g = [UInt8](repeating: 0, count: 16)
        func backtrack(_ idx: Int) {
            if idx == 16 { out.append(g); return }
            let row = idx / 4, col = idx % 4
            let br = (row / 2) * 2, bc = (col / 2) * 2
            for num in UInt8(1)...4 {
                var valid = true
                for i in 0..<4 where g[row * 4 + i] == num || g[i * 4 + col] == num {
                    valid = false
                    break
                }
                if valid {
                    outer: for r in 0..<2 {
                        for c in 0..<2 where g[(br + r) * 4 + (bc + c)] == num {
                            valid = false
                            break outer
                        }
                    }
                }
                if valid {
                    g[idx] = num
                    backtrack(idx + 1)
                    g[idx] = 0
                }
            }
        }
        backtrack(0)
        return out
    }

    /// Every set of 4 grid cells (16 choose 4 = 1820) in lexicographic order, packed a | b<<4 | c<<8 | d<<12.
    static let hintPositions: [UInt16] = {
        var out = [UInt16]()
        out.reserveCapacity(1820)
        for a in 0..<13 {
            for b in (a + 1)..<14 {
                for c in (b + 1)..<15 {
                    for d in (c + 1)..<16 {
                        out.append(UInt16(a | b << 4 | c << 8 | d << 12))
                    }
                }
            }
        }
        return out
    }()

    /// The 24 orders of four hints, as indexes.
    static let permutations: [(Int, Int, Int, Int)] = {
        var out = [(Int, Int, Int, Int)]()
        for a in 0..<4 {
            for b in 0..<4 where b != a {
                for c in 0..<4 where c != a && c != b {
                    out.append((a, b, c, 6 - a - b - c))
                }
            }
        }
        return out
    }()
}

// MARK: - Byte layouts

/// How hints / padding look on the wire for one direction: `prefer_ascii`, `prefer_entropy`, or a custom
/// 8-symbol x/p/v pattern (`xpxvvpvv`).
final class NCSudokuLayout {
    static let notHint: UInt8 = 0x80
    static let poisonHint: UInt8 = 64

    let name: String
    let paddingPool: [UInt8]
    let padMarker: UInt8
    /// pos<<2|val for a hint byte, poisonHint for hint-class bytes no encoder emits, notHint otherwise.
    private(set) var hintIdx = [UInt8](repeating: NCSudokuLayout.notHint, count: 256)
    /// encodeHint[val*16 + pos]
    private(set) var encodeHint = [UInt8](repeating: 0, count: 64)
    /// 0..63 for packed-downlink groups, 0xff otherwise.
    private(set) var decodeGroup = [UInt8](repeating: 0xff, count: 256)

    private init(name: String, pool: [UInt8], padMarker: UInt8) {
        self.name = name
        paddingPool = pool
        self.padMarker = padMarker
    }

    private func indexHints(aliases: [UInt8] = []) {
        for b in aliases { hintIdx[Int(b)] = Self.poisonHint }
        for val in 0..<4 {
            for pos in 0..<16 {
                hintIdx[Int(encodeHint[val * 16 + pos])] = UInt8(pos << 2 | val)
            }
        }
    }

    static func ascii() -> NCSudokuLayout {
        let l = NCSudokuLayout(name: "ascii", pool: (0..<32).map { UInt8(0x20 + $0) }, padMarker: 0x3F)
        for val in 0..<4 {
            for pos in 0..<16 {
                let b = UInt8(0x40 | val << 4 | pos)
                l.encodeHint[val * 16 + pos] = b == 0x7F ? 0x0A : b
            }
        }
        var aliases = [UInt8]()
        for b in 0..<256 where b & 0x40 == 0x40 {
            l.decodeGroup[b] = UInt8(b & 0x3F)
            aliases.append(UInt8(b))
        }
        l.decodeGroup[0x0A] = 0x3F
        l.indexHints(aliases: aliases)
        return l
    }

    static func entropy() -> NCSudokuLayout {
        var pool = [UInt8]()
        for i in 0..<8 {
            pool.append(UInt8(0x80 + i))
            pool.append(UInt8(0x10 + i))
        }
        let l = NCSudokuLayout(name: "entropy", pool: pool, padMarker: 0x80)
        for val in 0..<4 {
            for pos in 0..<16 { l.encodeHint[val * 16 + pos] = UInt8(val << 5 | pos) }
        }
        for b in 0..<256 where b & 0x90 == 0 {
            l.decodeGroup[b] = UInt8(((b >> 1) & 0x30) | (b & 0x0F))
        }
        l.indexHints()
        return l
    }

    /// `pattern`: 8 symbols, exactly 2 x / 2 p / 4 v (case-insensitive, spaces ignored); nil if invalid.
    static func custom(_ pattern: String) -> NCSudokuLayout? {
        let cleaned = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: " ", with: "").lowercased()
        let chars = Array(cleaned.utf8)
        guard chars.count == 8 else { return nil }
        var xBits = [Int](), pBits = [Int](), vBits = [Int]()
        for (i, c) in chars.enumerated() {
            let bit = 7 - i
            switch c {
            case UInt8(ascii: "x"): xBits.append(bit)
            case UInt8(ascii: "p"): pBits.append(bit)
            case UInt8(ascii: "v"): vBits.append(bit)
            default: return nil
            }
        }
        guard xBits.count == 2, pBits.count == 2, vBits.count == 4 else { return nil }
        let xMask = UInt8(1 << xBits[0] | 1 << xBits[1])
        func encodeBits(_ val: Int, _ pos: Int, _ dropX: Int) -> UInt8 {
            var out = xMask
            if dropX >= 0 { out &= ~UInt8(1 << xBits[dropX]) }
            if val & 0x02 != 0 { out |= UInt8(1 << pBits[0]) }
            if val & 0x01 != 0 { out |= UInt8(1 << pBits[1]) }
            for (i, bit) in vBits.enumerated() where (pos >> (3 - i)) & 1 == 1 {
                out |= UInt8(1 << bit)
            }
            return out
        }
        var seen = Set<UInt8>()
        for drop in 0..<2 {
            for val in 0..<4 {
                for pos in 0..<16 {
                    let b = encodeBits(val, pos, drop)
                    if b.nonzeroBitCount >= 5 { seen.insert(b) }
                }
            }
        }
        let pool = seen.sorted()
        guard let marker = pool.first else { return nil }
        let l = NCSudokuLayout(name: "custom(\(cleaned))", pool: pool, padMarker: marker)
        for val in 0..<4 {
            for pos in 0..<16 { l.encodeHint[val * 16 + pos] = encodeBits(val, pos, -1) }
        }
        for b in 0..<256 where UInt8(b) & xMask == xMask {
            var val = 0, pos = 0
            if b & (1 << pBits[0]) != 0 { val |= 0x02 }
            if b & (1 << pBits[1]) != 0 { val |= 0x01 }
            for (i, bit) in vBits.enumerated() where b & (1 << bit) != 0 { pos |= 1 << (3 - i) }
            l.decodeGroup[b] = UInt8(val << 4 | pos)
        }
        l.indexHints()
        return l
    }

    @inline(__always) func hintByte(val: Int, pos: Int) -> UInt8 { encodeHint[(val & 3) * 16 + (pos & 15)] }
}

// MARK: - ASCII mode (table-type)

/// `table-type` / `ascii`: symmetric `prefer_ascii` / `prefer_entropy` or directional `up_X_down_Y`.
struct NCSudokuASCIIMode: Equatable {
    var uplinkASCII: Bool
    var downlinkASCII: Bool

    static func parse(_ raw: String?) -> NCSudokuASCIIMode? {
        let s = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch s {
        case "", "entropy", "prefer_entropy": return NCSudokuASCIIMode(uplinkASCII: false, downlinkASCII: false)
        case "ascii", "prefer_ascii": return NCSudokuASCIIMode(uplinkASCII: true, downlinkASCII: true)
        default: break
        }
        guard s.hasPrefix("up_") else { return nil }
        let body = String(s.dropFirst(3))
        guard let r = body.range(of: "_down_") else { return nil }
        guard let up = token(String(body[..<r.lowerBound])), let down = token(String(body[r.upperBound...])) else {
            return nil
        }
        return NCSudokuASCIIMode(uplinkASCII: up, downlinkASCII: down)
    }

    private static func token(_ t: String) -> Bool? {
        switch t.trimmingCharacters(in: .whitespacesAndNewlines) {
        case "ascii", "prefer_ascii": return true
        case "entropy", "prefer_entropy", "": return false
        default: return nil
        }
    }

    var canonical: String {
        switch (uplinkASCII, downlinkASCII) {
        case (true, true): return "prefer_ascii"
        case (false, false): return "prefer_entropy"
        default: return "up_\(uplinkASCII ? "ascii" : "entropy")_down_\(downlinkASCII ? "ascii" : "entropy")"
        }
    }
}

// MARK: - Table

/// The key-derived part of a Sudoku table, shared by both directions and every connection of a node:
/// the 288 grids in shuffled order (as hint sets), and for every byte the list of 4-cell hint position sets
/// that identify its grid uniquely (the encoder's choices). ~55 KB per key; cached.
final class NCSudokuTableCore {
    /// sets[idx*5 + w]: bit k of word w set when shuffled grid 64*w+k has value (idx&3)+1 at cell idx>>2.
    /// Index 64 (poison) and above stay empty.
    private let sets: [UInt64]
    /// grids[byte*16 + cell] (1...4) for the 256 grids that carry a byte.
    private let grids: [UInt8]
    let puzzleStart: [UInt32]
    /// Index into NCSudokuGrids.hintPositions.
    let puzzlePositions: [UInt16]

    init(seed: Int64) {
        let base = NCSudokuGrids.all()
        var order = Array(0..<base.count)
        var rng = NCGoRandV1(seed: seed)
        rng.shuffle(order.count) { i, j in order.swapAt(i, j) }
        var s = [UInt64](repeating: 0, count: 128 * 5)
        var g = [UInt8](repeating: 0, count: 256 * 16)
        for (k, gi) in order.enumerated() {
            let grid = base[gi]
            for pos in 0..<16 {
                s[(pos << 2 | Int(grid[pos] - 1)) * 5 + (k >> 6)] |= 1 << UInt64(k & 63)
            }
            if k < 256 {
                for pos in 0..<16 { g[k * 16 + pos] = grid[pos] }
            }
        }
        sets = s
        grids = g
        var start = [UInt32](repeating: 0, count: 257)
        var positions = [UInt16]()
        positions.reserveCapacity(23_000)
        let hp = NCSudokuGrids.hintPositions
        for byte in 0..<256 {
            start[byte] = UInt32(positions.count)
            let row = byte * 16
            for (pi, packed) in hp.enumerated() {
                let p0 = Int(packed) & 15, p1 = Int(packed >> 4) & 15
                let p2 = Int(packed >> 8) & 15, p3 = Int(packed >> 12) & 15
                let h0 = UInt8(p0 << 2 | Int(g[row + p0] - 1)), h1 = UInt8(p1 << 2 | Int(g[row + p1] - 1))
                let h2 = UInt8(p2 << 2 | Int(g[row + p2] - 1)), h3 = UInt8(p3 << 2 | Int(g[row + p3] - 1))
                if let got = Self.decode(s, h0, h1, h2, h3), Int(got) == byte {
                    positions.append(UInt16(pi))
                }
            }
        }
        start[256] = UInt32(positions.count)
        puzzleStart = start
        puzzlePositions = positions
    }

    @inline(__always) func cell(byte: Int, pos: Int) -> Int { Int(grids[byte * 16 + pos]) }

    /// The byte whose puzzle is exactly these four hint indexes (pos<<2|val, any order), or nil.
    @inline(__always) func decodeHints(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> UInt8? {
        Self.decode(sets, a, b, c, d)
    }

    @inline(__always)
    private static func decode(_ s: [UInt64], _ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> UInt8? {
        let ia = Int(a & 127) * 5, ib = Int(b & 127) * 5, ic = Int(c & 127) * 5, id = Int(d & 127) * 5
        if s[ia + 4] & s[ib + 4] & s[ic + 4] & s[id + 4] != 0 { return nil } // a grid that carries no byte
        var found = -1
        for w in 0..<4 {
            let r = s[ia + w] & s[ib + w] & s[ic + w] & s[id + w]
            if r == 0 { continue }
            if found >= 0 || r & (r &- 1) != 0 { return nil } // more than one grid shares these hints
            found = w * 64 + r.trailingZeroBitCount
        }
        return found >= 0 ? UInt8(found) : nil
    }
}

/// One direction of a Sudoku table: the shared key core plus a byte layout.
struct NCSudokuTable {
    let core: NCSudokuTableCore
    let layout: NCSudokuLayout
}

/// Process-wide cache of table cores (built once per key, ~55 KB each, at most a few keys alive).
enum NCSudokuTableCache {
    private static let lock = NSLock()
    private static var entries: [(seed: Int64, core: NCSudokuTableCore)] = []
    private static let limit = 4

    static func core(seed: Int64) -> NCSudokuTableCore {
        lock.lock()
        if let i = entries.firstIndex(where: { $0.seed == seed }) {
            let e = entries.remove(at: i)
            entries.append(e)
            lock.unlock()
            return e.core
        }
        lock.unlock()
        let built = NCSudokuTableCore(seed: seed) // outside the lock: a few ms
        lock.lock()
        defer { lock.unlock() }
        if let e = entries.first(where: { $0.seed == seed }) { return e.core }
        entries.append((seed, built))
        if entries.count > limit { entries.removeFirst() }
        return built
    }

    static func removeAll() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }
}

// MARK: - Encoder (classic Sudoku, uplink)

/// Turns plaintext into hint bytes: each byte becomes one of its puzzles' four hints in a random order, with
/// a padding byte possible before every hint and before every group (probability drawn once per connection
/// between padding-min% and padding-max%), plus a possible trailing pad per write.
final class NCSudokuEncoder {
    private let table: NCSudokuTable
    private var rng: NCSudokuWyRand
    let threshold: UInt64

    init(table: NCSudokuTable, paddingMin: Int, paddingMax: Int, rng: NCSudokuWyRand = NCSudokuWyRand()) {
        self.table = table
        self.rng = rng
        threshold = Self.paddingThreshold(&self.rng, paddingMin, paddingMax)
    }

    static func paddingThreshold(_ r: inout NCSudokuWyRand, _ pMin: Int, _ pMax: Int) -> UInt64 {
        let lo = max(0, min(pMin, 100))
        var hi = max(0, min(pMax, 100))
        if hi < lo { hi = lo }
        let one: UInt64 = 1 << 32
        let minT = UInt64(lo) * one / 100
        let maxT = UInt64(hi) * one / 100
        if maxT <= minT { return minT }
        let u = r.next() >> 32
        return minT + (u * (maxT - minT) >> 32)
    }

    @inline(__always) private func maybePad(_ out: inout [UInt8]) {
        guard threshold != 0 else { return }
        let draw = rng.next()
        if draw & 0xffff_ffff < threshold {
            let pool = table.layout.paddingPool
            out.append(pool[NCSudokuWyRand.pick(draw >> 32, pool.count)])
        }
    }

    func encode(_ data: Data) -> Data {
        guard !data.isEmpty else { return Data() }
        let core = table.core
        let layout = table.layout
        let hp = NCSudokuGrids.hintPositions
        let perms = NCSudokuGrids.permutations
        var out = [UInt8]()
        out.reserveCapacity(data.count * (threshold == 0 ? 4 : 6) + 1)
        var hints = [UInt8](repeating: 0, count: 4)
        for byte in data {
            let b = Int(byte)
            let draw = rng.next()
            let first = Int(core.puzzleStart[b])
            let count = Int(core.puzzleStart[b + 1]) - first
            let packed = hp[Int(core.puzzlePositions[first + NCSudokuWyRand.pick(draw >> 32, count)])]
            for i in 0..<4 {
                let pos = Int(packed >> UInt16(4 * i)) & 15
                hints[i] = layout.hintByte(val: core.cell(byte: b, pos: pos) - 1, pos: pos)
            }
            let p = perms[NCSudokuWyRand.pick(draw & 0xffff_ffff, perms.count)]
            maybePad(&out)
            maybePad(&out); out.append(hints[p.0])
            maybePad(&out); out.append(hints[p.1])
            maybePad(&out); out.append(hints[p.2])
            maybePad(&out); out.append(hints[p.3])
        }
        maybePad(&out)
        return Data(out)
    }
}

// MARK: - Decoders (downlink)

protocol NCSudokuStreamDecoder: AnyObject {
    /// Plaintext recovered from these wire bytes (may be empty); throws on a byte stream no peer emits.
    func feed(_ wire: Data) throws -> Data
}

enum NCSudokuWireError: Error, LocalizedError {
    case invalidPuzzle
    var errorDescription: String? { "Sudoku 解码失败：收到的提示不构成本密钥的谜题（密钥 / 编码表不一致）" }
}

/// Classic Sudoku decode: any byte that is not a hint is padding, wherever it sits; every 4 hints form a
/// puzzle whose unique grid is the byte. A partial group carries over to the next feed.
final class NCSudokuClassicDecoder: NCSudokuStreamDecoder {
    private let table: NCSudokuTable
    private var pending = [UInt8](repeating: 0, count: 4)
    private var count = 0

    init(table: NCSudokuTable) { self.table = table }

    func feed(_ wire: Data) throws -> Data {
        let hintIdx = table.layout.hintIdx
        let core = table.core
        var out = [UInt8]()
        out.reserveCapacity(wire.count / 4 + 1)
        for b in wire {
            let idx = hintIdx[Int(b)]
            if idx & 0x80 != 0 { continue }
            pending[count] = idx
            count += 1
            if count == 4 {
                count = 0
                guard let v = core.decodeHints(pending[0], pending[1], pending[2], pending[3]) else {
                    throw NCSudokuWireError.invalidPuzzle
                }
                out.append(v)
            }
        }
        return Data(out)
    }
}

/// Packed (bandwidth-optimised) downlink: 6-bit groups, MSB first; non-group bytes are padding, and the
/// layout's pad marker ends a write (drops the residual bits).
final class NCSudokuPackedDecoder: NCSudokuStreamDecoder {
    private let layout: NCSudokuLayout
    private var bitBuf: UInt64 = 0
    private var bits = 0

    init(layout: NCSudokuLayout) { self.layout = layout }

    func feed(_ wire: Data) throws -> Data {
        let groups = layout.decodeGroup
        let marker = layout.padMarker
        var out = [UInt8]()
        out.reserveCapacity(wire.count * 3 / 4 + 1)
        for b in wire {
            let g = groups[Int(b)]
            if g >= 64 {
                if b == marker {
                    bitBuf = 0
                    bits = 0
                }
                continue
            }
            bitBuf = bitBuf << 6 | UInt64(g)
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: bitBuf >> UInt64(bits)))
                bitBuf &= (1 << UInt64(bits)) - 1
            }
        }
        return Data(out)
    }
}

// MARK: - Ed25519 public key recovery (key normalisation)

/// The official client turns a private key (32-byte master scalar or 64-byte split key r||k, hex) into the
/// master public key hex and uses that as the shared PSK / table seed. Field arithmetic mod 2^255-19 in
/// sixteen 16-bit limbs and the unified Edwards addition (public-domain TweetNaCl formulation); runs once
/// per key.
enum NCSudokuEd25519 {
    typealias FE = [Int64]

    private static let gf0: FE = [Int64](repeating: 0, count: 16)
    private static let gf1: FE = [1] + [Int64](repeating: 0, count: 15)
    private static let d2: FE = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                                 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]
    private static let bx: FE = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                                 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]
    private static let by: FE = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                                 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]
    /// Group order L, little-endian.
    private static let order: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
                                         0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]

    /// Master public key hex for a 64-hex master scalar or 128-hex split key; nil when `keyHex` is not one
    /// (non-hex, other length, or a non-canonical scalar) — the key is then used as given.
    static func recoverPublicKeyHex(_ keyHex: String) -> String? {
        guard let bytes = hexBytes(keyHex) else { return nil }
        let point: [FE]
        switch bytes.count {
        case 32:
            guard isCanonical(bytes) else { return nil }
            point = scalarBase(bytes)
        case 64:
            let r = Array(bytes[0..<32]), k = Array(bytes[32..<64])
            guard isCanonical(r), isCanonical(k) else { return nil }
            var p = scalarBase(r) // (r + k)·B = r·B + k·B, so no scalar reduction is needed
            var q = scalarBase(k)
            add(&p, &q)
            point = p
        default:
            return nil
        }
        return pack(point).map { String(format: "%02x", $0) }.joined()
    }

    static func hexBytes(_ s: String) -> [UInt8]? {
        let u = Array(s.utf8)
        guard u.count % 2 == 0, !u.isEmpty else { return nil }
        func nib(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 97...102: return c - 87
            case 65...70: return c - 55
            default: return nil
            }
        }
        var out = [UInt8]()
        out.reserveCapacity(u.count / 2)
        var i = 0
        while i < u.count {
            guard let h = nib(u[i]), let l = nib(u[i + 1]) else { return nil }
            out.append(h << 4 | l)
            i += 2
        }
        return out
    }

    private static func isCanonical(_ s: [UInt8]) -> Bool {
        var i = 31
        while i >= 0 {
            if s[i] < order[i] { return true }
            if s[i] > order[i] { return false }
            i -= 1
        }
        return false // equal to L
    }

    private static func car(_ o: inout FE) {
        for i in 0..<16 {
            o[i] += 1 << 16
            let c = o[i] >> 16
            if i < 15 {
                o[i + 1] += c - 1
            } else {
                o[0] += 38 * (c - 1)
            }
            o[i] -= c << 16
        }
    }

    private static func sel(_ p: inout FE, _ q: inout FE, _ b: Int64) {
        let c = ~(b - 1)
        for i in 0..<16 {
            let t = c & (p[i] ^ q[i])
            p[i] ^= t
            q[i] ^= t
        }
    }

    private static func packFE(_ n: FE) -> [UInt8] {
        var t = n
        car(&t); car(&t); car(&t)
        var m = gf0
        for _ in 0..<2 {
            m[0] = t[0] - 0xffed
            for i in 1..<15 {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
                m[i - 1] &= 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
            let b = (m[15] >> 16) & 1
            m[14] &= 0xffff
            sel(&t, &m, 1 - b)
        }
        var o = [UInt8](repeating: 0, count: 32)
        for i in 0..<16 {
            o[2 * i] = UInt8(truncatingIfNeeded: t[i] & 0xff)
            o[2 * i + 1] = UInt8(truncatingIfNeeded: t[i] >> 8)
        }
        return o
    }

    private static func A(_ a: FE, _ b: FE) -> FE { (0..<16).map { a[$0] + b[$0] } }
    private static func Z(_ a: FE, _ b: FE) -> FE { (0..<16).map { a[$0] - b[$0] } }

    private static func M(_ a: FE, _ b: FE) -> FE {
        var t = [Int64](repeating: 0, count: 31)
        for i in 0..<16 {
            for j in 0..<16 { t[i + j] += a[i] * b[j] }
        }
        for i in 0..<15 { t[i] += 38 * t[i + 16] }
        var o = Array(t[0..<16])
        car(&o); car(&o)
        return o
    }

    private static func inv(_ i: FE) -> FE {
        var c = i
        var a = 253
        while a >= 0 {
            c = M(c, c)
            if a != 2 && a != 4 { c = M(c, i) }
            a -= 1
        }
        return c
    }

    /// p += q (extended coordinates X, Y, Z, T).
    private static func add(_ p: inout [FE], _ q: inout [FE]) {
        let a = M(Z(p[1], p[0]), Z(q[1], q[0]))
        let b = M(A(p[0], p[1]), A(q[0], q[1]))
        let c = M(M(p[3], q[3]), d2)
        var d = M(p[2], q[2])
        d = A(d, d)
        let e = Z(b, a), f = Z(d, c), g = A(d, c), h = A(b, a)
        p[0] = M(e, f)
        p[1] = M(h, g)
        p[2] = M(g, f)
        p[3] = M(e, h)
    }

    private static func cswap(_ p: inout [FE], _ q: inout [FE], _ b: Int64) {
        for i in 0..<4 { sel(&p[i], &q[i], b) }
    }

    private static func scalarBase(_ s: [UInt8]) -> [FE] {
        var q: [FE] = [bx, by, gf1, M(bx, by)]
        var p: [FE] = [gf0, gf1, gf1, gf0]
        var i = 255
        while i >= 0 {
            let b = Int64((s[i / 8] >> UInt8(i & 7)) & 1)
            cswap(&p, &q, b)
            add(&q, &p)
            var pp = p
            add(&p, &pp)
            cswap(&p, &q, b)
            i -= 1
        }
        return p
    }

    private static func pack(_ p: [FE]) -> [UInt8] {
        let zi = inv(p[2])
        let tx = M(p[0], zi), ty = M(p[1], zi)
        var r = packFE(ty)
        r[31] ^= (packFE(tx)[0] & 1) << 7
        return r
    }
}
