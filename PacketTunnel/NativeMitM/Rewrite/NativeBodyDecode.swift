// Native MitM stage 3b — Content-Encoding decoding with the old core's exact accept / reject behaviour.
//
// the old core decodes gzip / x-gzip (compress/gzip, multistream), deflate (gzip
// magic → gzip; a zlib header whose whole stream checks out → zlib; otherwise raw flate) and br (strict brotli).
// A body the old core fails to decode passes through untouched, so a decoder that accepted a little more or less than the old core's
// would change the response. Apple's COMPRESSION_ZLIB reads past the end of a deflate stream and cannot say
// where it stopped, so gzip / zlib / raw deflate are decoded here by a small inflate that reads input exactly the
// way the old core's compress/flate does (a byte at a time, only when bits are needed), with the old core's validity rules
// (complete Huffman codes except one length-1 code, HLIT ≤ 286, HDIST ≤ 30, distances within the history,
// stored-length complement), and the gzip / zlib framing checks of the old core's readers (header, FEXTRA, FNAME / FCOMMENT
// ≤ 511 bytes, CRC-32 + ISIZE / Adler-32, further gzip members). brotli uses Apple's decoder (only on Apple
// platforms) and must reach the stream end. Anything else → nil: the caller hands the request back to the old core.

import Foundation
#if canImport(Compression)
import Compression
#endif

enum NativeBodyDecode {
    enum Outcome: Equatable {
        case decoded(Data)
        case unsupported(String)   // hand back to the old core
    }

    /// decodeBody(enc, b, limit) where the old core would succeed with the same bytes; .unsupported otherwise.
    static func decode(_ encRaw: String, _ b: Data, limit: Int) -> Outcome {
        let enc = RWAscii.lower(RWAscii.trimSpace(encRaw))
        if !RWAscii.isPrintable(encRaw) { return .unsupported("encoding bytes") }
        if enc.contains(",") { return .unsupported("encoding list") }
        switch enc {
        case "", "identity":
            return b.count <= limit ? .decoded(b) : .unsupported("too large")
        case "gzip", "x-gzip":
            return gunzip([UInt8](b), limit: limit)
        case "deflate":
            let bytes = [UInt8](b)
            if bytes.count > 2 && bytes[0] == 0x1F && bytes[1] == 0x8B { return gunzip(bytes, limit: limit) }
            if bytes.count >= 2 && bytes[0] & 0x0F == 8 && bytes[0] >> 4 <= 7 && (UInt16(bytes[0]) << 8 | UInt16(bytes[1])) % 31 == 0
                && bytes[1] & 0x20 != 0 {
                return .unsupported("zlib dictionary") // the old core: an Adler-32 of 1 is "the empty dictionary"
            }
            if let z = zlibHeader(bytes) {
                if case .decoded(let d) = zlib(bytes, headerLen: z, limit: limit) { return .decoded(d) }
                // the old core: the zlib stream did not check out → raw flate over the whole body. Its zlib attempt reads
                // up to limit+1 decoded bytes; a body that only failed by being too big is the old core's raw-flate retry
                // of a zlib stream, which ends in an error or garbage: hand back.
                return .unsupported("zlib fallback")
            }
            var inf = Inflater(bytes, limit: limit)
            switch inf.run() {
            case .ok: return .decoded(Data(inf.out))
            case .tooLarge: return .unsupported("too large")
            case .corrupt: return .unsupported("deflate")
            }
        case "br":
            return brotli(b, limit: limit)
        default:
            return .unsupported("encoding \(enc)")
        }
    }

    // MARK: gzip (compress/gzip Reader, multistream)

    static func gunzip(_ b: [UInt8], limit: Int) -> Outcome {
        var pos = 0
        var out: [UInt8] = []
        var members = 0
        while true {
            if pos == b.count && members > 0 { return .decoded(Data(out)) }
            // readHeader: 10 bytes (0 left after a member: io.EOF, clean)
            guard pos + 10 <= b.count else { return .unsupported("gzip header") }
            guard b[pos] == 0x1F, b[pos + 1] == 0x8B, b[pos + 2] == 8 else { return .unsupported("gzip header") }
            let flg = b[pos + 3]
            var p = pos + 10
            if flg & 0x04 != 0 { // FEXTRA
                guard p + 2 <= b.count else { return .unsupported("gzip header") }
                let xlen = Int(b[p]) | Int(b[p + 1]) << 8
                p += 2
                guard p + xlen <= b.count else { return .unsupported("gzip header") }
                p += xlen
            }
            for bit: UInt8 in [0x08, 0x10] where flg & bit != 0 { // FNAME, FCOMMENT: NUL-terminated, < 512 bytes
                var i = 0
                while true {
                    guard i < 512 else { return .unsupported("gzip header") }
                    guard p < b.count else { return .unsupported("gzip header") }
                    let c = b[p]; p += 1; i += 1
                    if c == 0 { break }
                }
            }
            if flg & 0x02 != 0 { return .unsupported("gzip header crc") }
            var inf = Inflater(b, start: p, limit: limit - out.count)
            switch inf.run() {
            case .ok: break
            case .tooLarge: return .unsupported("too large")
            case .corrupt: return .unsupported("gzip data")
            }
            p = inf.pos
            guard p + 8 <= b.count else { return .unsupported("gzip trailer") }
            let crc = UInt32(b[p]) | UInt32(b[p + 1]) << 8 | UInt32(b[p + 2]) << 16 | UInt32(b[p + 3]) << 24
            let size = UInt32(b[p + 4]) | UInt32(b[p + 5]) << 8 | UInt32(b[p + 6]) << 16 | UInt32(b[p + 7]) << 24
            guard crc == CRC32.checksum(inf.out), size == UInt32(truncatingIfNeeded: inf.out.count) else { return .unsupported("gzip checksum") }
            out.append(contentsOf: inf.out)
            pos = p + 8
            members += 1
        }
    }

    // MARK: zlib (compress/zlib reader)

    /// The zlib header length when the old core's zlib.NewReader accepts the first two bytes (FDICT → nil: hand back).
    static func zlibHeader(_ b: [UInt8]) -> Int? {
        guard b.count >= 2 else { return nil }
        let h = UInt16(b[0]) << 8 | UInt16(b[1])
        guard b[0] & 0x0F == 8, b[0] >> 4 <= 7, h % 31 == 0 else { return nil }
        if b[1] & 0x20 != 0 { return nil }
        return 2
    }

    static func zlib(_ b: [UInt8], headerLen: Int, limit: Int) -> Outcome {
        var inf = Inflater(b, start: headerLen, limit: limit)
        switch inf.run() {
        case .ok: break
        case .tooLarge: return .unsupported("too large")
        case .corrupt: return .unsupported("zlib data")
        }
        let p = inf.pos
        guard p + 4 <= b.count else { return .unsupported("zlib trailer") }
        let sum = UInt32(b[p]) << 24 | UInt32(b[p + 1]) << 16 | UInt32(b[p + 2]) << 8 | UInt32(b[p + 3])
        guard sum == Adler32.checksum(inf.out) else { return .unsupported("zlib checksum") }
        return .decoded(Data(inf.out))
    }

    // MARK: brotli

    static func brotli(_ b: Data, limit: Int) -> Outcome {
        #if canImport(Compression)
        if b.isEmpty { return .decoded(Data()) }
        var out = Data()
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }
        guard compression_stream_init(stream, COMPRESSION_STREAM_DECODE, COMPRESSION_BROTLI) == COMPRESSION_STATUS_OK else {
            return .unsupported("brotli init")
        }
        defer { compression_stream_destroy(stream) }
        let cap = 64 << 10
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: cap)
        defer { dst.deallocate() }
        let result: Outcome = b.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Outcome in
            stream.pointee.src_ptr = src.bindMemory(to: UInt8.self).baseAddress!
            stream.pointee.src_size = src.count
            while true {
                stream.pointee.dst_ptr = dst
                stream.pointee.dst_size = cap
                let st = compression_stream_process(stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                let n = cap - stream.pointee.dst_size
                if n > 0 {
                    if out.count + n > limit { return .unsupported("too large") }
                    out.append(dst, count: n)
                }
                switch st {
                case COMPRESSION_STATUS_END:
                    // Bytes after the end of the stream: the old core's reading of them is not pinned down here.
                    return stream.pointee.src_size == 0 ? .decoded(out) : .unsupported("brotli trailing")
                case COMPRESSION_STATUS_OK:
                    if n == 0 && stream.pointee.src_size == 0 { return .unsupported("brotli truncated") }
                default:
                    return .unsupported("brotli data")
                }
            }
        }
        return result
        #else
        return .unsupported("brotli")
        #endif
    }
}

// MARK: - Checksums

enum CRC32 {
    static let table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1 }
        return c
    }
    static func checksum(_ b: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        for x in b { c = table[Int((c ^ UInt32(x)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFFFFFF
    }
}

enum Adler32 {
    static func checksum(_ b: [UInt8]) -> UInt32 {
        var a: UInt32 = 1, s: UInt32 = 0
        var i = 0
        while i < b.count {
            let end = min(i + 5552, b.count)
            while i < end { a += UInt32(b[i]); s += a; i += 1 }
            a %= 65521; s %= 65521
        }
        return s << 16 | a
    }
}

// MARK: - Inflate (RFC 1951) with compress/flate's input consumption and validity rules

struct Inflater {
    enum Result { case ok, corrupt, tooLarge }

    private let b: [UInt8]
    private(set) var pos: Int
    private let limit: Int
    private(set) var out: [UInt8] = []
    private var bitbuf: UInt32 = 0
    private var bitcnt: UInt32 = 0

    init(_ b: [UInt8], start: Int = 0, limit: Int) {
        self.b = b
        self.pos = start
        self.limit = max(0, limit)
    }

    private struct Corrupt: Error {}
    private struct TooLarge: Error {}

    /// the old core's moreBits: one input byte (an error at the end of input).
    private mutating func needBits(_ n: UInt32) throws {
        while bitcnt < n {
            guard pos < b.count else { throw Corrupt() }
            bitbuf |= UInt32(b[pos]) << bitcnt
            pos += 1
            bitcnt += 8
        }
    }

    private mutating func bits(_ n: UInt32) throws -> Int {
        if n == 0 { return 0 }
        try needBits(n)
        let v = bitbuf & ((1 << n) - 1)
        bitbuf >>= n
        bitcnt -= n
        return Int(v)
    }

    /// Canonical Huffman code (puff.c layout): count per length, symbols by code order.
    private struct Huffman {
        var count = [Int](repeating: 0, count: 16)
        var symbol: [Int] = []
        var empty = true
    }

    /// huffmanDecoder.init's acceptance: complete, or a single code of length 1, or empty.
    private static func build(_ lengths: ArraySlice<Int>) -> Huffman? {
        var h = Huffman()
        var maxLen = 0, minLen = 0
        for n in lengths where n != 0 {
            h.count[n] += 1
            if n > maxLen { maxLen = n }
            if minLen == 0 || n < minLen { minLen = n }
        }
        if maxLen == 0 { return h } // empty: any use fails
        var code = 0
        for i in minLen...maxLen { code = (code << 1) + h.count[i] }
        // code after the loop = nextcode-style total; the old core: code != 1<<max && !(code == 1 && max == 1) → reject
        if code != 1 << maxLen && !(code == 1 && maxLen == 1) { return nil }
        h.empty = false
        // o[len] = number of symbols with shorter codes
        var o = [Int](repeating: 0, count: 17)
        for len in 1...15 { o[len + 1] = o[len] + h.count[len] }
        h.symbol = [Int](repeating: 0, count: lengths.count)
        var next = o
        for (k, n) in lengths.enumerated() where n != 0 {
            h.symbol[next[n]] = k
            next[n] += 1
        }
        h.symbol = Array(h.symbol.prefix(o[16]))
        return h
    }

    /// One symbol, bit by bit (input bytes are taken only when the code needs their bits, as in the old core's huffSym).
    private mutating func decode(_ h: Huffman) throws -> Int {
        if h.empty { throw Corrupt() }
        var code = 0, first = 0, index = 0
        for len in 1...15 {
            code |= try bits(1)
            let count = h.count[len]
            if code - count < first { return h.symbol[index + (code - first)] }
            index += count
            first += count
            first <<= 1
            code <<= 1
        }
        throw Corrupt() // unused code of a degenerate / incomplete tree
    }

    private static let lenBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    private static let lenExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
    private static let distBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
                                   4097, 6145, 8193, 12289, 16385, 24577]
    private static let distExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
    private static let fixedLit: Huffman = {
        var l = [Int](repeating: 8, count: 288)
        for i in 144..<256 { l[i] = 9 }
        for i in 256..<280 { l[i] = 7 }
        return build(l[...])!
    }()

    private mutating func emit(_ c: UInt8) throws {
        if out.count >= limit { throw TooLarge() }
        out.append(c)
    }

    private mutating func codes(_ lit: Huffman, _ dist: Huffman?) throws {
        while true {
            let sym = try decode(lit)
            if sym < 256 { try emit(UInt8(sym)); continue }
            if sym == 256 { return }
            let li = sym - 257
            guard li < 29 else { throw Corrupt() } // 286, 287
            let length = Self.lenBase[li] + (try bits(UInt32(Self.lenExtra[li])))
            let ds: Int
            if let dist {
                ds = try decode(dist)
            } else {
                // fixed: 5 bits, most significant first
                let v = try bits(5)
                var r = 0
                for k in 0..<5 where v & (1 << k) != 0 { r |= 1 << (4 - k) }
                ds = r
            }
            guard ds < 30 else { throw Corrupt() }
            let d = Self.distBase[ds] + (try bits(UInt32(Self.distExtra[ds])))
            guard d <= min(out.count, 32768) else { throw Corrupt() }
            if out.count + length > limit { throw TooLarge() }
            let from = out.count - d
            for k in 0..<length { out.append(out[from + k]) }
        }
    }

    private static let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

    private mutating func dynamic() throws {
        let nlit = try bits(5) + 257
        let ndist = try bits(5) + 1
        let ncode = try bits(4) + 4
        guard nlit <= 286, ndist <= 30 else { throw Corrupt() }
        var cl = [Int](repeating: 0, count: 19)
        for i in 0..<ncode { cl[Self.order[i]] = try bits(3) }
        guard let lencode = Self.build(cl[...]) else { throw Corrupt() }
        var lengths = [Int](repeating: 0, count: nlit + ndist)
        var i = 0
        while i < nlit + ndist {
            let sym = try decode(lencode)
            if sym < 16 { lengths[i] = sym; i += 1; continue }
            var rep = 0, val = 0
            switch sym {
            case 16:
                guard i > 0 else { throw Corrupt() }
                val = lengths[i - 1]; rep = 3 + (try bits(2))
            case 17: rep = 3 + (try bits(3))
            default: rep = 11 + (try bits(7))
            }
            guard i + rep <= nlit + ndist else { throw Corrupt() }
            for _ in 0..<rep { lengths[i] = val; i += 1 }
        }
        guard let lit = Self.build(lengths[0..<nlit]), let dist = Self.build(lengths[nlit...]) else { throw Corrupt() }
        try codes(lit, dist)
    }

    private mutating func stored() throws {
        bitbuf = 0; bitcnt = 0 // discard the rest of the current byte
        guard pos + 4 <= b.count else { throw Corrupt() }
        let n = Int(b[pos]) | Int(b[pos + 1]) << 8
        let nn = Int(b[pos + 2]) | Int(b[pos + 3]) << 8
        pos += 4
        guard UInt16(nn) == ~UInt16(n) else { throw Corrupt() }
        guard pos + n <= b.count else { throw Corrupt() }
        if out.count + n > limit { throw TooLarge() }
        out.append(contentsOf: b[pos..<(pos + n)])
        pos += n
    }

    mutating func run() -> Result {
        do {
            var last = false
            repeat {
                last = try bits(1) == 1
                switch try bits(2) {
                case 0: try stored()
                case 1: try codes(Self.fixedLit, nil)
                case 2: try dynamic()
                default: throw Corrupt()
                }
            } while !last
            return .ok
        } catch is TooLarge {
            return .tooLarge
        } catch {
            return .corrupt
        }
    }
}
