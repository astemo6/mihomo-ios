import Foundation

/// HPACK (RFC 7541): enough for tunnel clients — literal encoding without
/// Huffman on the way out; full decoding (indexed / literal / dynamic
/// table / Huffman strings) for server header blocks. Huffman tables
/// generated from golang.org/x/net/http2/hpack (RFC 7541 Appendix B).
enum NCHPACK {
    static let staticTable: [(String, String)] = [
        (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
        (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
        (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
        (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
        ("accept-language", ""), ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
        ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
        ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
        ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
        ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
        ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
        ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
        ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
        ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""),
        ("retry-after", ""), ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""),
        ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
        ("www-authenticate", ""),
    ]

    // MARK: integers & strings

    static func encodeInteger(_ value: Int, prefixBits: Int, firstByte: UInt8) -> Data {
        var out = Data()
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            out.append(firstByte | UInt8(value))
            return out
        }
        out.append(firstByte | UInt8(maxPrefix))
        var v = value - maxPrefix
        while v >= 128 {
            out.append(UInt8((v % 128) + 128))
            v /= 128
        }
        out.append(UInt8(v))
        return out
    }

    static func encodeString(_ s: String) -> Data {
        let bytes = Data(s.utf8)
        var out = encodeInteger(bytes.count, prefixBits: 7, firstByte: 0)
        out.append(bytes)
        return out
    }

    /// One header field: Indexed when the static table has the exact
    /// name+value, otherwise Literal Without Indexing.
    static func encodeHeader(name: String, value: String) -> Data {
        if let idx = staticTable.firstIndex(where: { $0.0 == name && $0.1 == value && !value.isEmpty }) {
            return encodeInteger(idx + 1, prefixBits: 7, firstByte: 0x80)
        }
        var out = Data()
        if let idx = staticTable.firstIndex(where: { $0.0 == name }) {
            out.append(encodeInteger(idx + 1, prefixBits: 4, firstByte: 0x00))
        } else {
            out.append(encodeInteger(0, prefixBits: 4, firstByte: 0x00))
            out.append(encodeString(name))
        }
        out.append(encodeString(value))
        return out
    }

    static func encodeHeaders(_ headers: [(String, String)]) -> Data {
        var out = Data()
        for (name, value) in headers { out.append(encodeHeader(name: name, value: value)) }
        return out
    }
}

/// Stateful HPACK decoder (dynamic table persists across blocks on one
/// connection, as the spec requires).
final class NCHPACKDecoder {
    private var dynamic: [(String, String)] = [] // newest first
    private var dynamicSize = 0
    /// SETTINGS_HEADER_TABLE_SIZE we advertise: we never send one, so the RFC 7541 default 4096 bounds every
    /// dynamic table size update the peer's encoder may send (fix/nc-h2-cidr). 需同步 feat/nc-kernel.
    static let settingsMaxDynamicSize = 4096
    private var maxDynamicSize = NCHPACKDecoder.settingsMaxDynamicSize

    func entry(_ index: Int) -> (String, String)? {
        if index >= 1 && index <= NCHPACK.staticTable.count {
            return NCHPACK.staticTable[index - 1]
        }
        let dyn = index - NCHPACK.staticTable.count - 1
        guard dyn >= 0 && dyn < dynamic.count else { return nil }
        return dynamic[dyn]
    }

    private func insert(_ e: (String, String)) {
        dynamic.insert(e, at: 0)
        dynamicSize += e.0.utf8.count + e.1.utf8.count + 32
        evict()
    }

    /// RFC 7541 §4.4: evict oldest until the table fits (an entry larger than the limit empties the table).
    private func evict() {
        while dynamicSize > maxDynamicSize, let last = dynamic.last {
            dynamic.removeLast()
            dynamicSize -= last.0.utf8.count + last.1.utf8.count + 32
        }
    }

    /// Decode a full header block; nil on malformed input.
    func decode(_ block: Data) -> [(String, String)]? {
        var reader = Reader(block)
        var out: [(String, String)] = []
        while !reader.atEnd {
            guard let first = reader.peek() else { return nil }
            if first & 0x80 != 0 { // indexed
                guard let idx = reader.integer(prefixBits: 7), idx > 0, let e = entry(idx) else { return nil }
                out.append(e)
            } else if first & 0xc0 == 0x40 { // literal, incremental indexing
                guard let e = readLiteral(&reader, prefixBits: 6) else { return nil }
                insert(e)
                out.append(e)
            } else if first & 0xe0 == 0x20 { // dynamic table size update
                // §6.3: the new limit must not exceed our SETTINGS_HEADER_TABLE_SIZE; it applies at once
                // (was read and ignored, so a peer shrinking its table could index entries we never evicted).
                guard let size = reader.integer(prefixBits: 5),
                      size <= NCHPACKDecoder.settingsMaxDynamicSize else { return nil }
                maxDynamicSize = size
                evict()
            } else { // literal without / never indexing (0000xxxx / 0001xxxx)
                guard let e = readLiteral(&reader, prefixBits: 4) else { return nil }
                out.append(e)
            }
        }
        return out
    }

    private func readLiteral(_ reader: inout Reader, prefixBits: Int) -> (String, String)? {
        guard let nameIndex = reader.integer(prefixBits: prefixBits) else { return nil }
        let name: String
        if nameIndex == 0 {
            guard let s = reader.string() else { return nil }
            name = s
        } else {
            guard let e = entry(nameIndex) else { return nil }
            name = e.0
        }
        guard let value = reader.string() else { return nil }
        return (name, value)
    }

    struct Reader {
        let data: Data
        var pos = 0
        init(_ data: Data) { self.data = data }
        var atEnd: Bool { pos >= data.count }
        func peek() -> UInt8? { pos < data.count ? data[data.startIndex + pos] : nil }

        mutating func integer(prefixBits: Int) -> Int? {
            guard let first = peek() else { return nil }
            pos += 1
            let maxPrefix = (1 << prefixBits) - 1
            var value = Int(first) & maxPrefix
            if value < maxPrefix { return value }
            var shift = 0
            while true {
                guard let b = peek() else { return nil }
                pos += 1
                value += Int(b & 0x7f) << shift
                shift += 7
                if b & 0x80 == 0 { break }
                if shift > 28 { return nil }
            }
            return value
        }

        mutating func string() -> String? {
            guard let first = peek() else { return nil }
            let huffman = first & 0x80 != 0
            guard let len = integer(prefixBits: 7) else { return nil }
            guard pos + len <= data.count else { return nil }
            let raw = Data(data[(data.startIndex + pos)..<(data.startIndex + pos + len)])
            pos += len
            if huffman {
                guard let decoded = NCHPACK.huffmanDecode(raw) else { return nil }
                return String(decoding: decoded, as: UTF8.self)
            }
            return String(decoding: raw, as: UTF8.self)
        }
    }
}

private var huffmanLookupCache: [UInt64: UInt8] = [:]

extension NCHPACK {
    static let huffmanCodes: [UInt32] = [
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    ]
    static let huffmanCodeLens: [UInt8] = [
        13, 23, 28, 28, 28, 28, 28, 28,
        28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11,
        10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6,
        6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6,
        6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7,
        7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23,
        22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23,
        23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23,
        20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25,
        26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23,
        22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27,
        27, 28, 27, 27, 27, 27, 27, 26,
    ]

    /// Bit-by-bit Huffman decode (blocks are small; clarity over speed).
    /// Trailing EOS padding (all-ones prefix) is tolerated.
    static func huffmanDecode(_ data: Data) -> Data? {
        if huffmanLookupCache.isEmpty {
            for (sym, code) in huffmanCodes.enumerated() {
                huffmanLookupCache[(UInt64(huffmanCodeLens[sym]) << 32) | UInt64(code)] = UInt8(sym)
            }
        }
        let lookup = huffmanLookupCache
        var out = Data()
        var cur: UInt32 = 0
        var curLen: UInt8 = 0
        for byte in data {
            var bits = 8
            while bits > 0 {
                bits -= 1
                cur = (cur << 1) | UInt32((byte >> bits) & 1)
                curLen += 1
                if let sym = lookup[(UInt64(curLen) << 32) | UInt64(cur)] {
                    out.append(sym)
                    cur = 0
                    curLen = 0
                } else if curLen > 30 {
                    return nil
                }
            }
        }
        if curLen > 0 {
            let ones = (UInt32(1) << curLen) - 1
            guard cur == ones else { return nil }
        }
        return out
    }
}
