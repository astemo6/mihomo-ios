// Native MitM stage 3 lane s3-h2: HPACK (RFC 7541) for the native HTTP/2 front and its upstream h2 client.
//
// Self-contained (no swift-nio-hpack: NIO is not a dependency and its footprint does not suit the tunnel).
// Header bytes ⇄ String follow the HTTP/1.1 lane exactly (HTTPWire.latin1 / HTTPWire.bytes): ISO-8859-1, one
// scalar per byte, so obs-text survives decode → flow API → encode unchanged.
//
// Limits: the decoder's dynamic table is capped by the size we advertise (SETTINGS_HEADER_TABLE_SIZE, 4096); a
// header list over maxHeaderListSize is still decoded to the end (the table must stay in sync) and then reported
// as .headerListTooLarge, which the connection turns into a stream-level refusal, not a connection error.
// Tests: UnitTests/NativeMitmH2Tests.swift (RFC 7541 Appendix C vectors, the old core hpack cross-check fixtures).

import Foundation

enum HPACKError: Error, Equatable {
    case truncated
    case integerOverflow
    case badIndex(Int)
    case huffman
    case tableSizeUpdate          // larger than allowed, or not at the start of a block
    case headerListTooLarge
}

/// Byte ⇄ String mapping for header fields (= HTTPWire.latin1 / HTTPWire.bytes).
enum H2Text {
    static func string<C: Collection>(_ b: C) -> String where C.Element == UInt8 {
        var ascii = true
        for x in b where x >= 0x80 { ascii = false; break }
        if ascii { return String(decoding: b, as: UTF8.self) }
        var s = String.UnicodeScalarView()
        for x in b { s.append(Unicode.Scalar(x)) }
        return String(s)
    }

    static func bytes(_ s: String) -> [UInt8] {
        var ascii = true
        for u in s.utf8 where u >= 0x80 { ascii = false; break }
        if ascii { return Array(s.utf8) }
        if let d = s.data(using: .isoLatin1) { return [UInt8](d) }
        return Array(s.utf8)
    }

    /// ASCII lowercase (HTTP/2 field names must be lowercase on the wire).
    static func lower(_ s: String) -> String {
        var needs = false
        for u in s.utf8 where u >= 0x41 && u <= 0x5A { needs = true; break }
        if !needs { return s }
        return String(decoding: s.utf8.map { ($0 >= 0x41 && $0 <= 0x5A) ? $0 + 32 : $0 }, as: UTF8.self)
    }

    /// Size of a field for the dynamic table / header list accounting (RFC 7541 §4.1).
    static func entrySize(_ name: String, _ value: String) -> Int { bytes(name).count + bytes(value).count + 32 }
}

// MARK: - Huffman

enum HPACKHuffman {
    /// Decode tree: node n has children at tree[2n] (bit 0) and tree[2n+1] (bit 1); a value > 0 is a node
    /// index, < 0 a leaf -(symbol+1), 0 unset (the root is never a child).
    private static let tree: [Int32] = {
        var t: [Int32] = [0, 0]
        for sym in 0..<257 {
            // selfreview-g2: the shared RFC 7541 table (NCHPACK; the duplicate HPACKHuffmanTable is gone).
            let code = sym < 256 ? NCHPACK.huffmanCodes[sym] : NCHPACK.huffmanEOSCode
            let len = Int(sym < 256 ? NCHPACK.huffmanCodeLens[sym] : NCHPACK.huffmanEOSLen)
            var node = 0
            var i = len - 1
            while i >= 0 {
                let bit = Int((code >> UInt32(i)) & 1)
                let slot = 2 * node + bit
                if i == 0 {
                    t[slot] = -Int32(sym + 1)
                } else {
                    if t[slot] == 0 {
                        t.append(0); t.append(0)
                        t[slot] = Int32(t.count / 2 - 1)
                    }
                    node = Int(t[slot])
                }
                i -= 1
            }
        }
        return t
    }()

    static func decode<C: Collection>(_ input: C) throws -> [UInt8] where C.Element == UInt8 {
        let t = tree
        var out: [UInt8] = []
        out.reserveCapacity(input.count * 8 / 5)
        var node = 0
        var pending = 0          // bits since the last complete symbol
        var allOnes = true
        for byte in input {
            var i = 7
            while i >= 0 {
                let bit = Int((byte >> UInt8(i)) & 1)
                let v = t[2 * node + bit]
                if v < 0 {
                    let sym = Int(-v - 1)
                    if sym == 256 { throw HPACKError.huffman } // EOS inside a string
                    out.append(UInt8(sym))
                    node = 0; pending = 0; allOnes = true
                } else if v == 0 {
                    throw HPACKError.huffman
                } else {
                    node = Int(v); pending += 1
                    if bit == 0 { allOnes = false }
                }
                i -= 1
            }
        }
        // Padding: fewer than 8 bits, all ones (a prefix of EOS).
        if pending > 7 || !allOnes { throw HPACKError.huffman }
        return out
    }

    static func encodedLength(_ s: [UInt8]) -> Int {
        var bits = 0
        for b in s { bits += Int(NCHPACK.huffmanCodeLens[Int(b)]) }
        return (bits + 7) / 8
    }

    static func encode(_ s: [UInt8], into out: inout [UInt8]) {
        var acc: UInt64 = 0
        var n = 0
        for b in s {
            let l = Int(NCHPACK.huffmanCodeLens[Int(b)])
            acc = (acc << UInt64(l)) | UInt64(NCHPACK.huffmanCodes[Int(b)])
            n += l
            while n >= 8 {
                n -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> UInt64(n)))
            }
            acc &= (UInt64(1) << UInt64(n)) - 1
        }
        if n > 0 {
            let pad = 8 - n
            out.append(UInt8(truncatingIfNeeded: (acc << UInt64(pad)) | ((UInt64(1) << UInt64(pad)) - 1)))
        }
    }
}

// MARK: - Integers and strings (RFC 7541 §5)

enum HPACKPrimitive {
    static func encodeInt(_ v: Int, prefix: Int, flags: UInt8, into out: inout [UInt8]) {
        let maxP = (1 << prefix) - 1
        if v < maxP { out.append(flags | UInt8(v)); return }
        out.append(flags | UInt8(maxP))
        var r = v - maxP
        while r >= 128 {
            out.append(UInt8(r % 128 + 128))
            r /= 128
        }
        out.append(UInt8(r))
    }

    static func decodeInt(_ b: [UInt8], _ i: inout Int, prefix: Int) throws -> Int {
        guard i < b.count else { throw HPACKError.truncated }
        let maxP = (1 << prefix) - 1
        var v = Int(b[i]) & maxP
        i += 1
        if v < maxP { return v }
        var m = 0
        while true {
            guard i < b.count else { throw HPACKError.truncated }
            let x = b[i]
            i += 1
            v += Int(x & 0x7f) << m
            m += 7
            if x & 0x80 == 0 { break }
            if m > 28 { throw HPACKError.integerOverflow }
        }
        return v
    }

    static func decodeString(_ b: [UInt8], _ i: inout Int) throws -> [UInt8] {
        guard i < b.count else { throw HPACKError.truncated }
        let huff = b[i] & 0x80 != 0
        let n = try decodeInt(b, &i, prefix: 7)
        guard n <= b.count - i else { throw HPACKError.truncated }
        let slice = b[i..<(i + n)]
        i += n
        return huff ? try HPACKHuffman.decode(slice) : Array(slice)
    }

    static func encodeString(_ s: [UInt8], huffman: Bool, into out: inout [UInt8]) {
        if huffman {
            encodeInt(HPACKHuffman.encodedLength(s), prefix: 7, flags: 0x80, into: &out)
            HPACKHuffman.encode(s, into: &out)
        } else {
            encodeInt(s.count, prefix: 7, flags: 0, into: &out)
            out.append(contentsOf: s)
        }
    }
}

// MARK: - Tables

enum HPACKStaticTable {
    static let entries: [(name: String, value: String)] = [
        (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"),
        (":scheme", "http"), (":scheme", "https"), (":status", "200"), (":status", "204"), (":status", "206"),
        (":status", "304"), (":status", "400"), (":status", "404"), (":status", "500"), ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
        ("access-control-allow-origin", ""), ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
        ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
        ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
        ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""),
        ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
        ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
        ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""),
        ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
        ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
    ]
    /// "name\u{0}value" → 1-based index; name → first 1-based index.
    static let exact: [String: Int] = {
        var m: [String: Int] = [:]
        for (i, e) in entries.enumerated() where m[e.name + "\u{0}" + e.value] == nil { m[e.name + "\u{0}" + e.value] = i + 1 }
        return m
    }()
    static let names: [String: Int] = {
        var m: [String: Int] = [:]
        for (i, e) in entries.enumerated() where m[e.name] == nil { m[e.name] = i + 1 }
        return m
    }()
}

struct HPACKDynamicTable {
    /// Newest first: HPACK index 62 is entries[0].
    private(set) var entries: [(name: String, value: String, size: Int)] = []
    private(set) var size = 0
    private(set) var maxSize: Int

    init(maxSize: Int) { self.maxSize = maxSize }

    mutating func setMaxSize(_ n: Int) {
        maxSize = n
        evict(toFit: 0)
    }

    mutating func add(_ name: String, _ value: String) {
        let s = H2Text.entrySize(name, value)
        if s > maxSize { entries.removeAll(); size = 0; return }
        evict(toFit: s)
        entries.insert((name, value, s), at: 0)
        size += s
    }

    private mutating func evict(toFit s: Int) {
        while size + s > maxSize, let last = entries.popLast() { size -= last.size }
    }

    func lookup(_ index: Int) -> (name: String, value: String)? {
        if index >= 1 && index <= HPACKStaticTable.entries.count { return HPACKStaticTable.entries[index - 1] }
        let d = index - HPACKStaticTable.entries.count - 1
        guard d >= 0 && d < entries.count else { return nil }
        return (entries[d].name, entries[d].value)
    }
}

// MARK: - Decoder

final class HPACKDecoder {
    private(set) var table: HPACKDynamicTable
    /// The table size we advertised (SETTINGS_HEADER_TABLE_SIZE): the peer's size updates may not exceed it.
    var maxAllowedTableSize: Int
    var maxHeaderListSize: Int

    init(maxTableSize: Int = 4096, maxHeaderListSize: Int = 64 << 10) {
        table = HPACKDynamicTable(maxSize: maxTableSize)
        maxAllowedTableSize = maxTableSize
        self.maxHeaderListSize = maxHeaderListSize
    }

    func decode(_ block: [UInt8]) throws -> HTTPHeaderList {
        var out: HTTPHeaderList = []
        var i = 0
        var listSize = 0
        var tooLarge = false
        var sawField = false
        func emit(_ name: String, _ value: String) {
            listSize += H2Text.entrySize(name, value)
            if listSize > maxHeaderListSize { tooLarge = true }
            if !tooLarge { out.append((name, value)) }
            sawField = true
        }
        while i < block.count {
            let b = block[i]
            if b & 0x80 != 0 {                                  // indexed field
                let idx = try HPACKPrimitive.decodeInt(block, &i, prefix: 7)
                guard idx > 0, let e = table.lookup(idx) else { throw HPACKError.badIndex(idx) }
                emit(e.name, e.value)
            } else if b & 0xC0 == 0x40 {                        // literal with incremental indexing
                let (n, v) = try literal(block, &i, prefix: 6)
                table.add(n, v)
                emit(n, v)
            } else if b & 0xE0 == 0x20 {                        // dynamic table size update
                if sawField { throw HPACKError.tableSizeUpdate }
                let n = try HPACKPrimitive.decodeInt(block, &i, prefix: 5)
                guard n <= maxAllowedTableSize else { throw HPACKError.tableSizeUpdate }
                table.setMaxSize(n)
            } else {                                            // literal without indexing / never indexed
                let (n, v) = try literal(block, &i, prefix: 4)
                emit(n, v)
            }
        }
        if tooLarge { throw HPACKError.headerListTooLarge }
        return out
    }

    private func literal(_ b: [UInt8], _ i: inout Int, prefix: Int) throws -> (String, String) {
        let idx = try HPACKPrimitive.decodeInt(b, &i, prefix: prefix)
        let name: String
        if idx == 0 {
            name = H2Text.string(try HPACKPrimitive.decodeString(b, &i))
        } else {
            guard let e = table.lookup(idx) else { throw HPACKError.badIndex(idx) }
            name = e.name
        }
        let value = H2Text.string(try HPACKPrimitive.decodeString(b, &i))
        return (name, value)
    }
}

// MARK: - Encoder

final class HPACKEncoder {
    enum Huffman { case never, always, shorter }
    var huffman: Huffman = .shorter
    /// Literal with incremental indexing for fields that fit (RFC 7541 Appendix C style); false: never index.
    var useIndexing = true
    /// Fields encoded as never-indexed literals (credentials).
    var neverIndex: Set<String> = ["authorization", "proxy-authorization"]
    private(set) var table: HPACKDynamicTable
    /// Our own cap on the encoder table regardless of what the peer allows (memory).
    let maxOwnTableSize: Int
    private var pendingMin: Int?
    private var pendingFinal: Int?

    init(maxTableSize: Int = 4096) {
        maxOwnTableSize = maxTableSize
        table = HPACKDynamicTable(maxSize: maxTableSize)
    }

    /// The peer's SETTINGS_HEADER_TABLE_SIZE; the change is signalled at the start of the next block.
    func setPeerMaxTableSize(_ peer: Int) {
        let n = min(peer, maxOwnTableSize)
        if n == table.maxSize && pendingFinal == nil { return }
        pendingMin = min(pendingMin ?? n, n)
        pendingFinal = n
    }

    func encode(_ fields: HTTPHeaderList) -> [UInt8] {
        var out: [UInt8] = []
        if let f = pendingFinal {
            if let m = pendingMin, m < f {
                HPACKPrimitive.encodeInt(m, prefix: 5, flags: 0x20, into: &out)
                table.setMaxSize(m)
            }
            HPACKPrimitive.encodeInt(f, prefix: 5, flags: 0x20, into: &out)
            table.setMaxSize(f)
            pendingMin = nil
            pendingFinal = nil
        }
        for (name, value) in fields { encodeField(name, value, into: &out) }
        return out
    }

    private func encodeField(_ name: String, _ value: String, into out: inout [UInt8]) {
        let never = neverIndex.contains(name)
        if !never {
            if let i = HPACKStaticTable.exact[name + "\u{0}" + value] {
                HPACKPrimitive.encodeInt(i, prefix: 7, flags: 0x80, into: &out); return
            }
            if let d = table.entries.firstIndex(where: { $0.name == name && $0.value == value }) {
                HPACKPrimitive.encodeInt(HPACKStaticTable.entries.count + 1 + d, prefix: 7, flags: 0x80, into: &out); return
            }
        }
        var nameIndex = HPACKStaticTable.names[name] ?? 0
        if nameIndex == 0, let d = table.entries.firstIndex(where: { $0.name == name }) {
            nameIndex = HPACKStaticTable.entries.count + 1 + d
        }
        let index = !never && useIndexing && H2Text.entrySize(name, value) <= table.maxSize
        if never {
            HPACKPrimitive.encodeInt(nameIndex, prefix: 4, flags: 0x10, into: &out)
        } else if index {
            HPACKPrimitive.encodeInt(nameIndex, prefix: 6, flags: 0x40, into: &out)
        } else {
            HPACKPrimitive.encodeInt(nameIndex, prefix: 4, flags: 0x00, into: &out)
        }
        if nameIndex == 0 { putString(H2Text.bytes(name), into: &out) }
        putString(H2Text.bytes(value), into: &out)
        if index { table.add(name, value) }
    }

    private func putString(_ s: [UInt8], into out: inout [UInt8]) {
        let h: Bool
        switch huffman {
        case .never: h = false
        case .always: h = true
        case .shorter: h = HPACKHuffman.encodedLength(s) < s.count
        }
        HPACKPrimitive.encodeString(s, huffman: h, into: &out)
    }
}
