import Foundation

/// Tern Rule Set (.mrs) binary format decoder.
///
/// Specification reference:
/// - upstream Clash.Meta rules/provider/mrs_reader (MrsMagicBytes, rulesMrsParse)
/// - upstream Clash.Meta rules/provider/mrs_converter (ConvertToMrs)
/// - upstream Clash.Meta constant/provider/interface (RuleBehavior, RuleFormat)
/// - upstream Clash.Meta component/trie/domain_set_bin & domain_set (DomainSet binary)
/// - upstream Clash.Meta component/cidr/ipcidr_set_bin & ipcidr_set (IpCidrSet binary)
///
/// Wire / File Structure:
/// 1. Outer compression: Zstandard (RFC 8878, magic 0xFD2FB528 / [0x28, 0xB5, 0x2F, 0xFD]).
/// 2. Uncompressed payload:
///    - Header:
///      - Magic: 4 bytes `['M', 'R', 'S', 0x01]` (ASCII "MRS" + version 1)
///      - Behavior: 1 byte (0: Domain, 1: IPCIDR, 2: Classical)
///      - Count: Int64 Big-Endian (number of rules)
///      - Extra length: Int64 Big-Endian (reserved for future use)
///      - Extra data: `extraLength` bytes
///    - Body:
///      - Domain: version (1 byte = 1) + leaves + labelBitmap + labels
///      - IPCIDR: version (1 byte = 1) + rr ranges count + ranges (from: 16B, to: 16B)

enum NCMRSBehavior: UInt8, Equatable {
    case domain = 0
    case ipcidr = 1
    case classical = 2

    var name: String {
        switch self {
        case .domain: return "domain"
        case .ipcidr: return "ipcidr"
        case .classical: return "classical"
        }
    }
}

enum NCMRSError: Error, CustomStringConvertible, Equatable {
    case invalidMagic
    case unsupportedZstandard
    case invalidBehavior(UInt8)
    case unsupportedBehavior(String)
    case invalidCount(Int64)
    case invalidExtraLength(Int64)
    case invalidVersion(UInt8)
    case truncated(String)
    case corrupted(String)

    var description: String {
        switch self {
        case .invalidMagic:
            return "NCMRSError: invalid MRS magic bytes (expected 'MRS\\x01')"
        case .unsupportedZstandard:
            return "NCMRSError: MRS payload is compressed with Zstandard (magic 0xFD2FB528); Swift standard library and Apple Compression framework lack zstd decompression support"
        case .invalidBehavior(let b):
            return "NCMRSError: invalid or unknown MRS behavior byte: \(b)"
        case .unsupportedBehavior(let s):
            return "NCMRSError: unsupported MRS behavior: \(s) (only domain and ipcidr are supported)"
        case .invalidCount(let c):
            return "NCMRSError: invalid MRS rule count: \(c)"
        case .invalidExtraLength(let l):
            return "NCMRSError: invalid MRS extra length: \(l)"
        case .invalidVersion(let v):
            return "NCMRSError: invalid payload version: \(v) (expected 1)"
        case .truncated(let msg):
            return "NCMRSError: truncated MRS data: \(msg)"
        case .corrupted(let msg):
            return "NCMRSError: corrupted MRS data: \(msg)"
        }
    }
}

struct NCMRSHeader: Equatable {
    let behavior: NCMRSBehavior
    let count: Int
    let extra: Data
    let payloadOffset: Int
}

enum NCMRS {
    /// MRS container magic bytes: 'M', 'R', 'S', 0x01
    static let mrsMagic: [UInt8] = [0x4D, 0x52, 0x53, 0x01]

    /// Optional pluggable decompressor hook for environments with zstd available.
    /// If unset and zstd-compressed data is fed, an explicit `.unsupportedZstandard` error is thrown.
    static var decompressor: ((Data) throws -> Data)? = nil

    /// Detect whether data has a Zstandard frame header.
    static func isZstandard(data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let s = data.startIndex
        return data[s] == 0x28 && data[s + 1] == 0xB5 && data[s + 2] == 0x2F && data[s + 3] == 0xFD
    }

    /// Detect whether data has MRS magic (either uncompressed or zstd-wrapped).
    static func isMRS(data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let s = data.startIndex
        if data[s] == 0x4D && data[s + 1] == 0x52 && data[s + 2] == 0x53 && data[s + 3] == 0x01 {
            return true
        }
        return isZstandard(data: data)
    }

    /// Ensure data is uncompressed MRS payload, decompressing via `decompressor` if zstd,
    /// or throwing `.unsupportedZstandard` if zstd and no decompressor is registered.
    static func uncompressedData(_ rawData: Data) throws -> Data {
        if isZstandard(data: rawData) {
            guard let decompressor = decompressor else {
                throw NCMRSError.unsupportedZstandard
            }
            return try decompressor(rawData)
        }
        return rawData
    }

    /// Parse MRS container header.
    static func parseHeader(from data: Data) throws -> (header: NCMRSHeader, reader: NCMRSByteReader) {
        var reader = NCMRSByteReader(data: data)
        let magic = try reader.readBytes(4)
        guard magic.elementsEqual(mrsMagic) else {
            throw NCMRSError.invalidMagic
        }
        let behaviorByte = try reader.readByte()
        guard let behavior = NCMRSBehavior(rawValue: behaviorByte) else {
            throw NCMRSError.invalidBehavior(behaviorByte)
        }
        let count = try reader.readInt64BE()
        guard count >= 0 else {
            throw NCMRSError.invalidCount(count)
        }
        let extraLength = try reader.readInt64BE()
        guard extraLength >= 0 else {
            throw NCMRSError.invalidExtraLength(extraLength)
        }
        let extra = try reader.readBytes(Int(extraLength))
        let header = NCMRSHeader(
            behavior: behavior,
            count: Int(count),
            extra: extra,
            payloadOffset: reader.offset
        )
        return (header, reader)
    }

    /// Decode MRS data into either a DomainSet or IPCIDRSet.
    static func decode(data rawData: Data, expectedBehavior: String? = nil) throws -> NCMRSDecodedPayload {
        let uncompressed = try uncompressedData(rawData)
        var (header, reader) = try parseHeader(from: uncompressed)

        if let expected = expectedBehavior?.lowercased(), !expected.isEmpty {
            switch expected {
            case "domain":
                guard header.behavior == .domain else {
                    throw NCMRSError.unsupportedBehavior("expected domain behavior but MRS file has \(header.behavior.name)")
                }
            case "ipcidr":
                guard header.behavior == .ipcidr else {
                    throw NCMRSError.unsupportedBehavior("expected ipcidr behavior but MRS file has \(header.behavior.name)")
                }
            default:
                break
            }
        }

        switch header.behavior {
        case .domain:
            let domainSet = try NCMRSDomainSet.decode(reader: &reader, ruleCount: header.count)
            return .domain(domainSet)
        case .ipcidr:
            let ipcidrSet = try NCMRSIPCIDRSet.decode(reader: &reader, ruleCount: header.count)
            return .ipcidr(ipcidrSet)
        case .classical:
            throw NCMRSError.unsupportedBehavior("classical behavior is not supported in MRS format")
        }
    }
}

enum NCMRSDecodedPayload {
    case domain(NCMRSDomainSet)
    case ipcidr(NCMRSIPCIDRSet)

    var count: Int {
        switch self {
        case .domain(let d): return d.ruleCount
        case .ipcidr(let i): return i.ruleCount
        }
    }
}

// MARK: - Domain Set (Behavior: domain)

/// Succinct trie representation of domain patterns decoded from MRS domain behavior.
/// Matches Clash.Meta's `component/trie/domain_set` and `domain_set_bin`.
struct NCMRSDomainSet: Equatable {
    let leaves: [UInt64]
    let labelBitmap: [UInt64]
    let labels: [UInt8]
    let oneIndices: [Int]
    let ruleCount: Int

    static func decode(reader: inout NCMRSByteReader, ruleCount: Int) throws -> NCMRSDomainSet {
        let version = try reader.readByte()
        guard version == 1 else {
            throw NCMRSError.invalidVersion(version)
        }

        // leaves
        let leavesLen = try reader.readInt64BE()
        guard leavesLen >= 1 else {
            throw NCMRSError.corrupted("leaves length must be >= 1, got \(leavesLen)")
        }
        // Each entry is 8 bytes: a length the file cannot hold is corrupt. Checked before reserveCapacity, which
        // aborted the process on a hostile 2^60 length (allocation failure) from a downloaded rule set.
        guard leavesLen <= Int64(reader.remaining / 8) else {
            throw NCMRSError.truncated("leaves length \(leavesLen) exceeds the remaining data")
        }
        var leaves = [UInt64]()
        leaves.reserveCapacity(Int(leavesLen))
        for _ in 0..<leavesLen {
            leaves.append(try reader.readUInt64BE())
        }

        // labelBitmap
        let bmLen = try reader.readInt64BE()
        guard bmLen >= 1 else {
            throw NCMRSError.corrupted("labelBitmap length must be >= 1, got \(bmLen)")
        }
        guard bmLen <= Int64(reader.remaining / 8) else {
            throw NCMRSError.truncated("labelBitmap length \(bmLen) exceeds the remaining data")
        }
        var labelBitmap = [UInt64]()
        labelBitmap.reserveCapacity(Int(bmLen))
        for _ in 0..<bmLen {
            labelBitmap.append(try reader.readUInt64BE())
        }

        // labels
        let labelsLen = try reader.readInt64BE()
        guard labelsLen >= 0 else {
            throw NCMRSError.corrupted("labels length must be >= 0, got \(labelsLen)")
        }
        let labelsData = try reader.readBytes(Int(labelsLen))
        let labels = [UInt8](labelsData)

        // Precompute oneIndices: bit index of each 1 bit in labelBitmap
        var oneIndices = [Int]()
        for wordIdx in 0..<labelBitmap.count {
            let word = labelBitmap[wordIdx]
            if word == 0 { continue }
            for bitIdx in 0..<64 {
                if ((word >> bitIdx) & 1) != 0 {
                    oneIndices.append(wordIdx * 64 + bitIdx)
                }
            }
        }

        return NCMRSDomainSet(
            leaves: leaves,
            labelBitmap: labelBitmap,
            labels: labels,
            oneIndices: oneIndices,
            ruleCount: ruleCount
        )
    }

    private static func getBit(_ bm: [UInt64], _ i: Int) -> Bool {
        let wordIdx = i >> 6
        guard wordIdx < bm.count else { return false }
        return ((bm[wordIdx] >> (i & 63)) & 1) != 0
    }

    /// Query whether a hostname matches the domain set.
    /// Traverses the succinct trie character-by-character from right to left,
    /// evaluating exact domains, suffix wildcards (+.), and single-label wildcards (*).
    func has(_ domain: String) -> Bool {
        let key = [UInt8](domain.lowercased().utf8)
        guard !key.isEmpty else { return false }

        var nodeId = 0
        var bmIdx = 0
        struct WildcardCursor {
            let bmIdx: Int
            let index: Int
        }
        var stack = [WildcardCursor]()

        let complexWildcardByte: UInt8 = 0x2B // '+'
        let wildcardByte: UInt8 = 0x2A        // '*'
        let domainStepByte: UInt8 = 0x2E      // '.'

        var i = 0
        while i < key.count {
            restart: while true {
                let c = key[key.count - 1 - i]
                while true {
                    if Self.getBit(labelBitmap, bmIdx) {
                        // End of edges for this node. Pop any saved wildcard cursors.
                        while !stack.isEmpty {
                            let cursor = stack.removeLast()
                            let nextNodeId = cursor.bmIdx - nodeId + 1
                            var j = cursor.index
                            while j < key.count && key[key.count - 1 - j] != domainStepByte {
                                j += 1
                            }
                            if j == key.count {
                                if Self.getBit(leaves, nextNodeId) {
                                    return true
                                }
                                continue
                            }
                            guard nextNodeId - 1 < oneIndices.count else { continue }
                            var nextBmIdx = oneIndices[nextNodeId - 1] + 1
                            while !Self.getBit(labelBitmap, nextBmIdx) {
                                let labelIdx = nextBmIdx - nextNodeId
                                if labelIdx < labels.count && labels[labelIdx] == domainStepByte {
                                    bmIdx = nextBmIdx
                                    nodeId = nextNodeId
                                    i = j
                                    continue restart
                                }
                                nextBmIdx += 1
                            }
                        }
                        return false
                    }

                    let labelIdx = bmIdx - nodeId
                    guard labelIdx < labels.count else { return false }
                    let label = labels[labelIdx]
                    if label == complexWildcardByte {
                        return true
                    } else if label == wildcardByte {
                        stack.append(WildcardCursor(bmIdx: bmIdx, index: i))
                    } else if label == c {
                        break
                    }
                    bmIdx += 1
                }

                nodeId = bmIdx - nodeId + 1
                if i == key.count - 1 {
                    if Self.getBit(leaves, nodeId) {
                        return true
                    }
                    if stack.isEmpty {
                        return false
                    }
                    guard nodeId < oneIndices.count else { return false }
                    bmIdx = oneIndices[nodeId]
                    continue restart
                }
                guard nodeId - 1 < oneIndices.count else { return false }
                bmIdx = oneIndices[nodeId - 1] + 1
                i += 1
                break
            }
        }

        return Self.getBit(leaves, nodeId)
    }

}

// MARK: - IPCIDR Set (Behavior: ipcidr)

/// IPv4 range [from, to] inclusive.
struct NCV4Range: Equatable {
    let from: UInt32
    let to: UInt32
}

/// 128-bit IPv6 address represented as two UInt64 words for fast arithmetic and register comparison.
struct NCV6Addr: Comparable, Equatable {
    let hi: UInt64
    let lo: UInt64

    init(bytes: [UInt8]) {
        var h: UInt64 = 0
        var l: UInt64 = 0
        for i in 0..<min(8, bytes.count) {
            h = (h << 8) | UInt64(bytes[i])
        }
        for i in 8..<min(16, bytes.count) {
            l = (l << 8) | UInt64(bytes[i])
        }
        self.hi = h
        self.lo = l
    }

    init(hi: UInt64, lo: UInt64) {
        self.hi = hi
        self.lo = lo
    }

    static func < (lhs: NCV6Addr, rhs: NCV6Addr) -> Bool {
        if lhs.hi != rhs.hi {
            return lhs.hi < rhs.hi
        }
        return lhs.lo < rhs.lo
    }
}

/// IPv6 range [from, to] inclusive.
struct NCV6Range: Equatable {
    let from: NCV6Addr
    let to: NCV6Addr
}

/// Range-set representation of IP-CIDR rules decoded from MRS ipcidr behavior.
/// Matches Clash.Meta's `component/cidr/ipcidr_set` and `ipcidr_set_bin`.
struct NCMRSIPCIDRSet: Equatable {
    let v4Ranges: [NCV4Range]
    let v6Ranges: [NCV6Range]
    let ruleCount: Int

    static func decode(reader: inout NCMRSByteReader, ruleCount: Int) throws -> NCMRSIPCIDRSet {
        let version = try reader.readByte()
        guard version == 1 else {
            throw NCMRSError.invalidVersion(version)
        }

        let length = try reader.readInt64BE()
        guard length >= 0 else {
            throw NCMRSError.corrupted("IPCIDR ranges length must be >= 0, got \(length)")
        }

        var v4 = [NCV4Range]()
        var v6 = [NCV6Range]()
        v4.reserveCapacity(Int(min(length, 10000)))
        v6.reserveCapacity(Int(min(length, 10000)))

        for _ in 0..<length {
            let fromData = try reader.readBytes(16)
            let toData = try reader.readBytes(16)

            let fromBytes = [UInt8](fromData)
            let toBytes = [UInt8](toData)

            let fromIsV4Mapped = isV4Mapped(fromBytes)
            let toIsV4Mapped = isV4Mapped(toBytes)

            if fromIsV4Mapped && toIsV4Mapped {
                let fromVal = parseV4UInt32(fromBytes, offset: 12)
                let toVal = parseV4UInt32(toBytes, offset: 12)
                v4.append(NCV4Range(from: min(fromVal, toVal), to: max(fromVal, toVal)))
            } else {
                let fromAddr = NCV6Addr(bytes: fromBytes)
                let toAddr = NCV6Addr(bytes: toBytes)
                if fromAddr < toAddr {
                    v6.append(NCV6Range(from: fromAddr, to: toAddr))
                } else {
                    v6.append(NCV6Range(from: toAddr, to: fromAddr))
                }
            }
        }

        v4.sort { $0.from < $1.from }
        v6.sort { $0.from < $1.from }

        return NCMRSIPCIDRSet(
            v4Ranges: v4,
            v6Ranges: v6,
            ruleCount: ruleCount > 0 ? ruleCount : (v4.count + v6.count)
        )
    }

    private static func isV4Mapped(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        for i in 0..<10 {
            if b[i] != 0 { return false }
        }
        return b[10] == 0xff && b[11] == 0xff
    }

    private static func parseV4UInt32(_ b: [UInt8], offset: Int) -> UInt32 {
        guard offset + 4 <= b.count else { return 0 }
        return (UInt32(b[offset]) << 24) |
               (UInt32(b[offset + 1]) << 16) |
               (UInt32(b[offset + 2]) << 8) |
               UInt32(b[offset + 3])
    }

    func contains(_ ip: NCIP) -> Bool {
        switch ip {
        case .v4(let v):
            return containsV4(v)
        case .v6(let b):
            if Self.isV4Mapped(b) {
                let v = Self.parseV4UInt32(b, offset: 12)
                return containsV4(v)
            }
            return containsV6(NCV6Addr(bytes: b))
        }
    }

    func containsV4(_ val: UInt32) -> Bool {
        var low = 0
        var high = v4Ranges.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let r = v4Ranges[mid]
            if val < r.from {
                high = mid - 1
            } else if val > r.to {
                low = mid + 1
            } else {
                return true
            }
        }
        return false
    }

    func containsV6(_ addr: NCV6Addr) -> Bool {
        var low = 0
        var high = v6Ranges.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let r = v6Ranges[mid]
            if addr < r.from {
                high = mid - 1
            } else if r.to < addr {
                low = mid + 1
            } else {
                return true
            }
        }
        return false
    }
}

/// Helper for reading big-endian binary primitives safely without unaligned access.
struct NCMRSByteReader {
    let data: Data
    private(set) var offset: Int = 0

    init(data: Data, offset: Int = 0) {
        self.data = data
        self.offset = offset
    }

    var remaining: Int { data.count - offset }

    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else {
            throw NCMRSError.truncated("unexpected EOF reading byte at offset \(offset)")
        }
        defer { offset += 1 }
        return data[data.startIndex + offset]
    }

    mutating func readBytes(_ count: Int) throws -> Data {
        // `count <= remaining`, not `offset + count <= data.count`: a hostile Int64.max length overflowed the sum (trap).
        guard count >= 0, count <= data.count - offset else {
            throw NCMRSError.truncated("unexpected EOF reading \(count) bytes at offset \(offset)")
        }
        let slice = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + count))
        offset += count
        return slice
    }

    mutating func readUInt64BE() throws -> UInt64 {
        let b = try readBytes(8)
        var val: UInt64 = 0
        for byte in b {
            val = (val << 8) | UInt64(byte)
        }
        return val
    }

    mutating func readInt64BE() throws -> Int64 {
        let u = try readUInt64BE()
        return Int64(bitPattern: u)
    }
}
