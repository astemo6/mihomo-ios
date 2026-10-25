import Foundation

/// Mihomo Rule Set (.mrs) binary format decoder.
///
/// Specification reference:
/// - MetaCubeX/mihomo rules/provider/mrs_reader.go (MrsMagicBytes, rulesMrsParse)
/// - MetaCubeX/mihomo rules/provider/mrs_converter.go (ConvertToMrs)
/// - MetaCubeX/mihomo constant/provider/interface.go (RuleBehavior, RuleFormat)
/// - MetaCubeX/mihomo component/trie/domain_set_bin.go & domain_set.go (DomainSet binary)
/// - MetaCubeX/mihomo component/cidr/ipcidr_set_bin.go & ipcidr_set.go (IpCidrSet binary)
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

    /// Zstandard frame header magic: 0xFD2FB528 (little-endian: 0x28, 0xB5, 0x2F, 0xFD)
    static let zstdMagic: [UInt8] = [0x28, 0xB5, 0x2F, 0xFD]

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
/// Matches Mihomo's `component/trie/domain_set.go` and `domain_set_bin.go`.
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

    /// Traverse the trie and emit decoded domain patterns.
    /// Internal keys are reversed; keys ending in '+' denote suffix patterns.
    func forEachPattern(_ callback: (String) -> Void) {
        var currentKey = [UInt8]()
        func traverse(nodeId: Int, bmIdx0: Int) {
            if Self.getBit(leaves, nodeId) {
                if !currentKey.isEmpty {
                    var k = currentKey
                    if k.last == 0x2B { // '+'
                        k.removeLast()
                    }
                    let pattern = String(decoding: k.reversed(), as: UTF8.self)
                    callback(pattern)
                }
            }

            var bmIdx = bmIdx0
            while true {
                if Self.getBit(labelBitmap, bmIdx) {
                    return
                }
                let labelIdx = bmIdx - nodeId
                guard labelIdx < labels.count else { return }
                let nextLabel = labels[labelIdx]
                currentKey.append(nextLabel)
                let nextNodeId = bmIdx - nodeId + 1
                guard nextNodeId - 1 < oneIndices.count else {
                    currentKey.removeLast()
                    return
                }
                let nextBmIdx = oneIndices[nextNodeId - 1] + 1
                traverse(nodeId: nextNodeId, bmIdx0: nextBmIdx)
                currentKey.removeLast()
                bmIdx += 1
            }
        }

        traverse(nodeId: 0, bmIdx0: 0)
    }
}

// Placeholder for IPCIDR set (completed in next step)
struct NCMRSIPCIDRSet: Equatable {
    let ruleCount: Int
    static func decode(reader: inout NCMRSByteReader, ruleCount: Int) throws -> NCMRSIPCIDRSet {
        return NCMRSIPCIDRSet(ruleCount: ruleCount)
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
        guard count >= 0, offset + count <= data.count else {
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
