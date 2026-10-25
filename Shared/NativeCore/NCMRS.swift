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
