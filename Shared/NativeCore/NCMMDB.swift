import Foundation

/// MaxMind DB reader (the format of geoip.metadb / GeoLite2-Country.mmdb /
/// ASN.mmdb bundled with the app): binary search tree over IP bits, records
/// decoded from the data section (maps, arrays, strings, numbers, booleans,
/// pointers). Lookup only; no network iteration.
final class NCMMDB {
    private let data: Data
    private let nodeCount: Int
    private let recordSize: Int // bits per record (24/28/32)
    private let ipVersion: Int
    private let treeSize: Int
    private let dataStart: Int
    /// fix/nc-0.20.3-geoip: the node an IPv4 lookup starts from in an IPv6 tree — reached by 96 zero bits from the
    /// root (`::a.b.c.d`, the MaxMind spec / libmaxminddb / Go maxminddb-golang `ipv4Start`). 0 for an IPv4 tree.
    private var ipv4Start = 0
    public let buildEpoch: Double?
    public let databaseType: String?

    convenience init?(contentsOfFile path: String) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return nil }
        self.init(data: data)
    }

    init?(data: Data) {
        self.data = data
        // Metadata follows the marker "\xab\xcd\xefMaxMind.com".
        let marker = Data([0xab, 0xcd, 0xef]) + Data("MaxMind.com".utf8)
        guard let markerRange = data.range(of: marker, options: .backwards) else { return nil }
        var decoder = NCMMDBDecoder(data: data, offset: markerRange.upperBound, dataStart: markerRange.upperBound)
        guard let meta = decoder.decode(), case .object(let m) = meta,
              let nodes = m["node_count"]?.int, let recSize = m["record_size"]?.int else { return nil }
        // A malformed / hostile database (it is downloaded from a config URL) must not trap: record sizes other than
        // 24/28/32 are unsupported, and node_count * record_size * 2 used to overflow Int on a huge node_count.
        // The search tree must also fit inside the file, so readRecord never indexes past the end.
        guard nodes > 0, [24, 28, 32].contains(recSize) else { return nil }
        let (bits, o1) = nodes.multipliedReportingOverflow(by: recSize * 2)
        guard !o1, bits / 8 <= data.count - 16 else { return nil }
        nodeCount = nodes
        recordSize = recSize
        ipVersion = m["ip_version"]?.int ?? 6
        treeSize = bits / 8
        dataStart = treeSize + 16 // separator
        buildEpoch = m["build_epoch"]?.number ?? m["build_epoch"]?.int.map(Double.init)
        databaseType = m["database_type"]?.string
        if ipVersion == 6 {
            var node = 0
            var depth = 0
            while depth < 96, node < nodeCount {
                node = readRecord(node: node, index: 0)
                depth += 1
            }
            ipv4Start = node
        }
    }

    /// Raw record for an IP, if any network covers it.
    ///
    /// fix/nc-0.20.3-geoip: IPv4 used to be walked as `::ffff:a.b.c.d` through the IPv6 tree. MaxMind's own GeoLite2
    /// aliases ::ffff:0:0/96 onto the IPv4 subtree, so that worked there — but MetaCubeX `geoip.metadb` (Meta-geoip0)
    /// has no such alias: every IPv4 lookup hit an empty node at bit 80 and returned nil, so `GEOIP,cn` never matched
    /// and CN traffic fell through to the final (proxy) rule. IPv4 now starts at `ipv4Start` (the `::a.b.c.d`
    /// subtree), exactly like libmaxminddb / maxminddb-golang, which Clash.Meta uses.
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, which NCIP keeps as .v6) is looked up as its IPv4 address, as
    /// maxminddb-golang does (`ip.To4() != nil`).
    func lookup(_ ip: NCIP) -> NCJSONValue? {
        var bytes = ip.bytes
        if bytes.count == 16, bytes[10] == 0xff, bytes[11] == 0xff, bytes[0..<10].allSatisfy({ $0 == 0 }) {
            bytes = Array(bytes[12..<16])
        }
        var node: Int
        let bitCount: Int
        switch bytes.count {
        case 4:
            node = ipv4Start
            bitCount = 32
        case 16:
            guard ipVersion == 6 else { return nil }
            node = 0
            bitCount = 128
        default:
            return nil
        }
        var i = 0
        while true {
            if node > nodeCount { return record(at: node) }
            if node == nodeCount { return nil }
            guard i < bitCount else { return nil }
            let bit = (bytes[i >> 3] >> (7 - UInt8(i & 7))) & 1
            node = readRecord(node: node, index: Int(bit))
            i += 1
        }
    }

    private func record(at node: Int) -> NCJSONValue? {
        let pointer = node - nodeCount - 16
        guard pointer >= 0 else { return nil }
        var decoder = NCMMDBDecoder(data: data, offset: dataStart + pointer, dataStart: dataStart)
        return decoder.decode()
    }

    private func readRecord(node: Int, index: Int) -> Int {
        let byteOffset = node * recordSize * 2 / 8 + index * recordSize / 8
        switch recordSize {
        case 24:
            return Int(data[byteOffset]) << 16 | Int(data[byteOffset + 1]) << 8 | Int(data[byteOffset + 2])
        case 28:
            let middle = data[byteOffset + 3]
            if index == 0 {
                return Int(middle & 0xf0) << 20 | Int(data[byteOffset]) << 16 | Int(data[byteOffset + 1]) << 8 | Int(data[byteOffset + 2])
            } else {
                let offset2 = byteOffset + 4
                return Int(middle & 0x0f) << 24 | Int(data[offset2]) << 16 | Int(data[offset2 + 1]) << 8 | Int(data[offset2 + 2])
            }
        case 32:
            return Int(data[byteOffset]) << 24 | Int(data[byteOffset + 1]) << 16 | Int(data[byteOffset + 2]) << 8 | Int(data[byteOffset + 3])
        default:
            return nodeCount
        }
    }

    /// Country code for an IP: handles GeoLite2 records ({"country":
    /// {"iso_code": …}}), MetaCubeX metadb records ({"country_code": …}) and
    /// bare string records.
    func countryCode(for ip: NCIP) -> String? {
        countryCodes(for: ip).first
    }

    /// Every code an IP carries. fix/nc-diag-439 (A): MetaCubeX `Meta-geoip0` stores a network that belongs to several
    /// lists as an ARRAY of codes (`["google","us"]`, `["cloudflare","cn"]` — 1,030 networks carry `cn` this way);
    /// Clash.Meta's MetaV0 reader matches GEOIP against any of them. The single-code reader returned nil for those, so
    /// `GEOIP,cn` silently missed. Order kept as stored; empty when nothing covers the IP.
    func countryCodes(for ip: NCIP) -> [String] {
        guard let record = lookup(ip) else { return [] }
        return Self.codes(in: record)
    }

    static func codes(in record: NCJSONValue) -> [String] {
        switch record {
        case .string(let s):
            return s.isEmpty ? [] : [s]
        case .array(let a):
            return a.compactMap { $0.string }.filter { !$0.isEmpty }
        case .object(let m):
            if let cc = m["country_code"]?.string { return [cc] }
            if let iso = m["country"]?.object?["iso_code"]?.string { return [iso] }
            if let iso = m["registered_country"]?.object?["iso_code"]?.string { return [iso] }
            return []
        default:
            return []
        }
    }

    /// ASN for an IP from an ASN database ({"autonomous_system_number": …}).
    func asn(for ip: NCIP) -> Int? {
        guard let record = lookup(ip), case .object(let m) = record else { return nil }
        return m["autonomous_system_number"]?.int
    }
}

/// The mmdb data-section value decoder (control byte: type + size, with
/// extended types, pointers, and the 29/30/31 size escapes).
private struct NCMMDBDecoder {
    let data: Data
    var offset: Int
    var dataStart: Int = 0
    /// Pointer / map / array nesting so far: a hostile file with a self-referencing pointer or deep nesting would
    /// otherwise recurse until the stack overflows. Real MaxMind records nest a handful of levels.
    var depth: Int = 0

    mutating func decode() -> NCJSONValue? {
        guard offset >= 0, offset < data.count, depth < 64 else { return nil }
        let ctrl = data[offset]
        offset += 1
        var type = Int(ctrl >> 5)
        let sizeBits = Int(ctrl & 0x1f)
        if type == 0 { // extended type follows
            guard offset < data.count else { return nil }
            type = Int(data[offset]) + 7
            offset += 1
        }
        if type == 1 { // pointer: size bits encode the pointer width/value
            let pointerSize = (sizeBits >> 3) & 0x3
            let base = sizeBits & 0x7
            let pointer: Int
            switch pointerSize {
            case 0:
                guard offset < data.count else { return nil }
                pointer = base << 8 | Int(data[offset])
                offset += 1
            case 1:
                guard offset + 1 < data.count else { return nil }
                pointer = (base << 16 | Int(data[offset]) << 8 | Int(data[offset + 1])) + 2048
                offset += 2
            case 2:
                guard offset + 2 < data.count else { return nil }
                pointer = (base << 24 | Int(data[offset]) << 16 | Int(data[offset + 1]) << 8 | Int(data[offset + 2])) + 526336
                offset += 3
            default:
                guard offset + 3 < data.count else { return nil }
                pointer = Int(data[offset]) << 24 | Int(data[offset + 1]) << 16 | Int(data[offset + 2]) << 8 | Int(data[offset + 3])
                offset += 4
            }
            var target = NCMMDBDecoder(data: data, offset: dataStart + pointer, dataStart: dataStart, depth: depth + 1)
            return target.decode()
        }
        let size: Int
        switch sizeBits {
        case 29:
            guard offset < data.count else { return nil }
            size = 29 + Int(data[offset])
            offset += 1
        case 30:
            guard offset + 1 < data.count else { return nil }
            size = 285 + (Int(data[offset]) << 8 | Int(data[offset + 1]))
            offset += 2
        case 31:
            guard offset + 2 < data.count else { return nil }
            size = 65821 + (Int(data[offset]) << 16 | Int(data[offset + 1]) << 8 | Int(data[offset + 2]))
            offset += 3
        default:
            size = sizeBits
        }
        switch type {
        case 2: // utf8 string
            guard offset + size <= data.count else { return nil }
            let s = String(decoding: data[offset..<(offset + size)], as: UTF8.self)
            offset += size
            return .string(s)
        case 3: // double
            guard offset + 8 <= data.count else { return nil }
            let bytes = [UInt8](data[offset..<(offset + 8)])
            offset += 8
            let bits = bytes.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            return .number(Double(bitPattern: bits))
        case 4: // bytes
            offset += size
            return .string("bytes(\(size))")
        case 5, 6, 9: // uint16 / uint32 / uint64: big-endian unsigned
            var value: UInt64 = 0
            for k in 0..<size {
                guard offset + k < data.count else { return nil }
                value = value << 8 | UInt64(data[offset + k])
            }
            offset += size
            return .number(Double(value))
        case 10: // uint128 -> approximate
            var value: Double = 0
            for k in 0..<size {
                guard offset + k < data.count else { return nil }
                value = value * 256 + Double(data[offset + k])
            }
            offset += size
            return .number(value)
        case 8: // int32
            var raw: UInt32 = 0
            for k in 0..<size {
                guard offset + k < data.count else { return nil }
                raw = raw << 8 | UInt32(data[offset + k])
            }
            offset += size
            if size > 0, size < 4 { raw <<= (4 - size) * 8 }
            return .number(Double(Int32(bitPattern: raw)))
        case 7: // map
            var obj: [String: NCJSONValue] = [:]
            depth += 1
            defer { depth -= 1 }
            for _ in 0..<size {
                guard let key = decode(), case .string(let k) = key, let value = decode() else { return nil }
                obj[k] = value
            }
            return .object(obj)
        case 11: // array
            var arr: [NCJSONValue] = []
            depth += 1
            defer { depth -= 1 }
            for _ in 0..<size {
                guard let v = decode() else { return nil }
                arr.append(v)
            }
            return .array(arr)
        case 14: // boolean: the size bits ARE the value
            return .bool(sizeBits != 0)
        case 15: // float
            guard offset + 4 <= data.count else { return nil }
            let bytes = [UInt8](data[offset..<(offset + 4)])
            offset += 4
            let bits = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return .number(Double(Float(bitPattern: bits)))
        default:
            return nil
        }
    }
}
