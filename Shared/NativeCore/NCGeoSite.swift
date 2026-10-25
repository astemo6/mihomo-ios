import Foundation

/// GEOSITE database (GeoSite.dat, v2ray geosite protobuf format) with
/// mihomo's matching semantics (metacubex/mihomo component/geodata +
/// rules/common/geosite.go are the spec):
///
///   GEOSITE,google,PROXY            — domain in category GOOGLE
///   GEOSITE,google@cn,PROXY         — only entries carrying attribute "cn"
///   GEOSITE,category-ads-all@ads    — attributes are comma-separated,
///                                     every listed attribute must be
///                                     present on the entry (lowercased)
///
/// Entry match types follow the geosite format: RootDomain = the domain
/// itself or any subdomain, Full = exact, Plain = keyword substring,
/// Regex = regular expression search.
///
/// Categories are parsed lazily on first use (the file can hold 100k+
/// domains; the tunnel cannot afford to materialise all of them), mirroring
/// mihomo's memconservative loader. The index pass only records each
/// category's byte range and name.
final class NCGeoSiteDB {
    private let data: Data
    /// Uppercased category code -> byte range of its GeoSite message in `data`.
    private var index: [String: Range<Int>] = [:]
    private var cache: [String: [Entry]] = [:]
    private var regexCache: [String: NSRegularExpression] = [:]
    private let lock = NSLock()

    struct Entry {
        enum Kind { case plain, regex, rootDomain, full }
        let kind: Kind
        let value: String // lowercased (regex kept as authored)
        let attrs: Set<String> // lowercased attribute keys
    }

    init?(data: Data) {
        self.data = data
        var reader = ProtoReader(data: data, range: data.startIndex..<data.endIndex)
        var found: [String: Range<Int>] = [:]
        while let field = reader.nextField() {
            guard field.number == 1, let payload = field.bytes else { continue }
            // Inside a GeoSite message the first field is the country code;
            // read just that to index the category without parsing domains.
            var inner = ProtoReader(data: data, range: payload)
            if let first = inner.nextField(), first.number == 1, let codeData = first.bytes,
               let code = String(data: data[codeData], encoding: .utf8) {
                found[code.uppercased()] = payload
            }
        }
        guard !found.isEmpty else { return nil }
        index = found
    }

    /// mihomo GEOSITE match: `payload` is the rule payload ("NAME" or
    /// "NAME@attr1,attr2"), `domain` the host being routed.
    func matches(payload: String, domain: String) -> Bool {
        let d = domain.lowercased()
        guard !d.isEmpty else { return false }
        var name = payload
        var attrs: [String] = []
        if let at = payload.firstIndex(of: "@") {
            name = String(payload[..<at])
            attrs = payload[payload.index(after: at)...]
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty }
        }
        guard let entries = entries(for: name.uppercased()) else { return false }
        for e in entries {
            if !attrs.allSatisfy({ e.attrs.contains($0) }) { continue }
            switch e.kind {
            case .full:
                if d == e.value { return true }
            case .rootDomain:
                if d == e.value || d.hasSuffix("." + e.value) { return true }
            case .plain:
                if d.contains(e.value) { return true }
            case .regex:
                if let re = regex(for: e.value),
                   re.firstMatch(in: d, range: NSRange(d.startIndex..., in: d)) != nil { return true }
            }
        }
        return false
    }

    private func regex(for pattern: String) -> NSRegularExpression? {
        lock.lock(); defer { lock.unlock() }
        if let re = regexCache[pattern] { return re }
        let re = try? NSRegularExpression(pattern: pattern)
        regexCache[pattern] = re
        return re
    }

    private func entries(for category: String) -> [Entry]? {
        lock.lock()
        if let cached = cache[category] { lock.unlock(); return cached }
        let range = index[category]
        lock.unlock()
        guard let range else { return nil }
        var parsed: [Entry] = []
        var reader = ProtoReader(data: data, range: range)
        while let field = reader.nextField() {
            guard field.number == 2, let domainRange = field.bytes else { continue }
            if let e = parseDomain(domainRange) { parsed.append(e) }
        }
        lock.lock(); cache[category] = parsed; lock.unlock()
        return parsed
    }

    /// One Domain message: field 1 = type (varint), field 2 = value (string),
    /// field 3 = repeated Attribute (field 1 of which is the key string).
    private func parseDomain(_ range: Range<Int>) -> Entry? {
        var reader = ProtoReader(data: data, range: range)
        var kind: Entry.Kind = .rootDomain
        var value: String?
        var attrs: Set<String> = []
        while let field = reader.nextField() {
            switch field.number {
            case 1:
                if let v = field.varint {
                    switch v {
                    case 0: kind = .plain
                    case 1: kind = .regex
                    case 3: kind = .full
                    default: kind = .rootDomain // 2 = RootDomain
                    }
                }
            case 2:
                if let r = field.bytes { value = String(data: data[r], encoding: .utf8) }
            case 3:
                if let attrRange = field.bytes {
                    var attrReader = ProtoReader(data: data, range: attrRange)
                    if let keyField = attrReader.nextField(), keyField.number == 1,
                       let kr = keyField.bytes, let key = String(data: data[kr], encoding: .utf8) {
                        attrs.insert(key.lowercased())
                    }
                }
            default:
                continue
            }
        }
        guard let value, !value.isEmpty else { return nil }
        return Entry(kind: kind, value: kind == .regex ? value : value.lowercased(), attrs: attrs)
    }
}

/// Minimal protobuf wire reader (varint + length-delimited + fixed32/64
/// skipping), bounds-checked throughout. Operates on byte ranges of one
/// backing Data so callers can index into a large file without copying.
struct ProtoReader {
    let data: Data
    private var pos: Int
    private let end: Int

    init(data: Data, range: Range<Int>) {
        self.data = data
        self.pos = range.lowerBound
        self.end = range.upperBound
    }

    struct Field {
        let number: Int
        let varint: UInt64?
        let bytes: Range<Int>?
    }

    mutating func nextField() -> Field? {
        guard pos < end, let tag = readVarint() else { return nil }
        let number = Int(tag >> 3)
        switch tag & 0x7 {
        case 0: // varint
            guard let v = readVarint() else { return nil }
            return Field(number: number, varint: v, bytes: nil)
        case 2: // length-delimited
            guard let len = readVarint(), len <= UInt64(end - pos) else { return nil }
            let start = pos
            pos += Int(len)
            return Field(number: number, varint: nil, bytes: start..<pos)
        case 5: // fixed32
            guard end - pos >= 4 else { return nil }
            pos += 4
            return Field(number: number, varint: nil, bytes: nil)
        case 1: // fixed64
            guard end - pos >= 8 else { return nil }
            pos += 8
            return Field(number: number, varint: nil, bytes: nil)
        default:
            return nil
        }
    }

    private mutating func readVarint() -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while pos < end, shift < 70 {
            let b = data[pos]
            pos += 1
            result |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
        }
        return nil
    }
}
