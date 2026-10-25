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
    /// Parsed categories, bounded (rv2: geosite:cn alone is ~100k entries;
    /// nameserver-policy / fake-ip-filter / fallback-filter now consult the
    /// store on every DNS query, so the cache must not grow per category
    /// forever). Least-recently-used category is dropped past the caps.
    /// nc-memory: the count cap alone does not bound bytes — 8 large categories
    /// (50–100k entries each) could pin tens of MB of Sets/Strings against the
    /// extension's 50 MB budget. An estimated-byte cap now sits alongside it:
    /// ~72 B per entry (Swift String + Set slot, estimate), 8 MB total, LRU
    /// eviction; the just-parsed category is always kept.
    private var cache: [String: Category] = [:]
    private var cacheOrder: [String] = []
    private var cacheBytes: [String: Int] = [:]
    private var cacheBytesTotal = 0
    private let maxCachedCategories = 8
    private let maxCachedBytes = 8 << 20
    private let lock = NSLock()

    /// One category, indexed for O(labels) lookups: exact and root-domain
    /// entries in hash sets (walk the host's suffixes), keyword / regex
    /// entries scanned linearly (few in practice). Entries carrying
    /// attributes are kept apart for `@attr` queries.
    private final class Category {
        var full: Set<String> = []
        var root: Set<String> = []
        var plain: [String] = []
        var regex: [NSRegularExpression] = []
        var attributed: [Entry] = []
        var hasAttributed: Bool { !attributed.isEmpty }
    }

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
        var d = domain.lowercased()
        if d.hasSuffix(".") { d.removeLast() }
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
        guard let cat = category(for: name.trimmingCharacters(in: .whitespaces).uppercased()) else { return false }
        if attrs.isEmpty {
            if cat.full.contains(d) || cat.root.contains(d) { return true }
            if !cat.root.isEmpty {
                var rest = Substring(d)
                while let dot = rest.firstIndex(of: ".") {
                    rest = rest[rest.index(after: dot)...]
                    if cat.root.contains(String(rest)) { return true }
                }
            }
            for k in cat.plain where d.contains(k) { return true }
            let range = NSRange(d.startIndex..., in: d)
            for re in cat.regex where re.firstMatch(in: d, range: range) != nil { return true }
        }
        // Attribute entries: only they can satisfy an @attr query; with no
        // attribute filter they match like any other entry.
        for e in cat.attributed where attrs.allSatisfy({ e.attrs.contains($0) }) {
            if Self.entryMatches(e, d) { return true }
        }
        return false
    }

    /// Whether the database has this category (diagnostics).
    func hasCategory(_ name: String) -> Bool {
        var n = name
        if let at = n.firstIndex(of: "@") { n = String(n[..<at]) }
        lock.lock(); defer { lock.unlock() }
        return index[n.trimmingCharacters(in: .whitespaces).uppercased()] != nil
    }

    private static func entryMatches(_ e: Entry, _ d: String) -> Bool {
        switch e.kind {
        case .full: return d == e.value
        case .rootDomain: return d == e.value || d.hasSuffix("." + e.value)
        case .plain: return d.contains(e.value)
        case .regex:
            guard let re = NCRegexCache.shared.regex(e.value) else { return false }
            return re.firstMatch(in: d, range: NSRange(d.startIndex..., in: d)) != nil
        }
    }

    /// E-B1: the category's domains as classical rule lines, for the
    /// native runtime lowering (bridge lowerForNative writes these
    /// to nativecore-geosite/<code>.list via the geodata loader):
    /// Plain -> DOMAIN-KEYWORD, Regex -> DOMAIN-REGEX, Domain ->
    /// DOMAIN-SUFFIX, Full -> DOMAIN. nil when absent.
    func classicalLines(for category: String) -> [String]? {
        guard let entries = entries(for: category.uppercased()) else { return nil }
        return entries.map { e in
            switch e.kind {
            case .plain: return "DOMAIN-KEYWORD," + e.value
            case .regex: return "DOMAIN-REGEX," + e.value
            case .rootDomain: return "DOMAIN-SUFFIX," + e.value
            case .full: return "DOMAIN," + e.value
            }
        }
    }

    private func entries(for category: String) -> [Entry]? {
        lock.lock()
        let range = index[category]
        lock.unlock()
        guard let range else { return nil }
        var parsed: [Entry] = []
        var reader = ProtoReader(data: data, range: range)
        while let field = reader.nextField() {
            guard field.number == 2, let domainRange = field.bytes else { continue }
            if let e = parseDomain(domainRange) { parsed.append(e) }
        }
        return parsed
    }

    /// Indexed category, parsed on first use and kept in the bounded cache.
    private func category(for code: String) -> Category? {
        lock.lock()
        if let cached = cache[code] {
            if cacheOrder.last != code, let i = cacheOrder.firstIndex(of: code) {
                cacheOrder.remove(at: i)
                cacheOrder.append(code)
            }
            lock.unlock()
            return cached
        }
        lock.unlock()
        guard let list = entries(for: code) else { return nil }
        let cat = Category()
        for e in list {
            if !e.attrs.isEmpty { cat.attributed.append(e); continue }
            switch e.kind {
            case .full: cat.full.insert(e.value)
            case .rootDomain: cat.root.insert(e.value)
            case .plain: cat.plain.append(e.value)
            case .regex: if let re = try? NSRegularExpression(pattern: e.value) { cat.regex.append(re) }
            }
        }
        let entryCount = cat.full.count + cat.root.count + cat.plain.count + cat.regex.count + cat.attributed.count
        let estBytes = entryCount * 72
        lock.lock()
        if cache[code] == nil {
            cache[code] = cat
            cacheOrder.append(code)
            cacheBytes[code] = estBytes
            cacheBytesTotal += estBytes
            while cacheOrder.count > 1,
                  cacheOrder.count > maxCachedCategories || cacheBytesTotal > maxCachedBytes {
                let victim = cacheOrder.removeFirst()
                cache.removeValue(forKey: victim)
                cacheBytesTotal -= cacheBytes.removeValue(forKey: victim) ?? 0
            }
        }
        lock.unlock()
        return cat
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
