import Foundation

/// Rule-set (remote rule list) parsing + matching index.
///
/// One parser normalizes the four ecosystems' list dialects into the same
/// buckets, per the user's direction to benchmark rule subscriptions
/// against Quantumult X / Loon / Surge rather than only mihomo:
///
/// - mihomo classical provider payload: `DOMAIN-SUFFIX,google.com[,policy]`
///   lines, or a YAML document with a `payload:` list of such strings
///   (behavior "classical" / "domain" / "ipcidr" texts all reduce to lines)
/// - Surge RULE-SET lists: same classical lines; DOMAIN-SET lists: bare
///   domains, one per line (see suffix semantics below)
/// - Loon remote rules: classical lines
/// - QX filter files: lowercase dialect (`host-suffix,google.com,Policy`)
///
/// A rule SET is an OR of its entries (they all route to the policy the
/// referencing RULE-SET rule names), so the index answers one question:
/// "does this context hit any entry?" — exposed via `contains(_ ctx:)`,
/// which the engine injects as `NCMatchContext.ruleSetContains`.
///
/// DOMAIN-SET semantics (Surge manual, "DOMAIN-SET File Format"): a plain
/// line matches the hostname exactly (like DOMAIN); a line starting with `.`
/// matches the domain itself and all subdomains (like DOMAIN-SUFFIX). The
/// clash spelling `+.d` means the same as `.d`; `*.d` (mihomo one-level
/// wildcard) is approximated as subdomains-only. Exact and suffix entries
/// live in one compact sorted table of reversed hostnames (NCDomainTable,
/// fix/nc-mem-providers): ~15 bytes + 5 bytes of index per entry instead of a
/// String Set plus a class-per-label trie (~120 bytes per entry), and a
/// lookup is one binary search per label boundary of the queried host.
/// (mihomo's `.d` excludes `d` itself; the leaner Surge reading is used for
/// both — a mihomo list gains at most the bare parent domain.)

enum NCRuleSetFlavor {
    case classical   // TYPE,payload[,policy] lines (mihomo / Surge RULE-SET / Loon)
    case qx          // lowercase QX dialect lines
    case domainSet   // bare domains per line (Surge DOMAIN-SET)
    case auto        // per-line detection (mixed sources)
}

struct NCRuleSetIndex {
    /// Exact (DOMAIN / bare DOMAIN-SET) and suffix (DOMAIN-SUFFIX / `.d` / `+.d` / `*.d`) entries.
    private(set) var domains = NCDomainTable()
    /// IP-ASN entries of a classical list (ASN.China: ~5k lines): one ASN lookup + a set probe per flow instead
    /// of one NCRule (and one mmdb lookup) per line.
    private(set) var asns: Set<UInt32> = []
    /// An IP-ASN line whose payload never parses (never matches) — kept only for needsIP parity.
    private var hasDeadIPEntry = false
    private(set) var mrsDomainSet: NCMRSDomainSet? = nil
    private(set) var mrsIPCIDRSet: NCMRSIPCIDRSet? = nil
    private(set) var others: [NCRule] = [] // keywords, wildcards, regex, CIDRs, GEOIP, ASN, ports…
    private(set) var entryCount = 0
    /// Rule types NCRuleMatcher.matches can answer true for as a rule-set entry (its `default:` returns false;
    /// AND/OR/NOT need sub-rules and RULE-SET/DOMAIN-SET/SUB-RULE are disabled or meaningless inside a set).
    static let matchableKinds: Set<String> = [
        "MATCH", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
        "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN",
        "DST-PORT", "DEST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "NETWORK",
        "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX",
        "URL-REGEX", "PROTOCOL", "USER-AGENT",
    ]
    /// Whether any entry reads the destination IP (CIDR sets, IP-CIDR /
    /// GEOIP / IP-ASN lines): mihomo RuleSet.ShouldResolveIP.
    var needsIP: Bool {
        mrsIPCIDRSet != nil || !asns.isEmpty || hasDeadIPEntry || others.contains { NCRuleMatcher.ipKinds.contains($0.kind) }
    }

    /// Sort + dedupe the domain table and trim spare capacity. The store calls this once a list is parsed, before
    /// the index is published; an unfinalized index still answers correctly (linear scan), just slower.
    mutating func finalize() {
        domains.finalize()
        if others.capacity > others.count + others.count / 4 + 8 {
            var c: [NCRule] = []
            c.reserveCapacity(others.count)
            c.append(contentsOf: others)
            others = c
        }
    }

    // MARK: building

    mutating func addLine(_ rawLine: String, flavor: NCRuleSetFlavor) {
        var line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { return }
        // Trailing comments in published lists are separated by " #"/" //".
        if let r = line.range(of: " #") { line = String(line[..<r.lowerBound]).trimmingCharacters(in: .whitespaces) }
        if line.isEmpty { return }

        switch flavor {
        case .domainSet:
            addDomainSetEntry(line)
        case .qx:
            addClassicalLine(line, dialect: .qx)
        case .classical:
            addClassicalLine(line, dialect: .standard)
        case .auto:
            if line.contains(",") {
                let head = line.prefix { $0 != "," }
                // QX dialect type tokens are all-lowercase; classical lists
                // spell types UPPERCASE.
                let isQX = !head.isEmpty && head == head.lowercased() && head != head.uppercased()
                addClassicalLine(line, dialect: isQX ? .qx : .standard)
            } else {
                addDomainSetEntry(line)
            }
        }
    }

    mutating func addText(_ text: String, flavor: NCRuleSetFlavor) {
        // mihomo YAML provider document: `payload: [ "line", … ]`. Only tried when the text has a `payload:` key —
        // building a YAML tree of a 36k-line text list just to find none cost several MB (fix/nc-mem-providers).
        if flavor == .classical || flavor == .auto, text.contains("payload:"),
           let root = NCYAML.parse(text), let payload = root["payload"]?.array {
            for item in payload {
                if let s = item.string { addLine(s, flavor: .classical) }
            }
            if entryCount > 0 { return }
        }
        for line in text.components(separatedBy: .newlines) { addLine(line, flavor: flavor) }
    }

    /// Streaming load of a downloaded body (fix/nc-mem-providers): lines are cut straight out of the bytes, so a
    /// 1.2 MB list never exists as one String plus a 36k-element `components(separatedBy:)` array next to the Data.
    /// Returns false when the body is not UTF-8 (the caller reports it, as String(data:encoding:) did).
    /// A YAML `payload:` document goes through addText (it needs the tree); those are small in practice.
    mutating func addData(_ data: Data, flavor: NCRuleSetFlavor) -> Bool {
        let yamlKey = Array("payload:".utf8)
        if flavor == .classical || flavor == .auto, Self.hasLinePrefix(data, yamlKey) {
            guard let text = String(data: data, encoding: .utf8) else { return false }
            addText(text, flavor: flavor)
            return true
        }
        var ok = true
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let b = raw.bindMemory(to: UInt8.self)
            let n = b.count
            var start = 0
            // UTF-8 BOM
            if n >= 3, b[0] == 0xEF, b[1] == 0xBB, b[2] == 0xBF { start = 3 }
            var lineNo = 0
            while start < n, ok {
                var end = start
                while end < n, b[end] != 0x0A, b[end] != 0x0D { end += 1 }
                if end > start {
                    let slice = UnsafeBufferPointer(rebasing: b[start..<end])
                    // validate like String(data:encoding:.utf8) did for the whole body
                    if let line = String(validatingUTF8Bytes: slice) {
                        lineNo += 1
                        #if canImport(ObjectiveC)
                        if lineNo % 256 == 0 { autoreleasepool { addLine(line, flavor: flavor) } } else { addLine(line, flavor: flavor) }
                        #else
                        addLine(line, flavor: flavor)
                        #endif
                    } else {
                        ok = false
                    }
                }
                start = end + 1
            }
        }
        return ok
    }

    /// Whether some line of `data` starts (after spaces) with `key`.
    private static func hasLinePrefix(_ data: Data, _ key: [UInt8]) -> Bool {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            let b = raw.bindMemory(to: UInt8.self)
            let n = b.count, k = key.count
            var i = 0
            var atLineStart = true
            while i < n {
                let c = b[i]
                if c == 0x0A || c == 0x0D { atLineStart = true; i += 1; continue }
                if atLineStart {
                    if c == 0x20 || c == 0x09 { i += 1; continue }
                    if i + k <= n {
                        var j = 0
                        while j < k, b[i + j] == key[j] { j += 1 }
                        if j == k { return true }
                    }
                    atLineStart = false
                }
                i += 1
            }
            return false
        }
    }

    private enum Dialect { case standard, qx }

    private mutating func addClassicalLine(_ line: String, dialect: Dialect) {
        let fields = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard fields.count >= 2 else { return }
        var kind = fields[0].uppercased()
        let payload = fields[1]
        if dialect == .qx {
            kind = [
                "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD",
                "HOST-WILDCARD": "DOMAIN-WILDCARD", "IP6-CIDR": "IP-CIDR", "USER-AGENT": "USER-AGENT",
            ][kind] ?? kind
        }
        switch kind {
        case "DOMAIN":
            domains.insert(payload.lowercased(), flags: NCDomainTable.exact); entryCount += 1
        case "DOMAIN-SUFFIX":
            domains.insert(payload.lowercased(), flags: NCDomainTable.suffix); entryCount += 1
        case "IP-ASN":
            // Same acceptance as NCRuleMatcher's Int(payload): a payload that is not a bare number (e.g. a
            // trailing "// comment") never matched; it is counted, and still marks the set as IP-reading, but no
            // NCRule is kept for it.
            if let n = UInt32(payload) { asns.insert(n) } else { hasDeadIPEntry = true }
            entryCount += 1
        default:
            // Everything else (keywords, CIDRs, GEOIP, ports, regex…) reuses
            // the single-rule matcher, evaluated linearly — those buckets
            // are small in real lists; domains dominate and are indexed.
            appendOther(kind: kind, payload: payload, fields: fields)
        }
    }

    /// One non-domain entry, matched by NCRuleMatcher. `raw` and `policy` are never read for a rule-set entry
    /// (the referencing RULE-SET line owns the policy), so they are not kept.
    private mutating func appendOther(kind: String, payload: String, fields: [String]) {
        // A type NCRuleMatcher has no case for (or a logic / nested RULE-SET line, which never match inside a set:
        // no sub-rules are parsed here and nested sets are disabled) can never match: count it, keep nothing.
        // Run 40290997704: QX-dialect lists spelled in UPPERCASE (HOST-SUFFIX,…) under behavior classical kept
        // ~37k such NCRules (blackmatrix7 QuantumultX Global.list alone ~36k, ~7 MB) that no flow could ever hit.
        guard Self.matchableKinds.contains(kind) else { entryCount += 1; return }
        let opts = fields.dropFirst(3)
        others.append(NCRule(raw: "", kind: kind, payload: payload, policy: "",
                             noResolve: opts.contains { $0.lowercased() == "no-resolve" }, subRules: []))
        entryCount += 1
    }

    private mutating func addDomainSetEntry(_ line0: String) {
        var line = line0
        var suffix = false   // domain itself + subdomains
        var subOnly = false  // subdomains only
        if line.hasPrefix("+.") { suffix = true; line = String(line.dropFirst(2)) } // clash-style suffix marker
        else if line.hasPrefix("*.") { subOnly = true; line = String(line.dropFirst(2)) }
        else if line.hasPrefix(".") { suffix = true; line = String(line.dropFirst()) } // Surge: self + subdomains
        // DOMAIN-SET files sometimes carry full URLs; keep just the host.
        if let scheme = line.range(of: "://") { line = String(line[scheme.upperBound...]) }
        if let slash = line.firstIndex(of: "/") { line = String(line[..<slash]) }
        let host = line.lowercased()
        guard !host.isEmpty, host.contains(".") || suffix || subOnly else { return }
        domains.insert(host, flags: suffix ? NCDomainTable.suffix : (subOnly ? NCDomainTable.subOnly : NCDomainTable.exact))
        entryCount += 1
    }

    mutating func addMRSDomain(_ domainSet: NCMRSDomainSet) {
        mrsDomainSet = domainSet
        entryCount += domainSet.ruleCount
    }

    mutating func addMRSIPCIDR(_ ipcidrSet: NCMRSIPCIDRSet) {
        mrsIPCIDRSet = ipcidrSet
        entryCount += ipcidrSet.ruleCount
    }

    mutating func addMRS(data: Data, behavior: String? = nil) throws {
        let payload = try NCMRS.decode(data: data, expectedBehavior: behavior)
        switch payload {
        case .domain(let d):
            addMRSDomain(d)
        case .ipcidr(let i):
            addMRSIPCIDR(i)
        }
    }

    // MARK: matching

    func contains(_ ctx: NCMatchContext) -> Bool {
        if let d = ctx.domain?.lowercased() {
            if domains.matches(host: d) { return true }
            if let ds = mrsDomainSet, ds.has(d) { return true }
        }
        if let ip = ctx.ip {
            if let iset = mrsIPCIDRSet, iset.contains(ip) { return true }
            if !asns.isEmpty, let a = ctx.asnOf(ip), a >= 0, asns.contains(UInt32(truncatingIfNeeded: a)) { return true }
        }
        if others.isEmpty { return false }
        // Rule-set entries must not recurse into other rule sets.
        var sub = ctx
        sub.ruleSetContains = { _, _ in false }
        return others.contains { NCRuleMatcher.matches($0, sub) }
    }
}

/// Compact domain table (fix/nc-mem-providers): every entry's hostname stored byte-reversed
/// ("www.google.com" → "moc.elgoog.www") back to back in one [UInt8], with a UInt32 end offset and a flag byte per
/// entry, sorted once after the list is parsed. A host matches when its whole reversed name is an entry flagged
/// exact / suffix, or a reversed ancestor ending at a label boundary is an entry flagged suffix / subOnly — the same
/// answers the old Set<String> + label trie gave, at ~20 bytes per entry instead of ~120.
struct NCDomainTable {
    static let exact: UInt8 = 1    // host itself only (DOMAIN, bare DOMAIN-SET line)
    static let suffix: UInt8 = 2   // host itself + subdomains (DOMAIN-SUFFIX, `.d`, `+.d`)
    static let subOnly: UInt8 = 4  // subdomains only (`*.d`)

    private var bytes: [UInt8] = []
    private var ends: [UInt32] = []   // entry i spans bytes[(i == 0 ? 0 : ends[i-1]) ..< ends[i]]
    private var flags: [UInt8] = []
    private(set) var isSorted = true

    var count: Int { ends.count }

    mutating func insert(_ host: String, flags f: UInt8) {
        var u = Array(host.utf8)
        while u.last == 0x2E { u.removeLast() }           // trailing dots
        var lead = 0
        while lead < u.count, u[lead] == 0x2E { lead += 1 } // leading dots
        guard lead < u.count else { return }
        bytes.append(contentsOf: u[lead...].reversed())
        ends.append(UInt32(bytes.count))
        flags.append(f)
        isSorted = false
    }

    private func range(_ i: Int) -> Range<Int> { (i == 0 ? 0 : Int(ends[i - 1]))..<Int(ends[i]) }

    /// Sort by reversed name, merge duplicates (OR of flags), drop spare capacity.
    mutating func finalize() {
        guard !isSorted else { return }
        let n = ends.count
        var order = Array(0..<n)
        bytes.withUnsafeBufferPointer { b in
            let e = ends
            func cmp(_ x: Int, _ y: Int) -> Bool {
                let xs = x == 0 ? 0 : Int(e[x - 1]), xe = Int(e[x])
                let ys = y == 0 ? 0 : Int(e[y - 1]), ye = Int(e[y])
                return Self.compare(b, xs, xe, b, ys, ye) < 0
            }
            order.sort(by: cmp)
        }
        var nb: [UInt8] = []; nb.reserveCapacity(bytes.count)
        var ne: [UInt32] = []; ne.reserveCapacity(n)
        var nf: [UInt8] = []; nf.reserveCapacity(n)
        bytes.withUnsafeBufferPointer { b in
            for idx in order {
                let r = range(idx)
                if let last = ne.last {
                    let ls = ne.count == 1 ? 0 : Int(ne[ne.count - 2])
                    let same: Bool = nb.withUnsafeBufferPointer { p in Self.compare(p, ls, Int(last), b, r.lowerBound, r.upperBound) == 0 }
                    if same { nf[nf.count - 1] |= flags[idx]; continue }
                }
                nb.append(contentsOf: b[r])
                ne.append(UInt32(nb.count))
                nf.append(flags[idx])
            }
        }
        bytes = nb; ends = ne; flags = nf // reserved at the pre-dedupe size: no growth slack
        isSorted = true
    }

    @inline(__always)
    private static func compare(_ a: UnsafeBufferPointer<UInt8>, _ as0: Int, _ ae: Int,
                                _ b: UnsafeBufferPointer<UInt8>, _ bs0: Int, _ be: Int) -> Int {
        var i = as0, j = bs0
        while i < ae, j < be {
            let x = a[i], y = b[j]
            if x != y { return x < y ? -1 : 1 }
            i += 1; j += 1
        }
        let la = ae - as0, lb = be - bs0
        return la == lb ? 0 : (la < lb ? -1 : 1)
    }

    /// Flags of the entry equal to key[0..<len], 0 when absent.
    private func lookup(_ key: UnsafeBufferPointer<UInt8>, _ len: Int) -> UInt8 {
        bytes.withUnsafeBufferPointer { b -> UInt8 in
            if isSorted {
                var lo = 0, hi = ends.count - 1
                while lo <= hi {
                    let mid = (lo + hi) >> 1
                    let r = range(mid)
                    let c = Self.compare(b, r.lowerBound, r.upperBound, key, 0, len)
                    if c == 0 { return flags[mid] }
                    if c < 0 { lo = mid + 1 } else { hi = mid - 1 }
                }
                return 0
            }
            var f: UInt8 = 0
            for i in 0..<ends.count {
                let r = range(i)
                if Self.compare(b, r.lowerBound, r.upperBound, key, 0, len) == 0 { f |= flags[i] }
            }
            return f
        }
    }

    /// `host` is expected lowercased (NCRuleSetIndex.contains lowercases).
    func matches(host: String) -> Bool {
        guard !ends.isEmpty else { return false }
        var u = Array(host.utf8)
        while u.last == 0x2E { u.removeLast() }
        guard !u.isEmpty else { return false }
        u.reverse()
        return u.withUnsafeBufferPointer { k -> Bool in
            let n = k.count
            var i = 0
            while i <= n {
                if i == n {
                    return lookup(k, n) & (Self.exact | Self.suffix) != 0
                }
                if k[i] == 0x2E, i > 0, lookup(k, i) & (Self.suffix | Self.subOnly) != 0 { return true }
                i += 1
            }
            return false
        }
    }
}

extension String {
    /// UTF-8 bytes → String, nil when they are not valid UTF-8 (String(decoding:) would repair them instead).
    init?(validatingUTF8Bytes buf: UnsafeBufferPointer<UInt8>) {
        var it = buf.makeIterator()
        var dec = UTF8()
        loop: while true {
            switch dec.decode(&it) {
            case .scalarValue: continue
            case .emptyInput: break loop
            case .error: return nil
            }
        }
        self.init(decoding: buf, as: UTF8.self)
    }
}
