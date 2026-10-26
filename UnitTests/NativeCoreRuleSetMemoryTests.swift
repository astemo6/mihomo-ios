import XCTest
import Darwin
@testable import Mihomo

/// fix/nc-mem-providers: the compact rule-set index (NCDomainTable + IP-ASN set + streamed body parse) answers
/// exactly what the old Set<String> + label-trie index did, and retains a fraction of its heap.
final class NativeCoreRuleSetMemoryTests: XCTestCase {

    // MARK: - reference: the pre-fix storage (Set<String> exact + class-per-label suffix trie)

    private final class OldTrie {
        var children: [String: OldTrie] = [:]
        var matchSelf = false
        var subOnly = false
        func insert(_ domain: String, matchSelf ms: Bool, subOnly so: Bool) {
            var node = self
            for label in domain.split(separator: ".").reversed() {
                let k = String(label)
                if let n = node.children[k] { node = n } else { let n = OldTrie(); node.children[k] = n; node = n }
            }
            node.matchSelf = node.matchSelf || ms
            node.subOnly = node.subOnly || so
        }
        func matches(_ host: String) -> Bool {
            let labels = host.split(separator: ".").reversed().map(String.init)
            var node = self
            for (i, l) in labels.enumerated() {
                guard let n = node.children[l] else { return false }
                node = n
                if node.matchSelf { return true }
                if node.subOnly, i < labels.count - 1 { return true }
            }
            return false
        }
    }

    private struct OldIndex {
        var exact: Set<String> = []
        let trie = OldTrie()
        mutating func add(classicalLine line: String) {
            let f = line.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            guard f.count >= 2 else { return }
            switch f[0].uppercased() {
            case "DOMAIN": exact.insert(f[1].lowercased())
            case "DOMAIN-SUFFIX": trie.insert(f[1].lowercased(), matchSelf: true, subOnly: false)
            default: break
            }
        }
        func contains(_ d: String) -> Bool { exact.contains(d) || trie.matches(d) }
    }

    // MARK: - synthetic Global.list-shaped body (blackmatrix7 Global: ~35k HOST-SUFFIX, ~800 HOST)

    private static let tlds = ["com", "net", "org", "io", "co", "app", "dev", "jp", "tv", "me", "info", "xyz", "co.uk", "com.tw"]

    private func globalLikeLines(_ n: Int, qxUpper: Bool = false) -> [String] {
        var out: [String] = ["# NAME: Global", "# TOTAL: \(n)"]
        out.reserveCapacity(n + 2)
        var x: UInt64 = 0x9E3779B97F4A7C15
        func rnd() -> UInt64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
        for i in 0..<n {
            let tld = Self.tlds[Int(rnd() % UInt64(Self.tlds.count))]
            let len = 4 + Int(rnd() % 12)
            var name = ""
            for _ in 0..<len { name.append(Character(UnicodeScalar(UInt8(97 + rnd() % 26)))) }
            let host = (i % 9 == 0 ? "cdn\(i % 5)." : "") + name + "\(i % 100).\(tld)"
            let (e, sfx) = qxUpper ? ("HOST", "HOST-SUFFIX") : ("DOMAIN", "DOMAIN-SUFFIX")
            out.append(i % 44 == 0 ? "\(e),\(host),Global" : "\(sfx),\(host),Global")
        }
        return out
    }

    private func heapInUse() -> Int {
        var s = malloc_statistics_t()
        malloc_zone_statistics(nil, &s)
        return Int(s.size_in_use)
    }

    // MARK: - tests

    func testCompactIndexMatchesOldIndexOnGlobalShapedList() throws {
        let lines = globalLikeLines(36_000)
        var old = OldIndex()
        for l in lines { old.add(classicalLine: l) }
        var idx = NCRuleSetIndex()
        let p = NCRuleProviderStore.Provider(name: "Global", behavior: "classical", format: "text")
        try NCRuleProviderStore.populateIndex(idx: &idx, data: Data(lines.joined(separator: "\n").utf8), provider: p)
        XCTAssertEqual(idx.entryCount, 36_000)
        XCTAssertTrue(idx.domains.isSorted)
        // every entry, a subdomain of it, a look-alike and an unrelated host
        var checked = 0
        for l in lines.dropFirst(2).prefix(6000) {
            let host = String(l.split(separator: ",")[1])
            for q in [host, "a.b." + host, "x" + host, host + ".evil.org", String(host.dropFirst())] {
                var c = NCMatchContext(); c.domain = q
                XCTAssertEqual(idx.contains(c), old.contains(q), q)
                checked += 1
            }
        }
        XCTAssertEqual(checked, 30_000)
    }

    func testRetainedHeapIsAFractionOfTheOldIndex() throws {
        let body = Data(globalLikeLines(36_000).joined(separator: "\n").utf8)
        let p = NCRuleProviderStore.Provider(name: "Global", behavior: "classical", format: "text")

        let h0 = heapInUse()
        var old: OldIndex? = OldIndex()
        if let text = String(data: body, encoding: .utf8) {
            for l in text.components(separatedBy: .newlines) { old?.add(classicalLine: l) }
        }
        let oldBytes = heapInUse() - h0
        XCTAssertTrue(old?.contains("cdn0." + "zzzz") == false)
        old = nil

        let h1 = heapInUse()
        var idx: NCRuleSetIndex? = NCRuleSetIndex()
        try NCRuleProviderStore.populateIndex(idx: &idx!, data: body, provider: p)
        let newBytes = heapInUse() - h1
        XCTAssertEqual(idx?.entryCount, 36_000)
        print(String(format: "MEM-MEASURE rule-set Global-shaped 36k entries (%d B body): old index retained %.2f MB, compact index retained %.2f MB",
                     body.count, Double(oldBytes) / 1_048_576, Double(newBytes) / 1_048_576))
        idx = nil
        XCTAssertLessThan(newBytes, oldBytes / 3, "compact index should retain well under a third of the old one")
        XCTAssertLessThan(newBytes, 1_500_000)
    }

    func testUnknownTypesAreCountedNotKept() {
        var idx = NCRuleSetIndex()
        var text = ""
        for i in 0..<2000 { text += "NOT-A-TYPE,x\(i).example.com,P\n" }
        text += "DOMAIN-SUFFIX,real.example.com\n"
        idx.addText(text, flavor: .classical)
        idx.finalize()
        XCTAssertEqual(idx.entryCount, 2001)
        XCTAssertTrue(idx.others.isEmpty)
        var c = NCMatchContext(); c.domain = "x1.example.com"
        XCTAssertFalse(idx.contains(c))
        c.domain = "a.real.example.com"
        XCTAssertTrue(idx.contains(c))
    }

    /// blackmatrix7 QuantumultX lists spell QX type names UPPERCASE (HOST-SUFFIX,google.com,Google) and the import
    /// declares them behavior classical: they now match like DOMAIN-SUFFIX (they were dead NCRules before).
    func testUppercaseQXNamesUnderClassical() {
        var idx = NCRuleSetIndex()
        idx.addText("HOST-SUFFIX,googleapis.com,Google\nHOST,exact.g.com,Google\nHOST-KEYWORD,gstatic,Google\nIP6-CIDR,2001:db8::/32,Google\n", flavor: .classical)
        idx.finalize()
        func has(_ d: String) -> Bool { var c = NCMatchContext(); c.domain = d; return idx.contains(c) }
        XCTAssertTrue(has("www.googleapis.com"))
        XCTAssertTrue(has("exact.g.com"))
        XCTAssertFalse(has("x.exact.g.com"))
        XCTAssertTrue(has("fonts.gstatic.cn"))
        var ip = NCMatchContext(); ip.ip = NCIP("2001:db8::1")
        XCTAssertTrue(idx.contains(ip))
        XCTAssertFalse(has("example.org"))
    }

    /// The real blackmatrix7 QuantumultX lists spell types in UPPERCASE QX names (HOST-SUFFIX) under behavior
    /// classical: the old index kept one NCRule (with its raw line) per such line in `others`, none matchable.
    /// Now they go into the compact domain table.
    func testUnmatchableEntriesAreCountedNotKept() throws {
        let lines = globalLikeLines(36_000, qxUpper: true)
        let body = Data(lines.joined(separator: "\n").utf8)
        let h0 = heapInUse()
        var oldOthers: [NCRule]? = []
        for l in lines.dropFirst(2) {
            let f = l.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            oldOthers?.append(NCRule(raw: l, kind: f[0].uppercased(), payload: f[1], policy: f[2], noResolve: false, subRules: []))
        }
        let oldBytes = heapInUse() - h0
        XCTAssertEqual(oldOthers?.count, 36_000)
        oldOthers = nil
        let p = NCRuleProviderStore.Provider(name: "GlobalQX", behavior: "classical", format: "text")
        let h1 = heapInUse()
        var idx: NCRuleSetIndex? = NCRuleSetIndex()
        try NCRuleProviderStore.populateIndex(idx: &idx!, data: body, provider: p)
        let newBytes = heapInUse() - h1
        XCTAssertEqual(idx?.entryCount, 36_000)
        print(String(format: "MEM-MEASURE rule-set QX-uppercase 36k entries under classical: old others[] retained %.2f MB, now (domain table) %.2f MB",
                     Double(oldBytes) / 1_048_576, Double(newBytes) / 1_048_576))
        idx = nil
        XCTAssertLessThan(newBytes, oldBytes / 3)
    }

    func testStreamedBodyEqualsTextParse() {
        let text = "\u{FEFF}# head\r\nDOMAIN-SUFFIX,a.com\r\nHOST,b.net,P\r\n\r\nDOMAIN-KEYWORD,trk\nIP-CIDR,10.1.0.0/16,no-resolve\nlast.example\n"
        var a = NCRuleSetIndex(); XCTAssertTrue(a.addData(Data(text.utf8), flavor: .auto)); a.finalize()
        var b = NCRuleSetIndex(); b.addText(text.replacingOccurrences(of: "\u{FEFF}", with: ""), flavor: .auto)
        XCTAssertEqual(a.entryCount, b.entryCount)
        XCTAssertEqual(a.entryCount, 5)
        for d in ["a.com", "x.a.com", "b.net", "x.b.net", "atrk.io", "last.example", "y.last.example", "c.org"] {
            var c = NCMatchContext(); c.domain = d
            XCTAssertEqual(a.contains(c), b.contains(c), d)
        }
        var ip = NCMatchContext(); ip.ip = NCIP("10.1.2.3")
        XCTAssertTrue(a.contains(ip))
        XCTAssertTrue(a.needsIP)
    }

    func testInvalidUTF8IsRejected() {
        var idx = NCRuleSetIndex()
        XCTAssertFalse(idx.addData(Data([0x44, 0x4F, 0x4D, 0x0A, 0xFF, 0xFE, 0x0A]), flavor: .classical))
        let p = NCRuleProviderStore.Provider(name: "bad", behavior: "classical", format: "text")
        var j = NCRuleSetIndex()
        XCTAssertThrowsError(try NCRuleProviderStore.populateIndex(idx: &j, data: Data([0x41, 0xC3, 0x28, 0x0A]), provider: p))
    }

    func testYAMLPayloadStillParsedFromData() {
        let y = "payload:\n  - 'DOMAIN-SUFFIX,yaml.example.com'\n  - 'IP-CIDR,192.0.2.0/24'\n"
        var idx = NCRuleSetIndex(); XCTAssertTrue(idx.addData(Data(y.utf8), flavor: .classical)); idx.finalize()
        XCTAssertEqual(idx.entryCount, 2)
        var c = NCMatchContext(); c.domain = "a.yaml.example.com"
        XCTAssertTrue(idx.contains(c))
    }

    func testDomainSetFlagsMergeAndSubOnly() {
        var idx = NCRuleSetIndex()
        idx.addText("*.wild.com\nexact.org\n.exact.org\nplain.net\nhttps://url.example/path\n", flavor: .domainSet)
        for finalized in [false, true] {
            if finalized { idx.finalize() }
            func has(_ d: String) -> Bool { var c = NCMatchContext(); c.domain = d; return idx.contains(c) }
            XCTAssertFalse(has("wild.com"), "subOnly excludes self (finalized \(finalized))")
            XCTAssertTrue(has("a.wild.com"))
            XCTAssertTrue(has("exact.org"))     // exact + suffix merged
            XCTAssertTrue(has("x.exact.org"))
            XCTAssertTrue(has("plain.net"))
            XCTAssertFalse(has("x.plain.net"))
            XCTAssertTrue(has("url.example"))
            XCTAssertTrue(has("plain.net."))    // trailing dot
            XCTAssertFalse(has("net"))
        }
    }

    func testIPASNEntriesUseOneLookup() {
        var idx = NCRuleSetIndex()
        idx.addText("IP-ASN,4134\nIP-ASN,4538,no-resolve\nIP-ASN,4808 // 中国联通\n", flavor: .classical)
        idx.finalize()
        XCTAssertEqual(idx.entryCount, 3)
        XCTAssertTrue(idx.needsIP)
        var lookups = 0
        var c = NCMatchContext(); c.ip = NCIP("1.2.3.4")
        c.asnOf = { _ in lookups += 1; return 4538 }
        XCTAssertTrue(idx.contains(c))
        XCTAssertEqual(lookups, 1)
        c.asnOf = { _ in 4808 } // the commented line never parsed as a number (same as NCRuleMatcher's Int(payload))
        XCTAssertFalse(idx.contains(c))
        c.asnOf = { _ in 9999 }
        XCTAssertFalse(idx.contains(c))
    }
}
