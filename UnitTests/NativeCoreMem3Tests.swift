import XCTest
@testable import Mihomo

/// fix/nc-mem-3: the cold rule-set refresh no longer holds whole bodies / bridged per-line strings.
/// - native whitespace trim == Foundation `trimmingCharacters(in: .whitespaces)`
/// - streamed parse (addData, pooled per 256 lines, Substring fields) == a Foundation reference parse
/// - production path: download-to-file → mapped parse → rename to the cache file (no body copy), gates kept
final class NativeCoreMem3Tests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("nc-mem3-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    // MARK: trim

    func testNativeTrimMatchesFoundation() {
        let samples = [
            "", " ", "\t", "  a  ", "\ta\t", "a", "a b", " a b ", "\u{00A0}x\u{00A0}", "\u{3000}全角\u{3000}",
            "\u{2003}em\u{2002}", " \u{0301}a", "a \u{0301}", "\u{FEFF}bom", "x\n", "\ny", " \r ", "\u{200B}zw", "zw\u{200B}", "\u{202F}nnbsp\u{205F}", "\u{2028}ls", "\u{180E}mvs",
            "DOMAIN-SUFFIX , google.com ", "  # comment", "\u{1680}ogham\u{205F}", "😀 ", " 😀",
        ]
        for s in samples {
            XCTAssertEqual(NCRuleSetIndex.trimSpaces(s), s.trimmingCharacters(in: .whitespaces), "\(s.unicodeScalars.map { $0.value })")
            XCTAssertEqual(String(NCRuleSetIndex.trimSpacesSub(s[...])), s.trimmingCharacters(in: .whitespaces))
        }
        XCTAssertEqual(NCRuleSetIndex.indexAfterScheme("https://a.b/c").map { String("https://a.b/c"[$0...]) }, "a.b/c")
        XCTAssertNil(NCRuleSetIndex.indexAfterScheme("a.b:80/c"))
        XCTAssertNil(NCRuleSetIndex.indexAfterScheme("x:/"))
    }

    // MARK: parse equivalence

    /// A Global-shaped mixed list: UPPERCASE QX names, classical, comments (leading and trailing), CRLF, blank and
    /// Unicode-space-padded lines, IP-ASN with comments, CIDRs, keywords, an unknown type, duplicates.
    private func mixedBody(_ n: Int, crlf: Bool) -> String {
        var lines: [String] = ["# NAME: Global", "# TOTAL: \(n)", ""]
        for i in 0..<n {
            switch i % 11 {
            case 0: lines.append("HOST-SUFFIX,site\(i).com,Global")
            case 1: lines.append("HOST,www.site\(i).net,Global")
            case 2: lines.append("DOMAIN-SUFFIX, sfx\(i).org ")
            case 3: lines.append("\u{3000}DOMAIN,exact\(i).io\u{00A0}")
            case 4: lines.append("IP-ASN,\(4000 + i) // carrier \(i)")
            case 5: lines.append("IP-CIDR,10.\(i % 256).0.0/16,no-resolve")
            case 6: lines.append("DOMAIN-KEYWORD,kw\(i)")
            case 7: lines.append("host-wildcard,*.w\(i).cn,Proxy")
            case 8: lines.append("FOO-BAR,unknown\(i)")
            case 9: lines.append("DOMAIN-SUFFIX,dup.com # again")
            default: lines.append("   ")
            }
        }
        lines.append("// tail comment")
        return lines.joined(separator: crlf ? "\r\n" : "\n") + (crlf ? "\r\n" : "\n")
    }

    private struct Ref {
        var flags: [String: UInt8] = [:]
        var asns: Set<UInt32> = []
        var others = 0
        var entries = 0
    }

    /// Reference parse with Foundation (the pre-mem-3 per-line steps) for classical lines.
    private func reference(_ body: String) -> Ref {
        var r = Ref()
        let qx = ["HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD",
                  "HOST-WILDCARD": "DOMAIN-WILDCARD", "IP6-CIDR": "IP-CIDR"]
        for raw in body.components(separatedBy: .newlines) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { continue }
            if let cut = NCRuleSetIndex.trailingCommentStart(line) {
                line = String(line[..<cut]).trimmingCharacters(in: .whitespaces)
            }
            if line.isEmpty { continue }
            let f = line.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            guard f.count >= 2 else { continue }
            var kind = f[0].uppercased()
            kind = qx[kind] ?? kind
            switch kind {
            case "DOMAIN": r.flags[f[1].lowercased(), default: 0] |= NCDomainTable.exact; r.entries += 1
            case "DOMAIN-SUFFIX": r.flags[f[1].lowercased(), default: 0] |= NCDomainTable.suffix; r.entries += 1
            case "IP-ASN":
                if let n = UInt32(f[1]) { r.asns.insert(n) }
                r.entries += 1
            default:
                if NCRuleSetIndex.matchableKinds.contains(kind) { r.others += 1 }
                r.entries += 1
            }
        }
        return r
    }

    func testStreamedParseMatchesFoundationReference() {
        for crlf in [false, true] {
            let body = mixedBody(6000, crlf: crlf)
            let ref = reference(body)
            var idx = NCRuleSetIndex()
            XCTAssertTrue(idx.addData(Data(("\u{FEFF}" + body).utf8), flavor: .classical))
            idx.finalize()
            XCTAssertEqual(idx.entryCount, ref.entries)
            XCTAssertEqual(idx.others.count, ref.others)
            XCTAssertEqual(idx.asns, ref.asns)
            XCTAssertEqual(idx.domains.count, ref.flags.count)
            for (host, fl) in ref.flags {
                let exact = idx.contains(NCMatchContext(domain: host))
                let sub = idx.contains(NCMatchContext(domain: "a." + host))
                XCTAssertTrue(exact, host)
                XCTAssertEqual(sub, fl & NCDomainTable.suffix != 0, host)
            }
            XCTAssertFalse(idx.contains(NCMatchContext(domain: "nothere.example")))
            XCTAssertTrue(idx.contains(NCMatchContext(domain: "x.kw6.test")))
            XCTAssertTrue(idx.needsIP)
        }
    }

    func testStreamedParseMatchesTextParse() {
        // Same index from the byte stream and from the String path (addText → components → addLine), all flavours.
        let domainBody = (0..<3000).map { i -> String in
            switch i % 5 {
            case 0: return ".s\(i).com"
            case 1: return "+.p\(i).net"
            case 2: return "*.w\(i).org"
            case 3: return "https://u\(i).io/path"
            default: return " e\(i).cn "
            }
        }.joined(separator: "\n")
        let cases: [(String, NCRuleSetFlavor)] = [
            (mixedBody(3000, crlf: false), .classical), (mixedBody(3000, crlf: true), .auto),
            (domainBody, .domainSet), (domainBody, .auto),
            ("host-suffix,qx.com,Proxy\nhost,a.qx.com,Proxy\nip-cidr,1.2.3.0/24,Proxy\n", .qx),
        ]
        for (body, flavor) in cases {
            var a = NCRuleSetIndex(), b = NCRuleSetIndex()
            XCTAssertTrue(a.addData(Data(body.utf8), flavor: flavor))
            b.addText(body, flavor: flavor)
            a.finalize(); b.finalize()
            XCTAssertEqual(a.entryCount, b.entryCount)
            XCTAssertEqual(a.domains.count, b.domains.count)
            XCTAssertEqual(a.others.count, b.others.count)
            XCTAssertEqual(a.asns, b.asns)
            for probe in ["s0.com", "a.s0.com", "p1.net", "x.p1.net", "w2.org", "x.w2.org", "u3.io", "e4.cn",
                          "site0.com", "a.site0.com", "www.site1.net", "exact3.io", "qx.com", "z.qx.com"] {
                XCTAssertEqual(a.contains(NCMatchContext(domain: probe)), b.contains(NCMatchContext(domain: probe)), probe)
            }
        }
    }

    func testInvalidUTF8StillRejectsWholeBody() {
        var d = Data("DOMAIN,a.com\n".utf8)
        d.append(contentsOf: [0xFF, 0xFE, 0x0A])
        d.append(Data("DOMAIN,b.com\n".utf8))
        var idx = NCRuleSetIndex()
        XCTAssertFalse(idx.addData(d, flavor: .classical))
    }

    // MARK: store: download-to-file path

    private func tempBody(_ text: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("nc-mem3-dl-\(UUID().uuidString).tmp")
        try? Data(text.utf8).write(to: u)
        return u
    }

    private func cacheFiles(_ store: NCRuleProviderStore) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasPrefix("set-") }.sorted()
    }

    func testDownloadedFileIsParsedAndBecomesTheCache() {
        let store = NCRuleProviderStore(dir: dir)
        let p = NCRuleProviderStore.Provider(name: "G", behavior: "classical", url: "https://lists.example.com/g.list")
        let body = mixedBody(2000, crlf: false)
        let tmp = tempBody(body)
        store.downloader = { _, done in done(tmp) }
        let e = expectation(description: "refresh")
        store.refresh(p) { e.fulfill() }
        wait(for: [e], timeout: 5)
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.site0.com")))
        XCTAssertFalse(FileManager.default.fileExists(atPath: tmp.path), "temporary download moved, not copied")
        let files = cacheFiles(store)
        XCTAssertEqual(files.count, 1, "\(files)")
        XCTAssertFalse(files.contains { $0.hasSuffix(".part") })
        XCTAssertEqual(try? Data(contentsOf: dir.appendingPathComponent(files[0])), Data(body.utf8))

        // a fresh store loads the renamed file as its cache, same index as the Data path
        let store2 = NCRuleProviderStore(dir: dir)
        let stale = store2.loadCached(providers: [p], home: dir.path)
        XCTAssertTrue(stale.isEmpty)
        XCTAssertTrue(store2.contains(name: "G", ctx: NCMatchContext(domain: "a.site0.com")))
        let store3 = NCRuleProviderStore(dir: dir.appendingPathComponent("d3"))
        store3.fetcher = { _, done in done(Data(body.utf8)) }
        let e3 = expectation(description: "data path")
        store3.refresh(p) { e3.fulfill() }
        wait(for: [e3], timeout: 5)
        for probe in ["site0.com", "a.site0.com", "www.site1.net", "a.sfx2.org", "exact3.io", "dup.com", "kw6.x"] {
            XCTAssertEqual(store2.contains(name: "G", ctx: NCMatchContext(domain: probe)),
                           store3.contains(name: "G", ctx: NCMatchContext(domain: probe)), probe)
        }
    }

    func testDownloadFailuresKeepOldIndexAndCache() {
        let store = NCRuleProviderStore(dir: dir)
        var p = NCRuleProviderStore.Provider(name: "S", behavior: "classical", url: "https://x.example.com/s.txt")
        store.downloader = { [unowned self] _, done in done(self.tempBody("DOMAIN-SUFFIX,keep.com\n")) }
        let e1 = expectation(description: "first")
        store.refresh(p) { e1.fulfill() }
        wait(for: [e1], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
        let cached = cacheFiles(store)
        XCTAssertEqual(cached.count, 1)
        p.interval = 0

        func refresh(_ make: @escaping () -> URL?) {
            store.downloader = { _, done in done(make()) }
            let e = expectation(description: "refresh")
            store.refresh(p) { e.fulfill() }
            wait(for: [e], timeout: 10)
            XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
            XCTAssertEqual(cacheFiles(store), cached, "no .part left, cache not replaced")
            XCTAssertEqual(try? Data(contentsOf: dir.appendingPathComponent(cached[0])), Data("DOMAIN-SUFFIX,keep.com\n".utf8))
        }
        refresh { nil }                                                     // network failure
        refresh { [unowned self] in self.tempBody("# nothing but comments\n") } // parses to nothing
        refresh { [unowned self] in                                          // invalid UTF-8
            let u = self.tempBody("DOMAIN,a.com\n")
            if let h = try? FileHandle(forWritingTo: u) { h.seekToEndOfFile(); h.write(Data([0xFF, 0x0A])); h.closeFile() }
            return u
        }
        refresh {                                                            // over the payload cap (sparse file)
            let u = FileManager.default.temporaryDirectory.appendingPathComponent("nc-mem3-big-\(UUID().uuidString)")
            FileManager.default.createFile(atPath: u.path, contents: Data("DOMAIN,big.com\n".utf8))
            if let h = try? FileHandle(forWritingTo: u) { h.truncateFile(atOffset: UInt64(NCRuleProviderStore.maxPayloadBytes + 1)); h.closeFile() }
            return u
        }
        XCTAssertFalse(store.contains(name: "S", ctx: NCMatchContext(domain: "big.com")))
    }

    func testRefreshAllWithDownloaderStaysBounded() {
        let store = NCRuleProviderStore(dir: dir)
        let lock = NSLock()
        var inFlight = 0, maxInFlight = 0, started = 0
        let q = DispatchQueue(label: "mem3.dl", attributes: .concurrent)
        store.downloader = { url, done in
            lock.lock(); inFlight += 1; started += 1; maxInFlight = max(maxInFlight, inFlight); lock.unlock()
            let name = String(url.split(separator: "/").last ?? "x")
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("nc-mem3-\(UUID().uuidString)")
            try? Data("DOMAIN-SUFFIX,\(name).test\n".utf8).write(to: tmp)
            q.asyncAfter(deadline: .now() + 0.02) {
                lock.lock(); inFlight -= 1; lock.unlock()
                done(name == "p4" ? nil : tmp)
            }
        }
        let ps = (0..<10).map { NCRuleProviderStore.Provider(name: "p\($0)", behavior: "classical", format: "text",
                                                            url: "https://lists.example.com/p\($0)") }
        store.refreshAll(ps)
        let want = Set(ps.map(\.name)).subtracting(["p4"])
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, !want.allSatisfy({ store.isLoaded(name: $0) }) {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        XCTAssertTrue(want.allSatisfy { store.isLoaded(name: $0) }, "\(store.loadedNames().sorted())")
        XCTAssertFalse(store.isLoaded(name: "p4"))
        lock.lock(); defer { lock.unlock() }
        XCTAssertEqual(started, 10)
        XCTAssertLessThanOrEqual(maxInFlight, NCRuleProviderStore.maxConcurrentFetches)
        XCTAssertTrue(store.contains(name: "p9", ctx: NCMatchContext(domain: "a.p9.test")))
    }

    func testMemLineDoesNotThrowOrBlock() {
        let was = NCRuleProviderStore.memLog
        NCRuleProviderStore.memLog = true
        NCRuleProviderStore.memLine("https://raw.githubusercontent.com/x/Global.list", "parsed entries=1 ms=0")
        NCRuleProviderStore.memLog = was
    }
}
