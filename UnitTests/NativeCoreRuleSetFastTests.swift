import XCTest
@testable import Mihomo

/// fix/nc-ruleset-fast: rule-set / module / script updates as fast as QuantumultX's 「更新」 without costing memory —
/// conditional GET (ETag / Last-Modified sidecar), 304 and byte-identical bodies keep the index without a parse,
/// six downloads in flight with one parse at a time, failures keep the old cache.
final class NativeCoreRuleSetFastTests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("nc-rsfast-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    private final class Counter {
        let lock = NSLock()
        var parses = 0, inParse = 0, maxInParse = 0
        var downloads = 0, inDownload = 0, maxInDownload = 0
        var headers: [[String: String]] = []
        func parse(_ begin: Bool) {
            lock.lock(); defer { lock.unlock() }
            if begin { parses += 1; inParse += 1; maxInParse = max(maxInParse, inParse) } else { inParse -= 1 }
        }
        func read<T>(_ f: (Counter) -> T) -> T { lock.lock(); defer { lock.unlock() }; return f(self) }
    }

    private func tempBody(_ text: String) -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("nc-rsfast-dl-\(UUID().uuidString).tmp")
        try? Data(text.utf8).write(to: u)
        return u
    }

    private func setFiles() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasPrefix("set-") }.sorted()
    }

    private func sidecars() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasSuffix(".etag") }.sorted()
    }

    private func refresh(_ store: NCRuleProviderStore, _ p: NCRuleProviderStore.Provider) {
        let e = expectation(description: "refresh \(p.name)")
        store.refresh(p) { e.fulfill() }
        wait(for: [e], timeout: 10)
    }

    private let provider = NCRuleProviderStore.Provider(name: "G", behavior: "classical", format: "text",
                                                       url: "https://lists.example.com/g.list")
    private let body = "DOMAIN-SUFFIX,keep.com\nDOMAIN,exact.io\n"
    private let lm = "Wed, 21 Oct 2026 07:28:00 GMT"

    // MARK: 304

    func testNotModifiedKeepsIndexWithoutParse() {
        let store = NCRuleProviderStore(dir: dir)
        let c = Counter()
        store.parseObserver = { c.parse($0) }
        let lm = self.lm
        var answer: () -> NCRuleProviderStore.Download = { [unowned self] in
            .file(self.tempBody(self.body), etag: "\"v1\"", lastModified: lm)
        }
        store.httpDownloader = { _, headers, done in
            c.lock.lock(); c.headers.append(headers); c.lock.unlock()
            done(answer())
        }
        refresh(store, provider)
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")))
        XCTAssertEqual(c.read { $0.parses }, 1)
        XCTAssertEqual(c.read { $0.headers.first }, [:], "first download sends no validators")
        XCTAssertEqual(sidecars().count, 1)
        let cache = dir.appendingPathComponent(setFiles()[0])
        let before = try? Data(contentsOf: cache)

        answer = { .notModified }
        refresh(store, provider)
        let sent = c.read { $0.headers.last } ?? [:]
        XCTAssertEqual(sent["If-None-Match"], "\"v1\"")
        XCTAssertEqual(sent["If-Modified-Since"], lm)
        XCTAssertEqual(c.read { $0.parses }, 1, "304 does not parse")
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")))
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "exact.io")))
        XCTAssertEqual(try? Data(contentsOf: cache), before, "cache kept")
        XCTAssertEqual(setFiles().count, 1)
        XCTAssertFalse(store.needsRefresh(provider), "a 304 stamps the list fresh")

        // across a restart: the cold store loads the cache and still sends the validators
        let store2 = NCRuleProviderStore(dir: dir)
        store2.loadCached(providers: [provider], home: dir.path)
        let c2 = Counter()
        store2.parseObserver = { c2.parse($0) }
        store2.httpDownloader = { _, headers, done in
            c2.lock.lock(); c2.headers.append(headers); c2.lock.unlock()
            done(.notModified)
        }
        refresh(store2, provider)
        XCTAssertEqual(c2.read { $0.headers.first?["If-None-Match"] }, "\"v1\"")
        XCTAssertEqual(c2.read { $0.parses }, 0)
        XCTAssertTrue(store2.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")))
    }

    func testNotModifiedWithoutLoadedIndexIsAFailure() {
        let store = NCRuleProviderStore(dir: dir)
        var sent: [String: String]? = nil
        store.httpDownloader = { _, headers, done in sent = headers; done(.notModified) }
        refresh(store, provider)
        XCTAssertEqual(sent, [:], "nothing loaded: no validators sent")
        XCTAssertFalse(store.isLoaded(name: "G"))
        XCTAssertTrue(store.needsRefresh(provider), "not stamped fresh")
    }

    // MARK: sidecar

    func testValidatorsSidecarRoundTrip() throws {
        let cache = dir.appendingPathComponent("set-0123456789abcdef.txt")
        try Data(body.utf8).write(to: cache)
        let url = "https://lists.example.com/g.list"
        let v = NCFetchValidators(url: url, etag: "W/\"abc\"", lastModified: lm, bodySize: body.utf8.count,
                                  bodyHash: NCContentHash.hex(Data(body.utf8)), cacheSize: body.utf8.count)
        v.save(for: cache)
        let side = NCFetchValidators.sidecar(for: cache)
        XCTAssertEqual(side.lastPathComponent, ".set-0123456789abcdef.txt.etag")
        XCTAssertFalse(side.lastPathComponent.hasPrefix("set-"), "never mistaken for a cache file")
        XCTAssertEqual(NCFetchValidators.load(for: cache, url: url), v)
        XCTAssertEqual(v.requestHeaders, ["If-None-Match": "W/\"abc\"", "If-Modified-Since": lm])
        var req = URLRequest(url: URL(string: url)!)
        v.apply(to: &req)
        XCTAssertEqual(req.value(forHTTPHeaderField: "If-None-Match"), "W/\"abc\"")
        XCTAssertTrue(v.sameBody(size: body.utf8.count, hash: NCContentHash.hex(Data(body.utf8))))
        XCTAssertFalse(v.sameBody(size: body.utf8.count, hash: NCContentHash.hex(Data("x".utf8))))
        XCTAssertEqual(NCContentHash.file(cache)?.hash, v.bodyHash)

        XCTAssertNil(NCFetchValidators.load(for: cache, url: url + "?x"), "another URL's validators are ignored")
        try Data("DOMAIN,other.com\n".utf8).write(to: cache)
        XCTAssertNil(NCFetchValidators.load(for: cache, url: url), "a cache rewritten elsewhere invalidates them")
        try Data(body.utf8).write(to: cache)
        XCTAssertNotNil(NCFetchValidators.load(for: cache, url: url))
        NCFetchValidators.remove(for: cache)
        XCTAssertNil(NCFetchValidators.load(for: cache, url: url))
        XCTAssertEqual(NCFetchValidators(url: url).requestHeaders, [:])
    }

    // MARK: identical body

    func testIdenticalBodySkipsParse() {
        let store = NCRuleProviderStore(dir: dir)
        let c = Counter()
        store.parseObserver = { c.parse($0) }
        var text = body
        store.downloader = { [unowned self] _, done in done(self.tempBody(text)) }
        refresh(store, provider)
        XCTAssertEqual(c.read { $0.parses }, 1)
        let cache = dir.appendingPathComponent(setFiles()[0])

        refresh(store, provider)
        XCTAssertEqual(c.read { $0.parses }, 1, "byte-identical body is not parsed again")
        XCTAssertEqual(setFiles(), [cache.lastPathComponent], "no .part left")
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")))
        XCTAssertFalse(store.needsRefresh(provider))

        // without a sidecar (cache written by an older build) the cache file itself is compared
        NCFetchValidators.remove(for: cache)
        refresh(store, provider)
        XCTAssertEqual(c.read { $0.parses }, 1)

        // same size, different bytes: parsed
        text = body.replacingOccurrences(of: "keep.com", with: "kept.com")
        XCTAssertEqual(text.utf8.count, body.utf8.count)
        refresh(store, provider)
        XCTAssertEqual(c.read { $0.parses }, 2)
        XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.kept.com")))
        XCTAssertFalse(store.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")))
        XCTAssertEqual(try? Data(contentsOf: cache), Data(text.utf8))
    }

    // MARK: concurrency

    func testSixDownloadsOneParse() {
        let store = NCRuleProviderStore(dir: dir)
        let c = Counter()
        var parsedDone = 0
        var parsedWhenAllStarted = -1
        store.parseObserver = { begin in
            c.parse(begin)
            if begin { Thread.sleep(forTimeInterval: 0.03) } else { c.lock.lock(); parsedDone += 1; c.lock.unlock() }
        }
        let q = DispatchQueue(label: "rsfast.dl", attributes: .concurrent)
        store.httpDownloader = { url, _, done in
            c.lock.lock()
            c.downloads += 1; c.inDownload += 1; c.maxInDownload = max(c.maxInDownload, c.inDownload)
            if c.downloads == 20 { parsedWhenAllStarted = parsedDone }
            c.lock.unlock()
            let name = String(url.split(separator: "/").last ?? "x")
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("nc-rsfast-\(UUID().uuidString)")
            try? Data("DOMAIN-SUFFIX,\(name).test\n".utf8).write(to: tmp)
            q.asyncAfter(deadline: .now() + 0.01) {
                c.lock.lock(); c.inDownload -= 1; c.lock.unlock()
                done(.file(tmp, etag: nil, lastModified: nil))
            }
        }
        let ps = (0..<20).map { NCRuleProviderStore.Provider(name: "p\($0)", behavior: "classical", format: "text",
                                                            url: "https://lists.example.com/p\($0)") }
        store.refreshAll(ps)
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !ps.allSatisfy({ store.isLoaded(name: $0.name) }) {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        XCTAssertTrue(ps.allSatisfy { store.isLoaded(name: $0.name) }, "\(store.loadedNames().sorted())")
        XCTAssertEqual(NCRuleProviderStore.maxConcurrentFetches, 6)
        c.lock.lock(); defer { c.lock.unlock() }
        XCTAssertEqual(c.downloads, 20)
        XCTAssertEqual(c.maxInDownload, 6, "six downloads in flight")
        XCTAssertEqual(c.maxInParse, 1, "one parse at a time")
        XCTAssertEqual(c.parses, 20)
        XCTAssertGreaterThanOrEqual(parsedWhenAllStarted, 0)
        XCTAssertLessThan(parsedWhenAllStarted, 20, "downloads do not wait for parses")
    }

    // MARK: failures

    func testFailuresKeepOldCacheAndValidators() {
        let store = NCRuleProviderStore(dir: dir)
        var answer: () -> NCRuleProviderStore.Download = { [unowned self] in
            .file(self.tempBody(self.body), etag: "\"v1\"", lastModified: nil)
        }
        store.httpDownloader = { _, _, done in done(answer()) }
        refresh(store, provider)
        let cache = dir.appendingPathComponent(setFiles()[0])
        let side = try? Data(contentsOf: NCFetchValidators.sidecar(for: cache))
        XCTAssertNotNil(side)

        func check(_ what: String) {
            XCTAssertTrue(store.contains(name: "G", ctx: NCMatchContext(domain: "a.keep.com")), what)
            XCTAssertEqual(setFiles(), [cache.lastPathComponent], what + ": no .part left, cache not replaced")
            XCTAssertEqual(try? Data(contentsOf: cache), Data(body.utf8), what)
            XCTAssertEqual(try? Data(contentsOf: NCFetchValidators.sidecar(for: cache)), side, what + ": validators kept")
        }
        answer = { .failed }
        refresh(store, provider); check("network failure")
        answer = { [unowned self] in .file(self.tempBody("# only comments\n"), etag: "\"v2\"", lastModified: nil) }
        refresh(store, provider); check("parses to nothing")
        answer = { [unowned self] in
            let u = self.tempBody("DOMAIN,a.com\n")
            if let h = try? FileHandle(forWritingTo: u) { h.seekToEndOfFile(); h.write(Data([0xFF, 0x0A])); h.closeFile() }
            return .file(u, etag: "\"v3\"", lastModified: nil)
        }
        refresh(store, provider); check("invalid UTF-8")
        // after the failures the next request still carries the last good validators
        var sent: [String: String] = [:]
        store.httpDownloader = { _, headers, done in sent = headers; done(.notModified) }
        refresh(store, provider)
        XCTAssertEqual(sent["If-None-Match"], "\"v1\"")
        check("304 after failures")
    }

    // MARK: App-side conditional fetch (modules / scripts / remote rule lists / providers)

    private func response(_ code: Int, _ headers: [String: String] = [:]) -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: "https://x.example.com/m.sgmodule")!, statusCode: code,
                        httpVersion: "HTTP/1.1", headerFields: headers)!
    }

    func testAppConditionalFetch() async throws {
        let cache = dir.appendingPathComponent("module.txt")
        let url = "https://x.example.com/m.sgmodule"
        let v1 = Data("#!name=M\n[Rule]\nDOMAIN,a.com,REJECT\n".utf8)
        var requests: [URLRequest] = []
        var reply: (Int, Data, [String: String]) = (200, v1, ["ETag": "\"m1\"", "Last-Modified": lm])
        let get: (URLRequest) async throws -> (Data, URLResponse) = { req in
            requests.append(req)
            return (reply.1, self.response(reply.0, reply.2))
        }

        // first: a body; the caller writes its cache, then commits the validators
        guard case .body(let d1, let commit1) = await NCConditionalFetch.fetch(url, cache: cache, userAgent: "UA", httpGet: get) else {
            return XCTFail("expected a body")
        }
        XCTAssertNil(requests[0].value(forHTTPHeaderField: "If-None-Match"))
        XCTAssertEqual(requests[0].value(forHTTPHeaderField: "User-Agent"), "UA")
        try (d1 + Data("# converted\n".utf8)).write(to: cache) // the written cache may differ from the body
        commit1(cache)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_000_000)], ofItemAtPath: cache.path)

        // 304: kept, 「更新于」 moves
        reply = (304, Data(), [:])
        guard case .unchanged = await NCConditionalFetch.fetch(url, cache: cache, userAgent: "UA", httpGet: get) else {
            return XCTFail("expected unchanged on 304")
        }
        XCTAssertEqual(requests[1].value(forHTTPHeaderField: "If-None-Match"), "\"m1\"")
        XCTAssertEqual(requests[1].value(forHTTPHeaderField: "If-Modified-Since"), lm)
        let m = (try FileManager.default.attributesOfItem(atPath: cache.path))[.modificationDate] as? Date
        XCTAssertGreaterThan(m?.timeIntervalSince1970 ?? 0, 1_000_000)

        // 200, same bytes, no validators: still unchanged
        reply = (200, v1, [:])
        guard case .unchanged = await NCConditionalFetch.fetch(url, cache: cache, userAgent: "UA", httpGet: get) else {
            return XCTFail("expected unchanged on identical body")
        }

        // 200, new bytes: a body
        reply = (200, Data("#!name=M\n[Rule]\nDOMAIN,b.com,REJECT\n".utf8), [:])
        guard case .body = await NCConditionalFetch.fetch(url, cache: cache, userAgent: "UA", httpGet: get) else {
            return XCTFail("expected a new body")
        }

        // failure: reported, cache untouched
        reply = (500, Data(), [:])
        guard case .failed(let e) = await NCConditionalFetch.fetch(url, cache: cache, userAgent: "UA", httpGet: get) else {
            return XCTFail("expected a failure")
        }
        XCTAssertEqual(e, "HTTP 500")
        XCTAssertEqual(try Data(contentsOf: cache), v1 + Data("# converted\n".utf8))

        // a 304 to a request that carried no validators is not ours to keep
        let other = dir.appendingPathComponent("other.txt")
        reply = (304, Data(), [:])
        guard case .failed = await NCConditionalFetch.fetch(url, cache: other, userAgent: nil, httpGet: get) else {
            return XCTFail("expected a failure on an unsolicited 304")
        }
        // over the size cap
        reply = (200, Data(count: 2 << 20), [:])
        guard case .failed = await NCConditionalFetch.fetch(url, cache: other, userAgent: nil, maxBytes: 1 << 20, httpGet: get) else {
            return XCTFail("expected a failure over the cap")
        }
    }
}
