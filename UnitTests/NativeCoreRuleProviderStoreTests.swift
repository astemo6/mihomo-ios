import XCTest
@testable import Mihomo

final class NativeCoreRuleProviderStoreTests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-rps-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    private func config() -> NCConfig {
        NCConfig.decode(root: [
            "rules": .array([
                .string("RULE-SET,Reject,REJECT"),
                .string("RULE-SET,https://lists.example.com/ads.txt,REJECT"),
                .string("MATCH,DIRECT"),
            ]),
            "rule-providers": .object([
                "Reject": .object([
                    "type": .string("http"), "behavior": .string("classical"),
                    "url": .string("https://rules.example.com/reject.yaml"),
                    "interval": .number(3600)]),
                "Inline": .object([
                    "type": .string("inline"), "behavior": .string("domain"),
                    "payload": .array([.string("example.org"), .string(".subonly.org")])]),
            ]),
        ])
    }

    func testProviderDiscovery() {
        let ps = NCRuleProviderStore.providers(from: config())
        XCTAssertEqual(Set(ps.map { $0.name }),
                       ["Reject", "Inline", "https://lists.example.com/ads.txt"])
        let reject = ps.first { $0.name == "Reject" }
        XCTAssertEqual(reject?.behavior, "classical")
        XCTAssertEqual(reject?.interval, 3600)
        let urlSet = ps.first { $0.name.hasPrefix("https://lists") }
        XCTAssertEqual(urlSet?.flavor, .auto)
    }

    func testInlineAndCacheAndRefresh() {
        let store = NCRuleProviderStore(dir: dir)
        let ps = NCRuleProviderStore.providers(from: config())
        let stale = store.loadCached(providers: ps, home: dir.path)
        // Inline loads immediately; the http ones have no cache yet → stale.
        // Domain-set semantics (Surge): plain = exact, leading dot = self + subdomains.
        XCTAssertTrue(store.contains(name: "Inline", ctx: NCMatchContext(domain: "example.org")))
        XCTAssertFalse(store.contains(name: "Inline", ctx: NCMatchContext(domain: "a.example.org")))
        XCTAssertTrue(store.contains(name: "Inline", ctx: NCMatchContext(domain: "a.subonly.org")))
        XCTAssertEqual(Set(stale.map { $0.name }), ["Reject", "https://lists.example.com/ads.txt"])
        XCTAssertFalse(store.contains(name: "Reject", ctx: NCMatchContext(domain: "bad.com")))

        // Stubbed fetch swaps the index and writes the cache file.
        store.fetcher = { _, done in
            done(Data("DOMAIN-SUFFIX,bad.com\nDOMAIN,exact.bad.com\n".utf8))
        }
        let exp = expectation(description: "refresh")
        store.refresh(ps.first { $0.name == "Reject" }!) { exp.fulfill() }
        wait(for: [exp], timeout: 5)
        XCTAssertTrue(store.contains(name: "Reject", ctx: NCMatchContext(domain: "x.bad.com")))
        XCTAssertTrue(store.contains(name: "Reject", ctx: NCMatchContext(domain: "exact.bad.com")))

        // A fresh store over the same dir loads from cache without network.
        let store2 = NCRuleProviderStore(dir: dir)
        let stale2 = store2.loadCached(providers: ps, home: dir.path)
        XCTAssertTrue(store2.contains(name: "Reject", ctx: NCMatchContext(domain: "x.bad.com")))
        XCTAssertFalse(stale2.contains { $0.name == "Reject" }) // timestamp persisted → fresh
    }

    func testFailedRefreshKeepsOldIndex() {
        let store = NCRuleProviderStore(dir: dir)
        var p = NCRuleProviderStore.Provider(name: "S", behavior: "classical",
                                             url: "https://x.example.com/s.txt")
        store.fetcher = { _, done in done(Data("DOMAIN-SUFFIX,keep.com\n".utf8)) }
        let e1 = expectation(description: "first")
        store.refresh(p) { e1.fulfill() }
        wait(for: [e1], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
        p.interval = 0
        store.fetcher = { _, done in done(nil) }
        let e2 = expectation(description: "second")
        store.refresh(p) { e2.fulfill() }
        wait(for: [e2], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
    }

    func testOversizedPayloadRefreshKeepsOldIndexAndCache() {
        let store = NCRuleProviderStore(dir: dir)
        let p = NCRuleProviderStore.Provider(name: "S", behavior: "classical",
                                             url: "https://x.example.com/s.txt")
        store.fetcher = { _, done in done(Data("DOMAIN-SUFFIX,keep.com\n".utf8)) }
        let e1 = expectation(description: "first")
        store.refresh(p) { e1.fulfill() }
        wait(for: [e1], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))

        // Over the 32 MB payload cap: a refresh failure — old index stays,
        // and the disk cache must not be overwritten with the bad body.
        store.fetcher = { _, done in done(Data(count: NCRuleProviderStore.maxPayloadBytes + 1)) }
        let e2 = expectation(description: "oversized")
        store.refresh(p) { e2.fulfill() }
        wait(for: [e2], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
        let store2 = NCRuleProviderStore(dir: dir)
        store2.loadCached(providers: [p], home: dir.path)
        XCTAssertTrue(store2.contains(name: "S", ctx: NCMatchContext(domain: "a.keep.com")))
    }

    func testTooManyEntriesRefreshKeepsOldIndex() {
        // Domain behavior (plain host per line) keeps the generated list on
        // the line-by-line path — no YAML `payload:` document probe.
        let store = NCRuleProviderStore(dir: dir)
        let p = NCRuleProviderStore.Provider(name: "S", behavior: "domain",
                                             url: "https://x.example.com/s.txt")
        store.fetcher = { _, done in done(Data("keep.com\n".utf8)) }
        let e1 = expectation(description: "first")
        store.refresh(p) { e1.fulfill() }
        wait(for: [e1], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "keep.com")))

        // One entry over the cap: rejected as a whole, old index kept.
        var big = ""
        big.reserveCapacity(9_000_000)
        for i in 0...NCRuleProviderStore.maxEntries { big += "d\(i).example.com\n" }
        store.fetcher = { _, done in done(Data(big.utf8)) }
        let e2 = expectation(description: "too many")
        store.refresh(p) { e2.fulfill() }
        wait(for: [e2], timeout: 5)
        XCTAssertTrue(store.contains(name: "S", ctx: NCMatchContext(domain: "keep.com")))
        XCTAssertFalse(store.contains(name: "S", ctx: NCMatchContext(domain: "d0.example.com")))
    }

    func testTooManyEntriesLocalFileIsRejected() {
        var big = ""
        big.reserveCapacity(9_000_000)
        for i in 0...NCRuleProviderStore.maxEntries { big += "d\(i).example.com\n" }
        let file = dir.appendingPathComponent("big.txt")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try! big.write(to: file, atomically: true, encoding: .utf8)
        let store = NCRuleProviderStore(dir: dir)
        let p = NCRuleProviderStore.Provider(name: "F", behavior: "domain",
                                             filePath: file.path)
        store.loadCached(providers: [p], home: dir.path)
        XCTAssertFalse(store.isLoaded(name: "F"))
        XCTAssertFalse(store.contains(name: "F", ctx: NCMatchContext(domain: "d0.example.com")))
    }

    // MARK: one entry gate for every load path (fix/nc-followup-a)

    private func domainLines(_ n: Int) -> [String] {
        var out: [String] = []
        out.reserveCapacity(n)
        for i in 0..<n { out.append("d\(i).example.com") }
        return out
    }

    func testInlinePayloadOverCapIsRejectedBySharedGate() {
        // Inline payloads never reach populateIndex; they must still hit the
        // same gate (same limit, same comparison) as file / cache / refresh.
        let store = NCRuleProviderStore(dir: dir)
        let p = NCRuleProviderStore.Provider(name: "I", behavior: "domain",
                                             inlinePayload: domainLines(NCRuleProviderStore.maxEntries + 1))
        store.loadCached(providers: [p], home: dir.path)
        XCTAssertFalse(store.isLoaded(name: "I"))
        XCTAssertFalse(store.contains(name: "I", ctx: NCMatchContext(domain: "d0.example.com")))
    }

    func testInlinePayloadExactlyAtCapStillLoads() {
        // Valid input at the boundary keeps loading (gate is inclusive).
        let store = NCRuleProviderStore(dir: dir)
        let n = NCRuleProviderStore.maxEntries
        let p = NCRuleProviderStore.Provider(name: "I", behavior: "domain",
                                             inlinePayload: domainLines(n))
        store.loadCached(providers: [p], home: dir.path)
        XCTAssertTrue(store.isLoaded(name: "I"))
        XCTAssertTrue(store.contains(name: "I", ctx: NCMatchContext(domain: "d\(n - 1).example.com")))
    }

    func testPopulateIndexAndInlineGateAgreeAtBoundary() {
        // Same list through both entry points: at the cap both accept, one
        // over both reject with the same error — one gate, one limit.
        let p = NCRuleProviderStore.Provider(name: "G", behavior: "domain")
        let atCap = domainLines(NCRuleProviderStore.maxEntries)

        var viaData = NCRuleSetIndex()
        XCTAssertNoThrow(try NCRuleProviderStore.populateIndex(
            idx: &viaData, data: Data(atCap.joined(separator: "\n").utf8), provider: p))
        var viaLines = NCRuleSetIndex()
        for l in atCap { viaLines.addLine(l, flavor: p.flavor) }
        XCTAssertNoThrow(try NCRuleProviderStore.checkEntryGate(viaLines, provider: p))
        XCTAssertEqual(viaData.entryCount, viaLines.entryCount)

        viaLines.addLine("one-more.example.com", flavor: p.flavor)
        XCTAssertThrowsError(try NCRuleProviderStore.checkEntryGate(viaLines, provider: p)) { err in
            guard case NCRuleProviderGateError.tooManyEntries(_, let count, let limit)? = err as? NCRuleProviderGateError else {
                return XCTFail("unexpected error \(err)")
            }
            XCTAssertEqual(count, NCRuleProviderStore.maxEntries + 1)
            XCTAssertEqual(limit, NCRuleProviderStore.maxEntries)
        }
        var overData = NCRuleSetIndex()
        XCTAssertThrowsError(try NCRuleProviderStore.populateIndex(
            idx: &overData, data: Data((atCap + ["one-more.example.com"]).joined(separator: "\n").utf8), provider: p)) { err in
            guard case NCRuleProviderGateError.tooManyEntries? = err as? NCRuleProviderGateError else {
                return XCTFail("unexpected error \(err)")
            }
        }
    }

    /// Go-era configs carry http://127.0.0.1:9090/rules/convert?url=<src>&kind=<kind>; NativeCore has no
    /// converter (27 × 401 on device, build 401), so the store fetches <src> directly.
    func testLoopbackConvertUnwrapped() {
        let src = "https://example.com/QX/Filter/Ads.list"
        var comps = URLComponents(string: "http://127.0.0.1:9090/rules/convert")!
        comps.queryItems = [URLQueryItem(name: "url", value: src), URLQueryItem(name: "kind", value: "domainset")]
        let wrapped = comps.string!
        XCTAssertEqual(NCRuleProviderStore.unwrapLoopbackConvert(wrapped), src)
        XCTAssertEqual(NCRuleProviderStore.unwrapLoopbackConvert(src), src)
        XCTAssertEqual(NCRuleProviderStore.unwrapLoopbackConvert("http://127.0.0.1:9090/version"), "http://127.0.0.1:9090/version")
        XCTAssertEqual(NCRuleProviderStore.loopbackConvertKind(wrapped), "domainset")
    }

    /// Same for proxy-providers: http://127.0.0.1:<port>/nodes/convert?url=<sub> → the store fetches <sub> and
    /// NCSubscriptionParser reads the raw subscription body itself.
    func testLoopbackNodesConvertUnwrapped() {
        let src = "https://sub.example.com/api/v1/client/subscribe?token=abc&flag=clash"
        var comps = URLComponents(string: "http://127.0.0.1:9090/nodes/convert")!
        comps.queryItems = [URLQueryItem(name: "url", value: src)]
        let wrapped = comps.string!
        XCTAssertEqual(NCNodeSubscriptionStore.unwrapLoopbackConvert(wrapped), src)
        XCTAssertEqual(NCNodeSubscriptionStore.unwrapLoopbackConvert(src), src)
        XCTAssertEqual(NCNodeSubscriptionStore.unwrapLoopbackConvert("http://127.0.0.1:9090/rules/convert?url=https%3A%2F%2Fa.b%2Fc"),
                       "http://127.0.0.1:9090/rules/convert?url=https%3A%2F%2Fa.b%2Fc")

        let store = NCNodeSubscriptionStore(dir: dir)
        var fetched: [String] = []
        store.fetcher = { url, done in
            fetched.append(url)
            done(Data("""
            proxies:
              - name: HK-01
                type: ss
                server: 1.2.3.4
                port: 8388
                cipher: aes-256-gcm
                password: pass
            """.utf8))
        }
        let sub = NCNodeSubscription(name: "Airport", url: wrapped)
        let done = expectation(description: "refresh")
        store.refresh(sub) { done.fulfill() }
        wait(for: [done], timeout: 5)
        XCTAssertEqual(fetched, [src])
        XCTAssertEqual(store.nodes(for: sub).map { $0.name }, ["HK-01"])
    }

    /// New runtime configs no longer emit the loopback converter URL (nor the Bearer header) for convert providers.
    func testRuntimeConvertProvidersKeepSourceURL() {
        let o = NCRuntimeSettings(core: CoreOverrides(), dns: nil, local: nil, home: "", manualPath: "")
        var raw: [String: NCJSONValue] = [
            "rule-providers": .object([
                "Ads": .object(["type": .string("http"), "behavior": .string("classical"), "format": .string("text"),
                                "url": .string("https://example.com/Ads.list"), "x-convert": .string("domainset")]),
                "Plain": .object(["type": .string("http"), "behavior": .string("classical"),
                                  "url": .string("https://example.com/plain.yaml")]),
            ]),
            "proxy-providers": .object([
                "Sub": .object(["type": .string("http"), "url": .string("https://sub.example.com/s"),
                                "x-convert": .string("nodes")]),
            ]),
        ]
        NCRuntimeSteps.rewriteConvertProviders(&raw, o)
        let ads = raw["rule-providers"]?.object?["Ads"]?.object
        XCTAssertEqual(ads?["url"]?.string, "https://example.com/Ads.list")
        XCTAssertEqual(ads?["behavior"]?.string, "domain")
        XCTAssertEqual(ads?["format"]?.string, "text")
        XCTAssertNil(ads?["header"])
        XCTAssertNil(ads?["x-convert"])
        XCTAssertEqual(raw["rule-providers"]?.object?["Plain"]?.object?["url"]?.string, "https://example.com/plain.yaml")
        let sub = raw["proxy-providers"]?.object?["Sub"]?.object
        XCTAssertEqual(sub?["url"]?.string, "https://sub.example.com/s")
        XCTAssertNil(sub?["header"])

        var raw2: [String: NCJSONValue] = [:]
        let rule = NCRuntimeSteps.addRemoteProvider(
            &raw2, o, sp: NCRuleValidator.RemoteSpec(url: "https://example.com/Video.list", kind: "list"), interval: 0)
        XCTAssertTrue(rule.hasPrefix("RULE-SET,"))
        let p = raw2["rule-providers"]?.object?.values.first?.object
        XCTAssertEqual(p?["url"]?.string, "https://example.com/Video.list")
        XCTAssertEqual(p?["behavior"]?.string, "classical")
        XCTAssertNil(p?["header"])
    }
}
