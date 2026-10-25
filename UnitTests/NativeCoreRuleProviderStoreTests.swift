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
}
