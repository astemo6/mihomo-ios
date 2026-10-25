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
}
