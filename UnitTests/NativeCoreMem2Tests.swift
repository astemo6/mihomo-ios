import XCTest
@testable import Mihomo

/// fix/nc-mem-2: rule-set refreshes are bounded (NCRuleProviderStore.maxConcurrentFetches lists in flight), every
/// list still lands, a failed / empty fetch does not stall the chain, and a store dropped by a reload stops its own
/// chain instead of being kept alive by it.
final class NativeCoreMem2Tests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("nc-mem2-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    private final class Gauge {
        let lock = NSLock()
        var inFlight = 0, maxInFlight = 0, started = 0
        func begin() { lock.lock(); inFlight += 1; started += 1; maxInFlight = max(maxInFlight, inFlight); lock.unlock() }
        func end() { lock.lock(); inFlight -= 1; lock.unlock() }
    }

    private func providers(_ n: Int) -> [NCRuleProviderStore.Provider] {
        (0..<n).map { NCRuleProviderStore.Provider(name: "p\($0)", behavior: "classical", format: "text",
                                                   url: "https://lists.example.com/p\($0).list") }
    }

    func testRefreshAllBoundsListsInFlight() {
        let store = NCRuleProviderStore(dir: dir)
        let gauge = Gauge()
        let q = DispatchQueue(label: "mem2.fetch", attributes: .concurrent)
        store.fetcher = { url, done in
            gauge.begin()
            let name = String(url.split(separator: "/").last ?? "").replacingOccurrences(of: ".list", with: "")
            q.asyncAfter(deadline: .now() + 0.02) {
                gauge.end()
                // p3 fails, p5 parses to nothing: neither may stall the chain
                if name == "p3" { done(nil); return }
                if name == "p5" { done(Data("# only a comment\n".utf8)); return }
                done(Data("DOMAIN-SUFFIX,\(name).example.com\n".utf8))
            }
        }
        let ps = providers(12)
        store.refreshAll(ps)
        let all = Set(ps.map(\.name)).subtracting(["p3", "p5"])
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, !all.allSatisfy({ store.isLoaded(name: $0) }) {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        XCTAssertTrue(all.allSatisfy { store.isLoaded(name: $0) }, "loaded: \(store.loadedNames().sorted())")
        XCTAssertFalse(store.isLoaded(name: "p3"))
        XCTAssertFalse(store.isLoaded(name: "p5"))
        XCTAssertEqual(gauge.started, 12)
        XCTAssertLessThanOrEqual(gauge.maxInFlight, NCRuleProviderStore.maxConcurrentFetches)
        XCTAssertGreaterThanOrEqual(gauge.maxInFlight, 1)
        XCTAssertTrue(store.contains(name: "p11", ctx: NCMatchContext(domain: "a.p11.example.com")))
    }

    func testRefreshAllSynchronousFetcherCompletes() {
        let store = NCRuleProviderStore(dir: dir)
        store.fetcher = { url, done in done(Data("DOMAIN,\(url.split(separator: "/").last ?? "x").test\n".utf8)) }
        let ps = providers(40)
        store.refreshAll(ps)
        XCTAssertEqual(store.loadedNames().count, 40)
    }

    func testDroppedStoreStopsItsChain() {
        let gauge = Gauge()
        let q = DispatchQueue(label: "mem2.fetch2")
        weak var weakStore: NCRuleProviderStore?
        do {
            let store = NCRuleProviderStore(dir: dir)
            weakStore = store
            store.fetcher = { _, done in
                gauge.begin()
                q.asyncAfter(deadline: .now() + 0.05) { gauge.end(); done(Data("DOMAIN,x.test\n".utf8)) }
            }
            store.refreshAll(providers(20))
        }
        // the store is gone once its last strong owner is: the in-flight fetches hold it only weakly
        XCTAssertNil(weakStore)
        let until = Date().addingTimeInterval(1)
        while Date() < until { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        gauge.lock.lock(); let started = gauge.started; gauge.lock.unlock()
        XCTAssertLessThanOrEqual(started, NCRuleProviderStore.maxConcurrentFetches, "no new fetches after the store went away")
    }
}
