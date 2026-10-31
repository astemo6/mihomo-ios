import XCTest
@testable import Tern

/// fix/httpdns-guard: the guard's set construction, hit test and refresh
/// semantics. The mechanism it serves: apps resolving through their own
/// HTTPDNS (Baidu Maps is the proven case) dial bare IPs with no SNI, so
/// the ONLY policy surface left is the HTTPDNS service's own addresses —
/// the engine resolves the four documented service domains itself and the
/// data plane rejects flows to the resulting IPs. These tests pin:
/// fake answers build the set, the hit test names the owning domain,
/// a failed resolution leaves the set empty (traffic passes), a refresh
/// that moves a service to new IPs retires the old ones, and a failed
/// refresh keeps the last good set.
final class NCHTTPDNSGuardTests: XCTestCase {

    private func ip(_ s: String) -> NCIP { NCIP(s)! }

    private func enabledGuard() -> NCHTTPDNSGuard {
        let g = NCHTTPDNSGuard()
        g.setEnabled(true)
        return g
    }

    /// The resolver the engine wires to its upstream DNS, faked: answers
    /// per domain, a domain mapped to nil (or absent when `failAll`)
    /// fails its lookup, exactly the production contract.
    private func fakeResolver(_ answers: [String: [NCIP]?]) -> NCHTTPDNSGuard.Resolver {
        { domain, completion in completion(answers[domain] ?? nil) }
    }

    // MARK: watchlist

    func testWatchlistIsTheFourDocumentedServices() {
        XCTAssertEqual(NCHTTPDNSGuard.watchDomains, [
            "httpdns.baidu.com",
            "httpdns.baidubce.com",
            "httpdns.alicdn.com",
            "httpdns-api.aliyuncs.com",
        ])
    }

    // MARK: set construction + hit test (the connection layer's verdict)

    func testFakeAnswersBuildTheSetAndHitsNameTheDomain() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver([
            "httpdns.baidu.com": [ip("110.242.69.16")],
            "httpdns.baidubce.com": [ip("180.76.76.200")],
            "httpdns.alicdn.com": [ip("163.181.154.191"), ip("163.181.154.192")],
            "httpdns-api.aliyuncs.com": [ip("2001:4860:4860::8888")],
        ]))
        XCTAssertEqual(g.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")
        XCTAssertEqual(g.domain(for: ip("180.76.76.200")), "httpdns.baidubce.com")
        XCTAssertEqual(g.domain(for: ip("163.181.154.191")), "httpdns.alicdn.com")
        XCTAssertEqual(g.domain(for: ip("163.181.154.192")), "httpdns.alicdn.com")
        XCTAssertEqual(g.domain(for: ip("2001:4860:4860::8888")), "httpdns-api.aliyuncs.com")
        XCTAssertEqual(g.ipCount, 5)
    }

    func testUnrelatedIPsMiss() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": [ip("110.242.69.16")]]))
        XCTAssertNil(g.domain(for: ip("110.242.69.17"))) // neighbour in the same block
        XCTAssertNil(g.domain(for: ip("8.8.8.8")))
        XCTAssertNil(g.domain(for: ip("2001:4860:4860::8844")))
    }

    func testSnapshotSeamBuildsTheSameSet() {
        let g = enabledGuard()
        g.applySnapshot([
            "httpdns.baidu.com": [ip("110.242.69.16")],
            "httpdns.baidubce.com": [ip("180.76.76.200")],
        ])
        XCTAssertEqual(g.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")
        XCTAssertEqual(g.domain(for: ip("180.76.76.200")), "httpdns.baidubce.com")
        XCTAssertEqual(g.ipCount, 2)
        // A domain outside the watchlist contributes nothing.
        g.applySnapshot(["httpdns.evil.example": [ip("203.0.113.1")]])
        XCTAssertNil(g.domain(for: ip("203.0.113.1")))
        XCTAssertEqual(g.ipCount, 0)
    }

    // MARK: fail-open gates

    func testNeverEnabledGuardPassesEverything() {
        let g = NCHTTPDNSGuard() // engine arms it only when the config says on
        g.applySnapshot(["httpdns.baidu.com": [ip("110.242.69.16")]])
        XCTAssertFalse(g.isEnabled)
        XCTAssertNil(g.domain(for: ip("110.242.69.16")))
    }

    func testDisablingEmptiesTheTable() {
        let g = enabledGuard()
        g.applySnapshot(["httpdns.baidu.com": [ip("110.242.69.16")]])
        XCTAssertNotNil(g.domain(for: ip("110.242.69.16")))
        g.setEnabled(false)
        XCTAssertEqual(g.ipCount, 0)
        XCTAssertNil(g.domain(for: ip("110.242.69.16")))
    }

    func testFailedResolutionLeavesEmptySetAndPasses() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver([:])) // every lookup fails (nil)
        XCTAssertEqual(g.ipCount, 0)
        for domain in NCHTTPDNSGuard.watchDomains {
            XCTAssertNil(g.domain(for: ip("110.242.69.16")), domain)
        }
    }

    // MARK: refresh semantics

    func testRefreshReplacesMovedIPs() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver([
            "httpdns.baidu.com": [ip("110.242.69.16")],
            "httpdns.alicdn.com": [ip("163.181.154.191")],
        ]))
        XCTAssertEqual(g.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")

        // The service moved: the old IP must stop hitting, the new one hits,
        // and a domain the refresh did not touch keeps its addresses when
        // its lookup FAILS — only completed answers replace.
        g.refresh(resolver: fakeResolver([
            "httpdns.baidu.com": [ip("110.242.69.99")],
            "httpdns.alicdn.com": nil,
        ]))
        XCTAssertNil(g.domain(for: ip("110.242.69.16")))
        XCTAssertEqual(g.domain(for: ip("110.242.69.99")), "httpdns.baidu.com")
        XCTAssertEqual(g.domain(for: ip("163.181.154.191")), "httpdns.alicdn.com")
    }

    func testCompletedEmptyAnswerRetiresTheDomain() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": [ip("110.242.69.16")]]))
        XCTAssertNotNil(g.domain(for: ip("110.242.69.16")))
        // A completed answer with no address records: the subset is
        // replaced (fail-open), unlike a failed lookup above.
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": []]))
        XCTAssertNil(g.domain(for: ip("110.242.69.16")))
        XCTAssertEqual(g.ipCount, 0)
    }

    func testFailedRefreshKeepsTheLastGoodSet() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": [ip("110.242.69.16")]]))
        g.refresh(resolver: fakeResolver([:])) // total outage this round
        XCTAssertEqual(g.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")
        XCTAssertEqual(g.ipCount, 1)
    }

    // MARK: record labelling

    func testRuleTextNamesTheService() {
        XCTAssertEqual(NCHTTPDNSGuard.ruleText(for: "httpdns.baidu.com"),
                       "HTTPDNS-GUARD,httpdns.baidu.com,REJECT")
    }

    // MARK: config plumbing defaults

    func testConfigDefaultsGuardOn() {
        // A runtime config without the key (built before the toggle
        // existed) decodes with the guard ON, matching the override's
        // factory default; an explicit false is honoured.
        let absent = NCConfig.decode(root: [:])
        XCTAssertTrue(absent.httpdnsGuard)
        let off = NCConfig.decode(root: ["httpdns-guard": .bool(false)])
        XCTAssertFalse(off.httpdnsGuard)
        let on = NCConfig.decode(root: ["httpdns-guard": .bool(true)])
        XCTAssertTrue(on.httpdnsGuard)
        // And the override model itself defaults on.
        XCTAssertTrue(CoreOverrides().httpdnsGuard)
    }

    // MARK: persistence (fix/httpdns-guard-persist)

    private func tempStoreFile() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("httpdns-guard-\(UUID().uuidString).json")
    }

    func testPersistedTableRoundTripsIntoAFreshGuard() {
        let file = tempStoreFile()
        defer { try? FileManager.default.removeItem(at: file) }
        let a = enabledGuard()
        a.setStoreFile(file)
        a.refresh(resolver: fakeResolver([
            "httpdns.baidu.com": [ip("110.242.69.16")],
            "httpdns.alicdn.com": [ip("163.181.154.191"), ip("163.181.154.192")],
        ]))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))

        // A fresh guard — the extension relaunched under memory
        // pressure — restores last run's table before any refresh.
        let b = enabledGuard()
        b.setStoreFile(file)
        b.loadPersisted()
        XCTAssertEqual(b.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")
        XCTAssertEqual(b.domain(for: ip("163.181.154.191")), "httpdns.alicdn.com")
        XCTAssertEqual(b.domain(for: ip("163.181.154.192")), "httpdns.alicdn.com")
        XCTAssertEqual(b.ipCount, 3)
    }

    func testCorruptOrForeignStoreFileStartsEmpty() {
        let file = tempStoreFile()
        defer { try? FileManager.default.removeItem(at: file) }
        let g = enabledGuard()
        g.setStoreFile(file)
        // Garbage bytes: no throw, empty table.
        try? Data([0x00, 0xFF, 0x42]).write(to: file)
        g.loadPersisted()
        XCTAssertEqual(g.ipCount, 0)
        // Valid JSON, foreign version: ignored.
        try? Data(#"{"version":99,"ips":{"110.242.69.16":"httpdns.baidu.com"}}"#.utf8).write(to: file)
        g.loadPersisted()
        XCTAssertEqual(g.ipCount, 0)
        // Current version: an unwatched domain and an unparseable IP
        // are dropped, the legitimate entry survives.
        try? Data(#"{"version":1,"ips":{"203.0.113.1":"httpdns.evil.example","not-an-ip":"httpdns.baidu.com","110.242.69.16":"httpdns.baidu.com"}}"#.utf8).write(to: file)
        g.loadPersisted()
        XCTAssertEqual(g.ipCount, 1)
        XCTAssertEqual(g.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")
    }

    func testDisablingDeletesTheStoreFile() {
        let file = tempStoreFile()
        defer { try? FileManager.default.removeItem(at: file) }
        let g = enabledGuard()
        g.setStoreFile(file)
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": [ip("110.242.69.16")]]))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        g.setEnabled(false)
        XCTAssertEqual(g.ipCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func testLoadPersistedKeepsAFresherInMemoryTable() {
        let file = tempStoreFile()
        defer { try? FileManager.default.removeItem(at: file) }
        let a = enabledGuard()
        a.setStoreFile(file)
        a.refresh(resolver: fakeResolver(["httpdns.baidu.com": [ip("110.242.69.16")]]))
        // Warm reload: memory already holds a NEWER set than disk, the
        // restore must not roll it back.
        let b = enabledGuard()
        b.setStoreFile(file)
        b.applySnapshot(["httpdns.baidu.com": [ip("110.242.69.99")]])
        b.loadPersisted()
        XCTAssertNil(b.domain(for: ip("110.242.69.16")))
        XCTAssertEqual(b.domain(for: ip("110.242.69.99")), "httpdns.baidu.com")
    }

    // MARK: cold-start fill (fix/httpdns-guard-persist)

    func testFillMissingResolvesOnlyTheMissingDomains() {
        var queried: [String] = []
        let counting: NCHTTPDNSGuard.Resolver = { domain, completion in
            queried.append(domain)
            completion(domain == "httpdns.alicdn.com" ? [self.ip("163.181.154.191")] : nil)
        }
        let g = enabledGuard()
        g.applySnapshot(["httpdns.baidu.com": [ip("110.242.69.16")]])
        XCTAssertEqual(g.missingDomains(), [
            "httpdns.baidubce.com", "httpdns.alicdn.com", "httpdns-api.aliyuncs.com",
        ])
        g.fillMissing(resolver: counting)
        // Only the three missing domains were queried — the covered one
        // is never re-resolved by a fill pass.
        XCTAssertEqual(queried, [
            "httpdns.baidubce.com", "httpdns.alicdn.com", "httpdns-api.aliyuncs.com",
        ])
        XCTAssertEqual(g.domain(for: ip("163.181.154.191")), "httpdns.alicdn.com")
        // The next fill pass retries only what is STILL missing.
        queried = []
        g.fillMissing(resolver: counting)
        XCTAssertEqual(queried, ["httpdns.baidubce.com", "httpdns-api.aliyuncs.com"])
    }

    func testCompletedEmptyAnswerCountsAsMissingForTheFill() {
        let g = enabledGuard()
        g.refresh(resolver: fakeResolver(["httpdns.baidu.com": []])) // completed, no addresses
        XCTAssertTrue(g.missingDomains().contains("httpdns.baidu.com"))
    }

    func testInitialRetryBackoffMarks() {
        XCTAssertEqual(NCHTTPDNSGuard.initialRetryDelays, [20, 60, 180])
        XCTAssertLessThan(NCHTTPDNSGuard.initialRetryDelays.last!, NCHTTPDNSGuard.refreshInterval)
    }
}
