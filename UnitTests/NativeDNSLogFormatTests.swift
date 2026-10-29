import XCTest
@testable import Tern

/// The [DNS] log-line contract. Two consumers aggregate the same controller log lines:
/// the Home DNS card (HomeDNSModel.parse — upstream counts) and the DNS log page
/// (DNSLogStore.ingest — per-query rows). fix/nc-dns-log-lines emitted a format only the
/// card parses ("[DNS] resolve <name> <type> from <upstream>"), so the card counted while
/// the page silently dropped every line and stayed empty (device 2026-10-29). The lines
/// are now built by NCDNSLogLine (Shared) in the one shape both consumers accept, and
/// these tests run the BUILT lines through BOTH consumers — a format change on either
/// side fails here instead of shipping.
final class NativeDNSLogFormatTests: XCTestCase {

    private func aMessage() -> NCDNSMessage {
        var m = NCDNSMessage()
        m.answers = [NCDNSRecord(name: "example.com", type: NCDNSMessage.typeA, klass: 1,
                                 ttl: 300, rdata: Data([93, 184, 216, 34]))]
        return m
    }

    // MARK: - the card (HomeDNSModel.parse)

    func testResolveLineCountsTheUpstream() {
        let line = NCDNSLogLine.resolve(name: "example.com", type: "A", response: aMessage(), upstream: "223.5.5.5")
        let d = HomeDNSModel.parse([line])
        XCTAssertEqual(d.upstreams["223.5.5.5"], 1)
        XCTAssertEqual(d.cached, 0)
        XCTAssertEqual(d.failed, 0)
    }

    func testResolveLineWithDoHURLLabelsByHost() {
        let line = NCDNSLogLine.resolve(name: "example.com", type: "AAAA", response: aMessage(), upstream: "https://doh.pub/dns-query")
        let d = HomeDNSModel.parse([line])
        XCTAssertEqual(d.upstreams["doh.pub"], 1)
    }

    func testCacheHitLineCountsAsCached() {
        let line = NCDNSLogLine.cacheHit(name: "example.com", type: "A", response: aMessage())
        let d = HomeDNSModel.parse([line])
        XCTAssertEqual(d.cached, 1)
        XCTAssertTrue(d.upstreams.isEmpty)
    }

    func testErrorLineCountsAsFailed() {
        let line = NCDNSLogLine.failure(name: "example.com", type: "HTTPS", detail: "223.5.5.5 no answer 2500 ms")
        let d = HomeDNSModel.parse([line])
        XCTAssertEqual(d.failed, 1)
        XCTAssertTrue(d.upstreams.isEmpty)
    }

    // MARK: - the page (DNSLogStore.ingest)

    @MainActor
    func testResolveLineIngestsAsQueryRow() {
        let store = DNSLogStore()
        store.ingest(NCDNSLogLine.resolve(name: "example.com", type: "A", response: aMessage(), upstream: "223.5.5.5"))
        XCTAssertEqual(store.queries.count, 1)
        let e = store.queries.first
        XCTAssertEqual(e?.domain, "example.com")
        XCTAssertEqual(e?.qtype, "A")
        XCTAssertEqual(e?.answer, "93.184.216.34")
        XCTAssertEqual(e?.upstream, "223.5.5.5")
        XCTAssertEqual(e?.cached, false)
        XCTAssertEqual(e?.failed, false)
    }

    @MainActor
    func testCacheHitLineIngestsAsCachedRow() {
        let store = DNSLogStore()
        store.ingest(NCDNSLogLine.cacheHit(name: "example.com", type: "A", response: aMessage()))
        XCTAssertEqual(store.queries.count, 1)
        XCTAssertEqual(store.queries.first?.cached, true)
        XCTAssertEqual(store.queries.first?.answer, "93.184.216.34")
    }

    @MainActor
    func testErrorLineIngestsAsFailedRow() {
        let store = DNSLogStore()
        store.ingest(NCDNSLogLine.failure(name: "example.com", type: "HTTPS", detail: "223.5.5.5 no answer 2500 ms"))
        XCTAssertEqual(store.queries.count, 1)
        XCTAssertEqual(store.queries.first?.failed, true)
        XCTAssertEqual(store.queries.first?.domain, "example.com")
    }
}
