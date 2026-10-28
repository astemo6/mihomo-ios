import XCTest
@testable import Tern

/// fix/nc-dns-log-lines: the Home DNS card and the DNS log page aggregate controller log
/// lines in the old core's formats ("[DNS] resolve <name> <type> from <upstream>",
/// "[DNS] cache hit …", "[DNS] resolve … error: …"). The native core never emitted them —
/// both surfaces stayed permanently empty while DNS itself worked (device 2026-10-28).
/// These tests pin the consumer side of the contract the data plane now produces.
final class NativeDNSLogFormatTests: XCTestCase {
    func testResolveLineCountsTheUpstream() {
        let d = HomeDNSModel.parse(["[DNS] resolve example.com A from 223.5.5.5"])
        XCTAssertEqual(d.upstreams["223.5.5.5"], 1)
        XCTAssertEqual(d.cached, 0)
        XCTAssertEqual(d.failed, 0)
    }

    func testResolveLineWithDoHURLLabelsByHost() {
        let d = HomeDNSModel.parse(["[DNS] resolve example.com AAAA from https://doh.pub/dns-query"])
        XCTAssertEqual(d.upstreams["doh.pub"], 1)
    }

    func testCacheHitLineCountsAsCached() {
        let d = HomeDNSModel.parse(["[DNS] cache hit example.com A"])
        XCTAssertEqual(d.cached, 1)
        XCTAssertTrue(d.upstreams.isEmpty)
    }

    func testErrorLineCountsAsFailed() {
        let d = HomeDNSModel.parse(["[DNS] resolve example.com HTTPS error: 223.5.5.5 no answer 2500 ms"])
        XCTAssertEqual(d.failed, 1)
        XCTAssertTrue(d.upstreams.isEmpty)
    }
}
