import XCTest
@testable import Tern

/// fix/nc-reject-log-tab (user 2026-10-29): the DNS page's 已拦截 tab parsed only the old
/// Go core's "[TCP] src --> host match … using REJECT" lines; the native core's outcome
/// lines (NCFlowLogLine) never matched, so the tab stayed empty while the core's rejected
/// counter kept counting. These tests feed the store lines composed by the core's own
/// builder — the same strings NCDataPlane emits — so the two sides cannot drift apart
/// silently again (the NCDNSLogLine doctrine of fix/nc-dns-log-page, second organ).
@MainActor
final class DNSLogRejectFormatTests: XCTestCase {
    private func tcp(_ host: String, rule: String, via: String = "REJECT", matchNote: String = "") -> String {
        NCFlowLogLine.head(proto: "TCP", host: host, port: 443, rule: rule, matchNote: matchNote, via: via) + " rejected"
    }

    func testNativeTCPRejectLandsInBlocked() {
        let s = DNSLogStore()
        s.ingest(tcp("ads.example.com", rule: "DomainSuffix(ads.example.com)"))
        s.ingest(tcp("ads.example.com", rule: "DomainSuffix(ads.example.com)"))
        XCTAssertEqual(s.blockedTotal, 2)
        XCTAssertEqual(s.blocked["ads.example.com"]?.ruleLabel, "域名后缀 · ads.example.com")
        XCTAssertEqual(s.quicTotal, 0)
        XCTAssertTrue(s.queries.isEmpty)
    }

    func testNativeTCPRejectDropViaCounts() {
        // A REJECT-DROP policy logs via "REJECT-DROP (REJECT)".
        let s = DNSLogStore()
        s.ingest(tcp("ads.example.com", rule: "RuleSet(ads)", via: "REJECT-DROP (REJECT)"))
        XCTAssertEqual(s.blockedTotal, 1)
    }

    func testNativeUDPRejectLandsInBlocked() {
        let s = DNSLogStore()
        s.ingest(NCFlowLogLine.udpOutcome(host: "tracker.example.net", port: 443, rule: "RuleSet(ads)", via: "REJECT", opened: false))
        XCTAssertEqual(s.blockedTotal, 1)
        XCTAssertEqual(s.blocked["tracker.example.net"]?.ruleLabel, "规则集 · ads")
    }

    func testNativeUDPQUICGoesToTheQuicBucket() {
        let s = DNSLogStore()
        s.ingest(NCFlowLogLine.udpOutcome(host: "app.example.com", port: 443, rule: "AND(((Network,udp) && (DstPort,443)))", via: "REJECT", opened: false))
        XCTAssertEqual(s.blockedTotal, 0)
        XCTAssertEqual(s.quicTotal, 1)
    }

    func testNativeUDPProxyDropIsNotABlock() {
        // Same "dropped (…)" wording, but the via is a proxy without UDP relay — not a reject.
        let s = DNSLogStore()
        s.ingest(NCFlowLogLine.udpOutcome(host: "app.example.com", port: 443, rule: "DomainSuffix(app.example.com)", via: "Demo (ss)", opened: false))
        XCTAssertEqual(s.blockedTotal, 0)
        XCTAssertEqual(s.quicTotal, 0)
    }

    func testNativeTCPConnectedLineIsNotABlock() {
        let s = DNSLogStore()
        let head = NCFlowLogLine.head(proto: "TCP", host: "www.example.com", port: 443, rule: "DomainSuffix(example.com)", matchNote: "", via: "Demo")
        s.ingest(head + " connected in 12 ms")
        XCTAssertEqual(s.blockedTotal, 0)
        XCTAssertEqual(s.quicTotal, 0)
    }

    func testFinalRuleMatchNoteIsStripped() {
        let s = DNSLogStore()
        s.ingest(tcp("203.0.113.7", rule: "Match", matchNote: " [203.0.113.7 US AS64500]"))
        XCTAssertEqual(s.blockedTotal, 1)
        XCTAssertEqual(s.blocked["203.0.113.7"]?.rule, "Match")
    }

    func testLegacyClashShapeStillParses() {
        let s = DNSLogStore()
        s.ingest("[TCP] 198.18.0.1:50001 --> ads.example.com:443 match DomainSuffix(ads.example.com) using REJECT")
        XCTAssertEqual(s.blockedTotal, 1)
    }
}
