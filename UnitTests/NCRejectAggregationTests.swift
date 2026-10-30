import XCTest
@testable import Tern

/// fix/dns-reject-storm (records half): rejected connections coalesce per
/// (host-or-IP, port, rule) inside a 5 s window into one stored record
/// with a count; a hard session cap fuses runaway key diversity; normal
/// connections keep the whole-session, one-record-per-connection rule.
/// Timestamps are relative to real now because statsJSON flushes expired
/// aggregates against the wall clock.
final class NCRejectAggregationTests: XCTestCase {

    private func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    private func rejected(id: Int, host: String = "ads.example.com", ip: String = "203.0.113.7",
                          port: Int = 443, rule: String = "RULE-SET,ads,REJECT",
                          start: Int64, closedAt: Int64, up: Int64 = 0, down: Int64 = 0) -> NCStatsRecorder.Closed {
        NCStatsRecorder.Closed(seq: 0, id: "c\(id)", network: "tcp", srcPort: 50000,
                               dstIP: ip, dstPort: port, host: host, remote: host,
                               chains: ["REJECT"], rule: rule, up: up, down: down,
                               start: start, closedAt: closedAt)
    }

    private func normal(id: Int, at ms: Int64) -> NCStatsRecorder.Closed {
        NCStatsRecorder.Closed(seq: 0, id: "n\(id)", network: "tcp", srcPort: 50001,
                               dstIP: "93.184.216.34", dstPort: 443, host: "example.com",
                               remote: "example.com", chains: ["DIRECT"], rule: "MATCH,DIRECT",
                               up: 10, down: 20, start: ms, closedAt: ms)
    }

    private func stats(_ rec: NCStatsRecorder) -> [String: Any] {
        rec.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
    }

    private func stored(_ rec: NCStatsRecorder) -> [[String: Any]] {
        stats(rec)["closed"] as? [[String: Any]] ?? []
    }

    func testSameKeyStormCoalesces() {
        let rec = NCStatsRecorder()
        let t = nowMs() - 60_000
        for i in 0..<500 {
            rec.closed(rejected(id: i, start: t, closedAt: t + Int64(i % 400), up: 3, down: 7))
        }
        let out = stored(rec)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out.first?["count"] as? Int, 500)
        XCTAssertEqual(out.first?["upload"] as? Int64, 1500)
        XCTAssertEqual(out.first?["download"] as? Int64, 3500)
        XCTAssertEqual(stats(rec)["rejectedMerged"] as? Int, 499)
        XCTAssertEqual(stats(rec)["rejectedOverflow"] as? Int, 0)
    }

    func testDistinctKeysDoNotMerge() {
        let rec = NCStatsRecorder()
        let t = nowMs() - 60_000
        let keys: [(String, Int, String)] = [
            ("ads.example.com", 443, "RULE-SET,ads,REJECT"),
            ("ads.example.com", 8443, "RULE-SET,ads,REJECT"), // port differs
            ("tracker.example.com", 443, "RULE-SET,ads,REJECT"), // host differs
            ("ads.example.com", 443, "DOMAIN-SUFFIX,example.com,REJECT"), // rule differs
        ]
        var id = 0
        for (host, port, rule) in keys {
            for _ in 0..<10 {
                rec.closed(rejected(id: id, host: host, port: port, rule: rule, start: t, closedAt: t + 10))
                id += 1
            }
        }
        let out = stored(rec)
        XCTAssertEqual(out.count, 4)
        XCTAssertTrue(out.allSatisfy { ($0["count"] as? Int) == 10 })
    }

    func testIPOnlyKeyFallsBackToDestinationIP() {
        // HTTPDNS-style flows carry no domain: keyed by dstIP, record stays
        // IP-shaped (no fabricated domain attribution).
        let rec = NCStatsRecorder()
        let t = nowMs() - 60_000
        for i in 0..<5 {
            rec.closed(rejected(id: i, host: "", ip: "180.76.76.200", start: t, closedAt: t + Int64(i)))
        }
        let out = stored(rec)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out.first?["count"] as? Int, 5)
        let meta = out.first?["metadata"] as? [String: Any]
        XCTAssertEqual(meta?["host"] as? String, "")
        XCTAssertEqual(meta?["destinationIP"] as? String, "180.76.76.200")
    }

    func testNormalConnectionsAreNotAggregated() {
        let rec = NCStatsRecorder()
        let t = nowMs() - 60_000
        for i in 0..<50 { rec.closed(normal(id: i, at: t + Int64(i))) }
        let out = stored(rec)
        XCTAssertEqual(out.count, 50)
        XCTAssertTrue(out.allSatisfy { $0["count"] == nil }) // ordinary records carry no count key
        XCTAssertEqual(stats(rec)["rejectedMerged"] as? Int, 0)
    }

    func testWindowBoundaryStartsNewAggregate() {
        let rec = NCStatsRecorder()
        let t = nowMs() - 60_000
        rec.closed(rejected(id: 1, start: t, closedAt: t))
        rec.closed(rejected(id: 2, start: t + 6_000, closedAt: t + 6_000)) // past the 5 s window
        let out = stored(rec)
        XCTAssertEqual(out.count, 2)
        XCTAssertTrue(out.allSatisfy { $0["count"] == nil })
    }

    func testPendingAggregateIsNotYetStored() {
        let rec = NCStatsRecorder()
        let t = nowMs()
        for i in 0..<10 { rec.closed(rejected(id: i, start: t, closedAt: t)) }
        XCTAssertEqual(stored(rec).count, 0) // still inside its window
        XCTAssertEqual(stats(rec)["rejectedMerged"] as? Int, 9)
    }

    func testSessionCapFusesRunawayDiversity() {
        let rec = NCStatsRecorder()
        // The cap governs the session store; without an archive statsJSON
        // serves only the newest 300 from the ring, so enable the archive
        // (its init truncates — a fresh session) to observe all 2000.
        rec.enableSessionArchive()
        let t = nowMs() - 60_000
        let total = NCStatsRecorder.rejectStoredCap + 50
        for i in 0..<total {
            rec.closed(rejected(id: i, host: "h\(i).example.com", start: t, closedAt: t))
        }
        let s = stats(rec)
        let rejectedStored = stored(rec).filter { (($0["chains"] as? [String]) ?? []).contains("REJECT") }
        XCTAssertEqual(rejectedStored.count, NCStatsRecorder.rejectStoredCap)
        XCTAssertEqual(s["rejectedOverflow"] as? Int, 50)
        // And it stays fused: one more new key changes nothing stored.
        rec.closed(rejected(id: 99999, host: "late.example.com", start: t, closedAt: t))
        XCTAssertEqual(stored(rec).count, NCStatsRecorder.rejectStoredCap)
        XCTAssertEqual(stats(rec)["rejectedOverflow"] as? Int, 51)
    }

    func testDNSBlockedRecordsAggregateByDomain() {
        // The DNS-layer block records ride the same gate: a name the SDK
        // keeps re-asking about becomes ONE blocked entry with a count.
        let rec = NCStatsRecorder()
        let t = Date(timeIntervalSinceNow: -60)
        for _ in 0..<30 {
            rec.dnsBlocked(host: "afdconf.baidu.com", rule: "HOST,AFDCONF.BAIDU.COM,REJECT", at: t)
        }
        let out = stored(rec)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out.first?["count"] as? Int, 30)
        let meta = out.first?["metadata"] as? [String: Any]
        XCTAssertEqual(meta?["host"] as? String, "afdconf.baidu.com")
    }

    func testResetDropsPendingAggregates() {
        let rec = NCStatsRecorder()
        let t = nowMs()
        for i in 0..<10 { rec.closed(rejected(id: i, start: t, closedAt: t)) }
        rec.reset()
        rec.closed(normal(id: 1, at: t - 60_000))
        let out = stored(rec)
        XCTAssertEqual(out.count, 1) // only the post-reset normal record
        XCTAssertEqual(stats(rec)["rejectedMerged"] as? Int, 0)
    }
}
