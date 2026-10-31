import XCTest
@testable import Tern

/// fix/quic-block: the generated QUIC rule (`AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`)
/// for the default blockQUIC mode ("nondirect") used to be APPENDED to the rule
/// list — behind the terminal MATCH and behind deciding rules such as
/// GEOIP,CN,DIRECT — so it reached the engine, was counted in its rule total,
/// and could never be the first match: QUIC blocking silently did nothing
/// (field report: Baidu Maps' QUIC channels ran DIRECT for a whole session
/// while the same config under Quantumult X fell back and lost its splash ad).
/// These tests pin (a) the generated rule's presence and position after the
/// runtime build step and (b) the decisions the built list actually produces.
final class NCQUICBlockTests: XCTestCase {

    private func raw(_ rules: [String]) -> [String: NCJSONValue] {
        ["rules": .array(rules.map { NCJSONValue.string($0) })]
    }

    private func lines(_ raw: [String: NCJSONValue]) -> [String] {
        raw.list("rules").compactMap { v in
            if case .string(let s) = v { return s }
            return nil
        }
    }

    /// A user-shaped list: an early ad REJECT, a DIRECT grant that would
    /// otherwise decide Baidu's flows, and the terminal MATCH.
    private let userRules = [
        "DOMAIN,ad.example.com,REJECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,FINAL",
    ]

    // MARK: (a) generation: presence + position

    func testNondirectPrependsQUICRuleAheadOfMatch() {
        var r = raw(userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        let out = lines(r)
        XCTAssertEqual(out.count, userRules.count + 1, "\(out)")
        XCTAssertEqual(out.first, NCRuntimeSteps.udpFallbackRule, "\(out)")
        let quicIdx = out.firstIndex(of: NCRuntimeSteps.udpFallbackRule)
        let matchIdx = out.firstIndex(of: "MATCH,FINAL")
        XCTAssertNotNil(quicIdx)
        XCTAssertNotNil(matchIdx)
        XCTAssertLessThan(quicIdx!, matchIdx!, "\(out)")
    }

    func testNondirectIsIdempotent() {
        var r = raw(userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        let out = lines(r)
        XCTAssertEqual(out.filter { $0 == NCRuntimeSteps.udpFallbackRule }.count, 1, "\(out)")
        XCTAssertEqual(out.count, userRules.count + 1, "\(out)")
    }

    func testNondirectLeavesExistingRuleAlone() {
        var r = raw([NCRuntimeSteps.udpFallbackRule] + userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        XCTAssertEqual(lines(r).count, userRules.count + 1, "\(lines(r))")
    }

    func testOffAddsNothing() {
        var r = raw(userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "off")
        XCTAssertEqual(lines(r), userRules)
    }

    func testAlwaysPrependsGuardedRule() {
        var r = raw(userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "always")
        XCTAssertEqual(lines(r).first, NCRuntimeSteps.quicBlockAllRule, "\(lines(r))")
    }

    func testEmptyRulesStayEmpty() {
        var r = raw([])
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        XCTAssertEqual(lines(r), [])
    }

    // MARK: (b) the built list actually decides

    private func builtRules() -> [NCRule] {
        var r = raw(userRules)
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        return lines(r).compactMap(NCRule.parse)
    }

    private func ctx(domain: String?, network: String, dstPort: Int) -> NCMatchContext {
        var c = NCMatchContext()
        c.domain = domain
        c.network = network
        c.dstPort = dstPort
        return c
    }

    func testUDP443HitsGeneratedRejectAheadOfDirectGrant() {
        let hit = NCRuleMatcher.firstMatchWithPolicy(
            builtRules(), ctx(domain: "qclient.map.baidu.com", network: "udp", dstPort: 443))
        XCTAssertEqual(hit?.policy, "REJECT")
        XCTAssertEqual(hit?.rule.kind, "AND")
    }

    func testUDPNon443FallsThroughToDirectGrant() {
        let hit = NCRuleMatcher.firstMatchWithPolicy(
            builtRules(), ctx(domain: "qclient.map.baidu.com", network: "udp", dstPort: 8443))
        XCTAssertEqual(hit?.policy, "DIRECT")
    }

    func testTCP443FallsThroughToDirectGrant() {
        let hit = NCRuleMatcher.firstMatchWithPolicy(
            builtRules(), ctx(domain: "qclient.map.baidu.com", network: "tcp", dstPort: 443))
        XCTAssertEqual(hit?.policy, "DIRECT")
    }

    func testUDP443RejectedEvenWithOnlyMatchBehind() {
        var r = raw(["MATCH,FINAL"])
        NCRuntimeSteps.applyQUICBlock(&r, mode: "nondirect")
        let parsed = lines(r).compactMap(NCRule.parse)
        let quic = NCRuleMatcher.firstMatchWithPolicy(
            parsed, ctx(domain: nil, network: "udp", dstPort: 443))
        XCTAssertEqual(quic?.policy, "REJECT")
        let other = NCRuleMatcher.firstMatchWithPolicy(
            parsed, ctx(domain: nil, network: "udp", dstPort: 8443))
        XCTAssertEqual(other?.policy, "FINAL")
    }
}
