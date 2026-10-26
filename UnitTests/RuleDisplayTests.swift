import XCTest
@testable import Mihomo

/// fix/rule-labels: Egern-style rule / policy text for the Home 规则 card, 规则命中 and the 连接 pages. Inputs are the
/// strings Clash.Meta puts in /connections `rule` / `rulePayload` (and ConnectionItem.ruleText = `Type(payload)`).
final class RuleDisplayTests: XCTestCase {
    private let rewrite = String(localized: "重写")

    func testEngineRulesNeverShowInternals() {
        // the retired bridge: AND,((NETWORK,TCP),(NOT,((IN-TYPE,INNER))),(DST-PORT,80)),__MITM__
        let http = RuleDisplay.describe("AND(((Network,tcp) && (NOT,(!(InType,INNER))) && (DstPort,80)))", policy: "__MITM__")
        XCTAssertEqual(http.primary, String(localized: "HTTP 明文（端口 80）"))
        XCTAssertEqual(http.type, rewrite)
        XCTAssertEqual(http.key, "AND", "tag colour / accessibility id keep the profile spelling")
        // Detected from the rule itself too (the filter sheet has no policy).
        XCTAssertEqual(RuleDisplay.describe("AND(((Network,tcp) && (NOT,(!(InType,INNER))) && (DstPort,80)))").primary, http.primary)

        let mitm = RuleDisplay.describe(
            "AND(((Network,tcp) && (NOT,(!(InType,INNER))) && (DstPort,443) && (RuleSet,__mitm_hosts) && (NOT,(!(RuleSet,__mitm_skip)))))",
            policy: "__MITM__")
        XCTAssertEqual(mitm.primary, String(localized: "HTTPS 解密（MitM）"))
        XCTAssertEqual(mitm.type, rewrite)

        let quic = RuleDisplay.describe("AND(((Network,udp) && (DstPort,443) && (RuleSet,__mitm_hosts)))", policy: "REJECT")
        XCTAssertEqual(quic.primary, String(localized: "UDP 443（QUIC）· MitM 主机"))
        XCTAssertEqual(quic.type, String(localized: "阻止 QUIC"))

        for p in [http, mitm, quic] {
            for bad in ["__", "Network", "InType", "&&", "(("] { XCTAssertFalse(p.primary.contains(bad), "\(p.primary) shows \(bad)") }
        }
    }

    func testEngineOutboundName() {
        XCTAssertEqual(RuleDisplay.policyName("__MITM__"), String(localized: "重写引擎"))
        XCTAssertEqual(RuleDisplay.policyName("Proxy"), "Proxy")
        XCTAssertEqual(RuleDisplay.chainText(["__MITM__"]), String(localized: "重写引擎"))
        XCTAssertEqual(RuleDisplay.chainText(["🇯🇵 Tokyo 01", "Proxy"]), "Proxy → 🇯🇵 Tokyo 01")
    }

    func testLogicalRulesAreSummarised() {
        let and = RuleDisplay.describe("AND(((Network,tcp) && (DstPort,80)))", policy: "Proxy")
        XCTAssertEqual(and.primary, "TCP · " + String(localized: "端口 \("80")"))
        XCTAssertEqual(and.type, String(localized: "逻辑与"))

        let or = RuleDisplay.describe("OR(((DomainSuffix,a.com) || (DomainKeyword,ads)))", policy: "REJECT")
        XCTAssertEqual(or.primary, "a.com / ads")
        XCTAssertEqual(or.type, String(localized: "逻辑或"))

        let not = RuleDisplay.describe("NOT((!(Network,udp)))", policy: "DIRECT")
        XCTAssertEqual(not.primary, String(localized: "非 \("UDP")"))
        XCTAssertEqual(not.type, String(localized: "逻辑非"))

        let nested = RuleDisplay.describe("AND(((AND,((Network,tcp) && (DstPort,22))) && (GeoIP,CN)))", policy: "DIRECT")
        XCTAssertEqual(nested.primary, "(TCP · " + String(localized: "端口 \("22")") + ") · GeoIP CN")

        // The QUIC fallback rule (memtune) reads as what it does.
        XCTAssertEqual(RuleDisplay.describe("AND(((Network,udp) && (DstPort,443)))", policy: "REJECT").primary, String(localized: "UDP 443（QUIC）"))
    }

    func testPlainRules() {
        let set = RuleDisplay.describe("RuleSet(Facebook)", policy: "Proxy")
        XCTAssertEqual(set.primary, "Facebook")
        XCTAssertEqual(set.type, String(localized: "rule.type.ruleset", defaultValue: "规则集"))
        XCTAssertEqual(set.key, "RULE-SET")

        let domain = RuleDisplay.describe(type: "Domain", payload: "gateway.icloud.com")
        XCTAssertEqual(domain.primary, "gateway.icloud.com")
        XCTAssertEqual(domain.type, String(localized: "域名"))
        XCTAssertEqual(domain.key, "DOMAIN")

        XCTAssertEqual(RuleDisplay.describe("DomainSuffix(example.com)").type, String(localized: "域名后缀"))
        XCTAssertEqual(RuleDisplay.describe("DomainKeyword(ads)").type, String(localized: "域名关键词"))
        XCTAssertEqual(RuleDisplay.describe("IPCIDR(10.0.0.0/8)").type, String(localized: "IP 段"))
        XCTAssertEqual(RuleDisplay.describe("ProcessName(Telegram)").type, String(localized: "进程"))
        XCTAssertEqual(RuleDisplay.describe("DstPort(8080)").primary, "8080")

        let geo = RuleDisplay.describe("GeoIP(CN)", policy: "DIRECT")
        XCTAssertEqual(geo.primary, "CN")
        XCTAssertEqual(geo.type, "GeoIP")

        let match = RuleDisplay.describe("Match", policy: "DIRECT")
        XCTAssertEqual(match.primary, String(localized: "兜底规则"))
        XCTAssertEqual(match.type, "", "no second type line when the type is the first line")
        XCTAssertEqual(match.key, "MATCH")

        XCTAssertEqual(RuleDisplay.describe("—").primary, "—")
        XCTAssertEqual(RuleDisplay.describe(type: nil, payload: nil).primary, "—")
    }

    func testSplit() {
        XCTAssertEqual(RuleDisplay.split("DomainKeyword(example)").type, "DomainKeyword")
        XCTAssertEqual(RuleDisplay.split("DomainKeyword(example)").payload, "example")
        XCTAssertEqual(RuleDisplay.split("Match").type, "Match")
        XCTAssertEqual(RuleDisplay.split("Match").payload, "")
    }
}
