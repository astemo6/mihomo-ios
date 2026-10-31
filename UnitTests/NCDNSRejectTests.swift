import XCTest
@testable import Tern

/// fix/dns-reject-storm (part 1): the DNS-layer REJECT verdict + the fake-IP
/// responder's NXDOMAIN path. The verdict must reuse the connection layer's
/// own matching (NCRuleMatcher.matches) restricted to domain-class rules —
/// these tests pin the semantics: first domain-class match decides, suffix /
/// keyword / rule-set behave exactly as at connection time, non-domain rules
/// never decide at DNS time, and only A / AAAA are ever intercepted.
final class NCDNSRejectTests: XCTestCase {

    private func rules(_ lines: [String]) -> [NCRule] {
        lines.compactMap(NCRule.parse)
    }

    private func ctx(_ domain: String,
                     ruleSet: @escaping (String, NCMatchContext) -> Bool = { _, _ in false },
                     geosite: @escaping (String, String) -> Bool = { _, _ in false }) -> NCMatchContext {
        var c = NCMatchContext(domain: domain)
        c.ruleSetContains = ruleSet
        c.geositeMatches = geosite
        return c
    }

    private func verdict(_ lines: [String], _ domain: String,
                         ruleSet: @escaping (String, NCMatchContext) -> Bool = { _, _ in false }) -> Bool {
        NCRuleMatcher.dnsRejectVerdict(rules(lines), ctx(domain, ruleSet: ruleSet))
    }

    // MARK: verdict semantics

    func testExactDomainReject() {
        XCTAssertTrue(verdict(["DOMAIN,afd.baidu.com,REJECT"], "afd.baidu.com"))
        XCTAssertFalse(verdict(["DOMAIN,afd.baidu.com,REJECT"], "x.afd.baidu.com"))
        XCTAssertFalse(verdict(["DOMAIN,afd.baidu.com,REJECT"], "afd.baidu.com.evil.com"))
    }

    func testSuffixRejectCoversSubdomainsAndApex() {
        XCTAssertTrue(verdict(["DOMAIN-SUFFIX,baidu.com,REJECT"], "afdconf.baidu.com"))
        XCTAssertTrue(verdict(["DOMAIN-SUFFIX,baidu.com,REJECT"], "baidu.com"))
        XCTAssertFalse(verdict(["DOMAIN-SUFFIX,baidu.com,REJECT"], "notbaidu.com"))
        XCTAssertFalse(verdict(["DOMAIN-SUFFIX,baidu.com,REJECT"], "baidu.com.cn"))
    }

    func testKeywordReject() {
        XCTAssertTrue(verdict(["DOMAIN-KEYWORD,adsdk,REJECT"], "x.adsdk.example.com"))
        XCTAssertFalse(verdict(["DOMAIN-KEYWORD,adsdk,REJECT"], "x.example.com"))
    }

    func testWildcardAndRegexReject() {
        XCTAssertTrue(verdict(["DOMAIN-WILDCARD,*.ads.example.com,REJECT"], "a.ads.example.com"))
        XCTAssertTrue(verdict([#"DOMAIN-REGEX,^track\d+\.example\.com$,REJECT"#], "track9.example.com"))
    }

    func testRuleSetDomainEntriesReject() {
        let inSet: (String, NCMatchContext) -> Bool = { name, c in
            name == "ads" && (c.domain?.hasSuffix("ubixioe.com") ?? false)
        }
        XCTAssertTrue(verdict(["RULE-SET,ads,REJECT"], "adx-cfg-u1.ubixioe.com", ruleSet: inSet))
        XCTAssertFalse(verdict(["RULE-SET,ads,REJECT"], "www.example.com", ruleSet: inSet))
        // Same set, non-reject policy: decided, not blocked.
        XCTAssertFalse(verdict(["RULE-SET,ads,DIRECT"], "adx-cfg-u1.ubixioe.com", ruleSet: inSet))
    }

    func testGeositeReject() {
        let geo: (String, String) -> Bool = { payload, domain in
            payload == "category-ads-all" && domain.hasSuffix("doubleclick.net")
        }
        var c = ctx("ad.doubleclick.net")
        c.geositeMatches = geo
        XCTAssertTrue(NCRuleMatcher.dnsRejectVerdict(rules(["GEOSITE,category-ads-all,REJECT"]), c))
    }

    func testFirstDomainMatchDecides() {
        // An earlier non-reject domain rule wins over a later reject rule.
        XCTAssertFalse(verdict([
            "DOMAIN-SUFFIX,baidu.com,DIRECT",
            "DOMAIN,afd.baidu.com,REJECT",
        ], "afd.baidu.com"))
        // And the reverse order blocks.
        XCTAssertTrue(verdict([
            "DOMAIN,afd.baidu.com,REJECT",
            "DOMAIN-SUFFIX,baidu.com,DIRECT",
        ], "afd.baidu.com"))
    }

    func testNonDomainRulesNeverDecide() {
        // IP / port rules are skipped at DNS time; the domain rule behind
        // them still decides (the connection layer remains the backstop for
        // whatever those rules would have caught).
        XCTAssertTrue(verdict([
            "IP-CIDR,180.76.0.0/16,REJECT",
            "DST-PORT,443,REJECT",
            "DOMAIN,afd.baidu.com,REJECT",
        ], "afd.baidu.com"))
        // A name matched ONLY by non-domain rules is not DNS-blocked.
        XCTAssertFalse(verdict([
            "IP-CIDR,180.76.0.0/16,REJECT",
            "GEOIP,CN,REJECT",
        ], "afd.baidu.com"))
    }

    func testMatchRuleDecides() {
        XCTAssertTrue(verdict(["MATCH,REJECT"], "anything.example.com"))
        // MATCH with a proxy policy in front of a domain reject: MATCH wins,
        // as it would at connection time.
        XCTAssertFalse(verdict([
            "MATCH,PROXY",
            "DOMAIN,afd.baidu.com,REJECT",
        ], "afd.baidu.com"))
    }

    func testRejectDropCountsAsReject() {
        XCTAssertTrue(verdict(["DOMAIN-SUFFIX,baidu.com,REJECT-DROP"], "afd.baidu.com"))
    }

    func testNonRejectPoliciesDoNotBlock() {
        XCTAssertFalse(verdict(["DOMAIN,afd.baidu.com,DIRECT"], "afd.baidu.com"))
        XCTAssertFalse(verdict(["DOMAIN,afd.baidu.com,SomeGroup"], "afd.baidu.com"))
        XCTAssertFalse(verdict([], "afd.baidu.com"))
    }

    // MARK: responder wire behavior

    private func query(name: String, type: UInt16 = NCDNSMessage.typeA) -> Data {
        var q = NCDNSMessage()
        q.id = 0x4242
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        return q.serialized()
    }

    private func responder(blocking blocked: Set<String>) -> (NCFakeIPResponder, NCFakeIPPool) {
        let pool = NCFakeIPPool()
        let r = NCFakeIPResponder(pool: pool)
        r.rejectMatcher = { blocked.contains($0) ? "DOMAIN,\($0),REJECT" : nil }
        return (r, pool)
    }

    func testBlockedNameGetsNXDOMAIN() {
        let (r, pool) = responder(blocking: ["afd.baidu.com"])
        let resp = NCDNSMessage.parse(r.respond(to: query(name: "afd.baidu.com"))!)
        XCTAssertEqual(resp?.rcode, 3)
        XCTAssertEqual(resp?.answers.count, 0)
        XCTAssertEqual(resp?.id, 0x4242)
        XCTAssertEqual(pool.size, 0) // no fake IP was allocated for the blocked name
    }

    func testBlockedNameAAAAAlsoNXDOMAIN() {
        let (r, _) = responder(blocking: ["afd.baidu.com"])
        let resp = NCDNSMessage.parse(r.respond(to: query(name: "afd.baidu.com", type: NCDNSMessage.typeAAAA))!)
        XCTAssertEqual(resp?.rcode, 3)
        XCTAssertTrue(resp?.answers.isEmpty ?? false)
    }

    func testAllowedNameStillGetsFakeIP() {
        let (r, pool) = responder(blocking: ["afd.baidu.com"])
        let resp = NCDNSMessage.parse(r.respond(to: query(name: "map.baidu.com"))!)
        XCTAssertEqual(resp?.rcode, 0)
        XCTAssertEqual(resp?.answers.count, 1)
        XCTAssertEqual(pool.size, 1)
        if let a = resp?.answers.first {
            // Default fake range is 198.18.0.0/16.
            XCTAssertEqual(a.rdata.count, 4)
            XCTAssertEqual(a.rdata[0], 198)
            XCTAssertEqual(a.rdata[1], 18)
        }
    }

    func testOtherQueryTypesAreNotIntercepted() {
        let (r, _) = responder(blocking: ["afd.baidu.com"])
        // HTTPS (65) queries keep the forward-upstream behavior, blocked or not.
        XCTAssertNil(r.respond(to: query(name: "afd.baidu.com", type: NCDNSMessage.typeHTTPS)))
    }

    func testFilteredNameIsOutOfScope() {
        // fake-ip-filter (blacklist -> real IPs): the responder declines
        // before the reject check, exactly as before this change.
        let pool = NCFakeIPPool(filter: ["+.baidu.com"])
        let r = NCFakeIPResponder(pool: pool)
        r.rejectMatcher = { _ in "DOMAIN,afd.baidu.com,REJECT" }
        XCTAssertNil(r.respond(to: query(name: "afd.baidu.com")))
    }

    func testNoRejectMatcherKeepsClassicBehavior() {
        let pool = NCFakeIPPool()
        let r = NCFakeIPResponder(pool: pool)
        let resp = NCDNSMessage.parse(r.respond(to: query(name: "afd.baidu.com"))!)
        XCTAssertEqual(resp?.rcode, 0)
        XCTAssertEqual(resp?.answers.count, 1)
    }

    func testRejectedLogLineShape() {
        // Both DNS-log consumers parse the `resolve … error:` shape.
        XCTAssertEqual(NCDNSLogLine.rejected(name: "afd.baidu.com", type: "A"),
                       "[DNS] resolve afd.baidu.com error: A NXDOMAIN (REJECT rule)")
    }

    // MARK: blocked-by-domain records (the follow-up requirement)

    func testOutcomeCarriesHostAndRule() {
        let (r, _) = responder(blocking: ["afd.baidu.com"])
        let out = r.respondWithOutcome(to: query(name: "afd.baidu.com"))
        XCTAssertNotNil(out.reply)
        XCTAssertEqual(out.rejection?.host, "afd.baidu.com")
        XCTAssertEqual(out.rejection?.rule, "DOMAIN,afd.baidu.com,REJECT")
        let allowed = r.respondWithOutcome(to: query(name: "map.baidu.com"))
        XCTAssertNotNil(allowed.reply)
        XCTAssertNil(allowed.rejection)
    }

    func testRejectRuleIsTheDecidingRule() {
        let rs = rules([
            "DOMAIN-SUFFIX,baidu.com,DIRECT",
            "DOMAIN,afd.baidu.com,REJECT",
        ])
        XCTAssertNil(NCRuleMatcher.dnsRejectRule(rs, ctx("afd.baidu.com"))) // DIRECT decides first
        let rs2 = rules([
            "IP-CIDR,180.76.0.0/16,REJECT",
            "DOMAIN-SUFFIX,ubixioe.com,REJECT",
        ])
        XCTAssertEqual(NCRuleMatcher.dnsRejectRule(rs2, ctx("adx.ubixioe.com"))?.raw,
                       "DOMAIN-SUFFIX,ubixioe.com,REJECT")
    }

    func testDNSBlockedRecordAppearsByDomain() {
        // After a DNS-layer block, the connection records (the App's 已拦截
        // filter reads exactly these: chains ∋ REJECT) hold an entry keyed
        // by the domain — not a bare IP.
        let rec = NCStatsRecorder()
        // Timestamped a minute back: once the storm-aggregation gate exists
        // (fix(records) commit) a DNS-block record is a rejected record and
        // coalesces for its window first; an aged one is flushed by the
        // stats read itself. Pre-gate it stores immediately either way.
        rec.dnsBlocked(host: "afdconf.baidu.com", rule: "HOST,AFDCONF.BAIDU.COM,REJECT",
                       at: Date(timeIntervalSinceNow: -60))
        let stats = rec.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
        let closed = stats["closed"] as? [[String: Any]] ?? []
        XCTAssertEqual(closed.count, 1)
        let entry = closed.first
        let meta = entry?["metadata"] as? [String: Any]
        XCTAssertEqual(meta?["host"] as? String, "afdconf.baidu.com")
        XCTAssertEqual(meta?["destinationIP"] as? String, "")
        XCTAssertEqual((entry?["chains"] as? [String])?.first, "REJECT")
        XCTAssertEqual(entry?["rule"] as? String, "HOST,AFDCONF.BAIDU.COM,REJECT")
        // Not a connection: the session total must not move.
        XCTAssertEqual(stats["totalConnections"] as? Int, 0)
    }
}
