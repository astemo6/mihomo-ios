import XCTest
@testable import Tern

/// fix/app-policy-ui (user 2026-10-26): group 测速 streams each member's result as it lands (#2), 分流规则 → 编辑排序
/// writes the RULE-SET order back into the runtime's rules and keeps it across a profile refresh (#3), and Home
/// cards can be half width so two share a row (#6).
final class PolicyUILaneTests: XCTestCase {

    // MARK: #2 delay streaming

    private actor Gauge {
        var now = 0, peak = 0
        func enter() { now += 1; peak = max(peak, now) }
        func leave() { now -= 1 }
    }

    private actor Log {
        var items: [(String, TimeInterval)] = []
        func add(_ n: String, _ t: TimeInterval) { items.append((n, t)) }
    }

    /// The fast members reach the caller long before the slow one finishes (the old membersDelay returned only
    /// after every member, so the page waited for the slowest node / the timeout).
    func testDelayStreamReportsEachResultAsItLands() async {
        let delays: [String: UInt64] = ["slow": 900, "a": 20, "b": 40, "c": 60, "d": 80]
        let names = ["slow", "a", "b", "c", "d"]
        let log = Log()
        let start = Date()
        await DelayStream.run(names, width: DelayStream.groupWidth, run: { n -> (String, Int) in
            try? await Task.sleep(nanoseconds: delays[n]! * 1_000_000)
            return (n, Int(delays[n]!))
        }, onResult: { r in await log.add(r.0, Date().timeIntervalSince(start)) })
        let items = await log.items
        XCTAssertEqual(items.count, names.count, "every member reported once")
        XCTAssertEqual(Set(items.map(\.0)), Set(names))
        XCTAssertEqual(items.last?.0, "slow", "the slow member lands last")
        let first = items.first!
        XCTAssertNotEqual(first.0, "slow")
        XCTAssertLessThan(first.1, 0.6, "the first result arrives while the slow member is still running (\(first.1) s)")
        XCTAssertGreaterThanOrEqual(items.last!.1, 0.85, "the run itself still waits for every member")
    }

    func testDelayStreamRespectsWidth() async {
        let gauge = Gauge()
        let names = (0..<24).map { "n\($0)" }
        var got: [String] = []
        await DelayStream.run(names, width: 4, run: { n -> String in
            await gauge.enter()
            try? await Task.sleep(nanoseconds: 25_000_000)
            await gauge.leave()
            return n
        }, onResult: { got.append($0) })
        let peak = await gauge.peak
        XCTAssertLessThanOrEqual(peak, 4, "never more than `width` in flight")
        XCTAssertGreaterThan(peak, 1, "members do run in parallel")
        XCTAssertEqual(got.sorted(), names.sorted())
        // Empty input returns at once.
        await DelayStream.run([], width: 4, run: { $0 }, onResult: { _ in XCTFail("no result for no members") })
    }

    @MainActor
    func testDelayStreamBufferCoalescesResults() async {
        var flushes: [[String: Int]] = []
        let buffer = DelayStreamBuffer(intervalMs: 50) { flushes.append($0) }
        buffer.add("a", 10)
        buffer.add("b", 0)
        buffer.add("a", 12) // a newer result of the same node wins
        XCTAssertTrue(flushes.isEmpty, "batched, not one publish per result")
        try? await Task.sleep(nanoseconds: 250_000_000)
        XCTAssertEqual(flushes.count, 1)
        XCTAssertEqual(flushes.first, ["a": 12, "b": 0])
        buffer.add("c", 30)
        buffer.drain() // the end of a test publishes what is left right away
        XCTAssertEqual(flushes.count, 2)
        XCTAssertEqual(flushes.last, ["c": 30])
        try? await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(flushes.count, 2, "nothing pending, nothing published")
    }

    // MARK: #3 rule-set order write-back

    private func profile(rules: [String], sets: [String]) -> [String: NCJSONValue] {
        var rp: [String: NCJSONValue] = [:]
        for s in sets { rp[s] = .object(["type": .string("http"), "behavior": .string("domain"), "url": .string("https://e.x/\(s).yaml")]) }
        return ["rule-providers": .object(rp), "rules": .array(rules.map { .string($0) })]
    }

    private func rules(_ raw: [String: NCJSONValue]) -> [String] {
        raw.list("rules").compactMap { if case .string(let s) = $0 { return s }; return nil }
    }

    /// 编辑排序 saves `#rule-order`; the runtime build puts the RULE-SET lines into that order. Local / inline rules,
    /// a logical rule that mentions a set and the final MATCH keep their positions.
    func testRuleSetOrderIsWrittenIntoTheRuntimeRules() {
        var raw = profile(rules: [
            "DOMAIN-SUFFIX,local.lan,DIRECT",
            "RULE-SET,China,DIRECT",
            "RULE-SET,AI,Proxy",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "AND,((RULE-SET,AI),(NETWORK,UDP)),REJECT",
            "RULE-SET,Facebook,Proxy",
            "MATCH,Final",
        ], sets: ["China", "AI", "Facebook"])
        var ov: [String: NCProviderOverride] = [:]
        ov[ProviderOverride.ruleOrderKey] = NCProviderOverride(order: ["Facebook", "China", "AI"])
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        XCTAssertEqual(rules(raw), [
            "DOMAIN-SUFFIX,local.lan,DIRECT",
            "RULE-SET,Facebook,Proxy",
            "RULE-SET,China,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "AND,((RULE-SET,AI),(NETWORK,UDP)),REJECT",
            "RULE-SET,AI,Proxy",
            "MATCH,Final",
        ])
    }

    /// The order lives in the override, not in the profile file: a refreshed subscription (a set added, one gone)
    /// gets it again; the new set keeps the slot the subscription gave it.
    func testRuleSetOrderSurvivesASubscriptionRefresh() {
        var ov: [String: NCProviderOverride] = [:]
        ov[ProviderOverride.ruleOrderKey] = NCProviderOverride(order: ["Facebook", "China", "AI"])
        var raw = profile(rules: [
            "RULE-SET,China,DIRECT",
            "RULE-SET,Netflix,Proxy",
            "RULE-SET,Facebook,Proxy",
            "GEOIP,CN,DIRECT",
            "MATCH,Final",
        ], sets: ["China", "Netflix", "Facebook"])
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        XCTAssertEqual(rules(raw), [
            "RULE-SET,Facebook,Proxy",
            "RULE-SET,Netflix,Proxy",
            "RULE-SET,China,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,Final",
        ])
        // Applying it again (a hot reload) changes nothing.
        let once = rules(raw)
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        XCTAssertEqual(rules(raw), once)
    }

    /// The App writes provider-overrides.json (ProviderOverride); the runtime reads it as NCProviderOverride.
    func testRuleOrderOverrideFileFeedsTheRuntime() throws {
        var o = ProviderOverride()
        o.order = ["B", "A"]
        let data = try JSONEncoder().encode([ProviderOverride.ruleOrderKey: o])
        let read = try JSONDecoder().decode([String: NCProviderOverride].self, from: data)
        XCTAssertEqual(read[ProviderOverride.ruleOrderKey]?.order, ["B", "A"])
    }

    /// 完成: only what changed is written; the user's own lists keep the slots they hold among local custom rules.
    func testRuleSetOrderPlan() {
        let rows = ["A", "B", "C"].map { RuleOrderRow(id: $0, name: $0, policy: "") }
        XCTAssertNil(RuleSetOrderPlan.setOrder(rows, original: ["A", "B", "C"]), "unchanged → nothing saved")
        XCTAssertEqual(RuleSetOrderPlan.setOrder(Array(rows.reversed()), original: ["A", "B", "C"]), ["C", "B", "A"])

        let rules = [
            CustomRule(id: "r1", line: "RULE-SET,https://e.x/one.list,DIRECT"),
            CustomRule(id: "l1", line: "DOMAIN,a.com,DIRECT"),
            CustomRule(id: "r2", line: "RULE-SET,https://e.x/two.list,Proxy"),
            CustomRule(id: "r3", line: "RULE-SET,https://e.x/three.list,REJECT"),
        ]
        let out = RuleSetOrderPlan.reordered(rules, ids: ["r3", "r1", "r2"])
        XCTAssertEqual(out.map(\.id), ["r3", "l1", "r1", "r2"], "the local rule keeps its slot")
        XCTAssertEqual(RuleSetOrderPlan.mineOrder(rows, original: ["A", "B", "C"]), nil)
    }

    // MARK: #6 Home card width

    func testHomeRowLayoutPairsHalfWidthCards() {
        let half: Set<String> = ["u", "m", "p1", "x"]
        let ids = ["u", "m", "wave", "p1", "p2", "x"]
        XCTAssertEqual(HomeRow.layout(ids, half: { half.contains($0) }), [["u", "m"], ["wave"], ["p1"], ["p2"], ["x"]])
        XCTAssertEqual(HomeRow.layout(["a", "b", "c"], half: { _ in true }), [["a", "b"], ["c"]])
        XCTAssertEqual(HomeRow.layout(["a", "b"], half: { _ in false }), [["a"], ["b"]])
        XCTAssertEqual(HomeRow.layout([], half: { _ in true }), [])
    }

    func testPanelWidthDefaultsAndOverride() {
        XCTAssertTrue(PanelOverride.isHalf(id: BuiltinTile.uptime.id, override: nil), "small built-in tiles: half by default")
        XCTAssertFalse(PanelOverride.isHalf(id: BuiltinTile.speed.id, override: nil), "wide tiles: full by default")
        XCTAssertFalse(PanelOverride.isHalf(id: "surge-panel-1", override: nil), "script panels: full by default")
        XCTAssertTrue(PanelOverride.isHalf(id: "surge-panel-1", override: PanelOverride(width: PanelOverride.half)))
        XCTAssertFalse(PanelOverride.isHalf(id: BuiltinTile.uptime.id, override: PanelOverride(width: PanelOverride.full)))
        XCTAssertFalse(PanelOverride(width: PanelOverride.half).isEmpty, "a width-only override is kept")
        XCTAssertTrue(PanelOverride().isEmpty)
        // Old panel-overrides.json without the key still decodes.
        let old = try? JSONDecoder().decode(PanelOverride.self, from: Data(#"{"title":"T"}"#.utf8))
        XCTAssertEqual(old?.title, "T")
        XCTAssertNil(old?.width)
    }
}
