import XCTest
@testable import Tern

/// fix/nc-0.20.2: 订阅规则集 into the generated config, QX entries switched off in the original config imported as
/// 停用, node-subscription User-Agent 自动 fallback order, module client User-Agents.
final class NCFix0202Tests: XCTestCase {
    private func tempHome() throws -> String {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("fix0202-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: home) }
        return home.path
    }

    private func baseRaw() -> [String: NCJSONValue] {
        [
            "proxies": .array([.object(["name": .string("N1"), "type": .string("direct")])]),
            "proxy-groups": .array([
                .object(["name": .string("Main"), "type": .string("select"), "proxies": .array([.string("N1"), .string("DIRECT")])]),
            ]),
            "rules": .array([.string("MATCH,Main")]),
        ]
    }

    private func strings(_ v: [NCJSONValue]) -> [String] { v.compactMap { if case .string(let s) = $0 { return s }; return nil } }

    // MARK: 订阅规则集

    func testRuleSetSubscriptionLineRoundTrip() {
        let l = RuleSetSubscriptionSheet.line(url: "https://e.invalid/ads.list", tag: "My Ads", policy: "REJECT")
        XCTAssertEqual(l, "https://e.invalid/ads.list, tag=My Ads, force-policy=REJECT")
        let p = RuleSetSubscriptionSheet.parse(l)
        XCTAssertEqual(p?.url, "https://e.invalid/ads.list"); XCTAssertEqual(p?.tag, "My Ads"); XCTAssertEqual(p?.policy, "REJECT")
        XCTAssertEqual(RuleSetSubscriptionSheet.parse("RULE-SET,https://e.invalid/x.list,Main")?.policy, "Main")
        XCTAssertNil(RuleSetSubscriptionSheet.parse("DOMAIN,a.com,Main"))
        XCTAssertNil(RuleSetSubscriptionSheet.parse(RuleSetSubscriptionSheet.line(url: "https://e.invalid/a.list", tag: "", policy: nil))?.policy)
    }

    /// The sheet's rules.json entry reaches the generated config as a rule provider + RULE-SET; 停用 keeps it out.
    func testRuleSetSubscriptionLandsInGeneratedConfig() throws {
        let home = try tempHome()
        let line = RuleSetSubscriptionSheet.line(url: "https://rules.example.com/ads.list", tag: "Ads", policy: "REJECT")
        func write(enabled: Bool) throws {
            let r = CustomRule(id: "s1", line: line, enabled: enabled, interval: 86400)
            let d = try JSONEncoder().encode(["rules": [r]])
            try d.write(to: URL(fileURLWithPath: home + "/rules.json"))
        }
        let o = NCRuntimeSettings(core: CoreOverrides(), dns: nil, local: nil, home: home, manualPath: "")
        try write(enabled: true)
        var raw = baseRaw()
        NCRuntimeSteps.applyCustomRules(&raw, o)
        let rules = strings(raw.list("rules"))
        XCTAssertTrue(rules.contains { $0.hasPrefix("RULE-SET,") && $0.hasSuffix(",REJECT") }, "\(rules)")
        let rp = raw.map("rule-providers")
        XCTAssertTrue(rp.values.contains { $0.object?["url"]?.string == "https://rules.example.com/ads.list" }, "\(rp)")

        try write(enabled: false)
        var raw2 = baseRaw()
        NCRuntimeSteps.applyCustomRules(&raw2, o)
        XCTAssertFalse(strings(raw2.list("rules")).contains { $0.hasPrefix("RULE-SET,") }, "停用 stays out")
    }

    // MARK: QX disabled entries

    static let qx = """
    [policy]
    static=Main, direct

    [server_remote]
    https://sub.example.com/a, tag=SubOn, enabled=true
    https://sub.example.com/b, tag=SubOff, enabled=false

    [filter_remote]
    https://rules.example.com/on.list, tag=On, force-policy=Main, enabled=true
    https://rules.example.com/off.list, tag=Off, force-policy=Main, enabled=false

    [rewrite_remote]
    https://rw.example.com/off.snippet, tag=RwOff, enabled=false

    [filter_local]
    final, Main
    """

    func testQXDisabledRemotesImportAsDisabled() throws {
        let r = NCConfImportPort.importConfResult(Self.qx)
        XCTAssertNil(r.error)
        XCTAssertEqual(r.report.disabledProviders?.count, 1, "\(String(describing: r.report.disabledProviders))")
        XCTAssertEqual(r.report.disabledRuleSets?.count, 1, "\(String(describing: r.report.disabledRuleSets))")
        XCTAssertEqual(r.report.disabled?.count, 2)
        XCTAssertEqual(r.rewriteRemotes?.first?.enabled, false, "rewrite_remote kept, switched off")
        guard case .object(var raw)? = NCYAML.parse(r.yaml) else { return XCTFail("yaml") }
        let offNode = r.report.disabledProviders![0], offRules = r.report.disabledRuleSets![0]
        XCTAssertNotNil(raw.map("proxy-providers")[offNode], "imported")
        XCTAssertNotNil(raw.map("rule-providers")[offRules], "imported")

        // switched off: not in the generated config (not fetched, not loaded)
        let ov: [String: NCProviderOverride] = [offNode: NCProviderOverride(disabled: true),
                                                "rule:" + offRules: NCProviderOverride(disabled: true)]
        var off = raw
        _ = NCRuntimeSteps.applyProviderOverridesDeferred(&off, ov: ov)
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&off, ov: ov)
        XCTAssertNil(off.map("proxy-providers")[offNode])
        XCTAssertNil(off.map("rule-providers")[offRules])
        XCTAssertFalse(strings(off.list("rules")).contains { $0.contains("RULE-SET," + offRules + ",") })
        XCTAssertNotNil(off.map("rule-providers").first { $0.key != offRules }, "the enabled list stays")

        // turned on: back in
        _ = NCRuntimeSteps.applyProviderOverridesDeferred(&raw, ov: [:])
        XCTAssertNotNil(raw.map("proxy-providers")[offNode])
        XCTAssertTrue(strings(raw.list("rules")).contains { $0.contains("RULE-SET," + offRules + ",") })
    }

    // MARK: User-Agent

    func testNodeSubscriptionAutoUAFallbackOrder() {
        XCTAssertEqual(SubscriptionUA.attempts(SubscriptionUA.auto, remembered: nil),
                       ["clash.meta", "Quantumult%20X/1.5.2", "Shadowrocket/2070"])
        XCTAssertEqual(SubscriptionUA.attempts(SubscriptionUA.auto, remembered: "Shadowrocket/2070"),
                       ["Shadowrocket/2070", "clash.meta", "Quantumult%20X/1.5.2"])
        XCTAssertEqual(SubscriptionUA.attempts("custom/1", remembered: "clash.meta"), ["custom/1"])
        XCTAssertEqual(SubscriptionUA.attempts(SubscriptionUA.metaCore, remembered: nil), ["clash.meta"], "old duplicate migrated")
        XCTAssertTrue(SubscriptionUA.isNoNodes(ProfileStore.StoreError.invalid("没有识别到节点")))
        XCTAssertFalse(SubscriptionUA.isNoNodes(ProfileStore.StoreError.http(403)))
    }

    func testModuleClientUserAgent() {
        XCTAssertTrue(EngineStore.moduleUserAgent("https://a.example/x.plugin").hasPrefix("Loon"))
        XCTAssertTrue(EngineStore.moduleUserAgent("https://a.example/x.snippet").hasPrefix("Quantumult"))
        XCTAssertTrue(EngineStore.moduleUserAgent("https://a.example/x.sgmodule").hasPrefix("Surge"))
        XCTAssertTrue(EngineStore.moduleUserAgent("https://a.example/x.conf", client: "qx").hasPrefix("Quantumult"))
    }

    func testTaskCronValidation() {
        XCTAssertTrue(TaskFormSheet.cronOK("0 8 * * *"))
        XCTAssertTrue(TaskFormSheet.cronOK("0 0 8 * * *"))
        XCTAssertTrue(TaskFormSheet.cronOK("@daily"))
        XCTAssertFalse(TaskFormSheet.cronOK("0 8 * *"))
        XCTAssertFalse(TaskFormSheet.cronOK("0 8 * * * sample.js"))
    }
}
