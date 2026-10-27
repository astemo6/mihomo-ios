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
    // MARK: fix/nc-0.20.2 round 2

    /// The task form's next-run preview uses the tunnel's own cron parser (NCCron, now in Shared/NativeCore).
    func testCronNextRunPreview() throws {
        var c = DateComponents()
        c.year = 2026; c.month = 10; c.day = 27; c.hour = 9; c.minute = 15
        let t = try XCTUnwrap(Calendar.current.date(from: c))
        let n = try XCTUnwrap(TaskFormSheet.nextRun("0 8 * * *", after: t))
        let nc = Calendar.current.dateComponents([.day, .hour, .minute], from: n)
        XCTAssertEqual(nc.day, 28); XCTAssertEqual(nc.hour, 8); XCTAssertEqual(nc.minute, 0)
        XCTAssertNotNil(TaskFormSheet.nextRun("@hourly", after: t))
        XCTAssertNil(TaskFormSheet.nextRun("0 8 * *", after: t), "invalid → no preview")
        XCTAssertNotNil(NCCron("*/5 * * * *")?.next(after: t))
        XCTAssertNotNil(TaskFormSheet.nextRunText("0 8 * * *"))
    }

    /// 文本方式添加 saves the line into 脚本 (parsed with section "script"): Surge, Loon and QX task lines all list.
    func testTaskTextLinesParse() {
        let lines = [
            "签到 = type=cron,cronexp=\"0 8 * * *\",script-path=https://e.invalid/a.js",
            "cron \"0 8 * * *\" script-path=https://e.invalid/b.js, tag=签到B",
            "0 8 * * * https://e.invalid/c.js, tag=签到C, enabled=true",
        ]
        for l in lines {
            let rs = NCEngineRuleset()
            rs.parseLine(l, section: "script", source: "用户")
            XCTAssertEqual(rs.tasks.count, 1, "task from: \(l) (errors \(rs.errors), unsupported \(rs.unsupported))")
            XCTAssertEqual(rs.tasks.first?.cron.map(TaskFormSheet.normCron), "0 8 * * *", l)
        }
    }

    static let surgeOff = """
    [Proxy]
    N1 = direct

    [Proxy Group]
    Main = select, N1, DIRECT

    [Rule]
    DOMAIN,on.example.com,Main
    # DOMAIN-SUFFIX,off.example.com,REJECT
    # 这是一段说明
    # 注释, 不是规则
    FINAL,Main

    [URL Rewrite]
    # ^https?://off\\.example\\.com/ - reject

    [Script]
    # 签到 = type=cron,cronexp="0 8 * * *",script-path=https://e.invalid/a.js
    """

    /// Commented-out local lines import 停用: the rule is in the profile and switched off by the #profile-rules
    /// override; rewrite / script lines become 停用 local items. Prose comments are ignored.
    func testSurgeCommentedLinesImportDisabled() throws {
        let r = NCConfImportPort.importConfResult(Self.surgeOff)
        XCTAssertNil(r.error)
        let refs = try XCTUnwrap(r.report.disabledRules)
        XCTAssertEqual(refs.count, 1, "\(refs)")
        XCTAssertTrue(refs[0].rule.hasPrefix("DOMAIN-SUFFIX,off.example.com,"), refs[0].rule)
        XCTAssertEqual(refs[0].index, 0)
        let local = r.report.disabledLocal ?? []
        XCTAssertEqual(local.filter { $0.script }.count, 1, "\(local)")
        XCTAssertEqual(local.filter { !$0.script }.count, 1, "\(local)")
        guard case .object(var raw)? = NCYAML.parse(r.yaml) else { return XCTFail("yaml") }
        XCTAssertTrue(strings(raw.list("rules")).contains(refs[0].rule), "imported into the profile")
        XCTAssertFalse(strings(raw.list("rules")).contains { $0.contains("说明") || $0.contains("注释") })
        let ov: [String: NCProviderOverride] = ["#profile-rules": NCProviderOverride(rules: [
            NCProfileRuleOverride(rule: refs[0].rule, index: refs[0].index, disabled: true)])]
        _ = NCRuntimeSteps.applyProfileRuleOverrides(&raw, ov: ov)
        let after = strings(raw.list("rules"))
        XCTAssertFalse(after.contains(refs[0].rule), "停用: not in the runtime rules")
        XCTAssertTrue(after.contains { $0.hasPrefix("DOMAIN,on.example.com") }, "the enabled rule stays")
    }

    static let loon = """
    [Proxy]
    N1 = direct

    [Proxy Group]
    Main = select, N1, DIRECT

    [Rule]
    FINAL,Main

    [Remote Rule]
    https://rules.example.com/on.list, policy=Main, tag=LoonOn, enabled=true
    https://rules.example.com/off.list, policy=Main, tag=LoonOff, enabled=false

    [Plugin]
    https://plugins.example.com/off.plugin, tag=PlugOff, enabled=false
    https://plugins.example.com/on.plugin, tag=PlugOn, enabled=true
    """

    /// Loon [Remote Rule] → rule sets (enabled=false → 停用), [Plugin] → remote modules (enabled=false kept, Loon UA).
    func testLoonRemoteRulesAndPlugins() throws {
        let r = NCConfImportPort.importConfResult(Self.loon)
        XCTAssertNil(r.error)
        XCTAssertEqual(r.report.disabledRuleSets?.count, 1, "\(String(describing: r.report.disabledRuleSets))")
        guard case .object(let raw)? = NCYAML.parse(r.yaml) else { return XCTFail("yaml") }
        XCTAssertEqual(raw.map("rule-providers").count, 2)
        let rem = try XCTUnwrap(r.rewriteRemotes)
        XCTAssertEqual(rem.count, 2)
        XCTAssertEqual(rem.first { $0.name == "PlugOff" }?.enabled, false)
        XCTAssertEqual(rem.first { $0.name == "PlugOn" }?.enabled, true)
        XCTAssertTrue(rem.allSatisfy { $0.client == "loon" })
        XCTAssertFalse(r.report.notes.contains { $0.contains("[plugin]") || $0.contains("[remote rule]") }, "\(r.report.notes)")
    }

    /// A QX rewrite_remote with enabled=false is reported off (ConfImport adds it without downloading).
    func testQXDisabledRewriteRemoteClient() throws {
        let r = NCConfImportPort.importConfResult(Self.qx)
        let m = try XCTUnwrap(r.rewriteRemotes?.first)
        XCTAssertFalse(m.enabled)
        XCTAssertEqual(m.client, "qx")
    }

    /// BackgroundDownloads never downloads a 停用 module (it is fetched when switched on).
    @MainActor func testDisabledModuleIsNotDownloaded() async {
        let store = EngineStore.shared
        let saved = store.config.modules
        defer { store.config.modules = saved }
        let m = EngineModule(name: "off", url: "https://e.invalid/off.snippet", enabled: false, args: nil, updatedAt: nil)
        store.config.modules.append(m)
        let e = await BackgroundDownloads.shared.fetchModule(m.id)
        XCTAssertNil(e)
        XCTAssertFalse(FileManager.default.fileExists(atPath: EnginePaths.moduleURL(m.id).path), "not downloaded")
        XCTAssertNil(BackgroundDownloads.shared.pendingModules[m.id])
    }

    /// NCResources' completion queue runs at the waiting caller's QoS (no priority inversion in prefetch).
    func testResourceSessionQoSMatchesCaller() {
        XCTAssertEqual(NCResources.session(for: QOS_CLASS_USER_INITIATED).delegateQueue.qualityOfService, .userInitiated)
        XCTAssertEqual(NCResources.session(for: QOS_CLASS_USER_INTERACTIVE).delegateQueue.qualityOfService, .userInteractive)
        XCTAssertEqual(NCResources.session(for: QOS_CLASS_UTILITY).delegateQueue.qualityOfService, .utility)
        XCTAssertTrue(NCResources.session(for: QOS_CLASS_UTILITY) === NCResources.session(for: QOS_CLASS_BACKGROUND), "one per band")
    }
}
