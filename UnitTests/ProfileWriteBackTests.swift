import XCTest
@testable import Tern

/// feat/profile-write-back (user 2026-10-29): rule-page edits bake into the profile file. These tests pin
/// the model-level bake: the builder's own apply functions, fed from the override store's rule family —
/// the Final's policy, profile-rule edits / deletions, rule-set policies and the rule-set order — plus
/// the split that keeps 停用 entries as overrides (no file representation).
final class ProfileWriteBackTests: XCTestCase {
    private func baseRaw() -> [String: NCJSONValue] {
        [
            "proxies": .array([.object(["name": .string("N1"), "type": .string("direct")])]),
            "proxy-groups": .array([
                .object(["name": .string("Main"), "type": .string("select"),
                         "proxies": .array([.string("N1"), .string("DIRECT")])]),
            ]),
            "rules": .array([.string("MATCH,Main")]),
        ]
    }

    private func strings(_ v: [NCJSONValue]) -> [String] { v.compactMap { if case .string(let s) = $0 { return s }; return nil } }
    private func rulesOf(_ raw: [String: NCJSONValue]) -> [String] { strings(raw.list("rules")) }

    private func bake(_ raw: [String: NCJSONValue], _ fam: [String: ProviderOverride]) -> [String: NCJSONValue] {
        ProfileWriteBack.bakedProfile(raw, ov: ProfileWriteBack.bakeSplit(fam).bake)
    }

    func testFinalPolicyBaked() {
        var raw = baseRaw()
        raw["rules"] = .array([.string("DOMAIN,a.com,Main"), .string("MATCH,Main")])
        var fin = ProviderOverride()
        fin.policy = "DIRECT"
        let out = bake(raw, [ProviderOverride.finalKey: fin])
        XCTAssertEqual(rulesOf(out), ["DOMAIN,a.com,Main", "MATCH,DIRECT"])
    }

    func testProfileRuleEditAndDeleteBaked() {
        var raw = baseRaw()
        raw["rules"] = .array([.string("DOMAIN,a.com,Main"), .string("DOMAIN,b.com,Main"), .string("MATCH,Main")])
        var entry = ProviderOverride()
        entry.rules = [
            ProfileRuleOverride(rule: "DOMAIN,a.com,Main", index: 0, line: "DOMAIN,a.com,DIRECT"),
            ProfileRuleOverride(rule: "DOMAIN,b.com,Main", index: 0, deleted: true),
        ]
        let out = bake(raw, [ProviderOverride.profileRulesKey: entry])
        XCTAssertEqual(rulesOf(out), ["DOMAIN,a.com,DIRECT", "MATCH,Main"])
    }

    func testRuleSetPolicyAndOrderBaked() {
        var raw = baseRaw()
        raw["rule-providers"] = .object([
            "ads": .object(["type": .string("http"), "behavior": .string("classical"),
                            "url": .string("https://e.invalid/ads.list"), "path": .string("./rules/ads.list")]),
            "track": .object(["type": .string("http"), "behavior": .string("classical"),
                              "url": .string("https://e.invalid/track.list"), "path": .string("./rules/track.list")]),
        ])
        raw["rules"] = .array([.string("RULE-SET,ads,Main"), .string("RULE-SET,track,Main"), .string("MATCH,Main")])
        var ads = ProviderOverride()
        ads.policy = "REJECT"
        var ord = ProviderOverride()
        ord.order = ["track", "ads"]
        let out = bake(raw, [ProviderOverride.ruleKey("ads"): ads, ProviderOverride.ruleOrderKey: ord])
        XCTAssertEqual(rulesOf(out), ["RULE-SET,track,Main", "RULE-SET,ads,REJECT", "MATCH,Main"])
    }

    func testDisabledEntriesStayOverrides() {
        var entry = ProviderOverride()
        let disabledRule = ProfileRuleOverride(rule: "DOMAIN,a.com,Main", index: 0, disabled: true)
        let deletedRule = ProfileRuleOverride(rule: "DOMAIN,b.com,Main", index: 0, deleted: true)
        entry.rules = [disabledRule, deletedRule]
        var set = ProviderOverride()
        set.disabled = true
        set.policy = "REJECT"
        let fam: [String: ProviderOverride] = [
            ProviderOverride.profileRulesKey: entry,
            ProviderOverride.ruleKey("ads"): set,
        ]
        let split = ProfileWriteBack.bakeSplit(fam)
        XCTAssertEqual(split.keptRules, [disabledRule])
        XCTAssertNil(split.bake[ProviderOverride.ruleKey("ads")], "a disabled rule set stays an override, whole entry")
        let bakedRules = split.bake[ProviderOverride.profileRulesKey]?.rules ?? []
        XCTAssertEqual(bakedRules.map(\.rule), ["DOMAIN,b.com,Main"], "only the deletion bakes")
    }

    func testBakedModelRoundTripsThroughConf() throws {
        var raw = baseRaw()
        raw["rules"] = .array([.string("DOMAIN,a.com,Main"), .string("MATCH,Main")])
        var fin = ProviderOverride()
        fin.policy = "DIRECT"
        let out = bake(raw, [ProviderOverride.finalKey: fin])
        let parsed = try TernConf.parse(TernConf.serializeProfile(out))
        XCTAssertEqual(parsed.profile, out)
    }

    func testRuleFamilyKeyClassification() {
        XCTAssertTrue(ProviderOverride.isRuleFamilyKey(ProviderOverride.finalKey))
        XCTAssertTrue(ProviderOverride.isRuleFamilyKey(ProviderOverride.profileRulesKey))
        XCTAssertTrue(ProviderOverride.isRuleFamilyKey(ProviderOverride.ruleOrderKey))
        XCTAssertTrue(ProviderOverride.isRuleFamilyKey("rule:ads"))
        XCTAssertFalse(ProviderOverride.isRuleFamilyKey("SelfBuild"))
        XCTAssertFalse(ProviderOverride.isRuleFamilyKey("rule"))
    }
}
