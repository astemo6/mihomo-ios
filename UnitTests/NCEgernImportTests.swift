import XCTest
@testable import Tern

/// feat/nc-egern-disabled-import (#169): an Egern configuration imports through
/// the ConfImport pipeline with the source's disabled state preserved, and
/// single items inside an Egern module file are not imported as enabled.
/// The fixture shapes follow the Egern documentation (typed rule / scripting
/// entries; `disabled` on items, `enabled` on module references; policy groups
/// and proxies have no such field).
final class NCEgernImportTests: XCTestCase {

    // MARK: - Configuration import

    private let config = """
    name: Egern Sample
    proxies:
      - trojan:
          name: Inline Node
          server: 192.0.2.1
          port: 443
          password: secret
    policy_groups:
      - external:
          name: Sub
          type: select
          urls:
            - https://example.com/sub.yaml
      - select:
          name: PROXY
          policies:
            - Sub
            - Inline Node
            - DIRECT
    rules:
      - rule_set:
          match: https://example.com/rules.yaml
          policy: PROXY
      - rule_set:
          match: https://example.com/off.yaml
          policy: PROXY
          disabled: true
      - domain_suffix:
          match: example.com
          policy: DIRECT
      - domain_suffix:
          match: off.example.com
          policy: DIRECT
          disabled: true
      - default:
          policy: PROXY
    modules:
      - name: Mod On
        url: https://example.com/on.yaml
        enabled: true
      - name: Mod Off
        url: https://example.com/off-mod.yaml
        enabled: false
    scriptings:
      - schedule:
          name: Daily Off
          cron: "0 8 * * *"
          script_url: https://example.com/daily.js
          disabled: true
    mitm:
      hostnames:
        - "*.example.com"
    """

    func testConfigIsDetected() {
        XCTAssertTrue(NCEgernImport.isConfig(config))
        XCTAssertEqual(ImportTools.classifyText(config), "conf")
        // A module-shaped Egern document (no proxies / policy_groups) stays a module.
        let module = """
        name: Just A Module
        scriptings:
          - name: s
            url: https://example.com/s.js
            schedule: "0 9 * * *"
        """
        XCTAssertFalse(NCEgernImport.isConfig(module))
        XCTAssertEqual(ImportTools.classifyText(module), "module:egern")
    }

    func testDisabledModuleReferenceIsAddedNotDownloaded() {
        let r = NCEgernImport.convert(config)
        XCTAssertNil(r.error)
        let remotes = r.rewriteRemotes ?? []
        XCTAssertEqual(remotes.count, 2)
        XCTAssertEqual(remotes.first { $0.name == "Mod On" }?.enabled, true)
        XCTAssertEqual(remotes.first { $0.name == "Mod Off" }?.enabled, false)
        XCTAssertTrue((r.report?.disabled ?? []).contains("[模块] Mod Off"))
    }

    func testDisabledRuleSetImportedThenSwitchedOff() throws {
        let r = NCEgernImport.convert(config)
        XCTAssertNil(r.error)
        XCTAssertEqual(r.report?.disabledRuleSets?.count, 1)
        let offName = try XCTUnwrap(r.report?.disabledRuleSets?.first)
        guard case .object(var raw)? = NCYAML.parse(try XCTUnwrap(r.yaml)) else { return XCTFail("yaml") }
        // Imported: the provider and its RULE-SET line exist…
        XCTAssertNotNil(raw.map("rule-providers")[offName], "disabled rule set is imported")
        XCTAssertTrue(strings(raw.list("rules")).contains { $0.hasPrefix("RULE-SET,\(offName),") })
        XCTAssertEqual(raw.map("rule-providers").count, 2, "the enabled rule set stays too")
        // …and switched off by the same override the import applies: gone from
        // the generated config, back when the override is lifted.
        let ov: [String: NCProviderOverride] = ["rule:" + offName: NCProviderOverride(disabled: true)]
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        XCTAssertNil(raw.map("rule-providers")[offName])
        XCTAssertFalse(strings(raw.list("rules")).contains { $0.hasPrefix("RULE-SET,\(offName),") })
    }

    func testDisabledLocalRuleKeptInProfileAndMarked() throws {
        let r = NCEgernImport.convert(config)
        guard case .object(let raw)? = NCYAML.parse(try XCTUnwrap(r.yaml)) else { return XCTFail("yaml") }
        let lines = strings(raw.list("rules"))
        XCTAssertTrue(lines.contains("DOMAIN-SUFFIX,example.com,DIRECT"), "enabled rule unaffected")
        XCTAssertTrue(lines.contains("DOMAIN-SUFFIX,off.example.com,DIRECT"), "disabled rule text stays in the profile")
        XCTAssertEqual(lines.last, "MATCH,PROXY")
        let off = try XCTUnwrap(r.report?.disabledRules)
        XCTAssertEqual(off.count, 1)
        XCTAssertEqual(off.first?.rule, "DOMAIN-SUFFIX,off.example.com,DIRECT")
        XCTAssertEqual(off.first?.index, 0, "first (only) occurrence of its text")
    }

    func testGroupsProvidersAndInlineProxyHandling() throws {
        let r = NCEgernImport.convert(config)
        guard case .object(let raw)? = NCYAML.parse(try XCTUnwrap(r.yaml)) else { return XCTFail("yaml") }
        // The subscription group became a proxy-provider named after the group.
        XCTAssertNotNil(raw.map("proxy-providers")["Sub"])
        let groups = raw.list("proxy-groups")
        let proxyGroup = groups.compactMap { $0.object }.first { $0["name"]?.string == "PROXY" }
        let members = strings(proxyGroup?["proxies"]?.array ?? [])
        XCTAssertTrue(members.contains("Sub"))
        XCTAssertTrue(members.contains("DIRECT"))
        XCTAssertFalse(members.contains("Inline Node"), "unconverted inline node is filtered out")
        // …and reported, never silently dropped; the group/proxy schema has no
        // disabled field, so nothing is (or can be) marked off there.
        XCTAssertTrue((r.report?.skipped ?? []).contains { $0.contains("Inline Node") })
        XCTAssertNil(r.report?.disabledProviders)
        XCTAssertEqual(r.report?.groups, 2)
    }

    func testEngineSectionsAttachAsModule() throws {
        let r = NCEgernImport.convert(config)
        let module = try XCTUnwrap(r.module)
        XCTAssertTrue(module.contains("scriptings:"))
        XCTAssertTrue(module.contains("mitm:"))
        XCTAssertFalse(module.contains("policy_groups:"), "routing sections are not duplicated into the module")
        XCTAssertEqual(r.report?.module, true)
        // The disabled cron scripting inside imports as a switched-off task.
        XCTAssertEqual(r.report?.tasks, 1)
        XCTAssertEqual(r.report?.hostnames, 1)
    }

    // MARK: - Module-file item level (parseEgern)

    private let moduleText = """
    name: ModSample
    scriptings:
      - name: cronoff
        url: https://example.com/cron.js
        schedule: "0 9 * * *"
        disabled: true
      - name: cronon
        url: https://example.com/cron2.js
        schedule: "0 10 * * *"
      - name: reqoff
        url: https://example.com/req.js
        disabled: true
        http_request:
          patterns:
            - ^https://api.example.com/
    body_rewrites:
      - response_jq:
          match: "^https://api.example.com/"
          filter: ".data"
          disabled: true
    rules:
      - domain_suffix:
          match: off.example.com
          policy: REJECT
          disabled: true
      - domain_suffix:
          match: on.example.com
          policy: REJECT
    """

    func testModuleItemsDisabled() {
        let rs = NCEngineRuleset()
        rs.parseText(moduleText, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "egern")
        // Tasks keep their off state; script rules / jq rules / routing rules
        // with disabled: true are not imported as enabled.
        XCTAssertEqual(rs.tasks.first { $0.name == "cronoff" }?.disabledByLine, true)
        XCTAssertEqual(rs.tasks.first { $0.name == "cronon" }?.disabledByLine, false)
        XCTAssertFalse(rs.rules.contains { $0.script?.name == "reqoff" }, "disabled script rule not imported")
        XCTAssertFalse(rs.rules.contains { $0.kind == "jq" }, "disabled body rewrite not imported")
        XCTAssertFalse(rs.rules.contains { $0.line.contains("off.example.com") }, "disabled routing rule not imported")
        XCTAssertTrue(rs.rules.contains { $0.line.contains("on.example.com") }, "enabled routing rule unaffected")
        XCTAssertFalse(rs.unsupported.contains { $0.contains("disabled") }, "disabled is consumed, not reported unparsed: \(rs.unsupported)")
    }

    func testTypedScriptingEntriesImportAndDisable() {
        let text = """
        name: TypedSample
        scriptings:
          - schedule:
              name: Typed Off
              cron: "0 8 * * *"
              script_url: https://example.com/typed.js
              disabled: true
          - http_request:
              name: Typed Req
              match: "^https://api.example.com/"
              script_url: https://example.com/req.js
              body_required: true
        """
        let rs = NCEngineRuleset()
        rs.parseText(text, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "egern")
        XCTAssertEqual(rs.tasks.first { $0.name == "Typed Off" }?.disabledByLine, true)
        let rule = rs.rules.first { $0.script?.name == "Typed Req" }
        XCTAssertEqual(rule?.pattern, "^https://api.example.com/")
        XCTAssertEqual(rule?.script?.requiresBody, true)
    }

    // MARK: helpers

    private func strings(_ v: [NCJSONValue]) -> [String] { v.compactMap { $0.string } }
}
