import XCTest
@testable import Mihomo

// Coverage for PR #120 (fix/nc-compat): Loon plugin reference lines, the
// full #! metadata set, .lpx expression script lines with typed plugin-
// object arguments, and Egern `scriptings:` import. Inputs follow the
// grammars documented in EngineParser.swift (Loon 3.5.1 .lpx syntax) and
// the classic .plugin shape seeded in UITestSeed.
final class NativeCoreLoonPluginTests: XCTestCase {

    private let pluginText = """
    #!name = LoonCov Plugin
    #!desc = coverage fixture
    #!homepage = https://example.com/plugin
    #!icon = https://example.com/icon.png
    #!system = iOS
    #!system_version = 16
    #!loon_version = 3.5.1
    #!date = 2026-01-01

    [Argument]
    flag = switch, true, tag=开关, type=boolean
    limit = input, 5, tag=上限, type=number
    kw = input, hello, tag=词

    [Script]
    http-request if ${url} ~= /api/v1/ && ${flag} == true then script("https://example.com/a.js", {${flag}, ${limit}}) with tag=demo, requires_body=true
    http-response if ${flag} == false then script("https://example.com/off.js")
    cron "30 8 * * *" then script("https://example.com/cron.js") with tag=daily
    network-changed then script("https://example.com/net.js")
    generic then script("https://example.com/generic.js")

    [Plugin]
    https://example.com/other.lpx, tag=sub, icon=https://example.com/i.png
    """

    private func ruleset() -> NCEngineRuleset {
        let rs = NCEngineRuleset()
        rs.parseText(pluginText, source: "模块", args: [:])
        return rs
    }

    /// [Plugin] reference lines split into url + params, original line kept.
    func testPluginReferenceLine() {
        let parsed = NCEngineParser.parseText(pluginText, argsJSON: "{}")
        XCTAssertEqual(parsed.plugins?.count, 1)
        XCTAssertEqual(parsed.plugins?.first?.url, "https://example.com/other.lpx")
        XCTAssertEqual(parsed.plugins?.first?.params["tag"], "sub")
        XCTAssertEqual(parsed.plugins?.first?.params["icon"], "https://example.com/i.png")
        XCTAssertEqual(parsed.plugins?.first?.line,
                       "https://example.com/other.lpx, tag=sub, icon=https://example.com/i.png")
    }

    /// Every #! key lands in metadata (first occurrence wins) — before
    /// #120 only name/desc/author/category/tag survived.
    func testFullMetadataSet() {
        let parsed = NCEngineParser.parseText(pluginText, argsJSON: "{}")
        XCTAssertEqual(parsed.name, "LoonCov Plugin")
        XCTAssertEqual(parsed.metadata?["homepage"], "https://example.com/plugin")
        XCTAssertEqual(parsed.metadata?["icon"], "https://example.com/icon.png")
        XCTAssertEqual(parsed.metadata?["system"], "iOS")
        XCTAssertEqual(parsed.metadata?["system_version"], "16")
        XCTAssertEqual(parsed.metadata?["loon_version"], "3.5.1")
        XCTAssertEqual(parsed.metadata?["date"], "2026-01-01")
    }

    /// The `if` expression form: ${url} ~= becomes the pattern, the
    /// argument term is decided at import (flag defaults to true, so the
    /// rule survives), and {${flag}, ${limit}} becomes a typed object
    /// argument — boolean stays boolean, number stays a number.
    func testExpressionIfLineWithObjectArgument() throws {
        let rs = ruleset()
        let rule = try XCTUnwrap(rs.rules.first { $0.pattern == "api/v1" })
        XCTAssertEqual(rule.kind, "script")
        XCTAssertEqual(rule.phase, "request")
        XCTAssertEqual(rule.script?.name, "demo")
        XCTAssertEqual(rule.script?.path, "https://example.com/a.js")
        XCTAssertEqual(rule.script?.requiresBody, true)
        XCTAssertEqual(rule.script?.argObject, true)
        let argObj = try XCTUnwrap(rule.script?.argument)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(argObj.utf8)) as? [String: Any])
        XCTAssertEqual(obj["flag"] as? Bool, true)
        XCTAssertEqual(obj["limit"] as? Int, 5)
    }

    /// A condition that cannot hold for this install (flag defaults to
    /// true, the line wants false) disables the script at import: the line
    /// is consumed and no rule is produced.
    func testExpressionIfLineDisabledByCondition() {
        let rs = ruleset()
        XCTAssertFalse(rs.rules.contains { $0.script?.path == "https://example.com/off.js" })
    }

    /// The cron and bare (network-changed / generic) expression forms.
    func testExpressionCronAndBareLines() {
        let rs = ruleset()
        let cron = rs.tasks.first { $0.kind == "cron" }
        XCTAssertEqual(cron?.cron, "30 8 * * *")
        XCTAssertEqual(cron?.name, "daily")
        XCTAssertEqual(cron?.path, "https://example.com/cron.js")
        let event = rs.tasks.first { $0.kind == "event" }
        XCTAssertEqual(event?.event, "network-changed")
        XCTAssertEqual(event?.path, "https://example.com/net.js")
        let generic = rs.tasks.first { $0.kind == "generic" }
        XCTAssertEqual(generic?.path, "https://example.com/generic.js")
    }

    /// `||` conditions are outside the import-time evaluator: unparseable,
    /// so the line is retained verbatim upstream instead of half-imported.
    func testOrConditionIsUnparseable() {
        let rs = NCEngineRuleset()
        rs.loonArgContext = ["flag": (value: "true", valueType: "boolean", type: nil)]
        switch rs.evalLoonIfExpression("${url} ~= /x/ || ${flag}") {
        case .unparseable: break
        default: XCTFail("expected .unparseable")
        }
    }
}

final class NativeCoreEgernScriptingTests: XCTestCase {
    private let egernText = """
    name: EgernCov
    scriptings:
      - name: req
        url: https://example.com/req.js
        http_request:
          patterns:
            - ^https://api.example.com/
          requires_body: true
      - name: sched
        url: https://example.com/sched.js
        schedule: "15 9 * * *"
      - name: net
        url: https://example.com/net.js
        network_changed: true
      - name: dnsscript
        url: https://example.com/dns.js
        dns: true
      - name: rulescript
        url: https://example.com/rule.js
        rule: true
      - name: weird
        url: https://example.com/weird.js
        http_request: ^https://w.example.com/
        mystery_field: abc
    """

    private func ruleset() -> NCEngineRuleset {
        let rs = NCEngineRuleset()
        rs.parseText(egernText, source: "模块", args: [:])
        return rs
    }

    func testHTTPRequestScripting() {
        let rs = ruleset()
        XCTAssertEqual(rs.format, "egern")
        let rule = rs.rules.first { $0.script?.name == "req" }
        XCTAssertEqual(rule?.kind, "script")
        XCTAssertEqual(rule?.phase, "request")
        XCTAssertEqual(rule?.pattern, "^https://api.example.com/")
        XCTAssertEqual(rule?.script?.path, "https://example.com/req.js")
        XCTAssertEqual(rule?.script?.requiresBody, true)
    }

    func testScheduleAndNetworkChangedScriptings() {
        let rs = ruleset()
        let cron = rs.tasks.first { $0.name == "sched" }
        XCTAssertEqual(cron?.kind, "cron")
        XCTAssertEqual(cron?.cron, "15 9 * * *")
        let event = rs.tasks.first { $0.name == "net" }
        XCTAssertEqual(event?.kind, "event")
        XCTAssertEqual(event?.event, "network-changed")
    }

    /// dns / rule scriptings become script rules in the dns / rule phases —
    /// the NCScriptHooks contract's registration half (kernel execution is
    /// a separate lane; registration is what #120 added).
    func testDNSAndRuleScriptings() {
        let rs = ruleset()
        XCTAssertEqual(rs.rules.first { $0.script?.name == "dnsscript" }?.phase, "dns")
        XCTAssertEqual(rs.rules.first { $0.script?.name == "rulescript" }?.phase, "rule")
    }

    /// Fields with no equivalent are surfaced in unsupported with their
    /// value, never silently dropped; the mappable parts still import.
    func testUnknownFieldSurfacedNotDropped() {
        let rs = ruleset()
        XCTAssertTrue(rs.rules.contains { $0.script?.name == "weird" && $0.pattern == "^https://w.example.com/" })
        XCTAssertTrue(rs.unsupported.contains { $0.contains("mystery_field") && $0.contains("abc") },
                      rs.unsupported.joined(separator: " | "))
    }
}
