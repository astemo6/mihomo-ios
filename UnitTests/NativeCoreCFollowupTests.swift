import XCTest
@testable import Mihomo

/// fix/nc-c-followup: fixture tests for the behaviour changes PR #139
/// (fix/nc-callsite-audit) landed without parity tests — NCSubscription D1
/// (node order), EngineParser P5 (Loon argument substitution) and P1 (Stash
/// no longer routed through isEgern) — plus the two bugs the follow-up
/// found while pinning them (Surge lines in node subscriptions swallowed by
/// the QX builder; isEgern trimming leading indentation).

// MARK: - NCSubscription D1: node order + selection persistence

final class NativeCoreSubscriptionOrderTests: XCTestCase {

    /// A mixed "airport" body as panels serve it in plain text: share URIs,
    /// a QX server_local line, a socks5 URI (a bridge self-parsed scheme)
    /// and a Surge [Proxy] line.
    private let mixedBody = """
    ss://YWVzLTEyOC1nY206cHc@1.1.1.1:8388#%E9%A6%99%E6%B8%AF%2001
    shadowsocks=2.2.2.2:443, method=aes-128-gcm, password=pw, tag=🇯🇵 JP QX
    trojan://pw@3.3.3.3:443?sni=t.example.com#US%2001
    socks5://user:pass@4.4.4.4:1080#Socks%20Node
    🇹🇼 TW Surge = ss, 5.5.5.5, 8388, encrypt-method=aes-128-gcm, password=pw
    """

    /// the retired bridge parseNodeText order: self-parsed lines (QX / Surge
    /// named lines, wireguard / snell / ssh / socks / http schemes) first in
    /// line order, then the converted :// URIs in line order.
    func testMixedBodyOrderSelfParsedFirst() {
        let nodes = NCSubscriptionParser.parse(mixedBody)
        XCTAssertEqual(nodes.map { $0.name }, ["🇯🇵 JP QX", "Socks Node", "🇹🇼 TW Surge", "香港 01", "US 01"])
        XCTAssertEqual(nodes.map { $0.type }, ["ss", "socks5", "ss", "ss", "trojan"])
        XCTAssertEqual(nodes[0].server, "2.2.2.2")
        XCTAssertEqual(nodes[1].server, "4.4.4.4")
        XCTAssertEqual(nodes[3].server, "1.1.1.1")
        XCTAssertEqual(nodes[4].server, "3.3.3.3")
    }

    /// Regression (found by this follow-up, pre-dates #139): a Surge
    /// "Name = ss, host, port, …" line used to be handed to the QX builder
    /// first, which accepts any key — the node came out typed "🇹🇼 tw surge"
    /// with server "ss". the old core dispatches on the qxTypes keyword set.
    func testSurgeLineIsNotParsedAsQX() {
        let nodes = NCSubscriptionParser.parse(mixedBody)
        let tw = nodes.first { $0.name == "🇹🇼 TW Surge" }
        XCTAssertEqual(tw?.type, "ss")
        XCTAssertEqual(tw?.server, "5.5.5.5")
        XCTAssertEqual(tw?.port, 8388)
        XCTAssertEqual(tw?.cipher, "aes-128-gcm")
        XCTAssertEqual(tw?.password, "pw")
        // A QX keyword line still goes to the QX builder.
        let qx = nodes.first { $0.name == "🇯🇵 JP QX" }
        XCTAssertEqual(qx?.cipher, "aes-128-gcm")
        XCTAssertEqual(qx?.port, 443)
    }

    /// Name collisions are numbered AFTER reordering (the old core uniqueNames runs on
    /// the reordered list): a QX line and a URI with the same name — the QX
    /// node keeps the bare name even though the URI came first in the file.
    /// Pinned because this is the one way D1 can move an existing
    /// selection: a saved "HK 2" now names the other server.
    func testDedupNumberingFollowsNewOrder() {
        let body = """
        trojan://pw@9.9.9.9:443#HK
        trojan=8.8.8.8:443, password=pw, tag=HK
        """
        let nodes = NCSubscriptionParser.parse(body)
        XCTAssertEqual(nodes.map { $0.name }, ["HK", "HK 2"])
        XCTAssertEqual(nodes[0].server, "8.8.8.8")
        XCTAssertEqual(nodes[1].server, "9.9.9.9")
    }

    /// Selected-node persistence is keyed by node NAME (NCGroupEngine
    /// selections = [group: member name], written as JSON next to the
    /// profile by NativeCoreEngine.setSelection), not by index: the D1
    /// reorder moves "US 01" from line position 2 to member index 4, and a
    /// restored selection still resolves to the same server.
    func testSelectionPersistedByNameSurvivesReorder() throws {
        let nodes = NCSubscriptionParser.parse(mixedBody)
        var cfg = NCConfig.decode(root: [:])
        cfg.proxies = nodes
        cfg.groups = [NCProxyGroup(name: "节点选择", type: "select", proxies: nodes.map { $0.name }, fields: [:])]

        let before = NCGroupEngine(config: cfg)
        let saved = before.setSelection(group: "节点选择", member: "US 01")
        let data = try JSONEncoder().encode(saved)
        let restored = try JSONDecoder().decode([String: String].self, from: data)
        XCTAssertEqual(restored, ["节点选择": "US 01"])

        // The pre-#139 line order had "US 01" at index 2; that index now
        // holds a different node, so an index-keyed store would have moved
        // the user. The name-keyed one does not.
        XCTAssertNotEqual(nodes[2].name, "US 01")
        let after = NCGroupEngine(config: cfg)
        after.selections = restored
        guard case .proxy(let p) = after.resolve("节点选择") else {
            return XCTFail("expected a proxy resolution")
        }
        XCTAssertEqual(p.name, "US 01")
        XCTAssertEqual(p.server, "3.3.3.3")
        XCTAssertEqual(after.currentMember(of: try XCTUnwrap(cfg.groupMap["节点选择"])), "US 01")
    }
}

// MARK: - EngineParser P5: Loon [Argument] substitution

final class NativeCoreLoonArgumentFixtureTests: XCTestCase {

    /// Loon0x00/LoonExampleConfig Plugin/Plugin_Arg.plugin (official
    /// [Argument] demo, Loon 3.2.1 build 733+), verbatim.
    private let officialPlugin = """
    #!name = 带参数的插件Demo
    #!desc = 这是一个可设定参数的插件，适用于Loon 3.2.1(build 733 +)
    #!author = Loon0x00[https://github.com/Loon0x00/LoonExampleConfig]
    #!homePage = https://nsloon.com
    #!data = 2024-08-09
    #!icon = https://raw.githubusercontent.com/Loon0x00/Loon0x00.github.io/main/static/img/loon.png
    #!system = ios,tvos,macos
    #!system_version = 300
    #!loon_version = 3.2.1(734)
    #!tag = 官方,Demo

    [Argument]
    appName = input,"Loon",tag=app的名字,desc=填写app的用户名，用于提交app的相关信息
    appCategory = select,"Tool","Video&Photo","Game",tag=app的分类
    isSupportChinese = switch,true,tag=是否支持中文,desc=选择app是否支持中文
    cron = input,"*/5 * * * *",tag=定时任务时间,desc=定时任务的cron表达式
    cookieScriptEnable = switch,true,tag=是否启用获取cookie的脚本

    [Script]
    http-request ^https://nsloon\\.app script-path = https://raw.githubusercontent.com/Loon0x00/LoonExampleConfig/master/Script/plugin_arg.js,argument=[{appName},{appCategory},{isSupportChinese}],enable = {cookieScriptEnable},tag=plugin_arg_demo_request

    cron {cron} script-path=https://raw.githubusercontent.com/Loon0x00/LoonExampleConfig/master/Script/cron.js,tag = cronExample,argument=[{appName}],enable=true

    [MITM]
    hostname = nsloon.app
    """

    /// nsloon.app/docs/Plugin (3.5.1+): expression lines reference the
    /// same arguments as ${key}; legacy lines keep {key} / argument=[{…}].
    private let expressionPlugin = """
    #!name = Expr Demo
    [Argument]
    enabled = switch,true,tag=启用
    price = input,9.99,type=number,tag=价格

    [Rewrite]
    response if ${url} ~= /^https:\\/\\/example\\.com\\/api/ && ${enabled} == true then response.json.replace(["data.price"], [${price}])

    [Script]
    http-request ^https:\\/\\/example\\.com script-path=request.js,argument=[{enabled},{price}],tag=legacy
    http-request ^https:\\/\\/legacy\\.example\\.com script-path=legacy.js,argument="p=${price}",tag=dollar
    """

    private func envelope(_ line: String) throws -> [String: Any] {
        let r = try XCTUnwrap(line.range(of: "argument=__tern_loon_obj__:"), "no object envelope in \(line)")
        var b64 = String(line[r.upperBound...].prefix { $0 != "," && $0 != " " })
        b64 = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        let d = try XCTUnwrap(Data(base64Encoded: b64))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: d) as? [String: Any])
    }

    private func line(_ text: String, prefix: String) throws -> String {
        try XCTUnwrap(text.split(separator: "\n").map(String.init).first { $0.hasPrefix(prefix) },
                      "no line starting with \(prefix)")
    }

    /// The cron task line. applyLoonArgs only rewrites lines in place and
    /// keeps the [Argument] section, whose `cron = input,"*/5 * * * *",…`
    /// declaration also starts with "cron" and precedes [Script]; match
    /// the script line itself (it carries script-path=).
    private func cronTaskLine(_ text: String) throws -> String {
        try XCTUnwrap(text.split(separator: "\n").map(String.init).first {
            $0.hasPrefix("cron") && $0.contains("script-path=")
        }, "no cron task line")
    }

    func testOfficialPluginArgumentsDeclared() {
        let args = NCEngineRuleset.parseLoonArguments(officialPlugin)
        XCTAssertEqual(args.map { $0.key }, ["appName", "appCategory", "isSupportChinese", "cron", "cookieScriptEnable"])
        XCTAssertEqual(args.first { $0.key == "appName" }?.def, "Loon")
        XCTAssertEqual(args.first { $0.key == "appCategory" }?.def, "Tool")
        XCTAssertEqual(args.first { $0.key == "appCategory" }?.options, ["Tool", "Video&Photo", "Game"])
        XCTAssertEqual(args.first { $0.key == "isSupportChinese" }?.def, "true")
        XCTAssertEqual(args.first { $0.key == "cron" }?.def, "*/5 * * * *")
    }

    /// Defaults: argument=[{…}] becomes the typed object envelope ($argument
    /// is an Object in the script: switch → Boolean, the rest String),
    /// {cron} is substituted textually, enable = {switch} resolves to true
    /// and the option is stripped.
    func testOfficialPluginDefaults() throws {
        let args = NCEngineRuleset.parseLoonArguments(officialPlugin)
        let out = NCEngineRuleset.applyLoonArgs(officialPlugin, args: args, user: [:])

        let req = try line(out, prefix: "http-request")
        XCTAssertFalse(req.contains("{"), req)
        XCTAssertFalse(req.lowercased().contains("enable"), req)
        XCTAssertTrue(req.hasSuffix(",tag=plugin_arg_demo_request"), req)
        let obj = try envelope(req)
        XCTAssertEqual(obj["appName"] as? String, "Loon")
        XCTAssertEqual(obj["appCategory"] as? String, "Tool")
        XCTAssertEqual(obj["isSupportChinese"] as? Bool, true)

        let cron = try cronTaskLine(out)
        XCTAssertTrue(cron.hasPrefix("cron */5 * * * * script-path="), cron)
        XCTAssertFalse(cron.lowercased().contains("enable"), cron)
        XCTAssertEqual(try envelope(cron)["appName"] as? String, "Loon")
    }

    /// User values win; a switch bound to enable= that is off drops the
    /// whole line (Loon: "switch 参数可以控制脚本是否启用").
    func testOfficialPluginUserValues() throws {
        let args = NCEngineRuleset.parseLoonArguments(officialPlugin)
        let user = ["appName": "Tern", "isSupportChinese": "false", "cron": "0 9 * * *", "cookieScriptEnable": "false"]
        let out = NCEngineRuleset.applyLoonArgs(officialPlugin, args: args, user: user)
        XCTAssertFalse(out.contains("plugin_arg_demo_request"), "enable=false line must be dropped")
        let cron = try cronTaskLine(out)
        XCTAssertTrue(cron.hasPrefix("cron 0 9 * * * script-path="), cron)
        XCTAssertEqual(try envelope(cron)["appName"] as? String, "Tern")
    }

    /// End to end through parseText: the legacy http-request script gets an
    /// object argument, the cron task takes the substituted expression.
    func testOfficialPluginParseText() throws {
        let rs = NCEngineRuleset()
        rs.parseText(officialPlugin, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "loon")
        XCTAssertEqual(rs.name, "带参数的插件Demo")
        XCTAssertTrue(rs.hostnames.contains("nsloon.app"))
        let rule = try XCTUnwrap(rs.rules.first { $0.script?.path.hasSuffix("/plugin_arg.js") == true })
        XCTAssertEqual(rule.script?.argObject, true)
        let argObj = try XCTUnwrap(rule.script?.argument)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(argObj.utf8)) as? [String: Any])
        XCTAssertEqual(obj["isSupportChinese"] as? Bool, true)
        let task = try XCTUnwrap(rs.tasks.first { $0.path.hasSuffix("/cron.js") })
        XCTAssertEqual(task.kind, "cron")
        XCTAssertEqual(task.cron, "*/5 * * * *")
        XCTAssertEqual(task.script?.argObject, true)
    }

    /// P5: ${key} is the expression syntax's own binding — expression lines
    /// pass through applyLoonArgs byte-for-byte (parseLoonExpressionLine
    /// types them later), and there is no ${key} → value pass. On a legacy
    /// line, where Loon defines only {key}, the {key} pass leaves the "$"
    /// in front (the retired bridge applyLoonArgs does the same; pinned as the old core
    /// parity — no real Loon plugin writes ${key} on a legacy line).
    func testExpressionLinesUntouchedAndNoDollarPass() throws {
        let args = NCEngineRuleset.parseLoonArguments(expressionPlugin)
        let out = NCEngineRuleset.applyLoonArgs(expressionPlugin, args: args, user: [:])

        let expr = try line(out, prefix: "response if")
        XCTAssertEqual(expr, #"response if ${url} ~= /^https:\/\/example\.com\/api/ && ${enabled} == true then response.json.replace(["data.price"], [${price}])"#)

        let legacy = try XCTUnwrap(out.split(separator: "\n").map(String.init).first { $0.hasSuffix("tag=legacy") })
        let obj = try envelope(legacy)
        XCTAssertEqual(obj["enabled"] as? Bool, true)
        XCTAssertEqual(obj["price"] as? Double, 9.99) // type=number stays a Number

        let dollar = try XCTUnwrap(out.split(separator: "\n").map(String.init).first { $0.hasSuffix("tag=dollar") })
        XCTAssertTrue(dollar.contains(#"argument="p=$9.99""#), dollar)
    }
}

// MARK: - EngineParser P1: Egern vs Stash classification

final class NativeCoreEgernStashDetectionTests: XCTestCase {

    /// Stash override (stash.wiki/en/configuration/override): http.mitm +
    /// http.url-rewrite + rules.
    private let stashOverride = """
    name: "AdBlock Override"
    desc: "Stash override fixture"
    http:
      mitm:
        - "api.example.com"
      url-rewrite:
        - '^https?:\\/\\/api\\.example\\.com\\/ad - reject'
    rules:
      - DOMAIN-SUFFIX,doubleclick.net,REJECT
      - DOMAIN,ad.example.com,REJECT
    """

    /// A rules-only Stash override: `rules:` + `- DOMAIN,…` items. Before
    /// P1 this shape matched isEgern's extra Stash branch and was parsed
    /// as an Egern module (the old core IsEgern has no such branch).
    private let stashRulesOnly = """
    name: Block Ads
    rules:
      - DOMAIN-SUFFIX,doubleclick.net,REJECT
      - DOMAIN,ad.example.com,REJECT
    """

    /// Egern module (egernapp docs): scriptings + mitm hostnames map.
    private let egernModule = """
    name: Egern Demo
    description: Egern module fixture
    scriptings:
      - http_request:
          name: demo-req
          match: ^https://api\\.example\\.com/v1/
          script_url: https://example.com/req.js
    mitm:
      hostnames:
        includes:
          - api.example.com
    """

    /// MITM-only Egern module: no top-level Egern key other than mitm, so
    /// detection rests on the indented "  hostnames:" marker (the old core IsEgern
    /// keeps leading indentation; Swift used to trim it and miss this).
    private let egernMitmOnly = """
    name: MITM only
    mitm:
      hostnames:
        includes:
          - "*.example.com"
        excludes:
          - skip.example.com
    """

    /// Egern rules module: `rules:` + lowercase single-key items.
    private let egernRules = """
    rules:
      - domain_suffix:
          match: ads.example.com
          policy: REJECT
    """

    func testStashOverrideIsNotEgern() {
        XCTAssertFalse(NCEngineRuleset.isEgern(stashOverride))
        XCTAssertTrue(NCEngineRuleset.isStash(stashOverride))
        let rs = NCEngineRuleset()
        rs.parseText(stashOverride, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "stash")
        XCTAssertEqual(rs.name, "AdBlock Override")
        XCTAssertTrue(rs.hostnames.contains("api.example.com"))
        XCTAssertEqual(rs.coreRules.count, 2)
        XCTAssertTrue(rs.coreRules.first?.contains("doubleclick.net") == true, "\(rs.coreRules)")
    }

    func testStashRulesOnlyIsNotEgern() {
        XCTAssertFalse(NCEngineRuleset.isEgern(stashRulesOnly))
        XCTAssertTrue(NCEngineRuleset.isStash(stashRulesOnly))
        let rs = NCEngineRuleset()
        rs.parseText(stashRulesOnly, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "stash")
        XCTAssertEqual(rs.coreRules.count, 2)
    }

    func testEgernModuleIsEgern() {
        XCTAssertTrue(NCEngineRuleset.isEgern(egernModule))
        let rs = NCEngineRuleset()
        rs.parseText(egernModule, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "egern")
        XCTAssertEqual(rs.name, "Egern Demo")
        XCTAssertTrue(rs.hostnames.contains("api.example.com"))
    }

    func testEgernMitmOnlyModuleIsEgern() {
        XCTAssertTrue(NCEngineRuleset.isEgern(egernMitmOnly))
        let rs = NCEngineRuleset()
        rs.parseText(egernMitmOnly, source: "模块", args: [:])
        XCTAssertEqual(rs.format, "egern")
        XCTAssertTrue(rs.hostnames.contains("*.example.com"))
        XCTAssertTrue(rs.hostnames.contains("-skip.example.com"))
    }

    func testEgernRulesModuleIsEgern() {
        XCTAssertTrue(NCEngineRuleset.isEgern(egernRules))
        XCTAssertFalse(NCEngineRuleset.isStash(egernRules))
    }

    /// Indented keys are not top-level: a nested "scriptings:" under some
    /// other map does not make a document Egern (the old core TrimRight semantics).
    func testIndentedEgernKeyIsNotTopLevel() {
        let doc = """
        name: Not Egern
        notes:
          scriptings: just a string
        """
        XCTAssertFalse(NCEngineRuleset.isEgern(doc))
    }
}
