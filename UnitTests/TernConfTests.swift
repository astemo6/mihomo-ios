import XCTest
@testable import Tern

// feat/nc-conf-native: Tern's own .conf — canonical serializer / parser round trip (golden fixtures from Quantumult X,
// Surge, Loon and Clash sources), the value grammar, hand-written Quantumult X lines, the shared rewrite / MitM part,
// and the per-profile .conf storage (migration, sync after another writer, save).
final class TernConfTests: XCTestCase {

    struct Case: Decodable {
        var name: String
        var format: String
        var source: String
        /// Whole lines (trimmed) the canonical .conf must contain.
        var expect: [String]
        /// Substrings the canonical .conf must contain.
        var contains: [String]
    }
    struct Fixtures: Decodable { var cases: [Case] }

    private func fixtures() throws -> [Case] {
        let bundle = Bundle(for: TernConfTests.self)
        guard let url = bundle.url(forResource: "TernConfFixtures", withExtension: "json") else {
            XCTFail("TernConfFixtures.json missing from the test bundle")
            return []
        }
        return try JSONDecoder().decode(Fixtures.self, from: Data(contentsOf: url)).cases
    }

    /// Internal profile for a fixture: Clash YAML as is, the other formats through the app's importer.
    private func internalProfile(_ c: Case) throws -> [String: NCJSONValue] {
        let yaml: String
        if c.format == "clash" {
            yaml = c.source
        } else {
            let r = NCConfImportPort.importConfResult(c.source)
            XCTAssertNil(r.error, "\(c.name): import error \(r.error ?? "")")
            yaml = r.yaml
        }
        guard case .object(let m)? = NCYAML.parse(yaml) else {
            XCTFail("\(c.name): YAML did not parse")
            return [:]
        }
        return m
    }

    private func attach(_ name: String, _ text: String) {
        let a = XCTAttachment(string: text)
        a.name = name
        a.lifetime = .keepAlways
        add(a)
        print("----- \(name) -----\n\(text)\n----- end \(name) -----")
    }

    // MARK: Golden fixtures

    func testGoldenSourcesRoundTrip() throws {
        let cases = try fixtures()
        XCTAssertEqual(Set(cases.map(\.format)), ["clash", "qx", "surge", "loon"])
        for c in cases {
            let profile = try internalProfile(c)
            XCTAssertFalse(profile.isEmpty, c.name)
            let conf = TernConf.serializeProfile(profile)
            attach("conf-\(c.name)", conf)
            let lines = Set(conf.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) })
            for l in c.expect { XCTAssertTrue(lines.contains(l), "\(c.name): missing line «\(l)»") }
            for s in c.contains { XCTAssertTrue(conf.contains(s), "\(c.name): missing «\(s)»") }
            XCTAssertFalse(conf.contains("tern-node=-"), "\(c.name): a node fell back to the JSON form")
            XCTAssertFalse(conf.contains("tern-group=-"), "\(c.name): a group fell back to the JSON form")
            XCTAssertFalse(conf.contains("tern-raw"), "\(c.name): a rule fell back to the raw form")
            let back = try TernConf.parse(conf)
            XCTAssertEqual(back.profile, profile, "\(c.name): round trip changed the profile")
            XCTAssertNil(back.engine, "\(c.name): a profile .conf has no shared sections")
            // Second pass is a fixed point.
            XCTAssertEqual(TernConf.serializeProfile(back.profile), conf, "\(c.name): serialize is not stable")
        }
    }

    func testYAMLCacheRoundTrip() throws {
        for c in try fixtures() {
            let profile = try internalProfile(c)
            let yaml = TernConfStore.yamlFromProfile(profile)
            guard case .object(let again)? = NCYAML.parse(yaml) else { return XCTFail("\(c.name): cache YAML did not parse") }
            XCTAssertEqual(again, profile, "\(c.name): the regenerated YAML reads back differently")
        }
    }

    // MARK: Value grammar

    func testValueGrammar() {
        let values: [NCJSONValue] = [
            .string(""), .string(" lead"), .string("trail "), .string("true"), .string("null"), .string("1"), .string("1e5"),
            .string("+1"), .string("a,b"), .string("%2C"), .string("50%"), .string("[x"), .string("{"), .string("\"q\""),
            .string("多语言 🚀"), .string("line\nbreak"), .string("tab\tx"), .string("a=b"), .string("1.2.3.4"), .string("0x10"),
            .number(0), .number(-3), .number(0.25), .number(1e20), .number(65535), .bool(true), .bool(false), .null,
            .array([]), .array([.string("a,b"), .number(1), .null]), .object([:]),
            .object(["k": .string("v,w"), "n": .object(["x": .array([.bool(true)])])]),
        ]
        for v in values {
            XCTAssertEqual(TernConf.decodeValue(TernConf.encodeValue(v)), v, "key=value form of \(v)")
            let field = TernConf.fieldValue(v)
            XCTAssertEqual(TernConf.readFieldValue(field), v, "field form of \(v)")
            // A field never splits a comma line.
            let parts = TernConf.splitFields("x, k=" + field + ", tag=t")
            XCTAssertEqual(parts.count, 3, "\(v) split into \(parts)")
        }
        XCTAssertEqual(TernConf.splitFields(#"a, tag="x,y", k=[1,2], j={"a":"b,c"}"#), ["a", #"tag="x,y""#, "k=[1,2]", #"j={"a":"b,c"}"#])
    }

    // MARK: Hard cases (lossless)

    func testHardProfileRoundTrip() throws {
        let yaml = #"""
        mode: rule
        "weird.key": 1
        sniffer:
          enable: true
          sniff:
            HTTP: {ports: [80, 8080-8880], override-destination: true}
            TLS: {}
        sub-rules:
          inner: ["DOMAIN,x.com,DIRECT", "MATCH,REJECT"]
        hosts:
          "*.lan": [10.0.0.1, 10.0.0.2]
        proxies:
          - {name: "名字,含逗号", type: ss, server: "2001:db8::1", port: 443, cipher: aes-128-gcm, password: "p=w\"d", plugin: obfs, plugin-opts: {mode: tls, host: bing.com}}
          - {name: "a=b", type: vless, server: v.example.com, port: 443, uuid: 11111111-2222-4333-8444-555555555555, flow: xtls-rprx-vision, tls: true, servername: www.apple.com, client-fingerprint: chrome, reality-opts: {public-key: abc, short-id: "0123"}, udp: true}
          - {name: "50% off", type: tuic, server: t.example.com, port: 443, uuid: u, password: p, alpn: [h3], congestion-controller: bbr}
          - {name: NoServer, type: direct}
          - {name: direct, type: socks5, server: 127.0.0.1, port: 1080}
          - {name: "[x]", type: http, server: h.example.com, port: 8080, username: u, password: "", tls: true, sni: h.example.com, skip-cert-verify: true}
        proxy-groups:
          - {name: Chain, type: relay, proxies: [direct, "a=b"]}
          - {name: "G,1", type: select, proxies: [DIRECT, REJECT, "名字,含逗号"], icon: "https://x/y.png", hidden: true}
          - {name: Smart, type: load-balance, strategy: consistent-hashing, include-all: true, filter: "(?i)港|HK", exclude-filter: "x,y"}
          - {name: Empty, type: select, proxies: []}
        rule-providers:
          inline1: {type: inline, behavior: classical, payload: ["DOMAIN,a.com", "IP-CIDR,1.1.1.1/32"]}
          file1: {type: file, behavior: ipcidr, format: text, path: ./ruleset/file1.txt}
        rules:
          - DOMAIN,direct.example.com,direct
          - GEOIP,LAN,DIRECT,no-resolve
          - GEOIP,cn,DIRECT
          - SUB-RULE,(NETWORK,UDP),inner
          - OR,((DST-PORT,443),(DOMAIN-KEYWORD,ads)),REJECT-DROP
          - DOMAIN-SUFFIX, spaced.example.com, DIRECT
          - PROCESS-NAME,Telegram,G,1
          - MATCH,DIRECT
        """#
        guard case .object(let profile)? = NCYAML.parse(yaml) else { return XCTFail("fixture YAML") }
        let conf = TernConf.serializeProfile(profile)
        attach("conf-hard", conf)
        let back = try TernConf.parse(conf)
        XCTAssertEqual(back.profile, profile)
        for key in profile.keys.sorted() { XCTAssertEqual(back.profile[key], profile[key], "key \(key)") }
        // "direct" is a node here: the built-in DIRECT member stays upper-case, the node keeps its name.
        XCTAssertTrue(conf.contains("relay=Chain, direct, a%3Db"))
        XCTAssertTrue(conf.contains("hysteria2") == false)
    }

    // MARK: Hand-written Quantumult X

    func testHandWrittenQuantumultX() throws {
        let text = """
        ; my config
        [general]
        server_check_url = http://cp.cloudflare.com/generate_204

        [policy]
        static=Proxy, HK, direct, img-url=https://example.com/p.png
        available=Backup, HK, JP

        [server_local]
        shadowsocks=1.1.1.1:443, method=aes-128-gcm, password=pw, tag=HK
        trojan=jp.example.com:443, password=pw2, over-tls=true, tls-host=jp.example.com, tag=JP

        [filter_remote]
        https://example.com/ads.list, tag=Ads, force-policy=reject, update-interval=86400, opt-parser=false, enabled=true
        https://example.com/off.list, tag=Off, force-policy=Proxy, enabled=false

        [filter_local]
        # host, disabled.example.com, direct
        host-suffix, google.com, Proxy
        ip6-cidr, 2001:db8::/32, direct
        geoip, cn, direct
        final, Proxy
        """
        let p = try TernConf.parse(text).profile
        XCTAssertEqual(p["server_check_url"], .string("http://cp.cloudflare.com/generate_204"))
        let groups = p["proxy-groups"]?.array ?? []
        XCTAssertEqual(groups.first?["type"], .string("select"))
        XCTAssertEqual(groups.first?["proxies"], .array([.string("HK"), .string("DIRECT")]))
        XCTAssertEqual(groups.first?["icon"], .string("https://example.com/p.png"))
        XCTAssertEqual(groups.last?["type"], .string("fallback"))
        let nodes = p["proxies"]?.array ?? []
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(nodes.first?["type"], .string("ss"))
        XCTAssertEqual(nodes.last?["sni"], .string("jp.example.com"))
        XCTAssertEqual(p["rules"], .array([
            .string("RULE-SET,Ads,REJECT"), .string("DOMAIN-SUFFIX,google.com,Proxy"), .string("IP-CIDR6,2001:db8::/32,DIRECT"),
            .string("GEOIP,CN,DIRECT"), .string("MATCH,Proxy"),
        ]))
        let ads = p["rule-providers"]?["Ads"]
        XCTAssertEqual(ads?["url"], .string("https://example.com/ads.list"))
        XCTAssertEqual(ads?["x-convert"], .string("list"))
        XCTAssertNil(p["rule-providers"]?["Off"], "an enabled=false filter list is left out")
    }

    func testParseErrorsCarryLines() {
        let text = "[general]\nmode = rule\n\n[server_local]\nvmess=nohost, password=x, tag=A\n"
        XCTAssertThrowsError(try TernConf.parse(text)) { e in
            XCTAssertEqual((e as? TernConf.ParseError)?.line, 5)
        }
        XCTAssertThrowsError(try TernConf.parse("[general]\nnot a key value\n")) { e in
            XCTAssertEqual((e as? TernConf.ParseError)?.line, 2)
        }
    }

    func testTemplateParses() throws {
        let p = try TernConf.parse(TernConfStore.template).profile
        XCTAssertEqual(p["mode"], .string("rule"))
        XCTAssertEqual(p["proxies"], .array([]))
        XCTAssertEqual(p["proxy-groups"]?.array?.first?["proxies"], .array([.string("DIRECT")]))
        XCTAssertEqual(p["rules"], .array([.string("MATCH,节点选择")]))
    }

    // MARK: Shared part (rewrite / scripts / MitM)

    func testEngineSectionsRoundTrip() throws {
        var c = EngineConfig()
        c.enabled = true
        c.scriptsEnabled = false
        c.mitm = true
        c.skipCertVerify = true
        c.h2 = false
        c.captureBodies = true
        c.hostnames = ["ad.example.com", "-*.apple.com", "api.example.com:8443"]
        c.quic = "all"
        c.quicAllow = ["video.example.com"]
        var r1 = EngineItem(line: #"^https?://ad\.example\.com url reject"#)
        r1.note = "广告, 去掉"
        var r2 = EngineItem(line: #"^https?://(www\.)?example\.com/track url reject-200"#)
        r2.enabled = false
        c.rules = [r1, r2]
        let s1 = EngineItem(line: #"^https://api\.example\.com/v1 url script-response-body https://s.example.com/a.js"#)
        let cron = EngineItem(line: "0 9 * * * https://s.example.com/checkin.js, tag=签到, enabled=true")
        c.scripts = [s1, cron]
        var m1 = EngineModule(name: "去广告, 模块", url: "https://example.com/a%20b.sgmodule?x=1,2")
        m1.id = "mod-1"
        m1.args = ["token": "a,b=c", "on": "true"]
        m1.policies = ["Proxy": "节点选择"]
        m1.updatedAt = 1_730_000_000.5
        m1.interval = 3600
        m1.customName = true
        var m2 = EngineModule(name: "本地", url: "")
        m2.id = "local-2"
        m2.enabled = false
        c.modules = [m1, m2]
        c.scriptResources = ["https://s.example.com/a.js": ScriptResourceSetting(disabled: true, interval: 600)]

        var e = TernConf.EngineSection(c)
        e.ca = TernConf.CAFile(passphrase: "Pass123", p12: Data([1, 2, 3, 250]))
        let text = TernConf.header + "\n[general]\nmode = rule\n" + TernConf.serializeEngine(e)
        attach("conf-engine", text)
        let back = try TernConf.parse(text)
        guard let be = back.engine else { return XCTFail("no shared part") }
        XCTAssertTrue(be.sameContent(e), "shared part changed:\n\(be)\nvs\n\(e)")
        XCTAssertEqual(be.modules, e.modules)
        XCTAssertEqual(be.ca, e.ca)
        XCTAssertEqual(back.profile, ["mode": .string("rule")])

        // Applied onto the current config: ids of unchanged lines are kept.
        let applied = be.applied(to: c)
        XCTAssertEqual(applied.rules.map(\.id), c.rules.map(\.id))
        XCTAssertEqual(applied.modules.map(\.id), ["mod-1", "local-2"])

        // Storing the profile part drops the shared sections and their banner.
        let split = TernConf.splitText(text)
        XCTAssertFalse(split.profile.contains("[mitm]"))
        XCTAssertFalse(split.profile.contains("—— "))
        XCTAssertTrue(split.shared.contains("[rewrite_local]"))
        XCTAssertNil(try TernConf.parse(split.profile).engine)
    }

    // MARK: Storage: migration, sync, save

    private func scratch() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("ternconf-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    func testMigrationSyncAndSave() throws {
        let dir = scratch()
        defer { try? FileManager.default.removeItem(at: dir) }
        let yamlPath = dir.appendingPathComponent("p1.yaml").path
        let yaml = "mode: rule\nproxies:\n  - {name: A, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: pw}\nproxy-groups:\n  - {name: G, type: select, proxies: [A, DIRECT]}\nrules:\n  - MATCH,G\n"
        try Data(yaml.utf8).write(to: URL(fileURLWithPath: yamlPath))

        // First launch with this build: .conf generated, YAML backed up once.
        let first = TernConfStore.sync(yamlPath: yamlPath)
        XCTAssertEqual(first.result, .migrated)
        XCTAssertTrue(first.text?.contains("[filter_local]") == true)
        XCTAssertTrue(first.text?.contains("final, G") == true)
        XCTAssertEqual(FileManager.default.contents(atPath: TernConfStore.backupPath(yamlPath)), Data(yaml.utf8))
        XCTAssertTrue(FileManager.default.fileExists(atPath: TernConfStore.confPath(yamlPath)))
        XCTAssertEqual(TernConfStore.sync(yamlPath: yamlPath).result, .unchanged)

        // Another writer changed the YAML (node editor, subscription update): the .conf follows it.
        let changed = yaml.replacingOccurrences(of: "  - MATCH,G\n", with: "  - DOMAIN-SUFFIX,example.org,DIRECT\n  - MATCH,G\n")
        try Data(changed.utf8).write(to: URL(fileURLWithPath: yamlPath))
        let second = TernConfStore.sync(yamlPath: yamlPath)
        XCTAssertEqual(second.result, .regenerated)
        XCTAssertTrue(second.text?.contains("host-suffix, example.org, direct") == true)

        // Saving the editor: YAML regenerated from the text, the text (with its comment) kept verbatim.
        var edited = second.text ?? ""
        edited = edited.replacingOccurrences(of: "final, G", with: "# my note\nhost, keep.example.com, G\nfinal, G")
        let full = edited + TernConf.serializeEngine(TernConf.EngineSection(EngineConfig()))
        let prep = try TernConfStore.prepare(text: full)
        XCTAssertFalse(prep.profileConf.contains("[mitm]"))
        try NCRuntimeFiles.writeAtomic(Data(prep.yaml.utf8), to: yamlPath)
        try TernConfStore.commit(yamlPath: yamlPath, yaml: prep.yaml, conf: prep.profileConf)
        let third = TernConfStore.sync(yamlPath: yamlPath)
        XCTAssertEqual(third.result, .unchanged)
        XCTAssertTrue(third.text?.contains("# my note") == true)
        guard case .object(let m)? = NCYAML.parse(String(decoding: FileManager.default.contents(atPath: yamlPath) ?? Data(), as: UTF8.self)) else {
            return XCTFail("regenerated YAML")
        }
        XCTAssertEqual(m["rules"]?.array?.compactMap { $0.string }, ["DOMAIN-SUFFIX,example.org,DIRECT", "DOMAIN,keep.example.com,G", "MATCH,G"])
        // The backup is never overwritten.
        XCTAssertEqual(FileManager.default.contents(atPath: TernConfStore.backupPath(yamlPath)), Data(yaml.utf8))
    }

    func testAdoptOriginalQuantumultX() throws {
        let dir = scratch()
        defer { try? FileManager.default.removeItem(at: dir) }
        let yamlPath = dir.appendingPathComponent("qx.yaml").path
        let original = "# 我的 QX 配置\n[policy]\nstatic=P, A, direct\n\n[server_local]\nshadowsocks=1.2.3.4:443, method=aes-128-gcm, password=pw, tag=A\n\n[filter_local]\nfinal, P\n\n[mitm]\nhostname = a.example.com\n"
        let profile = try TernConf.parse(original).profile
        let yaml = TernConfStore.yamlFromProfile(profile)
        try Data(yaml.utf8).write(to: URL(fileURLWithPath: yamlPath))
        XCTAssertTrue(TernConfStore.adoptOriginal(yamlPath: yamlPath, original: original))
        let s = TernConfStore.sync(yamlPath: yamlPath)
        XCTAssertEqual(s.result, .unchanged)
        XCTAssertTrue(s.text?.hasPrefix("# 我的 QX 配置") == true)
        XCTAssertFalse(s.text?.contains("[mitm]") == true)
    }
}
