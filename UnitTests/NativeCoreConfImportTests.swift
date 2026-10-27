import XCTest
@testable import Tern

/// Fixture-driven tests for the .conf importers (Surge / Loon / QX →
/// canonical model). One representative config per ecosystem; assertions
/// cover the mapped canonical contents, not just counts.
final class NativeCoreConfImportTests: XCTestCase {

    func testSurgeImport() {
        let text = """
        #!name=Fixture
        [General]
        loglevel = notify
        dns-server = 8.8.8.8, 1.1.1.1
        encrypted-dns-server = https://dns.google/dns-query
        ipv6 = true
        skip-proxy = 192.168.0.0/16

        [Proxy]
        Direct = direct
        SS1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=secret, udp-relay=true
        VM1 = vmess, vm.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, ws=true, ws-path=/ws, ws-headers=Host:cdn.example.com, tls=true, tls-name=vm.example.com, skip-cert-verify=true

        [Proxy Group]
        Main = select, SS1, VM1, Direct
        Auto = url-test, SS1, VM1, url=http://www.gstatic.com/generate_204, interval=300, tolerance=50
        Ext = select, policy-path=https://sub.example.com/nodes, update-interval=3600

        [Rule]
        DOMAIN-SUFFIX,google.com,Main
        DOMAIN-KEYWORD,ads,REJECT
        RULE-SET,https://rules.example.com/reject.list,REJECT
        FINAL,Main

        [Host]
        router.lan = 192.168.1.1
        nas.lan = server:8.8.8.8
        *.corp = 10.0.0.1

        [MITM]
        hostname = *.example.com
        """
        let c = NCConfImport.surge(text)

        XCTAssertEqual(c.sourceFormat, "surge")
        XCTAssertTrue(c.ipv6)
        XCTAssertEqual(c.logLevel, "notify")
        XCTAssertEqual(c.dns.defaultServers.count, 3)
        XCTAssertEqual(c.dns.encryptedServers.count, 1)
        XCTAssertEqual(c.dns.encryptedServers.first?.scheme, .doh)

        XCTAssertEqual(c.nodes.count, 3)
        let ss = c.nodeMap["SS1"]
        XCTAssertEqual(ss?.type, "ss")
        XCTAssertEqual(ss?.server, "1.2.3.4")
        XCTAssertEqual(ss?.port, 8388)
        XCTAssertEqual(ss?.cipher, "aes-256-gcm")
        XCTAssertEqual(ss?.password, "secret")
        XCTAssertEqual(ss?.udp, true)

        let vm = c.nodeMap["VM1"]
        XCTAssertEqual(vm?.type, "vmess")
        XCTAssertEqual(vm?.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811")
        XCTAssertEqual(vm?.fields["network"]?.string, "ws")
        XCTAssertEqual(vm?.fields["tls"]?.bool, true)
        XCTAssertEqual(vm?.fields["sni"]?.string, "vm.example.com")
        XCTAssertEqual(vm?.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(vm?.fields["ws-opts"]?["path"]?.string, "/ws")
        XCTAssertEqual(vm?.fields["ws-opts"]?["headers"]?["Host"]?.string, "cdn.example.com")

        XCTAssertEqual(c.groupMap["Main"]?.kind, .select)
        XCTAssertEqual(c.groupMap["Main"]?.members, ["SS1", "VM1", "Direct"])
        XCTAssertEqual(c.groupMap["Auto"]?.kind, .urlTest)
        XCTAssertEqual(c.groupMap["Auto"]?.interval, 300)
        XCTAssertEqual(c.groupMap["Auto"]?.tolerance, 50)
        XCTAssertEqual(c.groupMap["Auto"]?.url, "http://www.gstatic.com/generate_204")
        XCTAssertEqual(c.groupMap["Ext"]?.kind, .external)
        XCTAssertEqual(c.groupMap["Ext"]?.use, ["Ext"])
        XCTAssertEqual(c.subscriptions.count, 1)
        XCTAssertEqual(c.subscriptions.first?.name, "Ext")
        XCTAssertEqual(c.subscriptions.first?.url, "https://sub.example.com/nodes")
        XCTAssertEqual(c.subscriptions.first?.interval, 3600)

        XCTAssertEqual(c.ruleSets.count, 1)
        XCTAssertEqual(c.ruleSets.first?.url, "https://rules.example.com/reject.list")
        XCTAssertEqual(c.ruleSets.first?.forcedPolicy, "REJECT")
        XCTAssertTrue(c.rules.contains("DOMAIN-SUFFIX,google.com,Main"))
        XCTAssertTrue(c.rules.contains("RULE-SET,https://rules.example.com/reject.list,REJECT"))
        XCTAssertEqual(c.rules.last, "MATCH,Main") // FINAL translated

        XCTAssertEqual(c.hosts.count, 3)
        XCTAssertEqual(c.hosts.first { $0.pattern == "router.lan" }?.kind, .address)
        XCTAssertEqual(c.hosts.first { $0.pattern == "nas.lan" }?.kind, .dnsServer)
        XCTAssertEqual(c.hosts.first { $0.pattern == "nas.lan" }?.dnsServer?.host, "8.8.8.8")
        // [MITM] is imported into the canonical model since 58ec3e2 (native
        // MitM/rewrite/scripts), so it is no longer a skipped section.
        XCTAssertFalse(c.report.skippedSections.contains("MITM"))
        XCTAssertTrue(c.mitm.enabled)
        XCTAssertEqual(c.mitm.hostnames, ["*.example.com"])
    }

    func testLoonImport() {
        let text = """
        [General]
        dns-server = 119.29.29.29
        doh-server = https://dns.alidns.com/dns-query

        [Proxy]
        SS-Loon = Shadowsocks, 5.6.7.8, 8388, method=chacha20-ietf-poly1305, password=pw123
        VM-Loon = VMess, vm2.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, transport=ws, path=/loon, host=cdn2.example.com, over-tls=true

        [Proxy Group]
        PROXY = select, SS-Loon, VM-Loon

        [Remote Proxy]
        SubA = https://loon.example.com/sub, update-interval=7200
        https://loon2.example.com/plain

        [Remote Rule]
        https://loon.example.com/rules.list, policy=PROXY, enabled=true

        [Rule]
        DOMAIN-SUFFIX,example.com,PROXY

        [Mitm]
        skip-server-cert-verify = true
        """
        let c = NCConfImport.loon(text)

        XCTAssertEqual(c.sourceFormat, "loon")
        XCTAssertEqual(c.dns.defaultServers.count, 2)
        XCTAssertEqual(c.dns.encryptedServers.count, 1)
        XCTAssertEqual(c.dns.encryptedServers.first?.scheme, .doh)

        let ss = c.nodeMap["SS-Loon"]
        XCTAssertEqual(ss?.type, "ss") // "Shadowsocks" normalized, method= spelling
        XCTAssertEqual(ss?.cipher, "chacha20-ietf-poly1305")
        XCTAssertEqual(ss?.password, "pw123")

        let vm = c.nodeMap["VM-Loon"]
        XCTAssertEqual(vm?.type, "vmess")
        XCTAssertEqual(vm?.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811")
        XCTAssertEqual(vm?.fields["network"]?.string, "ws") // transport=ws spelling
        XCTAssertEqual(vm?.fields["tls"]?.bool, true)        // over-tls=
        XCTAssertEqual(vm?.fields["ws-opts"]?["path"]?.string, "/loon")
        XCTAssertEqual(vm?.fields["ws-opts"]?["headers"]?["Host"]?.string, "cdn2.example.com")

        XCTAssertEqual(c.groupMap["PROXY"]?.kind, .select)
        XCTAssertEqual(c.groupMap["PROXY"]?.members, ["SS-Loon", "VM-Loon"])

        XCTAssertEqual(c.subscriptions.count, 2)
        XCTAssertEqual(c.subscriptions.first?.name, "SubA")
        XCTAssertEqual(c.subscriptions.first?.interval, 7200)
        XCTAssertEqual(c.subscriptions.last?.name, "loon2.example.com") // host-derived
        XCTAssertEqual(c.subscriptions.last?.url, "https://loon2.example.com/plain")

        XCTAssertEqual(c.ruleSets.count, 1)
        XCTAssertEqual(c.ruleSets.first?.forcedPolicy, "PROXY")
        // Remote-rule RULE-SET lines are appended after local [Rule] lines.
        XCTAssertEqual(c.rules, ["DOMAIN-SUFFIX,example.com,PROXY",
                                 "RULE-SET,https://loon.example.com/rules.list,PROXY"])
        XCTAssertTrue(c.mitm.skipCertVerify)
        XCTAssertFalse(c.report.skippedSections.contains("Mitm"))
    }

    func testQuantumultXImport() {
        let text = """
        [general]
        server_check_url = http://www.gstatic.com/generate_204

        [dns]
        server=223.5.5.5
        server=/google.com/8.8.8.8
        address=/router.lan/192.168.1.1
        doh-server=https://dns.google/dns-query
        no-ipv6=true

        [server_local]
        shadowsocks=ss.example.com:8388, method=aes-128-gcm, password=qxpw, obfs=http, obfs-host=cdn.example.com, fast-open=true, tag=QX-SS
        vmess=vm.example.com:443, method=aes-128-gcm, password=b831381d-6324-4d53-ad4f-8cda48b30811, obfs=ws, obfs-host=cdn.example.com, obfs-uri=/qxws, tls-verification=false, tag=QX-VM

        [server_remote]
        https://qx.example.com/sub, update-interval=43200, tag=QXSub, enabled=true

        [policy]
        static=QX-Main, QX-SS, QX-VM, direct
        url-test=QX-Auto, server-tag-regex=QX-, url=http://www.gstatic.com/generate_204, interval=600

        [filter_local]
        host, example.com, QX-Main
        host-suffix, google.com, QX-Main
        ip-cidr, 10.0.0.0/8, direct
        final, QX-Main

        [filter_remote]
        https://qx.example.com/ads.list, tag=QXAds, force-policy=reject, update-interval=86400, enabled=true

        [rewrite_local]
        ^http://example.com url reject
        """
        let c = NCQXImport.quantumultx(text)

        XCTAssertEqual(c.sourceFormat, "quantumultx")
        XCTAssertFalse(c.ipv6) // no-ipv6=true
        XCTAssertEqual(c.dns.defaultServers.count, 2)
        XCTAssertEqual(c.dns.encryptedServers.count, 1)
        XCTAssertEqual(c.dns.domainServers.count, 1)
        XCTAssertEqual(c.dns.domainServers.first?.key, "google.com")
        XCTAssertEqual(c.dns.domainServers.first?.servers.first?.host, "8.8.8.8")
        XCTAssertEqual(c.hosts.first { $0.pattern == "router.lan" }?.kind, .address)

        let ss = c.nodeMap["QX-SS"]
        XCTAssertEqual(ss?.type, "ss")
        XCTAssertEqual(ss?.server, "ss.example.com")
        XCTAssertEqual(ss?.port, 8388)
        XCTAssertEqual(ss?.cipher, "aes-128-gcm")
        XCTAssertEqual(ss?.password, "qxpw")
        XCTAssertEqual(ss?.fields["tfo"]?.bool, true)
        XCTAssertEqual(ss?.fields["plugin"]?.string, "obfs")
        XCTAssertEqual(ss?.fields["plugin-opts"]?["mode"]?.string, "http")
        XCTAssertEqual(ss?.fields["plugin-opts"]?["host"]?.string, "cdn.example.com")

        let vm = c.nodeMap["QX-VM"]
        XCTAssertEqual(vm?.type, "vmess")
        XCTAssertEqual(vm?.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811") // UUID arrives in password=
        XCTAssertEqual(vm?.cipher, "aes-128-gcm")
        XCTAssertEqual(vm?.fields["network"]?.string, "ws") // obfs=ws spelling
        XCTAssertEqual(vm?.fields["ws-opts"]?["path"]?.string, "/qxws")
        XCTAssertEqual(vm?.fields["ws-opts"]?["headers"]?["Host"]?.string, "cdn.example.com")
        XCTAssertEqual(vm?.fields["skip-cert-verify"]?.bool, true) // tls-verification=false, inverted

        XCTAssertEqual(c.subscriptions.count, 1)
        XCTAssertEqual(c.subscriptions.first?.name, "QXSub")
        XCTAssertEqual(c.subscriptions.first?.interval, 43200)

        XCTAssertEqual(c.groupMap["QX-Main"]?.kind, .select)
        XCTAssertEqual(c.groupMap["QX-Main"]?.members, ["QX-SS", "QX-VM", "direct"])
        XCTAssertEqual(c.groupMap["QX-Auto"]?.kind, .urlTest)
        XCTAssertEqual(c.groupMap["QX-Auto"]?.includeRegex, "QX-")
        XCTAssertEqual(c.groupMap["QX-Auto"]?.interval, 600)
        XCTAssertEqual(c.groupMap["QX-Auto"]?.members, [])

        XCTAssertEqual(c.rules, [
            "DOMAIN,example.com,QX-Main",
            "DOMAIN-SUFFIX,google.com,QX-Main",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "MATCH,QX-Main",
            "RULE-SET,https://qx.example.com/ads.list,REJECT",
        ])
        XCTAssertEqual(c.ruleSets.count, 1)
        XCTAssertEqual(c.ruleSets.first?.name, "QXAds")
        XCTAssertEqual(c.ruleSets.first?.forcedPolicy, "REJECT")
        // [rewrite_local] is imported into cfg.rewrites since 58ec3e2 (native
        // MitM/rewrite/scripts), so it is no longer a skipped section.
        XCTAssertFalse(c.report.skippedSections.contains("rewrite_local"))
        XCTAssertEqual(c.rewrites.count, 1)
        XCTAssertEqual(c.rewrites.first?.pattern, "^http://example.com")
        XCTAssertEqual(c.rewrites.first?.action, "reject")
    }

    // MARK: - QX filter_remote without force-policy (fix/nc-qx-remote-own)

    private static let ownURL = "https://rules.example.com/own.list"
    private static let forcedURL = "https://rules.example.com/forced.list"
    private static let ownList = """
    host-suffix, a.example, Streaming
    host, b.example, direct
    DOMAIN-SUFFIX,c.example,Missing
    host-keyword, dkw, proxy
    ip-cidr, 203.0.113.0/24, reject
    host-suffix, e.example, Streaming
    """
    private static var ownPath: String { "./ruleset/" + NCRuleValidator.providerNameFor(url: ownURL, kind: "list-own") + ".txt" }

    private func tempHome() throws -> String {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("qxown-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: home) }
        return home.path
    }

    private func baseRaw() -> [String: NCJSONValue] {
        [
            "proxies": .array([.object(["name": .string("N1"), "type": .string("direct")])]),
            "proxy-groups": .array([
                .object(["name": .string("Main"), "type": .string("select"), "proxies": .array([.string("N1"), .string("DIRECT")])]),
                .object(["name": .string("Streaming"), "type": .string("select"), "proxies": .array([.string("N1")])]),
            ]),
            "rules": .array([.string("MATCH,Main")]),
        ]
    }

    private func strings(_ v: [NCJSONValue]) -> [String] { v.compactMap { if case .string(let s) = $0 { return s }; return nil } }

    /// Canonical importer (tunnel runtime.conf fallback / share-link conversion): no force-policy → the list keeps
    /// its own per-line policies (provider x-own-policy, same shape as the App import); force-policy → all forced.
    func testQXFilterRemoteOwnPolicyCanonical() {
        let text = """
        [policy]
        static=Main, direct
        static=Streaming, direct

        [filter_remote]
        \(Self.ownURL), tag=Own, update-interval=3600, enabled=true
        \(Self.forcedURL), tag=Forced, force-policy=reject, enabled=true
        """
        let c = NCQXImport.quantumultx(text)
        XCTAssertEqual(c.rules, ["RULE-SET,Own,Main", "RULE-SET,\(Self.forcedURL),REJECT"])
        let own = c.ruleSets.first { $0.name == "Own" }
        XCTAssertNil(own?.forcedPolicy)
        XCTAssertEqual(own?.url, Self.ownURL)
        XCTAssertEqual(own?.interval, 3600)
        XCTAssertEqual(own?.fields["x-own-policy"]?.bool, true)
        XCTAssertEqual(own?.fields["x-convert"]?.string, "list")
        XCTAssertEqual(own?.fields["type"]?.string, "http")
        XCTAssertEqual(own?.path, Self.ownPath)
        let forced = c.ruleSets.first { $0.name == "Forced" }
        XCTAssertEqual(forced?.forcedPolicy, "REJECT")
        XCTAssertNil(forced?.fields["x-own-policy"])
        // The tunnel resolves the RULE-SET by provider name and still loads the list (own path, URL).
        let legacy = c.legacyConfig()
        let provs = NCRuleProviderStore.providers(from: legacy)
        XCTAssertEqual(provs.first { $0.name == "Own" }?.url, Self.ownURL)
        XCTAssertEqual(provs.first { $0.name == "Own" }?.filePath, Self.ownPath)
    }

    /// App import (导入配置): the same list-own provider; force-policy keeps a plain list.
    func testQXFilterRemoteOwnPolicyAppImport() throws {
        let text = """
        [server_local]
        shadowsocks=192.0.2.1:8388, method=aes-128-gcm, password=pw, tag=N1

        [policy]
        static=Main, N1, direct

        [filter_local]
        final, Main

        [filter_remote]
        \(Self.ownURL), tag=Own, enabled=true
        \(Self.forcedURL), tag=Forced, force-policy=direct, enabled=true
        """
        let res = NCConfImportPort.importConfResult(text)
        XCTAssertTrue(res.error?.isEmpty ?? true, res.error ?? "")
        guard case .object(let m)? = NCYAML.parse(res.yaml) else { return XCTFail("profile YAML does not parse:\n" + res.yaml) }
        guard case .object(let rp)? = m["rule-providers"] else { return XCTFail("no rule-providers:\n" + res.yaml) }
        guard case .object(let own)? = rp["Own"], case .object(let forced)? = rp["Forced"] else { return XCTFail(res.yaml) }
        XCTAssertEqual(own["x-own-policy"]?.bool, true, res.yaml)
        XCTAssertEqual(own["x-convert"]?.string, "list")
        XCTAssertEqual(own["path"]?.string, Self.ownPath)
        XCTAssertNil(forced["x-own-policy"])
        guard case .array(let rules)? = m["rules"] else { return XCTFail(res.yaml) }
        let rs = strings(rules)
        XCTAssertTrue(rs.contains("RULE-SET,Own,Main"), "\(rs)")
        XCTAssertTrue(rs.contains("RULE-SET,Forced,DIRECT"), "\(rs)")
    }

    /// Rule editor → runtime, end to end: the custom QX list without force-policy gets the own-policy provider; the
    /// download splits it per policy; the next build routes each part to its own policy, creates a manual-select
    /// group for the policy the config lacks, and keeps the whole-list RULE-SET (proxy) behind the parts. The list
    /// with force-policy stays one RULE-SET on the forced policy.
    func testQXRemoteOwnPolicyCustomRuleRuntimeEndToEnd() throws {
        let home = try tempHome()
        let rulesJSON = """
        {"rules":[{"id":"1","line":"\(Self.ownURL), tag=Own","enabled":true},
                  {"id":"2","line":"\(Self.forcedURL), tag=Forced, force-policy=direct","enabled":true}]}
        """
        try Data(rulesJSON.utf8).write(to: URL(fileURLWithPath: home + "/rules.json"))
        let o = NCRuntimeSettings(core: CoreOverrides(), dns: nil, local: nil, home: home, manualPath: "")

        // The runtime names the provider after the URL (own.list → own), as it always did for custom lists.
        // Before the download: whole list on proxy (the first select group).
        var raw = baseRaw()
        NCRuntimeSteps.applyCustomRules(&raw, o)
        XCTAssertEqual(strings(raw.list("rules")), ["RULE-SET,own,Main", "RULE-SET,forced,DIRECT", "MATCH,Main"])
        guard case .object(let own)? = raw.map("rule-providers")["own"],
              case .object(let forced)? = raw.map("rule-providers")["forced"] else { return XCTFail("\(raw)") }
        XCTAssertEqual(own["x-own-policy"], .bool(true))
        XCTAssertEqual(own["x-convert"]?.string, "list") // providerPlan → convert "list-split"
        XCTAssertEqual(own["path"]?.string, Self.ownPath)
        XCTAssertNil(forced["x-own-policy"])
        XCTAssertNil(forced["x-convert"])

        // The download (ProviderStore, convert list-split) writes the converted list, the parts and the sidecar.
        let cache = (home as NSString).appendingPathComponent(String(Self.ownPath.dropFirst(2)))
        let stored = NCProviderPorts.providerStore(home: home, kind: "rule", cachePath: cache, convert: "list-split",
                                                   data: Data(Self.ownList.utf8))
        XCTAssertTrue(stored.contains("\"error\":\"\""), stored)
        XCTAssertTrue(FileManager.default.fileExists(atPath: cache + ".policies.json"))

        // The next build: per-line policies.
        var raw2 = baseRaw()
        NCRuntimeSteps.applyCustomRules(&raw2, o)
        XCTAssertEqual(strings(raw2.list("rules")), [
            "RULE-SET,own#Streaming,Streaming",
            "RULE-SET,own#direct,DIRECT",
            "RULE-SET,own#Missing,Missing",
            "RULE-SET,own#proxy,Main",
            "RULE-SET,own#reject,REJECT",
            "RULE-SET,own,Main",
            "RULE-SET,forced,DIRECT",
            "MATCH,Main",
        ])
        let groups = raw2.list("proxy-groups").compactMap { v -> [String: NCJSONValue]? in
            if case .object(let m) = v { return m }; return nil
        }
        XCTAssertEqual(groups.map { $0.str("name") }, ["Main", "Streaming", "Missing"]) // existing group not duplicated
        XCTAssertEqual(groups.last?.str("type"), "select")
        XCTAssertEqual(groups.last?["proxies"], .array([.string("Main"), .string("DIRECT")]))
        guard case .object(let part)? = raw2.map("rule-providers")["own#Streaming"] else { return XCTFail("no part provider") }
        XCTAssertEqual(part["type"]?.string, "file")
        let partText = try String(contentsOfFile: part["path"]?.string ?? "", encoding: .utf8)
        let partLines = partText.split(separator: "\n").map(String.init)
        XCTAssertEqual(partLines.count, 2, partText)
        XCTAssertTrue(partLines[0].contains("a.example") && partLines[1].contains("e.example"), partText)
    }

    /// 资源 page: the custom line maps to the same list-own cache file, and a manual refresh writes the parts too.
    func testQXRemoteOwnPolicyResourceStore() throws {
        let home = try tempHome()
        let ownLine = "\(Self.ownURL), tag=Own"
        XCTAssertEqual(NCResourcesPort.remoteOfLine(ownLine)?.kind, "list-own")
        XCTAssertEqual(NCResourcesPort.remoteOfLine("\(Self.forcedURL), force-policy=direct")?.kind, "list")
        let key = "ruleset:list-own|" + Self.ownURL
        let cache = (home as NSString).appendingPathComponent(String(Self.ownPath.dropFirst(2)))
        XCTAssertEqual(NCResourcesPort.cachePath(home: home, key: key), cache)
        _ = try NCResourcesPort.store(home: home, key: key, data: Data(Self.ownList.utf8))
        XCTAssertTrue(FileManager.default.fileExists(atPath: cache))
        XCTAssertTrue(FileManager.default.fileExists(atPath: cache + ".policies.json"))
    }

    /// Rule editor check: the new note without force-policy, none with it.
    func testQXRemoteOwnPolicyEditorNote() throws {
        let home = try tempHome()
        let profile = home + "/p.yaml"
        try Data("""
        proxies:
          - {name: N1, type: direct}
        proxy-groups:
          - {name: Main, type: select, proxies: [N1, DIRECT]}
        rules:
          - MATCH,Main
        """.utf8).write(to: URL(fileURLWithPath: profile))
        let ck = NCRuleValidator.checkRuleLine(homeDir: home, profilePath: profile, line: "\(Self.ownURL), tag=Own")
        XCTAssertNil(ck.error)
        XCTAssertEqual(ck.note, NCRuleValidator.qxRemoteOwnNote)
        XCTAssertEqual(ck.note, "未指定 force-policy：按列表内每行自己的策略分流；配置中不存在的策略自动创建为手动选择组")
        XCTAssertEqual(ck.rule, "RULE-SET,Own,Main")
        let ck2 = NCRuleValidator.checkRuleLine(homeDir: home, profilePath: profile,
                                                line: "\(Self.forcedURL), tag=F, force-policy=direct")
        XCTAssertNil(ck2.error)
        XCTAssertNotEqual(ck2.note, NCRuleValidator.qxRemoteOwnNote)
        XCTAssertEqual(ck2.rule, "RULE-SET,F,DIRECT")
        XCTAssertEqual(NCRuleValidator.qxRemoteKind("\(Self.ownURL), force-policy=\"\""), "list-own")
        XCTAssertEqual(NCRuleValidator.qxRemoteKind("\(Self.ownURL), Force-Policy = Main"), "list")
    }
}
