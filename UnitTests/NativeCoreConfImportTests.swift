import XCTest
@testable import Mihomo

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
}
