import XCTest
@testable import Tern

final class NativeCoreCanonicalTests: XCTestCase {

    func testDNSServerParse() {
        let plain = NCDNSServerRef.parse("8.8.8.8")
        XCTAssertEqual(plain.scheme, .udp); XCTAssertEqual(plain.host, "8.8.8.8"); XCTAssertEqual(plain.port, 53)
        let ported = NCDNSServerRef.parse("1.1.1.1:5353")
        XCTAssertEqual(ported.port, 5353)
        let doh = NCDNSServerRef.parse("https://dns.google/dns-query")
        XCTAssertEqual(doh.scheme, .doh); XCTAssertEqual(doh.host, "dns.google")
        XCTAssertEqual(doh.port, 443); XCTAssertEqual(doh.path, "/dns-query")
        let dot = NCDNSServerRef.parse("tls://1.0.0.1")
        XCTAssertEqual(dot.scheme, .dot); XCTAssertEqual(dot.port, 853)
        let doq = NCDNSServerRef.parse("quic://dns.adguard.com:784")
        XCTAssertEqual(doq.scheme, .doq); XCTAssertEqual(doq.port, 784)
        let hashed = NCDNSServerRef.parse("https://dns.alidns.com/dns-query#h3")
        XCTAssertEqual(hashed.scheme, .doh); XCTAssertEqual(hashed.host, "dns.alidns.com")
        XCTAssertEqual(NCDNSServerRef.parse("system").scheme, .system)
        let v6 = NCDNSServerRef.parse("[2001:4860:4860::8888]:53")
        XCTAssertEqual(v6.host, "2001:4860:4860::8888"); XCTAssertEqual(v6.port, 53)
    }

    func testClashMapping() {
        let root: [String: NCJSONValue] = [
            "mode": .string("rule"),
            "ipv6": .bool(true),
            "proxies": .array([.object([
                "name": .string("A"), "type": .string("ss"),
                "server": .string("1.2.3.4"), "port": .number(443)])]),
            "proxy-groups": .array([.object([
                "name": .string("G"), "type": .string("url-test"),
                "proxies": .array([.string("A")]),
                "url": .string("https://www.gstatic.com/generate_204"),
                "interval": .number(120), "tolerance": .number(30),
                "use": .array([.string("Sub1")])])]),
            "rules": .array([.string("MATCH,G")]),
            "dns": .object([
                "enhanced-mode": .string("fake-ip"),
                "fake-ip-range": .string("198.18.0.1/16"),
                "fake-ip-range6": .string("fc00::/18"),
                "fake-ip-filter": .array([.string("*.lan")]),
                "nameserver": .array([.string("https://dns.google/dns-query"), .string("8.8.8.8")]),
                "nameserver-policy": .object(["+.google.com": .array([.string("tls://1.1.1.1")])]),
                "fallback": .array([.string("quic://dns.adguard.com")]),
                "fallback-filter": .object(["geosite": .array([.string("gfw")]),
                                             "ipcidr": .array([.string("240.0.0.0/4")])]),
                "respect-rules": .bool(true)]),
            "hosts": .object(["router.lan": .string("192.168.1.1"),
                              "nas.lan": .string("server:8.8.8.8")]),
            "proxy-providers": .object(["Sub1": .object([
                "type": .string("http"), "url": .string("https://sub.example.com/x"),
                "interval": .number(3600)])]),
            "rule-providers": .object(["Reject": .object([
                "type": .string("http"), "url": .string("https://rules.example.com/reject.yaml"),
                "interval": .number(7200)])]),
        ]
        let cfg = NCConfig.decode(root: root)
        let c = NCCanonicalConfig.from(clash: cfg)

        XCTAssertEqual(c.sourceFormat, "clash")
        XCTAssertEqual(c.nodes.count, 1)
        XCTAssertEqual(c.groups.count, 1)
        XCTAssertEqual(c.groups[0].kind, .urlTest)
        XCTAssertEqual(c.groups[0].interval, 120)
        XCTAssertEqual(c.groups[0].use, ["Sub1"])

        XCTAssertEqual(c.dns.mode, .fakeIP)
        XCTAssertEqual(c.dns.fakeIPRange6, "fc00::/18")
        XCTAssertEqual(c.dns.alwaysRealIP, ["*.lan"])
        XCTAssertEqual(c.dns.defaultServers.count, 2)
        XCTAssertEqual(c.dns.encryptedServers.map { $0.scheme }, [.doh])
        XCTAssertEqual(c.dns.domainServers.count, 1)
        XCTAssertEqual(c.dns.domainServers[0].key, "+.google.com")
        XCTAssertEqual(c.dns.domainServers[0].servers.first?.scheme, .dot)
        XCTAssertEqual(c.dns.fallback.first?.scheme, .doq)
        XCTAssertEqual(c.dns.fallbackFilter.geosite, ["gfw"])
        XCTAssertEqual(c.dns.fallbackFilter.ipcidr, ["240.0.0.0/4"])
        XCTAssertTrue(c.dns.respectRules)

        XCTAssertEqual(c.hosts.count, 2)
        let nas = c.hosts.first { $0.pattern == "nas.lan" }
        XCTAssertEqual(nas?.kind, .dnsServer)
        XCTAssertEqual(nas?.dnsServer?.host, "8.8.8.8")
        XCTAssertEqual(c.hosts.first { $0.pattern == "router.lan" }?.kind, .address)

        XCTAssertEqual(c.subscriptions.count, 1)
        XCTAssertEqual(c.subscriptions[0].name, "Sub1")
        XCTAssertEqual(c.subscriptions[0].interval, 3600)
        XCTAssertEqual(c.ruleSets.count, 1)
        XCTAssertEqual(c.ruleSets[0].name, "Reject")
        XCTAssertEqual(c.ruleSets[0].interval, 7200)

        // Legacy adapters keep their shapes for the existing engines.
        XCTAssertEqual(c.groups[0].legacy().type, "url-test")
        XCTAssertEqual(c.legacyConfig().proxies.count, 1)
    }
}
