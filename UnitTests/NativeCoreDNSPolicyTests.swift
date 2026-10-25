import XCTest
@testable import Mihomo

final class NativeCoreDNSPolicyTests: XCTestCase {
    private func policy() -> NCDNSPolicy {
        var dns = NCDNSModel()
        dns.domainServers = [
            (key: "+.google.com", servers: [NCDNSServerRef.parse("tls://1.1.1.1")]),
            (key: "corp.example.com", servers: [NCDNSServerRef.parse("10.0.0.53")]),
            (key: "deep.corp.example.com", servers: [NCDNSServerRef.parse("https://dns.corp/dns-query")]),
        ]
        let hosts = [
            NCHostEntry(pattern: "router.lan", value: "192.168.1.1"),
            NCHostEntry(pattern: "*.printer.lan", value: "192.168.1.50"),
            NCHostEntry(pattern: "v6.lan", value: "fd00::1"),
            NCHostEntry(pattern: "alias.lan", value: "router.lan"),
            NCHostEntry(pattern: "special.com", value: "server:9.9.9.9"),
        ]
        return NCDNSPolicy(model: dns, hosts: hosts)
    }

    private func query(_ name: String, _ type: UInt16) -> Data {
        var q = NCDNSMessage()
        q.id = 0x1234
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: 1)]
        return q.serialized()
    }

    func testHostsReplies() {
        let p = policy()
        let a = NCDNSMessage.parse(p.hostsReply(queryData: query("router.lan", 1))!)!
        XCTAssertTrue(a.isResponse)
        XCTAssertEqual(a.answers.count, 1)
        XCTAssertEqual(a.answers[0].rdata, Data([192, 168, 1, 1]))
        // Wildcard + alias chase.
        XCTAssertNotNil(p.hostsReply(queryData: query("hp.printer.lan", 1)))
        XCTAssertNotNil(p.hostsReply(queryData: query("alias.lan", 1)))
        // Family mismatch: NOERROR with no records (name is locally defined).
        let nodata = NCDNSMessage.parse(p.hostsReply(queryData: query("router.lan", 28))!)!
        XCTAssertEqual(nodata.answers.count, 0)
        let v6 = NCDNSMessage.parse(p.hostsReply(queryData: query("v6.lan", 28))!)!
        XCTAssertEqual(v6.answers[0].rdata.count, 16)
        // Unknown names and server: entries are not answered locally.
        XCTAssertNil(p.hostsReply(queryData: query("unknown.lan", 1)))
        XCTAssertNil(p.hostsReply(queryData: query("special.com", 1)))
        // Non-A/AAAA types pass through.
        XCTAssertNil(p.hostsReply(queryData: query("router.lan", 15)))
    }

    func testPerDomainServers() {
        let p = policy()
        XCTAssertEqual(p.servers(for: "www.google.com").first?.scheme, .dot)
        XCTAssertEqual(p.servers(for: "google.com").first?.scheme, .dot)
        XCTAssertEqual(p.servers(for: "mail.corp.example.com").first?.host, "10.0.0.53")
        // Longest suffix wins.
        XCTAssertEqual(p.servers(for: "x.deep.corp.example.com").first?.scheme, .doh)
        // Hosts server: entries beat the policy table.
        XCTAssertEqual(p.servers(for: "special.com").first?.host, "9.9.9.9")
        XCTAssertTrue(p.servers(for: "unrelated.org").isEmpty)
    }

    func testUpstreamMapping() {
        XCTAssertEqual(NCDNSUpstream.parse("quic://dns.example.com"), .doq(host: "dns.example.com", port: 853))
        XCTAssertEqual(NCDNSUpstream.parse("quic://dns.example.com:784"), .doq(host: "dns.example.com", port: 784))
        XCTAssertEqual(NCDNSUpstream.parse("tcp://1.2.3.4:5353"), .tcp(host: "1.2.3.4", port: 5353))
        XCTAssertEqual(NCDNSUpstream.parse("1.2.3.4:5353"), .udp(host: "1.2.3.4", port: 5353))
        XCTAssertEqual(NCDNSUpstream(NCDNSServerRef.parse("https://dns.google/dns-query")),
                       .doh(url: "https://dns.google/dns-query"))
        XCTAssertNil(NCDNSUpstream(NCDNSServerRef.parse("system")))
    }

    // rv2-rules: IPv6 upstreams, comma / geosite / rule-set / regexp policy keys, dual-stack hosts.
    func testIPv6UpstreamParse() {
        XCTAssertEqual(NCDNSUpstream.parse("tls://[2001:db8::1]:853"), .dot(host: "2001:db8::1", port: 853))
        XCTAssertEqual(NCDNSUpstream.parse("tls://[2001:db8::1]"), .dot(host: "2001:db8::1", port: 853))
        XCTAssertEqual(NCDNSUpstream.parse("[2001:db8::2]:5353"), .udp(host: "2001:db8::2", port: 5353))
        XCTAssertEqual(NCDNSUpstream.parse("2001:db8::3"), .udp(host: "2001:db8::3", port: 53))
        XCTAssertEqual(NCDNSServerRef.parse("2001:db8::3").host, "2001:db8::3")
        XCTAssertEqual(NCDNSServerRef.parse("2001:db8::3").port, 53)
        XCTAssertEqual(NCDNSUpstream.of([.udp(host: "a", port: 53), .udp(host: "a", port: 53)]),
                       .udp(host: "a", port: 53))
    }

    func testPolicyMatcherKeys() {
        var dns = NCDNSModel()
        dns.domainServers = [
            (key: "geosite:cn,private", servers: [NCDNSServerRef.parse("223.5.5.5")]),
            (key: "rule-set:corp", servers: [NCDNSServerRef.parse("10.0.0.53")]),
            (key: "regexp:^ads[0-9]+\\.", servers: [NCDNSServerRef.parse("9.9.9.9")]),
            (key: "a.example,b.example", servers: [NCDNSServerRef.parse("8.8.8.8")]),
            (key: "geoip:cn", servers: [NCDNSServerRef.parse("1.1.1.1")]),
        ]
        var p = NCDNSPolicy(model: dns, hosts: [])
        p.geositeContains = { cat, name in
            (cat == "cn" && name.hasSuffix(".cn")) || (cat == "private" && name.hasSuffix(".lan"))
        }
        p.ruleSetContainsDomain = { set, name in set == "corp" && name == "intra.corp" }
        XCTAssertEqual(p.servers(for: "www.baidu.cn").first?.host, "223.5.5.5")
        XCTAssertEqual(p.servers(for: "nas.lan").first?.host, "223.5.5.5")
        XCTAssertEqual(p.servers(for: "intra.corp").first?.host, "10.0.0.53")
        XCTAssertEqual(p.servers(for: "ads12.tracker.com").first?.host, "9.9.9.9")
        XCTAssertEqual(p.servers(for: "x.b.example").first?.host, "8.8.8.8")
        XCTAssertTrue(p.servers(for: "example.org").isEmpty)
        XCTAssertEqual(p.diagnostics.count, 1) // geoip: key unsupported
    }

    func testDualStackHosts() {
        let p = NCDNSPolicy(model: NCDNSModel(), hosts: [NCHostEntry(pattern: "dual.lan", value: "192.168.1.2,fd00::2")])
        let a = NCDNSMessage.parse(p.hostsReply(queryData: query("dual.lan", 1))!)!
        XCTAssertEqual(a.answers.count, 1)
        XCTAssertEqual(a.answers.first?.rdata, Data([192, 168, 1, 2]))
        let aaaa = NCDNSMessage.parse(p.hostsReply(queryData: query("dual.lan", 28))!)!
        XCTAssertEqual(aaaa.answers.count, 1)
        XCTAssertEqual(aaaa.answers.first?.rdata.count, 16)
    }
}
