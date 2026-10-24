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
}
