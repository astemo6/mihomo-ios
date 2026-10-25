import XCTest
@testable import Mihomo

final class NativeCoreRuleSetTests: XCTestCase {

    private func ctx(domain: String? = nil, ip: String? = nil) -> NCMatchContext {
        var c = NCMatchContext()
        c.domain = domain
        c.ip = ip.flatMap { NCIP($0) }
        return c
    }

    func testClassicalDialect() {
        var idx = NCRuleSetIndex()
        idx.addText("""
        # comment line
        DOMAIN,exact.example.com
        DOMAIN-SUFFIX,google.com
        DOMAIN-KEYWORD,tracker
        IP-CIDR,203.0.113.0/24,no-resolve
        GEOIP,CN
        """, flavor: .classical)
        XCTAssertEqual(idx.entryCount, 5)
        XCTAssertTrue(idx.contains(ctx(domain: "exact.example.com")))
        XCTAssertFalse(idx.contains(ctx(domain: "sub.exact.example.com")))
        XCTAssertTrue(idx.contains(ctx(domain: "mail.google.com")))
        XCTAssertTrue(idx.contains(ctx(domain: "google.com")))
        XCTAssertTrue(idx.contains(ctx(domain: "ads.tracker.io")))
        XCTAssertTrue(idx.contains(ctx(ip: "203.0.113.9")))
        XCTAssertFalse(idx.contains(ctx(ip: "203.0.114.9")))
        XCTAssertFalse(idx.contains(ctx(domain: "example.org")))
    }

    func testQXDialect() {
        var idx = NCRuleSetIndex()
        idx.addText("""
        host, exact.qx.com, Proxy
        host-suffix, qxgoogle.com, Proxy
        ip-cidr, 198.51.100.0/24, DIRECT
        """, flavor: .qx)
        XCTAssertTrue(idx.contains(ctx(domain: "exact.qx.com")))
        XCTAssertTrue(idx.contains(ctx(domain: "a.qxgoogle.com")))
        XCTAssertTrue(idx.contains(ctx(ip: "198.51.100.7")))
        XCTAssertFalse(idx.contains(ctx(domain: "other.com")))
    }

    func testDomainSetSemantics() {
        var idx = NCRuleSetIndex()
        idx.addText("""
        // ads list
        ads.com
        .dotted.net
        +.clashstyle.org
        """, flavor: .domainSet)
        // Surge DOMAIN-SET: plain line = exact host; leading dot = self + subdomains.
        XCTAssertTrue(idx.contains(ctx(domain: "ads.com")))          // bare: self
        XCTAssertFalse(idx.contains(ctx(domain: "x.ads.com")))       // bare: exact only
        XCTAssertTrue(idx.contains(ctx(domain: "dotted.net")))       // dot: self included
        XCTAssertTrue(idx.contains(ctx(domain: "a.dotted.net")))     // dot: subdomain
        XCTAssertTrue(idx.contains(ctx(domain: "clashstyle.org")))   // +. prefix = suffix incl self
        XCTAssertTrue(idx.contains(ctx(domain: "www.clashstyle.org")))
        XCTAssertFalse(idx.contains(ctx(domain: "notads.com")))
        XCTAssertFalse(idx.contains(ctx(domain: "ads.com.evil.com")))
    }

    func testYAMLPayloadDocument() {
        var idx = NCRuleSetIndex()
        idx.addText("""
        payload:
          - 'DOMAIN-SUFFIX,yaml.example.com'
          - 'IP-CIDR,192.0.2.0/24'
        """, flavor: .classical)
        XCTAssertEqual(idx.entryCount, 2)
        XCTAssertTrue(idx.contains(ctx(domain: "a.yaml.example.com")))
        XCTAssertTrue(idx.contains(ctx(ip: "192.0.2.55")))
    }

    func testLargeSuffixListStaysCorrect() {
        var idx = NCRuleSetIndex()
        var text = ""
        for i in 0..<5000 { text += "DOMAIN-SUFFIX,d\(i).example.com\n" }
        text += "DOMAIN-SUFFIX,target.example.com\n"
        idx.addText(text, flavor: .classical)
        XCTAssertEqual(idx.entryCount, 5001)
        XCTAssertTrue(idx.contains(ctx(domain: "x.target.example.com")))
        XCTAssertFalse(idx.contains(ctx(domain: "target.example.com.evil.org")))
        XCTAssertFalse(idx.contains(ctx(domain: "d4999.example.com.evil.org")))
    }
}
