import XCTest
@testable import Tern

// Vectors ported from the old core test suite deleted in 81de91b ("native-only").
// Sources are the pre-deletion files at 81de91b^:
//  - the retired bridge       (TestParseAllProtocols: share links + the
//                                base64 subscription blob)
//  - the retired bridge  (the rule list every dialect import had to
//                                reproduce, incl. GEOIP / DOMAIN-SET / AND)
// The the old core tests asserted the Clash.Meta core accepted the parsed nodes; here the
// same vectors go through the Swift parser (NCSubscriptionParser) and the
// share-link encoder (NCShareLink) in a full parse → encode → parse loop.
final class NativeCorePortedRuleVectorTests: XCTestCase {

    private func ctx(domain: String? = nil, ip: String? = nil, port: Int? = nil) -> NCMatchContext {
        var c = NCMatchContext()
        c.domain = domain
        c.ip = ip.flatMap { NCIP($0) }
        c.dstPort = port
        return c
    }

    /// confimport_test's canonical list (policies renamed to the groups
    /// the fixture defined). DOMAIN-SET / GEOIP resolve through the
    /// context's injected lookups, as the engine wires them.
    func testConfImportRuleList() {
        let lines = [
            "DOMAIN-SUFFIX,netflix.com,Streaming",
            "DOMAIN-KEYWORD,ads,REJECT",
            "DOMAIN-SET,reject-list,REJECT",
            "AND,((DOMAIN-SUFFIX,a.com),(DEST-PORT,443)),Proxy",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,Proxy",
        ]
        let rules = lines.compactMap(NCRule.parse)
        XCTAssertEqual(rules.count, lines.count)
        XCTAssertTrue(rules[4].noResolve)

        var c = ctx(domain: "www.netflix.com")
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, c), "Streaming")
        c = ctx(domain: "ads.example.com")
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, c), "REJECT")
        // DOMAIN-SET through the injected rule-set lookup.
        c = ctx(domain: "tracker.example")
        c.ruleSetContains = { name, inner in name == "reject-list" && inner.domain == "tracker.example" }
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, c), "REJECT")
        // AND: both halves must hold.
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(domain: "x.a.com", port: 443)), "Proxy")
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(domain: "x.a.com", port: 80)), "Proxy") // via MATCH
        // IP-CIDR on a bare IP flow.
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(ip: "192.168.1.9")), "DIRECT")
        // GEOIP through the injected country lookup.
        var g = ctx(ip: "1.2.3.4")
        g.countryOf = { _ in "CN" }
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, g), "DIRECT")
        g.countryOf = { _ in "US" }
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, g), "Proxy") // falls through to MATCH
        // Nothing above matches: MATCH wins.
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(domain: "plain.example")), "Proxy")
    }
}

final class NativeCorePortedShareLinkTests: XCTestCase {

    // the retired bridge vectors (the four schemes
    // with a canonical share-link form; the vmess JSON is the old core test's).
    private static let ssVector = "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#ss1"
    private static let vmessVector: String = {
        let json = #"{"v":"2","ps":"vm","add":"v.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"ws","path":"/ws","host":"v.example.com","tls":"tls"}"#
        return "vmess://" + Data(json.utf8).base64EncodedString()
    }()
    private static let vlessVector = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=7Pq1mu0nSG2Jm1TTaR8dhJOiwSIn0PFk5Jc7mzeK_zU&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision&type=tcp#vless1"
    private static let trojanVector = "trojan://pw@t.example.com:443?sni=t.example.com#tj"

    /// parse (NCSubscriptionParser) → encode (NCShareLink) → parse again:
    /// the node's identity fields must survive the whole loop.
    private func roundTrip(_ uri: String, type: String) throws -> NCProxy {
        let node = try XCTUnwrap(NCSubscriptionParser.parseURI(uri), uri)
        XCTAssertEqual(node.type, type)
        let link = try NCShareLink.encode(node)
        let again = try XCTUnwrap(NCSubscriptionParser.parseURI(link), link)
        XCTAssertEqual(again.type, node.type)
        XCTAssertEqual(again.name, node.name)
        XCTAssertEqual(again.server, node.server)
        XCTAssertEqual(again.port, node.port)
        XCTAssertEqual(again.password, node.password)
        XCTAssertEqual(again.uuid, node.uuid)
        XCTAssertEqual(again.cipher, node.cipher)
        return node
    }

    func testSSVector() throws {
        let node = try roundTrip(Self.ssVector, type: "ss")
        XCTAssertEqual(node.cipher, "aes-128-gcm")
        XCTAssertEqual(node.password, "pass")
        XCTAssertEqual(node.name, "ss1")
    }

    func testVMessVector() throws {
        let node = try roundTrip(Self.vmessVector, type: "vmess")
        XCTAssertEqual(node.name, "vm")
        XCTAssertEqual(node.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811")
        XCTAssertEqual(node.fields["network"]?.string, "ws")
        XCTAssertEqual(node.fields["ws-opts"]?.object?["path"]?.string, "/ws")
        XCTAssertEqual(node.fields["tls"]?.bool, true)
    }

    func testVLESSVector() throws {
        let node = try roundTrip(Self.vlessVector, type: "vless")
        XCTAssertEqual(node.name, "vless1")
        XCTAssertEqual(node.fields["flow"]?.string, "xtls-rprx-vision")
        XCTAssertEqual(node.fields["reality-opts"]?.object?["public-key"]?.string,
                       "7Pq1mu0nSG2Jm1TTaR8dhJOiwSIn0PFk5Jc7mzeK_zU")
        XCTAssertEqual(node.fields["reality-opts"]?.object?["short-id"]?.string, "6ba85179e30d4fc2")
        XCTAssertEqual(node.fields["servername"]?.string, "www.apple.com")
    }

    func testTrojanVector() throws {
        let node = try roundTrip(Self.trojanVector, type: "trojan")
        XCTAssertEqual(node.password, "pw")
        XCTAssertEqual(node.fields["sni"]?.string, "t.example.com")
    }

    /// The the old core test's base64 subscription blob: ss + trojan + vless +
    /// wireguard links in one blob must yield four nodes. Order follows
    /// the retired bridge parseNodeText: self-parsed schemes (wireguard) come
    /// first in line order, the :// URIs converted afterwards — so wg1 leads.
    func testBase64SubscriptionBlob() {
        let wg = "wireguard://yAnz5TF%2BlXXJte14tji3zlMNq%2BhD2rYUIgJBgB3fBmk%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32,2606:4700::2%2F128&reserved=1,2,3&mtu=1280#wg1"
        let blob = [Self.ssVector, Self.trojanVector, Self.vlessVector, wg].joined(separator: "\n")
        let nodes = NCSubscriptionParser.parse(Data(blob.utf8).base64EncodedString())
        XCTAssertEqual(nodes.map { $0.type }, ["wireguard", "ss", "trojan", "vless"])
        XCTAssertEqual(nodes.map { $0.name }, ["wg1", "ss1", "tj", "vless1"])
    }

    /// More of the old core test's table, parse-only (their share-link forms are
    /// not all canonical): each must still yield exactly one node of the
    /// expected type through NCSubscriptionParser.parse.
    func testMoreGoVectorsParse() {
        let cases: [(String, String)] = [
            ("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@1.2.3.4:8388#ss2022", "ss"),
            ("hysteria2://pw@h2.example.com:443?sni=h2.example.com#hy2a", "hysteria2"),
            ("hy2://pw@h2.example.com:443?sni=h2.example.com#hy2b", "hysteria2"),
            ("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example.com:443?congestion_control=bbr&alpn=h3&sni=tu.example.com#tuic1", "tuic"),
            ("anytls://pw@a.example.com:443?sni=a.example.com#any1", "anytls"),
            ("snell://psk123@1.2.3.4:6333?version=4&obfs=http&obfs-host=bing.com#sn1", "snell"),
            ("socks5://user:pass@1.2.3.4:1080#s5", "socks5"),
            ("http://user:pass@1.2.3.4:8080#h1", "http"),
            ("ssh://root:pw@1.2.3.4:2222#ssh1", "ssh"),
        ]
        for (uri, type) in cases {
            let nodes = NCSubscriptionParser.parse(uri)
            XCTAssertEqual(nodes.count, 1, uri)
            XCTAssertEqual(nodes.first?.type, type, uri)
        }
    }
}
