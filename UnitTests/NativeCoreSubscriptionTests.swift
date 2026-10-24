import XCTest
@testable import Mihomo

final class NativeCoreSubscriptionTests: XCTestCase {

    func testURIs() {
        // SIP002 ss with base64 userinfo
        let ssInfo = Data("aes-256-gcm:secret".utf8).base64EncodedString()
        let ss = NCSubscriptionParser.parseURI("ss://\(ssInfo)@1.2.3.4:8388#HK%20Node")!
        XCTAssertEqual(ss.type, "ss")
        XCTAssertEqual(ss.cipher, "aes-256-gcm")
        XCTAssertEqual(ss.password, "secret")
        XCTAssertEqual(ss.name, "HK Node")
        XCTAssertEqual(ss.port, 8388)

        // vmess base64 JSON
        let vmJSON = #"{"v":"2","ps":"VM-WS","add":"vm.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"sni.example.com"}"#
        let vm = NCSubscriptionParser.parseURI("vmess://" + Data(vmJSON.utf8).base64EncodedString())!
        XCTAssertEqual(vm.name, "VM-WS")
        XCTAssertEqual(vm.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811")
        XCTAssertEqual(vm.fields["network"]?.string, "ws")
        XCTAssertEqual(vm.fields["ws-opts"]?.object?["path"]?.string, "/ws")
        XCTAssertEqual(vm.fields["servername"]?.string, "sni.example.com")

        // vless reality
        let vl = NCSubscriptionParser.parseURI("vless://b831381d-6324-4d53-ad4f-8cda48b30811@vl.example.com:443?security=reality&sni=www.microsoft.com&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#VL-R")!
        XCTAssertEqual(vl.fields["flow"]?.string, "xtls-rprx-vision")
        XCTAssertEqual(vl.fields["reality-opts"]?.object?["public-key"]?.string, "PUBKEY")
        XCTAssertEqual(vl.fields["reality-opts"]?.object?["short-id"]?.string, "ab12")

        // trojan ws
        let tj = NCSubscriptionParser.parseURI("trojan://p%40ss@tj.example.com:443?sni=t.example.com&type=ws&path=%2Ftj&host=h.example.com#TJ")!
        XCTAssertEqual(tj.password, "p@ss")
        XCTAssertEqual(tj.fields["network"]?.string, "ws")
        XCTAssertEqual(tj.fields["ws-opts"]?.object?["path"]?.string, "/tj")

        // hysteria2 + tuic
        let hy = NCSubscriptionParser.parseURI("hysteria2://auth@hy.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=ob#HY")!
        XCTAssertEqual(hy.type, "hysteria2")
        XCTAssertEqual(hy.fields["obfs"]?.string, "salamander")
        let tu = NCSubscriptionParser.parseURI("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example.com:10443?congestion_control=bbr&sni=t.example.com#TU")!
        XCTAssertEqual(tu.type, "tuic")
        XCTAssertEqual(tu.fields["congestion-controller"]?.string, "bbr")
    }

    func testBase64BlobAndDedup() {
        let blob = """
        ss://YWVzLTEyOC1nY206cHc@5.6.7.8:9999#Same
        ss://YWVzLTEyOC1nY206cHc@5.6.7.9:9999#Same
        trojan://pw@9.9.9.9:443#Other
        """
        let nodes = NCSubscriptionParser.parse(Data(blob.utf8).base64EncodedString())
        XCTAssertEqual(nodes.map { $0.name }, ["Same", "Same 2", "Other"])
        XCTAssertEqual(nodes[0].cipher, "aes-128-gcm")
    }

    func testClashYAML() {
        let yaml = """
        proxies:
          - name: Y1
            type: ss
            server: 1.1.1.1
            port: 443
            cipher: aes-256-gcm
            password: pw
        """
        let nodes = NCSubscriptionParser.parse(yaml)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes[0].name, "Y1")
    }

    func testFilter() {
        let nodes = [
            NCProxy(name: "HK 01", type: "ss", fields: [:]),
            NCProxy(name: "JP 01", type: "ss", fields: [:]),
            NCProxy(name: "HK Premium", type: "ss", fields: [:]),
        ]
        XCTAssertEqual(NCNodeFilter.apply(nodes, include: "HK", exclude: "Premium").map { $0.name }, ["HK 01"])
        XCTAssertEqual(NCNodeFilter.apply(nodes, include: nil, exclude: nil).count, 3)
    }

    func testSubnetGroupEngine() {
        let cfg = NCConfig.decode(root: [
            "proxies": .array([
                .object(["name": .string("HomeProxy"), "type": .string("ss")]),
                .object(["name": .string("MobileProxy"), "type": .string("ss")]),
            ]),
            "proxy-groups": .array([.object([
                "name": .string("Auto"), "type": .string("select"),
                "proxies": .array([.string("MobileProxy"), .string("HomeProxy")]),
                "subnet": .object(["HomeWiFi": .string("HomeProxy"), "DEFAULT": .string("MobileProxy")]),
            ])],
        ])
        let engine = NCGroupEngine(config: cfg)
        var ssid: String? = "HomeWiFi"
        engine.ssidProvider = { ssid }
        XCTAssertEqual(engine.currentMember(of: cfg.groupMap["Auto"]!), "HomeProxy")
        ssid = "CoffeeShop"
        XCTAssertEqual(engine.currentMember(of: cfg.groupMap["Auto"]!), "MobileProxy") // DEFAULT
        ssid = nil
        XCTAssertEqual(engine.currentMember(of: cfg.groupMap["Auto"]!), "MobileProxy") // DEFAULT still applies
        if case .proxy(let p) = engine.resolve("Auto") {
            XCTAssertEqual(p.name, "MobileProxy")
        } else {
            XCTFail("expected proxy resolution")
        }
    }
}
