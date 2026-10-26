import XCTest
@testable import Mihomo

final class NativeCoreOpenConnectTests: XCTestCase {

    // MARK: - 1. Positive Parsing Tests

    func testOpenConnectURIParsing() {
        let uri = "openconnect://alice:secret123@vpn.example.com:443?group=Engineering&sni=vpn.corp.com#Corp%20VPN"
        guard let p = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse openconnect URI")
            return
        }
        XCTAssertEqual(p.type, "openconnect")
        XCTAssertEqual(p.name, "Corp VPN")
        XCTAssertEqual(p.server, "vpn.example.com")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.fields["username"]?.string, "alice")
        XCTAssertEqual(p.password, "secret123")
        XCTAssertEqual(p.fields["auth-group"]?.string, "Engineering")
        XCTAssertEqual(p.fields["sni"]?.string, "vpn.corp.com")

        let (cfg, err) = NCOpenConnect.Config.parse(p)
        XCTAssertNil(err)
        XCTAssertNotNil(cfg)
        XCTAssertEqual(cfg?.username, "alice")
        XCTAssertEqual(cfg?.password, "secret123")
        XCTAssertEqual(cfg?.authGroup, "Engineering")
        XCTAssertEqual(cfg?.port, 443)
        XCTAssertEqual(cfg?.dtls, true) // default true
    }

    func testAnyConnectURIParsingWithCookieAndOptions() {
        let uri = "anyconnect://vpn2.example.com:8443?cookie=webvpn%3Dtoken456&dtls=0&insecure=1&mtu=1300#AnyConnect%20Node"
        guard let p = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse anyconnect URI")
            return
        }
        XCTAssertEqual(p.type, "openconnect")
        XCTAssertEqual(p.name, "AnyConnect Node")
        XCTAssertEqual(p.server, "vpn2.example.com")
        XCTAssertEqual(p.port, 8443)
        XCTAssertEqual(p.fields["cookie"]?.string, "webvpn=token456")
        XCTAssertEqual(p.fields["dtls"]?.bool, false)
        XCTAssertEqual(p.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(p.fields["mtu"]?.int, 1300)

        let (cfg, err) = NCOpenConnect.Config.parse(p)
        XCTAssertNil(err)
        XCTAssertNotNil(cfg)
        XCTAssertEqual(cfg?.cookie, "webvpn=token456")
        XCTAssertEqual(cfg?.dtls, false)
        XCTAssertEqual(cfg?.skipCertVerify, true)
        XCTAssertEqual(cfg?.mtu, 1300)
    }

    func testShadowrocketConfNodeParsing() {
        let line = "Corporate = openconnect, vpn.example.com, 443, username=bob, password=mypass, auth-group=Staff, dtls=true, skip-cert-verify=true, user-agent=CustomAgent/1.0"
        guard let parsed = NCConfImport.parseNamedNodeLine(line) else {
            XCTFail("Failed to parse node line")
            return
        }
        var report = NCImportReport()
        guard let p = NCConfImport.buildSurgeLikeNode(name: parsed.name, positional: parsed.positional, kv: parsed.kv, order: parsed.order, report: &report) else {
            XCTFail("Failed to build Surge-like node")
            return
        }
        XCTAssertEqual(p.name, "Corporate")
        XCTAssertEqual(p.type, "openconnect")
        XCTAssertEqual(p.server, "vpn.example.com")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.fields["username"]?.string, "bob")
        XCTAssertEqual(p.password, "mypass")
        XCTAssertEqual(p.fields["auth-group"]?.string, "Staff")
        XCTAssertEqual(p.fields["dtls"]?.bool, true)
        XCTAssertEqual(p.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(p.fields["user-agent"]?.string, "CustomAgent/1.0")

        let (cfg, err) = NCOpenConnect.Config.parse(p)
        XCTAssertNil(err)
        XCTAssertNotNil(cfg)
        XCTAssertEqual(cfg?.userAgent, "CustomAgent/1.0")
    }

    func testClashYAMLOpenConnect() {
        let yaml = """
        proxies:
          - name: OC-Node-1
            type: openconnect
            server: oc.example.com
            port: 443
            username: user1
            password: pass1
            auth-group: Engineering
            dtls: true
          - name: AC-Node-2
            type: anyconnect
            server: ac.example.com
            port: 10443
            cookie: webvpn=session_abc123
        """
        let nodes = NCSubscriptionParser.parse(yaml)
        XCTAssertEqual(nodes.count, 2)

        XCTAssertEqual(nodes[0].name, "OC-Node-1")
        XCTAssertEqual(nodes[0].type, "openconnect")
        XCTAssertEqual(nodes[0].server, "oc.example.com")
        XCTAssertEqual(nodes[0].port, 443)
        XCTAssertEqual(nodes[0].fields["username"]?.string, "user1")
        XCTAssertEqual(nodes[0].password, "pass1")
        XCTAssertEqual(nodes[0].fields["auth-group"]?.string, "Engineering")

        XCTAssertEqual(nodes[1].name, "AC-Node-2")
        XCTAssertEqual(nodes[1].type, "anyconnect")
        XCTAssertEqual(nodes[1].server, "ac.example.com")
        XCTAssertEqual(nodes[1].port, 10443)
        XCTAssertEqual(nodes[1].fields["cookie"]?.string, "webvpn=session_abc123")

        let (cfg1, err1) = NCOpenConnect.Config.parse(nodes[0])
        XCTAssertNil(err1)
        XCTAssertNotNil(cfg1)

        let (cfg2, err2) = NCOpenConnect.Config.parse(nodes[1])
        XCTAssertNil(err2)
        XCTAssertNotNil(cfg2)
    }

    func testCSTPAndDTLSFraming() {
        // CSTP data packet encoding
        let ipPayload = Data([0x45, 0x00, 0x00, 0x28, 0x12, 0x34])
        let encoded = NCOpenConnect.encodeCSTP(type: .data, payload: ipPayload)
        XCTAssertEqual(encoded.count, 8 + ipPayload.count)
        XCTAssertEqual(encoded.prefix(4), Data([0x53, 0x54, 0x46, 0x01])) // "STF\x01"

        // CSTP decoding
        guard let decoded = NCOpenConnect.decodeCSTP(encoded) else {
            XCTFail("Failed to decode CSTP packet")
            return
        }
        XCTAssertEqual(decoded.type, .data)
        XCTAssertEqual(decoded.payload, ipPayload)
        XCTAssertEqual(decoded.consumed, encoded.count)

        // CSTP keepalive (0-length payload)
        let keepalive = NCOpenConnect.encodeCSTP(type: .keepalive)
        guard let decodedKA = NCOpenConnect.decodeCSTP(keepalive) else {
            XCTFail("Failed to decode keepalive packet")
            return
        }
        XCTAssertEqual(decodedKA.type, .keepalive)
        XCTAssertEqual(decodedKA.payload.count, 0)
        XCTAssertEqual(decodedKA.consumed, 8)

        // DTLS 1-byte header framing
        let dtlsPacket = NCOpenConnect.encodeDTLS(type: .data, payload: ipPayload)
        XCTAssertEqual(dtlsPacket.count, 1 + ipPayload.count)
        guard let decodedDTLS = NCOpenConnect.decodeDTLS(dtlsPacket) else {
            XCTFail("Failed to decode DTLS packet")
            return
        }
        XCTAssertEqual(decodedDTLS.type, .data)
        XCTAssertEqual(decodedDTLS.payload, ipPayload)
    }

    // MARK: - 2. Negative Parsing & Validation Tests

    func testInvalidURIs() {
        // Missing host
        XCTAssertNil(NCSubscriptionParser.parseURI("openconnect:///path?query=1"))
        // Empty body
        XCTAssertNil(NCSubscriptionParser.parseURI("openconnect://"))
    }

    func testMissingCredentialsFailsValidation() {
        let p = NCProxy(name: "NoCreds", type: "openconnect", fields: [
            "server": .string("vpn.example.com"),
            "port": .number(443)
        ])
        let (cfg, err) = NCOpenConnect.Config.parse(p)
        XCTAssertNil(cfg)
        XCTAssertNotNil(err)
        XCTAssertTrue(err!.contains("缺少认证凭据"))

        let unsupported = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(unsupported)
        XCTAssertTrue(unsupported!.contains("缺少认证凭据"))
    }

    func testInvalidPortFailsValidation() {
        let p = NCProxy(name: "BadPort", type: "openconnect", fields: [
            "server": .string("vpn.example.com"),
            "port": .number(70000),
            "username": .string("user"),
            "password": .string("pass")
        ])
        let (cfg, err) = NCOpenConnect.Config.parse(p)
        XCTAssertNil(cfg)
        XCTAssertNotNil(err)
        XCTAssertTrue(err!.contains("端口无效"))
    }

    // MARK: - 3. Unsupported Field Marking Tests

    func testUnsupportedFieldsCSDWrapper() {
        let uri = "openconnect://user:pass@vpn.example.com:443?csd_wrapper=/usr/bin/csd.sh#CSDNode"
        guard let p = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse URI with CSD")
            return
        }
        XCTAssertNotNil(p.fields["csd-wrapper"])
        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("CSD"))
    }

    func testUnsupportedFieldsHIPReport() {
        let uri = "openconnect://user:pass@vpn.example.com:443?hip_report=true#HIPNode"
        guard let p = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse URI with HIP")
            return
        }
        XCTAssertNotNil(p.fields["hip"])
        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("HIP"))
    }

    func testUnsupportedFieldsTNCC() {
        let p = NCProxy(name: "TNCCNode", type: "openconnect", fields: [
            "server": .string("vpn.example.com"),
            "port": .number(443),
            "username": .string("user"),
            "password": .string("pass"),
            "tncc": .string("1")
        ])
        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("TNCC"))
    }

    func testUnsupportedFieldsTokenSecret() {
        let p = NCProxy(name: "TokenNode", type: "openconnect", fields: [
            "server": .string("vpn.example.com"),
            "port": .number(443),
            "username": .string("user"),
            "password": .string("pass"),
            "token-secret": .string("totp-secret-key")
        ])
        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("软件令牌"))
    }

    func testUnsupportedCompression() {
        let p = NCProxy(name: "CompressNode", type: "openconnect", fields: [
            "server": .string("vpn.example.com"),
            "port": .number(443),
            "username": .string("user"),
            "password": .string("pass"),
            "compression": .string("oc-lz4")
        ])
        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("压缩"))
    }

    // MARK: - 4. Quantumult X Rejection / No Public Format

    func testQuantumultXExplicitlyUnavailable() {
        let line = "openconnect=vpn.example.com:443, tag=OC-QX, username=alice, password=secret"
        var report = NCImportReport()
        guard let p = NCQXImport.buildQXNode(line: line, report: &report) else {
            XCTFail("Expected non-nil node with unsupported flag")
            return
        }
        XCTAssertEqual(p.type, "openconnect")
        XCTAssertEqual(p.fields["unsupported"]?.string, "Quantumult X 无公开 OpenConnect 格式")
        XCTAssertTrue(report.warnings.contains(where: { $0.contains("无公开 Quantumult X 格式") }))

        let reason = NCSupport.unsupportedReason(p)
        XCTAssertNotNil(reason)
        XCTAssertEqual(reason, "Quantumult X 无公开 OpenConnect 格式")
    }
}
