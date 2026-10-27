import XCTest
@testable import Tern

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

    // MARK: - 5. S2 Authentication State Machine Tests

    func testAuthXMLParsingAndGeneration() {
        let authReqXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth client="vpn" type="auth-request">
            <version who="sg">0.1(1)</version>
            <auth id="main">
                <title>Corporate VPN</title>
                <message>Please enter your credentials.</message>
                <form action="/auth" method="post">
                    <input label="Group:" name="group_list" type="select" />
                    <input label="Username:" name="username" type="text" />
                    <input label="Password:" name="password" type="password" />
                </form>
            </auth>
        </config-auth>
        """

        guard let parsed = NCOpenConnect.AuthResponse.parse(xmlString: authReqXML) else {
            XCTFail("Failed to parse auth-request XML")
            return
        }

        XCTAssertEqual(parsed.type, .authRequest)
        XCTAssertEqual(parsed.formAction, "/auth")
        XCTAssertEqual(parsed.message, "Please enter your credentials.")
        XCTAssertEqual(parsed.inputs["group_list"], "select")
        XCTAssertEqual(parsed.inputs["username"], "text")
        XCTAssertEqual(parsed.inputs["password"], "password")

        // XML builder tests
        let initXML = NCOpenConnect.buildInitXML()
        XCTAssertTrue(initXML.contains("type=\"init\""))
        XCTAssertTrue(initXML.contains("<version who=\"vpn\">v5.01</version>"))

        let replyXML = NCOpenConnect.buildAuthReplyXML(username: "alice", password: "p&w", authGroup: "Engineering")
        XCTAssertTrue(replyXML.contains("type=\"auth-reply\""))
        XCTAssertTrue(replyXML.contains("<username>alice</username>"))
        XCTAssertTrue(replyXML.contains("<password>p&amp;w</password>")) // escaped
        XCTAssertTrue(replyXML.contains("<group_list>Engineering</group_list>"))

        // Form urlencoded builder
        let form = NCOpenConnect.buildFormURLEncoded(fields: [("username", "alice@corp"), ("password", "pass 123")])
        XCTAssertEqual(form, "username=alice%40corp&password=pass%20123")

        // Complete XML
        let completeXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth client="vpn" type="complete">
            <version who="sg">0.1(1)</version>
            <auth id="success"><title>SSL VPN Service</title></auth>
        </config-auth>
        """
        guard let completeParsed = NCOpenConnect.AuthResponse.parse(xmlString: completeXML) else {
            XCTFail("Failed to parse complete XML")
            return
        }
        XCTAssertEqual(completeParsed.type, .complete)

        // Error XML
        let errorXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth client="vpn" type="error">
            <error>Invalid username or password</error>
        </config-auth>
        """
        guard let errorParsed = NCOpenConnect.AuthResponse.parse(xmlString: errorXML) else {
            XCTFail("Failed to parse error XML")
            return
        }
        XCTAssertEqual(errorParsed.type, .error)
        XCTAssertEqual(errorParsed.error, "Invalid username or password")
    }

    func testHTTPMessageParserWithCookiesAndHeaders() {
        let rawHTTP = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/xml",
            "Content-Length: 13",
            "Set-Cookie: webvpncontext=ABC123Context; path=/; Secure; HttpOnly",
            "Set-Cookie: webvpn=SessionTokenXYZ789; path=/; Secure; HttpOnly",
            "X-Transcend-Version: 1",
            "",
            "Hello World!\n"
        ].joined(separator: "\r\n")

        guard let rawData = rawHTTP.data(using: .utf8),
              let (msg, consumed) = NCOpenConnect.HTTPMessage.parse(data: rawData) else {
            XCTFail("Failed to parse valid HTTP response")
            return
        }

        XCTAssertEqual(msg.statusCode, 200)
        XCTAssertEqual(msg.statusText, "OK")
        XCTAssertEqual(msg.headers["content-type"], "text/xml")
        XCTAssertEqual(msg.headers["x-transcend-version"], "1")
        XCTAssertEqual(msg.cookies["webvpncontext"], "ABC123Context")
        XCTAssertEqual(msg.cookies["webvpn"], "SessionTokenXYZ789")
        XCTAssertEqual(String(data: msg.body, encoding: .utf8), "Hello World!\n")
        XCTAssertEqual(consumed, rawData.count)

        // Incomplete HTTP header returns nil
        let partialData = Data("HTTP/1.1 200 OK\r\nContent-Type: text".utf8)
        XCTAssertNil(NCOpenConnect.HTTPMessage.parse(data: partialData))

        // Incomplete body (< Content-Length) returns nil
        let partialBodyData = Data("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nShort".utf8)
        XCTAssertNil(NCOpenConnect.HTTPMessage.parse(data: partialBodyData))
    }

    func testTunnelParametersParsing() {
        let headers: [String: String] = [
            "x-cstp-version": "1",
            "X-CSTP-Address": "192.168.109.55",
            "X-CSTP-Netmask": "255.255.255.0",
            "X-CSTP-DNS": "192.168.109.1",
            "X-CSTP-Base-MTU": "1500",
            "X-CSTP-MTU": "1434",
            "X-CSTP-DPD": "30",
            "X-CSTP-Keepalive": "300",
            "X-DTLS-Port": "18011",
            "X-DTLS-App-ID": "0102030405060708090a0b0c0d0e0f10",
            "X-DTLS-CipherSuite": "PSK-NEGOTIATE",
            "X-DTLS-DPD": "30",
            "X-DTLS-Keepalive": "300"
        ]

        let params = NCOpenConnect.TunnelParameters.parse(headers: headers)
        XCTAssertEqual(params.assignedIPv4, "192.168.109.55")
        XCTAssertEqual(params.netmaskIPv4, "255.255.255.0")
        XCTAssertEqual(params.dnsServers, ["192.168.109.1"])
        XCTAssertEqual(params.baseMTU, 1500)
        XCTAssertEqual(params.mtu, 1434)
        XCTAssertEqual(params.dpd, 30)
        XCTAssertEqual(params.keepalive, 300)
        XCTAssertEqual(params.dtlsPort, 18011)
        XCTAssertEqual(params.dtlsAppID, "0102030405060708090a0b0c0d0e0f10")
        XCTAssertEqual(params.dtlsCipherSuite, "PSK-NEGOTIATE")
    }

    // MARK: - 6. S2 CSTP Codec Boundary Tests

    func testCSTPCodecBoundaries() {
        // 1. Buffer smaller than header (7 bytes)
        let shortHeader = Data([0x53, 0x54, 0x46, 0x01, 0x00, 0x05, 0x00])
        XCTAssertNil(NCOpenConnect.decodeCSTP(shortHeader))

        // 2. Corrupted magic header
        let badMagic = Data([0x53, 0x54, 0x46, 0x02, 0x00, 0x01, 0x00, 0x00, 0xff])
        XCTAssertNil(NCOpenConnect.decodeCSTP(badMagic))

        // 3. Truncated payload: declares 10 bytes, only provides 4
        let truncated = Data([0x53, 0x54, 0x46, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04])
        XCTAssertNil(NCOpenConnect.decodeCSTP(truncated))

        // 4. Unknown payload type (0xef)
        let unknownType = Data([0x53, 0x54, 0x46, 0x01, 0x00, 0x01, 0xef, 0x00, 0x42])
        XCTAssertNil(NCOpenConnect.decodeCSTP(unknownType))

        // 5. Zero-length payload
        let zeroPayloadPacket = NCOpenConnect.encodeCSTP(type: .dpdReq, payload: Data())
        guard let decodedZero = NCOpenConnect.decodeCSTP(zeroPayloadPacket) else {
            XCTFail("Failed to decode zero-length CSTP packet")
            return
        }
        XCTAssertEqual(decodedZero.type, .dpdReq)
        XCTAssertEqual(decodedZero.payload.count, 0)
        XCTAssertEqual(decodedZero.consumed, 8)

        // 6. Concatenated packets in a single buffer
        let p1 = NCOpenConnect.encodeCSTP(type: .data, payload: Data([0x11, 0x22]))
        let p2 = NCOpenConnect.encodeCSTP(type: .dpdResp, payload: Data([0x33, 0x44, 0x55]))
        var combined = Data()
        combined.append(p1)
        combined.append(p2)

        // First packet
        guard let d1 = NCOpenConnect.decodeCSTP(combined) else {
            XCTFail("Failed to decode first concatenated packet")
            return
        }
        XCTAssertEqual(d1.type, .data)
        XCTAssertEqual(d1.payload, Data([0x11, 0x22]))
        XCTAssertEqual(d1.consumed, p1.count)

        // Second packet
        let remaining = Data(combined.dropFirst(d1.consumed))
        guard let d2 = NCOpenConnect.decodeCSTP(remaining) else {
            XCTFail("Failed to decode second concatenated packet")
            return
        }
        XCTAssertEqual(d2.type, .dpdResp)
        XCTAssertEqual(d2.payload, Data([0x33, 0x44, 0x55]))
        XCTAssertEqual(d2.consumed, p2.count)

        // 7. Max 16384 bytes payload
        let bigPayload = Data(repeating: 0xaa, count: 16384)
        let bigPacket = NCOpenConnect.encodeCSTP(type: .data, payload: bigPayload)
        guard let decodedBig = NCOpenConnect.decodeCSTP(bigPacket) else {
            XCTFail("Failed to decode large CSTP packet")
            return
        }
        XCTAssertEqual(decodedBig.payload.count, 16384)
        XCTAssertEqual(decodedBig.consumed, 8 + 16384)
    }

    // MARK: - 7. S2 DTLS Fallback Decision Tests

    func testDTLSFallbackWhenDisabledByConfig() {
        let p = NCProxy(name: "NoDTLSNode", type: "openconnect", fields: [
            "server": .string("127.0.0.1"),
            "port": .number(18011),
            "username": .string("user"),
            "password": .string("pass"),
            "dtls": .bool(false)
        ])
        let (cfg, _) = NCOpenConnect.Config.parse(p)
        guard let config = cfg else {
            XCTFail("Config parse failed")
            return
        }
        XCTAssertEqual(config.dtls, false)

        let session = NCOpenConnectSession(config: config, target: NCTarget(host: "127.0.0.1", port: 18080), queue: .main)
        session.evaluateDTLSChannel()

        XCTAssertEqual(session.activeMode, .cstp)
        XCTAssertEqual(session.dtlsFallbackReason, .disabledByConfig)
        XCTAssertEqual(session.channelState, .dtlsFallbackToCSTP(reason: .disabledByConfig))
    }

    func testDTLSFallbackWhenServerNotOffering() {
        let p = NCProxy(name: "DTLSNode", type: "openconnect", fields: [
            "server": .string("127.0.0.1"),
            "port": .number(18011),
            "username": .string("user"),
            "password": .string("pass"),
            "dtls": .bool(true)
        ])
        let (cfg, _) = NCOpenConnect.Config.parse(p)
        guard let config = cfg else {
            XCTFail("Config parse failed")
            return
        }

        let session = NCOpenConnectSession(config: config, target: NCTarget(host: "127.0.0.1", port: 18080), queue: .main)
        // No tunnel parameters set yet (simulating server without DTLS headers)
        session.evaluateDTLSChannel()

        XCTAssertEqual(session.activeMode, .cstp)
        XCTAssertEqual(session.dtlsFallbackReason, .serverNotOffered)
        XCTAssertEqual(session.channelState, .dtlsFallbackToCSTP(reason: .serverNotOffered))
    }

    func testDTLSFallbackWhenMissingAppID() {
        let p = NCProxy(name: "DTLSNode", type: "openconnect", fields: [
            "server": .string("127.0.0.1"),
            "port": .number(18011),
            "username": .string("user"),
            "password": .string("pass"),
            "dtls": .bool(true)
        ])
        let (cfg, _) = NCOpenConnect.Config.parse(p)
        guard let config = cfg else {
            XCTFail("Config parse failed")
            return
        }

        let session = NCOpenConnectSession(config: config, target: NCTarget(host: "127.0.0.1", port: 18080), queue: .main)
        // Set tunnel parameters with DTLS port and cipher but no App-ID
        let headers: [String: String] = [
            "x-dtls-port": "18011",
            "x-dtls-ciphersuite": "PSK-NEGOTIATE"
        ]
        session.tunnelParams = NCOpenConnect.TunnelParameters.parse(headers: headers)
        session.evaluateDTLSChannel()

        XCTAssertEqual(session.activeMode, .cstp)
        XCTAssertEqual(session.dtlsFallbackReason, .missingAppID)
        XCTAssertEqual(session.channelState, .dtlsFallbackToCSTP(reason: .missingAppID))
    }

    func testDTLSFallbackWhenPlatformUnsupported() {
        let p = NCProxy(name: "DTLSNode", type: "openconnect", fields: [
            "server": .string("127.0.0.1"),
            "port": .number(18011),
            "username": .string("user"),
            "password": .string("pass"),
            "dtls": .bool(true)
        ])
        let (cfg, _) = NCOpenConnect.Config.parse(p)
        guard let config = cfg else {
            XCTFail("Config parse failed")
            return
        }

        let session = NCOpenConnectSession(config: config, target: NCTarget(host: "127.0.0.1", port: 18080), queue: .main)
        session.triggerDTLSFallback(reason: .platformUnsupported)

        XCTAssertEqual(session.activeMode, .cstp)
        XCTAssertEqual(session.dtlsFallbackReason, .platformUnsupported)
        XCTAssertEqual(session.channelState, .dtlsFallbackToCSTP(reason: .platformUnsupported))
        XCTAssertTrue(session.channelState.description.contains("Network.framework does not support custom SessionID"))
    }

    // MARK: - fix/nc-proto-openconnect-int: honest availability

    /// A complete, valid node is still shown unavailable (the CSTP channel carries IP packets; no netif yet),
    /// and the connector refuses instead of dialling.
    func testValidNodeIsUnavailableUntilDataPlaneExists() {
        let p = NCProxy(name: "oc", type: "openconnect", fields: [
            "server": .string("vpn.example.com"), "port": .number(443),
            "username": .string("u"), "password": .string("p"),
        ])
        XCTAssertNil(NCOpenConnect.unsupportedReason(p))
        XCTAssertEqual(NCSupport.unsupportedReason(p), NCOpenConnect.dataPlaneUnavailable)
        let exp = expectation(description: "connector")
        var failure: Error?
        NCConnector.connect(target: NCTarget(host: "example.com", port: 443), proxy: p,
                            queue: DispatchQueue(label: "oc.test")) { stream, err in
            XCTAssertNil(stream)
            failure = err
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
        XCTAssertTrue("\(failure.map { "\($0)" } ?? "")".contains("数据面"), "\(String(describing: failure))")
    }

    func testUnknownCSTPFrameLengthIsSkippable() {
        var unknown = Data(NCOpenConnect.cstpMagic)
        unknown.append(contentsOf: [0x00, 0x02, 0x0a, 0x00, 0xaa, 0xbb]) // type 0x0a (not a PayloadType), 2-byte body
        XCTAssertNil(NCOpenConnect.decodeCSTP(unknown))
        XCTAssertEqual(NCOpenConnect.completeFrameLength(unknown), 10)
        XCTAssertNil(NCOpenConnect.completeFrameLength(unknown.prefix(9)))
    }

}
