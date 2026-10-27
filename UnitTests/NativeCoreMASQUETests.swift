import XCTest
@testable import Tern

final class NativeCoreMASQUETests: XCTestCase {

    // MARK: - Positive Tests

    func testClashYAMLWARPMasque() {
        let yaml = """
        proxies:
          - name: WARP-MASQUE-HK
            type: masque
            server: 162.159.198.1
            port: 443
            private-key: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIVKEY"
            public-key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUBKEY"
            ip: 172.16.0.2
            ipv6: 2606:4700:110:875d:838d:69b0:dd25:f9c5
            mtu: 1280
            udp: true
            remote-dns-resolve: true
            dns:
              - 1.1.1.1
              - 2606:4700:4700::1111
            sni: consumer-masque.cloudflareclient.com
            uri: https://cloudflareaccess.com
        """

        let nodes = NCSubscriptionParser.parse(yaml)
        XCTAssertEqual(nodes.count, 1)
        let node = nodes[0]
        XCTAssertEqual(node.name, "WARP-MASQUE-HK")
        XCTAssertEqual(node.type, "masque")
        XCTAssertEqual(node.server, "162.159.198.1")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.fields["ip"]?.string, "172.16.0.2")
        XCTAssertEqual(node.fields["ipv6"]?.string, "2606:4700:110:875d:838d:69b0:dd25:f9c5")
        XCTAssertEqual(node.fields["mtu"]?.int, 1280)
        XCTAssertEqual(node.fields["udp"]?.bool, true)
        XCTAssertEqual(node.fields["sni"]?.string, "consumer-masque.cloudflareclient.com")
        XCTAssertEqual(node.fields["uri"]?.string, "https://cloudflareaccess.com")

        // Validate typed config mapping
        guard let cfg = NCMASQUE.Config(proxy: node) else {
            XCTFail("Failed to build NCMASQUE.Config from proxy")
            return
        }
        XCTAssertEqual(cfg.mode, .connectIP)
        XCTAssertEqual(cfg.dns.count, 2)
        XCTAssertEqual(cfg.remoteDnsResolve, true)

        // Validate NCSupport marks this fully supported
        let reason = NCSupport.unsupportedReason(node)
        // feat/nc-masque-warp: the placeholder keys here are not real P-256 keys → the WARP key check refuses the node.
        XCTAssertEqual(reason, NCMASQUEWarp.warpKeyInvalid, "\(String(describing: reason))")
    }

    func testShadowrocketMASQUEParsingAndEncoding() {
        let uri = "masque://162.159.198.2:4443?publicKey=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUB&privateKey=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIV&ip=172.16.0.3&dns=1.1.1.1%2C%208.8.8.8&udp=1&cc=bbr&flag=CDN#WARP-SG"

        guard let proxy = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse Shadowrocket masque:// URI")
            return
        }

        XCTAssertEqual(proxy.type, "masque")
        XCTAssertEqual(proxy.name, "WARP-SG")
        XCTAssertEqual(proxy.server, "162.159.198.2")
        XCTAssertEqual(proxy.port, 4443)
        XCTAssertEqual(proxy.fields["private-key"]?.string, "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIV")
        XCTAssertEqual(proxy.fields["public-key"]?.string, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUB")
        XCTAssertEqual(proxy.fields["ip"]?.string, "172.16.0.3")
        XCTAssertEqual(proxy.fields["udp"]?.bool, true)
        XCTAssertEqual(proxy.fields["congestion-controller"]?.string, "bbr")
        XCTAssertEqual(proxy.fields["flag"]?.string, "CDN")

        // WARP key pair = CONNECT-IP: parsed; placeholder keys → refused by the WARP key check (feat/nc-masque-warp)
        XCTAssertEqual(NCSupport.unsupportedReason(proxy), NCMASQUEWarp.warpKeyInvalid)

        // Round-trip encode to share link
        do {
            let encoded = try NCShareLink.encode(proxy)
            XCTAssertTrue(encoded.hasPrefix("masque://162.159.198.2:4443"))
            XCTAssertTrue(encoded.contains("publicKey=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUB"))
            XCTAssertTrue(encoded.contains("privateKey=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIV"))
            XCTAssertTrue(encoded.contains("#WARP-SG"))

            // Parse back
            let reParsed = NCSubscriptionParser.parseURI(encoded)
            XCTAssertNotNil(reParsed)
            XCTAssertEqual(reParsed?.name, proxy.name)
            XCTAssertEqual(reParsed?.server, proxy.server)
            XCTAssertEqual(reParsed?.port, proxy.port)
        } catch {
            XCTFail("Share link encoding failed: \(error)")
        }
    }

    func testShadowrocketBracketedIPv6URI() {
        let uri = "masque://[2606:4700:103::1]:8443?publicKey=PUBKEY&privateKey=PRIVKEY&ip=172.16.0.2&ipv6=2606:4700:110:875d::1#WARP-IPv6"
        guard let p = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("Failed to parse IPv6 masque:// URI")
            return
        }
        XCTAssertEqual(p.server, "2606:4700:103::1")
        XCTAssertEqual(p.port, 8443)
        XCTAssertEqual(p.name, "WARP-IPv6")
        XCTAssertEqual(p.fields["ipv6"]?.string, "2606:4700:110:875d::1")
    }

    func testSurgeConfMASQUELine() {
        let conf = """
        [Proxy]
        Surge-MASQUE = masque, masque.example.com, 443, username=alice, password=secret123, udp-relay=true
        """
        let proxies = NCSubscriptionParser.parse(conf)
        XCTAssertEqual(proxies.count, 1)
        let p = proxies[0]
        XCTAssertEqual(p.name, "Surge-MASQUE")
        XCTAssertEqual(p.type, "masque")
        XCTAssertEqual(p.server, "masque.example.com")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.fields["username"]?.string, "alice")
        XCTAssertEqual(p.fields["password"]?.string, "secret123")
        XCTAssertEqual(p.fields["udp"]?.bool, true)
        XCTAssertNil(NCSupport.unsupportedReason(p))
    }

    // MARK: - Negative Tests

    func testMalformedURIs() {
        // Missing port
        XCTAssertNil(NCSubscriptionParser.parseURI("masque://1.1.1.1"))
        // Missing host
        XCTAssertNil(NCSubscriptionParser.parseURI("masque://:443"))
        // Wrong scheme
        XCTAssertNil(NCMASQUE.parseShadowrocket("https://1.1.1.1:443"))
    }

    func testMissingRequiredFields() {
        // Node with server/port but neither keys nor credentials
        let emptyProxy = NCProxy(name: "Empty", type: "masque", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
        ])
        let r1 = NCSupport.unsupportedReason(emptyProxy)
        XCTAssertEqual(r1, "MASQUE 缺少 private-key / public-key 或认证凭据")

        // Missing server/port
        let noServer = NCProxy(name: "NoServer", type: "masque", fields: [
            "private-key": .string("PRIV"),
            "public-key": .string("PUB"),
            "ip": .string("172.16.0.2"),
        ])
        let r2 = NCSupport.unsupportedReason(noServer)
        XCTAssertEqual(r2, "MASQUE 缺少 server / port")
    }

    // MARK: - Unsupported Field Marking Tests

    func testUnsupportedFieldMarkers() {
        // 1. Missing IP/IPv6 in CONNECT-IP mode
        let noIP = NCProxy(name: "NoIP", type: "masque", fields: [
            "server": .string("1.1.1.1"),
            "port": .number(443),
            "private-key": .string("PRIV"),
            "public-key": .string("PUB"),
        ])
        XCTAssertEqual(NCSupport.unsupportedReason(noIP), "MASQUE CONNECT-IP 缺少 ip / ipv6")

        // 2. Unsupported network (e.g. grpc)
        let badNet = NCProxy(name: "BadNet", type: "masque", fields: [
            "server": .string("1.1.1.1"),
            "port": .number(443),
            "private-key": .string("PRIV"),
            "public-key": .string("PUB"),
            "ip": .string("172.16.0.2"),
            "network": .string("grpc"),
        ])
        XCTAssertEqual(NCSupport.unsupportedReason(badNet), "MASQUE network grpc 尚未接入（仅支持 h3 / quic / h2 / h3-l4proxy）")

        // 3. Unsupported ip-stack (gvisor)
        let gvisor = NCProxy(name: "GVisor", type: "masque", fields: [
            "server": .string("1.1.1.1"),
            "port": .number(443),
            "private-key": .string("PRIV"),
            "public-key": .string("PUB"),
            "ip": .string("172.16.0.2"),
            "ip-stack": .string("gvisor"),
        ])
        XCTAssertEqual(NCSupport.unsupportedReason(gvisor), "MASQUE ip-stack gvisor 尚未接入（仅支持 lwip / system）")

        // 4. Unsupported port-hopping
        let hopping = NCProxy(name: "Hopping", type: "masque", fields: [
            "server": .string("1.1.1.1"),
            "port": .number(443),
            "username": .string("user"),
            "password": .string("pass"),
            "port-hopping": .string("1000-2000"),
        ])
        XCTAssertEqual(NCSupport.unsupportedReason(hopping), "MASQUE port-hopping 尚未接入")

        // 5. Quantumult X import line: must be marked explicitly unsupported
        let qxLine = "masque=1.2.3.4:443, tag=QX-Masque"
        var report = NCImportReport()
        let qxNode = NCQXImport.buildQXNode(line: qxLine, report: &report)
        XCTAssertNotNil(qxNode)
        XCTAssertEqual(qxNode?.type, "masque")
        XCTAssertEqual(qxNode?.fields["unsupported"]?.string, "Quantumult X 不支持 MASQUE 协议")
        XCTAssertEqual(NCSupport.unsupportedReason(qxNode!), "Quantumult X 不支持 MASQUE 协议")
        XCTAssertTrue(report.warnings.contains { $0.contains("Quantumult X 中无公开规范") })
    }

    // MARK: - Wire Primitives & Framing Tests

    func testVarintCodec() {
        let testValues: [UInt64] = [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903]
        for val in testValues {
            let encoded = NCMASQUE.varintEncode(val)
            let decoded = NCMASQUE.varintDecode(encoded)
            XCTAssertNotNil(decoded, "Failed to decode varint for \(val)")
            XCTAssertEqual(decoded?.value, val)
            XCTAssertEqual(decoded?.length, encoded.count)
        }
    }

    func testHTTP3DatagramCodec() {
        let streamID: UInt64 = 8 // stream 8 -> quarter stream ID = 2
        let contextID: UInt64 = 0
        let payload = Data("PING-UDP-PACKET".utf8)

        let datagram = NCMASQUE.encodeH3Datagram(streamID: streamID, contextID: contextID, payload: payload)

        // First byte: quarter stream ID = 2 (fits in 1 byte: 0x02)
        XCTAssertEqual(datagram[0], 0x02)
        // Second byte: context ID = 0 (0x00)
        XCTAssertEqual(datagram[1], 0x00)

        guard let result = NCMASQUE.decodeH3Datagram(datagram) else {
            XCTFail("Failed to decode H3 datagram")
            return
        }
        XCTAssertEqual(result.streamID, streamID)
        XCTAssertEqual(result.contextID, contextID)
        XCTAssertEqual(result.payload, payload)
    }

    func testCapsuleProtocolCodec() {
        var parser = NCMASQUE.CapsuleParser()
        let datagramPayload = Data([0x00]) + Data("TEST-DATAGRAM-INSIDE-CAPSULE".utf8)
        let capWire = NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeDatagram, value: datagramPayload)

        // Feed in two chunks to test stream reassembly
        let mid = capWire.count / 2
        let chunk1 = Data(capWire[0..<mid])
        let chunk2 = Data(capWire[mid...])

        let res1 = parser.feed(chunk1)
        XCTAssertEqual(res1.count, 0)
        let res2 = parser.feed(chunk2)
        XCTAssertEqual(res2.count, 1)
        XCTAssertEqual(res2[0].type, NCMASQUE.capsuleTypeDatagram)
        XCTAssertEqual(res2[0].value, datagramPayload)
    }

    func testRFC9484Capsules() {
        // 1. AssignedAddress
        let v4Addr = Data([192, 0, 2, 10])
        let assigned = NCMASQUE.AssignedAddress(requestID: 1, ipVersion: 4, address: v4Addr, prefixLength: 32)
        let wire = assigned.encode()
        let decodedList = NCMASQUE.AssignedAddress.decodeSequence(wire)
        XCTAssertNotNil(decodedList)
        XCTAssertEqual(decodedList?.count, 1)
        XCTAssertEqual(decodedList?[0], assigned)

        // 2. RequestedAddress
        let req = NCMASQUE.RequestedAddress(requestID: 42, ipVersion: 4, address: Data([0, 0, 0, 0]), prefixLength: 32)
        let reqWire = req.encode()
        let reqDecoded = NCMASQUE.RequestedAddress.decodeSequence(reqWire)
        XCTAssertNotNil(reqDecoded)
        XCTAssertEqual(reqDecoded?.count, 1)
        XCTAssertEqual(reqDecoded?[0], req)

        // 3. RouteAdvertisement
        let route = NCMASQUE.RouteAdvertisement(
            ipVersion: 4,
            startIP: Data([0, 0, 0, 0]),
            endIP: Data([255, 255, 255, 255]),
            ipProtocol: 0
        )
        let routeWire = route.encode()
        let routeDecoded = NCMASQUE.RouteAdvertisement.decodeSequence(routeWire)
        XCTAssertNotNil(routeDecoded)
        XCTAssertEqual(routeDecoded?.count, 1)
        XCTAssertEqual(routeDecoded?[0], route)
    }

    func testHTTP3SettingsFrameAndQPACKRequest() {
        // Test SETTINGS frame
        let settings = NCMASQUE.http3SettingsFrame()
        XCTAssertEqual(settings[0], 0x04) // Type: SETTINGS

        // Test QPACK Extended CONNECT request encoding
        let qpack = NCMASQUE.qpackEncodeExtendedConnect(
            protocolValue: "connect-ip",
            authority: "cloudflareaccess.com",
            path: "/.well-known/masque/ip/*/*/",
            extraHeaders: [("user-agent", "NativeCore")]
        )
        // Must start with 2-byte QPACK prefix (0x00 0x00)
        XCTAssertEqual(qpack[0], 0x00)
        XCTAssertEqual(qpack[1], 0x00)
        // Must contain connect-ip
        XCTAssertTrue(String(data: qpack, encoding: .isoLatin1)?.contains("connect-ip") == true)
        XCTAssertTrue(String(data: qpack, encoding: .isoLatin1)?.contains("capsule-protocol") == true)
    }

    // MARK: - S2 Data Plane & Boundary Tests

    func testDatagramCodecBoundaries() {
        // 1. Empty data
        XCTAssertNil(NCMASQUE.decodeH3Datagram(Data()))

        // 2. Truncated Quarter Stream ID (declared 2 bytes but only 1 byte present)
        let truncatedSID = Data([0x40])
        XCTAssertNil(NCMASQUE.decodeH3Datagram(truncatedSID))

        // 3. Truncated Context ID (valid SID but incomplete context ID)
        let truncatedCtx = Data([0x00, 0x80])
        XCTAssertNil(NCMASQUE.decodeH3Datagram(truncatedCtx))

        // 4. Zero payload datagram (valid header, empty payload)
        let emptyPayloadWire = NCMASQUE.encodeH3Datagram(streamID: 4, contextID: 0, payload: Data())
        let decodedEmpty = NCMASQUE.decodeH3Datagram(emptyPayloadWire)
        XCTAssertNotNil(decodedEmpty)
        XCTAssertEqual(decodedEmpty?.streamID, 4)
        XCTAssertEqual(decodedEmpty?.contextID, 0)
        XCTAssertEqual(decodedEmpty?.payload, Data())

        // 5. Multi-byte varint stream ID (e.g. streamID 1024 -> quarterStreamID 256)
        let largeSID: UInt64 = 1024
        let largeWire = NCMASQUE.encodeH3Datagram(streamID: largeSID, contextID: 1, payload: Data("BOUNDARY".utf8))
        let decodedLarge = NCMASQUE.decodeH3Datagram(largeWire)
        XCTAssertNotNil(decodedLarge)
        XCTAssertEqual(decodedLarge?.streamID, largeSID)
        XCTAssertEqual(decodedLarge?.contextID, 1)
        XCTAssertEqual(decodedLarge?.payload, Data("BOUNDARY".utf8))
    }

    func testCapsuleCodecBoundaries() {
        var parser = NCMASQUE.CapsuleParser()

        // 1. Truncated header (only 1 byte with 2-byte varint length prefix)
        let truncated = parser.feed(Data([0x40]))
        XCTAssertEqual(truncated.count, 0)

        // The parser keeps the partial header buffered (stream semantics); later cases use a fresh parser.
        parser = NCMASQUE.CapsuleParser()

        // 2. Unknown capsule type (RFC 9297 §3.2 requires endpoints to ignore unknown capsules)
        let unknownType: UInt64 = 0x12345
        let unknownPayload = Data([0xde, 0xad, 0xbe, 0xef])
        let unknownWire = NCMASQUE.encodeCapsule(type: unknownType, value: unknownPayload)
        let parsedUnknown = parser.feed(unknownWire)
        XCTAssertEqual(parsedUnknown.count, 1)
        XCTAssertEqual(parsedUnknown[0].type, unknownType)
        XCTAssertEqual(parsedUnknown[0].value, unknownPayload)

        // 3. Consecutive mixed capsules in a single chunk
        let cap1 = NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeDatagram, value: Data([0x00, 0x01, 0x02]))
        let cap2 = NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeAddressAssign, value: Data([0x03, 0x04]))
        parser = NCMASQUE.CapsuleParser()
        let batch = parser.feed(cap1 + cap2)
        XCTAssertEqual(batch.count, 2)
        XCTAssertEqual(batch[0].type, NCMASQUE.capsuleTypeDatagram)
        XCTAssertEqual(batch[1].type, NCMASQUE.capsuleTypeAddressAssign)
    }

    func testNegotiationFailurePaths() {
        // 1. QPACK response with non-2xx status (e.g. 403 Forbidden: static index 68)
        var qpack403 = Data([0x00, 0x00]) // QPACK section prefix
        // Indexed static field line 1 T iiiiii: index 68 (:status 403) exceeds the 6-bit prefix (63),
        // so it is 0xFF followed by the continuation 68 - 63 = 5 (RFC 9204 §4.5.2, RFC 7541 §5.1).
        qpack403.append(contentsOf: [0xFF, 0x05])
        let fields = NCMASQUE.qpackDecodeFieldSection(qpack403)
        XCTAssertNotNil(fields)
        let status = fields?.first(where: { $0.name == ":status" })?.value
        XCTAssertEqual(status, "403")

        // 2. Malformed QPACK field section (missing prefix / out of bounds)
        let malformed = Data([0xff, 0xff])
        XCTAssertNil(NCMASQUE.qpackDecodeFieldSection(malformed))
    }

    func testURITemplateExpansion() {
        // 1. Standard RFC 9298 template
        let tmpl1 = "/.well-known/masque/udp/{target_host}/{target_port}/"
        let t1 = NCTarget(host: "1.1.1.1", port: 53)
        let res1 = NCMASQUE.expandURITemplate(tmpl1, target: t1)
        XCTAssertEqual(res1, "/.well-known/masque/udp/1.1.1.1/53/")

        // 2. Absolute URL template
        let tmpl2 = "https://127.0.0.1:18012/.well-known/masque/udp/{target_host}/{target_port}/"
        let t2 = NCTarget(host: "127.0.0.1", port: 18081)
        let res2 = NCMASQUE.expandURITemplate(tmpl2, target: t2)
        XCTAssertEqual(res2, "/.well-known/masque/udp/127.0.0.1/18081/")

        // 3. IPv6 target: RFC 6570 simple expansion percent-encodes ":" (no brackets, RFC 9298 §2)
        let tmpl3 = "/.well-known/masque/udp/{target_host}/{target_port}/"
        let t3 = NCTarget(host: "2606:4700::1", port: 53)
        let res3 = NCMASQUE.expandURITemplate(tmpl3, target: t3)
        XCTAssertEqual(res3, "/.well-known/masque/udp/2606%3A4700%3A%3A1/53/")

        // 4. Absolute template keeps its trailing slash (URL.path dropped it → masque-go 307)
        let res4 = NCMASQUE.expandURITemplate("https://proxy.example:443/masque?h={target_host}&p={target_port}", target: t1)
        XCTAssertEqual(res4, "/masque?h=1.1.1.1&p=53")
    }

    func testCredentialNodeIsConnectUDPAndTCPIsRefused() {
        let p = NCProxy(name: "surge-masque", type: "masque", fields: [
            "server": .string("masque.example.com"), "port": .number(443),
            "username": .string("alice"), "password": .string("pw"),
        ])
        XCTAssertEqual(NCMASQUE.Config(proxy: p)?.mode, .connectUDP)
        XCTAssertNil(NCSupport.unsupportedReason(p))
        let exp = expectation(description: "tcp refused")
        NCConnector.connect(target: NCTarget(host: "example.com", port: 443), proxy: p,
                            queue: DispatchQueue(label: "masque.tcp")) { stream, err in
            XCTAssertNil(stream)
            XCTAssertTrue("\(String(describing: err))".contains("UDP"), "\(String(describing: err))")
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }

    func testConnectIPModeRejectedAtConnector() {
        // CONNECT-IP mode (WARP MASQUE node) called through NCConnector.connect must fail explicitly
        let warpProxy = NCProxy(name: "WARP-Test", type: "masque", fields: [
            "server": .string("162.159.198.1"),
            "port": .number(443),
            "private-key": .string("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIV"),
            "public-key": .string("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUB"),
            "ip": .string("172.16.0.2"),
            "ipv6": .string("2606:4700::1"),
        ])
        let target = NCTarget(host: "1.1.1.1", port: 53)
        let exp = expectation(description: "reject connect-ip at connector")
        let queue = DispatchQueue(label: "nc.masque.test")

        NCConnector.connect(target: target, proxy: warpProxy, queue: queue) { stream, error in
            XCTAssertNil(stream)
            XCTAssertNotNil(error)
            let desc = error?.localizedDescription ?? ""
            // feat/nc-masque-warp: placeholder keys → the connector refuses with the WARP key error (no dial).
            XCTAssertTrue(desc.contains("WARP"), "Error must explain the WARP key problem: \(desc)")
            exp.fulfill()
        }

        wait(for: [exp], timeout: 5)
    }
}
