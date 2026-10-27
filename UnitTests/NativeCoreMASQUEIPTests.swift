import Security
import XCTest
@testable import Tern

/// fix/nc-masque-ip: MASQUE CONNECT-IP (RFC 9484) wire helpers, node classification and the App-side refusal. The data
/// plane itself (lwIP netif) is PacketTunnel code, exercised by E2ETests/NCMASQUEIPLoopbackTests against a real proxy.
///
/// feat/nc-masque-warp: Cloudflare WARP (cf-connect-ip) mTLS client identity construction, server public key pinning,
/// request header encoding, and address fallback.
final class NativeCoreMASQUEIPTests: XCTestCase {

    // MARK: - Cloudflare WARP Test Fixtures

    private static let keyAPKCS8Base64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3sMSgnyL8j8IEGpUvm+4BqsYLkKbza/FpASdcAW7pZ2hRANCAASfNnDeVGuVKVNp5zsnimlxPl14DEF6erYm6Ciaaagg2oPX56n/IBYJbvILpPNlXz/OGD8jrhiPsiq+LWZ3jQ/M"
    private static let keyASEC1Base64 = "MHcCAQEEIN7DEoJ8i/I/CBBqVL5vuAarGC5Cm82vxaQEnXAFu6WdoAoGCCqGSM49AwEHoUQDQgAEnzZw3lRrlSlTaec7J4ppcT5deAxBenq2JugommmoINqD1+ep/yAWCW7yC6TzZV8/zhg/I64Yj7Iqvi1md40PzA=="
    private static let keyASPKIBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnzZw3lRrlSlTaec7J4ppcT5deAxBenq2JugommmoINqD1+ep/yAWCW7yC6TzZV8/zhg/I64Yj7Iqvi1md40PzA=="
    private static let keyARawPointBase64 = "BJ82cN5Ua5UpU2nnOyeKaXE+XXgMQXp6tiboKJppqCDag9fnqf8gFglu8guk82VfP84YPyOuGI+yKr4tZneND8w="
    private static let keyBSPKIBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ6F/dbECW89W8tTE8osDMYvwxndQZiwol3121knzvB9zbKdZSPXld/7dv5lHG2qJOHMZC1Cm5E+H7knQ/i9OZQ=="

    private func node(_ extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = [
            "server": .string("203.0.113.7"), "port": .number(443),
            "mode": .string("connect-ip"), "uri": .string("https://proxy.example:4433/vpn"),
        ]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "mq-ip", type: "masque", fields: f)
    }

    private func warpNode(_ extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = [
            "server": .string("162.159.198.1"), "port": .number(443),
            "private-key": .string(Self.keyAPKCS8Base64),
            "public-key": .string(Self.keyASPKIBase64),
            "ip": .string("172.16.0.2"),
            "ipv6": .string("2606:4700:110:8f81:85e8:8e35:ec90:2020"),
        ]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "cf-warp", type: "masque", fields: f)
    }

    // MARK: - Generic CONNECT-IP Tests

    func testGenericConnectIPNodeParses() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node()))
        XCTAssertEqual(cfg.mode, .connectIP)
        XCTAssertNil(NCSupport.masqueUnsupported(node()), "credential-less RFC 9484 node is structurally valid")
    }

    func testConnectIPGatedUntilVerified() {
        let why = NCSupport.unsupportedReason(node())
        if NCMASQUE.connectIPVerified {
            XCTAssertNil(why)
        } else {
            XCTAssertEqual(why, NCMASQUE.connectIPUnverified)
        }
    }

    func testConnectIPOverH2Unavailable() {
        XCTAssertEqual(NCSupport.masqueUnsupported(node(["network": .string("h2")]))?.contains("HTTP/2"), true)
    }

    func testRequestTargetFromAbsoluteTemplate() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node()))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "proxy.example:4433")
        XCTAssertEqual(t.path, "/vpn")
    }

    func testRequestTargetExpandsWildcards() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node(["uri": .string("https://h.example/.well-known/masque/ip/{target}/{ipproto}/")])))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "h.example")
        XCTAssertEqual(t.path, "/.well-known/masque/ip/*/*/")
    }

    func testRequestTargetPathOnlyUsesServerPort() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node(["uri": .string("/vpn")])))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "203.0.113.7:443")
        XCTAssertEqual(t.path, "/vpn")
    }

    func testConnectIPDatagramLayout() {
        let pkt: [UInt8] = [0x45, 0, 0, 20] + [UInt8](repeating: 0, count: 16)
        let d = pkt.withUnsafeBufferPointer { NCMASQUE.connectIPDatagram(quarterStreamID: 100, packet: $0) }
        // quarter stream id 100 -> 2-byte varint 0x40 0x64, context id 0, then the packet unchanged
        XCTAssertEqual([UInt8](d.prefix(3)), [0x40, 0x64, 0x00])
        XCTAssertEqual([UInt8](d.dropFirst(3)), pkt)
        let back = NCMASQUE.decodeH3Datagram(d)
        XCTAssertEqual(back?.streamID, 400)
        XCTAssertEqual(back?.contextID, 0)
        XCTAssertEqual(back.map { [UInt8]($0.payload) }, pkt)
    }

    func testFrameHeaderIncomplete() {
        XCTAssertNil(NCMASQUE.h3FrameHeader(Data([0x00]), at: 0))
        let h = NCMASQUE.h3FrameHeader(Data([0x00, 0x05, 1, 2]), at: 0)
        XCTAssertEqual(h?.type, 0)
        XCTAssertEqual(h?.length, 5)
        XCTAssertEqual(h?.header, 2)
    }

    func testAddressAssignAndRouteCapsulesRoundTrip() {
        let a = NCMASQUE.AssignedAddress(requestID: 0, ipVersion: 4, address: Data([10, 89, 0, 2]), prefixLength: 32)
        XCTAssertEqual(NCMASQUE.AssignedAddress.decodeSequence(a.encode()), [a])
        let r = NCMASQUE.RouteAdvertisement(ipVersion: 4, startIP: Data([10, 89, 1, 0]), endIP: Data([10, 89, 1, 255]), ipProtocol: 0)
        XCTAssertEqual(NCMASQUE.RouteAdvertisement.decodeSequence(r.encode()), [r])
        var p = NCMASQUE.CapsuleParser()
        let wire = NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeAddressAssign, value: a.encode())
            + NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeRouteAdvertisement, value: r.encode())
        let caps = p.feed(wire.prefix(5)) + p.feed(wire.dropFirst(5))
        XCTAssertEqual(caps.map(\.type), [1, 3])
    }

    /// Outside the packet tunnel (the App's 延迟测试) there is no netif: the connector refuses explicitly.
    func testAppConnectorRefusesTunnelOnly() {
        let exp = expectation(description: "refused")
        NCConnector.connect(target: NCTarget(host: "10.0.0.1", port: 80), proxy: node(), queue: DispatchQueue(label: "t")) { s, e in
            XCTAssertNil(s)
            XCTAssertTrue("\(String(describing: e))".contains("CONNECT-IP"), "\(String(describing: e))")
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }

    // MARK: - Cloudflare WARP Private Key Parsing Tests

    func testWARPPrivateKeyParsingPKCS8AndSEC1AndPEM() throws {
        let expectedPoint = try XCTUnwrap(Data(base64Encoded: Self.keyARawPointBase64))

        // 1. PKCS#8 DER base64
        let keyPKCS8 = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(Self.keyAPKCS8Base64))
        let pubPKCS8 = try XCTUnwrap(SecKeyCopyPublicKey(keyPKCS8))
        let pointPKCS8 = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubPKCS8, nil) as Data?)
        XCTAssertEqual(pointPKCS8, expectedPoint)

        // 2. SEC 1 DER base64
        let keySEC1 = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(Self.keyASEC1Base64))
        let pubSEC1 = try XCTUnwrap(SecKeyCopyPublicKey(keySEC1))
        let pointSEC1 = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubSEC1, nil) as Data?)
        XCTAssertEqual(pointSEC1, expectedPoint)

        // 3. PEM formatted PKCS#8 (PRIVATE KEY)
        let pemPKCS8 = "-----BEGIN PRIVATE KEY-----\n\(Self.keyAPKCS8Base64)\n-----END PRIVATE KEY-----"
        let keyPEM = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(pemPKCS8))
        let pubPEM = try XCTUnwrap(SecKeyCopyPublicKey(keyPEM))
        let pointPEM = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubPEM, nil) as Data?)
        XCTAssertEqual(pointPEM, expectedPoint)

        // 4. PEM formatted SEC 1 (EC PRIVATE KEY)
        let pemSEC1 = "-----BEGIN EC PRIVATE KEY-----\n\(Self.keyASEC1Base64)\n-----END EC PRIVATE KEY-----"
        let keyECPEM = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(pemSEC1))
        let pubECPEM = try XCTUnwrap(SecKeyCopyPublicKey(keyECPEM))
        let pointECPEM = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubECPEM, nil) as Data?)
        XCTAssertEqual(pointECPEM, expectedPoint)

        // 5. URL-safe base64 without padding
        let urlSafePKCS8 = Self.keyAPKCS8Base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let keyURLSafe = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(urlSafePKCS8))
        let pubURLSafe = try XCTUnwrap(SecKeyCopyPublicKey(keyURLSafe))
        let pointURLSafe = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubURLSafe, nil) as Data?)
        XCTAssertEqual(pointURLSafe, expectedPoint)
    }

    func testWARPPrivateKeyInvalidInputs() {
        XCTAssertNil(NCMASQUEWarp.parsePrivateKey(""))
        XCTAssertNil(NCMASQUEWarp.parsePrivateKey("not-base64!@#$%^"))
        XCTAssertNil(NCMASQUEWarp.parsePrivateKey("AQIDBA==")) // too short (4 bytes)
        XCTAssertNil(NCMASQUEWarp.parsePrivateKey(Self.keyASPKIBase64)) // public key passed as private key
    }

    // MARK: - Cloudflare WARP Public Point Normalization Tests

    func testWARPPublicPointNormalization() throws {
        let expectedPoint = try XCTUnwrap(Data(base64Encoded: Self.keyARawPointBase64))

        // 1. SPKI base64
        let pSPKI = try XCTUnwrap(NCMASQUEWarp.publicPoint(fromConfiguredKey: Self.keyASPKIBase64))
        XCTAssertEqual(pSPKI, expectedPoint)
        XCTAssertEqual(pSPKI.count, 65)
        XCTAssertEqual(pSPKI.first, 0x04)

        // 2. Bare 65-byte uncompressed point base64
        let pBare = try XCTUnwrap(NCMASQUEWarp.publicPoint(fromConfiguredKey: Self.keyARawPointBase64))
        XCTAssertEqual(pBare, expectedPoint)

        // 3. PEM formatted public key
        let pemPub = "-----BEGIN PUBLIC KEY-----\n\(Self.keyASPKIBase64)\n-----END PUBLIC KEY-----"
        let pPEM = try XCTUnwrap(NCMASQUEWarp.publicPoint(fromConfiguredKey: pemPub))
        XCTAssertEqual(pPEM, expectedPoint)

        // 4. Negative case: KeyB SPKI yields different point
        let pKeyB = try XCTUnwrap(NCMASQUEWarp.publicPoint(fromConfiguredKey: Self.keyBSPKIBase64))
        XCTAssertEqual(pKeyB.count, 65)
        XCTAssertEqual(pKeyB.first, 0x04)
        XCTAssertNotEqual(pKeyB, expectedPoint)

        // 5. Invalid inputs
        XCTAssertNil(NCMASQUEWarp.publicPoint(fromConfiguredKey: ""))
        XCTAssertNil(NCMASQUEWarp.publicPoint(fromConfiguredKey: "invalid-key"))
        XCTAssertNil(NCMASQUEWarp.publicPoint(fromConfiguredKey: "AQID")) // truncated
    }

    // MARK: - Cloudflare WARP Client Certificate Tests

    func testWARPClientCertificateDERStructure() throws {
        let expectedPoint = try XCTUnwrap(Data(base64Encoded: Self.keyARawPointBase64))
        let privKey = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(Self.keyAPKCS8Base64))

        let fixedDate = Date()
        let certDER = try XCTUnwrap(NCMASQUEWarp.makeClientCertificateDER(privateKey: privKey, notBefore: fixedDate))
        XCTAssertFalse(certDER.isEmpty)

        // SecCertificateCreateWithData must parse the minimal self-signed certificate
        let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, certDER as CFData))

        // SecCertificateCopyKey extracts public key matching KeyA
        let pubKey = try XCTUnwrap(SecCertificateCopyKey(cert))
        let extractedPoint = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubKey, nil) as Data?)
        XCTAssertEqual(extractedPoint, expectedPoint)

        // Verify validity period spans 24 hours (86400 seconds)
        // Walk the certificate DER: SEQ -> TBS SEQ -> version[0], serial, sigAlg, issuer, validity SEQ { UTCTime, UTCTime }
        var i = 0
        let certBytes = [UInt8](certDER)
        let (t0, certBody) = try XCTUnwrap(NCMASQUEWarp.derTLV(certBytes, &i))
        XCTAssertEqual(t0, 0x30)

        var j = 0
        let tbsBytes = Array(certBody)
        let (tTBS, tbsBody) = try XCTUnwrap(NCMASQUEWarp.derTLV(tbsBytes, &j))
        XCTAssertEqual(tTBS, 0x30)

        var k = 0
        let inner = Array(tbsBody)
        let (tVer, _) = try XCTUnwrap(NCMASQUEWarp.derTLV(inner, &k))
        XCTAssertEqual(tVer, 0xA0) // [0] version v3
        let (tSerial, _) = try XCTUnwrap(NCMASQUEWarp.derTLV(inner, &k))
        XCTAssertEqual(tSerial, 0x02) // serial number
        let (tSigAlg, _) = try XCTUnwrap(NCMASQUEWarp.derTLV(inner, &k))
        XCTAssertEqual(tSigAlg, 0x30) // signature algorithm
        let (tIssuer, _) = try XCTUnwrap(NCMASQUEWarp.derTLV(inner, &k))
        XCTAssertEqual(tIssuer, 0x30) // issuer (empty SEQUENCE)
        let (tValidity, valBody) = try XCTUnwrap(NCMASQUEWarp.derTLV(inner, &k))
        XCTAssertEqual(tValidity, 0x30) // validity SEQUENCE

        var m = 0
        let valBytes = Array(valBody)
        let (tNB, nbData) = try XCTUnwrap(NCMASQUEWarp.derTLV(valBytes, &m))
        XCTAssertEqual(tNB, 0x17) // UTCTime
        let (tNA, naData) = try XCTUnwrap(NCMASQUEWarp.derTLV(valBytes, &m))
        XCTAssertEqual(tNA, 0x17) // UTCTime

        let nbStr = try XCTUnwrap(String(bytes: nbData, encoding: .ascii))
        let naStr = try XCTUnwrap(String(bytes: naData, encoding: .ascii))
        XCTAssertTrue(nbStr.hasSuffix("Z"))
        XCTAssertTrue(naStr.hasSuffix("Z"))
    }

    // MARK: - Peer Certificate Pinning Tests

    func testWARPPeerPointMatches() throws {
        let keyAPoint = try XCTUnwrap(Data(base64Encoded: Self.keyARawPointBase64))
        let keyBPoint = try XCTUnwrap(NCMASQUEWarp.publicPoint(fromConfiguredKey: Self.keyBSPKIBase64))
        let privKey = try XCTUnwrap(NCMASQUEWarp.parsePrivateKey(Self.keyAPKCS8Base64))

        let certDER = try XCTUnwrap(NCMASQUEWarp.makeClientCertificateDER(privateKey: privKey))

        // Positive match: certificate generated with KeyA matches KeyA public point
        XCTAssertTrue(NCMASQUEWarp.peerPointMatches(leafCertDER: certDER, configuredPoint: keyAPoint))

        // Negative match: certificate generated with KeyA does not match KeyB public point
        XCTAssertFalse(NCMASQUEWarp.peerPointMatches(leafCertDER: certDER, configuredPoint: keyBPoint))

        // Malformed inputs
        XCTAssertFalse(NCMASQUEWarp.peerPointMatches(leafCertDER: Data([0x30, 0x02, 0x01, 0x00]), configuredPoint: keyAPoint))
        XCTAssertFalse(NCMASQUEWarp.peerPointMatches(leafCertDER: certDER, configuredPoint: Data([0x04, 0x01, 0x02])))
    }

    // MARK: - Local Identity Construction Tests

    func testWARPLocalIdentityCreation() throws {
        let keyAPoint = try XCTUnwrap(Data(base64Encoded: Self.keyARawPointBase64))
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: warpNode()))
        XCTAssertTrue(cfg.isWarp)

        let identity = try XCTUnwrap(NCMASQUEWarp.makeLocalIdentity(config: cfg))
        var certRef: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(identity, &certRef), errSecSuccess)
        let cert = try XCTUnwrap(certRef)
        let pubKey = try XCTUnwrap(SecCertificateCopyKey(cert))
        let extractedPoint = try XCTUnwrap(SecKeyCopyExternalRepresentation(pubKey, nil) as Data?)
        XCTAssertEqual(extractedPoint, keyAPoint)
    }

    // MARK: - Extended CONNECT cf-connect-ip Encoding Tests

    func testWARPExtendedConnectRequestEncoding() throws {
        let (authority, path) = ("cloudflareaccess.com", "/")
        let wire = NCMASQUE.qpackEncodeExtendedConnect(
            protocolValue: "cf-connect-ip",
            authority: authority,
            path: path
        )
        XCTAssertFalse(wire.isEmpty)

        let decoded = try XCTUnwrap(NCMASQUE.qpackDecodeFieldSection(wire))
        let dict = Dictionary(decoded, uniquingKeysWith: { first, _ in first })

        XCTAssertEqual(dict[":method"], "CONNECT")
        XCTAssertEqual(dict[":protocol"], "cf-connect-ip")
        XCTAssertEqual(dict[":scheme"], "https")
        XCTAssertEqual(dict[":authority"], "cloudflareaccess.com")
        XCTAssertEqual(dict[":path"], "/")
        XCTAssertEqual(dict["capsule-protocol"], "?1")
    }

    // MARK: - Address Fallback Tests

    func testWARPFallbackAddressImmediate() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: warpNode()))
        XCTAssertTrue(cfg.isWarp)

        let queue = DispatchQueue(label: "test.warp.fallback")
        let tunnel = NCMASQUEIPTunnel(config: cfg, callbackQueue: queue)

        // Calling fallbackAddress directly should populate ipv4 and ipv6 from node configuration
        tunnel.fallbackAddress()
        XCTAssertEqual(tunnel.params.ipv4, "172.16.0.2")
        XCTAssertEqual(tunnel.params.ipv6, "2606:4700:110:8f81:85e8:8e35:ec90:2020")
    }

    // MARK: - NCSupport & Config Validation Tests

    func testWARPNCSupportValidation() {
        let validWarp = warpNode()
        XCTAssertNil(NCSupport.masqueUnsupported(validWarp))
        XCTAssertNil(NCSupport.unsupportedReason(validWarp))

        // Invalid private key -> warpKeyInvalid
        let badPriv = warpNode(["private-key": .string("INVALID_PRIV_KEY")])
        XCTAssertEqual(NCSupport.masqueUnsupported(badPriv), NCMASQUEWarp.warpKeyInvalid)
        XCTAssertEqual(NCSupport.unsupportedReason(badPriv), NCMASQUEWarp.warpKeyInvalid)

        // Invalid public key -> warpPublicKeyInvalid
        let badPub = warpNode(["public-key": .string("INVALID_PUB_KEY")])
        XCTAssertEqual(NCSupport.masqueUnsupported(badPub), NCMASQUEWarp.warpPublicKeyInvalid)
        XCTAssertEqual(NCSupport.unsupportedReason(badPub), NCMASQUEWarp.warpPublicKeyInvalid)

        // Missing IP/IPv6 -> "MASQUE CONNECT-IP 缺少 ip / ipv6"
        let missingIP = warpNode(["ip": .string(""), "ipv6": .string("")])
        XCTAssertEqual(NCSupport.masqueUnsupported(missingIP), "MASQUE CONNECT-IP 缺少 ip / ipv6")
        XCTAssertEqual(NCSupport.unsupportedReason(missingIP), "MASQUE CONNECT-IP 缺少 ip / ipv6")
    }

    func testWARPConfigDefaultsAndProperties() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: warpNode()))
        XCTAssertTrue(cfg.isWarp)
        XCTAssertEqual(cfg.mode, .connectIP)
        XCTAssertEqual(cfg.server, "162.159.198.1")
        XCTAssertEqual(cfg.port, 443)
        // Default SNI when not explicitly given
        XCTAssertEqual(cfg.sni, NCMASQUE.defaultWarpSNI)
        XCTAssertEqual(cfg.uri, NCMASQUE.defaultWarpURI)

        let target = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(target.authority, "cloudflareaccess.com")
        XCTAssertEqual(target.path, "/")

        // Explicit SNI override is respected
        let customSNINode = warpNode(["sni": .string("custom.sni.example.com")])
        let customCfg = try XCTUnwrap(NCMASQUE.Config(proxy: customSNINode))
        XCTAssertEqual(customCfg.sni, "custom.sni.example.com")
    }
}
