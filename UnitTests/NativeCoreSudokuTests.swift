import XCTest
import CryptoKit
@testable import Mihomo

final class NativeCoreSudokuTests: XCTestCase {

    // MARK: - Positive parsing tests

    func testClashYAMLSudokuParsing() {
        let yaml = """
        proxies:
          - name: "sudoku-meta"
            type: sudoku
            server: 1.2.3.4
            port: 443
            key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            aead-method: chacha20-poly1305
            padding-min: 2
            padding-max: 7
            table-type: prefer_ascii
            custom-table: xpxvvpvv
            enable-pure-downlink: false
            multiplex: off
            httpmask:
              disable: false
              mode: legacy
              tls: true
              host: "cdn.example.com"
              path-root: "aabbcc"
        """
        guard let nodes = NCSubscriptionParser.parseClashYAML(yaml), let node = nodes.first else {
            XCTFail("failed to parse Clash YAML")
            return
        }
        XCTAssertEqual(node.name, "sudoku-meta")
        XCTAssertEqual(node.type, "sudoku")
        XCTAssertEqual(node.server, "1.2.3.4")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.fields["key"]?.string, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        XCTAssertEqual(node.fields["aead-method"]?.string, "chacha20-poly1305")
        XCTAssertEqual(node.fields["padding-min"]?.int, 2)
        XCTAssertEqual(node.fields["padding-max"]?.int, 7)
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_ascii")
        XCTAssertEqual(node.fields["custom-table"]?.string, "xpxvvpvv")
        XCTAssertEqual(node.fields["enable-pure-downlink"]?.bool, false)
        XCTAssertEqual(node.fields["multiplex"]?.string, "off")

        let hm = node.fields["httpmask"]?.object
        XCTAssertEqual(hm?["mode"]?.string, "legacy")
        XCTAssertEqual(hm?["tls"]?.bool, true)
        XCTAssertEqual(hm?["host"]?.string, "cdn.example.com")
        XCTAssertEqual(hm?["path-root"]?.string, "aabbcc")

        // Valid node passes unsupportedReason check
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testShortLinkSudokuParsing() {
        // Build payload according to official SUDOKU-ASCII/sudoku short link format
        let payload: [String: Any] = [
            "n": "HK-Sudoku",
            "h": "2.3.4.5",
            "p": 8443,
            "k": "avail_private_key_hex_value",
            "a": "ascii",
            "e": "aes-128-gcm",
            "x": true, // packed downlink -> enable-pure-downlink = false
            "t": "xpxvvpvv",
            "hd": false,
            "hm": "stream",
            "ht": true,
            "hh": "edge.example.com",
            "hy": "prefix",
            "hx": "auto"
        ]
        let data = try! JSONSerialization.data(withJSONObject: payload)
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let uri = "sudoku://\(b64)"
        guard let node = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("failed to parse short link")
            return
        }
        XCTAssertEqual(node.name, "HK-Sudoku")
        XCTAssertEqual(node.type, "sudoku")
        XCTAssertEqual(node.server, "2.3.4.5")
        XCTAssertEqual(node.port, 8443)
        XCTAssertEqual(node.fields["key"]?.string, "avail_private_key_hex_value")
        XCTAssertEqual(node.fields["aead-method"]?.string, "aes-128-gcm")
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_ascii")
        XCTAssertEqual(node.fields["enable-pure-downlink"]?.bool, false)
        XCTAssertEqual(node.fields["custom-table"]?.string, "xpxvvpvv")
        XCTAssertEqual(node.fields["multiplex"]?.string, "auto")

        let hm = node.fields["httpmask"]?.object
        XCTAssertEqual(hm?["mode"]?.string, "stream")
        XCTAssertEqual(hm?["tls"]?.bool, true)
        XCTAssertEqual(hm?["host"]?.string, "edge.example.com")
        XCTAssertEqual(hm?["path-root"]?.string, "prefix")

        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testShortLinkRoundTrip() {
        let original = NCProxy(name: "RoundTrip-Node", type: "sudoku", fields: [
            "server": .string("5.6.7.8"),
            "port": .number(9090),
            "key": .string("master_public_key_hex"),
            "aead-method": .string("chacha20-poly1305"),
            "table-type": .string("prefer_entropy"),
            "enable-pure-downlink": .bool(true),
            "custom-table": .string("xpxvvpvv"),
            "multiplex": .string("off")
        ])

        guard let link = NCSudoku.buildShortLink(from: original) else {
            XCTFail("failed to build short link")
            return
        }
        XCTAssertTrue(link.hasPrefix("sudoku://"))

        guard let decoded = NCSubscriptionParser.parseURI(link) else {
            XCTFail("failed to parse back round-trip short link")
            return
        }
        XCTAssertEqual(decoded.name, "RoundTrip-Node")
        XCTAssertEqual(decoded.server, "5.6.7.8")
        XCTAssertEqual(decoded.port, 9090)
        XCTAssertEqual(decoded.fields["key"]?.string, "master_public_key_hex")
        XCTAssertEqual(decoded.fields["aead-method"]?.string, "chacha20-poly1305")
        XCTAssertEqual(decoded.fields["table-type"]?.string, "prefer_entropy")
        XCTAssertEqual(decoded.fields["enable-pure-downlink"]?.bool, true)
        XCTAssertEqual(decoded.fields["custom-table"]?.string, "xpxvvpvv")
        XCTAssertNil(NCSupport.unsupportedReason(decoded))
    }

    func testStandardURISudokuParsing() {
        let uri = "sudoku://secretkey123@198.51.100.1:443?aead=chacha20-poly1305&table-type=prefer_ascii&padding-min=4&padding-max=12#JP%20Sudoku"
        guard let node = NCSubscriptionParser.parseURI(uri) else {
            XCTFail("failed to parse standard URI")
            return
        }
        XCTAssertEqual(node.name, "JP Sudoku")
        XCTAssertEqual(node.type, "sudoku")
        XCTAssertEqual(node.server, "198.51.100.1")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.fields["key"]?.string, "secretkey123")
        XCTAssertEqual(node.fields["aead-method"]?.string, "chacha20-poly1305")
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_ascii")
        XCTAssertEqual(node.fields["padding-min"]?.int, 4)
        XCTAssertEqual(node.fields["padding-max"]?.int, 12)
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testSurgeConfSudokuParsing() {
        let line = "Sudoku-Surge = sudoku, 192.0.2.1, 443, key=confkey123, aead=chacha20-poly1305, table-type=prefer_ascii, padding-min=3, padding-max=10, custom-table=xpxvvpvv, enable-pure-downlink=true"
        guard let parsed = NCConfImport.parseNamedNodeLine(line) else {
            XCTFail("failed to parse named node line")
            return
        }
        var report = NCImportReport()
        guard let node = NCConfImport.buildSurgeLikeNode(name: parsed.name, positional: parsed.positional, kv: parsed.kv, order: parsed.order, report: &report) else {
            XCTFail("failed to build node")
            return
        }
        XCTAssertEqual(node.name, "Sudoku-Surge")
        XCTAssertEqual(node.type, "sudoku")
        XCTAssertEqual(node.server, "192.0.2.1")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.fields["key"]?.string, "confkey123")
        XCTAssertEqual(node.fields["aead-method"]?.string, "chacha20-poly1305")
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_ascii")
        XCTAssertEqual(node.fields["padding-min"]?.int, 3)
        XCTAssertEqual(node.fields["padding-max"]?.int, 10)
        XCTAssertEqual(node.fields["custom-table"]?.string, "xpxvvpvv")
        XCTAssertEqual(node.fields["enable-pure-downlink"]?.bool, true)
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testQuantumultXSudokuParsing() {
        let line = "sudoku=192.0.2.2:443, key=qxkey456, aead=chacha20-poly1305, table-type=prefer_entropy, tag=Sudoku-QX"
        var report = NCImportReport()
        guard let node = NCQXImport.buildQXNode(line: line, report: &report) else {
            XCTFail("failed to build QX node")
            return
        }
        XCTAssertEqual(node.name, "Sudoku-QX")
        XCTAssertEqual(node.type, "sudoku")
        XCTAssertEqual(node.server, "192.0.2.2")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.fields["key"]?.string, "qxkey456")
        XCTAssertEqual(node.fields["aead-method"]?.string, "chacha20-poly1305")
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_entropy")
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testSubscriptionBatchAndDedup() {
        let payload1 = try! JSONSerialization.data(withJSONObject: ["h": "1.1.1.1", "p": 443, "k": "key1", "n": "Node"])
            .base64EncodedString()
        let payload2 = try! JSONSerialization.data(withJSONObject: ["h": "1.1.1.2", "p": 443, "k": "key2", "n": "Node"])
            .base64EncodedString()
        let blob = """
        # Comments should be ignored
        sudoku://\(payload1)
        sudoku://\(payload2)
        """
        let nodes = NCSubscriptionParser.parse(blob)
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(nodes[0].name, "Node")
        XCTAssertEqual(nodes[1].name, "Node 2") // dedup suffix
        XCTAssertEqual(nodes[0].type, "sudoku")
        XCTAssertEqual(nodes[1].type, "sudoku")
    }

    // MARK: - Negative parsing tests

    func testNegativeMissingRequiredShortLinkFields() {
        // Missing key ('k')
        let noKey = try! JSONSerialization.data(withJSONObject: ["h": "1.2.3.4", "p": 443]).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(noKey)"))

        // Missing host ('h')
        let noHost = try! JSONSerialization.data(withJSONObject: ["k": "secret", "p": 443]).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(noHost)"))

        // Missing port ('p')
        let noPort = try! JSONSerialization.data(withJSONObject: ["h": "1.2.3.4", "k": "secret"]).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(noPort)"))

        // Invalid port (0)
        let zeroPort = try! JSONSerialization.data(withJSONObject: ["h": "1.2.3.4", "p": 0, "k": "secret"]).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(zeroPort)"))

        // Invalid port (70000 > 65535)
        let largePort = try! JSONSerialization.data(withJSONObject: ["h": "1.2.3.4", "p": 70000, "k": "secret"]).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(largePort)"))

        // Corrupted base64
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://!!not-valid-base64!!"))

        // Non-JSON valid base64
        let plainTextB64 = Data("just plain text".utf8).base64EncodedString()
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://\(plainTextB64)"))
    }

    func testNegativeMalformedStandardURI() {
        // Missing key (no userinfo before @)
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://@1.2.3.4:443"))

        // Missing port
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://key@1.2.3.4"))

        // Missing host
        XCTAssertNil(NCSubscriptionParser.parseURI("sudoku://key@:443"))
    }

    // MARK: - Unsupported field marker tests

    func testUnsupportedMissingKey() {
        let node = NCProxy(name: "MissingKey", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443)
        ])
        let reason = NCSupport.unsupportedReason(node)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("缺少 key") == true, "expected missing key message, got: \(reason ?? "")")
    }

    func testUnsupportedInvalidAEAD() {
        let node = NCProxy(name: "BadAEAD", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "aead-method": .string("des-ede3-cbc")
        ])
        let reason = NCSupport.unsupportedReason(node)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("不支持的 aead-method") == true, "expected bad aead message, got: \(reason ?? "")")
    }

    func testUnsupportedInvalidTableType() {
        let node = NCProxy(name: "BadTable", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "table-type": .string("custom_gaussian_noise")
        ])
        let reason = NCSupport.unsupportedReason(node)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("不支持的 table-type") == true, "expected bad table-type message, got: \(reason ?? "")")
    }

    func testUnsupportedInvalidPaddingRange() {
        // min > max
        let node1 = NCProxy(name: "InvertedPadding", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "padding-min": .number(20),
            "padding-max": .number(5)
        ])
        let reason1 = NCSupport.unsupportedReason(node1)
        XCTAssertNotNil(reason1)
        XCTAssertTrue(reason1?.contains("padding 范围无效") == true, "expected invalid padding message, got: \(reason1 ?? "")")

        // max > 100
        let node2 = NCProxy(name: "OutOfRangePadding", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "padding-min": .number(5),
            "padding-max": .number(120)
        ])
        let reason2 = NCSupport.unsupportedReason(node2)
        XCTAssertNotNil(reason2)
        XCTAssertTrue(reason2?.contains("padding 范围无效") == true, "expected invalid padding message, got: \(reason2 ?? "")")
    }

    func testUnsupportedInvalidCustomTable() {
        // Table not containing 2 x, 2 p, 4 v
        let node1 = NCProxy(name: "BadLettersTable", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "custom-table": .string("xxxxpppp")
        ])
        let reason1 = NCSupport.unsupportedReason(node1)
        XCTAssertNotNil(reason1)
        XCTAssertTrue(reason1?.contains("custom-table 无效") == true, "expected invalid custom-table message, got: \(reason1 ?? "")")

        // Table with wrong length (7 chars)
        let node2 = NCProxy(name: "ShortTable", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "custom-table": .string("xpxvvpv")
        ])
        let reason2 = NCSupport.unsupportedReason(node2)
        XCTAssertNotNil(reason2)
        XCTAssertTrue(reason2?.contains("custom-table 无效") == true, "expected invalid custom-table message, got: \(reason2 ?? "")")
    }

    func testUnsupportedInvalidHTTPMaskMode() {
        let node = NCProxy(name: "BadHTTPMask", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "httpmask": .object(["mode": .string("unsupported_ftp_mask")])
        ])
        let reason = NCSupport.unsupportedReason(node)
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("httpmask mode 不支持") == true, "expected unsupported httpmask mode, got: \(reason ?? "")")
    }

    func testUnsupportedServerSideFeaturesOnClient() {
        // Reverse proxy is server-driven exposure of services, unsupported on client outbound
        let node1 = NCProxy(name: "ReverseNode", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "reverse": .object(["client_id": .string("client-1")])
        ])
        let reason1 = NCSupport.unsupportedReason(node1)
        XCTAssertNotNil(reason1)
        XCTAssertTrue(reason1?.contains("reverse") == true, "expected reverse message, got: \(reason1 ?? "")")

        // Users whitelist is server-only
        let node2 = NCProxy(name: "UsersNode", type: "sudoku", fields: [
            "server": .string("1.2.3.4"),
            "port": .number(443),
            "key": .string("secret"),
            "users": .array([.object(["key": .string("hash1")])])
        ])
        let reason2 = NCSupport.unsupportedReason(node2)
        XCTAssertNotNil(reason2)
        XCTAssertTrue(reason2?.contains("users") == true, "expected users message, got: \(reason2 ?? "")")
    }

    func testConnectorDialFailsAgainstClosedPort() {
        // S2 wired the real dialer (commit 2041932), so a dial no longer returns
        // a deferred-unsupported marker — it must attempt the TCP dial and fail
        // against a closed port with a non-nil error and no stream.
        let proxy = NCProxy(name: "DialTest", type: "sudoku", fields: [
            "server": .string("127.0.0.1"),
            "port": .number(1),
            "key": .string("valid_secret")
        ])
        let exp = expectation(description: "dial fails against closed port")
        let target = NCTarget(host: "example.com", port: 80)
        NCConnector.connect(target: target, proxy: proxy, queue: .main) { stream, error in
            XCTAssertNil(stream)
            XCTAssertNotNil(error)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 10.0)
    }

    // MARK: - Key negotiation vectors (S2)

    private static let vectorKey64 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    private static let vectorKey64Other = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000"
    private static let vectorKey128 = "e2eac3d4c0036ceb028048417bf2bf7c213681e145603c38ec8bffadb2e40c014130de746760b7dc9b515545f47e29df255687fe3ee972c2c517264f6a37b60b"

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// user_hash = SHA256(private-key bytes)[:8] — the value the ClientHello
    /// carries and the official server logs / whitelists on
    /// (upstream internal/tunnel/kip.go kipUserHashFromPrivateKey).
    func testUserHashDerivationVectors() {
        // 128-hex split ("available") key → SHA256(decoded 64 bytes)[:8]
        XCTAssertEqual(self.hex(NCSudoku.deriveUserHash(from: Self.vectorKey128)), "5254fd3ed5acedc6")
        // 64-hex master scalar → SHA256(decoded 32 bytes)[:8]
        XCTAssertEqual(self.hex(NCSudoku.deriveUserHash(from: Self.vectorKey64)), "630dcd2966c43366")
        // non-hex string → SHA256(utf8 bytes)[:8]
        XCTAssertEqual(self.hex(NCSudoku.deriveUserHash(from: "nc-loop-sudoku-key")), "fe0a05dd746a650c")
    }

    /// The ECDH primitive the official handshake derives its session keys
    /// from (upstream internal/tunnel/session_keys.go x25519SharedSecret),
    /// pinned against RFC 7748 §6.1.
    func testX25519KeyAgreementRFC7748Vector() throws {
        let aliceSk = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: XCTUnwrap(NCSudoku.hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))
        let bobSk = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: XCTUnwrap(NCSudoku.hexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")))
        XCTAssertEqual(self.hex(aliceSk.publicKey.rawRepresentation),
                       "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        XCTAssertEqual(self.hex(bobSk.publicKey.rawRepresentation),
                       "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let ab = try aliceSk.sharedSecretFromKeyAgreement(with: bobSk.publicKey)
        let ba = try bobSk.sharedSecretFromKeyAgreement(with: aliceSk.publicKey)
        let want = XCTUnwrap(NCSudoku.hexDecode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
        XCTAssertEqual(ab.withUnsafeBytes { Data($0) }, want)
        XCTAssertEqual(ba.withUnsafeBytes { Data($0) }, want)
    }

    /// ClientHello wire bytes: KIP frame ("kip" + 0x01 + u16 BE len) over the
    /// 68-byte payload timestamp(8 BE) ‖ user_hash(8) ‖ nonce(16) ‖ pub(32) ‖
    /// features(4=0) — upstream kip.go EncodePayload without the optional
    /// table hint.
    func testClientHelloLayoutBytes() {
        let nonce = Data((0..<16).map { UInt8($0) })
        let pub = Data((0..<32).map { UInt8(0x40 + $0) })
        let frame = NCSudokuKIP.buildClientHello(key: Self.vectorKey64, nonce: nonce, clientPub: pub)
        XCTAssertEqual(frame.count, 6 + 68)
        XCTAssertEqual(frame.prefix(3), Data("kip".utf8))
        XCTAssertEqual(frame[frame.startIndex + 3], 0x01)
        XCTAssertEqual((Int(frame[frame.startIndex + 4]) << 8) | Int(frame[frame.startIndex + 5]), 68)

        let s = frame.startIndex
        var ts: UInt64 = 0
        for i in 6..<14 { ts = (ts << 8) | UInt64(frame[s + i]) }
        XCTAssertTrue(abs(Double(ts) - Date().timeIntervalSince1970) < 5, "timestamp must be unix seconds BE")
        XCTAssertEqual(frame.subdata(in: s + 14 ..< s + 22), NCSudoku.deriveUserHash(from: Self.vectorKey64))
        XCTAssertEqual(frame.subdata(in: s + 22 ..< s + 38), nonce)
        XCTAssertEqual(frame.subdata(in: s + 38 ..< s + 70), pub)
        XCTAssertEqual(frame.subdata(in: s + 70 ..< s + 74), Data([0x00, 0x00, 0x00, 0x00]))
    }

    /// ServerHello: nonce(16) ‖ server_pub(32) ‖ selected_features(4 BE);
    /// rejects a nonce mismatch and a short payload.
    func testServerHelloParseAcceptsValidAndRejects() throws {
        let nonce = Data(repeating: 0x2a, count: 16)
        var payload = nonce
        payload.append(contentsOf: (0..<32).map { UInt8(0x50 + $0) })
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x07])
        let (serverPub, features) = try NCSudokuKIP.parseServerHello(payload: payload, expectedNonce: nonce)
        XCTAssertEqual(serverPub, Data((0..<32).map { UInt8(0x50 + $0) }))
        XCTAssertEqual(features, 7)

        XCTAssertThrowsError(try NCSudokuKIP.parseServerHello(payload: payload,
                                                              expectedNonce: Data(repeating: 0x2b, count: 16)))
        XCTAssertThrowsError(try NCSudokuKIP.parseServerHello(payload: Data(payload.prefix(51)), expectedNonce: nonce))
    }

    func testKIPFrameRoundTripAndBadMagic() {
        let payload = Data([0x01, 0x02, 0x03])
        let frame = NCSudokuKIP.buildMessage(type: .openTCP, payload: payload)
        let unwrapped = NCSudokuKIP.unwrapMessage(from: frame)
        XCTAssertNotNil(unwrapped)
        XCTAssertEqual(unwrapped?.type, .openTCP)
        XCTAssertEqual(unwrapped?.payload, payload)
        XCTAssertEqual(unwrapped?.consumed, frame.count)

        var bad = frame
        bad[bad.startIndex + 1] = 0x78 // "kip" → "kxp"
        XCTAssertNil(NCSudokuKIP.unwrapMessage(from: bad))
    }

    /// OpenTCP carries a SOCKS5-style address: atyp 0x03 + u8 len + domain +
    /// u16 BE port, or atyp 0x01 + 4 raw bytes + port.
    func testOpenTCPWireEncoding() {
        let domain = NCSudokuKIP.buildOpenTCP(target: NCTarget(host: "example.com", port: 443))
        XCTAssertEqual(domain.count, 6 + 1 + 1 + 11 + 2)
        XCTAssertEqual(domain[domain.startIndex + 3], 0x10)
        XCTAssertEqual(domain[domain.startIndex + 6], 0x03)
        XCTAssertEqual(domain[domain.startIndex + 7], 11)
        XCTAssertEqual(domain.subdata(in: domain.startIndex + 8 ..< domain.startIndex + 19), Data("example.com".utf8))
        XCTAssertEqual(domain.subdata(in: domain.startIndex + 19 ..< domain.startIndex + 21), Data([0x01, 0xbb]))

        let v4 = NCSudokuKIP.buildOpenTCP(target: NCTarget(host: "127.0.0.1", port: 80))
        XCTAssertEqual(v4.count, 6 + 1 + 4 + 2)
        XCTAssertEqual(v4[v4.startIndex + 6], 0x01)
        XCTAssertEqual(v4.subdata(in: v4.startIndex + 7 ..< v4.startIndex + 11), Data([127, 0, 0, 1]))
        XCTAssertEqual(v4.subdata(in: v4.startIndex + 11 ..< v4.startIndex + 13), Data([0x00, 0x50]))
    }

    // MARK: - Codec boundaries (S2)

    private func makeCodec(_ table: NCSudoku.TableType = .preferEntropy,
                           key: String = NativeCoreSudokuTests.vectorKey64,
                           custom: String? = nil) -> NCSudokuCodec {
        NCSudokuCodec(key: key, tableType: table, customTable: custom,
                      enablePureDownlink: true, paddingMin: 0, paddingMax: 0)
    }

    func testCodecRoundTripAllByteValuesAcrossLayouts() {
        let all = Data((0...255).map { UInt8($0) })
        let cases: [(String, NCSudoku.TableType, String?)] = [
            ("ascii", .preferASCII, nil),
            ("entropy", .preferEntropy, nil),
            ("custom", .preferEntropy, "vpxxvpvv"),
            ("directional", .upASCIIToDownEntropy, nil),
        ]
        for (name, table, custom) in cases {
            let codec = self.makeCodec(table, custom: custom)
            XCTAssertEqual(codec.decode(codec.encode(all)), all, "round trip failed for \(name)")
        }
    }

    func testASCIILayoutStaysPrintable() {
        let encoded = self.makeCodec(.preferASCII).encode(Data((0...255).map { UInt8($0) }))
        XCTAssertTrue(encoded.allSatisfy { $0 >= 0x20 && $0 <= 0x6f },
                      "prefer_ascii wire bytes must stay in the printable clue band")
    }

    /// Whole groups of non-clue bytes decode as padding and are dropped;
    /// a trailing 1–3 byte tail cannot form a group and is ignored.
    func testDecoderDropsWholeGroupPaddingAndPartialTail() {
        let codec = self.makeCodec(.preferEntropy)
        let wire = codec.encode(Data([0xab]))
        let garbage = Data(repeating: 0xff, count: 8) // non-one-hot v bits → padding in both groups
        let padded = wire + garbage + codec.encode(Data([0xcd]))
        XCTAssertEqual(codec.decode(padded), Data([0xab, 0xcd]))
        XCTAssertEqual(codec.decode(wire + Data([0x11, 0x22, 0x33])), Data([0xab]))
        XCTAssertTrue(codec.decode(Data([0x01, 0x02])).isEmpty)
        XCTAssertTrue(codec.decode(Data()).isEmpty)
    }

    func testXVPPackUnpackExhaustiveAndNonOneHot() {
        for r: UInt8 in 0..<4 {
            for c: UInt8 in 0..<4 {
                for v: UInt8 in 1...4 {
                    let packed = NCSudokuCodec.packXVP(row: r, col: c, val: v, pattern: "xpxvvpvv")
                    let unpacked = NCSudokuCodec.unpackXVP(byte: packed, pattern: "xpxvvpvv")
                    XCTAssertEqual(unpacked?.cell, r * 4 + c)
                    XCTAssertEqual(unpacked?.val, v)
                }
            }
        }
        // v field 0b0011 is not one-hot → must read as padding
        XCTAssertNil(NCSudokuCodec.unpackXVP(byte: 0b0000_0011, pattern: "xpxvvpvv"))
        // a pattern without exactly 2x/2p/4v cannot unpack at all
        XCTAssertNil(NCSudokuCodec.unpackXVP(byte: 0x00, pattern: "xxxxvvvv"))
    }

    func testCodecIsDeterministicAndKeySensitive() {
        let payload = Data((0..<64).map { UInt8(($0 * 3 + 1) & 0xff) })
        XCTAssertEqual(self.makeCodec().encode(payload), self.makeCodec().encode(payload),
                       "same key must produce the same table")
        let other = self.makeCodec(key: Self.vectorKey64Other).encode(payload)
        XCTAssertNotEqual(self.makeCodec().encode(payload), other,
                          "different keys must derive different tables")
        XCTAssertNotEqual(self.makeCodec(key: Self.vectorKey64Other).decode(other),
                          payload, "cross-key decode must not round-trip")
    }

    /// Pins the current contract: the encoder emits exactly 4 clue bytes per
    /// data byte and injects no padding yet (paddingMin/paddingMax unused).
    /// A future padding implementation must update this deliberately.
    func testEncoderEmitsNoPaddingYet() {
        let codec = NCSudokuCodec(key: Self.vectorKey64, tableType: .preferEntropy, customTable: nil,
                                  enablePureDownlink: true, paddingMin: 20, paddingMax: 40)
        let payload = Data(repeating: 0x5a, count: 64)
        XCTAssertEqual(codec.encode(payload).count, 64 * 4)
        XCTAssertEqual(codec.decode(codec.encode(payload)), payload)
    }

    // MARK: - AEAD record layer (S2)

    func testAEADRoundTripBothCiphers() throws {
        let plain = Data((0..<100).map { UInt8($0) })
        for method in [NCSudoku.AEADMethod.chacha20Poly1305, .aes128GCM] {
            let aead = NCSudokuAEAD(method: method, key: Self.vectorKey64)
            var buf = try aead.seal(plaintext: plain)
            XCTAssertEqual(try aead.unseal(from: &buf), plain, "\(method.rawValue) round trip")
            XCTAssertEqual(buf.count, 0, "\(method.rawValue): record must be consumed")
        }
    }

    /// Frame = body_len(u16 BE) ‖ header(12B = epoch u32 BE ‖ seq u64 BE) ‖
    /// ciphertext ‖ tag; first two records are epoch 0, seq 0 and 1.
    func testAEADFrameLayoutAndSeqProgression() throws {
        let aead = NCSudokuAEAD(method: .chacha20Poly1305, key: Self.vectorKey64)
        let r1 = try aead.seal(plaintext: Data([0x01]))
        let r2 = try aead.seal(plaintext: Data([0x02]))
        XCTAssertEqual((Int(r1[r1.startIndex]) << 8) | Int(r1[r1.startIndex + 1]), 29) // 12 + 1 + 16
        let h1 = Array(r1.subdata(in: r1.startIndex + 2 ..< r1.startIndex + 14))
        let h2 = Array(r2.subdata(in: r2.startIndex + 2 ..< r2.startIndex + 14))
        XCTAssertEqual(Array(h1.prefix(4)), [0, 0, 0, 0], "epoch starts at 0")
        XCTAssertEqual(Array(h1.suffix(8)), [0, 0, 0, 0, 0, 0, 0, 0], "first seq is 0")
        XCTAssertEqual(Array(h2.suffix(8)), [0, 0, 0, 0, 0, 0, 0, 1], "seq increments per record")
    }

    /// 错误密钥负例: records sealed under one key must never open under another.
    func testAEADWrongKeyRejected() throws {
        let plain = Data("wrong key must not open".utf8)
        for method in [NCSudoku.AEADMethod.chacha20Poly1305, .aes128GCM] {
            let aead = NCSudokuAEAD(method: method, key: Self.vectorKey64)
            let attacker = NCSudokuAEAD(method: method, key: Self.vectorKey64Other)
            var buf = try aead.seal(plaintext: plain)
            XCTAssertThrowsError(try attacker.unseal(from: &buf),
                                 "\(method.rawValue): different key must fail AEAD verification")
        }
    }

    func testAEADCorruptedCiphertextRejected() throws {
        let aead = NCSudokuAEAD(method: .chacha20Poly1305, key: Self.vectorKey64)
        var buf = try aead.seal(plaintext: Data(repeating: 0x33, count: 64))
        buf[buf.count - 5] ^= 0xff // inside the tag
        XCTAssertThrowsError(try aead.unseal(from: &buf), "flipped tag byte must fail verification")
    }

    func testAEADTruncatedRecordNeedsMoreBytes() throws {
        let aead = NCSudokuAEAD(method: .chacha20Poly1305, key: Self.vectorKey64)
        let full = try aead.seal(plaintext: Data(repeating: 0x09, count: 50))
        var short = Data(full.prefix(full.count - 5))
        XCTAssertNil(try aead.unseal(from: &short), "partial record must ask for more bytes, not throw")
        var headerOnly = Data(full.prefix(2 + 12 + 4))
        XCTAssertNil(try aead.unseal(from: &headerOnly))
    }

    func testAEADInvalidBodyLengthRejected() throws {
        let aead = NCSudokuAEAD(method: .chacha20Poly1305, key: Self.vectorKey64)
        var tiny = Data([0x00, 0x05]) + Data(repeating: 0x00, count: 5) // body_len 5 < 12 header
        XCTAssertThrowsError(try aead.unseal(from: &tiny))
        var noTag = Data([0x00, 0x0e]) + Data(repeating: 0x00, count: 14) // body lacks the 16-byte tag
        XCTAssertThrowsError(try aead.unseal(from: &noTag))
    }

    /// aead=none is framed plaintext (u16 BE length ‖ visible bytes) in this
    /// implementation — note the official RecordConn passes none-mode through
    /// unframed; see docs/nc-proto-sudoku.md.
    func testAEADNoneModeFramedPlaintext() throws {
        let aead = NCSudokuAEAD(method: .none, key: "anything")
        let plain = Data("no-cipher frame".utf8)
        let frame = try aead.seal(plaintext: plain)
        XCTAssertEqual((Int(frame[frame.startIndex]) << 8) | Int(frame[frame.startIndex + 1]), plain.count)
        XCTAssertEqual(frame.subdata(in: frame.startIndex + 2 ..< frame.startIndex + 2 + plain.count), plain)
        var buf = frame
        XCTAssertEqual(try aead.unseal(from: &buf), plain)
    }
}
