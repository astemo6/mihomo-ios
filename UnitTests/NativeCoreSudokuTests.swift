import XCTest
import CryptoKit
@testable import Tern

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
        XCTAssertNil(NCSupport.sudokuUnsupported(node))
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

        // Normalised into the canonical (mihomo) flat fields.
        XCTAssertEqual(node.fields["http-mask"]?.bool, true)
        XCTAssertEqual(node.fields["http-mask-mode"]?.string, "stream")
        XCTAssertEqual(node.fields["http-mask-tls"]?.bool, true)
        XCTAssertEqual(node.fields["http-mask-host"]?.string, "edge.example.com")
        XCTAssertEqual(node.fields["path-root"]?.string, "prefix")
        XCTAssertNil(node.fields["httpmask"])

        // A valid link, but the HTTP tunnel modes are not in this data plane: an explicit reason.
        XCTAssertTrue(NCSupport.sudokuUnsupported(node)?.contains("隧道") == true)
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
        XCTAssertNil(NCSupport.sudokuUnsupported(decoded))
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
        XCTAssertNil(NCSupport.sudokuUnsupported(node))
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
        XCTAssertNil(NCSupport.sudokuUnsupported(node))
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
        XCTAssertNil(NCSupport.sudokuUnsupported(node))
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

    // MARK: - fix/nc-sudoku-interop: availability + canonical fields
    // (wire vectors: NativeCoreSudokuWireTests; official-server echo: NativeCoreLoopbackTests)

    func testValidNodeIsAvailable() {
        let node = NCProxy(name: "sd", type: "sudoku", fields: [
            "server": .string("198.51.100.7"), "port": .number(443), "key": .string("k"),
        ])
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testTunnelModesAndSessionMuxAreExplicitMarkers() {
        func reason(_ extra: [String: NCJSONValue]) -> String? {
            var f: [String: NCJSONValue] = ["server": .string("1.2.3.4"), "port": .number(443), "key": .string("k")]
            for (k, v) in extra { f[k] = v }
            return NCSupport.unsupportedReason(NCProxy(name: "x", type: "sudoku", fields: f))
        }
        for mode in ["stream", "poll", "auto", "ws"] {
            XCTAssertTrue(reason(["http-mask-mode": .string(mode)])?.contains("隧道") == true, mode)
        }
        XCTAssertNil(reason(["http-mask-mode": .string("stream"), "http-mask": .bool(false)]), "mask off: mode unused")
        XCTAssertTrue(reason(["multiplex": .string("on")])?.contains("multiplex") == true)
        XCTAssertNil(reason(["multiplex": .string("auto")]))
        XCTAssertNil(reason(["aead-method": .string("none")]))
    }

    func testShortLinkDefaultsFollowOfficialClient() {
        // No "e": the official client runs aead none; padding 5–15; legacy mask on.
        let raw = try! JSONSerialization.data(withJSONObject: ["h": "1.2.3.4", "p": 443, "k": "kk"])
        let b64 = raw.base64EncodedString().replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        guard let node = NCSubscriptionParser.parseURI("sudoku://\(b64)") else { return XCTFail("parse") }
        XCTAssertEqual(node.fields["aead-method"]?.string, "none")
        XCTAssertEqual(node.fields["padding-min"]?.int, 5)
        XCTAssertEqual(node.fields["padding-max"]?.int, 15)
        XCTAssertEqual(node.fields["table-type"]?.string, "prefer_entropy")
        XCTAssertNil(node.fields["http-mask"])
        let o = NCSudoku.Options(proxy: node)
        XCTAssertEqual(o.aead, NCSudoku.AEADMethod.none)
        XCTAssertTrue(o.httpMaskEnabled)
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }

    func testSurgeLineNormalisesHTTPMaskFields() {
        let line = "SD = sudoku, 192.0.2.9, 8443, password=pw, ascii=up_ascii_down_entropy, httpmask-disable=true, custom-tables=xpxvvpvv|vxpvxvvp, multiplex=auto"
        guard let parsed = NCConfImport.parseNamedNodeLine(line) else { return XCTFail("line") }
        var report = NCImportReport()
        guard let node = NCConfImport.buildSurgeLikeNode(name: parsed.name, positional: parsed.positional, kv: parsed.kv,
                                                         order: parsed.order, report: &report) else { return XCTFail("node") }
        XCTAssertEqual(node.fields["key"]?.string, "pw")
        XCTAssertNil(node.fields["password"])
        XCTAssertEqual(node.fields["table-type"]?.string, "up_ascii_down_entropy")
        XCTAssertEqual(node.fields["http-mask"]?.bool, false)
        XCTAssertEqual(node.fields["custom-tables"]?.array?.compactMap { $0.string }, ["xpxvvpvv", "vxpvxvvp"])
        XCTAssertEqual(node.fields["multiplex"]?.string, "auto")
        XCTAssertNil(NCSupport.unsupportedReason(node))
    }
}
