import XCTest
@testable import Tern

/// Unit tests covering NCECHOpts models, sing-box TLS ECH configuration import,
/// default enable behaviour, and share link encoding/decoding parity across three ECH forms.
final class NativeCoreECHTests: XCTestCase {

    private let sampleBase64 = "AEb+DQBB/wAgACCH507x8z5u8T8P4q8ka8A9tQ9t8/wAgACCH507x8z5u8T8P4q8" // 64 chars = 48 bytes (was 65 with a stray "=": invalid base64)
    private let sampleBase64URL = "AEb-DQBB_wAgACCH507x8z5u8T8P4q8ka8A9tQ9t8_wAgACCH507x8z5u8T8P4q8"

    // MARK: - 1. NCECHOpts Decode / Encode Round-Trip

    func testECHOptsRoundTrip() throws {
        let opts = NCECHOpts(enable: true, config: sampleBase64, queryServerName: "dns.example.com")

        // toObject() -> NCECHOpts(object:) round-trip
        let obj = opts.toObject()
        let fromObj = try XCTUnwrap(NCECHOpts(object: obj))
        XCTAssertEqual(fromObj, opts)
        XCTAssertTrue(fromObj.enable)
        XCTAssertEqual(fromObj.config, sampleBase64)
        XCTAssertEqual(fromObj.queryServerName, "dns.example.com")

        // toDictionary() -> NCECHOpts(dictionary:) round-trip
        let dict = opts.toDictionary()
        let fromDict = try XCTUnwrap(NCECHOpts(dictionary: dict))
        XCTAssertEqual(fromDict, opts)
        XCTAssertTrue(fromDict.enable)
        XCTAssertEqual(fromDict.config, sampleBase64)
        XCTAssertEqual(fromDict.queryServerName, "dns.example.com")

        // Codable round-trip
        let encoded = try JSONEncoder().encode(opts)
        let decoded = try JSONDecoder().decode(NCECHOpts.self, from: encoded)
        XCTAssertEqual(decoded, opts)

        // configBytes and configBase64URL
        let bytes = try XCTUnwrap(opts.configBytes)
        XCTAssertEqual(bytes.count, 48)
        XCTAssertEqual(opts.configBase64URL, sampleBase64URL)

        // Minimal enabled opts (no config, no qsn)
        let minimal = NCECHOpts(enable: true)
        XCTAssertEqual(NCECHOpts(object: minimal.toObject()), minimal)
        XCTAssertEqual(NCECHOpts(dictionary: minimal.toDictionary()), minimal)

        // Disabled opts with config preserved
        let disabledWithConfig = NCECHOpts(enable: false, config: sampleBase64)
        XCTAssertEqual(NCECHOpts(object: disabledWithConfig.toObject()), disabledWithConfig)
        XCTAssertEqual(NCECHOpts(dictionary: disabledWithConfig.toDictionary()), disabledWithConfig)
    }

    // MARK: - 2. Enable Defaults to False

    func testEnableDefaultsToFalse() throws {
        // Struct init default
        let defaultOpts = NCECHOpts()
        XCTAssertFalse(defaultOpts.enable)
        XCTAssertNil(defaultOpts.config)
        XCTAssertNil(defaultOpts.queryServerName)

        // Missing enable key in object map defaults to false even when config/qsn are present
        let objWithConfig: [String: NCJSONValue] = ["config": .string(sampleBase64)]
        let fromObjConfig = try XCTUnwrap(NCECHOpts(object: objWithConfig))
        XCTAssertFalse(fromObjConfig.enable)
        XCTAssertEqual(fromObjConfig.config, sampleBase64)

        let objWithQSN: [String: NCJSONValue] = ["query-server-name": .string("dns.example.com")]
        let fromObjQSN = try XCTUnwrap(NCECHOpts(object: objWithQSN))
        XCTAssertFalse(fromObjQSN.enable)
        XCTAssertEqual(fromObjQSN.queryServerName, "dns.example.com")

        // Missing enable key in dictionary defaults to false
        let dictWithConfig: [String: Any] = ["config": sampleBase64]
        let fromDictConfig = try XCTUnwrap(NCECHOpts(dictionary: dictWithConfig))
        XCTAssertFalse(fromDictConfig.enable)
        XCTAssertEqual(fromDictConfig.config, sampleBase64)

        let dictWithQSN: [String: Any] = ["query-server-name": "dns.example.com"]
        let fromDictQSN = try XCTUnwrap(NCECHOpts(dictionary: dictWithQSN))
        XCTAssertFalse(fromDictQSN.enable)
        XCTAssertEqual(fromDictQSN.queryServerName, "dns.example.com")

        // Explicit true forms
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(object: ["enable": .bool(true)])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(object: ["enable": .string("true")])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(object: ["enable": .string("1")])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(object: ["enable": .number(1)])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(dictionary: ["enable": true])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(dictionary: ["enable": "true"])).enable)
        XCTAssertTrue(try XCTUnwrap(NCECHOpts(dictionary: ["enable": 1])).enable)

        // Explicit false forms
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(object: ["enable": .bool(false)])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(object: ["enable": .string("false")])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(object: ["enable": .string("0")])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(object: ["enable": .number(0)])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(dictionary: ["enable": false])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(dictionary: ["enable": "false"])).enable)
        XCTAssertFalse(try XCTUnwrap(NCECHOpts(dictionary: ["enable": 0])).enable)

        // URL query parser without explicit enable defaults to false
        let parsedNoEnable = try XCTUnwrap(NCECHOpts.parse(query: ["ech-config": sampleBase64URL]))
        XCTAssertFalse(parsedNoEnable.enable)
        XCTAssertEqual(parsedNoEnable.config, sampleBase64)

        // Proxy accessor reads enable == false when enable is omitted from fields
        let proxy = NCProxy(
            name: "test-node",
            type: "trojan",
            fields: ["ech-opts": .object(["config": .string(sampleBase64)])]
        )
        let proxyECH = try XCTUnwrap(proxy.echOpts)
        XCTAssertFalse(proxyECH.enable)
        XCTAssertEqual(proxyECH.config, sampleBase64)
    }

    // MARK: - 3. sing-box ECH Import (Multiline PEM & Bare Base64)

    func testSingBoxECHImport() throws {
        // Form 1a: Multiline PEM in sing-box outbound config as an array of lines
        let jsonPEMArray = """
        {
          "outbounds": [
            {
              "type": "trojan",
              "tag": "sb-pem-array",
              "server": "1.2.3.4",
              "server_port": 443,
              "password": "pass",
              "tls": {
                "enabled": true,
                "server_name": "example.com",
                "ech": {
                  "enabled": true,
                  "config": [
                    "-----BEGIN ECH CONFIGS-----",
                    "AEb+DQBB/wAgACCH507x8z5u8T8P4q8",
                    "ka8A9tQ9t8/wAgACCH507x8z5u8T8P4q8",
                    "-----END ECH CONFIGS-----"
                  ],
                  "query_server_name": "dns.example.com"
                }
              }
            }
          ]
        }
        """
        let nodes1 = try XCTUnwrap(NCSubscriptionParser.parse(jsonPEMArray))
        XCTAssertEqual(nodes1.count, 1)
        let node1 = nodes1[0]
        XCTAssertEqual(node1.name, "sb-pem-array")
        XCTAssertEqual(node1.type, "trojan")
        let ech1 = try XCTUnwrap(node1.echOpts)
        XCTAssertTrue(ech1.enable)
        XCTAssertEqual(ech1.config, sampleBase64)
        XCTAssertEqual(ech1.queryServerName, "dns.example.com")
        XCTAssertEqual(ech1.configBytes?.count, 48)

        // Form 1b: Multiline PEM in sing-box outbound config as a single string with newlines
        let jsonPEMString = """
        {
          "outbounds": [
            {
              "type": "trojan",
              "tag": "sb-pem-string",
              "server": "1.2.3.4",
              "server_port": 443,
              "password": "pass",
              "tls": {
                "enabled": true,
                "server_name": "example.com",
                "ech": {
                  "enabled": true,
                  "config": "-----BEGIN ECH CONFIGS-----\\nAEb+DQBB/wAgACCH507x8z5u8T8P4q8\\nka8A9tQ9t8/wAgACCH507x8z5u8T8P4q8\\n-----END ECH CONFIGS-----",
                  "query_server_name": "dns.example.com"
                }
              }
            }
          ]
        }
        """
        let nodes1b = try XCTUnwrap(NCSubscriptionParser.parse(jsonPEMString))
        XCTAssertEqual(nodes1b.count, 1)
        let ech1b = try XCTUnwrap(nodes1b[0].echOpts)
        XCTAssertTrue(ech1b.enable)
        XCTAssertEqual(ech1b.config, sampleBase64)
        XCTAssertEqual(ech1b.queryServerName, "dns.example.com")

        // Form 2a: Bare base64 in sing-box outbound config as a single string
        let jsonBareString = """
        {
          "outbounds": [
            {
              "type": "trojan",
              "tag": "sb-bare-string",
              "server": "1.2.3.4",
              "server_port": 443,
              "password": "pass",
              "tls": {
                "enabled": true,
                "server_name": "example.com",
                "ech": {
                  "enabled": true,
                  "config": "\(sampleBase64)",
                  "query_server_name": "dns.example.com"
                }
              }
            }
          ]
        }
        """
        let nodes2 = try XCTUnwrap(NCSubscriptionParser.parse(jsonBareString))
        XCTAssertEqual(nodes2.count, 1)
        let ech2 = try XCTUnwrap(nodes2[0].echOpts)
        XCTAssertTrue(ech2.enable)
        XCTAssertEqual(ech2.config, sampleBase64)
        XCTAssertEqual(ech2.queryServerName, "dns.example.com")

        // Form 2b: Bare base64 in sing-box outbound config as single-element array
        let jsonBareArray = """
        {
          "outbounds": [
            {
              "type": "trojan",
              "tag": "sb-bare-array",
              "server": "1.2.3.4",
              "server_port": 443,
              "password": "pass",
              "tls": {
                "enabled": true,
                "server_name": "example.com",
                "ech": {
                  "enabled": true,
                  "config": ["\(sampleBase64)"]
                }
              }
            }
          ]
        }
        """
        let nodes2b = try XCTUnwrap(NCSubscriptionParser.parse(jsonBareArray))
        XCTAssertEqual(nodes2b.count, 1)
        let ech2b = try XCTUnwrap(nodes2b[0].echOpts)
        XCTAssertTrue(ech2b.enable)
        XCTAssertEqual(ech2b.config, sampleBase64)
        XCTAssertNil(ech2b.queryServerName)

        // Helper normalizeSingBoxECHConfig validation
        let pemLines = [
            "-----BEGIN ECH CONFIGS-----",
            "AEb+DQBB/wAgACCH507x8z5u8T8P4q8",
            "ka8A9tQ9t8/wAgACCH507x8z5u8T8P4q8",
            "-----END ECH CONFIGS-----"
        ]
        XCTAssertEqual(NCSubscriptionParser.normalizeSingBoxECHConfig(pemLines), sampleBase64)
        XCTAssertEqual(NCSubscriptionParser.normalizeSingBoxECHConfig(sampleBase64), sampleBase64)
        // Corrupted base64 within PEM header fails validation and returns nil
        let corruptedPEM = [
            "-----BEGIN ECH CONFIGS-----",
            "!!!not-valid-base64???",
            "-----END ECH CONFIGS-----"
        ]
        XCTAssertNil(NCSubscriptionParser.normalizeSingBoxECHConfig(corruptedPEM))
    }

    // MARK: - 4. Share Link ech= Three Forms (Static / ech=1 / ech-qsn) Decode & Re-Encode

    func testShareLinkECHThreeForms() throws {
        // Form 1: Static ECH Config (ech=<base64url>)
        let uriStatic = "trojan://pass123@1.2.3.4:443?sni=example.com&ech=\(sampleBase64URL)#StaticECH"
        let nodeStatic = try XCTUnwrap(NCSubscriptionParser.parseURI(uriStatic))
        let echStatic = try XCTUnwrap(nodeStatic.echOpts)
        XCTAssertTrue(echStatic.enable)
        XCTAssertEqual(echStatic.config, sampleBase64)
        XCTAssertEqual(echStatic.configBase64URL, sampleBase64URL)
        XCTAssertNil(echStatic.queryServerName)

        let linkStatic = try NCShareLink.encode(nodeStatic)
        XCTAssertTrue(linkStatic.contains("ech=\(sampleBase64URL)"))
        let roundtripStatic = try XCTUnwrap(NCSubscriptionParser.parseURI(linkStatic))
        XCTAssertEqual(roundtripStatic.echOpts, nodeStatic.echOpts)

        // Form 2: Dynamic ECH (ech=1)
        let uriDynamic = "trojan://pass123@1.2.3.4:443?sni=example.com&ech=1#DynamicECH"
        let nodeDynamic = try XCTUnwrap(NCSubscriptionParser.parseURI(uriDynamic))
        let echDynamic = try XCTUnwrap(nodeDynamic.echOpts)
        XCTAssertTrue(echDynamic.enable)
        XCTAssertNil(echDynamic.config)
        XCTAssertNil(echDynamic.queryServerName)

        let linkDynamic = try NCShareLink.encode(nodeDynamic)
        XCTAssertTrue(linkDynamic.contains("ech=1"))
        let roundtripDynamic = try XCTUnwrap(NCSubscriptionParser.parseURI(linkDynamic))
        XCTAssertEqual(roundtripDynamic.echOpts, nodeDynamic.echOpts)

        // Form 3: ECH with Query Server Name (ech-qsn)
        // 3a: Dynamic ECH with QSN
        let uriQSN = "trojan://pass123@1.2.3.4:443?sni=example.com&ech=1&ech-qsn=dns.cloudflare.com#QSNECH"
        let nodeQSN = try XCTUnwrap(NCSubscriptionParser.parseURI(uriQSN))
        let echQSN = try XCTUnwrap(nodeQSN.echOpts)
        XCTAssertTrue(echQSN.enable)
        XCTAssertNil(echQSN.config)
        XCTAssertEqual(echQSN.queryServerName, "dns.cloudflare.com")

        let linkQSN = try NCShareLink.encode(nodeQSN)
        XCTAssertTrue(linkQSN.contains("ech=1"))
        XCTAssertTrue(linkQSN.contains("ech-qsn=dns.cloudflare.com"))
        let roundtripQSN = try XCTUnwrap(NCSubscriptionParser.parseURI(linkQSN))
        XCTAssertEqual(roundtripQSN.echOpts, nodeQSN.echOpts)

        // 3b: Static ECH with QSN
        let uriStaticQSN = "trojan://pass123@1.2.3.4:443?sni=example.com&ech=\(sampleBase64URL)&ech-qsn=dns.cloudflare.com#StaticQSNECH"
        let nodeStaticQSN = try XCTUnwrap(NCSubscriptionParser.parseURI(uriStaticQSN))
        let echStaticQSN = try XCTUnwrap(nodeStaticQSN.echOpts)
        XCTAssertTrue(echStaticQSN.enable)
        XCTAssertEqual(echStaticQSN.config, sampleBase64)
        XCTAssertEqual(echStaticQSN.queryServerName, "dns.cloudflare.com")

        let linkStaticQSN = try NCShareLink.encode(nodeStaticQSN)
        XCTAssertTrue(linkStaticQSN.contains("ech=\(sampleBase64URL)"))
        XCTAssertTrue(linkStaticQSN.contains("ech-qsn=dns.cloudflare.com"))
        let roundtripStaticQSN = try XCTUnwrap(NCSubscriptionParser.parseURI(linkStaticQSN))
        XCTAssertEqual(roundtripStaticQSN.echOpts, nodeStaticQSN.echOpts)

        // Cross-protocol: VLESS share link with ECH
        let vlessURI = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=tls&sni=example.com&ech=1&ech-qsn=dns.example.com#VLESSECH"
        let vlessNode = try XCTUnwrap(NCSubscriptionParser.parseURI(vlessURI))
        XCTAssertEqual(vlessNode.echOpts?.enable, true)
        XCTAssertEqual(vlessNode.echOpts?.queryServerName, "dns.example.com")
        let vlessLink = try NCShareLink.encode(vlessNode)
        XCTAssertTrue(vlessLink.contains("ech=1"))
        XCTAssertTrue(vlessLink.contains("ech-qsn=dns.example.com"))
        let vlessRoundtrip = try XCTUnwrap(NCSubscriptionParser.parseURI(vlessLink))
        XCTAssertEqual(vlessRoundtrip.echOpts, vlessNode.echOpts)
    }
}
