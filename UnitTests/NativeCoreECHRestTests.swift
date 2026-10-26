import XCTest
@testable import Tern

/// fix/nc-ech-rest: the integration layer of the ECH stack (#148–#153) — one NCSupport judgement, dynamic ECH
/// through the DNS lookup hook, transport-aware default ALPN, the system QUIC switch default, share-link `ech=0`.
final class NativeCoreECHRestTests: XCTestCase {

    /// tools/loopback/ech_config.pem (sing-box generate ech-keypair outer.localhost).
    private let echConfigBase64 = "AEr+DQBGAAAgACCb7RpDhFlwk1UfROZmEKsx55OeBngAV46wCg57TCInAQAMAAEAAQABAAIAAQADAA9vdXRlci5sb2NhbGhvc3QAAA=="

    private func proxy(_ type: String, _ fields: [String: NCJSONValue]) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string("example.com"), "port": .number(443)]
        for (k, v) in fields { f[k] = v }
        return NCProxy(name: "n-\(type)", type: type, fields: f)
    }

    private let echOn: NCJSONValue = .object(["enable": .bool(true)])

    override func tearDown() {
        NCConnector.echConfigLookup = nil
        super.tearDown()
    }

    // MARK: NCSupport

    func testSupportAcceptsECHOnNativeTLSAndQUICTypes() {
        for t in ["trojan", "vmess", "anytls", "https", "hysteria2", "tuic"] {
            XCTAssertNil(NCSupport.unsupportedReason(proxy(t, ["ech-opts": echOn, "password": .string("p"),
                                                                "uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"),
                                                                "cipher": .string("auto")])),
                         "\(t) + ECH should be dialable")
        }
        XCTAssertNil(NCSupport.unsupportedReason(proxy("vless", ["ech-opts": echOn, "tls": .bool(true),
                                                                  "uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811")])))
    }

    func testSupportRefusesECHWhereNotWired() {
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy("vless", ["ech-opts": echOn, "flow": .string("xtls-rprx-vision"),
                                                                     "uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy("trojan", ["ech-opts": echOn, "password": .string("p"),
                                                                      "reality-opts": .object(["public-key": .string("x")])])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy("ss", ["cipher": .string("aes-128-gcm"), "password": .string("p"),
                                                                  "plugin": .string("v2ray-plugin"),
                                                                  "plugin-opts": .object(["mode": .string("websocket"), "tls": .bool(true),
                                                                                          "ech-opts": echOn])])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy("socks5", ["ech-opts": echOn])))
    }

    func testECHNeedsExplicitEnable() {
        // Clash.Meta semantics: config without enable is not ECH (E3); no ech-opts at all → nothing changes.
        let p = proxy("trojan", ["password": .string("p"), "ech-opts": .object(["config": .string(echConfigBase64)])])
        XCTAssertFalse(NCConnector.isECHEnabled(p))
        XCTAssertFalse(NCConnector.needsNativeTLS(p))
        XCTAssertFalse(NCConnector.needsNativeTLS(proxy("trojan", ["password": .string("p")])))
        XCTAssertFalse(NCConnector.needsNativeTLS(proxy("trojan", ["password": .string("p"), "client-fingerprint": .string("none")])))
    }

    // MARK: System QUIC ECH (#150): off unless ech-opts.enable is true

    func testSystemQUICECHDefaultsOff() {
        XCTAssertFalse(NCSupport.systemQUICECHEnabled(proxy("hysteria2", ["password": .string("p")])))
        XCTAssertFalse(NCSupport.systemQUICECHEnabled(proxy("tuic", ["ech-opts": .object(["enable": .bool(false)])])))
        XCTAssertFalse(NCSupport.systemQUICECHEnabled(proxy("tuic", ["ech-opts": .object(["config": .string(echConfigBase64)])])))
        XCTAssertTrue(NCSupport.systemQUICECHEnabled(proxy("hysteria2", ["ech-opts": echOn])))
        XCTAssertFalse(NCSupport.hasStaticECHConfig(proxy("hysteria2", ["ech-opts": echOn])))
        XCTAssertTrue(NCSupport.hasStaticECHConfig(proxy("hysteria2", ["ech-opts": .object(["enable": .bool(true), "config": .string(echConfigBase64)])])))
    }

    // MARK: Default ALPN by transport (#153 item 1)

    func testDefaultALPNByTransport() {
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vless", ["network": .string("ws")])), ["http/1.1"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vmess", ["network": .string("httpupgrade")])), ["http/1.1"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vmess", ["network": .string("grpc")])), ["h2"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vless", ["network": .string("h2")])), ["h2"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vless", ["network": .string("tcp")])), [])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("vmess", [:])), [])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("trojan", [:])), ["h2", "http/1.1"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("https", [:])), ["http/1.1"])
        XCTAssertEqual(NCConnector.defaultALPN(for: proxy("anytls", [:])), [])
    }

    func testClientHelloOmitsEmptyALPN() {
        let share = Data(repeating: 9, count: 32)
        let with = NCTLS13.buildClientHello(random: Data(count: 32), sessionID: Data(count: 32), serverName: "a.example",
                                            alpn: ["h2"], keyShare: share)
        let without = NCTLS13.buildClientHello(random: Data(count: 32), sessionID: Data(count: 32), serverName: "a.example",
                                               alpn: [], keyShare: share)
        XCTAssertNotNil(with.range(of: Data([0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32])))
        XCTAssertNil(without.range(of: Data([0x00, 0x10, 0x00, 0x02, 0x00, 0x00])), "no empty ALPN extension on the wire")
        // supported_versions = {TLS 1.3, TLS 1.2} with an even u8 list length (was 0x03 → the old core decode_error).
        XCTAssertNotNil(with.range(of: Data([0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03])))
    }

    // MARK: ECHConfigList source (#153 item 2)

    private func resolve(_ p: NCProxy, serverName: String = "inner.example") -> (Data?, Error?) {
        let exp = expectation(description: "resolve")
        var out: (Data?, Error?) = (nil, nil)
        let q = DispatchQueue(label: "t.ech.resolve")
        NCConnector.resolveECHConfigList(p, serverName: serverName, queue: q) { d, e in out = (d, e); exp.fulfill() }
        wait(for: [exp], timeout: 5)
        return out
    }

    func testStaticConfigWins() throws {
        var called = false
        NCConnector.echConfigLookup = { _, done in called = true; done(nil, nil) }
        let p = proxy("trojan", ["ech-opts": .object(["enable": .bool(true), "config": .string(echConfigBase64)])])
        let (d, e) = resolve(p)
        XCTAssertNil(e)
        XCTAssertEqual(d, Data(base64Encoded: echConfigBase64))
        XCTAssertFalse(called)
    }

    func testBadStaticConfigFails() {
        let p = proxy("trojan", ["ech-opts": .object(["enable": .bool(true), "config": .string("AAAA")])])
        XCTAssertNotNil(resolve(p).1)
    }

    func testDynamicLookupUsesQueryServerNameElseSNI() throws {
        let list = try XCTUnwrap(Data(base64Encoded: echConfigBase64))
        var names: [String] = []
        NCConnector.echConfigLookup = { n, done in names.append(n); done(list, nil) }
        XCTAssertEqual(resolve(proxy("trojan", ["ech-opts": echOn])).0, list)
        XCTAssertEqual(resolve(proxy("trojan", ["ech-opts": .object(["enable": .bool(true),
                                                                      "query-server-name": .string("cf.example")])])).0, list)
        XCTAssertEqual(names, ["inner.example", "cf.example"])
    }

    func testDynamicWithoutRecordOrResolverFails() {
        // No resolver (app process / engine not loaded): explicit error, never a plaintext handshake.
        XCTAssertNotNil(resolve(proxy("trojan", ["ech-opts": echOn])).1)
        NCConnector.echConfigLookup = { _, done in done(nil, nil) }
        XCTAssertNotNil(resolve(proxy("trojan", ["ech-opts": echOn])).1)
        NCConnector.echConfigLookup = { _, done in done(nil, NCECHError.timeout) }
        XCTAssertNotNil(resolve(proxy("trojan", ["ech-opts": echOn])).1)
        NCConnector.echConfigLookup = { _, done in done(Data([0, 2, 1, 2]), nil) }
        XCTAssertNotNil(resolve(proxy("trojan", ["ech-opts": echOn])).1)
    }

    func testECHOffSkipsLookup() {
        var called = false
        NCConnector.echConfigLookup = { _, done in called = true; done(nil, nil) }
        let (d, e) = resolve(proxy("trojan", [:]))
        XCTAssertNil(d); XCTAssertNil(e); XCTAssertFalse(called)
    }

    // MARK: Share link (#149 item 5)

    func testShareLinkECHZeroWritesNothing() {
        XCTAssertNil(NCECHOpts.parse(query: ["ech": "0"]))
        XCTAssertNil(NCECHOpts.parse(query: ["ech": "false"]))
        XCTAssertEqual(NCECHOpts.parse(query: ["ech": "1"])?.enable, true)
    }
}
