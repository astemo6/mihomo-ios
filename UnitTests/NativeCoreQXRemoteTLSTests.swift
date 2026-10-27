import XCTest
import Security
@testable import Tern

/// fix-tls-c (E2E 40543432526: provider SelfBuild 17/33 `tls · -9808: bad certificate format`, runner log boringssl
/// CERTIFICATE_VERIFY_FAILED from the verify callback, the node-tls row saw skip-cert-verify false on every one).
///
/// Root cause reproduced here: the Quantumult X default "certificate verification off unless tls-verification=true" was
/// applied only to bodies made of QX lines (buildQXNode). A `[server_remote]` panel that answers with share links /
/// base64 / Clash YAML gave nodes with skip-cert-verify false, so self-signed / IP / expired certificates that QX
/// accepts were rejected. Fix: the provider (x-origin qx / x-convert nodes / QuanX UA) applies the QX default to every
/// node whatever the body format. Also: `https` / `http`+`tls` proxies honour sni + skip-cert-verify, and a rejected
/// chain is described (NCCertSummary) in the dial error.
final class NativeCoreQXRemoteTLSTests: XCTestCase {

    private static let uuid = "00000000-0000-0000-0000-000000000001"

    private static func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }

    /// The body shape the node-tls row reported for SelfBuild is unknown until the next E2E; base64 share links are the
    /// common self-built panel answer, so that is the reproduction.
    private static var shareLinkBody: String {
        let vm = #"{"v":"2","ps":"V1","add":"b.example","port":"443","id":"\#(uuid)","aid":"0","net":"ws","type":"none","host":"b.example","path":"/ws","tls":"tls"}"#
        let lines = [
            "trojan://pw@a.example:443?sni=a.example#T1",
            "vmess://" + b64(vm),
            "trojan://pw@c.example:443?allowInsecure=1#T2",
            "ss://" + b64("aes-128-gcm:pw") + "@d.example:8388#S1",
        ]
        return b64(lines.joined(separator: "\n"))
    }

    func testShareLinkBodyWithoutQXDefaultVerifies() {
        // The bug as it was: the same body read as a plain provider keeps verification on.
        let p = NCSubscriptionParser.parseDetailed(Self.shareLinkBody, qxRemote: false)
        XCTAssertEqual(p.format, "base64 share links")
        XCTAssertEqual(p.nodes.first { $0.name == "T1" }?.skipCertVerify, false)
        XCTAssertEqual(p.nodes.first { $0.name == "V1" }?.skipCertVerify, false)
        XCTAssertEqual(p.qxTLSDefaulted, 0)
    }

    func testQXRemoteShareLinkBodyDefaultsVerificationOff() {
        let p = NCSubscriptionParser.parseDetailed(Self.shareLinkBody, qxRemote: true)
        XCTAssertEqual(p.nodes.count, 4)
        XCTAssertEqual(p.nodes.first { $0.name == "T1" }?.skipCertVerify, true, "trojan share link")
        XCTAssertEqual(p.nodes.first { $0.name == "V1" }?.skipCertVerify, true, "vmess ws + tls share link")
        XCTAssertEqual(p.nodes.first { $0.name == "T2" }?.skipCertVerify, true, "already insecure")
        XCTAssertNil(p.nodes.first { $0.name == "S1" }?.fields["skip-cert-verify"], "no TLS, untouched")
        XCTAssertEqual(p.qxTLSDefaulted, 2)
        // the plain entry point is unchanged
        XCTAssertEqual(NCSubscriptionParser.parse(Self.shareLinkBody).first { $0.name == "T1" }?.skipCertVerify, false)
    }

    func testQXRemoteClashYAMLBody() {
        let pin = String(repeating: "ab", count: 32)
        let body = """
        proxies:
          - name: Y1
            type: trojan
            server: a.example
            port: 443
            password: pw
            skip-cert-verify: false
          - name: Y2
            type: trojan
            server: b.example
            port: 443
            password: pw
            skip-cert-verify: false
            tls-verification: true
          - name: Y3
            type: vless
            server: c.example
            port: 443
            uuid: \(Self.uuid)
            tls: true
            reality-opts:
              public-key: k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk
          - name: Y4
            type: trojan
            server: d.example
            port: 443
            password: pw
            fingerprint: \(pin)
          - name: Y5
            type: ss
            server: e.example
            port: 8388
            cipher: aes-128-gcm
            password: pw
          - name: Y6
            type: http
            server: f.example
            port: 443
            tls: true
        """
        let p = NCSubscriptionParser.parseDetailed(body, qxRemote: true)
        func n(_ x: String) -> NCProxy? { p.nodes.first { $0.name == x } }
        XCTAssertEqual(p.format, "Clash YAML")
        XCTAssertEqual(n("Y1")?.skipCertVerify, true, "explicit false in a panel's YAML is not QX's tls-verification=true")
        XCTAssertEqual(n("Y2")?.skipCertVerify, false, "the node asked for verification")
        XCTAssertEqual(n("Y3")?.skipCertVerify, false, "REALITY authenticates the server itself")
        XCTAssertEqual(n("Y4")?.skipCertVerify, false, "a pin is its own check")
        XCTAssertNil(n("Y5")?.fields["skip-cert-verify"])
        XCTAssertEqual(n("Y6")?.skipCertVerify, true, "http + tls")
        XCTAssertEqual(p.qxTLSDefaulted, 2)
    }

    func testQXLinesSurviveTheAppYAMLConversion() {
        // The App stores a QX-line body as Clash YAML (convertNodesText); tls-verification=true must survive that.
        let body = """
        vmess=1.2.3.4:443, method=none, password=\(Self.uuid), obfs=over-tls, obfs-host=a.example, tag=SZ CN
        trojan=b.example:443, password=pw, over-tls=true, tls-verification=true, tag=Verified
        """
        let direct = NCSubscriptionParser.parseDetailed(body, qxRemote: true)
        XCTAssertEqual(direct.format, "QX lines")
        XCTAssertEqual(direct.nodes.first { $0.name == "SZ CN" }?.skipCertVerify, true)
        XCTAssertEqual(direct.nodes.first { $0.name == "Verified" }?.skipCertVerify, false)
        guard let conv = NCProviderPorts.convertNodesText(Data(body.utf8)) else { return XCTFail("no conversion") }
        let yaml = NCSubscriptionParser.parseDetailed(String(decoding: conv.data, as: UTF8.self), qxRemote: true)
        XCTAssertEqual(yaml.format, "Clash YAML")
        XCTAssertEqual(yaml.nodes.first { $0.name == "SZ CN" }?.skipCertVerify, true)
        XCTAssertEqual(yaml.nodes.first { $0.name == "Verified" }?.skipCertVerify, false)
        XCTAssertEqual(yaml.qxTLSDefaulted, 0)
    }

    func testIsQXRemote() {
        func sub(_ f: [String: NCJSONValue]) -> NCNodeSubscription { NCNodeSubscription(name: "S", url: "https://p.test/s", fields: f) }
        XCTAssertTrue(NCNodeSubscriptionStore.isQXRemote(sub(["x-origin": .string("qx")])))
        XCTAssertTrue(NCNodeSubscriptionStore.isQXRemote(sub(["x-convert": .string("nodes")])), "App QX import / device build506 profile")
        XCTAssertTrue(NCNodeSubscriptionStore.isQXRemote(sub(["header": .object(["User-Agent": .array([.string(NCNodeSubscriptionStore.qxUserAgent)])])])))
        XCTAssertFalse(NCNodeSubscriptionStore.isQXRemote(sub([:])))
        XCTAssertFalse(NCNodeSubscriptionStore.isQXRemote(sub(["type": .string("file"), "path": .string("./nodesubs/a.yaml")])))
    }

    func testStoreAppliesTheQXDefaultOnRefreshAndLogsTheFormat() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("qxremote-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = NCNodeSubscriptionStore(dir: dir, home: dir)
        var logs: [String] = []
        store.log = { logs.append($0) }
        let body = Self.shareLinkBody
        store.fetcher = { _, _, done in done(Data(body.utf8), 200) }
        let qx = NCNodeSubscription(name: "SelfBuild", url: "https://p.test/s", fields: ["x-convert": .string("nodes")])
        let exp = expectation(description: "refresh")
        store.refresh(qx) { exp.fulfill() }
        wait(for: [exp], timeout: 5)
        XCTAssertEqual(store.nodes(for: qx).first { $0.name == "T1" }?.skipCertVerify, true)
        XCTAssertTrue(logs.contains("proxy provider SelfBuild: 4 nodes (fetched)"), "\(logs)")
        XCTAssertTrue(logs.contains("proxy provider SelfBuild: body base64 share links, QX TLS default: 2 node(s) verification off"), "\(logs)")
        // a reload from the raw-body cache gets the same default
        let again = NCNodeSubscriptionStore(dir: dir, home: dir)
        again.log = { _ in }
        _ = again.loadCached([qx])
        XCTAssertEqual(again.nodes(for: qx).first { $0.name == "V1" }?.skipCertVerify, true)
        XCTAssertEqual(NCNodeSubscriptionStore.cacheFileName(for: "SelfBuild").hasPrefix("sub-"), true)
    }

    // MARK: - https / http + tls

    func testHTTPProxyTLSReading() {
        let https = NCProxy(name: "h", type: "https", fields: ["server": .string("1.2.3.4"), "port": .number(443)])
        let httpTLS = NCProxy(name: "h", type: "http", fields: ["server": .string("1.2.3.4"), "port": .number(443),
                                                                 "tls": .bool(true), "sni": .string("h.example"),
                                                                 "skip-cert-verify": .bool(true)])
        let plain = NCProxy(name: "h", type: "http", fields: ["server": .string("1.2.3.4"), "port": .number(8080)])
        XCTAssertTrue(NCConnector.httpProxyUsesTLS(https))
        XCTAssertTrue(NCConnector.httpProxyUsesTLS(httpTLS), "share-link https:// is type http + tls")
        XCTAssertFalse(NCConnector.httpProxyUsesTLS(plain))
        XCTAssertEqual(NCConnector.httpProxySNI(httpTLS, server: "1.2.3.4"), "h.example")
        XCTAssertEqual(NCConnector.httpProxySNI(https, server: "1.2.3.4"), "1.2.3.4")
        // QX `http=…, over-tls=true` without tls-verification → https, verification off
        var r = NCImportReport()
        let qx = NCQXImport.buildQXNode(line: "http=1.2.3.4:443, username=u, password=p, over-tls=true, tls-host=h.example, tag=H", report: &r)
        XCTAssertEqual(qx?.type, "https")
        XCTAssertEqual(qx?.skipCertVerify, true)
        if let qx { XCTAssertEqual(NCConnector.httpProxySNI(qx, server: "1.2.3.4"), "h.example") }
    }

    // MARK: - NCCertSummary (the dial error's chain description)

    func testCertSummaryOfASelfSignedChainAndMaskedTrustError() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("certsum-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let ca = try NCCAManager.generateCA(home: home, reload: false).caCert
        let leaf = NCCertSummary.leaf(ca)
        XCTAssertEqual(leaf.key, "EC-256")
        XCTAssertTrue(leaf.selfSigned)
        let v = try XCTUnwrap(NCCertSummary.validity(der: SecCertificateCopyData(ca) as Data))
        XCTAssertLessThan(v.notBefore, Date())
        XCTAssertGreaterThan(v.notAfter, Date().addingTimeInterval(9 * 365 * 86400), "UTCTime 20xx, not 19xx")
        let d = NCCertSummary.describe(chain: [ca])
        XCTAssertTrue(d.hasPrefix("chain 1, leaf EC-256 self-signed, valid "), d)
        XCTAssertFalse(d.contains("expired"), d)
        XCTAssertTrue(NCCertSummary.describe(chain: [ca], now: Date().addingTimeInterval(11 * 365 * 86400)).hasSuffix(", expired"))

        // What a verification-on dial sees for it: SecTrust rejects, the reason is masked.
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(ca, SecPolicyCreateSSL(true, "node.example" as CFString), &trust), errSecSuccess)
        var err: CFError?
        XCTAssertFalse(SecTrustEvaluateWithError(trust!, &err))
        let line = NCCertSummary.trustFailure(trust: trust!, error: err)
        XCTAssertFalse(line.contains("Tern MitM CA"), line)
        XCTAssertFalse(line.contains("node.example"), line)
        XCTAssertTrue(line.contains(" · chain 1, leaf EC-256 self-signed"), line)
    }

    func testMaskTrustError() {
        XCTAssertEqual(NCCertSummary.maskTrustError("“1.2.3.4” certificate is not trusted"), "“<cert>” certificate is not trusted")
        XCTAssertEqual(NCCertSummary.maskTrustError("\"a.example\" certificate name does not match input"), "\"<cert>\" certificate name does not match input")
        XCTAssertEqual(NCCertSummary.maskTrustError("no quotes"), "no quotes")
    }

    func testDelayFailureGroupingIgnoresTheChain() {
        let p = [
            "[delay] A: failed at stage tls (-9808: bad certificate format · verify on: “<cert>” certificate is not trusted · chain 1, leaf RSA-2048 self-signed, valid 2025-01-01…2026-01-01) | dial 41 ms",
            "[delay] B: failed at stage tls (-9808: bad certificate format · verify on: “<cert>” certificate is not trusted · chain 2, leaf EC-256, valid 2024-01-01…2025-01-01, expired) | dial 50 ms",
        ]
        let f = SelfCheckLogic.delayFailures(p)
        XCTAssertEqual(f.count, 1, "\(f)")
        XCTAssertEqual(f.first?.nodes, ["A", "B"])
    }
}
