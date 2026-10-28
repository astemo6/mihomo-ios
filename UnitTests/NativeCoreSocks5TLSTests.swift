import XCTest
@testable import Tern

/// feat/nc-socks5-tls (#168): SOCKS5 over TLS — the dialer used to ignore
/// `tls: true` on socks5 nodes and connect in plaintext. These tests pin the
/// TLS decision + SNI priority, the four import normalisations, and the
/// share-link round trip. Wire behaviour is covered by the loopback tests
/// (`testSocks5TLS*` in NativeCoreLoopbackTests against the TLS-wrapped
/// SOCKS5 server in tools/loopback/echo_server.py).
final class NativeCoreSocks5TLSTests: XCTestCase {

    private func proxy(type: String, _ fields: [String: NCJSONValue]) -> NCProxy {
        NCProxy(name: "n", type: type, fields: fields)
    }

    // MARK: - Dial decision

    func testProxyUsesTLS() {
        XCTAssertTrue(NCConnector.proxyUsesTLS(proxy(type: "socks5", ["tls": .bool(true)])))
        XCTAssertFalse(NCConnector.proxyUsesTLS(proxy(type: "socks5", [:])))
        XCTAssertFalse(NCConnector.proxyUsesTLS(proxy(type: "socks5", ["tls": .bool(false)])))
        XCTAssertTrue(NCConnector.proxyUsesTLS(proxy(type: "https", [:])))
        XCTAssertTrue(NCConnector.proxyUsesTLS(proxy(type: "http", ["tls": .bool(true)])))
        XCTAssertFalse(NCConnector.proxyUsesTLS(proxy(type: "http", [:])))
        XCTAssertFalse(NCConnector.proxyUsesTLS(proxy(type: "trojan", ["tls": .bool(true)])))
    }

    func testSocks5SNIPriority() {
        let server = "203.0.113.7"
        XCTAssertEqual(NCConnector.httpProxySNI(proxy(type: "socks5", [
            "sni": .string("a.example.com"), "servername": .string("b.example.com"),
            "tls-host": .string("c.example.com"),
        ]), server: server), "a.example.com")
        XCTAssertEqual(NCConnector.httpProxySNI(proxy(type: "socks5", [
            "servername": .string("b.example.com"), "tls-host": .string("c.example.com"),
        ]), server: server), "b.example.com")
        XCTAssertEqual(NCConnector.httpProxySNI(proxy(type: "socks5", [
            "tls-host": .string("c.example.com"),
        ]), server: server), "c.example.com")
        XCTAssertEqual(NCConnector.httpProxySNI(proxy(type: "socks5", [
            "sni": .string(""),
        ]), server: server), server)
        XCTAssertEqual(NCConnector.httpProxySNI(proxy(type: "socks5", [:]), server: server), server)
    }

    // MARK: - Import normalisation (all four spellings → socks5 + tls + sni)

    func testSurgeSocks5TLSImport() {
        let text = """
        [Proxy]
        S1 = socks5-tls, tls.example.com, 1080, user1, pass1
        S2 = socks5, plain.example.com, 1081, username=user2, password=pass2, tls=true, tls-host=sni.example.com
        """
        let c = NCConfImport.surge(text)
        let s1 = c.nodeMap["S1"]
        XCTAssertEqual(s1?.type, "socks5")
        XCTAssertEqual(s1?.fields["tls"]?.bool, true)
        let s2 = c.nodeMap["S2"]
        XCTAssertEqual(s2?.type, "socks5")
        XCTAssertEqual(s2?.fields["tls"]?.bool, true)
        XCTAssertEqual(s2?.fields["sni"]?.string, "sni.example.com")
    }

    func testQXOverTLSImport() {
        let text = """
        [server_local]
        socks5=qx.example.com:1080, username=user1, password=pass1, over-tls=true, tls-host=qx-sni.example.com, tag=QX-SocksTLS
        """
        let c = NCQXImport.quantumultx(text)
        let n = c.nodeMap["QX-SocksTLS"]
        XCTAssertEqual(n?.type, "socks5")
        XCTAssertEqual(n?.fields["tls"]?.bool, true)
        XCTAssertEqual(n?.fields["sni"]?.string, "qx-sni.example.com")
    }

    func testClashYAMLImport() throws {
        let yaml = """
        proxies:
          - name: Clash-SocksTLS
            type: socks5
            server: clash.example.com
            port: 1080
            username: user1
            password: pass1
            tls: true
            sni: clash-sni.example.com
            skip-cert-verify: true
        """
        let proxies = try XCTUnwrap(NCSubscription.parseClashYAML(yaml))
        let n = try XCTUnwrap(proxies.first { $0.name == "Clash-SocksTLS" })
        XCTAssertEqual(n.type, "socks5")
        XCTAssertEqual(n.fields["tls"]?.bool, true)
        XCTAssertEqual(n.fields["sni"]?.string, "clash-sni.example.com")
        XCTAssertEqual(n.fields["skip-cert-verify"]?.bool, true)
        XCTAssertTrue(NCConnector.proxyUsesTLS(n))
    }

    func testShadowrocketLinkImport() throws {
        let a = try XCTUnwrap(NCSubscription.parseURI(
            "socks5://user1:pass1@sr.example.com:1080?tls=1&peer=sr-sni.example.com#SR"))
        XCTAssertEqual(a.type, "socks5")
        XCTAssertEqual(a.fields["tls"]?.bool, true)
        XCTAssertEqual(a.fields["sni"]?.string, "sr-sni.example.com")

        let b = try XCTUnwrap(NCSubscription.parseURI(
            "socks5-tls://user1:pass1@sr2.example.com:1080?sni=sr2-sni.example.com&insecure=1#SR2"))
        XCTAssertEqual(b.fields["tls"]?.bool, true)
        XCTAssertEqual(b.fields["sni"]?.string, "sr2-sni.example.com")
        XCTAssertEqual(b.fields["skip-cert-verify"]?.bool, true)

        let plain = try XCTUnwrap(NCSubscription.parseURI("socks5://user1:pass1@sr.example.com:1080#Plain"))
        XCTAssertNil(plain.fields["tls"])
        XCTAssertFalse(NCConnector.proxyUsesTLS(plain))
    }

    // MARK: - Export round trip

    func testShareLinkRoundTripKeepsTLS() throws {
        let node = NCProxy(name: "RT", type: "socks5", fields: [
            "server": .string("rt.example.com"), "port": .number(1080),
            "username": .string("user1"), "password": .string("pass1"),
            "tls": .bool(true), "sni": .string("rt-sni.example.com"),
            "skip-cert-verify": .bool(true),
        ])
        let link = try NCShareLink.encode(node)
        XCTAssertTrue(link.contains("tls=1"), link)
        let back = try XCTUnwrap(NCSubscription.parseURI(link))
        XCTAssertEqual(back.type, "socks5")
        XCTAssertEqual(back.fields["tls"]?.bool, true)
        XCTAssertEqual(back.fields["sni"]?.string, "rt-sni.example.com")
        XCTAssertEqual(back.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(back.fields["username"]?.string, "user1")
        XCTAssertEqual(back.fields["password"]?.string, "pass1")
    }
}
