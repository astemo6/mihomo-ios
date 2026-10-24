import Network
import Security
import XCTest
@testable import Mihomo

/// feat/s2-tls (native MitM stage 2, B7): leaf identity cache + PKCS#12 import + the loopback TLS server.
/// NativeMitmTLSFixtures.json: PKCS#12 blobs written by Go exactly like Engine.LeafIdentity (pkcs12.Legacy, password
/// "tern", leaf + throwaway test CA) plus one pkcs12.Modern copy as a probe (design §4.2 open question).
final class NativeMitmTLSTests: XCTestCase {
    private func fixtures() throws -> [String: String] {
        let bundle = Bundle(for: NativeMitmTLSTests.self)
        let url = try XCTUnwrap(bundle.url(forResource: "NativeMitmTLSFixtures", withExtension: "json"),
                                "NativeMitmTLSFixtures.json missing from the test bundle")
        return try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
    }

    private func p12(_ key: String) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(fixtures()[key])))
    }

    // MARK: BoundedLRU

    func testLRUCountEvictsLeastRecent() {
        let c = BoundedLRU<Int>(maxCount: 3, maxBytes: 1000)
        c.set("a", 1, cost: 1); c.set("b", 2, cost: 1); c.set("c", 3, cost: 1)
        XCTAssertEqual(c.get("a"), 1) // a is now most recent
        XCTAssertEqual(c.set("d", 4, cost: 1), ["b"])
        XCTAssertNil(c.get("b"))
        XCTAssertEqual(c.keys, ["c", "a", "d"])
        XCTAssertEqual(c.count, 3)
    }

    func testLRUByteBudget() {
        let c = BoundedLRU<Int>(maxCount: 10, maxBytes: 100)
        c.set("a", 1, cost: 40); c.set("b", 2, cost: 40)
        XCTAssertEqual(c.set("c", 3, cost: 40), ["a"])
        XCTAssertEqual(c.bytes, 80)
        c.set("b", 22, cost: 10) // replace updates cost and recency
        XCTAssertEqual(c.bytes, 50)
        XCTAssertEqual(c.keys, ["c", "b"])
        XCTAssertEqual(c.set("huge", 9, cost: 101), []) // larger than the whole budget: not kept
        XCTAssertNil(c.get("huge"))
        XCTAssertEqual(c.bytes, 50)
        c.remove("c")
        XCTAssertEqual(c.bytes, 10)
        c.removeAll()
        XCTAssertEqual(c.count, 0)
        XCTAssertEqual(c.bytes, 0)
    }

    func testLRUNormalizesHost() {
        let c = BoundedLRU<Int>(maxCount: 2, maxBytes: 10)
        c.set("API.Example.COM.", 1, cost: 1)
        XCTAssertEqual(c.get("api.example.com"), 1)
        XCTAssertEqual(c.count, 1)
    }

    // MARK: PKCS#12 import

    func testImportGoLegacyPKCS12() throws {
        let id = try LeafIdentityCache.importPKCS12(try p12("api.example.com"), password: "tern")
        var cert: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(id, &cert), errSecSuccess)
        let summary = try XCTUnwrap(cert.flatMap { SecCertificateCopySubjectSummary($0) as String? })
        XCTAssertTrue(summary.contains("api.example.com"), summary)
        var key: SecKey?
        XCTAssertEqual(SecIdentityCopyPrivateKey(id, &key), errSecSuccess)
        XCTAssertNotNil(key)
        XCTAssertNotNil(MitmTLSFront.tlsOptions(identity: id))
    }

    func testImportModernPKCS12Probe() throws {
        // Probe only (design §4.2): Go ships Legacy; log whether this OS also reads the AES profile.
        do {
            _ = try LeafIdentityCache.importPKCS12(try p12("api.example.com#modern"), password: "tern")
            print("NativeMitmTLS probe: pkcs12.Modern import OK on \(ProcessInfo.processInfo.operatingSystemVersionString)")
        } catch {
            print("NativeMitmTLS probe: pkcs12.Modern import FAILED on \(ProcessInfo.processInfo.operatingSystemVersionString): \(error)")
        }
    }

    func testImportWrongPasswordFails() throws {
        XCTAssertThrowsError(try LeafIdentityCache.importPKCS12(try p12("api.example.com"), password: "nope")) { e in
            guard case NativeTLSError.importFailed(let st)? = e as? NativeTLSError else { return XCTFail("\(e)") }
            XCTAssertNotEqual(st, errSecSuccess)
        }
        XCTAssertThrowsError(try LeafIdentityCache.importPKCS12(Data("garbage".utf8), password: "tern"))
    }

    // MARK: LeafIdentityCache

    func testIdentityCacheCallsGoOncePerHostAndBounds() throws {
        let fx = try fixtures()
        var calls: [String] = []
        let cache = LeafIdentityCache(maxCount: 1, maxBytes: 1 << 20) { host in
            calls.append(host)
            return fx[host].flatMap { Data(base64Encoded: $0) }
        }
        let a = cache.identity(for: "API.example.com")
        guard case .success(let leaf) = a else { return XCTFail("\(a)") }
        XCTAssertGreaterThan(leaf.cost, 0)
        _ = cache.identity(for: "api.example.com")
        XCTAssertEqual(calls, ["api.example.com"]) // normalized, cached
        _ = cache.identity(for: "img.example.com") // evicts api (maxCount 1)
        _ = cache.identity(for: "api.example.com")
        XCTAssertEqual(calls, ["api.example.com", "img.example.com", "api.example.com"])
        XCTAssertEqual(cache.cache.count, 1)
    }

    func testIdentityCacheFailuresAreNotCached() {
        var n = 0
        let none = LeafIdentityCache { _ in n += 1; return nil }
        XCTAssertEqual(none.identity(for: "x.com").failureValue, .noIdentity)
        XCTAssertEqual(none.identity(for: "x.com").failureValue, .noIdentity)
        XCTAssertEqual(n, 2)
        let bad = LeafIdentityCache { _ in Data("not a p12".utf8) }
        guard case .importFailed? = bad.identity(for: "x.com").failureValue else { return XCTFail() }
        XCTAssertEqual(bad.cache.count, 0)
    }

    // MARK: MitmTLSFront (loopback TLS server)

    func testFrontDeclinesWithoutHandlerOrIdentity() {
        let front = MitmTLSFront(identities: LeafIdentityCache { _ in nil })
        XCTAssertEqual(front.listen("api.example.com", alpn: "http/1.1"), 0) // no onAccept
        front.onAccept = { $0.close() }
        XCTAssertEqual(front.listen("api.example.com", alpn: "http/1.1"), 0) // no identity → Go path
        XCTAssertEqual(front.listen("", alpn: nil), 0)
        XCTAssertEqual(front.listenerCount, 0)
    }

    /// End to end on loopback: client offers h2 + http/1.1 with SNI, server must pick http/1.1, see the SNI and
    /// move plaintext both ways through TLSByteStream.
    func testFrontHandshakeALPNSNIAndEcho() throws {
        let fx = try fixtures()
        let front = MitmTLSFront(identities: LeafIdentityCache { fx[$0].flatMap { Data(base64Encoded: $0) } })
        var failures: [String] = []
        front.reportHandshakeFailure = { h, k in failures.append("\(h):\(k)") }
        let accepted = expectation(description: "accepted")
        var server: TLSByteStream?
        front.onAccept = { s in
            server = s
            s.read(min: 1, max: 1024) { data, _, _ in
                s.write(Data("echo:".utf8) + (data ?? Data())) { _ in }
            }
            accepted.fulfill()
        }
        defer { front.reset() }
        let port = try front.port(for: "api.example.com").get()
        XCTAssertGreaterThan(port, 0)
        XCTAssertEqual(try front.port(for: "API.example.com").get(), port) // one listener per host
        XCTAssertEqual(front.listenerCount, 1)

        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, "api.example.com")
        sec_protocol_options_add_tls_application_protocol(sec, "h2")
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_verify_block(sec, { _, _, done in done(true) }, .global()) // test CA is not trusted
        let client = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!,
                                  using: NWParameters(tls: tls, tcp: .init()))
        let ready = expectation(description: "client ready")
        client.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        client.start(queue: .global())
        wait(for: [ready, accepted], timeout: 10)
        XCTAssertEqual(TLSByteStream.handshakeInfo(client).alpn, "http/1.1")
        XCTAssertEqual(server?.sni, "api.example.com")
        XCTAssertEqual(server?.alpn, "http/1.1")
        XCTAssertEqual(server?.routingHost, "api.example.com")

        let echoed = expectation(description: "echo")
        client.send(content: Data("hi".utf8), completion: .contentProcessed { _ in })
        client.receive(minimumIncompleteLength: 7, maximumLength: 64) { data, _, _, _ in
            XCTAssertEqual(data.map { String(decoding: $0, as: UTF8.self) }, "echo:hi")
            echoed.fulfill()
        }
        wait(for: [echoed], timeout: 10)
        client.cancel()
        server?.close()
        XCTAssertEqual(failures, [])
    }

    func testClassifyHandshakeErrors() {
        XCTAssertEqual(MitmTLSFront.classify(.tls(errSSLPeerUnknownCA)), "cert")
        XCTAssertEqual(MitmTLSFront.classify(.tls(errSSLPeerBadCert)), "cert")
        XCTAssertEqual(MitmTLSFront.classify(.tls(errSSLClosedAbort)), "closed")
        XCTAssertEqual(MitmTLSFront.classify(.posix(.ECONNRESET)), "closed")
        XCTAssertEqual(MitmTLSFront.classify(.posix(.ETIMEDOUT)), "timeout")
    }
}

private extension Result {
    var failureValue: Failure? {
        if case .failure(let e) = self { return e }
        return nil
    }
}
