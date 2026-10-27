import CommonCrypto
import Network
import Security
import XCTest
@testable import Tern

/// fix/nc-mitm-live (build 404 device: 「重写脚本一个都用不了」, 脚本日志 empty, stale fake-ip dropped): the TUN MitM
/// decision (NCMitmGate, independent of the sniffer), the host list matching it consults (wildcards, exclusions,
/// QX %APPEND%, explicit ports), a real ClientHello handed through a relay into the native front (what NCDataPlane
/// does), the shared diagnostics limiter, script-log folding and fake-ip persistence.
final class NativeCoreMitmLiveTests: XCTestCase {

    // MARK: helpers

    private func u16(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }

    /// A minimal but well-formed TLS 1.2/1.3 ClientHello record.
    private func clientHello(sni: String?, alpn: [String]) -> Data {
        var ext = Data()
        if let sni {
            let n = Data(sni.utf8)
            var list = Data([0x00]) + u16(n.count) + n
            list = u16(list.count) + list
            ext += u16(0x0000) + u16(list.count) + list
        }
        if !alpn.isEmpty {
            var list = Data()
            for a in alpn { list.append(UInt8(a.utf8.count)); list += Data(a.utf8) }
            let body = u16(list.count) + list
            ext += u16(0x0010) + u16(body.count) + body
        }
        var hs = Data([0x03, 0x03]) + Data(repeating: 7, count: 32)
        hs += Data([0x00])                       // session id
        hs += u16(2) + Data([0x13, 0x01])        // cipher suites
        hs += Data([0x01, 0x00])                 // compression
        hs += u16(ext.count) + ext
        let msg = Data([0x01, UInt8((hs.count >> 16) & 0xff), UInt8((hs.count >> 8) & 0xff), UInt8(hs.count & 0xff)]) + hs
        return Data([0x16, 0x03, 0x01]) + u16(msg.count) + msg
    }

    private func snapshot() -> RWSnapshot {
        let json = """
        {"version":1,"gen":7,"on":true,"capture":false,"rules":[],
         "inc":[{"pat":"%APPEND% api.example.com"},{"pat":"*.example.org"},{"pat":"svc.example.net","port":8443},{"pat":"10.0.0.9"}],
         "exc":[{"pat":"skip.example.org"}]}
        """
        return RWSnapshot.decode(json)!
    }

    private func fixtures() throws -> [String: String] {
        let bundle = Bundle(for: NativeCoreMitmLiveTests.self)
        let url = try XCTUnwrap(bundle.url(forResource: "NativeMitmTLSFixtures", withExtension: "json"),
                                "NativeMitmTLSFixtures.json missing from the test bundle")
        return try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
    }

    // MARK: host list

    func testInterceptsWildcardsExclusionsAppendAndPorts() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        XCTAssertTrue(e.hasMitmHosts)
        XCTAssertEqual(e.mitmHostCount, 4)
        XCTAssertTrue(e.intercepts(host: "api.example.com", port: 443), "%APPEND% prefix must be stripped")
        XCTAssertTrue(e.intercepts(host: "API.Example.COM.", port: 443))
        XCTAssertTrue(e.intercepts(host: "a.b.example.org", port: 443))
        XCTAssertFalse(e.intercepts(host: "example.org", port: 443))
        XCTAssertFalse(e.intercepts(host: "skip.example.org", port: 443), "-exclusion wins")
        XCTAssertFalse(e.intercepts(host: "svc.example.net", port: 443))
        XCTAssertTrue(e.intercepts(host: "svc.example.net", port: 8443))
        XCTAssertFalse(e.intercepts(host: "api.example.com", port: 80))
        XCTAssertEqual(e.mitmPorts, [443, 8443])
    }

    // MARK: gate

    func testShouldPeekIgnoresSnifferAndUsesKnownDomain() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        let isMitm: (String, Int) -> Bool = { e.intercepts(host: $0, port: $1) }
        // redir-host / fake-ip domain known: the list decides (this is what never happened before the fix)
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: "api.example.com", port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: "www.apple.com", port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        // bare IP / unmapped fake-ip: the SNI decides on MitM ports only
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: nil, port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: nil, port: 8443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: nil, port: 5222, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: "api.example.com", port: 443, mitmActive: false, mitmPorts: e.mitmPorts, isMitm: isMitm))
    }

    func testVerdictsOnClientHello() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        let isMitm: (String, Int) -> Bool = { e.intercepts(host: $0, port: $1) }
        let hello = clientHello(sni: "api.example.com", alpn: ["h2", "http/1.1"])
        XCTAssertEqual(NCMitmGate.decide(firstBytes: hello, knownDomain: nil, dstIP: "1.2.3.4", port: 443, isMitm: isMitm),
                       .mitm(host: "api.example.com", alpn: ["h2", "http/1.1"]))
        // split over segments: wait for the rest at every cut
        for cut in [1, 4, 5, 20, hello.count - 1] {
            XCTAssertEqual(NCMitmGate.decide(firstBytes: hello.prefix(cut), knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm), .needMore, "cut \(cut)")
        }
        XCTAssertEqual(NCMitmGate.decide(firstBytes: Data("GET / HTTP/1.1\r\n".utf8), knownDomain: "api.example.com", dstIP: nil, port: 443, isMitm: isMitm),
                       .passthrough(reason: "not TLS"))
        // SNI is authoritative: a DNS-derived domain in the list does not MitM a different SNI (shared CDN IPs)
        let other = clientHello(sni: "www.apple.com", alpn: [])
        if case .passthrough(let why) = NCMitmGate.decide(firstBytes: other, knownDomain: "api.example.com", dstIP: nil, port: 443, isMitm: isMitm) {
            XCTAssertTrue(why.contains("www.apple.com"))
        } else { XCTFail("expected passthrough") }
        // no SNI: known domain, then the IP literal
        let bare = clientHello(sni: nil, alpn: ["http/1.1"])
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: "x.example.org", dstIP: "5.6.7.8", port: 443, isMitm: isMitm),
                       .mitm(host: "x.example.org", alpn: ["http/1.1"]))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: nil, dstIP: "10.0.0.9", port: 443, isMitm: isMitm),
                       .mitm(host: "10.0.0.9", alpn: ["http/1.1"]))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm),
                       .passthrough(reason: "no SNI"))
        // a first record that claims more than the cap and never completes
        var huge = Data([0x16, 0x03, 0x01, 0xff, 0xff])
        huge += Data(repeating: 0, count: NCMitmGate.maxHelloBytes)
        if case .passthrough = NCMitmGate.decide(firstBytes: huge, knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm) {} else {
            XCTFail("oversized first record must pass through")
        }
    }

    /// The data plane's handoff with a real client: the relay buffers the client's actual ClientHello until the gate
    /// decides, opens the native front for the SNI and replays the bytes; the client's TLS handshake completes with
    /// the leaf for that host and data flows both ways.
    func testRealClientHelloHandedThroughRelayIntoFront() throws {
        let fx = try fixtures()
        let engine = NativeRewriteEngine(snapshot: snapshot())
        let front = MitmTLSFront(identities: LeafIdentityCache { fx[$0].flatMap { Data(base64Encoded: $0) } })
        let accepted = expectation(description: "front accepted")
        var server: TLSByteStream?
        front.onAccept = { s in
            server = s
            s.read(min: 1, max: 1024) { data, _, _ in
                s.write(Data("echo:".utf8) + (data ?? Data())) { _ in }
            }
            accepted.fulfill()
        }
        defer { front.reset() }

        let q = DispatchQueue(label: "mitm-live.relay")
        let relay = NCLoopbackListener(queue: q)
        XCTAssertNil(relay.start(port: 0))
        defer { relay.stop() }
        var verdict: NCMitmGate.Verdict?
        var keep: [AnyObject] = []
        relay.onAccept = { conn in
            keep.append(conn)
            var buf = Data()
            func toFront(_ up: NCStream) {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, _ in
                    if let data, !data.isEmpty { up.send(data) }
                    if !done { toFront(up) }
                }
            }
            func toClient(_ up: NCStream) {
                up.receive { data, _ in
                    guard let data else { conn.cancel(); return }
                    conn.send(content: data, completion: .idempotent)
                    toClient(up)
                }
            }
            func peek() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                    if let data { buf.append(data) }
                    let v = NCMitmGate.decide(firstBytes: buf, knownDomain: nil, dstIP: "127.0.0.1", port: 443,
                                              isMitm: { engine.intercepts(host: $0, port: $1) })
                    if v == .needMore { peek(); return }
                    verdict = v
                    guard case .mitm(let host, let alpn) = v else { conn.cancel(); return }
                    let port = front.listen(host, alpn: alpn.joined(separator: ","))
                    guard port > 0 else { conn.cancel(); return }
                    let up = NCStream(to: "127.0.0.1", port: Int(port), queue: q)
                    keep.append(up)
                    up.start { err in
                        guard err == nil else { conn.cancel(); return }
                        up.send(buf)
                        toFront(up)
                        toClient(up)
                    }
                }
            }
            peek()
        }

        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, "api.example.com")
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_verify_block(sec, { _, _, done in done(true) }, .global()) // test CA is not trusted
        let client = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: relay.port)!,
                                  using: NWParameters(tls: tls, tcp: .init()))
        let ready = expectation(description: "client TLS ready")
        client.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        client.start(queue: .global())
        wait(for: [ready, accepted], timeout: 15)
        q.sync {}
        XCTAssertEqual(verdict, .mitm(host: "api.example.com", alpn: ["http/1.1"]))
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
        _ = keep
    }

    // MARK: diagnostics

    func testDiagLimiterSharedWindowAndSuppressedLine() {
        var out: [(String, String)] = []
        let lim = NCDiagLimiter(sink: { out.append(($0, $1)) })
        let t0: UInt64 = 5_000_000_000
        var admitted = 0
        for i in 0..<25 where lim.line("[MITM] line \(i)", now: t0 + UInt64(i)) { admitted += 1 }
        XCTAssertEqual(admitted, NCDiagLimiter.perSecond)
        XCTAssertEqual(out.count, NCDiagLimiter.perSecond)
        XCTAssertTrue(lim.line("[SCRIPT] next window", now: t0 + 1_100_000_000))
        XCTAssertEqual(out.count, NCDiagLimiter.perSecond + 2)
        XCTAssertEqual(out[NCDiagLimiter.perSecond].0, "warning")
        XCTAssertTrue(out[NCDiagLimiter.perSecond].1.contains("5 line(s) suppressed"))
        XCTAssertEqual(out.last?.1, "[SCRIPT] next window")
    }

    func testScriptLogFoldsRepeatsAndKeepsLevels() {
        let ring = NativeLogRing.shared
        ring.clearScripts()
        for _ in 0..<3 { ring.addScript(script: "a.js", level: "error", msg: "boom") }
        ring.addScript(script: "a.js", level: "notify", msg: "title — body")
        ring.addScript(script: "Tern", level: "info", msg: "脚本引擎已加载")
        let lines = ring.scriptLines(since: 0)
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0].count, 3)
        XCTAssertEqual(lines[0].level, "error")
        XCTAssertEqual(lines[1].level, "notify")
        // a folded repeat gets a new id so `since` pollers see it
        let last = lines[2].id
        ring.addScript(script: "Tern", level: "info", msg: "脚本引擎已加载")
        let again = ring.scriptLines(since: last)
        XCTAssertEqual(again.count, 1)
        XCTAssertEqual(again[0].count, 2)
        ring.clearScripts()
    }

    // MARK: fake-ip persistence

    func testFakeIPMutationsCountAndPersistRoundTrip() throws {
        let pool = NCFakeIPPool()
        let m0 = pool.mutations
        let ip = pool.address(for: "app.example.com")
        XCTAssertEqual(pool.mutations, m0 + 1)
        _ = pool.address(for: "app.example.com") // existing mapping: no change to persist
        XCTAssertEqual(pool.mutations, m0 + 1)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("mitm-live-fakeip-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        pool.persist(to: url)
        let next = NCFakeIPPool()
        next.restore(data: try Data(contentsOf: url))
        XCTAssertEqual(next.host(for: ip), "app.example.com", "a restarted tunnel must still map the address apps cached")
        XCTAssertTrue(next.isFakeAddress(ip))
    }
}

/// fix/nc-rsa-ca: an RSA MitM CA (QuanX `[mitm]` passphrase + p12 exports an RSA CA) imports, round-trips through
/// ca.pem / ca.key and the full-export p12, and signs EC P-256 leaves with sha256WithRSAEncryption that SecTrust accepts
/// with the CA as the only anchor. The EC P-256 CA path is unchanged (ECDSA leaves, no AKI).
final class NativeCoreRSACATests: XCTestCase {

    private var tmpRoots: [URL] = []

    override func tearDown() {
        for u in tmpRoots { try? FileManager.default.removeItem(at: u) }
        tmpRoots = []
        super.tearDown()
    }

    private func tmpHome() throws -> String {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("rsa-ca-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        tmpRoots.append(u)
        return u.path
    }

    private func sha1(_ d: Data) -> Data {
        var out = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        d.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(d.count), &out) }
        return Data(out)
    }

    /// A self-signed RSA root like QuanX's: v3, BasicConstraints CA (critical), KeyUsage certSign|cRLSign (critical), SKI.
    private func makeRSACA(bits: Int, cn: String = "QuanX MitM Test CA") throws -> (cert: SecCertificate, der: Data, key: SecKey, ski: Data) {
        var err: Unmanaged<CFError>?
        let keyAttrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: NSNumber(value: bits)]
        guard let key = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &err),
              let pub = SecKeyCopyPublicKey(key),
              let pkcs1Pub = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
            throw XCTSkip("RSA \(bits) key generation failed: \(String(describing: err?.takeRetainedValue()))")
        }
        let ski = sha1(pkcs1Pub)
        let spki = DER.seq(DER.seq(DER.oid(DER.oidRSAEncryption), Data([0x05, 0x00])), DER.bitString(pkcs1Pub))
        let bc = DER.extn(DER.oidBasicConstraints, critical: true, valueDER: DER.seq(DER.boolean(true)))
        let ku = DER.extn(DER.oidKeyUsage, critical: true, valueDER: DER.bitString(Data([0x06]), unusedBits: 1))
        let skiExt = DER.extn(DER.oidSubjectKeyIdentifier, critical: false, valueDER: DER.octetString(ski))
        let name = DER.seq(DER.set(DER.seq(DER.oid(DER.oidCN), DER.utf8(cn))))
        let now = Date()
        let tbs = DER.seq(
            DER.explicit(0, DER.integer(bigEndian: Data([2]))),
            DER.integer(bigEndian: Data([0x01, 0x23, 0x45, 0x67])),
            DER.algIdRSASHA256(),
            name,
            DER.seq(DER.utcTime(now.addingTimeInterval(-86400)), DER.utcTime(now.addingTimeInterval(5 * 365 * 86400))),
            name,
            spki,
            DER.explicit(3, DER.seq(bc, ku, skiExt)))
        let sig = try XCTUnwrap(SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, tbs as CFData, &err) as Data?)
        let der = DER.certificate(tbs: tbs, rsaSignature: sig)
        let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData), "CA DER rejected by Security")
        return (cert, der, key, ski)
    }

    // MARK: DER walking

    private struct Parsed {
        var tbsSigAlg: Data
        var outerSigAlg: Data
        var issuer: Data
        var subject: Data
        var extensions: [Data: Data] = [:]   // OID content → extnValue content
    }

    private func parse(_ der: Data) throws -> Parsed {
        var r = DERReader(data: der)
        let cert = try r.readTLV(tag: 0x30)
        var c = DERReader(data: cert)
        let tbs = try c.readTLV(tag: 0x30)
        let outer = try c.readRawTLV()
        var t = DERReader(data: tbs)
        if t.peekTag() == 0xA0 { try t.readAnyTLV() }
        try t.readAnyTLV()                       // serial
        let sigAlg = try t.readRawTLV()
        let issuer = try t.readRawTLV()
        try t.readAnyTLV()                       // validity
        let subject = try t.readRawTLV()
        try t.readAnyTLV()                       // spki
        var p = Parsed(tbsSigAlg: sigAlg, outerSigAlg: outer, issuer: issuer, subject: subject)
        if t.peekTag() == 0xA3 {
            let a3 = try t.readTLV(tag: 0xA3)
            var w = DERReader(data: a3)
            let seq = try w.readTLV(tag: 0x30)
            var e = DERReader(data: seq)
            while e.peekTag() == 0x30 {
                let one = try e.readTLV(tag: 0x30)
                var x = DERReader(data: one)
                let oid = try x.readTLV(tag: 0x06)
                if x.peekTag() == 0x01 { try x.readAnyTLV() }
                p.extensions[oid] = try x.readTLV(tag: 0x04)
            }
        }
        return p
    }

    /// (raw TBS TLV, signature BIT STRING payload) of a certificate.
    private func tbsAndSignature(_ der: Data) throws -> (Data, Data) {
        var r = DERReader(data: der)
        let cert = try r.readTLV(tag: 0x30)
        var c = DERReader(data: cert)
        let tbs = try c.readRawTLV()
        try c.readAnyTLV()
        let bits = try c.readTLV(tag: 0x03)
        return (tbs, bits.dropFirst())
    }

    private func trusts(leafDER: Data, caDER: Data, host: String) throws -> (Bool, String) {
        let leaf = try XCTUnwrap(SecCertificateCreateWithData(nil, leafDER as CFData), "leaf DER rejected by Security")
        let ca = try XCTUnwrap(SecCertificateCreateWithData(nil, caDER as CFData))
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, host as CFString)
        let created = SecTrustCreateWithCertificates([leaf, ca] as CFArray, policy, &trust)
        XCTAssertEqual(created, errSecSuccess)
        let tr = try XCTUnwrap(trust)
        let anchored = SecTrustSetAnchorCertificates(tr, [ca] as CFArray)
        XCTAssertEqual(anchored, errSecSuccess)
        let only = SecTrustSetAnchorCertificatesOnly(tr, true)
        XCTAssertEqual(only, errSecSuccess)
        var cfErr: CFError?
        let ok = SecTrustEvaluateWithError(tr, &cfErr)
        return (ok, cfErr.map { String(describing: $0) } ?? "")
    }

    private func checkRSALeaf(_ leafDER: Data, caDER: Data, ski: Data, host: String) throws {
        let leaf = try parse(leafDER)
        let ca = try parse(caDER)
        let rsaAlgId = Data([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00])
        XCTAssertEqual(leaf.tbsSigAlg, rsaAlgId, "tbsCertificate.signature must be sha256WithRSAEncryption + NULL")
        XCTAssertEqual(leaf.outerSigAlg, rsaAlgId, "signatureAlgorithm must be sha256WithRSAEncryption + NULL")
        XCTAssertEqual(leaf.issuer, ca.subject, "issuer must be the CA subject DER verbatim")
        let aki = try XCTUnwrap(leaf.extensions[Data([0x55, 0x1D, 0x23])], "leaf has no AuthorityKeyIdentifier")
        XCTAssertEqual(aki, DER.seq(DER.tlv(0x80, ski)), "AKI keyIdentifier must equal the CA SKI")
        // The leaf key stays EC P-256.
        let leafCert = try XCTUnwrap(SecCertificateCreateWithData(nil, leafDER as CFData))
        let leafKey = try XCTUnwrap(SecCertificateCopyKey(leafCert))
        let attrs = try XCTUnwrap(SecKeyCopyAttributes(leafKey) as? [CFString: Any])
        XCTAssertEqual(attrs[kSecAttrKeyType] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
        let (ok, why) = try trusts(leafDER: leafDER, caDER: caDER, host: host)
        XCTAssertTrue(ok, "SecTrust rejected the RSA-signed leaf: \(why)")
    }

    // MARK: tests

    func testRSA2048CAImportsFromP12IssuesTrustedLeafAndRoundTrips() throws {
        let ca = try makeRSACA(bits: 2048)
        let p12 = try NCPKCS12Exporter.shared.export(leafDER: ca.der, leafKey: ca.key, caDER: Data(), password: "quanx")

        // QX import path: pemPair (validateCAPair) must accept the RSA CA.
        let pair = try NCCAManager.pemPair(fromP12: p12, password: "quanx")
        XCTAssertTrue(String(decoding: pair.pemKey, as: UTF8.self).contains("-----BEGIN PRIVATE KEY-----"))

        let home = try tmpHome()
        let dir = NCCAManager.caDir(home: home)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try pair.pemCert.write(to: dir.appendingPathComponent("ca.pem"))
        try pair.pemKey.write(to: dir.appendingPathComponent("ca.key"))

        let loaded = try XCTUnwrap(NCCAManager.loadCA(home: home), "loadCA could not read the imported RSA CA")
        XCTAssertTrue(DER.isRSAKey(loaded.caKey))
        XCTAssertEqual(SecCertificateCopyData(loaded.caCert) as Data, ca.der)
        XCTAssertEqual(NCCAManager.caInfo(home: home).algorithm, "RSA")

        let issuer = try LeafCertIssuer(caCertificate: loaded.caCert, caPrivateKey: loaded.caKey)
        let host = "api.example.com"
        let leaf = try issuer.issueLeafCertificate(for: host)
        try checkRSALeaf(leaf.leafCertificateDER, caDER: ca.der, ski: ca.ski, host: host)
        XCTAssertNotNil(leaf.pkcs12Data)
        let leafP12 = try XCTUnwrap(leaf.pkcs12Data)
        XCTAssertNoThrow(try LeafIdentityCache.importPKCS12(leafP12, password: "tern"))

        // trustChain / full export: the RSA CA exports to a p12 that imports again.
        let chain = try XCTUnwrap(NCCAManager.trustChain(home: home))
        try checkRSALeaf(chain.leafDER, caDER: chain.caDER, ski: ca.ski, host: chain.hostname)
        let exported = try NCCAManager.exportP12(home: home, password: "again")
        let again = try NCCAManager.pemPair(fromP12: exported, password: "again")
        XCTAssertEqual(again.pemCert, pair.pemCert)
    }

    func testRSA3072And4096CAsAccepted() throws {
        for bits in [3072, 4096] {
            let ca = try makeRSACA(bits: bits)
            let p12 = try NCPKCS12Exporter.shared.export(leafDER: ca.der, leafKey: ca.key, caDER: Data(), password: "p")
            XCTAssertNoThrow(try NCCAManager.pemPair(fromP12: p12, password: "p"), "RSA \(bits) CA rejected")
            let issuer = try LeafCertIssuer(caCertificate: ca.cert, caPrivateKey: ca.key)
            let leaf = try issuer.issueLeafCertificate(for: "rsa\(bits).example.org")
            try checkRSALeaf(leaf.leafCertificateDER, caDER: ca.der, ski: ca.ski, host: "rsa\(bits).example.org")
        }
    }

    func testECCAPathUnchanged() throws {
        let home = try tmpHome()
        let gen = try NCCAManager.generateCA(home: home, reload: false)
        XCTAssertFalse(DER.isRSAKey(gen.caKey))
        let loaded = try XCTUnwrap(NCCAManager.loadCA(home: home))
        let caDER = SecCertificateCopyData(loaded.caCert) as Data
        let issuer = try LeafCertIssuer(caCertificate: loaded.caCert, caPrivateKey: loaded.caKey)
        let leaf = try issuer.issueLeafCertificate(for: "ec.example.com")
        let p = try parse(leaf.leafCertificateDER)
        XCTAssertEqual(p.tbsSigAlg, DER.algIdECDSA())
        XCTAssertEqual(p.outerSigAlg, DER.algIdECDSA())
        let caParsed = try parse(caDER)
        XCTAssertEqual(p.issuer, caParsed.subject)
        XCTAssertNil(p.extensions[Data([0x55, 0x1D, 0x23])], "EC leaves carry no AKI (unchanged)")
        // The EC leaf + CA signatures must verify (ecdsa-with-SHA256 over the TBS, DER ECDSA-Sig-Value) — before this lane
        // DER.certificate split the DER signature as raw r||s and neither verified (run 40277857806).
        let caPub = try XCTUnwrap(SecCertificateCopyKey(loaded.caCert))
        let (leafTBS, leafSig) = try tbsAndSignature(leaf.leafCertificateDER)
        XCTAssertTrue(SecKeyVerifySignature(caPub, .ecdsaSignatureMessageX962SHA256, leafTBS as CFData, leafSig as CFData, nil),
                      "EC leaf signature does not verify with the CA key")
        let (caTBS, caSig) = try tbsAndSignature(caDER)
        XCTAssertTrue(SecKeyVerifySignature(caPub, .ecdsaSignatureMessageX962SHA256, caTBS as CFData, caSig as CFData, nil),
                      "EC CA self-signature does not verify")
        let (ok, why) = try trusts(leafDER: leaf.leafCertificateDER, caDER: caDER, host: "ec.example.com")
        XCTAssertTrue(ok, "SecTrust rejected the EC leaf: \(why)")
        // EC CA still exports / re-imports through the p12 path.
        let p12 = try NCCAManager.exportP12(home: home, password: "ec")
        let pair = try NCCAManager.pemPair(fromP12: p12, password: "ec")
        XCTAssertTrue(String(decoding: pair.pemKey, as: UTF8.self).contains("-----BEGIN PRIVATE KEY-----"))
    }
}
