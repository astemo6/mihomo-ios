import XCTest
import CryptoKit
import Security
@testable import Tern

/// fix/nc-tls-scripts (device build506 diag 22:11): node TLS failures, unmapped fake-ip, QX TLS semantics.
///
/// The TLS cases drive the real NCTLSClientStream against an in-memory TLS 1.3 server built from the same key
/// schedule helpers (NCTLS13): X25519 / P-256 after HelloRetryRequest, Ed25519 / ECDSA P-256 / P-384 / RSA-PSS
/// certificates, one coalesced record or one record per message, TLSInnerPlaintext zero padding (REALITY pads its
/// encrypted handshake records), and a server that omits CertificateVerify.
final class NativeCoreTLSScriptsTests: XCTestCase {

    // MARK: - DER helpers (a minimal certificate: NCX509Certificate only reads the SPKI and the signature field;
    // skip-cert-verify keeps SecTrust out of the way, the CertificateVerify signature is still checked)

    static func tlv(_ tag: UInt8, _ v: Data) -> Data {
        var out = Data([tag])
        let n = v.count
        if n < 0x80 { out.append(UInt8(n)) }
        else if n < 0x100 { out.append(contentsOf: [0x81, UInt8(n)]) }
        else { out.append(contentsOf: [0x82, UInt8(n >> 8), UInt8(n & 0xff)]) }
        out.append(v)
        return out
    }
    static func seq(_ parts: Data...) -> Data { tlv(0x30, parts.reduce(Data(), +)) }
    static func oid(_ b: [UInt8]) -> Data { tlv(0x06, Data(b)) }
    static func bits(_ d: Data) -> Data { tlv(0x03, Data([0]) + d) }

    static func cert(spki: Data) -> Data {
        let tbs = seq(tlv(0xa0, tlv(0x02, Data([2]))), tlv(0x02, Data([1])),
                      seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])),
                      seq(), seq(), seq(), spki)
        return seq(tbs, seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])), bits(Data(repeating: 7, count: 16)))
    }

    enum KeyKind { case ed25519, p256, p384, rsaPSS }

    /// A server identity: certificate DER, CertificateVerify scheme and signer.
    struct Identity {
        let der: Data
        let scheme: UInt16
        let sign: (Data) -> Data
    }

    static func identity(_ k: KeyKind) -> Identity {
        switch k {
        case .ed25519:
            let key = Curve25519.Signing.PrivateKey()
            let spki = seq(seq(oid([0x2b, 0x65, 0x70])), bits(key.publicKey.rawRepresentation))
            return Identity(der: cert(spki: spki), scheme: 0x0807) { (try? key.signature(for: $0)) ?? Data() }
        case .p256:
            let key = P256.Signing.PrivateKey()
            let spki = seq(seq(oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])),
                           bits(key.publicKey.x963Representation))
            return Identity(der: cert(spki: spki), scheme: 0x0403) {
                (try? key.signature(for: SHA256.hash(data: $0)))?.derRepresentation ?? Data()
            }
        case .p384:
            let key = P384.Signing.PrivateKey()
            let spki = seq(seq(oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), oid([0x2b, 0x81, 0x04, 0x00, 0x22])),
                           bits(key.publicKey.x963Representation))
            return Identity(der: cert(spki: spki), scheme: 0x0503) {
                (try? key.signature(for: SHA384.hash(data: $0)))?.derRepresentation ?? Data()
            }
        case .rsaPSS:
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
            let priv = SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
            let pub = SecKeyCopyPublicKey(priv)!
            let pkcs1 = SecKeyCopyExternalRepresentation(pub, nil)! as Data
            let spki = seq(seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), tlv(0x05, Data())), bits(pkcs1))
            return Identity(der: cert(spki: spki), scheme: 0x0804) {
                (SecKeyCreateSignature(priv, .rsaSignatureMessagePSSSHA256, $0 as CFData, nil) as Data?) ?? Data()
            }
        }
    }

    // MARK: - In-memory TLS 1.3 server

    struct ServerOptions {
        var identity: Identity
        var hrrGroup: UInt16? = nil          // answer the first hello with a HelloRetryRequest for this group
        var coalesce = false                 // EE + Certificate + CertificateVerify + Finished in one record
        var padding = 0                      // TLSInnerPlaintext zero padding per encrypted record
        var omitCertificateVerify = false
        var corruptSignature = false
    }

    final class FakeServer: NCRelayStream {
        let q: DispatchQueue
        var opt: ServerOptions
        private var inbox = Data()
        private var pending: ((Data?, Error?) -> Void)?
        private var outbox: [Data] = []
        private var transcript = Data()
        private var hellos = 0
        private var done = false
        private(set) var sawSecondHelloGroup: UInt16?

        init(queue: DispatchQueue, options: ServerOptions) { q = queue; opt = options }

        func send(_ data: Data, completion: @escaping () -> Void) {
            q.async {
                completion()
                self.inbox.append(data)
                self.process()
            }
        }
        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            q.async {
                if !self.outbox.isEmpty { handler(self.outbox.removeFirst(), nil) } else { self.pending = handler }
            }
        }
        func cancel() {}

        private func emit(_ d: Data) {
            if let h = pending { pending = nil; h(d, nil) } else { outbox.append(d) }
        }

        private func process() {
            while inbox.count >= 5 {
                let len = Int(inbox[inbox.startIndex + 3]) << 8 | Int(inbox[inbox.startIndex + 4])
                guard inbox.count >= 5 + len else { return }
                let type = inbox[inbox.startIndex]
                let payload = Data(inbox[(inbox.startIndex + 5)..<(inbox.startIndex + 5 + len)])
                inbox = Data(inbox[(inbox.startIndex + 5 + len)...])
                if type == 22, !done, payload.first == 1 { clientHello(payload) }
            }
        }

        /// (group, key) of the client's key_share.
        private static func keyShare(_ hello: Data) -> (UInt16, Data)? {
            let b = [UInt8](hello)
            var i = 4 + 2 + 32
            i += 1 + Int(b[i])
            i += 2 + (Int(b[i]) << 8 | Int(b[i + 1]))
            i += 1 + Int(b[i])
            let end = i + 2 + (Int(b[i]) << 8 | Int(b[i + 1]))
            i += 2
            while i + 4 <= end {
                let t = Int(b[i]) << 8 | Int(b[i + 1]); let n = Int(b[i + 2]) << 8 | Int(b[i + 3])
                if t == 51 {
                    let g = UInt16(b[i + 6]) << 8 | UInt16(b[i + 7])
                    let kl = Int(b[i + 8]) << 8 | Int(b[i + 9])
                    return (g, Data(b[(i + 10)..<(i + 10 + kl)]))
                }
                i += 4 + n
            }
            return nil
        }

        private static func handshake(_ type: UInt8, _ body: Data) -> Data {
            var m = Data([type, UInt8(body.count >> 16), UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)])
            m.append(body)
            return m
        }
        private static func ext(_ t: UInt16, _ d: Data) -> Data {
            var e = Data(); e.appendBE16(t); e.appendBE16(UInt16(d.count)); e.append(d); return e
        }
        private static func serverHello(random: Data, exts: Data) -> Data {
            var body = Data([0x03, 0x03]); body.append(random)
            body.append(32); body.append(Data(repeating: 0, count: 32))
            body.append(contentsOf: [0x13, 0x01, 0x00])
            body.appendBE16(UInt16(exts.count)); body.append(exts)
            return handshake(2, body)
        }
        private static func plainRecord(_ m: Data) -> Data {
            var r = Data([22, 3, 3]); r.appendBE16(UInt16(m.count)); r.append(m); return r
        }

        private func clientHello(_ hello: Data) {
            hellos += 1
            guard let (group, clientKey) = Self.keyShare(hello) else { return }
            if hellos == 1, let g = opt.hrrGroup {
                var exts = Self.ext(43, Data([0x03, 0x04]))
                var gd = Data(); gd.appendBE16(g)
                exts.append(Self.ext(51, gd))
                exts.append(Self.ext(44, Data([0x00, 0x04, 0xc0, 0x0c, 0x1e, 0x55])))
                let hrr = Self.serverHello(random: NCTLS13.helloRetryRequestRandom, exts: exts)
                transcript = NCTLS13.syntheticMessageHash(for: hello, kind: .sha256)
                transcript.append(hrr)
                emit(Self.plainRecord(hrr))
                return
            }
            if hellos == 2 { sawSecondHelloGroup = group }
            transcript.append(hello)
            let shared: Data
            let serverKey: Data
            switch group {
            case 0x0017:
                let k = P256.KeyAgreement.PrivateKey()
                guard let p = try? P256.KeyAgreement.PublicKey(x963Representation: clientKey),
                      let s = try? k.sharedSecretFromKeyAgreement(with: p) else { return }
                shared = s.withUnsafeBytes { Data($0) }; serverKey = k.publicKey.x963Representation
            default:
                let k = Curve25519.KeyAgreement.PrivateKey()
                guard let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientKey),
                      let s = try? k.sharedSecretFromKeyAgreement(with: p) else { return }
                shared = s.withUnsafeBytes { Data($0) }; serverKey = k.publicKey.rawRepresentation
            }
            var ks = Data(); ks.appendBE16(group); ks.appendBE16(UInt16(serverKey.count)); ks.append(serverKey)
            let sh = Self.serverHello(random: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
                                      exts: Self.ext(43, Data([0x03, 0x04])) + Self.ext(51, ks))
            transcript.append(sh)
            var flight = Self.plainRecord(sh)
            flight.append(Data([20, 3, 3, 0, 1, 1])) // middlebox-compat ChangeCipherSpec

            let k: NCTLS13.HashKind = .sha256
            let zero = Data(repeating: 0, count: 32)
            let early = NCTLS13.hkdfExtract(k, salt: zero, ikm: zero)
            let derived = NCTLS13.deriveSecret(k, secret: early, label: "derived", transcriptHash: k.hash(Data()))
            let hs = NCTLS13.hkdfExtract(k, salt: derived, ikm: shared)
            let sHS = NCTLS13.deriveSecret(k, secret: hs, label: "s hs traffic", transcriptHash: k.hash(transcript))
            let keys = NCTLS13.trafficKeyIV(k, suite: .aes128GCM, secret: sHS)

            var messages: [Data] = []
            let ee = Self.handshake(8, Data([0, 0]))
            transcript.append(ee); messages.append(ee)
            var cl = Data([0])
            var entry = Data([UInt8(opt.identity.der.count >> 16), UInt8((opt.identity.der.count >> 8) & 0xff), UInt8(opt.identity.der.count & 0xff)])
            entry.append(opt.identity.der); entry.append(contentsOf: [0, 0])
            cl.append(contentsOf: [UInt8(entry.count >> 16), UInt8((entry.count >> 8) & 0xff), UInt8(entry.count & 0xff)])
            cl.append(entry)
            let certMsg = Self.handshake(11, cl)
            transcript.append(certMsg); messages.append(certMsg)
            if !opt.omitCertificateVerify {
                var content = Data(repeating: 0x20, count: 64)
                content.append(Data("TLS 1.3, server CertificateVerify".utf8)); content.append(0)
                content.append(k.hash(transcript))
                var sig = opt.identity.sign(content)
                if opt.corruptSignature, !sig.isEmpty { sig[sig.startIndex + sig.count / 2] ^= 0x55 }
                var cv = Data(); cv.appendBE16(opt.identity.scheme); cv.appendBE16(UInt16(sig.count)); cv.append(sig)
                let cvMsg = Self.handshake(15, cv)
                transcript.append(cvMsg); messages.append(cvMsg)
            }
            let fin = Self.handshake(20, NCTLS13.finishedVerifyData(k, trafficSecret: sHS, transcriptHash: k.hash(transcript)))
            transcript.append(fin); messages.append(fin)

            var seqNo: UInt64 = 0
            func seal(_ content: Data) -> Data {
                var inner = content
                inner.append(22)
                inner.append(Data(repeating: 0, count: opt.padding))
                var header = Data([23, 3, 3]); header.appendBE16(UInt16(inner.count + 16))
                let sealed = NCTLS13.sealRecord(suite: .aes128GCM, key: keys.key, iv: keys.iv, seq: seqNo, header: header, plaintext: inner)!
                seqNo += 1
                return header + sealed
            }
            if opt.coalesce { flight.append(seal(messages.reduce(Data(), +))) }
            else { for m in messages { flight.append(seal(m)) } }
            done = true
            emit(flight)
        }
    }

    /// Runs the client handshake against the fake server; nil = success, else the error text.
    private func handshake(_ opt: ServerOptions, server: inout FakeServer?) -> String? {
        let q = DispatchQueue(label: "tls.test")
        let s = FakeServer(queue: q, options: opt)
        server = s
        var cfg = NCTLSClientStream.Config(serverName: "node.example")
        cfg.alpn = []
        cfg.allowInsecure = true
        let tls = NCTLSClientStream(raw: s, config: cfg, queue: q)
        let e = expectation(description: "handshake")
        var out: String? = "no completion"
        q.async {
            tls.startHandshake { err in
                out = err.map { ($0 as? LocalizedError)?.errorDescription ?? "\($0)" }
                e.fulfill()
            }
        }
        wait(for: [e], timeout: 10)
        return out
    }

    private func ok(_ opt: ServerOptions, file: StaticString = #filePath, line: UInt = #line) {
        var s: FakeServer?
        XCTAssertNil(handshake(opt, server: &s), file: file, line: line)
    }

    // MARK: - TLS cases

    func testEd25519CoalescedPaddedRecord() {
        // REALITY shape: everything in one encrypted record with zero padding after the content type.
        ok(ServerOptions(identity: Self.identity(.ed25519), coalesce: true, padding: 48))
    }

    func testPaddedRecordsOnePerMessage() {
        // Before the fix: padded records read content type 0 and were dropped → "server Finished without a verified
        // CertificateVerify" (the 薯条 provider's failure on device).
        ok(ServerOptions(identity: Self.identity(.p256), padding: 200))
    }

    func testRSAPSSCertificateVerify() {
        ok(ServerOptions(identity: Self.identity(.rsaPSS)))
    }

    func testECDSAP384CertificateVerify() {
        ok(ServerOptions(identity: Self.identity(.p384), coalesce: true))
    }

    func testHelloRetryRequestToP256() {
        var s: FakeServer?
        let err = handshake(ServerOptions(identity: Self.identity(.p256), hrrGroup: 0x0017), server: &s)
        XCTAssertNil(err)
        XCTAssertEqual(s?.sawSecondHelloGroup, 0x0017, "ClientHello2 carries a P-256 key share")
    }

    func testHelloRetryRequestCookieOnlyKeepsX25519() {
        var s: FakeServer?
        XCTAssertNil(handshake(ServerOptions(identity: Self.identity(.ed25519), hrrGroup: 0x001d), server: &s))
        XCTAssertEqual(s?.sawSecondHelloGroup, 0x001d)
    }

    func testFinishedWithoutCertificateVerifyFailsWithDetail() {
        var s: FakeServer?
        let err = handshake(ServerOptions(identity: Self.identity(.ed25519), omitCertificateVerify: true), server: &s) ?? ""
        XCTAssertTrue(err.contains("without a verified CertificateVerify"), err)
        XCTAssertTrue(err.contains("Certificate yes"), err)
        XCTAssertTrue(err.contains("CertificateVerify no"), err)
    }

    func testCorruptSignatureStillRejectedWithSkipCertVerify() {
        // skip-cert-verify waives the chain, never the handshake signature (Clash.Meta / crypto/tls semantics).
        var s: FakeServer?
        let err = handshake(ServerOptions(identity: Self.identity(.p384), corruptSignature: true), server: &s) ?? ""
        XCTAssertTrue(err.contains("CertificateVerify signature invalid"), err)
    }

    func testInnerPlaintextStripsPadding() {
        XCTAssertEqual(NCTLS13.innerPlaintext(Data([1, 2, 22, 0, 0, 0]))?.type, 22)
        XCTAssertEqual(NCTLS13.innerPlaintext(Data([1, 2, 22, 0, 0, 0]))?.content, Data([1, 2]))
        XCTAssertEqual(NCTLS13.innerPlaintext(Data([5, 23]))?.type, 23)
        XCTAssertNil(NCTLS13.innerPlaintext(Data([0, 0, 0])))
        XCTAssertNil(NCTLS13.innerPlaintext(Data()))
        let slice = Data([9, 9, 7, 21, 0])[1...]
        XCTAssertEqual(NCTLS13.innerPlaintext(Data(slice))?.content, Data([9, 7]))
    }

    // MARK: - skip-cert-verify reading

    func testSkipCertVerifyAcceptsEverySpelling() {
        func p(_ f: [String: NCJSONValue]) -> NCProxy { NCProxy(name: "n", type: "trojan", fields: f) }
        XCTAssertTrue(p(["skip-cert-verify": .bool(true)]).skipCertVerify)
        XCTAssertTrue(p(["skip-cert-verify": .string("true")]).skipCertVerify)
        XCTAssertTrue(p(["skip-cert-verify": .number(1)]).skipCertVerify)
        XCTAssertTrue(p(["allowInsecure": .string("1")]).skipCertVerify)
        XCTAssertTrue(p(["allow-insecure": .bool(true)]).skipCertVerify)
        XCTAssertFalse(p(["skip-cert-verify": .string("false")]).skipCertVerify)
        XCTAssertFalse(p([:]).skipCertVerify)
    }

    // MARK: - Quantumult X TLS semantics

    private func qx(_ line: String) -> NCProxy? {
        var r = NCImportReport()
        return NCQXImport.buildQXNode(line: line, report: &r)
    }

    func testQXTLSVerificationDefaultsToOff() {
        // QX: tls-verification is opt-in (crossutility sample.conf) — a node without it must not verify.
        let vm = qx("vmess=1.2.3.4:443, method=none, password=00000000-0000-0000-0000-000000000001, obfs=over-tls, obfs-host=a.example, tag=SZ")
        XCTAssertEqual(vm?.fields["skip-cert-verify"]?.bool, true)
        let tj = qx("trojan=b.example:443, password=pw, over-tls=true, tls-host=b.example, tag=T")
        XCTAssertEqual(tj?.fields["skip-cert-verify"]?.bool, true)
        let ws = qx("vmess=c.example:443, method=none, password=00000000-0000-0000-0000-000000000001, obfs=wss, obfs-host=c.example, obfs-uri=/ws, tag=W")
        XCTAssertEqual(ws?.fields["skip-cert-verify"]?.bool, true)
        // plain (no TLS): untouched
        let plain = qx("shadowsocks=d.example:8388, method=aes-128-gcm, password=pw, tag=S")
        XCTAssertNil(plain?.fields["skip-cert-verify"])
    }

    func testQXTLSVerificationTrueAndPin() {
        let pin = String(repeating: "ab", count: 32)
        let tj = qx("trojan=b.example:443, password=pw, over-tls=true, tls-verification=true, tls-cert-sha256=\(pin), tag=T")
        XCTAssertEqual(tj?.fields["skip-cert-verify"]?.bool, false)
        XCTAssertEqual(tj?.fields["fingerprint"]?.string, pin)
        // pins are ignored without verification (QX)
        let off = qx("trojan=b.example:443, password=pw, over-tls=true, tls-verification=false, tls-cert-sha256=\(pin), tag=T")
        XCTAssertEqual(off?.fields["skip-cert-verify"]?.bool, true)
        XCTAssertNil(off?.fields["fingerprint"])
    }

    func testQXRealityAndVisionFlow() {
        let v = qx("vless=5.6.7.8:443, method=none, password=00000000-0000-0000-0000-000000000001, obfs=over-tls, obfs-host=www.apple.com, reality-base64-pubkey=k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk, reality-hex-shortid=0123456789abcdef, vless-flow=xtls-rprx-vision, tag=R")
        XCTAssertEqual(v?.fields["reality-opts"]?.object?["public-key"]?.string, "k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk")
        XCTAssertEqual(v?.fields["reality-opts"]?.object?["short-id"]?.string, "0123456789abcdef")
        XCTAssertEqual(v?.fields["flow"]?.string, "xtls-rprx-vision")
        XCTAssertNotNil(v?.fields["client-fingerprint"])
        XCTAssertNil(v?.fields["reality-base64-pubkey"], "consumed, not passed through verbatim")
    }

    func testQXProviderBodyGoesThroughTheSameRules() {
        // A [server_remote] body fetched with the QuanX User-Agent is parsed by NCSubscriptionParser → buildQXNode.
        let body = """
        vmess=1.2.3.4:443, method=none, password=00000000-0000-0000-0000-000000000001, obfs=over-tls, obfs-host=a.example, tag=SZ CN
        trojan=b.example:443, password=pw, over-tls=true, tls-verification=true, tag=Verified
        """
        let nodes = NCSubscriptionParser.parse(body)
        XCTAssertEqual(nodes.first { $0.name == "SZ CN" }?.skipCertVerify, true)
        XCTAssertEqual(nodes.first { $0.name == "Verified" }?.skipCertVerify, false)
    }

    // MARK: - Fake-IP

    func testUnmappedFakeIPRefusedAtAccept() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        let mapped = pool.address(for: "www.gstatic.com")
        XCTAssertFalse(pool.refusesAtAccept(mapped), "a mapped fake IP is served")
        XCTAssertTrue(pool.refusesAtAccept(NCIP("198.18.251.77")!), "an address nobody was given is refused at accept")
        XCTAssertFalse(pool.refusesAtAccept(NCIP("1.1.1.1")!), "real addresses are not the pool's business")
        pool.flush()
        XCTAssertTrue(pool.refusesAtAccept(mapped), "after a flush the old address is stale")
    }
}
