import XCTest
@testable import Mihomo

// NativeCore batch 1 (docs/native-core-design.md): config decode, rule engine,
// fake-IP pool, group resolution, SOCKS/HTTP builders, Shadowsocks AEAD.
// All pure logic — no sockets, no app container.

private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
private func unhex(_ s: String) -> Data {
    var out = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

final class NativeCoreConfigTests: XCTestCase {
    func testDecode() throws {
        let json = """
        {"mode":"rule","log-level":"debug","ipv6":true,
         "proxies":[{"name":"A","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw","udp":true},
                    {"name":"B","type":"socks5","server":"example.com","port":1080}],
         "proxy-groups":[{"name":"G","type":"url-test","proxies":["A","B"],"url":"http://x/generate_204","interval":120,"tolerance":50}],
         "rules":["DOMAIN-SUFFIX,google.com,G","MATCH,DIRECT"],
         "dns":{"enable":true,"enhanced-mode":"fake-ip","fake-ip-range":"198.18.0.1/16","fake-ip-filter":["*.lan"]}}
        """
        let cfg = try NCConfig.decode(jsonData: Data(json.utf8))
        XCTAssertEqual(cfg.mode, "rule")
        XCTAssertEqual(cfg.proxies.count, 2)
        XCTAssertEqual(cfg.proxyMap["A"]?.cipher, "aes-256-gcm")
        XCTAssertEqual(cfg.proxyMap["A"]?.udp, true)
        XCTAssertEqual(cfg.groupMap["G"]?.interval, 120)
        XCTAssertEqual(cfg.groupMap["G"]?.tolerance, 50)
        XCTAssertEqual(cfg.rules.count, 2)
        XCTAssertEqual(cfg.dns.fakeIPFilter, ["*.lan"])
    }
}

final class NativeCoreIPTests: XCTestCase {
    func testParseAndCIDR() {
        XCTAssertEqual(NCIP("1.2.3.4"), .v4(0x0102_0304))
        XCTAssertNil(NCIP("1.2.3.256"))
        XCTAssertNil(NCIP("01.2.3.4"))
        XCTAssertNotNil(NCIP("::1"))
        XCTAssertNotNil(NCIP("2001:db8::1"))
        XCTAssertEqual(NCIP("::ffff:1.2.3.4")?.string, "1.2.3.4")
        XCTAssertTrue(NCCIDR("10.0.0.0/8")!.contains(NCIP("10.1.2.3")!))
        XCTAssertFalse(NCCIDR("10.0.0.0/8")!.contains(NCIP("11.0.0.1")!))
        XCTAssertTrue(NCCIDR("192.168.0.0/16")!.contains(NCIP("::ffff:192.168.1.1")!))
        XCTAssertTrue(NCCIDR("2001:db8::/32")!.contains(NCIP("2001:db8:1::1")!))
        XCTAssertFalse(NCCIDR("2001:db8::/32")!.contains(NCIP("2001:db9::1")!))
        XCTAssertTrue(NCCIDR("0.0.0.0/0")!.contains(NCIP("8.8.8.8")!))
    }
}

final class NativeCoreRuleTests: XCTestCase {
    private func ctx(domain: String? = nil, ip: String? = nil, port: Int? = nil) -> NCMatchContext {
        var c = NCMatchContext()
        c.domain = domain
        c.ip = ip.flatMap { NCIP($0) }
        c.dstPort = port
        return c
    }

    func testBasicKinds() {
        let suffix = NCRule.parse("DOMAIN-SUFFIX,google.com,PROXY")!
        XCTAssertTrue(NCRuleMatcher.matches(suffix, ctx(domain: "www.google.com")))
        XCTAssertTrue(NCRuleMatcher.matches(suffix, ctx(domain: "google.com")))
        XCTAssertFalse(NCRuleMatcher.matches(suffix, ctx(domain: "notgoogle.com")))
        let cidr = NCRule.parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")!
        XCTAssertTrue(cidr.noResolve)
        XCTAssertTrue(NCRuleMatcher.matches(cidr, ctx(ip: "10.2.3.4")))
        XCTAssertFalse(NCRuleMatcher.matches(cidr, ctx(domain: "a.com")))
        let port = NCRule.parse("DST-PORT,8000-9000,PROXY")!
        XCTAssertTrue(NCRuleMatcher.matches(port, ctx(port: 8443)))
        XCTAssertFalse(NCRuleMatcher.matches(port, ctx(port: 80)))
        let wild = NCRule.parse("DOMAIN-WILDCARD,*.example.com,PROXY")!
        XCTAssertTrue(NCRuleMatcher.matches(wild, ctx(domain: "a.example.com")))
        XCTAssertFalse(NCRuleMatcher.matches(wild, ctx(domain: "example.com")))
    }

    func testLogicAndEvaluate() {
        let and = NCRule.parse("AND,((DOMAIN,example.com),(DST-PORT,443)),PROXY")!
        XCTAssertEqual(and.subRules.count, 2)
        XCTAssertTrue(NCRuleMatcher.matches(and, ctx(domain: "example.com", port: 443)))
        XCTAssertFalse(NCRuleMatcher.matches(and, ctx(domain: "example.com", port: 80)))
        let not = NCRule.parse("NOT,((DOMAIN,example.com)),DIRECT")!
        XCTAssertTrue(NCRuleMatcher.matches(not, ctx(domain: "other.com")))
        let rules = ["DOMAIN,example.com,DIRECT", "MATCH,PROXY"].compactMap(NCRule.parse)
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(domain: "example.com")), "DIRECT")
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx(domain: "x.com")), "PROXY")
    }
}

final class NativeCoreFakeIPTests: XCTestCase {
    func testPool() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16", filter: ["*.lan", "localhost"])
        let a = pool.address(for: "Example.COM")
        let b = pool.address(for: "example.com")
        XCTAssertEqual(a, b) // stable + case-insensitive
        XCTAssertEqual(pool.host(for: a), "example.com")
        XCTAssertFalse(pool.shouldFake("printer.lan"))
        XCTAssertFalse(pool.shouldFake("localhost"))
        XCTAssertTrue(pool.shouldFake("example.com"))
        let data = pool.snapshotData()!
        let pool2 = NCFakeIPPool(range: "198.18.0.1/16")
        pool2.restore(data: data)
        XCTAssertEqual(pool2.address(for: "example.com"), a)
        XCTAssertEqual(pool2.host(for: a), "example.com")
    }
}

final class NativeCoreGroupTests: XCTestCase {
    private func engine() -> NCGroupEngine {
        let json = """
        {"proxies":[{"name":"A","type":"socks5","server":"a","port":1},{"name":"B","type":"socks5","server":"b","port":2}],
         "proxy-groups":[{"name":"SEL","type":"select","proxies":["A","B"]},
                          {"name":"AUTO","type":"url-test","proxies":["A","B"]},
                          {"name":"FB","type":"fallback","proxies":["A","B"]},
                          {"name":"LB","type":"load-balance","proxies":["A","B"]}]}
        """
        return NCGroupEngine(config: try! NCConfig.decode(jsonData: Data(json.utf8)))
    }

    func testResolve() {
        let e = engine()
        XCTAssertEqual(e.resolve("SEL"), .proxy(NCProxy(name: "A", type: "socks5", fields: ["name": .string("A"), "type": .string("socks5"), "server": .string("a"), "port": .number(1)])))
        e.selections["SEL"] = "B"
        if case .proxy(let p) = e.resolve("SEL") { XCTAssertEqual(p.name, "B") } else { XCTFail() }
        e.delays = ["A": 300, "B": 90]
        if case .proxy(let p) = e.resolve("AUTO") { XCTAssertEqual(p.name, "B") } else { XCTFail() }
        e.alive = ["A": false, "B": true]
        if case .proxy(let p) = e.resolve("FB") { XCTAssertEqual(p.name, "B") } else { XCTFail() }
        var seen: [String] = []
        for _ in 0..<3 { if case .proxy(let p) = e.resolve("LB") { seen.append(p.name) } }
        XCTAssertEqual(seen, ["A", "B", "A"])
        XCTAssertEqual(e.resolve("DIRECT"), .direct)
        XCTAssertEqual(e.resolve("REJECT"), .reject)
        XCTAssertEqual(e.resolve("NOPE"), .unknown("NOPE"))
    }
}

final class NativeCoreOutboundTests: XCTestCase {
    func testBuilders() {
        let t = NCTarget(host: "example.com", port: 443)
        XCTAssertEqual(hex(t.atypEncoded), "030b6578616d706c652e636f6d01bb")
        XCTAssertEqual(hex(NCSOCKS5.greeting(username: nil, password: nil)), "050100")
        let req = NCSOCKS5.connectRequest(target: t)
        XCTAssertEqual(hex(req), "050100030b6578616d706c652e636f6d01bb")
        // Response: ver, rep=0, rsv, atyp=v4, 1.2.3.4:80
        let resp = unhex("05000001" + "01020304" + "0050")
        XCTAssertEqual(NCSOCKS5.parseResponse(resp)?.0, 10)
        XCTAssertEqual(NCSOCKS5.parseResponse(resp)?.1, 0)
        XCTAssertNil(NCSOCKS5.parseResponse(Data([0x05, 0x00])))
        let http = String(decoding: NCHTTPProxy.connectRequest(target: t, username: "u", password: "p"), as: UTF8.self)
        XCTAssertTrue(http.hasPrefix("CONNECT example.com:443 HTTP/1.1\r\n"))
        XCTAssertTrue(http.contains("Proxy-Authorization: Basic dTpw\r\n"))
    }
}

final class NativeCoreShadowsocksTests: XCTestCase {
    func testKeyVectors() {
        // EVP_BytesToKey("shadowsocks", 32) and HKDF-SHA1 subkey with salt 00..0f,
        // computed independently (python hashlib/hmac) from the spec.
        let master = NCShadowsocks.masterKey(password: "shadowsocks", keyLen: 32)
        XCTAssertEqual(hex(master), "d210b068815fd83ccce65e5fe82f905c7bd39705b9454e571da3a25e607cfe06")
        let salt = Data((0..<16).map { UInt8($0) })
        let sub = NCShadowsocks.subkey(master: master, salt: salt, keyLen: 32)
        XCTAssertEqual(hex(sub), "fad074ccee3639786451af244e902342d127127484cfb6b7d504d7759b3e119a")
    }

    func testRoundtrip() {
        for cipher in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"] {
            let salt = Data(repeating: 0x42, count: cipher == "aes-128-gcm" ? 16 : 32)
            let enc = NCSSEncoder(cipher: cipher, password: "shadowsocks", salt: salt)!
            let dec = NCSSDecoder(cipher: cipher, password: "shadowsocks")!
            let payload = Data((0..<20000).map { UInt8($0 % 251) }) // > 0x3FFF forces multiple chunks
            let wire = enc.encode(payload)!
            XCTAssertEqual(Data(wire.prefix(salt.count)), salt)
            var out = Data()
            // Feed in awkward slices to exercise the streaming decoder.
            var rest = wire
            while !rest.isEmpty {
                let n = min(rest.count, 997)
                out.append(dec.feed(Data(rest.prefix(n)))!)
                rest = rest.dropFirst(n)
            }
            XCTAssertEqual(out, payload, cipher)
        }
    }

    /// SIP022 UDP packet codec (fix/nc-ss-udp): golden vectors generated by
    /// the independent python reference in tools/loopback/ss-aead-udp-check.py
    /// (EVP_BytesToKey + HKDF-SHA1 via hashlib/hmac, AEAD via `cryptography`),
    /// whose crypto was cross-checked byte-exact against sing-box over TCP.
    /// Plain = ATYP(127.0.0.1:18081) ‖ the loopback tests' DNS-shaped payload,
    /// password "nc-loop-ss-pw" (the loopback fixtures).
    func testUDPPacketGoldenVectors() {
        let plain = unhex("017f00000146a1"
                          + "4e4301000001000000000000" + "076578616d706c6503636f6d00" + "00010001")
        let reqSalt = Data((0x00..<0x20).map { UInt8($0) })
        let repSalt = Data((0x20..<0x40).map { UInt8($0) })

        let aesReq = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "c1bf4f54770127eaefe14cb79414f3d5cb54cea7372ddc014583b854a3891da3"
            + "dcc01ade88f0a6f5c444c9be039adeea144056de"
        XCTAssertEqual(hex(NCShadowsocks.udpPacketEncode(cipher: "aes-256-gcm", password: "nc-loop-ss-pw",
                                                         plain: plain, salt: reqSalt)!), aesReq)
        XCTAssertEqual(NCShadowsocks.udpPacketDecode(cipher: "aes-256-gcm", password: "nc-loop-ss-pw",
                                                     packet: unhex(aesReq)), plain)

        // Server direction: fresh salt, identical construction.
        let aesRep = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            + "2448f3cad3fa1a47635f9562f750b7a15bea1478f959203644c7f429013678650"
            + "dd6209c1aee0bedec7f7c02548f93ced574fb15"
        XCTAssertEqual(NCShadowsocks.udpPacketDecode(cipher: "aes-256-gcm", password: "nc-loop-ss-pw",
                                                     packet: unhex(aesRep)), plain)

        let chachaReq = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "bed6aa6b9b19e96227112fddf9d0535a9025d77780c69bec287d67f987e3ff77"
            + "27263c60bee52e0899dc59f3de3d969634d24dff"
        XCTAssertEqual(hex(NCShadowsocks.udpPacketEncode(cipher: "chacha20-ietf-poly1305",
                                                         password: "nc-loop-ss-pw",
                                                         plain: plain, salt: reqSalt)!), chachaReq)
        XCTAssertEqual(NCShadowsocks.udpPacketDecode(cipher: "chacha20-ietf-poly1305",
                                                     password: "nc-loop-ss-pw",
                                                     packet: unhex(chachaReq)), plain)

        // Roundtrip with random salts, and rejection of damaged packets.
        for cipher in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"] {
            let packet = NCShadowsocks.udpPacketEncode(cipher: cipher, password: "pw", plain: plain)!
            XCTAssertEqual(NCShadowsocks.udpPacketDecode(cipher: cipher, password: "pw", packet: packet),
                           plain, cipher)
            var tampered = packet
            tampered[tampered.count - 1] ^= 0xff
            XCTAssertNil(NCShadowsocks.udpPacketDecode(cipher: cipher, password: "pw", packet: tampered),
                         cipher)
            XCTAssertNil(NCShadowsocks.udpPacketDecode(cipher: cipher, password: "pw",
                                                       packet: Data(packet.prefix(20))), cipher)
            XCTAssertNil(NCShadowsocks.udpPacketDecode(cipher: cipher, password: "nope", packet: packet),
                         cipher)
        }
    }
}

final class NativeCoreBridgeExportTests: XCTestCase {
    /// The Go bridge export turns runtime.yaml into the JSON NCConfig eats —
    /// this is the seam between the old core and the native one.
    func testNativeConfigJSONExport() throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let yaml = """
        mode: rule
        proxies:
          - {name: A, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
        rules:
          - DOMAIN-SUFFIX,google.com,A
          - MATCH,DIRECT
        """
        try Data(yaml.utf8).write(to: home.appendingPathComponent("runtime.yaml"))
        // Go-zero: was LibmihomoNativeConfigJSON (Go re-encoding runtime.yaml); the app now writes
        // nativecore-runtime.json from the NCYAML tree (NativeRuntimePrep), so decode that tree directly.
        let text = try String(contentsOf: home.appendingPathComponent("runtime.yaml"), encoding: .utf8)
        guard case .object(let root)? = NCYAML.parse(text) else { return XCTFail("runtime.yaml did not parse") }
        let cfg = NCConfig.decode(root: root)
        XCTAssertEqual(cfg.proxyMap["A"]?.port, 8388)
        XCTAssertEqual(cfg.rules.count, 2)
        let rules = cfg.rules.compactMap(NCRule.parse)
        var ctx = NCMatchContext()
        ctx.domain = "www.google.com"
        XCTAssertEqual(NCRuleMatcher.evaluate(rules, ctx), "A")
    }
}

final class NativeCoreDNSTests: XCTestCase {
    func testParseCompressedResponse() {
        // example.com A 1.2.3.4, answer name is a pointer to the question name.
        let wire = unhex("1234" + "8180" + "0001" + "0001" + "0000" + "0000"
            + "076578616d706c6503636f6d00" + "0001" + "0001"
            + "c00c" + "0001" + "0001" + "0000003c" + "0004" + "01020304")
        let msg = NCDNSMessage.parse(wire)!
        XCTAssertEqual(msg.id, 0x1234)
        XCTAssertEqual(msg.questions.first?.name, "example.com")
        XCTAssertEqual(msg.answers.count, 1)
        XCTAssertEqual(msg.answers[0].name, "example.com")
        XCTAssertEqual(msg.answers[0].rdata, Data([1, 2, 3, 4]))
        XCTAssertEqual(msg.answers[0].ttl, 60)
    }

    func testFakeIPResponder() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16", filter: ["*.lan"])
        let responder = NCFakeIPResponder(pool: pool)
        var query = NCDNSMessage()
        query.id = 0x2222
        query.recursionDesired = true
        query.questions = [NCDNSQuestion(name: "www.Example.com", type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        let respData = responder.respond(to: query.serialized())!
        let resp = NCDNSMessage.parse(respData)!
        XCTAssertTrue(resp.isResponse)
        XCTAssertEqual(resp.answers.count, 1)
        let ip = NCIP(resp.answers[0].rdata.map { "\($0)" }.joined(separator: "."))
        XCTAssertNotNil(ip)
        XCTAssertEqual(pool.host(for: ip!), "www.example.com")
        // Filtered hosts and non-A/AAAA types go upstream (nil).
        var lanQuery = query
        lanQuery.questions = [NCDNSQuestion(name: "printer.lan", type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        XCTAssertNil(responder.respond(to: lanQuery.serialized()))
        var mxQuery = query
        mxQuery.questions = [NCDNSQuestion(name: "example.com", type: 15, klass: NCDNSMessage.classIN)]
        XCTAssertNil(responder.respond(to: mxQuery.serialized()))
        // AAAA in v4 fake mode: NOERROR, zero answers.
        var aaaaQuery = query
        aaaaQuery.questions = [NCDNSQuestion(name: "example.com", type: NCDNSMessage.typeAAAA, klass: NCDNSMessage.classIN)]
        let aaaaResp = NCDNSMessage.parse(responder.respond(to: aaaaQuery.serialized())!)!
        XCTAssertEqual(aaaaResp.answers.count, 0)
    }
}

final class NativeCoreSnifferTests: XCTestCase {
    /// Build a minimal ClientHello carrying SNI example.com and ALPN h2/http1.1.
    private func clientHello() -> Data {
        var ext = Data()
        // server_name ext: type 0x0000, len 16, list len 14, type 0, name len 11
        var sni = Data([0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b])
        sni.append(Data("example.com".utf8))
        ext.append(sni)
        // alpn: list len 8, "h2", "http/1.1" -> list = 02 h2 08 http/1.1 = 12 bytes
        var alpnBody = Data([0x00, 0x0c, 0x02])
        alpnBody.append(Data("h2".utf8))
        alpnBody.append(0x08)
        alpnBody.append(Data("http/1.1".utf8))
        var alpnExt = Data([0x00, 0x10])
        alpnExt.append(UInt8(alpnBody.count >> 8)); alpnExt.append(UInt8(alpnBody.count & 0xff))
        alpnExt.append(alpnBody)
        ext.append(alpnExt)

        var body = Data([0x03, 0x03]) // TLS1.2
        body.append(Data(repeating: 0xaa, count: 32)) // random
        body.append(0x00) // session id len
        body.append(contentsOf: [0x00, 0x02, 0x13, 0x01]) // cipher suites
        body.append(contentsOf: [0x01, 0x00]) // compression
        body.append(UInt8(ext.count >> 8)); body.append(UInt8(ext.count & 0xff))
        body.append(ext)
        var hs = Data([0x01, UInt8((body.count >> 16) & 0xff), UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)])
        hs.append(body)
        var rec = Data([0x16, 0x03, 0x01, UInt8((hs.count >> 8) & 0xff), UInt8(hs.count & 0xff)])
        rec.append(hs)
        return rec
    }

    func testTLS() {
        XCTAssertEqual(NCSniffer.detect(clientHello()), .tls(sni: "example.com", alpn: ["h2", "http/1.1"]))
        XCTAssertEqual(NCSniffer.detect(Data([0x16, 0x03])), .unknown)
    }

    func testHTTP() {
        let req = Data("GET /x HTTP/1.1\r\nHost: www.example.com:8080\r\nUser-Agent: t\r\n\r\n".utf8)
        XCTAssertEqual(NCSniffer.detect(req), .http(host: "www.example.com", method: "GET"))
        XCTAssertEqual(NCSniffer.detect(Data([0x00, 0x01, 0x02])), .unknown)
    }
}

final class NativeCoreTrojanTests: XCTestCase {
    func testSHA() {
        // FIPS 180-4 example vectors.
        XCTAssertEqual(hex(NCSHA256.hash(Data("abc".utf8))),
                       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(hex(NCSHA256.hash(Data("abc".utf8), variant224: true)),
                       "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        XCTAssertEqual(hex(NCSHA256.hash(Data())),
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        // 56-byte message exercises the padding boundary.
        let long = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
        XCTAssertEqual(hex(NCSHA256.hash(long)),
                       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    func testTrojanHead() {
        let head = NCTrojan.requestHead(password: "password", target: NCTarget(host: "example.com", port: 443))
        let hashHex = NCTrojan.passwordHashHex("password")
        XCTAssertEqual(hashHex.count, 56)
        XCTAssertTrue(String(decoding: head, as: UTF8.self).hasPrefix(hashHex + "\r\n"))
        XCTAssertEqual(head[58], 0x01) // CMD connect after hash(56) + CRLF(2)
        XCTAssertEqual(Data(head.suffix(2)), Data([0x0d, 0x0a]))
    }
}

// MARK: - VLESS

final class NativeCoreVLESSTests: XCTestCase {
    private func hex(_ d: Data?) -> String {
        (d ?? Data()).map { String(format: "%02x", $0) }.joined()
    }

    func testRequestHeadNoFlow() {
        let head = NCVLESS.requestHead(uuid: "b831381d-6324-4d53-ad4f-8cda48b30811",
                                       target: NCTarget(host: "google.com", port: 443))
        XCTAssertEqual(hex(head), "00b831381d63244d53ad4f8cda48b30811000101bb020a676f6f676c652e636f6d")
    }

    func testRequestHeadWithFlow() {
        let head = NCVLESS.requestHead(uuid: "b831381d-6324-4d53-ad4f-8cda48b30811",
                                       target: NCTarget(host: "google.com", port: 443),
                                       flow: "xtls-rprx-vision")
        XCTAssertEqual(hex(head), "00b831381d63244d53ad4f8cda48b30811120a1078746c732d727072782d766973696f6e0101bb020a676f6f676c652e636f6d")
    }

    func testBadUUID() {
        XCTAssertNil(NCVLESS.requestHead(uuid: "not-a-uuid", target: NCTarget(host: "a.com", port: 80)))
    }
}

// MARK: - Crypto primitives (MD5 / AES / CRC32 / FNV)

final class NativeCoreCryptoTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testMD5RFC1321() {
        XCTAssertEqual(hex(NCMD5.hash(Data())), "d41d8cd98f00b204e9800998ecf8427e")
        XCTAssertEqual(hex(NCMD5.hash(Data("abc".utf8))), "900150983cd24fb0d6963f7d28e17f72")
        XCTAssertEqual(hex(NCMD5.hash(Data("message digest".utf8))), "f96b697d7cb7938d525a2f31aaf161d0")
        XCTAssertEqual(hex(NCMD5.hash(Data("abcdefghijklmnopqrstuvwxyz".utf8))), "c3fcd3d76192e4007dfb496cca67e13b")
        XCTAssertEqual(hex(NCMD5.hash(Data(String(repeating: "1234567890", count: 8).utf8))), "57edf4a22be3c955ac49da2e2107b67a")
    }

    func testAESFIPS197() {
        let pt = Data((0..<16).map { UInt8($0) })
        let k128 = Data((0..<16).map { UInt8($0) })
        let k256 = Data((0..<32).map { UInt8($0) })
        let aes128 = NCAES(key: k128)!
        XCTAssertEqual(hex(aes128.encryptBlock(pt)), "0a940bb5416ef045f1c39458c653ea5a")
        XCTAssertEqual(aes128.decryptBlock(aes128.encryptBlock(pt)), pt)
        let aes256 = NCAES(key: k256)!
        XCTAssertEqual(hex(aes256.encryptBlock(pt)), "5a6e045708fb7196f02e553d02c3a692")
        XCTAssertEqual(aes256.decryptBlock(aes256.encryptBlock(pt)), pt)
    }

    func testCRC32AndFNV() {
        XCTAssertEqual(NCCRC32.checksum(Data("123456789".utf8)), 0xcbf43926)
        XCTAssertEqual(NCFNV1a.hash32(Data()), 0x811c9dc5)
        XCTAssertEqual(NCFNV1a.hash32(Data("a".utf8)), 0xe40c292c)
    }
}

// MARK: - VMess (vectors generated with the real sing-vmess Go library)

final class NativeCoreVMessTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func unhex(_ s: String) -> Data {
        var out = Data()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }

    func testShake128Vectors() {
        XCTAssertEqual(hex(NCShake128(seed: Data()).read(32)),
                       "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        XCTAssertEqual(hex(NCShake128(seed: Data((16..<32).map { UInt8($0) })).read(16)),
                       "fc918e43ecc4b6aea436a3be55984a75")
        XCTAssertEqual(hex(NCShake128(seed: Data("abc".utf8)).read(16)),
                       "5881092dd818bf5cf8a3ddb793fbcba7")
    }

    func testSHA1AndUUIDv5() {
        XCTAssertEqual(hex(NCSHA1.hash(Data("abc".utf8))), "a9993e364706816aba3e25717850c26c9cd0d89d")
        XCTAssertEqual(hex(NCSHA1.uuidV5NilNamespace("test-string")), "f26edc5d820e5e86ade0932eaabeefc7")
    }

    func testCmdKeyAndKDF() {
        let uuid = unhex("b831381d63244d53ad4f8cda48b30811")
        let cmdKey = NCVMess.cmdKey(uuidBytes: uuid)
        XCTAssertEqual(hex(cmdKey), "b50d916ac0cec067981af8e5f38a758f")
        let auth = unhex("00112233445566778899aabbccddeeff")
        let nonce = unhex("0102030405060708")
        let lenKey = NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Key_Length".utf8), auth, nonce])
        XCTAssertEqual(hex(Data(lenKey.prefix(16))), "849560ea0eb7da19a3a59a48d19b0085")
        let lenNonce = NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Nonce_Length".utf8), auth, nonce])
        XCTAssertEqual(hex(Data(lenNonce.prefix(12))), "6d940d2b2ec74db24aa33e9a")
    }

    func testSealedLengthAndHeader() {
        // Rebuild the Go vector inputs: lenKey/lenNonce above seal BE16(100)
        // with authID as AAD; payKey/payNonce seal the 100-byte ramp header.
        let cmdKey = unhex("b50d916ac0cec067981af8e5f38a758f")
        let auth = unhex("00112233445566778899aabbccddeeff")
        let nonce = unhex("0102030405060708")
        let lenKey = Data(NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Key_Length".utf8), auth, nonce]).prefix(16))
        let lenNonce = Data(NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Nonce_Length".utf8), auth, nonce]).prefix(12))
        var lenPlain = Data()
        lenPlain.appendBE16(100)
        XCTAssertEqual(hex(NCVMess.gcmSeal(key: lenKey, nonce: lenNonce, plain: lenPlain, aad: auth)!),
                       "4f62575127ce12f352a0d09a1d04472e3ae9")
        let payKey = Data(NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Key".utf8), auth, nonce]).prefix(16))
        let payNonce = Data(NCVMess.kdf(key: cmdKey, values: [Data("VMess Header AEAD Nonce".utf8), auth, nonce]).prefix(12))
        let header = Data((0..<100).map { UInt8($0) })
        XCTAssertEqual(hex(NCVMess.gcmSeal(key: payKey, nonce: payNonce, plain: header, aad: auth)!),
                       "75748ec14494afebf71161e6cd4fe09079e1c32c1cfceda4ced9a8fb82cb63fa85c641e97c6271fcb759ef749b9636d5555f9493ea4793589031a326b227c1f101d92aab03c341e0b0bd747dd3ba8d802a7706acb86b5d415407d9e5f3090893af89bceda62ce203c85343cabd1280b4b5396068")
    }

    func testBodyChunksMatchGo() {
        let reqKey = unhex("000102030405060708090a0b0c0d0e0f")
        let reqNonce = unhex("101112131415161718191a1b1c1d1e1f")
        let enc = NCVMessChunkEncoder(bodyKey: reqKey, nonceBase: reqNonce, security: NCVMess.securityAESGCM)
        XCTAssertEqual(hex(enc.encode(Data("hello".utf8))), "fc84a316c4d586054e854b4a74fc9040de5bd5eb74d177")
        XCTAssertEqual(hex(enc.encode(Data("world!".utf8))), "8e5540387f8943863177611c700a6d10a08b2d5bffd7b1b9")
        // And the decoder round-trips the same wire bytes.
        let dec = NCVMessChunkDecoder(bodyKey: reqKey, nonceBase: reqNonce, security: NCVMess.securityAESGCM)
        XCTAssertEqual(dec.feed(unhex("fc84a316c4d586054e854b4a74fc9040de5bd5eb74d177")), Data("hello".utf8))
        XCTAssertEqual(dec.feed(unhex("8e5540387f8943863177611c700a6d10a08b2d5bffd7b1b9")), Data("world!".utf8))
    }
}

// MARK: - YAML subset parser

final class NativeCoreYAMLTests: XCTestCase {
    private let sample = """
    # a comment
    mixed-port: 7890
    mode: rule
    ipv6: true
    external-controller: 127.0.0.1:9090
    dns:
      enable: true
      nameserver:
        - 223.5.5.5
        - https://doh.pub/dns-query
      fake-ip-range: 198.18.0.1/16
      fake-ip-filter:
        - '*.lan'
        - time.*.com
    proxies:
      - name: "ss one"
        type: ss
        server: example.com
        port: 8388
        cipher: aes-128-gcm
        password: "p@ss: word"
        udp: true
      - {name: direct-out, type: direct}
    proxy-groups:
      - name: PROXY
        type: select
        proxies: [ss one, direct-out, DIRECT]
    rules:
      - DOMAIN-SUFFIX,google.com,PROXY
      - GEOIP,CN,DIRECT
      - MATCH,PROXY
    empty-list: []
    nothing: ~
    ratio: 1.5
    literal: |
      line one
      line two
    """

    func testParseSample() {
        guard case .object(let root)? = NCYAML.parse(sample) else {
            XCTFail("root not object")
            return
        }
        XCTAssertEqual(root["mixed-port"]?.int, 7890)
        XCTAssertEqual(root["mode"]?.string, "rule")
        XCTAssertEqual(root["ipv6"]?.bool, true)
        XCTAssertEqual(root["external-controller"]?.string, "127.0.0.1:9090")
        let dns = root["dns"]?.object
        XCTAssertEqual(dns?["nameserver"]?.array?.compactMap { $0.string }, ["223.5.5.5", "https://doh.pub/dns-query"])
        XCTAssertEqual(dns?["fake-ip-filter"]?.array?.compactMap { $0.string }, ["*.lan", "time.*.com"])
        let proxies = root["proxies"]?.array
        XCTAssertEqual(proxies?.count, 2)
        XCTAssertEqual(proxies?[0].object?["password"]?.string, "p@ss: word")
        XCTAssertEqual(proxies?[0].object?["port"]?.int, 8388)
        XCTAssertEqual(proxies?[1].object?["name"]?.string, "direct-out")
        let group = root["proxy-groups"]?.array?.first?.object
        XCTAssertEqual(group?["proxies"]?.array?.compactMap { $0.string }, ["ss one", "direct-out", "DIRECT"])
        XCTAssertEqual(root["rules"]?.array?.count, 3)
        XCTAssertEqual(root["empty-list"]?.array?.count, 0)
        XCTAssertEqual(root["nothing"], NCJSONValue.null)
        XCTAssertEqual(root["ratio"]?.number, 1.5)
        XCTAssertEqual(root["literal"]?.string, "line one\nline two\n")
    }

    func testConfigFromYAML() {
        guard case .object(let root)? = NCYAML.parse(sample) else {
            XCTFail("root not object")
            return
        }
        let cfg = NCConfig.decode(root: root)
        XCTAssertEqual(cfg.proxies.count, 2)
        XCTAssertEqual(cfg.proxyMap["ss one"]?.server, "example.com")
        XCTAssertEqual(cfg.groupMap["PROXY"]?.type, "select")
        XCTAssertEqual(cfg.rules.count, 3)
    }
}
