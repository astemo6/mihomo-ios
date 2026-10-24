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
        XCTAssertEqual(hex(t.atypEncoded), "036578616d706c652e636f6d01bb")
        XCTAssertEqual(hex(NCSOCKS5.greeting(username: nil, password: nil)), "050100")
        let req = NCSOCKS5.connectRequest(target: t)
        XCTAssertEqual(hex(req), "050100036578616d706c652e636f6d01bb")
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
}
