import XCTest
@testable import Mihomo

/// feat/nc-lan-share: 局域网共享 on the NativeCore mixed port (NCLanShare — mihomo allow-lan / bind-address /
/// authentication / skip-auth-prefixes / lan-allowed-ips semantics, and the listener the tunnel picks).
final class NativeCoreLanShareTests: XCTestCase {

    private func ip(_ s: String) -> NCIP? { NCLanShare.sourceIP(s) }

    // MARK: authentication parsing

    func testAuthenticationCutsAtFirstColon() {
        let u = NCLanShare.parseAuthentication(["alice:p:a:ss", "bob:", "noColon", ":anon", "carol:x"])
        XCTAssertEqual(u["alice"], "p:a:ss")
        XCTAssertEqual(u["bob"], "")
        XCTAssertNil(u["noColon"])
        XCTAssertEqual(u[""], "anon")
        XCTAssertEqual(u["carol"], "x")
        XCTAssertEqual(u.count, 4)
    }

    func testAuthenticationLaterDuplicateWins() {
        XCTAssertEqual(NCLanShare.parseAuthentication(["a:1", "a:2"])["a"], "2")
    }

    func testCredentialsMatchAppTranslation() {
        let main = CoreOverrides.LanAuth(username: " admin ", password: "pw")
        let extra = [
            CoreOverrides.LanAuth(username: "admin", password: "dup"),   // main name: skipped
            CoreOverrides.LanAuth(username: "x:y", password: "p"),       // ':' in name: skipped
            CoreOverrides.LanAuth(username: "  ", password: "p"),        // empty: skipped
            CoreOverrides.LanAuth(username: "nopw", password: ""),       // no password: skipped
            CoreOverrides.LanAuth(username: " guest ", password: "g:1"),
            CoreOverrides.LanAuth(username: "guest", password: "second"), // first wins
        ]
        XCTAssertEqual(NCLanShare.credentials(main: main, extra: extra), ["admin:pw", "guest:g:1"])
        XCTAssertEqual(NCLanShare.credentials(main: CoreOverrides.LanAuth(username: "a", password: ""), extra: []), [])
    }

    func testBasicHeader() {
        let token = Data("alice:se:cret".utf8).base64EncodedString()
        let c = NCLanShare.parseBasic("Basic \(token)")
        XCTAssertEqual(c?.user, "alice")
        XCTAssertEqual(c?.password, "se:cret")
        XCTAssertEqual(NCLanShare.parseBasic("  basic   \(token) ")?.user, "alice")
        XCTAssertNil(NCLanShare.parseBasic("Bearer \(token)"))
        XCTAssertNil(NCLanShare.parseBasic("Basic !!!"))
        XCTAssertNil(NCLanShare.parseBasic("Basic \(Data("nocolon".utf8).base64EncodedString())"))
    }

    func testVerifyHTTPHeaders() {
        var lan = NCLanShare(allowLan: true)
        lan.users = ["u": "p"]
        let good = "Basic " + Data("u:p".utf8).base64EncodedString()
        let bad = "Basic " + Data("u:x".utf8).base64EncodedString()
        XCTAssertTrue(lan.verifyHTTP(headerLines: ["Host: a", "proxy-authorization: \(good)"]))
        XCTAssertTrue(lan.verifyHTTP(headerLines: ["Proxy-Authorization:\(bad)", "Proxy-Authorization: \(good)"]))
        XCTAssertFalse(lan.verifyHTTP(headerLines: ["Proxy-Authorization: \(bad)"]))
        XCTAssertFalse(lan.verifyHTTP(headerLines: ["Authorization: \(good)"]))
        XCTAssertFalse(lan.verify(user: "nobody", password: ""))
    }

    func testSocksUserPass() {
        let req: [UInt8] = [0x01, 0x03] + Array("bob".utf8) + [0x02] + Array("pw".utf8) + [0x05, 0x01]
        XCTAssertEqual(NCLanShare.parseSocksUserPass(req), .ok(consumed: 8, user: "bob", password: "pw"))
        XCTAssertEqual(NCLanShare.parseSocksUserPass(Array(req.prefix(5))), .needMore)
        XCTAssertEqual(NCLanShare.parseSocksUserPass([0x01]), .needMore)
        XCTAssertEqual(NCLanShare.parseSocksUserPass([0x05, 0x01, 0x00]), .invalid)
        XCTAssertEqual(NCLanShare.parseSocksUserPass([0x01, 0x00, 0x00]), .ok(consumed: 3, user: "", password: ""))
    }

    // MARK: listen address

    func testBindAddressSelection() {
        XCTAssertEqual(NCLanShare.bind(allowLan: false, bindAddress: "*"), .loopback)
        XCTAssertEqual(NCLanShare.bind(allowLan: false, bindAddress: "192.168.1.2"), .loopback)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "*"), .any)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: ""), .any)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "0.0.0.0"), .any)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "[::]"), .any)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "127.0.0.1"), .loopback)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "::1"), .loopback)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "localhost"), .loopback)
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: " 192.168.1.2 "), .address("192.168.1.2"))
        XCTAssertEqual(NCLanShare.bind(allowLan: true, bindAddress: "not a host"), .any)
    }

    func testPlan() {
        let off = NCLanShare()
        var on = NCLanShare(allowLan: true)
        XCTAssertNil(NCLanShare.plan(needLocal: false, port: 7890, lan: off))           // TUN, no sharing
        XCTAssertEqual(NCLanShare.plan(needLocal: true, port: 7890, lan: off)?.bind, .loopback)
        XCTAssertEqual(NCLanShare.plan(needLocal: false, port: 7890, lan: on)?.bind, .any) // TUN + 局域网共享
        XCTAssertEqual(NCLanShare.plan(needLocal: true, port: 7891, lan: on)?.port, 7891)
        on.bindAddress = "10.0.0.5"
        XCTAssertEqual(NCLanShare.plan(needLocal: true, port: 7890, lan: on)?.bind, .address("10.0.0.5"))
        XCTAssertNil(NCLanShare.plan(needLocal: true, port: 0, lan: on))
        XCTAssertEqual(NCLanShare.mixedPort(raw: ["mixed-port": .number(7900)], fallback: 7890), 7900)
        XCTAssertEqual(NCLanShare.mixedPort(raw: ["mixed-port": .number(70000)], fallback: 7890), 7890)
        XCTAssertEqual(NCLanShare.mixedPort(raw: [:], fallback: 7890), 7890)
    }

    // MARK: source policy

    func testSourceIPNormalization() {
        XCTAssertEqual(ip("192.168.1.5"), NCIP("192.168.1.5"))
        XCTAssertEqual(ip("::ffff:10.0.0.2"), NCIP("10.0.0.2"))
        XCTAssertEqual(ip("fe80::1%en0"), NCIP("fe80::1"))
        XCTAssertEqual(ip("[::1]"), NCIP("::1"))
        XCTAssertNil(ip("example.com"))
    }

    /// NCCIDR v6 prefixes whose length is not a multiple of 8 trapped (UInt8(0xff << n)).
    func testCIDRV6OddPrefix() {
        XCTAssertTrue(NCCIDR("fe80::/10")!.contains(NCIP("fe80::2")!))
        XCTAssertTrue(NCCIDR("fe80::/10")!.contains(NCIP("febf::1")!))
        XCTAssertFalse(NCCIDR("fe80::/10")!.contains(NCIP("fec0::1")!))
        XCTAssertTrue(NCCIDR("fc00::/7")!.contains(NCIP("fd12::1")!))
        XCTAssertFalse(NCCIDR("fc00::/7")!.contains(NCIP("fe00::1")!))
        XCTAssertTrue(NCCIDR("2001:db8::/33")!.contains(NCIP("2001:db8:7fff::1")!))
        XCTAssertFalse(NCCIDR("2001:db8::/33")!.contains(NCIP("2001:db8:8000::1")!))
    }

    func testAdmitsAndSkipAuth() {
        var o = CoreOverrides()
        o.allowLan = true
        o.lanLocalOnly = true
        o.lanAuth = CoreOverrides.LanAuth(username: "u", password: "p")
        let lan = NCLanShare.from(overrides: o)
        XCTAssertTrue(lan.admits(ip("192.168.1.9")))
        XCTAssertTrue(lan.admits(ip("10.1.2.3")))
        XCTAssertTrue(lan.admits(ip("fe80::2%en0")))
        XCTAssertFalse(lan.admits(ip("8.8.8.8")))          // 仅允许局域网设备
        XCTAssertTrue(lan.admits(ip("127.0.0.1")))
        XCTAssertTrue(lan.needsAuth(ip("192.168.1.9")))
        XCTAssertFalse(lan.needsAuth(ip("127.0.0.1")))      // the device's own system proxy
        XCTAssertFalse(lan.needsAuth(ip("::1")))
        XCTAssertTrue(lan.needsAuth(nil))

        o.lanLocalOnly = false
        XCTAssertTrue(NCLanShare.from(overrides: o).admits(ip("8.8.8.8")))
        o.lanAuth = CoreOverrides.LanAuth()
        XCTAssertFalse(NCLanShare.from(overrides: o).needsAuth(ip("192.168.1.9")))
    }

    func testLoopbackOnlyWhenOff() {
        let lan = NCLanShare.from(overrides: CoreOverrides())
        XCTAssertFalse(lan.allowLan)
        XCTAssertEqual(lan.bind, .loopback)
        XCTAssertTrue(lan.admits(ip("127.0.0.1")))
        XCTAssertFalse(lan.admits(ip("192.168.1.9")))
        XCTAssertFalse(lan.needsAuth(ip("127.0.0.1")))
    }

    func testDisallowedWinsAndLoopbackAlwaysAdmitted() {
        let raw: [String: NCJSONValue] = [
            "allow-lan": .bool(true),
            "lan-allowed-ips": .array([.string("192.168.0.0/16")]),
            "lan-disallowed-ips": .array([.string("192.168.1.66/32")]),
        ]
        let lan = NCLanShare.from(raw: raw)!
        XCTAssertTrue(lan.admits(ip("192.168.1.5")))
        XCTAssertFalse(lan.admits(ip("192.168.1.66")))
        XCTAssertFalse(lan.admits(ip("10.0.0.1")))
        XCTAssertTrue(lan.admits(ip("127.0.0.1")))
        XCTAssertFalse(lan.requiresAuth)
    }

    // MARK: runtime config (what the app writes) ⇄ app settings

    func testFromRawParsesMihomoKeys() {
        let raw: [String: NCJSONValue] = [
            "allow-lan": .string("true"),
            "bind-address": .string("*"),
            "authentication": .array([.string("a:1"), .string("b:2:3")]),
            "skip-auth-prefixes": .array([.string("127.0.0.0/8"), .string("bogus")]),
            "mixed-port": .number(7890),
        ]
        let lan = NCLanShare.from(raw: raw)!
        XCTAssertTrue(lan.allowLan)
        XCTAssertEqual(lan.bind, .any)
        XCTAssertEqual(lan.users, ["a": "1", "b": "2:3"])
        XCTAssertEqual(lan.skipAuth.count, 1)
        XCTAssertTrue(lan.allowed.isEmpty)
        XCTAssertNil(NCLanShare.from(raw: ["mixed-port": .number(7890)]))  // no allow-lan → caller falls back
        XCTAssertEqual(NCLanShare.from(raw: ["allow-lan": .bool(false), "bind-address": .string("*")])?.bind, .loopback)
    }

    func testRuntimeConfigMatchesAppSettings() {
        var o = CoreOverrides()
        o.allowLan = true
        o.lanLocalOnly = true
        o.lanAuth = CoreOverrides.LanAuth(username: "main", password: "m:pw")
        o.lanUsers = [CoreOverrides.LanAuth(username: "guest", password: "g"),
                      CoreOverrides.LanAuth(username: "main", password: "dup")]
        for (allowLan, mode) in [(true, "tun"), (true, "proxy"), (false, "mix"), (false, "proxy")] {
            o.allowLan = allowLan
            o.tunnelMode = mode
            var raw: [String: NCJSONValue] = ["allow-lan": .bool(o.allowLan)]
            let settings = NCRuntimeSettings(core: o, dns: nil, local: nil, home: "", manualPath: "")
            NCRuntimeSteps.applyInbound(&raw, settings)
            let fromRaw = NCLanShare.from(raw: raw)
            XCTAssertEqual(fromRaw, NCLanShare.from(overrides: o), "allowLan \(allowLan) mode \(mode)")
            let setup = NCLanShare.plan(needLocal: o.isProxyOnly || o.isMixed,
                                        port: NCLanShare.mixedPort(raw: raw, fallback: o.mixedPort), lan: fromRaw!)
            XCTAssertEqual(setup?.bind, allowLan ? .any : .loopback)
            XCTAssertEqual(setup?.port, o.mixedPort)
        }
        // TUN without 局域网共享: no listener at all.
        o.allowLan = false
        o.tunnelMode = "tun"
        var raw: [String: NCJSONValue] = ["allow-lan": .bool(false)]
        NCRuntimeSteps.applyInbound(&raw, NCRuntimeSettings(core: o, dns: nil, local: nil, home: "", manualPath: ""))
        XCTAssertNil(NCLanShare.plan(needLocal: false, port: o.mixedPort, lan: NCLanShare.from(raw: raw)!))
    }
}
