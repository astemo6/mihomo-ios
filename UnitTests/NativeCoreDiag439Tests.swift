import XCTest
@testable import Mihomo

/// fix/nc-diag-439: regressions for the build-439 device diagnosis (root causes A–I).
final class NativeCoreDiag439Tests: XCTestCase {

    // MARK: A — GEOIP over Meta-geoip0 multi-code records

    /// A one-node IPv4 MaxMind DB: 0.0.0.0/1 → ["cloudflare","cn"] (array record), 128.0.0.0/1 → "us".
    private static func tinyGeoDB() -> Data {
        func str(_ s: String) -> [UInt8] { [0x40 | UInt8(s.utf8.count)] + Array(s.utf8) }
        let recA: [UInt8] = [0x02, 0x04] + str("cloudflare") + str("cn")   // array (extended type 11), 2 items
        let recB: [UInt8] = str("us")
        let nodeCount = 1
        func rec24(_ v: Int) -> [UInt8] { [UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
        let left = nodeCount + 16 + 0
        let right = nodeCount + 16 + recA.count
        let tree = rec24(left) + rec24(right)
        let separator = [UInt8](repeating: 0, count: 16)
        let marker: [UInt8] = [0xab, 0xcd, 0xef] + Array("MaxMind.com".utf8)
        let meta: [UInt8] = [0xE3] + str("node_count") + [0xA1, UInt8(nodeCount)]
            + str("record_size") + [0xA1, 24] + str("ip_version") + [0xA1, 4]
        return Data(tree + separator + recA + recB + marker + meta)
    }

    func testMMDBMultiCodeRecordReturnsEveryCode() throws {
        let db = try XCTUnwrap(NCMMDB(data: Self.tinyGeoDB()))
        XCTAssertEqual(db.countryCodes(for: try XCTUnwrap(NCIP("1.1.1.1"))), ["cloudflare", "cn"])
        XCTAssertEqual(db.countryCodes(for: try XCTUnwrap(NCIP("200.1.1.1"))), ["us"])
        XCTAssertEqual(db.countryCode(for: try XCTUnwrap(NCIP("1.1.1.1"))), "cloudflare")
        XCTAssertEqual(NCMMDB.codes(in: .object(["country": .object(["iso_code": .string("CN")])])), ["CN"])
        XCTAssertEqual(NCMMDB.codes(in: .string("")), [])
    }

    func testGEOIPMatchesAnyCodeOfMultiCodeRecord() throws {
        let db = try XCTUnwrap(NCMMDB(data: Self.tinyGeoDB()))
        let cn = try XCTUnwrap(NCRule.parse("GEOIP,cn,DIRECT"))
        let cf = try XCTUnwrap(NCRule.parse("GEOIP,CLOUDFLARE,Proxy"))
        var c = NCMatchContext()
        c.countryOf = { db.countryCode(for: $0) }
        c.countryCodesOf = { db.countryCodes(for: $0) }
        c.ip = NCIP("1.1.1.1")
        XCTAssertTrue(NCRuleMatcher.matches(cn, c), "cn is the 2nd code of the array record")
        XCTAssertTrue(NCRuleMatcher.matches(cf, c))
        c.ip = NCIP("200.1.1.1")
        XCTAssertFalse(NCRuleMatcher.matches(cn, c))
        // Without the multi-code lookup only the first code counts (the old behaviour).
        var old = NCMatchContext()
        old.countryOf = { db.countryCode(for: $0) }
        old.ip = NCIP("1.1.1.1")
        XCTAssertFalse(NCRuleMatcher.matches(cn, old))
    }

    // MARK: C — upstream-failure memory

    func testUpstreamFailurePassesThroughAfterThreeInWindow() {
        NativeMitmUpstreamHealth.reset()
        defer { NativeMitmUpstreamHealth.reset() }
        var pinned: [String] = []
        let pin: (String, String) -> Void = { h, _ in pinned.append(h) }
        XCTAssertFalse(NativeMitmUpstreamHealth.failure(host: "A.example.com", why: "x", now: 1000, pin: pin))
        XCTAssertFalse(NativeMitmUpstreamHealth.failure(host: "a.example.com", why: "x", now: 1010, pin: pin))
        XCTAssertTrue(NativeMitmUpstreamHealth.failure(host: "a.example.com", why: "x", now: 1020, pin: pin))
        XCTAssertEqual(pinned, ["a.example.com"])
    }

    func testUpstreamFailureWindowAndSuccessReset() {
        NativeMitmUpstreamHealth.reset()
        defer { NativeMitmUpstreamHealth.reset() }
        var trips = 0
        let pin: (String, String) -> Void = { _, _ in trips += 1 }
        // Spread over more than the 60 s window: never three inside it.
        for t in [0.0, 40, 80, 120, 160] {
            NativeMitmUpstreamHealth.failure(host: "b.example.com", why: "x", now: 5000 + t, pin: pin)
        }
        XCTAssertEqual(trips, 0)
        // A success in between clears the count.
        NativeMitmUpstreamHealth.reset()
        NativeMitmUpstreamHealth.failure(host: "c.example.com", why: "x", now: 1, pin: pin)
        NativeMitmUpstreamHealth.failure(host: "c.example.com", why: "x", now: 2, pin: pin)
        NativeMitmUpstreamHealth.success(host: "c.example.com")
        NativeMitmUpstreamHealth.failure(host: "c.example.com", why: "x", now: 3, pin: pin)
        XCTAssertEqual(trips, 0)
    }

    // MARK: G — TLS SNI helper, ws early-data path

    private func proxy(_ fields: [String: Any]) -> NCProxy {
        var f: [String: NCJSONValue] = [:]
        for (k, v) in fields { f[k] = NCJSONValue(v) }
        return NCProxy(name: "n", type: "vmess", fields: f)
    }

    func testTLSSNIFallsBackToTransportHost() {
        let ip = "104.16.1.1"
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["servername": "sni.example.com", "network": "ws",
                                                 "ws-opts": ["headers": ["Host": "ws.example.com"]]]), server: ip), "sni.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["sni": "s.example.com"]), server: ip), "s.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["network": "ws", "ws-opts": ["path": "/", "headers": ["Host": "ws.example.com"]] as [String: Any]]), server: ip),
                       "ws.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["servername": "", "network": "ws", "ws-opts": ["headers": ["host": "lower.example.com"]]]), server: ip),
                       "lower.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["network": "h2", "h2-opts": ["host": ["h2.example.com"]]]), server: ip), "h2.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["network": "http", "http-opts": ["headers": ["Host": ["http.example.com"]]]]), server: ip),
                       "http.example.com")
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["network": "tcp"]), server: ip), ip)
        XCTAssertEqual(NCConnector.tlsSNI(proxy(["network": "ws"]), server: "node.example.com"), "node.example.com")
    }

    func testWSPathStripsEarlyDataQuery() {
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/path?ed=2048"), "/path")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/p?ed=2048&x=1"), "/p?x=1")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/p?x=1&ed=2560"), "/p?x=1")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/?ed=2560"), "/")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("?ed=1"), "/")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/p"), "/p")
        XCTAssertEqual(NCConnector.wsPathStrippingEarlyData("/p?red=1"), "/p?red=1")
        let p = proxy(["network": "ws", "ws-opts": ["path": "/vless?ed=2048"]])
        XCTAssertEqual(NCConnector.wsOptions(p).path, "/vless")
    }

    // MARK: H — a module enabled twice is loaded once

    func testModuleDedupeKey() {
        XCTAssertEqual(NCMitmBuild.moduleDedupeKey(url: " https://x/m.sgmodule ", args: ["b": "2", "a": "1"]),
                       NCMitmBuild.moduleDedupeKey(url: "https://x/m.sgmodule", args: ["a": "1", "b": "2"]))
        XCTAssertNotEqual(NCMitmBuild.moduleDedupeKey(url: "https://x/m.sgmodule", args: ["a": "1"]),
                          NCMitmBuild.moduleDedupeKey(url: "https://x/m.sgmodule", args: ["a": "2"]))
        XCTAssertNil(NCMitmBuild.moduleDedupeKey(url: "", args: nil))
    }

    func testSameModuleEnabledTwiceLoadsOnce() throws {
        let home = NSTemporaryDirectory() + "nc-diag439-\(UUID().uuidString)"
        let dir = home + "/engine/modules"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let engineJSON = """
        {"enabled":true,"mitm":true,"hostnames":[],
         "modules":[{"id":"m1","name":"油管去广告","url":"https://example.com/yt.sgmodule","enabled":true},
                    {"id":"m2","name":"油管去广告","url":"https://example.com/yt.sgmodule","enabled":true},
                    {"id":"m3","name":"带参数","url":"https://example.com/yt.sgmodule","enabled":true,"args":{"k":"v"}},
                    {"id":"m4","name":"本地","url":"","enabled":true}]}
        """
        try engineJSON.write(toFile: home + "/engine/engine.json", atomically: true, encoding: .utf8)
        let module = """
        #!name=YT
        [URL Rewrite]
        ^https://ad.example.com/x reject-dict
        [MITM]
        hostname = ad.example.com
        """
        for id in ["m1", "m2", "m3", "m4"] {
            try module.write(toFile: dir + "/\(id).txt", atomically: true, encoding: .utf8)
        }
        let rs = NCMitmBuild.build(home: home, cfg: NCEngineConfig.load(home: home))
        XCTAssertEqual(rs.rules.count, 3, "m2 duplicates m1; m3 (other args) and m4 (no URL) load: \(rs.rules.count)")
        XCTAssertTrue(rs.errors.contains { $0.contains("只加载一次") }, "\(rs.errors)")
    }

    // MARK: F — bare local script names

    func testBareLocalScriptDetection() {
        XCTAssertTrue(SelfCheckLogic.isBareLocalScript("CloudflareIP.js"))
        XCTAssertTrue(SelfCheckLogic.isBareLocalScript(" Cloudflare.js "))
        XCTAssertFalse(SelfCheckLogic.isBareLocalScript("https://raw.githubusercontent.com/a/b/famijia_checkin.js"))
        XCTAssertFalse(SelfCheckLogic.isBareLocalScript("/var/mobile/x.js"))
        XCTAssertFalse(SelfCheckLogic.isBareLocalScript(""))
    }

    // MARK: E — provider status text, overrides summary

    func testProviderFetchFailureStatusText() {
        XCTAssertEqual(NCNodeSubscriptionStore.failureStatusText(403), "HTTP 403")
        XCTAssertEqual(NCNodeSubscriptionStore.failureStatusText(0), "no response")
    }

    func testProviderOverridesSummaryHasNamesNotURLs() throws {
        let home = NSTemporaryDirectory() + "nc-diag439-ov-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let json = """
        {"p1":{"薯条":{"disabled":true,"url":"https://secret.example.com/sub?token=abc"},"B":{"deleted":true}}}
        """
        try json.write(toFile: home + "/provider-overrides.json", atomically: true, encoding: .utf8)
        let s = DiagnosticSummary.providerOverridesSummary(home: home, profilePath: home + "/profiles/p1.yaml")
        XCTAssertTrue(s.contains("薯条: 已停用"), s)
        XCTAssertTrue(s.contains("B: 已删除"), s)
        XCTAssertFalse(s.contains("secret.example.com"), s)
        XCTAssertFalse(s.contains("token"), s)
        let none = DiagnosticSummary.providerOverridesSummary(home: home, profilePath: home + "/profiles/other.yaml")
        XCTAssertTrue(none.contains("没有改动"), none)
    }

    // MARK: I — 最近 backfill merge

    private func item(_ id: String, closed: TimeInterval?) throws -> ConnectionItem {
        let json = #"{"id":"\#(id)","metadata":{},"upload":0,"download":0}"#
        var c = try JSONDecoder().decode(ConnectionItem.self, from: Data(json.utf8))
        c.closedAt = closed.map { Date(timeIntervalSince1970: $0) }
        return c
    }

    func testRecentBackfillMergeDedupesSortsAndCaps() throws {
        let recent = [try item("a", closed: 300), try item("b", closed: 100)]
        let incoming = [try item("a", closed: 299), try item("c", closed: 200), try item("live", closed: 250), try item("d", closed: 50)]
        let merged = RequestsModel.mergeClosed(recent: recent, incoming: incoming, activeIDs: ["live"], cap: 300)
        XCTAssertEqual(merged.map(\.id), ["a", "c", "b", "d"])
        XCTAssertEqual(merged.first?.closedAt, Date(timeIntervalSince1970: 300), "existing entry wins")
        let capped = RequestsModel.mergeClosed(recent: recent, incoming: incoming, activeIDs: [], cap: 3)
        XCTAssertEqual(capped.map(\.id), ["a", "live", "c"])
    }
}
