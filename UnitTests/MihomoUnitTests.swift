import XCTest
@testable import Mihomo

// v0.19.5: Swift-only logic that the Go suite cannot reach. Hosted in the app (simulator, Debug); every test
// works in its own scratch directory / UserDefaults suite, never in the app's container.

private func scratch(_ name: String = #function) -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("unit-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

private func write(_ root: URL, _ rel: String, _ text: String) {
    let u = root.appendingPathComponent(rel)
    try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? Data(text.utf8).write(to: u)
}

private func read(_ root: URL, _ rel: String) -> String? {
    (try? Data(contentsOf: root.appendingPathComponent(rel))).map { String(decoding: $0, as: UTF8.self) }
}

private func suite() -> UserDefaults {
    let name = "unit.\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    return d
}

final class BackupTests: XCTestCase {
    func seed(_ root: URL) {
        write(root, "profiles.json", #"[{"id":"p1","name":"演示","kind":"local"}]"#)
        write(root, "profiles/p1.yaml", "proxies: []\n# 注释\n")
        write(root, "profiles/p1.yaml.bak", "old\n")
        write(root, "mihomo/overrides.json", #"{"mode":"global"}"#)
        write(root, "mihomo/override-scripts/index.json", #"{"p1":[{"id":"s1"}]}"#)
        write(root, "mihomo/override-scripts/s1.js", "function main(c){return c}\n")
        write(root, "mihomo/engine/engine.json", "{}")
        write(root, "mihomo/engine/ca/ca.key", "SECRET-CA-KEY-MARKER")
        write(root, "mihomo/cache.db", "not backed up")
        write(root, "mihomo/geoip.metadb", "not backed up")
    }

    func testRoundTripWithoutCA() throws {
        let a = scratch(), b = scratch()
        seed(a)
        let da = suite(), db = suite()
        da.set("p1", forKey: "activeProfileID")
        let (data, n) = try BackupManager.makeData(includeCA: false, root: a, defaults: da)
        XCTAssertEqual(n, 7)
        let restored = try BackupManager.restore(data, root: b, defaults: db)
        XCTAssertEqual(restored, 7)
        for rel in ["profiles.json", "profiles/p1.yaml", "profiles/p1.yaml.bak", "mihomo/overrides.json",
                    "mihomo/override-scripts/index.json", "mihomo/override-scripts/s1.js", "mihomo/engine/engine.json"] {
            XCTAssertEqual(read(b, rel), read(a, rel), rel)
        }
        XCTAssertNil(read(b, "mihomo/engine/ca/ca.key"), "CA only when asked for")
        XCTAssertNil(read(b, "mihomo/cache.db"))
        XCTAssertNil(read(b, "mihomo/geoip.metadb"))
        XCTAssertEqual(db.string(forKey: "activeProfileID"), "p1")
    }

    func testRoundTripWithCAKeepsKeyPrivate() throws {
        let a = scratch(), b = scratch()
        seed(a)
        let (data, n) = try BackupManager.makeData(includeCA: true, root: a, defaults: suite())
        XCTAssertEqual(n, 8)
        try BackupManager.restore(data, root: b, defaults: suite())
        XCTAssertEqual(read(b, "mihomo/engine/ca/ca.key"), "SECRET-CA-KEY-MARKER")
        let perms = try FileManager.default.attributesOfItem(atPath: b.appendingPathComponent("mihomo/engine/ca/ca.key").path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testEncryptedRoundTrip() throws {
        let a = scratch(), b = scratch()
        seed(a)
        let (plain, _) = try BackupManager.makeData(includeCA: true, root: a, defaults: suite())
        let enc = try BackupCrypto.encrypt(plain, password: "pässwörd 密码")
        XCTAssertTrue(BackupCrypto.isEncrypted(enc))
        XCTAssertFalse(BackupCrypto.isEncrypted(plain))
        XCTAssertNil(String(data: enc, encoding: .utf8)?.range(of: "SECRET-CA"), "no clear text in the envelope")
        let obj = try JSONSerialization.jsonObject(with: enc) as? [String: Any]
        XCTAssertEqual(obj?["kdf"] as? String, "pbkdf2-sha256")
        XCTAssertEqual(obj?["encrypted"] as? String, "aes-256-gcm")
        XCTAssertEqual(obj?["iterations"] as? Int, Int(BackupCrypto.iterations))
        let dec = try BackupCrypto.decrypt(enc, password: "pässwörd 密码")
        XCTAssertEqual(dec, plain)
        try BackupManager.restore(dec, root: b, defaults: suite())
        XCTAssertEqual(read(b, "profiles/p1.yaml"), read(a, "profiles/p1.yaml"))
    }

    func testEncryptedWrongPasswordTamperedAndBadRounds() throws {
        let enc = try BackupCrypto.encrypt(Data("{\"app\":\"mihomo-ios\",\"files\":{}}".utf8), password: "a")
        XCTAssertThrowsError(try BackupCrypto.decrypt(enc, password: "b")) { e in
            XCTAssertEqual(e as? BackupCrypto.CryptoError, .wrongPassword)
        }
        var obj = try JSONSerialization.jsonObject(with: enc) as! [String: Any]
        var blob = Data(base64Encoded: obj["data"] as! String)!
        blob[blob.count / 2] ^= 0x01
        obj["data"] = blob.base64EncodedString()
        XCTAssertThrowsError(try BackupCrypto.decrypt(try JSONSerialization.data(withJSONObject: obj), password: "a")) { e in
            XCTAssertEqual(e as? BackupCrypto.CryptoError, .wrongPassword)
        }
        var weak = try JSONSerialization.jsonObject(with: enc) as! [String: Any]
        weak["iterations"] = 10
        XCTAssertThrowsError(try BackupCrypto.decrypt(try JSONSerialization.data(withJSONObject: weak), password: "a")) { e in
            XCTAssertEqual(e as? BackupCrypto.CryptoError, .badFile)
        }
        XCTAssertThrowsError(try BackupCrypto.decrypt(Data("{}".utf8), password: "a"))
        XCTAssertThrowsError(try BackupCrypto.decrypt(Data("garbage".utf8), password: "a"))
    }

    func testCorruptArchiveWritesNothing() throws {
        let a = scratch(), b = scratch()
        seed(a)
        let (data, _) = try BackupManager.makeData(includeCA: false, root: a, defaults: suite())
        var obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        var files = obj["files"] as! [String: String]
        files["profiles/p1.yaml"] = "%%% not base64 %%%"
        obj["files"] = files
        write(b, "profiles/p1.yaml", "mine\n")
        XCTAssertThrowsError(try BackupManager.restore(try JSONSerialization.data(withJSONObject: obj), root: b, defaults: suite()))
        XCTAssertEqual(read(b, "profiles/p1.yaml"), "mine\n", "nothing written from a damaged backup")
        XCTAssertNil(read(b, "profiles.json"))
        // truncated download
        XCTAssertThrowsError(try BackupManager.restore(data.prefix(data.count / 2), root: b, defaults: suite()))
        // another app's JSON
        XCTAssertThrowsError(try BackupManager.restore(Data(#"{"app":"other","files":{}}"#.utf8), root: b, defaults: suite()))
        XCTAssertNil(read(b, "profiles.json"))
    }

    func testRestoreIgnoresUnknownAndEscapingPaths() throws {
        let b = scratch()
        let ok = Data("ok".utf8).base64EncodedString()
        let json = """
        {"app":"mihomo-ios","files":{"profiles/x.yaml":"\(ok)","../evil":"\(ok)","profiles/../../evil2":"\(ok)",
        "mihomo/cache.db":"\(ok)","/etc/hosts":"\(ok)","profilesX/y":"\(ok)"},"defaults":{"activeProfileID":"x","other":"y"}}
        """
        let d = suite()
        let n = try BackupManager.restore(Data(json.utf8), root: b, defaults: d)
        XCTAssertEqual(n, 1)
        XCTAssertEqual(read(b, "profiles/x.yaml"), "ok")
        XCTAssertNil(read(b, "mihomo/cache.db"))
        XCTAssertNil(read(b, "profilesX/y"))
        XCTAssertNil(read(b.deletingLastPathComponent(), "evil"))
        XCTAssertEqual(d.string(forKey: "activeProfileID"), "x")
        XCTAssertNil(d.string(forKey: "other"))
    }

    /// v0.19.5: created / version / appVersion / defaults are optional (only app + files are needed).
    func testMinimalBackupRestores() throws {
        let b = scratch()
        let json = #"{"app":"mihomo-ios","files":{"profiles.json":"\#(Data("[]".utf8).base64EncodedString())"}}"#
        XCTAssertEqual(try BackupManager.restore(Data(json.utf8), root: b, defaults: suite()), 1)
        XCTAssertEqual(read(b, "profiles.json"), "[]")
    }
}

final class CoreOverridesTests: XCTestCase {
    func decode(_ s: String) throws -> CoreOverrides { try JSONDecoder().decode(CoreOverrides.self, from: Data(s.utf8)) }

    func testEmptyAndMistypedFallBackToDefaults() throws {
        let d = CoreOverrides()
        XCTAssertEqual(try decode("{}"), d)
        let o = try decode(#"{"mode":"global","mixedPort":"x","tunMTU":99999,"blockQUIC":"sometimes","testURL":"ftp://a","testTimeoutMs":5,"tunnelMode":"weird","memoryLimitMB":500,"ipPreference":"v7","controllerPort":70000,"sniffer":"yes"}"#)
        XCTAssertEqual(o.mode, "global")
        XCTAssertEqual(o.mixedPort, d.mixedPort)
        XCTAssertEqual(o.tunMTU, d.tunMTU)
        XCTAssertEqual(o.blockQUIC, d.blockQUIC)
        XCTAssertEqual(o.testURL, d.testURL)
        XCTAssertEqual(o.testTimeoutMs, d.testTimeoutMs)
        XCTAssertEqual(o.tunnelMode, "tun")
        XCTAssertEqual(o.memoryLimitMB, d.memoryLimitMB)
        XCTAssertEqual(o.ipPreference, d.ipPreference)
        XCTAssertEqual(o.controllerPort, d.controllerPort, "v0.19.5: out-of-range controller port falls back")
        XCTAssertEqual(o.sniffer, d.sniffer)
    }

    func testLegacyIPv6Bool() throws {
        XCTAssertEqual(try decode(#"{"ipv6":true}"#).ipv6Mode, "always")
        XCTAssertEqual(try decode(#"{"ipv6":false}"#).ipv6Mode, "off")
        XCTAssertEqual(try decode(#"{"ipv6":true,"ipv6Mode":"auto"}"#).ipv6Mode, "auto")
        XCTAssertEqual(try decode(#"{"ipv6":true,"ipv6Mode":"bogus"}"#).ipv6Mode, "always")
    }

    /// v0.19.5: one malformed 其他用户 entry / a lanAuth without password kept the rest.
    func testLanUsersTolerant() throws {
        let o = try decode(#"{"lanAuth":{"username":"me"},"lanUsers":[{"username":"tv","password":"1"},{"username":"x"},{"password":5}]}"#)
        XCTAssertEqual(o.lanAuth.username, "me")
        XCTAssertEqual(o.lanAuth.password, "")
        XCTAssertEqual(o.lanUsers.count, 3)
        XCTAssertEqual(o.lanUsers.first, CoreOverrides.LanAuth(username: "tv", password: "1"))
    }

    func testEncodeDecodeRoundTrip() throws {
        var o = CoreOverrides()
        o.mode = "direct"; o.mixedPort = 7999; o.includedRoutes = ["10.0.0.0/8"]; o.lanUsers = [.init(username: "a", password: "b")]
        o.flushDNSOnNetworkChange = false; o.geoURLs = ["mmdb": "https://example.com/a.mmdb"]
        let back = try JSONDecoder().decode(CoreOverrides.self, from: try JSONEncoder().encode(o))
        XCTAssertEqual(back, o)
    }

    func testReconcile() {
        XCTAssertEqual(CoreOverrides.reconcile(json: "j", keychain: nil).value, "j")
        XCTAssertFalse(CoreOverrides.reconcile(json: "j", keychain: "").jsonNeedsSync)
        XCTAssertTrue(CoreOverrides.reconcile(json: "", keychain: "k").jsonNeedsSync)
        XCTAssertEqual(CoreOverrides.reconcile(json: "", keychain: "k").value, "k")
        XCTAssertFalse(CoreOverrides.reconcile(json: "k", keychain: "k").jsonNeedsSync)
    }

    func testProbePortAvoidsOtherPorts() {
        var o = CoreOverrides()
        o.mixedPort = 7899
        XCTAssertEqual(o.probePort, 7898)
        o.controllerPort = 7898
        XCTAssertEqual(o.probePort, 7897)
    }
}

final class SubscriptionUserInfoTests: XCTestCase {
    func testParse() {
        let i = SubscriptionUserInfo.parse("upload=1024; download=2048; total=10737418240; expire=1767225600")
        XCTAssertEqual(i?.upload, 1024)
        XCTAssertEqual(i?.used, 3072)
        XCTAssertEqual(i?.expireDate, Date(timeIntervalSince1970: 1767225600))
        XCTAssertNil(SubscriptionUserInfo.parse(nil))
        XCTAssertNil(SubscriptionUserInfo.parse(""))
        XCTAssertNil(SubscriptionUserInfo.parse("foo=bar"))
        XCTAssertEqual(SubscriptionUserInfo.parse("Upload = 5 ;DOWNLOAD=6")?.used, 11)
        XCTAssertEqual(SubscriptionUserInfo.parse("upload=1.5e3")?.upload, 1500)
    }

    func testHostileValuesDoNotTrap() {
        let i = SubscriptionUserInfo.parse("upload=1e30; download=inf; total=nan; expire=-5")
        XCTAssertEqual(i?.upload, .max)
        XCTAssertEqual(i?.download, 0)
        XCTAssertEqual(i?.total, 0)
        XCTAssertEqual(i?.expire, 0)
        XCTAssertNil(i?.expireDate)
        let big = SubscriptionUserInfo.parse("upload=9223372036854775807; download=9223372036854775807; total=1")
        XCTAssertEqual(big?.used, .max)
        XCTAssertEqual(big?.fraction, 1)
        XCTAssertEqual(SubscriptionUserInfo.parse("total=0; upload=5")?.fraction, 0)
    }
}

final class RouteSpecTests: XCTestCase {
    func testValid() {
        XCTAssertEqual(RouteSpec("10.0.0.0/8")?.mask, "255.0.0.0")
        XCTAssertEqual(RouteSpec(" 192.168.1.1 ")?.prefix, 32)
        XCTAssertEqual(RouteSpec("0.0.0.0/0")?.mask, "0.0.0.0")
        XCTAssertEqual(RouteSpec("172.16.0.0/12")?.mask, "255.240.0.0")
        XCTAssertEqual(RouteSpec("fd00::/8")?.isV6, true)
        XCTAssertEqual(RouteSpec("::/0")?.prefix, 0)
        XCTAssertEqual(RouteSpec("2001:db8::1")?.prefix, 128)
    }

    func testInvalid() {
        for s in ["", "/", "//", "/8", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0/8", "fd00::/129", "example.com", "10.0.0.0/8/9", "10.0.0.0/ 8", "1.2.3.4/x"] {
            XCTAssertNil(RouteSpec(s), s)
        }
        XCTAssertEqual(RouteSpec.invalid(["10.0.0.0/8", "", "  ", "bad", "/"]), ["bad", "/"])
    }
}

@MainActor
final class ProfileStoreLogicTests: XCTestCase {
    func testRefreshMergeKeepsEditsMadeDuringDownload() {
        var before = Profile(name: "Sub", kind: .remote, url: "https://example.com/a")
        before.updateIntervalHours = 24
        var current = before
        current.name = "Renamed"
        current.updateIntervalHours = 6
        current.userAgent = "mihomo"
        var downloaded = before
        downloaded.userInfo = SubscriptionUserInfo(upload: 1, download: 2, total: 3, expire: 0)
        downloaded.lastUpdated = Date(timeIntervalSince1970: 100)
        let m = ProfileStore.mergeRefreshed(current: current, downloaded: downloaded)
        XCTAssertEqual(m.name, "Renamed")
        XCTAssertEqual(m.updateIntervalHours, 6)
        XCTAssertEqual(m.userAgent, "mihomo")
        XCTAssertEqual(m.userInfo, downloaded.userInfo)
        XCTAssertEqual(m.lastUpdated, downloaded.lastUpdated)
        var unnamed = current
        unnamed.name = "  "
        downloaded.name = "From Header"
        XCTAssertEqual(ProfileStore.mergeRefreshed(current: unnamed, downloaded: downloaded).name, "From Header")
    }

    func header(_ h: [String: String]) -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: "https://example.com")!, statusCode: 200, httpVersion: nil, headerFields: h)!
    }

    func testNameFromHeaders() {
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["profile-title": "机场"])), "机场")
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["profile-title": "base64:" + Data("机场 A".utf8).base64EncodedString()])), "机场 A")
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["Content-Disposition": "attachment; filename*=UTF-8''%E6%9C%BA%E5%9C%BA.yaml"])), "机场")
        // v0.19.5
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["Content-Disposition": "attachment; filename*=utf-8''%E6%9C%BA%E5%9C%BA.yml"])), "机场")
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["Content-Disposition": "attachment; filename=\"My Sub.yaml\"; size=12"])), "My Sub")
        XCTAssertEqual(ProfileStore.nameFromHeaders(header(["Content-Disposition": "attachment; FILENAME=plain.yaml"])), "plain")
        XCTAssertNil(ProfileStore.nameFromHeaders(header([:])))
        XCTAssertEqual(ProfileStore.stripYAMLExtension(".yaml"), ".yaml")
    }
}

// MARK: v0.19.6 (review 7) scale + concurrency, through the same gomobile calls the app makes. Scratch dirs only.

final class ScaleTests: XCTestCase {
    private func bigProfile(_ root: URL, nodes: Int = 3000, rules: Int = 10000) -> String {
        let path = root.appendingPathComponent("big.yaml").path
        try? UITestSeed.bigProfileYAML(nodes: nodes, rules: rules).write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    func testLargeProfileValidatesAndInspects() {
        let root = scratch(), path = bigProfile(root)
        var t = Date()
        XCTAssertEqual(TestBridge.validate(home: root.path, path: path), "")
        let validate = Date().timeIntervalSince(t)
        t = Date()
        let json = TestBridge.inspect(home: root.path, path: path)
        let inspect = Date().timeIntervalSince(t)
        let o = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]
        XCTAssertEqual((o?["proxies"] as? [Any])?.count, 3000)
        let big = (o?["groups"] as? [[String: Any]])?.first { $0["name"] as? String == "Big Select" }
        XCTAssertEqual((big?["proxies"] as? [Any])?.count, 3000)
        print("3000 nodes / 10000 rules: validate \(validate) s, inspect \(inspect) s, \(json.utf8.count / 1024) KB JSON")
        XCTAssertLessThan(validate, 15)
        XCTAssertLessThan(inspect, 15)
    }

    func testLargeManualListOffMainActor() async {
        let root = scratch()
        let path = root.appendingPathComponent("manual.yaml").path
        _ = TestBridge.manualDelete(path, "")
        XCTAssertEqual(TestBridge.manualAdd(path, UITestSeed.bigManualLinks(3000)), 3000)
        let t = Date()
        let list = await Task.detached { ProfileStore.manualNodes(path: path) }.value
        XCTAssertEqual(list.count, 3000)
        XCTAssertEqual(list.last?["name"] as? String, "BM 2999")
        XCTAssertLessThan(Date().timeIntervalSince(t), 10)
        XCTAssertTrue(ProfileStore.manualNodes(path: nil).isEmpty)
    }

    /// The Go side serialises read-modify-write per file (v0.19.6); before, most concurrent additions were lost.
    func testConcurrentProfileNodeWrites() async {
        let root = scratch(), path = bigProfile(root, nodes: 50, rules: 50)
        await withTaskGroup(of: String.self) { g in
            for i in 0..<12 {
                g.addTask {
                    TestBridge.nodeUpsert(home: root.path, path: path, json: #"{"name":"NEW \#(i)","type":"ss","server":"192.0.2.\#(i + 1)","port":443,"cipher":"aes-128-gcm","password":"x"}"#, oldName: "")
                }
            }
            for await e in g { XCTAssertEqual(e, "") }
        }
        for i in 0..<12 { XCTAssertTrue(TestBridge.hasNode(path, "NEW \(i)"), "NEW \(i) lost") }
    }

    func testConcurrentManualAddsAndSelections() async {
        let root = scratch()
        let manual = root.appendingPathComponent("manual.yaml").path
        _ = TestBridge.manualDelete(manual, "")
        let profile = root.appendingPathComponent("p.yaml").path
        try? "proxies: []\n".write(toFile: profile, atomically: true, encoding: .utf8)
        let ui = Data("aes-128-gcm:pw".utf8).base64EncodedString()
        await withTaskGroup(of: Void.self) { g in
            for i in 0..<16 {
                g.addTask { _ = TestBridge.manualAdd(manual, "ss://\(ui)@192.0.2.\(i + 1):443#M\(i)") }
                g.addTask { _ = TestBridge.saveSelection(profile, "G\(i)", "DIRECT") }
            }
        }
        XCTAssertEqual(ProfileStore.manualNodes(path: manual).count, 16)
        let sel = (try? Data(contentsOf: root.appendingPathComponent("p.selected.json")))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
        XCTAssertEqual(sel?.count, 16, "offline selections lost")
    }

    /// ProfileStore's refresh merge stays correct when many refresh results land at once.
    func testConcurrentRefreshMerges() async {
        let cur = Profile(name: "Mine", kind: .remote, url: "https://example.com/s", userAgent: "ua", updateIntervalHours: 6)
        let merged = await withTaskGroup(of: Profile.self, returning: [Profile].self) { g in
            for i in 0..<64 {
                g.addTask {
                    var d = cur
                    d.name = "server-\(i)"
                    d.lastUpdated = Date(timeIntervalSince1970: TimeInterval(i))
                    return ProfileStore.mergeRefreshed(current: cur, downloaded: d)
                }
            }
            var out: [Profile] = []
            for await p in g { out.append(p) }
            return out
        }
        XCTAssertEqual(merged.count, 64)
        XCTAssertTrue(merged.allSatisfy { $0.name == "Mine" && $0.userAgent == "ua" && $0.updateIntervalHours == 6 })
    }
}

// v0.19.8 配置快照 dedupe: same configuration with another key order / timestamps / volatile files hashes the
// same; a real change does not; same-reason captures within a minute coalesce.
final class SnapshotDedupeTests: XCTestCase {
    func testContentHashIgnoresKeyOrderTimestampsAndVolatileFiles() {
        let a: [String: Data] = [
            "mihomo/group-edits.json": Data(#"{"b":{"x":1,"y":[1,2]},"a":"Proxy"}"#.utf8),
            "profiles.json": Data(#"[{"id":"p1","name":"Sub","lastUpdated":"2026-10-20T07:00:00Z","userInfo":{"upload":1}}]"#.utf8),
            "profiles/p1.yaml": Data("proxies: []\n".utf8),
        ]
        var b = a
        b["mihomo/group-edits.json"] = Data(#"{"a":"Proxy","b":{"y":[1,2],"x":1}}"#.utf8)
        b["profiles.json"] = Data(#"[{"name":"Sub","id":"p1","lastUpdated":"2026-10-20T07:00:45Z","userInfo":{"upload":99}}]"#.utf8)
        b["mihomo/runtime-groups.json"] = Data(#"{"order":["A","B"]}"#.utf8)
        b["mihomo/engine/store.json"] = Data(#"{"token":"changes"}"#.utf8)
        XCTAssertEqual(SnapshotStore.contentHash(a), SnapshotStore.contentHash(b))

        var c = a
        c["mihomo/group-edits.json"] = Data(#"{"a":"DIRECT","b":{"x":1,"y":[1,2]}}"#.utf8)
        XCTAssertNotEqual(SnapshotStore.contentHash(a), SnapshotStore.contentHash(c))
        var d = a
        d["profiles/p1.yaml"] = Data("proxies: [x]\n".utf8)
        XCTAssertNotEqual(SnapshotStore.contentHash(a), SnapshotStore.contentHash(d))
        // Array order is configuration (group order, rule order).
        var e = a
        e["mihomo/group-edits.json"] = Data(#"{"a":"Proxy","b":{"x":1,"y":[2,1]}}"#.utf8)
        XCTAssertNotEqual(SnapshotStore.contentHash(a), SnapshotStore.contentHash(e))
    }

    func testSameReasonWithinAMinuteCoalesces() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let newest = SnapshotMeta(id: "1", date: t0, reason: "编辑策略组前", files: 47, bytes: 1, hash: "h1")
        XCTAssertTrue(SnapshotStore.shouldSkip(newest: newest, reason: "编辑策略组前", contentHash: "h2", manual: false, now: t0.addingTimeInterval(20)))
        XCTAssertFalse(SnapshotStore.shouldSkip(newest: newest, reason: "编辑策略组前", contentHash: "h2", manual: false, now: t0.addingTimeInterval(61)))
        XCTAssertFalse(SnapshotStore.shouldSkip(newest: newest, reason: "添加模块前", contentHash: "h2", manual: false, now: t0.addingTimeInterval(5)))
        XCTAssertFalse(SnapshotStore.shouldSkip(newest: newest, reason: "编辑策略组前", contentHash: "h2", manual: true, now: t0.addingTimeInterval(5)))
        XCTAssertTrue(SnapshotStore.shouldSkip(newest: newest, reason: "手动快照", contentHash: "h1", manual: true, now: t0.addingTimeInterval(500)))
        XCTAssertFalse(SnapshotStore.shouldSkip(newest: nil, reason: "x", contentHash: "h1", manual: false))
    }
}
