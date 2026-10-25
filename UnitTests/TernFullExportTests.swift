import XCTest
import Security
@testable import Mihomo

// feat/nc-full-export: 完整导出（.conf）round trip and failure atomicity. Every test works in scratch containers
// and its own UserDefaults suite, never in the app's container.

private func fxScratch() -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("fullexport-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

private func fxWrite(_ root: URL, _ rel: String, _ data: Data) {
    let u = root.appendingPathComponent(rel)
    try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? data.write(to: u)
}

private func fxRead(_ root: URL, _ rel: String) -> Data? { try? Data(contentsOf: root.appendingPathComponent(rel)) }

private func fxSuite() -> UserDefaults {
    let name = "fullexport.\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    return d
}

private func fxFiles(_ root: URL) -> [String] {
    let all = (FileManager.default.subpaths(atPath: root.path) ?? []).sorted()
    return all.filter { rel in
        var isDir: ObjCBool = false
        _ = FileManager.default.fileExists(atPath: root.appendingPathComponent(rel).path, isDirectory: &isDir)
        return !isDir.boolValue
    }
}

private func fxJSON(_ d: Data?) -> Any? { d.flatMap { try? JSONSerialization.jsonObject(with: $0) } }

final class TernFullExportTests: XCTestCase {
    /// YAML whose lines look like .conf sections / keys; it must come back byte for byte.
    let yaml = """
    # 中文注释 🚀
    mixed-port: 7890
    proxies:
      - {name: "香港 01", type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: "p,w=d#x"}
    rules:
      - MATCH,DIRECT
    # lines below look like sections of the export and must survive
    [general]
    tern-export = 2
    [end]
    [mitm]
    p12 = AAAA
    note: |
      [rewrite_local]
      ^http://x reject

    """

    let profileID = "prof-1"
    let scriptNames = ["中文脚本.js", "🚀 emoji 脚本.js", "a,b=c #x;[y].js"]

    func home(_ root: URL) -> String { root.appendingPathComponent("mihomo").path }

    func makeSource() throws -> (root: URL, defaults: UserDefaults, profile: Profile, engine: EngineConfig) {
        let root = fxScratch()
        let defaults = fxSuite()

        var p = Profile(name: "我的配置 🚀, a=b", kind: .remote, url: "https://sub.example.com/link?token=abc&flag=1")
        p.id = profileID
        p.lastUpdated = Date(timeIntervalSinceReferenceDate: 750_000_000)
        p.sourceName = "来源配置"
        p.copyModified = true
        var other = Profile(name: "其他", kind: .local)
        other.id = "other"
        fxWrite(root, "profiles.json", try JSONEncoder().encode([other, p]))
        fxWrite(root, "profiles/\(profileID).yaml", Data(yaml.utf8))
        fxWrite(root, "profiles/other.yaml", Data("mixed-port: 1\n".utf8))
        defaults.set(profileID, forKey: "activeProfileID")

        var c = EngineConfig()
        c.enabled = true
        c.scriptsEnabled = false
        c.mitm = true
        c.skipCertVerify = true
        c.h2 = false
        c.hostnames = ["*.example.com", "api.中文.com", "-skip.example.com"]
        c.quic = "all"
        c.quicAllow = ["quic.example.com"]
        var r2 = EngineItem(line: "^https?://track\\.example\\.com/ url reject-200")
        r2.enabled = false
        r2.note = "备注, with = signs\nand a newline"
        c.rules = [EngineItem(line: "^https?://ad\\.example\\.com/ url reject"), r2,
                   EngineItem(line: "[weird] looks like a section"), EngineItem(line: "#not a comment"),
                   EngineItem(line: "  padded line  ")]
        var s1 = EngineItem(line: "签到 = type=cron, cronexp=\"0 9 * * *\", script-path=中文脚本.js")
        s1.note = "定时"
        c.scripts = [s1]
        var m1 = EngineModule(name: "广告拦截, Pro=1", url: "https://example.com/rules/ad.sgmodule", enabled: true,
                              args: ["key": "a,b=c", "开关": "true", "emoji": "🚀"], policies: ["Proxy": "🚀 节点选择"],
                              updatedAt: 1_729_849_812.125, interval: 3600)
        m1.id = "mod-1"
        var m2 = EngineModule(name: "本地模块", url: "", enabled: false)
        m2.id = "mod-2"
        c.modules = [m1, m2]
        c.scriptResources = ["https://example.com/s.js": ScriptResourceSetting(disabled: true, interval: 600)]
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        fxWrite(root, "mihomo/engine/engine.json", try enc.encode(c))
        fxWrite(root, TernFullExport.moduleRel("mod-1"), Data("#!name=广告拦截\n[URL Rewrite]\n^http://ad - reject\n".utf8))
        fxWrite(root, TernFullExport.moduleRel("mod-2"), Data("hostname = local.example.com\n".utf8))

        for (i, n) in scriptNames.enumerated() {
            fxWrite(root, "mihomo/engine/scripts/\(n)", Data("console.log('脚本 \(i) 🚀');\n".utf8))
        }

        let overrideIndex: [String: Any] = [
            profileID: [["id": "ov-1", "name": "覆写 1, x=y", "enabled": true, "updateIntervalHours": 24, "options": ["a": true]]],
            "other": [["id": "ov-other", "name": "其他", "enabled": false, "updateIntervalHours": 0]],
        ]
        fxWrite(root, TernFullExport.overrideIndexRel, try JSONSerialization.data(withJSONObject: overrideIndex))
        fxWrite(root, TernFullExport.overrideContentRel("ov-1"), Data("function main(c){return c} // 覆写\n".utf8))
        fxWrite(root, TernFullExport.overrideContentRel("ov-other"), Data("other".utf8))

        let subs: [[String: Any]] = [["id": "ns-1", "name": "机场, A", "url": "https://n.example.com/sub?a=1", "enabled": true,
                                      "userAgent": "clash.meta", "updateIntervalHours": 12, "groups": ["🚀 节点选择"]]]
        fxWrite(root, TernFullExport.nodeSubsRel, try JSONSerialization.data(withJSONObject: subs))
        fxWrite(root, "mihomo/dns.json", Data(#"{"nameserver":["223.5.5.5"]}"#.utf8))
        fxWrite(root, "mihomo/engine/store.json", Data(#"{"cookie":"secret"}"#.utf8)) // travels only with includeSensitive
        fxWrite(root, "mihomo/secrets.json", Data(#"{"controller-secret":"pw"}"#.utf8))

        try NCCAManager.generateCA(home: home(root))
        return (root, defaults, p, c)
    }

    func export(_ src: (root: URL, defaults: UserDefaults, profile: Profile, engine: EngineConfig)) throws -> String {
        try TernFullExport.build(profileID: profileID, root: src.root, defaults: src.defaults,
                                 appVersion: "0.20.0", appBuild: "1", passphrase: "test-passphrase")
    }

    func keyData(_ root: URL) -> Data? {
        guard let ca = NCCAManager.loadCA(home: home(root)) else { return nil }
        return SecKeyCopyExternalRepresentation(ca.caKey, nil) as Data?
    }

    struct ItemView: Equatable { var line: String; var enabled: Bool; var note: String? }
    func view(_ l: [EngineItem]) -> [ItemView] { l.map { ItemView(line: $0.line, enabled: $0.enabled, note: $0.note) } }

    func testRoundTripRestoresEverything() throws {
        let src = try makeSource()
        let text = try export(src)
        XCTAssertTrue(TernFullExport.isFullExport(text))
        XCTAssertTrue(text.contains("[rewrite_remote]") && text.contains("[mitm]") && text.contains("passphrase = test-passphrase"))
        XCTAssertTrue(text.contains("hostname = *.example.com, api.中文.com, -skip.example.com"))
        XCTAssertFalse(text.contains("cookie"), "the scripts' key-value store stays out")

        // Destination with its own data that must survive (another profile, another profile's override scripts).
        let dst = fxScratch()
        let d2 = fxSuite()
        var keep = Profile(name: "保留", kind: .local)
        keep.id = "keep"
        fxWrite(dst, "profiles.json", try JSONEncoder().encode([keep]))
        fxWrite(dst, TernFullExport.overrideIndexRel, try JSONSerialization.data(withJSONObject: ["keep": [["id": "k1", "name": "k"]]]))

        let payload = try TernFullExport.importText(text, root: dst, defaults: d2)
        XCTAssertFalse(payload.summaryLines.isEmpty)

        // Profile: YAML byte for byte (incl. the "[general]" / "[end]" lines), metadata, active.
        XCTAssertEqual(fxRead(dst, "profiles/\(profileID).yaml"), Data(yaml.utf8))
        let profiles = try JSONDecoder().decode([Profile].self, from: XCTUnwrap(fxRead(dst, "profiles.json")))
        XCTAssertEqual(profiles.first { $0.id == profileID }, src.profile)
        XCTAssertNotNil(profiles.first { $0.id == "keep" })
        XCTAssertEqual(d2.string(forKey: "activeProfileID"), profileID)

        // Engine: modules (args, policies, interval, updatedAt, ids), rewrite / script lines, MitM settings.
        let e = try JSONDecoder().decode(EngineConfig.self, from: XCTUnwrap(fxRead(dst, TernFullExport.engineRel)))
        let srcE = try JSONDecoder().decode(EngineConfig.self, from: XCTUnwrap(fxRead(src.root, TernFullExport.engineRel)))
        XCTAssertEqual(e.modules, srcE.modules)
        XCTAssertEqual(e.modules.first?.args, ["key": "a,b=c", "开关": "true", "emoji": "🚀"])
        XCTAssertEqual(view(e.rules), view(srcE.rules))
        XCTAssertEqual(view(e.scripts), view(srcE.scripts))
        XCTAssertEqual(e.enabled, srcE.enabled)
        XCTAssertEqual(e.scriptsEnabled, srcE.scriptsEnabled)
        XCTAssertEqual(e.mitm, srcE.mitm)
        XCTAssertEqual(e.skipCertVerify, srcE.skipCertVerify)
        XCTAssertEqual(e.h2, srcE.h2)
        XCTAssertEqual(e.captureBodies, srcE.captureBodies)
        XCTAssertEqual(e.hostnames, srcE.hostnames)
        XCTAssertEqual(e.quic, srcE.quic)
        XCTAssertEqual(e.quicAllow, srcE.quicAllow)
        XCTAssertEqual(e.scriptResources, srcE.scriptResources)
        for id in ["mod-1", "mod-2"] {
            XCTAssertEqual(fxRead(dst, TernFullExport.moduleRel(id)), fxRead(src.root, TernFullExport.moduleRel(id)), id)
        }

        // Local scripts with 中文 / emoji / punctuation in their names.
        for n in scriptNames {
            XCTAssertEqual(fxRead(dst, "mihomo/engine/scripts/\(n)"), fxRead(src.root, "mihomo/engine/scripts/\(n)"), n)
        }

        // Override scripts: this profile's list + content; the destination's other profile kept.
        let idx = try XCTUnwrap(fxJSON(fxRead(dst, TernFullExport.overrideIndexRel)) as? [String: Any])
        let srcIdx = try XCTUnwrap(fxJSON(fxRead(src.root, TernFullExport.overrideIndexRel)) as? [String: Any])
        XCTAssertTrue((idx[profileID] as? NSArray)?.isEqual(srcIdx[profileID] as? [Any] ?? []) == true)
        XCTAssertNotNil(idx["keep"])
        XCTAssertNil(idx["other"], "only the exported profile's override scripts travel")
        XCTAssertEqual(fxRead(dst, TernFullExport.overrideContentRel("ov-1")), fxRead(src.root, TernFullExport.overrideContentRel("ov-1")))

        // Node subscriptions and settings files.
        XCTAssertTrue((fxJSON(fxRead(dst, TernFullExport.nodeSubsRel)) as? NSArray)?.isEqual(fxJSON(fxRead(src.root, TernFullExport.nodeSubsRel)) as? [Any] ?? []) == true)
        XCTAssertEqual(fxRead(dst, "mihomo/dns.json"), fxRead(src.root, "mihomo/dns.json"))
        XCTAssertNil(fxRead(dst, "mihomo/engine/store.json"))

        // MitM CA: the same certificate and the same private key.
        XCTAssertNotNil(NCCAManager.caCertDER(home: home(dst)))
        XCTAssertEqual(NCCAManager.caCertDER(home: home(dst)), NCCAManager.caCertDER(home: home(src.root)))
        XCTAssertNotNil(keyData(dst))
        XCTAssertEqual(keyData(dst), keyData(src.root))

        // No staging leftovers.
        XCTAssertFalse(fxFiles(dst).contains { $0.hasPrefix(".tern-import-") })
    }

    /// 完整导出（含脚本数据与密码）: the opt-in export carries store.json + secrets.json and restores them 0600.
    func testSensitiveDataOnlyWhenOptedIn() throws {
        let src = try makeSource()
        let plain = try export(src)
        XCTAssertFalse(plain.contains("controller-secret") || plain.contains("mihomo/secrets.json"))
        let full = try TernFullExport.build(profileID: profileID, root: src.root, defaults: src.defaults,
                                            appVersion: "0.20.0", appBuild: "1", passphrase: "test-passphrase",
                                            includeSensitive: true)
        XCTAssertTrue(full.contains("mihomo/engine/store.json") && full.contains("mihomo/secrets.json"))
        let dst = fxScratch()
        _ = try TernFullExport.importText(full, root: dst, defaults: fxSuite())
        XCTAssertEqual(fxRead(dst, "mihomo/engine/store.json"), Data(#"{"cookie":"secret"}"#.utf8))
        XCTAssertEqual(fxRead(dst, "mihomo/secrets.json"), Data(#"{"controller-secret":"pw"}"#.utf8))
        let attrs = try FileManager.default.attributesOfItem(atPath: dst.appendingPathComponent("mihomo/secrets.json").path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    /// Review 10-25 #3/#5: a module with no cache leaves the target's cache alone and refreshes; URLs round-trip exactly.
    func testUncachedModuleAndURLEscaping() throws {
        let src = try makeSource()
        let engineURL = src.root.appendingPathComponent("mihomo/engine/engine.json")
        var c = try JSONDecoder().decode(EngineConfig.self, from: Data(contentsOf: engineURL))
        let odd = "https://example.com/a,b%2Cc%20d.sgmodule?x=1,2"
        var m3 = EngineModule(name: "无缓存", url: odd, enabled: true, updatedAt: 1_700_000_000)
        m3.id = "mod-3"
        c.modules.append(m3)
        try JSONEncoder().encode(c).write(to: engineURL)
        let text = try export(src)

        let dst = fxScratch()
        fxWrite(dst, TernFullExport.moduleRel("mod-3"), Data("good cache".utf8))
        let p = try TernFullExport.importText(text, root: dst, defaults: fxSuite())
        let m = try XCTUnwrap(p.modules.first { $0.id == "mod-3" })
        XCTAssertEqual(m.url, odd)
        XCTAssertNil(m.updatedAt, "no cache in the file → refresh")
        XCTAssertEqual(fxRead(dst, TernFullExport.moduleRel("mod-3")), Data("good cache".utf8))
        XCTAssertNotNil(p.modules.first { $0.id == "mod-1" }?.updatedAt)
    }

    /// Review 10-25 #4: a module id that isn't its own cache file name is refused before anything is written.
    func testUnsafeModuleIDRejected() throws {
        let src = try makeSource()
        let text = try export(src).replacingOccurrences(of: "id=mod-1", with: "id=a%3Ab")
        let dst = fxScratch()
        XCTAssertThrowsError(try TernFullExport.importText(text, root: dst, defaults: fxSuite()))
        XCTAssertEqual(fxFiles(dst), [])
    }

    func testExportTwiceIsStableAndReimportable() throws {
        let src = try makeSource()
        let dst = fxScratch()
        try TernFullExport.importText(try export(src), root: dst, defaults: fxSuite())
        // Export the restored container again: same profile YAML and modules.
        let again = try TernFullExport.build(profileID: profileID, root: dst, defaults: fxSuite(), appVersion: "0.20.0", appBuild: "1")
        let p = try TernFullExport.parse(again)
        XCTAssertEqual(p.profileYAML, Data(yaml.utf8))
        XCTAssertEqual(p.modules.map(\.id), ["mod-1", "mod-2"])
        XCTAssertEqual(p.scripts.map(\.name).sorted(), scriptNames.sorted())
        XCTAssertNotNil(p.caPEM)
    }

    func testCorruptedBase64WritesNothing() throws {
        let src = try makeSource()
        let text = try export(src).components(separatedBy: "\n")
            .map { $0.hasPrefix("content = ") ? "content = @@@not*base64@@@" : $0 }.joined(separator: "\n")
        let dst = fxScratch()
        let d2 = fxSuite()
        XCTAssertThrowsError(try TernFullExport.importText(text, root: dst, defaults: d2)) { e in
            guard case .corrupt? = e as? TernFullExport.ExportError else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(fxFiles(dst), [])
        XCTAssertNil(d2.string(forKey: "activeProfileID"))
    }

    func testWrongPassphraseWritesNothing() throws {
        let src = try makeSource()
        let text = try export(src).components(separatedBy: "\n")
            .map { $0.hasPrefix("passphrase = ") ? "passphrase = wrong-passphrase" : $0 }.joined(separator: "\n")
        let dst = fxScratch()
        XCTAssertThrowsError(try TernFullExport.importText(text, root: dst, defaults: fxSuite())) { e in
            guard case .badCertificate? = e as? TernFullExport.ExportError else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(fxFiles(dst), [])
    }

    func testTruncatedFileWritesNothing() throws {
        let src = try makeSource()
        let text = try export(src)
        let cut = String(text.prefix(text.count * 2 / 3))
        let dst = fxScratch()
        XCTAssertThrowsError(try TernFullExport.importText(cut, root: dst, defaults: fxSuite()))
        XCTAssertEqual(fxFiles(dst), [])
    }

    func testPathTraversalNameRejected() throws {
        let src = try makeSource()
        let text = try export(src).replacingOccurrences(of: "[script_local]\n", with: "[script_local]\n..%2F..%2Fevil.js = aGk=\n")
        let dst = fxScratch()
        XCTAssertThrowsError(try TernFullExport.importText(text, root: dst, defaults: fxSuite()))
        XCTAssertEqual(fxFiles(dst), [])
    }

    func testUnreadableDestinationIndexWritesNothing() throws {
        let src = try makeSource()
        let text = try export(src)
        let dst = fxScratch()
        fxWrite(dst, "profiles.json", Data("not json".utf8))
        XCTAssertThrowsError(try TernFullExport.importText(text, root: dst, defaults: fxSuite()))
        XCTAssertEqual(fxFiles(dst), ["profiles.json"])
        XCTAssertEqual(fxRead(dst, "profiles.json"), Data("not json".utf8))
    }

    func testDetection() throws {
        XCTAssertFalse(TernFullExport.isFullExport("[General]\nloglevel = notify\n[Proxy]\nA = direct\n"))
        XCTAssertFalse(TernFullExport.isFullExport("[general]\nserver_check_url = http://x\n[server_local]\n"))
        XCTAssertFalse(TernFullExport.isFullExport("mixed-port: 7890\n[general]\ntern-export = 1\n"), "a YAML profile is not an export")
        XCTAssertTrue(TernFullExport.isFullExport("# Tern\n\n[general]\ntern-export = 1\n[end]\n"))
        XCTAssertThrowsError(try TernFullExport.parse("[general]\ntern-export = 99\n[profile]\n[end]\n")) { e in
            XCTAssertEqual(e as? TernFullExport.ExportError, .unsupportedVersion(99))
        }
        // A full export opened from Files routes to the full-export import, a plain QX conf does not.
        let src = try makeSource()
        let f = FileManager.default.temporaryDirectory.appendingPathComponent("fx-\(UUID().uuidString).conf")
        try Data(try export(src).utf8).write(to: f)
        defer { try? FileManager.default.removeItem(at: f) }
        guard case .fullExport = ImportRouter.action(forFile: f) else { return XCTFail("not routed to the full export import") }
    }

    func testEscapingRoundTrips() {
        for s in ["a,b=c", "#x;[y]", " lead", "trail ", "100%", "中文 🚀", "line\nbreak\r\t"] {
            XCTAssertEqual(TernFullExport.unesc(TernFullExport.esc(s)), s, s)
            XCTAssertFalse(TernFullExport.esc(s).contains(","))
            XCTAssertFalse(TernFullExport.esc(s).contains("="))
            XCTAssertFalse(TernFullExport.esc(s).contains("\n"))
        }
    }
}
