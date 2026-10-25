import XCTest
@testable import Mihomo

/// nc-callsite-audit REWORK regressions (follow-up to PR #139, which the
/// maintainer review rejected on three counts):
///
/// 1. Mojibake — Build briefly decoded module files as Latin-1. Go's
///    mitm config.go Build does ParseText(string(b)): the module bytes
///    ARE the text and module files are UTF-8. The Latin-1 decode
///    re-read every multibyte sequence as separate characters, so all
///    Chinese content (comments, names, policy references) garbled and
///    Chinese policy names stopped matching. testModuleChineseText-
///    SurvivesBuild pins the UTF-8 round-trip through the real build
///    path (engine.json + module file on disk → NCMitmBuild.build).
///
/// 2. A bad rewrite aborting startup — #139 made
///    NCRewriteSnapshotBuilder.exportData errors fail the whole
///    NativeRuntimePrep.prepare. Go's ExportRewriteSnapshot returns
///    (string, int): it has no error path, content problems can never
///    abort a prepare; bad entries are collected in rs.errors at parse
///    time and simply never reach the snapshot. The prep block is back
///    to warn-and-continue (only the transaction's TxError — the file
///    write, fatal in Go too — propagates). prepareSyncLocked is
///    private and prepare() needs the app-group container, so the
///    regression is pinned at the deepest drivable level: the exact
///    two calls the prep block composes — NCMitmBuild.build (bad entry
///    skipped + recorded, good entry effective) and exportData (does
///    not throw, snapshot carries the good rule only).
final class NativeCoreCallsiteReworkTests: XCTestCase {

    /// Temp core home with engine.json (one enabled module, MitM on)
    /// and the module file at engine/modules/mod1.txt.
    private func makeHome(moduleText: String) throws -> String {
        let home = NSTemporaryDirectory() + "nc-rework-\(UUID().uuidString)"
        let modulesDir = home + "/engine/modules"
        try FileManager.default.createDirectory(atPath: modulesDir, withIntermediateDirectories: true)
        let engineJSON = """
        {"enabled":true,"mitm":true,"hostnames":["*.example.com"],
         "modules":[{"id":"mod1","name":"测试模块","enabled":true}]}
        """
        try engineJSON.write(toFile: home + "/engine/engine.json", atomically: true, encoding: .utf8)
        try moduleText.write(toFile: modulesDir + "/mod1.txt", atomically: true, encoding: .utf8)
        return home
    }

    /// Issue 1: Chinese text in a module file must survive the build
    /// byte-for-byte — in a core rule's policy name and in a rewrite
    /// target. Under the Latin-1 decode both came out as mojibake.
    func testModuleChineseTextSurvivesBuild() throws {
        let module = """
        #!name=中文测试模块
        #!desc=验证中文不乱码

        [Rule]
        DOMAIN,example.com,中文策略

        [URL Rewrite]
        ^https://good.example.com/ad 302 https://example.com/中文路径

        [MITM]
        hostname = *.example.com
        """
        let home = try makeHome(moduleText: module)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let cfg = NCEngineConfig.load(home: home)
        let rs = NCMitmBuild.build(home: home, cfg: cfg)

        XCTAssertTrue(rs.coreRules.contains("DOMAIN,example.com,中文策略"),
                      "core rules: \(rs.coreRules)")
        XCTAssertEqual(rs.rules.first?.target, "https://example.com/中文路径")

        // Fingerprints of the Latin-1 mis-decode (e.g. 中 → "ä¸­"):
        // none may appear in anything the build produced.
        let produced = (rs.coreRules + rs.rules.map { $0.pattern + $0.target }).joined(separator: "\n")
        XCTAssertFalse(produced.contains("ä"), "mojibake fingerprint in: \(produced)")
        XCTAssertFalse(produced.contains("\u{FFFD}"), "replacement char in: \(produced)")
    }

    /// Issue 2: a module whose [URL Rewrite] section contains one bad
    /// entry (a 302 with no target) must still build: the bad entry is
    /// recorded in rs.errors and skipped, the good entry takes effect,
    /// and the snapshot export the prepare stages does not throw.
    func testBadRewriteSkippedGoodRewriteExported() throws {
        let module = """
        #!name=BadRewrite

        [URL Rewrite]
        ^https://good.example.com/ad reject-dict
        ^https://bad.example.com/ad 302

        [MITM]
        hostname = *.example.com
        """
        let home = try makeHome(moduleText: module)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let cfg = NCEngineConfig.load(home: home)
        let rs = NCMitmBuild.build(home: home, cfg: cfg)

        XCTAssertTrue(rs.errors.contains { $0.contains("缺少目标地址") },
                      "bad entry must be recorded, errors: \(rs.errors)")
        XCTAssertEqual(rs.rules.count, 1, "only the good rewrite survives: \(rs.rules)")
        XCTAssertEqual(rs.rules.first?.action, "reject-dict")
        XCTAssertEqual(rs.rules.first?.pattern, "^https://good.example.com/ad")

        let (data, hosts) = try NCRewriteSnapshotBuilder.exportData(home: home, cfg: cfg, rs: rs)
        XCTAssertGreaterThan(hosts, 0)
        let snapText = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(snapText.contains("good.example.com"), "snapshot: \(snapText)")
        XCTAssertFalse(snapText.contains("bad.example.com"), "snapshot: \(snapText)")
    }
}
