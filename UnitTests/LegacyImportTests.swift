import XCTest
@testable import Tern

/// Rename (2026-10-27): the new bundle ids / App Group start an empty container, so importing what the pre-rename
/// app wrote (backups, WebDAV copies, 完整导出) is the migration path. Old names come from LegacyImport only.
final class LegacyImportTests: XCTestCase {
    private func scratch() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("legacy-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    private func suite() -> UserDefaults {
        let n = "legacy.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: n)!
        d.removePersistentDomain(forName: n)
        return d
    }
    private var oldApp: String { LegacyImport.backupAppNames.first! }
    private var oldDir: String { LegacyImport.storageDir }

    func testMapPath() {
        XCTAssertEqual(LegacyImport.mapPath(oldDir + "/overrides.json"), "tern/overrides.json")
        XCTAssertEqual(LegacyImport.mapPath(oldDir + "/engine/ca/ca.key"), "tern/engine/ca/ca.key")
        XCTAssertEqual(LegacyImport.mapPath(oldDir), "tern")
        XCTAssertEqual(LegacyImport.mapPath("profiles/p1.yaml"), "profiles/p1.yaml")
        XCTAssertEqual(LegacyImport.mapPath(oldDir + "x/y"), oldDir + "x/y", "only the directory itself")
        XCTAssertEqual(LegacyImport.mapPath("tern/dns.json"), "tern/dns.json")
    }

    func testOldBackupRestoresIntoTern() throws {
        let b = scratch()
        let ok = Data(#"{"mode":"rule"}"#.utf8).base64EncodedString()
        let json = """
        {"app":"\(oldApp)","files":{"\(oldDir)/overrides.json":"\(ok)","\(oldDir)/engine/engine.json":"\(ok)",
        "profiles.json":"\(Data("[]".utf8).base64EncodedString())","\(oldDir)/cache.db":"\(ok)"}}
        """
        let n = try BackupManager.restore(Data(json.utf8), root: b, defaults: suite())
        XCTAssertEqual(n, 3, "cache.db is not a backup item, old dir or new")
        XCTAssertNotNil(FileManager.default.contents(atPath: b.appendingPathComponent("tern/overrides.json").path))
        XCTAssertNotNil(FileManager.default.contents(atPath: b.appendingPathComponent("tern/engine/engine.json").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: b.appendingPathComponent(oldDir).path), "nothing written under the old dir")
        XCTAssertThrowsError(try BackupManager.restore(Data(#"{"app":"other","files":{}}"#.utf8), root: b, defaults: suite()))
    }

    func testNewBackupsUseTheNewEnvelope() throws {
        let a = scratch()
        let u = a.appendingPathComponent("tern/dns.json")
        try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: u)
        let (data, _) = try BackupManager.makeData(includeCA: false, root: a, defaults: suite())
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(obj?["app"] as? String, "tern")
        XCTAssertNotNil((obj?["files"] as? [String: String])?["tern/dns.json"])
    }

    func testOldEncryptedEnvelopeDecrypts() throws {
        let plain = Data(#"{"app":"tern","files":{}}"#.utf8)
        let enc = try BackupCrypto.encrypt(plain, password: "pw")
        var obj = try JSONSerialization.jsonObject(with: enc) as! [String: Any]
        XCTAssertEqual(obj["app"] as? String, "tern")
        obj["app"] = oldApp
        XCTAssertEqual(try BackupCrypto.decrypt(try JSONSerialization.data(withJSONObject: obj), password: "pw"), plain)
        obj["app"] = "other"
        XCTAssertThrowsError(try BackupCrypto.decrypt(try JSONSerialization.data(withJSONObject: obj), password: "pw"))
    }

    func testOldWebDAVNamesListedNotPruned() {
        let d = Date(timeIntervalSince1970: 1_790_000_000)
        let stamp = WebDAVClient.stampFormatterUTC.string(from: d) + "Z.json"
        let old = WebDAVFile(name: LegacyImport.webDAVPrefixes[0] + stamp)
        XCTAssertTrue(old.legacy)
        XCTAssertEqual(old.stamp?.timeIntervalSince1970 ?? 0, d.timeIntervalSince1970, accuracy: 1)
        let new = WebDAVFile(name: WebDAVClient.stampName(d) + ".json")
        XCTAssertFalse(new.legacy)
        XCTAssertTrue(new.name.hasPrefix("tern-backup-"))
        XCTAssertTrue(WebDAVClient.readPrefixes.contains { old.name.hasPrefix($0) })
    }

    func testStorageDirMovesOnceAndNeverOverwrites() throws {
        let fm = FileManager.default
        let c = scratch()
        try fm.createDirectory(at: c.appendingPathComponent(oldDir + "/engine"), withIntermediateDirectories: true)
        try Data("a".utf8).write(to: c.appendingPathComponent(oldDir + "/engine/engine.json"))
        try fm.createDirectory(at: c.appendingPathComponent("tern"), withIntermediateDirectories: true) // empty: ok
        LegacyImport.migrateStorageDirIfNeeded(container: c)
        XCTAssertEqual(fm.contents(atPath: c.appendingPathComponent("tern/engine/engine.json").path), Data("a".utf8))
        XCTAssertFalse(fm.fileExists(atPath: c.appendingPathComponent(oldDir).path))

        let c2 = scratch()
        try fm.createDirectory(at: c2.appendingPathComponent(oldDir), withIntermediateDirectories: true)
        try Data("old".utf8).write(to: c2.appendingPathComponent(oldDir + "/dns.json"))
        try fm.createDirectory(at: c2.appendingPathComponent("tern"), withIntermediateDirectories: true)
        try Data("new".utf8).write(to: c2.appendingPathComponent("tern/dns.json"))
        LegacyImport.migrateStorageDirIfNeeded(container: c2)
        XCTAssertEqual(fm.contents(atPath: c2.appendingPathComponent("tern/dns.json").path), Data("new".utf8))
        XCTAssertTrue(fm.fileExists(atPath: c2.appendingPathComponent(oldDir + "/dns.json").path))

        // selfreview-g2: the current dir already exists with other files (e.g. the tunnel started first) → the old
        // items it lacks are merged in, the clash is left alone, and the old dir stays only while something is left.
        let c3 = scratch()
        try fm.createDirectory(at: c3.appendingPathComponent(oldDir + "/engine"), withIntermediateDirectories: true)
        try Data("o".utf8).write(to: c3.appendingPathComponent(oldDir + "/overrides.json"))
        try Data("e".utf8).write(to: c3.appendingPathComponent(oldDir + "/engine/engine.json"))
        try fm.createDirectory(at: c3.appendingPathComponent("tern"), withIntermediateDirectories: true)
        try Data("r".utf8).write(to: c3.appendingPathComponent("tern/runtime.yaml"))
        LegacyImport.migrateStorageDirIfNeeded(container: c3)
        XCTAssertEqual(fm.contents(atPath: c3.appendingPathComponent("tern/overrides.json").path), Data("o".utf8))
        XCTAssertEqual(fm.contents(atPath: c3.appendingPathComponent("tern/engine/engine.json").path), Data("e".utf8))
        XCTAssertEqual(fm.contents(atPath: c3.appendingPathComponent("tern/runtime.yaml").path), Data("r".utf8))
        XCTAssertFalse(fm.fileExists(atPath: c3.appendingPathComponent(oldDir).path))
    }
}
