import XCTest
@testable import Tern

/// r7 (review7 R7A-1): every file a backup / snapshot / sync restore writes must have a reload path. A store that
/// caches one of them in memory and writes its whole list back would otherwise undo the restore on its next save.
@MainActor
final class ReloadCoverageTests: XCTestCase {
    func testEveryBackupItemHasAReloadPath() {
        for item in BackupManager.items(includeCA: true) + BackupManager.fullBackupOnlyItems {
            XCTAssertNotNil(SnapshotStore.reloadCoverage[item], "\(item): add its store to SnapshotStore.reloadStores() and reloadCoverage")
        }
    }

    /// r7 R7A-11: settings round-trip through a full backup; device state stays out.
    func testPrefsRoundTrip() throws {
        let name = "r7.prefs.\(UUID().uuidString)"
        let g = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { g.removePersistentDomain(forName: name) }
        g.set(true, forKey: "liveActivity.enabled")
        g.set(Data([1, 2]), forKey: "onDemandSettings")
        g.set("x", forKey: "home.groups.order")
        g.set("bookmark", forKey: "sync.folderBookmark")
        g.set("g", forKey: AppShared.rememberedGroupKey)
        let prefs = BackupManager.collectPrefs(group: g, groupName: name, standard: UserDefaults(suiteName: name + ".s")!)
        XCTAssertNotNil(prefs["g:liveActivity.enabled"])
        XCTAssertNotNil(prefs["g:home.groups.order"])
        XCTAssertNil(prefs["g:sync.folderBookmark"])
        XCTAssertNil(prefs["g:" + AppShared.rememberedGroupKey])
        let name2 = name + ".restore"
        let r = try XCTUnwrap(UserDefaults(suiteName: name2))
        defer { r.removePersistentDomain(forName: name2) }
        BackupManager.applyPrefs(prefs, group: r, standard: r)
        XCTAssertTrue(r.bool(forKey: "liveActivity.enabled"))
        XCTAssertEqual(r.data(forKey: "onDemandSettings"), Data([1, 2]))
        XCTAssertEqual(r.string(forKey: "home.groups.order"), "x")
    }

    func testNodeSubStoreReloadsAfterTheFileChanges() throws {
        let url = NodeSubStore.url
        let backup = try? Data(contentsOf: url)
        defer {
            if let backup { try? backup.write(to: url) } else { try? FileManager.default.removeItem(at: url) }
            NodeSubStore.shared.load()
        }
        let restored = #"[{"id":"r7-restored","name":"Restored","url":"https://example.com/sub","enabled":true,"userAgent":"clash.meta","updateIntervalHours":0}]"#
        try Data(restored.utf8).write(to: url)
        NodeSubStore.shared.load()
        XCTAssertEqual(NodeSubStore.shared.subs.map(\.id), ["r7-restored"])
        try? FileManager.default.removeItem(at: url)
        NodeSubStore.shared.load()
        XCTAssertTrue(NodeSubStore.shared.subs.isEmpty, "a restored state without the file has no node subscriptions")
    }
}
