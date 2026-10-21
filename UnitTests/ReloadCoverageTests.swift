import XCTest
@testable import Mihomo

/// r7 (review7 R7A-1): every file a backup / snapshot / sync restore writes must have a reload path. A store that
/// caches one of them in memory and writes its whole list back would otherwise undo the restore on its next save.
@MainActor
final class ReloadCoverageTests: XCTestCase {
    func testEveryBackupItemHasAReloadPath() {
        for item in BackupManager.items(includeCA: true) {
            XCTAssertNotNil(SnapshotStore.reloadCoverage[item], "\(item): add its store to SnapshotStore.reloadStores() and reloadCoverage")
        }
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
