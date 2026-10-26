import XCTest
@testable import Tern

/// feat/native-core-eval: $persistentStore in the native-only tunnel.
final class NativeCorePersistentStoreTests: XCTestCase {
    private var dir: URL!
    private var file: URL { dir.appendingPathComponent("engine/store.json") }

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ncstore-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir.appendingPathComponent("engine"), withIntermediateDirectories: true)
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    private func fileMap() -> [String: String] {
        guard let d = try? Data(contentsOf: file) else { return [:] }
        return (try? JSONSerialization.jsonObject(with: d)) as? [String: String] ?? [:]
    }

    private func appWrites(_ m: [String: String]) throws {
        // a later modification date than anything the store saw (HFS+/APFS dates are fine-grained, but be sure)
        try JSONSerialization.data(withJSONObject: m).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(5)], ofItemAtPath: file.path)
    }

    func testReadsTheAppsFile() throws {
        try appWrites(["boxjs": "1"])
        let s = NCPersistentStore(fileURL: file)
        XCTAssertEqual(s.read(key: "boxjs"), "1")
        try appWrites(["boxjs": "2", "new": "x"])
        XCTAssertEqual(s.read(key: "boxjs"), "2", "an app edit is seen by the next read")
        XCTAssertEqual(s.read(key: "new"), "x")
    }

    func testWriteDoesNotClobberAppEdits() throws {
        try appWrites(["a": "1", "b": "1"])
        let s = NCPersistentStore(fileURL: file)
        XCTAssertEqual(s.read(key: "a"), "1")
        s.write(key: "mine", value: "v")
        try appWrites(["a": "app", "b": "1", "appkey": "y"]) // the app edits before our flush
        s.flush()
        let m = fileMap()
        XCTAssertEqual(m["mine"], "v")
        XCTAssertEqual(m["a"], "app")
        XCTAssertEqual(m["appkey"], "y")
        s.delete(key: "b")
        s.flush()
        XCTAssertNil(fileMap()["b"])
        XCTAssertEqual(fileMap()["a"], "app")
    }

    func testUnreadableFileIsKeptAside() throws {
        try Data("{not json".utf8).write(to: file)
        let s = NCPersistentStore(fileURL: file)
        XCTAssertNil(s.read(key: "x"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path + ".bad"))
        s.write(key: "x", value: "1")
        s.flush()
        XCTAssertEqual(fileMap(), ["x": "1"])
        XCTAssertEqual(try String(contentsOf: URL(fileURLWithPath: file.path + ".bad")), "{not json")
    }

    func testCoalescedFlush() throws {
        NCPersistentStore.flushDelay = 0.05
        defer { NCPersistentStore.flushDelay = 0.25 }
        let s = NCPersistentStore(fileURL: file)
        for i in 0..<50 { s.write(key: "k\(i)", value: "\(i)") }
        let exp = expectation(description: "flushed")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { exp.fulfill() }
        wait(for: [exp], timeout: 3)
        XCTAssertEqual(fileMap().count, 50)
    }
}
