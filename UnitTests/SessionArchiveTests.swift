import XCTest

/// feat/session-records: the session archive behind whole-connection retention of
/// closed connections (NCStatsRecorder) and DNS queries (NativeLogRing).
final class SessionArchiveTests: XCTestCase {
    private var dir: URL!
    private var file: URL!

    override func setUp() {
        super.setUp()
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("archive-\(UUID().uuidString)")
        file = dir.appendingPathComponent("session.jsonl")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
        super.tearDown()
    }

    private func rec(_ seq: Int64, _ v: String = "") -> [String: Any] { ["seq": seq, "v": v] }

    func testAppendAndReadNewestFirst() {
        let a = NCSessionArchive(url: file)
        for i in 1...5 { a.append(rec(Int64(i), "r\(i)")) }
        XCTAssertEqual(a.count, 5)
        XCTAssertEqual(a.newestSeq, 5)
        let page = a.read(afterSeq: 0, limit: 100)
        XCTAssertEqual(page.map { ($0["seq"] as? NSNumber)?.int64Value }, [5, 4, 3, 2, 1])
        XCTAssertEqual(page.first?["v"] as? String, "r5")
    }

    func testReadAfterSeqPages() {
        let a = NCSessionArchive(url: file)
        for i in 1...10 { a.append(rec(Int64(i))) }
        XCTAssertEqual(a.read(afterSeq: 8, limit: 100).map { ($0["seq"] as? NSNumber)?.int64Value }, [10, 9])
        XCTAssertEqual(a.read(afterSeq: 0, limit: 3).map { ($0["seq"] as? NSNumber)?.int64Value }, [10, 9, 8])
        XCTAssertTrue(a.read(afterSeq: 10, limit: 100).isEmpty)
    }

    func testReadAllOldestFirst() {
        let a = NCSessionArchive(url: file)
        for i in 1...3 { a.append(rec(Int64(i))) }
        XCTAssertEqual(a.readAll().map { ($0["seq"] as? NSNumber)?.int64Value }, [1, 2, 3])
    }

    func testResetTruncates() {
        let a = NCSessionArchive(url: file)
        for i in 1...4 { a.append(rec(Int64(i))) }
        a.reset()
        XCTAssertEqual(a.count, 0)
        XCTAssertEqual(a.newestSeq, 0)
        XCTAssertTrue(a.read(afterSeq: 0, limit: 10).isEmpty)
        a.append(rec(1, "new session"))
        XCTAssertEqual(a.read(afterSeq: 0, limit: 10).first?["v"] as? String, "new session")
    }

    func testReinitStartsFreshSession() {
        var a: NCSessionArchive? = NCSessionArchive(url: file)
        a?.append(rec(7))
        a = nil
        let b = NCSessionArchive(url: file) // a new session truncates the previous file
        XCTAssertEqual(b.count, 0)
    }
}
