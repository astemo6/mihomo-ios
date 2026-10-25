import XCTest
import Darwin
@testable import Mihomo

/// fix/nc-storage-other: 存储空间 accounting (allocated bytes, symlinks, hard links, exact 其他) and leftover cleanup.
final class StorageScanTests: XCTestCase {
    private var root: URL!
    private let fm = FileManager.default

    override func setUp() {
        root = fm.temporaryDirectory.appendingPathComponent("storagescan-\(UUID().uuidString)", isDirectory: true)
        try? fm.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDown() { try? fm.removeItem(at: root) }

    @discardableResult
    private func put(_ rel: String, _ bytes: Int, age: TimeInterval = 0) -> URL {
        let u = root.appendingPathComponent(rel)
        try? fm.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(repeating: 0x61, count: bytes).write(to: u)
        if age > 0 { try? fm.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -age)], ofItemAtPath: u.path) }
        return u
    }

    func testClassify() {
        XCTAssertEqual(StorageScan.classify("profiles/a.yaml"), .profiles)
        XCTAssertEqual(StorageScan.classify("nodesubs/x.yaml"), .profiles)
        XCTAssertEqual(StorageScan.classify("mihomo/nodesubs/x.yaml"), .profiles)
        XCTAssertEqual(StorageScan.classify("mihomo/ruleset/a.yaml"), .providers)
        XCTAssertEqual(StorageScan.classify("mihomo/proxies/sub/b.yaml"), .providers)
        XCTAssertEqual(StorageScan.classify("mihomo/geoip.metadb"), .geo)
        XCTAssertEqual(StorageScan.classify("mihomo/GeoSite.dat"), .geo)
        XCTAssertEqual(StorageScan.classify("mihomo/nativecore-geosite/cn.list"), .other)
        XCTAssertEqual(StorageScan.classify("snapshots/1.json"), .snapshots)
        XCTAssertEqual(StorageScan.classify("icon-cache/a.png"), .icons)
        XCTAssertEqual(StorageScan.classify("startup-log.txt"), .logs)
        XCTAssertEqual(StorageScan.classify("mihomo/diag/core-log.txt"), .logs)
        XCTAssertEqual(StorageScan.classify("traffic-history.json"), .stats)
        XCTAssertEqual(StorageScan.classify("mihomo/probe-results.json"), .stats)
        XCTAssertEqual(StorageScan.classify("mitm-requests.jsonl"), .other)
        XCTAssertEqual(StorageScan.classify("mihomo/engine/store.json"), .other)
        XCTAssertEqual(StorageScan.classify("profiles.json"), .other)
    }

    func testLeftoverRules() {
        let old = StorageScan.orphanAge + 1
        XCTAssertTrue(StorageScan.isLeftover("mihomo/.nativecore-stage-ABC/runtime.yaml", age: old))
        XCTAssertFalse(StorageScan.isLeftover("mihomo/.nativecore-stage-ABC/runtime.yaml", age: 5), "a prepare may be running")
        XCTAssertTrue(StorageScan.isLeftover("mihomo/.runtime.yaml.tmp1234-5678", age: old))
        XCTAssertTrue(StorageScan.isLeftover("mihomo/engine/.store.json.nosync1a2b", age: old))
        XCTAssertTrue(StorageScan.isLeftover("mihomo/GeoSite.dat.download", age: old))
        XCTAssertTrue(StorageScan.isLeftover("mihomo/cache.db", age: 0))
        XCTAssertTrue(StorageScan.isLeftover("mihomo/ui/index.html", age: 0))
        XCTAssertTrue(StorageScan.isLeftover("Library/Caches/x", age: 0))
        XCTAssertFalse(StorageScan.isLeftover("mihomo/engine/store.json", age: old))
        XCTAssertFalse(StorageScan.isLeftover("mihomo/engine/ca/ca.key", age: old))
        XCTAssertFalse(StorageScan.isLeftover("mitm-requests.jsonl", age: old))
        XCTAssertEqual(StorageScan.leftoverRoot("mihomo/.nativecore-stage-ABC/.old/0"), "mihomo/.nativecore-stage-ABC")
        XCTAssertEqual(StorageScan.leftoverRoot("mihomo/ui/a/b.js"), "mihomo/ui")
        XCTAssertEqual(StorageScan.leftoverRoot("mihomo/cache.db"), "mihomo/cache.db")
        XCTAssertFalse(StorageScan.isAutoSweepable("mihomo/cache.db", age: old), "Go-era files only via the button")
        XCTAssertTrue(StorageScan.isAutoSweepable("mihomo/.nativecore-stage-ABC/x", age: old))
    }

    func testHardLinkCountedOnceAndSymlinkSkipped() throws {
        let a = put("mihomo/a.bin", 64 * 1024)
        let w1 = StorageScan.Walker().size(root)
        XCTAssertGreaterThan(w1, 0)
        try fm.createDirectory(at: root.appendingPathComponent("mihomo/.nativecore-stage-X/.old"), withIntermediateDirectories: true)
        XCTAssertEqual(link(a.path, root.appendingPathComponent("mihomo/.nativecore-stage-X/.old/0").path), 0)
        XCTAssertEqual(StorageScan.Walker().size(root), w1, "a hard link is the same blocks")

        // A symlink to a directory outside the root (and a loop back to the root) adds nothing.
        let outside = fm.temporaryDirectory.appendingPathComponent("storagescan-out-\(UUID().uuidString)")
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: outside) }
        try Data(repeating: 1, count: 256 * 1024).write(to: outside.appendingPathComponent("big"))
        try fm.createSymbolicLink(at: root.appendingPathComponent("mihomo/out"), withDestinationURL: outside)
        try fm.createSymbolicLink(at: root.appendingPathComponent("mihomo/loop"), withDestinationURL: root)
        XCTAssertEqual(StorageScan.Walker().size(root), w1)
    }

    func testSparseFileCountsAllocatedBytes() throws {
        let u = root.appendingPathComponent("sparse.bin")
        XCTAssertTrue(fm.createFile(atPath: u.path, contents: nil))
        let h = try FileHandle(forWritingTo: u)
        try h.seek(toOffset: 1 << 30)
        try h.write(contentsOf: Data([1]))
        try h.close()
        let logical = (try fm.attributesOfItem(atPath: u.path)[.size] as? NSNumber)?.int64Value ?? 0
        XCTAssertGreaterThan(logical, 1 << 30)
        // APFS / HFS+ both keep the hole unallocated; the page must not report a gigabyte.
        XCTAssertLessThan(StorageScan.Walker().size(root), 16 << 20)
    }

    func testScanOtherIsExactSumAndTopPathsDrillDown() {
        put("profiles/p.yaml", 4096)
        put("mihomo/geoip.metadb", 8192)
        put("mihomo/ruleset/r.yaml", 4096)
        put("mihomo/engine/store.json", 4096)
        put("mihomo/engine/cache/aa", 200 * 1024)
        put("mihomo/engine/cache/bb", 100 * 1024)
        put("mihomo/.nativecore-stage-OLD/runtime.yaml", 50 * 1024, age: 3600)
        put("mitm-requests.jsonl", 4096)
        let s = StorageScan.scan(container: root, tmp: nil)
        let sum = StorageScan.Kind.allCases.reduce(Int64(0)) { $0 + (s.bytes[$1] ?? 0) }
        XCTAssertEqual(sum, s.containerBytes, "every file is in exactly one category")
        XCTAssertEqual(s.other.reduce(Int64(0)) { $0 + $1.bytes }, s.bytes[.other] ?? 0)
        XCTAssertEqual(s.providerFiles.count, 1)
        XCTAssertEqual(s.leftovers.map(\.rel), ["mihomo/.nativecore-stage-OLD/runtime.yaml"])

        let top = StorageScan.topPaths(s.other)
        XCTAssertLessThanOrEqual(top.count, 5)
        // "mihomo" holds nearly everything → opened, then "mihomo/engine", then its cache (still over half).
        XCTAssertEqual(top.first?.path, "mihomo/engine/cache/aa")
        XCTAssertEqual(top.first?.isDirectory, false)
        XCTAssertFalse(top.first?.clearable ?? true)
        XCTAssertTrue(top.contains { $0.path == "mihomo/.nativecore-stage-OLD" && $0.isDirectory && $0.clearable })
        XCTAssertFalse(top.contains { $0.path == "mihomo" }, "the runaway parent is replaced by its children")
        XCTAssertEqual(top.map(\.bytes), top.map(\.bytes).sorted(by: >))
    }

    func testRemoveLeftovers() {
        put("mihomo/.nativecore-stage-OLD/runtime.yaml", 1024, age: 3600)
        put("mihomo/.nativecore-stage-NEW/runtime.yaml", 1024)
        put("mihomo/.groups.json.tmpAAAA", 1024, age: 3600)
        put("mihomo/cache.db", 1024)
        put("mihomo/engine/store.json", 1024, age: 3600)
        put("mihomo/ruleset/.x.tmp1", 1024, age: 3600) // a provider-category file is never touched here

        StorageScan.removeLeftovers(container: root, autoOnly: true)
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("mihomo/.nativecore-stage-OLD").path))
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("mihomo/.nativecore-stage-NEW/runtime.yaml").path))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("mihomo/.groups.json.tmpAAAA").path))
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("mihomo/cache.db").path), "auto sweep keeps Go-era files")
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("mihomo/engine/store.json").path))
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("mihomo/ruleset/.x.tmp1").path))

        StorageScan.removeLeftovers(container: root, under: "mihomo/cache.db")
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("mihomo/cache.db").path))
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("mihomo/engine/store.json").path))
    }

    func testRequestLogLineCap() {
        var e = NativeRequestLogEntry(id: 1, time: 0, method: "GET", url: "https://a.example/", host: "a.example")
        e.respBody = String(repeating: "x", count: NativeRequestLogFile.lineMax * 2)
        let big = (try? JSONEncoder().encode(e))?.count ?? 0
        XCTAssertGreaterThan(big, NativeRequestLogFile.lineMax)
        let small = (try? JSONEncoder().encode(e.summary))?.count ?? .max
        XCTAssertLessThanOrEqual(small, NativeRequestLogFile.lineMax)
    }
}
