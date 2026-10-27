import XCTest
@testable import Mihomo

/// fix/nc-ui-smooth: main-thread costs behind the 策略 / 首页 / 节点 rows. Every member cell asks for its node's test
/// URL to read the right delay out of the core's per-URL history, on every render (a delay test re-renders the page
/// every ~120 ms). The measure blocks print their averages in the test log ("measured [Clock Monotonic Time, s]").
final class UISmoothTests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        super.setUp()
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ui-smooth-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        CoreOverrides.testStoreDir = dir
        TestSettingsCache.invalidate()
        var o = CoreOverrides()
        o.testURL = "https://www.gstatic.com/generate_204"
        o.save()
    }

    override func tearDown() {
        CoreOverrides.testStoreDir = nil
        TestSettingsCache.invalidate()
        try? FileManager.default.removeItem(at: dir)
        super.tearDown()
    }

    /// 600 member cells of one render (an expanded big group / 节点 list).
    func testPerf_NodeTestURLLookups() {
        let names = (0..<600).map { "Node \($0)" }
        measure(metrics: [XCTClockMetric()]) {
            for n in names { _ = NodeSettingsStore.testURL(for: n) }
        }
    }

    func testPerf_TestSettingsReads() {
        measure(metrics: [XCTClockMetric()]) {
            for _ in 0..<600 { _ = ControllerClient.testSettings }
        }
    }

    // MARK: TestSettingsCache correctness

    /// A save (any process: atomic replace of overrides.json) is seen by the very next read.
    func testCacheFollowsEverySave() {
        XCTAssertEqual(ControllerClient.testSettings.url, "https://www.gstatic.com/generate_204")
        XCTAssertNil(ControllerClient.directTestURL)
        XCTAssertFalse(ControllerClient.tcpHandshake)
        var o = CoreOverrides.load()
        o.testURL = "http://cp.cloudflare.com/generate_204"
        o.testTimeoutMs = 3000
        o.directTestURL = "http://www.apple.com/library/test/success.html"
        o.tcpHandshakeDelay = true
        o.save()
        XCTAssertEqual(ControllerClient.testSettings.url, "http://cp.cloudflare.com/generate_204")
        XCTAssertEqual(ControllerClient.testSettings.timeoutMs, 3000)
        XCTAssertEqual(ControllerClient.directTestURL, "http://www.apple.com/library/test/success.html")
        XCTAssertTrue(ControllerClient.tcpHandshake)
        XCTAssertEqual(NodeSettingsStore.testURL(for: "Some Node"), "http://cp.cloudflare.com/generate_204")
        // Same values as an uncached load, field by field.
        XCTAssertEqual(TestSettingsCache.current, TestSettingsCache.values(CoreOverrides.load()))
        o = CoreOverrides.load()
        o.testURL = "not a url"
        o.save()
        XCTAssertEqual(ControllerClient.testSettings.url, CoreOverrides.defaultTestURL, "invalid URL falls back like before")
    }

    /// A file written behind the app's back (another process, a restore) without going through save().
    func testCacheFollowsExternalRewrite() throws {
        _ = ControllerClient.testSettings
        let file = CoreOverrides.overridesFile
        var obj = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any] ?? [:]
        obj["testURL"] = "http://connectivitycheck.gstatic.com/generate_204"
        try JSONSerialization.data(withJSONObject: obj).write(to: file, options: .atomic)
        XCTAssertEqual(ControllerClient.testSettings.url, "http://connectivitycheck.gstatic.com/generate_204")
    }

    /// The cache is keyed by the file path too (unit tests switch store directories).
    func testCacheFollowsStoreDirectory() {
        _ = ControllerClient.testSettings
        let other = FileManager.default.temporaryDirectory.appendingPathComponent("ui-smooth-b-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: other) }
        CoreOverrides.testStoreDir = other
        var o = CoreOverrides()
        o.testURL = "http://cp.cloudflare.com/generate_204"
        o.save()
        XCTAssertEqual(ControllerClient.testSettings.url, "http://cp.cloudflare.com/generate_204")
        CoreOverrides.testStoreDir = dir
        XCTAssertEqual(ControllerClient.testSettings.url, "https://www.gstatic.com/generate_204")
    }

    // MARK: UIBatcher

    @MainActor
    func testBatcherKeepsOrderAndCoalesces() async throws {
        var flushes: [[Int]] = []
        let b = UIBatcher<Int>(intervalMs: 50) { flushes.append($0) }
        for i in 0..<100 { b.add(i) }
        XCTAssertTrue(flushes.isEmpty, "nothing published synchronously")
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(flushes.count, 1, "100 adds in one window = one publish")
        XCTAssertEqual(flushes.first, Array(0..<100))
        b.add(100); b.drain()
        XCTAssertEqual(flushes.last, [100])
        b.add(101); b.reset()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(flushes.count, 2, "reset drops what was waiting")
    }

    @MainActor
    func testBatcherCap() {
        var got: [Int] = []
        let b = UIBatcher<Int>(intervalMs: 1000, cap: 3) { got = $0 }
        for i in 0..<10 { b.add(i) }
        b.drain()
        XCTAssertEqual(got, [7, 8, 9], "oldest dropped first")
    }
}
