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
        var o = CoreOverrides()
        o.testURL = "https://www.gstatic.com/generate_204"
        o.save()
    }

    override func tearDown() {
        CoreOverrides.testStoreDir = nil
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
}
