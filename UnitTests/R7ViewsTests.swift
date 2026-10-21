import XCTest
@testable import Mihomo

/// Review 7 views lane: Home chain display (P3-5) and the masked links on 更新资源 (P3-6).
@MainActor
final class R7ViewsTests: XCTestCase {

    func testHomeChainFlagsTheFinalNode() {
        // 「Tokyo 01」 matches the JP region pattern of 筛选节点; the group hop stays as it is.
        let parts = PolicyChainText.homeParts(["节点选择", "日本节点", "Tokyo 01"], cut: false)
        XCTAssertEqual(parts.count, 2)
        XCTAssertEqual(parts[0], "日本节点")
        XCTAssertEqual(parts[1], NodeFlag.decorate("Tokyo 01"))
        XCTAssertNotEqual(parts[1], "Tokyo 01", "final node gets its region flag like 策略")
    }

    func testHomeChainMarksACut() {
        let parts = PolicyChainText.homeParts(["A", "B", "C", "D", "E", "F"], cut: true)
        XCTAssertEqual(parts, ["B", "C", "D", "E", "…", "F"], "「…」 before the last hop reached")
    }

    func testHomeChainWithoutHops() {
        XCTAssertEqual(PolicyChainText.homeParts(["Proxy"], cut: false), ["—"])
        XCTAssertEqual(PolicyChainText.homeParts(["Proxy", "DIRECT"], cut: false), ["DIRECT"], "built-ins never get a flag")
    }

    func testUpdateResourcesHidesTokens() {
        XCTAssertEqual(ResourceUpdateRow.displayURL("https://sub.example.com/api/v1/client/subscribe?token=abc123"), "sub.example.com/…")
        XCTAssertEqual(ResourceUpdateRow.displayURL("https://example.com:8443/link/SECRETTOKEN"), "example.com:8443/…")
        XCTAssertEqual(ResourceUpdateRow.displayURL("https://example.com/"), "example.com")
        XCTAssertEqual(ResourceUpdateRow.displayURL("https://example.com?token=x"), "example.com/…")
        XCTAssertFalse(ResourceUpdateRow.displayURL("https://h.example/s?token=abc").contains("abc"))
        XCTAssertEqual(ResourceUpdateRow.displayURL("rules/local.list"), "local.list")
    }
}
