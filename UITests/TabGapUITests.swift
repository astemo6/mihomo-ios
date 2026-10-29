import XCTest

/// fix/tab-top-gap (user 2026-10-29): on 请求 and 更多 the gap between the search drawer
/// and the first card is visibly larger than on the other tab roots ("上方留白太大了，跟其他
/// 页的不一样"). Baseline/comparison screenshots of the three List roots — 工具 is the
/// reference the user calls normal — measured from the ui-screens artifact.
extension TernUITests {
    func testTabRootGaps() {
        launch(["-UITestDemoAnalytics", "-UITestDemoConnections", "-UITestDemoExitIP"])
        XCTAssertEqual(app.tabBars.buttons.count, 5, "five tabs")
        tab(3) // 工具 — List, no search drawer (reference)
        snap("tabgap-tools")
        tab(2) // 请求 — List + searchable drawer
        snap("tabgap-requests")
        tab(4) // 更多 — List + searchable drawer
        snap("tabgap-more")
    }
}
