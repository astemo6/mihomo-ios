import XCTest

/// feat/more-search: a Settings-app style search field at the top of 更多 (static feature index, grouped results
/// with breadcrumbs, tap → page), and 外观 → 实时活动与灵动岛 as its own row (user couldn't find the switch).
extension TernUITests {

    var moreSearchField: XCUIElement { app.searchFields.firstMatch }

    /// Replaces the search text (the field keeps its text after a push / pop).
    func searchMore(_ text: String, fallback: String? = nil) {
        let f = moreSearchField
        XCTAssertTrue(f.waitForExistence(timeout: 6), "更多 search field")
        f.tap()
        usleep(300_000)
        if let v = f.value as? String, !v.isEmpty, v != f.placeholderValue {
            f.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: v.count + 2))
        }
        f.typeText(text)
        usleep(700_000)
        // CJK input through the simulator keyboard can fail on a runner; the index also matches pinyin.
        if let fb = fallback, let v = f.value as? String, !v.contains(text) {
            f.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: v.count + 2) + fb)
            usleep(700_000)
        }
    }

    func cancelMoreSearch() {
        let cancel = app.buttons[L("取消")].exists ? app.buttons[L("取消")] : app.buttons["Cancel"]
        if cancel.exists { cancel.tap() }
        usleep(500_000)
    }

    // MARK: 76. 更多 search: 地理 → 地理数据库, mitm → HTTPS 解密, empty state

    func test76_MoreSearch() {
        launch()
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 6), "更多")
        XCTAssertTrue(moreSearchField.waitForExistence(timeout: 4), "search field always shown at the top")
        snap("more-search-field")

        // 地理 → 地理数据库 (breadcrumb 更多 › 高级设置), tap opens the page.
        searchMore("地理", fallback: "dili")
        let geo = app.element(id: "search.result.geo")
        XCTAssertTrue(geo.waitForExistence(timeout: 6), "地理数据库 result")
        XCTAssertTrue(geo.label.contains(L("高级设置")), "breadcrumb: \(geo.label)")
        snap("more-search-geo")
        geo.tap()
        XCTAssertTrue(app.navigationBars[L("地理数据库")].waitForExistence(timeout: 8), "地理数据库 opens")
        snap("more-search-geo-page")
        assertAlive("search → 地理数据库")
        back()
        // While the search is active the bar hides 「更多」; the field (with its text) is what is back.
        XCTAssertTrue(moreSearchField.waitForExistence(timeout: 6), "back on 更多's search")

        // mitm → HTTPS 解密 (工具 page pushed in 更多's stack).
        searchMore("mitm")
        let mitm = app.element(id: "search.result.mitm")
        XCTAssertTrue(mitm.waitForExistence(timeout: 6), "HTTPS 解密 result")
        XCTAssertTrue(mitm.label.contains(L("HTTPS 解密")), "title: \(mitm.label)")
        XCTAssertTrue(mitm.label.contains(L("工具")), "breadcrumb 工具: \(mitm.label)")
        snap("more-search-mitm")
        mitm.tap()
        XCTAssertTrue(app.navigationBars[L("HTTPS 解密")].waitForExistence(timeout: 8), "HTTPS 解密 page opens")
        snap("more-search-mitm-page")
        assertAlive("search → MitM")
        back()

        // A technical term in several sections: grouped results.
        searchMore("dns")
        XCTAssertTrue(app.element(id: "search.result.dns").waitForExistence(timeout: 6), "DNS")
        XCTAssertTrue(app.element(id: "search.result.dnsLog").exists, "域名解析记录 via keyword")
        snap("more-search-dns")

        // Live Activity is findable by its English / Chinese terms.
        searchMore("live activity")
        let live = app.element(id: "search.result.liveActivity")
        XCTAssertTrue(live.waitForExistence(timeout: 6), "实时活动与灵动岛 result")
        snap("more-search-live")

        // No match → empty state.
        searchMore("zzqqxx")
        XCTAssertTrue(app.element(id: "search.empty").waitForExistence(timeout: 4), "empty state")
        snap("more-search-empty")
        cancelMoreSearch()
        XCTAssertTrue(scrollTo(app.element(id: "more.高级设置")), "normal 更多 list after cancel")
        assertAlive("more search")
    }

    // MARK: 77. 更多 → 外观 → 实时活动与灵动岛 row + page

    func test77_LiveActivityRow() {
        launch()
        tab(4)
        let row = app.element(id: "more.实时活动")
        XCTAssertTrue(scrollTo(row), "实时活动与灵动岛 row in 外观")
        XCTAssertTrue(row.label.contains(L("实时活动与灵动岛")), "title: \(row.label)")
        XCTAssertTrue(row.label.contains(L("关")) || row.label.contains(L("开")), "value 开 / 关: \(row.label)")
        snap("more-live-row")
        row.tap()
        let toggle = app.switches["liveActivity.toggle"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 6), "toggle on its own page")
        snap("live-activity-page")
        back()
        // 深色与浅色 no longer carries the switch.
        openMore("外观")
        usleep(500_000)
        XCTAssertFalse(app.switches["liveActivity.toggle"].exists, "moved out of 深色与浅色")
        back()
        assertAlive("live activity row")
    }
}
