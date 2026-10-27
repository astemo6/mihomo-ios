import XCTest

/// hotfix/home-isp (device 2026-10-21 「首页最上方也显示运营商信息的 比如xtom」, then 「做成可选的，供选择」): the Home
/// header's small line shows 运营商 · ASN · IP by default; 更多 → 高级设置 → 出口信息来源 → 首页副标题显示 picks the items
/// and Home follows live. Demo exit info: Example Net · AS64500 · 203.0.113.45 (no time zone).
extension TernUITests {

    // MARK: 62. 首页副标题显示

    func test50_HomeExitSubtitle() {
        launch(["-UITestDemoExitIP"])
        let full = app.element(labelContains: "Example Net · AS64500 · 203.0.113.45")
        XCTAssertTrue(full.waitForExistence(timeout: 8), "Home header shows 运营商 · ASN · IP by default")
        snap("exit-subtitle-default")

        openMore("出口信息查询")
        let isp = app.switches.matching(identifier: "geo.detail.isp").firstMatch
        XCTAssertTrue(scrollTo(isp), "运营商 toggle")
        XCTAssertEqual(switchValue(isp), "1", "运营商 on by default")
        for id in ["asn", "ip"] {
            XCTAssertEqual(switchValue(app.switches.matching(identifier: "geo.detail." + id).firstMatch), "1", "\(id) on by default")
        }
        XCTAssertEqual(switchValue(app.switches.matching(identifier: "geo.detail.timezone").firstMatch), "0", "时区 off by default")
        let preview = app.element(id: "geo.detail.preview")
        XCTAssertTrue(scrollTo(preview), "preview row")
        XCTAssertEqual(preview.label, "Example Net · AS64500 · 203.0.113.45", "preview = default line")

        flip(isp, to: "0")
        XCTAssertEqual(switchValue(isp), "0", "运营商 off")
        XCTAssertEqual(app.element(id: "geo.detail.preview").label, "AS64500 · 203.0.113.45", "preview follows the toggle")
        snap("exit-subtitle-settings")

        back()
        tab(0)
        let short = app.element(labelContains: "AS64500 · 203.0.113.45")
        XCTAssertTrue(short.waitForExistence(timeout: 6), "Home follows the choice")
        XCTAssertFalse(app.element(labelContains: "Example Net").exists, "运营商 hidden on Home")
        snap("exit-subtitle-home-no-isp")

        // Back to the default so the choice does not leak into later screenshots (the seed resets it anyway).
        openMore("出口信息查询")
        let isp2 = app.switches.matching(identifier: "geo.detail.isp").firstMatch
        XCTAssertTrue(scrollTo(isp2))
        flip(isp2, to: "1")
        back()
        tab(0)
        XCTAssertTrue(app.element(labelContains: "Example Net · AS64500 · 203.0.113.45").waitForExistence(timeout: 6), "default line again")
        assertAlive("exit subtitle")
    }

    /// fix/nc-combine-2: the coordinate tap on the switch occasionally lands while the Form is still settling after
    /// scrollTo and is dropped (gate 3b en, combine-2 zh full; the same sha passed alone and in en). The view code
    /// is unchanged since 8a590e4, so tap once more only when the value did not change — the assertions after it
    /// still check the stored value, the preview and Home.
    private func flip(_ sw: XCUIElement, to value: String) {
        toggleSwitch(sw)
        usleep(400_000)
        if switchValue(sw) != value {
            usleep(600_000)
            if switchValue(sw) != value { toggleSwitch(sw); usleep(600_000) }
        }
    }
}
