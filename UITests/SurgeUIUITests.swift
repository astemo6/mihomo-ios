import XCTest

/// feat/surge-ui (user 「现在的感觉有点专业工具风」): screenshots of the calmer 更多 / 高级设置 / 开始标签页 and the
/// friendly empty states, VPN off (rows that need the tunnel are greyed with 「需开启 VPN」).
extension MihomoUITests {

    // MARK: 57. Surge-inspired 更多 + empty states

    func test49_SurgeUIShots() {
        launch()
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 8), "更多")
        snap("surge-more-1")
        // feat/more-dedup: the tunnel pages are cards on the 工具 tab now.
        tab(3)
        let logs = app.element(id: "more.日志")
        XCTAssertTrue(scrollTo(logs), "运行日志 card")
        XCTAssertTrue(app.element(labelContains: L("需开启 VPN")).exists, "tunnel cards greyed while disconnected")
        snap("surge-more-2-status")
        tab(4)
        let stats = app.element(id: "more.流量统计")
        XCTAssertTrue(scrollTo(stats), "已保存数据")
        snap("surge-more-3-tools")
        let launchRow = app.element(id: "more.开始标签页")
        XCTAssertTrue(scrollTo(launchRow), "开始标签页 row")
        snap("surge-more-4-appearance")
        for _ in 0..<4 { app.swipeUp(velocity: .slow) }
        snap("surge-more-5-bottom")

        // 开始标签页 picker (not changed: the next tests expect 首页 at launch; data is wiped per launch anyway).
        XCTAssertTrue(scrollTo(launchRow))
        launchRow.tap()
        XCTAssertTrue(app.element(id: "launchTab.0").waitForExistence(timeout: 5), "launch tab list")
        snap("surge-launchtab")
        back()

        // 外观
        openMore("外观")
        snap("surge-appearance")
        back()

        // 高级设置
        openMore("高级设置")
        XCTAssertTrue(app.navigationBars[L("高级设置")].waitForExistence(timeout: 5), "高级设置 page")
        snap("surge-advanced-1")
        app.swipeUp(velocity: .slow)
        snap("surge-advanced-2")
        back()

        // A tunnel page while disconnected: friendly empty state with 连接.
        openMore("连接分析")
        XCTAssertTrue(app.element(id: "empty.connect").waitForExistence(timeout: 5), "连接 action on the empty state")
        snap("surge-empty-analytics")
        back()

        tab(0)
        snap("surge-home")
        tab(1)
        snap("surge-policy")

        // First run without any profile: Home card + 策略 empty state lead to 配置.
        app.terminate()
        launch(["-UITestNoProfile"])
        XCTAssertTrue(app.element(id: "home.addProfile").waitForExistence(timeout: 8), "Home 添加配置")
        snap("surge-home-empty")
        tab(1)
        let go = app.element(id: "policy.emptyAction")
        XCTAssertTrue(go.waitForExistence(timeout: 6), "策略 empty action")
        snap("surge-policy-empty")
        go.tap()
        usleep(800_000)
        XCTAssertTrue(app.tabBars.buttons.element(boundBy: 4).isSelected, "前往配置 opens 更多")
        XCTAssertTrue(app.navigationBars[L("配置")].waitForExistence(timeout: 5), "前往配置 pushes 更多 → 配置")
    }
}
