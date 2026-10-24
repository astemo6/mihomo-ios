import XCTest

/// Lane D (UI & copy): one name for the node list the user edits (「本地节点」, the 节点与订阅 row that opens it), 高级设置's
/// subtitle names 隧道 (高级设置 → 网络 → 隧道), and a panel 刷新 that fails says why instead of only stopping the spinner.
extension MihomoUITests {

    // MARK: 92. Lane D copy + panel refresh failure

    func test92_LaneDCopyAndPanelRefreshError() {
        // 1. Panel refresh failure: demo panels, but 刷新 sends the real request. No engine runs in UI tests, so the
        //    controller request fails and the card shows that failure's own text.
        launch(["-UITestDemoPanels", "-UITestPanelRefreshLive", "-UITestScreen", "panels"])
        let title = app.staticTexts.matching(NSPredicate(format: "label == %@", "Demo Script Panel")).firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 8), "demo panels")
        XCTAssertFalse(app.element(id: "panel.refreshError").exists, "no failure before a refresh")
        let refresh = app.element(id: "panel.refresh")
        XCTAssertTrue(refresh.waitForExistence(timeout: 4), "刷新 button on the script panel")
        refresh.tap()
        let failure = app.element(id: "panel.refreshError")
        XCTAssertTrue(failure.waitForExistence(timeout: 20), "refresh failure shown on the card")
        let prefix = L("刷新失败：%@").components(separatedBy: "%@").first ?? ""
        XCTAssertTrue(failure.label.hasPrefix(prefix), "failure text: \(failure.label)")
        XCTAssertGreaterThan(failure.label.count, prefix.count, "failure carries a reason: \(failure.label)")
        XCTAssertTrue(title.exists, "the panel's content stays")
        snap("laned-panel-refresh-error")
        app.terminate()

        // 2. 高级设置 row subtitle names 隧道.
        launch()
        tab(4)
        let adv = app.element(id: "more.高级设置")
        XCTAssertTrue(scrollTo(adv), "高级设置 row")
        XCTAssertTrue(adv.label.contains(L("连接方式 · 隧道 · 内核 · 测速")), "高级设置 subtitle: \(adv.label)")
        adv.tap()
        XCTAssertTrue(scrollTo(app.element(id: "more.隧道")), "高级设置 → 隧道")
        back()

        // 3. 本地节点: the 节点与订阅 row, the page it opens, and the node source all use one name.
        let old = Env.isEnglish ? "Manual Nodes" : "手动节点"
        let oldLower = Env.isEnglish ? "manual node" : "手动节点"
        tab(3)
        let nodes = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(nodes), "节点与订阅 card")
        nodes.tap()
        let localRow = app.staticTexts.matching(NSPredicate(format: "label == %@", L("本地节点"))).firstMatch
        XCTAssertTrue(scrollTo(localRow), "本地节点 row")
        snap("laned-nodes-local-row")
        let tree = app.debugDescription
        XCTAssertFalse(tree.contains(old) || tree.contains(oldLower), "节点与订阅 still says \(old)")
        localRow.tap()
        XCTAssertTrue(app.navigationBars[L("本地节点")].waitForExistence(timeout: 6), "page title = the row that opens it")
        usleep(800_000)
        snap("laned-local-nodes")
        let page = app.debugDescription
        XCTAssertFalse(page.contains(old) || page.contains(oldLower), "本地节点 page still says \(old)")
        back()
        back()

        // The built-in profile keeps its stored name but is shown with the same term.
        openProfiles()
        usleep(600_000)
        XCTAssertFalse(app.debugDescription.contains(old), "配置 still lists \(old)")
        snap("laned-profiles")
    }
}
