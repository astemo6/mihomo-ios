import XCTest

/// fb-subs-global device feedback (offline, simulator): 节点与订阅 is one page, and a config subscription has the
/// same swipes as a node subscription (right 更新, left 删除 / 停用) plus 停用 that keeps it from becoming active.
extension MihomoUITests {

    // MARK: 56. 节点与订阅: a config subscription switched off (unified rows: the switch is its 停用 flag) cannot become
    // the current profile; swipes / menu are covered by test72.

    func test56_ProfileSubscriptionSwipe() {
        launch(["-UITestRemoteProfile"])
        tab(4)
        XCTAssertFalse(app.element(id: "more.订阅管理").exists, "no separate 订阅管理 row")
        openMore("节点与订阅")
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 8), "merged page")
        XCTAssertTrue(app.element(id: "nodesub.row.Demo Sub").waitForExistence(timeout: 8), "node subscription on the merged page")
        let row = app.element(id: "subs.profile.UITest Remote")
        XCTAssertTrue(scrollTo(row), "config subscription row")
        let sw = app.element(id: "subs.profile.UITest Remote.toggle")
        toggleSwitch(sw)
        XCTAssertTrue(app.element(labelContains: L("已关闭")).waitForExistence(timeout: 6), "row shows 已关闭")
        snap("fb-subs-profile-disabled")
        row.tap()
        let activate = app.element(id: "sub.sheet.activate")
        XCTAssertTrue(activate.waitForExistence(timeout: 6), "设为当前配置 in the sheet")
        XCTAssertFalse(activate.isEnabled, "a switched-off subscription cannot become the current profile")
        XCTAssertTrue(tapIfExists(app.element(id: "sub.sheet.close"), timeout: 3))
        usleep(600_000)
        toggleSwitch(sw)
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: L("已关闭")))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 6), .completed, "enabled again")
        assertAlive("config subscription switch")
    }
}
