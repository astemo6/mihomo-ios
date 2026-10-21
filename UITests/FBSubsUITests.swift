import XCTest

/// fb-subs-global device feedback (offline, simulator): 节点与订阅 is one page, and a config subscription has the
/// same swipes as a node subscription (right 更新, left 删除 / 停用) plus 停用 that keeps it from becoming active.
extension MihomoUITests {

    // MARK: 56. 节点与订阅: config subscription swipe 停用 / 启用 / 删除

    func test56_ProfileSubscriptionSwipe() {
        launch(["-UITestRemoteProfile"])
        tab(4)
        XCTAssertFalse(app.element(id: "more.订阅管理").exists, "no separate 订阅管理 row")
        openMore("节点与订阅")
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 8), "merged page")
        XCTAssertTrue(app.element(id: "nodesub.row.Demo Sub").waitForExistence(timeout: 8), "node subscription on the merged page")
        let row = app.element(id: "subs.profile.UITest Remote")
        XCTAssertTrue(scrollTo(row), "config subscription row")
        snap("fb-subs-merged")
        // Left swipe (trailing): 停用.
        row.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("停用")), timeout: 3), "停用 in the trailing swipe of a config subscription")
        XCTAssertTrue(app.element(labelContains: L("已停用")).waitForExistence(timeout: 6), "row shows 已停用")
        snap("fb-subs-profile-disabled")
        // A disabled subscription cannot become the active profile.
        row.tap()
        XCTAssertTrue(app.staticTexts[L("该配置已停用，启用后才能设为当前配置")].waitForExistence(timeout: 4), "activation refused")
        XCTAssertTrue(tapIfExists(app.button(L("好")), timeout: 3))
        // 启用 again.
        row.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("启用")), timeout: 3), "启用 after 停用")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: L("已停用")))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 6), .completed, "enabled again")
        // 删除 asks first; cancel keeps the row.
        row.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 3), "删除 in the trailing swipe")
        XCTAssertTrue(app.element(id: "profile.confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(500_000)
        XCTAssertTrue(row.exists, "cancel keeps the subscription")
        // Right swipe (leading): 更新.
        row.swipeRight()
        XCTAssertTrue(app.button(L("更新")).waitForExistence(timeout: 3), "更新 in the leading swipe")
        snap("fb-subs-profile-update-swipe")
        assertAlive("config subscription swipe")
    }
}
