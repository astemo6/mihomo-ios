import XCTest

/// Review 5 (views lane) paths, offline on the simulator. Same helpers as MihomoUITests.
extension MihomoUITests {

    // MARK: 48. 节点与订阅: deleting a node subscription (long-press → 删除) asks first (same dialog as 节点管理)

    func test48_SubscriptionsDeleteAsks() {
        launch()
        openMore("节点与订阅")
        let row = app.element(labelContains: "Demo Sub")
        XCTAssertTrue(scrollTo(row), "Demo Sub card")
        // #69 (subs split, Loon-like): a node subscription's left swipe is 复制链接 only; 删除 lives in the long-press menu.
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 4), "删除 in the long-press menu")
        XCTAssertTrue(app.element(id: "nodesub.confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        snap("r5-subscriptions-delete-confirm")
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(600_000)
        XCTAssertTrue(app.element(labelContains: "Demo Sub").exists, "cancel keeps the subscription")
        assertAlive("subscriptions delete confirm")
    }
}
