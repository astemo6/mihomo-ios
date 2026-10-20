import XCTest

/// Review 5 (views lane) paths, offline on the simulator. Same helpers as MihomoUITests.
extension MihomoUITests {

    // MARK: 48. 订阅管理: deleting a node subscription asks first (same dialog as 节点管理)

    func test48_SubscriptionsDeleteAsks() {
        launch()
        openMore("订阅管理")
        let row = app.element(labelContains: "Demo Sub")
        XCTAssertTrue(scrollTo(row), "Demo Sub card")
        row.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 3), "删除 in the trailing swipe")
        XCTAssertTrue(app.element(id: "nodesub.confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        snap("r5-subscriptions-delete-confirm")
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(600_000)
        XCTAssertTrue(app.element(labelContains: "Demo Sub").exists, "cancel keeps the subscription")
        assertAlive("subscriptions delete confirm")
    }
}
