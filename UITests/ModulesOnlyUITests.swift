import XCTest

/// fix/modules-only (user device report 2026-10-22): 工具 → 模块 lists modules only. No 全部 / 模块 / 规则集 / 脚本
/// filter and no script-file / rule-set rows (the seeded module's remote script used to be a 「uitest-panel.js」 row);
/// the header counts modules; a module row swipes left to 删除 (asks first).
extension MihomoUITests {

    // MARK: 71. 模块: modules only + left-swipe 删除

    func test71_ModulesOnly() {
        launch()
        openMore("模块与资源")
        XCTAssertTrue(app.navigationBars[L("模块")].waitForExistence(timeout: 6), "模块 page")
        let row = app.element(id: "module.row.UITest Panel Module")
        XCTAssertTrue(scrollTo(row), "seeded module listed")
        XCTAssertEqual(app.segmentedControls.count, 0, "no 全部 / 模块 / 规则集 / 脚本 filter")
        XCTAssertFalse(app.element(labelContains: "uitest-panel.js").exists, "no script-file rows on 模块")
        XCTAssertFalse(app.element(id: "res.update.script.uitest-panel.js").exists)
        let header = app.element(id: "modules.header")
        XCTAssertTrue(header.exists || scrollTo(header, fail: false), "module count header")
        snap("modules-only-list")

        // Left swipe (trailing): 删除, which asks first; cancel keeps the module.
        row.swipeLeft()
        let del = app.button(L("删除"))
        XCTAssertTrue(del.waitForExistence(timeout: 3), "删除 in the trailing swipe of a module")
        snap("modules-only-swipe-delete")
        del.tap()
        XCTAssertTrue(app.element(id: "confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        snap("modules-only-confirm")
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(600_000)
        XCTAssertTrue(row.exists, "cancel keeps the module")

        // Tap opens the module's own page.
        row.tap()
        usleep(900_000)
        assertAlive("module detail")
        snap("modules-only-detail")
        back()
        XCTAssertTrue(app.navigationBars[L("模块")].waitForExistence(timeout: 5), "back on 模块")

        // Confirmed delete removes the row.
        row.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 3))
        XCTAssertTrue(tapIfExists(app.element(id: "confirmDelete"), timeout: 4), "confirm delete")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: row)
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 6), .completed, "module deleted")
        snap("modules-only-deleted")
    }
}
