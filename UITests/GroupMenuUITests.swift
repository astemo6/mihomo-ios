import XCTest

/// hotfix/group-longpress (device 2026-10-21 「长按策略组无法编辑，之前是可以的」): a long-press anywhere on a policy
/// group header opens its menu with 编辑策略组, offline (来自配置文件) in 规则 and in 全局 mode. The header is also the
/// direct-reorder drag source (test31 keeps checking that drag).
extension TernUITests {

    // MARK: 57. 策略: long-press a group header → 编辑策略组 / 更换图标 menu

    /// Long-presses the card title and returns the menu's 编辑策略组 item (the header's own pencil button has the
    /// same label, so the menu item is the wide one).
    private func openGroupMenu(_ name: String, _ ctx: String) -> XCUIElement? {
        let title = app.element(id: "policy.card." + name)
        guard scrollTo(title) else { XCTFail("\(ctx): card \(name)"); return nil }
        title.press(forDuration: 1.2)
        XCTAssertTrue(app.button(L("更换图标")).waitForExistence(timeout: 4), "\(ctx): long-press on \(name) shows the group menu")
        let edits = app.buttons.matching(NSPredicate(format: "label == %@", L("编辑策略组")))
        let deadline = Date().addingTimeInterval(4)
        while Date() < deadline {
            if let item = edits.allElementsBoundByIndex.filter({ $0.exists && $0.frame.width > 120 }).first { return item }
            usleep(250_000)
        }
        XCTFail("\(ctx): 编辑策略组 item in the menu of \(name)")
        return nil
    }

    private func editFromMenu(_ name: String, _ ctx: String) {
        guard let item = openGroupMenu(name, ctx) else { return }
        snap("grpmenu-\(ctx)")
        item.tap()
        XCTAssertTrue(app.navigationBars[L("编辑策略组")].waitForExistence(timeout: 8), "\(ctx): 编辑策略组 opens the editor for \(name)")
        XCTAssertTrue(tapIfExists(app.button(L("取消")), timeout: 4), "\(ctx): 取消 closes the editor")
        for _ in 0..<20 where app.navigationBars[L("编辑策略组")].exists { usleep(250_000) }
    }

    func test57_GroupLongPressMenu() {
        launch()
        tab(1)
        XCTAssertTrue(app.element(id: "policy.card.Proxy").waitForExistence(timeout: 10), "policy cards")
        XCTAssertTrue(app.element(labelContains: L("未连接")).exists, "offline list (未连接)")
        let mode = app.element(id: "policy.mode")
        XCTAssertTrue(scrollTo(mode), "mode picker")
        func seg(_ k: String) -> XCUIElement { app.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch }

        // 规则: a draggable file group (direct reorder source) still gets the menu.
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "规则")
        usleep(600_000)
        editFromMenu("Proxy", "rule")

        // 全局: GLOBAL plus its group chain; every card shown keeps the menu.
        XCTAssertTrue(scrollTo(mode), "mode picker again")
        XCTAssertTrue(tapIfExists(seg("全局"), timeout: 4), "全局")
        XCTAssertTrue(app.element(id: "policy.card.GLOBAL").waitForExistence(timeout: 6), "全局: GLOBAL card")
        editFromMenu("GLOBAL", "global")
        let cards = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'policy.card.' AND identifier != 'policy.card.GLOBAL'"))
        if let other = cards.allElementsBoundByIndex.first(where: { $0.exists }) {
            editFromMenu(String(other.identifier.dropFirst("policy.card.".count)), "global-chain")
        } else {
            warnings.append("全局: no group besides GLOBAL shown")
        }

        XCTAssertTrue(scrollTo(mode), "mode picker, back")
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "back to 规则")
        assertAlive("group long-press menu")
    }
}
