import XCTest

/// feat/subs-split (user 2026-10-21 「将这里的配置订阅与节点订阅拆开」): 节点与订阅 has a 配置订阅 section and a 节点订阅
/// section; a profile's 节点集 (proxy-provider) works like a node subscription (unified rows since fix/modules-only:
/// right 更新, left 删除, long-press 更新 · 编辑 · 复制地址 · 关闭 · 删除) — through the override store.
extension MihomoUITests {

    func header(_ key: String, _ n: Int) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label ==[c] %@", String(format: L(key), n))).firstMatch
    }

    // MARK: 58. 节点与订阅: two sections + 节点集 actions

    func test58_SubsSplitProviderActions() {
        launch(["-UITestRemoteProfile"])
        openMore("节点与订阅")
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 8), "节点与订阅")
        let cfg = header("配置订阅 %lld", 1)
        let nodes = header("节点订阅 %lld", 2)
        XCTAssertTrue(cfg.waitForExistence(timeout: 8), "配置订阅 section with its own count")
        XCTAssertTrue(nodes.waitForExistence(timeout: 8), "节点订阅 section: Demo Sub + the profile's Demo Provider")
        XCTAssertLessThan(cfg.frame.minY, nodes.frame.minY, "配置订阅 first")
        let remote = app.element(id: "subs.profile.UITest Remote")
        let sub = app.element(id: "nodesub.row.Demo Sub")
        let provider = app.element(id: "provider.row.Demo Provider")
        XCTAssertTrue(remote.exists && sub.exists, "rows listed")
        XCTAssertTrue(scrollTo(provider), "节点集 row")
        XCTAssertLessThan(remote.frame.minY, nodes.frame.minY, "config subscription in 配置订阅")
        XCTAssertGreaterThan(provider.frame.minY, nodes.frame.minY, "节点集 in 节点订阅")
        app.swipeDown(velocity: .slow)
        snap("subs-split-sections")

        // Unified rows (fix/modules-only): swipes and the edit sheet are covered by test79; here the 节点集 menu
        // (关闭 / 启用, 编辑 → shared sheet) and the node subscription sheet's 图标 / 查看节点.
        XCTAssertTrue(scrollTo(provider))
        provider.press(forDuration: 1.3)
        for k in ["更新", "编辑", "复制地址", "关闭", "删除"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 4), "menu: \(k)")
        }
        snap("subs-split-provider-menu")
        XCTAssertTrue(tapIfExists(app.button(L("关闭")), timeout: 3), "关闭 from the menu")
        XCTAssertTrue(app.element(labelContains: L("已关闭")).waitForExistence(timeout: 8), "row shows 已关闭")
        XCTAssertTrue(provider.waitForExistence(timeout: 4), "a disabled 节点集 stays listed")
        snap("subs-split-provider-disabled")
        // uiaudit zh-light-3: the second long-press did not open the menu once (row redrawn as 已关闭 / near the tab
        // bar). Bring it clear of the tab bar and retry the press once.
        clearOfTabBar(provider)
        provider.press(forDuration: 1.3)
        if !app.button(L("启用")).waitForExistence(timeout: 3) {
            app.swipeDown(velocity: .slow) // dismiss whatever the press opened, if anything
            clearOfTabBar(provider)
            provider.press(forDuration: 1.5)
        }
        XCTAssertTrue(tapIfExists(app.button(L("启用")), timeout: 4), "启用 from the menu")
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: L("已关闭")))
        XCTAssertEqual(XCTWaiter().wait(for: [enabled], timeout: 8), .completed, "enabled again")

        // 编辑 (tap → shared sheet): display name; a file 节点集 has no 订阅地址.
        XCTAssertTrue(scrollTo(provider))
        provider.tap()
        let name = app.element(id: "sub.sheet.name")
        XCTAssertTrue(name.waitForExistence(timeout: 5), "name field")
        XCTAssertFalse(app.element(id: "sub.sheet.url").exists, "file 节点集: no 订阅地址")
        replaceText(name, "My Provider")
        snap("subs-split-provider-edit")
        XCTAssertTrue(tapIfExists(app.element(id: "sub.sheet.save"), timeout: 4), "保存")
        XCTAssertTrue(app.element(labelContains: "My Provider").waitForExistence(timeout: 8), "display name shown")

        // Node subscription sheet: 图标 opens the shared picker; 查看节点 → 添加到本地节点 (#68).
        XCTAssertTrue(scrollTo(sub))
        sub.tap()
        XCTAssertTrue(tapIfExists(app.button(L("图标")), timeout: 5), "图标 in the sheet")
        let pick = app.element(id: "icon.pick.🎯")
        XCTAssertTrue(scrollTo(pick), "🎯 in 常用")
        pick.tap()
        usleep(800_000)
        let nodesLink = app.button(L("查看节点"))
        XCTAssertTrue(scrollTo(nodesLink), "查看节点 in the sheet")
        nodesLink.tap()
        let subNode = app.element(label: Self.credSubNode)
        XCTAssertTrue(scrollTo(subNode), "subscription node listed")
        subNode.press(forDuration: 1.3)
        let addLocal = app.button(L("添加到本地节点"))
        XCTAssertTrue(addLocal.waitForExistence(timeout: 4), "添加到本地节点 in the node row menu")
        snap("subs-split-node-menu")
        addLocal.tap()
        let added = app.alerts.firstMatch
        XCTAssertTrue(added.waitForExistence(timeout: 10), "added confirmation")
        XCTAssertTrue(added.staticTexts[L("已添加到本地节点")].exists, "confirmation title")
        snap("subs-split-node-added")
        added.buttons[L("好")].tap()
        usleep(600_000)
        // 查看节点 is pushed inside the sheet: back to the sheet's root first, then close it.
        let close = app.element(id: "sub.sheet.close")
        if !close.waitForExistence(timeout: 2) {
            let back = app.navigationBars["Demo Sub"].buttons.element(boundBy: 0)
            if back.exists { back.tap() } else { app.navigationBars.buttons.element(boundBy: 0).tap() }
        }
        XCTAssertTrue(tapIfExists(close, timeout: 4), "close the sheet")
        let sheetGone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: close)
        _ = XCTWaiter().wait(for: [sheetGone], timeout: 5)
        XCTAssertTrue(sub.waitForExistence(timeout: 6), "back on 节点与订阅")
        snap("subs-split-icon")

        // 删除 (menu) asks first, hides the row, and 恢复已删除的节点集 brings it back.
        XCTAssertTrue(scrollTo(provider))
        provider.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 4), "删除 in the menu")
        let confirm = app.element(id: "provider.confirmDelete")
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "delete confirmation")
        snap("subs-split-provider-delete-confirm")
        confirm.tap()
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: provider)
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 8), .completed, "deleted 节点集 hidden")
        let restore = app.element(id: "provider.restoreDeleted")
        XCTAssertTrue(scrollTo(restore), "恢复已删除的节点集")
        snap("subs-split-provider-deleted")
        restore.tap()
        XCTAssertTrue(provider.waitForExistence(timeout: 8), "restored")
        assertAlive("subs split")
    }
}
