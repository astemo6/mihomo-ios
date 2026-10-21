import XCTest

/// feat/subs-split (user 2026-10-21 「将这里的配置订阅与节点订阅拆开」): 节点与订阅 has a 配置订阅 section and a 节点订阅
/// section; a profile's 节点集 (proxy-provider) works like a node subscription — right swipe 更新, left swipe 删除 / 停用,
/// long-press 图标 / 更新 / 编辑 / 停用 / 复制链接 / 删除 — through the override store.
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

        // Left swipe: 删除 + 停用 (no 复制链接 any more).
        XCTAssertTrue(scrollTo(provider))
        provider.swipeLeft()
        XCTAssertTrue(app.button(L("删除")).waitForExistence(timeout: 3), "删除 in the trailing swipe of a 节点集")
        XCTAssertFalse(app.button(L("复制链接")).exists, "no 复制链接 in the swipe")
        snap("subs-split-provider-swipe")
        XCTAssertTrue(tapIfExists(app.button(L("停用")), timeout: 3), "停用 in the trailing swipe")
        XCTAssertTrue(app.element(labelContains: L("已停用")).waitForExistence(timeout: 8), "row shows 已停用")
        XCTAssertTrue(provider.waitForExistence(timeout: 4), "a 停用 节点集 stays listed")
        snap("subs-split-provider-disabled")

        // Long-press menu (Loon-like), 启用 from it.
        provider.press(forDuration: 1.3)
        for k in ["图标", "更新", "编辑", "启用", "删除"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 4), "menu: \(k)")
        }
        snap("subs-split-provider-menu")
        XCTAssertTrue(tapIfExists(app.button(L("启用")), timeout: 3), "启用 from the menu")
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: L("已停用")))
        XCTAssertEqual(XCTWaiter().wait(for: [enabled], timeout: 8), .completed, "enabled again")

        // 编辑: display name.
        XCTAssertTrue(scrollTo(provider))
        provider.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("编辑")), timeout: 4), "编辑 from the menu")
        let name = app.textFields.matching(identifier: "provider.edit.name").firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 5), "name field")
        replaceText(name, "My Provider")
        snap("subs-split-provider-edit")
        XCTAssertTrue(tapIfExists(app.element(id: "provider.edit.save"), timeout: 4), "保存")
        XCTAssertTrue(app.element(labelContains: "My Provider").waitForExistence(timeout: 8), "display name shown")

        // Node subscription menu: same items, 图标 opens the shared picker.
        XCTAssertTrue(scrollTo(sub))
        sub.press(forDuration: 1.3)
        for k in ["图标", "更新", "编辑", "停用", "复制链接", "删除"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 4), "node subscription menu: \(k)")
        }
        XCTAssertTrue(tapIfExists(app.button(L("图标")), timeout: 3), "图标")
        let pick = app.element(id: "icon.pick.🎯")
        XCTAssertTrue(scrollTo(pick), "🎯 in 常用")
        pick.tap()
        usleep(800_000)
        XCTAssertTrue(sub.waitForExistence(timeout: 5), "back on the page")
        snap("subs-split-icon")

        // 删除 asks first, hides the row, and 恢复已删除的节点集 brings it back.
        XCTAssertTrue(scrollTo(provider))
        provider.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 3), "删除 in the trailing swipe")
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
