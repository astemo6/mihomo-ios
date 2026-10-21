import XCTest

/// feat/subs-split (user 2026-10-21 「将这里的配置订阅与节点订阅拆开」): 节点与订阅 has a 配置订阅 section and a 节点订阅
/// section; a profile's 节点集 (proxy-provider) works like a node subscription — right swipe 更新, left swipe 复制链接 only,
/// long-press 图标 / 更新 / 编辑 / 禁用 / 复制链接 / 删除 — through the override store.
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

        // Node subscription swipes: right 更新, left 复制链接 only (user 11:55).
        XCTAssertTrue(scrollTo(sub))
        sub.swipeLeft()
        XCTAssertTrue(app.button(L("复制链接")).waitForExistence(timeout: 3), "复制链接 in the trailing swipe")
        XCTAssertFalse(app.button(L("删除")).exists, "no 删除 in the swipe")
        XCTAssertFalse(app.button(L("禁用")).exists || app.button(L("停用")).exists, "no 禁用 in the swipe")
        snap("subs-split-sub-swipe-left")
        XCTAssertTrue(tapIfExists(app.button(L("复制链接")), timeout: 3))
        sub.swipeRight()
        XCTAssertTrue(app.button(L("更新")).waitForExistence(timeout: 3), "更新 in the leading swipe")
        snap("subs-split-sub-swipe-right")
        app.navigationBars.firstMatch.tap() // close the swipe
        usleep(400_000)

        // A file 节点集 has no link: its left swipe offers nothing (no 删除 / 禁用).
        XCTAssertTrue(scrollTo(provider))
        provider.swipeLeft()
        usleep(600_000)
        XCTAssertFalse(app.button(L("删除")).exists, "no 删除 in the 节点集 swipe")
        XCTAssertFalse(app.button(L("禁用")).exists, "no 禁用 in the 节点集 swipe")

        // Long-press menu (Loon-like): 图标 / 更新 / 编辑 / 禁用 / 删除 (no link for a file 节点集); 禁用 from it.
        XCTAssertTrue(scrollTo(provider))
        provider.press(forDuration: 1.3)
        for k in ["图标", "更新", "编辑", "禁用", "删除"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 4), "menu: \(k)")
        }
        snap("subs-split-provider-menu")
        XCTAssertTrue(tapIfExists(app.button(L("禁用")), timeout: 3), "禁用 from the menu")
        XCTAssertTrue(app.element(labelContains: L("已停用")).waitForExistence(timeout: 8), "row shows 已停用")
        XCTAssertTrue(provider.waitForExistence(timeout: 4), "a disabled 节点集 stays listed")
        snap("subs-split-provider-disabled")
        provider.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("启用")), timeout: 4), "启用 from the menu")
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
        for k in ["图标", "更新", "编辑", "禁用", "复制链接", "删除"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 4), "node subscription menu: \(k)")
        }
        snap("subs-split-sub-menu")
        XCTAssertTrue(tapIfExists(app.button(L("图标")), timeout: 3), "图标")
        let pick = app.element(id: "icon.pick.🎯")
        XCTAssertTrue(scrollTo(pick), "🎯 in 常用")
        pick.tap()
        usleep(800_000)
        XCTAssertTrue(sub.waitForExistence(timeout: 5), "back on the page")
        snap("subs-split-icon")

        // 添加到本地节点 from a subscription node row's long-press menu (same action as the node detail page, #68).
        XCTAssertTrue(scrollTo(sub))
        sub.tap()
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
        back()
        XCTAssertTrue(sub.waitForExistence(timeout: 6), "back on 节点与订阅")

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
