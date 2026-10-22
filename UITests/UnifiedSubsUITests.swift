import XCTest

/// fix/modules-only (user 2026-10-22): every remote-subscription list uses one interaction model (SubscriptionKit) —
/// switch = 启用 / 关闭, swipe right 更新, swipe left 删除 (asks first), tap = the shared edit sheet (订阅地址 editable,
/// saving re-downloads and shows the result), long press 更新 · 编辑 · 复制地址 · 启用/关闭 · 删除. And the QX-style
/// 重写 page: one 工具 card for subscriptions (modules) + local rules + script tools.
extension MihomoUITests {

    static let subMenu = ["更新", "编辑", "复制地址", "关闭", "删除"]

    /// Dismisses an open menu (the + menu or a row's long-press menu) without choosing an item: taps the empty
    /// middle of the navigation bar (a swipe could land on a menu item and trigger it).
    func dismissMenu() {
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.09)).tap()
        usleep(600_000)
    }

    func closeSwipe() {
        app.navigationBars.firstMatch.tap()
        usleep(400_000)
    }

    func cancelDialog() {
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(600_000)
    }

    /// Right swipe offers 更新; left swipe offers 删除, which asks first (`confirmID`); cancel keeps the row.
    func checkSwipes(_ row: XCUIElement, confirmID: String, shot: String) {
        XCTAssertTrue(scrollTo(row), "row \(shot)")
        row.swipeRight()
        XCTAssertTrue(app.button(L("更新")).waitForExistence(timeout: 3), "\(shot): 更新 in the leading swipe")
        snap("unified-\(shot)-swipe-right")
        closeSwipe()
        XCTAssertTrue(scrollTo(row))
        row.swipeLeft()
        let del = app.button(L("删除"))
        XCTAssertTrue(del.waitForExistence(timeout: 3), "\(shot): 删除 in the trailing swipe")
        snap("unified-\(shot)-swipe-left")
        del.tap()
        XCTAssertTrue(app.element(id: confirmID).waitForExistence(timeout: 4), "\(shot): delete confirmation")
        snap("unified-\(shot)-confirm")
        cancelDialog()
        XCTAssertTrue(row.waitForExistence(timeout: 4), "\(shot): cancel keeps the row")
    }

    /// The long-press menu lists the same actions in the same order.
    func checkMenu(_ row: XCUIElement, shot: String) {
        XCTAssertTrue(scrollTo(row))
        row.press(forDuration: 1.3)
        var lastY: CGFloat = -1
        for k in Self.subMenu {
            let b = app.button(L(k))
            XCTAssertTrue(b.waitForExistence(timeout: 4), "\(shot) menu: \(k)")
            if b.exists {
                XCTAssertGreaterThan(b.frame.minY, lastY, "\(shot) menu order at \(k)")
                lastY = b.frame.minY
            }
        }
        snap("unified-\(shot)-menu")
    }

    /// Tap → shared sheet: edit the address, 保存 re-downloads (the .invalid host fails) and the sheet shows the result.
    func checkSheetEditURL(_ row: XCUIElement, newURL: String, shot: String) {
        XCTAssertTrue(scrollTo(row))
        row.tap()
        let url = app.element(id: "sub.sheet.url")
        XCTAssertTrue(url.waitForExistence(timeout: 6), "\(shot): sheet with 订阅地址")
        XCTAssertTrue(app.element(id: "sub.sheet.update").exists, "\(shot): 立即更新")
        XCTAssertTrue(app.element(id: "sub.sheet.copy").exists, "\(shot): 复制地址")
        snap("unified-\(shot)-sheet")
        replaceText(url, newURL)
        let save = app.element(id: "sub.sheet.save")
        XCTAssertTrue(save.waitHittable(), "\(shot): 保存 enabled after the edit")
        save.tap()
        XCTAssertTrue(app.element(id: "sub.sheet.result").waitForExistence(timeout: 30), "\(shot): download result shown")
        snap("unified-\(shot)-sheet-result")
        app.swipeUp()
        XCTAssertTrue(app.element(id: "sub.sheet.delete").exists || scrollTo(app.element(id: "sub.sheet.delete"), fail: false), "\(shot): 删除 at the bottom")
        XCTAssertTrue(tapIfExists(app.element(id: "sub.sheet.close"), timeout: 3), "\(shot): close")
        usleep(800_000)
    }

    // MARK: 78. 重写 (QX-style): one card, 订阅 = modules with the unified rows, 本地, browse entries

    func test78_RewritePage() {
        launch()
        tab(3)
        if !app.navigationBars[L("工具")].waitForExistence(timeout: 5) { tab(3) } // first tap right after launch can be lost
        XCTAssertTrue(app.navigationBars[L("工具")].waitForExistence(timeout: 8), "工具 tab")
        for gone in ["模块与资源", "重写（本地模块）", "脚本"] {
            XCTAssertFalse(app.element(id: "more." + gone).exists, "old card \(gone) gone")
        }
        snap("rewrite-tools-card")
        openMore("重写")
        XCTAssertTrue(app.navigationBars[L("重写")].waitForExistence(timeout: 6), "重写 page")
        XCTAssertEqual(app.segmentedControls.count, 0, "no 全部 / 模块 / 规则集 / 脚本 filter")
        XCTAssertFalse(app.element(labelContains: "uitest-panel.js").exists, "no script-file rows")
        let row = app.element(id: "module.row.UITest Panel Module")
        XCTAssertTrue(scrollTo(row), "seeded (local) subscription listed")
        XCTAssertTrue(app.element(id: "module.row.UITest Panel Module.toggle").exists, "启用 switch on the row")
        snap("rewrite-page")

        // A local subscription: left swipe 删除 asks first; no 更新 (nothing to download).
        row.swipeLeft()
        let del = app.button(L("删除"))
        XCTAssertTrue(del.waitForExistence(timeout: 3), "删除 in the trailing swipe")
        snap("rewrite-swipe-delete")
        del.tap()
        XCTAssertTrue(app.element(id: "confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        cancelDialog()
        XCTAssertTrue(row.exists, "cancel keeps it")
        checkMenu(row, shot: "module")
        XCTAssertTrue(tapIfExists(app.button(L("编辑")), timeout: 3), "编辑 opens the sheet")
        XCTAssertTrue(app.element(id: "sub.sheet.name").waitForExistence(timeout: 6), "shared sheet")
        XCTAssertFalse(app.element(id: "sub.sheet.url").exists, "local subscription: no 订阅地址")
        XCTAssertTrue(app.element(id: "sub.sheet.moduleDetail").exists, "参数、策略与内容 link")
        snap("rewrite-module-sheet")
        XCTAssertTrue(tapIfExists(app.element(id: "sub.sheet.close"), timeout: 3))
        usleep(700_000)

        // Remote subscription: add one by URL (download fails offline, so nothing is added) — the + menu has the
        // 订阅 / 本地重写 / 本地脚本 sections.
        XCTAssertTrue(tapIfExists(app.element(id: "localmodule.add"), timeout: 4), "+ menu")
        for k in ["从 URL 添加订阅", "拒绝请求（reject）", "新建 / 导入脚本"] {
            XCTAssertTrue(app.button(L(k)).waitForExistence(timeout: 3), "+ menu: \(k)")
        }
        snap("rewrite-add-menu")
        dismissMenu()
        if app.button(L("从 URL 添加订阅")).exists { dismissMenu() }

        for key in Self.moduleRows { XCTAssertTrue(scrollTo(app.element(id: "more." + key)), "重写 lists \(key)") }
        snap("rewrite-page-bottom")
        // Switch off the subscription from its row.
        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)
        let sw = app.element(id: "module.row.UITest Panel Module.toggle")
        XCTAssertTrue(scrollTo(sw))
        toggleSwitch(sw)
        XCTAssertTrue(app.element(labelContains: L("已关闭")).waitForExistence(timeout: 5), "row shows 已关闭")
        snap("rewrite-module-off")
        assertAlive("重写")
    }

    // MARK: 79. 节点与订阅: 配置订阅 / 节点订阅 / 节点集 share swipes, menu and the edit sheet

    func test79_UnifiedSubscriptionRows() {
        launch(["-UITestRemoteProfile", "-UITestHTTPProvider"])
        openMore("节点与订阅")
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 8), "节点与订阅")
        let profile = app.element(id: "subs.profile.UITest Remote")
        let sub = app.element(id: "nodesub.row.Demo Sub")
        let provider = app.element(id: "provider.row.Demo HTTP Provider")
        XCTAssertTrue(profile.waitForExistence(timeout: 8) && sub.exists, "rows listed")
        for id in ["subs.profile.UITest Remote", "nodesub.row.Demo Sub"] {
            XCTAssertTrue(app.element(id: id + ".toggle").exists, "启用 switch on \(id)")
        }
        snap("unified-list")

        // 配置订阅
        checkSwipes(profile, confirmID: "profile.confirmDelete", shot: "profile")
        checkMenu(profile, shot: "profile")
        dismissMenu()
        checkSheetEditURL(profile, newURL: "https://profile.uitest.invalid/new.yaml", shot: "profile")
        // The switch is the 停用 flag (the active profile is another one, so it can be switched off).
        let psw = app.element(id: "subs.profile.UITest Remote.toggle")
        XCTAssertTrue(scrollTo(psw))
        toggleSwitch(psw)
        XCTAssertTrue(app.element(labelContains: L("已关闭")).waitForExistence(timeout: 5), "profile row shows 已关闭")
        snap("unified-profile-off")
        toggleSwitch(psw)

        // 节点订阅
        checkSwipes(sub, confirmID: "nodesub.confirmDelete", shot: "nodesub")
        checkMenu(sub, shot: "nodesub")
        dismissMenu()
        checkSheetEditURL(sub, newURL: "https://nodes.uitest.invalid/new?token=1", shot: "nodesub")

        // 节点集 (http provider of the current profile)
        XCTAssertTrue(scrollTo(provider), "http 节点集 row")
        provider.swipeLeft()
        XCTAssertTrue(app.button(L("删除")).waitForExistence(timeout: 3), "节点集: 删除 in the trailing swipe")
        snap("unified-provider-swipe-left")
        app.button(L("删除")).tap()
        XCTAssertTrue(app.element(id: "provider.confirmDelete").waitForExistence(timeout: 4), "节点集: delete confirmation")
        cancelDialog()
        provider.swipeRight()
        XCTAssertTrue(app.button(L("更新")).waitForExistence(timeout: 3), "节点集: 更新 in the leading swipe")
        snap("unified-provider-swipe-right")
        closeSwipe()
        checkMenu(provider, shot: "provider")
        dismissMenu()
        checkSheetEditURL(provider, newURL: "https://provider.uitest.invalid/other.yaml", shot: "provider")
        assertAlive("unified subscriptions")
    }
}
