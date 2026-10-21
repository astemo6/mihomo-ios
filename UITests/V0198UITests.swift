import XCTest

/// v0.19.8 paths (offline, simulator). Same helpers as MihomoUITests; identifiers rather than labels where the
/// app provides them.
extension MihomoUITests {

    // MARK: 40. 筛选节点: rename + icon

    func test40_FilterRenameAndIcon() {
        launch()
        openMore("节点与订阅")
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8), "筛选节点")
        let jp = app.element(id: "filter.JP")
        XCTAssertTrue(jp.waitForExistence(timeout: 8), "JP filter")
        jp.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("编辑筛选")), timeout: 3), "edit action")
        let name = app.textFields.matching(identifier: "filter.name").firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 5), "name field")
        replaceText(name, "JP Icon")
        XCTAssertTrue(tapIfExists(app.element(id: "filter.flag"), timeout: 4), "icon row opens the picker")
        let pick = app.element(id: "icon.pick.🎯")
        XCTAssertTrue(scrollTo(pick), "🎯 in 常用")
        pick.tap()
        usleep(600_000)
        XCTAssertTrue(app.element(id: "filter.flag").waitForExistence(timeout: 5), "back in the filter editor")
        snap("v0198-filter-icon")
        let save = app.navigationBars.buttons[L("保存")]
        XCTAssertTrue(save.waitHittable(), "保存 enabled")
        save.tap()
        XCTAssertTrue(app.element(labelContains: "JP Icon").waitForExistence(timeout: 6), "renamed filter listed")
        XCTAssertTrue(app.element(labelContains: "🎯").waitForExistence(timeout: 4), "new icon shown")
        snap("v0198-filter-renamed")
        // Reopen: both kept.
        back()
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        XCTAssertTrue(app.element(labelContains: "JP Icon").waitForExistence(timeout: 6), "rename kept")
        XCTAssertTrue(app.element(labelContains: "🎯").exists, "icon kept")
        assertAlive("filter rename + icon")
    }

    // MARK: 41. 节点订阅: swipes (right 更新, left 复制链接 only) + menu 禁用 / 启用 / 删除

    func test41_SubscriptionSwipeDisable() {
        launch()
        openMore("节点与订阅")
        let row = app.element(id: "nodesub.row.Demo Sub")
        XCTAssertTrue(scrollTo(row), "Demo Sub row")
        // feat/subs-split (user 11:55): the left swipe only copies the link.
        row.swipeLeft()
        XCTAssertTrue(app.button(L("复制链接")).waitForExistence(timeout: 3), "复制链接 in the trailing swipe")
        XCTAssertFalse(app.button(L("删除")).exists, "no 删除 in the swipe")
        XCTAssertFalse(app.button(L("禁用")).exists || app.button(L("停用")).exists, "no 禁用 in the swipe")
        snap("v0198-sub-copy-swipe")
        XCTAssertTrue(tapIfExists(app.button(L("复制链接")), timeout: 3))
        // 禁用 / 启用 from the long-press menu.
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("禁用")), timeout: 4), "禁用 in the menu")
        XCTAssertTrue(app.element(labelContains: L("已停用")).waitForExistence(timeout: 6), "row shows 已停用")
        snap("v0198-sub-disabled")
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("启用")), timeout: 4), "启用 in the menu")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: L("已停用")))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 6), .completed, "enabled again")
        // 删除 (menu) asks first; cancel keeps the row.
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("删除")), timeout: 4), "删除 in the menu")
        XCTAssertTrue(app.element(id: "nodesub.confirmDelete").waitForExistence(timeout: 4), "delete confirmation")
        snap("v0198-sub-delete-confirm")
        let cancel = app.buttons.matching(NSPredicate(format: "label == %@", L("取消"))).firstMatch
        if cancel.exists { cancel.tap() } else { app.swipeDown() }
        usleep(500_000)
        XCTAssertTrue(row.exists, "cancel keeps the subscription")
        // Leading swipe offers 更新.
        row.swipeRight()
        XCTAssertTrue(app.button(L("更新")).waitForExistence(timeout: 3), "更新 in the leading swipe")
        snap("v0198-sub-update-swipe")
        assertAlive("subscription swipe")
    }

    // MARK: 42. 策略组顺序: drag down and up on the cards

    func test42_GroupReorderBothWays() {
        launch()
        tab(1)
        let card: (String) -> XCUIElement = { self.app.element(id: "policy.card." + $0) }
        func above(_ a: String, _ b: String, _ timeout: Double = 8) -> Bool {
            let deadline = Date().addingTimeInterval(timeout)
            repeat {
                if card(a).exists && card(b).exists && card(a).frame.minY < card(b).frame.minY { return true }
                usleep(250_000)
            } while Date() < deadline
            return false
        }
        XCTAssertTrue(card("Proxy").waitForExistence(timeout: 10), "policy cards")
        XCTAssertTrue(above("Proxy", "Auto", 2), "seed order: Proxy before Auto")
        // Down: Proxy dropped on Apple (further down) → Auto is now above Proxy, whatever side it lands on.
        card("Proxy").press(forDuration: 1.2, thenDragTo: card("Apple"), withVelocity: .slow, thenHoldForDuration: 0.8)
        XCTAssertTrue(above("Auto", "Proxy"), "drag down: Proxy moved below Auto")
        XCTAssertTrue(app.element(id: "policy.orderSource").waitForExistence(timeout: 8), "switched to the 自定义 copy")
        usleep(1_000_000)
        snap("v0198-order-down")
        // Up: Final dropped on Auto (now first) → Final above Fallback.
        XCTAssertTrue(scrollTo(card("Final")), "Final card")
        card("Final").press(forDuration: 1.2, thenDragTo: card("Auto"), withVelocity: .slow, thenHoldForDuration: 0.8)
        XCTAssertTrue(above("Final", "Fallback"), "drag up: Final moved above Fallback")
        usleep(1_000_000)
        snap("v0198-order-up")
        // The order sticks after leaving the tab.
        tab(0)
        tab(1)
        XCTAssertTrue(above("Auto", "Proxy"), "down move kept")
        XCTAssertTrue(above("Final", "Fallback"), "up move kept")
        assertAlive("reorder both ways")
    }

    // MARK: 43. 出站模式 → GLOBAL card only in 全局

    func test43_ModeGlobalVisibility() {
        launch()
        tab(1)
        let mode = app.element(id: "policy.mode")
        XCTAssertTrue(scrollTo(mode), "mode picker")
        let global = app.element(id: "policy.card.GLOBAL")
        func seg(_ k: String) -> XCUIElement { app.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch }
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "规则")
        usleep(600_000)
        XCTAssertFalse(global.exists, "规则: no GLOBAL card")
        XCTAssertTrue(tapIfExists(seg("全局"), timeout: 4), "全局")
        XCTAssertTrue(global.waitForExistence(timeout: 6), "全局: GLOBAL card shown")
        // fb-subs-global (user 「全局下，策略里下方的域名规则不需要显示」): the rule groups are hidden in 全局.
        XCTAssertTrue(app.element(id: "policy.globalHidden").waitForExistence(timeout: 4), "全局: hidden-groups note")
        XCTAssertFalse(app.element(id: "policy.card.Apple").exists, "全局: rule group Apple hidden")
        snap("v0198-mode-global")
        XCTAssertTrue(tapIfExists(seg("直连"), timeout: 4), "直连")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: global)
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 6), .completed, "直连: GLOBAL hidden")
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "back to 规则")
        XCTAssertTrue(scrollTo(app.element(id: "policy.card.Apple")), "规则: rule group Apple shown again")
        XCTAssertFalse(app.element(id: "policy.globalHidden").exists, "规则: no hidden-groups note")
        assertAlive("mode → GLOBAL")
    }

    // MARK: 44. 首页卡片: 流媒体解锁 tile; 编辑首页面板 → 脚本任务

    func test44_HomeUnlockTileAndScriptTasks() {
        launch()
        let add = app.element(id: "home.addTiles")
        let editor = app.navigationBars[L("编辑首页面板")]
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(editor.waitForExistence(timeout: 6), "editor")
        let unlock = app.element(id: "homepanels.add.unlock")
        XCTAssertTrue(scrollTo(unlock), "流媒体解锁 in 添加")
        unlock.tap()
        XCTAssertTrue(app.element(id: "homepanels.row.unlock").waitForExistence(timeout: 4), "unlock pinned")
        snap("v0198-unlock-pinned")
        // 编辑首页面板 → 脚本任务 opens the tasks page (a button row, not a dead label).
        let tasks = app.element(id: "homepanels.scriptTasks")
        XCTAssertTrue(scrollTo(tasks), "脚本任务 row")
        // It is the last row of the sheet; in en the longer card captions push it under the home indicator, where a
        // tap does not land. One more swipe settles the list at its bottom inset, and the tap is retried once.
        app.swipeUp(velocity: .slow)
        usleep(400_000)
        let tasksPage = app.element(id: "scriptTasksView")
        tasks.tap()
        if !tasksPage.waitForExistence(timeout: 4), tasks.exists, tasks.isHittable { tasks.tap() }
        XCTAssertTrue(tasksPage.waitForExistence(timeout: 6), "脚本任务 → 任务 page")
        snap("v0198-script-tasks")
        // Back to the editor, close it; the tile is part of Home's tree (existence only: the tile sits low on the
        // page and the simulator reports its title as not hittable).
        back()
        if editor.waitForExistence(timeout: 4) { closeSheet() }
        for _ in 0..<3 where editor.exists { usleep(700_000); if editor.exists { closeSheet() } }
        let tile = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile.unlock")).firstMatch
        XCTAssertTrue(tile.waitForExistence(timeout: 8), "流媒体解锁 tile on Home")
        assertAlive("home unlock tile + 脚本任务")
    }

    // MARK: 45. 自定义规则 form: DOMAIN-SUFFIX with only the value typed

    func test45_RuleFormDefaults() {
        launch()
        openMore("规则")
        app.buttons[L10n.f("自定义 %lld", 0)].firstMatch.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "rules.add"), timeout: 5), "rules +")
        let value = app.textFields.matching(identifier: "rule.value").firstMatch
        XCTAssertTrue(value.waitForExistence(timeout: 5), "value field (form is the default)")
        value.tap()
        value.typeText("form.uitest.example")
        usleep(1_000_000)
        let line = app.element(id: "rule.line")
        XCTAssertTrue(line.waitForExistence(timeout: 4), "line preview")
        XCTAssertTrue(line.label.hasPrefix("DOMAIN-SUFFIX,form.uitest.example,"), "type and policy prefilled: \(line.label)")
        snap("v0198-rule-form")
        let save = app.element(id: "rule.save")
        XCTAssertTrue(save.waitHittable(), "保存 enabled without choosing type / policy")
        save.tap()
        XCTAssertTrue(app.element(labelContains: "form.uitest.example").waitForExistence(timeout: 6), "rule saved")
        assertAlive("rule form")
    }

    // MARK: 46. 日志 not empty on first open (UITestSeed lines; on a device: the extension's history)

    func test46_LogsNotEmptyOnFirstOpen() {
        launch()
        openMore("日志")
        XCTAssertTrue(app.element(id: "logs.line").waitForExistence(timeout: 6), "log lines on first open")
        XCTAssertTrue(app.element(id: "logs.hint").exists, "从连接开始记录 hint")
        snap("v0198-logs")
        XCTAssertTrue(tapIfExists(app.element(id: "logs.clear"), timeout: 3), "清空")
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(id: "logs.line"))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 4), .completed, "cleared")
        assertAlive("logs")
    }

    // MARK: 47. 配置快照: 选择 → 全选 → 删除 (N)

    func test47_SnapshotMultiDelete() {
        launch()
        openMore("配置快照")
        let rows = app.descendants(matching: .any).matching(identifier: "snapshots.row")
        if rows.count == 0 {
            XCTAssertTrue(tapIfExists(app.element(id: "snapshots.create"), timeout: 4), "立即创建快照")
            usleep(800_000)
        }
        XCTAssertTrue(rows.firstMatch.waitForExistence(timeout: 6), "at least one snapshot")
        XCTAssertTrue(tapIfExists(app.element(id: "snapshots.select"), timeout: 4), "选择")
        let del = app.element(id: "snapshots.deleteSelected")
        XCTAssertTrue(del.waitForExistence(timeout: 4), "删除 (N) bar")
        XCTAssertFalse(del.isEnabled, "nothing selected → disabled")
        // One row toggles on and off.
        rows.firstMatch.tap()
        XCTAssertTrue(del.waitHittable(3), "one selected → enabled")
        rows.firstMatch.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "snapshots.selectAll"), timeout: 4), "全选")
        let total = rows.count
        XCTAssertTrue(del.label.contains("\(total)"), "删除 (\(total)): \(del.label)")
        snap("v0198-snapshots-select")
        del.tap()
        let confirm = app.buttons.matching(NSPredicate(format: "label == %@", L("删除"))).firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "confirmation")
        confirm.tap()
        usleep(800_000)
        let ok = app.buttons.matching(NSPredicate(format: "label == %@", L("好"))).firstMatch
        if ok.waitForExistence(timeout: 3) { ok.tap() }
        var left = rows.count
        for _ in 0..<24 where left > 0 { usleep(250_000); left = rows.count }
        XCTAssertEqual(left, 0, "all snapshots deleted")
        snap("v0198-snapshots-empty")
        assertAlive("snapshot multi-delete")
    }
}
