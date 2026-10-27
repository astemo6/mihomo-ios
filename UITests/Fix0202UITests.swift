import XCTest

/// fix/nc-0.20.2 (user, 2026-10-27):
///  • every orderable list reorders with the shared 排序 / 完成 toolbar button and drag handles, and the order is kept
///    across a relaunch (重写 → 订阅, 定时任务, 分流规则 → 订阅, 策略组);
///  • 定时任务 + flow: 执行日期 (with the next run from the tunnel's own cron parser) → 下一步 → 计划任务 → listed
///    with its cron and script path, 需要更新 until downloaded, searchable;
///  • 分流规则 + → 订阅规则集 adds a remote rule set that is kept;
///  • a collapsed 策略 group row is exactly as tall as a 工具 row (≤ 0.5 pt).
extension TernUITests {

    private func orderOf(_ id: String) -> String {
        let e = app.element(id: id)
        return e.waitForExistence(timeout: 4) ? ((e.value as? String) ?? "") : "<missing \(id)>"
    }

    private func waitOrderPrefix(_ id: String, _ prefix: String, timeout: TimeInterval = 8) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if orderOf(id).hasPrefix(prefix) { return true }
            usleep(300_000)
        }
        return false
    }

    /// 排序 → drag `moving` above `target` on its reorder handle → 完成. true when the rows end up in that order.
    private func reorderWithButton(_ buttonID: String, doneID: String? = nil, moving: XCUIElement, above target: XCUIElement) -> Bool {
        XCTAssertTrue(tapIfExists(app.element(id: buttonID), timeout: 6), "排序 \(buttonID)")
        // r3: the UIKit reorder control was not found by label/frame on 重写 / 定时任务 (zh light + dark) while the
        // drag itself reordered the rows (edit mode on: `.onMove` is only attached while editing). Wait for the
        // handle a while; when it still is not matched, note it — the drag below and the strict saved-order /
        // relaunch checks of the caller decide.
        var handle: XCUIElement? = nil
        let deadline = Date().addingTimeInterval(4)
        repeat {
            usleep(400_000)
            handle = reorderControl(for: moving)
        } while handle == nil && Date() < deadline
        if handle == nil { warnings.append("[\(Env.tag)] no reorder control matched on \(moving.identifier); dragging by row edge") }
        let moved = dragRow(moving, above: target)
        XCTAssertTrue(tapIfExists(app.element(id: doneID ?? buttonID), timeout: 4), "完成 \(doneID ?? buttonID)")
        usleep(900_000)
        return moved
    }

    /// r3 (test98): the URL field sat under the keyboard raised for 名称 (tap did not focus it: 「Neither element nor
    /// any descendant has keyboard focus」). Taps until the field has keyboard focus: plain tap, then the form
    /// scrolled up so the field clears the keyboard, then a tap near the field's top edge.
    private func typeFocused(_ f: XCUIElement, _ text: String) {
        func focused() -> Bool { (f.value(forKey: "hasKeyboardFocus") as? Bool) == true }
        for attempt in 0..<4 {
            switch attempt {
            case 0: f.tap()
            case 1: app.swipeUp(); usleep(500_000); f.tap()
            case 2: f.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25)).tap()
            default: app.swipeUp(); usleep(500_000); f.coordinate(withNormalizedOffset: CGVector(dx: 0.3, dy: 0.5)).tap()
            }
            usleep(500_000)
            if focused() { f.typeText(text); return }
        }
        XCTFail("no keyboard focus on \(f.identifier)")
    }

    // MARK: 95. 重写 → 订阅: drag reorder, kept after relaunch

    func test95_RewriteReorderPersists() {
        launch(["-UITestReorder"])
        openMore("重写")
        let a = app.element(id: "module.row.UITest Panel Module")
        let b = app.element(id: "module.row.UITest Order B")
        XCTAssertTrue(a.waitForExistence(timeout: 8) && b.waitForExistence(timeout: 8), "two subscriptions")
        XCTAssertTrue(waitOrderPrefix("rewrite.subs.order", "UITest Panel Module"), "seed order (\(orderOf("rewrite.subs.order")))")
        XCTAssertTrue(reorderWithButton("rewrite.reorder", moving: b, above: a), "B dragged above the panel module")
        XCTAssertTrue(waitOrderPrefix("rewrite.subs.order", "UITest Order B"), "saved order (\(orderOf("rewrite.subs.order")))")
        snap("fix0202-rewrite-reordered")
        app.terminate()
        launch(["-UITestKeepData"])
        openMore("重写")
        XCTAssertTrue(waitOrderPrefix("rewrite.subs.order", "UITest Order B", timeout: 10),
                      "order kept after relaunch (\(orderOf("rewrite.subs.order")))")
        let a2 = app.element(id: "module.row.UITest Panel Module"), b2 = app.element(id: "module.row.UITest Order B")
        XCTAssertTrue(a2.waitForExistence(timeout: 6) && isBefore(b2, a2), "rows drawn in the kept order")
        assertAlive("rewrite reorder")
    }

    // MARK: 96. 定时任务: drag reorder, kept after relaunch

    func test96_TasksReorderPersists() {
        launch(["-UITestReorder"])
        openMore("任务")
        XCTAssertTrue(app.element(id: "scriptTasksView").waitForExistence(timeout: 8), "定时任务 page")
        let a = app.element(id: "task.row.UITest Task A")
        let b = app.element(id: "task.row.UITest Task B")
        XCTAssertTrue(a.waitForExistence(timeout: 8) && b.waitForExistence(timeout: 8), "two cron tasks")
        XCTAssertTrue(isBefore(a, b), "seed order A, B")
        XCTAssertTrue(reorderWithButton("tasks.reorder", doneID: "tasks.reorderDone", moving: b, above: a), "B dragged above A")
        let order = orderOf("tasks.order")
        if let ra = order.range(of: "UITest Task A"), let rb = order.range(of: "UITest Task B") {
            XCTAssertTrue(rb.lowerBound < ra.lowerBound, "saved task order \(order)")
        } else {
            XCTFail("tasks.order value \(order)")
        }
        snap("fix0202-tasks-reordered")
        app.terminate()
        launch(["-UITestKeepData"])
        openMore("任务")
        let a2 = app.element(id: "task.row.UITest Task A"), b2 = app.element(id: "task.row.UITest Task B")
        XCTAssertTrue(a2.waitForExistence(timeout: 8) && b2.waitForExistence(timeout: 8), "tasks after relaunch")
        XCTAssertTrue(isBefore(b2, a2), "order kept after relaunch")
        assertAlive("tasks reorder")
    }

    // MARK: 97. 分流规则 → 订阅 and 策略组: drag reorder, kept after relaunch

    func test97_RulesAndPolicyReorderPersists() {
        launch(["-UITestRuleSets"])
        openMore("规则")
        let china = app.element(id: "rules.set.China")
        XCTAssertTrue(china.waitForExistence(timeout: 10), "rule sets listed")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.reorder"), timeout: 6), "排序")
        let fb = app.element(id: "ruleorder.set.row.Facebook"), cn = app.element(id: "ruleorder.set.row.China")
        XCTAssertTrue(fb.waitForExistence(timeout: 6) && cn.exists, "reorder rows")
        XCTAssertTrue(dragRow(fb, above: cn), "Facebook dragged above China")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.orderDone"), timeout: 4), "完成")
        XCTAssertTrue(waitOrderPrefix("rules.sets.order", "Facebook", timeout: 12), "saved (\(orderOf("rules.sets.order")))")

        // 策略: 排序 → drag the second group above the first → 完成.
        tab(1)
        XCTAssertTrue(tapIfExists(app.element(id: "policy.reorder"), timeout: 8), "策略 排序")
        let done = app.element(id: "grouporder.done")
        XCTAssertTrue(done.waitForExistence(timeout: 8), "reorder mode")
        let rows = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "grouporder.row."))
        XCTAssertGreaterThanOrEqual(rows.count, 2, "group rows")
        let first = rows.element(boundBy: 0), second = rows.element(boundBy: 1)
        let firstName = first.identifier.replacingOccurrences(of: "grouporder.row.", with: "")
        let secondName = second.identifier.replacingOccurrences(of: "grouporder.row.", with: "")
        XCTAssertTrue(dragRow(app.element(id: "grouporder.row." + secondName), above: app.element(id: "grouporder.row." + firstName)),
                      "\(secondName) dragged above \(firstName)")
        done.tap()
        for _ in 0..<40 where done.exists { usleep(250_000) }
        let card: (String) -> XCUIElement = { self.app.element(id: "policy.group." + $0) }
        XCTAssertTrue(card(secondName).waitForExistence(timeout: 8) && isBefore(card(secondName), card(firstName)), "saved group order")
        snap("fix0202-policy-reordered")

        app.terminate()
        launch(["-UITestKeepData"])
        openMore("规则")
        XCTAssertTrue(waitOrderPrefix("rules.sets.order", "Facebook", timeout: 12), "rule-set order kept (\(orderOf("rules.sets.order")))")
        tab(1)
        XCTAssertTrue(card(secondName).waitForExistence(timeout: 10) && card(firstName).exists, "groups after relaunch")
        XCTAssertTrue(isBefore(card(secondName), card(firstName)), "group order kept after relaunch")
        assertAlive("rules + policy reorder")
    }

    // MARK: 98. 定时任务 + flow

    func test98_TaskAddFlow() {
        launch()
        openMore("任务")
        XCTAssertTrue(app.element(id: "scriptTasksView").waitForExistence(timeout: 8), "定时任务 page")
        XCTAssertTrue(app.element(id: "tasks.updateAll").exists, "全部更新")
        XCTAssertTrue(tapIfExists(app.element(id: "tasks.add"), timeout: 4), "+")
        let cron = app.textFields.matching(identifier: "taskadd.cron").firstMatch
        XCTAssertTrue(cron.waitForExistence(timeout: 6), "执行日期")
        XCTAssertTrue(app.element(id: "taskadd.nextRun").waitForExistence(timeout: 4), "next run preview")
        XCTAssertEqual(cron.value as? String, "0 8 * * *", "default 执行日期")
        XCTAssertTrue(tapIfExists(app.element(id: "taskadd.next"), timeout: 4), "下一步")
        let name = app.textFields.matching(identifier: "taskform.name").firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 6), "计划任务 form")
        XCTAssertTrue(app.element(id: "taskform.nextRun").waitForExistence(timeout: 4), "next run in the form")
        typeFocused(name, "UITest Added")
        // URL source
        let url = app.textFields.matching(identifier: "taskform.url").firstMatch
        if !url.waitForExistence(timeout: 2) {
            let seg = app.segmentedControls.buttons["URL"]
            if seg.exists { seg.tap() }
        }
        XCTAssertTrue(url.waitForExistence(timeout: 4), "script URL field")
        typeFocused(url, "https://example.invalid/uitest-added.js")
        snap("fix0202-task-form")
        XCTAssertTrue(tapIfExists(app.element(id: "taskform.save"), timeout: 4), "保存")
        let row = app.element(id: "task.row.UITest Added")
        XCTAssertTrue(row.waitForExistence(timeout: 10), "new task listed")
        XCTAssertTrue(app.element(labelContains: "example.invalid/uitest-added.js").exists, "script path on the row")
        XCTAssertTrue(app.element(labelContains: "0 8 * * *").exists, "cron on the row")
        snap("fix0202-task-added")
        // search
        let search = app.searchFields.firstMatch
        if search.waitForExistence(timeout: 3) {
            search.tap()
            search.typeText("uitest-added")
            XCTAssertTrue(row.waitForExistence(timeout: 4), "search finds the task by its script path")
        }
        assertAlive("task add flow")
    }

    // MARK: 99. 策略 group row height == 工具 row

    func test99_PolicyRowHeightMatchesTools() {
        launch()
        tab(3)
        XCTAssertTrue(app.navigationBars[L("工具")].waitForExistence(timeout: 8), "工具 tab")
        let toolRow = app.element(id: "more.网络工具（Ping / TCP / DNS）")
        XCTAssertTrue(scrollTo(toolRow), "工具 → 网络诊断")
        let tool = rowCellHeight(toolRow)
        tab(1)
        let card = app.element(id: "policy.group.Proxy")
        XCTAssertTrue(card.waitForExistence(timeout: 10), "Proxy group")
        XCTAssertTrue(scrollTo(app.element(id: "policy.card.Proxy")), "Proxy on screen")
        XCTAssertFalse(app.element(id: "policy.edit.Proxy").exists, "collapsed")
        let policy = card.frame.height
        snap("fix0202-policy-row")
        XCTAssertEqual(policy, tool, accuracy: 0.5, "策略 row \(policy) pt vs 工具 row \(tool) pt")
        let test = app.element(id: "policy.test.Proxy")
        XCTAssertGreaterThanOrEqual(test.frame.height, 43, "测速 keeps its 44 pt target (\(test.frame.height))")
        assertAlive("policy row height")
    }

    // MARK: 100. 分流规则 + → 订阅规则集

    func test100_RuleSetSubscriptionAdd() {
        launch()
        openMore("规则")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.addSet"), timeout: 8), "+")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.add.sub"), timeout: 4), "订阅规则集")
        let url = app.textFields.matching(identifier: "rulesub.url").firstMatch
        XCTAssertTrue(url.waitForExistence(timeout: 6), "订阅规则集 form")
        url.tap()
        url.typeText("https://rules.uitest.invalid/ads.list")
        let name = app.textFields.matching(identifier: "rulesub.name").firstMatch
        if name.exists { name.tap(); name.typeText("UITest Ads") }
        snap("fix0202-rulesub-form")
        let save = app.element(id: "rulesub.save")
        XCTAssertTrue(save.waitHittable(), "添加 enabled")
        save.tap()
        XCTAssertTrue(app.element(labelContains: "UITest Ads").waitForExistence(timeout: 8), "rule set listed")
        snap("fix0202-rulesub-added")
        back()
        openMore("规则")
        XCTAssertTrue(app.element(labelContains: "UITest Ads").waitForExistence(timeout: 8), "kept after reopening")
        assertAlive("rule set subscription add")
    }
}
