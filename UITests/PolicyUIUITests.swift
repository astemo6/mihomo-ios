import XCTest

/// fix/app-policy-ui (user 2026-10-26, IMG_3620–3623):
///  #1 a 策略 group row has one button on the right (测速, 44 pt target); a tap on the row expands it, 编辑策略组 is in
///     the expanded section (and the long-press menu, test57);
///  #3 分流规则 → ⋯ → 编辑排序 reorders the 订阅 like 策略 → 编辑排序, and the order is kept;
///  #4 a collapsed 策略 group row is as tall as a 分流规则 订阅 row;
///  #6 Home cards: long-press → 半宽 / 全宽 and 编辑排序.
extension TernUITests {

    private func orderValue(_ id: String) -> String {
        let e = app.element(id: id)
        return e.exists ? ((e.value as? String) ?? "") : "<missing \(id)>"
    }

    private func waitOrder(_ id: String, _ want: String, timeout: TimeInterval = 8) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if orderValue(id) == want { return true }
            usleep(300_000)
        }
        return false
    }

    // MARK: 93. 分流规则 编辑排序 + row height parity with 策略

    func test93_RuleSetOrderAndPolicyRow() {
        launch(["-UITestRuleSets"])
        openMore("规则")
        XCTAssertTrue(app.element(id: "rules.final").waitForExistence(timeout: 10), "分流规则 page")
        let china = app.element(id: "rules.set.China")
        XCTAssertTrue(china.waitForExistence(timeout: 10), "rule set China listed")
        XCTAssertTrue(waitOrder("rules.sets.order", "China | AI | Facebook"), "profile order (got \(orderValue("rules.sets.order")))")
        XCTAssertTrue(scrollTo(china), "China row on screen")
        let ruleRow = rowCellHeight(china)
        snap("policyui-rules")

        // ⋯ → 编辑排序 → 置顶 Facebook → 完成.
        XCTAssertTrue(tapIfExists(app.element(id: "rules.more"), timeout: 4), "⋯")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.reorder"), timeout: 4), "编辑排序 in ⋯")
        XCTAssertTrue(waitOrder("ruleorder.sets.order", "China | AI | Facebook"), "reorder list (got \(orderValue("ruleorder.sets.order")))")
        XCTAssertTrue(app.element(id: "ruleorder.set.row.Facebook").exists, "reorder row Facebook")
        snap("policyui-rules-reorder")
        let top = app.element(id: "ruleorder.set.top.Facebook")
        XCTAssertTrue(scrollTo(top), "置顶 Facebook")
        top.tap()
        XCTAssertTrue(waitOrder("ruleorder.sets.order", "Facebook | China | AI"), "置顶 moved it (got \(orderValue("ruleorder.sets.order")))")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.orderDone"), timeout: 4), "完成")
        XCTAssertTrue(waitOrder("rules.sets.order", "Facebook | China | AI", timeout: 12),
                      "saved order shown on 分流规则 (got \(orderValue("rules.sets.order")))")
        snap("policyui-rules-reordered")
        // Kept: leave the page and come back.
        back()
        openMore("规则")
        XCTAssertTrue(waitOrder("rules.sets.order", "Facebook | China | AI", timeout: 10),
                      "order kept after reopening (got \(orderValue("rules.sets.order")))")
        // 取消 leaves the order alone.
        XCTAssertTrue(tapIfExists(app.element(id: "rules.more"), timeout: 4), "⋯ again")
        XCTAssertTrue(tapIfExists(app.element(id: "rules.reorder"), timeout: 4), "编辑排序 again")
        XCTAssertTrue(waitOrder("ruleorder.sets.order", "Facebook | China | AI"), "reorder list shows the saved order")
        let topAI = app.element(id: "ruleorder.set.top.AI")
        if scrollTo(topAI, fail: false) { topAI.tap() }
        XCTAssertTrue(tapIfExists(app.element(id: "rules.orderCancel"), timeout: 4), "取消")
        XCTAssertTrue(waitOrder("rules.sets.order", "Facebook | China | AI"), "取消 keeps the saved order")

        // 策略: the collapsed group row is as tall as the rule row; one 44 pt 测速 button; tap expands.
        tab(1)
        let card = app.element(id: "policy.group.Proxy")
        XCTAssertTrue(card.waitForExistence(timeout: 10), "Proxy group card")
        XCTAssertTrue(scrollTo(app.element(id: "policy.card.Proxy")), "Proxy on screen")
        let policyRow = card.frame.height
        snap("policyui-policy")
        XCTAssertEqual(policyRow, ruleRow, accuracy: 2.5, "策略 row \(policyRow) pt vs 分流规则 row \(ruleRow) pt")
        let test = app.element(id: "policy.test.Proxy")
        XCTAssertTrue(test.exists, "测速 button")
        XCTAssertGreaterThanOrEqual(test.frame.width, 43, "测速 target width \(test.frame.width)")
        XCTAssertGreaterThanOrEqual(test.frame.height, 43, "测速 target height \(test.frame.height)")
        XCTAssertFalse(app.element(id: "policy.edit.Proxy").exists, "collapsed: no 编辑策略组 row")
        app.element(id: "policy.card.Proxy").tap()
        XCTAssertTrue(app.element(id: "policy.edit.Proxy").waitForExistence(timeout: 4), "expanded: 编辑策略组 row")
        snap("policyui-policy-expanded")
        app.element(id: "policy.edit.Proxy").tap()
        XCTAssertTrue(app.navigationBars[L("编辑策略组")].waitForExistence(timeout: 8), "编辑策略组 opens the editor")
        XCTAssertTrue(tapIfExists(app.button(L("取消")), timeout: 4), "取消 closes the editor")
        for _ in 0..<20 where app.navigationBars[L("编辑策略组")].exists { usleep(250_000) }
        let name = app.element(id: "policy.card.Proxy")
        if scrollTo(name, fail: false) { name.tap() }
        XCTAssertTrue(waitGone(app.element(id: "policy.edit.Proxy")), "tap again collapses")
        assertAlive("policy ui rules")
    }

    private func waitGone(_ e: XCUIElement, timeout: TimeInterval = 4) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !e.exists { return true }
            usleep(250_000)
        }
        return !e.exists
    }

    // MARK: 94. Home cards: 半宽 / 全宽, 编辑排序 from a long-press

    func test94_HomePanelWidth() {
        launch()
        tab(0)
        // + is in the bar now (top right), not floating over the cards.
        let plus = app.element(id: "home.quickAdd")
        XCTAssertTrue(plus.waitForExistence(timeout: 8), "+ on Home")
        XCTAssertLessThan(plus.frame.midY, 140, "+ sits in the top bar (y \(plus.frame.midY))")

        // Pin two small tiles through the editor (both half width by default → one row).
        let add = app.element(id: "home.addTiles")
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor")
        for t in ["uptime", "memory"] {
            let b = app.element(id: "homepanels.add." + t)
            if scrollTo(b, fail: false) { b.tap(); usleep(400_000) }
        }
        snap("policyui-home-editor")
        XCTAssertTrue(tapIfExists(app.navigationBars.buttons[L("完成")].firstMatch, timeout: 4), "完成")
        usleep(800_000)

        func tile(_ t: String) -> XCUIElement {
            app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile." + t)).firstMatch
        }
        let uptime = tile("uptime"), memory = tile("memory")
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile")
        XCTAssertTrue(memory.exists, "内存 tile")
        snap("policyui-home-half")
        let screenW = app.windows.firstMatch.frame.width
        XCTAssertEqual(uptime.frame.midY, memory.frame.midY, accuracy: 4, "two half tiles share a row")
        XCTAssertLessThan(uptime.frame.width, screenW * 0.6, "运行时长 is half width (\(uptime.frame.width) of \(screenW))")

        // Long-press → 全宽显示: 运行时长 takes the whole row, 内存 moves below it.
        uptime.press(forDuration: 1.2)
        XCTAssertTrue(app.button(L("编辑排序")).waitForExistence(timeout: 4), "编辑排序 in the long-press menu")
        XCTAssertTrue(tapIfExists(app.button(L("全宽显示")), timeout: 4), "全宽显示")
        usleep(900_000)
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile again")
        snap("policyui-home-full")
        XCTAssertGreaterThan(uptime.frame.width, screenW * 0.8, "运行时长 is full width (\(uptime.frame.width) of \(screenW))")
        XCTAssertGreaterThan(memory.frame.minY, uptime.frame.maxY - 2, "内存 moved to the next row")

        // Back to half, then long-press → 编辑排序 opens the editor (its drag / 上移下移 list).
        uptime.press(forDuration: 1.2)
        XCTAssertTrue(tapIfExists(app.button(L("半宽显示")), timeout: 4), "半宽显示")
        usleep(900_000)
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile, half again")
        XCTAssertEqual(uptime.frame.midY, memory.frame.midY, accuracy: 4, "half again: shares the row")
        uptime.press(forDuration: 1.2)
        XCTAssertTrue(tapIfExists(app.button(L("编辑排序")), timeout: 4), "编辑排序")
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor from 编辑排序")
        XCTAssertTrue(app.element(id: "homepanels.move.uptime").exists, "上移 / 下移 menu kept in the editor")
        snap("policyui-home-order")
        closeSheet()
        assertAlive("home panel width")
    }
}
