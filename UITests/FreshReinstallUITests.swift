import XCTest

/// feat/fresh-reinstall: the reinstall question (保留 path) and 更多 → 备份与恢复 → 清除全部数据 (double confirmation,
/// wipe, 「已清除全部数据」 page, 退出 Tern).
extension TernUITests {

    // MARK: 95. Reinstall question → 保留; 清除全部数据 → wipe → quit

    func test95_FreshReinstall() {
        // 1. Reinstall question (forced by -UITestReinstallPrompt; nothing behind it runs until a choice is made).
        let a = XCUIApplication()
        let locale = Env.isEnglish ? "en_US" : "zh_CN"
        a.launchArguments = ["-UITestSeed", "-UITestReinstallPrompt", "-AppleLanguages", "(\(Env.lang))", "-AppleLocale", locale,
                             "-appearance", Env.style]
        a.launch()
        app = a
        XCTAssertTrue(app.element(id: "reinstall.title").waitForExistence(timeout: 20), "reinstall question")
        XCTAssertFalse(app.element(id: "uitest.ready").exists, "the app waits behind the question")
        XCTAssertTrue(app.element(id: "reinstall.wipe").exists, "全部清除，从新开始")
        snap("reinstall-prompt")
        // 全部清除 asks first; 取消 keeps the question up.
        app.element(id: "reinstall.wipe").tap()
        XCTAssertTrue(app.button(L("全部清除")).waitForExistence(timeout: 4), "wipe confirmation")
        snap("reinstall-confirm")
        XCTAssertTrue(tapIfExists(app.button(L("取消")), timeout: 3), "取消")
        usleep(600_000)
        XCTAssertTrue(app.element(id: "reinstall.keep").waitForExistence(timeout: 4), "question still up after 取消")
        app.element(id: "reinstall.keep").tap()
        XCTAssertTrue(app.element(id: "uitest.ready").waitForExistence(timeout: 40), "保留 → the app starts (seed finished)")
        assertAlive("保留")

        // 2. 更多 → 备份与恢复 → 清除全部数据: two confirmations, 取消 on the second keeps everything.
        openMore("备份与恢复")
        let reset = app.element(id: "backup.resetAll")
        XCTAssertTrue(scrollTo(reset), "清除全部数据 row")
        snap("backup-reset-row")
        reset.tap()
        let cont = app.element(id: "backup.resetAll.continue")
        XCTAssertTrue(cont.waitForExistence(timeout: 4), "first confirmation")
        cont.tap()
        // Alert actions carry their title, not the SwiftUI identifier.
        let confirm = app.alerts.buttons[L("全部清除")].firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "second confirmation")
        snap("backup-reset-confirm2")
        XCTAssertTrue(tapIfExists(app.alerts.buttons[L("取消")].firstMatch, timeout: 3), "取消 on the second confirmation")
        usleep(600_000)
        XCTAssertTrue(reset.exists, "still on 备份与恢复 after 取消")

        // 3. Wipe for real → 「已清除全部数据」 → 退出 Tern ends the app.
        reset.tap()
        XCTAssertTrue(cont.waitForExistence(timeout: 4), "first confirmation (again)")
        cont.tap()
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "second confirmation (again)")
        confirm.tap()
        XCTAssertTrue(app.element(id: "reset.done").waitForExistence(timeout: 20), "已清除全部数据")
        snap("reset-done")
        app.element(id: "reset.quit").tap()
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 10) || app.state == .runningBackground, "退出 Tern leaves the app (state \(app.state.rawValue))")
    }

    // MARK: 96. Home: long-press-and-drag reorder (half- and full-width cards), persisted across a relaunch

    func test96_HomeDragReorder() {
        launch()
        tab(0)
        let add = app.element(id: "home.addTiles")
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor")
        for t in ["uptime", "memory"] {
            let b = app.element(id: "homepanels.add." + t)
            if scrollTo(b, fail: false) { b.tap(); usleep(400_000) }
        }
        XCTAssertTrue(tapIfExists(app.navigationBars.buttons[L("完成")].firstMatch, timeout: 4), "完成")
        usleep(800_000)

        func tile(_ t: String) -> XCUIElement {
            app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile." + t)).firstMatch
        }
        func order() -> [String] {
            let e = app.element(id: "home.panels.order")
            // Saved tokens are "builtin.<id>"; compare on the bare id.
            return ((e.value as? String) ?? "").split(separator: ",").map {
                let t = String($0); return t.hasPrefix("builtin.") ? String(t.dropFirst(8)) : t
            }
        }
        func before(_ a: String, _ b: String) -> Bool {
            let o = order()
            guard let i = o.firstIndex(of: a), let j = o.firstIndex(of: b) else { return false }
            return i < j
        }
        /// Long-press (the menu preview lifts), then drag slowly onto `target` and hold; one retry from the target's edge.
        func drag(_ e: XCUIElement, onto target: XCUIElement, until done: () -> Bool) -> Bool {
            e.press(forDuration: 1.0, thenDragTo: target, withVelocity: .slow, thenHoldForDuration: 0.6)
            usleep(1_500_000) // drop + 0.6 s save
            if done() { return true }
            warnings.append("[\(Env.tag)] home drag retry")
            // A press that ended as a context menu (or its 从首页移除 confirmation) must be closed first, or the retry
            // lands on a menu item.
            if app.button(L("从首页移除")).exists || app.button(L("全宽显示")).exists || app.button(L("半宽显示")).exists {
                app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.06)).tap()
                usleep(700_000)
            }
            e.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
                .press(forDuration: 1.0, thenDragTo: target.coordinate(withNormalizedOffset: CGVector(dx: 0.25, dy: 0.5)),
                       withVelocity: .slow, thenHoldForDuration: 0.8)
            usleep(1_500_000)
            return done()
        }
        /// After a drag: tap the title area once, so a drag session the simulator is still winding down ends (outside
        /// Home → saved) before the next long-press, which would otherwise open no menu (CI 40601214518 en light).
        func settle() {
            app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.06)).tap()
            usleep(1_200_000)
        }
        /// Both cards fully above the tab bar (a drop target under the tab bar never gets the drop: CI 40601214518 en
        /// dark, 运行时长 full width sat behind it). The page ends below the cards, so scrolling to the end shows them.
        func reveal(_ e: XCUIElement) {
            let bar = app.tabBars.firstMatch
            for _ in 0..<3 where bar.exists && e.exists && e.frame.maxY > bar.frame.minY - 8 {
                app.swipeUp(velocity: .slow)
                usleep(700_000)
            }
        }
        let uptime = tile("uptime"), memory = tile("memory")
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile")
        XCTAssertTrue(memory.exists, "内存 tile")
        XCTAssertTrue(app.element(id: "home.panels.order").exists, "order probe (Debug UI tests)")
        XCTAssertTrue(before("uptime", "memory"), "pinned in that order: \(order())")
        XCTAssertLessThan(uptime.frame.midX, memory.frame.midX, "half tiles: 运行时长 left of 内存")

        // Half width: drag 内存 onto 运行时长 → 内存 first.
        reveal(uptime)
        XCTAssertTrue(drag(memory, onto: uptime) { before("memory", "uptime") }, "drag reordered (half): \(order())")
        snap("home-drag-half")
        settle()
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile after the drag")
        XCTAssertLessThan(memory.frame.midX, uptime.frame.midX, "内存 drawn first")

        // Full width: 运行时长 full (it moves to its own row below 内存), then drag 内存 down onto it → 运行时长 first.
        // Dragged downwards on purpose: the cards sit low on the page, so their long-press menu opens above them, and
        // a drag upwards slides over that menu instead of starting (rel 0.20.2 CI: it ended on 从首页移除).
        uptime.press(forDuration: 1.2)
        XCTAssertTrue(tapIfExists(app.button(L("全宽显示")), timeout: 4), "全宽显示")
        usleep(900_000)
        XCTAssertTrue(scrollTo(uptime), "运行时长 full width")
        XCTAssertTrue(memory.exists, "内存 above it")
        reveal(uptime)
        XCTAssertTrue(drag(memory, onto: uptime) { before("uptime", "memory") }, "drag reordered (full): \(order())")
        snap("home-drag-full")
        settle()
        XCTAssertTrue(scrollTo(uptime), "运行时长 tile after the full-width drag")
        // The long-press menu no longer offers 在首页隐藏; removal is 从首页移除.
        uptime.press(forDuration: 1.2)
        XCTAssertTrue(app.button(L("从首页移除")).waitForExistence(timeout: 4), "从首页移除 in the long-press menu")
        XCTAssertFalse(app.button(L("在首页隐藏")).exists, "no 在首页隐藏")
        XCTAssertFalse(app.button(L("取消固定")).exists, "取消固定 renamed")
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.06)).tap() // close the menu (tap above it)
        usleep(600_000)
        let saved = order()

        // Persisted: relaunch keeping the data.
        app.terminate()
        launch(["-UITestKeepData"])
        tab(0)
        XCTAssertTrue(scrollTo(tile("uptime")), "运行时长 tile after relaunch")
        XCTAssertEqual(order(), saved, "order survived the relaunch")
        XCTAssertTrue(before("uptime", "memory"), "relaunch order: \(order())")
        assertAlive("home drag reorder")
    }
}
