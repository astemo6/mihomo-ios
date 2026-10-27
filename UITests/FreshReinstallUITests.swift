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
}
