import XCTest

/// feat/nc-conf-native (user 2026-10-28): the profile editor shows Tern's own .conf (Quantumult X-style sections), not
/// the internal YAML. Open 编辑配置 on the demo profile, see `[filter_local]`, add a rule, 保存并重载, reopen: the rule
/// is still in the .conf.
extension TernUITests {

    func confEditorText() -> String {
        let tv = app.textViews.firstMatch
        return (tv.value as? String) ?? ""
    }

    func openDemoConfEditor() {
        openProfiles()
        let row = app.cells.containing(NSPredicate(format: "label == %@", "UITest Demo"))
            .containing(NSPredicate(format: "label == %@", L("本地"))).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 5), "UITest Demo profile row")
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("编辑配置")), timeout: 4), "编辑配置 in the profile menu")
        XCTAssertTrue(app.navigationBars[L("编辑配置")].waitForExistence(timeout: 8), "编辑配置 sheet")
        XCTAssertTrue(app.textViews.firstMatch.waitForExistence(timeout: 10), "the .conf editor")
        // The text loads off the main thread.
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline && !confEditorText().contains("[filter_local]") { usleep(300_000) }
    }

    func test101_ConfNativeEditor() {
        launch()
        openDemoConfEditor()
        let text = confEditorText()
        XCTAssertTrue(text.contains("[filter_local]"), "the editor shows the .conf ([filter_local])")
        XCTAssertTrue(text.contains("[policy]") && text.contains("[server_local]"), "QX-style sections")
        XCTAssertFalse(text.contains("proxy-groups:"), "no internal YAML in the editor")
        XCTAssertTrue(text.contains("[mitm]"), "shared MitM section shown")
        snap("conf-editor-open")

        // Add a rule at the end of the first line (a comment): a new [filter_local] block before [general].
        let tv = app.textViews.firstMatch
        tv.coordinate(withNormalizedOffset: CGVector(dx: 0.97, dy: 0)).withOffset(CGVector(dx: 0, dy: 19)).tap()
        usleep(600_000)
        tv.typeText("\n[filter_local]\nhost-suffix, uitest-conf.example, direct")
        usleep(1_800_000) // live check (debounced 0.7 s)
        snap("conf-editor-edited")
        XCTAssertTrue(confEditorText().contains("uitest-conf.example"), "typed rule in the editor")
        let status = app.element(id: "conf.status")
        XCTAssertTrue(status.waitForExistence(timeout: 6), "status line")
        let save = app.navigationBars.buttons[L("保存并重载")]
        XCTAssertTrue(save.waitHittable(), "保存并重载 enabled (status: \(status.label))")
        save.tap()
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.navigationBars[L("编辑配置")])
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 12), .completed, "editor closed after 保存并重载")
        snap("conf-editor-saved")
        assertAlive("conf save")

        // Reopen: the edit is part of the profile's .conf.
        openDemoConfEditor()
        XCTAssertTrue(confEditorText().contains("host-suffix, uitest-conf.example, direct"), "saved rule kept in the .conf")
        snap("conf-editor-reopened")
        if app.navigationBars.buttons[L("取消")].exists { app.navigationBars.buttons[L("取消")].tap() }
        assertAlive("conf reopen")
    }
}
