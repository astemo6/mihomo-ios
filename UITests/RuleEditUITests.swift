import XCTest

/// User 2026-10-23 「Final 指向无法修改」「本地规则点进去无法修改」: 规则 → Final opens a policy picker; 本地规则 →
/// 配置规则 rows are edited / 停用 / 删除 like 自定义 rows. Both are overrides (provider-overrides.json), the profile
/// file is not touched, and 恢复配置原样 undoes them.
extension TernUITests {

    func waitLabel(_ e: XCUIElement, contains s: String, _ want: Bool = true, timeout: TimeInterval = 8) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if e.exists && e.label.contains(s) == want { return true }
            usleep(300_000)
        }
        return false
    }

    func waitValue(_ e: XCUIElement, _ v: String, timeout: TimeInterval = 8) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if e.exists, (e.value as? String) == v { return true }
            usleep(300_000)
        }
        return false
    }

    func test91_ProfileRuleAndFinalEdit() {
        launch()
        openMore("规则")
        // Final: tap → picker (groups, built-ins, nodes) → DIRECT → 保存.
        let final = app.element(id: "rules.final")
        XCTAssertTrue(final.waitForExistence(timeout: 10), "Final row")
        XCTAssertTrue(waitLabel(final, contains: "DIRECT", false), "demo Final is the Final group")
        final.tap()
        let direct = app.element(id: "policy.pick.DIRECT")
        XCTAssertTrue(direct.waitForExistence(timeout: 8), "picker lists DIRECT")
        XCTAssertTrue(app.element(id: "policy.pick.Proxy").exists, "picker lists the groups")
        XCTAssertTrue(app.element(id: "policy.pick.REJECT-DROP").exists, "picker lists the built-in policies")
        snap("final-picker")
        direct.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "policy.save"), timeout: 4), "保存")
        XCTAssertTrue(waitLabel(final, contains: "DIRECT"), "Final shows DIRECT")
        snap("final-direct")
        // 恢复配置原样
        final.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "policy.restore"), timeout: 6), "恢复配置原样 in the picker")
        XCTAssertTrue(waitLabel(final, contains: "DIRECT", false), "Final back to the profile's")

        // 本地规则 → 配置规则: tap → 编辑规则, the edit shows in place.
        app.element(id: "rules.local").tap()
        let row0 = app.element(id: "rules.profile.row.0")
        XCTAssertTrue(row0.waitForExistence(timeout: 10), "first profile rule")
        snap("profile-rules")
        row0.tap()
        XCTAssertTrue(app.navigationBars[L("编辑规则")].waitForExistence(timeout: 6), "编辑规则 sheet")
        typeRuleText("DOMAIN-SUFFIX,apple.com,DIRECT")
        let save = app.element(id: "rule.save")
        XCTAssertTrue(save.waitHittable(), "保存 enabled")
        save.tap()
        XCTAssertTrue(app.element(id: "rules.modified").waitForExistence(timeout: 8), "edited rule marked 已修改")
        XCTAssertTrue(app.element(id: "rules.profile.row.0").waitForExistence(timeout: 4), "edited rule keeps its place")
        snap("profile-rule-edited")

        // The switch is 停用.
        let sw = app.element(id: "rules.profile.toggle.1")
        XCTAssertTrue(sw.waitForExistence(timeout: 5), "switch on the profile rule")
        toggleSwitch(sw)
        XCTAssertTrue(waitValue(sw, "0"), "rule switched off")
        snap("profile-rule-off")

        // Leave and come back: both are read from the override store again.
        back()
        app.element(id: "rules.local").tap()
        XCTAssertTrue(app.element(id: "rules.modified").waitForExistence(timeout: 8), "edit persisted")
        XCTAssertTrue(waitValue(app.element(id: "rules.profile.toggle.1"), "0"), "停用 persisted")

        // Left swipe 删除 asks first; the row goes, 恢复已删除的规则 brings it back.
        let row2 = app.element(id: "rules.profile.row.2")
        XCTAssertTrue(row2.waitForExistence(timeout: 5))
        XCTAssertTrue(reveal(row2, left: true, action: "删除"), "删除 in the trailing swipe")
        XCTAssertTrue(app.button(L("编辑")).exists, "编辑 in the trailing swipe")
        app.button(L("删除")).tap()
        let confirm = app.element(id: "rules.confirmDeleteProfileRule")
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "delete confirmation")
        confirm.tap()
        let restoreDeleted = app.element(id: "rules.restoreDeletedProfileRules")
        XCTAssertTrue(restoreDeleted.waitForExistence(timeout: 8), "恢复已删除的规则")
        XCTAssertFalse(app.element(id: "rules.profile.row.2").exists, "deleted rule hidden")
        snap("profile-rule-deleted")
        restoreDeleted.tap()
        XCTAssertTrue(app.element(id: "rules.profile.row.2").waitForExistence(timeout: 8), "deleted rule restored")

        // ⋯ → 全部恢复配置原样
        XCTAssertTrue(tapIfExists(app.element(id: "rules.profile.more"), timeout: 4), "⋯ menu")
        XCTAssertTrue(tapIfExists(app.button(L("全部恢复配置原样")), timeout: 4), "全部恢复配置原样")
        XCTAssertTrue(tapIfExists(app.button(L("恢复")), timeout: 4), "confirm 恢复")
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline && app.element(id: "rules.modified").exists { usleep(300_000) }
        XCTAssertFalse(app.element(id: "rules.modified").exists, "no edited rule left")
        XCTAssertTrue(waitValue(app.element(id: "rules.profile.toggle.1"), "1"), "rule on again")
        snap("profile-rules-restored")
        assertAlive("profile rule edit")
    }
}
