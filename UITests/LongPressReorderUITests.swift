import XCTest

/// feat/long-press-reorder (user 2026-10-29 「正常情况下没法直接按住拖动吗」): the lists that only
/// reordered in edit mode (排序) now reorder by long-press drag in the normal list — 重写 → 订阅,
/// 分流规则 → 订阅 (the profile's rule sets), and the 节点列表 (whose manual order is a new persisted
/// layer, kept across a relaunch). No test here taps a 排序 button: the drag itself must do it.
extension TernUITests {

    private func lpOrderOf(_ id: String) -> String {
        let e = app.element(id: id)
        return e.waitForExistence(timeout: 4) ? ((e.value as? String) ?? "") : "<missing \(id)>"
    }

    private func lpWaitOrderPrefix(_ id: String, _ prefix: String, timeout: TimeInterval = 10) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if lpOrderOf(id).hasPrefix(prefix) { return true }
            usleep(300_000)
        }
        return false
    }

    /// Long-press (a context-menu preview may lift first; moving the finger hands it to the drag, as on
    /// Home), drag slowly onto the target's upper part and hold. One retry from a different x after
    /// dismissing a menu the first press may have left open.
    private func longPressDrag(_ e: XCUIElement, above target: XCUIElement) -> Bool {
        e.press(forDuration: 1.0, thenDragTo: target.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25)),
                withVelocity: .slow, thenHoldForDuration: 0.8)
        usleep(1_800_000) // drop, or the 1.5 s idle commit
        if isBefore(e, target) { return true }
        warnings.append("[\(Env.tag)] long-press drag retry on \(e.identifier)")
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.06)).tap()
        usleep(700_000)
        e.press(forDuration: 1.0, thenDragTo: target.coordinate(withNormalizedOffset: CGVector(dx: 0.3, dy: 0.2)),
                withVelocity: .slow, thenHoldForDuration: 0.8)
        usleep(1_800_000)
        return isBefore(e, target)
    }

    // MARK: 重写 → 订阅: long-press drag, no 排序 button

    func testLongPress_RewriteModules() {
        launch(["-UITestReorder"])
        openMore("重写")
        let a = app.element(id: "module.row.UITest Panel Module")
        let b = app.element(id: "module.row.UITest Order B")
        XCTAssertTrue(a.waitForExistence(timeout: 8) && b.waitForExistence(timeout: 8), "two subscriptions")
        XCTAssertTrue(lpWaitOrderPrefix("rewrite.subs.order", "UITest Panel Module"), "seed order (\(lpOrderOf("rewrite.subs.order")))")
        XCTAssertTrue(longPressDrag(b, above: a), "B long-press dragged above the panel module")
        XCTAssertTrue(lpWaitOrderPrefix("rewrite.subs.order", "UITest Order B", timeout: 12),
                      "saved order (\(lpOrderOf("rewrite.subs.order")))")
        snap("longpress-rewrite-reordered")
        assertAlive("long-press rewrite reorder")
    }

    // MARK: 分流规则 → 订阅: long-press drag of a profile rule set

    func testLongPress_RuleSets() {
        launch(["-UITestRuleSets"])
        openMore("规则")
        let china = app.element(id: "rules.set.China")
        let fb = app.element(id: "rules.set.Facebook")
        XCTAssertTrue(china.waitForExistence(timeout: 10) && fb.waitForExistence(timeout: 8), "rule sets listed")
        XCTAssertTrue(lpWaitOrderPrefix("rules.sets.order", "China", timeout: 12), "profile order (\(lpOrderOf("rules.sets.order")))")
        XCTAssertTrue(longPressDrag(fb, above: china), "Facebook long-press dragged above China")
        XCTAssertTrue(lpWaitOrderPrefix("rules.sets.order", "Facebook", timeout: 12),
                      "saved order (\(lpOrderOf("rules.sets.order")))")
        snap("longpress-rulesets-reordered")
        assertAlive("long-press rule-set reorder")
    }

    // MARK: 节点列表: long-press drag inside the 配置 section, kept after relaunch

    func testLongPress_Nodes() {
        launch()
        openMore("节点与订阅")
        XCTAssertTrue(tapIfExists(app.element(label: L("全部节点")), timeout: 8), "全部节点")
        let t1 = app.element(labelContains: "Tokyo 01")
        let t2 = app.element(labelContains: "Tokyo 02")
        XCTAssertTrue(t1.waitForExistence(timeout: 10) && t2.waitForExistence(timeout: 8), "profile nodes listed")
        XCTAssertTrue(lpWaitOrderPrefix("nodes.order", "🇯🇵 Tokyo 01", timeout: 10), "source order (\(lpOrderOf("nodes.order")))")
        XCTAssertTrue(longPressDrag(t2, above: t1), "Tokyo 02 long-press dragged above Tokyo 01")
        XCTAssertTrue(lpWaitOrderPrefix("nodes.order", "🇯🇵 Tokyo 02", timeout: 12),
                      "manual order saved (\(lpOrderOf("nodes.order")))")
        snap("longpress-nodes-reordered")
        app.terminate()
        launch(["-UITestKeepData"])
        openMore("节点与订阅")
        XCTAssertTrue(tapIfExists(app.element(label: L("全部节点")), timeout: 8), "全部节点 after relaunch")
        XCTAssertTrue(lpWaitOrderPrefix("nodes.order", "🇯🇵 Tokyo 02", timeout: 12),
                      "manual order kept after relaunch (\(lpOrderOf("nodes.order")))")
        assertAlive("long-press node reorder")
    }
}
