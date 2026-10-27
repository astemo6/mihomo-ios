import XCTest

/// hotfix/group-test-offline (device v0.19.13-build206 「未开启状态下，策略里，节点选择点测速无反应」): offline, 测速 on a
/// select group whose members are all groups runs (spinner), measures the nodes behind them and shows each member
/// group's delay and current node; a group with nothing to dial says so; GLOBAL in 全局 does the same.
/// Seed: -UITestGroupsOnly (UITestSeed.groupsOnlyYAML; nodes on 192.0.2.x never answer, so results are timeouts —
/// real measurements, not 「—」).
extension TernUITests {

    private func memberDelay(_ group: String, _ member: String) -> XCUIElement {
        app.element(id: "policy.member.\(group).\(member).delay")
    }

    private func waitMeasured(_ e: XCUIElement, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if e.exists, !e.label.isEmpty, e.label != "—" { return true }
            usleep(500_000)
        }
        return false
    }

    // MARK: 62. 策略 (offline): 测速 on a group of groups

    func test62_GroupTestNestedOffline() {
        launch(["-UITestGroupsOnly"])
        tab(1)
        let card = app.element(id: "policy.card.Node Select")
        XCTAssertTrue(card.waitForExistence(timeout: 12), "Node Select card")
        XCTAssertTrue(app.element(labelContains: L("未连接")).exists, "offline list (未连接)")
        func seg(_ k: String) -> XCUIElement { app.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch }
        let mode = app.element(id: "policy.mode")
        XCTAssertTrue(scrollTo(mode), "mode picker")
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "规则")
        usleep(500_000)

        XCTAssertTrue(scrollTo(card), "Node Select card on screen")
        card.tap() // expand
        let japan = memberDelay("Node Select", "Japan")
        XCTAssertTrue(japan.waitForExistence(timeout: 6), "expanded: member group Japan")
        XCTAssertEqual(japan.label, "—", "nothing measured before the test")

        let test = app.element(id: "policy.test.Node Select")
        XCTAssertTrue(test.exists, "测速 button of Node Select")
        test.tap()
        XCTAssertTrue(app.activityIndicators.firstMatch.waitForExistence(timeout: 3), "测速 shows the spinner")
        snap("grptest-running")
        XCTAssertTrue(waitMeasured(japan, timeout: 60), "Japan shows a measured delay (got \(japan.label))")
        XCTAssertTrue(waitMeasured(memberDelay("Node Select", "Auto Select"), timeout: 10), "Auto Select measured")
        XCTAssertTrue(waitMeasured(memberDelay("Node Select", "Failover"), timeout: 10), "Failover measured")
        XCTAssertEqual(memberDelay("Node Select", "Direct Only").label, "—", "DIRECT is never measured")
        let via = app.element(id: "policy.member.Node Select.Japan.via")
        XCTAssertTrue(via.exists && via.label.contains("GT Tokyo A"), "Japan shows the node it is on (got \(via.label))")
        // feat/policy-chain: the header shows the whole path (Auto Select › 🇯🇵 GT Tokyo A) instead of 「→ node」.
        let chain = app.element(id: "policy.chain.Node Select")
        XCTAssertTrue(chain.exists && chain.label.contains("Auto Select › ") && chain.label.contains("GT Tokyo A"),
                      "header names the path Node Select resolves to (got \(chain.label))")
        snap("grptest-done")

        // A group with nothing to dial says so instead of doing nothing.
        let directTest = app.element(id: "policy.test.Direct Only")
        XCTAssertTrue(scrollTo(directTest), "测速 button of Direct Only")
        directTest.tap()
        XCTAssertTrue(app.element(id: "policy.notice").waitForExistence(timeout: 4), "「没有可测速的节点」 notice")
        snap("grptest-notice")

        // 全局: GLOBAL (synthesized) expands its groups the same way.
        XCTAssertTrue(scrollTo(mode), "mode picker again")
        XCTAssertTrue(tapIfExists(seg("全局"), timeout: 4), "全局")
        let global = app.element(id: "policy.card.GLOBAL")
        XCTAssertTrue(global.waitForExistence(timeout: 6), "全局: GLOBAL card")
        global.tap()
        let gTest = app.element(id: "policy.test.GLOBAL")
        XCTAssertTrue(gTest.exists, "测速 button of GLOBAL")
        gTest.tap()
        XCTAssertTrue(app.activityIndicators.firstMatch.waitForExistence(timeout: 3), "GLOBAL 测速 shows the spinner")
        let gMember = memberDelay("GLOBAL", "Node Select")
        XCTAssertTrue(scrollTo(gMember), "GLOBAL lists Node Select")
        XCTAssertTrue(waitMeasured(gMember, timeout: 60), "GLOBAL: Node Select shows a measured delay (got \(gMember.label))")
        snap("grptest-global")

        XCTAssertTrue(scrollTo(mode), "mode picker, back")
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "back to 规则")
        assertAlive("group test offline")
    }
}
