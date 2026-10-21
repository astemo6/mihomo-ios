import XCTest

/// feat/egern-style (user 2026-10-21 「所以你的整体风格可向它看齐」): the whole app in Egern's compact style. This test
/// walks the main screens for review screenshots and checks the new Egern pieces: the 启动 capsule on Home, the
/// 出站模式 menu row, the compact policy rows with the chain subtitle, and the five tabs still in place.
extension MihomoUITests {

    // MARK: 65. Egern style screenshots

    func test65_EgernShots() {
        // Home with the synthetic analysis data (VPN off in the simulator).
        launch(["-UITestDemoAnalytics"])
        XCTAssertEqual(app.tabBars.buttons.count, 5, "five tabs kept")
        let power = app.element(id: "home.power")
        XCTAssertTrue(power.waitForExistence(timeout: 8), "启动 capsule in the navigation bar")
        XCTAssertEqual(power.label, L("启动"), "capsule says 启动 while off")
        snap("egern-01-home-top")
        let mode = app.element(id: "home.mode")
        XCTAssertTrue(scrollTo(mode), "出站模式 row")
        snap("egern-02-home-mode")
        XCTAssertTrue(scrollTo(app.element(id: "home.analysis.policies")), "策略 analysis")
        snap("egern-03-home-scrolled")
        XCTAssertTrue(scrollTo(app.element(id: "home.analysis.hosts")), "主机名")
        snap("egern-04-home-bottom")

        // 请求
        tab(2)
        usleep(600_000)
        snap("egern-05-requests")

        // 工具
        tab(3)
        XCTAssertTrue(app.navigationBars[L("工具")].waitForExistence(timeout: 8), "工具")
        snap("egern-06-tools")
        for _ in 0..<3 { app.swipeUp(velocity: .slow) }
        snap("egern-07-tools-2")
        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)

        // 节点与订阅
        let nodes = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(nodes), "节点与订阅 card")
        nodes.tap()
        usleep(1_000_000)
        snap("egern-08-nodes")
        back()

        // 更多 + 高级设置
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 8), "更多")
        snap("egern-09-more")
        for _ in 0..<3 { app.swipeUp(velocity: .slow) }
        snap("egern-10-more-2")
        let adv = app.element(id: "more.高级设置")
        XCTAssertTrue(scrollTo(adv), "高级设置")
        adv.tap()
        XCTAssertTrue(app.navigationBars[L("高级设置")].waitForExistence(timeout: 5), "高级设置 page")
        snap("egern-11-advanced")
        back()

        // 策略 with the chain seed: collapsed rows, then one expanded.
        app.terminate()
        launch(["-UITestPolicyChain"])
        tab(1)
        let top = app.element(id: "policy.card.节点选择")
        XCTAssertTrue(top.waitForExistence(timeout: 12), "节点选择 row")
        let chain = app.element(id: "policy.chain.流媒体")
        XCTAssertTrue(chain.waitForExistence(timeout: 6), "chain subtitle")
        XCTAssertTrue(chain.label.hasSuffix("JP01"), "chain keeps the final node (got \(chain.label))")
        snap("egern-12-policy")
        let japan = app.element(id: "policy.card.日本节点")
        XCTAssertTrue(scrollTo(japan), "日本节点 row")
        japan.tap()
        XCTAssertTrue(app.element(id: "policy.member.日本节点.大阪 JP02.delay").waitForExistence(timeout: 6), "expanded")
        snap("egern-13-policy-expanded")
        japan.tap()
        assertAlive("egern shots")
    }
}
