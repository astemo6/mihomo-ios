import XCTest

/// feat/policy-chain (Egern 策略): each 策略 card's subtitle is the whole path down to the final node, the final node
/// with its flag — 「日本节点 › 🇯🇵 东京 AZ JP01」; DIRECT / REJECT plainly; a new selection updates every card on the
/// path at once. Seed: -UITestPolicyChain (UITestSeed.policyChainYAML, offline — servers on 192.0.2.x).
extension MihomoUITests {

    private func chainLabel(_ group: String) -> String {
        let e = app.element(id: "policy.chain." + group)
        return e.waitForExistence(timeout: 4) ? e.label : "<missing>"
    }

    private func waitChain(_ group: String, _ expected: String, timeout: TimeInterval = 6) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if chainLabel(group) == expected { return true }
            usleep(400_000)
        }
        return false
    }

    // MARK: 64. 策略: chain subtitles

    func test51_PolicyChainShots() {
        launch(["-UITestPolicyChain"])
        tab(1)
        let top = app.element(id: "policy.card.节点选择")
        XCTAssertTrue(top.waitForExistence(timeout: 12), "节点选择 card")
        func seg(_ k: String) -> XCUIElement { app.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch }
        let mode = app.element(id: "policy.mode")
        XCTAssertTrue(scrollTo(mode), "mode picker")
        XCTAssertTrue(tapIfExists(seg("规则"), timeout: 4), "规则")
        usleep(500_000)

        let sep = " › "
        XCTAssertTrue(waitChain("节点选择", "日本节点" + sep + "🇯🇵 东京 AZ JP01"), "节点选择 chain (got \(chainLabel("节点选择")))")
        XCTAssertEqual(chainLabel("流媒体"), "节点选择" + sep + "日本节点" + sep + "🇯🇵 东京 AZ JP01", "three hops")
        XCTAssertEqual(chainLabel("日本节点"), "🇯🇵 东京 AZ JP01", "a node: flag from its name")
        snap("policy-chain")

        XCTAssertTrue(scrollTo(app.element(id: "policy.card.故障转移")), "故障转移 card")
        XCTAssertEqual(chainLabel("故障转移"), "🇺🇸 洛杉矶 US01", "a name that already has its flag keeps it, no second flag")
        XCTAssertTrue(scrollTo(app.element(id: "policy.card.广告拦截")), "广告拦截 card")
        XCTAssertEqual(chainLabel("国内直连"), "DIRECT", "DIRECT plainly")
        XCTAssertEqual(chainLabel("广告拦截"), "REJECT", "REJECT plainly")
        snap("policy-chain-builtins")

        // A new selection in 日本节点 updates 日本节点, 节点选择 and 流媒体 together.
        let japan = app.element(id: "policy.card.日本节点")
        XCTAssertTrue(scrollTo(japan), "日本节点 card")
        japan.tap() // expand
        let osaka = app.element(id: "policy.member.日本节点.大阪 JP02.delay")
        XCTAssertTrue(osaka.waitForExistence(timeout: 6), "expanded: 大阪 JP02")
        osaka.tap()
        XCTAssertTrue(waitChain("日本节点", "🇯🇵 大阪 JP02"), "日本节点 follows the tap (got \(chainLabel("日本节点")))")
        XCTAssertTrue(scrollTo(top), "节点选择 card again")
        XCTAssertTrue(waitChain("节点选择", "日本节点" + sep + "🇯🇵 大阪 JP02"), "节点选择 follows (got \(chainLabel("节点选择")))")
        XCTAssertEqual(chainLabel("流媒体"), "节点选择" + sep + "日本节点" + sep + "🇯🇵 大阪 JP02", "流媒体 follows")
        snap("policy-chain-updated")

        // Put the seed selection back (the profile keeps offline selections).
        XCTAssertTrue(scrollTo(japan), "日本节点 card, restore")
        let tokyo = app.element(id: "policy.member.日本节点.东京 AZ JP01.delay")
        if tokyo.waitForExistence(timeout: 3) { tokyo.tap() }
        assertAlive("policy chain")
    }
}
