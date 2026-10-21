import XCTest

/// feat/home-analysis (Egern 分析 on 首页): 全部连接 / 活跃连接 → 网络 → 策略 → 规则 → 主机名 on Home, a floating +
/// quick-add menu, and the empty state while the VPN is off. Demo data (-UITestDemoAnalytics) is a private synthetic
/// ConnectionAnalytics (example.* hosts), never the live session.
extension MihomoUITests {

    // MARK: 64. Home analysis + quick add

    func test64_HomeAnalysis() {
        launch(["-UITestDemoAnalytics"])
        let tiles = app.element(id: "home.analysis.connections")
        XCTAssertTrue(scrollTo(tiles), "全部连接 / 活跃连接 tiles")
        XCTAssertTrue(app.element(labelContains: L("全部连接")).exists, "全部连接")
        XCTAssertTrue(app.element(id: "home.section.network").exists, "网络 label")
        snap("home-analysis-1-top")

        let policies = app.element(id: "home.analysis.policies")
        XCTAssertTrue(scrollTo(policies), "策略 card")
        XCTAssertTrue(app.element(labelContains: "Proxy").exists, "policy legend")
        snap("home-analysis-2-policies")

        let rules = app.element(id: "home.analysis.rules")
        XCTAssertTrue(scrollTo(rules), "规则 rings")
        let hosts = app.element(id: "home.analysis.hosts")
        XCTAssertTrue(scrollTo(hosts), "主机名 card")
        XCTAssertTrue(app.element(labelContains: "video.example.com").exists, "top hostname")
        snap("home-analysis-3-rules-hosts")

        // Collapse 主机名 from its label, then expand again.
        let hostsHeader = app.element(id: "home.analysis.header.hosts")
        XCTAssertTrue(scrollTo(hostsHeader), "主机名 header")
        hostsHeader.tap()
        usleep(600_000)
        XCTAssertFalse(app.element(id: "home.analysis.hosts").exists, "主机名 collapsed")
        hostsHeader.tap()
        usleep(600_000)
        XCTAssertTrue(app.element(id: "home.analysis.hosts").waitForExistence(timeout: 3), "主机名 expanded")

        // Floating + → quick-add menu (Egern style).
        let plus = app.element(id: "home.quickAdd")
        XCTAssertTrue(plus.waitForExistence(timeout: 5), "floating +")
        plus.tap()
        let addSub = app.buttons[L("添加订阅")].firstMatch
        XCTAssertTrue(addSub.waitForExistence(timeout: 4), "添加订阅 item")
        for k in ["扫描添加节点", "添加节点", "添加规则", "导入配置"] {
            XCTAssertTrue(app.buttons[L(k)].firstMatch.exists, "\(k) item")
        }
        snap("home-analysis-4-quickadd")
        addSub.tap()
        XCTAssertTrue(app.navigationBars[L("添加订阅")].waitForExistence(timeout: 5), "添加订阅 sheet (AddRemoteSheet)")
        closeSheet()

        plus.tap()
        let addNode = app.buttons[L("添加节点")].firstMatch
        XCTAssertTrue(addNode.waitForExistence(timeout: 4), "添加节点 item")
        addNode.tap()
        XCTAssertTrue(app.buttons[L("扫描二维码")].waitForExistence(timeout: 5), "添加节点 page (AddNodeView)")
        closeSheet()
        assertAlive("home analysis")

        // VPN off without demo data: one empty state, no fake numbers.
        app.terminate()
        launch()
        let empty = app.element(id: "home.analysis.empty")
        XCTAssertTrue(scrollTo(empty), "empty state while disconnected")
        XCTAssertFalse(app.element(id: "home.analysis.connections").exists, "no connection tiles while off")
        snap("home-analysis-5-empty")
    }
}
