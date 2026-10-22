import XCTest

/// feat/home-drilldown (user 2026-10-22 「空有其表」): every Home card opens a real page, like Egern's 分析.
/// Demo data: -UITestDemoAnalytics (synthetic ConnectionAnalytics, example.* hosts: 20 open + 99 closed connections,
/// a synthetic 网络 sample stretch with one gap); -UITestDemoExitIP for the 出口 IP tile.
extension MihomoUITests {

    /// A Home element by id, or by a label fragment when an enclosing identifier took over the id.
    func homeElement(id: String, label: String? = nil) -> XCUIElement {
        let byID = app.element(id: id)
        if byID.waitForExistence(timeout: 1.5) || label == nil { return byID }
        return app.buttons.matching(NSPredicate(format: "label CONTAINS %@", label!)).firstMatch
    }

    func assertNavBar(_ title: String, _ step: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(app.navigationBars[title].waitForExistence(timeout: 8), "\(step): page 「\(title)」", file: file, line: line)
    }

    func chipValue(_ id: String) -> String {
        let e = app.element(id: id)
        guard e.waitForExistence(timeout: 4) else { return "missing" }
        return (e.value as? String) ?? ""
    }

    // MARK: 90. Home cards → destinations

    func test90_HomeDrillDown() {
        launch(["-UITestDemoAnalytics", "-UITestDemoExitIP"])
        addAnalysisPanels(["policies", "rules", "hosts", "dns"])

        // 全部连接 → 连接 (no filter), row → detail (摘要 / 请求 / 响应).
        let all = homeElement(id: "home.analysis.connections.all", label: L("全部连接"))
        XCTAssertTrue(scrollTo(all), "全部连接 tile")
        snap("drill-00-home")
        all.tap()
        assertNavBar(L("连接"), "全部连接")
        XCTAssertEqual(chipValue("connlist.chip.active"), "0", "全部连接: 活跃 off")
        XCTAssertTrue(app.element(id: "connlist.row").waitForExistence(timeout: 6), "connections listed")
        snap("drill-01-connections-all")
        app.element(id: "connlist.row").tap()
        XCTAssertTrue(app.element(id: "conndetail.tabs").waitForExistence(timeout: 6), "connection detail tabs")
        snap("drill-02-connection-summary")
        let reqTab = app.segmentedControls.buttons[L("请求")].firstMatch
        if reqTab.waitForExistence(timeout: 3) {
            reqTab.tap()
            XCTAssertTrue(app.element(id: "conndetail.http.none").waitForExistence(timeout: 6), "请求 tab says when nothing was captured")
            snap("drill-03-connection-request")
        } else {
            issues.append("[\(Env.tag)] 请求 segment not found")
        }
        back(); back()

        // 活跃连接 → 连接 with 活跃 on.
        let active = homeElement(id: "home.analysis.connections.active", label: L("活跃连接"))
        XCTAssertTrue(scrollTo(active), "活跃连接 tile")
        active.tap()
        assertNavBar(L("连接"), "活跃连接")
        XCTAssertEqual(chipValue("connlist.chip.active"), "1", "活跃连接: 活跃 on")
        XCTAssertTrue(app.element(id: "connlist.row").waitForExistence(timeout: 6), "active connections listed")
        snap("drill-04-connections-active")
        back()

        // 网络 speed card → 网络 (秒 / 分钟 / 小时, scrub).
        let net = app.element(id: "home.network")
        XCTAssertTrue(scrollTo(net), "网络 card")
        net.tap()
        assertNavBar(L("网络"), "网络 card")
        XCTAssertTrue(app.element(id: "network.scale").waitForExistence(timeout: 4), "秒 / 分钟 / 小时")
        let chart = app.element(id: "network.chart")
        XCTAssertTrue(chart.waitForExistence(timeout: 6), "chart")
        snap("drill-05-network-seconds")
        chart.coordinate(withNormalizedOffset: CGVector(dx: 0.55, dy: 0.5))
            .press(forDuration: 0.2, thenDragTo: chart.coordinate(withNormalizedOffset: CGVector(dx: 0.7, dy: 0.5)))
        if app.element(id: "network.clearSelection").waitForExistence(timeout: 3) {
            snap("drill-06-network-scrub")
        } else {
            issues.append("[\(Env.tag)] 网络: scrub did not select a point")
        }
        let minutes = app.segmentedControls.buttons[L("分钟")].firstMatch
        if minutes.waitForExistence(timeout: 3) { minutes.tap(); usleep(500_000); snap("drill-07-network-minutes") }
        back()

        // 总上传 / 总下载 → 流量统计.
        let totals = app.element(id: "home.totals")
        XCTAssertTrue(scrollTo(totals), "totals")
        totals.tap()
        assertNavBar(L("流量统计"), "totals")
        snap("drill-08-stats")
        back()

        // 策略 → 策略流量 → one policy's connections.
        let pol = app.element(id: "home.analysis.policies")
        XCTAssertTrue(scrollTo(pol), "策略 card")
        pol.tap()
        assertNavBar(L("策略流量"), "策略 card")
        let proxyRow = app.element(id: "policytraffic.row.Proxy")
        XCTAssertTrue(proxyRow.waitForExistence(timeout: 6), "Proxy row")
        snap("drill-09-policy-traffic")
        proxyRow.tap()
        assertNavBar("Proxy", "policy row")
        XCTAssertEqual(chipValue("connlist.chip.policies"), "1", "filtered by the policy")
        XCTAssertTrue(app.element(id: "connlist.row").waitForExistence(timeout: 6), "Proxy connections")
        snap("drill-10-policy-connections")
        back(); back()

        // 规则 ring → 连接 filtered by that rule; the rule sheet shows 「已选择 1 项」.
        let ring = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "GeoIP(CN)")).firstMatch
        XCTAssertTrue(scrollTo(ring), "GeoIP rule ring")
        ring.tap()
        assertNavBar(L("连接"), "rule ring")
        XCTAssertEqual(chipValue("connlist.chip.rules"), "1", "filtered by the rule")
        XCTAssertTrue(app.element(id: "connlist.row").waitForExistence(timeout: 6), "rule connections")
        snap("drill-11-rule-connections")
        app.element(id: "connlist.chip.rules").tap()
        let picked = L10n.f("已选择 %lld 项", 1)
        XCTAssertTrue(app.navigationBars[picked].waitForExistence(timeout: 5), "rule sheet 「\(picked)」")
        snap("drill-12-rule-sheet")
        closeSheet()
        back()

        // 主机名 → 主机名 (↑↓) → one host's connections.
        let hosts = app.element(id: "home.analysis.hosts")
        XCTAssertTrue(scrollTo(hosts), "主机名 card")
        hosts.tap()
        assertNavBar(L("主机名"), "主机名 card")
        let hostRow = app.element(id: "hosttraffic.row.video.example.com")
        XCTAssertTrue(hostRow.waitForExistence(timeout: 6), "host row")
        snap("drill-13-hosts")
        hostRow.tap()
        assertNavBar("video.example.com", "host row")
        XCTAssertTrue(app.element(id: "connlist.chip.host").waitForExistence(timeout: 4), "host chip")
        XCTAssertTrue(app.element(id: "connlist.row").waitForExistence(timeout: 6), "host connections")
        snap("drill-14-host-connections")
        back(); back()

        // DNS → DNS 日志.
        let dns = app.element(id: "home.analysis.dns")
        XCTAssertTrue(scrollTo(dns), "DNS card")
        snap("drill-15-dns-card")
        dns.tap()
        assertNavBar(L("DNS 日志"), "DNS card")
        snap("drill-16-dns-log")
        back()

        // Built-in tiles → their pages.
        let add = app.element(id: "home.addTiles")
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor")
        for t in ["speed", "traffic", "uptime", "exitip", "memory"] {
            let b = app.element(id: "homepanels.add." + t)
            if scrollTo(b, fail: false) { b.tap(); usleep(300_000) } else { issues.append("[\(Env.tag)] add tile \(t) not found") }
        }
        closeSheet()
        func tile(_ t: String) -> XCUIElement {
            app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile." + t)).firstMatch
        }
        for (t, title) in [("speed", "网络"), ("traffic", "流量统计"), ("uptime", "日志"), ("memory", "诊断")] {
            let e = tile(t)
            XCTAssertTrue(scrollTo(e), "tile \(t)")
            if t == "speed" { snap("drill-17-tiles") }
            e.tap()
            assertNavBar(L(title), "tile \(t)")
            snap("drill-tile-\(t)")
            back()
        }
        let detail = app.buttons.matching(NSPredicate(format: "label == %@", L("详情"))).firstMatch
        XCTAssertTrue(scrollTo(detail), "出口 IP 详情 button")
        detail.tap()
        assertNavBar(L("出口 IP"), "出口 IP tile")
        snap("drill-tile-exitip")
        back()
        assertAlive("home drill-down")
    }
}
