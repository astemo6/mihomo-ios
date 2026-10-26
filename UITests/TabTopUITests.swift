import XCTest

/// fix/app-policy-ui #5b (user 2026-10-26): every tab root has its title in the bar row with its buttons.
/// fix/tab-top-spacing (user 2026-10-22): the five tab roots share one compact top — no large titles (the tab bar
/// names the page), one slim row right under the status bar (system inline bar with the trailing buttons on 策略 /
/// 请求 / 工具 / 更多, the pinned Quantumult X-style exit header on 首页), same gap on every tab. Home's header stays put
/// while the cards scroll under it. Screenshots of every tab, top and scrolled, plus Home at a large Dynamic Type size.
extension MihomoUITests {

    // MARK: 72. Shared tab-root top

    func test72_TabTopShots() {
        launch(["-UITestDemoAnalytics", "-UITestDemoConnections", "-UITestDemoExitIP"])
        XCTAssertEqual(app.tabBars.buttons.count, 5, "five tabs")
        let names = ["home", "policy", "requests", "tools", "more"]
        let titles = ["首页", "策略", "请求", "工具", "更多"]
        var tops: [String: CGFloat] = [:]       // top of the bar row under the status bar
        var barHeights: [String: CGFloat] = [:]
        var titleMid: [String: CGFloat] = [:]   // vertical centre of the drawn title
        var titleLeft: [String: CGFloat] = [:]
        var buttonMid: [String: CGFloat] = [:]  // vertical centre of the first trailing button

        // fix/app-policy-ui #5b (user 2026-10-26): every tab root, 首页 included, shows its title IN the bar row,
        // leading, on the same line as its trailing buttons — no separate large-title row.
        func measure(_ i: Int) {
            let bar = app.navigationBars[L(titles[i])]
            _ = bar.waitForExistence(timeout: 8)
            guard bar.exists else { return }
            tops[names[i]] = bar.frame.minY
            barHeights[names[i]] = bar.frame.height
            let t = bar.staticTexts.matching(NSPredicate(format: "label == %@", L(titles[i]))).firstMatch
            if t.exists { titleMid[names[i]] = t.frame.midY; titleLeft[names[i]] = t.frame.minX }
            let buttons = bar.buttons.allElementsBoundByIndex.filter { $0.exists && $0.frame.minX > bar.frame.midX }
            if let b = buttons.first { buttonMid[names[i]] = b.frame.midY }
        }

        // 首页: bar row + the pinned exit header under it.
        let place = app.element(id: "home.exit.place")
        _ = place.waitForExistence(timeout: 8)
        measure(0)
        snap("tabtop-0-home")
        let powerShown = app.element(id: "home.power").exists
        let placeTop = place.exists ? place.frame.minY : -1
        let homeBarBottom = (tops["home"] ?? 0) + (barHeights["home"] ?? 0)
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        usleep(500_000)
        snap("tabtop-0-home-scrolled")
        let placeTopScrolled = place.exists ? place.frame.minY : -2

        for i in 1..<5 {
            tab(i)
            usleep(700_000)
            measure(i)
            snap("tabtop-\(i)-\(names[i])")
            for _ in 0..<2 { app.swipeUp(velocity: .slow) }
            usleep(500_000)
            snap("tabtop-\(i)-\(names[i])-scrolled")
            app.swipeDown(velocity: .fast)
            usleep(300_000)
        }

        // Large Dynamic Type: header still pinned and readable.
        app.terminate()
        launch(["-UITestDemoAnalytics", "-UITestDemoConnections", "-UITestDemoExitIP",
                "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityL"])
        _ = app.element(id: "home.exit.place").waitForExistence(timeout: 8)
        snap("tabtop-0-home-xl")
        let xlTop = app.element(id: "home.exit.place").frame.minY
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        usleep(500_000)
        snap("tabtop-0-home-xl-scrolled")
        let xlTopScrolled = app.element(id: "home.exit.place").frame.minY
        tab(2)
        usleep(700_000)
        snap("tabtop-2-requests-xl")

        // Checks after all screenshots.
        XCTAssertTrue(place.exists || placeTop >= 0, "pinned exit header on 首页")
        XCTAssertTrue(powerShown, "VPN switch in the header")
        XCTAssertEqual(xlTop, xlTopScrolled, accuracy: 1, "Home header does not scroll away (large text)")
        XCTAssertEqual(placeTop, placeTopScrolled, accuracy: 1, "Home header does not scroll away")
        XCTAssertGreaterThanOrEqual(placeTop, homeBarBottom - 2, "exit header sits under Home's bar row")
        XCTAssertEqual(tops.count, 5, "bar measured on all five tabs: \(tops)")
        if let lo = tops.values.min(), let hi = tops.values.max() {
            XCTAssertLessThanOrEqual(hi - lo, 2, "same bar top on every tab: \(tops)")
        }
        // 请求 / 更多 carry a search drawer inside their bar; compare the bar row on the other three, and the title
        // position on all five.
        let rows = barHeights.filter { $0.key != "requests" && $0.key != "more" }.values
        if let lo = rows.min(), let hi = rows.max() {
            XCTAssertLessThanOrEqual(hi - lo, 2, "same bar row height on 首页 / 策略 / 工具: \(barHeights)")
            XCTAssertLessThan(hi, 80, "no separate large-title row: \(barHeights)")
        }
        XCTAssertEqual(titleMid.count, 5, "title drawn in the bar on all five tabs: \(titleMid)")
        if let lo = titleMid.values.min(), let hi = titleMid.values.max() {
            XCTAssertLessThanOrEqual(hi - lo, 2, "titles on one line across tabs: \(titleMid)")
        }
        if let lo = titleLeft.values.min(), let hi = titleLeft.values.max() {
            XCTAssertLessThanOrEqual(hi - lo, 2, "titles leading-aligned across tabs: \(titleLeft)")
            XCTAssertLessThan(hi, 40, "title is leading, not centred: \(titleLeft)")
        }
        for (k, m) in buttonMid {
            if let t = titleMid[k] { XCTAssertEqual(t, m, accuracy: 8, "\(k): title on the same row as its buttons") }
        }
        XCTAssertNotNil(buttonMid["home"], "首页 has a trailing button (+) in its bar")
    }
}
