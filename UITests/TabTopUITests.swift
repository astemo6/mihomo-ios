import XCTest

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
        var tops: [String: CGFloat] = [:]     // top of the first row under the status bar
        var barHeights: [String: CGFloat] = [:]

        // 首页: pinned header.
        let place = app.element(id: "home.exit.place")
        _ = place.waitForExistence(timeout: 8)
        snap("tabtop-0-home")
        if place.exists { tops["home"] = place.frame.minY }
        let power = app.element(id: "home.power")
        let placeTop = place.exists ? place.frame.minY : -1
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        usleep(500_000)
        snap("tabtop-0-home-scrolled")
        let placeTopScrolled = place.exists ? place.frame.minY : -2

        for i in 1..<5 {
            tab(i)
            usleep(700_000)
            let bar = app.navigationBars[L(titles[i])]
            _ = bar.waitForExistence(timeout: 8)
            snap("tabtop-\(i)-\(names[i])")
            if bar.exists { tops[names[i]] = bar.frame.minY; barHeights[names[i]] = bar.frame.height }
            for _ in 0..<2 { app.swipeUp(velocity: .slow) }
            usleep(500_000)
            snap("tabtop-\(i)-\(names[i])-scrolled")
            app.swipeDown(velocity: .fast)
            usleep(300_000)
        }

        // Large Dynamic Type: header still pinned and readable, bars still slim.
        app.terminate()
        launch(["-UITestDemoAnalytics", "-UITestDemoConnections", "-UITestDemoExitIP",
                "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityL"])
        _ = app.element(id: "home.exit.place").waitForExistence(timeout: 8)
        snap("tabtop-0-home-xl")
        tab(2)
        usleep(700_000)
        snap("tabtop-2-requests-xl")

        // Checks after all screenshots (the same test also documents the old layout).
        XCTAssertTrue(place.exists || tops["home"] != nil, "pinned exit header on 首页")
        XCTAssertTrue(power.exists || app.element(id: "home.power").exists, "VPN switch in the header")
        XCTAssertEqual(placeTop, placeTopScrolled, accuracy: 1, "Home header does not scroll away")
        for n in ["policy", "requests", "tools", "more"] {
            XCTAssertNotNil(barHeights[n], "\(n): navigation bar")
            if let h = barHeights[n] { XCTAssertLessThan(h, 60, "\(n): no large title (bar \(h) pt)") }
        }
        let values = tops.values
        if let lo = values.min(), let hi = values.max() {
            XCTAssertLessThanOrEqual(hi - lo, 12, "same top on every tab: \(tops)")
        }
        XCTAssertEqual(tops.count, 5, "top measured on all five tabs: \(tops)")
    }
}
