import XCTest

/// fix/nc-ui-smooth: transition smoothness, measured in the simulator.
///
/// - testA / testB: the in-app scripted scenario (App/Core/UIPerfProbe.swift, `-UIPerfProbe -UIPerfScenario`): tab
///   switches, 出站模式 on 策略 and 首页, offline node selection, Home layout edits. The app counts late frames with a
///   CADisplayLink while this process stays idle (an XCUITest query runs on the app's main thread and would show up
///   as a hitch itself). Numbers go to the report as `[perf] …` lines (printed in the job log) and to an attachment.
/// - testC: push / pop and policy group expand with XCTOSSignpostMetric (navigation transition, scroll deceleration)
///   and the same probe around each tap.
/// Nothing here asserts a frame budget (simulator timing varies per runner); the tests fail only when a step is
/// missing or the app died, so before / after numbers can be compared run by run.
final class UISmoothPerfUITests: MihomoUITestCase {

    private func probeLabel() -> String {
        let e = app.element(id: "uiperf.probe")
        guard e.waitForExistence(timeout: 10) else { return "" }
        return e.label
    }

    private func record(_ title: String, _ summary: String) {
        let lines = summary.split(separator: "\n").map(String.init)
        for l in lines { warnings.append("[perf] \(title) \(l.hasPrefix("SUM ") || l.hasPrefix("state=") ? l : "STEP " + l)") }
        print("UIPERF \(title)\n\(summary)")
        let att = XCTAttachment(string: summary)
        att.name = "uiperf-\(title)"
        att.lifetime = .keepAlways
        add(att)
    }

    private func runScenario(_ title: String, extra: [String], timeout: TimeInterval) {
        launch(extra + ["-UIPerfProbe", "-UIPerfScenario"])
        // Stay idle while the app runs the scenario; look only every 10 s.
        let deadline = Date().addingTimeInterval(timeout)
        var summary = ""
        sleep(20)
        while Date() < deadline {
            summary = probeLabel()
            if summary.hasPrefix("state=done") { break }
            sleep(10)
        }
        record(title, summary)
        XCTAssertTrue(summary.hasPrefix("state=done"), "scenario did not finish: \(summary.prefix(200))")
        assertAlive("scenario \(title)")
    }

    func testA_ScenarioDemoProfile() {
        runScenario("demo", extra: [], timeout: 180)
    }

    func testB_ScenarioBigProfile() {
        // 3000 nodes in one select group, 10000 rules, +1500 manual nodes (same seed as test39).
        runScenario("big", extra: ["-UITestBigProfile"], timeout: 300)
    }

    /// Hitch counters (frames, hitches, hitch ms) parsed from the first summary line.
    private func totals() -> (hitches: Int, hitchMs: Int) {
        let first = probeLabel().split(separator: "\n").first.map(String.init) ?? ""
        var h = 0, ms = 0
        for part in first.split(separator: "|") {
            let kv = part.split(separator: "=")
            guard kv.count == 2 else { continue }
            if kv[0] == "hitches" { h = Int(kv[1]) ?? 0 }
            if kv[0] == "hitchMs" { ms = Int(kv[1]) ?? 0 }
        }
        return (h, ms)
    }

    /// Probe delta around `body` (includes the cost of the XCUITest queries inside it, the same before and after).
    private func probed(_ name: String, _ body: () -> Void) {
        let a = totals()
        body()
        sleep(1)
        let b = totals()
        warnings.append("[perf] probe STEP \(name) hitches=\(b.hitches - a.hitches) hitchMs=\(b.hitchMs - a.hitchMs)")
    }

    func testC_PushPopAndExpand() {
        launch(["-UIPerfProbe", "-UITestBigProfile"])
        // Push / pop: 更多 → 高级设置 (a page with several sections).
        tab(4)
        let row = app.element(id: "more.高级设置")
        XCTAssertTrue(scrollTo(row), "高级设置 row")
        for i in 0..<3 {
            probed("push-pop:\(i)") {
                row.tap()
                XCTAssertTrue(app.navigationBars[L("高级设置")].waitForExistence(timeout: 8), "高级设置 pushed")
                back()
                XCTAssertTrue(row.waitForExistence(timeout: 8), "back on 更多")
            }
        }
        let opts = XCTMeasureOptions()
        opts.iterationCount = 3
        opts.invocationOptions = [.manuallyStop]
        measure(metrics: [XCTOSSignpostMetric.navigationTransitionMetric], options: opts) {
            row.tap()
            _ = app.navigationBars[L("高级设置")].waitForExistence(timeout: 8)
            stopMeasuring()
            back()
            _ = row.waitForExistence(timeout: 8)
        }

        // 策略 with the 3000-member group: expand / collapse the card, then fling the list.
        tab(1)
        let header = app.element(id: "policy.card.Big Select")
        XCTAssertTrue(header.waitForExistence(timeout: 20), "big group on 策略")
        for i in 0..<2 {
            probed("expand:\(i)") {
                header.tap()
                XCTAssertTrue(app.element(id: "policy.member.Big Select.Big 00000.delay").waitForExistence(timeout: 15), "members shown")
            }
            probed("collapse:\(i)") {
                header.tap()
                sleep(1)
            }
        }
        header.tap()
        _ = app.element(id: "policy.member.Big Select.Big 00000.delay").waitForExistence(timeout: 15)
        probed("fling") {
            app.swipeUp(velocity: .fast)
            app.swipeUp(velocity: .fast)
            app.swipeDown(velocity: .fast)
            app.swipeDown(velocity: .fast)
        }
        assertAlive("push-pop-expand")
        print("UIPERF probe\n" + warnings.joined(separator: "\n"))
    }

    /// Fling the 策略 list with the 3000-member group expanded (XCTest allows one metric set per test method).
    func testD_ScrollExpandedBigGroup() {
        launch(["-UIPerfProbe", "-UITestBigProfile"])
        tab(1)
        let header = app.element(id: "policy.card.Big Select")
        XCTAssertTrue(header.waitForExistence(timeout: 20), "big group on 策略")
        header.tap()
        XCTAssertTrue(app.element(id: "policy.member.Big Select.Big 00000.delay").waitForExistence(timeout: 15), "members shown")
        let opts = XCTMeasureOptions()
        opts.iterationCount = 3
        opts.invocationOptions = [.manuallyStop]
        measure(metrics: [XCTOSSignpostMetric.scrollDecelerationMetric], options: opts) {
            app.swipeUp(velocity: .fast)
            stopMeasuring()
            app.swipeDown(velocity: .fast)
        }
        probed("fling-down-up") {
            app.swipeUp(velocity: .fast)
            app.swipeUp(velocity: .fast)
            app.swipeDown(velocity: .fast)
            app.swipeDown(velocity: .fast)
        }
        assertAlive("scroll expanded")
    }
}
