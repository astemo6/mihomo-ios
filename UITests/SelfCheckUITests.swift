import XCTest

/// feat/nc-e2e: 设置 → 诊断与反馈 → 一键自检 opens, runs in the simulator, every step that needs the VPN shows
/// 「需要真机」 (not a failure), and the run ends with a summary + 诊断包 share button.
extension MihomoUITests {

    func test71_SelfCheckSmoke() {
        launch()
        openMore("诊断")
        let entry = app.element(id: "diagnostics.selfcheck")
        XCTAssertTrue(scrollTo(entry), "一键自检 row on 诊断与反馈")
        entry.tap()
        let run = app.element(id: "selfcheck.run")
        XCTAssertTrue(run.waitForExistence(timeout: 8), "self-check page")
        for id in ["vpn", "controller", "counts", "delay", "fetch", "mitm", "script", "restart"] {
            XCTAssertTrue(app.element(id: "selfcheck.step.\(id)").exists, "step \(id) listed")
        }
        snap("selfcheck-idle")
        run.tap()
        let summary = app.element(id: "selfcheck.summary")
        XCTAssertTrue(summary.waitForExistence(timeout: 60), "run finishes with a summary")
        for id in ["vpn", "controller", "restart"] {
            let step = app.element(id: "selfcheck.step.\(id)")
            XCTAssertTrue(step.label.contains(L("需要真机")), "\(id) needs a device in the simulator: \(step.label)")
        }
        XCTAssertTrue(scrollTo(app.element(id: "selfcheck.share")), "诊断包 ready to share")
        snap("selfcheck-done")
        assertAlive("self-check")
    }
}
