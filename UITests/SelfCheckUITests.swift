import XCTest

/// feat/nc-e2e: 设置 → 诊断与反馈 → 一键自检 opens, runs in the simulator, every step that needs the VPN shows
/// 「需要真机」 (not a failure), and the run ends with a summary + 诊断包 share button. selfcheck-2: 16 steps, every
/// one listed and every one 「需要真机」 in the simulator.
extension TernUITests {

    func test71_SelfCheckSmoke() {
        launch()
        openMore("诊断")
        let entry = app.element(id: "diagnostics.selfcheck")
        XCTAssertTrue(scrollTo(entry), "一键自检 row on 诊断与反馈")
        entry.tap()
        let run = app.element(id: "selfcheck.run")
        XCTAssertTrue(run.waitForExistence(timeout: 8), "self-check page")
        // feat/nc-selfcheck-2: same ids as SelfCheck.stepIDs.
        let ids = ["delay-offline", "vpn", "controller", "counts", "resources", "delay", "delay-nodes", "exitip",
                   "fetch", "dataplane", "mitm", "rewrite", "rewrite-http", "script", "restart", "memory"]
        for id in ids {
            XCTAssertTrue(scrollTo(app.element(id: "selfcheck.step.\(id)")), "step \(id) listed")
        }
        snap("selfcheck-idle")
        XCTAssertTrue(scrollTo(run), "run button")
        run.tap()
        // 16 steps push the result section below the fold (a lazy List has no element for it until scrolled to):
        // wait for the run button to turn into 「再次自检」, then scroll to the summary.
        let done = expectation(for: NSPredicate(format: "label CONTAINS %@", L("再次自检")), evaluatedWith: run)
        wait(for: [done], timeout: 60)
        XCTAssertTrue(scrollTo(app.element(id: "selfcheck.summary")), "run finishes with a summary")
        for id in ids {
            let step = app.element(id: "selfcheck.step.\(id)")
            XCTAssertTrue(scrollTo(step), "step \(id) after the run")
            XCTAssertTrue(step.label.contains(L("需要真机")), "\(id) needs a device in the simulator: \(step.label)")
        }
        XCTAssertTrue(scrollTo(app.element(id: "selfcheck.share")), "诊断包 ready to share")
        snap("selfcheck-done")
        assertAlive("self-check")
    }
}
