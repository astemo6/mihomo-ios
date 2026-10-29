import XCTest

/// probe/reality-e2e: drive a REAL group delay test from the genuine native dial against a
/// debug-logging reference Xray REALITY server (seed profile "UITest Reality", nodes
/// PROBE-VISION / PROBE-PLAIN on 45.92.159.155:24443). The verdict lives in the server's
/// log, read out of band; here we only run the mechanics and record the outcome labels
/// (a failed probe may keep the "—" label, so nothing here hard-asserts a measurement).
extension TernUITests {

    func test98_RealityProbe() {
        allowHan = true // tab/group labels are CJK UI
        launch(["-UITestRealityProbe"])
        tab(1)
        let group = app.element(id: "policy.card.ProbeGroup")
        XCTAssertTrue(group.waitForExistence(timeout: 15), "ProbeGroup row")
        group.tap()
        let visionDelay = app.element(id: "policy.member.ProbeGroup.PROBE-VISION.delay")
        let plainDelay = app.element(id: "policy.member.ProbeGroup.PROBE-PLAIN.delay")
        XCTAssertTrue(visionDelay.waitForExistence(timeout: 8), "PROBE-VISION delay label")
        XCTAssertTrue(plainDelay.waitForExistence(timeout: 8), "PROBE-PLAIN delay label")
        let test = app.element(id: "policy.test.ProbeGroup")
        XCTAssertTrue(test.waitForExistence(timeout: 8), "ProbeGroup test button")
        test.tap()
        // Both members probe in parallel (5 s timeout each); give slow CI networking room.
        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            let v = visionDelay.exists && !visionDelay.label.isEmpty && visionDelay.label != "—"
            let p = plainDelay.exists && !plainDelay.label.isEmpty && plainDelay.label != "—"
            if v && p { break }
            usleep(500_000)
        }
        snap("reality-probe-result")
        print("PROBE-RESULT vision=\(visionDelay.label) plain=\(plainDelay.label)")
        assertAlive("reality probe")
    }
}
