import XCTest

/// probe/reality-e2e: drive REAL delay tests from the genuine native dial against a
/// debug-logging reference Xray REALITY server (seed profile "UITest Reality", nodes
/// PROBE-VISION / PROBE-PLAIN on 45.92.159.155:24443). The assertions here only check
/// the UI mechanics — the verdict lives in the server's log, read out of band.
extension TernUITests {

    func test98_RealityProbe() {
        allowHan = true // node names are ASCII, but the tab/group labels are CJK UI
        launch(["-UITestRealityProbe"])
        tab(1)
        let group = app.element(id: "policy.card.ProbeGroup")
        XCTAssertTrue(group.waitForExistence(timeout: 15), "ProbeGroup row")
        group.tap()
        let vision = app.element(id: "policy.member.ProbeGroup.PROBE-VISION.delay")
        let plain = app.element(id: "policy.member.ProbeGroup.PROBE-PLAIN.delay")
        XCTAssertTrue(vision.waitForExistence(timeout: 8), "PROBE-VISION delay button")
        XCTAssertTrue(plain.waitForExistence(timeout: 8), "PROBE-PLAIN delay button")
        vision.tap()
        usleep(10_000_000) // a stalled dial hits the 5 s probe timeout; a good one lands ~1 s
        snap("reality-probe-vision")
        plain.tap()
        usleep(10_000_000)
        snap("reality-probe-plain")
        assertAlive("reality probe")
    }
}
