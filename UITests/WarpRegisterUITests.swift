import XCTest

/// feat/nc-warp-register-ui (#166): the WARP registration UI against the scripted API
/// (-UITestWarpMock / -UITestWarpMock429, installed by UITestSeed into WarpNodeLifecycle):
/// entry row in 添加节点, terms gating, a successful registration landing in the node list,
/// a second one numbered "Cloudflare WARP 2", the 429 wording, and deletion of the node.
final class WarpRegisterUITests: TernUITestCase {

    /// From anywhere reachable: 更多 → 节点与订阅 → + → 添加节点 → the Cloudflare WARP row → sheet.
    private func openWarpSheet() {
        tab(3)
        let row = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(row), "节点与订阅 row")
        row.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "nodes.add"), timeout: 8), "+")
        XCTAssertTrue(tapIfExists(app.button(L("添加节点")), timeout: 4), "添加节点 in the + menu")
        XCTAssertTrue(app.navigationBars[L("添加节点")].waitForExistence(timeout: 8), "AddNodeView")
        let warp = app.element(id: "addnode.warp")
        XCTAssertTrue(scrollTo(warp), "Cloudflare WARP row in 更多")
        warp.tap()
        XCTAssertTrue(app.element(id: "warp.register").waitForExistence(timeout: 8), "register sheet")
    }

    /// Accepts the terms and registers; waits for the done line naming the new node.
    private func registerAndWaitDone(_ name: String) {
        let register = app.element(id: "warp.register")
        XCTAssertFalse(register.isEnabled, "register disabled before the terms are accepted")
        app.element(id: "warp.terms").tap()
        XCTAssertTrue(register.waitHittable(), "register enabled after the terms")
        register.tap()
        XCTAssertTrue(app.element(labelContains: name).waitForExistence(timeout: 10), "done line for \(name)")
    }

    /// Closes the register sheet (toolbar 取消/完成) and the 添加节点 page, back at the node list.
    private func closeSheetAndAddNode() {
        closeSheet()
        XCTAssertFalse(app.element(id: "warp.register").exists, "sheet closed")
        back()
    }

    func test01_RegisterTwiceFromAddNode() {
        launch(["-UITestWarpMock"])
        openWarpSheet()
        registerAndWaitDone("Cloudflare WARP")
        snap("warp-registered")
        closeSheetAndAddNode()
        XCTAssertTrue(app.element(label: "Cloudflare WARP").waitForExistence(timeout: 8), "node in the list")

        // A second registration keeps the first node and numbers the new one.
        openWarpSheet()
        registerAndWaitDone("Cloudflare WARP 2")
        closeSheetAndAddNode()
        XCTAssertTrue(app.element(label: "Cloudflare WARP 2").waitForExistence(timeout: 8), "second node in the list")
        XCTAssertTrue(app.element(label: "Cloudflare WARP").exists, "first node still there")
        assertAlive("warp-register-twice")
    }

    func test02_RateLimitedShowsWordingAndAddsNothing() {
        launch(["-UITestWarpMock429"])
        openWarpSheet()
        app.element(id: "warp.terms").tap()
        let register = app.element(id: "warp.register")
        XCTAssertTrue(register.waitHittable())
        register.tap()
        XCTAssertTrue(app.element(labelContains: "429").waitForExistence(timeout: 10), "rate-limit wording shown")
        snap("warp-429")
        closeSheetAndAddNode()
        XCTAssertFalse(app.element(label: "Cloudflare WARP").exists, "no node after a 429")
        assertAlive("warp-429")
    }

    func test03_DeleteRegisteredNode() {
        launch(["-UITestWarpMock"])
        openWarpSheet()
        registerAndWaitDone("Cloudflare WARP")
        closeSheetAndAddNode()
        let row = app.element(label: "Cloudflare WARP")
        XCTAssertTrue(row.waitForExistence(timeout: 8), "node in the list")
        row.tap()
        let del = app.button(L("删除"))
        XCTAssertTrue(scrollTo(del), "删除 in the detail page")
        del.tap()
        let confirm = app.buttons[L("删除")].firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 5), "delete confirmation")
        confirm.tap()
        XCTAssertFalse(app.element(label: "Cloudflare WARP").waitForExistence(timeout: 5), "node gone from the list")
        assertAlive("warp-delete")
    }
}
