import XCTest

/// hotfix/node-cred-reveal (device 2026-10-21 「这里长按uuid需要可显示」 / 「选中订阅里的某个节点时，增加一个添加到本地节点的选项」):
/// node detail credentials are hidden until 显示 (long press or the eye), and a subscription node can be copied
/// into the local (manual) nodes. Demo data: subscription node 🇰🇷 Seoul Sub 02 (vless, fake uuid).
extension TernUITests {

    static let credSubNode = "🇰🇷 Seoul Sub 02"
    static let credUUID = "00000000-0000-4000-8000-000000000011"

    private func openNodeDetail(_ name: String) {
        let node = app.element(label: name)
        XCTAssertTrue(scrollTo(node), "node \(name) listed")
        node.tap()
        XCTAssertTrue(app.element(label: L("协议")).waitForExistence(timeout: 8), "detail of \(name)")
    }

    /// Long-presses the credential's title and taps a menu item (显示 / 隐藏 / 复制).
    private func credMenu(_ key: String, _ item: String) {
        let label = app.element(id: "node.cred.label.\(key)")
        XCTAssertTrue(scrollTo(label), "credential row \(key)")
        label.press(forDuration: 1.2)
        let b = app.button(L(item))
        XCTAssertTrue(b.waitForExistence(timeout: 4), "long-press menu offers \(item)")
        b.tap()
        usleep(600_000)
    }

    // MARK: 60. 凭据: long-press → 显示 / 隐藏 / 复制, eye button, hidden again after leaving the page

    func test60_NodeCredentialReveal() {
        launch()
        openAllNodes()
        openNodeDetail(Self.credSubNode)
        let value = app.element(id: "node.cred.value.uuid")
        XCTAssertTrue(scrollTo(app.element(id: "node.cred.label.uuid")), "UUID row")
        XCTAssertFalse(value.exists, "hidden by default")
        XCTAssertFalse(app.element(label: Self.credUUID).exists, "uuid not on screen before 显示")
        XCTAssertTrue(scrollTo(app.element(label: L("默认隐藏，长按可显示或复制。"))), "footer")
        snap("cred-hidden")

        credMenu("uuid", "显示")
        XCTAssertTrue(value.waitForExistence(timeout: 4), "value shown after 显示")
        XCTAssertEqual(value.label, Self.credUUID, "the real uuid")
        snap("cred-revealed")

        credMenu("uuid", "隐藏")
        XCTAssertFalse(value.waitForExistence(timeout: 1), "hidden again after 隐藏")

        let eye = app.element(id: "node.cred.eye.uuid")
        XCTAssertTrue(eye.exists, "eye button")
        eye.tap()
        XCTAssertTrue(value.waitForExistence(timeout: 4), "eye shows the value")

        credMenu("uuid", "复制")
        XCTAssertTrue(app.element(label: L("已复制")).waitForExistence(timeout: 3) || value.exists, "copy acknowledged")

        // Leaving the page drops what was revealed.
        back()
        openNodeDetail(Self.credSubNode)
        XCTAssertTrue(scrollTo(app.element(id: "node.cred.label.uuid")), "UUID row again")
        XCTAssertFalse(app.element(id: "node.cred.value.uuid").exists, "hidden again after leaving the page")
        back()
    }

    // MARK: 61. 添加到本地节点: subscription node → editable manual copy with the same secrets

    func test61_SubNodeAddToLocal() {
        launch()
        openAllNodes()
        openNodeDetail(Self.credSubNode)
        let add = app.element(id: "node.addLocal")
        XCTAssertTrue(scrollTo(add), "添加到本地节点 offered for a subscription node")
        XCTAssertTrue(scrollTo(app.element(label: L("订阅里的节点是只读的；添加到本地后可以编辑，不受订阅更新影响。"))), "footer")
        add.tap()
        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10), "confirmation")
        XCTAssertTrue(alert.staticTexts[L("已添加到本地节点")].exists, "confirmation title")
        snap("addlocal-alert")
        // 编辑 opens the copy in the node editor.
        alert.buttons[L("编辑")].tap()
        XCTAssertTrue(app.navigationBars[L("编辑节点")].waitForExistence(timeout: 8), "editor for the copy")
        closeSheet()
        for _ in 0..<20 where app.navigationBars[L("编辑节点")].exists { usleep(250_000) }

        let copy = L10n.f("%@ 副本", Self.credSubNode)
        back()
        XCTAssertTrue(scrollTo(app.element(label: copy)), "copy listed as \(copy)")
        XCTAssertTrue(app.element(label: Self.credSubNode).exists || scrollTo(app.element(label: Self.credSubNode)), "subscription node still there")
        openNodeDetail(copy)
        XCTAssertTrue(scrollTo(app.element(id: "node.cred.label.uuid")), "copy keeps the uuid")
        credMenu("uuid", "显示")
        let value = app.element(id: "node.cred.value.uuid")
        XCTAssertTrue(value.waitForExistence(timeout: 4))
        XCTAssertEqual(value.label, Self.credUUID, "secret copied unchanged")
        XCTAssertFalse(app.element(id: "node.addLocal").exists, "no 添加到本地节点 on a local node")
        XCTAssertTrue(scrollTo(app.button(L("编辑"))), "the copy is editable")
        snap("addlocal-copy-detail")
        back()
    }
}
