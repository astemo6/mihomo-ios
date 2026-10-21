import XCTest

/// r7 (backlog B13): UI tests that were never written — custom rule drag reorder, Home tile reorder, node
/// subscription add / edit (the seed fakes the download for *.uitest.invalid, Debug builds only).
extension MihomoUITests {

    /// The trailing drag area of a List row (edit mode reorder handle / the row itself for long-press reorder).
    func rowHandle(_ e: XCUIElement, dx: CGFloat? = nil) -> XCUICoordinate {
        let win = app.windows.firstMatch
        let w = win.frame.width
        let x = dx ?? (w - 26)
        return win.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: x, dy: e.frame.midY))
    }

    /// A Form text field by placeholder, else by position.
    func field(_ placeholder: String, index: Int) -> XCUIElement {
        let byPlaceholder = app.textFields.matching(NSPredicate(format: "placeholderValue == %@ OR label == %@", placeholder, placeholder)).firstMatch
        if byPlaceholder.waitForExistence(timeout: 3) { return byPlaceholder }
        return app.textFields.element(boundBy: index)
    }

    /// true when `a` is laid out before `b` (rows: above; grids: above, or same row and left).
    func isBefore(_ a: XCUIElement, _ b: XCUIElement) -> Bool {
        let fa = a.frame, fb = b.frame
        if abs(fa.midY - fb.midY) < 4 { return fa.minX < fb.minX }
        return fa.midY < fb.midY
    }

    /// Drags `e`'s handle to just above `target` (up to two tries); true when `e` ends up before `target`.
    @discardableResult
    func dragRow(_ e: XCUIElement, above target: XCUIElement, dx: CGFloat? = nil, press: TimeInterval = 0.8) -> Bool {
        for attempt in 0..<2 {
            let from = rowHandle(e, dx: dx)
            let to = rowHandle(target, dx: dx).withOffset(CGVector(dx: 0, dy: -target.frame.height * 0.45))
            from.press(forDuration: press, thenDragTo: to, withVelocity: .slow, thenHoldForDuration: 0.4)
            // let the list settle (frames move with the drop animation)
            let deadline = Date().addingTimeInterval(3)
            while Date() < deadline {
                if isBefore(e, target) { return true }
                usleep(250_000)
            }
            if attempt == 0 { warnings.append("[\(Env.tag)] drag \(e.identifier) retry") }
        }
        return isBefore(e, target)
    }

    // MARK: 66. Custom rules: long-press drag reorders, and the order is saved

    func test66_RulesDragMove() {
        launch()
        openMore("规则")
        app.buttons[L10n.f("自定义 %lld", 0)].firstMatch.tap()
        addCustomRule("DOMAIN-SUFFIX,first.uitest.example,Proxy")
        addCustomRule("DOMAIN,second.uitest.example,DIRECT")
        let a = app.element(labelContains: "first.uitest.example")
        let b = app.element(labelContains: "second.uitest.example")
        XCTAssertTrue(a.waitForExistence(timeout: 6) && b.waitForExistence(timeout: 6), "two rules")
        XCTAssertTrue(isBefore(a, b), "added in order")
        // No edit mode on this list: iOS 16+ reorders a List with onMove by long-press drag on the row.
        let moved = dragRow(b, above: a, dx: app.windows.firstMatch.frame.width * 0.5, press: 1.2)
        XCTAssertTrue(moved, "second rule dragged above the first")
        snap("rules-dragged")
        // Leave and come back: the new order is read from rules.json.
        back()
        openMore("规则")
        let tab2 = app.buttons[L10n.f("自定义 %lld", 2)].firstMatch
        XCTAssertTrue(tab2.waitForExistence(timeout: 6), "two custom rules after reopening")
        if tab2.exists { tab2.tap() }
        let a2 = app.element(labelContains: "first.uitest.example")
        let b2 = app.element(labelContains: "second.uitest.example")
        XCTAssertTrue(a2.waitForExistence(timeout: 6) && b2.waitForExistence(timeout: 6))
        XCTAssertTrue(isBefore(b2, a2), "order kept after reopening")
        assertAlive("rules drag")
    }

    // MARK: 67. 编辑首页面板: drag reorders the pinned tiles, Home follows

    func test67_HomeTileReorder() {
        launch(["-UITestDemoMemory"])
        let add = app.element(id: "home.addTiles")
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor")
        for t in ["speed", "memory"] {
            let b = app.element(id: "homepanels.add." + t)
            if b.waitForExistence(timeout: 2) || scrollTo(b) { b.tap(); usleep(400_000) }
        }
        let speed = app.element(id: "homepanels.row.speed")
        let memory = app.element(id: "homepanels.row.memory")
        XCTAssertTrue(speed.waitForExistence(timeout: 4) && memory.waitForExistence(timeout: 4), "both pinned")
        if isBefore(memory, speed) {
            XCTAssertTrue(dragRow(speed, above: memory), "speed dragged above memory")
        }
        XCTAssertTrue(dragRow(memory, above: speed), "memory dragged above speed (reorder handle)")
        snap("home-tiles-reordered")
        closeSheet()
        func tile(_ t: String) -> XCUIElement {
            app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile." + t)).firstMatch
        }
        let ts = tile("speed"), tm = tile("memory")
        XCTAssertTrue(scrollTo(tm), "memory tile on Home")
        XCTAssertTrue(ts.exists || scrollTo(ts), "speed tile on Home")
        XCTAssertTrue(isBefore(tm, ts), "Home shows memory before speed")
        snap("home-tiles-order")
        // Reopen the editor: the order was saved.
        XCTAssertTrue(scrollTo(add))
        add.tap()
        XCTAssertTrue(app.element(id: "homepanels.row.memory").waitForExistence(timeout: 6))
        XCTAssertTrue(isBefore(app.element(id: "homepanels.row.memory"), app.element(id: "homepanels.row.speed")), "order saved")
        closeSheet()
        assertAlive("home tile reorder")
    }

    // MARK: 68. 节点与订阅: add a node subscription, then edit it

    func test68_SubscriptionAddEdit() {
        launch()
        openMore("节点与订阅")
        let addMenu = app.element(id: "nodes.add")
        XCTAssertTrue(addMenu.waitForExistence(timeout: 6), "+ menu")
        addMenu.tap()
        XCTAssertTrue(tapIfExists(app.button(L("添加节点订阅")), timeout: 4), "添加节点订阅")
        XCTAssertTrue(app.navigationBars[L("添加节点订阅")].waitForExistence(timeout: 6), "editor")
        let url = field(L("订阅链接 https://…"), index: 0)
        XCTAssertTrue(url.waitForExistence(timeout: 4), "URL field")
        url.tap()
        url.typeText("https://nodes.uitest.invalid/sub?token=r7")
        let name = field(L("名称（留空自动获取）"), index: 1)
        name.tap()
        name.typeText("R7 Added")
        snap("nodesub-add")
        let addBtn = app.navigationBars.buttons[L("添加")]
        XCTAssertTrue(addBtn.waitHittable(), "添加 enabled")
        addBtn.tap()
        let row = app.element(id: "nodesub.row.R7 Added")
        XCTAssertTrue(row.waitForExistence(timeout: 15) || scrollTo(row), "added subscription listed")
        XCTAssertFalse(app.navigationBars[L("添加节点订阅")].exists, "editor closed after the download")
        snap("nodesub-added")
        // Edit: rename through the long-press menu.
        XCTAssertTrue(scrollTo(row))
        row.press(forDuration: 1.3)
        XCTAssertTrue(tapIfExists(app.button(L("编辑")), timeout: 4), "编辑 in the long-press menu")
        XCTAssertTrue(app.navigationBars[L("编辑节点订阅")].waitForExistence(timeout: 6), "edit editor")
        let urlField = field(L("订阅链接 https://…"), index: 0)
        XCTAssertEqual(urlField.value as? String, "https://nodes.uitest.invalid/sub?token=r7", "editor loads the URL")
        let name2 = field(L("名称（留空自动获取）"), index: 1)
        replaceText(name2, "R7 Edited")
        let save = app.navigationBars.buttons[L("保存")]
        XCTAssertTrue(save.waitHittable(), "保存 enabled")
        save.tap()
        let renamed = app.element(id: "nodesub.row.R7 Edited")
        XCTAssertTrue(renamed.waitForExistence(timeout: 8) || scrollTo(renamed), "renamed subscription listed")
        XCTAssertFalse(app.element(id: "nodesub.row.R7 Added").exists, "old name gone")
        snap("nodesub-edited")
        assertAlive("subscription add / edit")
    }
}
