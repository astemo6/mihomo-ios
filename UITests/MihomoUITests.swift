import XCTest

/// test/selftest: offline UI paths on the simulator (the tunnel cannot run there). Every screen gets a
/// screenshot and an audit (no crash, no unformatted %lld / %@, no Chinese left in English).
final class MihomoUITests: MihomoUITestCase {

    // MARK: 1. Launch + every tab

    func test01_TabsAndHome() {
        launch()
        snap("home")
        // Default Home policy cards: the first four non-hidden groups.
        for g in ["Proxy", "Auto", "Fallback", "Streaming"] {
            XCTAssertTrue(app.element(id: "home.card." + g).waitForExistence(timeout: 10), "default card \(g)")
        }
        XCTAssertFalse(app.element(id: "home.card.Apple").exists, "5th group must not be on Home by default")
        XCTAssertFalse(app.element(id: "home.card.Hidden Probe").exists, "hidden group on Home")
        // A card opens the offline group picker.
        app.element(id: "home.card.Proxy").tap()
        XCTAssertTrue(app.element(label: "🇯🇵 Tokyo 01").waitForExistence(timeout: 8), "offline picker lists members")
        snap("home-group-picker")
        back()
        for (i, n) in ["policy", "requests", "profiles", "more"].enumerated() {
            tab(i + 1)
            snap("tab-\(n)")
        }
        tab(0)
        assertAlive("tabs")
    }

    // MARK: 2. 编辑首页策略

    func test02_HomePolicyPicker() {
        launch()
        let edit = app.button(L("编辑首页策略"))
        XCTAssertTrue(edit.waitForExistence(timeout: 10))
        edit.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页策略")].waitForExistence(timeout: 8))
        snap("home-groups-editor")
        // Select a fifth group.
        app.element(id: "homegroups.row.Apple").tap()
        // Reorder: drag Streaming above Proxy (edit mode is always on).
        let handles = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Reorder"))
        if handles.count >= 4 {
            handles.element(boundBy: 3).press(forDuration: 0.6, thenDragTo: handles.element(boundBy: 0))
        } else {
            warnings.append("reorder handles not found (\(handles.count))")
        }
        snap("home-groups-editor-edited")
        closeSheet()
        XCTAssertTrue(app.element(id: "home.card.Apple").waitForExistence(timeout: 8), "selected group shows on Home")
        snap("home-five-cards")

        // Zero groups: uncheck everything → the section disappears.
        edit.tap()
        for g in ["Proxy", "Auto", "Fallback", "Streaming", "Apple", "Final"] {
            let r = app.element(id: "homegroups.row." + g)
            // A lazy row can vanish between exists and isSelected; read both from one snapshot.
            if let snap = try? r.snapshot(), snap.isSelected { r.tap() }
        }
        // Rows report selection through the trait; tap any still selected one again.
        for g in ["Proxy", "Auto", "Fallback", "Streaming", "Apple", "Final"] {
            let r = app.element(id: "homegroups.row." + g)
            // A lazy row can vanish between exists and isSelected; read both from one snapshot.
            if let snap = try? r.snapshot(), snap.isSelected { r.tap() }
        }
        snap("home-groups-none")
        closeSheet()
        XCTAssertFalse(app.element(id: "home.card.Proxy").waitForExistence(timeout: 3), "zero groups → no cards")
        XCTAssertFalse(edit.exists, "zero groups → no 编辑 pill")
        snap("home-no-cards")

        // Restore from 策略 → 排序 menu → 编辑首页策略 → 恢复默认.
        tab(1)
        let sortMenu = app.button(L("排序"))
        XCTAssertTrue(sortMenu.waitForExistence(timeout: 8), "策略 sort menu")
        sortMenu.tap()
        XCTAssertTrue(tapIfExists(app.button(L("编辑首页策略"))), "menu entry 编辑首页策略")
        let restore = app.button(L("恢复默认"))
        XCTAssertTrue(restore.waitForExistence(timeout: 8), "恢复默认")
        restore.tap()
        snap("home-groups-restored")
        closeSheet()
        tab(0)
        for g in ["Proxy", "Auto", "Fallback", "Streaming"] {
            XCTAssertTrue(app.element(id: "home.card." + g).waitForExistence(timeout: 8), "restored card \(g)")
        }
        XCTAssertFalse(app.element(id: "home.card.Apple").exists)
    }

    // MARK: 3. 更多: every row opens and comes back

    static let moreRows = [
        "连接方式", "DNS", "节点管理", "订阅管理", "规则", "提供者（规则集 / 节点集）", "地理与规则库", "模块与资源",
        "重写（本地模块）", "脚本", "任务", "MitM", "网络工具（Ping / TCP / DNS）", "网络测试（带宽 / NAT 类型）", "解锁检测",
        "连接分析", "流量统计", "日志", "DNS 日志", "备份与恢复", "配置快照", "存储空间", "外观", "内核设置", "测速", "出口信息查询",
        "App 图标", "诊断", "关于 / 开源许可",
    ]

    func test03_MoreEveryPage() {
        launch()
        tab(4)
        snap("more")
        for (i, key) in Self.moreRows.enumerated() {
            let row = app.element(id: "more." + key)
            guard scrollTo(row) else { continue }
            row.tap()
            usleep(900_000)
            snap(String(format: "more-%02d", i))
            assertAlive("more → \(key)")
            back()
            // Back on 更多? (navigation must not get stuck)
            if !app.navigationBars[L("更多")].waitForExistence(timeout: 4) {
                issues.append("[\(Env.tag)] more → \(key): did not return to 更多")
                tab(4)
            }
        }
        // 新手引导 opens full screen and closes.
        let onboarding = app.element(id: "more.新手引导")
        if scrollTo(onboarding) {
            onboarding.tap()
            usleep(800_000)
            snap("onboarding")
            for k in ["跳过", "完成", "关闭", "以后再说"] where tapIfExists(app.button(L(k)), timeout: 1) { break }
        }
    }

    // MARK: 4. 节点管理

    func test04_NodeManager() {
        launch()
        tab(4)
        let row = app.element(id: "more.节点管理")
        XCTAssertTrue(scrollTo(row))
        row.tap()
        XCTAssertTrue(app.navigationBars[L("节点管理")].waitForExistence(timeout: 8))
        XCTAssertTrue(app.element(label: "Demo Sub").waitForExistence(timeout: 8), "node subscription row")
        snap("nodes-home")

        // 全部节点
        XCTAssertTrue(tapIfExists(app.element(label: L("全部节点"))))
        XCTAssertTrue(app.element(label: "🇯🇵 Tokyo 01").waitForExistence(timeout: 10), "profile node listed")
        snap("nodes-all")
        // selftest: the list is lazy — rows further down only exist once scrolled to.
        XCTAssertTrue(scrollTo(app.element(label: "🇰🇷 Seoul Sub 01")), "subscription node listed")
        XCTAssertTrue(scrollTo(app.element(label: "Manual SS")), "manual node listed")

        // Search (the field appears when the list is pulled down to the top)
        let search = app.searchFields.firstMatch
        for _ in 0..<8 where !search.exists { app.swipeDown(velocity: .fast) }
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.tap()
        search.typeText("Tokyo")
        usleep(800_000)
        XCTAssertTrue(app.element(label: "🇯🇵 Tokyo 02").exists, "search hit")
        XCTAssertFalse(app.element(label: "🇭🇰 Hong Kong 01").exists, "search filters others")
        snap("nodes-search")
        let cancel = app.buttons[L("取消")].exists ? app.buttons[L("取消")] : app.buttons["Cancel"]
        if cancel.exists { cancel.tap() }
        usleep(500_000)

        // Protocol filter + sort (menu)
        let menu = app.button(L("排序与筛选"))
        XCTAssertTrue(menu.waitForExistence(timeout: 5), "排序与筛选 menu")
        menu.tap()
        snap("nodes-menu")
        // The protocol filter is inline in the menu (badge names: Hy2, SS, …); older builds had a 协议 submenu.
        if tapIfExists(app.button(L("协议")), timeout: 2) { snap("nodes-protocols") }
        let hy2 = app.button("Hy2").exists ? app.button("Hy2") : app.button("Hysteria2")
        if tapIfExists(hy2, timeout: 3) {
            usleep(700_000)
            XCTAssertTrue(app.element(label: "🇸🇬 Singapore Hy2").exists, "hy2 node after filter")
            XCTAssertFalse(app.element(label: "🇯🇵 Tokyo 01").exists, "ss node hidden by filter")
            snap("nodes-filter-hy2")
        } else { issues.append("[\(Env.tag)] protocol Hy2 not in the filter menu") }
        menu.tap()
        _ = tapIfExists(app.button(L("协议")), timeout: 2)
        _ = tapIfExists(app.button(L("全部协议")), timeout: 3)
        menu.tap()
        if tapIfExists(app.button(L("排序")), timeout: 3) {
            _ = tapIfExists(app.button(L("名称")), timeout: 3)
            usleep(600_000)
            snap("nodes-sort-name")
        } else {
            _ = tapIfExists(app.button(L("名称")), timeout: 2)
        }

        // Node detail masks secrets
        let node = app.element(label: "🇭🇰 Hong Kong 01")
        XCTAssertTrue(scrollTo(node))
        node.tap()
        XCTAssertTrue(app.element(label: L("凭据")).waitForExistence(timeout: 10) || app.element(label: "••••••").waitForExistence(timeout: 2),
                      "credentials section")
        let tree = app.debugDescription
        for secret in ["uitest-secret", "00000000-0000-4000-8000", "AAAAAAAAAAAAAAAA"] {
            XCTAssertFalse(tree.contains(secret), "secret visible in node detail: \(secret)")
        }
        snap("node-detail-trojan")
        back()
        let awg = app.element(label: "🇺🇸 San Jose AWG")
        if scrollTo(awg) {
            awg.tap()
            usleep(1_200_000)
            XCTAssertFalse(app.debugDescription.contains("AAAAAAAAAAAAAAAA"), "wireguard key visible")
            snap("node-detail-awg")
            back()
        }
        back()

        // 筛选节点 → 加为策略组 / 移除
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点"))))
        let jp = app.element(label: L("日本节点"))
        XCTAssertTrue(jp.waitForExistence(timeout: 8), "region JP")
        snap("nodes-filter-regions")
        jp.swipeLeft()
        if tapIfExists(app.button(L("加为策略组")), timeout: 3) {
            XCTAssertTrue(app.element(label: L("已加为策略组")).waitForExistence(timeout: 10), "group added")
            snap("nodes-filter-added")
            jp.swipeLeft()
            XCTAssertTrue(tapIfExists(app.button(L("移除策略组")), timeout: 3), "remove action")
            usleep(1_500_000)
            XCTAssertFalse(app.element(label: L("已加为策略组")).exists, "group removed")
        } else { issues.append("[\(Env.tag)] 加为策略组 swipe action missing") }
        jp.tap()
        usleep(800_000)
        XCTAssertTrue(app.element(label: "🇯🇵 Tokyo 01").waitForExistence(timeout: 6), "region list")
        snap("nodes-region-jp")
        back()
        back()

        // Node subscription list
        XCTAssertTrue(tapIfExists(app.element(label: "Demo Sub")))
        // B13: 🇹🇼 is drawn as a TW badge where the system can't render it (the name's flag is replaced in the row).
        XCTAssertTrue(app.element(labelContains: "Taipei Sub").waitForExistence(timeout: 8), "subscription nodes")
        snap("nodes-sub")
        back()
        // 本地节点
        XCTAssertTrue(tapIfExists(app.element(label: L("本地节点"))))
        XCTAssertTrue(scrollTo(app.element(label: "Manual Hy2")), "local nodes")
        snap("nodes-local")
    }

    // MARK: 5. 添加节点 + node editor

    func test05_AddNodeAndEditor() {
        launch()
        tab(4)
        let row = app.element(id: "more.节点管理")
        XCTAssertTrue(scrollTo(row))
        row.tap()
        XCTAssertTrue(tapIfExists(app.button(L("添加节点")), timeout: 8), "+")
        XCTAssertTrue(app.navigationBars[L("添加节点")].waitForExistence(timeout: 8))
        snap("add-node")

        // Paste detection (typed into the box; the clipboard button would raise the paste prompt).
        let box = app.textViews.firstMatch
        XCTAssertTrue(box.waitForExistence(timeout: 5))
        box.tap()
        box.typeText("hysteria2://uitest-secret-typed@192.0.2.61:443/?sni=example.com#Typed%20Hy2\ntrojan://uitest-secret-typed2@192.0.2.62:443?sni=example.com#Typed%20Trojan")
        let found = app.element(label: L10n.f("识别到 %lld 个节点", 2))
        XCTAssertTrue(found.waitForExistence(timeout: 6), "detected 2 nodes")
        snap("add-node-detected")
        if app.toolbars.buttons[L("完成")].exists { app.toolbars.buttons[L("完成")].tap() }
        let add = app.button(L("添加"))
        XCTAssertTrue(add.waitHittable(), "添加 enabled")
        add.tap()
        XCTAssertTrue(app.element(label: L10n.f("已添加 %lld 个节点", 2)).waitForExistence(timeout: 8), "added")
        snap("add-node-added")

        // Editors for several protocols, saved as manual nodes.
        let editors: [(String, String, String)] = [("VLESS XHTTP", "UITest XHTTP", "192.0.2.71"),
                                                   ("AmneziaWG", "UITest AWG", "192.0.2.72"),
                                                   ("Hysteria2", "UITest Hy2 Form", "192.0.2.73"),
                                                   ("Sudoku", "UITest Sudoku", "192.0.2.74")]
        for (i, e) in editors.enumerated() {
            let r = app.buttons[e.0]
            guard scrollTo(r) else { continue }
            r.tap()
            XCTAssertTrue(app.navigationBars[L("添加节点")].waitForExistence(timeout: 6), "editor \(e.0)")
            snap(String(format: "editor-%d-top", i))
            fill(L("名称"), e.1)
            fill(L("服务器"), e.2)
            fill(L("端口"), "443")
            // Required protocol fields, so the editor can save.
            if e.0 == "VLESS XHTTP" { fill("UUID", "11111111-2222-4333-8444-555555555555") }
            if e.0 == "AmneziaWG" { fill(L("对端公钥"), "VlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlY=") }
            // Protocol credentials (best effort: the first secure field).
            let sec = app.secureTextFields.firstMatch
            if sec.exists {
                sec.tap()
                sec.typeText(e.0 == "AmneziaWG" ? "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=" : "uitest-secret-form")
            }
            app.swipeUp()
            snap(String(format: "editor-%d-bottom", i))
            let save = app.navigationBars.buttons[L("保存")]
            XCTAssertTrue(save.waitHittable(), "保存 \(e.0)")
            save.tap()
            // Saving validates in Go; give it time before calling it a failure (the page below is also 添加节点).
            let gone = NSPredicate(format: "exists == false")
            let closed = XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: gone, object: app.navigationBars.buttons[L("保存")])], timeout: 6) == .completed
            if !closed {
                // Still open: an error is shown; screenshot it and cancel.
                snap(String(format: "editor-%d-error", i))
                issues.append("[\(Env.tag)] editor \(e.0) did not save")
                closeSheet()
            }
            usleep(600_000)
        }
        back()
        XCTAssertTrue(tapIfExists(app.element(label: L("本地节点"))))
        for n in ["Typed Hy2", "UITest XHTTP", "UITest Hy2 Form"] {
            XCTAssertTrue(app.element(label: L("本地节点")).waitForExistence(timeout: 6) && scrollTo(app.element(label: n)), "saved node \(n)")
        }
        snap("nodes-local-after-add")
    }

    func fill(_ placeholder: String, _ text: String) {
        let f = app.textFields[placeholder]
        if f.waitForExistence(timeout: 3) {
            f.tap()
            f.typeText(text)
        } else {
            warnings.append("[\(Env.tag)] text field \(placeholder) not found")
        }
    }

    // MARK: 6. Imports of each sample

    func importSample(_ file: String, expectProfile: Bool) {
        launch(["-UITestImport", file])
        let sheet = app.navigationBars[L("导入")]
        XCTAssertTrue(sheet.waitForExistence(timeout: 15), "import sheet for \(file)")
        snap("import-\(file)-sheet")
        let btn = app.navigationBars.buttons[L("导入")]
        XCTAssertTrue(btn.waitHittable(10), "导入 button \(file)")
        btn.tap()
        let fail = app.alerts[L("导入失败")]
        let deadline = Date().addingTimeInterval(30)
        var done = false
        while Date() < deadline {
            if fail.exists { break }
            if app.navigationBars.buttons[L("完成")].exists { done = true; break }
            usleep(300_000)
        }
        snap("import-\(file)-result")
        if fail.exists {
            issues.append("[\(Env.tag)] import \(file) failed: \(fail.staticTexts.allElementsBoundByIndex.map(\.label).joined(separator: " / "))")
            fail.buttons[L("好")].tap()
        }
        XCTAssertTrue(done, "import \(file) finished")
        closeSheet()
        if expectProfile {
            tab(3)
            snap("import-\(file)-profiles")
        }
    }

    func test06a_ImportQX() { importSample("uitest-qx.conf", expectProfile: true) }
    func test06b_ImportSurge() { importSample("uitest-surge.conf", expectProfile: true) }
    func test06c_ImportClash() { importSample("uitest-clash.yaml", expectProfile: true) }
    func test06d_ImportLoon() { importSample("uitest-loon.plugin", expectProfile: false) }
    func test06e_ImportLinks() { importSample("uitest-links.txt", expectProfile: false) }

    // MARK: 7. Rule / rewrite / script editors open and save

    func openMore(_ key: String) {
        tab(4)
        let row = app.element(id: "more." + key)
        XCTAssertTrue(scrollTo(row), key)
        row.tap()
        usleep(800_000)
    }

    func test07_Editors() {
        launch()
        // Custom rule
        openMore("规则")
        app.buttons[L10n.f("自定义 %lld", 0)].firstMatch.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "rules.add"), timeout: 5), "rules +")
        let rule = app.textFields[L("规则")]
        XCTAssertTrue(rule.waitForExistence(timeout: 5))
        rule.tap()
        rule.typeText("DOMAIN-SUFFIX,uitest.example.com,Proxy")
        usleep(1_200_000)
        snap("editor-rule")
        app.navigationBars.buttons[L("保存")].tap()
        XCTAssertTrue(app.element(labelContains: "uitest.example.com").waitForExistence(timeout: 6), "rule saved")
        snap("rules-custom")
        back()

        // Rewrite (本地模块)
        openMore("重写（本地模块）")
        XCTAssertTrue(tapIfExists(app.element(id: "localmodule.add"), timeout: 5), "rewrite +")
        XCTAssertTrue(tapIfExists(app.button(L("拒绝请求（reject）")), timeout: 4), "reject entry")
        let pat = app.textFields.firstMatch
        XCTAssertTrue(pat.waitForExistence(timeout: 5))
        pat.tap()
        pat.typeText("^https?://ads\\.uitest\\.example/")
        usleep(800_000)
        snap("editor-rewrite")
        let save = app.navigationBars.buttons[L("保存")]
        XCTAssertTrue(save.waitHittable(), "rewrite 保存 enabled")
        save.tap()
        XCTAssertTrue(app.element(labelContains: "ads").waitForExistence(timeout: 6), "rewrite saved")
        snap("rewrite-list")
        back()

        // Script
        openMore("脚本")
        XCTAssertTrue(tapIfExists(app.element(id: "scripts.add"), timeout: 5), "scripts +")
        XCTAssertTrue(tapIfExists(app.button(L("新建 / 导入脚本")), timeout: 4), "new script")
        usleep(800_000)
        snap("editor-script")
        let name = app.textFields[L("名称")]
        if name.waitForExistence(timeout: 4) { name.tap(); name.typeText("UITest Script") }
        let pattern = app.textFields[L("pattern（正则，匹配完整 URL）")]
        if pattern.exists { pattern.tap(); pattern.typeText("^https://api\\.uitest\\.example/") }
        app.swipeUp()
        snap("editor-script-bottom")
        let ssave = app.navigationBars.buttons[L("保存")]
        if ssave.exists && ssave.isEnabled { ssave.tap() } else { closeSheet() }
        usleep(800_000)
        snap("scripts-list")
        back()
    }

    // MARK: 8. 模块库 + panels

    func test08_ModulesAndPanels() {
        launch()
        openMore("模块与资源")
        snap("modules")
        XCTAssertTrue(app.element(label: "UITest Panel Module").waitForExistence(timeout: 6), "seeded module listed")
        let gallery = app.element(label: L("模块库"))
        if scrollTo(gallery) {
            gallery.tap()
            usleep(1_500_000)
            snap("module-library")
            let first = app.cells.element(boundBy: 0)
            if first.exists { first.tap(); usleep(1_000_000); snap("module-preview"); back() }
            back()
        } else { issues.append("[\(Env.tag)] 模块库 entry not found") }
        back()
        tab(0)
        let panels = app.element(label: L("全部面板"))
        app.swipeUp()
        snap("home-bottom-panels")
        if panels.exists && panels.isHittable {
            panels.tap()
            usleep(800_000)
            snap("panels")
        }
        // The panels page itself (linked from Home only while connected).
        app.terminate()
        launch(["-UITestScreen", "panels"])
        XCTAssertTrue(app.navigationBars.firstMatch.waitForExistence(timeout: 8), "panels page")
        usleep(1_000_000)
        snap("panels-page")
    }

    // MARK: 9. 更多 settings apply on change (v0.15.4): no 保存 button, the change survives leaving the page.

    func switchValue(_ sw: XCUIElement) -> String { (sw.value as? String) ?? "" }

    func toggleSwitch(_ sw: XCUIElement) {
        sw.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
    }

    func test09_AutoApplySettings() {
        launch()
        let pages: [(String, String)] = [("内核设置", "域名嗅探（Sniffer）"), ("测速", "健康检查也使用此地址"),
                                         ("DNS", "使用自定义 DNS"), ("连接方式", "接管所有网络流量")]
        for (page, toggle) in pages {
            openMore(page)
            for k in ["保存", "保存并重载", "保存并重载内核"] {
                XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch.exists, "\(page): 保存 button still there (\(k))")
            }
            let sw = app.switches[L(toggle)]
            guard scrollTo(sw) else { back(); continue }
            let before = switchValue(sw)
            toggleSwitch(sw)
            usleep(300_000)
            XCTAssertNotEqual(switchValue(sw), before, "\(page): \(toggle) did not toggle")
            snap("autoapply-\(page)")
            usleep(1_200_000)   // debounce 0.5 s + write
            back()
            openMore(page)
            let again = app.switches[L(toggle)]
            XCTAssertTrue(scrollTo(again), "\(page) reopened")
            XCTAssertNotEqual(switchValue(again), before, "\(page): \(toggle) not kept after leaving the page")
            // Put it back (also exercises a second apply).
            toggleSwitch(again)
            usleep(1_200_000)
            back()
        }
        // Text field: an invalid controller port shows the inline error and is not applied.
        openMore("内核设置")
        let port = app.textFields.matching(identifier: "settings.port").firstMatch
        if scrollTo(port) {
            port.tap()
            port.press(forDuration: 1.0)
            if tapIfExists(app.menuItems.matching(NSPredicate(format: "label IN %@", ["Select All", "全选"])).firstMatch, timeout: 2) {
                port.typeText(XCUIKeyboardKey.delete.rawValue)
            } else {
                port.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 6))
            }
            port.typeText("80")
            XCTAssertTrue(app.element(labelContains: L("端口应为 1024–65535，修改前不会应用。")).waitForExistence(timeout: 3), "invalid port error")
            snap("autoapply-port-invalid")
        }
        back()
    }

    // MARK: 10. 节点管理: a node defined in the profile file is editable (v0.15.4)

    func replaceText(_ f: XCUIElement, _ text: String) {
        f.tap()
        let cur = (f.value as? String) ?? ""
        // Cursor to the end, then delete everything.
        f.coordinate(withNormalizedOffset: CGVector(dx: 0.98, dy: 0.5)).tap()
        if !cur.isEmpty { f.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: cur.count + 2)) }
        f.typeText(text)
    }

    func openAllNodes() {
        openMore("节点管理")
        XCTAssertTrue(tapIfExists(app.element(label: L("全部节点")), timeout: 8), "全部节点")
    }

    func test10_ProfileNodeEdit() {
        launch()
        openAllNodes()
        let node = app.element(label: "🇯🇵 Tokyo 02")
        XCTAssertTrue(scrollTo(node), "profile node")
        node.tap()
        let edit = app.element(id: "node.edit")
        XCTAssertTrue(scrollTo(edit), "编辑 offered for a node from the profile file")
        snap("profile-node-detail")
        edit.tap()
        XCTAssertTrue(app.navigationBars[L("编辑节点")].waitForExistence(timeout: 6), "node editor")
        let name = app.textFields[L("名称")]
        XCTAssertTrue(name.waitForExistence(timeout: 4))
        replaceText(name, "Tokyo 02 Edited")
        let server = app.textFields[L("服务器")]
        replaceText(server, "192.0.2.222")
        snap("profile-node-editor")
        app.navigationBars.buttons[L("保存")].tap()
        let gone = NSPredicate(format: "exists == false")
        let closed = XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: gone, object: app.navigationBars[L("编辑节点")])], timeout: 10) == .completed
        if !closed { snap("profile-node-editor-error"); issues.append("[\(Env.tag)] profile node did not save"); closeSheet() }
        usleep(1_000_000)
        // Renamed → the old detail closes; leave and come back, the list is read from the file again.
        for _ in 0..<3 where !app.navigationBars[L("更多")].exists { back() }
        openAllNodes()
        let renamed = app.element(label: "Tokyo 02 Edited")
        XCTAssertTrue(scrollTo(renamed), "renamed node listed after reopening")
        XCTAssertFalse(app.element(label: "🇯🇵 Tokyo 02").exists, "old name still listed")
        renamed.tap()
        XCTAssertTrue(app.element(labelContains: "192.0.2.222").waitForExistence(timeout: 6), "edited server kept")
        snap("profile-node-after")
        // Group members follow the rename (offline picker of the Proxy card on Home).
        for _ in 0..<4 where !app.navigationBars[L("更多")].exists { back() }
        tab(0)
        let card = app.element(id: "home.card.Proxy")
        XCTAssertTrue(card.waitForExistence(timeout: 8))
        card.tap()
        XCTAssertTrue(scrollTo(app.element(label: "Tokyo 02 Edited")), "group member renamed")
        snap("profile-node-group-member")
        back()
    }

    // MARK: 11. 筛选节点: editable filters, rename follows the 策略组, flag fallback (v0.15.4)

    func test11_RegionFilters() {
        launch(["-UITestMissingFlags", "TW"])
        openMore("节点管理")
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        let jp = app.element(id: "filter.JP")
        XCTAssertTrue(jp.waitForExistence(timeout: 8), "JP filter")
        // 🇹🇼 drawn as a letter badge when the system cannot draw it.
        XCTAssertTrue(app.element(labelContains: "TW").waitForExistence(timeout: 4), "TW badge instead of the 🇹🇼 glyph")
        XCTAssertFalse(app.element(labelContains: "🇹🇼").exists, "undrawable flag still shown")
        snap("filters-flag-fallback")

        // Rename + type
        jp.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("编辑筛选")), timeout: 3), "edit action")
        let name = app.textFields.matching(identifier: "filter.name").firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        replaceText(name, "JP UI")
        snap("filter-editor")
        app.navigationBars.buttons[L("保存")].tap()
        XCTAssertTrue(app.element(labelContains: "JP UI").waitForExistence(timeout: 5), "renamed filter")

        // Add as a group, then rename again: the group follows.
        jp.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("加为策略组")), timeout: 3), "add as group")
        XCTAssertTrue(app.element(label: L("已加为策略组")).waitForExistence(timeout: 10), "group added")
        jp.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("编辑筛选")), timeout: 3))
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        replaceText(name, "JP Group 2")
        app.navigationBars.buttons[L("保存")].tap()
        XCTAssertTrue(app.element(labelContains: "JP Group 2").waitForExistence(timeout: 8), "renamed group filter")
        snap("filters-renamed-group")
        // Duplicate names are refused.
        jp.swipeLeft()
        XCTAssertTrue(tapIfExists(app.button(L("编辑筛选")), timeout: 3))
        replaceText(name, "Proxy")
        XCTAssertFalse(app.navigationBars.buttons[L("保存")].isEnabled, "duplicate group name accepted")
        closeSheet()

        // Leave and reopen: kept; 策略 shows the renamed group.
        back()
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        XCTAssertTrue(app.element(labelContains: "JP Group 2").waitForExistence(timeout: 6), "filter kept after reopening")
        for _ in 0..<3 where !app.navigationBars[L("更多")].exists { back() }
        tab(1)
        XCTAssertTrue(scrollTo(app.element(labelContains: "JP Group 2")), "renamed group on 策略")
        snap("filters-group-on-policy")

        // New filter via +
        tab(4)
        openMore("节点管理")
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        XCTAssertTrue(tapIfExists(app.element(id: "filters.add"), timeout: 4), "+")
        let n2 = app.textFields.matching(identifier: "filter.name").firstMatch
        XCTAssertTrue(n2.waitForExistence(timeout: 5))
        n2.tap(); n2.typeText("Hy2 Nodes")
        let pat = app.textFields.matching(identifier: "filter.pattern").firstMatch
        pat.tap(); pat.typeText("Hy2")
        app.navigationBars.buttons[L("保存")].tap()
        XCTAssertTrue(scrollTo(app.element(labelContains: "Hy2 Nodes")), "custom filter listed")
        snap("filters-custom")
    }

    // v0.15.4: Loon-style 节点来源 per filter (本地节点 / 全部订阅 / chosen subscriptions) + 关键词 / 排除关键词.
    func test12_FilterSources() {
        launch()
        openMore("节点管理")
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        XCTAssertTrue(tapIfExists(app.element(id: "filters.add"), timeout: 4), "+")
        let name = app.textFields.matching(identifier: "filter.name").firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap(); name.typeText("Sub Only")
        let pat = app.textFields.matching(identifier: "filter.pattern").firstMatch
        pat.tap(); pat.typeText("Seoul|Tokyo")
        func flip(_ id: String) -> XCUIElement {
            let sw = app.switches.matching(identifier: id).firstMatch
            if scrollTo(sw, maxSwipes: 4) { sw.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap() }
            usleep(400_000)
            return sw
        }
        let local = flip("filter.src.local")
        XCTAssertEqual(local.value as? String, "0", "本地节点 off")
        let all = flip("filter.src.all")
        XCTAssertEqual(all.value as? String, "0", "全部订阅 off")
        // Nothing chosen → not savable.
        XCTAssertFalse(app.navigationBars.buttons[L("保存")].isEnabled, "saved without a node source")
        // The seed's node subscription appears as a source once 全部订阅 is off.
        let demo = app.switches.matching(identifier: "filter.src.Demo Sub").firstMatch
        if demo.waitForExistence(timeout: 3) {
            _ = flip("filter.src.Demo Sub")
        } else {
            _ = flip("filter.src.local") // no provider offline: local only still exercises the mapping
        }
        let exclude = app.textFields.matching(identifier: "filter.exclude").firstMatch
        if scrollTo(exclude, maxSwipes: 4) { exclude.tap(); exclude.typeText("02") }
        usleep(900_000)
        snap("filter-sources")
        XCTAssertTrue(app.navigationBars.buttons[L("保存")].isEnabled, "save enabled with a source")
        app.navigationBars.buttons[L("保存")].tap()
        XCTAssertTrue(scrollTo(app.element(labelContains: "Sub Only")), "filter with sources listed")
        // Reopen: the sources were kept.
        back()
        XCTAssertTrue(tapIfExists(app.element(label: L("筛选节点")), timeout: 8))
        let row = app.element(labelContains: "Sub Only")
        XCTAssertTrue(scrollTo(row), "kept after reopening")
        row.press(forDuration: 1.0)
        XCTAssertTrue(tapIfExists(app.button(L("编辑筛选")), timeout: 3), "edit from the context menu")
        let local2 = app.switches.matching(identifier: "filter.src.local").firstMatch
        XCTAssertTrue(local2.waitForExistence(timeout: 5))
        XCTAssertEqual(app.switches.matching(identifier: "filter.src.all").firstMatch.value as? String, "0", "全部订阅 stays off")
        snap("filter-sources-reopened")
        closeSheet()
    }

    // MARK: 13. v0.16 rule chips: coloured type chip + policy chip in 规则

    func test13_RuleChips() {
        launch()
        openMore("规则")
        XCTAssertTrue(app.element(id: "ruletype.DOMAIN-SUFFIX").waitForExistence(timeout: 10), "DOMAIN-SUFFIX chip")
        XCTAssertTrue(app.element(id: "policychip.Apple").exists, "policy chip Apple")
        XCTAssertTrue(app.element(id: "ruletype.DOMAIN-KEYWORD").exists, "DOMAIN-KEYWORD chip")
        XCTAssertTrue(app.element(id: "policychip.Streaming").exists, "policy chip Streaming")
        XCTAssertTrue(app.element(id: "ruletype.IP-CIDR").exists, "IP-CIDR chip")
        XCTAssertTrue(app.element(id: "policychip.DIRECT").exists, "policy chip DIRECT")
        let match = app.element(id: "ruletype.MATCH")
        if !match.exists { app.swipeUp() }
        XCTAssertTrue(match.waitForExistence(timeout: 5), "MATCH chip")
        snap("rules-chips")
    }

    // MARK: 14. v0.16 DNS 日志 (seeded through the real log-line parser)

    func test14_DNSLog() {
        launch()
        openMore("DNS 日志")
        XCTAssertTrue(app.element(labelContains: "www.example.com").waitForExistence(timeout: 8), "parsed query")
        XCTAssertTrue(app.element(labelContains: "api.example.org").exists, "parsed cache hit")
        XCTAssertTrue(app.element(labelContains: "broken.example.invalid").exists, "parsed resolve error")
        snap("dnslog-queries")
        let search = app.searchFields.firstMatch
        for _ in 0..<6 where !search.exists { app.swipeDown(velocity: .fast) }
        if search.waitForExistence(timeout: 4) {
            search.tap()
            search.typeText("v6.example")
            usleep(800_000)
            XCTAssertTrue(app.element(labelContains: "v6.example.net").exists, "search hit")
            XCTAssertFalse(app.element(labelContains: "www.example.com").exists, "search filters others")
            snap("dnslog-search")
            let cancel = app.buttons[L("取消")].exists ? app.buttons[L("取消")] : app.buttons["Cancel"]
            if cancel.exists { cancel.tap() }
            usleep(500_000)
        } else { issues.append("[\(Env.tag)] DNS 日志: no search field") }
        let blockedTab = app.buttons[L10n.f("拦截 %lld", 3)].firstMatch
        XCTAssertTrue(blockedTab.waitForExistence(timeout: 5), "拦截 3 tab")
        blockedTab.tap()
        let ads = app.element(labelContains: "ads.example.com")
        XCTAssertTrue(ads.waitForExistence(timeout: 5), "blocked domain listed")
        XCTAssertTrue(ads.label.contains("2"), "tally 2 for ads.example.com: \(ads.label)")
        XCTAssertTrue(app.element(labelContains: "tracker.example.net").exists, "REJECT-DROP via group counted")
        snap("dnslog-blocked")
        XCTAssertTrue(tapIfExists(app.element(id: "dnslog.clear")), "清空")
        XCTAssertTrue(app.element(label: L("没有被拦截的域名")).waitForExistence(timeout: 5), "cleared")
        snap("dnslog-cleared")
    }

    // MARK: 15. v0.16 全部重写规则 (flat list from 模块与资源 and 本地模块)

    func test15_AllRewrites() {
        launch()
        openMore("模块与资源")
        let entry = app.element(id: "modules.allRewrites")
        XCTAssertTrue(scrollTo(entry), "全部重写规则 entry")
        entry.tap()
        XCTAssertTrue(app.navigationBars[L("全部重写规则")].waitForExistence(timeout: 6), "page opens")
        let row = app.element(labelContains: "UITest Panel Module")
        XCTAssertTrue(row.waitForExistence(timeout: 6), "module rewrite listed with its source")
        // (the row label carries the pattern, kind, phase and source)
        snap("all-rewrites")
        let search = app.searchFields.firstMatch
        for _ in 0..<6 where !search.exists { app.swipeDown(velocity: .fast) }
        if search.waitForExistence(timeout: 4) {
            search.tap()
            search.typeText("nomatch-uitest")
            usleep(700_000)
            XCTAssertFalse(app.element(labelContains: "UITest Panel Module").exists, "search filters")
            snap("all-rewrites-search")
            let cancel = app.buttons[L("取消")].exists ? app.buttons[L("取消")] : app.buttons["Cancel"]
            if cancel.exists { cancel.tap() }
        } else { issues.append("[\(Env.tag)] 全部重写规则: no search field") }
        back()
        back()
        // Also reachable from 本地模块.
        openMore("重写（本地模块）")
        let local = app.element(id: "localmodule.allRewrites")
        XCTAssertTrue(local.waitForExistence(timeout: 6), "entry in 本地模块")
        local.tap()
        XCTAssertTrue(app.navigationBars[L("全部重写规则")].waitForExistence(timeout: 6), "page opens from 本地模块")
    }

    // MARK: 16. v0.16 策略 mode control drives the same mode as Home

    func test16_PolicyModeControl() {
        launch()
        tab(1)
        let seg = app.segmentedControls.matching(identifier: "policy.mode").firstMatch
        XCTAssertTrue(seg.waitForExistence(timeout: 8), "mode control above the policy cards")
        let global = seg.buttons[L("全局")]
        XCTAssertTrue(global.exists, "全局 segment")
        global.tap()
        usleep(600_000)
        XCTAssertTrue(global.isSelected, "全局 selected")
        snap("policy-mode-global")
        tab(0)
        let homeGlobal = app.segmentedControls.buttons.matching(NSPredicate(format: "label == %@", L("全局"))).firstMatch
        for _ in 0..<4 where !(homeGlobal.exists && homeGlobal.isHittable) { app.swipeUp(velocity: .slow) }
        if homeGlobal.exists { XCTAssertTrue(homeGlobal.isSelected, "Home 出站模式 follows") } else { warnings.append("Home 出站模式 not on screen") }
        tab(1)
        let rule = seg.buttons[L("规则")]
        rule.tap()
        usleep(600_000)
        XCTAssertTrue(rule.isSelected, "back to 规则")
        // Survives a relaunch (saved in the overrides).
        global.tap()
        usleep(600_000)
        app.terminate()
        let a = XCUIApplication()
        a.launchArguments = ["-AppleLanguages", "(\(Env.lang))", "-appearance", Env.style]
        a.launch()
        app = a
        tab(1)
        let seg2 = app.segmentedControls.matching(identifier: "policy.mode").firstMatch
        XCTAssertTrue(seg2.waitForExistence(timeout: 10))
        XCTAssertTrue(seg2.buttons[L("全局")].isSelected, "mode persisted")
        seg2.buttons[L("规则")].tap()
    }

    // MARK: 17. v0.16 请求 summary bar (synthetic connections)

    func test17_RequestsSummary() {
        launch(["-UITestDemoConnections"])
        tab(2)
        XCTAssertTrue(app.element(id: "requests.tcpCount").waitForExistence(timeout: 8), "summary bar")
        XCTAssertEqual(app.element(id: "requests.tcpCount").label, "2", "TCP count")
        XCTAssertEqual(app.element(id: "requests.udpCount").label, "1", "UDP count")
        XCTAssertTrue(app.element(labelContains: "/s").exists, "speed shown")
        XCTAssertTrue(app.element(id: "ruletype.DOMAIN-SUFFIX").exists, "connection rule chip")
        snap("requests-summary")
        let closeAll = app.element(id: "requests.closeAll")
        XCTAssertTrue(closeAll.waitHittable(), "全部断开")
        closeAll.tap()
        let confirm = app.sheets.buttons[L("全部断开")].exists ? app.sheets.buttons[L("全部断开")]
            : app.buttons.matching(NSPredicate(format: "label == %@", L("全部断开"))).element(boundBy: 1)
        XCTAssertTrue(confirm.waitForExistence(timeout: 4), "confirmation")
        confirm.tap()
        usleep(700_000)
        XCTAssertEqual(app.element(id: "requests.tcpCount").label, "0", "closed")
        snap("requests-summary-closed")
    }

    // MARK: 18. v0.16 按网络切换策略: permission status inline

    func test18_SSIDPermissions() {
        launch()
        openMore("连接方式")
        let link = app.element(id: "connection.networkPolicy")
        XCTAssertTrue(scrollTo(link), "按网络切换策略 link")
        link.tap()
        XCTAssertTrue(app.navigationBars[L("按网络切换策略")].waitForExistence(timeout: 6))
        for id in ["ssid.perm.services", "ssid.perm.location", "ssid.perm.wifiinfo"] {
            XCTAssertTrue(app.element(id: id).waitForExistence(timeout: 6), id)
        }
        let loc = app.element(id: "ssid.perm.location")
        XCTAssertTrue(loc.label.contains(L("未请求")), "simulator starts not requested: \(loc.label)")
        XCTAssertTrue(app.element(id: "ssid.perm.wifiinfo").label.contains(L("无描述文件")), "no profile on the simulator")
        snap("ssid-permissions")
        loc.tap()
        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 4), "explanation before the system prompt")
        snap("ssid-permission-explain")
        alert.buttons[L("取消")].tap()
    }

    // MARK: 19. v0.17 请求时间线 + 主机

    /// label + value (LabeledContent puts the trailing text in the value).
    func fullText(_ e: XCUIElement) -> String { e.label + " " + ((e.value as? String) ?? "") }

    func test19_RequestTimeline() {
        launch(["-UITestDemoConnections"])
        tab(2)
        XCTAssertTrue(app.element(id: "requests.tcpCount").waitForExistence(timeout: 8), "requests page")
        // Proxied connection: passive first bytes, active probe without a local DNS phase.
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "www.example.com")).firstMatch
        XCTAssertTrue(scrollTo(row), "connection row")
        row.tap()
        let down = app.element(id: "timeline.passive.down")
        XCTAssertTrue(down.waitForExistence(timeout: 6), "passive first download byte")
        XCTAssertTrue(fullText(down).contains("180–200 ms"), "bound shown as a range: \(fullText(down))")
        XCTAssertTrue(fullText(app.element(id: "timeline.passive.dns")).contains(L("未观察到")), "no DNS for the proxied host")
        snap("timeline-passive")
        let run = app.element(id: "timeline.probe.run")
        XCTAssertTrue(scrollTo(run), "测量 button")
        run.tap()
        let total = app.element(id: "timeline.probe.total")
        XCTAssertTrue(total.waitForExistence(timeout: 6), "probe result")
        XCTAssertTrue(fullText(total).contains("293 ms"), "total: \(fullText(total))")
        let connect = app.element(id: "timeline.probe.connect")
        XCTAssertTrue(scrollTo(connect))
        XCTAssertTrue(fullText(connect).contains("52 ms"), "connect: \(fullText(connect))")
        let dns = app.element(id: "timeline.probe.dns")
        XCTAssertTrue(fullText(dns).contains("—"), "DNS not measured through a proxy: \(fullText(dns))")
        snap("timeline-probe-proxy")
        back()
        // DIRECT connection: DNS seen passively and measured actively.
        let row2 = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "api.example.org")).firstMatch
        XCTAssertTrue(scrollTo(row2), "direct connection row")
        row2.tap()
        let pdns = app.element(id: "timeline.passive.dns")
        XCTAssertTrue(pdns.waitForExistence(timeout: 6))
        XCTAssertTrue(fullText(pdns).contains("24 ms"), "passive DNS: \(fullText(pdns))")
        let run2 = app.element(id: "timeline.probe.run")
        XCTAssertTrue(scrollTo(run2))
        run2.tap()
        XCTAssertTrue(app.element(id: "timeline.probe.total").waitForExistence(timeout: 6))
        let dns2 = app.element(id: "timeline.probe.dns")
        XCTAssertTrue(scrollTo(dns2))
        XCTAssertTrue(fullText(dns2).contains("18 ms"), "direct DNS measured: \(fullText(dns2))")
        snap("timeline-probe-direct")
        back()
        // UDP connection that was open before recording: no timings, said so.
        let row3 = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "quic.example.net")).firstMatch
        XCTAssertTrue(scrollTo(row3))
        row3.tap()
        XCTAssertTrue(app.element(id: "timeline.passive.none").waitForExistence(timeout: 6), "preexisting connection explained")
        back()
        // 主机 aggregate.
        let hosts = app.buttons[L("主机")]
        XCTAssertTrue(scrollTo(hosts), "主机 segment")
        hosts.tap()
        let h = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "api.example.org")).firstMatch
        XCTAssertTrue(h.waitForExistence(timeout: 6), "host row")
        XCTAssertTrue(h.label.contains(L10n.f("%lld 个连接", 1)) || h.label.contains("1"), "count: \(h.label)")
        XCTAssertTrue(h.label.contains("DNS 24 ms"), "host DNS median: \(h.label)")
        snap("timeline-hosts")
        h.tap()
        let median = app.element(labelContains: L("DNS 中位数"))
        XCTAssertTrue(median.waitForExistence(timeout: 6), "host detail with the DNS median")
        snap("timeline-host-detail")
    }

    // MARK: 20. v0.17 按节点设置: remark + test URL in node detail

    func test20_NodeSettings() {
        launch()
        openAllNodes()
        let node = app.element(label: "🇭🇰 Hong Kong 01")
        XCTAssertTrue(scrollTo(node), "node row")
        node.tap()
        let url = app.element(id: "node.settings.url")
        XCTAssertTrue(scrollTo(url), "节点设置 section")
        XCTAssertTrue(url.label.contains(L("跟随全局")), "default follows the global URL: \(url.label)")
        let edit = app.element(id: "node.settings.edit")
        XCTAssertTrue(scrollTo(edit))
        edit.tap()
        let noteField = app.element(id: "node.settings.noteField")
        XCTAssertTrue(noteField.waitForExistence(timeout: 6), "settings sheet")
        noteField.tap()
        noteField.typeText("Home line backup")
        let urlField = app.textFields["node.settings.urlField"]
        XCTAssertTrue(urlField.waitForExistence(timeout: 4))
        urlField.tap()
        urlField.typeText("htp:/bad")
        XCTAssertFalse(app.buttons["node.settings.save"].isEnabled, "invalid URL not savable")
        replaceText(urlField, "https://www.gstatic.com/generate_204")
        snap("node-settings-sheet")
        XCTAssertTrue(app.buttons["node.settings.save"].isEnabled)
        app.buttons["node.settings.save"].tap()
        XCTAssertTrue(app.element(id: "node.settings.note").waitForExistence(timeout: 6), "remark shown in detail")
        XCTAssertEqual(app.element(id: "node.settings.note").label, "Home line backup")
        XCTAssertTrue(app.element(id: "node.settings.url").label.contains("www.gstatic.com"), "custom URL shown")
        XCTAssertTrue(app.element(labelContains: "www.gstatic.com ·").exists || app.element(labelContains: "www.gstatic.com").exists, "test caption uses the node URL")
        snap("node-settings-detail")
        back()
        XCTAssertTrue(app.element(label: "Home line backup").waitForExistence(timeout: 6), "remark in the node list")
        // Other nodes keep the global URL.
        let other = app.element(label: "🇯🇵 Tokyo 01")
        XCTAssertTrue(scrollTo(other))
        other.tap()
        let url2 = app.element(id: "node.settings.url")
        XCTAssertTrue(scrollTo(url2))
        XCTAssertTrue(url2.label.contains(L("跟随全局")), "unaffected node: \(url2.label)")
        back()
        // Clearing both removes the entry.
        let hk = app.element(label: "🇭🇰 Hong Kong 01")
        XCTAssertTrue(scrollTo(hk))
        hk.tap()
        let edit2 = app.element(id: "node.settings.edit")
        XCTAssertTrue(scrollTo(edit2))
        edit2.tap()
        let uf = app.textFields["node.settings.urlField"]
        XCTAssertTrue(uf.waitForExistence(timeout: 6))
        XCTAssertEqual(uf.value as? String, "https://www.gstatic.com/generate_204", "sheet loads the saved URL")
        let reset = app.element(id: "node.settings.reset")
        XCTAssertTrue(scrollTo(reset), "恢复默认 offered when settings exist")
        reset.tap()
        usleep(800_000)
        XCTAssertFalse(app.element(id: "node.settings.note").exists, "remark cleared")
        XCTAssertTrue(app.element(id: "node.settings.url").label.contains(L("跟随全局")))
    }

    // MARK: 21. v0.17 磁贴编辑: title / icon / refresh interval as an override

    func openPanelEditor(_ title: String) {
        let card = app.staticTexts.matching(NSPredicate(format: "label == %@", title)).firstMatch
        XCTAssertTrue(card.waitForExistence(timeout: 8), "panel \(title)")
        card.press(forDuration: 1.2)
        let edit = app.buttons[L("编辑面板…")]
        XCTAssertTrue(edit.waitForExistence(timeout: 4), "编辑面板… in the context menu")
        edit.tap()
        XCTAssertTrue(app.navigationBars[L("编辑面板")].waitForExistence(timeout: 6), "tile editor")
    }

    func test21_TileEditing() {
        launch(["-UITestDemoPanels", "-UITestScreen", "panels"])
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "Demo Script Panel")).firstMatch.waitForExistence(timeout: 8), "demo panels")
        XCTAssertTrue(app.element(id: "panel.interval").label.contains(L("每小时")), "module interval shown: \(app.element(id: "panel.interval").label)")
        snap("tiles")
        openPanelEditor("Demo Script Panel")
        let title = app.textFields["panel.edit.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 4))
        title.tap()
        title.typeText("My Speed")
        let icon = app.element(id: "panel.edit.icon.speedometer")
        XCTAssertTrue(scrollTo(icon), "icon grid")
        icon.tap()
        let five = app.buttons[L("每 5 分钟")]
        XCTAssertTrue(scrollTo(five), "interval choices for a script panel")
        five.tap()
        XCTAssertTrue(app.element(id: "panel.edit.preview").label.contains("My Speed"), "preview follows the title")
        snap("tile-editor")
        app.buttons["panel.edit.save"].tap()
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "My Speed")).firstMatch.waitForExistence(timeout: 6), "override title shown")
        XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label == %@", "Demo Script Panel")).firstMatch.exists, "module title replaced")
        XCTAssertTrue(app.element(id: "panel.interval").label.contains(L("每 5 分钟")), "override interval shown")
        snap("tiles-edited")
        // Static Stash tile: title / icon only, no interval.
        openPanelEditor("Demo Tile")
        XCTAssertFalse(app.buttons[L("每 5 分钟")].exists, "no interval for a static tile")
        let iconField = app.textFields["panel.edit.iconField"]
        XCTAssertTrue(scrollTo(iconField))
        iconField.tap()
        iconField.typeText("not.a.symbol.xyz")
        XCTAssertFalse(app.buttons["panel.edit.save"].isEnabled, "unknown SF Symbol refused")
        app.navigationBars.buttons[L("取消")].tap()
        usleep(600_000)
        // Reset the script panel to the module's values.
        openPanelEditor("My Speed")
        XCTAssertEqual(app.textFields["panel.edit.title"].value as? String, "My Speed", "editor loads the override")
        let reset = app.buttons["panel.edit.reset"]
        XCTAssertTrue(scrollTo(reset))
        reset.tap()
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "Demo Script Panel")).firstMatch.waitForExistence(timeout: 6), "module title back")
        XCTAssertTrue(app.element(id: "panel.interval").label.contains(L("每小时")), "module interval back")
    }
}
