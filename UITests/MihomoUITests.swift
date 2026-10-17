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
            if r.exists && r.isSelected { r.tap() }
        }
        // Rows report selection through the trait; tap any still selected one again.
        for g in ["Proxy", "Auto", "Fallback", "Streaming", "Apple", "Final"] {
            let r = app.element(id: "homegroups.row." + g)
            if r.exists && r.isSelected { r.tap() }
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
        "连接分析", "流量统计", "日志", "备份与恢复", "配置快照", "存储空间", "外观", "内核设置", "测速", "出口信息查询",
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
        XCTAssertTrue(app.element(label: "🇰🇷 Seoul Sub 01").waitForExistence(timeout: 5), "subscription node listed")
        XCTAssertTrue(app.element(label: "Manual SS").waitForExistence(timeout: 5), "manual node listed")
        snap("nodes-all")

        // Search
        let search = app.searchFields.firstMatch
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
        if tapIfExists(app.button(L("协议")), timeout: 3) {
            snap("nodes-protocols")
            if tapIfExists(app.button("Hysteria2"), timeout: 3) {
                usleep(700_000)
                XCTAssertTrue(app.element(label: "🇸🇬 Singapore Hy2").exists, "hy2 node after filter")
                XCTAssertFalse(app.element(label: "🇯🇵 Tokyo 01").exists, "ss node hidden by filter")
                snap("nodes-filter-hy2")
            } else { issues.append("[\(Env.tag)] protocol Hysteria2 not in the filter menu") }
        } else { issues.append("[\(Env.tag)] 协议 submenu missing") }
        menu.tap()
        if tapIfExists(app.button(L("协议")), timeout: 3) { _ = tapIfExists(app.button(L("全部协议")), timeout: 3) }
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
        XCTAssertTrue(app.element(label: "🇹🇼 Taipei Sub").waitForExistence(timeout: 8), "subscription nodes")
        snap("nodes-sub")
        back()
        // 本地节点
        XCTAssertTrue(tapIfExists(app.element(label: L("本地节点"))))
        XCTAssertTrue(app.element(label: "Manual Hy2").waitForExistence(timeout: 8), "local nodes")
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
            // Protocol credentials (best effort: the first secure field).
            let sec = app.secureTextFields.firstMatch
            if sec.exists { sec.tap(); sec.typeText("uitest-secret-form") }
            app.swipeUp()
            snap(String(format: "editor-%d-bottom", i))
            let save = app.navigationBars.buttons[L("保存")]
            XCTAssertTrue(save.waitHittable(), "保存 \(e.0)")
            save.tap()
            if app.navigationBars[L("添加节点")].waitForExistence(timeout: 1.5) && app.navigationBars.buttons[L("保存")].exists {
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
            XCTAssertTrue(app.element(label: n).waitForExistence(timeout: 6), "saved node \(n)")
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
}
