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

    /// feat/surge-ui: rows on 更多 itself, then the expert rows that moved to 更多 → 高级设置. Ids are the old
    /// zh-Hans keys (titles changed to plain language).
    static let moreRows = [
        "节点与订阅", "规则", "模块与资源", "日志", "DNS 日志", "连接分析", "网络工具（Ping / TCP / DNS）", "网络测试（带宽 / NAT 类型）",
        "解锁检测", "内网 IP 与路由器", "流量统计", "配置快照", "备份与恢复", "存储空间", "外观", "App 图标", "开始标签页", "首页流量统计",
        "诊断", "关于 / 开源许可",
    ]
    static let advancedRows = [
        "连接方式", "DNS", "MitM", "地理与规则库", "内核设置", "测速", "出口信息查询",
    ]
    /// feat/more-dedup: 重写 / 脚本 / 定时任务 / 配置里的规则集 live only on 更多 → 模块 (ids unchanged).
    static let moduleRows = [
        "重写（本地模块）", "脚本", "任务", "规则集（配置）", "模块库", "全部重写规则",
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
        // 高级设置: every row opens and comes back to 高级设置.
        let adv = app.element(id: "more.高级设置")
        XCTAssertTrue(scrollTo(adv), "高级设置")
        adv.tap()
        usleep(800_000)
        snap("more-advanced")
        for (i, key) in Self.advancedRows.enumerated() {
            let row = app.element(id: "more." + key)
            guard scrollTo(row) else { issues.append("[\(Env.tag)] 高级设置 → \(key) missing"); continue }
            row.tap()
            usleep(900_000)
            snap(String(format: "more-adv-%02d", i))
            assertAlive("高级设置 → \(key)")
            back()
            if !app.navigationBars[L("高级设置")].waitForExistence(timeout: 4) {
                issues.append("[\(Env.tag)] 高级设置 → \(key): did not return")
                openMore("高级设置")
            }
        }
        back()
        // 模块: every row opens and comes back to 模块.
        openMore("模块与资源")
        XCTAssertTrue(app.navigationBars[L("模块")].waitForExistence(timeout: 5), "模块 page")
        snap("more-modules")
        for (i, key) in Self.moduleRows.enumerated() {
            let row = app.element(id: "more." + key)
            guard scrollTo(row) else { issues.append("[\(Env.tag)] 模块 → \(key) missing"); continue }
            row.tap()
            usleep(900_000)
            snap(String(format: "more-mod-%02d", i))
            assertAlive("模块 → \(key)")
            back()
            if !app.navigationBars[L("模块")].waitForExistence(timeout: 4) {
                issues.append("[\(Env.tag)] 模块 → \(key): did not return")
                openMore("模块与资源")
            }
        }
        back()
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
        let row = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(row))
        row.tap()
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 8))
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
            // The list re-renders after the menu closes; give it a moment (en-dark flake, v0.18).
            let hidden = NSPredicate(format: "exists == false")
            _ = XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: hidden, object: app.element(label: "🇯🇵 Tokyo 01"))], timeout: 4)
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
        // v0.17: the 节点设置 section sits above 基本, so 凭据 can be below the fold (lazy List, en is taller).
        // Existence only: a List section header is not always hittable, so scrollTo() cannot be used here.
        let cred = app.element(label: L("凭据"))
        let masked = app.element(labelContains: "••••••")
        // #68: credential rows carry their own accessibility label (no dots) and the en header reads CREDENTIALS,
        // so also accept any node.cred.label.<key> row.
        let credRow = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "node.cred.label.")).firstMatch
        _ = app.element(label: L("基本")).waitForExistence(timeout: 10)
        usleep(1_000_000)
        for _ in 0..<8 where !(cred.exists || masked.exists || credRow.exists) {
            app.swipeUp(velocity: .slow)
            usleep(400_000)
        }
        XCTAssertTrue(cred.exists || masked.exists || credRow.exists, "credentials section")
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
            // Review 5: removing the group asks first.
            XCTAssertTrue(tapIfExists(app.element(id: "filter.confirmRemove"), timeout: 4), "remove confirmation")
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
        let row = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(row))
        row.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "nodes.add"), timeout: 8), "+")
        XCTAssertTrue(tapIfExists(app.button(L("添加节点")), timeout: 4), "添加节点 in the + menu")
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

    /// Review 5 P2-10: 连接方式 switches by accessibility id (labels differ per language and are long in en).
    func connSwitch(_ label: String) -> XCUIElement {
        let ids = ["接管所有网络流量": "conn.includeAll", "局域网共享": "conn.allowLan"]
        if let id = ids[label] { return app.switches.matching(identifier: id).firstMatch }
        return app.switches[L(label)]
    }

    /// feat/surge-ui: expert rows live on 更多 → 高级设置; open that page first unless it is already showing.
    /// Re-tapping the 更多 tab can pop 高级设置 while the row check runs, so let the tab settle first and
    /// re-enter 高级设置 once if the row vanished (zh-light test09 race on surge-ui, 2026-10-21).
    func openMore(_ key: String) {
        tab(4)
        usleep(500_000)
        let row = app.element(id: "more." + key)
        if Self.moduleRows.contains(key) {
            let mod = app.element(id: "more.模块与资源")
            if !(row.waitForExistence(timeout: 1) && row.isHittable) {
                if !mod.waitForExistence(timeout: 1) { tab(4); usleep(500_000) }
                XCTAssertTrue(scrollTo(mod), "模块")
                mod.tap()
                usleep(800_000)
            }
        } else if Self.advancedRows.contains(key) {
            func enterAdvanced() {
                let adv = app.element(id: "more.高级设置")
                if !adv.waitForExistence(timeout: 1) { tab(4); usleep(500_000) }
                XCTAssertTrue(scrollTo(adv), "高级设置")
                adv.tap()
                usleep(800_000)
            }
            if !(row.waitForExistence(timeout: 1) && row.isHittable) { enterAdvanced() }
            if !row.waitForExistence(timeout: 2) { tab(4); usleep(800_000); enterAdvanced() }
        }
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
        typeRuleText("DOMAIN-SUFFIX,uitest.example.com,Proxy")
        snap("editor-rule")
        app.element(id: "rule.save").tap()
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
        let gallery = app.element(id: "more.模块库")
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
            let sw = connSwitch(toggle)
            guard scrollTo(sw) else { back(); continue }
            let before = switchValue(sw)
            toggleSwitch(sw)
            usleep(300_000)
            XCTAssertNotEqual(switchValue(sw), before, "\(page): \(toggle) did not toggle")
            snap("autoapply-\(page)")
            usleep(1_200_000)   // debounce 0.5 s + write
            back()
            openMore(page)
            let again = connSwitch(toggle)
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
        openMore("节点与订阅")
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
        openMore("节点与订阅")
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
        openMore("节点与订阅")
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
        openMore("节点与订阅")
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
        // Device report 2026-10-21: QUIC refusals (UDP 443 → TCP fallback) are their own group, not counted as 已拦截.
        let blockedTab = app.buttons[L10n.f("已拦截 %lld", 3)].firstMatch
        XCTAssertTrue(blockedTab.waitForExistence(timeout: 5), "已拦截 3 tab (3 QUIC hits not counted)")
        blockedTab.tap()
        let ads = app.element(labelContains: "ads.example.com")
        XCTAssertTrue(ads.waitForExistence(timeout: 5), "blocked domain listed")
        XCTAssertTrue(ads.label.contains("2"), "tally 2 for ads.example.com: \(ads.label)")
        XCTAssertTrue(app.element(labelContains: "tracker.example.net").exists, "REJECT-DROP via group counted")
        XCTAssertFalse(app.element(labelContains: "Network,udp").exists, "no raw AND(((Network,udp)…)) rule text")
        let quic = app.element(id: "dnslog.quic")
        XCTAssertTrue(quic.waitForExistence(timeout: 5), "QUIC group row")
        XCTAssertTrue(quic.label.contains(L("QUIC 已拦截 · 自动改走 TCP")), "QUIC group title: \(quic.label)")
        XCTAssertTrue(quic.label.contains("3"), "QUIC count 3: \(quic.label)")
        XCTAssertFalse(app.element(labelContains: "app.example.com").exists, "QUIC domains collapsed by default")
        snap("dnslog-blocked")
        quic.tap()
        let app1 = app.element(labelContains: "app.example.com")
        XCTAssertTrue(app1.waitForExistence(timeout: 5), "QUIC domain listed after expanding")
        XCTAssertTrue(app1.label.contains(L("UDP 443（QUIC）")), "humanised QUIC rule: \(app1.label)")
        XCTAssertTrue(app.element(labelContains: "video.example.org").exists, "阻止 QUIC 始终 rule recognised")
        snap("dnslog-quic")
        XCTAssertTrue(tapIfExists(app.element(id: "dnslog.clear")), "清空")
        XCTAssertTrue(app.element(label: L("没有被拦截的域名")).waitForExistence(timeout: 5), "cleared")
        snap("dnslog-cleared")
    }

    // MARK: 15. v0.16 全部重写规则 (flat list from 模块与资源 and 本地模块)

    func test15_AllRewrites() {
        launch()
        openMore("模块与资源")
        let entry = app.element(id: "more.全部重写规则")
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
        // feat/more-dedup: 我的重写 (本地模块) no longer carries a second 全部重写规则 entry.
        openMore("重写（本地模块）")
        XCTAssertTrue(app.element(id: "localmodule.add").waitForExistence(timeout: 6), "我的重写 opens")
        XCTAssertFalse(app.element(id: "localmodule.allRewrites").exists, "no duplicate 全部重写规则 entry")
    }

    // MARK: 16. v0.16 策略 mode control drives the same mode as Home

    func waitSelected(_ e: XCUIElement, _ timeout: TimeInterval) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        repeat {
            if e.exists && e.isSelected { return true }
            usleep(250_000)
        } while Date() < end
        return false
    }

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
        // Survives a relaunch (saved in the overrides). The tap right after 规则 was sometimes dropped on the
        // slower en-light simulator (v0.18 self-test), so wait for the selection (one re-tap) and give the
        // save a moment before terminating.
        global.tap()
        if !waitSelected(global, 3) { global.tap() }
        XCTAssertTrue(waitSelected(global, 3), "全局 selected before relaunch")
        usleep(1_500_000)
        app.terminate()
        let a = XCUIApplication()
        a.launchArguments = ["-AppleLanguages", "(\(Env.lang))", "-appearance", Env.style]
        a.launch()
        app = a
        tab(1)
        let seg2 = app.segmentedControls.matching(identifier: "policy.mode").firstMatch
        XCTAssertTrue(seg2.waitForExistence(timeout: 10))
        XCTAssertTrue(waitSelected(seg2.buttons[L("全局")], 5), "mode persisted")
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
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "My Speed")).firstMatch.waitForExistence(timeout: 3), "preview follows the title")
        let icon = app.element(id: "panel.edit.icon.speedometer")
        XCTAssertTrue(scrollTo(icon), "icon grid")
        icon.tap()
        let five = app.buttons[L("每 5 分钟")]
        XCTAssertTrue(scrollTo(five), "interval choices for a script panel")
        five.tap()
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

    // MARK: 22. v0.18 experimental Tailscale node: editor form, saved node detail

    func test22_TailscaleNode() {
        launch()
        tab(4)
        let row = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(row))
        row.tap()
        XCTAssertTrue(tapIfExists(app.element(id: "nodes.add"), timeout: 8), "+")
        XCTAssertTrue(tapIfExists(app.button(L("添加节点")), timeout: 4), "添加节点 in the + menu")
        let ts = app.buttons["Tailscale"]
        XCTAssertTrue(scrollTo(ts), "Tailscale in 新协议")
        ts.tap()
        XCTAssertTrue(app.navigationBars[L("添加节点")].waitForExistence(timeout: 6), "editor")
        XCTAssertTrue(app.element(id: "node.experimentalWarning").waitForExistence(timeout: 4), "实验性 warning")
        XCTAssertTrue(app.element(id: "node.experimentalWarning").label.contains("50 MB"), "warning mentions the 50 MB limit")
        XCTAssertFalse(app.textFields[L("服务器")].exists, "no server field for Tailscale")
        XCTAssertFalse(app.textFields[L("端口")].exists, "no port field for Tailscale")
        XCTAssertTrue(app.staticTexts[L("设备名")].exists || app.textFields["mihomo-ios"].exists, "hostname field")
        fill(L("名称"), "UITest Tailscale")
        let sec = app.secureTextFields.firstMatch
        XCTAssertTrue(sec.waitForExistence(timeout: 3), "auth key field")
        sec.tap()
        sec.typeText("tskey-auth-uitest-xxxx")
        snap("tailscale-editor")
        app.swipeUp()
        XCTAssertTrue(scrollTo(app.element(label: L("接受子网路由"))), "accept-routes toggle")
        snap("tailscale-editor-bottom")
        let save = app.navigationBars.buttons[L("保存")]
        XCTAssertTrue(save.waitHittable(), "保存 enabled without server / port")
        save.tap()
        let gone = NSPredicate(format: "exists == false")
        let closed = XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: gone, object: app.navigationBars.buttons[L("保存")])], timeout: 8) == .completed
        if !closed {
            snap("tailscale-editor-error")
            XCTFail("Tailscale node did not save")
            closeSheet()
            return
        }
        usleep(600_000)
        back()
        XCTAssertTrue(tapIfExists(app.element(label: L("本地节点"))))
        let node = app.element(label: "UITest Tailscale")
        XCTAssertTrue(scrollTo(node), "saved Tailscale node listed")
        node.tap()
        let mem = app.element(id: "node.tailscale.memory")
        XCTAssertTrue(scrollTo(mem), "Tailscale section with memory link")
        XCTAssertTrue(app.element(id: "node.experimentalWarning").exists, "warning on detail")
        XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "tskey-auth-uitest")).firstMatch.exists, "auth key not shown")
        snap("tailscale-detail")
        mem.tap()
        XCTAssertTrue(app.navigationBars[L("诊断")].waitForExistence(timeout: 6), "opens 诊断")
        // Section headers are upper-cased in English; check the section's content instead (no tunnel in the simulator).
        let memRow = app.element(labelContains: L("暂无内存数据"))
        XCTAssertTrue(memRow.waitForExistence(timeout: 4) || app.element(id: "diag.memory.current").exists, "隧道内存 section")
        snap("tailscale-diagnostics")
    }

    // MARK: 23. v0.18 隧道内存 readout in 更多 → 诊断

    func test23_DiagnosticsMemory() {
        launch(["-UITestDemoMemory"])
        openMore("诊断")
        let cur = app.element(id: "diag.memory.current")
        XCTAssertTrue(cur.waitForExistence(timeout: 8), "当前占用 row")
        XCTAssertTrue(cur.label.contains("23.4 MB"), "current footprint: \(cur.label)")
        XCTAssertTrue(app.element(id: "diag.memory.peak").label.contains("33.0 MB"), "peak: \(app.element(id: "diag.memory.peak").label)")
        XCTAssertTrue(app.element(id: "diag.memory.available").label.contains("26.6 MB"), "available")
        XCTAssertTrue(app.element(id: "diag.memory.limit").label.contains("50.0 MB"), "limit = footprint + available: \(app.element(id: "diag.memory.limit").label)")
        XCTAssertTrue(app.element(label: L("实时")).exists, "live badge")
        let ts = app.element(id: "diag.memory.tailscale")
        XCTAssertTrue(ts.exists, "Tailscale row")
        XCTAssertTrue(ts.label.contains(L("已启动")), "Tailscale state: \(ts.label)")
        XCTAssertTrue(app.element(id: "diag.memory.tsBefore").label.contains("20.5 MB"), "before start")
        XCTAssertTrue(app.element(id: "diag.memory.tsAfter").label.contains("30.0 MB"), "after start")
        snap("diagnostics-memory")
        // Refreshed while open: still there after a few polls, page alive.
        sleep(3)
        XCTAssertTrue(app.element(id: "diag.memory.current").exists, "still shown after refreshes")
        assertAlive("memory refresh")
    }

    // MARK: 24. v0.18 示例配置

    func test24_SampleProfile() {
        launch()
        tab(3)
        let entry = app.element(id: "profiles.sample")
        XCTAssertTrue(scrollTo(entry), "示例配置 entry in 配置")
        entry.tap()
        XCTAssertTrue(app.navigationBars[L("示例配置")].waitForExistence(timeout: 6), "sample page")
        let editor = app.textViews.firstMatch
        XCTAssertTrue(editor.waitForExistence(timeout: 4), "highlighted text")
        let text = (editor.value as? String) ?? ""
        for k in ["proxy-groups:", "rule-providers:", "type: tailscale", "[rewrite_local]", "MATCH,"] {
            XCTAssertTrue(text.contains(k), "sample contains \(k)")
        }
        // The profile text itself is Chinese by design (comments); only the UI around it is localized.
        allowHan = true
        snap("sample-profile")
        app.element(id: "sample.copy").tap()
        XCTAssertTrue(app.button(L("已复制")).waitForExistence(timeout: 3), "copied")
        app.element(id: "sample.create").tap()
        let msg = app.element(id: "sample.message")
        XCTAssertTrue(msg.waitForExistence(timeout: 15), "create result")
        XCTAssertTrue(msg.label.contains(L("示例配置")), "created: \(msg.label)")
        snap("sample-profile-created")
        allowHan = false
        back()
        let rows = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", L("示例配置")))
        XCTAssertTrue(rows.count >= 2, "new profile listed next to the entry")
        snap("sample-profile-list")
    }

    // MARK: 25. v0.19 覆写脚本 (Bettbox switches, run + validate, error, output)

    func test25_OverrideScripts() {
        launch(["-UITestDemoScripts", "-UITestScreen", "scripts"])
        XCTAssertTrue(app.navigationBars[L("覆写脚本")].waitForExistence(timeout: 10), "scripts page")
        XCTAssertTrue(app.element(id: "scripts.row.bettbox-demo.js").waitForExistence(timeout: 6), "demo script row")
        XCTAssertTrue(app.element(id: "scripts.row.broken.js").exists, "disabled broken script row")
        let run = app.element(id: "scripts.run")
        XCTAssertTrue(run.waitHittable(), "运行并校验")
        run.tap()
        XCTAssertTrue(app.element(id: "scripts.result.ok").waitForExistence(timeout: 20), "chain validated")
        snap("scripts-list")

        // Switches declared by the script: 2 policy-group switches + 「其他设置」 with the rest.
        app.element(id: "scripts.row.bettbox-demo.js").tap()
        let ai = app.switches["script.option.AI"]
        XCTAssertTrue(ai.waitForExistence(timeout: 8), "AI switch")
        XCTAssertTrue(app.switches["script.option.Video"].exists, "Video switch")
        XCTAssertFalse(app.switches["script.option.Block Ads"].exists, "others are on a sub page")
        snap("script-detail")
        let others = app.element(id: "script.others")
        XCTAssertTrue(scrollTo(others), "其他设置")
        others.tap()
        let ads = app.switches["script.option.Block Ads"]
        XCTAssertTrue(ads.waitForExistence(timeout: 6), "Block Ads switch")
        XCTAssertTrue(app.switches["script.option.Low Ratio"].exists, "Low Ratio switch")
        snap("script-others")
        back()
        let ai2 = app.switches["script.option.AI"]
        XCTAssertTrue(scrollTo(ai2))
        XCTAssertEqual(switchValue(ai2), "1", "AI on by the script's default")
        toggleSwitch(ai2)
        usleep(2_500_000) // 0.6 s debounce + run
        XCTAssertEqual(switchValue(app.switches["script.option.AI"]), "0", "AI switched off")
        back()
        XCTAssertTrue(app.element(id: "scripts.result.ok").waitForExistence(timeout: 15), "re-run after the switch")
        // The generated config has no AI group now, Video still there.
        let out = app.element(id: "scripts.output")
        XCTAssertTrue(scrollTo(out), "查看生成的配置")
        out.tap()
        let tv = app.textViews.firstMatch
        XCTAssertTrue(tv.waitForExistence(timeout: 6))
        let yaml = (tv.value as? String) ?? ""
        XCTAssertTrue(yaml.contains("name: Video"), "Video group in the output")
        XCTAssertFalse(yaml.contains("name: AI"), "AI group gone after the switch")
        XCTAssertFalse(yaml.contains("openai.com"), "AI rule gone")
        snap("script-output")
        back()

        // A failing script: enabling it shows its runtime error with the line.
        app.element(id: "scripts.row.broken.js").tap()
        let en = app.switches["script.enabled"]
        XCTAssertTrue(en.waitForExistence(timeout: 6))
        toggleSwitch(en)
        let err = app.element(id: "script.error")
        XCTAssertTrue(err.waitForExistence(timeout: 15), "runtime error shown")
        XCTAssertTrue(err.label.contains("boom"), "error text: \(err.label)")
        let linePrefix = L10n.f("第 %lld 行：%@", 3, "").trimmingCharacters(in: .whitespaces)
        XCTAssertTrue(err.label.contains(linePrefix), "line number (\(linePrefix)): \(err.label)")
        snap("script-error")
        back()
        XCTAssertTrue(app.element(id: "scripts.result.error").waitForExistence(timeout: 6), "chain error on the list")
        snap("scripts-error")

        // New script from the template saves and runs.
        let new = app.element(id: "scripts.new")
        XCTAssertTrue(scrollTo(new))
        new.tap()
        XCTAssertTrue(app.navigationBars[L("新建脚本")].waitForExistence(timeout: 6), "editor")
        allowHan = true // the template's comments are Chinese + English on purpose
        snap("script-editor")
        allowHan = false
        app.buttons["scripteditor.save"].tap()
        XCTAssertTrue(app.element(id: "scripts.row.script-3.js").waitForExistence(timeout: 15), "new script listed")
        assertAlive("override scripts")
    }

    // MARK: 26. v0.19 首页内置卡片

    func test26_HomeTiles() {
        launch(["-UITestDemoExitIP", "-UITestDemoMemory"])
        let add = app.element(id: "home.addTiles")
        XCTAssertTrue(scrollTo(add), "添加首页卡片")
        add.tap()
        XCTAssertTrue(app.navigationBars[L("编辑首页面板")].waitForExistence(timeout: 6), "editor")
        for t in ["speed", "traffic", "uptime", "exitip", "lanip", "memory"] {
            let b = app.element(id: "homepanels.add." + t)
            XCTAssertTrue(scrollTo(b), "add \(t)")
            b.tap()
            usleep(300_000)
        }
        XCTAssertTrue(app.element(id: "homepanels.row.memory").waitForExistence(timeout: 4), "memory pinned")
        snap("home-tiles-editor")
        closeSheet()
        func tile(_ t: String) -> XCUIElement {
            app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "home.tile." + t)).firstMatch
        }
        for t in ["speed", "traffic", "uptime", "exitip", "lanip", "memory"] {
            XCTAssertTrue(scrollTo(tile(t)), "tile \(t) on Home")
        }
        let masked = app.element(labelContains: "203.0.•••.•••")
        XCTAssertTrue(scrollTo(masked), "exit IP masked by default")
        snap("home-tiles")
        masked.tap()
        // (the header shows the full exit IP anyway; the card's masked text goes away)
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(labelContains: "203.0.•••.•••"))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 3), .completed, "revealed after a tap")
        XCTAssertTrue(app.element(labelContains: "23.4 MB").exists, "memory demo value")
        snap("home-tiles-revealed")
        // 内网 IP card opens the LAN page.
        let lan = tile("lanip")
        XCTAssertTrue(scrollTo(lan))
        lan.tap()
        XCTAssertTrue(app.navigationBars[L("内网 IP")].waitForExistence(timeout: 6), "LAN page from the card")
        back()
        assertAlive("home tiles")
    }

    // MARK: 27. v0.19 内网 IP 详情

    func test27_LANDetail() {
        launch(["-UITestDemoLAN"])
        openMore("内网 IP 与路由器")
        XCTAssertTrue(app.navigationBars[L("内网 IP")].waitForExistence(timeout: 6))
        let gw = app.element(id: "lan.gateway")
        XCTAssertTrue(gw.waitForExistence(timeout: 6))
        XCTAssertTrue(gw.label.contains("192.0.2.1"), "gateway: \(gw.label)")
        XCTAssertTrue(app.element(id: "lan.openRouter").exists, "打开路由器后台")
        XCTAssertTrue(app.element(id: "lan.iface.en0").exists, "Wi-Fi interface")
        XCTAssertTrue(app.element(labelContains: "192.0.2.23").exists, "LAN address")
        // v0.19.14: 网络类型 is one plain row (device: stray grey 「网络」 box) — tag inline, row no taller than 网关.
        let type = app.element(id: "lan.type")
        XCTAssertTrue(type.exists, "网络类型 row")
        XCTAssertTrue(type.label.contains(L("计费网络")), "tag inline: \(type.label)")
        XCTAssertLessThanOrEqual(type.frame.height, gw.frame.height + 6, "网络类型 row height \(type.frame.height) vs 网关 \(gw.frame.height)")
        snap("lan-detail")
        let share = app.element(id: "lan.share.off")
        XCTAssertTrue(scrollTo(share), "局域网共享 row")
        XCTAssertTrue(app.element(labelContains: "2001:db8::53").exists || app.element(labelContains: "192.0.2.1").exists, "DNS listed")
        snap("lan-detail-share")
    }

    // MARK: 28. v0.19 WebDAV 备份 (in-memory server)

    func test28_WebDAV() {
        launch(["-UITestDemoWebDAV"])
        openMore("备份与恢复")
        let entry = app.element(id: "backup.webdav")
        XCTAssertTrue(scrollTo(entry))
        entry.tap()
        XCTAssertTrue(app.navigationBars[L("WebDAV 备份")].waitForExistence(timeout: 6))
        let backup = app.element(id: "webdav.backup")
        XCTAssertTrue(scrollTo(backup))
        backup.tap()
        let ok = app.alerts.buttons[L("好")]
        XCTAssertTrue(ok.waitForExistence(timeout: 15), "backup done")
        snap("webdav-backed-up")
        ok.tap()
        // Encrypted backup.
        let enc = app.switches["webdav.encrypt"]
        XCTAssertTrue(scrollTo(enc))
        toggleSwitch(enc)
        let pw = app.secureTextFields["webdav.encpassword"]
        XCTAssertTrue(pw.waitForExistence(timeout: 4))
        pw.tap()
        pw.typeText("uitest-pass")
        XCTAssertTrue(scrollTo(app.element(id: "webdav.backup")))
        sleep(1) // keep the second backup's name (seconds) apart
        app.element(id: "webdav.backup").tap()
        XCTAssertTrue(ok.waitForExistence(timeout: 20), "encrypted backup done")
        ok.tap()
        let encRow = app.element(labelContains: L("已加密"))
        XCTAssertTrue(scrollTo(encRow), "encrypted version listed")
        snap("webdav-versions")
        // Restore it: password sheet, wrong then right.
        encRow.tap()
        let restore = app.buttons[L("恢复")]
        XCTAssertTrue(restore.waitForExistence(timeout: 5), "confirm restore")
        restore.tap()
        let bpw = app.secureTextFields["backup.password"]
        XCTAssertTrue(bpw.waitForExistence(timeout: 10), "password sheet")
        bpw.tap()
        bpw.typeText("wrong")
        app.buttons["backup.password.restore"].tap()
        XCTAssertTrue(app.element(labelContains: L("密码不对，或备份已损坏")).waitForExistence(timeout: 15), "wrong password refused")
        snap("webdav-wrong-password")
        bpw.tap()
        bpw.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 6) + "uitest-pass")
        app.buttons["backup.password.restore"].tap()
        XCTAssertTrue(ok.waitForExistence(timeout: 20), "restored")
        snap("webdav-restored")
        ok.tap()
        assertAlive("webdav")
    }

    // MARK: 29. v0.19 解锁检测 → 检测项目

    func test29_UnlockServices() {
        launch()
        openMore("解锁检测")
        let svc = app.element(id: "unlock.services")
        XCTAssertTrue(svc.waitForExistence(timeout: 6), "检测项目 while disconnected")
        XCTAssertTrue(svc.label.contains("14/14"), "all services by default: \(svc.label)")
        XCTAssertTrue(app.switches["unlock.auto"].exists, "auto re-test switch")
        svc.tap()
        XCTAssertTrue(app.navigationBars[L("检测项目")].waitForExistence(timeout: 6))
        let copilot = app.switches["unlock.service.copilot"]
        XCTAssertTrue(scrollTo(copilot), "Copilot in AI")
        toggleSwitch(copilot)
        let mytv = app.switches["unlock.service.mytvsuper"]
        XCTAssertTrue(scrollTo(mytv))
        toggleSwitch(mytv)
        snap("unlock-services")
        back()
        XCTAssertTrue(app.element(id: "unlock.services").label.contains("12/14"), "two off: \(app.element(id: "unlock.services").label)")
        snap("unlock-disconnected")
    }

    // MARK: 30. v0.19 small toggles + 局域网多用户

    func test30_SettingsToggles() {
        launch()
        openMore("内核设置")
        let close = app.switches["settings.closeOnSwitch"]
        let flush = app.switches["settings.flushDNS"]
        XCTAssertTrue(close.waitForExistence(timeout: 6), "close connections switch")
        XCTAssertTrue(flush.exists, "flush DNS switch")
        XCTAssertEqual(switchValue(close), "1", "on by default")
        XCTAssertEqual(switchValue(flush), "1", "on by default")
        toggleSwitch(flush)
        usleep(1_500_000)
        snap("settings-connection")
        back()
        openMore("内核设置")
        XCTAssertEqual(switchValue(app.switches["settings.flushDNS"]), "0", "flush DNS kept off")
        toggleSwitch(app.switches["settings.flushDNS"])
        usleep(1_200_000)
        back()
        // 局域网多用户 under 连接方式 → 局域网共享.
        openMore("连接方式")
        let lan = connSwitch("局域网共享")
        XCTAssertTrue(scrollTo(lan), "局域网共享 switch")
        if switchValue(lan) != "1" { toggleSwitch(lan) }
        let users = app.element(id: "lan.users")
        XCTAssertTrue(scrollTo(users), "其他用户")
        users.tap()
        XCTAssertTrue(app.navigationBars[L("其他用户")].waitForExistence(timeout: 6))
        app.element(id: "lan.users.add").tap()
        let name = app.textFields["lan.user.0.name"]
        XCTAssertTrue(name.waitForExistence(timeout: 4))
        name.tap()
        name.typeText("a:b")
        XCTAssertTrue(app.element(labelContains: L("用户名不能包含冒号")).waitForExistence(timeout: 3), "colon refused")
        replaceText(name, "tv")
        let pw = app.secureTextFields["lan.user.0.password"]
        pw.tap()
        pw.typeText("secret1")
        usleep(800_000)
        snap("lan-users")
        back()
        XCTAssertTrue(app.element(id: "lan.users").label.contains("1"), "one extra user: \(app.element(id: "lan.users").label)")
        // Put 局域网共享 back off.
        let lan2 = connSwitch("局域网共享")
        if scrollTo(lan2), switchValue(lan2) == "1" { toggleSwitch(lan2) }
        usleep(1_200_000)
    }

    // MARK: 31. feat/group-order: direct long-press drag in the policy list, 编辑排序 mode (置顶 + drag handle,
    // 完成), 置顶 from the group icon's context menu, tap-to-expand still working. Every save rewrites the profile
    // file; the offline list is read back from it.
    func test31_GroupOrder() {
        launch()
        tab(1)
        let card: (String) -> XCUIElement = { self.app.element(id: "policy.card." + $0) }
        func above(_ a: String, _ b: String, _ timeout: Double = 6) -> Bool {
            let deadline = Date().addingTimeInterval(timeout)
            repeat {
                if card(a).exists && card(b).exists && card(a).frame.minY < card(b).frame.minY { return true }
                usleep(250_000)
            } while Date() < deadline
            return false
        }
        XCTAssertTrue(card("Proxy").waitForExistence(timeout: 10), "policy cards")
        XCTAssertTrue(above("Proxy", "Apple", 2), "seed order: Proxy before Apple")
        XCTAssertFalse(app.element(id: "policy.orderSource").exists, "the seeded profile is an original, not a copy")
        snap("policy-before-order")

        // 1. Direct drag: long-press Apple's header and drop it on Proxy.
        XCTAssertTrue(card("Apple").waitForExistence(timeout: 6), "Apple card")
        card("Apple").press(forDuration: 1.2, thenDragTo: card("Proxy"), withVelocity: .slow, thenHoldForDuration: 0.8)
        XCTAssertTrue(above("Apple", "Proxy", 8), "drag: Apple dropped above Proxy")
        snap("policy-dragged")
        // The first reorder never rewrites the original: it creates 「UITest Demo (自定义)」 and switches to it.
        let source = app.element(id: "policy.orderSource")
        XCTAssertTrue(source.waitForExistence(timeout: 8), "switched to the 自定义 copy")
        XCTAssertTrue(source.label.contains("UITest Demo"), "copy names its source: \(source.label)")
        XCTAssertTrue(above("Apple", "Proxy", 8), "the copy has the dragged order")
        usleep(1_000_000)

        // 2. 编辑排序 mode: the list re-reads the file, so Apple is first there too.
        let edit = app.element(id: "policy.editOrder")
        XCTAssertTrue(scrollTo(edit), "编辑排序 above the groups")
        edit.tap()
        let done = app.element(id: "grouporder.done")
        XCTAssertTrue(done.waitForExistence(timeout: 6), "完成 in reorder mode")
        let row: (String) -> XCUIElement = { self.app.element(id: "grouporder.row." + $0) }
        XCTAssertTrue(row("Apple").waitForExistence(timeout: 6), "rows")
        XCTAssertLessThan(row("Apple").frame.minY, row("Proxy").frame.minY, "saved drag order shown in 编辑排序")
        XCTAssertFalse(row("Hidden Probe").exists, "hidden group is not listed")
        XCTAssertTrue(app.element(id: "grouporder.hint").exists, "hint under the list")
        snap("group-order-mode")
        // Drag handle: Final to the top (best effort; 置顶 below is the checked path).
        let handles = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@ OR label BEGINSWITH %@", "Reorder", L("重新排列")))
        if handles.count >= 2 {
            handles.element(boundBy: 1).press(forDuration: 0.6, thenDragTo: handles.element(boundBy: 0))
        } else {
            warnings.append("reorder handles not found (\(handles.count))")
        }
        XCTAssertTrue(tapIfExists(app.element(id: "grouporder.top.Streaming")), "置顶 Streaming")
        usleep(700_000)
        XCTAssertLessThan(row("Streaming").frame.minY, row("Apple").frame.minY, "Streaming row moved to the top")
        snap("group-order-edited")
        done.tap()
        for _ in 0..<40 where done.exists { usleep(250_000) }
        XCTAssertFalse(done.exists, "back to the cards after 完成")
        XCTAssertTrue(above("Streaming", "Proxy", 8), "完成 saved: Streaming above Proxy")
        snap("policy-reordered")

        // 3. 置顶 from the group icon's context menu: Auto to the top.
        let autoIcon = app.element(id: "policy.icon.Auto")
        XCTAssertTrue(scrollTo(autoIcon), "Auto icon")
        autoIcon.press(forDuration: 1.0)
        XCTAssertTrue(tapIfExists(app.button(L("置顶")), timeout: 4), "置顶 in the context menu")
        XCTAssertTrue(above("Auto", "Streaming", 8), "Auto moved to the top")
        snap("policy-top")

        // 4. Tap still expands a card (the drag source is the same header).
        let proxyHeader = card("Proxy")
        XCTAssertTrue(scrollTo(proxyHeader), "Proxy card")
        XCTAssertFalse(app.element(labelContains: "Frankfurt AnyTLS").exists, "Proxy collapsed before the tap")
        proxyHeader.tap()
        XCTAssertTrue(app.element(labelContains: "Frankfurt AnyTLS").waitForExistence(timeout: 5), "tap expands the group")
        snap("policy-expanded-after-order")

        // Home's default cards are the first four groups, so they follow the new order.
        tab(0)
        if !app.element(id: "home.card.Streaming").waitForExistence(timeout: 8) { warnings.append("Home cards did not follow the new order") }
        snap("home-after-order")
    }

    // MARK: 32. v0.19.2: a route list line that is just "/" crashed the app (RouteSpec split it into nothing and
    // read parts[0]); the editor validates on every keystroke, so typing "/" was enough.
    func test32_RouteEditorSlash() {
        launch()
        openMore("连接方式")
        let row = app.element(labelContains: L("排除的路由"))
        XCTAssertTrue(scrollTo(row), "排除的路由 row")
        row.tap()
        XCTAssertTrue(app.navigationBars[L("排除的路由")].waitForExistence(timeout: 6), "route editor")
        let tv = app.textViews.firstMatch
        let field = tv.waitForExistence(timeout: 3) ? tv : app.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 4), "route text field")
        field.tap()
        field.typeText("\n/")
        usleep(800_000)
        XCTAssertEqual(app.state, .runningForeground, "app still running after typing \"/\"")
        XCTAssertTrue(app.navigationBars[L("排除的路由")].exists, "still on the route editor")
        XCTAssertTrue(app.element(labelContains: "/").exists, "the line is shown")
        snap("route-slash")
        // Put the defaults back.
        let reset = app.button(L("恢复默认"))
        if scrollTo(reset) { reset.tap() }
        usleep(800_000)
        back()
    }

    // MARK: 33. v0.19.4 自定义规则 add / swipe-delete / persists; 本地模块 rewrite add / delete

    func swipeDelete(_ row: XCUIElement) -> Bool {
        row.swipeLeft()
        for label in [L("删除"), "Delete", "删除"] {
            let b = app.buttons.matching(NSPredicate(format: "label == %@", label)).firstMatch
            if b.waitForExistence(timeout: 2) { b.tap(); return true }
        }
        return false
    }

    /// v0.19.8: the rule editor opens on the form; the raw line is typed in 文本模式 (segment), field id rule.text.
    func typeRuleText(_ text: String) {
        let mode = app.element(id: "rule.mode")
        XCTAssertTrue(mode.waitForExistence(timeout: 5), "rule editor mode picker")
        let seg = app.buttons.matching(NSPredicate(format: "label == %@", L("文本模式"))).firstMatch
        XCTAssertTrue(tapIfExists(seg, timeout: 4), "文本模式 segment")
        var field = app.textViews.matching(identifier: "rule.text").firstMatch
        if !field.waitForExistence(timeout: 3) { field = app.textFields.matching(identifier: "rule.text").firstMatch }
        XCTAssertTrue(field.waitForExistence(timeout: 5), "rule text field")
        field.tap()
        if let v = field.value as? String, !v.isEmpty, v != L("规则") {
            field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: v.count + 2))
        }
        field.typeText(text)
        usleep(1_200_000)
    }

    func addCustomRule(_ text: String) {
        XCTAssertTrue(tapIfExists(app.element(id: "rules.add"), timeout: 5), "rules +")
        typeRuleText(text)
        let save = app.element(id: "rule.save")
        XCTAssertTrue(save.waitHittable(), "rule 保存 enabled")
        save.tap()
        usleep(800_000)
    }

    func test33_RulesAndRewriteAddDelete() {
        launch()
        openMore("规则")
        app.buttons[L10n.f("自定义 %lld", 0)].firstMatch.tap()
        addCustomRule("DOMAIN-SUFFIX,a1.uitest.example,Proxy")
        addCustomRule("DOMAIN,b2.uitest.example,DIRECT")
        let a = app.element(labelContains: "a1.uitest.example")
        let b = app.element(labelContains: "b2.uitest.example")
        XCTAssertTrue(a.waitForExistence(timeout: 6), "first rule saved")
        XCTAssertTrue(b.waitForExistence(timeout: 6), "second rule saved")
        snap("rules-two")
        XCTAssertTrue(swipeDelete(a), "swipe to delete the first rule")
        usleep(800_000)
        XCTAssertFalse(app.element(labelContains: "a1.uitest.example").exists, "deleted rule still listed")
        XCTAssertTrue(b.exists, "other rule kept")
        assertAlive("rule delete")
        // Leave and come back: the remaining rule is read from disk again.
        back()
        openMore("规则")
        let tab1 = app.buttons[L10n.f("自定义 %lld", 1)].firstMatch
        XCTAssertTrue(tab1.waitForExistence(timeout: 6), "custom count is 1 after the delete")
        if tab1.exists { tab1.tap() }
        XCTAssertTrue(app.element(labelContains: "b2.uitest.example").waitForExistence(timeout: 6), "rule persisted")
        XCTAssertFalse(app.element(labelContains: "a1.uitest.example").exists, "deleted rule came back")
        snap("rules-after-delete")
        back()

        // 本地模块: add a reject rewrite, then delete it.
        openMore("重写（本地模块）")
        XCTAssertTrue(tapIfExists(app.element(id: "localmodule.add"), timeout: 5), "rewrite +")
        XCTAssertTrue(tapIfExists(app.button(L("拒绝请求（reject）")), timeout: 4), "reject entry")
        let pat = app.textFields.firstMatch
        XCTAssertTrue(pat.waitForExistence(timeout: 5))
        pat.tap()
        pat.typeText("^https?://del\\.uitest\\.example/")
        usleep(800_000)
        let save = app.navigationBars.buttons[L("保存")]
        XCTAssertTrue(save.waitHittable(), "rewrite 保存 enabled")
        save.tap()
        let row = app.element(labelContains: "del\\.uitest")
        XCTAssertTrue(row.waitForExistence(timeout: 6), "rewrite saved")
        snap("rewrite-added")
        XCTAssertTrue(swipeDelete(row), "swipe to delete the rewrite")
        usleep(800_000)
        XCTAssertFalse(app.element(labelContains: "del\\.uitest").exists, "deleted rewrite still listed")
        assertAlive("rewrite delete")
        snap("rewrite-deleted")
        back()
    }

    // MARK: 34. v0.19.4 URL scheme: mihomo:// links opened from outside never crash; unknown actions are refused

    func test34_URLSchemeLinks() {
        launch()
        guard #available(iOS 16.4, *) else { return }
        // Unknown action → refused (alert or nothing), app stays up.
        app.open(URL(string: "mihomo://definitely-not-an-action?x=1")!)
        usleep(2_500_000)
        XCTAssertEqual(app.state, .runningForeground, "app alive after an unknown mihomo:// action")
        snap("scheme-unknown")
        for b in [L("好"), "OK", L("取消"), "Cancel"] where app.buttons[b].exists { app.buttons[b].firstMatch.tap(); break }
        // install-config with an unreachable URL → confirmation / error, never a silent import or a crash.
        app.open(URL(string: "mihomo://install-config?url=https%3A%2F%2Fuitest.invalid%2Fprofile.yaml&name=UITestScheme")!)
        usleep(3_000_000)
        XCTAssertEqual(app.state, .runningForeground, "app alive after install-config")
        snap("scheme-install-config")
        if !app.element(labelContains: "uitest.invalid").exists && !app.element(labelContains: "UITestScheme").exists {
            warnings.append("[\(Env.tag)] install-config: the link's URL / name is not shown on the import screen")
        }
        closeSheet()
        usleep(800_000)
        // Nothing was added without confirmation.
        tab(4)
        XCTAssertEqual(app.state, .runningForeground)
    }

    // MARK: 35. v0.19.5 profile node edit → 撤销上次修改 (only 复制一份 offered undo before), detail refreshed

    func test35_NodeEditUndo() {
        launch()
        openAllNodes()
        let node = app.element(label: "🇯🇵 Tokyo 02")
        XCTAssertTrue(scrollTo(node), "profile node")
        node.tap()
        let edit = app.element(id: "node.edit")
        XCTAssertTrue(scrollTo(edit), "编辑")
        XCTAssertFalse(app.element(id: "node.undo").exists, "undo before any change")
        edit.tap()
        XCTAssertTrue(app.navigationBars[L("编辑节点")].waitForExistence(timeout: 6), "node editor")
        let server = app.textFields[L("服务器")]
        XCTAssertTrue(server.waitForExistence(timeout: 4))
        replaceText(server, "192.0.2.233")
        app.navigationBars.buttons[L("保存")].tap()
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.navigationBars[L("编辑节点")])
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 10), .completed, "editor saved")
        // The list is lazy and was scrolled down to 编辑: look for the server row by scrolling.
        usleep(1_500_000)
        XCTAssertTrue(scrollTo(app.element(labelContains: "192.0.2.233")), "detail shows the edit")
        let undo = app.element(id: "node.undo")
        XCTAssertTrue(scrollTo(undo), "撤销上次修改 offered after an edit")
        snap("node-undo-offered")
        undo.tap()
        usleep(1_500_000)
        XCTAssertFalse(app.element(id: "node.undo").exists, "undo is one level")
        for _ in 0..<4 { app.swipeDown(velocity: .slow) }
        XCTAssertTrue(scrollTo(app.element(labelContains: "192.0.2.2:443")), "original server back")
        XCTAssertFalse(app.element(labelContains: "192.0.2.233").exists, "detail still shows the undone edit")
        snap("node-undo-done")
        // The file really went back: reopen the list.
        for _ in 0..<3 where !app.navigationBars[L("更多")].exists { back() }
        openAllNodes()
        let again = app.element(label: "🇯🇵 Tokyo 02")
        XCTAssertTrue(scrollTo(again))
        again.tap()
        XCTAssertTrue(app.element(labelContains: "192.0.2.2:443").waitForExistence(timeout: 6), "server after reopening")
        XCTAssertFalse(app.element(labelContains: "192.0.2.233").exists, "undo not persisted")
        back()
    }

    // MARK: 36. v0.19.5 every app language: main tabs carry no zh-Hans source text that has a translation

    func test36_LanguagesNoLeftovers() {
        // One job is enough (the suite already runs zh-Hans and en end to end); en-light skips it.
        guard !Env.isEnglish else { return }
        let langs: [(String, String)] = [("en", "en_US"), ("ja", "ja_JP"), ("ko", "ko_KR"), ("ru", "ru_RU"), ("zh-Hant", "zh_TW"), ("zh-Hans", "zh_CN")]
        let testBundle = Bundle(for: MihomoUITests.self)
        // Data names in the seed that happen to equal catalog keys (group / profile names written by the seed).
        let dataNames: Set<String> = ["手动节点", "节点订阅"]
        for (lang, locale) in langs {
            guard let path = testBundle.path(forResource: lang, ofType: "lproj"),
                  let table = NSDictionary(contentsOfFile: (path as NSString).appendingPathComponent("Localizable.strings")) as? [String: String] else {
                issues.append("[\(lang)] no compiled catalog in the test bundle"); continue
            }
            let translated = table.filter { k, v in k != v && Self.han.firstMatch(in: k, range: NSRange(location: 0, length: (k as NSString).length)) != nil }
            let a = XCUIApplication()
            a.launchArguments = ["-UITestSeed", "-AppleLanguages", "(\(lang))", "-AppleLocale", locale, "-appearance", Env.style]
            a.launch()
            app = a
            XCTAssertTrue(a.element(id: "uitest.ready").waitForExistence(timeout: 40), "\(lang): seed")
            var seen = Set<String>()
            for i in 0..<5 {
                tab(i)
                for pass in 0..<2 {
                    if pass == 1 { app.swipeUp(velocity: .slow); usleep(400_000) }
                    let tree = app.debugDescription as NSString
                    for m in Self.labelRE.matches(in: tree as String, range: NSRange(location: 0, length: tree.length)) {
                        let t = tree.substring(with: m.range(at: 2))
                        guard !t.isEmpty, !seen.contains(t) else { continue }
                        seen.insert(t)
                        if translated[t] != nil && !dataNames.contains(t) {
                            issues.append("[\(lang)] tab \(i): untranslated “\(t)” (\(lang): “\(translated[t]!)”)")
                        }
                    }
                }
                let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
                shot.name = "lang-\(lang)-tab\(i)"
                shot.lifetime = .keepAlways
                add(shot)
            }
            // Tab bar titles must not be empty / missing in any language.
            for i in 0..<5 {
                let b = app.tabBars.buttons.element(boundBy: i)
                if !b.exists || b.label.trimmingCharacters(in: .whitespaces).isEmpty { issues.append("[\(lang)] tab \(i) has no title") }
            }
            assertAlive("language \(lang)")
            a.terminate()
        }
    }

    // MARK: 37. v0.19.5 settings survive a relaunch (same data, no re-seed)

    func test37_SettingsPersistAcrossRelaunch() {
        launch()
        openMore("内核设置")
        let close = app.switches["settings.closeOnSwitch"]
        XCTAssertTrue(close.waitForExistence(timeout: 6))
        XCTAssertEqual(switchValue(close), "1")
        toggleSwitch(close)
        toggleSwitch(app.switches["settings.flushDNS"])
        usleep(1_800_000)
        XCTAssertEqual(switchValue(app.switches["settings.closeOnSwitch"]), "0")
        XCTAssertEqual(switchValue(app.switches["settings.flushDNS"]), "0")
        back()
        usleep(800_000)
        app.terminate()
        launch(["-UITestKeepData"])
        openMore("内核设置")
        XCTAssertTrue(app.switches["settings.closeOnSwitch"].waitForExistence(timeout: 6))
        XCTAssertEqual(switchValue(app.switches["settings.closeOnSwitch"]), "0", "断开所有连接 kept off after relaunch")
        XCTAssertEqual(switchValue(app.switches["settings.flushDNS"]), "0", "清空 DNS 缓存 kept off after relaunch")
        snap("settings-after-relaunch")
        // The profile and its nodes are still there (not re-seeded, not wiped).
        back()
        tab(0)
        XCTAssertTrue(app.element(id: "home.card.Proxy").waitForExistence(timeout: 10), "profile kept across relaunch")
    }

    // MARK: 38. v0.19.5 switching the active profile while 策略 / 首页 are open follows at once

    func test38_ProfileSwitch() {
        launch(["-UITestSecondProfile"])
        tab(1)
        XCTAssertTrue(app.element(id: "policy.card.Proxy").waitForExistence(timeout: 10), "demo groups")
        tab(3)
        let second = app.staticTexts["UITest Second"]
        XCTAssertTrue(scrollTo(second), "second profile listed")
        second.tap()
        usleep(1_500_000)
        snap("profiles-second-active")
        tab(1)
        XCTAssertTrue(app.element(id: "policy.card.Second Select").waitForExistence(timeout: 10), "策略 shows the new profile's groups")
        XCTAssertFalse(app.element(id: "policy.card.Proxy").exists, "策略 still shows the previous profile")
        snap("policy-second")
        tab(0)
        XCTAssertTrue(app.element(id: "home.card.Second Select").waitForExistence(timeout: 10), "Home follows the switch")
        XCTAssertFalse(app.element(id: "home.card.Proxy").exists, "Home still shows the previous profile")
        tab(3)
        let demo = app.staticTexts["UITest Demo"]
        XCTAssertTrue(scrollTo(demo))
        demo.tap()
        usleep(1_500_000)
        tab(1)
        XCTAssertTrue(app.element(id: "policy.card.Proxy").waitForExistence(timeout: 10), "back to the demo groups")
        XCTAssertFalse(app.element(id: "policy.card.Second Select").exists)
        tab(0)
        XCTAssertTrue(app.element(id: "home.card.Proxy").waitForExistence(timeout: 10))
        assertAlive("profile switch")
    }

    // MARK: 39. v0.19.6 a profile with thousands of nodes and rules stays responsive (seed: -UITestBigProfile)

    func test39_BigProfileResponsive() {
        let t0 = Date()
        launch(["-UITestBigProfile"]) // 3000 nodes in one select group, 10000 rules, +1500 manual nodes
        print("big profile seed + launch: \(String(format: "%.1f", Date().timeIntervalSince(t0))) s")
        // Home: the active big profile's cards; the 3000-member group's offline picker opens and lists members.
        let card = app.element(id: "home.card.Big Select")
        XCTAssertTrue(card.waitForExistence(timeout: 20), "big profile card on Home")
        var s = Date()
        card.tap()
        XCTAssertTrue(app.element(label: "Big 00000").waitForExistence(timeout: 15), "picker lists the first member")
        XCTAssertLessThan(Date().timeIntervalSince(s), 15, "group picker with 3000 members")
        snap("big-home-picker")
        back()
        // 策略 lists the groups.
        s = Date()
        tab(1)
        XCTAssertTrue(app.element(id: "policy.card.Big Select").waitForExistence(timeout: 15), "策略 shows the big profile")
        XCTAssertLessThan(Date().timeIntervalSince(s), 15, "策略 tab")
        snap("big-policy")
        // 节点管理 → 全部节点: 3000 profile + 1500 manual nodes, search narrows the list.
        tab(4)
        let row = app.element(id: "more.节点与订阅")
        XCTAssertTrue(scrollTo(row))
        s = Date()
        row.tap()
        XCTAssertTrue(app.navigationBars[L("节点与订阅")].waitForExistence(timeout: 15))
        XCTAssertTrue(tapIfExists(app.element(label: L("全部节点"))))
        XCTAssertTrue(app.element(label: "Big 00000").waitForExistence(timeout: 20), "big profile node listed")
        XCTAssertLessThan(Date().timeIntervalSince(s), 25, "全部节点 with 4500 nodes")
        snap("big-nodes-all")
        let search = app.searchFields.firstMatch
        for _ in 0..<8 where !search.exists { app.swipeDown(velocity: .fast) }
        if search.waitForExistence(timeout: 5) {
            search.tap()
            search.typeText("BM 1499")
            XCTAssertTrue(app.element(label: "BM 1499").waitForExistence(timeout: 10), "search finds the last manual node")
            XCTAssertFalse(app.element(label: "Big 00000").exists, "search filters the profile nodes")
            snap("big-nodes-search")
            let cancel = app.buttons[L("取消")].exists ? app.buttons[L("取消")] : app.buttons["Cancel"]
            if cancel.exists { cancel.tap() }
        } else {
            XCTFail("node search field")
        }
        // Every tab answers quickly with the big profile active (no main-thread hang).
        for i in [0, 1, 2, 3, 4, 0] {
            s = Date()
            tab(i)
            XCTAssertTrue(app.tabBars.buttons.element(boundBy: i).waitForExistence(timeout: 10))
            // Review 6 R6A-7: the time includes XCUITest's accessibility snapshot of a 3000/4500-row tree; 8 s flaked
            // on CI (13.9 s, run 39422537271). 15 s still catches a main-thread hang (the watchdog kills at ~20 s).
            let took = Date().timeIntervalSince(s)
            print("tab \(i) switch: \(String(format: "%.1f", took)) s")
            XCTAssertLessThan(took, 15, "tab \(i) switch")
        }
        assertAlive("big profile")
    }

    // MARK: 70. feat/traffic-scope 首页流量统计 (全部流量 / 仅代理流量)

    func test70_TrafficScope() {
        launch()
        // Default: all traffic, no 「仅代理」 tag on Home.
        XCTAssertTrue(scrollTo(app.element(label: L("总上传"))), "总上传 tile")
        XCTAssertFalse(app.element(id: "home.trafficScope.proxy").exists, "no proxy-only tag by default")
        openMore("首页流量统计")
        XCTAssertTrue(app.navigationBars[L("首页流量统计")].waitForExistence(timeout: 6), "首页流量统计 page")
        let all = app.element(id: "trafficScope.all"), proxy = app.element(id: "trafficScope.proxy")
        XCTAssertTrue(all.waitForExistence(timeout: 4) && proxy.exists)
        XCTAssertTrue(all.isSelected, "全部流量 is the default")
        proxy.tap()
        usleep(400_000)
        XCTAssertTrue(proxy.isSelected, "仅代理流量 selected")
        snap("traffic-scope")
        back()
        let row = app.element(id: "more.首页流量统计")
        XCTAssertTrue(row.waitForExistence(timeout: 4))
        XCTAssertTrue(row.label.contains(L("仅代理流量")), "row shows the choice: \(row.label)")
        tab(0)
        XCTAssertTrue(scrollTo(app.element(id: "home.trafficScope.proxy")), "「仅代理」 tag on the speed card")
        XCTAssertTrue(app.element(label: L("总上传（仅代理）")).exists, "totals say proxy only")
        snap("home-traffic-scope-proxy")
        // Back to the default so the choice cannot leak into a screenshot of another test run in this launch.
        openMore("首页流量统计")
        XCTAssertTrue(all.waitForExistence(timeout: 4))
        all.tap()
        usleep(300_000)
        XCTAssertTrue(all.isSelected)
        assertAlive("traffic scope")
    }
}
