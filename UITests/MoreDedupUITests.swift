import XCTest

/// feat/more-dedup (user 「更多里与更多－高级两个路径下的规则，重写是不是重复了」): every function has one home.
/// 重写 / 脚本 / 定时任务 / 配置里的规则集 only on 更多 → 模块; 高级设置 keeps 连接方式, DNS, HTTPS 解密, 地理数据库,
/// 内核 / 测速 / 出口; 节点集 only on 节点与订阅; 配置 no longer has its own 手动节点 / 节点与订阅 entries.
extension MihomoUITests {

    // MARK: 63. 更多 / 高级设置 / 模块 without duplicate entries (+ screenshots for review)

    func test63_MoreDedup() {
        launch()
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 8), "更多")
        snap("dedup-more-1")
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        snap("dedup-more-2")
        for _ in 0..<4 { app.swipeUp(velocity: .slow) }
        snap("dedup-more-3")

        // 高级设置: no 重写 / 脚本 / 定时任务 / 规则集与节点集 any more.
        openMore("高级设置")
        XCTAssertTrue(app.navigationBars[L("高级设置")].waitForExistence(timeout: 5), "高级设置 page")
        for gone in ["重写（本地模块）", "脚本", "任务", "提供者（规则集 / 节点集）"] {
            XCTAssertFalse(app.element(id: "more." + gone).exists, "高级设置 still lists \(gone)")
        }
        for kept in ["连接方式", "DNS", "MitM", "地理与规则库"] {
            XCTAssertTrue(app.element(id: "more." + kept).exists, "高级设置 lists \(kept)")
        }
        snap("dedup-advanced-1")
        app.swipeUp(velocity: .slow)
        snap("dedup-advanced-2")
        back()

        // 模块: the one home.
        openMore("模块与资源")
        XCTAssertTrue(app.navigationBars[L("模块")].waitForExistence(timeout: 5), "模块 page")
        for key in Self.moduleRows {
            XCTAssertTrue(scrollTo(app.element(id: "more." + key)), "模块 lists \(key)")
        }
        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)
        snap("dedup-modules-1")
        app.swipeUp(velocity: .slow)
        snap("dedup-modules-2")
        // 我的重写 / 脚本: no second 启用 switch, no second 全部重写规则 / 定时任务 entry.
        openMore("重写（本地模块）")
        XCTAssertFalse(app.element(id: "localmodule.allRewrites").exists, "我的重写: 全部重写规则 removed")
        XCTAssertFalse(app.switches[L("启用重写与脚本")].exists, "我的重写: 启用 switch only on 模块")
        snap("dedup-localmodule")
        back()
        openMore("脚本")
        XCTAssertFalse(app.switches[L("启用重写与脚本")].exists, "脚本: 启用 switch only on 模块")
        XCTAssertFalse(app.element(labelContains: L("任务（定时 / 网络变化 / 交互）")).exists, "脚本: 定时任务 entry removed")
        snap("dedup-scripts")
        back()
        openMore("规则集（配置）")
        XCTAssertTrue(app.navigationBars[L("配置里的规则集")].waitForExistence(timeout: 5), "配置里的规则集 page")
        XCTAssertFalse(app.element(labelContains: L("节点集")).exists, "节点集 only on 节点与订阅")
        snap("dedup-rulesets")
        back()
        back()

        // 配置: no 手动节点 row, no 节点与订阅 toolbar shortcut.
        tab(3)
        XCTAssertTrue(app.navigationBars[L("配置")].waitForExistence(timeout: 5), "配置")
        XCTAssertFalse(app.element(labelContains: L("手动节点（粘贴链接 / 扫码 / 手动填写）")).exists, "配置: 手动节点 row removed")
        XCTAssertFalse(app.navigationBars.buttons[L("节点与订阅")].exists, "配置: 节点与订阅 shortcut removed")
        snap("dedup-profiles")

        // 配置 long-press menu (user 2026-10-21 17:49): 导出 sits right above 删除; the YAML editor has it in its toolbar.
        let row = app.element(labelContains: "UITest Demo")
        XCTAssertTrue(row.waitForExistence(timeout: 5), "UITest Demo profile row")
        row.press(forDuration: 1.3)
        let export = app.button(L("导出"))
        let delete = app.button(L("删除"))
        XCTAssertTrue(export.waitForExistence(timeout: 4), "导出 in the profile long-press menu")
        XCTAssertTrue(delete.exists, "删除 in the profile long-press menu")
        XCTAssertLessThan(export.frame.midY, delete.frame.midY, "导出 is above 删除")
        snap("dedup-profile-menu")
        XCTAssertTrue(tapIfExists(app.button(L("编辑 YAML")), timeout: 3), "编辑 YAML in the menu")
        XCTAssertTrue(app.element(id: "yaml.export").waitForExistence(timeout: 5), "导出 in the YAML editor toolbar")
        snap("dedup-yaml-export")
        app.element(id: "yaml.export").tap()
        _ = app.otherElements["ActivityListView"].waitForExistence(timeout: 6) // share sheet (screenshot only, no assert)
        assertAlive("profile export")
        snap("dedup-yaml-share")
    }
}
