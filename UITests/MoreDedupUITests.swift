import XCTest

/// feat/more-dedup (user 「更多里与更多－高级两个路径下的规则，重写是不是重复了」 + 2026-10-21 18:06): every function has
/// one home. The 配置 tab became 工具 (Egern-style cards with counts: 节点与订阅, 分流规则, 模块, 重写, 脚本, 定时任务,
/// HTTPS 解密, DNS, logs, network tools); 更多 keeps settings-type rows with 配置 (配置管理) first and 更新资源 next to
/// 存储空间; 高级设置 keeps 连接方式, 地理数据库, 内核 / 测速 / 出口. Profile long-press menu has 导出 above 删除.
extension TernUITests {

    // MARK: 63. 工具 tab / 更多 / 配置 / 更新资源 without duplicate entries (+ screenshots for review)

    func test63_MoreDedup() {
        launch()

        // 工具 tab: cards with counts.
        tab(3)
        XCTAssertTrue(app.navigationBars[L("工具")].waitForExistence(timeout: 8), "工具 tab")
        for key in Self.toolRows.prefix(4) {
            XCTAssertTrue(app.element(id: "more." + key).waitForExistence(timeout: 4), "工具 lists \(key)")
        }
        XCTAssertFalse(app.tabBars.buttons[L("配置")].exists, "no 配置 tab any more")
        snap("dedup-tools-1")
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        snap("dedup-tools-2")
        for _ in 0..<3 { app.swipeUp(velocity: .slow) }
        snap("dedup-tools-3")
        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)

        // QX-style 重写 (user 2026-10-22): one card replaced 模块 / 重写 / 脚本.
        for gone in ["模块与资源", "重写（本地模块）", "脚本"] {
            XCTAssertFalse(app.element(id: "more." + gone).exists, "工具 still lists \(gone)")
        }
        openMore("重写")
        XCTAssertTrue(app.navigationBars[L("重写")].waitForExistence(timeout: 5), "重写 page")
        XCTAssertTrue(app.switches[L("启用重写与脚本")].exists || app.element(id: "rewrite.enabled").exists, "启用 switch on 重写")
        for key in Self.moduleRows {
            XCTAssertTrue(scrollTo(app.element(id: "more." + key)), "重写 lists \(key)")
        }
        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)
        snap("dedup-modules-1")
        back()
        // Loon-style 规则 (2026-10-22): rule sets are 订阅 on 规则 itself.
        openMore("规则")
        XCTAssertTrue(app.element(id: "rules.local").waitForExistence(timeout: 6), "规则 → 本地规则")
        assertAlive("规则")
        back()

        // 更多: settings-type rows only, 配置 first.
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 8), "更多")
        XCTAssertTrue(app.element(id: "more.配置").waitForExistence(timeout: 4), "更多 → 配置")
        for gone in ["节点与订阅", "规则", "模块与资源", "日志", "网络工具（Ping / TCP / DNS）"] {
            XCTAssertFalse(app.element(id: "more." + gone).exists, "更多 still lists \(gone)")
        }
        snap("dedup-more-1")
        for _ in 0..<2 { app.swipeUp(velocity: .slow) }
        snap("dedup-more-2")
        for _ in 0..<4 { app.swipeUp(velocity: .slow) }
        snap("dedup-more-3")

        // 高级设置: no DNS / MitM (工具 cards), no 重写 / 脚本 / 定时任务 / 规则集与节点集.
        openMore("高级设置")
        XCTAssertTrue(app.navigationBars[L("高级设置")].waitForExistence(timeout: 5), "高级设置 page")
        for gone in ["重写（本地模块）", "脚本", "任务", "提供者（规则集 / 节点集）", "DNS", "MitM"] {
            XCTAssertFalse(app.element(id: "more." + gone).exists, "高级设置 still lists \(gone)")
        }
        for kept in ["连接方式", "地理与规则库"] {
            XCTAssertTrue(app.element(id: "more." + kept).exists, "高级设置 lists \(kept)")
        }
        snap("dedup-advanced-1")
        back()

        // 备份与恢复: the export is labelled as the full .json backup and points at 配置 → 导出 for one YAML.
        openMore("备份与恢复")
        XCTAssertTrue(app.element(id: "backup.exportFiles").waitForExistence(timeout: 5) || scrollTo(app.element(id: "backup.exportFiles")), "完整备份 export")
        app.swipeUp(velocity: .slow)
        snap("dedup-backup")
        back()

        // 更新资源 removed (user 2026-10-23): each resource updates on its own 工具 page.
        XCTAssertFalse(app.element(id: "more.更新资源").exists, "no 更新资源 row on 更多")

        // 配置管理 (更多 → 配置): no 手动节点 row, no 节点与订阅 shortcut; long-press menu has 导出 above 删除.
        openProfiles()
        XCTAssertFalse(app.element(labelContains: L("手动节点（粘贴链接 / 扫码 / 手动填写）")).exists, "配置: 手动节点 row removed")
        XCTAssertFalse(app.navigationBars.buttons[L("节点与订阅")].exists, "配置: 节点与订阅 shortcut removed")
        snap("dedup-profiles")

        // The 快速编辑 row's label also contains the profile name ("快速编辑、UITest Demo"); press the profile's own cell.
        // (Its cell even holds a StaticText "UITest Demo"), so also require the profile row's own 本地 badge.
        let row = app.cells.containing(NSPredicate(format: "label == %@", "UITest Demo"))
            .containing(NSPredicate(format: "label == %@", L("本地"))).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 5), "UITest Demo profile row")
        row.press(forDuration: 1.3)
        let export = app.button(L("导出"))
        let delete = app.button(L("删除"))
        XCTAssertTrue(export.waitForExistence(timeout: 4), "导出 in the profile long-press menu")
        XCTAssertTrue(delete.exists, "删除 in the profile long-press menu")
        XCTAssertLessThan(export.frame.midY, delete.frame.midY, "导出 is above 删除")
        XCTAssertTrue(app.button(L("导出最终配置（含覆写）")).exists, "导出最终配置 in the long-press menu")
        snap("dedup-profile-menu")
        // feat/nc-conf-native: the editor edits the profile's .conf; 导出 .conf sits in its 更多 menu.
        XCTAssertTrue(tapIfExists(app.button(L("编辑配置")), timeout: 3), "编辑配置 in the menu")
        XCTAssertTrue(tapIfExists(app.element(id: "conf.more"), timeout: 8), "更多 in the .conf editor toolbar")
        XCTAssertTrue(app.button(L("导出 .conf")).waitForExistence(timeout: 4), "导出 .conf in the editor menu")
        snap("dedup-yaml-export")
        app.button(L("导出 .conf")).tap()
        _ = app.otherElements["ActivityListView"].waitForExistence(timeout: 6) // share sheet (screenshot only, no assert)
        snap("dedup-yaml-share")
        assertAlive("profile export")
    }
}
