import XCTest

/// feat/geo-mirror-edit (device 2026-10-22, IMG_3416): 更多 → 高级设置 → 地理数据库.
/// 国内镜像 gets a third choice 自定义 with an editable base URL (https only, live preview for geoip.metadb, 保存 / 重置,
/// kept across launches); the per-file 默认地址 follows it. The card's right button is 下载 only while a database is not
/// installed, 更新 (arrow.clockwise) once it is, red 重试 after an error.
/// Paused indicators: 请求 / DNS 日志 / 日志 show 「已暂停刷新 · 点按继续」 while paused (tap resumes) and the toolbar
/// button reads 暂停刷新 / 继续刷新.
extension MihomoUITests {

    private func geoMirrorSegment(_ key: String) -> XCUIElement {
        let byId = app.segmentedControls["geo.mirror.picker"]
        let seg = byId.exists ? byId : app.segmentedControls.firstMatch
        return seg.buttons[L(key)]
    }

    /// The field's own clear button (a tap lands the caret mid-text, so deleting from there leaves a tail).
    private func clearAndType(_ field: XCUIElement, _ text: String) {
        let clear = app.buttons["geo.mirror.clear"]
        if clear.exists { clear.tap(); usleep(300_000) }
        field.tap() // r2: after the clear button moved focus, field.typeText did not land (en light:1); tap first
        usleep(400_000)
        XCTAssertEqual(((field.value as? String) ?? ""), field.placeholderValue ?? "", "field cleared")
        app.typeText(text)
        usleep(400_000)
    }

    // MARK: 80. 地理数据库 · 自定义镜像 + 更新 button

    func test80_GeoMirrorEdit() {
        launch()
        openMore("地理与规则库")
        let picker = app.element(id: "geo.mirror.picker")
        XCTAssertTrue(picker.waitForExistence(timeout: 8), "镜像 picker (国内镜像 on by default)")
        XCTAssertTrue(app.element(id: "geo.mirror.base").label.hasPrefix("https://testingcf.jsdelivr.net/"), "jsDelivr base shown")
        snap("geo-default")

        // Right button follows the install state: 更新 when installed, 下载 when not; never both.
        for kind in ["mmdb", "geosite", "asn", "geoip"] {
            let status = app.element(id: "geo.status.\(kind)")
            XCTAssertTrue(scrollTo(status, maxSwipes: 6), "\(kind) card")
            let update = app.element(id: "geo.update.\(kind)"), download = app.element(id: "geo.download.\(kind)")
            let retry = app.element(id: "geo.retry.\(kind)")
            XCTAssertTrue(update.exists || download.exists || retry.exists, "\(kind): an action button")
            XCTAssertFalse(update.exists && download.exists, "\(kind): not both")
            if status.label == L("已安装") {
                XCTAssertTrue(update.exists, "\(kind) installed → 更新, not the download arrow")
                XCTAssertEqual(update.label, L("更新"), "\(kind) a11y label")
            } else if status.label == L("未安装") {
                XCTAssertTrue(download.exists, "\(kind) not installed → 下载")
                XCTAssertEqual(download.label, L("下载"), "\(kind) a11y label")
            }
        }
        if app.element(id: "geo.update.mmdb").exists { snap("geo-update-buttons") } else {
            warnings.append("[\(Env.tag)] geo: bundled geoip.metadb not installed in the simulator; 更新 state not shown")
        }

        // 自定义: invalid → message, 保存 disabled; valid → preview; saved → 默认地址 follows.
        XCTAssertTrue(scrollTo(picker, maxSwipes: 6), "back to the mirror card")
        let custom = geoMirrorSegment("自定义")
        XCTAssertTrue(custom.waitForExistence(timeout: 4), "自定义 segment")
        custom.tap()
        let field = app.textFields["geo.mirror.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 4), "base URL field")
        XCTAssertTrue(((field.value as? String) ?? "").hasPrefix("https://testingcf.jsdelivr.net/"), "prefilled with the base in use")
        XCTAssertTrue(app.element(id: "geo.mirror.unsaved").exists, "not saved yet hint")

        clearAndType(field, "http://bad.example.com/")
        XCTAssertTrue(app.element(id: "geo.mirror.invalid").waitForExistence(timeout: 3), "https required")
        XCTAssertFalse(app.buttons["geo.mirror.save"].isEnabled, "保存 disabled while invalid")
        snap("geo-custom-invalid")

        let base = "https://mirror.example.org/gh/MetaCubeX/meta-rules-dat@release"
        clearAndType(field, base)
        let preview = app.element(id: "geo.mirror.preview")
        XCTAssertTrue(preview.waitForExistence(timeout: 3), "live preview")
        XCTAssertEqual(preview.label, base + "/geoip.metadb", "preview appends / and the file name")
        let save = app.buttons["geo.mirror.save"]
        XCTAssertTrue(save.isEnabled, "保存 enabled")
        save.tap()
        usleep(600_000)
        XCTAssertFalse(app.buttons["geo.mirror.save"].isEnabled, "saved (nothing to save)")
        XCTAssertFalse(app.element(id: "geo.mirror.unsaved").exists, "unsaved hint gone")
        let mmdbURL = app.element(id: "geo.url.mmdb")
        XCTAssertTrue(scrollTo(mmdbURL, maxSwipes: 4), "mmdb 默认地址")
        XCTAssertEqual(mmdbURL.label, base + "/geoip.metadb", "默认地址 follows the custom mirror")
        snap("geo-custom-saved")

        // Persisted across launches.
        app.terminate()
        launch(["-UITestKeepData"])
        openMore("地理与规则库")
        let field2 = app.textFields["geo.mirror.field"]
        XCTAssertTrue(field2.waitForExistence(timeout: 8), "自定义 still selected after relaunch")
        XCTAssertEqual(field2.value as? String, base + "/", "saved base kept")
        XCTAssertEqual(app.element(id: "geo.url.geosite").label, base + "/geosite.dat", "geosite follows too")

        // 重置 → back to jsDelivr.
        let reset = app.buttons["geo.mirror.reset"]
        XCTAssertTrue(reset.waitHittable(), "重置")
        reset.tap()
        usleep(600_000)
        XCTAssertFalse(app.textFields["geo.mirror.field"].exists, "field hidden after 重置")
        XCTAssertTrue(app.element(id: "geo.mirror.base").label.hasPrefix("https://testingcf.jsdelivr.net/"), "jsDelivr again")
        XCTAssertTrue(app.element(id: "geo.url.mmdb").label.hasPrefix("https://testingcf.jsdelivr.net/"), "默认地址 back to jsDelivr")
        snap("geo-reset")
        assertAlive("geo mirror")
    }

    // MARK: 81. Paused indicators (请求 / DNS 日志 / 日志)

    func test81_PausedIndicators() {
        launch(["-UITestDemoConnections"])
        let pages: [(String?, String)] = [(nil, "requests"), ("DNS 日志", "dnslog"), ("日志", "logs")]
        for (page, key) in pages {
            if let page { openMore(page) } else { tab(2) }
            let pause = app.buttons["\(key).pause"]
            XCTAssertTrue(pause.waitForExistence(timeout: 8), "\(key): pause button")
            XCTAssertEqual(pause.label, L("暂停刷新"), "\(key): a11y label while live")
            XCTAssertFalse(app.element(id: "\(key).paused").exists, "\(key): no chip while live")
            pause.tap()
            let chip = app.element(id: "\(key).paused")
            XCTAssertTrue(chip.waitForExistence(timeout: 4), "\(key): paused chip")
            XCTAssertEqual(chip.label, L("已暂停刷新 · 点按继续"), "\(key): chip text")
            XCTAssertEqual(app.buttons["\(key).pause"].label, L("继续刷新"), "\(key): a11y label while paused")
            snap("\(key)-paused")
            chip.tap()
            let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: app.element(id: "\(key).paused"))
            XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 4), .completed, "\(key): tap resumes")
            XCTAssertEqual(app.buttons["\(key).pause"].label, L("暂停刷新"), "\(key): live again")
            if page != nil { back() }
        }
        assertAlive("paused indicators")
    }
}
