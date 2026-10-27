import XCTest

/// fix/more-row-height (user 「更多页每行的高度与其他页行高度不一样」): 更多's rows and 工具's cards share one row metric
/// (TernRowMetrics: 30 pt tile, 12 pt spacing, 2 pt padding, a Dynamic Type minimum height). Before, a one-line 更多 row
/// was ~40 pt while a 工具 card was ~56–60 pt.
extension TernUITests {

    /// Height of the list cell holding `e` (the row's own element when no cell contains it).
    func rowCellHeight(_ e: XCUIElement) -> CGFloat {
        let mid = e.frame.midY
        for c in app.cells.allElementsBoundByIndex where c.exists {
            let f = c.frame
            if f.height > 0, f.minY <= mid, f.maxY >= mid, f.width > e.frame.width * 0.8 { return f.height }
        }
        return e.frame.height
    }

    // MARK: 91. 更多 rows as tall as 工具 cards

    func test91_RowHeightParity() {
        launch()

        // 工具: 网络诊断 is a card with a caption line (title + detail).
        tab(3)
        XCTAssertTrue(app.navigationBars[L("工具")].waitForExistence(timeout: 8), "工具 tab")
        let toolRow = app.element(id: "more.网络工具（Ping / TCP / DNS）")
        XCTAssertTrue(scrollTo(toolRow), "工具 → 网络诊断")
        let toolTwoLine = rowCellHeight(toolRow)
        let toolContent = toolRow.frame.height
        snap("row-height-tools")

        // 更多: 通知 has a subtitle (two lines), 流量统计 has none (one line).
        tab(4)
        XCTAssertTrue(app.navigationBars[L("更多")].waitForExistence(timeout: 8), "更多")
        let notify = app.element(id: "more.通知")
        let stats = app.element(id: "more.流量统计")
        XCTAssertTrue(scrollTo(notify), "更多 → 通知")
        XCTAssertTrue(stats.exists, "更多 → 流量统计")
        let moreTwoLine = rowCellHeight(notify)
        let moreOneLine = rowCellHeight(stats)
        snap("row-height-more")

        XCTAssertEqual(moreTwoLine, toolTwoLine, accuracy: 2,
                       "两行：更多 \(moreTwoLine) vs 工具 \(toolTwoLine)")
        XCTAssertEqual(notify.frame.height, toolContent, accuracy: 2,
                       "row content: 更多 \(notify.frame.height) vs 工具 \(toolContent)")
        // One-line rows reach the shared minimum: at most a detail line shorter than a two-line card (was ~20 pt).
        XCTAssertGreaterThanOrEqual(moreOneLine, toolTwoLine - 10,
                                    "单行：更多 \(moreOneLine) vs 工具两行 \(toolTwoLine)")
        XCTAssertGreaterThanOrEqual(stats.frame.height, 30, "one-line row content ≥ the 30 pt tile + padding")
        assertAlive("row height")
    }
}
