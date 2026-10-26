import XCTest
import SwiftUI
@testable import Mihomo

// v0.19.14: renders the Live Activity views (Shared/LiveActivityViews.swift) with ImageRenderer in every
// shipped language, light and dark, with long node names, large Dynamic Type and the stale / disconnected
// states. PNGs go to $UI_SHOT_DIR/liveact (the Self-test "shots" artifact) and into the .xcresult.
// The Lock Screen card is asserted to stay inside the Live Activity height (160 pt).

@available(iOS 17.0, *)
@MainActor
final class LiveActivityLayoutTests: XCTestCase {

    private static let langs = ["zh-Hans", "en", "ja", "ko", "ru", "zh-Hant"]
    private static let shortNode = "🇯🇵 东京 Green CDN"
    private static let longNode = "🇺🇸 美国 洛杉矶 | IPLC 专线 01 · 0.5x · Netflix / Disney+ 解锁 · 超长节点名称测试"
    private static let cardWidth: CGFloat = 370   // Lock Screen activity on a 6.3" iPhone (402 pt − margins)

    private var outDir: URL {
        let env = ProcessInfo.processInfo.environment
        let base: URL
        if let d = env["UI_SHOT_DIR"], !d.isEmpty {
            base = URL(fileURLWithPath: d)
        } else {
            // The simulator shares the Mac's file system: <repo>/shots, which the workflow uploads.
            base = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("shots")
        }
        let u = base.appendingPathComponent("liveact", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    private func state(node: String, connected: Bool = true, up: Int64 = 34_714, down: Int64 = 145_408, proxyOnly: Bool = false,
                       totals: Bool = true, elapsed: TimeInterval = 166) -> TernActivityAttributes.ContentState {
        let now = Date()
        var s = TernActivityAttributes.ContentState(connected: connected, node: node, up: up, down: down, since: now.addingTimeInterval(-elapsed), updated: now.addingTimeInterval(-240))
        s.proxyOnly = proxyOnly ? true : nil
        if totals { s.totalUp = 12_345_678; s.totalDown = 987_654_321 }
        return s
    }

    @discardableResult
    private func render<V: View>(_ view: V, name: String, lang: String, scheme: ColorScheme, type: DynamicTypeSize = .large) -> CGSize {
        let content = view
            .environment(\.locale, Locale(identifier: lang))
            .environment(\.colorScheme, scheme)
            .environment(\.dynamicTypeSize, type)
        let r = ImageRenderer(content: content)
        r.scale = 3
        guard let img = r.uiImage, let png = img.pngData() else {
            XCTFail("render failed: \(name)")
            return .zero
        }
        try? png.write(to: outDir.appendingPathComponent("\(name).png"))
        let att = XCTAttachment(image: img)
        att.name = name
        att.lifetime = .keepAlways
        add(att)
        return img.size
    }

    /// The Lock Screen card on a wallpaper, like the device screenshot.
    private func lockScene(_ s: TernActivityAttributes.ContentState, stale: Bool = false) -> some View {
        LiveActivityLockContent(state: s, profile: "Tern", stale: stale)
            .frame(width: Self.cardWidth)
            .background(RoundedRectangle(cornerRadius: 24, style: .continuous).fill(WidgetTheme.bg.opacity(0.85)))
            .padding(16)
            .background(Color(red: 0.07, green: 0.08, blue: 0.11))
    }

    /// Expanded Dynamic Island mock (always dark, black).
    private func islandScene(_ s: TernActivityAttributes.ContentState, stale: Bool = false) -> some View {
        VStack(spacing: 10) {
            HStack(alignment: .center) {
                LiveIslandLeading(state: s)
                Spacer(minLength: 8)
                LiveIslandTrailing(state: s, stale: stale)
            }
            LiveIslandBottom(state: s, profile: "Tern")
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .frame(width: Self.cardWidth)
        .background(RoundedRectangle(cornerRadius: 44, style: .continuous).fill(Color.black))
        .padding(12)
        .background(Color(white: 0.25))
    }

    /// Compact pill mock: ↑ left of the camera cut-out, ↓ right.
    private func compactScene(_ s: TernActivityAttributes.ContentState) -> some View {
        HStack(spacing: 0) {
            LiveCompactSpeed(up: true, state: s).frame(width: 52, alignment: .leading)
            Spacer().frame(width: 126)
            LiveCompactSpeed(up: false, state: s).frame(width: 52, alignment: .trailing)
        }
        .padding(.horizontal, 14)
        .frame(height: 37)
        .background(Capsule().fill(Color.black))
        .padding(10)
        .background(Color(white: 0.25))
    }

    func testRenderLiveActivityLayouts() throws {
        for lang in Self.langs {
            for scheme in [ColorScheme.light, .dark] {
                let tag = "\(lang)-\(scheme == .light ? "light" : "dark")"
                let size = render(lockScene(state(node: Self.shortNode)), name: "lock-\(tag)", lang: lang, scheme: scheme)
                XCTAssertLessThanOrEqual(size.height - 32, 160, "lock card too tall: \(tag)")
                render(lockScene(state(node: Self.longNode)), name: "lock-long-\(tag)", lang: lang, scheme: scheme)
            }
            render(islandScene(state(node: Self.shortNode)), name: "island-\(lang)", lang: lang, scheme: .dark)
            render(islandScene(state(node: Self.longNode)), name: "island-long-\(lang)", lang: lang, scheme: .dark)
            render(compactScene(state(node: Self.shortNode)), name: "compact-\(lang)", lang: lang, scheme: .dark)
            // 首页流量统计 = 仅代理流量: small 「仅代理」 tag under the speeds.
            let p = render(lockScene(state(node: Self.shortNode, proxyOnly: true)), name: "lock-proxyonly-\(lang)-light", lang: lang, scheme: .light)
            XCTAssertLessThanOrEqual(p.height - 32, 160, "lock card too tall with 仅代理: \(lang)")
            render(islandScene(state(node: Self.shortNode, proxyOnly: true)), name: "island-proxyonly-\(lang)", lang: lang, scheme: .dark)
        }
        // Large Dynamic Type (capped at xxLarge by the view), stale and disconnected, big numbers.
        for lang in ["zh-Hans", "ru", "en"] {
            let s = render(lockScene(state(node: Self.longNode)), name: "lock-axl-\(lang)-light", lang: lang, scheme: .light, type: .accessibility3)
            XCTAssertLessThanOrEqual(s.height - 32, 160, "lock card too tall at accessibility3: \(lang)")
            render(lockScene(state(node: Self.longNode)), name: "lock-xxl-\(lang)-dark", lang: lang, scheme: .dark, type: .xxLarge)
            render(lockScene(state(node: Self.shortNode), stale: true), name: "lock-stale-\(lang)-light", lang: lang, scheme: .light)
            render(lockScene(state(node: Self.longNode, proxyOnly: true), stale: true), name: "lock-proxyonly-stale-axl-\(lang)-dark", lang: lang, scheme: .dark, type: .accessibility3)
            render(lockScene(state(node: "", connected: false, up: 0, down: 0)), name: "lock-off-\(lang)-dark", lang: lang, scheme: .dark)
            render(lockScene(state(node: Self.shortNode, up: 1_023_000, down: 98_765_432)), name: "lock-fast-\(lang)-light", lang: lang, scheme: .light)
            render(islandScene(state(node: Self.longNode), stale: true), name: "island-stale-\(lang)", lang: lang, scheme: .dark, type: .xxxLarge)
            // hotfix/liveact-lockscreen: stale without totals (older state) shows no numbers, only 「更新于」.
            render(lockScene(state(node: Self.shortNode, totals: false), stale: true), name: "lock-stale-nototals-\(lang)-dark", lang: lang, scheme: .dark)
            // Elapsed over an hour: 「已连接 2小时46分钟」 on one line, still inside the card.
            let h = render(lockScene(state(node: Self.longNode, elapsed: 2 * 3600 + 46 * 60)), name: "lock-hours-\(lang)-light", lang: lang, scheme: .light, type: .xxLarge)
            XCTAssertLessThanOrEqual(h.height - 32, 160, "lock card too tall with hours: \(lang)")
            render(islandScene(state(node: Self.shortNode, elapsed: 2 * 3600 + 46 * 60)), name: "island-hours-\(lang)", lang: lang, scheme: .dark)
        }
    }

    /// hotfix/liveact-lockscreen: only meaningful speed changes spend an ActivityKit update.
    func testMeaningfulSpeedChange() {
        let m = LiveActivityController.meaningful
        XCTAssertFalse(m((0, 0), (0, 0)))
        XCTAssertFalse(m((100_000, 500_000), (110_000, 520_000)), "±10 % is noise")
        XCTAssertFalse(m((0, 2_000), (0, 6_000)), "a few KB/s at idle is noise")
        XCTAssertTrue(m((0, 0), (0, 300_000)), "idle → busy")
        XCTAssertTrue(m((0, 400_000), (0, 20_000)), "busy → idle")
        XCTAssertTrue(m((50_000, 0), (200_000, 0)), "upload jump")
        XCTAssertGreaterThanOrEqual(LiveActivityController.minInterval, 15)
        XCTAssertGreaterThanOrEqual(LiveActivityController.staleAfter, LiveActivityController.keepAlive)
    }
}
