import XCTest
import SwiftUI
@testable import Mihomo

/// feat/more-search: the static feature index behind 更多's search field.
@MainActor
final class SettingsSearchTests: XCTestCase {

    let entries = SettingsSearchIndex.entries

    func testEveryEntryResolvesToARealDestination() {
        XCTAssertGreaterThan(entries.count, 40)
        XCTAssertEqual(Set(entries.map(\.id)).count, entries.count, "ids are unique")
        let tabs = Set(AppSection.allCases.map(\.rawValue))
        for e in entries {
            XCTAssertTrue(SearchDestination.allCases.contains(e.destination), e.id)
            XCTAssertFalse(e.path.isEmpty, "\(e.id): breadcrumb")
            XCTAssertTrue(["更多", "工具", "首页", "策略"].contains(e.section), "\(e.id): section \(e.section)")
            XCTAssertNotNil(UIImage(systemName: e.symbol), "\(e.id): SF Symbol \(e.symbol)")
            switch e.destination.presentation {
            case .push, .sheet:
                XCTAssertTrue(e.destination.buildsPage, e.id)
                // Builds the registry's view (the switch in SearchDestination.page is exhaustive).
                _ = AnyView(e.destination.page)
            case .tab(let t):
                XCTAssertTrue(tabs.contains(t), "\(e.id): tab \(t)")
            case .onboarding, .systemSettings:
                XCTAssertFalse(e.destination.buildsPage)
            }
        }
    }

    func testEveryDestinationIsIndexed() {
        let used = Set(entries.map(\.destination))
        for d in SearchDestination.allCases {
            XCTAssertTrue(used.contains(d), "\(d) has no index entry")
        }
    }

    /// Titles and breadcrumb segments are catalog keys translated into every shipped language.
    func testTitlesAndBreadcrumbsAreLocalized() throws {
        for lang in ["en", "zh-Hant", "ja", "ko", "ru"] {
            let path = try XCTUnwrap(Bundle.main.path(forResource: lang, ofType: "lproj"), lang)
            let b = try XCTUnwrap(Bundle(path: path))
            for e in entries {
                for k in [e.title] + e.path where k.unicodeScalars.contains(where: { $0.value > 0x2E80 }) {
                    let v = b.localizedString(forKey: k, value: "\u{1}", table: "Localizable")
                    XCTAssertNotEqual(v, "\u{1}", "\(lang): \(k) (\(e.id))")
                }
            }
        }
    }

    func first(_ q: String) -> String? { SettingsSearchIndex.search(q).first?.entry.id }
    func ids(_ q: String) -> [String] { SettingsSearchIndex.search(q).map(\.entry.id) }

    func testKeywordMatching() {
        XCTAssertEqual(first("地理"), "geo")
        XCTAssertEqual(first("mitm"), "mitm")
        XCTAssertEqual(first("MITM"), "mitm", "case-insensitive")
        XCTAssertEqual(first("GeoIP"), "geo")
        XCTAssertEqual(first("DNS"), "dns")
        XCTAssertEqual(first("实时活动"), "liveActivity")
        XCTAssertEqual(first("灵动岛"), "liveActivity")
        XCTAssertEqual(first("Dynamic Island"), "liveActivity")
        XCTAssertEqual(first("live activity"), "liveActivity")
        XCTAssertTrue(ids("锁屏").contains("liveActivity"))
        XCTAssertTrue(ids("TUN").contains("connection"))
        XCTAssertTrue(ids("Sub-Store").contains("modules"))
        XCTAssertTrue(ids("map local").contains("rewrites"))
        XCTAssertTrue(ids("证书").contains("mitm"))
        XCTAssertTrue(ids("證書").contains("mitm"), "Traditional input")
        XCTAssertTrue(ids("局域网共享").contains("lanSharing"))
        XCTAssertTrue(ids("控制器").contains("controller"))
        XCTAssertTrue(ids("备份").contains("backup"))
        XCTAssertTrue(ids("日志").contains("logs"))
        XCTAssertTrue(ids("小组件").contains("homePanels"))
        XCTAssertTrue(ids("规则集").contains("rules"))
        XCTAssertTrue(ids("订阅").contains("nodes"))
        XCTAssertTrue(ids("节点").contains("nodes"))
        XCTAssertTrue(SettingsSearchIndex.search("zzqqxx").isEmpty, "no match → empty state")
        XCTAssertTrue(SettingsSearchIndex.search("   ").isEmpty, "blank query → normal 更多 list")
    }

    func testPinyin() {
        XCTAssertEqual(SettingsSearchIndex.pinyinRange("dlsjk", in: "地理数据库"), 0..<5)
        XCTAssertEqual(SettingsSearchIndex.pinyinRange("dili", in: "地理数据库"), 0..<2, "\(SettingsSearchIndex.syllables("地理数据库").map { $0.full })")
        XCTAssertEqual(SettingsSearchIndex.pinyinRange("sjk", in: "地理数据库"), 2..<5)
        XCTAssertEqual(SettingsSearchIndex.pinyinRange("chongxie", in: "重写"), 0..<2, "polyphone reading")
        XCTAssertNil(SettingsSearchIndex.pinyinRange("xyz", in: "地理数据库"))
        XCTAssertTrue(ids("dlsjk").contains("geo"))
        XCTAssertTrue(ids("jd").contains("nodes"), "节点 initials")
        XCTAssertTrue(ids("dns").contains("dnsLog"))
    }

    func testHighlightRangeAndGrouping() {
        XCTAssertEqual(SettingsSearchIndex.textRange(of: "地理", in: "地理数据库"), 0..<2)
        XCTAssertEqual(SettingsSearchIndex.textRange(of: "https", in: "HTTPS 解密"), 0..<5)
        XCTAssertEqual(SettingsSearchIndex.textRange(of: "資料", in: "地理数据库"), nil)
        let zh: (String) -> String = { $0 }
        let hit = SettingsSearchIndex.search("地理", display: zh).first
        XCTAssertEqual(hit?.titleRange, 0..<2)
        let g = SettingsSearchIndex.grouped(SettingsSearchIndex.search("日志", display: zh))
        XCTAssertEqual(Set(g.map(\.section)).count, g.count, "one section per tab")
        XCTAssertTrue(g.contains { $0.section == "工具" })
    }
}
