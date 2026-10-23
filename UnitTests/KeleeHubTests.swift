import XCTest
@testable import Mihomo

/// feat/kelee-hub 「接入可莉插件中心」: hub.kelee.one/list.json read by the generic JSON index reader.
final class KeleeHubTests: XCTestCase {
    let sample = """
    {"name":"插件中心","notice":["本站内容由可莉个人维护"],
     "banners":[{"name":"PluginHub","img":"IMG/Banner/PluginHub.png","url":"https://github.com/luestr/IconResource","index":0}],
     "lists":[
      {"name":"HTTPDNS拦截器","desc":"依赖插件。\\\\n\\\\n第二行","tag":["去广告","依赖"],
       "icon":"https://raw.githubusercontent.com/luestr/IconResource/main/Other_icon/120px/HTTPDNS.png","date":"2026-10-02 13:57:49",
       "url":"loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/Block_HTTPDNS.lpx",
       "author":[{"name":"可莉🅥","homepage":"https://github.com/luestr"},{"name":"VirgilClyne","homepage":"https://github.com/VirgilClyne"}],"index":0},
      {"name":"Apple天气增强","desc":"","tag":["功能增强"],"icon":"IMG/a.png",
       "url":"loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/AppleWeatherEnhancer.lpx","author":[{"name":"VirgilClyne"}],"index":1}
     ]}
    """

    func testListJSON() throws {
        let items = try XCTUnwrap(ModuleGallery.parseJSON(Data(sample.utf8), base: URL(string: KeleeHub.indexURL)!))
        XCTAssertEqual(items.count, 2, "banners are not modules")
        let a = items[0]
        XCTAssertEqual(a.name, "HTTPDNS拦截器")
        XCTAssertEqual(a.url, "https://kelee.one/Tool/Loon/Lpx/Block_HTTPDNS.lpx")
        XCTAssertEqual(a.category, "去广告")
        XCTAssertEqual(a.author, "可莉🅥, VirgilClyne")
        XCTAssertEqual(a.desc, "依赖插件。\n\n第二行")
        XCTAssertTrue(a.icon.hasPrefix("https://raw.githubusercontent.com/"))
        XCTAssertEqual(a.formatHint, "loon")
        XCTAssertEqual(items[1].category, "功能增强")
        XCTAssertEqual(items[1].icon, "https://hub.kelee.one/IMG/a.png", "relative icons resolve against the index URL")
    }

    @MainActor func testDefaultSource() {
        XCTAssertTrue(ModuleGallery.defaultSources.contains { $0.id == KeleeHub.sourceID && $0.url == KeleeHub.indexURL })
    }
}
