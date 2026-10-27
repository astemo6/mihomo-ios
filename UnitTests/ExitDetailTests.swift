import XCTest
@testable import Tern

/// hotfix/home-isp (device 2026-10-21 「首页最上方也显示运营商信息的 比如xtom」): the Home header's small line shows
/// 运营商 · ASN · IP by default, chosen in 出口信息来源 → 首页副标题显示, and every built-in endpoint fills `org`.
final class ExitDetailTests: XCTestCase {

    private func info(org: String? = "xTom Japan Corporation", tz: String? = "Asia/Tokyo") -> IPInfo {
        IPInfo(ip: "45.92.159.155", countryCode: "JP", country: "Japan", region: "Tokyo", city: "Tokyo",
               asn: "AS3258", org: org, source: "test", timezone: tz)
    }

    func testShortOrg() {
        XCTAssertEqual(IPInfo.shortOrg("xTom Japan Corporation"), "xTom Japan")
        XCTAssertEqual(IPInfo.shortOrg("xTom GmbH"), "xTom")
        XCTAssertEqual(IPInfo.shortOrg("Cloudflare, Inc."), "Cloudflare")
        XCTAssertEqual(IPInfo.shortOrg("Akamai Technologies, Inc."), "Akamai Technologies")
        XCTAssertEqual(IPInfo.shortOrg("DigitalOcean, LLC"), "DigitalOcean")
        XCTAssertEqual(IPInfo.shortOrg("Telia Company AB"), "Telia")
        XCTAssertEqual(IPInfo.shortOrg("China Mobile Communications Co., Ltd."), "China Mobile…munications")
        XCTAssertEqual(IPInfo.shortOrg("Hetzner Online GmbH"), "Hetzner Online")
        XCTAssertEqual(IPInfo.shortOrg("LLC"), "LLC", "a name that is only a suffix stays")
        XCTAssertNil(IPInfo.shortOrg("  "))
        XCTAssertNil(IPInfo.shortOrg(nil))
        let long = IPInfo.shortOrg("Hong Kong Telecommunications Infrastructure Holdings Limited")!
        XCTAssertLessThanOrEqual(long.count, 24)
        XCTAssertTrue(long.contains("…"), long)
        XCTAssertTrue(long.hasPrefix("Hong Kong"), long)
    }

    func testDefaultLine() {
        let f = ExitDetailField.parse(nil)
        XCTAssertEqual(f, [.isp, .asn, .ip])
        XCTAssertEqual(info().detailText(fields: f), "xTom Japan · AS3258 · 45.92.159.155")
    }

    func testFallbackToTimeZone() {
        let f = ExitDetailField.parse(nil)
        XCTAssertEqual(info(org: nil).detailText(fields: f), "Asia/Tokyo · AS3258 · 45.92.159.155")
        // 时区 chosen anyway: no duplicate, unknown provider left out.
        XCTAssertEqual(info(org: nil).detailText(fields: [.isp, .timezone, .ip]), "Asia/Tokyo · 45.92.159.155")
        // Nothing known for the slot: left out, never invented.
        XCTAssertEqual(info(org: nil, tz: nil).detailText(fields: f), "AS3258 · 45.92.159.155")
    }

    func testChoiceAndOrder() {
        XCTAssertEqual(info().detailText(fields: [.ip, .timezone]), "Asia/Tokyo · 45.92.159.155", "fixed order")
        XCTAssertEqual(info().detailText(fields: ExitDetailField.legacy), "AS3258 · Asia/Tokyo · 45.92.159.155")
        XCTAssertEqual(info().detailText(fields: []), "")
        XCTAssertEqual(ExitDetailField.parse(""), [])
        XCTAssertEqual(ExitDetailField.encode([.ip, .isp]), "isp,ip")
        XCTAssertEqual(ExitDetailField.parse("ip, bogus ,asn"), [.ip, .asn])
    }

    func testCustomSubtitleWins() {
        var i = info()
        i.customSubtitle = "Script line"
        XCTAssertEqual(i.detailText(fields: ExitDetailField.parse(nil)), "Script line")
    }

    func testEndpointsFillOrg() {
        func ep(_ name: String) -> IPInfoFetcher.Endpoint { IPInfoFetcher.endpoints.first { $0.name == name }! }
        XCTAssertEqual(ep("ipinfo.io").parse(["ip": "1.2.3.4", "org": "AS3258 xTom Japan Corporation"])?.org, "xTom Japan Corporation")
        XCTAssertEqual(ep("ipinfo.io").parse(["ip": "1.2.3.4", "org": "AS3258 xTom Japan Corporation"])?.asn, "AS3258")
        let api = ep("ip-api.com")
        XCTAssertTrue(api.url.contains("isp") && api.url.contains("org") && api.url.contains("as"), "ip-api asks for isp/org/as")
        XCTAssertEqual(api.parse(["query": "1.2.3.4", "as": "AS3258 xTom Japan Corporation", "isp": "xTom Japan"])?.org, "xTom Japan")
        XCTAssertEqual(api.parse(["query": "1.2.3.4", "as": "AS3258 xTom Japan Corporation"])?.org, "xTom Japan Corporation")
        XCTAssertEqual(ep("ip.sb").parse(["ip": "1.2.3.4", "asn": 3258, "asn_organization": "xTom"])?.org, "xTom")
        XCTAssertEqual(ep("ipapi.co").parse(["ip": "1.2.3.4", "asn": "AS3258", "org": "xTom"])?.org, "xTom")
        XCTAssertEqual(ep("ipwho.is").parse(["ip": "1.2.3.4", "connection": ["asn": 3258, "isp": "xTom"]])?.org, "xTom")
        XCTAssertEqual(IPInfoFetcher.genericParse(["ip": "1.2.3.4", "isp": "xTom"], source: "x")?.org, "xTom")
        XCTAssertEqual(IPInfoFetcher.genericParse(["query": "1.2.3.4", "as": "AS3258 xTom Japan"], source: "x")?.org, "xTom Japan")
        XCTAssertEqual(IPInfoFetcher.genericParse(["ip": "1.2.3.4", "connection": ["org": "xTom"]], source: "x")?.org, "xTom")
    }

    func testFlagTaiwanDrawnAsCN() {
        XCTAssertEqual(CountryFlag.emoji("TW"), "🇨🇳")
        XCTAssertEqual(CountryFlag.emoji("tw"), "🇨🇳")
        XCTAssertEqual(CountryFlag.emoji("JP"), "🇯🇵")
        XCTAssertEqual(CountryFlag.emoji("HK"), "🇭🇰")
        XCTAssertNil(CountryFlag.emoji("TWN"))
        XCTAssertNil(CountryFlag.emoji("1A"))
        XCTAssertNil(CountryFlag.emoji(nil))
        var tw = IPInfo(ip: "1.2.3.4", countryCode: "TW", country: "Taiwan", region: nil, city: "Taipei", asn: nil, org: nil, source: "t")
        XCTAssertEqual(tw.flag, "🇨🇳")
        XCTAssertEqual(tw.city, "Taipei", "place text untouched")
        XCTAssertEqual(tw.countryCode, "TW", "country code untouched")
        tw.countryCode = nil
        XCTAssertEqual(tw.flag, "🌐")
    }
}
