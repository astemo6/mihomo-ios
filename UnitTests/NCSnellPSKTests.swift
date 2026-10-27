import XCTest
@testable import Tern

/// fix/nc-0.20.2: snell:// links and Clash nodes carry `psk`; Surge/QX importers write `password`. The dialer read
/// only `password` → "snell missing psk". NCProxy.password now reads either for snell.
final class NCSnellPSKTests: XCTestCase {
    func testSnellLinkPSKIsTheDialKey() {
        let nodes = NCSubscriptionParser.parse("snell://psk123@1.2.3.4:6333?version=4#sn1")
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes.first?.fields["psk"]?.string, "psk123")
        XCTAssertEqual(nodes.first?.password, "psk123")
    }

    func testClashSnellWithOnlyPSK() {
        let cfg = NCConfig.decode(root: ["proxies": .array([.object([
            "name": .string("s"), "type": .string("snell"), "server": .string("1.2.3.4"),
            "port": .number(443), "psk": .string("k1"), "version": .number(4)])])])
        XCTAssertEqual(cfg.proxies.first?.password, "k1")
    }

    func testPasswordStillWinsAndOtherTypesUnaffected() {
        let cfg = NCConfig.decode(root: ["proxies": .array([
            .object(["name": .string("s"), "type": .string("snell"), "password": .string("p"), "psk": .string("k")]),
            .object(["name": .string("t"), "type": .string("trojan"), "psk": .string("k")])])])
        XCTAssertEqual(cfg.proxies[0].password, "p")
        XCTAssertNil(cfg.proxies[1].password)
    }

    func testShareLinkExportFallsBackToPassword() throws {
        let link = try NCShareLink.encode(["name": "s", "type": "snell", "server": "1.2.3.4", "port": 443,
                                           "password": "pw9", "version": 4] as [String: Any])
        XCTAssertTrue(link.hasPrefix("snell://pw9@"), link)
    }
}
