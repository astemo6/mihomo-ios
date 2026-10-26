import XCTest
import NetworkExtension
@testable import Tern

/// fix/vpn-stays-on: 保持连接 — with 按需连接 关闭 a manual connect arms one "connect on any network" rule, so iOS
/// restarts the tunnel after the extension is ended; settings saved by older builds get it on.
final class KeepAliveTests: XCTestCase {
    func testOlderSettingsDecodeWithKeepAliveOn() throws {
        let old = Data(#"{"mode":"off","trustedSSIDs":[],"onlySSIDs":[],"ssidCellular":false}"#.utf8)
        let s = try JSONDecoder().decode(OnDemandSettings.self, from: old)
        XCTAssertTrue(s.keepAlive)
        XCTAssertTrue(OnDemandSettings().keepAlive)
    }

    func testKeepAliveRoundTrips() throws {
        var s = OnDemandSettings()
        s.keepAlive = false
        let back = try JSONDecoder().decode(OnDemandSettings.self, from: JSONEncoder().encode(s))
        XCTAssertFalse(back.keepAlive)
    }

    func testOffModeRules() {
        var s = OnDemandSettings()
        s.mode = .off
        s.keepAlive = true
        XCTAssertEqual(s.rules.count, 1)
        XCTAssertTrue(s.rules.first is NEOnDemandRuleConnect)
        XCTAssertEqual(s.rules.first?.interfaceTypeMatch, .any)
        s.keepAlive = false
        XCTAssertTrue(s.rules.isEmpty)
    }

    /// The user's own on-demand modes are unchanged by 保持连接.
    func testOtherModesIgnoreKeepAlive() {
        for mode in OnDemandSettings.Mode.allCases where mode != .off {
            var a = OnDemandSettings(); a.mode = mode; a.keepAlive = true
            var b = OnDemandSettings(); b.mode = mode; b.keepAlive = false
            XCTAssertEqual(OnDemandSettings.signature(a.rules), OnDemandSettings.signature(b.rules), mode.rawValue)
        }
    }

    func testUnexpectedEndHasAReason() {
        XCTAssertFalse(TunnelStopReason.describe(TunnelStopReason.endedBySystem).contains("-1"))
    }
}
