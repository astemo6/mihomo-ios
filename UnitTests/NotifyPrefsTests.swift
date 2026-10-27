import XCTest
@testable import Tern

/// feat/loon-menu-notify: 更多 → 通知 kinds (App Group switches shared with the tunnel) and the catalog keys the
/// tunnel's notifications use (localized by iOS from the app bundle when shown).
final class NotifyPrefsTests: XCTestCase {
    private var saved: [String: Any] = [:]

    override func setUp() {
        super.setUp()
        for k in NotifyKind.allCases.map(\.key) + [NotifyPrefs.masterKey] {
            if let v = AppShared.defaults.object(forKey: k) { saved[k] = v }
            AppShared.defaults.removeObject(forKey: k)
        }
    }

    override func tearDown() {
        for k in NotifyKind.allCases.map(\.key) + [NotifyPrefs.masterKey] {
            if let v = saved[k] { AppShared.defaults.set(v, forKey: k) } else { AppShared.defaults.removeObject(forKey: k) }
        }
        super.tearDown()
    }

    func testDefaultsFollowLoon() {
        XCTAssertTrue(NotifyPrefs.masterEnabled)
        XCTAssertFalse(NotifyPrefs.isOn(.network))
        XCTAssertFalse(NotifyPrefs.isOn(.memory))
        for k in [NotifyKind.policyFailure, .policyChange, .nodeFailure, .scripts, .vpn] {
            XCTAssertTrue(NotifyPrefs.isOn(k), k.rawValue)
        }
        XCTAssertEqual(NotifyKind.scripts.key, "notify.scripts", "pre-0.19.18 key kept")
    }

    func testCoreMaskAndMaster() {
        XCTAssertEqual(NotifyPrefs.coreMask, 7)
        NotifyPrefs.set(.policyChange, false)
        XCTAssertEqual(NotifyPrefs.coreMask, 6)
        NotifyPrefs.set(.network, true) // not a core kind
        XCTAssertEqual(NotifyPrefs.coreMask, 6)
        XCTAssertTrue(NotifyPrefs.allows(.network))
        NotifyPrefs.masterEnabled = false
        XCTAssertEqual(NotifyPrefs.coreMask, 0)
        XCTAssertFalse(NotifyPrefs.allows(.scripts))
    }

    func testOlderScriptSwitchIsRead() {
        AppShared.defaults.set(false, forKey: "notify.scripts")
        XCTAssertFalse(NotifyPrefs.allows(.scripts))
    }

    /// Every key PacketTunnel passes to NotifyText.loc is translated in every shipped language.
    func testTunnelNotificationKeysAreLocalized() throws {
        let keys = ["网络变化", "策略组异常", "自动策略切换", "节点异常", "内存警告", "VPN 意外断开", "VPN 已自动重新连接",
                    "「%@」已切换到 %@（原为 %@）", "「%@」里的节点全部测速失败，暂时没有可用节点。", "「%@」测速失败（策略组「%@」正在使用）。",
                    "隧道内存接近系统上限，已关闭 %@ 个最早的连接。", "已切换到 Wi-Fi「%@」", "已切换到 Wi-Fi", "已切换到蜂窝网络",
                    "已切换到有线网络", "已切换到其他网络", "扩展未正常退出（被系统终止、崩溃或设备关机）",
                    "扩展运行失败", "网络发生不可恢复的变化", "空闲超时", "被其他 VPN 配置取代", "连接失败", "内部错误"]
        for lang in ["en", "zh-Hant", "ja", "ko", "ru"] {
            let path = try XCTUnwrap(Bundle.main.path(forResource: lang, ofType: "lproj"), lang)
            let b = try XCTUnwrap(Bundle(path: path))
            for k in keys {
                let v = b.localizedString(forKey: k, value: "\u{1}", table: "Localizable")
                XCTAssertNotEqual(v, "\u{1}", "\(lang): \(k)")
                XCTAssertEqual(v.components(separatedBy: "@").count, k.components(separatedBy: "@").count, "\(lang): placeholders of \(k)")
            }
        }
    }
}
