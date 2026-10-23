import Foundation
import UserNotifications

/// 更多 → 通知 (feat/loon-menu-notify, user 2026-10-23 「借鉴下 Loon 的通知分类，现在的太少了」): which kinds of
/// system notification Tern may post. Stored in the App Group so the tunnel reads the same switches; the app tells a
/// running tunnel about a change with TunnelMessage.notifyPrefs (the core's policy watcher only runs while one of
/// its kinds is on).
///
/// Every kind is produced from real events:
/// - network        tunnel, NetworkWatcher (the debounced network-changed event, same one event scripts get)
/// - policyChange   core, policywatch.go: an automatic group (url-test / fallback) picked another node
/// - policyFailure  core, policywatch.go: every node of a policy group failed its latency test
/// - nodeFailure    core, policywatch.go: the node the main policy resolves to failed its latency test
/// - scripts        core, $notification.post / $notify from rewrites and modules
/// - memory         tunnel, MemoryGuard closed connections near the extension's memory limit
/// - vpn            tunnel, stopped by iOS for a reason other than the user (or reconnected after the system ended it)
/// The subscription usage / expiry and automatic-update notifications keep their own switches (UsageAlerts,
/// ScheduledUpdates) and are posted by the app.
enum NotifyKind: String, CaseIterable, Identifiable {
    case network, policyFailure, policyChange, nodeFailure, scripts, memory, vpn

    var id: String { rawValue }

    /// App Group key. `scripts` keeps its pre-0.19.18 key.
    var key: String { "notify." + rawValue }

    /// Loon's defaults where Loon has the same switch (网络变化 / 内存警告 off, the others on).
    var defaultOn: Bool {
        switch self {
        case .network, .memory: return false
        default: return true
        }
    }

    /// Bit for LibmihomoSetPolicyEvents (policywatch.go: 1 change, 2 failure, 4 node).
    var coreBit: Int32 {
        switch self {
        case .policyChange: return 1
        case .policyFailure: return 2
        case .nodeFailure: return 4
        default: return 0
        }
    }
}

enum NotifyPrefs {
    /// 允许通知: the master switch above the categories (Loon). Off = Tern posts nothing from the tunnel.
    static let masterKey = "notify.enabled"

    static var masterEnabled: Bool {
        get { AppShared.defaults.object(forKey: masterKey) as? Bool ?? true }
        set { AppShared.defaults.set(newValue, forKey: masterKey) }
    }

    static func isOn(_ k: NotifyKind) -> Bool {
        AppShared.defaults.object(forKey: k.key) as? Bool ?? k.defaultOn
    }

    static func set(_ k: NotifyKind, _ on: Bool) {
        AppShared.defaults.set(on, forKey: k.key)
    }

    /// Master switch and the kind's own switch.
    static func allows(_ k: NotifyKind) -> Bool { masterEnabled && isOn(k) }

    /// The policy-watcher kinds that are on, as LibmihomoSetPolicyEvents' mask (0 = watcher stopped).
    static var coreMask: Int32 {
        guard masterEnabled else { return 0 }
        var m: Int32 = 0
        for k in NotifyKind.allCases where k.coreBit != 0 && isOn(k) { m |= k.coreBit }
        return m
    }
}

/// Notification text built in the tunnel. The extension carries no string catalog (keeps it small), so titles and
/// bodies are catalog keys localized by iOS when the notification is shown, with the app bundle's
/// Localizable.strings (`NSString.localizedUserNotificationString`). Every key used here is a manual entry in
/// App/Localizable.xcstrings with %@ placeholders.
enum NotifyText {
    static func loc(_ key: String, _ args: [String] = []) -> String {
        let a: [Any]? = args.isEmpty ? nil : args.map { $0 as Any }
        return NSString.localizedUserNotificationString(forKey: key, arguments: a)
    }
}
