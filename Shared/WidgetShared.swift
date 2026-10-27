import Foundation

/// What the app last saw while connected, for the widget / Control Center toggle (v0.7). Stored in the
/// App Group defaults; the widget reads the connection state itself from NetworkExtension.
struct WidgetSnapshot: Codable, Equatable {
    var node: String = ""
    var policy: String = ""
    var profile: String = ""
    /// v0.9: remaining traffic of the active subscription ("" / nil = unknown), already formatted.
    var remaining: String? = nil
    var updated: Date = .distantPast

    private static let key = "widgetSnapshot.v1"

    static func load() -> WidgetSnapshot {
        guard let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode(WidgetSnapshot.self, from: d) else { return WidgetSnapshot() }
        return s
    }

    /// Saves and returns true when node / policy / profile changed (timestamps alone do not count).
    @discardableResult
    func save() -> Bool {
        let old = Self.load()
        guard old.node != node || old.policy != policy || old.profile != profile || old.remaining != remaining else { return false }
        if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) }
        return true
    }
}

/// v0.11 Live Activity path: the tunnel extension samples speed / totals / main node every 10 s while the
/// Live Activity is switched on and stores them here; the app (also when iOS wakes it in the background,
/// or when the activity's refresh button runs) pushes them into ActivityKit, which extensions can't call.
struct LiveStats: Codable, Equatable {
    var up: Int64 = 0
    var down: Int64 = 0
    var totalUp: Int64 = 0
    var totalDown: Int64 = 0
    var node: String = ""
    var time: Date = .distantPast
    /// feat/traffic-scope: the same numbers for traffic that left through a proxy node only (DIRECT / REJECT
    /// excluded), measured in the tunnel. Optional so samples stored by an older build still decode.
    var proxyUp: Int64? = nil
    var proxyDown: Int64? = nil
    var proxyTotalUp: Int64? = nil
    var proxyTotalDown: Int64? = nil

    /// Speed (bytes/s) in the user's 首页流量统计 scope; nil proxy fields (older tunnel) fall back to 0, never to
    /// the all-traffic numbers.
    func speed(_ scope: TrafficScope) -> (up: Int64, down: Int64) {
        scope == .proxy ? (proxyUp ?? 0, proxyDown ?? 0) : (up, down)
    }

    /// Session totals (bytes) in the same scope; nil when the proxy totals are unknown (older tunnel).
    func totals(_ scope: TrafficScope) -> (up: Int64, down: Int64)? {
        if scope == .proxy {
            guard let u = proxyTotalUp, let d = proxyTotalDown else { return nil }
            return (u, d)
        }
        return (totalUp, totalDown)
    }

    private static let key = "liveStats.v1"
    /// The app's 实时活动 switch (外观); the extension samples only while it is on.
    static var wanted: Bool { AppShared.defaults.bool(forKey: "liveActivity.enabled") }
    /// r7 (B19): posted by the app when the switch changes, so the tunnel's sampler starts / idles at once.
    static var wantedChangedNotification: String { AppShared.appGroup + ".liveStatsWanted" }
    static func postWantedChanged() {
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName(wantedChangedNotification as CFString), nil, nil, true)
    }

    static func load() -> LiveStats {
        guard let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode(LiveStats.self, from: d) else { return LiveStats() }
        return s
    }

    func save() {
        if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) }
    }

    /// Parses LiveStatus(): "up\tdown\ttotalUp\ttotalDown\tnode" plus, since feat/traffic-scope,
    /// "\tproxyUp\tproxyDown\tproxyUpTotal\tproxyDownTotal".
    init(status: String, time: Date = Date()) {
        let f = status.components(separatedBy: "\t")
        if f.count >= 5 {
            up = Int64(f[0]) ?? 0; down = Int64(f[1]) ?? 0
            totalUp = Int64(f[2]) ?? 0; totalDown = Int64(f[3]) ?? 0
            node = f[4]
        }
        if f.count >= 9 {
            proxyUp = Int64(f[5]); proxyDown = Int64(f[6])
            proxyTotalUp = Int64(f[7]); proxyTotalDown = Int64(f[8])
        }
        self.time = time
    }

    init() {}
}

/// feat/traffic-scope (user 2026-10-21 「首页的流量是显示走代理的还是全部的 做个选项」): what Home's speed, totals,
/// tiles and the Live Activity count. 全部流量 = everything the core relays (DIRECT included, the default and
/// the behaviour before); 仅代理流量 = only connections whose outbound is a proxy node (not DIRECT / REJECT).
/// Stored in the App Group so the app and the Live Activity path read the same choice.
enum TrafficScope: String, CaseIterable, Identifiable {
    case all
    case proxy

    var id: String { rawValue }
    static let key = "home.trafficScope"

    static var current: TrafficScope {
        get { TrafficScope(rawValue: AppShared.defaults.string(forKey: key) ?? "") ?? .all }
        set { AppShared.defaults.set(newValue.rawValue, forKey: key) }
    }

    /// zh-Hans source keys.
    var title: String { self == .all ? "全部流量" : "仅代理流量" }
}
