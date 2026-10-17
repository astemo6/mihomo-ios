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
    // qx/rebuild: QX-style widget (exit location header, policy chain, run mode). Optional so older saves decode.
    var flag: String? = nil
    var place: String? = nil
    var detail: String? = nil
    var chain: String? = nil
    var mode: String? = nil

    private static let key = "widgetSnapshot.v1"

    static func load() -> WidgetSnapshot {
        guard let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode(WidgetSnapshot.self, from: d) else { return WidgetSnapshot() }
        return s
    }

    /// Saves and returns true when node / policy / profile changed (timestamps alone do not count).
    @discardableResult
    func save() -> Bool {
        let old = Self.load()
        guard old.node != node || old.policy != policy || old.profile != profile || old.remaining != remaining
                || old.flag != flag || old.place != place || old.detail != detail || old.chain != chain || old.mode != mode else { return false }
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

    private static let key = "liveStats.v1"
    /// The app's 实时活动 switch (外观); the extension samples only while it is on.
    static var wanted: Bool { AppShared.defaults.bool(forKey: "liveActivity.enabled") }

    static func load() -> LiveStats {
        guard let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode(LiveStats.self, from: d) else { return LiveStats() }
        return s
    }

    func save() {
        if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) }
    }

    /// Parses LibmihomoLiveStatus(): "up\tdown\ttotalUp\ttotalDown\tnode".
    init(status: String, time: Date = Date()) {
        let f = status.components(separatedBy: "\t")
        if f.count >= 5 {
            up = Int64(f[0]) ?? 0; down = Int64(f[1]) ?? 0
            totalUp = Int64(f[2]) ?? 0; totalDown = Int64(f[3]) ?? 0
            node = f[4]
        }
        self.time = time
    }

    init() {}
}
