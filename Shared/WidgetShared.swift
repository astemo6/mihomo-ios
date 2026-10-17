import Foundation

/// What the app last saw while connected, for the widget / Control Center toggle (v0.7). Stored in the
/// App Group defaults; the widget reads the connection state itself from NetworkExtension.
struct WidgetSnapshot: Codable, Equatable {
    var node: String = ""
    var policy: String = ""
    var profile: String = ""
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
        guard old.node != node || old.policy != policy || old.profile != profile || old.flag != flag || old.place != place
                || old.detail != detail || old.chain != chain || old.mode != mode else { return false }
        if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) }
        return true
    }
}
