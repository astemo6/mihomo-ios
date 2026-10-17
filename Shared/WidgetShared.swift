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
