import Foundation
#if canImport(ActivityKit) && !os(macOS)
import ActivityKit
import AppIntents

/// v0.10 实时活动 / 灵动岛: attributes shared by the app (starts / updates / ends the activity) and the
/// widget extension (draws it). The tunnel extension compiles this file but never uses it.
@available(iOS 16.2, *)
struct MihomoActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var connected: Bool
        var node: String
        var up: Int64      // bytes/s
        var down: Int64    // bytes/s
        var since: Date    // connected since (drives the running timer)
        var updated: Date
    }
    var profile: String
}

/// v0.11: the refresh button on the Lock Screen / Dynamic Island. A LiveActivityIntent runs in the app's
/// process (launched in the background if needed), which may update the activity from the latest
/// numbers the tunnel extension stored (LiveStats).
@available(iOS 17.0, *)
struct RefreshLiveActivityIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "刷新实时活动"
    static var isDiscoverable = false
    init() {}
    func perform() async throws -> some IntentResult {
        if let refresh = await LiveActivityHook.refresh { await refresh() }
        return .result()
    }
}
#endif

/// Set by the app at launch (the widget extension leaves it nil).
@MainActor
enum LiveActivityHook {
    static var refresh: (@MainActor () async -> Void)?
}

enum LiveActivityFormat {
    /// "1.2 MB/s" style, compact for the Dynamic Island.
    static func speed(_ v: Int64) -> String {
        let units = ["B", "K", "M", "G"]
        var d = Double(max(v, 0)); var i = 0
        while d >= 1024 && i < units.count - 1 { d /= 1024; i += 1 }
        return (i == 0 ? "\(Int(d))" : String(format: d >= 100 ? "%.0f" : "%.1f", d)) + units[i]
    }
}
