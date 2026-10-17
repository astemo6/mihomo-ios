import Foundation
#if canImport(ActivityKit) && !os(macOS)
import ActivityKit

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
#endif

enum LiveActivityFormat {
    /// "1.2 MB/s" style, compact for the Dynamic Island.
    static func speed(_ v: Int64) -> String {
        let units = ["B", "K", "M", "G"]
        var d = Double(max(v, 0)); var i = 0
        while d >= 1024 && i < units.count - 1 { d /= 1024; i += 1 }
        return (i == 0 ? "\(Int(d))" : String(format: d >= 100 ? "%.0f" : "%.1f", d)) + units[i]
    }
}
