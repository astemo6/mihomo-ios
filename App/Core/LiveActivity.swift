import Foundation
import ActivityKit

/// Starts a Live Activity when the tunnel connects (if enabled), updates it with speed and node while the
/// app runs, and ends it on disconnect. The activity is drawn by the widget extension, so it only appears
/// with the "-widget" IPA. The timer keeps running on its own after the app is suspended; speed and node
/// refresh whenever the app is open.
@MainActor
final class LiveActivityController: ObservableObject {
    static let shared = LiveActivityController()
    static let key = "liveActivity.enabled"

    @Published var enabled: Bool {
        didSet {
            AppShared.defaults.set(enabled, forKey: Self.key)
            if enabled { if VPNManager.shared.isConnected { start() } } else { endAll() }
        }
    }
    private var lastUpdate = Date.distantPast
    private var last: (up: Int64, down: Int64, node: String) = (0, 0, "")

    init() { enabled = AppShared.defaults.bool(forKey: Self.key) }

    var systemAllowed: Bool {
        if #available(iOS 16.2, *) { return ActivityAuthorizationInfo().areActivitiesEnabled }
        return false
    }

    func statusChanged(connected: Bool) {
        if connected { start() } else { endAll() }
    }

    func start() {
        guard enabled, #available(iOS 16.2, *), ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        let since = VPNManager.shared.connectedDate ?? Date()
        let state = MihomoActivityAttributes.ContentState(connected: true, node: DashboardModel.shared.selectedNode, up: 0, down: 0, since: since, updated: Date())
        if let a = Activity<MihomoActivityAttributes>.activities.first {
            Task { await a.update(ActivityContent(state: state, staleDate: nil)) }
            return
        }
        let attrs = MihomoActivityAttributes(profile: ProfileStore.shared.active?.name ?? "Mihomo")
        _ = try? Activity.request(attributes: attrs, content: ActivityContent(state: state, staleDate: nil), pushType: nil)
    }

    /// Called from the dashboard's traffic stream; throttled to one update every 3 s.
    func traffic(up: Int64, down: Int64, node: String) {
        guard enabled, #available(iOS 16.2, *), let a = Activity<MihomoActivityAttributes>.activities.first else { return }
        let now = Date()
        guard now.timeIntervalSince(lastUpdate) >= 3 else { return }
        if last == (up, down, node) { return }
        lastUpdate = now
        last = (up, down, node)
        let since = VPNManager.shared.connectedDate ?? a.content.state.since
        let state = MihomoActivityAttributes.ContentState(connected: true, node: node, up: up, down: down, since: since, updated: now)
        Task { await a.update(ActivityContent(state: state, staleDate: now.addingTimeInterval(120))) }
    }

    func endAll() {
        guard #available(iOS 16.2, *) else { return }
        for a in Activity<MihomoActivityAttributes>.activities {
            var s = a.content.state
            s.connected = false; s.up = 0; s.down = 0; s.updated = Date()
            Task { await a.end(ActivityContent(state: s, staleDate: nil), dismissalPolicy: .immediate) }
        }
    }
}
