import Foundation
import ActivityKit
import BackgroundTasks
import UIKit

/// Starts a Live Activity when the tunnel connects (if enabled), updates it with speed and node while the
/// app runs, and ends it on disconnect. The activity is drawn by the widget extension, so it only appears
/// with the "-widget" IPA. The timer keeps running on its own after the app is suspended. v0.11: while the
/// app is closed the tunnel extension stores speed / node in the App Group (LiveStats); the app pushes
/// them into the activity for ~25 s after going to the background, whenever iOS grants a background
/// refresh, and when the activity's refresh button is tapped (iOS 17+). Between those the speed is shown
/// as stale rather than frozen.
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

    // MARK: v0.11 updates while the app is closed

    static let refreshTaskID = "mihomo.liveactivity.refresh"
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    /// AppDelegate.didFinishLaunching: background refresh handler + the refresh button's hook.
    static func registerBackgroundWork() {
        LiveActivityHook.refresh = { await LiveActivityController.shared.refreshFromShared() }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshTaskID, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            let work = Task { @MainActor in
                await LiveActivityController.shared.refreshFromShared()
                LiveActivityController.shared.scheduleBackgroundRefresh()
                task.setTaskCompleted(success: true)
            }
            task.expirationHandler = { work.cancel() }
        }
    }

    /// iOS decides when (typically every 15 min or more, less on low battery); nothing runs if it doesn't.
    func scheduleBackgroundRefresh() {
        guard enabled, #available(iOS 16.2, *), !Activity<MihomoActivityAttributes>.activities.isEmpty else { return }
        let req = BGAppRefreshTaskRequest(identifier: Self.refreshTaskID)
        req.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(req)
    }

    /// The app moved to the background: keep the activity current for the short time iOS allows.
    func didEnterBackground() {
        guard enabled, #available(iOS 16.2, *), !Activity<MihomoActivityAttributes>.activities.isEmpty else { return }
        scheduleBackgroundRefresh()
        if backgroundTask != .invalid { return }
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "LiveActivity") { [weak self] in
            self?.endBackgroundTask()
        }
        Task { @MainActor in
            for _ in 0..<5 {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                if UIApplication.shared.applicationState == .active { break }
                await refreshFromShared()
            }
            endBackgroundTask()
        }
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    /// Updates the activity from the extension's latest LiveStats (ends it when the tunnel is down).
    func refreshFromShared() async {
        guard enabled, #available(iOS 16.2, *), let a = Activity<MihomoActivityAttributes>.activities.first else { return }
        await VPNManager.shared.load()
        guard VPNManager.shared.isConnected else { endAll(); return }
        let s = LiveStats.load()
        let now = Date()
        let fresh = now.timeIntervalSince(s.time) < 30
        var state = a.content.state
        state.connected = true
        if !s.node.isEmpty { state.node = s.node }
        state.up = fresh ? s.up : 0
        state.down = fresh ? s.down : 0
        state.since = VPNManager.shared.connectedDate ?? state.since
        state.updated = fresh ? s.time : now
        await a.update(ActivityContent(state: state, staleDate: now.addingTimeInterval(fresh ? 60 : 1)))
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
