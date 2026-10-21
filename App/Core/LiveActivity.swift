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

    /// v0.12: only activities still on screen. Ended / dismissed ones can linger in `activities`; updating
    /// them is a no-op, which used to keep a new activity from starting after the user swiped one away.
    @available(iOS 16.2, *)
    private var current: [Activity<MihomoActivityAttributes>] {
        Activity<MihomoActivityAttributes>.activities.filter { $0.activityState == .active || $0.activityState == .stale }
    }

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
        var state = MihomoActivityAttributes.ContentState(connected: true, node: DashboardModel.shared.selectedNode, up: 0, down: 0, since: since, updated: Date())
        state.proxyOnly = TrafficScope.current == .proxy ? true : nil
        let live = current
        if let a = live.first {
            Task { await a.update(ActivityContent(state: state, staleDate: nil)) }
            // A second activity (e.g. from a relaunch race) would show twice on the Lock Screen.
            for extra in live.dropFirst() { Task { await extra.end(nil, dismissalPolicy: .immediate) } }
            return
        }
        let attrs = MihomoActivityAttributes(profile: ProfileStore.shared.active?.name ?? "Mihomo")
        _ = try? Activity.request(attributes: attrs, content: ActivityContent(state: state, staleDate: nil), pushType: nil)
    }

    /// Called from the dashboard's traffic poll with numbers in the 首页流量统计 scope; throttled to one update every 3 s.
    func traffic(up: Int64, down: Int64, node: String) {
        guard enabled, #available(iOS 16.2, *), let a = current.first else { return }
        let now = Date()
        guard now.timeIntervalSince(lastUpdate) >= 3 else { return }
        if last == (up, down, node) && now.timeIntervalSince(lastUpdate) < 20 { return } // still refresh the stale date
        lastUpdate = now
        last = (up, down, node)
        let since = VPNManager.shared.connectedDate ?? a.content.state.since
        var state = MihomoActivityAttributes.ContentState(connected: true, node: node, up: up, down: down, since: since, updated: now)
        state.proxyOnly = TrafficScope.current == .proxy ? true : nil
        // v0.19.8: updates arrive every 3 s while the app runs; 30 s without one means the app was suspended, so the
        // numbers turn grey (still shown) rather than looking live.
        Task { await a.update(ActivityContent(state: state, staleDate: now.addingTimeInterval(30))) }
    }

    // MARK: v0.11 updates while the app is closed

    static let refreshTaskID = "mihomo.liveactivity.refresh"
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    /// AppDelegate.didFinishLaunching: background refresh handler + the refresh button's hook.
    static func registerBackgroundWork() {
        LiveActivityHook.refresh = { await LiveActivityController.shared.refreshFromShared() }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshTaskID, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            let once = BGTaskOnce(task)
            let work = Task { @MainActor in
                await LiveActivityController.shared.refreshFromShared()
                LiveActivityController.shared.scheduleBackgroundRefresh()
                once.complete(success: true)
            }
            task.expirationHandler = { work.cancel(); once.complete(success: false) }
        }
    }

    /// iOS decides when (typically every 15 min or more, less on low battery); nothing runs if it doesn't.
    func scheduleBackgroundRefresh() {
        guard enabled, #available(iOS 16.2, *), !current.isEmpty else { return }
        let req = BGAppRefreshTaskRequest(identifier: Self.refreshTaskID)
        req.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(req)
    }

    /// The app moved to the background: keep the activity current for the short time iOS allows.
    func didEnterBackground() {
        guard enabled, #available(iOS 16.2, *), !current.isEmpty else { return }
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
        guard enabled, #available(iOS 16.2, *), let a = current.first else { return }
        await VPNManager.shared.load()
        guard VPNManager.shared.isConnected else { endAll(); return }
        let s = LiveStats.load()
        let now = Date()
        let fresh = now.timeIntervalSince(s.time) < 30
        var state = a.content.state
        state.connected = true
        if !s.node.isEmpty { state.node = s.node }
        // v0.19.8: the newest numbers we have (the tunnel's when they are newer than the activity's), with the time
        // they were taken; the activity draws them grey past the stale date instead of a bare "—". Before, an old
        // sample became 0 / 0 with a 1 s stale date, so the island showed "—" almost all the time.
        if s.time > state.updated || fresh {
            let sp = s.speed(TrafficScope.current) // feat/traffic-scope: same scope as Home
            state.up = sp.up
            state.down = sp.down
            state.updated = s.time
        }
        state.proxyOnly = TrafficScope.current == .proxy ? true : nil
        state.since = VPNManager.shared.connectedDate ?? state.since
        let staleAt = max(state.updated.addingTimeInterval(45), now.addingTimeInterval(fresh ? 30 : 0))
        await a.update(ActivityContent(state: state, staleDate: staleAt))
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
