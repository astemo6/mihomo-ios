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
            Task { await a.update(ActivityContent(state: state, staleDate: nil, relevanceScore: 50)) }
            // A second activity (e.g. from a relaunch race) would show twice on the Lock Screen.
            for extra in live.dropFirst() { Task { await extra.end(nil, dismissalPolicy: .immediate) } }
            return
        }
        let attrs = MihomoActivityAttributes(profile: ProfileStore.shared.active?.name ?? "Tern")
        _ = try? Activity.request(attributes: attrs, content: ActivityContent(state: state, staleDate: nil, relevanceScore: 50), pushType: nil)
    }

    // hotfix/liveact-lockscreen (device 2026-10-21: iOS asked 「要继续允许 Tern 的实时活动吗」 and the Lock Screen showed
    // speeds four minutes old). ActivityKit updates are kept rare: at most one every `minInterval`, and only when
    // something the card shows changed meaningfully; otherwise one keep-alive every `keepAlive` so the card doesn't go
    // stale while the app is open. The stale date is ~2× the cadence: past it the card drops the instant speeds and
    // shows totals + 「更新于」. The elapsed time is drawn by the system (Text style .relative) and needs no updates.
    static let minInterval: TimeInterval = 15
    static let keepAlive: TimeInterval = 30
    static let staleAfter: TimeInterval = 45

    /// True when the card would look different enough to spend an update: node / scope changed, or a speed moved by
    /// more than 30 % and at least 8 KB/s (idle ↔ busy still counts).
    nonisolated static func meaningful(old: (up: Int64, down: Int64), new: (up: Int64, down: Int64)) -> Bool {
        func moved(_ a: Int64, _ b: Int64) -> Bool {
            let d = abs(a - b)
            return d >= 8 * 1024 && Double(d) > 0.3 * Double(max(a, b, 1))
        }
        return moved(old.up, new.up) || moved(old.down, new.down)
    }

    /// Called from the dashboard's traffic poll with numbers in the 首页流量统计 scope (every ~2 s); throttled as above.
    func traffic(up: Int64, down: Int64, totalUp: Int64, totalDown: Int64, node: String) {
        guard enabled, #available(iOS 16.2, *), let a = current.first else { return }
        let now = Date()
        let age = now.timeIntervalSince(lastUpdate)
        guard age >= Self.minInterval else { return }
        let proxyOnly: Bool? = TrafficScope.current == .proxy ? true : nil
        let changed = node != last.node || proxyOnly != a.content.state.proxyOnly
            || Self.meaningful(old: (last.up, last.down), new: (up, down))
        guard changed || age >= Self.keepAlive else { return }
        lastUpdate = now
        last = (up, down, node)
        let since = VPNManager.shared.connectedDate ?? a.content.state.since
        var state = MihomoActivityAttributes.ContentState(connected: true, node: node, up: up, down: down, since: since, updated: now)
        state.proxyOnly = proxyOnly
        state.totalUp = totalUp
        state.totalDown = totalDown
        Task { await a.update(ActivityContent(state: state, staleDate: now.addingTimeInterval(Self.staleAfter), relevanceScore: 50)) }
    }

    // MARK: v0.11 updates while the app is closed

    static let refreshTaskID = "mihomo.liveactivity.refresh"
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    /// AppDelegate.didFinishLaunching: background refresh handler + the refresh button's hook.
    static func registerBackgroundWork() {
        LiveActivityHook.refresh = { await LiveActivityController.shared.refreshFromShared() }
        // r7: the tunnel posts this from stopTunnel (also when stopped from the widget / Control Center).
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), nil, { _, _, _, _, _ in
            Task { @MainActor in await LiveActivityController.shared.endIfTunnelDown() }
        }, AppShared.tunnelStoppedNotification as CFString, nil, .deliverImmediately)
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
        // hotfix/liveact-lockscreen: two refreshes ~15 s apart (was five, 5 s apart) — enough to carry the newest
        // tunnel sample (written every 10 s) onto the card without a burst of ActivityKit updates.
        Task { @MainActor in
            for _ in 0..<2 {
                try? await Task.sleep(nanoseconds: UInt64(Self.minInterval * 1_000_000_000))
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
            let tot = s.totals(TrafficScope.current)
            state.totalUp = tot?.up
            state.totalDown = tot?.down
        }
        state.proxyOnly = TrafficScope.current == .proxy ? true : nil
        state.since = VPNManager.shared.connectedDate ?? state.since
        // Stale ~2× the cadence after the sample was taken, so 「更新于」 and the hidden speeds stay honest. Nothing new
        // and already stale: skip the update (it would change nothing on screen).
        let staleAt = state.updated.addingTimeInterval(Self.staleAfter)
        if state == a.content.state && staleAt <= now { return }
        lastUpdate = now
        last = (state.up, state.down, state.node)
        await a.update(ActivityContent(state: state, staleDate: staleAt, relevanceScore: 50))
    }

    /// r7: ends a Live Activity left behind by a tunnel that stopped while the app was not running (widget / Control
    /// Center / iOS). Called on launch / foreground and on the tunnel's stop notification; cheap when none is shown.
    func endIfTunnelDown() async {
        guard #available(iOS 16.2, *), !Activity<MihomoActivityAttributes>.activities.isEmpty else { return }
        await VPNManager.shared.load()
        if !VPNManager.shared.isConnected && VPNManager.shared.status != .connecting && VPNManager.shared.status != .reasserting {
            endAll()
        }
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
