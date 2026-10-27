import Foundation
import UIKit
import UserNotifications
import BackgroundTasks

// v0.14 subscription notifications, all local (nothing leaves the device):
//  • 用量提醒 per subscription (订阅管理 → 编辑): used traffic ≥ N % of the quota, and N days before the
//    expiry date from the subscription-userinfo header. The expiry reminder is scheduled with iOS, so it
//    arrives even when the app is not opened; the quota one is checked after every download.
//  • 更新通知 (opt-in, 订阅管理 → 通知): a summary after scheduled (automatic) updates — failures and big
//    node-count drops only, or every run.
// Scheduled updates also run from a background refresh task now (iOS decides when; usually hours).

/// One subscription's alert settings (stored per subscription id in UserDefaults).
struct UsageAlertRule: Codable, Hashable {
    var enabled = false
    /// Notify when used / total reaches this percentage (0 = off).
    var quotaPercent = 80
    /// Notify this many days before expiry (0 = off).
    var expiryDays = 3

    static let quotaChoices = [50, 70, 80, 90, 95]
    static let expiryChoices = [1, 3, 7, 14]
}

/// What has already been notified, so a threshold fires once per billing cycle.
private struct UsageAlertState: Codable {
    var quotaKey: String?      // "<percent>-<total>-<expire>" of the last quota alert
    var exhaustedKey: String?  // same key for the 100 % alert
    var expiryNotified: Int64? // expire timestamp the reminder was shown / scheduled for
}

enum UsageAlerts {
    private static let rulesKey = "usageAlerts.rules"
    private static let stateKey = "usageAlerts.state"
    static let threadID = "tern.usage"

    static func rule(for id: String) -> UsageAlertRule { allRules()[id] ?? UsageAlertRule() }

    static func setRule(_ r: UsageAlertRule, for id: String) {
        var all = allRules()
        all[id] = r
        save(all, rulesKey)
        if r.enabled { NotificationAuth.request() }
        if !r.enabled || r.expiryDays == 0 { cancelExpiry(id) }
        var st = allStates()
        st[id] = nil // re-evaluate with the new thresholds
        save(st, stateKey)
    }

    static func remove(_ id: String) {
        var all = allRules(); all[id] = nil; save(all, rulesKey)
        var st = allStates(); st[id] = nil; save(st, stateKey)
        cancelExpiry(id)
    }

    /// Called after a successful download and when the app comes to the foreground.
    static func evaluate(id: String, name: String, info: SubscriptionUserInfo?, now: Date = Date()) {
        let r = rule(for: id)
        guard r.enabled, let info else { return }
        var states = allStates()
        var st = states[id] ?? UsageAlertState()
        let cycle = "\(info.total)-\(info.expire)"

        if r.quotaPercent > 0, info.total > 0 {
            let pct = Double(info.used) / Double(info.total) * 100
            let key = "\(r.quotaPercent)-\(cycle)"
            if pct >= 100 {
                if st.exhaustedKey != cycle {
                    post(id: "usage.quota.\(id)", title: String(localized: "「\(name)」流量已用完"),
                         body: String(localized: "已用 \(Fmt.bytes(info.used)) / \(Fmt.bytes(info.total))"))
                    st.exhaustedKey = cycle
                    st.quotaKey = key
                }
            } else if pct >= Double(r.quotaPercent) {
                if st.quotaKey != key {
                    let left = Fmt.bytes(max(info.total - info.used, 0))
                    post(id: "usage.quota.\(id)", title: String(localized: "「\(name)」流量已用 \(Int(pct))%"),
                         body: String(localized: "剩余 \(left)，共 \(Fmt.bytes(info.total))"))
                    st.quotaKey = key
                }
            } else {
                st.quotaKey = nil // below the threshold again (new cycle / quota reset)
                st.exhaustedKey = nil
            }
        }

        if r.expiryDays > 0, let exp = info.expireDate, exp > now {
            let fire = exp.addingTimeInterval(-Double(r.expiryDays) * 86400)
            if fire > now {
                scheduleExpiry(id: id, name: name, expire: exp, at: fire)
                st.expiryNotified = info.expire
            } else if st.expiryNotified != info.expire {
                post(id: "usage.expiry.\(id)", title: String(localized: "「\(name)」即将到期"),
                     body: expiryBody(exp, now: now))
                st.expiryNotified = info.expire
            }
        } else {
            cancelExpiry(id)
        }
        states[id] = st
        save(states, stateKey)
    }

    /// Foreground pass over every subscription (expiry dates move without a download).
    @MainActor static func evaluateAll() {
        for p in ProfileStore.shared.profiles where p.kind == .remote { evaluate(id: p.id, name: p.name, info: p.userInfo) }
        for s in NodeSubStore.shared.subs where s.enabled { evaluate(id: s.id, name: s.name, info: s.userInfo) }
    }

    private static func expiryBody(_ exp: Date, now: Date) -> String {
        let days = max(Int(ceil(exp.timeIntervalSince(now) / 86400)), 1)
        return String(localized: "\(days) 天后到期（\(exp.formatted(date: .abbreviated, time: .shortened))），记得续费。")
    }

    private static func scheduleExpiry(id: String, name: String, expire: Date, at fire: Date) {
        let c = UNMutableNotificationContent()
        c.title = String(localized: "「\(name)」即将到期")
        c.body = expiryBody(expire, now: fire)
        c.threadIdentifier = threadID
        c.sound = .default
        let comps = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: fire)
        let req = UNNotificationRequest(identifier: "usage.expiry.\(id)", content: c,
                                        trigger: UNCalendarNotificationTrigger(dateMatching: comps, repeats: false))
        UNUserNotificationCenter.current().add(req) // same identifier replaces the pending one
    }

    private static func cancelExpiry(_ id: String) {
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: ["usage.expiry.\(id)"])
    }

    static func post(id: String, title: String, body: String, thread: String = threadID) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.threadIdentifier = thread
        c.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id + "." + UUID().uuidString, content: c, trigger: nil))
    }

    private static func allRules() -> [String: UsageAlertRule] { load(rulesKey) ?? [:] }
    private static func allStates() -> [String: UsageAlertState] { load(stateKey) ?? [:] }
    private static func load<T: Decodable>(_ key: String) -> T? {
        UserDefaults.standard.data(forKey: key).flatMap { try? JSONDecoder().decode(T.self, from: $0) }
    }
    private static func save<T: Encodable>(_ v: T, _ key: String) {
        if let d = try? JSONEncoder().encode(v) { UserDefaults.standard.set(d, forKey: key) }
    }
}

enum NotificationAuth {
    static func request() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    /// nil = not determined yet.
    static func allowed() async -> Bool? {
        let s = await UNUserNotificationCenter.current().notificationSettings()
        switch s.authorizationStatus {
        case .notDetermined: return nil
        case .denied: return false
        default: return true
        }
    }
}

/// Shows our banners while the app is open too (iOS hides them by default for the foreground app).
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationPresenter()
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
}

/// Result of one subscription download during a scheduled run.
struct SubUpdateResult {
    var name: String
    var error: String?
    var oldCount: Int?
    var newCount: Int?

    /// Node count dropped by 30 % or more (or to zero).
    var bigDrop: Bool {
        guard let o = oldCount, let n = newCount, o >= 5 else { return false }
        return n == 0 || Double(n) <= Double(o) * 0.7
    }
}

enum UpdateNotifyMode: String, CaseIterable, Identifiable {
    case problems, always
    var id: String { rawValue }
    var title: String { self == .problems ? "仅失败或节点大幅减少时" : "每次自动更新后" }
}

/// Scheduled (automatic) subscription updates + the opt-in summary notification.
@MainActor
enum ScheduledUpdates {
    static let enabledKey = "notify.scheduledUpdates"
    static let modeKey = "notify.scheduledUpdatesMode"
    static let taskID = "tern.subscriptions.refresh"

    static var notifyEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: enabledKey) }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey); if newValue { NotificationAuth.request() } }
    }
    static var mode: UpdateNotifyMode {
        get { UpdateNotifyMode(rawValue: UserDefaults.standard.string(forKey: modeKey) ?? "") ?? .problems }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: modeKey) }
    }

    private static var running = false

    /// Updates every due subscription (config + node subscriptions), resources, then notifies.
    static func run() async {
        guard !running else { return }
        running = true
        defer { running = false }
        var results = await ProfileStore.shared.autoUpdateIfNeeded()
        results += await NodeSubStore.shared.autoUpdateIfNeeded()
        await OverrideScriptStore.shared.autoUpdateIfNeeded() // v0.19 remote 覆写脚本
        await ProviderUpdater.shared.autoUpdateIfNeeded() // the profile's rule sets / node sets (disconnected only)
        await GeoAutoUpdate.runIfDue() // 地理数据库 自动更新 (off by default)
        UsageAlerts.evaluateAll()
        notify(results)
        scheduleBackground()
    }

    static func notify(_ results: [SubUpdateResult]) {
        guard notifyEnabled, !results.isEmpty else { return }
        let failed = results.filter { $0.error != nil }
        let drops = results.filter { $0.error == nil && $0.bigDrop }
        if mode == .problems && failed.isEmpty && drops.isEmpty { return }
        let ok = results.count - failed.count
        let title: String = failed.isEmpty
            ? String(localized: "已自动更新 \(ok) 个订阅")
            : String(localized: "自动更新：\(ok) 个成功，\(failed.count) 个失败")
        var lines: [String] = failed.map { "\($0.name)：\($0.error ?? "")" }
        lines += drops.map { String(localized: "\($0.name)：节点 \($0.oldCount ?? 0) → \($0.newCount ?? 0)") }
        if lines.isEmpty { lines = results.map(\.name) }
        UsageAlerts.post(id: "updates.summary", title: title, body: lines.prefix(4).joined(separator: "\n"), thread: "tern.updates")
    }

    // MARK: Background refresh

    static func registerBackgroundWork() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: taskID, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            let once = BGTaskOnce(task)
            let work = Task { @MainActor in
                await ScheduledUpdates.run()
                once.complete(success: true)
            }
            // Review 5 P2-5: complete on expiry ourselves; the cancelled work may not return in time.
            task.expirationHandler = { work.cancel(); once.complete(success: false) }
        }
    }

    /// Asks iOS to wake the app when the next subscription is due (never sooner than one hour).
    static func scheduleBackground() {
        var next: Date?
        // r7 R7A-6: a disabled profile is never updated, so it stayed "due" and re-armed the task every hour.
        for p in ProfileStore.shared.profiles where p.kind == .remote && p.enabled && p.updateIntervalHours > 0 {
            let d = (p.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(p.updateIntervalHours) * 3600)
            next = min(next ?? d, d)
        }
        for s in NodeSubStore.shared.subs where s.enabled && s.updateIntervalHours > 0 {
            let d = (s.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(s.updateIntervalHours) * 3600)
            next = min(next ?? d, d)
        }
        if let g = GeoAutoUpdate.nextDue() { next = min(next ?? g, g) }
        guard let next else { BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: taskID); return }
        let req = BGAppRefreshTaskRequest(identifier: taskID)
        req.earliestBeginDate = max(next, Date().addingTimeInterval(3600))
        try? BGTaskScheduler.shared.submit(req)
    }
}

/// Review 5 P2-5: completes a BGTask exactly once, from whichever comes first — the work finishing or the
/// expiration handler (iOS kills the app when an expired task is left uncompleted).
final class BGTaskOnce: @unchecked Sendable {
    private let task: BGTask
    private let lock = NSLock()
    private var done = false

    init(_ task: BGTask) { self.task = task }

    func complete(success: Bool) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { task.setTaskCompleted(success: success) }
    }
}
