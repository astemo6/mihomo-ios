import Foundation
import UIKit

/// v0.8 连接分析 history: direct vs proxy bytes, traffic per policy and top hosts per day, kept across
/// sessions in the app's own store (App Group `analytics-history.json`, written only by the app).
///
/// Fed by ConnectionAnalytics from the /connections snapshots the app polls while it is open, so it counts
/// traffic seen while the app runs (foreground). The tunnel's own daily totals (TrafficHistory, incl. the
/// Wi-Fi / cellular split) cover everything; the UI says which number comes from where.
@MainActor
final class AnalyticsHistory: ObservableObject {
    static let shared = AnalyticsHistory()

    struct Bytes: Codable, Equatable {
        var up: Int64 = 0
        var down: Int64 = 0
        var total: Int64 { up + down }
        static func + (a: Bytes, b: Bytes) -> Bytes { Bytes(up: a.up + b.up, down: a.down + b.down) }
    }

    struct Day: Codable, Identifiable, Equatable {
        var day: String
        var direct = Bytes()
        var proxy = Bytes()
        var policies: [String: Bytes] = [:]
        var hosts: [String: Bytes] = [:]
        var id: String { day }
        var total: Int64 { direct.total + proxy.total }
    }

    @Published private(set) var days: [Day] = []

    static let keepDays = 90
    static let policyCap = 60
    static let hostCap = 120
    private var dirty = false
    private var lastSave = Date.distantPast
    private let url: URL
    /// E 线 #3: the stored history is read and decoded off the main thread (up to 90 days × 120 hosts of
    /// JSON). Until it is in, deltas collect in `days` and saving waits, so nothing on disk is lost or
    /// overwritten; `finishLoad` merges the two.
    private(set) var isLoaded = false

    init(fileURL: URL? = nil) {
        let url = fileURL ?? AppShared.containerURL.appendingPathComponent("analytics-history.json")
        self.url = url
        Task.detached(priority: .utility) { [weak self] in
            let stored = AnalyticsHistory.read(url)
            await self?.finishLoad(stored)
        }
        NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.save(force: true) }
        }
    }

    nonisolated static func read(_ url: URL) -> [Day]? {
        guard let d = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode([Day].self, from: d)
    }

    private func finishLoad(_ stored: [Day]?) {
        guard !isLoaded else { return } // clear() came first: the stored history is gone
        isLoaded = true
        if let stored, !stored.isEmpty {
            days = Self.merge(stored: stored, live: days, keep: Self.keepDays)
        }
        if dirty { save(force: false) }
    }

    /// The stored days with the deltas counted before they were loaded added in (same day: summed),
    /// oldest first (day keys are yyyy-MM-dd), at most `keep`.
    nonisolated static func merge(stored: [Day], live: [Day], keep: Int) -> [Day] {
        guard !live.isEmpty else { return stored }
        var byDay = Dictionary(stored.map { ($0.day, $0) }, uniquingKeysWith: { a, _ in a })
        for d in live {
            guard var s = byDay[d.day] else { byDay[d.day] = d; continue }
            s.direct = s.direct + d.direct
            s.proxy = s.proxy + d.proxy
            for (k, v) in d.policies { s.policies[k] = (s.policies[k] ?? Bytes()) + v }
            for (k, v) in d.hosts { s.hosts[k] = (s.hosts[k] ?? Bytes()) + v }
            byDay[d.day] = s
        }
        let out = byDay.values.sorted { $0.day < $1.day }
        return out.count > keep ? Array(out.suffix(keep)) : out
    }

    /// Policies that count as direct (everything else with bytes is proxy). REJECT has no bytes.
    static let directNames: Set<String> = ["DIRECT"]
    /// The MitM engine's inner hop: its upstream request is a connection of its own, counted there.
    static let skipNames: Set<String> = ["__MITM__", "REJECT", "REJECT-DROP"]

    /// One ingest step: byte deltas per policy and per host since the previous snapshot.
    func add(policies: [String: ConnectionAnalytics.Bytes], hosts: [String: ConnectionAnalytics.Bytes], at date: Date = Date()) {
        guard !policies.isEmpty else { return }
        let key = TrafficHistory.dayFormatter.string(from: date)
        var d: Day
        if let last = days.last, last.day == key { d = last } else { d = Day(day: key) }
        for (name, b) in policies where !Self.skipNames.contains(name) {
            let v = Bytes(up: b.up, down: b.down)
            if Self.directNames.contains(name) { d.direct = d.direct + v } else { d.proxy = d.proxy + v }
            d.policies[name] = (d.policies[name] ?? Bytes()) + v
        }
        for (h, b) in hosts { d.hosts[h] = (d.hosts[h] ?? Bytes()) + Bytes(up: b.up, down: b.down) }
        if d.hosts.count > Self.hostCap * 2 {
            d.hosts = Dictionary(uniqueKeysWithValues: d.hosts.sorted { $0.value.total > $1.value.total }.prefix(Self.hostCap).map { ($0.key, $0.value) })
        }
        if d.policies.count > Self.policyCap * 2 {
            d.policies = Dictionary(uniqueKeysWithValues: d.policies.sorted { $0.value.total > $1.value.total }.prefix(Self.policyCap).map { ($0.key, $0.value) })
        }
        if let last = days.last, last.day == key { days[days.count - 1] = d } else {
            days.append(d)
            if days.count > Self.keepDays { days.removeFirst(days.count - Self.keepDays) }
        }
        dirty = true
        save(force: false)
    }

    func save(force: Bool) {
        // Before the stored history is loaded a write would replace it with only the new deltas.
        guard isLoaded, dirty, force || Date().timeIntervalSince(lastSave) > 60 else { return }
        dirty = false
        lastSave = Date()
        // Trim each stored day to the caps so the file stays small.
        let trimmed = days.map { d -> Day in
            var t = d
            if t.hosts.count > Self.hostCap {
                t.hosts = Dictionary(uniqueKeysWithValues: t.hosts.sorted { $0.value.total > $1.value.total }.prefix(Self.hostCap).map { ($0.key, $0.value) })
            }
            if t.policies.count > Self.policyCap {
                t.policies = Dictionary(uniqueKeysWithValues: t.policies.sorted { $0.value.total > $1.value.total }.prefix(Self.policyCap).map { ($0.key, $0.value) })
            }
            return t
        }
        if let data = try? JSONEncoder().encode(trimmed) { try? data.write(to: url, options: .atomic) }
    }

    func clear() {
        days = []
        dirty = false
        isLoaded = true // a load still in flight must not bring the cleared history back
        try? FileManager.default.removeItem(at: url)
    }

    /// Merged view over the last `count` days (1 = today).
    func summary(lastDays count: Int) -> Day {
        let keys = Set(TrafficHistory.recent(count, from: []).map(\.day))
        var out = Day(day: "")
        for d in days where keys.contains(d.day) {
            out.direct = out.direct + d.direct
            out.proxy = out.proxy + d.proxy
            for (k, v) in d.policies { out.policies[k] = (out.policies[k] ?? Bytes()) + v }
            for (k, v) in d.hosts { out.hosts[k] = (out.hosts[k] ?? Bytes()) + v }
        }
        return out
    }

    /// Direct / proxy per day for charts, oldest first, empty days filled in.
    func recent(_ count: Int) -> [Day] {
        let byDay = Dictionary(days.map { ($0.day, $0) }, uniquingKeysWith: { a, _ in a })
        return TrafficHistory.recent(count, from: []).map { byDay[$0.day] ?? Day(day: $0.day) }
    }
}
