import Foundation
import Darwin

/// Daily traffic totals (about 120 days) in the App Group container. The PacketTunnel extension adds
/// deltas of the core's counters (TrafficRecorder); the app reads them for 统计.
struct TrafficDay: Codable, Hashable, Identifiable {
    var day: String   // yyyy-MM-dd in the device's time zone
    var up: Int64
    var down: Int64
    /// v0.8: bytes (up + down) while the physical network was Wi-Fi / cellular, sampled by the tunnel every
    /// two minutes (each delta goes to the interface in use at the sample). nil in days before v0.8.
    var wifi: Int64? = nil
    var cell: Int64? = nil

    var id: String { day }
    /// Bytes on neither (wired, other, or before v0.8 split tracking).
    var otherNet: Int64 { max(0, total - (wifi ?? 0) - (cell ?? 0)) }
    var total: Int64 { up + down }
    var date: Date { TrafficHistory.dayFormatter.date(from: day) ?? Date.distantPast }
}

enum TrafficHistory {
    static let keepDays = 120

    static var url: URL { AppShared.containerURL.appendingPathComponent("traffic-history.json") }

    static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    private static let lock = NSLock()

    /// Review 5 P2-7: app (clear) and extension (add) are different processes, so the in-process NSLock alone
    /// let a 2-minute sample in flight write the old days back after 清除统计. flock(2) on a side file
    /// serialises the read-modify-write across both.
    @discardableResult
    private static func withFileLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        let path = AppShared.containerURL.appendingPathComponent("traffic-history.lock").path
        let fd = open(path, O_RDWR | O_CREAT, 0o644)
        if fd >= 0 { flock(fd, LOCK_EX) }
        defer { if fd >= 0 { flock(fd, LOCK_UN); close(fd) } }
        return body()
    }

    /// All stored days, oldest first.
    static func load() -> [TrafficDay] {
        guard let data = try? Data(contentsOf: url),
              let days = try? JSONDecoder().decode([TrafficDay].self, from: data) else { return [] }
        return days.sorted { $0.day < $1.day }
    }

    /// Adds bytes to today's bucket and drops days older than keepDays.
    static func add(up: Int64, down: Int64, iface: String? = nil, at date: Date = Date()) {
        guard up > 0 || down > 0 else { return }
        withFileLock { addLocked(up: up, down: down, iface: iface, at: date) }
    }

    private static func addLocked(up: Int64, down: Int64, iface: String?, at date: Date) {
        var days = load()
        let key = dayFormatter.string(from: date)
        let i: Int
        if let found = days.firstIndex(where: { $0.day == key }) {
            i = found
        } else {
            days.append(TrafficDay(day: key, up: 0, down: 0))
            i = days.count - 1
        }
        days[i].up += max(up, 0)
        days[i].down += max(down, 0)
        let both = max(up, 0) + max(down, 0)
        switch iface {
        case "wifi": days[i].wifi = (days[i].wifi ?? 0) + both
        case "cellular": days[i].cell = (days[i].cell ?? 0) + both
        default: break
        }
        if let cutoff = Calendar.current.date(byAdding: .day, value: -keepDays, to: date) {
            let c = dayFormatter.string(from: cutoff)
            days.removeAll { $0.day < c }
        }
        save(days)
    }

    static func save(_ days: [TrafficDay]) {
        if let data = try? JSONEncoder().encode(days.sorted { $0.day < $1.day }) {
            try? data.write(to: url, options: .atomic)
        }
    }

    static func clear() {
        withFileLock { _ = try? FileManager.default.removeItem(at: url) }
    }

    /// Last `count` days ending today, with empty days filled in (for charts).
    static func recent(_ count: Int, from days: [TrafficDay]) -> [TrafficDay] {
        let byDay = Dictionary(days.map { ($0.day, $0) }, uniquingKeysWith: { a, b in
            TrafficDay(day: a.day, up: a.up + b.up, down: a.down + b.down,
                       wifi: (a.wifi ?? 0) + (b.wifi ?? 0), cell: (a.cell ?? 0) + (b.cell ?? 0))
        })
        let cal = Calendar.current
        let today = cal.startOfDay(for: Date())
        return (0..<count).reversed().compactMap { back -> TrafficDay? in
            guard let d = cal.date(byAdding: .day, value: -back, to: today) else { return nil }
            let k = dayFormatter.string(from: d)
            return byDay[k] ?? TrafficDay(day: k, up: 0, down: 0)
        }
    }
}
