import Foundation

/// Daily traffic totals (about 120 days) in the App Group container. The PacketTunnel extension adds
/// deltas of the core's counters (TrafficRecorder); the app reads them for 统计.
struct TrafficDay: Codable, Hashable, Identifiable {
    var day: String   // yyyy-MM-dd in the device's time zone
    var up: Int64
    var down: Int64

    var id: String { day }
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

    /// All stored days, oldest first.
    static func load() -> [TrafficDay] {
        guard let data = try? Data(contentsOf: url),
              let days = try? JSONDecoder().decode([TrafficDay].self, from: data) else { return [] }
        return days.sorted { $0.day < $1.day }
    }

    /// Adds bytes to today's bucket and drops days older than keepDays.
    static func add(up: Int64, down: Int64, at date: Date = Date()) {
        guard up > 0 || down > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        var days = load()
        let key = dayFormatter.string(from: date)
        if let i = days.firstIndex(where: { $0.day == key }) {
            days[i].up += max(up, 0)
            days[i].down += max(down, 0)
        } else {
            days.append(TrafficDay(day: key, up: max(up, 0), down: max(down, 0)))
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
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(at: url)
    }

    /// Last `count` days ending today, with empty days filled in (for charts).
    static func recent(_ count: Int, from days: [TrafficDay]) -> [TrafficDay] {
        let byDay = Dictionary(days.map { ($0.day, $0) }, uniquingKeysWith: { a, b in
            TrafficDay(day: a.day, up: a.up + b.up, down: a.down + b.down)
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
