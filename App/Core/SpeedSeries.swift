import Foundation

/// The last minute of speed samples behind Home's chart and the 网速 tile (fix/bg-chart, user 2026-10-21
/// 「切回mihomo时首页的网速图猛得往前串着更新」).
///
/// Rules, so the chart never "fast-forwards" after the app was in the background:
/// - a sample whose request took longer than `staleAfter` (it sat in a queue while the app was suspended)
///   is dropped, not appended;
/// - a sample older than the newest one already in the series is dropped (out of order);
/// - when more than `maxGap` passed since the last sample (app suspended, polling paused), the series
///   starts over from the empty baseline the chart shows on a fresh connect, and only the current sample
///   is added. Seconds we did not measure are never drawn and never replayed.
struct SpeedSeries: Equatable {
    static let capacity = 60
    static let maxGap: TimeInterval = 3
    static let staleAfter: TimeInterval = 1.5

    private(set) var up: [Int64] = Array(repeating: 0, count: SpeedSeries.capacity)
    private(set) var down: [Int64] = Array(repeating: 0, count: SpeedSeries.capacity)
    private(set) var lastAt: Date?

    enum Result: Equatable { case appended, restarted, dropped }

    /// requestedAt: when the sample was asked for; receivedAt: when it arrived (its time).
    @discardableResult
    mutating func append(up u: Int64, down d: Int64, requestedAt: Date, receivedAt: Date) -> Result {
        if receivedAt.timeIntervalSince(requestedAt) > Self.staleAfter { return .dropped }
        var result = Result.appended
        if let last = lastAt {
            if receivedAt < last { return .dropped }
            if receivedAt.timeIntervalSince(last) > Self.maxGap {
                reset()
                result = .restarted
            }
        }
        up.append(max(u, 0)); down.append(max(d, 0))
        if up.count > Self.capacity { up.removeFirst(up.count - Self.capacity) }
        if down.count > Self.capacity { down.removeFirst(down.count - Self.capacity) }
        lastAt = receivedAt
        return result
    }

    mutating func reset() {
        up = Array(repeating: 0, count: Self.capacity)
        down = Array(repeating: 0, count: Self.capacity)
        lastAt = nil
    }
}

/// GET /app/traffic (feat/traffic-scope): the core's counters in both scopes. Proxy-only numbers are
/// accumulated inside the tunnel from each connection's own byte counters (closed connections included).
struct AppTraffic: Decodable, Equatable {
    var up: Int64
    var down: Int64
    var upTotal: Int64
    var downTotal: Int64
    var proxyUp: Int64
    var proxyDown: Int64
    var proxyUpTotal: Int64
    var proxyDownTotal: Int64

    func speed(_ scope: TrafficScope) -> (up: Int64, down: Int64) {
        scope == .proxy ? (proxyUp, proxyDown) : (up, down)
    }

    func totals(_ scope: TrafficScope) -> (up: Int64, down: Int64) {
        scope == .proxy ? (proxyUpTotal, proxyDownTotal) : (upTotal, downTotal)
    }
}
