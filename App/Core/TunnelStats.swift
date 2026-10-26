import Foundation

// P0-2 (「App 进入后台或被杀后，流量和规则不再被记录」): the session statistics Home shows are recorded inside the
// tunnel, every second, also while the app is in the background or killed. The app reads
// them from the core's REST API:
//   GET /app/stats?session=&closedAfter=&hosts=&rules=  → TunnelStats (ConnectionAnalytics.refreshFromTunnel)
//   GET /app/stats/speed?seconds=&buckets=              → TunnelSpeedHistory (NetworkHistory / SpeedSeries)
//   DELETE /app/stats                                   → 清零本次连接
// An extension still running an older build answers 404; the app then keeps its own in-app sampling.

/// GET /app/stats: session counters recorded in the tunnel.
struct TunnelStats: Decodable {
    struct NameBytes: Decodable {
        let name: String
        let up: Int64
        let down: Int64
    }

    struct Rule: Decodable {
        let rule: String
        let policy: String
        let hits: Int
    }

    /// Changes on every fresh connect and on 清零 (unix ms).
    let session: Int64
    /// Unix ms the counters start from.
    let since: Int64
    let totalConnections: Int
    /// Every policy, busiest first.
    let policies: [NameBytes]
    /// The busiest rules (the `rules` limit asked for); ruleCount counts all of them.
    let rules: [Rule]
    let ruleCount: Int
    /// The busiest hosts (the `hosts` limit asked for); hostCount counts all of them.
    let hosts: [NameBytes]
    let hostCount: Int
    /// Newest closed-connection sequence number.
    let closedSeq: Int64
    /// Closed connections newer than `closedAfter`, newest first.
    let closed: [TunnelClosedConnection]
    /// `closed` is the whole ring (other session, or the asked seq fell out of it): replace, do not prepend.
    let full: Bool
}

/// One closed connection: the fields of Clash.Meta's /connections item (decoded as ConnectionItem) plus its sequence
/// number and close time (unix ms).
struct TunnelClosedConnection: Decodable {
    let seq: Int64
    let item: ConnectionItem

    private enum Keys: String, CodingKey { case seq, closedAt }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        seq = try c.decode(Int64.self, forKey: .seq)
        let ms = try c.decode(Double.self, forKey: .closedAt)
        var it = try ConnectionItem(from: decoder)
        it.closedAt = Date(timeIntervalSince1970: ms / 1000)
        item = it
    }
}

/// GET /app/stats/speed: [t, up, down, proxyUp, proxyDown] per second (B/s), and [start, upSum, downSum,
/// proxyUpSum, proxyDownSum, n] per minute / hour (sums of the per-second speeds over n recorded seconds).
struct TunnelSpeedHistory: Decodable {
    /// Unix seconds of the newest point (0 = nothing recorded).
    let at: Int64
    let seconds: [[Int64]]
    let minutes: [[Int64]]
    let hours: [[Int64]]
}
