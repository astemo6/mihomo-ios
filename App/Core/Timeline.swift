import Foundation

// v0.17 请求时间线 (parity #8). The core records what it can measure:
//  • passive, per real connection while 请求 is open: the DNS answer the core received for the host
//    shortly before the connection (upstream exchange time from the core's own events, or a cache hit),
//    and the first upload / download byte after the core established the outbound connection, as a
//    [lo, hi] range because the counters are sampled every 20 ms;
//  • active, on demand: one fresh connection through the same outbound with DNS / 连接 / TLS / 首字节.
// Nothing here estimates a phase the core did not measure.

struct TimelineBound: Decodable, Hashable {
    var lo: Double
    var hi: Double
    /// "200–220 ms", or one value when the range is narrower than 2 ms.
    var text: String {
        if hi - lo < 2 { return "\(Int(hi.rounded())) ms" }
        return "\(Int(lo.rounded()))–\(Int(hi.rounded())) ms"
    }
}

struct TimelineDNS: Decodable, Hashable {
    var ms: Double
    var cached: Bool?
    var upstream: String?
    var beforeMs: Double
}

struct TimelineRecord: Decodable, Hashable, Identifiable {
    var id: String
    var host: String
    var network: String?
    var preexisting: Bool?
    var firstUp: TimelineBound?
    var firstDown: TimelineBound?
    var dns: TimelineDNS?
    var closed: Bool?
}

struct TimelineConns: Decodable {
    var resolutionMs: Int?
    var records: [TimelineRecord]?
}

struct TimelinePhase: Decodable, Hashable {
    var ms: Double?
    var note: String?
    var error: String?
}

struct TimelineProbe: Decodable, Hashable {
    var host: String
    var port: String
    var policy: String?
    var chain: String?
    var remote: String?
    var dns: TimelinePhase
    var connect: TimelinePhase
    var tls: TimelinePhase
    var firstByte: TimelinePhase
    var totalMs: Double
    var tlsInfo: String?
    var status: String?
    var ok: Bool
    var error: String?

    /// Measured phases in order, for the bar (a failed phase still shows the time it took).
    var phases: [(TimelineStage, Double)] {
        let all: [(TimelineStage, TimelinePhase)] = [(.dns, dns), (.connect, connect), (.tls, tls), (.firstByte, firstByte)]
        return all.compactMap { s, p in p.ms.map { (s, $0) } }
    }

    func phase(_ s: TimelineStage) -> TimelinePhase {
        switch s {
        case .dns: return dns
        case .connect: return connect
        case .tls: return tls
        case .firstByte: return firstByte
        }
    }
}

enum TimelineStage: String, CaseIterable, Hashable {
    case dns, connect, tls, firstByte
    var title: String {
        switch self {
        case .dns: return "DNS"
        case .connect: return "连接"
        case .tls: return "TLS 握手"
        case .firstByte: return "首字节"
        }
    }
}

enum TimelineAPI {
    static func conns() async throws -> TimelineConns {
        try await ControllerClient.shared.get(TimelineConns.self, "/timeline/conns", timeout: 4)
    }

    /// One measurement through the connection's outbound (chain as Clash.Meta lists it, outbound first).
    static func probe(_ c: ConnectionItem) async throws -> TimelineProbe {
        if UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoConnections") {
            try? await Task.sleep(nanoseconds: 300_000_000)
            return UITestSeed.demoProbe(for: c)
        }
        let host = c.metadata.host?.isEmpty == false ? c.metadata.host! : (c.metadata.sniffHost?.isEmpty == false ? c.metadata.sniffHost! : (c.metadata.destinationIP ?? ""))
        return try await ControllerClient.shared.get(TimelineProbe.self, "/timeline/probe", query: [
            URLQueryItem(name: "host", value: host),
            URLQueryItem(name: "port", value: c.metadata.destinationPort ?? "443"),
            URLQueryItem(name: "chain", value: (c.chains ?? []).joined(separator: ",")),
        ], timeout: 30)
    }
}

/// 按主机 aggregate over the active + recent connections of the 请求 page.
struct HostAggregate: Identifiable, Hashable {
    var id: String { host }
    var host: String
    var connections: [ConnectionItem]
    var upload: Int64
    var download: Int64
    var active: Int
    var policies: [String]
    var lastStart: Date?
    /// Medians over the passive records that have the value (nil = none measured).
    var firstDown: TimelineBound?
    var dnsMs: Double?
    var measured: Int

    static func build(active: [ConnectionItem], recent: [ConnectionItem], timeline: [String: TimelineRecord]) -> [HostAggregate] {
        var by: [String: [ConnectionItem]] = [:]
        var order: [String] = []
        for c in active + recent {
            let h = c.metadata.displayHost
            if by[h] == nil { order.append(h) }
            by[h, default: []].append(c)
        }
        let activeIDs = Set(active.map(\.id))
        return order.map { h -> HostAggregate in
            let cs = by[h] ?? []
            var policies: [String] = []
            for c in cs where !c.chainText.isEmpty && !policies.contains(c.chainText) { policies.append(c.chainText) }
            let recs = cs.compactMap { timeline[$0.id] }.filter { $0.preexisting != true }
            let downs = recs.compactMap(\.firstDown)
            let dns = recs.compactMap { $0.dns?.ms }
            return HostAggregate(
                host: h, connections: cs,
                upload: cs.reduce(0) { $0 + $1.upload }, download: cs.reduce(0) { $0 + $1.download },
                active: cs.filter { activeIDs.contains($0.id) }.count, policies: policies,
                lastStart: cs.compactMap(\.startDate).max(),
                firstDown: downs.isEmpty ? nil : TimelineBound(lo: median(downs.map(\.lo)), hi: median(downs.map(\.hi))),
                dnsMs: dns.isEmpty ? nil : median(dns), measured: recs.count)
        }
        .sorted { ($0.upload + $0.download, $0.connections.count) > ($1.upload + $1.download, $1.connections.count) }
    }

    static func median(_ v: [Double]) -> Double {
        let s = v.sorted()
        guard !s.isEmpty else { return 0 }
        return s.count % 2 == 1 ? s[s.count / 2] : (s[s.count / 2 - 1] + s[s.count / 2]) / 2
    }
}
