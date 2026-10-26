import Foundation

/// fix/nc-e2e-gaps: the native core's session statistics behind `GET /app/stats`, `DELETE /app/stats` and
/// `GET /app/stats/speed` (统计 page, 首页速度历史, 网络 page). Same JSON as the Go-era recorder
/// (bridge/statsrecorder.go) that the App decodes as `TunnelStats` / `TunnelSpeedHistory`, so the App needs no change.
///
/// Lean and bounded (memory first): policies ≤ 256, hosts ≤ 600, rules ≤ 300 (the limits the App asks for), closed
/// connections ≤ 300 in a ring of compact structs (JSON built only when asked), speed 600 × 1 s / 180 × 1 min /
/// 48 × 1 h. Strings are clipped to 256 bytes. Worst case well under 0.5 MB. Not persisted across a tunnel restart
/// (the Go recorder resumed from a file; here a fresh process starts a new session, which the App handles as `full`).
///
/// Thread-safe (one NSLock); the data plane writes once per stats tick and per closed connection, the controller reads.
final class NCStatsRecorder {
    static let shared = NCStatsRecorder()

    static let policyCap = 256
    static let hostCap = 600
    static let ruleCap = 300
    static let closedCap = 300
    static let secCap = 600
    static let minCap = 180
    static let hourCap = 48
    static let strMax = 256
    static let chainMax = 8
    /// The policy name the App leaves out of 策略 / 规则 (RuleDisplay.engineOutbound): the hop into the rewrite engine.
    static let engineOutbound = "__MITM__"

    struct Closed {
        var seq: Int64
        var id: String
        var network: String
        var srcPort: Int
        var dstIP: String
        var dstPort: Int
        var host: String
        var remote: String
        var chains: [String]
        var rule: String
        var up: Int64
        var down: Int64
        var start: Int64   // unix ms
        var closedAt: Int64 // unix ms
    }

    fileprivate struct UpDown: Touched {
        var up: Int64 = 0, down: Int64 = 0, touched: UInt64 = 0
        var touchedAt: UInt64 { touched }
    }
    fileprivate struct Hit: Touched {
        var rule: String, policy: String, hits: Int = 0, touched: UInt64 = 0
        var touchedAt: UInt64 { touched }
    }

    private let lock = NSLock()
    private var session: Int64 = 0
    private var since: Int64 = 0
    private var total = 0
    private var version: UInt64 = 0
    private var clock: UInt64 = 0
    private var policies: [String: UpDown] = [:]
    private var hosts: [String: UpDown] = [:]
    private var rules: [String: Hit] = [:]
    private var ring: [Closed] = []
    private var closedPos = 0
    private var seq: Int64 = 0
    // speed: [t, up, down, pUp, pDown] / [start, up, down, pUp, pDown, n] in rings (flat Int64 arrays)
    private var secs = Ring(width: 5, cap: NCStatsRecorder.secCap)
    private var mins = Ring(width: 6, cap: NCStatsRecorder.minCap)
    private var hours = Ring(width: 6, cap: NCStatsRecorder.hourCap)
    private var lastTotals: (at: TimeInterval, up: Int64, down: Int64, pUp: Int64, pDown: Int64)?
    private static var lastSession: Int64 = 0

    init(now: Date = Date()) {
        resetLocked(now)
    }

    // MARK: recording

    /// A connection got its rule / policy: one rule hit, and one connection when `newConnection` (a MitM flow that
    /// falls back to a plain relay is matched again but stays one connection).
    func opened(rule: String, policy: String, newConnection: Bool = true) {
        lock.lock(); defer { lock.unlock() }
        if newConnection { total += 1 }
        let r = rule.isEmpty ? "—" : Self.clip(rule)
        let p = Self.clip(policy)
        let key = r + "\u{1}" + p
        clock &+= 1
        if var h = rules[key] {
            h.hits += 1; h.touched = clock
            rules[key] = h
        } else {
            rules[key] = Hit(rule: r, policy: p, hits: 1, touched: clock)
            Self.evict(&rules, cap: Self.ruleCap)
        }
        version &+= 1
    }

    /// Bytes a connection moved since its last report.
    func bytes(policy: String, host: String, up: Int64, down: Int64) {
        guard up != 0 || down != 0 else { return }
        lock.lock(); defer { lock.unlock() }
        bytesLocked(policy: policy, host: host, up: up, down: down)
        version &+= 1
    }

    /// Several connections' byte growth under one lock (the data plane's stats tick).
    func bytesBatch(_ items: [(policy: String, host: String, up: Int64, down: Int64)]) {
        guard !items.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        for i in items where i.up != 0 || i.down != 0 { bytesLocked(policy: i.policy, host: i.host, up: i.up, down: i.down) }
        version &+= 1
    }

    private func bytesLocked(policy: String, host: String, up: Int64, down: Int64) {
        clock &+= 1
        let p = Self.clip(policy)
        var pv = policies[p] ?? UpDown()
        let newP = policies[p] == nil
        pv.up += up; pv.down += down; pv.touched = clock
        policies[p] = pv
        if newP { Self.evict(&policies, cap: Self.policyCap) }
        let h = Self.clip(host.isEmpty ? "?" : host)
        var hv = hosts[h] ?? UpDown()
        let newH = hosts[h] == nil
        hv.up += up; hv.down += down; hv.touched = clock
        hosts[h] = hv
        if newH { Self.evict(&hosts, cap: Self.hostCap) }
    }

    /// A connection closed: into the ring (seq assigned here).
    func closed(_ c: Closed) {
        lock.lock(); defer { lock.unlock() }
        seq += 1
        var c = c
        c.seq = seq
        c.id = Self.clip(c.id); c.host = Self.clip(c.host); c.remote = Self.clip(c.remote); c.rule = Self.clip(c.rule)
        c.dstIP = Self.clip(c.dstIP)
        c.chains = c.chains.prefix(Self.chainMax).map(Self.clip)
        if ring.count < Self.closedCap {
            ring.append(c)
            closedPos = ring.count % Self.closedCap
        } else {
            ring[closedPos] = c
            closedPos = (closedPos + 1) % Self.closedCap
        }
        version &+= 1
    }

    /// Cumulative totals (all / proxied) at `now`; the recorder turns them into a 1 s rate point and folds it into the
    /// minute / hour buckets. Totals that went down (new data plane after a reload) restart the baseline.
    func sample(now: Date = Date(), up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) {
        lock.lock(); defer { lock.unlock() }
        let at = now.timeIntervalSince1970
        defer { lastTotals = (at, up, down, proxyUp, proxyDown) }
        guard let l = lastTotals, at > l.at else { return }
        guard up >= l.up, down >= l.down, proxyUp >= l.pUp, proxyDown >= l.pDown else { return }
        let dt = max(at - l.at, 1)
        func rate(_ a: Int64, _ b: Int64) -> Int64 { Int64(Double(a - b) / dt) }
        speedLocked(t: Int64(at), up: rate(up, l.up), down: rate(down, l.down),
                    pUp: rate(proxyUp, l.pUp), pDown: rate(proxyDown, l.pDown))
    }

    /// One speed point (B/s), the Go recorder's speedLocked.
    func speed(t: Int64, up: Int64, down: Int64, pUp: Int64, pDown: Int64) {
        lock.lock(); defer { lock.unlock() }
        speedLocked(t: t, up: up, down: down, pUp: pUp, pDown: pDown)
    }

    private func speedLocked(t: Int64, up: Int64, down: Int64, pUp: Int64, pDown: Int64) {
        if let last = secs.lastFirst(), last >= t {
            secs.setLast([last, up, down, pUp, pDown]) // same second: keep the newest
        } else {
            secs.push([t, up, down, pUp, pDown])
        }
        func fold(_ r: inout Ring, _ step: Int64) {
            let start = t - t % step
            if let ls = r.lastFirst() {
                if ls == start { r.addLast([0, up, down, pUp, pDown, 1]); return }
                if ls > start { return } // clock went back
            }
            r.push([start, up, down, pUp, pDown, 1])
        }
        fold(&mins, 60)
        fold(&hours, 3600)
    }

    /// DELETE /app/stats (清零本次连接): counters, hits and closed connections; the speed history stays.
    func reset(now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        resetLocked(now)
    }

    private func resetLocked(_ now: Date) {
        let ms = Int64(now.timeIntervalSince1970 * 1000)
        session = max(ms, Self.lastSession + 1)
        Self.lastSession = session
        since = ms
        total = 0
        policies = [:]; hosts = [:]; rules = [:]
        ring = []; closedPos = 0; seq = 0
        version &+= 1
    }

    // MARK: answers

    /// GET /app/stats?session=&closedAfter=&hosts=&rules= (limits ≤ 0 = all).
    func statsJSON(session asked: Int64, closedAfter: Int64, hostLimit: Int, ruleLimit: Int) -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        func nb(_ d: [String: UpDown], limit: Int) -> [[String: Any]] {
            var l = d.map { (name: $0.key, v: $0.value) }
            l.sort { a, b in
                let ta = a.v.up + a.v.down, tb = b.v.up + b.v.down
                return ta != tb ? ta > tb : a.name < b.name
            }
            if limit > 0, l.count > limit { l.removeLast(l.count - limit) }
            return l.map { ["name": $0.name, "up": $0.v.up, "down": $0.v.down] }
        }
        var rl = Array(rules.values)
        rl.sort { a, b in a.hits != b.hits ? a.hits > b.hits : (a.rule != b.rule ? a.rule < b.rule : a.policy < b.policy) }
        if ruleLimit > 0, rl.count > ruleLimit { rl.removeLast(rl.count - ruleLimit) }
        let oldest = seq - Int64(ring.count)
        let full = asked != session || closedAfter > seq || closedAfter < oldest
        let after = full ? 0 : closedAfter
        var out: [[String: Any]] = []
        for i in 0..<ring.count {
            let idx = (closedPos - 1 - i + 2 * Self.closedCap) % Self.closedCap
            guard idx < ring.count else { continue }
            let c = ring[idx]
            if c.seq <= after { break }
            out.append(Self.closedJSON(c))
        }
        return [
            "session": session, "since": since, "version": version, "totalConnections": total,
            "policies": nb(policies, limit: 0),
            "rules": rl.map { ["rule": $0.rule, "policy": $0.policy, "hits": $0.hits] as [String: Any] },
            "ruleCount": rules.count,
            "hosts": nb(hosts, limit: hostLimit), "hostCount": hosts.count,
            "closedSeq": seq, "closed": out, "full": full,
        ]
    }

    /// GET /app/stats/speed?seconds=N&buckets=0|1
    func speedJSON(lastSeconds: Int, buckets: Bool) -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        var s = secs.rows()
        if lastSeconds > 0, s.count > lastSeconds { s.removeFirst(s.count - lastSeconds) }
        return [
            "at": secs.lastFirst() ?? 0,
            "seconds": s,
            "minutes": buckets ? mins.rows() : [[Int64]](),
            "hours": buckets ? hours.rows() : [[Int64]](),
        ]
    }

    var countsLine: String {
        lock.lock(); defer { lock.unlock() }
        return "stats: conns \(total), policies \(policies.count), hosts \(hosts.count), rules \(rules.count), closed \(ring.count), speed \(secs.count)s"
    }

    // MARK: helpers

    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static func closedJSON(_ c: Closed) -> [String: Any] {
        [
            "seq": c.seq, "id": c.id,
            "metadata": [
                "network": c.network, "type": "Native", "sourceIP": "198.18.0.1", "destinationIP": c.dstIP,
                "sourcePort": c.srcPort <= 0 ? "" : String(c.srcPort),
                "destinationPort": c.dstPort <= 0 ? "" : String(c.dstPort),
                "host": c.host, "sniffHost": "", "process": "", "remoteDestination": c.remote,
            ],
            "upload": c.up, "download": c.down,
            "start": c.start > 0 ? iso.string(from: Date(timeIntervalSince1970: Double(c.start) / 1000)) : "",
            "chains": c.chains, "rule": c.rule, "rulePayload": "", "closedAt": c.closedAt,
        ]
    }

    static func clip(_ s: String) -> String {
        s.utf8.count <= strMax ? s : String(decoding: s.utf8.prefix(strMax), as: UTF8.self)
    }

    /// Over cap: drop the least recently touched eighth (amortised; a sort only every cap/8 inserts).
    fileprivate static func evict<V: Touched>(_ d: inout [String: V], cap: Int) {
        guard d.count > cap else { return }
        let drop = max(1, cap / 8)
        let victims = d.sorted { $0.value.touchedAt < $1.value.touchedAt }.prefix(drop).map(\.key)
        for k in victims { d.removeValue(forKey: k) }
    }

    /// Fixed-capacity ring of fixed-width Int64 rows, stored flat.
    struct Ring {
        let width: Int
        let cap: Int
        private var buf: [Int64] = []
        private var start = 0
        private(set) var count = 0
        init(width: Int, cap: Int) { self.width = width; self.cap = cap }
        private func base(_ i: Int) -> Int { ((start + i) % cap) * width }
        mutating func push(_ row: [Int64]) {
            if buf.isEmpty { buf = [Int64](repeating: 0, count: width * cap) }
            if count < cap {
                count += 1
            } else {
                start = (start + 1) % cap
            }
            let b = base(count - 1)
            for j in 0..<width { buf[b + j] = j < row.count ? row[j] : 0 }
        }
        func lastFirst() -> Int64? { count == 0 ? nil : buf[base(count - 1)] }
        mutating func setLast(_ row: [Int64]) {
            guard count > 0 else { return }
            let b = base(count - 1)
            for j in 0..<width { buf[b + j] = j < row.count ? row[j] : 0 }
        }
        mutating func addLast(_ row: [Int64]) {
            guard count > 0 else { return }
            let b = base(count - 1)
            for j in 1..<width where j < row.count { buf[b + j] += row[j] }
        }
        func rows() -> [[Int64]] {
            (0..<count).map { i in let b = base(i); return Array(buf[b..<(b + width)]) }
        }
    }
}

private protocol Touched { var touchedAt: UInt64 { get } }
