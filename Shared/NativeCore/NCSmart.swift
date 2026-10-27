import Foundation

/// 智能选择 (smart selection) for url-test / fallback groups — a pure Swift
/// port of the retired bridge (the old core's scorer). It is an option on the
/// group, not a new group type: the user enables it per group in the app,
/// stored per profile in <home>/groups.json
/// ({"<profile id>": {"smart": ["GroupName", …]}}, App/Core/SmartGroups.swift).
///
/// Every 30 s (first run 20 s after start) each enabled group scores its
/// members from their recent health-check history — recency-weighted
/// latency of the last successes, multiplied up for recent failures and
/// for a failed last check — and pins the best member. A switch only
/// happens when the new member is clearly better (score < 85 % of the
/// current), so the choice doesn't flap; the resolver drops a pin the
/// moment the pinned member's health check fails, so a dead pin never
/// blackholes traffic.
///
/// Differences from the old core version, both from the native core's shape:
/// history is kept per member name (fed by every recorded delay check of
/// that proxy) instead of per (proxy, test URL) — the old core falls back to the
/// proxy's default history the same way when no per-URL history exists;
/// and the pin is applied by the resolver (NCGroupEngine.smartPins)
/// instead of through Clash.Meta's group Set.
final class NCSmartSelector {
    /// One member's scored state, field-for-field the old core's smartMember.
    struct MemberStatus: Equatable {
        var name: String
        var score: Double // lower is better; -1 = no data
        var avg: Int      // weighted latency of recent successes (ms)
        var fails: Int    // failures in the recent window
        var count: Int    // checks in the recent window
        var alive: Bool
    }

    /// One group's status, field-for-field the old core's smartGroupStatus.
    struct GroupStatus: Equatable {
        var name: String
        var type: String = ""
        var now: String = ""
        var pinned: String? = nil
        var reason: String? = nil
        var switchedAt: Double = 0
        var checkedAt: Double = 0
        var members: [MemberStatus] = []
    }

    static let window = 10 // the old core smartWindow

    private let lock = NSLock()
    private var enabled: [String] = []
    private var history: [String: [Int]] = [:] // member name -> check delays, oldest first; 0 = failure
    private var aliveMap: [String: Bool] = [:]
    private(set) var pins: [String: String] = [:] // group name -> pinned member
    private var statusMap: [String: GroupStatus] = [:]

    init(enabledGroups: [String]) {
        configure(enabledGroups: enabledGroups)
    }

    /// (Re)arm the selector for a profile's smart groups (the old core startSmart):
    /// pins and status reset, history survives (it belongs to the proxies,
    /// not to the arming).
    func configure(enabledGroups: [String]) {
        lock.lock(); defer { lock.unlock() }
        enabled = enabledGroups
        pins = [:]
        statusMap = [:]
        for n in enabledGroups {
            statusMap[n] = GroupStatus(name: n)
        }
    }

    var enabledGroups: [String] {
        lock.lock(); defer { lock.unlock() }
        return enabled
    }

    /// Feed one health-check result for a proxy (0 / negative = failure).
    /// NativeCoreEngine.recordDelay forwards every recorded check here.
    func recordCheck(name: String, ms: Int) {
        lock.lock(); defer { lock.unlock() }
        var h = history[name] ?? []
        h.append(ms > 0 ? ms : 0)
        if h.count > Self.window { h.removeFirst(h.count - Self.window) }
        history[name] = h
        aliveMap[name] = ms > 0
    }

    /// One scoring pass over the enabled groups (the old core smartTick). `groups` is
    /// the effective config's group list; `currentMember` resolves a
    /// group's current member (with pins applied). Returns the pins to
    /// publish to the resolver.
    @discardableResult
    func tick(groups: [NCProxyGroup], currentMember: (NCProxyGroup) -> String?) -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        let now = Date().timeIntervalSince1970
        for name in enabled {
            guard let g = groups.first(where: { $0.name == name }),
                  g.type == "url-test" || g.type == "fallback" else { continue }
            var st = statusMap[name] ?? GroupStatus(name: name)
            st.type = g.type == "url-test" ? "UrlTest" : "Fallback"
            st.checkedAt = now
            st.members = []
            var scores: [Double] = []
            for m in g.proxies {
                let alive = aliveMap[m] ?? true
                let (s, avg, fails, count) = Self.smartScore(history: history[m] ?? [], alive: alive)
                scores.append(s)
                st.members.append(MemberStatus(name: m,
                                               score: s.isInfinite ? -1 : s.rounded(),
                                               avg: avg, fails: fails, count: count, alive: alive))
            }
            var cur = -1
            if let pinned = pins[name] { cur = g.proxies.firstIndex(of: pinned) ?? -1 }
            if cur < 0, let nowName = currentMember(g) { cur = g.proxies.firstIndex(of: nowName) ?? -1 }
            var switchedTo: String? = nil
            if let pick = Self.smartPick(scores: scores, cur: cur) {
                let target = g.proxies[pick]
                pins[name] = target
                st.pinned = target
                st.switchedAt = now
                st.reason = "延迟与失败率综合最优"
                switchedTo = target
            } else if let pinned = pins[name] {
                st.pinned = pinned
            }
            // The resolver's pins update after tick returns, so a fresh
            // switch is reflected here directly (the old core reads g.Now() after Set).
            st.now = switchedTo ?? currentMember(g) ?? pins[name] ?? ""
            statusMap[name] = st
        }
        return pins
    }

    /// Status snapshot sorted by group name (the old core's GET /smart shape).
    func statusList() -> [GroupStatus] {
        lock.lock(); defer { lock.unlock() }
        return statusMap.values.sorted { $0.name < $1.name }
    }

    /// GET /smart response body: {"groups": [ … ]} with the old core's field names
    /// and omissions (pinned / reason / switchedAt / checkedAt only when set).
    func statusJSON() -> [String: Any] {
        let groups: [[String: Any]] = statusList().map { st in
            var g: [String: Any] = [
                "name": st.name,
                "type": st.type,
                "now": st.now,
                "members": st.members.map { m -> [String: Any] in
                    ["name": m.name, "score": m.score, "avg": m.avg,
                     "fails": m.fails, "count": m.count, "alive": m.alive]
                },
            ]
            if let p = st.pinned { g["pinned"] = p }
            if let r = st.reason { g["reason"] = r }
            if st.switchedAt > 0 { g["switchedAt"] = st.switchedAt }
            if st.checkedAt > 0 { g["checkedAt"] = st.checkedAt }
            return g
        }
        return ["groups": groups]
    }

    // MARK: - Scoring (verbatim ports of the old core smartScore / smartPick)

    /// Scores one node from its health-check history (oldest first, delay
    /// 0 = failure). Lower is better; +inf = no usable data.
    static func smartScore(history hist0: [Int], alive: Bool) -> (score: Double, avg: Int, fails: Int, count: Int) {
        var hist = hist0
        if hist.count > window { hist = Array(hist[(hist.count - window)...]) }
        let count = hist.count
        if count == 0 { return (.infinity, 0, 0, 0) }
        var wsum = 0.0, dsum = 0.0
        var succ = 0
        var fails = 0
        for d in hist.reversed() {
            if d == 0 { fails += 1; continue }
            if succ < 5 { // recency-weighted mean of the last 5 successes
                let w = Double(5 - succ)
                dsum += w * Double(d)
                wsum += w
                succ += 1
            }
        }
        if wsum == 0 { return (.infinity, 0, fails, count) }
        let a = dsum / wsum
        var score = a * (1 + 2 * Double(fails) / Double(count))
        if hist[hist.count - 1] == 0 { score *= 2 }
        if !alive { score *= 4 }
        return (score, Int(a + 0.5), fails, count)
    }

    /// Index of the member to pin, or nil to keep the current one
    /// (the old core smartPick's -1). Switches only on a clear win (< 85 %).
    static func smartPick(scores: [Double], cur: Int) -> Int? {
        var best = -1
        for (i, s) in scores.enumerated() {
            if s.isInfinite { continue }
            if best < 0 || s < scores[best] { best = i }
        }
        if best < 0 || best == cur { return nil }
        if cur >= 0, !scores[cur].isInfinite, scores[best] >= 0.85 * scores[cur] { return nil }
        return best
    }
}
