import Foundation

/// fix/nc-tails: /app/stats accounting for connections that enter through a local listener instead of the TUN —
/// the mixed port (NCLocalProxy: HTTP / CONNECT / SOCKS5 on loopback or LAN) and the fixed-policy probe listeners
/// (NCProbeProxy, e.g. MIHOMO-PROBE on 127.0.0.1:7899). Before, they showed in /connections at most, never in
/// 统计's 主机 / 策略 / 规则 lists or the closed-connection list.
///
/// One small value per live connection (kept inside the listener's own Conn object, so nothing outlives the
/// connection): what was routed, how many bytes moved, how many were already reported. The recorder itself keeps its
/// caps (hosts ≤ 600, rules ≤ 300, closed ≤ 300), so memory stays bounded however many connections pass.
///
/// Not thread-safe: the owning listener mutates it on its own serial queue (as NCDataPlane does with TCPSession).
struct NCListenerFlowStats {
    /// mihomo chains.last: the rule's policy (group); the dialed node / chain is `chain`.
    private(set) var policy = ""
    private(set) var chain = ""
    private(set) var rule = ""
    private(set) var host = ""
    private(set) var opened = false
    private(set) var up: Int64 = 0
    private(set) var down: Int64 = 0
    private var reportedUp: Int64 = 0
    private var reportedDown: Int64 = 0

    init() {}

    /// The connection got its route: one connection + one rule hit, the first time only (a MitM front that falls
    /// back to a plain relay is routed again but stays one connection).
    mutating func open(rule: String, policy: String, chain: String, host: String,
                       recorder: NCStatsRecorder = .shared) {
        self.rule = rule
        self.chain = chain.isEmpty ? "DIRECT" : chain
        self.policy = policy.isEmpty ? self.chain : policy
        self.host = host
        recorder.opened(rule: rule, policy: self.policy, newConnection: !opened)
        opened = true
    }

    mutating func count(up: Int = 0, down: Int = 0) {
        self.up &+= Int64(up)
        self.down &+= Int64(down)
    }

    /// Bytes not yet reported (nil when none / not routed yet); marks them reported. For a stats tick batch.
    mutating func takePending() -> (policy: String, host: String, up: Int64, down: Int64)? {
        guard opened, up != reportedUp || down != reportedDown else { return nil }
        defer { reportedUp = up; reportedDown = down }
        return (policy, host, up - reportedUp, down - reportedDown)
    }

    /// The connection ended: its last bytes and one closed record. No-op when it was never routed. Idempotent.
    mutating func close(id: String, type: String, srcIP: String, srcPort: Int, dstIP: String, dstPort: Int,
                        remote: String, start: Date, end: Date = Date(), recorder: NCStatsRecorder = .shared) {
        guard opened else { return }
        if let p = takePending() { recorder.bytes(policy: p.policy, host: p.host, up: p.up, down: p.down) }
        var chains = [chain]
        if policy != chain { chains.append(policy) }
        recorder.closed(NCStatsRecorder.Closed(
            seq: 0, id: id, network: "tcp", srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, host: host,
            remote: remote, chains: chains, rule: rule, up: up, down: down,
            start: Int64(start.timeIntervalSince1970 * 1000), closedAt: Int64(end.timeIntervalSince1970 * 1000),
            type: type, srcIP: srcIP))
        opened = false
    }

    /// The chain string the App shows for a resolution (same spelling as /connections).
    static func chainName(_ r: NCGroupEngine.Resolution) -> String {
        switch r {
        case .direct: "DIRECT"
        case .reject: "REJECT"
        case .proxy(let p): p.name
        case .chain(let ps): ps.map { $0.name }.joined(separator: " -> ")
        case .unknown(let n): n
        }
    }

    /// Whether bytes of this chain count as proxied traffic (speed series' proxied split).
    static func isProxied(_ chain: String) -> Bool {
        chain != "DIRECT" && chain != "REJECT" && !chain.isEmpty
    }
}
