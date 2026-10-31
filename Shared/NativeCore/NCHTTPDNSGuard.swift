import Foundation

/// fix/httpdns-guard: the HTTPDNS guard.
///
/// Why this exists (device evidence, 2026-10-30/31): some apps — Baidu Maps
/// is the proven case — resolve through their OWN HTTPDNS instead of the
/// system resolver, then dial the returned IPs directly with no SNI in the
/// ClientHello. Every domain-layer defence is blind to that traffic: the
/// name never reaches the tunnel's DNS (so #209's DNS-layer REJECT never
/// fires), there is no domain for the rule matcher, and there is no SNI for
/// the sniffer to recover (the device's core log shows the SDK's flows as
/// `180.76.x.x:443 → passthrough(no SNI)`). The one surface left is the
/// HTTPDNS service itself: its endpoint domains are few, public and
/// documented, so the engine resolves THEM through its own upstreams and
/// rejects connections to the resulting IPs at the data plane. Losing its
/// private resolver forces the app back to the system DNS, where the
/// user's rules apply as written — which is exactly what happens under
/// Quantumult X on the same profile. The watched names are pure resolution
/// services (nobody browses them), and the apps' real content servers do
/// not live behind these IPs, so rejecting them costs the app nothing but
/// its policy bypass.
///
/// Behaviour contract:
/// - The table maps resolved IP -> watched domain. A lookup hit is the
///   data plane's REJECT verdict; a miss changes nothing (fail-open).
/// - Resolution is best-effort and never blocks traffic: at start-up the
///   table is empty until the first answers land, a failed lookup keeps
///   the domain's previous addresses, and a completed-but-empty answer
///   replaces them (the service really has no addresses right now).
/// - Refreshed every 30 minutes and on every engine (re)load, which is
///   the config-change hook.
final class NCHTTPDNSGuard {
    /// Public, documented HTTPDNS service domains (Baidu's app-family
    /// service, Baidu Cloud's, Alibaba Cloud's two endpoints).
    static let watchDomains: [String] = [
        "httpdns.baidu.com",
        "httpdns.baidubce.com",
        "httpdns.alicdn.com",
        "httpdns-api.aliyuncs.com",
    ]

    static let refreshInterval: TimeInterval = 30 * 60

    /// Resolver contract, wired to the engine's upstream DNS by the owner:
    /// `nil` = the lookup failed (previous addresses kept); a non-nil
    /// array — possibly empty — is a completed answer and REPLACES the
    /// domain's subset.
    typealias Resolver = (_ domain: String, _ completion: @escaping ([NCIP]?) -> Void) -> Void

    /// The rule text recorded for a guard rejection (Closed record + logs):
    /// names the service so the blocked page reads like a rule hit.
    static func ruleText(for domain: String) -> String { "HTTPDNS-GUARD,\(domain),REJECT" }

    private let lock = NSLock()
    private var ipToDomain: [NCIP: String] = [:]
    private var enabled = false
    /// Bumped on start/stop (under lock): answers still in flight from a
    /// dead run land in the void instead of resurrecting a stopped guard.
    private var generation: UInt64 = 0

    private let serviceQueue = DispatchQueue(label: "nc.httpdns-guard", qos: .utility)
    private var resolver: Resolver?
    private var timer: DispatchSourceTimer?

    // MARK: enablement + hit lookup (data-plane hot path; this lock only)

    var isEnabled: Bool {
        lock.lock(); defer { lock.unlock() }
        return enabled
    }

    /// Disabling also empties the table: a guard the user turned off must
    /// not keep rejecting from a stale snapshot.
    func setEnabled(_ on: Bool) {
        lock.lock()
        enabled = on
        if !on { ipToDomain = [:] }
        lock.unlock()
    }

    /// The watched HTTPDNS domain this destination IP currently belongs
    /// to, or nil. This is the connection layer's hit test — NCDataPlane
    /// calls it for every bare-IP flow (fake-IP destinations are excluded
    /// by the caller: they are the tunnel's own DNS answers, never
    /// HTTPDNS endpoints).
    func domain(for ip: NCIP) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard enabled else { return nil }
        return ipToDomain[ip]
    }

    var ipCount: Int {
        lock.lock(); defer { lock.unlock() }
        return ipToDomain.count
    }

    // MARK: table construction (pure; unit-tested)

    /// Replace one domain's subset with a completed answer. Shared IPs
    /// (two services behind one anycast address) keep whichever domain
    /// was applied last — either name is a truthful record label.
    func applyAnswer(domain: String, ips: [NCIP]) {
        lock.lock()
        ipToDomain = ipToDomain.filter { $0.value != domain }
        for ip in ips { ipToDomain[ip] = domain }
        lock.unlock()
    }

    /// Replace the WHOLE table from a snapshot of completed answers
    /// (test seam / first build). Domains absent from the snapshot
    /// contribute nothing.
    func applySnapshot(_ answers: [String: [NCIP]]) {
        var map: [NCIP: String] = [:]
        for domain in Self.watchDomains {
            for ip in answers[domain] ?? [] { map[ip] = domain }
        }
        lock.lock(); ipToDomain = map; lock.unlock()
    }

    // MARK: service (resolution + refresh timer)

    /// Arm (or re-arm, on reload) the resolution service. The first
    /// refresh runs immediately; the timer repeats it every
    /// `refreshInterval`. No-op while disabled.
    func start(resolver: @escaping Resolver) {
        serviceQueue.async { [weak self] in
            guard let self else { return }
            self.resolver = resolver
            self.lock.lock(); self.generation &+= 1; self.lock.unlock()
            self.refreshLocked()
            self.timer?.cancel()
            let t = DispatchSource.makeTimerSource(queue: self.serviceQueue)
            t.schedule(deadline: .now() + Self.refreshInterval, repeating: Self.refreshInterval)
            t.setEventHandler { [weak self] in self?.refreshLocked() }
            t.resume()
            self.timer = t
        }
    }

    /// One refresh pass NOW (the engine's config-change hook calls start()
    /// again instead; this is for completeness / tests of the wiring).
    func refreshNow() {
        serviceQueue.async { [weak self] in self?.refreshLocked() }
    }

    func stop() {
        serviceQueue.async { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.generation &+= 1; self.lock.unlock()
            self.timer?.cancel()
            self.timer = nil
            self.resolver = nil
        }
        setEnabled(false)
    }

    /// One pass over the watchlist (serviceQueue). Resolver completions
    /// may land on any queue: applyAnswer is lock-protected and the
    /// generation check keeps a stopped run's answers out.
    private func refreshLocked() {
        guard isEnabled, let resolver else { return }
        refreshPass(resolver: resolver)
    }

    /// Test / wiring seam: run one refresh pass against an injected
    /// resolver (a resolver that completes inline applies inline).
    func refresh(resolver: Resolver) {
        refreshPass(resolver: resolver)
    }

    private func refreshPass(resolver: Resolver) {
        lock.lock(); let gen = generation; lock.unlock()
        for domain in Self.watchDomains {
            resolver(domain) { [weak self] ips in
                guard let self, let ips else { return } // failed lookup: keep the previous subset
                self.lock.lock()
                let current = self.generation
                self.lock.unlock()
                guard current == gen else { return }
                self.applyAnswer(domain: domain, ips: ips)
            }
        }
    }
}
