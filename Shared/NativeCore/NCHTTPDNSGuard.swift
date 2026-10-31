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
/// - Persisted (fix/httpdns-guard-persist): every completed refresh
///   mirrors the table to a small JSON file in the tunnel home, and
///   start() restores it BEFORE the first refresh runs. An extension
///   relaunched under memory pressure (the device report behind this:
///   ads back exactly when Tern had been evicted from the background)
///   is therefore armed from its first flow, not from the first landed
///   answer — the watched services' addresses rotate slowly, so last
///   run's set is nearly as good as a fresh one.
/// - Cold-start fill (fix/httpdns-guard-persist): watch domains still
///   address-less after the first pass — their lookups raced the data
///   plane / DNS path still warming up — are retried at 20 s / 60 s /
///   180 s, ONLY the missing ones, before the 30 min cadence takes
///   over. An SDK that wins the unguarded window once caches its
///   answers and is done, so the window is worth closing.
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

    /// Backoff marks for the cold-start fill: a retry fires this many
    /// seconds after start() and resolves only the watch domains that
    /// still have no addresses at that moment.
    static let initialRetryDelays: [TimeInterval] = [20, 60, 180]

    /// On-disk snapshot version (the fake-IP pool's convention: a
    /// versioned JSON document, written atomically, restored silently).
    static let snapshotVersion = 1

    private struct Snapshot: Codable {
        var version: Int
        var ips: [String: String] // NCIP.string -> watched domain
    }

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
    /// Where the persisted table lives (engine-assigned per load();
    /// nil = in-memory only, the unit-test default). Under `lock`.
    private var storeFile: URL?
    /// Pending cold-start fill retries (serviceQueue only).
    private var retryItems: [DispatchWorkItem] = []

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
        let file = on ? nil : storeFile
        lock.unlock()
        // fix/httpdns-guard-persist: the disk copy goes with the memory
        // one — a stale file must not resurrect a table the user (or a
        // config reload) turned off.
        if let file { try? FileManager.default.removeItem(at: file) }
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

    // MARK: persistence (fix/httpdns-guard-persist)

    /// Assign the on-disk home of the table (the engine points this at
    /// `<home>/nativecore-httpdns-guard.json`, next to the fake-IP
    /// snapshot, on every load — before it arms or disarms the guard).
    func setStoreFile(_ url: URL?) {
        lock.lock(); storeFile = url; lock.unlock()
    }

    private func storeURL() -> URL? {
        lock.lock(); defer { lock.unlock() }
        return storeFile
    }

    /// Restore the persisted table (start() runs this before the first
    /// refresh; internal so tests can drive it directly). Only fills an
    /// EMPTY table: on a warm reload the in-memory set is fresher than
    /// disk. Anything wrong — no file, corrupt JSON, a foreign version,
    /// an unwatched domain, an unparseable IP — is silently dropped:
    /// the restore can narrow the guard, never break the tunnel.
    func loadPersisted() {
        guard let file = storeURL(),
              let data = try? Data(contentsOf: file),
              let snap = try? JSONDecoder().decode(Snapshot.self, from: data),
              snap.version == Self.snapshotVersion else { return }
        var map: [NCIP: String] = [:]
        for (text, domain) in snap.ips where Self.watchDomains.contains(domain) {
            if let ip = NCIP(text) { map[ip] = domain }
        }
        lock.lock()
        if ipToDomain.isEmpty { ipToDomain = map }
        lock.unlock()
    }

    /// Mirror the current table to disk (no-op without a store file).
    /// Runs after every completed refresh application: the document is
    /// a few hundred bytes and the write is atomic, so a kill at any
    /// moment leaves either the previous or the new table, never half.
    private func persist() {
        guard let file = storeURL() else { return }
        lock.lock(); let map = ipToDomain; lock.unlock()
        let snap = Snapshot(version: Self.snapshotVersion,
                            ips: Dictionary(map.map { ($0.key.string, $0.value) },
                                            uniquingKeysWith: { first, _ in first }))
        guard let data = try? JSONEncoder().encode(snap) else { return }
        try? data.write(to: file, options: .atomic)
    }

    // MARK: service (resolution + refresh timer)

    /// Arm (or re-arm, on reload) the resolution service. The first
    /// refresh runs immediately; the timer repeats it every
    /// `refreshInterval`. No-op while disabled.
    func start(resolver: @escaping Resolver) {
        // fix/httpdns-guard-persist: restore last run's table FIRST,
        // synchronously — an extension relaunched under memory pressure
        // must be armed from its first flow, not from the first answer
        // a still-warming DNS path hands back. The refresh below then
        // replaces each domain's subset as fresh answers land.
        loadPersisted()
        serviceQueue.async { [weak self] in
            guard let self else { return }
            self.resolver = resolver
            self.lock.lock(); self.generation &+= 1; self.lock.unlock()
            self.refreshLocked()
            self.scheduleInitialRetries()
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
            self.cancelInitialRetries()
            self.timer?.cancel()
            self.timer = nil
            self.resolver = nil
        }
        setEnabled(false)
    }

    // MARK: cold-start fill (fix/httpdns-guard-persist)

    /// Arm the fill retries (serviceQueue). Each fires once, at its
    /// backoff mark, and resolves ONLY the domains still missing at
    /// that moment. stop() cancels the pending items; the generation
    /// check inside each item is the second line of defence.
    private func scheduleInitialRetries() {
        cancelInitialRetries()
        lock.lock(); let gen = generation; lock.unlock()
        for delay in Self.initialRetryDelays {
            let item = DispatchWorkItem { [weak self] in
                guard let self else { return }
                self.lock.lock(); let current = self.generation; self.lock.unlock()
                guard current == gen, self.isEnabled, let resolver = self.resolver else { return }
                self.fillMissing(resolver: resolver)
            }
            retryItems.append(item)
            serviceQueue.asyncAfter(deadline: .now() + delay, execute: item)
        }
    }

    private func cancelInitialRetries() {
        for item in retryItems { item.cancel() }
        retryItems = []
    }

    /// Watch domains with no address in the current table — a domain
    /// whose lookups keep failing, or whose completed answers are
    /// empty, counts as missing until a non-empty answer lands.
    func missingDomains() -> [String] {
        lock.lock(); defer { lock.unlock() }
        let covered = Set(ipToDomain.values)
        return Self.watchDomains.filter { !covered.contains($0) }
    }

    /// Test / wiring seam: one fill pass over the still-missing domains
    /// only (the scheduled retries run this against the live resolver).
    func fillMissing(resolver: Resolver) {
        resolve(domains: missingDomains(), resolver: resolver)
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
        resolve(domains: Self.watchDomains, resolver: resolver)
    }

    /// One resolution pass over `domains`. Every completed answer is
    /// applied and then mirrored to disk (persist), so the persisted
    /// table tracks the freshest known set even if only some of the
    /// pass's lookups landed before a kill.
    private func resolve(domains: [String], resolver: Resolver) {
        lock.lock(); let gen = generation; lock.unlock()
        for domain in domains {
            resolver(domain) { [weak self] ips in
                guard let self, let ips else { return } // failed lookup: keep the previous subset
                self.lock.lock()
                let current = self.generation
                self.lock.unlock()
                guard current == gen else { return }
                self.applyAnswer(domain: domain, ips: ips)
                self.persist()
            }
        }
    }
}
