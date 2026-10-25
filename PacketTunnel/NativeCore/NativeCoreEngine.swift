import Foundation

/// The native core's control plane inside the tunnel: loads the runtime config
/// (written by the app, bridge/nativeprep.go — the tunnel never runs Go), parses
/// rules once, owns the fake-IP pool and the group engine, and routes targets
/// to outbounds. The data plane (TUN/lwIP) lands in the next batch; until the
/// provider switch is wired, nothing calls this in production paths.
///
/// Threading (gap D3): the data plane (its queue), the controller (its queue + delay-test queues), the MitM
/// upstream (NCUpstreamConnector, per-dial queues), the local mixed proxy and subscription refreshes (URLSession
/// queues) all call into one engine. Every piece of mutable state here — config, rules, the group engine (whose
/// selections / delays / round-robin counters change on every resolve), fake-IP responder, DNS policy — is read and
/// written under `stateLock` (recursive: public entry points call each other). The group engine is never handed out
/// unlocked: callers use `withGroups`.
final class NativeCoreEngine {
    private static let activeLock = NSLock()
    private static var _active: NativeCoreEngine?
    /// The running engine (MitM upstream / script geo lookups read it from their own queues).
    static var active: NativeCoreEngine? {
        get { activeLock.lock(); defer { activeLock.unlock() }; return _active }
        set { activeLock.lock(); _active = newValue; activeLock.unlock() }
    }

    private let stateLock = NSRecursiveLock()
    @inline(__always) private func locked<T>(_ body: () throws -> T) rethrows -> T {
        stateLock.lock(); defer { stateLock.unlock() }
        return try body()
    }

    private var _config: NCConfig?
    var config: NCConfig? { locked { _config } }
    private(set) var isRunning = false
    private var rules: [NCRule] = []
    private var groups: NCGroupEngine?
    private(set) var fakeIP: NCFakeIPPool?
    private var dnsResponder: NCFakeIPResponder?
    private(set) var realIPMap: NCRealIPMap?
    private var redirHostMode = false
    private var geoIPDB: NCMMDB?
    private var asnDB: NCMMDB?
    private var ruleProviders: NCRuleProviderStore?
    private var dnsPolicy: NCDNSPolicy?
    private var nodeSubStore: NCNodeSubscriptionStore?
    private var nodeSubs: [NCNodeSubscription] = []
    private var canonicalGroupMap: [String: NCGroupModel] = [:]
    private var healthCheck: NCHealthCheckScheduler?
    private var home = ""

    private var fakeIPFile: URL {
        URL(fileURLWithPath: home).appendingPathComponent("nativecore-fakeip.json")
    }

    /// Loads (or reloads) the config for `home`. Returns an error message or nil.
    /// Config acquisition, in order: (1) `runtime.yaml` read directly by
    /// the built-in YAML parser — no Go involved; (2) `runtime.conf`
    /// (Surge/Loon/Quantumult X) via the canonical importers; (3) the Go
    /// bridge's JSON export as a transitional fallback for YAML shapes
    /// the subset parser cannot handle (anchors at scale, merge keys in
    /// odd spots, …). Which source won is kept in `configSource`.
    private func loadConfig(home: String) -> (NCConfig?, String?) {
        let homeURL = URL(fileURLWithPath: home)
        // (1) the app's JSON re-encode of runtime.yaml (PrepareNativeRuntime) — Foundation's JSON decoder.
        if let data = try? Data(contentsOf: homeURL.appendingPathComponent("nativecore-runtime.json")),
           let cfg = try? NCConfig.decode(jsonData: data) {
            configSource = "json"
            loadedCanonical = nil
            return (cfg, nil)
        }
        // (2) runtime.yaml through the YAML subset parser.
        if let text = try? String(contentsOf: homeURL.appendingPathComponent("runtime.yaml"), encoding: .utf8),
           let root = NCYAML.parse(text)?.object {
            configSource = "yaml"
            loadedCanonical = nil
            return (NCConfig.decode(root: root), nil)
        }
        // (3) runtime.conf (Surge / Loon / Quantumult X) via the canonical importers.
        if let text = try? String(contentsOf: homeURL.appendingPathComponent("runtime.conf"), encoding: .utf8) {
            let canonical: NCCanonicalConfig
            if text.contains("_local]") || text.contains("[server_") {
                canonical = NCQXImport.quantumultx(text)
            } else if text.contains("[Remote Proxy]") || text.contains("[Remote Rule]") {
                canonical = NCConfImport.loon(text)
            } else {
                canonical = NCConfImport.surge(text)
            }
            configSource = "conf:\(canonical.sourceFormat)"
            loadedCanonical = canonical
            return (canonical.legacyConfig(), nil)
        }
        return (nil, "没有找到运行配置（nativecore-runtime.json / runtime.yaml）：请打开 App 重新连接一次")
    }

    private(set) var configSource = ""
    private var loadedCanonical: NCCanonicalConfig?

    var loadedCanonicalConfig: NCCanonicalConfig? { locked { loadedCanonical } }

    /// MitM decision for a TLS connection: the app's rewrite snapshot (module / 解密 hostnames) or, for .conf
    /// profiles, the canonical [MITM] section.
    func isMitm(host: String, port: Int = 443) -> Bool {
        if NativeRewriteEngine.shared.intercepts(host: host, port: port) { return true }
        return locked { loadedCanonical?.mitm.matches(host: host) ?? false }
    }

    /// Rule lines the parser did not understand (ignored, listed in the startup log / 诊断).
    private(set) var unparsedRules: [String] = []
    /// NCSupport.report for the loaded config.
    private var _supportReport: [String] = []
    var supportReport: [String] { locked { _supportReport } }
    /// The app's per-profile selections (`<profile>.selected.json`, bridge/inspect.go SaveSelection) — the same file
    /// the app writes when a node is picked while the VPN is off, so both sides agree.
    private var selectionsFile: URL {
        if let profile = AppShared.activeProfileURL {
            return profile.deletingPathExtension().appendingPathExtension("selected.json")
        }
        return URL(fileURLWithPath: home).appendingPathComponent("nativecore-selections.json")
    }

    func lookupCountry(_ ipStr: String) -> String? {
        guard let ip = NCIP(ipStr), let db = locked({ geoIPDB }) else { return nil }
        return db.countryCode(for: ip)
    }

    @discardableResult
    func load(home: String) -> String? {
        stateLock.lock(); defer { stateLock.unlock() }
        self.home = home
        let (loadedCfg, loadError) = loadConfig(home: home)
        if let loadError { return loadError }
        guard let cfg = loadedCfg else { return "native core: config decode failed" }
        _config = cfg
        var parsed: [NCRule] = []
        var unparsed: [String] = []
        for line in cfg.rules {
            if let rule = NCRule.parse(line) { parsed.append(rule) } else { unparsed.append(line) }
        }
        rules = parsed
        unparsedRules = unparsed
        let canonical = loadedCanonical ?? NCCanonicalConfig.from(mihomo: cfg)
        canonicalGroupMap = canonical.groupMap
        let pool = NCFakeIPPool(range: cfg.dns.fakeIPRange, range6: cfg.dns.fakeIPRange6,
                                filter: cfg.dns.fakeIPFilter)
        redirHostMode = cfg.dns.enhancedMode.lowercased() == "redir-host"
        if redirHostMode { realIPMap = NCRealIPMap() }
        if let data = try? Data(contentsOf: fakeIPFile) {
            pool.restore(data: data)
        }
        fakeIP = pool
        dnsResponder = nil
        // Rule providers: cache-first load, then refresh whatever is stale.
        let store = NCRuleProviderStore(dir: URL(fileURLWithPath: home)
            .appendingPathComponent("nativecore-rulesets"))
        let providers = NCRuleProviderStore.providers(from: cfg)
        let stale = store.loadCached(providers: providers, home: home)
        ruleProviders = store
        if !stale.isEmpty { store.refreshAll(stale) }
        // DNS policy (hosts answers + per-domain upstreams) from the
        // canonical view of the same config.
        dnsPolicy = NCDNSPolicy(model: canonical.dns, hosts: canonical.hosts)
        // Node subscriptions: cached nodes merge into the effective config;
        // stale ones refresh in the background and rebuild the group engine.
        nodeSubs = canonical.subscriptions
        let subStore = NCNodeSubscriptionStore(dir: URL(fileURLWithPath: home)
            .appendingPathComponent("nativecore-nodesubs"))
        nodeSubStore = subStore
        let staleSubs = subStore.loadCached(canonical.subscriptions)
        rebuildGroupEngine()
        for sub in staleSubs {
            subStore.refresh(sub) { [weak self] in self?.rebuildGroupEngine() }
        }
        let homeURL = URL(fileURLWithPath: home)
        if let data = try? Data(contentsOf: homeURL.appendingPathComponent("geoip.metadb")) {
            geoIPDB = NCMMDB(data: data)
            NativeScriptHost.geoLookup = { [weak self] ip in self?.lookupCountry(ip) }
        }
        if let data = try? Data(contentsOf: homeURL.appendingPathComponent("ASN.mmdb")), data.count > 1024 {
            asnDB = NCMMDB(data: data)
        }
        isRunning = true
        healthCheck?.stop()
        let hc = NCHealthCheckScheduler(engine: self)
        hc.start()
        healthCheck = hc
        Self.active = self
        return nil
    }

    /// (Re)build the group engine over the merged effective config:
    /// config nodes/groups plus subscription nodes, with group membership
    /// expanded through each group's `use` subscriptions and regex filters.
    /// Selections/delays survive rebuilds (subscription refresh lands async).
    private func rebuildGroupEngine() {
        stateLock.lock(); defer { stateLock.unlock() } // also runs from subscription refresh completions
        guard let cfg = _config else { return }
        let merged = mergedConfig(base: cfg)
        let engine = NCGroupEngine(config: merged)
        if let old = groups {
            // Snapshot under the old engine's lock: the health-check scheduler
            // may be writing delays/alive from its own queue right now.
            let snap = old.statusSnapshot()
            engine.selections = snap.selections
            engine.delays = snap.delays
            engine.alive = snap.alive
        } else if let data = try? Data(contentsOf: selectionsFile),
                  let saved = try? JSONDecoder().decode([String: String].self, from: data) {
            // Selections survive a reconnect (mihomo keeps them in cache.db, store-selected).
            engine.selections = saved
        }
        var unsupported = Set<String>()
        for p in merged.proxies where NCSupport.unsupportedReason(p) != nil {
            unsupported.insert(p.name)
            engine.alive[p.name] = false
        }
        engine.unsupported = unsupported
        _supportReport = NCSupport.report(config: merged, unparsedRules: unparsedRules)
        engine.ssidProvider = {
            UserDefaults(suiteName: AppShared.appGroup)?.string(forKey: "nativeCoreSSID")
        }
        engine.onGroupTouched = { [weak self] groupName in
            self?.healthCheck?.notifyTouch(group: groupName)
        }
        groups = engine
        healthCheck?.updateConfig()
    }

    private func mergedConfig(base cfg: NCConfig) -> NCConfig {
        guard let store = nodeSubStore, !nodeSubs.isEmpty else { return cfg }
        var names = Set(cfg.proxies.map { $0.name })
        let groupNames = Set(cfg.groups.map { $0.name })
        var subNodesBySub: [String: [NCProxy]] = [:]
        var proxies = cfg.proxies
        for sub in nodeSubs {
            let nodes = store.nodes(for: sub).filter {
                !names.contains($0.name) && !groupNames.contains($0.name)
            }
            for n in nodes { names.insert(n.name) }
            subNodesBySub[sub.name] = nodes
            proxies.append(contentsOf: nodes)
        }
        let groups = cfg.groups.map { g -> NCProxyGroup in
            let cg = canonicalGroupMap[g.name]
            let use = cg?.use ?? g.use
            guard !use.isEmpty else { return g }
            let include = cg?.includeRegex ?? g.fields["filter"]?.string
            let exclude = cg?.excludeRegex ?? g.fields["exclude-filter"]?.string
            var members = g.proxies
            for subName in use {
                for node in subNodesBySub[subName] ?? [] where
                    NCNodeFilter.matches(node.name, include: include, exclude: exclude)
                    && !members.contains(node.name) {
                    members.append(node.name)
                }
            }
            return NCProxyGroup(name: g.name, type: g.type, proxies: members, fields: g.fields)
        }
        return NCConfig(mode: cfg.mode, logLevel: cfg.logLevel, ipv6: cfg.ipv6,
                        proxies: proxies, groups: groups, rules: cfg.rules,
                        dns: cfg.dns, raw: cfg.raw)
    }

    /// Build a match context with this engine's GeoIP/ASN lookups injected.
    func matchContext(domain: String?, ip: NCIP?, srcIP: NCIP? = nil, dstPort: Int?, network: String) -> NCMatchContext {
        stateLock.lock(); defer { stateLock.unlock() }
        var ctx = NCMatchContext(domain: domain, ip: ip, srcIP: srcIP, dstPort: dstPort, network: network)
        if let geoIPDB {
            ctx.countryOf = { geoIPDB.countryCode(for: $0) }
        }
        if let asnDB {
            ctx.asnOf = { asnDB.asn(for: $0) }
        }
        if let ruleProviders {
            ctx.ruleSetContains = { name, c in ruleProviders.contains(name: name, ctx: c) }
        }
        return ctx
    }

    func stop() {
        stateLock.lock(); defer { stateLock.unlock() }
        healthCheck?.stop()
        healthCheck = nil
        persistFakeIP()
        isRunning = false
        _config = nil
        rules = []
        groups = nil
        fakeIP = nil
        dnsResponder = nil
        ruleProviders = nil
        dnsPolicy = nil
        nodeSubStore = nil
        nodeSubs = []
        canonicalGroupMap = [:]
    }

    func persistFakeIP() {
        guard let pool = locked({ fakeIP }), let data = pool.snapshotData() else { return }
        try? data.write(to: fakeIPFile, options: .atomic)
    }

    // MARK: Routing

    /// Runs `body` with the effective config and the group engine under the engine lock (gap D3: the controller
    /// and the Live Activity's main-node lookup used to read the group engine's dictionaries while the data plane
    /// mutated them). Keep `body` short: it blocks routing.
    func withGroups<T>(_ body: (NCConfig, NCGroupEngine) -> T) -> T? {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let cfg = effectiveConfig, let g = groups else { return nil }
        return body(cfg, g)
    }

    /// The live group engine for the health-check scheduler / delay tester (nc-healthcheck, astemo6). Since that
    /// change NCGroupEngine guards its own delays / alive / selections with its own lock (snapshot reads), so handing
    /// the reference out is safe; lock order is always engine → group engine.
    var groupEngine: NCGroupEngine? { locked { groups } }

    /// Resolves a policy / proxy / group name (controller delay tests) under the lock.
    func resolve(policyName: String) -> NCGroupEngine.Resolution? {
        locked { groups?.resolve(policyName) }
    }

    /// The config the controller should present: base config merged with
    /// subscription nodes (routing already runs on this view).
    var effectiveConfig: NCConfig? {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let cfg = _config else { return nil }
        return groups != nil ? mergedConfig(base: cfg) : cfg
    }

    /// Controller-driven mode override (PATCH /configs); nil = config's mode.
    private var _modeOverride: String?
    var modeOverride: String? {
        get { locked { _modeOverride } }
        set { locked { _modeOverride = newValue } }
    }

    var effectiveMode: String { locked { _modeOverride ?? _config?.mode ?? "rule" } }

    func setSelection(group: String, member: String?) {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let sel = groups?.setSelection(group: group, member: member) else { return }
        if let data = try? JSONEncoder().encode(sel) {
            try? data.write(to: selectionsFile, options: .atomic)
        }
    }

    func recordDelay(name: String, ms: Int) {
        stateLock.lock(); defer { stateLock.unlock() }
        groups?.recordDelay(name: name, ms: ms)
    }

    func recordFailure(name: String) {
        stateLock.lock(); defer { stateLock.unlock() }
        groups?.recordFailure(name: name)
    }

    /// Policy name for a connection, following the config mode:
    /// direct -> DIRECT; global -> the GLOBAL group; rule -> first rule hit.
    func policy(for ctx: NCMatchContext) -> String {
        policyWithRule(for: ctx).policy
    }

    func policyWithRule(for ctx: NCMatchContext) -> (policy: String, rule: String?) {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let cfg = _config else { return ("DIRECT", nil) }
        switch effectiveMode {
        case "direct":
            return ("DIRECT", nil)
        case "global":
            return (cfg.groupMap["GLOBAL"] != nil ? "GLOBAL" : (cfg.groups.first?.name ?? "DIRECT"), nil)
        default:
            if let hit = NCRuleMatcher.firstMatch(rules, ctx) {
                return (hit.policy, hit.raw)
            }
            return ("DIRECT", nil)
        }
    }

    /// Policy, matching rule and outbound for one connection in a single locked step (the rule is matched once and a
    /// load-balance group advances once). Used by the local mixed proxy (gap D1).
    func route(_ ctx: NCMatchContext) -> (policy: String, rule: String?, resolution: NCGroupEngine.Resolution) {
        stateLock.lock(); defer { stateLock.unlock() }
        let (policy, rule) = policyWithRule(for: ctx)
        guard let groups else { return (policy, rule, .direct) }
        return (policy, rule, groups.resolve(policy))
    }

    func resolve(_ ctx: NCMatchContext) -> NCGroupEngine.Resolution {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let groups else { return .direct }
        return groups.resolve(policy(for: ctx))
    }

    /// First configured nameserver, of any supported kind (plain UDP,
    /// tls:// DoT, https:// DoH).
    var firstDNSUpstream: NCDNSUpstream? {
        for raw in config?.dns.nameservers ?? [] {
            if let up = NCDNSUpstream.parse(raw) { return up }
        }
        return nil
    }

    /// Hosts-table answer for a query, if any (checked before fake-IP:
    /// a [Host] entry wins over the fake pool in all three reference apps).
    func dnsHostsReply(_ query: Data) -> Data? {
        locked { dnsPolicy }?.hostsReply(queryData: query)
    }

    /// Upstream for a query that neither hosts nor fake-IP answered: the
    /// per-domain assignment (nameserver-policy / [Host] server: / QX
    /// server=/) when one exists, else the first configured default.
    func dnsUpstream(for query: Data) -> NCDNSUpstream? {
        if let policy = locked({ dnsPolicy }), let msg = NCDNSMessage.parse(query),
           let name = msg.questions.first?.name {
            for ref in policy.servers(for: name) {
                if let up = NCDNSUpstream(ref) { return up }
            }
        }
        return firstDNSUpstream
    }

    /// Answers a raw DNS query in fake-IP mode (A -> fake IP, AAAA -> fake
    /// v6 when a range6 is configured, else empty NOERROR). nil means the
    /// query is not fake-IP business and must be forwarded upstream by the
    /// caller. In redir-host mode nothing is answered locally.
    func handleDNSQuery(_ query: Data) -> Data? {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !redirHostMode, let pool = fakeIP else { return nil }
        if dnsResponder == nil { dnsResponder = NCFakeIPResponder(pool: pool) }
        return dnsResponder?.respond(to: query)
    }

    /// redir-host: remember a forwarded response's A/AAAA answers so later
    /// connections to those real IPs match rules by the queried host.
    func recordDNSResponse(query: Data, response: Data) {
        guard let map = locked({ redirHostMode ? realIPMap : nil }),
              let q = NCDNSMessage.parse(query), let name = q.questions.first?.name,
              let resp = NCDNSMessage.parse(response) else { return }
        map.record(host: name, answers: resp.addressAnswers)
    }

    /// If the destination is a fake-IP address, swap in the original host (the
    /// DNS side filled the pool when the query came in). In redir-host mode,
    /// fall back to the recorded real-IP -> host mapping.
    func derefFakeIP(_ target: NCTarget) -> NCTarget {
        guard let ip = target.ip else { return target }
        let (fakeIP, realIPMap) = locked { (self.fakeIP, self.realIPMap) }
        if let pool = fakeIP, let host = pool.host(for: ip) {
            return NCTarget(host: host, port: target.port)
        }
        if let host = realIPMap?.host(for: ip) {
            return NCTarget(host: host, port: target.port)
        }
        return target
    }

    var statsLine: String {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let cfg = _config else { return "native core: not loaded" }
        return "native core (\(configSource)): \(cfg.proxies.count) proxies, \(cfg.groups.count) groups, \(rules.count) rules (\(unparsedRules.count) ignored), unsupported \(groups?.unsupported.count ?? 0), fake-ip \(fakeIP?.size ?? 0) entries"
    }

    /// Whether ICMP echo requests to this address should be answered
    /// locally: fake-IP destinations and the tunnel's own addresses
    /// (anything else goes to the stack, which answers its locals and
    /// drops the rest).
    func shouldAnswerEcho(to ip: NCIP) -> Bool {
        switch ip {
        case .v4(let v):
            if v == 0xc612_0001 || v == 0xc612_0002 { return true } // 198.18.0.1 / .2
        case .v6(let bytes):
            if let tunnel6 = NCIP("fdfe:dcba:9876::1"), case .v6(let tb) = tunnel6, bytes == tb { return true }
        }
        return locked { fakeIP }?.isFakeAddress(ip) ?? false
    }
}
