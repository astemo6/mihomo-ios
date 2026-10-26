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
    private var geoSiteDB: NCGeoSiteDB?
    private var ruleProviders: NCRuleProviderStore?
    /// Whether the live rule-provider store has an index for `name` (provider name or URL alias) — cache or fetch.
    /// fix/nc-mem-providers: the E2E replay checks the core's own store instead of loading every list a second time.
    func ruleProviderIsLoaded(_ name: String) -> Bool {
        locked { ruleProviders }?.isLoaded(name: name) ?? false
    }
    private var dnsPolicy: NCDNSPolicy?
    private var nodeSubStore: NCNodeSubscriptionStore?
    private var nodeSubs: [NCNodeSubscription] = []
    /// Base config merged with provider nodes, rebuilt with the group engine (was recomputed — every provider
    /// node through every group's regex — on each effectiveConfig read: /proxies, health checks, delay tests).
    private var _merged: NCConfig?
    /// 智能选择 scorer (bridge/smart.go port); armed from groups.json on load.
    private var smart: NCSmartSelector?
    private var smartTimer: DispatchSourceTimer?
    private let smartQueue = DispatchQueue(label: "nc.smart")
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
    /// rv2-life: pure (no engine state touched) so load() can run it before taking the engine lock.
    private static func loadConfig(home: String) -> (cfg: NCConfig?, error: String?, source: String, canonical: NCCanonicalConfig?) {
        let homeURL = URL(fileURLWithPath: home)
        // (1) the app's JSON re-encode of runtime.yaml (PrepareNativeRuntime) — Foundation's JSON decoder.
        if let data = try? Data(contentsOf: homeURL.appendingPathComponent("nativecore-runtime.json")),
           let cfg = try? NCConfig.decode(jsonData: data) {
            return (cfg, nil, "json", nil)
        }
        // (2) runtime.yaml through the YAML subset parser.
        if let text = try? String(contentsOf: homeURL.appendingPathComponent("runtime.yaml"), encoding: .utf8),
           let root = NCYAML.parse(text)?.object {
            return (NCConfig.decode(root: root), nil, "yaml", nil)
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
            return (canonical.legacyConfig(), nil, "conf:\(canonical.sourceFormat)", canonical)
        }
        return (nil, "没有找到运行配置（nativecore-runtime.json / runtime.yaml）：请打开 App 重新连接一次", "", nil)
    }

    /// rv2-life: size + mtime of each geo database last loaded; an unchanged file is not read again on reload
    /// (GeoSite.dat / geoip.metadb are several MB each — re-reading them held two copies at the reload peak).
    private var geoFileSigs: [String: String] = [:]

    private static func fileSig(_ url: URL) -> String? {
        guard let a = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = a[.size] as? NSNumber else { return nil }
        let mtime = (a[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        return "\(size.int64Value)@\(mtime)"
    }

    /// Returned by load(home:isCurrent:) when the caller's generation went stale (stop / newer start) before commit.
    static let supersededMessage = "内核已停止或已重启，本次重载已取消"

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
    func load(home: String, isCurrent: () -> Bool = { true }) -> String? {
        // rv2-life (#8 / M reload): everything slow and state-free runs BEFORE the engine lock — config parse, rule
        // parse, canonical view, rule-set cache, node-subscription cache, geo databases — so routing (which takes the
        // lock) and the lwIP queue are only blocked for the short swap below. A stale caller (stop / newer start
        // meanwhile) is refused inside the lock, before any state changes.
        let loaded = Self.loadConfig(home: home)
        if let loadError = loaded.error { return loadError }
        guard let cfg = loaded.cfg else { return "native core: config decode failed" }
        var parsed: [NCRule] = []
        var unparsed: [String] = []
        for line in cfg.rules {
            if let rule = NCRule.parse(line) { parsed.append(rule) } else { unparsed.append(line) }
        }
        let canonical = loaded.canonical ?? NCCanonicalConfig.from(mihomo: cfg)
        let preStore = NCRuleProviderStore(dir: URL(fileURLWithPath: home)
            .appendingPathComponent("nativecore-rulesets"))
        let preProviders = NCRuleProviderStore.providers(from: cfg)
        let preStale = preStore.loadCached(providers: preProviders, home: home)
        let preSubStore = NCNodeSubscriptionStore(dir: URL(fileURLWithPath: home)
            .appendingPathComponent("nativecore-nodesubs"), home: URL(fileURLWithPath: home))
        let preStaleSubs = preSubStore.loadCached(canonical.subscriptions)
        let homeURL = URL(fileURLWithPath: home)
        let oldSigs = locked { geoFileSigs }
        var newSigs: [String: String] = [:]
        var geoIP: NCMMDB??, asn: NCMMDB??, geoSite: NCGeoSiteDB?? // nil = unchanged, keep the loaded one
        let geoIPURL = homeURL.appendingPathComponent("geoip.metadb")
        newSigs["geoip"] = Self.fileSig(geoIPURL)
        if newSigs["geoip"] == nil || newSigs["geoip"] != oldSigs["geoip"] {
            geoIP = .some((try? Data(contentsOf: geoIPURL, options: .mappedIfSafe)).flatMap { NCMMDB(data: $0) })
        }
        let asnURL = homeURL.appendingPathComponent("ASN.mmdb")
        newSigs["asn"] = Self.fileSig(asnURL)
        if newSigs["asn"] == nil || newSigs["asn"] != oldSigs["asn"] {
            asn = .some((try? Data(contentsOf: asnURL, options: .mappedIfSafe)).flatMap { $0.count > 1024 ? NCMMDB(data: $0) : nil })
        }
        var siteURL = homeURL.appendingPathComponent("GeoSite.dat")
        if !FileManager.default.fileExists(atPath: siteURL.path) { siteURL = homeURL.appendingPathComponent("geosite.dat") }
        newSigs["geosite"] = Self.fileSig(siteURL).map { siteURL.lastPathComponent + ":" + $0 }
        if newSigs["geosite"] == nil || newSigs["geosite"] != oldSigs["geosite"] {
            // mapped (clean file-backed pages stay out of the footprint); the app installs these files by rename, so
            // a mapping never sees them truncated in place
            geoSite = .some((try? Data(contentsOf: siteURL, options: .mappedIfSafe)).flatMap { NCGeoSiteDB(data: $0) })
        }

        stateLock.lock(); defer { stateLock.unlock() }
        guard isCurrent() else { return Self.supersededMessage }
        fakeIP?.persist(to: fakeIPFile) // nc-dns: flush the live pool before it is replaced below, so a reload keeps every mapping (fakeIPFile still points at the outgoing home here)
        self.home = home
        configSource = loaded.source
        loadedCanonical = loaded.canonical
        _config = cfg
        rules = parsed
        unparsedRules = unparsed
        // Geo databases first (prepared off the lock above): the fake-IP filter, DNS policy and rule diagnostics
        // below consult them.
        if let geoIP { geoIPDB = geoIP }
        if geoIPDB != nil { NativeScriptHost.geoLookup = { [weak self] ip in self?.lookupCountry(ip) } }
        if let asn { asnDB = asn }
        if let geoSite { geoSiteDB = geoSite }
        geoFileSigs = newSigs
        canonicalGroupMap = canonical.groupMap
        let pool = NCFakeIPPool(range: cfg.dns.fakeIPRange, range6: cfg.dns.fakeIPRange6,
                                filter: cfg.dns.fakeIPFilter,
                                whitelist: cfg.dns.fakeIPFilterMode == "whitelist")
        redirHostMode = cfg.dns.enhancedMode.lowercased() == "redir-host"
        // nc-lifecycle: a reload that leaves redir-host mode must drop the old
        // mode's map with it — derefFakeIP consults realIPMap in every mode,
        // so a stale map would keep rewriting this config's targets to hosts
        // learned under the previous one.
        if redirHostMode { realIPMap = NCRealIPMap() } else { realIPMap = nil }
        if let data = try? Data(contentsOf: fakeIPFile) {
            pool.restore(data: data)
        }
        if redirHostMode, pool.size > 0 {
            // fix/nc-mitm-live: redir-host answers real IPs, but apps may still hold fake IPs handed out by an earlier
            // fake-ip session; the restored table keeps those reachable (derefFakeIP consults it in every mode).
            StartupLog.write("redir-host: kept \(pool.size) fake-ip mapping(s) from earlier sessions for apps still holding 198.18.x.x answers")
        }
        fakeIP = pool
        dnsResponder = nil
        // Rule providers: cache-first load (done above, off the lock), then refresh whatever is stale.
        let store = preStore
        let stale = preStale
        ruleProviders = store
        if !stale.isEmpty { store.refreshAll(stale) }
        // fake-ip-filter geosite: / rule-set: entries (mihomo parseDomain).
        let geo = geoSiteDB
        if !pool.externalEntries.isEmpty {
            let entries = pool.externalEntries
            pool.externalMatcher = { host in
                entries.contains { e in
                    e.hasPrefix("geosite:")
                        ? (geo?.matches(payload: String(e.dropFirst(8)), domain: host) ?? false)
                        : store.containsDomain(name: String(e.dropFirst(9)), domain: host)
                }
            }
        }
        // DNS policy (hosts answers + per-domain upstreams) from the
        // canonical view of the same config; geosite: / rule-set: keys and
        // fallback-filter geosite read the kernel's stores.
        var policy = NCDNSPolicy(model: canonical.dns, hosts: canonical.hosts)
        if let geo { policy.geositeContains = { cat, name in geo.matches(payload: cat, domain: name) } }
        policy.ruleSetContainsDomain = { name, domain in store.containsDomain(name: name, domain: domain) }
        dnsPolicy = policy
        // nc-lifecycle: a new resolve generation — lookups still in flight
        // from the previous config complete their waiters, but their answers
        // may no longer enter the cache (fetched under the old DNS policy).
        resolveLock.lock(); resolveCache = [:]; resolveGeneration += 1; resolveLock.unlock()
        ruleDiagnostics = Self.diagnose(cfg: cfg, rules: parsed, providers: preProviders, policy: policy,
                                        pool: pool, geoSite: geo, geoIP: geoIPDB != nil, asn: asnDB != nil)
        // Node subscriptions: cached nodes merge into the effective config;
        // stale ones refresh in the background and rebuild the group engine.
        nodeSubs = canonical.subscriptions
        let subStore = preSubStore
        nodeSubStore = subStore
        let staleSubs = preStaleSubs
        rebuildGroupEngine()
        for sub in staleSubs {
            subStore.refresh(sub) { [weak self] in self?.rebuildGroupEngine() }
        }
        configureSmart()
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
        _merged = merged
        let engine = NCGroupEngine(config: merged)
        if let old = groups {
            // Snapshot under the old engine's lock: the health-check scheduler
            // may be writing delays/alive from its own queue right now.
            let snap = old.statusSnapshot()
            engine.selections = snap.selections
            engine.delays = snap.delays
            engine.alive = snap.alive
            engine.smartPins = old.smartPins
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
        _supportReport = NCSupport.report(config: merged, unparsedRules: unparsedRules) + ruleDiagnostics
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
        return Self.merge(base: cfg, subs: nodeSubs, canonicalGroups: canonicalGroupMap) { store.nodes(for: $0) }
    }

    /// Provider nodes join the config's proxies (a name already taken by a proxy or group is skipped), and each
    /// group gains the nodes of the providers it `use`s — or of every provider with include-all /
    /// include-all-providers (include-all / include-all-proxies also add the config's own proxies) — through its
    /// filter / exclude-filter (several patterns may be joined with "`", as in mihomo). Static so unit tests
    /// can drive it.
    static func merge(base cfg: NCConfig, subs: [NCNodeSubscription], canonicalGroups: [String: NCGroupModel],
                      nodes: (NCNodeSubscription) -> [NCProxy]) -> NCConfig {
        var names = Set(cfg.proxies.map { $0.name })
        let groupNames = Set(cfg.groups.map { $0.name })
        var subNodesBySub: [String: [NCProxy]] = [:]
        var proxies = cfg.proxies
        for sub in subs {
            let ns = nodes(sub).filter {
                !names.contains($0.name) && !groupNames.contains($0.name)
            }
            for n in ns { names.insert(n.name) }
            subNodesBySub[sub.name] = ns
            proxies.append(contentsOf: ns)
        }
        func regexes(_ s: String?) -> [NSRegularExpression] {
            guard let s, !s.isEmpty else { return [] }
            return s.split(separator: "`").compactMap { try? NSRegularExpression(pattern: String($0)) }
        }
        func hit(_ res: [NSRegularExpression], _ name: String) -> Bool {
            let r = NSRange(name.startIndex..., in: name)
            return res.contains { $0.firstMatch(in: name, range: r) != nil }
        }
        func truthy(_ v: NCJSONValue?) -> Bool { v?.bool ?? (v?.string?.lowercased() == "true") }
        let groups = cfg.groups.map { g -> NCProxyGroup in
            let cg = canonicalGroups[g.name]
            var use = cg?.use ?? g.use
            let includeAll = truthy(g.fields["include-all"])
            if includeAll || truthy(g.fields["include-all-providers"]) {
                for sub in subs where !use.contains(sub.name) { use.append(sub.name) }
            }
            let withProxies = includeAll || truthy(g.fields["include-all-proxies"])
            guard !use.isEmpty || withProxies else { return g }
            let inc = regexes(cg?.includeRegex ?? g.fields["filter"]?.string)
            let exc = regexes(cg?.excludeRegex ?? g.fields["exclude-filter"]?.string)
            func keep(_ n: String) -> Bool { (inc.isEmpty || hit(inc, n)) && (exc.isEmpty || !hit(exc, n)) }
            var members = g.proxies
            var seen = Set(members)
            if withProxies {
                for p in cfg.proxies where keep(p.name) && seen.insert(p.name).inserted { members.append(p.name) }
            }
            for subName in use {
                for node in subNodesBySub[subName] ?? [] where keep(node.name) && seen.insert(node.name).inserted {
                    members.append(node.name)
                }
            }
            return NCProxyGroup(name: g.name, type: g.type, proxies: members, fields: g.fields)
        }
        return NCConfig(mode: cfg.mode, logLevel: cfg.logLevel, ipv6: cfg.ipv6,
                        proxies: proxies, groups: groups, rules: cfg.rules,
                        dns: cfg.dns, sniffer: cfg.sniffer, raw: cfg.raw, subRules: cfg.subRules)
    }

    /// GET /providers/proxies (mihomo shape): one entry per proxy provider with its (filtered / overridden) nodes.
    func proxyProvidersJSON(item: (NCProxy) -> [String: Any]) -> [String: Any] {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let store = nodeSubStore else { return [:] }
        let iso = ISO8601DateFormatter()
        var out: [String: Any] = [:]
        for sub in nodeSubs {
            var p: [String: Any] = [
                "name": sub.name, "type": "Proxy", "vehicleType": store.vehicleType(of: sub.name),
                "proxies": store.nodes(for: sub).map(item),
            ]
            if let at = store.updatedAt(of: sub.name) { p["updatedAt"] = iso.string(from: Date(timeIntervalSince1970: at)) }
            if let hc = sub.fields["health-check"]?.object, let u = hc["url"]?.string { p["testUrl"] = u }
            out[sub.name] = p
        }
        return out
    }

    /// PUT /providers/proxies/{name}: refetch one http provider now (false = no such provider).
    func refreshProxyProvider(_ name: String, completion: @escaping () -> Void) -> Bool {
        let found: (NCNodeSubscriptionStore, NCNodeSubscription)? = locked {
            guard let store = nodeSubStore, let sub = nodeSubs.first(where: { $0.name == name }) else { return nil }
            return (store, sub)
        }
        guard let found else { return false }
        let store = found.0, sub = found.1
        if sub.url.isEmpty {
            _ = store.loadCached([sub]); rebuildGroupEngine(); completion()
        } else {
            store.refresh(sub) { [weak self] in self?.rebuildGroupEngine(); completion() }
        }
        return true
    }

    /// Build a match context with this engine's GeoIP/ASN lookups injected.
    func matchContext(domain: String?, ip: NCIP?, srcIP: NCIP? = nil, dstPort: Int?, network: String) -> NCMatchContext {
        stateLock.lock(); defer { stateLock.unlock() }
        var ctx = NCMatchContext(domain: domain, ip: ip, srcIP: srcIP, dstPort: dstPort, network: network)
        // Every flow here arrived through the TUN inbound; there is no
        // listener port, so inPort stays nil and IN-PORT cannot match.
        ctx.inType = "TUN"
        ctx.subRules = config?.subRules ?? [:]
        if let geoIPDB {
            ctx.countryOf = { geoIPDB.countryCode(for: $0) }
        }
        if let asnDB {
            ctx.asnOf = { asnDB.asn(for: $0) }
        }
        if let geoSiteDB {
            ctx.geositeMatches = { payload, domain in geoSiteDB.matches(payload: payload, domain: domain) }
        }
        if let ruleProviders {
            ctx.ruleSetContains = { name, c in ruleProviders.contains(name: name, ctx: c) }
            ctx.ruleSetNeedsIP = { name in ruleProviders.needsIP(name: name) }
        }
        return ctx
    }

    func stop() {
        stateLock.lock(); defer { stateLock.unlock() }
        healthCheck?.stop()
        healthCheck = nil
        smartTimer?.cancel()
        smartTimer = nil
        smart = nil
        persistFakeIP()
        // nc-lifecycle: drain the rule-resolve state — pending lookups finish
        // with nil at once instead of completing into the stopped engine,
        // and the generation bump keeps a late upstream answer out of any
        // future cache. Waiters fire outside resolveLock (finishResolve's
        // shape); stateLock is recursive and the route completions hop to
        // their own queues from here.
        resolveLock.lock()
        resolveGeneration += 1
        resolveCache = [:]
        let stranded = resolveWaiters.values.flatMap { $0 }
        resolveWaiters = [:]
        resolveLock.unlock()
        for w in stranded { w(nil) }
        isRunning = false
        _config = nil
        rules = []
        groups = nil
        fakeIP = nil
        dnsResponder = nil
        realIPMap = nil
        loadedCanonical = nil
        ruleProviders = nil
        dnsPolicy = nil
        nodeSubStore = nil
        nodeSubs = []
        _merged = nil
        canonicalGroupMap = [:]
    }

    func persistFakeIP() {
        let (pool, file) = locked { (fakeIP, fakeIPFile) }
        guard let pool else { return }
        let m = pool.mutations
        pool.persist(to: file)
        persistLock.lock(); persistedMutations = m; persistedPool = ObjectIdentifier(pool); persistLock.unlock()
    }

    /// fix/nc-mitm-live: periodic flush (data-plane tick, ~60 s) — only when the pool gained mappings since the last
    /// write. Before this the table was written on stop / reload only, so an extension that ended without stopTunnel
    /// (jetsam, crash, iOS kill) lost every mapping while apps kept the 198.18.x.x answers in their own DNS caches:
    /// their next connections were dropped ("fake-ip without a domain mapping").
    func persistFakeIPIfChanged() {
        let (pool, file) = locked { (fakeIP, fakeIPFile) }
        guard let pool else { return }
        let m = pool.mutations
        persistLock.lock()
        let same = persistedPool == ObjectIdentifier(pool) && persistedMutations == m
        persistLock.unlock()
        guard !same else { return }
        pool.persist(to: file)
        persistLock.lock(); persistedMutations = m; persistedPool = ObjectIdentifier(pool); persistLock.unlock()
    }
    private let persistLock = NSLock()
    private var persistedMutations: UInt64 = 0
    private var persistedPool: ObjectIdentifier?

    var isRedirHost: Bool { locked { redirHostMode } }

    /// fix/nc-mitm-live: MitM can take TUN flows at all — the native front is installed (iOS 17+) and some host list
    /// (the app's rewrite snapshot, or a .conf profile's [MITM]) names hosts.
    var mitmActive: Bool {
        guard MitmTLSFront.shared.onAccept != nil else { return false }
        if NativeRewriteEngine.shared.hasMitmHosts { return true }
        return locked { !(loadedCanonical?.mitm.hostnames.isEmpty ?? true) }
    }

    /// Ports a bare-IP flow is held on for its ClientHello (443 + ports named in the host list).
    var mitmPorts: Set<Int> { NativeRewriteEngine.shared.mitmPorts }

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
        return groups != nil ? (_merged ?? mergedConfig(base: cfg)) : cfg
    }

    /// The loaded config's sniffer settings (disabled when no config).
    var snifferConfig: NCSnifferConfig {
        config?.sniffer ?? NCSnifferConfig(fields: [:])
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
        smart?.recordCheck(name: name, ms: ms)
    }

    func recordFailure(name: String) {
        stateLock.lock(); defer { stateLock.unlock() }
        groups?.recordFailure(name: name)
        smart?.recordCheck(name: name, ms: 0)
    }

    /// 智能选择 (bridge/smart.go): read this profile's smart group list from
    /// <home>/groups.json ({"<profile id>": {"smart": [names]}} — the same
    /// store the app edits via SmartGroups) and run the scorer: first pass
    /// 20 s after load, then every 30 s, publishing pins to the resolver.
    private func configureSmart() {
        smartTimer?.cancel()
        smartTimer = nil
        smart = nil
        groups?.smartPins = [:]
        guard let profileID = AppShared.activeProfileURL?.deletingPathExtension().lastPathComponent,
              let data = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("groups.json")),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let entry = root[profileID] as? [String: Any],
              let names = entry["smart"] as? [String], !names.isEmpty else { return }
        let selector = NCSmartSelector(enabledGroups: names)
        smart = selector
        let timer = DispatchSource.makeTimerSource(queue: smartQueue)
        timer.schedule(deadline: .now() + 20, repeating: 30)
        timer.setEventHandler { [weak self] in
            // Engine state read / written under the engine lock (gap D3); the scorer itself runs unlocked.
            guard let self, let selector = self.locked({ self.smart }) else { return }
            let cfgGroups = self.effectiveConfig?.groups ?? []
            let groupEngine = self.groupEngine
            let pins = selector.tick(groups: cfgGroups, currentMember: { g in groupEngine?.currentMember(of: g) })
            self.locked { if self.smart === selector { self.groups?.smartPins = pins } }
        }
        timer.resume()
        smartTimer = timer
    }

    /// GET /smart body for the controller (Go smartRoutes shape).
    func smartStatusJSON() -> [String: Any] {
        locked { smart }?.statusJSON() ?? ["groups": [Any]()]
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
            if let hit = NCRuleMatcher.firstMatchWithPolicy(rules, ctx) {
                return (hit.policy, hit.rule.raw)
            }
            return ("DIRECT", nil)
        }
    }

    /// Policy, matching rule and outbound for one connection in a single locked step (the rule is matched once and a
    /// load-balance group advances once). Used by the local mixed proxy (gap D1).
    /// nc-script-runtime: with type=rule scripts registered, they are consulted first; the wait is bounded by
    /// the scripts' own timeouts (NCScriptHookRunner.ruleVerdict) and any timeout / error falls through to
    /// normal rule matching (fail-open). Without rule scripts this is the pre-hook path, untouched.
    func route(_ ctx: NCMatchContext) -> (policy: String, rule: String?, resolution: NCGroupEngine.Resolution) {
        // nc-lifecycle (evidence rework): the script-hook runner is tunnel-only, so the
        // hook consult is compiled in only there (TERN_TUNNEL). App-target builds — unit
        // tests driving this engine in-process — route exactly like the tunnel does with
        // no rule scripts registered, which is the pre-hook path below.
        #if TERN_TUNNEL
        if hasRuleScripts, let verdict = NCScriptHookRunner.shared.ruleVerdict(ctx: ctx) {
            stateLock.lock(); defer { stateLock.unlock() }
            return (verdict.policy, "script:\(verdict.script)", groups?.resolve(verdict.policy) ?? .direct)
        }
        #endif
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

    /// Every configured nameserver (plain UDP, tcp://, tls:// DoT,
    /// https:// DoH, quic:// DoQ) as one sequential-failover group.
    var firstDNSUpstream: NCDNSUpstream? {
        // fix/nc-start-empty: nameserver first; when it holds nothing forwardable (only system / dhcp), the
        // bootstrap lists instead of dropping every query.
        guard let dns = config?.dns else { return nil }
        return NCDNSUpstream.firstUsable([dns.nameservers, dns.defaultNameservers, dns.proxyServerNameservers])
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
        dnsRoute(for: query).primary
    }

    /// Full DNS routing for a forwarded query (mihomo dns.fallback /
    /// fallback-filter): the primary upstream as dnsUpstream picks it,
    /// plus the first fallback server when dns.fallback is configured.
    /// `fallbackFirst` is set when the query name itself matches the
    /// fallback filter (domain/geosite) and no per-domain assignment
    /// governs the name — per-domain assignments always win, as in
    /// mihomo, where nameserver-policy bypasses the fallback logic.
    func dnsRoute(for query: Data) -> (primary: NCDNSUpstream?, fallback: NCDNSUpstream?, fallbackFirst: Bool) {
        // Gap D3: one locked read of the policy, the rest runs on the local copy.
        let dnsPolicy = locked { self.dnsPolicy }
        var primary: NCDNSUpstream? = nil
        var assigned = false
        var qname: String? = nil
        if let policy = dnsPolicy, let msg = NCDNSMessage.parse(query),
           let name = msg.questions.first?.name {
            qname = name
            let refs = policy.servers(for: name)
            assigned = !refs.isEmpty
            primary = NCDNSUpstream.of(refs.compactMap { NCDNSUpstream($0) })
        }
        if primary == nil { primary = firstDNSUpstream }
        var fallback: NCDNSUpstream? = nil
        if let policy = dnsPolicy {
            fallback = NCDNSUpstream.of(policy.fallbackServers.compactMap { NCDNSUpstream($0) })
        }
        let first = fallback != nil && !assigned && qname != nil
            && (dnsPolicy?.useFallbackFirst(forDomain: qname!) ?? false)
        return (primary, fallback, first)
    }

    /// Whether a primary upstream's answer is polluted per
    /// fallback-filter ipcidr and the fallback servers should be asked.
    func dnsAnswerTriggersFallback(_ response: Data) -> Bool {
        locked { dnsPolicy }?.answerTriggersFallback(response) ?? false
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

    // MARK: rv2-rules: resolve-then-continue rule matching

    /// Rule-match problems found at load (unknown rule types, missing geo
    /// databases, undeclared rule sets, invalid regex, unsupported DNS policy
    /// keys…). Listed once in the startup log with the support report.
    private var ruleDiagnostics: [String] = []

    func isFakeAddress(_ ip: NCIP) -> Bool { locked { fakeIP }?.isFakeAddress(ip) ?? false }

    /// Policy, rule and outbound for a flow, mihomo tunnel.match style: when
    /// an IP rule (without no-resolve) is reached by a domain-only flow, the
    /// domain is resolved ONCE through the kernel DNS (hosts, nameserver-
    /// policy, cached) without blocking the caller's queue, and matching
    /// resumes at that rule with the IP. `completion` runs on `queue` (or
    /// synchronously when no resolution was needed), never under the lock.
    func routeAsync(_ ctx0: NCMatchContext, queue: DispatchQueue,
                    completion: @escaping (_ policy: String, _ rule: String?,
                                           _ resolution: NCGroupEngine.Resolution) -> Void) {
        // nc-script-runtime: registered type=rule scripts run first, on the hook runner's serial queue
        // (never blocking this caller); a policy verdict short-circuits rule matching, no-match / error /
        // timeout falls through to it (fail-open). Without rule scripts this is the pre-hook path.
        // nc-lifecycle (evidence rework): tunnel-only, as in route() — see the note there.
        #if TERN_TUNNEL
        if hasRuleScripts {
            NCScriptHookRunner.shared.applyRule(ctx: ctx0, on: queue) { [weak self] policy, script in
                guard let self else { return }
                if let policy {
                    let resolution = self.locked { self.groups?.resolve(policy) ?? .direct }
                    completion(policy, script.map { "script:\($0)" }, resolution)
                    return
                }
                self.routeAsyncImpl(ctx0, queue: queue, completion: completion)
            }
            return
        }
        #endif
        routeAsyncImpl(ctx0, queue: queue, completion: completion)
    }

    private func routeAsyncImpl(_ ctx0: NCMatchContext, queue: DispatchQueue,
                                completion: @escaping (_ policy: String, _ rule: String?,
                                                       _ resolution: NCGroupEngine.Resolution) -> Void) {
        stateLock.lock()
        guard _config != nil, effectiveMode == "rule" else {
            let (p, r) = policyWithRule(for: ctx0)
            let res = groups?.resolve(p) ?? .direct
            stateLock.unlock()
            completion(p, r, res)
            return
        }
        let snapshot = rules
        let step = NCRuleMatcher.scan(snapshot, ctx0, from: 0, mayResolve: true)
        if case .needsResolve(let idx) = step, let host = ctx0.domain {
            stateLock.unlock()
            resolveHost(host) { [weak self] ip in
                queue.async {
                    guard let self else { return }
                    var ctx = ctx0
                    ctx.ip = ip
                    self.stateLock.lock()
                    let out = self.finishRoute(NCRuleMatcher.scan(snapshot, ctx, from: idx, mayResolve: false))
                    self.stateLock.unlock()
                    completion(out.0, out.1, out.2)
                }
            }
            return
        }
        let out = finishRoute(step)
        stateLock.unlock()
        completion(out.0, out.1, out.2)
    }

    /// Caller holds stateLock.
    private func finishRoute(_ step: NCRuleMatcher.Scan) -> (String, String?, NCGroupEngine.Resolution) {
        var policy = "DIRECT"
        var rule: String? = nil
        if case .hit(_, let r, let p) = step { policy = p; rule = r.raw }
        return (policy, rule, groups?.resolve(policy) ?? .direct)
    }

    private let resolveForwarder = NCDNSForwarder(queue: DispatchQueue(label: "nc.rule-resolve"))
    private let resolveLock = NSLock()
    private var resolveCache: [String: (ip: NCIP?, expires: Date)] = [:]
    private var resolveWaiters: [String: [(NCIP?) -> Void]] = [:]
    /// Bumped on every load and on stop (under resolveLock): finishResolve
    /// only caches answers from the current generation.
    private var resolveGeneration = 0

    /// One A lookup for rule matching (AAAA when the answer has no A and
    /// ipv6 is on is not attempted — mihomo prefers v4 too). Hosts first,
    /// then the upstreams dnsRoute picks (nameserver-policy honoured);
    /// identical in-flight lookups share one query; answers cached (TTL
    /// clamped 60–600 s, failures 30 s), at most 512 names.
    func resolveHost(_ host0: String, completion: @escaping (NCIP?) -> Void) {
        let host = host0.lowercased()
        if let ip = NCIP(host) { completion(ip); return }
        if let entry = locked({ dnsPolicy })?.hostsEntry(for: host), entry.kind == .address {
            let ips = entry.addresses
            completion(ips.first(where: { $0.isV4 }) ?? ips.first)
            return
        }
        let now = Date()
        resolveLock.lock()
        if let c = resolveCache[host], c.expires > now {
            resolveLock.unlock()
            completion(c.ip)
            return
        }
        if resolveWaiters[host] != nil {
            if resolveWaiters[host]!.count < 64 { resolveWaiters[host]!.append(completion) }
            resolveLock.unlock()
            return
        }
        resolveWaiters[host] = [completion]
        let gen = resolveGeneration
        resolveLock.unlock()
        var q = NCDNSMessage()
        q.id = UInt16.random(in: 1...0xffff)
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: host, type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        let query = q.serialized()
        guard let upstream = dnsRoute(for: query).primary else {
            finishResolve(host, ip: nil, ttl: 30, gen: gen)
            return
        }
        #if TERN_TUNNEL
        resolveForwarder.forward(query, upstream: upstream) { [weak self] (resp: Data?) in
            let answers = resp.flatMap { NCDNSMessage.parse($0) }?.addressAnswers ?? []
            let hit = answers.first(where: { $0.0.isV4 }) ?? answers.first
            self?.finishResolve(host, ip: hit?.0, ttl: hit.map { min(max(Double($0.1), 60), 600) } ?? 30, gen: gen)
        }
        #else
        // App target (unit-test evidence only): NCDNSForwarder.forward(_:upstream:) lives in the
        // tunnel-only NCUDPSessions.swift. The app never starts the engine, so resolve misses here.
        _ = upstream
        finishResolve(host, ip: nil, ttl: 30, gen: gen)
        #endif
    }

    /// fix/nc-e2e-real: POST /cache/dns/flush — the rule-matching resolver cache (in-flight lookups still complete).
    func flushDNSCache() {
        resolveLock.lock()
        resolveCache.removeAll()
        resolveLock.unlock()
    }

    /// fix/nc-e2e-real: POST /cache/fakeip/flush.
    func flushFakeIP() {
        locked { fakeIP }?.flush()
    }

    #if TERN_TUNNEL
    /// fix/nc-e2e-real: GET /dns/query (工具 → DNS 查询 answered 404 on the native core). One query of `type` through
    /// the kernel DNS — hosts first, then the upstream dnsRoute picks (nameserver-policy honoured) — real answers, never
    /// fake-ip (mihomo's /dns/query uses its resolver the same way). nil = no upstream / no answer.
    func queryDNS(name: String, type: UInt16, completion: @escaping (Data?) -> Void) {
        var q = NCDNSMessage()
        q.id = UInt16.random(in: 1...0xffff)
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        let query = q.serialized()
        if let local = dnsHostsReply(query) { completion(local); return }
        guard let upstream = dnsRoute(for: query).primary else { completion(nil); return }
        resolveForwarder.forward(query, upstream: upstream) { (resp: Data?) in completion(resp) }
    }
    #endif

    private func finishResolve(_ host: String, ip: NCIP?, ttl: Double, gen: Int) {
        resolveLock.lock()
        // Only the current generation caches: an answer fetched under a
        // previous config (or before stop) still completes its waiters — the
        // flows that asked — but must not seed the new config's cache.
        if gen == resolveGeneration {
            if resolveCache.count >= 512 {
                let now = Date()
                resolveCache = resolveCache.filter { $0.value.expires > now }
                if resolveCache.count >= 512 { resolveCache.removeAll() }
            }
            resolveCache[host] = (ip, Date().addingTimeInterval(ttl))
        }
        let waiters = resolveWaiters.removeValue(forKey: host) ?? []
        resolveLock.unlock()
        for w in waiters { w(ip) }
    }

    /// Load-time diagnostics (one line each, capped).
    private static func diagnose(cfg: NCConfig, rules: [NCRule], providers: [NCRuleProviderStore.Provider],
                                 policy: NCDNSPolicy, pool: NCFakeIPPool, geoSite: NCGeoSiteDB?,
                                 geoIP: Bool, asn: Bool) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        func add(_ line: String) { if seen.insert(line).inserted, out.count < 40 { out.append(line) } }
        let providerKeys = Set(providers.map { $0.name } + providers.flatMap { $0.aliases })
        var noResolveIP = 0
        func visit(_ r: NCRule, depth: Int) {
            guard depth < 8 else { return }
            let k = r.kind
            if !NCRuleMatcher.knownKinds.contains(k) { add("规则类型 \(k) 暂不支持，永不匹配：\(r.raw)") }
            switch k {
            case "GEOSITE":
                if let geoSite {
                    if !geoSite.hasCategory(r.payload) { add("GEOSITE 分类 \(r.payload) 不在 GeoSite.dat 中，永不匹配") }
                } else { add("缺少 GeoSite.dat：GEOSITE 规则永不匹配（\(r.raw)）") }
            case "GEOIP", "SRC-GEOIP":
                if !geoIP { add("缺少 geoip.metadb：GEOIP 规则永不匹配（\(r.raw)）") }
            case "IP-ASN":
                if !asn { add("缺少 ASN.mmdb：IP-ASN 规则永不匹配（\(r.raw)）") }
            case "RULE-SET", "DOMAIN-SET":
                if !providerKeys.contains(r.payload) { add("规则集 \(r.payload) 未声明，永不匹配") }
            case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "URL-REGEX":
                if !NCRegexCache.shared.isValid(r.payload) { add("正则无效，规则永不匹配：\(r.raw)") }
            case "PROTOCOL":
                if !NCRuleMatcher.supportedProtocols.contains(r.payload.uppercased()) {
                    add("PROTOCOL \(r.payload) 无法原生识别，永不匹配")
                }
            default: break
            }
            if r.noResolve, NCRuleMatcher.ipKinds.contains(k) { noResolveIP += 1 }
            for sub in r.subRules { visit(sub, depth: depth + 1) }
        }
        for r in rules { visit(r, depth: 0) }
        for name in cfg.subRules.keys.sorted() { for r in cfg.subRules[name] ?? [] { visit(r, depth: 0) } }
        if noResolveIP > 0 {
            add("\(noResolveIP) 条 IP 规则带 no-resolve：只按已知 IP 匹配，域名连接（fake-ip）不会命中")
        }
        out.append(contentsOf: policy.diagnostics.prefix(10))
        for (kind, arg) in policy.matcherKeyArgs {
            if kind == .geosite, geoSite == nil { add("缺少 GeoSite.dat：DNS 分流 geosite:\(arg) 不生效") }
            if kind == .ruleSet, !providerKeys.contains(arg) { add("DNS 分流 rule-set:\(arg) 未声明，不生效") }
        }
        if geoSite == nil, !policy.model.fallbackFilter.geosite.isEmpty {
            add("缺少 GeoSite.dat：fallback-filter geosite 不生效")
        }
        for e in pool.externalEntries {
            if e.hasPrefix("geosite:"), geoSite == nil { add("缺少 GeoSite.dat：fake-ip-filter \(e) 不生效") }
            if e.hasPrefix("rule-set:"), !providerKeys.contains(String(e.dropFirst(9))) {
                add("fake-ip-filter \(e) 未声明，不生效")
            }
        }
        let mode = cfg.dns.fakeIPFilterMode
        if mode != "blacklist", mode != "whitelist" {
            add("fake-ip-filter-mode: \(mode) 暂不支持，按 blacklist 处理")
        }
        return out
    }

    var statsLine: String {
        stateLock.lock(); defer { stateLock.unlock() }
        guard let cfg = _config else { return "native core: not loaded" }
        let fromProviders = (_merged?.proxies.count ?? cfg.proxies.count) - cfg.proxies.count
        return "native core (\(configSource)): \(cfg.proxies.count) proxies + \(fromProviders) from \(nodeSubs.count) provider(s), \(cfg.groups.count) groups, \(rules.count) rules (\(unparsedRules.count) ignored), unsupported \(groups?.unsupported.count ?? 0), fake-ip \(fakeIP?.size ?? 0) entries"
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
