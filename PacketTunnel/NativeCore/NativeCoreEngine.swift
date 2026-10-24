import Foundation
import Libmihomo

/// The native core's control plane inside the tunnel: loads the runtime config
/// (via the Go bridge's NativeConfigJSON export during the transition), parses
/// rules once, owns the fake-IP pool and the group engine, and routes targets
/// to outbounds. The data plane (TUN/lwIP) lands in the next batch; until the
/// provider switch is wired, nothing calls this in production paths.
final class NativeCoreEngine {
    private(set) var config: NCConfig?
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
    private var home = ""

    private var fakeIPFile: URL {
        URL(fileURLWithPath: home).appendingPathComponent("nativecore-fakeip.json")
    }

    /// Loads (or reloads) the config for `home`. Returns an error message or nil.
    @discardableResult
    func load(home: String) -> String? {
        self.home = home
        var err: NSError?
        let json = LibmihomoNativeConfigJSON(home, &err)
        if let err { return "NativeConfigJSON: \(err.localizedDescription)" }
        guard !json.isEmpty, let cfg = try? NCConfig.decode(jsonData: Data(json.utf8)) else {
            return "native core: config decode failed"
        }
        config = cfg
        rules = cfg.rules.compactMap(NCRule.parse)
        let canonical = NCCanonicalConfig.from(mihomo: cfg)
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
        }
        if let data = try? Data(contentsOf: homeURL.appendingPathComponent("ASN.mmdb")), data.count > 1024 {
            asnDB = NCMMDB(data: data)
        }
        isRunning = true
        return nil
    }

    /// (Re)build the group engine over the merged effective config:
    /// config nodes/groups plus subscription nodes, with group membership
    /// expanded through each group's `use` subscriptions and regex filters.
    /// Selections/delays survive rebuilds (subscription refresh lands async).
    private func rebuildGroupEngine() {
        guard let cfg = config else { return }
        let engine = NCGroupEngine(config: mergedConfig(base: cfg))
        if let old = groups {
            engine.selections = old.selections
            engine.delays = old.delays
            engine.alive = old.alive
        }
        engine.ssidProvider = {
            UserDefaults(suiteName: AppShared.appGroup)?.string(forKey: "nativeCoreSSID")
        }
        groups = engine
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
        persistFakeIP()
        isRunning = false
        config = nil
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
        guard let pool = fakeIP, let data = pool.snapshotData() else { return }
        try? data.write(to: fakeIPFile, options: .atomic)
    }

    // MARK: Routing

    var groupEngine: NCGroupEngine? { groups }

    /// Controller-driven mode override (PATCH /configs); nil = config's mode.
    var modeOverride: String?

    var effectiveMode: String { modeOverride ?? config?.mode ?? "rule" }

    func setSelection(group: String, member: String?) {
        if let member {
            groups?.selections[group] = member
        } else {
            groups?.selections.removeValue(forKey: group)
        }
    }

    func recordDelay(name: String, ms: Int) {
        groups?.delays[name] = ms
        groups?.alive[name] = ms > 0
    }

    /// Policy name for a connection, following the config mode:
    /// direct -> DIRECT; global -> the GLOBAL group; rule -> first rule hit.
    func policy(for ctx: NCMatchContext) -> String {
        policyWithRule(for: ctx).policy
    }

    func policyWithRule(for ctx: NCMatchContext) -> (policy: String, rule: String?) {
        guard let cfg = config else { return ("DIRECT", nil) }
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

    func resolve(_ ctx: NCMatchContext) -> NCGroupEngine.Resolution {
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
        dnsPolicy?.hostsReply(queryData: query)
    }

    /// Upstream for a query that neither hosts nor fake-IP answered: the
    /// per-domain assignment (nameserver-policy / [Host] server: / QX
    /// server=/) when one exists, else the first configured default.
    func dnsUpstream(for query: Data) -> NCDNSUpstream? {
        if let policy = dnsPolicy, let msg = NCDNSMessage.parse(query),
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
        guard !redirHostMode, let pool = fakeIP else { return nil }
        if dnsResponder == nil { dnsResponder = NCFakeIPResponder(pool: pool) }
        return dnsResponder?.respond(to: query)
    }

    /// redir-host: remember a forwarded response's A/AAAA answers so later
    /// connections to those real IPs match rules by the queried host.
    func recordDNSResponse(query: Data, response: Data) {
        guard redirHostMode, let map = realIPMap,
              let q = NCDNSMessage.parse(query), let name = q.questions.first?.name,
              let resp = NCDNSMessage.parse(response) else { return }
        map.record(host: name, answers: resp.addressAnswers)
    }

    /// If the destination is a fake-IP address, swap in the original host (the
    /// DNS side filled the pool when the query came in). In redir-host mode,
    /// fall back to the recorded real-IP -> host mapping.
    func derefFakeIP(_ target: NCTarget) -> NCTarget {
        guard let ip = target.ip else { return target }
        if let pool = fakeIP, let host = pool.host(for: ip) {
            return NCTarget(host: host, port: target.port)
        }
        if let host = realIPMap?.host(for: ip) {
            return NCTarget(host: host, port: target.port)
        }
        return target
    }

    var statsLine: String {
        guard let cfg = config else { return "native core: not loaded" }
        return "native core: \(cfg.proxies.count) proxies, \(cfg.groups.count) groups, \(rules.count) rules, fake-ip \(fakeIP?.size ?? 0) entries"
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
        return fakeIP?.isFakeAddress(ip) ?? false
    }
}
