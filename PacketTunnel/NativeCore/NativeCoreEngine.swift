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
        groups = NCGroupEngine(config: cfg)
        let pool = NCFakeIPPool(range: cfg.dns.fakeIPRange, filter: cfg.dns.fakeIPFilter)
        if let data = try? Data(contentsOf: fakeIPFile) {
            pool.restore(data: data)
        }
        fakeIP = pool
        dnsResponder = nil
        isRunning = true
        return nil
    }

    func stop() {
        persistFakeIP()
        isRunning = false
        config = nil
        rules = []
        groups = nil
        fakeIP = nil
        dnsResponder = nil
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

    /// First configured nameserver usable as plain UDP DNS (others, like
    /// DoH/DoT entries, are skipped until those transports land).
    var firstUDPNameserver: String? {
        for raw in config?.dns.nameservers ?? [] {
            var entry = raw
            if entry.hasPrefix("udp://") { entry = String(entry.dropFirst(6)) }
            if entry.contains("://") { continue }
            let host = entry.split(separator: ":").first.map(String.init) ?? entry
            if NCIP(host) != nil { return host }
        }
        return nil
    }

    /// Answers a raw DNS query in fake-IP mode (A -> fake IP, AAAA -> empty
    /// NOERROR). nil means the query is not fake-IP business and must be
    /// forwarded upstream by the caller.
    func handleDNSQuery(_ query: Data) -> Data? {
        guard let pool = fakeIP else { return nil }
        if dnsResponder == nil { dnsResponder = NCFakeIPResponder(pool: pool) }
        return dnsResponder?.respond(to: query)
    }

    /// If the destination is a fake-IP address, swap in the original host (the
    /// DNS side filled the pool when the query came in).
    func derefFakeIP(_ target: NCTarget) -> NCTarget {
        guard let ip = target.ip, let pool = fakeIP, let host = pool.host(for: ip) else { return target }
        return NCTarget(host: host, port: target.port)
    }

    var statsLine: String {
        guard let cfg = config else { return "native core: not loaded" }
        return "native core: \(cfg.proxies.count) proxies, \(cfg.groups.count) groups, \(rules.count) rules, fake-ip \(fakeIP?.size ?? 0) entries"
    }
}
