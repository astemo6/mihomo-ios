import Foundation
import Network
import Libmihomo

// Offline view of the active profile (bridge/inspect.go): what 策略 / 规则 / 提供者 show while the
// tunnel is down. Built by the Go bridge from the same runtime YAML the core would load.

struct InspectProxy: Decodable, Hashable {
    var name: String
    var type: String
    var server: String?
    var port: Int?
    var udp: Bool?
    var source: String?
}

struct InspectGroup: Decodable, Hashable, Identifiable {
    var id: String { name }
    var name: String
    var type: String
    var proxies: [String]
    var use: [String]
    var url: String?
    var hidden: Bool?
    var filter: String?
    var selected: String?
    var icon: String?
    /// B16: members as the core lists them (bridge groupMembers: filter / exclude-filter / exclude-type /
    /// providers / empty-fallback). nil from an older bridge.
    var members: [String]?

    enum CodingKeys: String, CodingKey { case name, type, proxies, use, url, hidden, filter, selected, icon, members }
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        type = (try? c.decodeIfPresent(String.self, forKey: .type)) ?? "select"
        proxies = (try? c.decodeIfPresent([String].self, forKey: .proxies)) ?? []
        use = (try? c.decodeIfPresent([String].self, forKey: .use)) ?? []
        url = try? c.decodeIfPresent(String.self, forKey: .url)
        hidden = try? c.decodeIfPresent(Bool.self, forKey: .hidden)
        filter = try? c.decodeIfPresent(String.self, forKey: .filter)
        selected = try? c.decodeIfPresent(String.self, forKey: .selected)
        icon = try? c.decodeIfPresent(String.self, forKey: .icon)
        members = try? c.decodeIfPresent([String].self, forKey: .members)
    }

    init(name: String, type: String, members: [String]) {
        self.name = name
        self.type = type
        proxies = members
        use = []
        self.members = members
    }
}

struct InspectRule: Decodable, Hashable {
    var type: String
    var payload: String
    var proxy: String
    var options: String?
}

struct InspectProvider: Decodable, Hashable, Identifiable {
    var id: String { kind + ":" + name }
    var name: String
    var kind: String
    var vehicle: String
    var behavior: String?
    var format: String?
    var url: String?
    var path: String?
    var interval: Int?
    var cached: Bool
    var cachedAt: Double?
    var size: Int64?
    var count: Int
    var proxies: [InspectProxy]?
    var preview: [String]?
    var cachePath: String?

    var cachedDate: Date? { cachedAt.map { Date(timeIntervalSince1970: $0) } }
}

struct InspectResult: Decodable {
    var mode: String = "rule"
    var proxies: [InspectProxy] = []
    var groups: [InspectGroup] = []
    var rules: [InspectRule] = []
    var proxyProviders: [InspectProvider] = []
    var ruleProviders: [InspectProvider] = []
    var selected: [String: String] = [:]
    var error: String?

    init() {}

    enum CodingKeys: String, CodingKey { case mode, proxies, groups, rules, proxyProviders, ruleProviders, selected, error }
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        mode = (try? c.decodeIfPresent(String.self, forKey: .mode)) ?? "rule"
        proxies = (try? c.decodeIfPresent([InspectProxy].self, forKey: .proxies)) ?? []
        groups = (try? c.decodeIfPresent([InspectGroup].self, forKey: .groups)) ?? []
        rules = (try? c.decodeIfPresent([InspectRule].self, forKey: .rules)) ?? []
        proxyProviders = (try? c.decodeIfPresent([InspectProvider].self, forKey: .proxyProviders)) ?? []
        ruleProviders = (try? c.decodeIfPresent([InspectProvider].self, forKey: .ruleProviders)) ?? []
        selected = (try? c.decodeIfPresent([String: String].self, forKey: .selected)) ?? [:]
        error = try? c.decodeIfPresent(String.self, forKey: .error)
    }
}

@MainActor
final class ProfileInspector: ObservableObject {
    static let shared = ProfileInspector()

    @Published private(set) var result = InspectResult() {
        // r7: derived values (members per group, node index, graph) are built once per result, not per render.
        didSet { membersCache = [:]; nodeIndexCache = nil; graphCache = nil }
    }
    private struct MembersKey: Equatable { var proxies: [String]; var use: [String]; var filter: String? }
    private var membersCache: [String: (key: MembersKey, members: [String])] = [:]
    private var nodeIndexCache: [String: InspectProxy]?
    private var graphCache: GroupGraph?
    @Published private(set) var loading = false
    @Published private(set) var profilePath: String?
    @Published var delays: [String: Int] = [:]
    @Published var testing: Set<String> = []

    /// Every node known offline: profile proxies + cached provider nodes (+ built-ins).
    var nodeIndex: [String: InspectProxy] {
        if let c = nodeIndexCache { return c }
        var out: [String: InspectProxy] = [:]
        for p in result.proxies { out[p.name] = p }
        for pv in result.proxyProviders { for p in pv.proxies ?? [] where out[p.name] == nil { out[p.name] = p } }
        out["DIRECT"] = out["DIRECT"] ?? InspectProxy(name: "DIRECT", type: "direct")
        out["REJECT"] = out["REJECT"] ?? InspectProxy(name: "REJECT", type: "reject")
        nodeIndexCache = out
        return out
    }

    /// v0.19.8: GLOBAL while disconnected: the profile's own GLOBAL group, else the one mihomo builds (DIRECT,
    /// REJECT, every node, every group, in config order). Shown in 全局 mode only.
    var globalGroup: InspectGroup {
        if let g = result.groups.first(where: { $0.name == "GLOBAL" }) { return g }
        var m = ["DIRECT", "REJECT"] + result.proxies.map(\.name)
        m += result.groups.filter { $0.name != "GLOBAL" }.map(\.name)
        var g = InspectGroup(name: "GLOBAL", type: "select", members: m)
        g.selected = result.selected["GLOBAL"]
        return g
    }

    /// Members of a group as the core would list them: explicit proxies, then nodes from `use` providers.
    func members(of g: InspectGroup) -> [String] {
        if let m = g.members { return m }
        let key = MembersKey(proxies: g.proxies, use: g.use, filter: g.filter)
        if let c = membersCache[g.name], c.key == key { return c.members }
        var out = g.proxies
        var seen = Set(out)
        let re = g.filter.flatMap { try? NSRegularExpression(pattern: $0) }
        for name in g.use {
            guard let pv = result.proxyProviders.first(where: { $0.name == name }) else { continue }
            for p in pv.proxies ?? [] where !seen.contains(p.name) {
                if let re, re.firstMatch(in: p.name, range: NSRange(p.name.startIndex..., in: p.name)) == nil { continue }
                out.append(p.name)
                seen.insert(p.name)
            }
        }
        membersCache[g.name] = (key, out)
        return out
    }

    struct GroupPreviewItem: Codable {
        var members: [String]?
        var empty: Bool?
        var error: String?
    }
    private struct GroupPreviewResult: Codable {
        var groups: [GroupPreviewItem]?
        var error: String?
    }

    /// B16: members the core would give each draft group in the active profile (bridge GroupPreview, the
    /// same expansion as the inspector), for 策略组编辑 previews and 筛选节点 counts. nil on failure.
    func preview(_ specs: [GroupSpec]) async -> [GroupPreviewItem]? {
        guard let url = AppShared.activeProfileURL else { return nil }
        let home = AppShared.homeURL
        let path = url.path
        let pool = NCGroupEditing.buildMemberPool(home: home, path: path, inspector: self)
        let items = await Task.detached(priority: .userInitiated) {
            NCGroupEditing.preview(specs: specs, pool: pool)
        }.value
        guard items.count == specs.count else { return nil }
        return items
    }

    func current(of g: InspectGroup) -> String? {
        if let s = g.selected ?? result.selected[g.name], members(of: g).contains(s) { return s }
        return members(of: g).first
    }

    /// v0.19.2: loads overlap (profile switch, subscription update, node edits all call load()). A slower earlier
    /// load finishing last used to put the previous profile's groups and path back — 策略 then showed the old
    /// profile and offline selections were saved into the wrong profile. Only the newest load publishes.
    private var loadSeq = 0

    func load() async {
        loadSeq += 1
        let seq = loadSeq
        guard let url = AppShared.activeProfileURL else {
            result = InspectResult()
            profilePath = nil
            return
        }
        loading = true
        defer { if seq == loadSeq { loading = false } }
        let home = AppShared.homeURL.path
        let path = url.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoInspectProfile(home, path) }.value
        guard seq == loadSeq else { return }
        if let r = try? JSONDecoder().decode(InspectResult.self, from: Data(json.utf8)) {
            result = r
        } else {
            var r = InspectResult()
            r.error = String(localized: "无法读取配置")
            result = r
        }
        if profilePath != path { delays = [:] }
        profilePath = path
    }

    /// Saves group → node for the active profile; applied by the core on the next connect.
    func select(group: String, node: String) {
        guard let path = profilePath ?? AppShared.activeProfileURL?.path else { return }
        let err = LibmihomoSaveSelection(path, group, node)
        guard err.isEmpty else { return }
        if let i = result.groups.firstIndex(where: { $0.name == group }) { result.groups[i].selected = node }
        result.selected[group] = node // v0.19.8: also the synthesized GLOBAL
    }

    /// hotfix/group-test-offline: the groups (GLOBAL included) as a graph, for expanding groups of groups to nodes.
    var graph: GroupGraph {
        if let c = graphCache { return c }
        var gs: [String: GroupGraph.Group] = [:]
        for g in result.groups { gs[g.name] = GroupGraph.Group(type: g.type, members: members(of: g), now: current(of: g)) }
        let global = globalGroup
        gs["GLOBAL"] = GroupGraph.Group(type: global.type, members: members(of: global), now: current(of: global))
        let index = nodeIndex
        let g = GroupGraph(groups: gs, isTestable: { index[$0] != nil && !GroupGraph.builtins.contains($0) })
        graphCache = g
        return g
    }

    /// The delay a card shows for `name`: a node's own measurement, or for a group the measurement of the node it
    /// resolves to (GroupGraph.resolve). nil = not measured.
    func displayDelay(_ name: String, graph: GroupGraph) -> Int? {
        if graph.groups[name] != nil { return graph.resolve(name, delays: delays)?.delay }
        return delays[name]
    }

    /// Shown once when a test had nothing to dial (e.g. a group of only DIRECT / REJECT); cleared by the page.
    @Published var notice: String?

    /// Delay test without the tunnel (direct from the app), group members in parallel (6 at a time).
    func test(group g: InspectGroup) async { await test(groups: [g]) }

    /// hotfix/group-test-offline: tests the real nodes behind the given groups — member groups are expanded to the
    /// nodes they reach (provider / filter members included, each node once), so a group made only of groups
    /// (节点选择 → 自动选择 / 日本 …) is measured too. Every group shows its spinner for the whole run; 全部测速 passes
    /// all groups at once so a node shared by several groups is dialled once.
    func test(groups gs: [InspectGroup]) async {
        guard let path = profilePath else { return }
        let fresh = gs.map(\.name).filter { !testing.contains($0) } // v0.19.3: no parallel duplicate
        guard !fresh.isEmpty else { return }
        testing.formUnion(fresh)
        defer { testing.subtract(fresh) }
        let home = AppShared.homeURL.path
        // The 测速 setting, not the group's own URL: manual tests use one URL everywhere (live too).
        let st = ControllerClient.testSettings
        let url = st.url
        let timeout = st.timeoutMs
        let names = graph.leaves(of: fresh)
        guard !names.isEmpty else {
            notice = fresh.count == 1 ? String(localized: "「\(fresh[0])」里没有可测速的节点") : String(localized: "没有可测速的节点")
            return
        }
        // v0.15.2: bind the test sockets to Wi-Fi / cellular so another app's VPN (QX, Surge …) that is up
        // while ours is off does not carry the test through its own node too. The core falls back to
        // normal routing when the bind fails.
        let iface = await PhysicalInterface.current() ?? ""
        NCDelayTester.setOfflineInterface(iface)
        LibmihomoSetOfflineTestInterface(iface)
        let tcp = ControllerClient.tcpHandshake
        var idx = 0
        while idx < names.count {
            let batch = Array(names[idx..<min(idx + 6, names.count)])
            idx += batch.count
            let got = await withTaskGroup(of: (String, Int).self, returning: [(String, Int)].self) { tg in
                for n in batch {
                    let u = NodeSettingsStore.customURL(for: n) ?? url
                    tg.addTask { (n, Int(await BlockingWork.run {
                        tcp ? NCDelayTester.tcpDelayByName(homeDir: home, profilePath: path, name: n, url: u, timeoutMs: timeout)
                            : NCDelayTester.testDelayByName(homeDir: home, profilePath: path, name: n, url: u, timeoutMs: timeout)
                    })) }
                }
                var out: [(String, Int)] = []
                for await r in tg { out.append(r) }
                return out
            }
            for (n, ms) in got { delays[n] = ms }
        }
    }

    /// Saves the live selection too, so the offline view and the next connect agree with it.
    static func rememberLiveSelection(group: String, node: String) {
        guard let path = AppShared.activeProfileURL?.path else { return }
        _ = LibmihomoSaveSelection(path, group, node)
    }
}

/// The physical interface (en0 / pdp_ip0 …) the system would use, ignoring VPN tunnels (v0.15.2).
enum PhysicalInterface {
    static func current() async -> String? {
        await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
            let lock = NSLock()
            var done = false
            func finish(_ v: String?) {
                lock.lock()
                defer { lock.unlock() }
                guard !done else { return }
                done = true
                monitor.cancel()
                cont.resume(returning: v)
            }
            monitor.pathUpdateHandler = { path in
                let iface = path.availableInterfaces.first { $0.type == .wifi || $0.type == .cellular || $0.type == .wiredEthernet }
                finish(path.status == .satisfied ? iface?.name : nil)
            }
            monitor.start(queue: DispatchQueue(label: "mihomo.physical-interface"))
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) { finish(nil) }
        }
    }
}
