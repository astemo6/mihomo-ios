import Foundation

// 节点管理 (v0.16): every node the app knows, grouped by where it comes from. The base list is the offline
// view of the active profile (ProfileInspector: profile proxies, merged manual nodes, cached provider and
// node-subscription nodes); while connected the core's /proxies + /providers/proxies add what is not cached
// yet and the last measured delays. Manual nodes that are not part of the current profile are listed too.

enum NodeSourceKind: Int, Comparable, Hashable {
    case profile = 0, manual, subscription, provider
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

struct NodeSource: Hashable, Identifiable {
    var kind: NodeSourceKind
    /// Profile name, provider name or subscription name.
    var name: String
    /// NodeSubscription.id for .subscription.
    var subID: String? = nil
    /// Review 7 R7A-4: the proxy-provider's name in the runtime (a node subscription's merged provider can differ
    /// from its display name). nil = same as `name`.
    var provider: String? = nil
    /// Provider vehicle ("http" / "file" / "inline") and whether its nodes are on disk (offline view).
    var cached: Bool = true
    var order: Int = 0
    /// Provider cache time (offline view); the active profile is a remote subscription (.profile).
    var updatedAt: Date? = nil
    var remote: Bool = false

    var id: String { "\(kind.rawValue):\(subID ?? name)" }

    /// R7A-4: where the core looks the node up — "" for the profile's own proxies (manual nodes merged into the
    /// profile included), else the runtime provider name. Same-named nodes of two subscriptions stay apart.
    var runtimeProvider: String {
        switch kind {
        case .profile, .manual: return ""
        case .subscription, .provider: return provider ?? name
        }
    }

    var title: String {
        switch kind {
        case .profile: return String(localized: "配置")
        case .manual: return String(localized: "手动")
        case .subscription, .provider: return name
        }
    }

    var icon: String {
        switch kind {
        case .profile: return "doc.text"
        case .manual: return "square.and.pencil"
        case .subscription: return "tray.full"
        case .provider: return "shippingbox"
        }
    }
}

struct ManagedNode: Identifiable, Hashable {
    var name: String
    /// Normalized config type (ss, ssr, vmess, vless, hysteria2, …).
    var type: String
    var server: String?
    var port: Int?
    var udp: Bool
    var source: NodeSource
    /// Part of the active profile's runtime (testable / shareable by name).
    var inRuntime: Bool
    /// The core knows it right now (connected).
    var live: Bool = false
    var order: Int = 0

    var id: String { source.id + "\u{1}" + name }

    var address: String? {
        guard let server, !server.isEmpty else { return nil }
        if let port, port > 0 { return server.contains(":") ? "[\(server)]:\(port)" : "\(server):\(port)" }
        return server
    }

    static func normalize(_ type: String) -> String {
        let t = type.lowercased()
        switch t {
        case "shadowsocks": return "ss"
        case "shadowsocksr": return "ssr"
        case "gostrelay": return "gost-relay"
        default: return t
        }
    }

    /// Built-ins and internal outbounds that are not nodes.
    static let hidden: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "__MITM__", PolicyProbe.group]
    static let nonNodeTypes: Set<String> = ["direct", "reject", "rejectdrop", "reject-drop", "pass", "compatible",
                                             "selector", "urltest", "fallback", "loadbalance", "relay", "select", "url-test", "load-balance", "smart"]
}

/// feat/long-press-reorder (user 2026-10-29): the node list's manual order, persisted as node ids
/// (ManagedNode.id = source + name, stable across subscription refreshes — a refreshed subscription's
/// nodes keep their ids, so the order survives updates). Applied with ManualOrder's slot rule: a node the
/// saved order does not name keeps the position its source gives it, and ids of deleted nodes simply stop
/// matching (the next drag rewrites the saved list from the nodes that exist, dropping them).
enum NodeManualOrder {
    static let defaultsKey = "nodes.manualOrder"

    static func load() -> [String] {
        guard let d = AppShared.defaults.data(forKey: defaultsKey),
              let ids = try? JSONDecoder().decode([String].self, from: d) else { return [] }
        return ids
    }

    static func save(_ ids: [String]) {
        if let d = try? JSONEncoder().encode(ids) { AppShared.defaults.set(d, forKey: defaultsKey) }
    }

    /// The full id list after one source section was dragged to `sectionNew`: the section's members, in
    /// their new order, keep the slots they hold in `all` (every node in display order); the rest stay put.
    static func spliced(all: [String], sectionNew: [String]) -> [String] {
        let ids = Set(sectionNew)
        var it = sectionNew.makeIterator()
        return all.map { ids.contains($0) ? (it.next() ?? $0) : $0 }
    }
}

/// Summary of one node from the retired bridge (no secret values).
struct NodeSummaryInfo: Decodable {
    var name: String?
    var type: String?
    var server: String?
    var port: Int?
    var udp: Bool?
    var source: String?
    var network: String?
    var security: String?
    var sni: String?
    var alpn: String?
    var fingerprint: String?
    var skipCertVerify: Bool?
    var cipher: String?
    var flow: String?
    var plugin: String?
    var pluginMode: String?
    var pluginVersion: Int?
    var obfs: String?
    var protocolParam: String?
    var congestion: String?
    var dialerProxy: String?
    var ipVersion: String?
    var tfo: Bool?
    var mptcp: Bool?
    var smux: String?
    var up: String?
    var down: String?
    var amnezia: Bool?
    var peers: Int?
    var credentials: [String]?
    var shareable: Bool?
    var error: String?
    var tailscale: TailscaleNodeSummary?
}

/// v0.18: the Tailscale fields of a node summary (the auth key is only listed under credentials).
struct TailscaleNodeSummary: Decodable {
    var hostname: String?
    var controlURL: String?
    var stateDir: String?
    var exitNode: String?
    var ephemeral: Bool?
    var acceptRoutes: Bool?
    var exitNodeAllowLAN: Bool?

    enum CodingKeys: String, CodingKey {
        case hostname, ephemeral
        case controlURL = "control-url"
        case stateDir = "state-dir"
        case exitNode = "exit-node"
        case acceptRoutes = "accept-routes"
        case exitNodeAllowLAN = "exit-node-allow-lan-access"
    }
}

@MainActor
final class NodeManagerModel: ObservableObject {
    static let shared = NodeManagerModel()

    enum SortMode: String, CaseIterable, Identifiable {
        case config, name, latency
        var id: String { rawValue }
        var title: String {
            switch self {
            case .config: return String(localized: "默认顺序")
            case .name: return String(localized: "名称")
            case .latency: return String(localized: "延迟")
            }
        }
    }

    @Published private(set) var nodes: [ManagedNode] = [] {
        didSet {
            var c: [NodeSource: Int] = [:]
            for n in nodes { c[n.source, default: 0] += 1 }
            countBySource = c
        }
    }
    /// r7: node count per source, computed once whenever `nodes` changes (NodeManagerHome reads it per row and
    /// when sorting by 节点数, instead of filtering every node per row per render).
    private(set) var countBySource: [NodeSource: Int] = [:]
    @Published private(set) var sources: [NodeSource] = []
    @Published private(set) var loading = false
    @Published private(set) var liveConnected = false
    @Published private(set) var error: String?
    /// node id → ms; 0 = timeout / failure.
    @Published var delays: [String: Int] = [:]
    @Published var testing: Set<String> = []
    @Published private(set) var bulk: (done: Int, total: Int)?
    /// Live: node name → groups that list it (from /proxies). Offline groups come from the inspector.
    @Published private(set) var liveGroups: [String: [String]] = [:]
    private var liveNames: Set<String> = []
    private var liveHistory: [String: Int] = [:]
    private var manualByName: [String: [String: Any]] = [:]
    private var bulkTask: Task<Void, Never>?

    static let concurrency = 8

    var isBulkTesting: Bool { bulk != nil }

    func delay(of n: ManagedNode) -> Int? { delays[n.id] ?? (n.live ? liveHistory[n.name] : nil) }

    /// feat/long-press-reorder: the saved manual node order (ids), loaded once, kept in sync on commit.
    @Published private(set) var manualOrder: [String] = NodeManualOrder.load()

    /// A list in build order with the manual order applied (the 节点列表's 配置排序).
    func applyingManualOrder(_ list: [ManagedNode]) -> [ManagedNode] {
        ManualOrder.apply(list, order: manualOrder) { $0.id }
    }

    /// Commit a long-press drag inside one source section: `sectionNew` is that section's nodes in their
    /// new order; every other node keeps its slot in the full display order.
    func commitNodeDrag(sectionNew: [ManagedNode]) {
        let all = applyingManualOrder(nodes.sorted { $0.order < $1.order }).map(\.id)
        let next = NodeManualOrder.spliced(all: all, sectionNew: sectionNew.map(\.id))
        guard next != manualOrder else { return }
        manualOrder = next
        NodeManualOrder.save(next)
    }

    func manualNode(_ n: ManagedNode) -> [String: Any]? {
        guard n.source.kind == .manual else { return nil }
        return manualByName[n.name] ?? manualByName[Self.strippedManualName(n.name)]
    }

    /// mergeManualNodes renames a manual node that collides with a profile node to "<name> (手动)".
    static func strippedManualName(_ name: String) -> String {
        name.hasSuffix(" (手动)") ? String(name.dropLast(5)) : name
    }

    // MARK: Loading

    func reload(force: Bool = false) async {
        loading = true
        defer { loading = false }
        let store = ProfileStore.shared
        let inspector = ProfileInspector.shared
        if force || inspector.profilePath != AppShared.activeProfileURL?.path || inspector.result.proxies.isEmpty {
            await inspector.load()
        }
        let r = inspector.result
        error = AppShared.activeProfileURL == nil ? nil : r.error

        // v0.19.6: read off the main actor (a few thousand manual nodes took a noticeable parse on every reload).
        let manualPath = store.manualProfile?.fileURL.path
        let manual = await Task.detached(priority: .userInitiated) { ProfileStore.manualNodes(path: manualPath) }.value
        manualByName = [:]
        for m in manual { if let n = m["name"] as? String { manualByName[n] = m } }
        let manualActive = store.activeID == ProfileStore.manualID
        let merge = CoreOverrides.load().mergeManual

        let profileSource = NodeSource(kind: .profile, name: store.active?.name ?? String(localized: "当前配置"), order: 0,
                                       updatedAt: store.active?.lastUpdated, remote: store.active?.kind == .remote)
        let manualSource = NodeSource(kind: .manual, name: String(localized: "手动节点"), order: 1)
        var srcs: [NodeSource] = []
        var out: [ManagedNode] = []
        var seen: Set<String> = []
        func add(_ n: ManagedNode) {
            guard !seen.contains(n.id) else { return }
            seen.insert(n.id)
            var n = n
            n.order = out.count
            out.append(n)
        }

        if AppShared.activeProfileURL != nil, !manualActive { srcs.append(profileSource) }
        srcs.append(manualSource)

        for p in r.proxies where !Self.isHidden(p.name, p.type) {
            let isManual = manualActive || (merge && manualByName[Self.strippedManualName(p.name)] != nil)
            add(ManagedNode(name: p.name, type: ManagedNode.normalize(p.type), server: p.server, port: p.port, udp: p.udp ?? false,
                            source: isManual ? manualSource : profileSource, inRuntime: true))
        }
        // Manual nodes the current profile does not include (merge off, or another profile active).
        // v0.19.6 (review 7): was `out.contains { … }` per manual node — O(manual × nodes) string work on the main
        // actor (2k manual + 3k profile nodes: millions of comparisons on every reload). One set lookup now.
        let manualInRuntime = Set(out.lazy.filter { $0.source.kind == .manual }.map { Self.strippedManualName($0.name) })
        for m in manual {
            guard let name = m["name"] as? String else { continue }
            if manualInRuntime.contains(name) { continue }
            add(ManagedNode(name: name, type: ManagedNode.normalize(m["type"] as? String ?? "?"), server: m["server"] as? String,
                            port: (m["port"] as? NSNumber)?.intValue ?? Int(m["port"] as? String ?? ""), udp: (m["udp"] as? Bool) ?? false,
                            source: manualSource, inRuntime: false))
        }

        let subs = NodeSubStore.shared.subs
        // hotfix/sub-disabled-nodes: 节点集 the user 停用 / 删除 and 停用 node subscriptions are not in the runtime. A core
        // that has not finished (or failed) its reload still serves them, so the live lists below skip them.
        let excluded = Self.excludedProviders(runtime: Set(r.proxyProviders.map(\.name)),
                                              overrides: ProviderOverrideStore.shared.overrides(manualActive ? nil : store.activeID),
                                              subs: subs)
        var order = 2
        for pv in r.proxyProviders {
            let sub = subs.first { s in (pv.path ?? "").contains("nodesubs/\(s.id).yaml") }
            let src = sub.map { NodeSource(kind: .subscription, name: $0.name, subID: $0.id, provider: pv.name, cached: pv.cached, order: order, updatedAt: pv.cachedDate) }
                ?? NodeSource(kind: .provider, name: pv.name, provider: pv.name, cached: pv.cached, order: order, updatedAt: pv.cachedDate)
            order += 1
            srcs.append(src)
            for p in pv.proxies ?? [] where !Self.isHidden(p.name, p.type) {
                add(ManagedNode(name: p.name, type: ManagedNode.normalize(p.type), server: p.server, port: p.port, udp: p.udp ?? false,
                                source: src, inRuntime: true))
            }
        }

        // Live data: providers that are not cached offline yet, and delays measured by the core.
        liveNames = []
        liveHistory = [:]
        liveGroups = [:]
        liveConnected = false
        if VPNManager.shared.isConnected, let proxies = try? await ControllerClient.shared.proxies() {
            liveConnected = true
            for (name, p) in proxies {
                if p.isGroup {
                    for m in p.all ?? [] { liveGroups[m, default: []].append(name) }
                } else if !Self.isHidden(name, p.type) {
                    liveNames.insert(name)
                    if let d = p.lastDelay(for: NodeSettingsStore.testURL(for: name)) { liveHistory[name] = d }
                }
            }
            for k in liveGroups.keys { liveGroups[k]?.sort() }
            let providers = (try? await ControllerClient.shared.proxyProviders()) ?? []
            var excludedNodes: Set<String> = []
            for pv in providers {
                if excluded.contains(pv.name) {
                    for p in pv.proxies ?? [] { excludedNodes.insert(p.name) }
                    continue
                }
                let src: NodeSource
                if let s = srcs.first(where: { ($0.kind == .provider || $0.kind == .subscription) && $0.runtimeProvider == pv.name }) {
                    src = s
                } else {
                    src = NodeSource(kind: .provider, name: pv.name, order: order)
                    order += 1
                    srcs.append(src)
                }
                for p in pv.proxies ?? [] where !Self.isHidden(p.name, p.type) {
                    if let d = p.lastDelay(for: NodeSettingsStore.testURL(for: p.name)) { liveHistory[p.name] = d }
                    add(ManagedNode(name: p.name, type: ManagedNode.normalize(p.type), server: nil, port: nil, udp: p.udp ?? false,
                                    source: src, inRuntime: true))
                }
            }
            for i in out.indices { out[i].live = liveNames.contains(out[i].name) }
            // The core may know nodes the offline view could not build (e.g. a runtime difference): list them under 配置.
            let known = Set(out.map(\.name))
            for name in liveNames.sorted() where !known.contains(name) && !excludedNodes.contains(name) {
                guard let p = proxies[name] else { continue }
                var n = ManagedNode(name: name, type: ManagedNode.normalize(p.type), server: nil, port: nil, udp: p.udp ?? false,
                                    source: manualActive ? manualSource : profileSource, inRuntime: true)
                n.live = true
                add(n)
            }
        }
        sources = srcs
        nodes = out
        let ids = Set(out.map(\.id))
        delays = delays.filter { ids.contains($0.key) }
    }

    /// hotfix/sub-disabled-nodes: provider names that must not be listed from the core: the profile's 节点集 that are
    /// 停用 / 删除 in the override store and 停用 node subscriptions — unless the current runtime (built from the profile
    /// with the overrides applied) still declares a provider of that name (e.g. a profile provider sharing the name).
    nonisolated static func excludedProviders(runtime: Set<String>, overrides: [String: ProviderOverride], subs: [NodeSubscription]) -> Set<String> {
        var out = Set(overrides.filter { $0.value.disabled == true || $0.value.deleted == true }.map(\.key))
        // r7: the old core build names a subscription's provider firstNonEmpty(trimmed name, "订阅") (mergeNodeSubs); an
        // unnamed disabled subscription was matched as "" and never excluded.
        out.formUnion(subs.filter { !$0.enabled }.map {
            let n = $0.name.trimmingCharacters(in: .whitespaces)
            return n.isEmpty ? "订阅" : n
        })
        out.subtract(runtime)
        out.remove("")
        return out
    }

    func source(_ kind: NodeSourceKind) -> NodeSource? { sources.first { $0.kind == kind } }
    func source(subID: String) -> NodeSource? { sources.first { $0.subID == subID } }
    func count(_ src: NodeSource) -> Int { countBySource[src] ?? 0 }

    static func isHidden(_ name: String, _ type: String) -> Bool {
        ManagedNode.hidden.contains(name) || ManagedNode.nonNodeTypes.contains(type.lowercased())
    }

    /// Groups whose members include the node (live when connected, otherwise the offline view).
    func groups(containing n: ManagedNode) -> [String] {
        if liveConnected, let g = liveGroups[n.name] { return g.filter { !ManagedNode.hidden.contains($0) } }
        let ins = ProfileInspector.shared
        guard n.inRuntime else { return [] }
        return ins.result.groups.filter { ins.members(of: $0).contains(n.name) }.map(\.name)
    }

    // MARK: Summary

    func summary(of n: ManagedNode) async -> NodeSummaryInfo? {
        let json: String
        if !n.inRuntime, let m = manualNode(n), let d = try? JSONSerialization.data(withJSONObject: m), let s = String(data: d, encoding: .utf8) {
            json = await Task.detached(priority: .userInitiated) { NCNodeManager.nodeSummaryJSON(s) }.value
        } else if let path = AppShared.activeProfileURL?.path {
            let home = AppShared.homeURL.path
            let name = n.name, provider = n.source.runtimeProvider
            json = await Task.detached(priority: .userInitiated) { NCNodeManager.nodeSummaryIn(home: home, profilePath: path, provider: provider, name: name) }.value
        } else {
            return nil
        }
        return try? JSONDecoder().decode(NodeSummaryInfo.self, from: Data(json.utf8))
    }

    // MARK: Latency

    /// One node: through the core when it knows the node, otherwise directly from the app.
    func test(_ n: ManagedNode) async {
        guard !testing.contains(n.id) else { return }
        testing.insert(n.id)
        defer { testing.remove(n.id) }
        delays[n.id] = await measure(n)
    }

    private func measure(_ n: ManagedNode) async -> Int {
        if liveConnected, liveNames.contains(n.name) {
            // R7A-4: test the node under its own provider (a same-named node of another subscription is not it).
            let prov = n.source.runtimeProvider
            if let ms = try? await ControllerClient.shared.proxyDelay(n.name, provider: prov.isEmpty ? nil : prov, resolved: prov.isEmpty) { return max(ms, 0) }
            return 0
        }
        let st = ControllerClient.testSettings
        let url = NodeSettingsStore.testURL(for: n.name), timeout = st.timeoutMs
        let tcp = ControllerClient.tcpHandshake
        await bindOfflineInterface()
        if n.inRuntime, let path = AppShared.activeProfileURL?.path {
            let home = AppShared.homeURL.path
            let name = n.name, provider = n.source.runtimeProvider
            let ms = await BlockingWork.run {
                tcp ? NCDelayTester.nodeTCPDelayIn(homeDir: home, profilePath: path, provider: provider, name: name, url: url, timeoutMs: timeout)
                    : NCDelayTester.nodeTestDelayIn(homeDir: home, profilePath: path, provider: provider, name: name, url: url, timeoutMs: timeout)
            }
            return max(ms, 0)
        }
        if let m = manualNode(n), let d = try? JSONSerialization.data(withJSONObject: m), let s = String(data: d, encoding: .utf8) {
            let ms = await BlockingWork.run {
                tcp ? NCDelayTester.testTCPDelay(proxyJSON: s, url: url, timeoutMs: timeout)
                    : NCDelayTester.testDelay(proxyJSON: s, url: url, timeoutMs: timeout)
            }
            return max(ms, 0)
        }
        return 0
    }

    /// selftest: offline tests here never bound to Wi-Fi / cellular (only 策略's offline test did, v0.15.2), so
    /// with another app's VPN up (QX while ours is off) 节点管理 measured through that VPN again — the latency
    /// the v0.15.2 hotfix removed. The interface is looked up at most every 30 s and shared by a bulk run.
    private var ifaceCheckedAt: Date?
    private var ifaceLookup: Task<Void, Never>?

    private func bindOfflineInterface() async {
        if let t = ifaceCheckedAt, Date().timeIntervalSince(t) < 30 { return }
        if let running = ifaceLookup { await running.value; return }
        let task = Task {
            let iface = await PhysicalInterface.current() ?? ""
            NCDelayTester.setOfflineInterface(iface)
        }
        ifaceLookup = task
        await task.value
        ifaceLookup = nil
        ifaceCheckedAt = Date()
    }

    /// 全部测速: `list` in order, at most `concurrency` at a time; cancel with stopAll().
    func testAll(_ list: [ManagedNode]) {
        guard bulkTask == nil, !list.isEmpty else { return }
        bulk = (0, list.count)
        bulkTask = Task { [weak self] in
            guard let self else { return }
            await withTaskGroup(of: Void.self) { tg in
                var next = 0
                while next < min(Self.concurrency, list.count) {
                    let n = list[next]
                    next += 1
                    tg.addTask { await self.test(n) }
                }
                while await tg.next() != nil {
                    if let b = self.bulk { self.bulk = (b.done + 1, b.total) }
                    if next < list.count, !Task.isCancelled {
                        let n = list[next]
                        next += 1
                        tg.addTask { await self.test(n) }
                    }
                }
            }
            self.bulk = nil
            self.bulkTask = nil
        }
    }

    func stopAll() {
        bulkTask?.cancel()
    }

    // MARK: Manual node actions

    func duplicate(_ n: ManagedNode) async throws {
        guard var m = manualNode(n) else { return }
        let base = (m["name"] as? String) ?? n.name
        var name = String(localized: "\(base) 副本")
        var i = 2
        while manualByName[name] != nil {
            name = String(localized: "\(base) 副本 \(i)")
            i += 1
        }
        m["name"] = name
        try await ProfileStore.shared.upsertManualNode(m, oldName: nil)
        await reload()
    }

    func manualNode(named name: String) -> [String: Any]? { manualByName[name] }

    // MARK: Full config (hotfix/node-cred-reveal)

    /// The node's full config, secrets included: only for 显示 / 复制 of one credential on the detail page and
    /// for 添加到本地节点. Never logged, never kept beyond the caller.
    func config(of n: ManagedNode) async -> [String: Any]? {
        if let m = manualNode(n) { return m }
        guard let path = AppShared.activeProfileURL?.path else { return nil }
        let home = AppShared.homeURL.path, name = n.name, provider = n.source.runtimeProvider
        let json = await Task.detached(priority: .userInitiated) { NCNodeManager.nodeConfigIn(home: home, profilePath: path, provider: provider, name: name) }.value
        guard !json.isEmpty, let o = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else { return nil }
        return o
    }

    /// One credential from a node config; `path` is a key of NodeSummaryInfo.credentials, either top level
    /// ("uuid") or dotted into option maps / arrays ("reality-opts.public-key", "peers.0.pre-shared-key").
    nonisolated static func credentialValue(_ node: [String: Any], path: String) -> String? {
        var cur: Any? = node[path]
        if cur == nil, path.contains(".") {
            cur = node
            for part in path.split(separator: ".").map(String.init) {
                if let d = cur as? [String: Any] { cur = d[part] }
                else if let a = cur as? [Any], let i = Int(part), a.indices.contains(i) { cur = a[i] }
                else { return nil }
            }
        }
        switch cur {
        case let s as String: return s.isEmpty ? nil : s
        case let n as NSNumber: return n.stringValue
        default: return nil
        }
    }

    /// A name no node of the current view uses: `base`, else 「base 副本」, 「base 副本 2」, … (the core keys
    /// /proxies by name, so a copy never shares a name with the subscription node it came from).
    nonisolated static func localCopyName(_ base: String, taken: Set<String>) -> String {
        if !taken.contains(base) { return base }
        var name = String(localized: "\(base) 副本")
        var i = 2
        while taken.contains(name) {
            name = String(localized: "\(base) 副本 \(i)")
            i += 1
        }
        return name
    }

    enum CopyError: LocalizedError {
        case notFound
        var errorDescription: String? { String(localized: "读取节点信息失败") }
    }

    /// 添加到本地节点: copies a subscription / provider node (every field, secrets unchanged) into the manual
    /// nodes as an editable node. Returns the new name.
    @discardableResult
    func addToLocal(_ n: ManagedNode) async throws -> String {
        guard var m = await config(of: n) else { throw CopyError.notFound }
        let base = (m["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? n.name
        let name = Self.localCopyName(base, taken: Set(manualByName.keys).union(nodes.map(\.name)))
        m["name"] = name
        try await ProfileStore.shared.upsertManualNode(m, oldName: nil)
        await reload(force: true)
        return name
    }

    /// Deletes a manual node. For WARP nodes, also cleans up the Cloudflare device registration.
    /// - Returns: A warning message if WARP unregister failed (nil on success or non-WARP node).
    @discardableResult
    func delete(_ n: ManagedNode) async -> String? {
        guard let m = manualNode(n), let name = m["name"] as? String else { return nil }
        await ProfileStore.shared.deleteManualNode(name)
        let warning = await WarpNodeLifecycle.deleteCleanup(nodeName: name)
        await reload()
        return warning
    }
}


/// v0.19.3: runs a blocking call (an offline delay test waits on the network for up to the test timeout)
/// on its own GCD queue instead of Swift's cooperative pool. Task.detached / task-group children still use
/// that pool, which has only as many threads as CPU cores: 8 (节点) or 6 (策略) blocked tests stalled every
/// other async task in the app (loads, downloads, UI refreshes) until the tests returned.
enum BlockingWork {
    private static let queue = DispatchQueue(label: "tern.blocking-work", qos: .userInitiated, attributes: .concurrent)

    static func run<T>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { c in
            queue.async { c.resume(returning: work()) }
        }
    }
}
