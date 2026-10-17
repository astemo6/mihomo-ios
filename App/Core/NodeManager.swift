import Foundation
import Libmihomo

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
    /// Provider vehicle ("http" / "file" / "inline") and whether its nodes are on disk (offline view).
    var cached: Bool = true
    var order: Int = 0
    /// Provider cache time (offline view); the active profile is a remote subscription (.profile).
    var updatedAt: Date? = nil
    var remote: Bool = false

    var id: String { "\(kind.rawValue):\(subID ?? name)" }

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

/// Summary of one node from bridge/nodemanager.go (no secret values).
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

    @Published private(set) var nodes: [ManagedNode] = []
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

        let manual = store.manualNodes()
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
        for m in manual {
            guard let name = m["name"] as? String else { continue }
            let inRuntime = out.contains { $0.source.kind == .manual && Self.strippedManualName($0.name) == name }
            if inRuntime { continue }
            add(ManagedNode(name: name, type: ManagedNode.normalize(m["type"] as? String ?? "?"), server: m["server"] as? String,
                            port: (m["port"] as? NSNumber)?.intValue ?? Int(m["port"] as? String ?? ""), udp: (m["udp"] as? Bool) ?? false,
                            source: manualSource, inRuntime: false))
        }

        let subs = NodeSubStore.shared.subs
        var order = 2
        for pv in r.proxyProviders {
            let sub = subs.first { s in (pv.path ?? "").contains("nodesubs/\(s.id).yaml") }
            let src = sub.map { NodeSource(kind: .subscription, name: $0.name, subID: $0.id, cached: pv.cached, order: order, updatedAt: pv.cachedDate) }
                ?? NodeSource(kind: .provider, name: pv.name, cached: pv.cached, order: order, updatedAt: pv.cachedDate)
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
            for pv in providers {
                let src: NodeSource
                if let s = srcs.first(where: { ($0.kind == .provider || $0.kind == .subscription) && $0.name == pv.name }) {
                    src = s
                } else {
                    src = NodeSource(kind: .provider, name: pv.name, order: order)
                    order += 1
                    srcs.append(src)
                }
                for p in pv.proxies ?? [] where !Self.isHidden(p.name, p.type) {
                    if let d = p.lastDelay(for: url) { liveHistory[p.name] = d }
                    add(ManagedNode(name: p.name, type: ManagedNode.normalize(p.type), server: nil, port: nil, udp: p.udp ?? false,
                                    source: src, inRuntime: true))
                }
            }
            for i in out.indices { out[i].live = liveNames.contains(out[i].name) }
            // The core may know nodes the offline view could not build (e.g. a runtime difference): list them under 配置.
            let known = Set(out.map(\.name))
            for name in liveNames.sorted() where !known.contains(name) {
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

    func source(_ kind: NodeSourceKind) -> NodeSource? { sources.first { $0.kind == kind } }
    func source(subID: String) -> NodeSource? { sources.first { $0.subID == subID } }
    func count(_ src: NodeSource) -> Int { nodes.filter { $0.source == src }.count }

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
            json = await Task.detached(priority: .userInitiated) { LibmihomoNodeSummaryJSON(s) }.value
        } else if let path = AppShared.activeProfileURL?.path {
            let home = AppShared.homeURL.path
            let name = n.name
            json = await Task.detached(priority: .userInitiated) { LibmihomoNodeSummary(home, path, name) }.value
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
            if let ms = try? await ControllerClient.shared.proxyDelay(n.name) { return max(ms, 0) }
            return 0
        }
        let st = ControllerClient.testSettings
        let url = NodeSettingsStore.testURL(for: n.name), timeout = st.timeoutMs
        await bindOfflineInterface()
        if n.inRuntime, let path = AppShared.activeProfileURL?.path {
            let home = AppShared.homeURL.path
            let name = n.name
            let ms = await Task.detached(priority: .userInitiated) { LibmihomoNodeTestDelay(home, path, name, url, timeout) }.value
            return max(ms, 0)
        }
        if let m = manualNode(n), let d = try? JSONSerialization.data(withJSONObject: m), let s = String(data: d, encoding: .utf8) {
            let ms = await Task.detached(priority: .userInitiated) { LibmihomoTestDelay(s, url, timeout) }.value
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
            LibmihomoSetOfflineTestInterface(await PhysicalInterface.current() ?? "")
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

    func delete(_ n: ManagedNode) async {
        guard let m = manualNode(n), let name = m["name"] as? String else { return }
        await ProfileStore.shared.deleteManualNode(name)
        await reload()
    }
}
