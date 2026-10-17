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

    @Published private(set) var result = InspectResult()
    @Published private(set) var loading = false
    @Published private(set) var profilePath: String?
    @Published var delays: [String: Int] = [:]
    @Published var testing: Set<String> = []

    /// Every node known offline: profile proxies + cached provider nodes (+ built-ins).
    var nodeIndex: [String: InspectProxy] {
        var out: [String: InspectProxy] = [:]
        for p in result.proxies { out[p.name] = p }
        for pv in result.proxyProviders { for p in pv.proxies ?? [] where out[p.name] == nil { out[p.name] = p } }
        out["DIRECT"] = out["DIRECT"] ?? InspectProxy(name: "DIRECT", type: "direct")
        out["REJECT"] = out["REJECT"] ?? InspectProxy(name: "REJECT", type: "reject")
        return out
    }

    /// Members of a group as the core would list them: explicit proxies, then nodes from `use` providers.
    func members(of g: InspectGroup) -> [String] {
        if let m = g.members { return m }
        var out = g.proxies
        let re = g.filter.flatMap { try? NSRegularExpression(pattern: $0) }
        for name in g.use {
            guard let pv = result.proxyProviders.first(where: { $0.name == name }) else { continue }
            for p in pv.proxies ?? [] where !out.contains(p.name) {
                if let re, re.firstMatch(in: p.name, range: NSRange(p.name.startIndex..., in: p.name)) == nil { continue }
                out.append(p.name)
            }
        }
        return out
    }

    struct GroupPreviewItem: Decodable {
        var members: [String]?
        var empty: Bool?
        var error: String?
    }
    private struct GroupPreviewResult: Decodable {
        var groups: [GroupPreviewItem]?
        var error: String?
    }

    /// B16: members the core would give each draft group in the active profile (bridge GroupPreview, the
    /// same expansion as the inspector), for 策略组编辑 previews and 筛选节点 counts. nil on failure.
    func preview(_ specs: [GroupSpec]) async -> [GroupPreviewItem]? {
        guard let url = AppShared.activeProfileURL, let data = try? JSONEncoder().encode(specs) else { return nil }
        let json = String(decoding: data, as: UTF8.self)
        let home = AppShared.homeURL.path
        let path = url.path
        let out = await Task.detached(priority: .userInitiated) { LibmihomoGroupPreview(home, path, json) }.value
        guard let r = try? JSONDecoder().decode(GroupPreviewResult.self, from: Data(out.utf8)), r.error == nil,
              let g = r.groups, g.count == specs.count else { return nil }
        return g
    }

    func current(of g: InspectGroup) -> String? {
        if let s = g.selected ?? result.selected[g.name], members(of: g).contains(s) { return s }
        return members(of: g).first
    }

    func load() async {
        guard let url = AppShared.activeProfileURL else {
            result = InspectResult()
            profilePath = nil
            return
        }
        loading = true
        defer { loading = false }
        let home = AppShared.homeURL.path
        let path = url.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoInspectProfile(home, path) }.value
        if let r = try? JSONDecoder().decode(InspectResult.self, from: Data(json.utf8)) {
            result = r
        } else {
            var r = InspectResult()
            r.error = "无法读取配置"
            result = r
        }
        if profilePath != path { delays = [:] }
        profilePath = path
    }

    /// Saves group → node for the active profile; applied by the core on the next connect.
    func select(group: String, node: String) {
        guard let path = profilePath ?? AppShared.activeProfileURL?.path else { return }
        let err = LibmihomoSaveSelection(path, group, node)
        if err.isEmpty, let i = result.groups.firstIndex(where: { $0.name == group }) {
            result.groups[i].selected = node
            result.selected[group] = node
        }
    }

    /// Delay test without the tunnel (direct from the app), group members in parallel (6 at a time).
    func test(group g: InspectGroup) async {
        guard let path = profilePath else { return }
        testing.insert(g.name)
        defer { testing.remove(g.name) }
        let home = AppShared.homeURL.path
        // The 测速 setting, not the group's own URL: manual tests use one URL everywhere (live too).
        let st = ControllerClient.testSettings
        let url = st.url
        let timeout = st.timeoutMs
        let names = members(of: g).filter { nodeIndex[$0] != nil && !["DIRECT", "REJECT"].contains($0) }
        // v0.15.2: bind the test sockets to Wi-Fi / cellular so another app's VPN (QX, Surge …) that is up
        // while ours is off does not carry the test through its own node too. The core falls back to
        // normal routing when the bind fails.
        LibmihomoSetOfflineTestInterface(await PhysicalInterface.current() ?? "")
        var idx = 0
        while idx < names.count {
            let batch = Array(names[idx..<min(idx + 6, names.count)])
            idx += batch.count
            let got = await withTaskGroup(of: (String, Int).self, returning: [(String, Int)].self) { tg in
                for n in batch {
                    tg.addTask { (n, Int(LibmihomoTestDelayByName(home, path, n, url, timeout))) }
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
