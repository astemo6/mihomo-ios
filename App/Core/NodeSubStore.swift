import Foundation
import Libmihomo

/// 订阅管理 (v0.9): a node-only subscription. Stored in <home>/node-subscriptions.json (the bridge reads
/// id / name / url / enabled / groups and merges each enabled one into every profile as a proxy-provider);
/// the app downloads it into <home>/nodesubs/<id>.yaml.
struct NodeSubscription: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String
    var url: String
    var enabled: Bool = true
    /// Groups that get it through `use:`; nil = the default (select groups with nodes + url-test groups).
    var groups: [String]? = nil
    var userAgent: String = "clash.meta"
    var updateIntervalHours: Int = 24
    var lastUpdated: Date? = nil
    var userInfo: SubscriptionUserInfo? = nil
    var count: Int? = nil
    var lastError: String? = nil
    /// feat/subs-split: 图标 (an image URL, "sf:<symbol>" or an emoji, like group-icons.json); nil = the default.
    var icon: String? = nil

    var cacheURL: URL { AppShared.homeURL.appendingPathComponent("nodesubs/\(id).yaml") }
    var rulesKey: String { "nodesub-" + id }
}

@MainActor
final class NodeSubStore: ObservableObject {
    static let shared = NodeSubStore()

    @Published private(set) var subs: [NodeSubscription] = []
    @Published var updating: Set<String> = []

    static var url: URL { AppShared.homeURL.appendingPathComponent("node-subscriptions.json") }

    init() { load() }

    func load() {
        if let d = try? Data(contentsOf: Self.url), let l = try? JSONDecoder().decode([NodeSubscription].self, from: d) { subs = l }
    }

    private func persist() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(subs) { try? d.write(to: Self.url, options: .atomic) }
    }

    private func set(_ s: NodeSubscription) {
        if let i = subs.firstIndex(where: { $0.id == s.id }) { subs[i] = s } else { subs.append(s) }
        persist()
    }

    /// Adds and downloads a subscription; throws when the first download fails (nothing is kept then).
    func add(url: String, name: String, userAgent: String, intervalHours: Int, groups: [String]?) async throws -> NodeSubscription {
        var s = NodeSubscription(name: name.trimmingCharacters(in: .whitespaces), url: url.trimmingCharacters(in: .whitespacesAndNewlines),
                                 groups: groups, userAgent: userAgent.isEmpty ? "clash.meta" : userAgent, updateIntervalHours: intervalHours)
        s = try await download(s)
        set(s)
        UsageAlerts.evaluate(id: s.id, name: s.name, info: s.userInfo)
        await applyChange()
        return s
    }

    func save(_ s: NodeSubscription) async {
        SnapshotStore.shared.capture(String(localized: "修改节点订阅前"))
        let oldName = subs.first(where: { $0.id == s.id })?.name
        set(s)
        if let oldName, oldName != s.name { RegionFilterStore.renameSource(oldName, to: s.name) }
        await applyChange()
    }

    /// feat/subs-split: 图标 only — display, so no reload of the core.
    func setIcon(_ id: String, _ icon: String?) {
        guard var s = subs.first(where: { $0.id == id }) else { return }
        s.icon = icon
        set(s)
    }

    func delete(_ s: NodeSubscription) async {
        try? FileManager.default.removeItem(at: s.cacheURL)
        SubRulesStore.set(s.rulesKey, nil)
        UsageAlerts.remove(s.id)
        subs.removeAll { $0.id == s.id }
        persist()
        RegionFilterStore.renameSource(s.name, to: nil)
        await applyChange()
    }

    /// Returns an error text, nil on success.
    @discardableResult
    func refresh(_ s: NodeSubscription, reload: Bool = true) async -> String? {
        guard !updating.contains(s.id) else { return nil } // v0.19.2: one download per subscription at a time
        updating.insert(s.id)
        defer { updating.remove(s.id) }
        do {
            let d = try await download(s)
            // v0.19.2: merge the download into the entry as it is now. set(<copy from before the download>) undid
            // edits made meanwhile and re-added a subscription the user deleted during the download (with its
            // freshly written cache file).
            guard var n = subs.first(where: { $0.id == s.id }) else {
                try? FileManager.default.removeItem(at: s.cacheURL)
                return nil
            }
            n.count = d.count
            n.userInfo = d.userInfo
            n.lastUpdated = d.lastUpdated
            n.lastError = nil
            if n.name.isEmpty { n.name = d.name }
            set(n)
            UsageAlerts.evaluate(id: n.id, name: n.name, info: n.userInfo)
            if reload { await applyChange() }
            return nil
        } catch {
            guard var e = subs.first(where: { $0.id == s.id }) else { return error.localizedDescription }
            e.lastError = error.localizedDescription
            set(e)
            return error.localizedDescription
        }
    }

    func refreshAll() async -> [String] {
        var errs: [String] = []
        for s in subs where s.enabled {
            if let e = await refresh(s, reload: false) { errs.append("\(s.name)：\(e)") }
        }
        await applyChange()
        return errs
    }

    @discardableResult
    func autoUpdateIfNeeded() async -> [SubUpdateResult] {
        var changed = false
        var out: [SubUpdateResult] = []
        for s in subs where s.enabled && s.updateIntervalHours > 0 {
            let due = (s.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(s.updateIntervalHours * 3600))
            guard due < Date() else { continue }
            let e = await refresh(s, reload: false)
            if e == nil { changed = true }
            out.append(SubUpdateResult(name: s.name, error: e, oldCount: s.count, newCount: subs.first { $0.id == s.id }?.count))
        }
        if changed { await applyChange() }
        return out
    }

    private func download(_ input: NodeSubscription) async throws -> NodeSubscription {
        var s = input
        guard let u = URL(string: s.url), u.scheme?.hasPrefix("http") == true else { throw ProfileStore.StoreError.badURL }
        var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue(s.userAgent, forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        let http = resp as? HTTPURLResponse
        if let c = http?.statusCode, !(200..<300).contains(c) { throw ProfileStore.StoreError.http(c) }
        let path = s.cacheURL.path
        let out = await Task.detached(priority: .userInitiated) {
            LibmihomoProviderStore(AppShared.homeURL.path, "proxy", path, "nodes", data)
        }.value
        struct R: Decodable { var count: Int; var error: String }
        guard let r = try? JSONDecoder().decode(R.self, from: Data(out.utf8)) else { throw ProfileStore.StoreError.empty }
        if !r.error.isEmpty { throw ProfileStore.StoreError.invalid(r.error) }
        s.count = r.count
        s.userInfo = SubscriptionUserInfo.parse(http?.value(forHTTPHeaderField: "subscription-userinfo")) ?? s.userInfo
        if s.name.isEmpty { s.name = ProfileStore.nameFromHeaders(http) ?? u.host ?? String(localized: "订阅") }
        s.lastUpdated = Date()
        s.lastError = nil
        return s
    }

    /// Node subscriptions apply to every profile: reload a running tunnel and refresh the offline view.
    private func applyChange() async {
        if VPNManager.shared.isConnected { _ = await VPNManager.shared.reload() }
        await ProfileInspector.shared.load()
    }
}
