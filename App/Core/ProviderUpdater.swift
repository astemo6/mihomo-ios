import Foundation
import Libmihomo

/// One HTTP provider of the active profile the app can download itself (bridge ProviderPlan).
struct ProviderTask: Decodable, Identifiable, Hashable {
    var kind: String      // rule | proxy
    var name: String
    var url: String       // download URL (mirrored when the GitHub mirror is on)
    var source: String    // shown to the user
    var convert: String   // list | domainset | nodes | ""
    var format: String?
    var path: String
    var interval: Int
    var updated: Double
    var id: String { kind + ":" + name }
}

/// v0.8.1: rule sets and node providers are downloaded by the app (URLSession — works while
/// disconnected, and through the tunnel when connected), converted like the core's converter would and
/// written to the cache file the profile's `path:` points to. The core loads that file at start and then
/// refreshes from the source on its interval.
@MainActor
final class ProviderUpdater: ObservableObject {
    static let shared = ProviderUpdater()

    @Published private(set) var running = false
    @Published private(set) var done = 0
    @Published private(set) var total = 0
    @Published private(set) var busy: Set<String> = []
    /// Last error per task id ("rule:Name"); cleared on success.
    @Published private(set) var errors: [String: String] = [:]

    struct Result { var ok = 0; var failed = 0 }

    nonisolated static func plan(profilePath: String) -> [ProviderTask] {
        let json = LibmihomoProviderPlan(AppShared.homeURL.path, profilePath)
        return (try? JSONDecoder().decode([ProviderTask].self, from: Data(json.utf8))) ?? []
    }

    /// Downloads every provider of `profile` (default: the active one). `only` limits it to task ids.
    @discardableResult
    func updateAll(profile: Profile? = nil, only: Set<String>? = nil) async -> Result {
        guard !running, let p = profile ?? ProfileStore.shared.active else { return Result() }
        let path = p.fileURL.path
        var tasks = await Task.detached(priority: .userInitiated) { Self.plan(profilePath: path) }.value
        if let only { tasks = tasks.filter { only.contains($0.id) } }
        guard !tasks.isEmpty else { return Result() }
        running = true
        done = 0
        total = tasks.count
        defer { running = false }
        var res = Result()
        // Four at a time: enough to be quick, polite to GitHub and the CDN mirrors.
        var idx = 0
        while idx < tasks.count {
            let batch = Array(tasks[idx..<min(idx + 4, tasks.count)])
            idx += batch.count
            for t in batch { busy.insert(t.id) }
            let outcomes = await withTaskGroup(of: (String, String?).self) { g -> [(String, String?)] in
                for t in batch { g.addTask { (t.id, await Self.run(t)) } }
                var out: [(String, String?)] = []
                for await o in g { out.append(o) }
                return out
            }
            for (id, err) in outcomes {
                busy.remove(id)
                done += 1
                if let err { errors[id] = err; res.failed += 1 } else { errors[id] = nil; res.ok += 1 }
            }
        }
        await ProfileInspector.shared.load()
        // User 2026-10-22 「不管是订阅还是节点，有更新后自动更新配置文件」: a fresh download takes effect right away.
        if res.ok > 0, VPNManager.shared.isConnected, p.id == ProfileStore.shared.activeID {
            _ = await VPNManager.shared.reload()
        }
        return res
    }

    private var lastDueCheck = Date.distantPast

    /// The active profile's rule sets / node sets whose cache is older than their interval (default one day).
    /// While connected the core refreshes them on its own interval, so this runs only when disconnected.
    func autoUpdateIfNeeded() async {
        guard !running, !VPNManager.shared.isConnected, Date().timeIntervalSince(lastDueCheck) > 600,
              let p = ProfileStore.shared.active else { return }
        lastDueCheck = Date()
        let path = p.fileURL.path
        let tasks = await Task.detached(priority: .utility) { Self.plan(profilePath: path) }.value
        let now = Date().timeIntervalSince1970
        let due = tasks.filter { now - $0.updated >= Double($0.interval > 0 ? $0.interval : 86400) }
        if !due.isEmpty { await updateAll(profile: p, only: Set(due.map(\.id))) }
    }

    func update(_ id: String) async {
        await updateAll(only: [id])
    }

    /// Download + convert + write. Returns an error text or nil.
    nonisolated static func run(_ t: ProviderTask) async -> String? {
        guard let u = URL(string: t.url), u.scheme?.hasPrefix("http") == true else { return String(localized: "链接无效") }
        var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue(t.kind == "proxy" ? "clash.meta" : "clash.meta mihomo-ios", forHTTPHeaderField: "User-Agent")
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) {
                return String(localized: "下载失败：HTTP \(h.statusCode)")
            }
            let out = LibmihomoProviderStore(AppShared.homeURL.path, t.kind, t.path, t.convert, data)
            struct R: Decodable { var count: Int; var error: String }
            guard let r = try? JSONDecoder().decode(R.self, from: Data(out.utf8)) else { return String(localized: "写入失败") }
            return r.error.isEmpty ? nil : r.error
        } catch {
            return error.localizedDescription
        }
    }
}
