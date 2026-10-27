import Foundation

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
    /// fix/nc-open-6-10 #10: provider `header` User-Agent (nil = the default below).
    var userAgent: String? = nil
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

    /// fix/nc-ruleset-fast: `changed` = downloads that wrote new content (a 304 / identical body is ok but unchanged).
    struct Result { var ok = 0; var failed = 0; var changed = 0 }

    /// fix/nc-ruleset-fast: downloads in flight at once (a sliding window, not batches that wait for their slowest).
    nonisolated static let maxConcurrent = 6

    nonisolated static func plan(profilePath: String) -> [ProviderTask] {
        let json = NCProviderPorts.providerPlan(home: AppShared.homeURL.path, profilePath: profilePath)
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
        // fix/nc-ruleset-fast: six in flight, the next one starts as soon as any finishes (was: batches of four, each
        // waiting for its slowest list). Conversion runs inside each task, off the main actor.
        await withTaskGroup(of: (String, Outcome).self) { g in
            var next = 0
            while next < min(Self.maxConcurrent, tasks.count) {
                let t = tasks[next]
                next += 1
                busy.insert(t.id)
                g.addTask { (t.id, await Self.run(t)) }
            }
            while let r = await g.next() {
                let id = r.0
                busy.remove(id)
                done += 1
                switch r.1 {
                case .failed(let err): errors[id] = err; res.failed += 1
                case .unchanged: errors[id] = nil; res.ok += 1
                case .changed: errors[id] = nil; res.ok += 1; res.changed += 1
                }
                if next < tasks.count {
                    let t = tasks[next]
                    next += 1
                    busy.insert(t.id)
                    g.addTask { (t.id, await Self.run(t)) }
                }
            }
        }
        await ProfileInspector.shared.load()
        // User 2026-10-22 「不管是订阅还是节点，有更新后自动更新配置文件」: a fresh download takes effect right away.
        // fix/nc-ruleset-fast: only when a list really changed — 304s / identical bodies need no tunnel reload.
        if res.changed > 0, VPNManager.shared.isConnected, p.id == ProfileStore.shared.activeID {
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

    enum Outcome: Sendable { case changed, unchanged, failed(String) }

    /// Download + convert + write. fix/nc-ruleset-fast: conditional GET against the cache file (ETag /
    /// Last-Modified sidecar, NCConditionalFetch); a 304 or a byte-identical body keeps the cache untouched (only its
    /// 「更新于」 time moves) and is not converted again.
    nonisolated static func run(_ t: ProviderTask) async -> Outcome {
        let cache = URL(fileURLWithPath: t.path)
        let ua = t.userAgent ?? (t.kind == "proxy" ? "clash.meta" : "clash.meta Tern")
        switch await NCConditionalFetch.fetch(t.url, cache: cache, userAgent: ua) {
        case .unchanged:
            return .unchanged
        case .failed(let e):
            if e == "链接无效" { return .failed(String(localized: "链接无效")) }
            if e.hasPrefix("HTTP "), let code = Int(e.dropFirst(5)) { return .failed(String(localized: "下载失败：HTTP \(code)")) }
            return .failed(e)
        case .body(let data, let commit):
            let out = NCProviderPorts.providerStore(home: AppShared.homeURL.path, kind: t.kind, cachePath: t.path, convert: t.convert, data: data)
            struct R: Decodable { var count: Int; var error: String }
            guard let r = try? JSONDecoder().decode(R.self, from: Data(out.utf8)) else { return .failed(String(localized: "写入失败")) }
            guard r.error.isEmpty else { return .failed(r.error) }
            commit(cache)
            return .changed
        }
    }
}
