import Foundation

/// One row of the module & resource manager (bridge/resources.go ResourceItem).
struct ResourceItem: Decodable, Identifiable, Hashable {
    var key: String
    var kind: String          // module | ruleset | script
    var name: String
    var url: String
    var format: String?
    var enabled: Bool
    var readOnly: Bool?
    var interval: Int
    var updatedAt: Double
    var checkedAt: Double?
    var error: String?
    var owner: String?
    var detail: String?
    var refId: String?
    var listKind: String?

    var id: String { key }
    var isRemote: Bool { url.hasPrefix("http://") || url.hasPrefix("https://") }
    var isDue: Bool {
        guard isRemote, enabled else { return false }
        return updatedAt == 0 || Date().timeIntervalSince1970 - updatedAt >= Double(max(interval, 600))
    }
}

/// QX-style remote resources inside the single module manager: modules / rewrite sets, remote rule
/// sets and remote scripts, each with an interval, last update, enable toggle and last error.
/// Settings stay in their own stores (engine.json modules / scriptResources, rules.json); this class
/// downloads and hands the bytes to Go (ResourceStore), which validates, converts and writes the cache.
@MainActor
final class ResourceStore: ObservableObject {
    static let shared = ResourceStore()

    @Published var items: [ResourceItem] = []
    @Published var busy: Set<String> = []
    @Published var updatingAll = false
    @Published var message: String?

    static let intervals: [(String, Int)] = [("1 小时", 3600), ("6 小时", 21600), ("12 小时", 43200), ("1 天", 86400), ("3 天", 259200), ("7 天", 604800)]

    var home: String { AppShared.homeURL.path }

    nonisolated static func intervalText(_ s: Int) -> String {
        if s % 86400 == 0 { return String(localized: "\(s / 86400) 天") }
        if s % 3600 == 0 { return String(localized: "\(s / 3600) 小时") }
        return String(localized: "\(max(1, s / 60)) 分钟")
    }

    func reload() {
        let home = self.home
        let json = NCResourcesPort.resourceList(home: home)
        items = (try? JSONDecoder().decode([ResourceItem].self, from: Data(json.utf8))) ?? []
    }

    /// v0.19.8: reload() off the main thread (the Go side reads every module and resource file), for page opens.
    func reloadInBackground() async {
        let home = self.home
        let list = await Task.detached(priority: .userInitiated) { () -> [ResourceItem] in
            let json = NCResourcesPort.resourceList(home: home)
            return (try? JSONDecoder().decode([ResourceItem].self, from: Data(json.utf8))) ?? []
        }.value
        if items != list { items = list }
    }

    // MARK: settings (written to the store each resource belongs to)

    func setEnabled(_ it: ResourceItem, _ on: Bool) {
        switch it.kind {
        case "module":
            let es = EngineStore.shared
            if let i = es.config.modules.firstIndex(where: { $0.id == it.refId }) { es.config.modules[i].enabled = on; es.save() }
        case "ruleset":
            let rs = CustomRulesStore.shared
            if let i = rs.rules.firstIndex(where: { $0.id == it.refId }) { rs.rules[i].enabled = on; rs.save() }
        case "script":
            let es = EngineStore.shared
            var m = es.config.scriptResources ?? [:]
            var s = m[it.url] ?? ScriptResourceSetting()
            s.disabled = on ? nil : true
            m[it.url] = (s.disabled == nil && s.interval == nil) ? nil : s
            es.config.scriptResources = m.isEmpty ? nil : m
            es.save()
        default: break
        }
        reload()
    }

    func setInterval(_ it: ResourceItem, _ seconds: Int) {
        switch it.kind {
        case "module":
            let es = EngineStore.shared
            if let i = es.config.modules.firstIndex(where: { $0.id == it.refId }) { es.config.modules[i].interval = seconds; es.save(reload: false) }
        case "ruleset":
            let rs = CustomRulesStore.shared
            if let i = rs.rules.firstIndex(where: { $0.id == it.refId }) { rs.rules[i].interval = seconds; rs.save() }
        case "script":
            let es = EngineStore.shared
            var m = es.config.scriptResources ?? [:]
            var s = m[it.url] ?? ScriptResourceSetting()
            s.interval = seconds
            m[it.url] = s
            es.config.scriptResources = m
            es.save()
        default: break
        }
        reload()
    }

    // MARK: updates

    /// Downloads one resource. Returns true when the cache changed. Does not reload the tunnel.
    @discardableResult
    func download(_ it: ResourceItem) async -> Bool {
        guard it.isRemote else { return false }
        busy.insert(it.key)
        defer { busy.remove(it.key) }
        let home = self.home
        do {
            guard let u = URL(string: it.url) else { throw URLError(.badURL) }
            var req = URLRequest(url: u, timeoutInterval: 30)
            req.setValue(it.kind == "script" ? "Surge iOS/3000" : "Surge iOS/3000 Mihomo-iOS", forHTTPHeaderField: "User-Agent")
            let (data, resp) = try await URLSession.shared.data(for: req)
            if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) {
                NCResourcesPort.resourceSetError(home: home, key: it.key, message: "HTTP \(h.statusCode)")
                return false
            }
            let key = it.key
            let res = await Task.detached(priority: .utility) { NCResourcesPort.resourceStore(home: home, key: key, data: data) }.value
            struct R: Decodable { var ok: Bool; var error: String? }
            let r = try? JSONDecoder().decode(R.self, from: Data(res.utf8))
            if r?.ok == true, it.kind == "module" {
                let es = EngineStore.shared
                if let i = es.config.modules.firstIndex(where: { $0.id == it.refId }) {
                    es.config.modules[i].updatedAt = Date().timeIntervalSince1970
                    es.save(reload: false)
                }
            }
            return r?.ok == true
        } catch {
            NCResourcesPort.resourceSetError(home: home, key: it.key, message: error.localizedDescription)
            return false
        }
    }

    /// quiet (the automatic update when the app becomes active): a reload that timed out is not shown — nobody asked for
    /// it, the core goes on applying it, and an alert popping up over whatever page is open (fix/xmly-memory-2: over 脚本日志
    /// while 喜马拉雅 kept the extension memory-critical) only alarms. Real errors still show.
    private func finish(changed: Bool, quiet: Bool = false) async {
        EngineStore.shared.reparseModules()
        reload()
        if changed, VPNManager.shared.isConnected, let err = await VPNManager.shared.reload() {
            if quiet && err == VPNManager.reloadTimeoutMessage { return }
            message = String(localized: "重载失败：\(err)")
        }
    }

    /// One resource from the subscription sheet (立即更新 / save with a new address): returns the error text, nil
    /// when it downloaded; reloads the tunnel when the content changed.
    func refresh(key: String) async -> String? {
        reload()
        guard let it = items.first(where: { $0.key == key }) else { return String(localized: "找不到这个订阅") }
        let changed = await download(it)
        await finish(changed: changed)
        if let e = items.first(where: { $0.key == key })?.error, !e.isEmpty { return e }
        return nil
    }

    func update(_ it: ResourceItem) async {
        let changed = await download(it)
        await finish(changed: changed)
        if let e = items.first(where: { $0.key == it.key })?.error, !e.isEmpty { message = String(localized: "更新「\(it.name)」失败：\(e)") }
    }

    /// 任务 → 全部更新 (2026-10-23): downloads the given resources (the tasks' remote scripts) one after another and
    /// reloads the tunnel once when anything changed. Returns how many failed.
    @discardableResult
    func updateItems(_ list: [ResourceItem]) async -> Int {
        var changed = false
        for it in list where it.isRemote {
            if await download(it) { changed = true }
        }
        await finish(changed: changed)
        let keys = Set(list.map(\.key))
        return items.filter { keys.contains($0.key) && ($0.error ?? "").isEmpty == false }.count
    }

    /// Update all (enabled, remote) resources, or only the due ones. Modules first so newly referenced
    /// rule sets / scripts are listed for the second pass.
    func updateAll(onlyDue: Bool = false) async {
        guard !updatingAll else { return }
        updatingAll = true
        defer { updatingAll = false }
        reload()
        var changed = false
        for it in items where it.kind == "module" && it.enabled && it.isRemote && (!onlyDue || it.isDue) {
            if await download(it) { changed = true }
        }
        if changed { EngineStore.shared.reparseModules(); reload() }
        for it in items where it.kind != "module" && it.enabled && it.isRemote && (!onlyDue || it.isDue) {
            if await download(it) { changed = true }
        }
        await finish(changed: changed, quiet: onlyDue)
        if !onlyDue {
            let failed = items.filter { ($0.error ?? "").isEmpty == false && $0.enabled }
            message = failed.isEmpty ? "已全部更新" : "\(failed.count) 项更新失败，详见列表"
        }
    }

    private var lastDueCheck = Date.distantPast

    /// Called when the app becomes active (at most every 10 minutes).
    func updateDueIfNeeded() async {
        guard Date().timeIntervalSince(lastDueCheck) > 600 else { return }
        lastDueCheck = Date()
        await updateAll(onlyDue: true)
    }
}
