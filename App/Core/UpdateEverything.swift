import Foundation

/// 工具 → top-right 「全部更新」 (user 2026-10-23: 「在工具最上方右侧加一个一键更新所有的按钮」): one tap updates every
/// remote resource — 配置订阅, 节点订阅, the profile's 节点集 / 规则集, modules with their scripts and rule lists.
/// Each still goes through the store that owns it, so nothing downloads differently from its own page.
@MainActor
final class UpdateEverything: ObservableObject {
    static let shared = UpdateEverything()
    @Published private(set) var running = false

    /// Returns a one-line result for an alert.
    /// fix/nc-ruleset-fast: 配置订阅 first (a new profile decides which providers there are), then 节点订阅, 模块与资源 and
    /// the profile's 节点集 / 规则集 run side by side instead of one after another — each store still reports its own
    /// per-item progress (busy / done) and still downloads exactly as from its own page. Tunnel reloads they ask for
    /// are coalesced by VPNManager.reload.
    func run() async -> String {
        guard !running else { return String(localized: "正在更新…") }
        running = true
        defer { running = false }
        var failed = await ProfileStore.shared.refreshAll().count
        async let nodes = updateNodeSubs()
        async let resources = updateResources()
        async let providers = updateProviders()
        failed += await nodes + resources + providers
        return failed == 0 ? String(localized: "已全部更新") : String(localized: "\(failed) 项更新失败，可在对应页面查看")
    }

    private func updateNodeSubs() async -> Int {
        await NodeSubStore.shared.refreshAll().count
    }

    private func updateResources() async -> Int {
        let res = ResourceStore.shared
        await res.updateAll()
        res.message = nil
        return res.items.filter { $0.isRemote && $0.enabled && !($0.error ?? "").isEmpty }.count
    }

    /// The profile's own providers: the core refreshes them in place when connected (six requests at a time);
    /// whatever it could not is downloaded by the app in ONE batch (the tunnel reloads at most once).
    private func updateProviders() async -> Int {
        let offline = ProfileInspector.shared
        await offline.load()
        let sets = (offline.result.proxyProviders + offline.result.ruleProviders).filter { $0.vehicle == "http" }
        guard !sets.isEmpty else { return 0 }
        var fallback = Set(sets.map(\.id))
        if VPNManager.shared.isConnected {
            let done = await withTaskGroup(of: String?.self) { g -> [String] in
                var next = 0, ok: [String] = []
                while next < min(6, sets.count) {
                    let p = sets[next]
                    next += 1
                    g.addTask { await Self.updateInCore(p) }
                }
                while let r = await g.next() {
                    if let r { ok.append(r) }
                    if next < sets.count {
                        let p = sets[next]
                        next += 1
                        g.addTask { await Self.updateInCore(p) }
                    }
                }
                return ok
            }
            fallback.subtract(done)
        }
        var failed = 0
        if !fallback.isEmpty { failed = await ProviderUpdater.shared.updateAll(only: fallback).failed }
        await offline.load()
        return failed
    }

    /// One provider refreshed by the running core; its id on success.
    nonisolated private static func updateInCore(_ p: InspectProvider) async -> String? {
        do {
            if p.kind == "proxy" { try await ControllerClient.shared.updateProxyProvider(p.name) }
            else { try await ControllerClient.shared.updateRuleProvider(p.name) }
            return p.id
        } catch { return nil }
    }
}
