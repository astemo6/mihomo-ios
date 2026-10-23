import Foundation

/// 工具 → top-right 「全部更新」 (user 2026-10-23: 「在工具最上方右侧加一个一键更新所有的按钮」): one tap updates every
/// remote resource — 配置订阅, 节点订阅, the profile's 节点集 / 规则集, modules with their scripts and rule lists.
/// Each still goes through the store that owns it, so nothing downloads differently from its own page.
@MainActor
final class UpdateEverything: ObservableObject {
    static let shared = UpdateEverything()
    @Published private(set) var running = false

    /// Returns a one-line result for an alert.
    func run() async -> String {
        guard !running else { return String(localized: "正在更新…") }
        running = true
        defer { running = false }
        var failed = 0
        failed += await ProfileStore.shared.refreshAll().count
        failed += await NodeSubStore.shared.refreshAll().count
        let res = ResourceStore.shared
        await res.updateAll()
        res.message = nil
        failed += res.items.filter { $0.isRemote && $0.enabled && !($0.error ?? "").isEmpty }.count
        // The profile's own providers: the core refreshes them in place when connected; whatever it could not is
        // downloaded by the app in ONE batch (the tunnel reloads at most once).
        let offline = ProfileInspector.shared
        await offline.load()
        let sets = (offline.result.proxyProviders + offline.result.ruleProviders).filter { $0.vehicle == "http" }
        var fallback: Set<String> = []
        for p in sets {
            var ok = false
            if VPNManager.shared.isConnected {
                do {
                    if p.kind == "proxy" { try await ControllerClient.shared.updateProxyProvider(p.name) }
                    else { try await ControllerClient.shared.updateRuleProvider(p.name) }
                    ok = true
                } catch {}
            }
            if !ok { fallback.insert(p.id) }
        }
        if !fallback.isEmpty { failed += await ProviderUpdater.shared.updateAll(only: fallback).failed }
        if !sets.isEmpty { await offline.load() }
        return failed == 0 ? String(localized: "已全部更新") : String(localized: "\(failed) 项更新失败，可在对应页面查看")
    }
}
