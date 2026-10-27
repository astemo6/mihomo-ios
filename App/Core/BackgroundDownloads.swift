import Combine
import Foundation
import UIKit

// fix/nc-0.20.2 (user: 导入后的下载不要卡在弹窗里): the downloads an import starts — its remote rewrite modules (QX
// rewrite_remote, Loon [Plugin]) and its rule sets / node sets — run here, outside the import sheet, under a
// UIApplication background task, and end with one local notification that sums them up. A module whose download
// fails while the VPN is off (its host is often only reachable through the proxy) is shown as
// 「待重试（连接后自动下载）」 and fetched again when the VPN connects or the app comes back to the foreground.
// An enabled remote module that has never been downloaded (imported 停用 and switched on later, or cut off by the
// background-time limit) is fetched the same way — so a 停用 module is never downloaded until it is switched on.
@MainActor
final class BackgroundDownloads: ObservableObject {
    static let shared = BackgroundDownloads()

    /// Module id → the status shown on its row while it waits for a retry.
    @Published private(set) var pendingModules: [String: String] = [:]
    /// Module ids being downloaded now.
    @Published private(set) var fetching: Set<String> = []
    /// Profiles whose rule sets / node sets did not finish downloading (retried with the modules).
    private var pendingProfiles: Set<String> = []
    /// Module id → the client whose User-Agent fetches it ("qx", "loon"); nil = guessed from the URL.
    private var clients: [String: String] = [:]
    private var cancellables = Set<AnyCancellable>()
    private var started = false
    private var inflight: [String: Task<String?, Never>] = [:]

    static var retryText: String { String(localized: "待重试（连接后自动下载）") }

    private static let pendingKey = "bgdl.pendingModules.v1"
    private static let clientsKey = "bgdl.moduleClients.v1"
    private static let profilesKey = "bgdl.pendingProfiles.v1"

    /// Called once at launch (RootView): restores the retry list and watches connect / foreground / module changes.
    func start() {
        guard !started else { return }
        started = true
        let d = UserDefaults.standard
        pendingModules = (d.dictionary(forKey: Self.pendingKey) as? [String: String]) ?? [:]
        clients = (d.dictionary(forKey: Self.clientsKey) as? [String: String]) ?? [:]
        pendingProfiles = Set(d.stringArray(forKey: Self.profilesKey) ?? [])
        VPNManager.shared.$status
            .map { $0 == .connected }
            .removeDuplicates()
            .filter { $0 }
            .sink { [weak self] _ in Task { @MainActor in await self?.resume(notify: true) } }
            .store(in: &cancellables)
        NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)
            .sink { [weak self] _ in Task { @MainActor in await self?.resume(notify: false) } }
            .store(in: &cancellables)
        // A module switched on that was never downloaded (imported 停用): fetch it now.
        EngineStore.shared.$config
            .map { $0.modules.filter { $0.enabled && !$0.url.isEmpty && ($0.updatedAt ?? 0) <= 0 }.map(\.id) }
            .removeDuplicates()
            .dropFirst()
            .sink { [weak self] ids in
                guard let self, !ids.isEmpty else { return }
                Task { @MainActor in await self.fetchModules(ids, notify: false) }
            }
            .store(in: &cancellables)
    }

    struct ImportSummary {
        var modulesOK = 0
        /// 「<module name>：<error>」 per module that failed.
        var modulesFailed: [String] = []
        var providers = ProviderUpdater.Result()
    }

    /// The import's downloads, in the background. Returns at once (the caller may await the task: the E2E replay
    /// does); the summary also arrives as a notification.
    @discardableResult
    func runImport(profile: Profile, moduleIDs: [String], clients newClients: [String: String], notify: Bool = true) -> Task<ImportSummary, Never> {
        for (k, v) in newClients { clients[k] = v }
        pendingProfiles.insert(profile.id)
        persist()
        return Task { @MainActor () -> ImportSummary in
            await self.withBackgroundTime("tern.import.downloads") { () -> ImportSummary in
                var sum = ImportSummary()
                var lines: [String] = []
                let (ok, failed) = await self.fetchModulesCounting(moduleIDs)
                sum.modulesOK = ok
                sum.modulesFailed = failed
                if !moduleIDs.isEmpty {
                    lines.append(String(localized: "远程重写：\(ok) 个已下载，\(failed.count) 个失败"))
                }
                let pr = await ProviderUpdater.shared.updateAll(profile: profile)
                sum.providers = pr
                if pr.failed == 0 { self.pendingProfiles.remove(profile.id); self.persist() }
                if pr.ok + pr.failed > 0 {
                    lines.append(String(localized: "规则集 / 节点集：\(pr.ok) 个已下载，\(pr.failed) 个失败"))
                }
                if (!failed.isEmpty || pr.failed > 0) && !VPNManager.shared.isConnected {
                    lines.append(String(localized: "失败的项目会在连接后自动重试。"))
                }
                if notify && !lines.isEmpty {
                    UsageAlerts.post(id: "tern.import.done", title: String(localized: "「\(profile.name)」的下载已完成"),
                                     body: lines.joined(separator: "\n"), thread: "tern.downloads")
                }
                return sum
            }
        }
    }

    /// Retries every pending module (and the profiles whose downloads did not finish).
    func resume(notify: Bool) async {
        let store = EngineStore.shared
        var ids = Array(pendingModules.keys)
        // enabled remote modules never downloaded (background time ran out before them)
        for m in store.config.modules where m.enabled && !m.url.isEmpty && (m.updatedAt ?? 0) <= 0 && !ids.contains(m.id) {
            ids.append(m.id)
        }
        let profiles = ProfileStore.shared.profiles.filter { pendingProfiles.contains($0.id) }
        guard !ids.isEmpty || !profiles.isEmpty else { return }
        await withBackgroundTime("tern.downloads.retry") {
            let (ok, failed) = await self.fetchModulesCounting(ids)
            var pOK = 0, pFail = 0
            for p in profiles {
                let r = await ProviderUpdater.shared.updateAll(profile: p)
                pOK += r.ok; pFail += r.failed
                if r.failed == 0 { self.pendingProfiles.remove(p.id) }
            }
            self.persist()
            if notify && (ok + pOK > 0 || !failed.isEmpty || pFail > 0) {
                var body = String(localized: "远程重写：\(ok) 个已下载，\(failed.count) 个失败")
                if pOK + pFail > 0 { body += "\n" + String(localized: "规则集 / 节点集：\(pOK) 个已下载，\(pFail) 个失败") }
                UsageAlerts.post(id: "tern.downloads.retry", title: String(localized: "连接后已重试下载"), body: body, thread: "tern.downloads")
            }
        }
    }

    func fetchModules(_ ids: [String], notify: Bool) async {
        _ = await fetchModulesCounting(ids)
    }

    /// Downloads the modules one after another; (ok count, failure lines).
    private func fetchModulesCounting(_ ids: [String]) async -> (Int, [String]) {
        var ok = 0
        var failed: [String] = []
        for id in ids {
            if let e = await fetchModule(id) {
                let name = EngineStore.shared.config.modules.first { $0.id == id }?.name ?? id
                failed.append("\(name)：\(e)")
            } else if EngineStore.shared.config.modules.contains(where: { $0.id == id }) {
                ok += 1
            }
        }
        return (ok, failed)
    }

    /// One module: download → module file → updatedAt → reparse + save (reloads the tunnel). nil on success. A
    /// second call for a module already downloading waits for that download and returns its result.
    @discardableResult
    func fetchModule(_ id: String) async -> String? {
        if let t = inflight[id] { return await t.value }
        let store = EngineStore.shared
        guard let m = store.config.modules.first(where: { $0.id == id }), !m.url.isEmpty else {
            pendingModules[id] = nil
            persist()
            return nil
        }
        guard m.enabled else { return nil } // a 停用 module is never downloaded
        let client = clients[id]
        let t = Task { @MainActor () -> String? in
            do {
                let text = try await EngineStore.download(m.url, client: client)
                try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
                if let i = store.config.modules.firstIndex(where: { $0.id == id }) {
                    store.config.modules[i].updatedAt = Date().timeIntervalSince1970
                }
                store.reparseModules()
                store.save()
                self.pendingModules[id] = nil
                self.persist()
                return nil
            } catch {
                self.pendingModules[id] = VPNManager.shared.isConnected ? nil : Self.retryText
                self.persist()
                return error.localizedDescription
            }
        }
        inflight[id] = t
        fetching.insert(id)
        let r = await t.value
        inflight[id] = nil
        fetching.remove(id)
        return r
    }

    /// Runs `work` with background execution time; when iOS takes it back, the rest is retried on the next
    /// foreground / connect (pending lists and never-downloaded modules are persisted state).
    private func withBackgroundTime<T>(_ name: String, _ work: () async -> T) async -> T {
        final class Token { var id = UIBackgroundTaskIdentifier.invalid }
        let token = Token()
        token.id = UIApplication.shared.beginBackgroundTask(withName: name) {
            // time is up: what did not finish stays pending (see above)
            if token.id != .invalid { UIApplication.shared.endBackgroundTask(token.id); token.id = .invalid }
        }
        let r = await work()
        if token.id != .invalid { UIApplication.shared.endBackgroundTask(token.id); token.id = .invalid }
        return r
    }

    private func persist() {
        let d = UserDefaults.standard
        d.set(pendingModules, forKey: Self.pendingKey)
        // clients of modules that are gone are dropped
        let ids = Set(EngineStore.shared.config.modules.map(\.id))
        clients = clients.filter { ids.contains($0.key) }
        d.set(clients, forKey: Self.clientsKey)
        d.set(Array(pendingProfiles), forKey: Self.profilesKey)
    }

    /// Unit tests: the retry list without UserDefaults.
    func _setPendingForTesting(_ m: [String: String]) { pendingModules = m }
}
