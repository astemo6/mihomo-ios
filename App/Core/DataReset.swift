import Foundation
import NetworkExtension
import Security
import UIKit

// feat/fresh-reinstall (user 2026-10-27: deleted Tern, reinstalled, every config was still there).
//
// Tern's data lives in the App Group container (AppShared.containerURL), its suite defaults and the Keychain (service
// com.astemo6.tern). iOS keeps the App Group container after the app is deleted when another app of the same signing
// team still uses that group, and Keychain items always survive a delete. The app's OWN sandbox (Documents, Library,
// tmp) is always deleted with the app, so an install marker there tells a reinstall apart from an update:
// - marker present                       → known install, nothing to do;
// - marker missing, group container empty → first install: the marker is written silently;
// - marker missing, group container holds Tern data → reinstall: 「检测到上次安装留下的配置」 asks 保留 / 全部清除
//   before any store, geo install, scheduled update or tunnel start runs (DataResetCoordinator + TernApp gate).
// Only the app writes the marker (this file is in the app target; the PacketTunnel and widget extensions have their
// own sandboxes and never compile App/Core).
//
// The wipe routine (reinstall prompt and 更多 → 备份与恢复 → 清除全部数据) is `DataReset.wipeAll()`: VPN configuration
// removed (tunnel stopped first), every file in the group container, group + standard defaults, every Keychain item of
// the service, the app's own Documents / caches / Application Support / tmp, widgets reloaded. Backups the user saved in
// 「文件」, iCloud Drive or WebDAV are outside the app and are not touched. The app then exits (DataResetCoordinator) so
// the next launch starts from first-launch state with no singleton holding the old data.

/// The install marker in the app's own sandbox.
enum InstallMarker {
    static let fileName = ".tern-install"

    /// Application Support of the app's own sandbox (deleted by iOS together with the app).
    static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    static func url(in dir: URL = defaultDirectory) -> URL { dir.appendingPathComponent(fileName) }

    static func exists(in dir: URL = defaultDirectory) -> Bool {
        FileManager.default.fileExists(atPath: url(in: dir).path)
    }

    @discardableResult
    static func write(in dir: URL = defaultDirectory) -> Bool {
        let fm = FileManager.default
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = "\(Bundle.main.bundleIdentifier ?? "tern") \(ISO8601DateFormatter().string(from: Date()))\n"
        do {
            try Data(stamp.utf8).write(to: url(in: dir), options: .atomic)
            return true
        } catch {
            NSLog("[Tern] install marker: %@", error.localizedDescription)
            return false
        }
    }

    enum Decision: Equatable {
        /// The marker is there: an update or a normal launch.
        case known
        /// No marker, nothing left over: write the marker silently.
        case firstInstall
        /// No marker but the group container still holds Tern data: ask 保留 / 全部清除.
        case reinstall
    }

    static func decide(markerPresent: Bool, containerHasData: Bool) -> Decision {
        if markerPresent { return .known }
        return containerHasData ? .reinstall : .firstInstall
    }

    /// The launch check: decides and writes the marker unless the answer is `.reinstall` (the marker is written once
    /// the user has chosen). `container` nil = no App Group (unsigned build): the fallback store is the app's own
    /// Documents, which a delete removes, so that is never a reinstall.
    static func evaluate(markerDir: URL = defaultDirectory, container: URL?, groupDomain: [String: Any]?) -> Decision {
        let present = exists(in: markerDir)
        let hasData = !present && container.map { DataReset.containerHasData($0, groupDomain: groupDomain) } == true
        let d = decide(markerPresent: present, containerHasData: hasData)
        if d == .firstInstall { write(in: markerDir) }
        return d
    }
}

enum DataReset {
    /// System bookkeeping in a container (".com.apple.mobile_container_manager.metadata.plist"); never ours to delete.
    static func isSystemEntry(_ name: String) -> Bool { name.hasPrefix(".com.apple") }

    /// True when the group container holds anything Tern wrote: any top-level entry except system files, the App Group
    /// choice marker (AppShared writes it on every launch) and Library (the suite plist lives there; the suite's
    /// contents are passed as `groupDomain`).
    static func containerHasData(_ root: URL, groupDomain: [String: Any]?) -> Bool {
        if let d = groupDomain, !d.isEmpty { return true }
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        return names.contains { !isSystemEntry($0) && $0 != AppShared.groupMarkerName && $0 != "Library" }
    }

    /// Deletes everything in the group container: profiles, modules, scripts, rule sets, node sets, caches, MitM CA /
    /// p12, logs, statistics, snapshots, secrets.json, the App Group marker. Keeps system entries and
    /// Library/Preferences (the suite plist: cleared through `wipeDefaults`, deleting it under cfprefsd is unsafe).
    /// Returns the paths (relative to `root`) that could not be removed.
    @discardableResult
    static func wipeContainer(_ root: URL) -> [String] {
        let fm = FileManager.default
        var failed: [String] = []
        func remove(_ u: URL, _ rel: String) {
            do { try fm.removeItem(at: u) } catch { if fm.fileExists(atPath: u.path) { failed.append(rel) } }
        }
        for name in (try? fm.contentsOfDirectory(atPath: root.path)) ?? [] where !isSystemEntry(name) {
            let u = root.appendingPathComponent(name)
            if name == "Library" {
                for sub in (try? fm.contentsOfDirectory(atPath: u.path)) ?? [] where sub != "Preferences" && !isSystemEntry(sub) {
                    remove(u.appendingPathComponent(sub), "Library/" + sub)
                }
                continue
            }
            remove(u, name)
        }
        return failed
    }

    /// Deletes the contents of each directory (the directories themselves stay). Returns what could not be removed.
    @discardableResult
    static func wipeContents(of dirs: [URL]) -> [String] {
        let fm = FileManager.default
        var failed: [String] = []
        for dir in dirs {
            for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] where !isSystemEntry(name) {
                let u = dir.appendingPathComponent(name)
                do { try fm.removeItem(at: u) } catch { if fm.fileExists(atPath: u.path) { failed.append(u.lastPathComponent) } }
            }
        }
        return failed
    }

    /// The app's own sandbox: Documents (UI-test samples, file imports), Library/Caches (module gallery …),
    /// Application Support (the install marker; rewritten after a wipe), tmp (exports). Library/Preferences goes
    /// through `wipeDefaults`.
    static var appSandboxDirectories: [URL] {
        let fm = FileManager.default
        return [fm.urls(for: .documentDirectory, in: .userDomainMask)[0],
                fm.urls(for: .cachesDirectory, in: .userDomainMask)[0],
                fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0],
                fm.temporaryDirectory]
    }

    /// Clears the App Group suite and the app's standard defaults.
    static func wipeDefaults(suite: UserDefaults?, suiteName: String, standard: UserDefaults, standardDomain: String?) {
        if let suite {
            suite.removePersistentDomain(forName: suiteName)
            for k in suite.persistentDomain(forName: suiteName)?.keys.map({ $0 }) ?? [] { suite.removeObject(forKey: k) }
        }
        if let standardDomain { standard.removePersistentDomain(forName: standardDomain) }
    }

    /// Deletes every generic-password item of `service`, all accounts (controller-secret, lan-share-password,
    /// lan-extra-users, WebDAV password / encryption password …), in every access group the app can reach (no
    /// kSecAttrAccessGroup = all of them), then once more scoped to `accessGroup`. True when nothing is left.
    @discardableResult
    static func wipeKeychain(service: String, accessGroup: String? = nil) -> Bool {
        var queries: [[String: Any]] = [[kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]]
        if let accessGroup {
            queries.append([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrAccessGroup as String: accessGroup])
        }
        var ok = true
        for q in queries {
            let s = SecItemDelete(q as CFDictionary)
            if s != errSecSuccess && s != errSecItemNotFound { ok = false }
        }
        return ok
    }

    /// Stops the tunnel (on-demand off first so iOS does not bring it back) and removes every NETunnelProviderManager
    /// configuration of this app. Returns an error message or nil.
    @MainActor
    static func removeVPNConfigurations() async -> String? {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            for m in managers where m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                try? await m.saveToPreferences()
            }
            let running: (NETunnelProviderManager) -> Bool = {
                [.connected, .connecting, .reasserting, .disconnecting].contains($0.connection.status)
            }
            for m in managers where running(m) { m.connection.stopVPNTunnel() }
            // The extension writes logs / stats until it stops; give it up to 5 s before the files go.
            let deadline = Date().addingTimeInterval(5)
            while Date() < deadline, managers.contains(where: running) {
                try? await Task.sleep(nanoseconds: 200_000_000)
            }
            for m in managers { try await m.removeFromPreferences() }
            return nil
        } catch {
            return VPNManager.describe(error)
        }
    }

    struct Outcome: Equatable {
        var failedPaths: [String] = []
        var keychainOK = true
        var vpnError: String?
        var problems: Int { failedPaths.count + (keychainOK ? 0 : 1) + (vpnError == nil ? 0 : 1) }
    }

    /// The whole wipe, in order: VPN (so the tunnel stops writing), group container files, defaults, Keychain, the
    /// app's own sandbox, HTTP caches / cookies, widgets.
    @MainActor
    static func wipeAll() async -> Outcome {
        var out = Outcome()
        out.vpnError = await removeVPNConfigurations()
        let group = AppShared.appGroup
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        let sandbox = appSandboxDirectories
        let failed = await Task.detached(priority: .userInitiated) { () -> [String] in
            var f: [String] = []
            if let container { f += DataReset.wipeContainer(container) }
            f += DataReset.wipeContents(of: sandbox)
            return f
        }.value
        out.failedPaths = failed
        wipeDefaults(suite: AppShared.defaults, suiteName: group, standard: .standard, standardDomain: Bundle.main.bundleIdentifier)
        out.keychainOK = wipeKeychain(service: Keychain.service, accessGroup: group)
        URLCache.shared.removeAllCachedResponses()
        HTTPCookieStorage.shared.removeCookies(since: .distantPast)
        WidgetBridge.reload()
        return out
    }
}

/// Drives the reinstall prompt and the wipe; TernApp shows `DataResetGateView` instead of the app while `phase` is not
/// `.normal`.
@MainActor
final class DataResetCoordinator: ObservableObject {
    static let shared = DataResetCoordinator()

    enum Phase: Equatable {
        case normal
        /// Reinstall detected: 保留 / 全部清除 before anything else runs.
        case reinstallPrompt
        case wiping
        /// Done; the app exits (button, or when it goes to the background). `problems` = items that could not be removed.
        case wiped(problems: Int)
    }

    @Published private(set) var phase: Phase = .normal
    private var deferredLaunch: (() -> Void)?

    /// Unit tests (hosted in the app) and the simulator UI tests never see the prompt.
    static var isTestRun: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil || UITestSeed.enabled
    }

    /// TernApp.init, before any store loads. `launchTasks` (geo install, storage sweep …) run now, or after 保留.
    func evaluateLaunch(launchTasks: @escaping () -> Void) {
        #if DEBUG
        // UI test of the question itself (FreshReinstallUITests): the seeded container stands in for leftover data.
        if UITestSeed.enabled && UITestSeed.args.contains("-UITestReinstallPrompt") {
            deferredLaunch = launchTasks
            phase = .reinstallPrompt
            return
        }
        #endif
        if Self.isTestRun {
            InstallMarker.write()
            launchTasks()
            return
        }
        let group = AppShared.appGroup
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        let domain = UserDefaults(suiteName: group)?.persistentDomain(forName: group)
        switch InstallMarker.evaluate(container: container, groupDomain: domain) {
        case .reinstall:
            deferredLaunch = launchTasks
            phase = .reinstallPrompt
        case .known, .firstInstall:
            launchTasks()
        }
    }

    /// 「保留」: keep the leftover data and continue as a normal launch.
    func keep() {
        InstallMarker.write()
        phase = .normal
        let tasks = deferredLaunch
        deferredLaunch = nil
        tasks?()
    }

    /// 「全部清除」 (reinstall prompt) / 「清除全部数据」 (更多 → 备份与恢复).
    func wipe() async {
        guard phase != .wiping else { return }
        phase = .wiping
        deferredLaunch = nil
        DashboardModel.shared.stop()
        LiveActivityController.shared.endAll()
        let out = await DataReset.wipeAll()
        // The next launch is a known install with an empty container (first-launch state, onboarding).
        InstallMarker.write()
        phase = .wiped(problems: out.problems)
    }

    /// Back to the Home Screen, then exit, so the next launch starts clean (no singleton keeps the old data).
    func quit() {
        UIControl().sendAction(#selector(URLSessionTask.suspend), to: UIApplication.shared, for: nil)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { exit(0) }
    }
}
