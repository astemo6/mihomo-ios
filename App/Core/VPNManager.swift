import Foundation
import NetworkExtension
import Combine

extension Notification.Name {
    /// Posted when the egress may have changed (connect/disconnect, node switch, mode change).
    static let egressMayHaveChanged = Notification.Name("MihomoEgressMayHaveChanged")
}

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var connectedDate: Date?
    @Published var lastError: String? { didSet { if lastError != nil { showErrorAlert = true } } }
    @Published var showErrorAlert = false
    @Published private(set) var isBusy = false
    /// The last start failed in the core / extension (not a missing profile or App Group): offer 安全模式.
    @Published private(set) var canOfferSafeMode = false
    /// The running (or last started) connection uses 安全模式.
    @Published private(set) var safeModeActive = CoreOverrides.load().safeMode

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    var isConnected: Bool { status == .connected }
    var isTransitioning: Bool { [.connecting, .disconnecting, .reasserting].contains(status) }

    var statusText: String {
        switch status {
        case .connected: return String(localized: "已连接")
        case .connecting: return String(localized: "连接中…")
        case .disconnecting: return String(localized: "断开中…")
        case .reasserting: return String(localized: "重连中…")
        case .disconnected: return String(localized: "未连接")
        case .invalid: return String(localized: "未配置")
        @unknown default: return String(localized: "未知")
        }
    }

    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.update(from: conn) }
        }
        Task { await load() }
    }

    private var userStopped = false

    private func update(from conn: NEVPNConnection) {
        let old = status
        status = conn.status
        connectedDate = conn.connectedDate
        // v0.19.2: a connect from the widget / Control Center / on-demand clears 安全模式 in overrides.json
        // without going through start(); re-read it so Home stops showing the safe-mode card and reload() runs
        // the override scripts again. Plain file read (no Keychain).
        if old != status, status == .connecting || status == .connected {
            safeModeActive = CoreOverrides.storedSafeMode()
        }
        if status == .connected { lastError = nil }
        // Connecting -> disconnected without the user stopping: the extension failed. Never stay silent.
        if (old == .connecting || old == .reasserting), status == .disconnected, !userStopped {
            Task { @MainActor in await self.reportStartFailure(conn) }
        }
        if status == .disconnected { userStopped = false }
        if old != status, status == .connected || status == .disconnected {
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
            WidgetBridge.reload()
        }
    }

    private func reportStartFailure(_ conn: NEVPNConnection) async {
        var msg: String?
        if let ext = TunnelErrorLog.recent(within: 120) { msg = ext }
        if msg == nil {
            msg = await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
                conn.fetchLastDisconnectError { err in cont.resume(returning: err?.localizedDescription) }
            }
        }
        if msg == nil, !AppShared.containerOK {
            msg = "App Group 不可用（\(AppShared.appGroup)），扩展无法读取配置。请检查重签名的描述文件是否包含 App Groups。"
        }
        // Safe mode helps when the core / modules failed, not when the signature or profile is missing.
        canOfferSafeMode = AppShared.containerOK && AppShared.activeProfileURL != nil && !safeModeActive
        await pauseKeepAliveAfterFailure()
        lastError = String(localized: "连接失败：") + (msg ?? String(localized: "网络扩展启动后立即退出（未返回原因）。请到 更多 → 诊断 导出诊断包查看。"))
        NSLog("[Mihomo] tunnel start failed: %@", lastError ?? "")
    }

    /// fix/vpn-stays-on: a tunnel that is up without the keep-alive rule (connected by an older build, from iOS
    /// Settings, or by the widget before the rule existed) gets it now, so iOS restarts it if the extension is ended.
    /// Only with 按需连接 关闭 + 保持连接; saving on-demand flags does not interrupt a running tunnel.
    private func armKeepAliveIfConnected(_ m: NETunnelProviderManager) async {
        guard !UITestSeed.enabled, m.connection.status == .connected else { return }
        let od = OnDemandSettings.load()
        guard od.mode == .off, od.keepAlive, !m.isOnDemandEnabled else { return }
        do { try await applyOnDemandRules(to: m, settings: od, enabled: true) } catch {
            NSLog("[Tern] arm keep-alive failed: %@", error.localizedDescription)
        }
    }

    /// fix/vpn-stays-on: a start that fails while only 保持连接 armed on-demand would make iOS retry it over and
    /// over (a broken profile, a missing App Group). Pause it like a manual disconnect; the next manual connect arms
    /// it again. On-demand chosen in 按需连接 (始终 / Wi-Fi …) is the user's own rule and is left alone.
    private func pauseKeepAliveAfterFailure() async {
        guard let m = manager, m.isOnDemandEnabled, OnDemandSettings.load().mode == .off else { return }
        m.isOnDemandEnabled = false
        OnDemandSettings.setPaused(true)
        do { try await m.saveToPreferences() } catch { NSLog("[Tern] pause keep-alive failed: %@", error.localizedDescription) }
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = Self.pickManager(managers)
            if let m = manager {
                try await fixStaleManager(m)
                update(from: m.connection)
                await armKeepAliveIfConnected(m)
            } else { status = .invalid }
        } catch {
            lastError = String(localized: "读取 VPN 配置失败：") + Self.describe(error)
            NSLog("[Mihomo] loadAllFromPreferences: %@", error.localizedDescription)
        }
    }

    /// The VPN configuration's server address / name. r7 (user 2026-10-21 「不用刻意保留」): renamed from
    /// "Mihomo"; existing configurations are matched by the tunnel bundle id (never by this name) and renamed in
    /// place by fixStaleManager, so no second VPN profile appears and the widget / Control Center / intents
    /// (which match the bundle id too) keep finding it.
    static let serverAddress = "Tern"
    static let legacyServerAddresses: Set<String> = ["Mihomo", "Tern"]

    /// This app's configuration: our tunnel bundle id first; then one carrying our (old or new) name, saved by a
    /// build with another tunnel bundle id (re-signing); then — NE only lists this app's own configurations —
    /// the first one, which fixStaleManager re-points.
    static func pickManager(_ managers: [NETunnelProviderManager]) -> NETunnelProviderManager? {
        func proto(_ m: NETunnelProviderManager) -> NETunnelProviderProtocol? { m.protocolConfiguration as? NETunnelProviderProtocol }
        return managers.first { proto($0)?.providerBundleIdentifier == AppShared.tunnelBundleID }
            ?? managers.first { legacyServerAddresses.contains(proto($0)?.serverAddress ?? "") }
            ?? managers.first
    }

    /// A manager saved by a build with another tunnel bundle id (e.g. before re-signing) would start a
    /// non-existent extension. Point it at the current one and save again. r7: also renames a configuration
    /// still called "Mihomo" to "Tern" in place.
    private func fixStaleManager(_ m: NETunnelProviderManager) async throws {
        guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else { return }
        let staleID = proto.providerBundleIdentifier != AppShared.tunnelBundleID
        let staleName = proto.serverAddress != Self.serverAddress || m.localizedDescription != "Tern"
        guard staleID || staleName else { return }
        // Renaming a running configuration could make iOS reconnect it: rename only while it is down.
        if !staleID && !(m.connection.status == .disconnected || m.connection.status == .invalid) { return }
        NSLog("[Tern] updating VPN configuration (bundle id %@ -> %@, name %@ -> Tern)", proto.providerBundleIdentifier ?? "nil", AppShared.tunnelBundleID, proto.serverAddress ?? "nil")
        proto.providerBundleIdentifier = AppShared.tunnelBundleID
        proto.serverAddress = Self.serverAddress
        m.localizedDescription = "Tern"
        m.protocolConfiguration = proto
        if staleID { m.isEnabled = true } // a rename alone must not take over from another VPN in use
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
        } catch {
            NSLog("[Tern] saveToPreferences (fix stale) failed: %@", error.localizedDescription)
            if staleID { throw error } // a failed rename alone is harmless: the old name keeps working
            try? await m.loadFromPreferences()
        }
    }

    private func ensureManager() async throws -> NETunnelProviderManager {
        if let m = manager {
            try await fixStaleManager(m)
            return m
        }
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppShared.tunnelBundleID
        proto.serverAddress = Self.serverAddress
        proto.disconnectOnSleep = false
        Self.applyScope(CoreOverrides.load(), to: proto)
        m.protocolConfiguration = proto
        m.localizedDescription = "Tern"
        m.isEnabled = true
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
        } catch {
            NSLog("[Mihomo] saveToPreferences (create) failed: %@", error.localizedDescription)
            throw error
        }
        manager = m
        return m
    }

    func toggle() async {
        if isConnected || status == .connecting { stop() } else { await start() }
    }

    /// Starts the tunnel. safeMode: this connection runs the profile without modules / scripts / MitM /
    /// custom rules (offered after a failed start); every normal start clears it again.
    func start(safeMode: Bool = false) async {
        lastError = nil
        canOfferSafeMode = false
        guard AppShared.containerOK else {
            lastError = String(localized: "App Group 不可用：重签名的描述文件需要包含 App Groups，且主程序和扩展使用同一个组。详见 更多 → 诊断。")
            return
        }
        guard AppShared.activeProfileURL != nil else {
            lastError = String(localized: "请先在「更多 → 配置」中添加并选择一个配置")
            return
        }
        isBusy = true
        defer { isBusy = false }
        // v0.19 覆写脚本: the active profile's scripts run (when anything changed) before the tunnel starts;
        // a failing script stops the connect with its error instead of running an unexpected config.
        if !safeMode, let err = await OverrideScriptStore.shared.prepareActive() {
            lastError = err
            canOfferSafeMode = AppShared.containerOK
            return
        }
        do {
            var o = CoreOverrides.load()
            o.safeMode = safeMode
            o.save()
            safeModeActive = safeMode
            let m = try await ensureManager()
            // r7 (review7 R7A-2): the scope in overrides.json (restored backup / snapshot / sync, a page that
            // short-circuited) must be what iOS enforces — re-applied before every start when it differs.
            var scopeStale = false
            if !UITestSeed.enabled, let proto = m.protocolConfiguration as? NETunnelProviderProtocol, !Self.scopeMatches(o, proto) {
                Self.applyScope(o, to: proto)
                m.protocolConfiguration = proto
                scopeStale = true
            }
            if !m.isEnabled || scopeStale {
                m.isEnabled = true
                do {
                    try await m.saveToPreferences()
                    try await m.loadFromPreferences()
                } catch {
                    NSLog("[Mihomo] saveToPreferences (enable) failed: %@", error.localizedDescription)
                    throw error
                }
            }
            // A manual connect resumes on-demand rules paused by an earlier manual disconnect, and (保持连接,
            // fix/vpn-stays-on) arms the keep-alive rule: iOS restarts the tunnel if the extension is ended.
            if !UITestSeed.enabled {
                try await applyOnDemandRules(to: m, settings: OnDemandSettings.load(), enabled: true)
            }
            userStopped = false
            TunnelErrorLog.clear()
            try m.connection.startVPNTunnel()
        } catch {
            lastError = String(localized: "启动失败：") + Self.describe(error)
            NSLog("[Mihomo] start failed: %@", error.localizedDescription)
        }
    }

    /// Reconnects normally after a safe-mode connection (or in safe mode after a failure).
    func restart(safeMode: Bool) async {
        if status != .disconnected && status != .invalid {
            await disconnectAndWait()
        }
        await start(safeMode: safeMode)
    }

    /// Creates the VPN configuration without connecting: iOS shows the 「添加 VPN 配置」 prompt now
    /// (first-run onboarding). Returns an error message or nil.
    func installConfiguration() async -> String? {
        do {
            _ = try await ensureManager()
            if let m = manager { update(from: m.connection) }
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    var hasConfiguration: Bool { manager != nil && status != .invalid }

    // MARK: Tunnel scope / reset (连接方式, v0.7)

    /// Public NETunnelProviderProtocol scope switches; the exclude* options only matter with includeAllNetworks.
    /// 仅代理 has no routes and no packet reader, so includeAllNetworks would capture every app's traffic into a
    /// tunnel nobody reads (no network at all): the switch only applies in TUN / 混合.
    static func applyScope(_ o: CoreOverrides, to proto: NETunnelProviderProtocol) {
        proto.includeAllNetworks = o.effectiveIncludeAll
        proto.excludeLocalNetworks = o.excludeLocalNetworks
        if #available(iOS 16.4, *) {
            proto.excludeAPNs = o.effectiveExcludeAPNs
            proto.excludeCellularServices = o.excludeCellularServices
        }
        if #available(iOS 17.4, *) {
            proto.excludeDeviceCommunication = o.excludeDeviceCommunication
        }
    }

    /// r7 R7A-2: true when the configuration already carries what applyScope would write.
    static func scopeMatches(_ o: CoreOverrides, _ proto: NETunnelProviderProtocol) -> Bool {
        if proto.includeAllNetworks != o.effectiveIncludeAll { return false }
        if proto.excludeLocalNetworks != o.excludeLocalNetworks { return false }
        if #available(iOS 16.4, *) {
            if proto.excludeAPNs != o.effectiveExcludeAPNs || proto.excludeCellularServices != o.excludeCellularServices { return false }
        }
        if #available(iOS 17.4, *) {
            if proto.excludeDeviceCommunication != o.excludeDeviceCommunication { return false }
        }
        return true
    }

    /// r7 R7A-2: after a restore (backup, snapshot, sync folder) or a 连接方式 apply that found nothing changed:
    /// writes the stored scope into the existing VPN configuration when they differ. Returns true when it had to
    /// (the running tunnel then needs a reconnect). Never creates a configuration.
    @discardableResult
    func syncTunnelScope() async -> Bool {
        if UITestSeed.enabled { return false }
        if manager == nil { await load() }
        guard let m = manager, let proto = m.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        let o = CoreOverrides.load()
        if Self.scopeMatches(o, proto) { return false }
        Self.applyScope(o, to: proto)
        m.protocolConfiguration = proto
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            NSLog("[Tern] tunnel scope re-applied (includeAllNetworks %d)", proto.includeAllNetworks ? 1 : 0)
            return true
        } catch {
            NSLog("[Tern] tunnel scope sync failed: %@", error.localizedDescription)
            return false
        }
    }

    /// r7 R7A-2: a scope change only applies to a new connection.
    func reconnectForScope() async {
        guard isConnected else { return }
        await restart(safeMode: false)
    }

    /// Writes the scope switches into the VPN configuration. Returns an error message or nil.
    func applyTunnelScope() async -> String? {
        // Review 5 P2-10: the simulator UI tests never save a VPN configuration from here (saveToPreferences can
        // raise a system prompt over the app, one cause of the en-light 连接方式 switch flake).
        if UITestSeed.enabled { return nil }
        do {
            let m = try await ensureManager()
            guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol else { return nil }
            Self.applyScope(CoreOverrides.load(), to: proto)
            m.protocolConfiguration = proto
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    /// 重置 VPN 配置: disconnects, removes this app's VPN configuration from iOS and creates a fresh one
    /// (iOS asks for permission again). Returns an error message or nil.
    func resetConfiguration() async -> String? {
        await disconnectAndWait()
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            for m in managers { try await m.removeFromPreferences() }
            manager = nil
            status = .invalid
            let m = try await ensureManager()
            let od = OnDemandSettings.load()
            if od.mode != .off {
                try await applyOnDemandRules(to: m, settings: od, enabled: true)
            }
            update(from: m.connection)
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    /// NetworkExtension / preference errors in plain Chinese (the system text is often just a code).
    nonisolated static func describe(_ error: Error) -> String {
        let ns = error as NSError
        let raw = ns.localizedDescription
        if raw.localizedCaseInsensitiveContains("permission denied") {
            return String(localized: "没有允许添加 VPN 配置。再次连接时在系统提示里选「允许」。")
        }
        if ns.domain == NEVPNErrorDomain, let code = NEVPNError.Code(rawValue: ns.code) {
            switch code {
            case .configurationInvalid: return String(localized: "VPN 配置无效（扩展 ID 可能与签名不符）。") + " (\(raw))"
            case .configurationDisabled: return String(localized: "VPN 配置已停用：在 设置 → VPN 中选中 Tern，或重新连接。")
            case .connectionFailed: return String(localized: "网络扩展连接失败。") + " (\(raw))"
            case .configurationStale: return String(localized: "VPN 配置已被其他地方修改，请重试一次。")
            case .configurationReadWriteFailed: return String(localized: "无法保存 VPN 配置：可能拒绝了「添加 VPN 配置」，或签名缺少 Network Extension 权限。")
            case .configurationUnknown: return String(localized: "未知的 VPN 配置错误。") + " (\(raw))"
            @unknown default: return raw
            }
        }
        return raw
    }

    func stop() {
        userStopped = true
        guard let m = manager else { return }
        if m.isOnDemandEnabled {
            // Otherwise iOS would reconnect right away: pause on-demand until the next manual connect.
            m.isOnDemandEnabled = false
            OnDemandSettings.setPaused(true)
            Task {
                do { try await m.saveToPreferences() } catch { NSLog("[Mihomo] pause on-demand failed: %@", error.localizedDescription) }
                m.connection.stopVPNTunnel()
            }
        } else {
            m.connection.stopVPNTunnel()
        }
    }

    /// Connects (if needed) and waits up to `timeout` seconds for the connected state. Used by App Intents.
    func connectAndWait(timeout: TimeInterval = 20) async -> Bool {
        if manager == nil { await load() }
        if isConnected { return true }
        await start()
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if isConnected { return true }
            if lastError != nil && status == .disconnected { return false }
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        return isConnected
    }

    func disconnectAndWait(timeout: TimeInterval = 10) async {
        if manager == nil { await load() }
        guard status != .disconnected && status != .invalid else { return }
        stop()
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline, status != .disconnected {
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    // MARK: On-demand

    /// Saves the on-demand choice and applies it to the VPN configuration. Returns an error message or nil.
    func applyOnDemand(_ settings: OnDemandSettings) async -> String? {
        settings.save()
        if UITestSeed.enabled { return nil }
        do {
            let m = try await ensureManager()
            // Turning it on while disconnected manually counts as a fresh choice: not paused. 保持连接 alone only
            // arms while connected (it never connects by itself; the next manual connect arms it).
            try await applyOnDemandRules(to: m, settings: settings, enabled: settings.mode != .off || isConnected)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func applyOnDemandRules(to m: NETunnelProviderManager, settings: OnDemandSettings, enabled: Bool) async throws {
        let rules = settings.rules
        let want = enabled && !rules.isEmpty
        let changed = m.isOnDemandEnabled != want || OnDemandSettings.signature(m.onDemandRules ?? []) != OnDemandSettings.signature(rules)
        guard changed else { return }
        m.onDemandRules = rules
        m.isOnDemandEnabled = want
        OnDemandSettings.setPaused(false)
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
    }

    var onDemandPaused: Bool { OnDemandSettings.isPaused && OnDemandSettings.load().mode != .off }

    /// Sends a message to the running tunnel and returns its reply.
    /// The reply is nil when the tunnel is not connected, the message could not be sent, or the tunnel
    /// did not answer within `timeout` seconds (a busy or stuck extension never blocks the UI).
    func send(_ msg: TunnelMessage, timeout: TimeInterval = 8) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession, status == .connected else { return nil }
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            let lock = NSLock()
            var resumed = false
            let finish: (Data?) -> Void = { data in
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                cont.resume(returning: data)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(nil) }
            do {
                try session.sendProviderMessage(Data(msg.rawValue.utf8)) { data in finish(data) }
            } catch {
                finish(nil)
            }
        }
    }

    /// Asks the tunnel to re-read the active profile and overrides. Returns an error message or nil.
    func reload() async -> String? {
        guard isConnected else { return nil }
        if !safeModeActive, let err = await OverrideScriptStore.shared.prepareActive() { return err } // v0.19 覆写脚本
        // v0.19.8: the extension answers when the new config is applied; with proxy-providers that takes longer than
        // the 8 s default, and a reply missing after 8 s used to count as success while the core still ran the old
        // config (a group order save then read the old order back and looked like it did nothing).
        let data = await send(.reload, timeout: 45)
        NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        return Self.reloadResult(data, stillConnected: isConnected)
    }

    /// Review 6 R6A-3: nil = applied. No reply while the tunnel is still up means the reload did not finish within
    /// the timeout (the core may still run the old config) — that used to count as success. No reply because the
    /// tunnel went down is fine: the next start reads the new config anyway.
    nonisolated static func reloadResult(_ data: Data?, stillConnected: Bool) -> String? {
        guard let data else {
            return stillConnected ? String(localized: "重新加载超时：内核可能仍在使用旧配置，请稍后重试或重新连接。") : nil
        }
        let msg = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return msg.isEmpty || msg == TunnelMessage.reloadOK ? nil : msg
    }
}

/// 按需连接: which networks iOS connects the tunnel on automatically (NEOnDemandRules).
struct OnDemandSettings: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case off, always, wifi, cellular, ssid
        var id: String { rawValue }
        var title: String {
            switch self {
            case .off: return String(localized: "关闭")
            case .always: return String(localized: "始终")
            case .wifi: return String(localized: "仅 Wi-Fi")
            case .cellular: return String(localized: "仅蜂窝网络")
            case .ssid: return String(localized: "仅指定 Wi-Fi")
            }
        }
    }

    var mode: Mode = .off
    /// 保持连接 (fix/vpn-stays-on, default on): with 按需连接 关闭, a manual connect also arms an on-demand
    /// "connect on any network" rule, so iOS restarts the tunnel when the extension is ended (memory, crash, a
    /// network change) — it keeps running whether the app is open, in the background or closed. A manual
    /// disconnect pauses it (VPNManager.stop / VPNControl.set), so it never reconnects against the user's choice.
    var keepAlive = true
    /// 受信任的 Wi-Fi (v0.7): on these SSIDs iOS disconnects instead of connecting (NEOnDemandRule ssidMatch).
    var trustedSSIDs: [String] = []
    /// 仅指定 Wi-Fi (v0.9): connect only on these SSIDs (system-matched, no SSID reading needed).
    var onlySSIDs: [String] = []
    /// 仅指定 Wi-Fi: also connect on cellular.
    var ssidCellular = false

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = (try? c.decodeIfPresent(Mode.self, forKey: .mode)) ?? .off
        trustedSSIDs = (try? c.decodeIfPresent([String].self, forKey: .trustedSSIDs)) ?? []
        onlySSIDs = (try? c.decodeIfPresent([String].self, forKey: .onlySSIDs)) ?? []
        ssidCellular = (try? c.decodeIfPresent(Bool.self, forKey: .ssidCellular)) ?? false
        keepAlive = (try? c.decodeIfPresent(Bool.self, forKey: .keepAlive)) ?? true
    }
    enum CodingKeys: String, CodingKey { case mode, trustedSSIDs, onlySSIDs, ssidCellular, keepAlive }

    /// Compares rule lists by kind, interface and SSIDs (NEOnDemandRule has no useful equality).
    static func signature(_ rules: [NEOnDemandRule]) -> String {
        rules.map { r in "\(type(of: r)):\(r.interfaceTypeMatch.rawValue):\((r.ssidMatch ?? []).joined(separator: ","))" }.joined(separator: "|")
    }

    private static let key = "onDemandSettings"
    private static let pausedKey = "onDemandPaused"

    static func load() -> OnDemandSettings {
        guard let d = AppShared.defaults.data(forKey: key),
              let s = try? JSONDecoder().decode(OnDemandSettings.self, from: d) else { return OnDemandSettings() }
        return s
    }

    func save() {
        if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) }
    }

    static var isPaused: Bool { AppShared.defaults.bool(forKey: pausedKey) }
    static func setPaused(_ v: Bool) { AppShared.defaults.set(v, forKey: pausedKey) }

    var rules: [NEOnDemandRule] {
        func connect(_ t: NEOnDemandRuleInterfaceType) -> NEOnDemandRule {
            let r = NEOnDemandRuleConnect(); r.interfaceTypeMatch = t; return r
        }
        func disconnect(_ t: NEOnDemandRuleInterfaceType) -> NEOnDemandRule {
            let r = NEOnDemandRuleDisconnect(); r.interfaceTypeMatch = t; return r
        }
        var trusted: [NEOnDemandRule] = []
        let ssids = trustedSSIDs.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        if !ssids.isEmpty, mode == .always || mode == .wifi {
            let r = NEOnDemandRuleDisconnect()
            r.interfaceTypeMatch = .wiFi
            r.ssidMatch = ssids
            trusted = [r]
        }
        switch mode {
        case .off: return keepAlive ? [connect(.any)] : []
        case .always: return trusted + [connect(.any)]
        case .wifi: return trusted + [connect(.wiFi), disconnect(.cellular)]
        case .cellular: return [connect(.cellular), disconnect(.wiFi)]
        case .ssid:
            // iOS evaluates the rules in order: the listed Wi-Fi (and cellular if wanted) connect, everything
            // else disconnects. With no names only cellular (or nothing) connects.
            var out: [NEOnDemandRule] = []
            let only = onlySSIDs.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if !only.isEmpty {
                let r = NEOnDemandRuleConnect()
                r.interfaceTypeMatch = .wiFi
                r.ssidMatch = only
                out.append(r)
            }
            if ssidCellular { out.append(connect(.cellular)) }
            return out + [disconnect(.any)]
        }
    }
}

extension CoreOverrides {
    /// FaceTime 走代理 needs every network in the tunnel (FaceTime media skips a normal VPN route). APNs (ringing /
    /// call signalling) stays the user's choice (user 2026-10-22: 不强制 APNs). 仅代理 never carries includeAllNetworks.
    var effectiveIncludeAll: Bool { (includeAllNetworks || faceTimeProxy) && !isProxyOnly }
    var effectiveExcludeAPNs: Bool { excludeAPNs }
}
