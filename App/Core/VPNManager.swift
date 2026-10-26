import Foundation
import NetworkExtension
import Combine

extension Notification.Name {
    /// Posted when the egress may have changed (connect/disconnect, node switch, mode change).
    static let egressMayHaveChanged = Notification.Name("TernEgressMayHaveChanged")
}

@MainActor
final class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var connectedDate: Date?
    @Published var lastError: String? { didSet { if lastError != nil { showErrorAlert = true } } }
    @Published var showErrorAlert = false
    @Published private(set) var isBusy = false
    /// fix/app-toggle-hitch: a tap asked for a connect / disconnect that iOS has not reflected in `status` yet.
    /// The Home switch shows the requested state at once (连接中… / off) instead of snapping back for the ~1.5 s
    /// the connect spends preparing, and ignores further taps meanwhile.
    @Published private(set) var pendingStart = false
    @Published private(set) var pendingStop = false
    /// The last start failed in the core / extension (not a missing profile or App Group): offer 安全模式.
    @Published private(set) var canOfferSafeMode = false
    /// The running (or last started) connection uses 安全模式.
    @Published private(set) var safeModeActive = CoreOverrides.load().safeMode

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    /// fix/nc-start-empty: iOS changed a VPN configuration (another VPN app enabled its own → ours is disabled, stop
    /// reason 9; the user picked another VPN in Settings). The cached manager kept `isEnabled == true`, so the next
    /// 启动 skipped re-enabling it and iOS ignored startVPNTunnel: the switch did nothing.
    private var configObserver: NSObjectProtocol?

    var isConnected: Bool { status == .connected }
    /// fix/app-toggle-hitch: what the Home switch shows — the requested state while a tap is pending.
    var switchOn: Bool {
        if pendingStop { return false }
        if pendingStart { return true }
        return isConnected || status == .connecting || status == .reasserting
    }

    /// fix/app-toggle-hitch: the switch / capsule ignores taps while this is true (no double start / stop).
    var switchBusy: Bool { isBusy || pendingStart || pendingStop || status == .connecting || status == .disconnecting }

    var statusText: String {
        if pendingStart && (status == .disconnected || status == .invalid) { return String(localized: "连接中…") }
        if pendingStop && status == .connected { return String(localized: "断开中…") }
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
        // Cold launch while the tunnel keeps running (QX shows the switch already on): loadAllFromPreferences takes a
        // moment, and starting from .invalid made the Home switch visibly animate off → on. The extension refreshes
        // its alive marker while it runs and removes it in stopTunnel, so a fresh marker means "most likely still
        // connected"; load() replaces this guess with the real status right after.
        if !UITestSeed.enabled, Self.tunnelLikelyRunning() { status = .connected }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.update(from: conn) }
        }
        configObserver = NotificationCenter.default.addObserver(forName: .NEVPNConfigurationChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.reloadManagerAfterConfigurationChange() }
        }
        Task { await load() }
    }

    /// fix/nc-start-empty: re-reads the cached manager from the preferences (isEnabled / on-demand flags as iOS has
    /// them now). Never while a start is preparing: start() refreshes it itself right before deciding.
    private func reloadManagerAfterConfigurationChange() async {
        guard !startInFlight else { return }
        if let m = manager {
            do { try await m.loadFromPreferences() } catch { NSLog("[Tern] reload VPN configuration failed: %@", error.localizedDescription) }
            update(from: m.connection)
        } else {
            await load()
        }
    }

    /// fix/nc-start-empty: one line per start decision in the shared startup log (tag "app"), so 诊断 shows why a
    /// tap on 启动 ended without a tunnel (it used to return silently on several paths).
    nonisolated static func trace(_ msg: String) {
        NSLog("[Tern] start: %@", msg)
        // fix/app-toggle-hitch: the file append (stat + open + write) ran on the main actor several times per tap.
        // One serial queue keeps the lines in order.
        traceQueue.async { StartupLog.write("vpn start: " + msg, tag: "app", mirror: false) }
    }
    nonisolated private static let traceQueue = DispatchQueue(label: "tern.vpn.trace", qos: .utility)

    /// fix/app-toggle-hitch: milliseconds since `t0` (DispatchTime uptime ns), for the phase timing line.
    nonisolated static func ms(since t0: UInt64) -> Int { Int((DispatchTime.now().uptimeNanoseconds &- t0) / 1_000_000) }

    /// fix/nc-start-empty: a start still marked in flight after this long is stuck (an await that never returned);
    /// the next tap proceeds instead of being ignored forever with the switch doing nothing.
    nonisolated static let startStuckAfter: TimeInterval = 60

    /// fix/nc-start-empty (pure, unit-tested): whether a new start may run while `startInFlightSince` is set.
    nonisolated static func mayStart(inFlightSince: Date?, now: Date = Date()) -> Bool {
        guard let since = inFlightSince else { return true }
        return now.timeIntervalSince(since) >= startStuckAfter
    }

    private var userStopped = false
    /// rv2-life: start() suspends at several awaits (scripts, preferences, runtime prep); a second toggle / restart /
    /// intent in that window used to run a second start and call startVPNTunnel twice. One start at a time; a stop()
    /// meanwhile bumps `stopSeq`, and the in-flight start then gives up before startVPNTunnel.
    private var startInFlight: Bool { startInFlightSince != nil }
    private var startInFlightSince: Date?
    private var startToken = 0
    private var stopSeq = 0

    /// The extension's alive marker exists and was refreshed recently (it is rewritten every couple of minutes).
    nonisolated static func tunnelLikelyRunning(now: Date = Date()) -> Bool {
        guard let s = try? String(contentsOf: TunnelStopReason.aliveURL, encoding: .utf8),
              let beat = ISO8601DateFormatter().date(from: s.trimmingCharacters(in: .whitespacesAndNewlines)) else { return false }
        return now.timeIntervalSince(beat) < 15 * 60
    }

    private func update(from conn: NEVPNConnection) {
        let old = status
        if status != conn.status { status = conn.status }
        if connectedDate != conn.connectedDate { connectedDate = conn.connectedDate }
        if pendingStop, [.disconnecting, .disconnected, .invalid].contains(status) { pendingStop = false }
        // v0.19.2: a connect from the widget / Control Center / on-demand clears 安全模式 in overrides.json
        // without going through start(); re-read it so Home stops showing the safe-mode card and reload() runs
        // the override scripts again. Plain file read (no Keychain).
        if old != status, status == .connecting || status == .connected {
            let s = CoreOverrides.storedSafeMode()
            if safeModeActive != s { safeModeActive = s }
        }
        if status == .connected, lastError != nil { lastError = nil }
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
        NSLog("[Tern] tunnel start failed: %@", lastError ?? "")
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
            NSLog("[Tern] loadAllFromPreferences: %@", error.localizedDescription)
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
            NSLog("[Tern] saveToPreferences (create) failed: %@", error.localizedDescription)
            throw error
        }
        manager = m
        return m
    }

    func toggle() async {
        if isConnected || status == .connecting { stop() } else { await start() }
    }

    /// fix/app-toggle-hitch: the Home switch / capsule entry point. Marks the request synchronously (the switch
    /// shows it in the same frame) and ignores taps while one is still being carried out.
    func requestToggle() {
        guard !switchBusy else {
            Self.trace("tap ignored: a connect / disconnect is still in progress")
            return
        }
        if isConnected || status == .connecting || status == .reasserting {
            stop()
        } else {
            pendingStart = true
            Task { await start() }
        }
    }

    /// Starts the tunnel. safeMode: this connection runs the profile without modules / scripts / MitM /
    /// custom rules (offered after a failed start); every normal start clears it again.
    func start(safeMode: Bool = false) async {
        guard Self.mayStart(inFlightSince: startInFlightSince) else {
            Self.trace("ignored: another start is still in progress (since \(Int(Date().timeIntervalSince(startInFlightSince ?? Date()))) s)")
            return
        }
        if let since = startInFlightSince {
            Self.trace("previous start stuck for \(Int(Date().timeIntervalSince(since))) s — starting again")
        }
        startToken &+= 1
        let token = startToken
        startInFlightSince = Date()
        // fix/app-toggle-hitch: optimistic 连接中 until iOS reports the new status (verifyStartTookEffect waits for
        // it) or the start gives up; then the switch follows `status` again.
        if !pendingStart { pendingStart = true }
        defer {
            if startToken == token {
                startInFlightSince = nil
                if pendingStart { pendingStart = false }
            }
        }
        let t0 = DispatchTime.now().uptimeNanoseconds
        Self.trace("requested (status \(status.rawValue), safeMode \(safeMode))")
        let seq = stopSeq
        if lastError != nil { lastError = nil }
        if canOfferSafeMode { canOfferSafeMode = false }
        // fix/app-toggle-hitch: App Group / profile checks, overrides.json (+ secrets.json, Keychain on a fresh
        // install) read + write and the old error log removal used to run on the main actor; one detached hop now.
        let pre = await Task.detached(priority: .userInitiated) { () -> (ok: Bool, profile: Bool, o: CoreOverrides) in
            guard AppShared.containerOK else { return (false, false, CoreOverrides()) }
            guard AppShared.activeProfileURL != nil else { return (true, false, CoreOverrides()) }
            var o = CoreOverrides.load()
            if o.safeMode != safeMode {
                o.safeMode = safeMode
                o.save()
            }
            TunnelErrorLog.clear()
            return (true, true, o)
        }.value
        guard pre.ok else {
            lastError = String(localized: "App Group 不可用：重签名的描述文件需要包含 App Groups，且主程序和扩展使用同一个组。详见 更多 → 诊断。")
            return
        }
        guard pre.profile else {
            lastError = String(localized: "请先在「更多 → 配置」中添加并选择一个配置")
            return
        }
        let o = pre.o
        isBusy = true
        defer { isBusy = false }
        // v0.19 覆写脚本: the active profile's scripts run (when anything changed) before the tunnel starts;
        // a failing script stops the connect with its error instead of running an unexpected config.
        let tScripts = DispatchTime.now().uptimeNanoseconds
        if !safeMode, let err = await OverrideScriptStore.shared.prepareActive() {
            lastError = err
            canOfferSafeMode = AppShared.containerOK
            return
        }
        let scriptsMs = Self.ms(since: tScripts)
        if safeModeActive != safeMode { safeModeActive = safeMode }
        do {
            // fix/nc-vpn-start-crash: prepare the runtime BEFORE enabling the configuration / arming on-demand.
            // Arming 保持连接 (connect on any network) first let iOS bring the tunnel up by itself while the app was
            // still preparing — with the PREVIOUS generation of runtime files — and then `start` saw .connected and
            // never started the new one. When the prepare crashed the app (build #374), that on-demand tunnel was
            // left running on stale files: "connected, but no network at all".
            // fix/app-toggle-hitch: off the main actor (detached) and skipped when the runtime on disk was built
            // from exactly the current inputs (NativeRuntimePrepCache).
            let prep = await NativeRuntimePrep.prepare(allowCached: true)
            if let err = prep.error {
                Self.trace("prepare failed after \(prep.millis) ms (\(prep.breakdown))")
                lastError = err
                return
            }
            let tPrefs = DispatchTime.now().uptimeNanoseconds
            let m = try await ensureManager()
            // fix/nc-start-empty: what iOS has now (another VPN may have disabled ours since we loaded it).
            do { try await m.loadFromPreferences() } catch { Self.trace("loadFromPreferences failed: \(error.localizedDescription)") }
            if !m.isEnabled { Self.trace("configuration is disabled in iOS (another VPN was enabled?) — enabling it again") }
            // r7 (review7 R7A-2): the scope in overrides.json (restored backup / snapshot / sync, a page that
            // short-circuited) must be what iOS enforces — re-applied before every start when it differs.
            var needsSave = false
            if !UITestSeed.enabled, let proto = m.protocolConfiguration as? NETunnelProviderProtocol, !Self.scopeMatches(o, proto) {
                Self.applyScope(o, to: proto)
                m.protocolConfiguration = proto
                needsSave = true
            }
            if !m.isEnabled {
                m.isEnabled = true
                needsSave = true
            }
            // A manual connect resumes on-demand rules paused by an earlier manual disconnect, and (保持连接,
            // fix/vpn-stays-on) arms the keep-alive rule: iOS restarts the tunnel if the extension is ended.
            // fix/app-toggle-hitch: folded into the same save as enable / scope (one preferences round trip
            // instead of two).
            if !UITestSeed.enabled, Self.stageOnDemandRules(on: m, settings: OnDemandSettings.load(), enabled: true) {
                needsSave = true
            }
            if needsSave {
                do {
                    try await m.saveToPreferences()
                    try await m.loadFromPreferences()
                } catch {
                    NSLog("[Tern] saveToPreferences (enable) failed: %@", error.localizedDescription)
                    throw error
                }
            }
            let prefsMs = Self.ms(since: tPrefs)
            userStopped = false
            // rv2-life: the user stopped while we were preparing, or iOS is already bringing it up (on-demand)
            guard seq == stopSeq else {
                Self.trace("abandoned: stop() arrived while preparing")
                return
            }
            if [.connected, .connecting, .reasserting].contains(m.connection.status) {
                Self.trace("tunnel already \(m.connection.status.rawValue), not starting again")
                update(from: m.connection)
                return
            }
            let tStart = DispatchTime.now().uptimeNanoseconds
            do {
                try m.connection.startVPNTunnel(options: TunnelStartOption.options)
            } catch let e as NSError where e.domain == NEVPNErrorDomain && e.code == NEVPNError.Code.configurationDisabled.rawValue {
                // fix/nc-start-empty: disabled behind our back (stale cached flag): enable, save, try once more.
                Self.trace("startVPNTunnel: configuration disabled — re-enabling and retrying once")
                m.isEnabled = true
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
                try m.connection.startVPNTunnel(options: TunnelStartOption.options)
            }
            Self.trace("startVPNTunnel accepted (status \(m.connection.status.rawValue))")
            // fix/app-toggle-hitch: one timing line per connect (startup log, tag app).
            // fix/nc-open-6-10 #8: where the prepare time went, one line before the summary.
            if !prep.breakdown.isEmpty { Self.trace("prepare stages (ms): \(prep.breakdown)") }
            Self.trace("prepare \(prep.millis) ms (\(prep.cached ? "cached" : "built")), prefs \(prefsMs) ms\(needsSave ? " (saved)" : ""), start \(Self.ms(since: tStart)) ms, scripts \(scriptsMs) ms, total \(Self.ms(since: t0)) ms")
            await verifyStartTookEffect(m)
        } catch {
            Self.trace("failed: \(Self.describe(error))")
            lastError = String(localized: "启动失败：") + Self.describe(error)
            NSLog("[Tern] start failed: %@", error.localizedDescription)
        }
    }

    /// fix/nc-start-empty: startVPNTunnel returned without error but iOS never left 未连接 (a disabled or stale
    /// configuration is ignored silently on some iOS versions). Say so instead of a switch that does nothing.
    private func verifyStartTookEffect(_ m: NETunnelProviderManager) async {
        for _ in 0..<25 { // ≤ 5 s
            if m.connection.status != .disconnected && m.connection.status != .invalid { return }
            if status != .disconnected && status != .invalid { return }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        guard m.connection.status == .disconnected || m.connection.status == .invalid, lastError == nil else { return }
        Self.trace("iOS did not start the tunnel within 5 s (status \(m.connection.status.rawValue), enabled \(m.isEnabled))")
        lastError = String(localized: "系统没有启动 VPN（5 秒内仍为未连接）。请到 设置 → VPN 选中 Tern 后再试；若仍无效，在 更多 → 诊断 重置 VPN 配置。")
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
    /// 高级设置 → 隧道 (feat/tunnel-include-options): 兼容性增强模式 is enforceRoutes; never with includeAllNetworks.
    static func applyScope(_ o: CoreOverrides, to proto: NETunnelProviderProtocol) {
        proto.includeAllNetworks = o.effectiveIncludeAll
        proto.enforceRoutes = o.effectiveEnforceRoutes
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
        if proto.enforceRoutes != o.effectiveEnforceRoutes { return false }
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
        stopSeq &+= 1
        guard let m = manager else { return }
        // fix/app-toggle-hitch: the switch shows off at once (saving the paused on-demand flag first takes a
        // preferences round trip); update(from:) clears it on .disconnecting, the timer if iOS never moves.
        if [.connected, .connecting, .reasserting].contains(m.connection.status) {
            pendingStop = true
            let seq = stopSeq
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard let self, self.stopSeq == seq, self.pendingStop else { return }
                self.pendingStop = false
            }
        }
        if m.isOnDemandEnabled {
            // Otherwise iOS would reconnect right away: pause on-demand until the next manual connect.
            m.isOnDemandEnabled = false
            OnDemandSettings.setPaused(true)
            Task {
                do { try await m.saveToPreferences() } catch { NSLog("[Tern] pause on-demand failed: %@", error.localizedDescription) }
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
        guard Self.stageOnDemandRules(on: m, settings: settings, enabled: enabled) else { return }
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
    }

    /// fix/app-toggle-hitch: puts the on-demand rules on `m` without saving; true when anything changed (the
    /// caller saves). Same rules as applyOnDemandRules.
    @discardableResult
    static func stageOnDemandRules(on m: NETunnelProviderManager, settings: OnDemandSettings, enabled: Bool) -> Bool {
        let rules = settings.rules
        let want = enabled && !rules.isEmpty
        let changed = m.isOnDemandEnabled != want || OnDemandSettings.signature(m.onDemandRules ?? []) != OnDemandSettings.signature(rules)
        guard changed else { return false }
        m.onDemandRules = rules
        m.isOnDemandEnabled = want
        OnDemandSettings.setPaused(false)
        return true
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

    private var reloadRunning = false
    private var reloadTrailing: [CheckedContinuation<String?, Never>] = []
    private var reloadTrailingHot = true

    /// Asks the tunnel to re-read the active profile and overrides. Returns an error message or nil.
    /// `hot` (v0.19.22 开关类设置热应用): a switch the user flipped — the core applies rule / rule-set / mode / log-level /
    /// engine changes in place and does the full reload for anything else. File refreshes (geo,
    /// providers, resources) and edits keep the full reload.
    /// Requests made while one is running share one trailing reload (full when any of them asked for full), so a burst
    /// of toggles costs at most two.
    func reload(hot: Bool = false) async -> String? {
        guard isConnected else { return nil }
        if reloadRunning {
            return await withCheckedContinuation { (c: CheckedContinuation<String?, Never>) in
                reloadTrailingHot = reloadTrailing.isEmpty ? hot : (reloadTrailingHot && hot)
                reloadTrailing.append(c)
            }
        }
        reloadRunning = true
        let r = await reloadNow(hot: hot)
        if reloadTrailing.isEmpty {
            reloadRunning = false
        } else {
            Task { @MainActor [weak self] in await self?.drainTrailingReloads() }
        }
        return r
    }

    private func drainTrailingReloads() async {
        while !reloadTrailing.isEmpty {
            let waiters = reloadTrailing, hot = reloadTrailingHot
            reloadTrailing = []
            let r = isConnected ? await reloadNow(hot: hot) : nil
            for c in waiters { c.resume(returning: r) }
        }
        reloadRunning = false
    }

    private func reloadNow(hot: Bool) async -> String? {
        guard isConnected else { return nil }
        if !safeModeActive, let err = await OverrideScriptStore.shared.prepareActive() { return err } // v0.19 覆写脚本
        // v0.19.8: the extension answers when the new config is applied; with proxy-providers that takes longer than
        // the 8 s default, and a reply missing after 8 s used to count as success while the core still ran the old
        // config (a group order save then read the old order back and looked like it did nothing).
        // feat/native-core-eval: the tunnel re-reads it. fix/nc-open-6-10 #8: timing line in the startup log.
        let prep = await NativeRuntimePrep.prepare(allowCached: false)
        Self.traceQueue.async {
            StartupLog.write("reload prepare \(prep.millis) ms\(prep.error == nil ? "" : " (failed)"): \(prep.breakdown)", tag: "app", mirror: false)
        }
        if let err = prep.error { return err }
        let before = Self.reloadStatus(await send(.reloadStatus, timeout: 3))
        let data = await send(hot ? .reloadHot : .reload, timeout: 45)
        NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        if data == nil, isConnected, let r = await followUpReload(baseline: before?.done) { return r.message }
        return Self.reloadResult(data, stillConnected: isConnected)
    }

    /// fix/xmly-memory-2 (device 2026-10-24 22:14, 喜马拉雅 open, 3 MB available: 「重载失败：重新加载超时」): the reply
    /// to a reload can be late or lost while the extension is memory-critical, though the core goes on applying it. After
    /// the 45 s timeout ask the core (`reloadStatus`, answered at once) for up to 60 s more: a finished reload reports
    /// its real result; still running or no answer → nil (the caller keeps the timeout message).
    private func followUpReload(baseline: Int64?) async -> ReloadFollowUp? {
        let deadline = Date().addingTimeInterval(60)
        while isConnected, Date() < deadline {
            let st = Self.reloadStatus(await send(.reloadStatus, timeout: 3))
            switch Self.reloadFollowUp(st, baselineDone: baseline) {
            case .finished(let msg): return .finished(msg)
            case .unknown: return nil
            case .running: try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
        return nil
    }

    struct ReloadStatus: Decodable, Equatable {
        var running: Bool
        var seq: Int64
        var done: Int64
        var lastError: String
    }

    enum ReloadFollowUp: Equatable {
        case finished(String?) // the reload's own result (nil = applied)
        case running
        case unknown
        var message: String? { if case .finished(let m) = self { return m }; return nil }
    }

    nonisolated static func reloadStatus(_ data: Data?) -> ReloadStatus? {
        guard let data else { return nil }
        return try? JSONDecoder().decode(ReloadStatus.self, from: data)
    }

    /// What a reload status read after a timed-out reply means. baselineDone: reloads finished before this one was sent
    /// (nil when that read failed: then only "nothing running any more" counts as finished).
    nonisolated static func reloadFollowUp(_ st: ReloadStatus?, baselineDone: Int64?) -> ReloadFollowUp {
        guard let st else { return .unknown }
        if st.running { return .running }
        if let b = baselineDone, st.done <= b { return .unknown } // ours never reached the core: really lost
        return .finished(st.lastError.isEmpty ? nil : st.lastError)
    }

    /// The text reloadResult gives for a reply that timed out (callers that run in the background stay quiet on it).
    nonisolated static var reloadTimeoutMessage: String { String(localized: "重新加载超时：内核可能仍在使用旧配置，请稍后重试或重新连接。") }

    /// Review 6 R6A-3: nil = applied. No reply while the tunnel is still up means the reload did not finish within
    /// the timeout (the core may still run the old config) — that used to count as success. No reply because the
    /// tunnel went down is fine: the next start reads the new config anyway.
    nonisolated static func reloadResult(_ data: Data?, stillConnected: Bool) -> String? {
        guard let data else {
            return stillConnected ? reloadTimeoutMessage : nil
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
    /// 包含 APNs (excludeAPNs off) only with every network in the tunnel; otherwise the system default (excluded).
    var effectiveExcludeAPNs: Bool { effectiveIncludeAll ? excludeAPNs : true }
    /// 兼容性增强模式: split routes only (never with includeAllNetworks); 仅代理 has no routes to enforce.
    var effectiveEnforceRoutes: Bool { enforceRoutes && !effectiveIncludeAll && !isProxyOnly }
}
