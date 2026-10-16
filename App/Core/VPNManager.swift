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
        if status == .connected { lastError = nil }
        // Connecting -> disconnected without the user stopping: the extension failed. Never stay silent.
        if (old == .connecting || old == .reasserting), status == .disconnected, !userStopped {
            Task { @MainActor in await self.reportStartFailure(conn) }
        }
        if status == .disconnected { userStopped = false }
        if old != status, status == .connected || status == .disconnected {
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
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
        lastError = "连接失败：" + (msg ?? "网络扩展启动后立即退出（未返回原因）。请到 更多 → 诊断 查看 App Group 与扩展 ID。")
        NSLog("[Mihomo] tunnel start failed: %@", lastError ?? "")
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let mine = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppShared.tunnelBundleID }
            manager = mine ?? managers.first
            if let m = manager {
                try await fixStaleManager(m)
                update(from: m.connection)
            } else { status = .invalid }
        } catch {
            lastError = "读取 VPN 配置失败：\(error.localizedDescription)"
            NSLog("[Mihomo] loadAllFromPreferences: %@", error.localizedDescription)
        }
    }

    /// A manager saved by a build with another tunnel bundle id (e.g. before re-signing) would start a
    /// non-existent extension. Point it at the current one and save again.
    private func fixStaleManager(_ m: NETunnelProviderManager) async throws {
        guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier != AppShared.tunnelBundleID else { return }
        NSLog("[Mihomo] fixing providerBundleIdentifier %@ -> %@", proto.providerBundleIdentifier ?? "nil", AppShared.tunnelBundleID)
        proto.providerBundleIdentifier = AppShared.tunnelBundleID
        m.protocolConfiguration = proto
        m.isEnabled = true
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
        } catch {
            NSLog("[Mihomo] saveToPreferences (fix stale) failed: %@", error.localizedDescription)
            throw error
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
        proto.serverAddress = "Mihomo"
        proto.disconnectOnSleep = false
        m.protocolConfiguration = proto
        m.localizedDescription = "Mihomo"
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

    func start() async {
        lastError = nil
        guard AppShared.activeProfileURL != nil else {
            lastError = "请先在「配置」中添加并选择一个配置"
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            CoreOverrides.load().save()
            let m = try await ensureManager()
            if !m.isEnabled {
                m.isEnabled = true
                do {
                    try await m.saveToPreferences()
                    try await m.loadFromPreferences()
                } catch {
                    NSLog("[Mihomo] saveToPreferences (enable) failed: %@", error.localizedDescription)
                    throw error
                }
            }
            // A manual connect resumes on-demand rules paused by an earlier manual disconnect.
            try await applyOnDemandRules(to: m, settings: OnDemandSettings.load(), enabled: true)
            userStopped = false
            TunnelErrorLog.clear()
            try m.connection.startVPNTunnel()
        } catch {
            lastError = "启动失败：\(error.localizedDescription)"
            NSLog("[Mihomo] start failed: %@", error.localizedDescription)
        }
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
        do {
            let m = try await ensureManager()
            // Turning it on while disconnected manually counts as a fresh choice: not paused.
            try await applyOnDemandRules(to: m, settings: settings, enabled: settings.mode != .off)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func applyOnDemandRules(to m: NETunnelProviderManager, settings: OnDemandSettings, enabled: Bool) async throws {
        let rules = settings.rules
        let want = enabled && settings.mode != .off
        let changed = m.isOnDemandEnabled != want || (m.onDemandRules?.count ?? 0) != rules.count
            || zip(m.onDemandRules ?? [], rules).contains { a, b in ObjectIdentifier(type(of: a)) != ObjectIdentifier(type(of: b)) || a.interfaceTypeMatch != b.interfaceTypeMatch }
        guard changed else { return }
        m.onDemandRules = rules
        m.isOnDemandEnabled = want
        OnDemandSettings.setPaused(false)
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
    }

    var onDemandPaused: Bool { OnDemandSettings.isPaused && OnDemandSettings.load().mode != .off }

    /// Sends a message to the running tunnel and returns its reply.
    func send(_ msg: TunnelMessage) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession, status == .connected else { return nil }
        return await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(msg.rawValue.data(using: .utf8)!) { data in
                    cont.resume(returning: data)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }

    /// Asks the tunnel to re-read the active profile and overrides. Returns an error message or nil.
    func reload() async -> String? {
        guard isConnected else { return nil }
        let data = await send(.reload)
        let msg = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        return msg.isEmpty ? nil : msg
    }
}

/// 按需连接: which networks iOS connects the tunnel on automatically (NEOnDemandRules).
struct OnDemandSettings: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case off, always, wifi, cellular
        var id: String { rawValue }
        var title: String {
            switch self {
            case .off: return String(localized: "关闭")
            case .always: return String(localized: "始终")
            case .wifi: return String(localized: "仅 Wi-Fi")
            case .cellular: return String(localized: "仅蜂窝网络")
            }
        }
    }

    var mode: Mode = .off

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
        switch mode {
        case .off: return []
        case .always: return [connect(.any)]
        case .wifi: return [connect(.wiFi), disconnect(.cellular)]
        case .cellular: return [connect(.cellular), disconnect(.wiFi)]
        }
    }
}
