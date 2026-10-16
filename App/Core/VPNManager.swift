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
        case .connected: return "已连接"
        case .connecting: return "连接中…"
        case .disconnecting: return "断开中…"
        case .reasserting: return "重连中…"
        case .disconnected: return "未连接"
        case .invalid: return "未配置"
        @unknown default: return "未知"
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
        lastError = "连接失败：" + (msg ?? "网络扩展启动后立即退出（未返回原因）。请到 更多 → 内核覆写设置 → 诊断 查看 App Group 与扩展 ID。")
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
        manager?.connection.stopVPNTunnel()
    }

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
