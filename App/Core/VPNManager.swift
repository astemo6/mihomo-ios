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
    @Published var lastError: String?
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

    private func update(from conn: NEVPNConnection) {
        let old = status
        status = conn.status
        connectedDate = conn.connectedDate
        if old != status, status == .connected || status == .disconnected {
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        }
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppShared.tunnelBundleID } ?? managers.first
            if let m = manager { update(from: m.connection) } else { status = .invalid }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func ensureManager() async throws -> NETunnelProviderManager {
        if let m = manager { return m }
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppShared.tunnelBundleID
        proto.serverAddress = "Mihomo"
        proto.disconnectOnSleep = false
        m.protocolConfiguration = proto
        m.localizedDescription = "Mihomo"
        m.isEnabled = true
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
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
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            try m.connection.startVPNTunnel()
        } catch {
            lastError = "启动失败：\(error.localizedDescription)"
        }
    }

    func stop() {
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
