import Foundation
#if canImport(ActivityKit) && !os(macOS)
import ActivityKit
import AppIntents
import NetworkExtension

// r7: shared by the widget extension (widget button, Control Center toggle) and the app. The toggle intents are
// LiveActivityIntents, so iOS performs them in the app's process and a disconnect also ends the Live Activity even
// when the app was not running. App + widget only (the tunnel excludes this file).

// MARK: - Tunnel control (shared by the widget button and the Control Center toggle)

enum VPNControl {
    static func manager() async -> NETunnelProviderManager? {
        guard let all = try? await NETunnelProviderManager.loadAllFromPreferences() else { return nil }
        // r7: only our own tunnel (bundle id) — never another configuration as a fallback; nil = ControlError.noConfiguration.
        return all.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppShared.tunnelBundleID }
    }

    static func status() async -> NEVPNStatus {
        await manager()?.connection.status ?? .invalid
    }

    static func isOn() async -> Bool {
        let s = await status()
        return s == .connected || s == .connecting || s == .reasserting
    }

    /// Same rules as the app: a manual connect resumes paused on-demand rules and never starts in 安全模式;
    /// a manual disconnect pauses on-demand so iOS does not reconnect right away.
    static func set(_ on: Bool) async throws {
        guard let m = await manager() else { throw ControlError.noConfiguration }
        if on {
            var o = CoreOverrides.load()
            if o.safeMode { o.safeMode = false; o.save() }
            var dirty = false
            if !m.isEnabled { m.isEnabled = true; dirty = true }
            if !(m.onDemandRules ?? []).isEmpty && !m.isOnDemandEnabled {
                m.isOnDemandEnabled = true
                AppShared.defaults.set(false, forKey: "onDemandPaused")
                dirty = true
            }
            if dirty {
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            try m.connection.startVPNTunnel(options: TunnelStartOption.options)
        } else {
            if m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                AppShared.defaults.set(true, forKey: "onDemandPaused")
                try? await m.saveToPreferences()
            }
            m.connection.stopVPNTunnel()
        }
        // Give the state a moment to move so the refreshed widget shows it.
        for _ in 0..<15 {
            let s = m.connection.status
            if on ? (s == .connected) : (s == .disconnected) { break }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    /// r7: a disconnect from the widget / Control Center while the app is not running left the Live Activity on the
    /// Lock Screen. These intents are LiveActivityIntents compiled into the app too, so iOS runs perform() in the app's
    /// process (launching it in the background), where ActivityKit may end the activity.
    @available(iOS 16.2, *)
    static func endLiveActivities() async {
        for a in Activity<TernActivityAttributes>.activities {
            var s = a.content.state
            s.connected = false; s.up = 0; s.down = 0; s.updated = Date()
            await a.end(ActivityContent(state: s, staleDate: nil), dismissalPolicy: .immediate)
        }
    }

    enum ControlError: Error, CustomLocalizedStringResourceConvertible {
        case noConfiguration
        var localizedStringResource: LocalizedStringResource { "请先打开 Tern 添加 VPN 配置" }
    }
}

@available(iOS 17.0, *)
struct ToggleTunnelIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "切换代理"
    static var description = IntentDescription("连接或断开 Tern。")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult {
        let on = await VPNControl.isOn()
        try await VPNControl.set(!on)
        if on { await VPNControl.endLiveActivities() }
        return .result()
    }
}

@available(iOS 17.0, *)
struct SetTunnelIntent: SetValueIntent, LiveActivityIntent {
    static var title: LocalizedStringResource = "设置代理开关"
    static var openAppWhenRun = false

    @Parameter(title: "开启")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try await VPNControl.set(value)
        if !value { await VPNControl.endLiveActivities() }
        return .result()
    }
}
#endif
