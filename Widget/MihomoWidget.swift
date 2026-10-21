import WidgetKit
import SwiftUI
import UIKit
import AppIntents
import NetworkExtension
import ActivityKit

// Mihomo widget extension (v0.7, only in the "-widget" IPA): a Home / Lock Screen widget with the
// connection state, current policy / node and a toggle (interactive, iOS 17+), and a Control Center toggle
// (iOS 18+). It shares data with the app only through the App Group (resolved at runtime like the app and
// the tunnel, so re-signed builds keep working) and drives the tunnel with the public NETunnelProviderManager
// API. Nothing here touches the Network Extension's memory.

@main
struct MihomoWidgets: WidgetBundle {
    var body: some Widget {
        StatusWidget()
        ConnectionLiveActivity()
        if #available(iOS 18.0, *) {
            TunnelToggleControl()
            ModeControl()
        }
    }
}

// MARK: - Tunnel control (shared by the widget button and the Control Center toggle)

enum VPNControl {
    static func manager() async -> NETunnelProviderManager? {
        guard let all = try? await NETunnelProviderManager.loadAllFromPreferences() else { return nil }
        return all.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppShared.tunnelBundleID } ?? all.first
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
            try m.connection.startVPNTunnel()
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

    enum ControlError: Error, CustomLocalizedStringResourceConvertible {
        case noConfiguration
        var localizedStringResource: LocalizedStringResource { "请先打开 Tern 添加 VPN 配置" }
    }
}

struct ToggleTunnelIntent: AppIntent {
    static var title: LocalizedStringResource = "切换代理"
    static var description = IntentDescription("连接或断开 Tern。")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult {
        let on = await VPNControl.isOn()
        try await VPNControl.set(!on)
        return .result()
    }
}

struct SetTunnelIntent: SetValueIntent {
    static var title: LocalizedStringResource = "设置代理开关"
    static var openAppWhenRun = false

    @Parameter(title: "开启")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try await VPNControl.set(value)
        return .result()
    }
}

// MARK: - Outbound mode (v0.13: Control Center control + widget row)

/// Reads and switches the outbound mode from the widget extension: the stored mode in overrides.json
/// (what the next start uses) and, while connected, the running core through its loopback controller.
enum ModeControlCore {
    static let order = ["rule", "global", "direct"]

    static func title(_ m: String) -> LocalizedStringResource {
        switch m {
        case "global": return "全局"
        case "direct": return "直连"
        default: return "规则"
        }
    }

    static func symbol(_ m: String) -> String {
        switch m {
        case "global": return "globe"
        case "direct": return "arrow.right.circle"
        default: return "arrow.triangle.branch"
        }
    }

    private static func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, overrides: CoreOverrides? = nil) -> URLRequest? {
        let o = overrides ?? CoreOverrides.load()
        let port = (1...65535).contains(o.controllerPort) ? o.controllerPort : 9090
        guard let url = URL(string: "http://127.0.0.1:\(port)\(path)") else { return nil }
        var r = URLRequest(url: url, timeoutInterval: 2)
        r.httpMethod = method
        if !o.secret.isEmpty { r.setValue("Bearer \(o.secret)", forHTTPHeaderField: "Authorization") }
        if let body, let d = try? JSONSerialization.data(withJSONObject: body) {
            r.httpBody = d
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return r
    }

    /// The running core's mode while connected (a network trigger may have changed it), else the stored one.
    /// Review 6 OPT-2: `connected` lets the timeline pass the status it already loaded (one
    /// loadAllFromPreferences per refresh instead of two); overrides.json + Keychain are read once.
    static func current(connected: Bool? = nil) async -> String {
        let o = CoreOverrides.load()
        let on: Bool
        if let connected { on = connected } else { on = await VPNControl.isOn() }
        if on, let r = request("/configs", overrides: o),
           let res = try? await URLSession.shared.data(for: r),
           let j = try? JSONSerialization.jsonObject(with: res.0) as? [String: Any], let m = (j["mode"] as? String)?.lowercased(),
           order.contains(m) {
            return m
        }
        let m = o.mode.lowercased()
        return order.contains(m) ? m : "rule"
    }

    static func set(_ m: String) async {
        var o = CoreOverrides.load()
        o.mode = m
        o.save()
        guard await VPNControl.isOn() else { return }
        if let r = request("/configs", method: "PATCH", body: ["mode": m], overrides: o) { _ = try? await URLSession.shared.data(for: r) }
        // Same as the app: drop existing connections so they follow the new mode — only when 切换节点或模式时
        // 断开所有连接 is on (v0.19.3: the widget ignored that setting).
        let close = AppShared.defaults.object(forKey: "switch.closeConnections") as? Bool ?? true
        if close, let r = request("/connections", method: "DELETE", overrides: o) { _ = try? await URLSession.shared.data(for: r) }
    }
}

struct CycleModeIntent: AppIntent {
    static var title: LocalizedStringResource = "切换出站模式"
    static var description = IntentDescription("在 规则 → 全局 → 直连 之间切换。")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult {
        let cur = await ModeControlCore.current()
        let i = ModeControlCore.order.firstIndex(of: cur) ?? 0
        await ModeControlCore.set(ModeControlCore.order[(i + 1) % ModeControlCore.order.count])
        WidgetCenter.shared.reloadAllTimelines()
        if #available(iOS 18.0, *) { ControlCenter.shared.reloadAllControls() }
        return .result()
    }
}

@available(iOS 18.0, *)
struct ModeControl: ControlWidget {
    static let kind = "MihomoModeControl"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { mode in
            ControlWidgetButton(action: CycleModeIntent()) {
                Label {
                    Text(ModeControlCore.title(mode))
                } icon: {
                    Image(systemName: ModeControlCore.symbol(mode))
                }
            }
        }
        .displayName("出站模式")
        .description("在 规则 → 全局 → 直连 之间切换")
    }

    struct Provider: ControlValueProvider {
        var previewValue: String { "rule" }
        func currentValue() async throws -> String { await ModeControlCore.current() }
    }
}

// MARK: - Control Center (iOS 18)

@available(iOS 18.0, *)
struct TunnelToggleControl: ControlWidget {
    static let kind = "MihomoTunnelToggle"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { on in
            ControlWidgetToggle("Tern", isOn: on, action: SetTunnelIntent()) { isOn in
                Label(isOn ? "已连接" : "未连接", systemImage: isOn ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle")
            }
        }
        .displayName("Tern")
        .description("连接或断开代理")
    }

    struct Provider: ControlValueProvider {
        var previewValue: Bool { false }
        func currentValue() async throws -> Bool { await VPNControl.isOn() }
    }
}

// MARK: - Widget

struct StatusEntry: TimelineEntry {
    let date: Date
    let status: NEVPNStatus
    let snapshot: WidgetSnapshot
    let profile: String
    var mode: String = "rule"

    var on: Bool { [.connected, .connecting, .reasserting].contains(status) }

    var statusText: LocalizedStringKey {
        switch status {
        case .connected: return "已连接"
        case .connecting: return "连接中…"
        case .disconnecting: return "断开中…"
        case .reasserting: return "重连中…"
        case .invalid: return "未配置"
        default: return "未连接"
        }
    }
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: Date(), status: .connected, snapshot: WidgetSnapshot(node: "🇯🇵 Tokyo 01", policy: "Proxy", profile: "Tern"), profile: "Tern")
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        if context.isPreview { completion(placeholder(in: context)); return }
        Task { completion(await entry()) }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        Task {
            let e = await entry()
            // The app reloads the timeline on every state / node change; this is only a safety net.
            completion(Timeline(entries: [e], policy: .after(Date().addingTimeInterval(30 * 60))))
        }
    }

    private func entry() async -> StatusEntry {
        let snap = WidgetSnapshot.load()
        // Review 6 OPT-2: one VPN preferences load per timeline refresh; the mode lookup reuses it.
        let status = await VPNControl.status()
        let on = status == .connected || status == .connecting || status == .reasserting
        return StatusEntry(date: Date(), status: status, snapshot: snap, profile: snap.profile, mode: await ModeControlCore.current(connected: on))
    }
}

struct StatusWidget: Widget {
    let kind = "MihomoStatus"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
                .containerBackground(for: .widget) { WidgetTheme.bg }
        }
        .configurationDisplayName("Tern")
        .description("连接状态、当前节点和开关")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryCircular, .accessoryInline])
    }
}

// WidgetTheme lives in Shared/LiveActivityViews.swift (v0.19.14; shared with the Live Activity views).

struct StatusWidgetView: View {
    @Environment(\.widgetFamily) var family
    let entry: StatusEntry

    var body: some View {
        switch family {
        case .accessoryCircular:
            Button(intent: ToggleTunnelIntent()) {
                ZStack {
                    AccessoryWidgetBackground()
                    Image(systemName: entry.on ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle").font(.title2)
                }
            }
            .buttonStyle(.plain)
        case .accessoryInline:
            // Lock Screen line above the clock: state, then the node while connected.
            Label {
                if entry.on && !entry.snapshot.node.isEmpty { Text(entry.snapshot.node) } else { Text(entry.statusText) }
            } icon: {
                Image(systemName: entry.on ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle")
            }
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 2) {
                Label { Text(entry.statusText).font(.headline) } icon: { Image(systemName: entry.on ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle") }
                Text(nodeText).font(.caption).lineLimit(1)
                if entry.on { Text(ModeControlCore.title(entry.mode)).font(.caption2).foregroundStyle(.secondary) }
            }
        case .systemMedium:
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 8) {
                    header
                    Spacer(minLength: 0)
                    infoRow(icon: "doc.text", text: entry.profile.isEmpty ? "—" : entry.profile)
                    infoRow(icon: "square.stack.3d.up", text: entry.snapshot.policy.isEmpty ? "—" : entry.snapshot.policy)
                    modeRow
                    if let r = entry.snapshot.remaining, !r.isEmpty { infoRow(icon: "gauge.with.dots.needle.33percent", text: r) }
                }
                Spacer(minLength: 0)
                VStack(alignment: .trailing) {
                    toggle
                    Spacer(minLength: 0)
                    Text(nodeText).font(.subheadline.weight(.semibold)).lineLimit(2).multilineTextAlignment(.trailing)
                }
            }
        default:
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    header
                    Spacer(minLength: 0)
                }
                Spacer(minLength: 0)
                Text(nodeText).font(.footnote.weight(.semibold)).lineLimit(2)
                toggle
            }
        }
    }

    var nodeText: String {
        entry.on && !entry.snapshot.node.isEmpty ? entry.snapshot.node : "—"
    }

    var header: some View {
        HStack(spacing: 6) {
            Circle().fill(entry.on ? WidgetTheme.good : Color.secondary.opacity(0.6)).frame(width: 7, height: 7)
            Text(entry.statusText).font(.caption.weight(.semibold))
        }
    }

    /// Tap to cycle 规则 → 全局 → 直连 (same intent as the Control Center control).
    var modeRow: some View {
        Button(intent: CycleModeIntent()) {
            Label { Text(ModeControlCore.title(entry.mode)) } icon: { Image(systemName: ModeControlCore.symbol(entry.mode)) }
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .buttonStyle(.plain)
    }

    func infoRow(icon: String, text: String) -> some View {
        Label(text, systemImage: icon).font(.caption).foregroundStyle(.secondary).lineLimit(1)
    }

    var toggle: some View {
        Button(intent: ToggleTunnelIntent()) {
            Label(entry.on ? "断开" : "连接", systemImage: entry.on ? "stop.fill" : "play.fill")
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Capsule().fill(Color.primary.opacity(0.1)))
        }
        .buttonStyle(.plain)
        .tint(WidgetTheme.accent)
    }
}

// MARK: - v0.10 实时活动 / 灵动岛 (layout v0.19.14: views in Shared/LiveActivityViews.swift)

struct ConnectionLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: MihomoActivityAttributes.self) { context in
            LiveActivityLockContent(state: context.state, profile: context.attributes.profile, stale: context.isStale)
                .activityBackgroundTint(WidgetTheme.bg.opacity(0.85))
                .activitySystemActionForegroundColor(WidgetTheme.accent)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    LiveIslandLeading(state: context.state)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    LiveIslandTrailing(state: context.state, stale: context.isStale)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    LiveIslandBottom(state: context.state, profile: context.attributes.profile)
                }
            } compactLeading: {
                // v0.19.8 (user): ↑ left, ↓ right, always numbers; stale = last known values in grey.
                LiveCompactSpeed(up: true, state: context.state, stale: context.isStale)
            } compactTrailing: {
                LiveCompactSpeed(up: false, state: context.state, stale: context.isStale)
            } minimal: {
                Image(systemName: "network")
                    .foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
                    .accessibilityLabel(Text(context.state.connected ? LocalizedStringKey("已连接") : LocalizedStringKey("未连接")))
            }
        }
    }
}
