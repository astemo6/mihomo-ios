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
        var localizedStringResource: LocalizedStringResource { "请先打开 Mihomo 添加 VPN 配置" }
    }
}

struct ToggleTunnelIntent: AppIntent {
    static var title: LocalizedStringResource = "切换代理"
    static var description = IntentDescription("连接或断开 Mihomo。")
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

// MARK: - Control Center (iOS 18)

@available(iOS 18.0, *)
struct TunnelToggleControl: ControlWidget {
    static let kind = "MihomoTunnelToggle"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { on in
            ControlWidgetToggle("Mihomo", isOn: on, action: SetTunnelIntent()) { isOn in
                Label(isOn ? "已连接" : "未连接", systemImage: isOn ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle")
            }
        }
        .displayName("Mihomo")
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
        StatusEntry(date: Date(), status: .connected, snapshot: WidgetSnapshot(node: "🇯🇵 Tokyo 01", policy: "Proxy", profile: "Mihomo"), profile: "Mihomo")
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
        return StatusEntry(date: Date(), status: await VPNControl.status(), snapshot: snap, profile: snap.profile)
    }
}

struct StatusWidget: Widget {
    let kind = "MihomoStatus"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
                .containerBackground(for: .widget) { WidgetTheme.bg }
        }
        .configurationDisplayName("Mihomo")
        .description("连接状态、当前节点和开关")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryCircular])
    }
}

/// Follows the system appearance (v0.9); same values as the app's Theme.
enum WidgetTheme {
    static func dyn(_ l: (CGFloat, CGFloat, CGFloat), _ d: (CGFloat, CGFloat, CGFloat)) -> Color {
        Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: d.0, green: d.1, blue: d.2, alpha: 1) : UIColor(red: l.0, green: l.1, blue: l.2, alpha: 1) })
    }
    static let bg = dyn((1, 1, 1), (0.06, 0.065, 0.09))
    static let good = dyn((0.09, 0.60, 0.29), (0.25, 0.85, 0.48))
    static let accent = dyn((0.0, 0.47, 0.78), (0.29, 0.78, 0.96))
}

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
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 2) {
                Label { Text(entry.statusText).font(.headline) } icon: { Image(systemName: entry.on ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle") }
                Text(nodeText).font(.caption).lineLimit(1)
            }
        case .systemMedium:
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 8) {
                    header
                    Spacer(minLength: 0)
                    infoRow(icon: "doc.text", text: entry.profile.isEmpty ? "—" : entry.profile)
                    infoRow(icon: "square.stack.3d.up", text: entry.snapshot.policy.isEmpty ? "—" : entry.snapshot.policy)
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

// MARK: - v0.10 实时活动 / 灵动岛

struct ConnectionLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: MihomoActivityAttributes.self) { context in
            LiveActivityLockView(context: context)
                .activityBackgroundTint(WidgetTheme.bg.opacity(0.85))
                .activitySystemActionForegroundColor(WidgetTheme.accent)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label {
                        Text(context.state.connected ? "已连接" : "未连接").font(.caption.weight(.semibold))
                    } icon: {
                        Circle().fill(context.state.connected ? WidgetTheme.good : Color.secondary).frame(width: 8, height: 8)
                    }
                    .padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text(timerInterval: context.state.since...Date.distantFuture, countsDown: false)
                        .font(.caption.monospacedDigit()).multilineTextAlignment(.trailing)
                        .frame(maxWidth: 70).padding(.trailing, 4)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    HStack {
                        Label(context.state.node.isEmpty ? context.attributes.profile : context.state.node, systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.caption).lineLimit(1)
                        Spacer()
                        LiveSpeeds(state: context.state, stale: context.isStale)
                        LiveRefreshButton()
                    }
                    .padding(.horizontal, 4)
                }
            } compactLeading: {
                Image(systemName: "network").foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
            } compactTrailing: {
                Text(context.isStale ? "—" : "↓" + LiveActivityFormat.speed(context.state.down)).font(.caption2.monospacedDigit()).foregroundStyle(WidgetTheme.accent)
            } minimal: {
                Image(systemName: "network").foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
            }
        }
    }
}

struct LiveSpeeds: View {
    let state: MihomoActivityAttributes.ContentState
    /// v0.11: past the stale date the numbers are old (the app was not allowed to run): show when they
    /// were taken instead of a frozen speed.
    var stale = false
    var body: some View {
        if stale {
            Text("更新于 \(state.updated.formatted(date: .omitted, time: .shortened))")
                .font(.caption2).foregroundStyle(.secondary)
        } else {
            HStack(spacing: 8) {
                Text("↑" + LiveActivityFormat.speed(state.up) + "/s").foregroundStyle(.orange)
                Text("↓" + LiveActivityFormat.speed(state.down) + "/s").foregroundStyle(WidgetTheme.accent)
            }
            .font(.caption.monospacedDigit())
        }
    }
}

/// v0.11: refreshes the activity from the tunnel's latest numbers (runs in the app process).
struct LiveRefreshButton: View {
    var body: some View {
        Button(intent: RefreshLiveActivityIntent()) {
            Image(systemName: "arrow.clockwise")
                .font(.caption.weight(.semibold))
                .frame(width: 28, height: 28)
                .background(Circle().fill(WidgetTheme.accent.opacity(0.18)))
        }
        .buttonStyle(.plain)
        .foregroundStyle(WidgetTheme.accent)
        .accessibilityLabel(Text("刷新"))
    }
}

struct LiveActivityLockView: View {
    let context: ActivityViewContext<MihomoActivityAttributes>
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "network")
                .font(.title2)
                .foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(context.state.connected ? "Mihomo 已连接" : "Mihomo 未连接").font(.subheadline.weight(.semibold))
                    Text(timerInterval: context.state.since...Date.distantFuture, countsDown: false)
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                Text(context.state.node.isEmpty ? context.attributes.profile : context.state.node)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                LiveSpeeds(state: context.state, stale: context.isStale)
                LiveRefreshButton()
            }
        }
        .padding(14)
    }
}
