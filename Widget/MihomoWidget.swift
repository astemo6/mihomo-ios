import WidgetKit
import SwiftUI
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
                Label(isOn ? LocalizedStringKey("已连接") : LocalizedStringKey("未连接"), systemImage: isOn ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle")
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
        .description("出口位置、当前策略链、今日流量和开关")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryCircular, .accessoryInline])
    }
}

// qx/rebuild: Quantumult X look — light grey / dark background, white card feel, blue switch, windmill.
enum WidgetTheme {
    static let bg = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: 0.06, green: 0.065, blue: 0.09, alpha: 1) : UIColor(red: 0.949, green: 0.949, blue: 0.969, alpha: 1) })
    static let card = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: 0.11, green: 0.12, blue: 0.15, alpha: 1) : .white })
    static let good = Color(red: 0.25, green: 0.85, blue: 0.48)
    static let blue = Color(red: 0.0, green: 0.48, blue: 1.0)
    static let accent = blue
    static let down = Color(red: 0.25, green: 0.55, blue: 1.0)
    static let up = Color(red: 0.62, green: 0.35, blue: 0.95)
}

struct WidgetWindmill: View {
    let mode: String
    var size: CGFloat = 18
    var colors: [Color] {
        let teal = Color(red: 0.20, green: 0.78, blue: 0.80), yellow = Color(red: 1.0, green: 0.76, blue: 0.10), red = Color(red: 0.95, green: 0.22, blue: 0.25)
        switch mode {
        case "global": return [teal, teal, teal]
        case "direct": return [yellow, yellow, yellow]
        default: return [red, yellow, teal]
        }
    }
    var body: some View {
        ZStack { ForEach(0..<3, id: \.self) { i in WidgetBlade(angle: Double(i) * 120).fill(colors[i]) } }
            .frame(width: size, height: size)
    }
}

struct WidgetBlade: Shape {
    let angle: Double
    func path(in rect: CGRect) -> Path {
        let c = CGPoint(x: rect.midX, y: rect.midY)
        let r = min(rect.width, rect.height) / 2
        func pt(_ deg: Double, _ d: CGFloat) -> CGPoint {
            let a = (deg - 90) * .pi / 180
            return CGPoint(x: c.x + CGFloat(cos(a)) * d, y: c.y + CGFloat(sin(a)) * d)
        }
        var p = Path()
        p.move(to: pt(angle + 200, r * 0.12))
        p.addLine(to: pt(angle, r))
        p.addLine(to: pt(angle + 62, r * 0.48))
        p.closeSubpath()
        return p
    }
}

struct StatusWidgetView: View {
    @Environment(\.widgetFamily) var family
    let entry: StatusEntry

    var today: TrafficDay? {
        let key = TrafficHistory.dayFormatter.string(from: Date())
        return TrafficHistory.load().first { $0.day == key }
    }

    var flag: String { entry.snapshot.flag ?? "🌐" }
    var place: String { entry.on ? (entry.snapshot.place ?? entry.snapshot.node) : String(localized: "未连接") }
    var chainText: String {
        guard entry.on else { return "—" }
        if let c = entry.snapshot.chain, !c.isEmpty { return c }
        return entry.snapshot.node.isEmpty ? "—" : entry.snapshot.node
    }

    var body: some View {
        switch family {
        case .accessoryInline:
            Text(verbatim: entry.on ? "\(flag) \(entry.snapshot.place ?? entry.snapshot.node)" : "Mihomo")
        case .accessoryCircular:
            Button(intent: ToggleTunnelIntent()) {
                ZStack {
                    AccessoryWidgetBackground()
                    VStack(spacing: 1) {
                        Text(verbatim: entry.on ? flag : "⏻").font(.title3)
                        Text(entry.on ? LocalizedStringKey("开") : LocalizedStringKey("关")).font(.caption2.weight(.semibold))
                    }
                }
            }
            .buttonStyle(.plain)
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(verbatim: entry.on ? flag : "⏻")
                    Text(verbatim: place).font(.headline).lineLimit(1)
                }
                Text(verbatim: chainText).font(.caption).lineLimit(1)
                if let t = today { Text(verbatim: "↓ \(bytes(t.down))  ↑ \(bytes(t.up))").font(.caption2.monospacedDigit()) }
            }
        case .systemMedium:
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    locationHeader
                    Spacer(minLength: 8)
                    VStack(alignment: .trailing, spacing: 6) {
                        toggle
                        if let r = entry.snapshot.remaining, !r.isEmpty {
                            Text(verbatim: r).font(.system(size: 11, weight: .medium).monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                Spacer(minLength: 0)
                HStack(spacing: 10) {
                    WidgetWindmill(mode: entry.snapshot.mode ?? "rule", size: 22)
                    Text(verbatim: chainText).font(.system(size: 13, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer(minLength: 4)
                    if let t = today {
                        trafficLabel("chevron.down.circle.fill", WidgetTheme.down, t.down)
                        trafficLabel("chevron.up.circle.fill", WidgetTheme.up, t.up)
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 9)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(WidgetTheme.card))
            }
        default:
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .top) {
                    Text(verbatim: entry.on ? flag : "⏻").font(.system(size: 22))
                    Spacer(minLength: 0)
                    WidgetWindmill(mode: entry.snapshot.mode ?? "rule", size: 20)
                }
                Text(verbatim: place).font(.system(size: 17, weight: .bold)).lineLimit(1).minimumScaleFactor(0.7)
                Text(verbatim: chainText).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).lineLimit(2)
                Spacer(minLength: 0)
                toggle
            }
        }
    }

    var locationHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(verbatim: entry.on ? flag : "⏻").font(.system(size: 20))
                Text(verbatim: place).font(.system(size: 20, weight: .bold)).lineLimit(1).minimumScaleFactor(0.7)
            }
            Text(verbatim: entry.on ? (entry.snapshot.detail ?? "").uppercased() : String(localized: "轻点开关连接"))
                .font(.system(size: 11, weight: .medium).monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
        }
    }

    func trafficLabel(_ icon: String, _ color: Color, _ v: Int64) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).font(.system(size: 11)).foregroundStyle(color)
            Text(verbatim: bytes(v)).font(.system(size: 12).monospacedDigit())
        }
    }

    func bytes(_ v: Int64) -> String { ByteCountFormatter.string(fromByteCount: v, countStyle: .binary) }

    var toggle: some View {
        Button(intent: ToggleTunnelIntent()) {
            ZStack(alignment: entry.on ? .trailing : .leading) {
                Capsule().fill(entry.on ? WidgetTheme.blue : Color.secondary.opacity(0.3)).frame(width: 50, height: 30)
                Circle().fill(Color.white).frame(width: 26, height: 26).padding(2).shadow(radius: 1)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(entry.on ? LocalizedStringKey("断开") : LocalizedStringKey("连接")))
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
                        LiveSpeeds(state: context.state)
                    }
                    .padding(.horizontal, 4)
                }
            } compactLeading: {
                Image(systemName: "network").foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
            } compactTrailing: {
                Text("↓" + LiveActivityFormat.speed(context.state.down)).font(.caption2.monospacedDigit()).foregroundStyle(WidgetTheme.accent)
            } minimal: {
                Image(systemName: "network").foregroundStyle(context.state.connected ? WidgetTheme.good : .secondary)
            }
        }
    }
}

struct LiveSpeeds: View {
    let state: MihomoActivityAttributes.ContentState
    var body: some View {
        HStack(spacing: 8) {
            Text("↑" + LiveActivityFormat.speed(state.up) + "/s").foregroundStyle(.orange)
            Text("↓" + LiveActivityFormat.speed(state.down) + "/s").foregroundStyle(WidgetTheme.accent)
        }
        .font(.caption.monospacedDigit())
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
            LiveSpeeds(state: context.state)
        }
        .padding(14)
    }
}
