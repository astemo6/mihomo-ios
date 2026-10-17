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

// MARK: - Run mode (v0.13 出站模式 control; QX names 规则分流 / 全局代理 / 全局直连, windmill colours)

/// Reads and switches the outbound mode from the widget extension: the stored mode in overrides.json
/// (what the next start uses) and, while connected, the running core through its loopback controller.
enum ModeControlCore {
    static let order = ["rule", "global", "direct"]

    static func title(_ m: String) -> LocalizedStringResource {
        switch m {
        case "global": return "全局代理"
        case "direct": return "全局直连"
        default: return "规则分流"
        }
    }

    static func symbol(_ m: String) -> String {
        switch m {
        case "global": return "globe.asia.australia.fill"
        case "direct": return "arrow.right.circle.fill"
        default: return "arrow.triangle.branch"
        }
    }

    private static func request(_ path: String, method: String = "GET", body: [String: Any]? = nil) -> URLRequest? {
        let o = CoreOverrides.load()
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
    static func current() async -> String {
        if await VPNControl.isOn(), let r = request("/configs"),
           let res = try? await URLSession.shared.data(for: r),
           let j = try? JSONSerialization.jsonObject(with: res.0) as? [String: Any], let m = (j["mode"] as? String)?.lowercased(),
           order.contains(m) {
            return m
        }
        let m = CoreOverrides.load().mode.lowercased()
        return order.contains(m) ? m : "rule"
    }

    static func set(_ m: String) async {
        var o = CoreOverrides.load()
        o.mode = m
        o.save()
        guard await VPNControl.isOn() else { return }
        if let r = request("/configs", method: "PATCH", body: ["mode": m]) { _ = try? await URLSession.shared.data(for: r) }
        // Same as the app: drop existing connections so they follow the new mode.
        if let r = request("/connections", method: "DELETE") { _ = try? await URLSession.shared.data(for: r) }
    }
}

struct CycleModeIntent: AppIntent {
    static var title: LocalizedStringResource = "切换运行模式"
    static var description = IntentDescription("在 规则分流 → 全局代理 → 全局直连 之间切换。")
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
    static let kind = "MihomoQXModeControl"   // qx/rebuild: distinct from the main-line app's control

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { mode in
            ControlWidgetButton(action: CycleModeIntent()) {
                Label {
                    Text(ModeControlCore.title(mode))
                } icon: {
                    Image(systemName: ModeControlCore.symbol(mode))
                }
            }
            .tint(WidgetTheme.modeColor(mode))   // the windmill colour of the mode
        }
        .displayName("Mihomo QX 运行模式")
        .description("在 规则分流 → 全局代理 → 全局直连 之间切换")
    }

    struct Provider: ControlValueProvider {
        var previewValue: String { "rule" }
        func currentValue() async throws -> String { await ModeControlCore.current() }
    }
}

// MARK: - Control Center (iOS 18)

@available(iOS 18.0, *)
struct TunnelToggleControl: ControlWidget {
    static let kind = "MihomoQXTunnelToggle"   // qx/rebuild: distinct from the main-line app's widgets

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { on in
            ControlWidgetToggle("Mihomo QX", isOn: on, action: SetTunnelIntent()) { isOn in
                Label(isOn ? LocalizedStringKey("已连接") : LocalizedStringKey("未连接"), systemImage: isOn ? "bolt.horizontal.circle.fill" : "bolt.horizontal.circle")
            }
        }
        .displayName("Mihomo QX")
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
        StatusEntry(date: Date(), status: .connected, snapshot: WidgetSnapshot(node: "🇯🇵 Tokyo 01", policy: "Proxy", profile: "Mihomo"), profile: "Mihomo QX")
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
        return StatusEntry(date: Date(), status: await VPNControl.status(), snapshot: snap, profile: snap.profile, mode: await ModeControlCore.current())
    }
}

struct StatusWidget: Widget {
    let kind = "MihomoQXStatus"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
                .containerBackground(for: .widget) { WidgetTheme.bg }
        }
        .configurationDisplayName("Mihomo QX")
        .description("出口位置、当前策略链、运行模式、今日流量和开关")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryRectangular, .accessoryCircular, .accessoryInline])
    }
}

// qx/rebuild (QX preview 6): the widget set uses the QX palette of the app (QXTheme.swift, preview 5):
// light #F2F3F7 page / white cards, dark pure black page / #1C1C1E cards with a 14 % white hairline instead
// of shadows; the 节点 tile teal (#3DB5E6 light / #1F86B8 dark, white label contrast ≥ 4:1); the windmill
// colour shows the run mode (tri-colour = 规则分流, teal = 全局代理, yellow = 全局直连) like the app's toolbar.
enum WidgetTheme {
    private static func dyn(_ light: UIColor, _ dark: UIColor) -> Color { Color(UIColor { $0.userInterfaceStyle == .dark ? dark : light }) }
    private static func rgb(_ hex: UInt32) -> UIColor {
        UIColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
    static let bg = dyn(rgb(0xF2F3F7), .black)
    static let card = dyn(.white, rgb(0x1C1C1E))
    static let cardHi = dyn(rgb(0xEAECF1), rgb(0x2C2C2E))
    static let hairline = dyn(UIColor.black.withAlphaComponent(0.07), UIColor.white.withAlphaComponent(0.14))
    // The QX 节点 teal deepened to the app's dark variant in both modes: white 13 pt chain text on the
    // recording's #3DB5E6 is only 2.35:1, on #1F86B8 it is 4.07:1 — a widget is read at a glance.
    static let nodeTile = dyn(rgb(0x1F86B8), rgb(0x1F86B8))
    static let good = Color(red: 0.20, green: 0.70, blue: 0.29)
    static let blue = dyn(rgb(0x007AFF), rgb(0x0A84FF))
    static let accent = blue
    static let down = dyn(rgb(0x1F86B8), rgb(0x48B8E8))   // ≥ 3:1 as a glyph on #F2F3F7 / black
    static let up = dyn(rgb(0x5E2FD0), rgb(0x9A7BF0))
    static let bladeEdge = dyn(UIColor.black.withAlphaComponent(0.16), UIColor.clear)
    static let teal = Color(red: 0.20, green: 0.78, blue: 0.80)
    static let yellow = Color(red: 1.0, green: 0.76, blue: 0.10)
    static let red = Color(red: 0.95, green: 0.22, blue: 0.25)

    /// The single colour that stands for a run mode (Control Center tint, rectangular accents).
    static func modeColor(_ m: String) -> Color {
        switch m {
        case "global": return teal
        case "direct": return yellow
        default: return red
        }
    }
}

struct WidgetWindmill: View {
    let mode: String
    var size: CGFloat = 18
    var colors: [Color] {
        switch mode {
        case "global": return [WidgetTheme.teal, WidgetTheme.teal, WidgetTheme.teal]
        case "direct": return [WidgetTheme.yellow, WidgetTheme.yellow, WidgetTheme.yellow]
        default: return [WidgetTheme.red, WidgetTheme.yellow, WidgetTheme.teal]
        }
    }
    var body: some View {
        // A hairline edge keeps the yellow (全局直连) and teal blades visible on a white card (1.6–2.1:1 fill).
        ZStack {
            ForEach(0..<3, id: \.self) { i in
                WidgetBlade(angle: Double(i) * 120).fill(colors[i])
                WidgetBlade(angle: Double(i) * 120).stroke(WidgetTheme.bladeEdge, lineWidth: max(0.5, size / 40))
            }
        }
        .frame(width: size, height: size)
        .accessibilityLabel(Text(ModeControlCore.title(mode)))
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

    /// The live mode (read from the core while connected), so the windmill follows the Control Center control.
    var mode: String { entry.mode }
    var flag: String { entry.snapshot.flag ?? "🌐" }
    var place: String { entry.on ? (entry.snapshot.place ?? entry.snapshot.node) : String(localized: "未连接") }
    var chainText: String {
        guard entry.on else { return "—" }
        if let c = entry.snapshot.chain, !c.isEmpty { return c }
        return entry.snapshot.node.isEmpty ? "—" : entry.snapshot.node
    }
    var detailText: String {
        entry.on ? (entry.snapshot.detail ?? "").uppercased() : String(localized: "轻点开关连接")
    }

    var body: some View {
        switch family {
        case .accessoryInline:
            // Lock Screen line above the clock: flag + exit place and the run mode while connected.
            if entry.on {
                Text(verbatim: "\(flag) \(entry.snapshot.place ?? entry.snapshot.node) · ") + Text(ModeControlCore.title(mode))
            } else {
                Text(verbatim: "Mihomo QX · ") + Text(entry.statusText)
            }
        case .accessoryCircular:
            Button(intent: ToggleTunnelIntent()) {
                ZStack {
                    AccessoryWidgetBackground()
                    VStack(spacing: 1) {
                        if entry.on {
                            Text(verbatim: flag).font(.title3)
                        } else {
                            WidgetWindmill(mode: mode, size: 20).widgetAccentable()
                        }
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
                HStack(spacing: 4) {
                    WidgetWindmill(mode: mode, size: 11).widgetAccentable()
                    Text(ModeControlCore.title(mode))
                    if let t = today { Text(verbatim: "↓\(bytes(t.down)) ↑\(bytes(t.up))").monospacedDigit() }
                }
                .font(.caption2).lineLimit(1)
            }
        case .systemMedium:
            VStack(alignment: .leading, spacing: 9) {
                HStack(alignment: .top) {
                    locationHeader
                    Spacer(minLength: 8)
                    toggle
                }
                HStack(spacing: 8) {
                    chainTile
                    modeTile
                }
                HStack(spacing: 10) {
                    if let t = today {
                        trafficLabel("chevron.down.circle.fill", WidgetTheme.down, t.down)
                        trafficLabel("chevron.up.circle.fill", WidgetTheme.up, t.up)
                    } else {
                        Text("今日流量").font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 4)
                    if let r = entry.snapshot.remaining, !r.isEmpty {
                        Label { Text(verbatim: r) } icon: { Image(systemName: "gauge.with.dots.needle.33percent") }
                            .font(.system(size: 11, weight: .medium).monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
        default:
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .top) {
                    Text(verbatim: entry.on ? flag : "⏻").font(.system(size: 22))
                    Spacer(minLength: 0)
                    Button(intent: CycleModeIntent()) {
                        WidgetWindmill(mode: mode, size: 22)
                            .padding(5)
                            .background(Circle().fill(WidgetTheme.card))
                            .overlay(Circle().strokeBorder(WidgetTheme.hairline, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
                Text(verbatim: place).font(.system(size: 17, weight: .bold)).lineLimit(1).minimumScaleFactor(0.7)
                Text(verbatim: entry.on ? chainText : detailText).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 0)
                HStack(alignment: .center) {
                    toggle
                    Spacer(minLength: 4)
                    Text(ModeControlCore.title(mode)).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.8)
                }
            }
        }
    }

    var locationHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(verbatim: entry.on ? flag : "⏻").font(.system(size: 20))
                Text(verbatim: place).font(.system(size: 20, weight: .bold)).lineLimit(1).minimumScaleFactor(0.7)
            }
            Text(verbatim: detailText)
                .font(.system(size: 11, weight: .medium).monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
        }
    }

    /// The QX 节点 tile (teal, white glyph + label) carrying the policy chain.
    var chainTile: some View {
        HStack(spacing: 8) {
            Image(systemName: "server.rack").font(.system(size: 15, weight: .semibold))
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: entry.snapshot.policy.isEmpty ? "PROXY" : entry.snapshot.policy)
                    .font(.system(size: 11, weight: .semibold)).opacity(0.85).lineLimit(1)
                Text(verbatim: chainText).font(.system(size: 13, weight: .bold)).lineLimit(1).minimumScaleFactor(0.75)
            }
            Spacer(minLength: 0)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 11)
        .frame(maxWidth: .infinity, minHeight: 46, maxHeight: 46, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(WidgetTheme.nodeTile))
    }

    /// Run mode on a QX card: the coloured windmill + mode name; tap cycles 规则分流 → 全局代理 → 全局直连.
    var modeTile: some View {
        Button(intent: CycleModeIntent()) {
            HStack(spacing: 7) {
                WidgetWindmill(mode: mode, size: 22)
                Text(ModeControlCore.title(mode)).font(.system(size: 13, weight: .semibold)).lineLimit(1).minimumScaleFactor(0.7)
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 10)
            .frame(width: 112, height: 46)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(WidgetTheme.card))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(WidgetTheme.hairline, lineWidth: 1))
        }
        .buttonStyle(.plain)
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
                Circle().fill(Color.white).frame(width: 26, height: 26).padding(2).shadow(color: .black.opacity(0.15), radius: 1, y: 0.5)
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
                    Text(context.state.connected ? "Mihomo QX 已连接" : "Mihomo QX 未连接").font(.subheadline.weight(.semibold))
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
