import SwiftUI

// v0.19 首页卡片 (Bettbox-style dashboard cards) as built-in tile types in the existing Home panel list:
// they are pinned, ordered and hidden in 编辑首页面板 like script panels (ids "builtin.<kind>" in
// PanelsModel.pinned), but drawn by the app and never sent to the engine. Two small tiles share a row.

enum BuiltinTile: String, CaseIterable, Identifiable {
    case speed, traffic, uptime, exitIP = "exitip", lanIP = "lanip", memory
    /// v0.19.8: 流媒体解锁 (the last real 解锁检测 through the current exit; 未检测 until one ran).
    case unlock

    static let prefix = "builtin."
    var id: String { Self.prefix + rawValue }
    static func from(_ id: String) -> BuiltinTile? {
        id.hasPrefix(prefix) ? BuiltinTile(rawValue: String(id.dropFirst(prefix.count))) : nil
    }
    static func isBuiltin(_ id: String) -> Bool { id.hasPrefix(prefix) }

    var title: String {
        switch self {
        case .speed: return String(localized: "网速波形图")
        case .traffic: return String(localized: "流量环形图")
        case .uptime: return String(localized: "运行时长")
        case .exitIP: return String(localized: "出口 IP")
        case .lanIP: return String(localized: "内网 IP")
        case .memory: return String(localized: "内存")
        case .unlock: return String(localized: "流媒体解锁")
        }
    }

    var icon: String {
        switch self {
        case .speed: return "waveform.path.ecg"
        case .traffic: return "chart.pie"
        case .uptime: return "timer"
        case .exitIP: return "globe"
        case .lanIP: return "wifi.router"
        case .memory: return "memorychip"
        case .unlock: return "checkmark.shield"
        }
    }

    var caption: String {
        switch self {
        case .speed: return String(localized: "最近一分钟的上传 / 下载速度")
        case .traffic: return String(localized: "本次连接的上传与下载占比")
        case .uptime: return String(localized: "本次连接已运行的时间")
        case .exitIP: return String(localized: "出口 IP 与国旗，默认打码，轻点显示")
        case .lanIP: return String(localized: "本机局域网地址，轻点查看网络详情")
        case .memory: return String(localized: "网络扩展当前占用的内存")
        case .unlock: return String(localized: "经当前出口检测的流媒体与 AI 服务解锁情况，轻点重新检测")
        }
    }

    /// Full-width cards; the rest pair up two per row.
    var wide: Bool { self == .speed || self == .traffic || self == .unlock }
}

/// One row on Home: a script panel, a wide built-in tile, or up to two small built-in tiles.
enum HomeRow: Identifiable {
    case panel(HomePanelEntry)
    case wide(BuiltinTile)
    case pair(BuiltinTile, BuiltinTile?)

    var id: String {
        switch self {
        case .panel(let e): return e.id
        case .wide(let t): return t.id
        case .pair(let a, let b): return a.id + "|" + (b?.id ?? "")
        }
    }

    static func rows(_ ids: [String], panel: (String) -> HomePanelEntry?) -> [HomeRow] {
        var out: [HomeRow] = []
        var pendingSmall: BuiltinTile?
        func flush() {
            if let s = pendingSmall { out.append(.pair(s, nil)); pendingSmall = nil }
        }
        for id in ids {
            if let t = BuiltinTile.from(id) {
                if t.wide {
                    flush()
                    out.append(.wide(t))
                } else if let s = pendingSmall {
                    out.append(.pair(s, t))
                    pendingSmall = nil
                } else {
                    pendingSmall = t
                }
            } else if let e = panel(id) {
                flush()
                out.append(.panel(e))
            }
        }
        flush()
        return out
    }
}

struct BuiltinTileView: View {
    let tile: BuiltinTile
    var body: some View {
        Group {
            switch tile {
            case .speed: SpeedWaveTile()
            case .traffic: TrafficRingTile()
            case .uptime: UptimeTile()
            case .exitIP: ExitIPTile()
            case .lanIP: LANIPTile()
            case .memory: MemoryTile()
            case .unlock: UnlockTile()
            }
        }
        .accessibilityIdentifier("home.tile.\(tile.rawValue)")
    }
}

/// Card chrome shared by the tiles (same radius / stroke as every Home card).
struct TileCard<Content: View>: View {
    let title: String
    let icon: String
    var trailing: String? = nil
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.caption.weight(.semibold)).foregroundStyle(Theme.accent).accessibilityHidden(true)
                Text(verbatim: title).font(.caption.weight(.semibold)).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 4)
                if let trailing { Text(verbatim: trailing).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
            }
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
    }
}

// MARK: - 网速波形图

struct SpeedWaveTile: View {
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        let up = Array(dash.upHistory.suffix(40)), down = Array(dash.downHistory.suffix(40))
        let peak = max((up + down).max() ?? 0, 0)
        TileCard(title: BuiltinTile.speed.title, icon: BuiltinTile.speed.icon,
                 trailing: peak > 0 ? String(localized: "峰值 \(Fmt.speed(peak))") : nil) {
            HStack(spacing: 16) {
                SpeedLabel(icon: "arrow.up", color: Theme.up, title: "上传", value: vpn.isConnected ? dash.up : 0)
                SpeedLabel(icon: "arrow.down", color: Theme.down, title: "下载", value: vpn.isConnected ? dash.down : 0)
                Spacer(minLength: 0)
            }
            MirroredBars(up: up, down: down)
                .frame(height: 64)
                .accessibilityHidden(true)
        }
    }
}

/// Upload bars above the centre line, download bars below, newest on the right.
struct MirroredBars: View {
    let up: [Int64]
    let down: [Int64]
    var body: some View {
        GeometryReader { geo in
            let n = max(up.count, down.count, 1)
            let maxV = Double(max((up + down).max() ?? 0, 1024))
            let slot = geo.size.width / CGFloat(n)
            let bar = max(slot * 0.62, 1.5)
            let mid = geo.size.height / 2
            ZStack(alignment: .topLeading) {
                Path { p in
                    p.move(to: CGPoint(x: 0, y: mid))
                    p.addLine(to: CGPoint(x: geo.size.width, y: mid))
                }
                .stroke(Theme.ink(0.08), lineWidth: 1)
                ForEach(0..<n, id: \.self) { i in
                    let u = i < up.count ? Double(up[i]) : 0
                    let d = i < down.count ? Double(down[i]) : 0
                    let x = CGFloat(i) * slot + (slot - bar) / 2
                    let hu = max(CGFloat(u / maxV) * (mid - 2), u > 0 ? 1.5 : 0)
                    let hd = max(CGFloat(d / maxV) * (mid - 2), d > 0 ? 1.5 : 0)
                    RoundedRectangle(cornerRadius: bar / 2).fill(Theme.up)
                        .frame(width: bar, height: hu)
                        .offset(x: x, y: mid - 1 - hu)
                    RoundedRectangle(cornerRadius: bar / 2).fill(Theme.down)
                        .frame(width: bar, height: hd)
                        .offset(x: x, y: mid + 1)
                }
            }
        }
    }
}

// MARK: - 流量环形图

struct TrafficRingTile: View {
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        let up = vpn.isConnected ? dash.uploadTotal : 0
        let down = vpn.isConnected ? dash.downloadTotal : 0
        let total = up + down
        let upFrac = total > 0 ? Double(up) / Double(total) : 0
        TileCard(title: BuiltinTile.traffic.title, icon: BuiltinTile.traffic.icon,
                 trailing: vpn.isConnected ? String(localized: "本次连接") : String(localized: "未连接")) {
            HStack(spacing: 18) {
                ZStack {
                    Circle().stroke(Theme.ink(0.08), lineWidth: 11)
                    if total > 0 {
                        Circle().trim(from: 0, to: max(upFrac, 0.004))
                            .stroke(Theme.up, style: StrokeStyle(lineWidth: 11, lineCap: .butt))
                            .rotationEffect(.degrees(-90))
                        Circle().trim(from: upFrac, to: 1)
                            .stroke(Theme.down, style: StrokeStyle(lineWidth: 11, lineCap: .butt))
                            .rotationEffect(.degrees(-90))
                    }
                    VStack(spacing: 0) {
                        Text(verbatim: Fmt.bytes(total)).font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
                            .lineLimit(1).minimumScaleFactor(0.6)
                        Text("合计").font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 14)
                }
                .frame(width: 96, height: 96)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 10) {
                    legend(color: Theme.up, title: "上传", value: up, frac: upFrac, show: total > 0)
                    legend(color: Theme.down, title: "下载", value: down, frac: 1 - upFrac, show: total > 0)
                }
                Spacer(minLength: 0)
            }
        }
    }

    func legend(color: Color, title: LocalizedStringKey, value: Int64, frac: Double, show: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Circle().fill(color).frame(width: 8, height: 8).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.caption2).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text(verbatim: Fmt.bytes(value)).font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
                    if show { Text(verbatim: "\(Int((frac * 100).rounded()))%").font(.caption2.monospacedDigit()).foregroundStyle(.secondary) }
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - 运行时长

struct UptimeTile: View {
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        TileCard(title: BuiltinTile.uptime.title, icon: BuiltinTile.uptime.icon) {
            if vpn.isConnected, let d = vpn.connectedDate {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    Text(verbatim: Self.clock(ctx.date.timeIntervalSince(d)))
                        .font(.system(.title3, design: .rounded).weight(.semibold).monospacedDigit())
                        .lineLimit(1).minimumScaleFactor(0.6)
                }
                Text("自 \(d.formatted(date: .omitted, time: .shortened)) 起").font(.caption2).foregroundStyle(.secondary)
            } else {
                Text(verbatim: "--:--:--").font(.system(.title3, design: .rounded).weight(.semibold).monospacedDigit()).foregroundStyle(.secondary)
                Text("未连接").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    /// 1:02:03, or "2d 03:04:05" past a day.
    static func clock(_ t: TimeInterval) -> String {
        let s = Int(max(t, 0))
        let d = s / 86400, h = s % 86400 / 3600, m = s % 3600 / 60, sec = s % 60
        let hms = String(format: "%02d:%02d:%02d", h, m, sec)
        return d > 0 ? "\(d)d \(hms)" : hms
    }
}

// MARK: - 出口 IP

struct ExitIPTile: View {
    @EnvironmentObject var ip: IPInfoModel
    @State private var revealed = false

    var body: some View {
        TileCard(title: BuiltinTile.exitIP.title, icon: BuiltinTile.exitIP.icon) {
            HStack(spacing: 8) {
                Text(verbatim: ip.exit?.flag ?? "🌐").font(.title2).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: ipText)
                        .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                        .lineLimit(1).minimumScaleFactor(0.55)
                        .accessibilityIdentifier("home.tile.exitip.value")
                    Text(revealed ? LocalizedStringKey("轻点隐藏") : LocalizedStringKey("轻点显示")).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard ip.exit != nil else { ip.scheduleRefresh(); return }
            withAnimation(.easeInOut(duration: 0.15)) { revealed.toggle() }
        }
        .onLongPressGesture(minimumDuration: 0.45) {
            guard let e = ip.exit else { return }
            UIPasteboard.general.string = e.ip
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        }
        .onAppear { if ip.exit == nil && !ip.loading { ip.scheduleRefresh() } }
        .accessibilityHint(Text("轻点显示或隐藏，长按复制"))
    }

    var ipText: String {
        guard let e = ip.exit else { return ip.loading ? String(localized: "正在查询…") : "—" }
        return revealed ? e.ip : Self.mask(e.ip)
    }

    /// 203.0.113.45 → 203.0.•••.••• ; 2001:db8:1:2::5 → 2001:db8:••••
    static func mask(_ s: String) -> String {
        if s.contains(":") {
            let parts = s.split(separator: ":", omittingEmptySubsequences: false)
            return parts.prefix(2).joined(separator: ":") + ":••••"
        }
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return String(repeating: "•", count: min(s.count, 8)) }
        return "\(parts[0]).\(parts[1]).•••.•••"
    }
}

// MARK: - 内网 IP

struct LANIPTile: View {
    @State private var addr: String?
    @State private var kind: String = ""

    var body: some View {
        NavigationLink { LANDetailView() } label: {
            TileCard(title: BuiltinTile.lanIP.title, icon: BuiltinTile.lanIP.icon) {
                Text(verbatim: addr ?? "—")
                    .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                    .lineLimit(1).minimumScaleFactor(0.55)
                    .foregroundStyle(.primary)
                    .accessibilityIdentifier("home.tile.lanip.value")
                HStack(spacing: 3) {
                    Text(verbatim: kind.isEmpty ? String(localized: "没有局域网地址") : kind)
                    Image(systemName: "chevron.right").font(.caption2.weight(.semibold))
                }
                .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
        .task {
            // Interfaces change with Wi-Fi / hotspot; re-read while Home is visible.
            while !Task.isCancelled {
                let a = LANInfo.addresses().first
                addr = a?.ip
                kind = a.map { NSLocalizedString($0.label, comment: "") } ?? ""
                try? await Task.sleep(nanoseconds: 10_000_000_000)
            }
        }
    }
}

// MARK: - 内存

struct MemoryTile: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var mon = TunnelMemoryMonitor()

    var body: some View {
        TileCard(title: BuiltinTile.memory.title, icon: BuiltinTile.memory.icon,
                 trailing: mon.snapshot == nil ? nil : (mon.live ? String(localized: "实时") : String(localized: "上次连接"))) {
            if let s = mon.snapshot {
                let frac = s.limit > 0 ? min(Double(s.footprint) / Double(s.limit), 1) : 0
                Text(verbatim: TunnelMemoryMonitor.mbText(s.footprint))
                    .font(.system(.title3, design: .rounded).weight(.semibold).monospacedDigit())
                    .lineLimit(1).minimumScaleFactor(0.6)
                    .accessibilityIdentifier("home.tile.memory.value")
                GeometryReader { g in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Theme.ink(0.08))
                        Capsule().fill(frac > 0.85 ? Theme.bad : (frac > 0.7 ? Theme.warn : Theme.good))
                            .frame(width: max(g.size.width * frac, 4))
                    }
                }
                .frame(height: 5)
                .accessibilityHidden(true)
                Text("上限 \(TunnelMemoryMonitor.mbText(s.limit))").font(.caption2).foregroundStyle(.secondary)
            } else {
                Text(verbatim: "—").font(.system(.title3, design: .rounded).weight(.semibold)).foregroundStyle(.secondary)
                Text("连接后显示").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .task(id: vpn.isConnected) {
            // Home only: every 5 s while connected (诊断 polls each second).
            while !Task.isCancelled {
                await mon.refresh(vpn: vpn)
                if !vpn.isConnected { break }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }
}

// MARK: - 流媒体解锁 (v0.19.8)

/// The policy the current exit goes through: GLOBAL in 全局 mode, else the first group (usually 节点选择), the
/// same start DashboardModel follows for the selected node. The result is the ProbeStore entry of that policy
/// (probe-results.json in the App Group), so it is the same data 解锁检测 shows — nothing is made up.
struct UnlockTile: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var probes = ProbeStore.shared
    @ObservedObject private var dash = DashboardModel.shared
    @AppStorage("home.unlockPolicy", store: AppShared.defaults) private var lastPolicy = ""
    @State private var error: String?

    var policy: String {
        if dash.mode == "global" { return "GLOBAL" }
        return dash.availableGroups.first ?? lastPolicy
    }

    var shownPolicy: String { probes.entry(policy)?.unlock != nil ? policy : lastPolicy }
    var entry: ProbeStore.Entry? { shownPolicy.isEmpty ? nil : probes.entry(shownPolicy) }
    var running: Bool { probes.running.contains(policy) }

    var body: some View {
        TileCard(title: BuiltinTile.unlock.title, icon: BuiltinTile.unlock.icon, trailing: trailing) {
            VStack(alignment: .leading, spacing: 8) {
                if let results = entry?.unlock, !results.isEmpty {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], alignment: .leading, spacing: 6) {
                        ForEach(results.prefix(8)) { r in
                            HStack(spacing: 5) {
                                Image(systemName: r.status == .yes ? "checkmark.circle.fill" : r.status == .partial ? "circle.lefthalf.filled" : r.status == .no ? "xmark.circle.fill" : "questionmark.circle")
                                    .font(.caption2.weight(.bold)).foregroundStyle(r.color)
                                Text(r.service.title).font(.caption).lineLimit(1).minimumScaleFactor(0.8)
                                Spacer(minLength: 2)
                                if let region = r.region { Text(verbatim: region.uppercased()).font(.caption2.monospaced()).foregroundStyle(.secondary) }
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                    .accessibilityIdentifier("home.tile.unlock.results")
                } else {
                    Text(running ? LocalizedStringKey("正在检测…") : LocalizedStringKey("未检测"))
                        .font(.subheadline.weight(.semibold))
                        .accessibilityIdentifier("home.tile.unlock.empty")
                }
                HStack(spacing: 10) {
                    if running {
                        ProgressView().controlSize(.small)
                    } else {
                        Button { Task { await run() } } label: { Label("重新检测", systemImage: "arrow.clockwise").font(.caption.weight(.semibold)) }
                            .buttonStyle(.borderless)
                            .disabled(!vpn.isConnected || policy.isEmpty)
                            .accessibilityIdentifier("home.tile.unlock.run")
                    }
                    if !vpn.isConnected { Text("连接后检测").font(.caption2).foregroundStyle(.secondary) }
                    Spacer()
                    NavigationLink { UnlockView() } label: { Text("全部").font(.caption.weight(.semibold)) }
                        .buttonStyle(.borderless)
                }
                if let error { Text(verbatim: error).font(.caption2).foregroundStyle(Theme.bad).lineLimit(2) }
            }
        }
    }

    var trailing: String? {
        guard let d = entry?.unlockDate else { return nil }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: d, relativeTo: Date())
    }

    func run() async {
        let p = policy
        guard vpn.isConnected, !p.isEmpty else { return }
        error = await probes.probeUnlock(p)
        if error == nil { lastPolicy = p }
    }
}
