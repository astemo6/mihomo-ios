import Foundation
import SwiftUI

/// v0.18 隧道内存 (更多 → 诊断): the tunnel extension's phys_footprint now, its peak and the headroom
/// iOS still allows (os_proc_available_memory), asked from the extension once a second while the page is
/// open (TunnelMessage.memoryStats). When not connected, the last snapshot the extension wrote to the App
/// Group (every MemoryGuard tick) is shown instead, so a jetsam kill still leaves its last reading.
struct TunnelMemorySnapshot: Decodable, Equatable {
    var footprint: Int64
    var peak: Int64
    var available: Int64
    var goHeap: Int64?
    var goSys: Int64?
    var goroutines: Int?
    var connections: Int?
    var at: Int64
    var tailscale: TailscaleGuardStatus?
    /// feat/s3-mem: the native memory governor (switch nativeMemGovernor), nil while it is off.
    var governor: NativeGovernorStatus?

    /// The extension's limit as iOS applies it (footprint + what is still available), else ~50 MB.
    var limit: Int64 { available >= 0 ? footprint + available : 50 << 20 }
}

struct NativeGovernorStatus: Decodable, Equatable {
    var level: String
    var refused: Int?
    var line: String?

    /// 「内存调度」 row: 原生 · 偏高 · 已拒绝 2.
    var text: String {
        let l: String
        switch level {
        case "elevated": l = String(localized: "偏高")
        case "high": l = String(localized: "紧张")
        case "critical": l = String(localized: "危急")
        default: l = String(localized: "正常")
        }
        return String(localized: "原生 · \(l) · 已拒绝 \(refused ?? 0)")
    }
}

struct TailscaleGuardStatus: Decodable, Equatable {
    var nodes: Int
    var state: String
    var node: String?
    var startedAt: Int64?
    var footprintBefore: Int64?
    var availableBefore: Int64?
    var footprintAfter: Int64?
    var startMillis: Int64?
    var peakSinceStart: Int64?
    var refusedAvailable: Int64?
    var refusedAt: Int64?
    var stoppedAvailable: Int64?
    var stoppedAt: Int64?
    var error: String?
    var authURL: String?
    var minAvailableToStart: Int64
    var stopBelowAvailable: Int64
}

@MainActor
final class TunnelMemoryMonitor: ObservableObject {
    @Published var snapshot: TunnelMemorySnapshot?
    /// true = fresh answer from the running extension; false = last saved snapshot.
    @Published var live = false
    private var task: Task<Void, Never>?

    static func mbText(_ v: Int64?) -> String {
        guard let v, v >= 0 else { return "—" }
        return String(format: "%.1f MB", Double(v) / 1_048_576)
    }

    func start(vpn: VPNManager) {
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh(vpn: vpn)
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    func refresh(vpn: VPNManager) async {
        if UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoMemory") {
            snapshot = Self.demo
            live = true
            return
        }
        if vpn.isConnected, let d = await vpn.send(.memoryStats, timeout: 3),
           let s = try? JSONDecoder().decode(TunnelMemorySnapshot.self, from: d) {
            snapshot = s
            live = true
            return
        }
        live = false
        if let d = TunnelMemoryFile.read(), let s = try? JSONDecoder().decode(TunnelMemorySnapshot.self, from: d) {
            snapshot = s
        }
    }

    /// Simulator UI tests (-UITestSeed -UITestDemoMemory): fixed numbers, Tailscale started.
    static let demo = TunnelMemorySnapshot(
        footprint: 24_536_678, peak: 34_603_008, available: 27_892_121, goHeap: 9_437_184, goSys: 20_971_520,
        goroutines: 61, connections: 3, at: Int64(Date().timeIntervalSince1970),
        tailscale: TailscaleGuardStatus(nodes: 1, state: "started", node: "UITest Tailscale",
                                        startedAt: Int64(Date().timeIntervalSince1970) - 30,
                                        footprintBefore: 21_495_808, availableBefore: 30_932_992,
                                        footprintAfter: 31_457_280, startMillis: 2_350, peakSinceStart: 34_603_008,
                                        minAvailableToStart: 14 << 20, stopBelowAvailable: 5 << 20))
}

/// The 隧道内存 section of 更多 → 诊断.
struct TunnelMemorySection: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var monitor = TunnelMemoryMonitor()

    var body: some View {
        Section {
            if let s = monitor.snapshot {
                HStack {
                    Text(monitor.live ? "实时" : "上次连接")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill((monitor.live ? Theme.good : Theme.neutral).opacity(0.16)))
                        .foregroundStyle(monitor.live ? Theme.good : Theme.neutral)
                    Spacer()
                    Text(Date(timeIntervalSince1970: TimeInterval(s.at)), style: .time)
                        .font(.caption).foregroundStyle(.secondary)
                }
                gauge(s)
                row("当前占用", TunnelMemoryMonitor.mbText(s.footprint), id: "diag.memory.current", color: color(s.footprint, s.limit))
                row("峰值", TunnelMemoryMonitor.mbText(s.peak), id: "diag.memory.peak", color: color(s.peak, s.limit))
                row("剩余可用", TunnelMemoryMonitor.mbText(s.available), id: "diag.memory.available", color: nil)
                row("系统上限", "≈ " + TunnelMemoryMonitor.mbText(s.limit), id: "diag.memory.limit", color: nil)
                if let h = s.goHeap {
                    row("Go 堆 / 向系统申请", TunnelMemoryMonitor.mbText(h) + " / " + TunnelMemoryMonitor.mbText(s.goSys), id: "diag.memory.go", color: nil)
                }
                if let c = s.connections { row("连接数", "\(c)", id: "diag.memory.conns", color: nil) }
                if let g = s.governor {
                    row("内存调度", g.text, id: "diag.memory.governor", color: g.level == "critical" ? Theme.bad : g.level == "high" ? Theme.warn : nil)
                }
                if let t = s.tailscale, t.nodes > 0 { tailscaleRows(t) }
            } else {
                EmptyStateRow(icon: "memorychip", title: "暂无内存数据", message: "连接一次后显示隧道扩展的内存占用。")
            }
        } header: { Text("隧道内存") } footer: {
            Text("phys_footprint，也就是 iOS 判断是否终止 VPN 扩展时看的数值；扩展上限约 50 MB。连接时每秒刷新；未连接时显示扩展最后一次记录的数值。峰值是扩展本次运行的最高值。")
        }
        .listRowBackground(Theme.card)
        .onAppear { monitor.start(vpn: vpn) }
        .onDisappear { monitor.stop() }
    }

    func color(_ v: Int64, _ limit: Int64) -> Color {
        let r = Double(v) / Double(max(limit, 1))
        return r >= 0.9 ? Theme.bad : r >= 0.75 ? Theme.warn : Theme.good
    }

    func gauge(_ s: TunnelMemorySnapshot) -> some View {
        GeometryReader { geo in
            let w = geo.size.width
            let lim = Double(max(s.limit, 1))
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.cardHi)
                Capsule().fill(color(s.footprint, s.limit))
                    .frame(width: max(4, w * min(1, Double(s.footprint) / lim)))
                Rectangle().fill(Theme.ink(0.6))
                    .frame(width: 2)
                    .offset(x: max(0, min(w - 2, w * Double(s.peak) / lim - 1)))
            }
        }
        .frame(height: 8)
        .accessibilityHidden(true)
    }

    func row(_ title: LocalizedStringKey, _ value: String, id: String, color: Color?) -> some View {
        LabeledContent {
            Text(verbatim: value).monospacedDigit().foregroundStyle(color ?? .secondary)
        } label: { Text(title) }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(id)
    }

    @ViewBuilder
    func tailscaleRows(_ t: TailscaleGuardStatus) -> some View {
        let mb = TunnelMemoryMonitor.mbText
        LabeledContent {
            Text(stateText(t)).foregroundStyle(stateColor(t))
        } label: {
            HStack(spacing: 6) {
                Text(verbatim: "Tailscale")
                Text("实验性").font(.caption2.weight(.bold))
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Capsule().fill(Theme.warn.opacity(0.18))).foregroundStyle(Theme.warn)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("diag.memory.tailscale")
        if let b = t.footprintBefore, b > 0 {
            row("启动前", mb(b), id: "diag.memory.tsBefore", color: nil)
        }
        if let a = t.footprintAfter, a > 0 {
            let delta = a - (t.footprintBefore ?? a)
            row("启动后", mb(a) + String(format: "（+%.1f MB）", Double(delta) / 1_048_576), id: "diag.memory.tsAfter", color: nil)
        }
        if let p = t.peakSinceStart, p > 0, t.footprintBefore != nil {
            row("启动以来峰值", mb(p), id: "diag.memory.tsPeak", color: nil)
        }
        if let ms = t.startMillis, ms > 0 {
            row("启动耗时", String(format: "%.1f s", Double(ms) / 1000), id: "diag.memory.tsTime", color: nil)
        }
        if t.state == "failed", let e = t.error, !e.isEmpty {
            Text(verbatim: e).font(.caption).foregroundStyle(.secondary).lineLimit(3)
        }
        if let u = t.authURL, let url = URL(string: u) {
            Link(destination: url) { Label("打开 Tailscale 登录链接", systemImage: "person.badge.key") }
        }
    }

    func stateText(_ t: TailscaleGuardStatus) -> String {
        let mb = TunnelMemoryMonitor.mbText
        switch t.state {
        case "starting": return String(localized: "启动中")
        case "started": return String(localized: "已启动")
        case "refused": return String(localized: "未启动：可用内存 \(mb(t.refusedAvailable)) 不足 \(mb(t.minAvailableToStart))")
        case "stopped": return String(localized: "已停止：可用内存降到 \(mb(t.stoppedAvailable))")
        case "failed": return String(localized: "启动失败")
        default: return String(localized: "\(t.nodes) 个节点，首次使用时启动")
        }
    }

    func stateColor(_ t: TailscaleGuardStatus) -> Color {
        switch t.state {
        case "started": return Theme.good
        case "refused", "stopped", "failed": return Theme.bad
        case "starting": return Theme.warn
        default: return .secondary
        }
    }
}
