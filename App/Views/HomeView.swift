import SwiftUI
import NetworkExtension

struct HomeView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var dash: DashboardModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    // Top bar: IP / ASN badge in the top-left corner.
                    HStack(alignment: .top) {
                        IPInfoCard()
                            .frame(maxWidth: 300, alignment: .leading)
                        Spacer(minLength: 8)
                        VStack(alignment: .trailing, spacing: 6) {
                            Text("Mihomo").font(.headline.weight(.heavy))
                            Text(vpn.statusText)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(vpn.isConnected ? Theme.good : .secondary)
                        }
                        .padding(.top, 6)
                    }

                    ConnectCard()
                    ModeCard()
                    TrafficCard()
                    StatsGrid()
                    PanelsEntry()

                    if let err = vpn.lastError {
                        Text(err)
                            .font(.footnote)
                            .foregroundStyle(Theme.bad)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 4)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 24)
            }
            .background(Theme.bg.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .alert("连接失败", isPresented: Binding(get: { vpn.lastError != nil && vpn.showErrorAlert }, set: { if !$0 { vpn.showErrorAlert = false } })) {
                Button("好") { vpn.showErrorAlert = false }
            } message: { Text(vpn.lastError ?? "") }
        }
    }
}

struct ConnectCard: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var dash: DashboardModel

    var body: some View {
        let on = vpn.isConnected
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(on ? "代理已开启" : "代理未开启")
                        .font(.title3.weight(.bold))
                    if on, let d = vpn.connectedDate {
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in
                            Text("已运行 \(Fmt.duration(ctx.date.timeIntervalSince(d)))")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.white.opacity(0.8))
                        }
                    } else {
                        Text(vpn.statusText).font(.caption).foregroundStyle(.white.opacity(0.7))
                    }
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { on || vpn.status == .connecting },
                    set: { _ in Task { await vpn.toggle() } }
                ))
                .labelsHidden()
                .tint(Theme.good)
                .scaleEffect(1.25)
                .disabled(vpn.isBusy || vpn.status == .disconnecting)
            }
            Divider().overlay(Color.white.opacity(0.15))
            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 3) {
                    Label("配置", systemImage: "doc.text").font(.caption2).foregroundStyle(.white.opacity(0.7))
                    Text(store.active?.name ?? "未选择").font(.subheadline.weight(.semibold)).lineLimit(1)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 3) {
                    Label("当前节点", systemImage: "point.3.connected.trianglepath.dotted").font(.caption2).foregroundStyle(.white.opacity(0.7))
                    Text(on ? dash.selectedNode : "—").font(.subheadline.weight(.semibold)).lineLimit(1)
                }
            }
        }
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(on ? Theme.connectedGradient : Theme.idleGradient))
        .shadow(color: on ? Theme.accent.opacity(0.35) : .clear, radius: 18, y: 6)
        .animation(.easeInOut(duration: 0.3), value: on)
    }
}

struct ModeCard: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("出站模式").font(.caption).foregroundStyle(.secondary)
                Picker("出站模式", selection: Binding(get: { dash.mode }, set: { m in Task { await dash.setMode(m) } })) {
                    Text("规则").tag("rule")
                    Text("全局").tag("global")
                    Text("直连").tag("direct")
                }
                .pickerStyle(.segmented)
            }
        }
    }
}

struct TrafficCard: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    SpeedLabel(icon: "arrow.up", color: Theme.up, title: "上传", value: dash.up)
                    Spacer()
                    SpeedLabel(icon: "arrow.down", color: Theme.down, title: "下载", value: dash.down)
                }
                TrafficChart(up: dash.upHistory, down: dash.downHistory)
                    .frame(height: 72)
            }
        }
    }
}

struct SpeedLabel: View {
    let icon: String, color: Color, title: String, value: Int64
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon).font(.caption.bold()).foregroundStyle(color)
                .frame(width: 24, height: 24).background(Circle().fill(color.opacity(0.15)))
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(.caption2).foregroundStyle(.secondary)
                Text(Fmt.speed(value)).font(.system(.headline, design: .rounded).monospacedDigit())
            }
        }
    }
}

struct TrafficChart: View {
    let up: [Int64]
    let down: [Int64]
    var body: some View {
        GeometryReader { geo in
            let maxV = max(Double((up + down).max() ?? 1), 1024)
            ZStack {
                area(down, maxV, geo.size).fill(LinearGradient(colors: [Theme.down.opacity(0.45), Theme.down.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                line(down, maxV, geo.size).stroke(Theme.down, lineWidth: 1.6)
                area(up, maxV, geo.size).fill(LinearGradient(colors: [Theme.up.opacity(0.35), Theme.up.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                line(up, maxV, geo.size).stroke(Theme.up, lineWidth: 1.4)
            }
        }
    }

    private func points(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> [CGPoint] {
        guard v.count > 1 else { return [] }
        let step = size.width / CGFloat(v.count - 1)
        return v.enumerated().map { i, x in
            CGPoint(x: CGFloat(i) * step, y: size.height - CGFloat(Double(x) / maxV) * size.height * 0.92)
        }
    }

    private func line(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> Path {
        Path { p in
            let pts = points(v, maxV, size)
            guard let f = pts.first else { return }
            p.move(to: f)
            pts.dropFirst().forEach { p.addLine(to: $0) }
        }
    }

    private func area(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> Path {
        Path { p in
            let pts = points(v, maxV, size)
            guard let f = pts.first, let l = pts.last else { return }
            p.move(to: CGPoint(x: f.x, y: size.height))
            pts.forEach { p.addLine(to: $0) }
            p.addLine(to: CGPoint(x: l.x, y: size.height))
            p.closeSubpath()
        }
    }
}

struct StatsGrid: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
            StatTile(icon: "arrow.up.circle.fill", color: Theme.up, title: "总上传", value: Fmt.bytes(dash.uploadTotal))
            StatTile(icon: "arrow.down.circle.fill", color: Theme.down, title: "总下载", value: Fmt.bytes(dash.downloadTotal))
        }
    }
}

struct StatTile: View {
    let icon: String, color: Color, title: String, value: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.title3).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.caption2).foregroundStyle(.secondary)
                Text(value).font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.white.opacity(0.06)))
    }
}
