import SwiftUI
import NetworkExtension

/// Top-left IP + ASN badge (Egern / Surge style). Tap = refresh, long-press = copy.
struct IPInfoCard: View {
    @EnvironmentObject var ip: IPInfoModel
    @EnvironmentObject var vpn: VPNManager
    @State private var copied = false
    @State private var spin = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(ip.exit?.flag ?? "🌐")
                    .font(.system(size: 26))
                    .frame(width: 34, height: 34)
                    .background(Circle().fill(Color.white.opacity(0.08)))
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(ip.exit?.ip ?? (ip.loading ? "正在查询…" : (ip.failed ? "查询失败" : "—")))
                            .font(.system(size: 17, weight: .semibold, design: .monospaced))
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(spin ? 360 : 0))
                            .animation(ip.loading ? .linear(duration: 0.8).repeatForever(autoreverses: false) : .default, value: spin)
                    }
                    Text(ip.exit?.locationText ?? (vpn.isConnected ? "出口 · 代理" : "出口 · 本机网络"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            HStack(spacing: 6) {
                Text(ip.exit?.asn ?? "AS —")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Capsule().fill(Theme.accent.opacity(0.18)))
                    .foregroundStyle(Theme.accent)
                Text(ip.exit?.org ?? "运营商未知")
                    .font(.caption)
                    .foregroundStyle(Color.primary.opacity(0.85))
                    .lineLimit(1)
            }
            if vpn.isConnected, let d = ip.direct {
                HStack(spacing: 4) {
                    Text("直连")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Capsule().stroke(Color.secondary.opacity(0.6)))
                    Text("\(d.flag) \(d.ip)")
                        .font(.system(size: 11, design: .monospaced))
                    if let a = d.asn { Text(a).font(.system(size: 10, design: .monospaced)) }
                    if let o = d.org { Text(o).font(.system(size: 10)).lineLimit(1) }
                }
                .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(LinearGradient(colors: [Theme.cardHi, Theme.card], startPoint: .topLeading, endPoint: .bottomTrailing))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(vpn.isConnected ? Theme.accent.opacity(0.45) : Color.white.opacity(0.08), lineWidth: 1)
        )
        .overlay(alignment: .topTrailing) {
            if copied {
                Text("已复制")
                    .font(.caption2.bold())
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Theme.good))
                    .foregroundStyle(.black)
                    .offset(x: 6, y: -8)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            ip.scheduleRefresh()
        }
        .onLongPressGesture(minimumDuration: 0.45) {
            ip.copy()
            withAnimation(.spring()) { copied = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { withAnimation { copied = false } }
        }
        .onChange(of: ip.loading) { l in spin = l }
        .onAppear { if ip.exit == nil && !ip.loading { ip.scheduleRefresh() } }
        .accessibilityElement(children: .combine)
        .accessibilityHint("轻点刷新，长按复制")
    }
}
