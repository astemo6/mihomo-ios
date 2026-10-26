import SwiftUI

// feat/egern-style (user 2026-10-21 「所以你的整体风格可向它看齐」): small shared pieces of the Egern look —
// the Home 启动 / 停止 capsule and the policy chain line that keeps its final node visible.

/// Egern's small capsule in the top-right corner of Home: 启动 while off, 停止 while on. Tinted, not filled, so the
/// connected state is not highlighted (user rule from v0.6.1). Observes VPNManager only.
struct HomePowerCapsule: View {
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        let on = vpn.isConnected
        let busy = vpn.switchBusy // fix/app-toggle-hitch: pending tap included (no double start)
        Button {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            vpn.requestToggle()
        } label: {
            HStack(spacing: 4) {
                if busy { ProgressView().controlSize(.mini) }
                Text(on ? "停止" : "启动")
                    .font(.footnote.weight(.semibold))
                    .lineLimit(1)
            }
            .padding(.horizontal, 12).padding(.vertical, 5)
            .background(Capsule().fill(Theme.accent.opacity(0.14)))
            .foregroundStyle(Theme.accent)
        }
        .buttonStyle(.plain)
        .disabled(busy)
        .accessibilityLabel(Text(on ? "停止" : "启动"))
        .accessibilityValue(Text(on ? "已连接" : "未连接"))
        .accessibilityIdentifier("home.power")
    }
}

/// One-line policy chain 「节点选择 › 日本节点 › 🇯🇵 东京 AZ JP01」. When it does not fit, the middle hops are
/// shortened first (truncated in the middle) and the final node keeps its room; only a final node that cannot fit
/// on its own is cut at its end. Read by VoiceOver / UI tests as the whole text (`label`).
struct ChainLine: View {
    /// Hops after the group itself, already display-ready (flags decorated by the caller).
    let hops: [String]
    var font: Font = .caption2
    var separator = " › " // = PolicyChainText.separator
    /// Full text for VoiceOver / tests; defaults to the hops joined with the separator.
    var label: String? = nil

    var body: some View {
        let last = hops.last ?? "—"
        let head = hops.dropLast().joined(separator: separator)
        HStack(spacing: 0) {
            if !head.isEmpty {
                Text(verbatim: head + separator)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .layoutPriority(0)
            }
            Text(verbatim: last)
                .lineLimit(1)
                .truncationMode(.tail)
                .layoutPriority(1)
        }
        .font(font)
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: label ?? hops.joined(separator: separator)))
    }
}
