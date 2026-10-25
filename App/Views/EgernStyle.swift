import SwiftUI

// feat/egern-style (user 2026-10-21 「所以你的整体风格可向它看齐」): small shared pieces of the Egern look —
// the Home 启动 / 停止 capsule and the policy chain line that keeps its final node visible.

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
