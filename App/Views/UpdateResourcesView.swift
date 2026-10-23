import SwiftUI

// The old 更多 → 更新资源 page was removed (user 2026-10-23: 「节点的更新也可以放到工具对应的模块下 这个更新资源可以去掉」):
// node subscriptions / node sets update in 工具 → 节点与订阅, rule sets in 工具 → 规则 → 订阅, modules (with their scripts
// and rule lists) in 工具 → 模块, config subscriptions in 配置管理. Only the shared row view is left here.

struct ResourceUpdateRow: View {
    let kind: String
    let name: String
    let url: String
    let symbol: String
    var tone: TileTone = .accent
    var updated: Date?
    var error: String?
    var disabled = false
    /// User 2026-10-22: a remote script's source — the rewrite subscription(s) / modules that reference it, or 脚本
    /// for the user's own script lines.
    var owner: String? = nil
    var busy = false
    let update: () -> Void
    /// User 2026-10-22: 「默认折叠，展开后才显示」 — the source line stays hidden until the row is tapped.
    @State private var expanded = false

    /// 「https://sub.example.com/api/v1/client/subscribe?token=abc」 → 「sub.example.com/…」; a link without a host
    /// (local file, malformed) shows only its last path component.
    static func displayURL(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let u = URLComponents(string: t), let host = u.host, !host.isEmpty else {
            return (t as NSString).lastPathComponent
        }
        let port = u.port.map { ":\($0)" } ?? ""
        let rest = (u.path.isEmpty || u.path == "/") && (u.query ?? "").isEmpty && (u.fragment ?? "").isEmpty ? "" : "/…"
        return host + port + rest
    }

    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconTile(symbol: symbol, tone: tone, dimmed: disabled)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    Text(verbatim: name).foregroundStyle(disabled ? Color.secondary : Color.primary).lineLimit(1)
                    if let owner, !owner.isEmpty {
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                }
                // r7 P3-6: host only — subscription links usually carry a token (?token=…, /api/v1/client/<token>)
                // that a screenshot or screen recording would leak.
                Text(verbatim: Self.displayURL(url)).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if expanded, let owner, !owner.isEmpty {
                    Text("来自 \(owner)").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 6) {
                    if disabled {
                        Text("已停用")
                    } else if let updated {
                        Text("更新于 \(Self.relative.localizedString(for: updated, relativeTo: Date()))")
                    } else {
                        Text("从未更新")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
                if let error, !error.isEmpty {
                    Label { Text(verbatim: error).lineLimit(2) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                        .font(.caption).foregroundStyle(Theme.bad)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                guard let owner, !owner.isEmpty else { return }
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            }
            Spacer(minLength: 6)
            if busy {
                ProgressView().frame(width: 30, height: 30)
            } else {
                Button(action: update) {
                    Image(systemName: "arrow.clockwise").font(.body.weight(.semibold)).frame(width: 30, height: 30)
                }
                .buttonStyle(.borderless)
                .disabled(disabled)
                .accessibilityLabel(Text("更新"))
                .accessibilityIdentifier("res.update.\(kind).\(name)")
            }
        }
        .padding(.vertical, 2)
    }
}
