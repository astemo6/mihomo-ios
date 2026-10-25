import SwiftUI

/// 更多 → 高级设置 → 网络 → Tailscale: the native core does not implement Tailscale — NCSupport
/// classifies every tailscale node as unsupported ("Tailscale 尚未接入") and the connector never
/// dials it. This page says exactly that instead of presenting the old live status / add-node
/// flow. Tailscale nodes already in a profile stay in the config; they are listed here read-only
/// and marked unavailable (the 诊断 page lists them with the same reason, from NCSupport).
struct TailscaleSettingsView: View {
    @ObservedObject private var model = NodeManagerModel.shared

    var nodes: [ManagedNode] { model.nodes.filter { $0.type.lowercased() == "tailscale" } }

    var body: some View {
        List {
            Section {
                LabeledContent {
                    Text("不支持").foregroundStyle(Theme.bad)
                } label: { Text("状态") }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("tailscale.state")
            } header: { Text("状态") } footer: {
                Text("当前版本使用原生内核，尚未接入 Tailscale。配置里的 Tailscale 节点会保留，但不会被连接，也不会加入 tailnet。")
            }
            .listRowBackground(Theme.card)

            Section {
                if nodes.isEmpty {
                    Text("当前配置没有 Tailscale 节点").foregroundStyle(.secondary)
                }
                ForEach(nodes) { n in
                    HStack(spacing: 12) {
                        Image(systemName: "circle.hexagongrid.fill")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(Theme.protocolColor("tailscale"))
                            .frame(width: 30, height: 30)
                            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.protocolColor("tailscale").opacity(0.15)))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(verbatim: FlagSafe.text(n.name)).font(.subheadline.weight(.semibold)).lineLimit(1)
                            Text(verbatim: n.source.title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Text("不可用").font(.caption).foregroundStyle(Theme.bad)
                    }
                    .accessibilityIdentifier("tailscale.node")
                }
            } header: { Text("节点") }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: "Tailscale"))
        .task { if model.nodes.isEmpty { await model.reload() } }
    }
}
