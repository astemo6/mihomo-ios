import SwiftUI

/// v0.19.22 更多 → 高级设置 → 网络 → Tailscale: the experimental Tailscale node(s) at a glance — whether one is
/// configured, what the tunnel's Tailscale guard reports (未启动 / 启动中 / 已连接 / 内存不足已停用 / 启动失败) and the
/// tailnet address tsnet got, all read from the running extension (nothing shown that it did not report). Adding opens
/// the node editor preset to Tailscale; a row opens the node's detail page (编辑 / 删除), manual nodes also swipe.
struct TailscaleSettingsView: View {
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var vpn = VPNManager.shared
    @ObservedObject private var model = NodeManagerModel.shared
    @StateObject private var status = TailscaleStatusModel()
    @State private var adding: AddNodeView.Target?
    @State private var editing: NodeEditTarget?
    @State private var confirmDelete: ManagedNode?

    var nodes: [ManagedNode] { model.nodes.filter { $0.type.lowercased() == "tailscale" } }

    var body: some View {
        List {
            Section {
                LabeledContent {
                    Text(verbatim: stateText).foregroundStyle(stateColor)
                } label: { Text("状态") }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("tailscale.state")
                ForEach(status.nodes.filter { $0.ipv4 != nil || $0.ipv6 != nil }, id: \.name) { n in
                    addressRow(n)
                }
                if let g = status.guardStatus, g.state == "failed", let e = g.error, !e.isEmpty {
                    Text(verbatim: GoText.localize(e)).font(.caption).foregroundStyle(.secondary).lineLimit(4)
                }
                if let u = status.guardStatus?.authURL, let url = URL(string: u) {
                    Link(destination: url) { Label("打开 Tailscale 登录链接", systemImage: "person.badge.key") }
                }
            } header: { Text("状态") } footer: {
                Text("Tailscale 只在 VPN 连接后、第一次有流量经过 Tailscale 节点时由隧道扩展启动；可用内存不足时不会启动，运行中内存过低会自动停用。")
            }
            .listRowBackground(Theme.card)

            Section {
                if nodes.isEmpty {
                    EmptyStateRow(icon: "circle.hexagongrid", title: "还没有 Tailscale 节点", message: "添加后，内核会在隧道扩展里加入你的 tailnet。建议填写 Auth Key。")
                }
                ForEach(nodes) { n in nodeRow(n) }
                Button { adding = AddNodeView.Target(type: "tailscale", preset: [:]) } label: {
                    Label("添加 Tailscale 节点", systemImage: "plus.circle.fill")
                }
                .accessibilityIdentifier("tailscale.add")
            } header: { Text("节点") } footer: {
                ExperimentalMemoryWarning()
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: "Tailscale"))
        .task { if model.nodes.isEmpty { await model.reload() } }
        .onAppear { status.start(vpn: vpn) }
        .onDisappear { status.stop() }
        .sheet(item: $adding, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(newType: t.type, preset: t.preset).environmentObject(store)
        }
        .sheet(item: $editing, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(node: t.node).environmentObject(store)
        }
        .confirmationDialog("删除这个手动节点？", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            titleVisibility: .visible, presenting: confirmDelete) { n in
            Button("删除", role: .destructive) { Task { await model.delete(n) } }
        } message: { n in Text(verbatim: n.name) }
    }

    func nodeRow(_ n: ManagedNode) -> some View {
        let live = status.nodes.first { $0.name == n.name }
        return NavigationLink {
            NodeDetailView(node: n)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: AddNodeView.symbol("tailscale"))
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.protocolColor("tailscale"))
                    .frame(width: 30, height: 30)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.protocolColor("tailscale").opacity(0.15)))
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: FlagSafe.text(n.name)).font(.subheadline.weight(.semibold)).lineLimit(1)
                    Text(verbatim: n.source.title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if let live {
                    Text(verbatim: nodeStateText(live)).font(.caption).foregroundStyle(live.started ? Theme.good : .secondary)
                } else if vpn.isConnected && !n.inRuntime {
                    Text("不在当前配置").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityIdentifier("tailscale.node")
        .swipeActions(edge: .trailing) {
            if model.manualNode(n) != nil {
                Button(role: .destructive) { confirmDelete = n } label: { Label("删除", systemImage: "trash") }
                Button { editing = NodeEditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
                    .tint(.orange)
            }
        }
    }

    func addressRow(_ n: TailnetNodeInfo) -> some View {
        let addrs = [n.ipv4, n.ipv6].compactMap { $0 }
        return LabeledContent {
            VStack(alignment: .trailing, spacing: 2) {
                ForEach(addrs, id: \.self) { a in Text(verbatim: a).font(.callout.monospaced()).foregroundStyle(.secondary) }
            }
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text("Tailnet 地址")
                if status.nodes.count > 1 { Text(verbatim: FlagSafe.text(n.name)).font(.caption).foregroundStyle(.secondary) }
            }
        }
        .contextMenu {
            ForEach(addrs, id: \.self) { a in
                Button { UIPasteboard.general.string = a } label: { Label { Text(verbatim: a) } icon: { Image(systemName: "doc.on.doc") } }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tailscale.address")
    }

    func nodeStateText(_ n: TailnetNodeInfo) -> String {
        if n.isStopped { return String(localized: "已停用") }
        return n.started ? String(localized: "已连接") : String(localized: "未启动")
    }

    var stateText: String {
        if nodes.isEmpty && status.nodes.isEmpty { return String(localized: "未配置") }
        guard vpn.isConnected else { return String(localized: "VPN 未连接") }
        guard status.loaded else { return "…" }
        guard let g = status.guardStatus, g.nodes > 0 else {
            return String(localized: "不在当前配置")
        }
        let mb = TunnelMemoryMonitor.mbText
        switch g.state {
        case "starting": return String(localized: "启动中")
        case "started": return String(localized: "已连接")
        case "refused": return String(localized: "内存不足，未启动（可用 \(mb(g.refusedAvailable))，需要 \(mb(g.minAvailableToStart))）")
        case "stopped": return String(localized: "内存不足，已停用（可用内存降到 \(mb(g.stoppedAvailable))）")
        case "failed": return String(localized: "启动失败")
        default: return String(localized: "未启动（首次使用时启动）")
        }
    }

    var stateColor: Color {
        guard vpn.isConnected, let g = status.guardStatus else { return .secondary }
        switch g.state {
        case "started": return Theme.good
        case "refused", "stopped", "failed": return Theme.bad
        case "starting": return Theme.warn
        default: return .secondary
        }
    }
}

/// One live Tailscale node as the core reports it (bridge tailnetinfo.go).
struct TailnetNodeInfo: Decodable, Equatable {
    var name: String
    var started: Bool
    var stopped: Bool?
    var ipv4: String?
    var ipv6: String?

    var isStopped: Bool { stopped ?? false }
}

/// Polls the extension every 3 s while the page is open: the Tailscale guard status (memoryStats) and the live
/// nodes with their tailnet addresses (tailscaleInfo). Nothing is read while disconnected.
@MainActor
final class TailscaleStatusModel: ObservableObject {
    @Published var guardStatus: TailscaleGuardStatus?
    @Published var nodes: [TailnetNodeInfo] = []
    @Published var loaded = false
    private var task: Task<Void, Never>?

    func start(vpn: VPNManager) {
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh(vpn: vpn)
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    func refresh(vpn: VPNManager) async {
        guard vpn.isConnected else {
            if guardStatus != nil { guardStatus = nil }
            if !nodes.isEmpty { nodes = [] }
            loaded = false
            return
        }
        let mem = await vpn.send(.memoryStats, timeout: 3)
        let info = await vpn.send(.tailscaleInfo, timeout: 3)
        let decoded = await Task.detached(priority: .utility) { () -> (TailscaleGuardStatus?, [TailnetNodeInfo]) in
            let g = mem.flatMap { try? JSONDecoder().decode(TunnelMemorySnapshot.self, from: $0) }?.tailscale
            let n = info.flatMap { try? JSONDecoder().decode([TailnetNodeInfo].self, from: $0) } ?? []
            return (g, n)
        }.value
        if guardStatus != decoded.0 { guardStatus = decoded.0 }
        if nodes != decoded.1 { nodes = decoded.1 }
        loaded = true
    }
}
