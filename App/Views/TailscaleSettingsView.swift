import SwiftUI

/// v0.19.22 更多 → 高级设置 → 网络 → Tailscale: the experimental Tailscale node(s) at a glance — whether one is
/// configured, what the status file reports (未启动 / 启动中 / 已连接 / 内存不足已停用 / 启动失败) with DERP region and
/// peer counts, read from the App Group disk (`<state-dir>/status.json`), with fallback to tunnel controller channels.
/// Status files remain readable even while disconnected. Adding opens the node editor preset to Tailscale;
/// a row opens the node's detail page (编辑 / 删除), each row supports reset state (重置 Tailscale 状态).
struct TailscaleSettingsView: View {
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var vpn = VPNManager.shared
    @ObservedObject private var model = NodeManagerModel.shared
    @StateObject private var status = TailscaleStatusModel()
    @State private var adding: AddNodeView.Target?
    @State private var editing: NodeEditTarget?
    @State private var confirmDelete: ManagedNode?
    @State private var confirmReset: ManagedNode?

    var nodes: [ManagedNode] { model.nodes.filter { $0.type.lowercased() == "tailscale" } }

    var body: some View {
        List {
            Section {
                if nodes.count <= 1 {
                    singleNodeStatusContent
                } else {
                    multiNodeStatusContent
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
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .task { if model.nodes.isEmpty { await model.reload() } }
        .onAppear { status.start(vpn: vpn) }
        .onDisappear { status.stop() }
        .sheet(item: $adding, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(newType: t.type, preset: t.preset).environmentObject(store)
        }
        .sheet(item: $editing, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(node: t.node).environmentObject(store)
        }
        .confirmationDialog(
            "删除这个本地节点？",
            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
            titleVisibility: .visible,
            presenting: confirmDelete
        ) { n in
            Button("删除", role: .destructive) { Task { await model.delete(n) } }
        } message: { n in Text(verbatim: n.name) }
        .confirmationDialog(
            TailscaleText.resetConfirmTitle,
            isPresented: Binding(get: { confirmReset != nil }, set: { if !$0 { confirmReset = nil } }),
            titleVisibility: .visible,
            presenting: confirmReset
        ) { n in
            Button(TailscaleText.resetAction, role: .destructive) {
                Task {
                    await status.resetState(of: n, home: AppShared.homeURL.path, vpn: vpn)
                    await model.reload()
                }
            }
            Button("取消", role: .cancel) { }
        } message: { n in
            Text(TailscaleText.resetConfirmMessage(nodeName: n.name, isVPNConnected: vpn.isConnected))
        }
    }

    // MARK: - Status Section Views

    @ViewBuilder
    private var singleNodeStatusContent: some View {
        let firstNode = nodes.first
        let file = firstNode.flatMap { status.statusFiles[$0.name] }

        LabeledContent {
            Text(verbatim: stateText).foregroundStyle(stateColor)
        } label: { Text("状态") }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tailscale.state")

        // Addresses: prefer status file, fallback to controller channel
        if let file, file.ipv4 != nil || file.ipv6 != nil {
            addressRow(name: firstNode?.name ?? "", ipv4: file.ipv4, ipv6: file.ipv6, showName: false)
        } else {
            ForEach(status.nodes.filter { $0.ipv4 != nil || $0.ipv6 != nil }, id: \.name) { n in
                addressRow(name: n.name, ipv4: n.ipv4, ipv6: n.ipv6, showName: status.nodes.count > 1)
            }
        }

        // DERP home region from status file
        if let r = file?.derpHomeRegion ?? file?.selfNode?.derpHomeRegion {
            derpRegionRow(r)
        }

        // Peer counts from status file
        if let p = file?.peerCounts, (file?.isRunning == true || p.total > 0 || p.direct > 0 || p.relay > 0) {
            peerCountsRow(p)
        }

        // Error message: prefer status file, fallback to guardStatus
        if let e = file?.lastError, !e.isEmpty {
            Text(verbatim: CoreText.localize(e)).font(.caption).foregroundStyle(.secondary).lineLimit(4)
        } else if let g = status.guardStatus, g.state == "failed", let e = g.error, !e.isEmpty {
            Text(verbatim: CoreText.localize(e)).font(.caption).foregroundStyle(.secondary).lineLimit(4)
        }

        // Auth URL: prefer status file, fallback to guardStatus
        if let u = (file?.authURL ?? status.guardStatus?.authURL), let url = URL(string: u) {
            Link(destination: url) {
                Label("打开 Tailscale 登录链接", systemImage: "person.badge.key")
            }
        }

        // Direct reset action button for single configured node
        if let firstNode {
            Button(role: .destructive) {
                confirmReset = firstNode
            } label: {
                Label(TailscaleText.resetMenuLabel, systemImage: "arrow.counterclockwise")
            }
        }
    }

    @ViewBuilder
    private var multiNodeStatusContent: some View {
        ForEach(nodes) { n in
            let file = status.statusFiles[n.name]
            let summary = nodeStateSummary(for: n)

            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: FlagSafe.text(n.name))
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.ink(0.7))
            }

            LabeledContent {
                Text(verbatim: summary.text).foregroundStyle(summary.color)
            } label: { Text("状态") }

            if let file, file.ipv4 != nil || file.ipv6 != nil {
                addressRow(name: n.name, ipv4: file.ipv4, ipv6: file.ipv6, showName: false)
            } else if let live = status.nodes.first(where: { $0.name == n.name }), live.ipv4 != nil || live.ipv6 != nil {
                addressRow(name: n.name, ipv4: live.ipv4, ipv6: live.ipv6, showName: false)
            }

            if let r = file?.derpHomeRegion ?? file?.selfNode?.derpHomeRegion {
                derpRegionRow(r)
            }

            if let p = file?.peerCounts, (file?.isRunning == true || p.total > 0 || p.direct > 0 || p.relay > 0) {
                peerCountsRow(p)
            }

            if let e = file?.lastError, !e.isEmpty {
                Text(verbatim: CoreText.localize(e)).font(.caption).foregroundStyle(.secondary).lineLimit(4)
            }

            if let u = file?.authURL, let url = URL(string: u) {
                Link(destination: url) {
                    Label("打开 Tailscale 登录链接", systemImage: "person.badge.key")
                }
            }

            Button(role: .destructive) {
                confirmReset = n
            } label: {
                Label(TailscaleText.resetMenuLabel, systemImage: "arrow.counterclockwise")
            }
        }
    }

    // MARK: - Node Row

    func nodeRow(_ n: ManagedNode) -> some View {
        let summary = nodeStateSummary(for: n)
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
                Text(verbatim: summary.text)
                    .font(.caption)
                    .foregroundStyle(summary.color)
            }
        }
        .accessibilityIdentifier("tailscale.node")
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                confirmReset = n
            } label: {
                Label(TailscaleText.resetAction, systemImage: "arrow.counterclockwise")
            }
            .tint(.red)
            if model.manualNode(n) != nil {
                Button(role: .destructive) { confirmDelete = n } label: { Label("删除", systemImage: "trash") }
                Button { editing = NodeEditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
                    .tint(.orange)
            }
        }
        .contextMenu {
            Button(role: .destructive) {
                confirmReset = n
            } label: {
                Label(TailscaleText.resetMenuLabel, systemImage: "arrow.counterclockwise")
            }
            if model.manualNode(n) != nil {
                Button { editing = NodeEditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
                Button(role: .destructive) { confirmDelete = n } label: { Label("删除", systemImage: "trash") }
            }
        }
    }

    // MARK: - Row Components

    func addressRow(name: String, ipv4: String?, ipv6: String?, showName: Bool) -> some View {
        let addrs = [ipv4, ipv6].compactMap { $0 }
        return LabeledContent {
            VStack(alignment: .trailing, spacing: 2) {
                ForEach(addrs, id: \.self) { a in
                    Text(verbatim: a).font(.callout.monospaced()).foregroundStyle(.secondary)
                }
            }
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text("Tailnet 地址")
                if showName {
                    Text(verbatim: FlagSafe.text(name)).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .contextMenu {
            ForEach(addrs, id: \.self) { a in
                Button { UIPasteboard.general.string = a } label: {
                    Label { Text(verbatim: a) } icon: { Image(systemName: "doc.on.doc") }
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tailscale.address")
    }

    func derpRegionRow(_ region: Int) -> some View {
        LabeledContent {
            Text(verbatim: TailscaleText.derpRegionText(region)).font(.callout.monospaced()).foregroundStyle(.secondary)
        } label: {
            Text("DERP 区域")
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tailscale.derp")
    }

    func peerCountsRow(_ counts: NCTailscalePeerCounts) -> some View {
        LabeledContent {
            Text(TailscaleText.peerCountsText(direct: counts.direct, relay: counts.relay))
                .font(.callout)
                .foregroundStyle(.secondary)
        } label: {
            Text("Peer 节点")
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("tailscale.peers")
    }

    // MARK: - State Computation

    func nodeStateSummary(for n: ManagedNode) -> (text: String, color: Color) {
        if let file = status.statusFiles[n.name] {
            let text = TailscaleText.statusStateText(file.state)
            let color: Color
            switch file.state {
            case "started": color = Theme.good
            case "starting", "needsLogin": color = Theme.warn
            case "refused", "stopped", "failed": color = Theme.bad
            default: color = .secondary
            }
            return (text, color)
        }
        // Fallback to controller info
        if let live = status.nodes.first(where: { $0.name == n.name }) {
            if live.isStopped { return (String(localized: "已停用"), Theme.bad) }
            return (live.started ? String(localized: "已连接") : String(localized: "未启动"), live.started ? Theme.good : .secondary)
        }
        if vpn.isConnected && !n.inRuntime {
            return (String(localized: "不在当前配置"), .secondary)
        }
        return (String(localized: "未启动"), .secondary)
    }

    var stateText: String {
        if nodes.isEmpty && status.nodes.isEmpty && status.statusFiles.isEmpty {
            return String(localized: "未配置")
        }
        // Prefer status file from first node
        if let primaryNode = nodes.first, let file = status.statusFiles[primaryNode.name] {
            return TailscaleText.statusStateText(file.state)
        }
        // Fallback to tunnel controller channels
        guard vpn.isConnected else { return String(localized: "未启动") }
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
        if let primaryNode = nodes.first, let file = status.statusFiles[primaryNode.name] {
            switch file.state {
            case "started": return Theme.good
            case "starting", "needsLogin": return Theme.warn
            case "refused", "stopped", "failed": return Theme.bad
            default: return .secondary
            }
        }
        guard vpn.isConnected, let g = status.guardStatus else { return .secondary }
        switch g.state {
        case "started": return Theme.good
        case "refused", "stopped", "failed": return Theme.bad
        case "starting": return Theme.warn
        default: return .secondary
        }
    }
}

/// One live Tailscale node as the core reports it.
struct TailnetNodeInfo: Decodable, Equatable {
    var name: String
    var started: Bool
    var stopped: Bool?
    var ipv4: String?
    var ipv6: String?

    var isStopped: Bool { stopped ?? false }
}

/// Polls state directory files (status.json) on disk for all configured Tailscale nodes every 3 s while the page is open,
/// and queries the tunnel extension (memoryStats & tailscaleInfo) as a fallback when connected.
/// Status files remain readable even while disconnected.
@MainActor
final class TailscaleStatusModel: ObservableObject {
    /// Live status files read from disk (<state-dir>/status.json), keyed by node name.
    @Published var statusFiles: [String: NCTailscaleStatusFile] = [:]
    /// Resolved state-dir URLs, keyed by node name.
    @Published var stateDirURLs: [String: URL] = [:]
    /// Fallback guard status from memoryStats.
    @Published var guardStatus: TailscaleGuardStatus?
    /// Fallback live nodes from tailscaleInfo.
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

    func resolveStateDirURL(for n: ManagedNode, home: String) async -> URL? {
        if let cached = stateDirURLs[n.name] {
            return cached
        }
        var dir: String? = nil
        if let summary = await NodeManagerModel.shared.summary(of: n),
           let sd = summary.tailscale?.stateDir, !sd.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dir = sd
        }
        do {
            let url = try TailscaleStatePath.resolveStateDir(home: home, stateDir: dir, nodeName: n.name)
            stateDirURLs[n.name] = url
            return url
        } catch {
            return nil
        }
    }

    func refresh(vpn: VPNManager) async {
        let home = AppShared.homeURL.path
        let tsNodes = NodeManagerModel.shared.nodes.filter { $0.type.lowercased() == "tailscale" }

        // 1. Read status files from disk for all known Tailscale nodes
        var newFiles: [String: NCTailscaleStatusFile] = [:]
        for n in tsNodes {
            if let dirURL = await resolveStateDirURL(for: n, home: home) {
                if let file = TailscaleStatePath.readStatusFile(at: dirURL) {
                    newFiles[n.name] = file
                }
            }
        }

        // 2. Query extension controller channels as fallback if connected
        var newGuard: TailscaleGuardStatus? = nil
        var newNodes: [TailnetNodeInfo] = []
        if vpn.isConnected {
            let mem = await vpn.send(.memoryStats, timeout: 3)
            let info = await vpn.send(.tailscaleInfo, timeout: 3)
            let decoded = await Task.detached(priority: .utility) { () -> (TailscaleGuardStatus?, [TailnetNodeInfo]) in
                let g = mem.flatMap { try? JSONDecoder().decode(TunnelMemorySnapshot.self, from: $0) }?.tailscale
                let n = info.flatMap { try? JSONDecoder().decode([TailnetNodeInfo].self, from: $0) } ?? []
                return (g, n)
            }.value
            newGuard = decoded.0
            newNodes = decoded.1
        }

        if statusFiles != newFiles { statusFiles = newFiles }
        if guardStatus != newGuard { guardStatus = newGuard }
        if nodes != newNodes { nodes = newNodes }
        loaded = true
    }

    /// Resets the persistent state directory for a node and refreshes the view.
    func resetState(of n: ManagedNode, home: String, vpn: VPNManager) async {
        if let dirURL = await resolveStateDirURL(for: n, home: home) {
            do {
                try TailscaleStatePath.deleteStateDir(at: dirURL, home: home)
            } catch {
                // Log or ignore if file already gone
            }
        }
        statusFiles.removeValue(forKey: n.name)
        stateDirURLs.removeValue(forKey: n.name)
        await refresh(vpn: vpn)
    }
}
