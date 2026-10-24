import SwiftUI
import UniformTypeIdentifiers

/// What a node list shows: everything, some sources, or the nodes whose names match a region pattern.
struct NodeListScope: Hashable {
    var title: String
    var sourceIDs: Set<String>? = nil
    var pattern: String? = nil
    /// Shown when the scope has no nodes at all (disabled / not downloaded subscription …).
    var emptyTitle: String? = nil
    var emptyMessage: String? = nil
    var subID: String? = nil
    /// v0.15.4: exact member names (a 筛选节点 filter as the core expands it); overrides pattern.
    var names: Set<String>? = nil
    /// feat/more-dedup: 节点与订阅 → 本地节点 (the old 手动节点 page's 导出为订阅文本 lives here now).
    var localNodes = false

    static let all = NodeListScope(title: String(localized: "全部节点"))

    /// The nodes in scope (the pattern is compiled once per call).
    func filter(_ nodes: [ManagedNode]) -> [ManagedNode] {
        let re = pattern.flatMap { try? NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }
        if pattern != nil && re == nil { return [] }
        if let names { return nodes.filter { names.contains($0.name) && (sourceIDs?.contains($0.source.id) ?? true) } }
        return nodes.filter { n in
            if let ids = sourceIDs, !ids.contains(n.source.id) { return false }
            if let re { return re.firstMatch(in: n.name, range: NSRange(n.name.startIndex..., in: n.name)) != nil }
            return true
        }
    }
}

/// A node list (全部节点, 本地节点, one subscription, a region): grouped by source, with search, a protocol
/// filter, sorting and latency tests (one node, one source, or everything shown — 8 at a time).
struct NodeListView: View {
    let scope: NodeListScope
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var nodeSubs = NodeSubStore.shared
    @AppStorage("nodes.sort") private var sortRaw = NodeManagerModel.SortMode.config.rawValue
    @State private var query = ""
    @State private var protocolFilter = ""
    @State private var editing: NodeEditTarget?
    @State private var confirmDelete: ManagedNode?
    @State private var message: String?
    @State private var editSub: NodeSubscription?
    // feat/subs-split: 添加到本地节点 from a subscription / 节点集 node row's long-press menu (same model.addToLocal
    // as the node detail page, same result alert).
    @State private var addedLocal: NodeDetailView.AddedLocal?
    @State private var exportSub = false

    var sort: NodeManagerModel.SortMode { NodeManagerModel.SortMode(rawValue: sortRaw) ?? .config }

    var protocols: [String] { Array(Set(scoped.map(\.type))).sorted { ProxyItem.label(for: $0) < ProxyItem.label(for: $1) } }

    func matches(_ n: ManagedNode) -> Bool {
        if !protocolFilter.isEmpty, n.type != protocolFilter { return false }
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return true }
        return n.name.localizedCaseInsensitiveContains(q)
            || (n.server ?? "").localizedCaseInsensitiveContains(q)
            || n.type.localizedCaseInsensitiveContains(q)
            || ProxyItem.label(for: n.type).localizedCaseInsensitiveContains(q)
    }

    func sorted(_ list: [ManagedNode]) -> [ManagedNode] {
        switch sort {
        case .config: return list.sorted { $0.order < $1.order }
        case .name: return list.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case .latency:
            // Measured first (fastest on top), then timeouts, then untested.
            func rank(_ n: ManagedNode) -> (Int, Int) {
                guard let d = model.delay(of: n) else { return (2, 0) }
                return d > 0 ? (0, d) : (1, 0)
            }
            return list.sorted { a, b in
                let ra = rank(a), rb = rank(b)
                return ra != rb ? ra < rb : a.order < b.order
            }
        }
    }

    var scoped: [ManagedNode] { scope.filter(model.nodes) }

    /// feat/more-dedup: 本地节点 only — 导出为订阅文本 (was on the removed 手动节点 page).
    @ViewBuilder
    func localExportItems(empty: Bool) -> some View {
        if scope.localNodes {
            Divider()
            Button { exportSub = true } label: { Label("导出为订阅文本", systemImage: "square.and.arrow.up") }
                .disabled(empty)
        }
    }

    var body: some View {
        let sc = scoped
        let shown = sc.filter(matches)
        List {
            summarySection(shown, total: sc.count)
            if sc.isEmpty && !model.loading {
                Section {
                    EmptyStateRow(icon: "server.rack", title: scope.emptyTitle ?? "还没有节点",
                                  message: scope.emptyMessage ?? "导入订阅、添加节点订阅，或手动添加节点后会显示在这里。") {
                        NavigationLink { AddNodeView() } label: { Text("添加节点").font(.footnote.weight(.semibold)) }
                            .padding(.top, 2)
                    }
                }
                .listRowBackground(Theme.card)
            } else if shown.isEmpty && !sc.isEmpty {
                Section {
                    EmptyStateRow(icon: "magnifyingglass", title: "没有匹配的节点", message: "换个关键词，或清除协议筛选。")
                }
                .listRowBackground(Theme.card)
            }
            ForEach(model.sources.filter { scope.sourceIDs?.contains($0.id) ?? true }) { src in
                let all = sc.filter { $0.source == src }
                let list = sorted(all.filter(matches))
                if !list.isEmpty || (all.isEmpty && scope.pattern == nil && query.isEmpty && protocolFilter.isEmpty && showsEmpty(src, hasNodes: !sc.isEmpty)) {
                    Section {
                        if all.isEmpty { emptyRow(src) }
                        ForEach(list) { n in nodeRow(n) }
                    } header: {
                        sourceHeader(src, count: all.count, shown: list)
                    }
                    .listRowBackground(Theme.card)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: scope.title))
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: Text("名称、服务器或协议"))
        .refreshable { await model.reload() }
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Menu {
                    Picker(selection: $sortRaw) {
                        ForEach(NodeManagerModel.SortMode.allCases) { m in Text(m.title).tag(m.rawValue) }
                    } label: { Label("排序", systemImage: "arrow.up.arrow.down") }
                    Picker(selection: $protocolFilter) {
                        Text("全部协议").tag("")
                        ForEach(protocols, id: \.self) { t in Text(ProxyItem.label(for: t)).tag(t) }
                    } label: { Label("协议", systemImage: "line.3.horizontal.decrease") }
                    localExportItems(empty: sc.isEmpty)
                    if let id = scope.subID, let sub = nodeSubs.subs.first(where: { $0.id == id }) {
                        Divider()
                        Button {
                            Task {
                                if let e = await nodeSubs.refresh(sub) { message = e }
                                await model.reload()
                            }
                        } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                            .disabled(nodeSubs.updating.contains(id))
                        Button { editSub = sub } label: { Label("编辑订阅", systemImage: "pencil") }
                        // v0.19.8: 停用 keeps the subscription (link, settings) but takes its nodes out of every profile.
                        Button {
                            Task {
                                var n = sub
                                n.enabled.toggle()
                                await nodeSubs.save(n)
                                await model.reload()
                            }
                        } label: {
                            Label(LocalizedStringKey(sub.enabled ? "停用" : "启用"), systemImage: sub.enabled ? "pause.circle" : "play.circle")
                        }
                    }
                } label: {
                    Image(systemName: protocolFilter.isEmpty ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                }
                .accessibilityLabel(Text("排序与筛选"))
                NavigationLink { AddNodeView() } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加节点"))
            }
        }
        .task { if model.nodes.isEmpty { await model.reload() } }
        .sheet(isPresented: $exportSub) { SubscriptionExportSheet() }
        .sheet(item: $editSub, onDismiss: { Task { await model.reload() } }) { s in NodeSubSheet(sub: s).environmentObject(ProfileStore.shared).environmentObject(VPNManager.shared) }
        .sheet(item: $editing, onDismiss: { Task { await model.reload() } }) { t in NodeEditorView(node: t.node).environmentObject(ProfileStore.shared) }
        .confirmationDialog("删除这个本地节点？", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            titleVisibility: .visible, presenting: confirmDelete) { n in
            Button("删除", role: .destructive) { Task { await model.delete(n) } }
        } message: { n in Text(verbatim: n.name) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .modifier(AddedLocalAlert(added: $addedLocal) { m in editing = NodeEditTarget(node: m) })
    }

    func addToLocal(_ n: ManagedNode) async {
        do {
            let name = try await model.addToLocal(n)
            let inRuntime = model.nodes.contains { $0.source.kind == .manual && $0.name == name && $0.inRuntime }
            addedLocal = NodeDetailView.AddedLocal(name: name, inRuntime: inRuntime)
        } catch {
            message = error.localizedDescription
        }
    }

    /// Empty sections worth showing: 手动 (with a hint) and providers that are not downloaded yet; not an empty 配置.
    func showsEmpty(_ src: NodeSource, hasNodes: Bool) -> Bool { src.kind != .profile && hasNodes }

    // MARK: Sections

    @ViewBuilder
    func summarySection(_ shown: [ManagedNode], total: Int) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    let tested = shown.compactMap { model.delay(of: $0) }
                    let ok = tested.filter { $0 > 0 }
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(shown.count) 个节点").font(.headline)
                        if !tested.isEmpty {
                            Text("已测 \(tested.count) · 可用 \(ok.count)").font(.caption).foregroundStyle(.secondary)
                        } else {
                            (model.liveConnected ? Text("已连接") : Text("未连接")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if let best = shown.filter({ (model.delay(of: $0) ?? 0) > 0 }).min(by: { (model.delay(of: $0) ?? 0) < (model.delay(of: $1) ?? 0) }) {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text("最快").font(.caption2).foregroundStyle(.secondary)
                            Text(verbatim: FlagSafe.text(best.name)).font(.caption.weight(.semibold)).lineLimit(1)
                        }
                    }
                }
                if let b = model.bulk {
                    ProgressView(value: Double(b.done), total: Double(max(b.total, 1)))
                        .tint(Theme.accent)
                    HStack {
                        Text("测速中 \(b.done)/\(b.total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Spacer()
                        Button("停止") { model.stopAll() }.font(.caption.weight(.semibold))
                    }
                } else {
                    Button {
                        model.testAll(sorted(shown).filter { canTest($0) })
                    } label: {
                        Group {
                            if shown.count == total {
                                Label("全部测速", systemImage: "bolt.horizontal.fill")
                            } else {
                                Label("测速当前列表", systemImage: "bolt.horizontal.fill")
                            }
                        }
                            .font(.subheadline.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .disabled(shown.isEmpty)
                }
                TestTargetCaption(live: model.liveConnected)
            }
            .padding(.vertical, 4)
        } footer: {
            if let e = model.error, !e.isEmpty { Text(verbatim: e).foregroundStyle(Theme.bad) }
        }
        .listRowBackground(Theme.card)
    }

    func canTest(_ n: ManagedNode) -> Bool { n.inRuntime || model.manualNode(n) != nil }

    func sourceHeader(_ src: NodeSource, count: Int, shown: [ManagedNode]) -> some View {
        HStack(spacing: 6) {
            Image(systemName: src.icon)
            Text(verbatim: src.title)
            if src.kind == .profile { Text(verbatim: "· " + src.name).lineLimit(1) }
            Text(verbatim: "\(count)").foregroundStyle(.secondary)
            Spacer()
            if !shown.isEmpty {
                Button {
                    model.testAll(shown.filter { canTest($0) })
                } label: { Image(systemName: "bolt.horizontal") }
                    .disabled(model.isBulkTesting)
                    .accessibilityLabel(Text("测速"))
            }
        }
    }

    @ViewBuilder
    func emptyRow(_ src: NodeSource) -> some View {
        switch src.kind {
        case .manual:
            EmptyStateRow(icon: "plus.viewfinder", title: "还没有本地节点", message: "点右上角 + 粘贴分享链接、扫码或选择协议填写。")
        case .subscription, .provider:
            if src.cached {
                EmptyStateRow(icon: "icloud.and.arrow.down", title: "没有节点")
            } else {
                EmptyStateRow(icon: "icloud.and.arrow.down", title: "还没有下载", message: "连接一次，或在「节点与订阅」里右滑更新后显示节点。")
            }
        case .profile:
            EmptyStateRow(icon: "doc.text", title: "配置里没有内联节点")
        }
    }

    func nodeRow(_ n: ManagedNode) -> some View {
        NavigationLink {
            NodeDetailView(node: n)
        } label: {
            NodeManagerRow(node: n, delay: model.delay(of: n), testing: model.testing.contains(n.id))
        }
        .swipeActions(edge: .trailing) {
            if model.manualNode(n) != nil {
                Button(role: .destructive) { confirmDelete = n } label: { Label("删除", systemImage: "trash") }
                Button { editing = NodeEditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
                    .tint(.orange)
            }
            if canTest(n) {
                Button { Task { await model.test(n) } } label: { Label("测速", systemImage: "bolt.horizontal") }
                    .tint(Theme.accent)
            }
        }
        .contextMenu {
            if canTest(n) {
                Button { Task { await model.test(n) } } label: { Label("测速", systemImage: "bolt.horizontal") }
            }
            Button { UIPasteboard.general.string = n.name } label: { Label("复制名称", systemImage: "doc.on.doc") }
            if n.source.kind == .subscription || n.source.kind == .provider {
                Button { Task { await addToLocal(n) } } label: { Label("添加到本地节点", systemImage: "square.and.arrow.down.on.square") }
            }
            if model.manualNode(n) != nil {
                Button { editing = NodeEditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
                Button {
                    Task {
                        do { try await model.duplicate(n) } catch { message = error.localizedDescription }
                    }
                } label: { Label("复制一份", systemImage: "plus.square.on.square") }
                Button(role: .destructive) { confirmDelete = n } label: { Label("删除", systemImage: "trash") }
            }
        }
    }
}

struct NodeManagerRow: View {
    let node: ManagedNode
    let delay: Int?
    let testing: Bool
    @ObservedObject private var nodeSettings = NodeSettingsStore.shared

    var body: some View {
        HStack(spacing: 10) {
            // selftest: fixed column so names line up (WireGuard / TrustTunnel badges pushed them right).
            ProtocolBadge(type: node.type)
                .minimumScaleFactor(0.6)
                .frame(width: 62, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: FlagSafe.text(node.name)).font(.subheadline.weight(.semibold)).lineLimit(1)
                if let note = nodeSettings.map[node.name]?.note, !note.isEmpty {
                    Text(verbatim: note).font(.caption).foregroundStyle(Theme.accent).lineLimit(1)
                        .accessibilityIdentifier("node.row.note")
                }
                HStack(spacing: 6) {
                    if let a = node.address {
                        Text(verbatim: a).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    } else if node.live {
                        Text("来自内核").font(.caption).foregroundStyle(.secondary)
                    }
                    if node.udp { Text(verbatim: "UDP").scaledFont(9, weight: .bold).foregroundStyle(.secondary) }
                    if node.source.kind == .manual && !node.inRuntime {
                        Text("未加入当前配置").scaledFont(9, weight: .bold).foregroundStyle(Theme.warn)
                    }
                }
            }
            Spacer(minLength: 6)
            if testing {
                ProgressView().controlSize(.small)
            } else {
                Text(Theme.delayText(delay))
                    .scaledFont(12, weight: .semibold, monospacedDigit: true)
                    .foregroundStyle(Theme.delayColor(delay))
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Detail

struct NodeDetailView: View {
    let node: ManagedNode
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var nodeSubs = NodeSubStore.shared
    @State private var info: NodeSummaryInfo?
    @State private var loaded = false
    @State private var share: ShareTarget?
    @State private var editing: NodeEditTarget?
    @State private var editSub: NodeSubscription?
    @State private var confirmDelete = false
    @State private var message: String?
    @State private var copied = false
    // v0.15.4: nodes defined in the profile file are editable too.
    @ObservedObject private var store = ProfileStore.shared
    @State private var profileEntry: [String: Any]?
    @State private var profileEdit: ProfileEditTarget?
    @State private var deleteCheck: ProfileStore.NodeDeleteCheck?
    @State private var confirmProfileDelete = false
    @State private var canUndo = false
    /// v0.19.5: the profile file's modification date when the editor opened; a later date on dismiss = saved
    /// → 撤销上次修改 is offered (before, only 复制一份 enabled it, so an edit could not be undone here).
    @State private var editBaseline: Date?
    // v0.17 按节点设置
    @ObservedObject private var nodeSettings = NodeSettingsStore.shared
    @State private var editSettings = false
    // hotfix/node-cred-reveal: credentials stay hidden until 显示 (long press or the eye); values are read only
    // then, kept in memory for this page only and dropped when it disappears or the app leaves the foreground.
    @Environment(\.scenePhase) private var scenePhase
    @State private var revealed: Set<String> = []
    @State private var secrets: [String: String] = [:]
    @State private var credCopied: String?
    // 添加到本地节点 (subscription / provider nodes)
    @State private var addingLocal = false
    @State private var addedLocal: AddedLocal?
    @State private var editingCopy: NodeEditTarget?

    struct AddedLocal: Identifiable {
        let name: String
        let inRuntime: Bool
        var id: String { name }
    }

    struct ProfileEditTarget: Identifiable {
        let id = UUID()
        let node: [String: Any]
        let profile: Profile
    }

    var editableProfile: Profile? { node.source.kind == .profile && profileEntry != nil ? store.active : nil }

    static func modified(_ url: URL) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
    }

    var manual: [String: Any]? { model.manualNode(node) }
    var delay: Int? { model.delay(of: node) }
    var canTest: Bool { node.inRuntime || manual != nil }
    var groups: [String] { model.groups(containing: node) }
    /// Export exists for manual nodes and profile nodes (NodeShare); provider / subscription nodes have none.
    var canShare: Bool { (manual != nil || node.source.kind == .profile) && info?.shareable != false }

    var body: some View {
        List {
            Section {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        ProtocolBadge(type: node.type)
                        Text(verbatim: FlagSafe.text(node.name)).font(.title3.weight(.semibold)).lineLimit(3)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        if model.testing.contains(node.id) {
                            ProgressView()
                        } else {
                            Text(Theme.delayText(delay))
                                .scaledFont(20, weight: .bold, monospacedDigit: true)
                                .foregroundStyle(Theme.delayColor(delay))
                        }
                        if canTest {
                            Button { Task { await model.test(node) } } label: { Label("测速", systemImage: "bolt.horizontal") }
                                .font(.caption.weight(.semibold))
                                .buttonStyle(.bordered)
                                .disabled(model.testing.contains(node.id))
                        }
                    }
                }
                .padding(.vertical, 4)
            } footer: {
                if canTest { TestTargetCaption(live: model.liveConnected && node.live, node: node.name) }
            }
            .listRowBackground(Theme.card)

            nodeSettingsSection

            Section("基本") {
                kv("协议", ProxyItem.label(for: node.type) + (info?.amnezia == true ? " · AmneziaWG" : ""))
                if let a = address { kv("服务器", a, mono: true) }
                kv("UDP", (info?.udp ?? node.udp) ? String(localized: "支持") : String(localized: "未开启"))
                sourceRow
                if !node.inRuntime && node.source.kind == .manual {
                    Text("这个本地节点不在当前配置里：在 工具 → 节点与订阅 → 本地 打开「把本地节点加入每个配置」，或把「本地节点」设为当前配置。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .listRowBackground(Theme.card)

            if node.type.lowercased() == "tailscale" { tailscaleSection }

            if let i = info, i.error == nil {
                let t = transportRows(i)
                if !t.isEmpty {
                    Section("传输与 TLS") {
                        ForEach(t) { row in kv(row.key, row.value, mono: row.mono) }
                        if i.skipCertVerify == true {
                            Label("跳过证书验证已开启", systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote).foregroundStyle(Theme.warn)
                        }
                    }
                    .listRowBackground(Theme.card)
                }
                if let c = i.credentials, !c.isEmpty {
                    Section {
                        ForEach(c, id: \.self) { k in credentialRow(k) }
                    } header: { Text("凭据") } footer: { Text("默认隐藏，长按可显示或复制。") }
                    .listRowBackground(Theme.card)
                }
            } else if loaded, node.live, !(info?.error ?? "").isEmpty {
                Section {
                    Text("这个节点来自连接中的内核，还没有本地缓存，暂时没有更多信息。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .listRowBackground(Theme.card)
            }

            Section {
                if groups.isEmpty {
                    (node.inRuntime ? Text("没有策略组包含这个节点") : Text("不在当前配置里"))
                        .font(.footnote).foregroundStyle(.secondary)
                } else {
                    ForEach(groups, id: \.self) { g in
                        Label { Text(verbatim: g) } icon: { Image(systemName: "square.stack.3d.up") }
                    }
                }
            } header: { Text("所在策略组 \(groups.count)") }
            .listRowBackground(Theme.card)

            Section {
                if canShare {
                    Button { Task { await copyLink() } } label: {
                        if copied {
                            Label("已复制", systemImage: "checkmark")
                        } else {
                            Label("复制分享链接", systemImage: "link")
                        }
                    }
                    Button { Task { await showQR() } } label: { Label("分享链接与二维码", systemImage: "qrcode") }
                }
                Button { UIPasteboard.general.string = node.name } label: { Label("复制名称", systemImage: "doc.on.doc") }
                if node.source.kind == .subscription || node.source.kind == .provider {
                    Button { Task { await addToLocal() } } label: { Label("添加到本地节点", systemImage: "square.and.arrow.down.on.square") }
                        .disabled(addingLocal)
                        .accessibilityIdentifier("node.addLocal")
                }
                if let m = manual {
                    Button { editing = NodeEditTarget(node: m) } label: { Label("编辑", systemImage: "pencil") }
                    Button {
                        Task {
                            do { try await model.duplicate(node); message = String(localized: "已复制一份") } catch { message = error.localizedDescription }
                        }
                    } label: { Label("复制一份", systemImage: "plus.square.on.square") }
                    Button(role: .destructive) { confirmDelete = true } label: { Label("删除", systemImage: "trash") }
                }
                if let p = editableProfile, let entry = profileEntry {
                    Button {
                        editBaseline = Self.modified(p.fileURL)
                        profileEdit = ProfileEditTarget(node: entry, profile: p)
                    } label: { Label("编辑", systemImage: "pencil") }
                        .accessibilityIdentifier("node.edit")
                    Button {
                        Task {
                            do {
                                let nn = try await store.duplicateProfileNode(p, node.name)
                                canUndo = true
                                await model.reload(force: true)
                                message = String(localized: "已复制为「\(nn)」")
                            } catch { message = error.localizedDescription }
                        }
                    } label: { Label("复制一份", systemImage: "plus.square.on.square") }
                    Button(role: .destructive) {
                        // v0.19.6: the check parses the whole profile; off the main actor.
                        let name = node.name
                        Task {
                            deleteCheck = await Task.detached(priority: .userInitiated) { ProfileStore.profileNodeDeleteCheck(p, name) }.value
                            confirmProfileDelete = true
                        }
                    } label: { Label("删除", systemImage: "trash") }
                    if canUndo {
                        Button {
                            Task {
                                do { try await store.undoProfileNodeEdit(p); canUndo = false; await model.reload(force: true); await loadEntry(); info = await model.summary(of: node) }
                                catch { message = error.localizedDescription }
                            }
                        } label: { Label("撤销上次修改", systemImage: "arrow.uturn.backward") }
                        .accessibilityIdentifier("node.undo")
                    }
                }
            } header: { Text("操作") } footer: {
                if node.source.kind == .subscription || node.source.kind == .provider {
                    Text("订阅里的节点是只读的；添加到本地后可以编辑，不受订阅更新影响。")
                } else if editableProfile != nil {
                    Text(store.active?.kind == .remote
                         ? "修改会直接写入这个配置文件（保留其他内容与注释），改名时策略组和规则里的引用一并更新。这是订阅配置：更新订阅后修改会被覆盖。"
                         : "修改会直接写入这个配置文件（保留其他内容与注释），改名时策略组和规则里的引用一并更新。")
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: FlagSafe.text(node.name)))
        .navigationBarTitleDisplayMode(.inline)
        .task {
            info = await model.summary(of: node)
            loaded = true
            await loadEntry()
        }
        .sheet(item: $profileEdit, onDismiss: {
            if let p = editableProfile, let m = Self.modified(p.fileURL), m != editBaseline,
               FileManager.default.fileExists(atPath: p.fileURL.path + ".bak") {
                canUndo = true
            }
            Task {
                await model.reload(force: true)
                guard let p = store.active else { return }
                let name = node.name
                if await Task.detached(priority: .userInitiated, operation: { ProfileStore.profileNode(p, name) == nil }).value { dismiss() } else {
                    await loadEntry()
                    info = await model.summary(of: node)
                }
            }
        }) { t in NodeEditorView(node: t.node, profile: t.profile).environmentObject(ProfileStore.shared) }
        .confirmationDialog("删除这个节点？", isPresented: $confirmProfileDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                guard let p = editableProfile else { return }
                Task {
                    do { try await store.deleteProfileNode(p, node.name); await model.reload(force: true); dismiss() }
                    catch { message = error.localizedDescription }
                }
            }
        } message: { Text(verbatim: deleteMessage) }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(isPresented: $editSettings) { NodeSettingsSheet(name: node.name) }
        // selftest: popped the detail even when the editor was cancelled; now only when the node is gone / renamed.
        .sheet(item: $editing, onDismiss: {
            Task {
                await model.reload()
                if model.manualNode(node) == nil { dismiss() } else { info = await model.summary(of: node) }
            }
        }) { t in NodeEditorView(node: t.node).environmentObject(ProfileStore.shared) }
        .sheet(item: $editSub) { s in NodeSubSheet(sub: s).environmentObject(ProfileStore.shared).environmentObject(VPNManager.shared) }
        .sheet(item: $editingCopy, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(node: t.node).environmentObject(ProfileStore.shared)
        }
        .alert("已添加到本地节点", isPresented: Binding(get: { addedLocal != nil }, set: { if !$0 { addedLocal = nil } }), presenting: addedLocal) { a in
            Button("编辑") {
                if let m = model.manualNode(named: a.name) { editingCopy = NodeEditTarget(node: m) }
            }
            Button("好", role: .cancel) {}
        } message: { a in
            a.inRuntime
                ? Text("「\(a.name)」现在是可编辑的本地节点，不受订阅更新影响。")
                : Text("「\(a.name)」现在是可编辑的本地节点，不受订阅更新影响。它还不在当前配置里：在 工具 → 节点与订阅 → 本地 打开「把本地节点加入每个配置」。")
        }
        .onDisappear { hideSecrets() }
        .onChange(of: scenePhase) { phase in if phase != .active { hideSecrets() } }
        .confirmationDialog("删除这个本地节点？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) { Task { await model.delete(node); dismiss() } }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    // MARK: 凭据 (hotfix/node-cred-reveal)

    @ViewBuilder
    func credentialRow(_ k: String) -> some View {
        let label = Self.credentialLabel(k)
        let shown = revealed.contains(k) ? secrets[k] : nil
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let v = shown {
                VStack(alignment: .leading, spacing: 4) {
                    Text(LocalizedStringKey(label)).foregroundStyle(.secondary)
                        .accessibilityIdentifier("node.cred.label.\(k)")
                    // No .textSelection: its own long-press menu would replace 隐藏 / 复制 (复制 is local-only and expires).
                    Text(verbatim: v)
                        .font(.callout.monospaced())
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("node.cred.value.\(k)")
                }
            } else {
                Text(LocalizedStringKey(label)).foregroundStyle(.secondary)
                    .accessibilityIdentifier("node.cred.label.\(k)")
                Spacer(minLength: 12)
                Group {
                    if credCopied == k { Text("已复制").foregroundStyle(Theme.accent) } else { Text(verbatim: "••••••") }
                }
                .font(.callout)
                .accessibilityLabel(credCopied == k ? Text("已复制") : Text("已隐藏"))
                .accessibilityHint(Text("长按可显示或复制。"))
            }
            Button { Task { await toggleReveal(k) } } label: {
                Image(systemName: shown != nil ? "eye.slash" : "eye").font(.callout)
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .accessibilityLabel(shown != nil ? Text("隐藏凭据") : Text("显示凭据"))
            .accessibilityValue(Text(LocalizedStringKey(label)))
            .accessibilityIdentifier("node.cred.eye.\(k)")
        }
        .contentShape(Rectangle())
        .contextMenu {
            Button { Task { await toggleReveal(k) } } label: {
                if shown != nil { Label("隐藏", systemImage: "eye.slash") } else { Label("显示", systemImage: "eye") }
            }
            Button { Task { await copySecret(k) } } label: { Label("复制", systemImage: "doc.on.doc") }
        }
    }

    /// The value of one credential, read from the node config on first use (never logged).
    func secret(_ k: String) async -> String? {
        if let v = secrets[k] { return v }
        guard let cfg = await model.config(of: node), let v = NodeManagerModel.credentialValue(cfg, path: k) else {
            message = String(localized: "读取节点信息失败")
            return nil
        }
        secrets[k] = v
        return v
    }

    func toggleReveal(_ k: String) async {
        if revealed.contains(k) { revealed.remove(k); return }
        if await secret(k) != nil { revealed.insert(k) }
    }

    /// Copies one credential: this device only (no Handoff / Universal Clipboard), cleared after 60 s.
    func copySecret(_ k: String) async {
        guard let v = await secret(k) else { return }
        UIPasteboard.general.setItems([[UTType.plainText.identifier: v]],
                                      options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
        credCopied = k
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        if credCopied == k { credCopied = nil }
    }

    func hideSecrets() {
        revealed = []
        secrets = [:]
        credCopied = nil
    }

    func addToLocal() async {
        addingLocal = true
        defer { addingLocal = false }
        do {
            let name = try await model.addToLocal(node)
            let inRuntime = model.nodes.contains { $0.source.kind == .manual && $0.name == name && $0.inRuntime }
            addedLocal = AddedLocal(name: name, inRuntime: inRuntime)
        } catch {
            message = error.localizedDescription
        }
    }

    // MARK: 按节点设置 (v0.17)

    @ViewBuilder var nodeSettingsSection: some View {
        let s = nodeSettings.map[node.name]
        Section {
            if let note = s?.note, !note.isEmpty {
                Text(verbatim: note).font(.subheadline)
                    .accessibilityIdentifier("node.settings.note")
            }
            HStack {
                Text("测速地址")
                Spacer(minLength: 8)
                if let u = NodeSettingsStore.customURL(for: node.name) {
                    Text(verbatim: u).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                } else {
                    Text("跟随全局").foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("node.settings.url")
            Button { editSettings = true } label: { Label("编辑备注与测速地址", systemImage: "slider.horizontal.3") }
                .accessibilityIdentifier("node.settings.edit")
        } header: {
            Text("节点设置")
        } footer: {
            Text("只保存在本机，不写入配置文件；单节点和策略组测速都会用这个地址。")
        }
        .listRowBackground(Theme.card)
    }

    func loadEntry() async {
        guard node.source.kind == .profile, let p = store.active else { profileEntry = nil; return }
        let name = node.name
        profileEntry = await Task.detached(priority: .userInitiated) { ProfileStore.profileNode(p, name) }.value
    }

    /// What deleting changes, from bridge ProfileNodeDeleteCheck (shown before confirming).
    var deleteMessage: String {
        var lines: [String] = [String(localized: "会从配置文件里删除这个节点，并从策略组里移除。")]
        if let g = deleteCheck?.emptyGroups, !g.isEmpty {
            lines.append(String(localized: "这些策略组只剩这一个节点，删除后改为 DIRECT：\(g.joined(separator: "、"))"))
        }
        if let n = deleteCheck?.rules, n > 0 { lines.append(String(localized: "指向它的 \(n) 条规则会被删除。")) }
        if let d = deleteCheck?.dialers, !d.isEmpty { lines.append(String(localized: "这些节点 / 策略组的前置代理会被清除：\(d.joined(separator: "、"))")) }
        if let e = deleteCheck?.error, !e.isEmpty { lines.append(e) }
        return lines.joined(separator: "\n")
    }

    var address: String? {
        if let s = info?.server, !s.isEmpty {
            let p = info?.port ?? 0
            if p > 0 { return s.contains(":") ? "[\(s)]:\(p)" : "\(s):\(p)" }
            return s
        }
        return node.address
    }

    @ViewBuilder
    var sourceRow: some View {
        switch node.source.kind {
        case .profile:
            kv("来源", String(localized: "配置") + " · " + node.source.name)
        case .manual:
            kv("来源", String(localized: "本地节点"))
        case .subscription:
            if let s = nodeSubs.subs.first(where: { $0.id == node.source.subID }) {
                Button { editSub = s } label: {
                    HStack {
                        kv("来源", String(localized: "订阅") + " · " + s.name)
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                    }
                }
                .foregroundStyle(.primary)
            } else {
                kv("来源", node.source.name)
            }
        case .provider:
            // feat/more-dedup: 节点集 are managed on 节点与订阅 (the old 提供者 page no longer lists them).
            kv("来源", String(localized: "节点集") + " · " + node.source.name)
        }
    }

    func kv(_ k: String, _ v: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(LocalizedStringKey(k)).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(verbatim: v)
                .font(mono ? .callout.monospaced() : .callout)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }

    struct KVRow: Identifiable {
        let key: String
        let value: String
        let mono: Bool
        var id: String { key }
    }

    func transportRows(_ i: NodeSummaryInfo) -> [KVRow] {
        var r: [KVRow] = []
        func add(_ k: String, _ v: String?, _ mono: Bool = false) { if let v, !v.isEmpty { r.append(KVRow(key: k, value: v, mono: mono)) } }
        add("传输", i.network.map { $0.uppercased() })
        add("安全", i.security.map { $0 == "reality" ? "Reality" : "TLS" })
        add("SNI", i.sni, true)
        add("ALPN", i.alpn, true)
        add("指纹", i.fingerprint)
        add("Flow", i.flow, true)
        add("加密", i.cipher, true)
        if let p = i.plugin {
            var s = p
            if let m = i.pluginMode { s += " · " + m }
            if let v = i.pluginVersion { s += " · v\(v)" }
            add("插件", s)
        }
        add("混淆", i.obfs)
        add("协议参数", i.protocolParam)
        add("拥塞控制", i.congestion)
        if i.up != nil || i.down != nil { add("带宽", "↑ \(i.up ?? "—")  ↓ \(i.down ?? "—")") }
        add("多路复用", i.smux)
        add("前置代理", i.dialerProxy)
        add("IP 版本", i.ipVersion)
        if let p = i.peers { add("对端", "\(p)") }
        var flags: [String] = []
        if i.tfo == true { flags.append("TFO") }
        if i.mptcp == true { flags.append("MPTCP") }
        if !flags.isEmpty { add("TCP", flags.joined(separator: " · ")) }
        return r
    }

    /// v0.18: experimental Tailscale node — its settings, the memory warning and a way to the readout.
    @ViewBuilder
    var tailscaleSection: some View {
        Section {
            ExperimentalMemoryWarning()
            if let t = info?.tailscale {
                kv("设备名", t.hostname ?? "mihomo-ios", mono: true)
                kv("控制服务器", t.controlURL ?? String(localized: "Tailscale 官方"), mono: t.controlURL != nil)
                kv("状态目录", t.stateDir ?? String(localized: "tailscale/节点名（App Group）"), mono: true)
                kv("临时设备（Ephemeral）", (t.ephemeral ?? false) ? String(localized: "开启") : String(localized: "关闭"))
                kv("接受子网路由", (t.acceptRoutes ?? false) ? String(localized: "开启") : String(localized: "关闭"))
                kv("出口节点", t.exitNode ?? String(localized: "无"), mono: t.exitNode != nil)
                if t.exitNode != nil {
                    kv("使用出口节点时允许访问局域网", (t.exitNodeAllowLAN ?? false) ? String(localized: "开启") : String(localized: "关闭"))
                }
            }
            NavigationLink { DiagnosticsView() } label: {
                Label("查看隧道内存", systemImage: "memorychip")
            }
            .accessibilityIdentifier("node.tailscale.memory")
        } header: {
            HStack(spacing: 6) {
                Text(verbatim: "Tailscale")
                Text("实验性")
            }
        } footer: {
            Text("Tailscale 只在连接后由隧道扩展启动和测速；离线测速不可用。")
        }
        .listRowBackground(Theme.card)
    }

    static func credentialLabel(_ k: String) -> String {
        switch k {
        case "auth-key": return "Auth Key"
        case "password": return "密码"
        case "uuid": return "UUID"
        case "username": return "用户名"
        case "private-key": return "私钥"
        case "pre-shared-key", "psk": return "预共享密钥"
        case "public-key": return "公钥"
        case "auth", "auth-str", "auth_str", "token": return "认证"
        case "obfs-password": return "混淆密码"
        case "private-key-passphrase": return "私钥口令"
        case "short-id": return "Short ID"
        case "reality-opts.public-key": return "Reality 公钥"
        case "reality-opts.short-id": return "Reality Short ID"
        case "plugin-opts.password": return "插件密码"
        default:
            // peers.<i>.public-key / peers.<i>.pre-shared-key (WireGuard with several peers)
            let parts = k.split(separator: ".").map(String.init)
            if parts.count == 3, parts[0] == "peers", let i = Int(parts[1]) {
                return parts[2] == "public-key" ? String(localized: "对端 \(i + 1) 公钥") : String(localized: "对端 \(i + 1) 预共享密钥")
            }
            return k
        }
    }

    func link() async -> Result<String, NodeShare.ShareError> {
        if let m = manual { return NodeShare.link(node: m) }
        // R7A-4: the node of THIS source (provider + name); a by-name link could be another subscription's node.
        if let m = await model.config(of: node) { return NodeShare.link(node: m) }
        return await NodeShare.link(named: node.name)
    }

    func copyLink() async {
        switch await link() {
        case .success(let l):
            UIPasteboard.general.string = l
            copied = true
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            copied = false
        case .failure(let e): message = e.message
        }
    }

    func showQR() async {
        switch await link() {
        case .success(let l): share = ShareTarget(name: node.name, link: l)
        case .failure(let e): message = e.message
        }
    }
}

/// v0.17 按节点设置 editor: remark + test URL (empty = 更多 → 测速).
struct NodeSettingsSheet: View {
    let name: String
    @Environment(\.dismiss) private var dismiss
    @State private var note = ""
    @State private var url = ""
    @State private var error: String?

    var urlValid: Bool { url.trimmingCharacters(in: .whitespaces).isEmpty || CoreOverrides.isValidTestURL(url) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("备注", text: $note, axis: .vertical)
                        .lineLimit(1...4)
                        .accessibilityIdentifier("node.settings.noteField")
                } header: { Text("备注") }
                Section {
                    TextField(ControllerClient.testSettings.url, text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.callout.monospaced())
                        .accessibilityIdentifier("node.settings.urlField")
                    if !urlValid {
                        Text("请输入 http:// 或 https:// 开头的地址").font(.caption).foregroundStyle(Theme.bad)
                    }
                    ForEach(CoreOverrides.testURLPresets, id: \.self) { u in
                        Button { url = u } label: {
                            HStack {
                                Text(LocalizedStringKey(CoreOverrides.testURLLabels[u] ?? (URL(string: u)?.host ?? u)))
                                Spacer()
                                if url == u { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                            }
                        }
                    }
                } header: { Text("测速地址") } footer: { Text("留空则跟随 更多 → 高级设置 → 测速设置 的全局地址。") }
                if let error { Text(verbatim: error).foregroundStyle(Theme.bad) }
                if NodeSettingsStore.setting(for: name) != nil {
                    Section {
                        Button(role: .destructive) {
                            do { try NodeSettingsStore.shared.set(nil, for: name); dismiss() } catch { self.error = error.localizedDescription }
                        } label: { Text("恢复默认") }
                        .accessibilityIdentifier("node.settings.reset")
                    }
                }
            }
            .navigationTitle(Text(verbatim: FlagSafe.text(name)))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        do {
                            try NodeSettingsStore.shared.set(NodeSetting(testURL: url, note: note), for: name)
                            dismiss()
                        } catch { self.error = error.localizedDescription }
                    }
                    .disabled(!urlValid)
                    .accessibilityIdentifier("node.settings.save")
                }
            }
            .onAppear {
                let s = NodeSettingsStore.setting(for: name)
                note = s?.note ?? ""
                url = s?.testURL ?? ""
            }
        }
    }
}

/// feat/subs-split: the 已添加到本地节点 result alert for the node list (split out of NodeListView.body so the
/// type checker stays fast); same text as NodeDetailView's.
struct AddedLocalAlert: ViewModifier {
    @Binding var added: NodeDetailView.AddedLocal?
    let edit: ([String: Any]) -> Void

    func body(content: Content) -> some View {
        content.alert("已添加到本地节点", isPresented: Binding(get: { added != nil }, set: { if !$0 { added = nil } }), presenting: added) { a in
            Button("编辑") {
                if let m = NodeManagerModel.shared.manualNode(named: a.name) { edit(m) }
            }
            Button("好", role: .cancel) {}
        } message: { a in
            if a.inRuntime {
                Text("「\(a.name)」现在是可编辑的本地节点，不受订阅更新影响。")
            } else {
                Text("「\(a.name)」现在是可编辑的本地节点，不受订阅更新影响。它还不在当前配置里：在 工具 → 节点与订阅 → 本地 打开「把本地节点加入每个配置」。")
            }
        }
    }
}
