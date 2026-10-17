import SwiftUI

/// What a node list shows: everything, some sources, or the nodes whose names match a region pattern.
struct NodeListScope: Hashable {
    var title: String
    var sourceIDs: Set<String>? = nil
    var pattern: String? = nil
    /// Shown when the scope has no nodes at all (disabled / not downloaded subscription …).
    var emptyTitle: String? = nil
    var emptyMessage: String? = nil
    var subID: String? = nil

    static let all = NodeListScope(title: String(localized: "全部节点"))

    /// The nodes in scope (the pattern is compiled once per call).
    func filter(_ nodes: [ManagedNode]) -> [ManagedNode] {
        let re = pattern.flatMap { try? NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }
        if pattern != nil && re == nil { return [] }
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
    @State private var editing: ManualNodesView.EditTarget?
    @State private var confirmDelete: ManagedNode?
    @State private var message: String?
    @State private var editSub: NodeSubscription?

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
        .searchable(text: $query, prompt: Text("名称、服务器或协议"))
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
        .sheet(item: $editSub, onDismiss: { Task { await model.reload() } }) { s in NodeSubEditor(sub: s).environmentObject(ProfileStore.shared) }
        .sheet(item: $editing, onDismiss: { Task { await model.reload() } }) { t in NodeEditorView(node: t.node).environmentObject(ProfileStore.shared) }
        .confirmationDialog("删除这个手动节点？", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            titleVisibility: .visible, presenting: confirmDelete) { n in
            Button("删除", role: .destructive) { Task { await model.delete(n) } }
        } message: { n in Text(verbatim: n.name) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    /// Empty sections worth showing: 手动 (with a hint) and providers that are not downloaded yet; not an empty 配置.
    func showsEmpty(_ src: NodeSource, hasNodes: Bool) -> Bool { (src.kind != .profile && hasNodes) || scope.sourceIDs?.count == 1 }

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
                            Text(verbatim: best.name).font(.caption.weight(.semibold)).lineLimit(1)
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
            EmptyStateRow(icon: "plus.viewfinder", title: "还没有手动节点", message: "点右上角 + 粘贴分享链接、扫码或选择协议填写。")
        case .subscription, .provider:
            if src.cached {
                EmptyStateRow(icon: "icloud.and.arrow.down", title: "没有节点")
            } else {
                EmptyStateRow(icon: "icloud.and.arrow.down", title: "还没有下载", message: "连接一次，或在订阅 / 提供者页面更新后显示节点。")
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
                Button { editing = ManualNodesView.EditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
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
            if model.manualNode(n) != nil {
                Button { editing = ManualNodesView.EditTarget(node: model.manualNode(n)) } label: { Label("编辑", systemImage: "pencil") }
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

    var body: some View {
        HStack(spacing: 10) {
            ProtocolBadge(type: node.type)
                .frame(minWidth: 44, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: node.name).font(.subheadline.weight(.semibold)).lineLimit(1)
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
    @State private var editing: ManualNodesView.EditTarget?
    @State private var editSub: NodeSubscription?
    @State private var confirmDelete = false
    @State private var message: String?
    @State private var copied = false

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
                        Text(verbatim: node.name).font(.title3.weight(.semibold)).lineLimit(3)
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
                if canTest { TestTargetCaption(live: model.liveConnected && node.live) }
            }
            .listRowBackground(Theme.card)

            Section("基本") {
                kv("协议", ProxyItem.label(for: node.type) + (info?.amnezia == true ? " · AmneziaWG" : ""))
                if let a = address { kv("服务器", a, mono: true) }
                kv("UDP", (info?.udp ?? node.udp) ? String(localized: "支持") : String(localized: "未开启"))
                sourceRow
                if !node.inRuntime && node.source.kind == .manual {
                    Text("这个手动节点不在当前配置里：在 更多 → 内核设置 打开「把手动节点加入每个配置」，或把「手动节点」设为当前配置。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .listRowBackground(Theme.card)

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
                        ForEach(c, id: \.self) { k in kv(Self.credentialLabel(k), "••••••") }
                    } header: { Text("凭据") } footer: { Text("出于安全考虑，这里不显示密码、UUID 和密钥。") }
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
                if let m = manual {
                    Button { editing = ManualNodesView.EditTarget(node: m) } label: { Label("编辑", systemImage: "pencil") }
                    Button {
                        Task {
                            do { try await model.duplicate(node); message = String(localized: "已复制一份") } catch { message = error.localizedDescription }
                        }
                    } label: { Label("复制一份", systemImage: "plus.square.on.square") }
                    Button(role: .destructive) { confirmDelete = true } label: { Label("删除", systemImage: "trash") }
                }
            } header: { Text("操作") } footer: {
                if node.source.kind == .subscription || node.source.kind == .provider {
                    Text("订阅里的节点是只读的，更新订阅后会被覆盖。")
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: node.name))
        .navigationBarTitleDisplayMode(.inline)
        .task {
            info = await model.summary(of: node)
            loaded = true
        }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(item: $editing, onDismiss: { Task { await model.reload(); dismiss() } }) { t in NodeEditorView(node: t.node).environmentObject(ProfileStore.shared) }
        .sheet(item: $editSub) { s in NodeSubEditor(sub: s).environmentObject(ProfileStore.shared) }
        .confirmationDialog("删除这个手动节点？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) { Task { await model.delete(node); dismiss() } }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
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
            NavigationLink { ManualNodesView() } label: { kv("来源", String(localized: "手动节点")) }
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
            NavigationLink { SubscriptionsView() } label: { Label("订阅管理", systemImage: "tray.full") }
        case .provider:
            NavigationLink { ProvidersView() } label: { kv("来源", String(localized: "节点集") + " · " + node.source.name) }
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

    static func credentialLabel(_ k: String) -> String {
        switch k {
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
        default: return k
        }
    }

    func link() async -> Result<String, NodeShare.ShareError> {
        if let m = manual { return NodeShare.link(node: m) }
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
