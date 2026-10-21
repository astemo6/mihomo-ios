import SwiftUI

/// 更多 → 节点与订阅 (fb-subs-global, user 「还是分开的」): one page for nodes and subscriptions. feat/subs-split (user
/// 2026-10-21 「将这里的配置订阅与节点订阅拆开」): 配置订阅 (remote profiles) and 节点订阅 (the app's node subscriptions and
/// the 节点集 / proxy-providers of the current profile) are two sections. Every node subscription row works the same,
/// Loon-like: right swipe 更新, left swipe 复制链接 only, long-press 图标 / 更新 / 编辑 / 禁用 / 复制链接 / 删除. A profile's
/// 节点集 is changed through the override store (ProviderOverrideStore), never in the profile file. Then 本地节点,
/// 全部节点 and 筛选节点 (Loon's 所有节点 page in the main style). It replaces the separate 订阅管理 page.
struct NodeManagerView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var nodeSubs = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @ObservedObject private var providerOV = ProviderOverrideStore.shared
    @AppStorage("nodes.subSort") private var subSort = "config"
    @State private var mergeManual = CoreOverrides.load().mergeManual
    @State private var parserURL = ResourceParserSetting.url
    @State private var refreshing = false
    @State private var message: String?
    /// v0.19.8 (user): swipe actions on subscription rows; 删除 asks first.
    @State private var confirmDeleteSub: NodeSubscription?
    @State private var confirmDeleteProfile: Profile?
    @State private var editingProfile: Profile?
    @State private var editingSub: NodeSubscription?
    @State private var rulesFor: RulesTarget?
    @State private var showAddSub = false
    @State private var showAddRemote = false
    @State private var showAddNode = false
    @State private var pendingMessage: String?
    /// feat/subs-split: 节点集 (profile proxy-provider) actions.
    @State private var confirmDeleteProvider: ProviderTarget?
    @State private var editingProvider: ProviderTarget?
    @State private var iconTarget: IconTarget?
    /// r7 OPT-2: per-row file / defaults reads (cache file present, usage alerts on), refreshed when the lists change
    /// or a sheet closes — not on every redraw (each delay result during 全部测速 redraws this page).
    @State private var downloadedSubs: Set<String> = []
    @State private var alertIDs: Set<String> = []

    struct ProviderTarget: Identifiable {
        let name: String
        var id: String { name }
    }

    struct IconTarget: Identifiable {
        let id: String
        let title: String
        let current: String?
        let apply: (String?) -> Void
    }

    struct RulesTarget: Identifiable {
        let id = UUID()
        let profile: Profile
        var key: String? = nil
        var path: String? = nil
        var title: String
    }

    var manualActive: Bool { store.activeID == ProfileStore.manualID }

    /// 本地节点 = manual nodes + the inline nodes of a local profile (a remote profile is a subscription row).
    var localIDs: Set<String> {
        var ids: Set<String> = []
        if let m = model.source(.manual) { ids.insert(m.id) }
        if let p = model.source(.profile), !p.remote { ids.insert(p.id) }
        return ids
    }

    var localCount: Int {
        let ids = localIDs
        return model.countBySource.reduce(0) { ids.contains($1.key.id) ? $0 + $1.value : $0 }
    }

    enum SubRow: Identifiable {
        case profile(Profile)
        case nodeSub(NodeSubscription)
        /// A 节点集 of the current profile; nil source = 停用 (not in the runtime, listed from the override store).
        case provider(String, NodeSource?)
        var id: String {
            switch self {
            case .profile(let p): return "profile:" + p.id
            case .provider(let n, _): return "provider:" + n
            case .nodeSub(let s): return "sub:" + s.id
            }
        }
        var name: String {
            switch self {
            case .profile(let p): return p.displayName
            case .provider(let n, _): return n
            case .nodeSub(let s): return s.name
            }
        }
    }

    func sorted(_ rows: [SubRow]) -> [SubRow] {
        switch subSort {
        case "name": return rows.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case "count": return rows.sorted { (count($0) ?? -1) > (count($1) ?? -1) }
        default: return rows
        }
    }

    /// 配置订阅: remote profiles.
    var configRows: [SubRow] { sorted(store.profiles.filter { $0.kind == .remote }.map { .profile($0) }) }

    var providerOverrides: [String: ProviderOverride] { providerOV.overrides(manualActive ? nil : store.activeID) }

    /// 节点订阅: the app's node subscriptions, then the current profile's 节点集 (停用 ones included, 删除 ones hidden).
    var nodeRows: [SubRow] {
        var rows: [SubRow] = nodeSubs.subs.map { .nodeSub($0) }
        let ours = Set(nodeSubs.subs.map(\.name))
        let ov = providerOverrides
        let live = model.sources.filter { $0.kind == .provider && !ours.contains($0.name) && ov[$0.name]?.deleted != true }
        rows += live.map { .provider($0.name, $0) }
        let shown = Set(live.map(\.name))
        rows += providerOV.declared.map(\.name)
            .filter { ov[$0]?.disabled == true && ov[$0]?.deleted != true && !shown.contains($0) && !ours.contains($0) }
            .map { .provider($0, nil) }
        return sorted(rows)
    }

    /// 删除 节点集 of the current profile that the profile still declares (恢复已删除的节点集).
    var deletedProviders: [String] {
        let ov = providerOverrides
        return providerOV.declared.map(\.name).filter { ov[$0]?.deleted == true }
    }

    /// The active remote profile's own nodes (the core / offline inspector only knows the active profile).
    var activeProfileSource: NodeSource? {
        guard let s = model.source(.profile), s.remote else { return nil }
        return s
    }

    func count(_ r: SubRow) -> Int? {
        switch r {
        case .profile(let p): return p.id == store.activeID ? activeProfileSource.map(model.count) : nil
        case .provider(_, let s): return s.map(model.count)
        case .nodeSub(let s): return model.source(subID: s.id).map(model.count) ?? s.count ?? 0
        }
    }

    /// Providers of the current profile that can be downloaded (http), by name.
    var httpProviders: [String: InspectProvider] {
        let ours = Set(nodeSubs.subs.map(\.name))
        var out: [String: InspectProvider] = [:]
        for pv in offline.result.proxyProviders where pv.vehicle == "http" && !ours.contains(pv.name) { out[pv.name] = pv }
        return out
    }

    var body: some View {
        List {
            Section {
                if configRows.isEmpty {
                    EmptyStateRow(icon: "doc.text", title: "还没有配置订阅", message: "点右上角 + 添加配置订阅。")
                }
                ForEach(configRows) { r in subscriptionRow(r) }
            } header: { Text("配置订阅 \(configRows.count)") } footer: {
                if !configRows.isEmpty { Text("轻点切换为当前配置。右滑更新；左滑删除或停用；长按查看更多操作。") }
            }
            .listRowBackground(Theme.card)

            Section {
                if nodeRows.isEmpty {
                    EmptyStateRow(icon: "tray", title: "还没有节点订阅", message: "点右上角 + 添加节点订阅；配置里的节点集也会列在这里。")
                }
                ForEach(nodeRows) { r in subscriptionRow(r) }
                if !deletedProviders.isEmpty, let id = store.activeID {
                    Button {
                        providerOV.restoreDeleted(id)
                        Task { await applyProviderChange() }
                    } label: {
                        Label("恢复已删除的节点集（\(deletedProviders.count)）", systemImage: "arrow.uturn.backward")
                    }
                    .accessibilityIdentifier("provider.restoreDeleted")
                }
            } header: { Text("节点订阅 \(nodeRows.count)") } footer: {
                if !nodeRows.isEmpty { Text("右滑更新；左滑复制链接；长按查看更多操作。") }
            }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink {
                    NodeListView(scope: NodeListScope(title: String(localized: "本地节点"), sourceIDs: localIDs,
                                                      emptyTitle: String(localized: "还没有本地节点"),
                                                      emptyMessage: String(localized: "点右上角 + 粘贴分享链接、扫码或选择协议填写。"), localNodes: true))
                } label: {
                    HStack(spacing: 12) {
                        SourceIcon(systemName: "internaldrive", color: Theme.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("本地节点").font(.subheadline.weight(.semibold))
                            Group {
                                if manualActive {
                                    Text("当前配置就是「手动节点」")
                                } else if mergeManual {
                                    Text("手动节点已加入每个配置")
                                } else {
                                    Text("手动节点只在「手动节点」配置里使用")
                                }
                            }
                            .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer(minLength: 6)
                        Text(verbatim: "\(localCount)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                if !manualActive {
                    Toggle(isOn: $mergeManual) { Label("把手动节点加入每个配置", systemImage: "square.and.pencil") }
                        .onChange(of: mergeManual) { on in
                            var o = CoreOverrides.load()
                            guard o.mergeManual != on else { return }
                            o.mergeManual = on
                            o.save()
                            Task {
                                if vpn.isConnected, let e = await VPNManager.shared.reload() { message = e }
                                await ProfileInspector.shared.load()
                                await model.reload()
                            }
                        }
                }
            } header: { Text("本地") }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink { NodeListView(scope: .all) } label: {
                    HStack(spacing: 12) {
                        SourceIcon(systemName: "square.stack.3d.up", color: Theme.good)
                        Text("全部节点").font(.subheadline.weight(.semibold))
                        Spacer()
                        Text(verbatim: "\(model.nodes.count)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                NavigationLink { NodeFilterView() } label: {
                    HStack(spacing: 12) {
                        SourceIcon(systemName: "line.3.horizontal.decrease", color: Theme.warn)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("筛选节点").font(.subheadline.weight(.semibold))
                            Text("按地区查看，或建成自动选择策略组").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } header: { Text("节点") } footer: {
                if model.loading { Text("正在读取节点…") } else if model.liveConnected { Text("已连接：节点与延迟来自内核。") } else { Text("未连接：显示配置和本地缓存里的节点。") }
            }
            .listRowBackground(Theme.card)

            UpdateNotifySection()

            // v0.12: QX resource_parser_url, stored only (mihomo parses resources natively).
            Section {
                DisclosureGroup("高级") {
                    TextField("资源解析器地址（resource_parser_url）", text: $parserURL, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        .onSubmit { ResourceParserSetting.url = parserURL }
                        .onChange(of: parserURL) { ResourceParserSetting.url = $0 }
                }
            } footer: {
                Text("Tern 直接识别 Quantumult X / Surge / Clash / sing-box / 分享链接等格式，不需要资源解析器。这里只保存 Quantumult X 配置中的 resource_parser_url，不会下载或运行。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("节点与订阅")
        .refreshable { await updateAll() }
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if refreshing {
                    ProgressView()
                } else {
                    Button { Task { await updateAll() } } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel(Text("更新全部订阅"))
                }
                Menu {
                    Picker(selection: $subSort) {
                        Text("默认顺序").tag("config")
                        Text("名称").tag("name")
                        Text("节点数").tag("count")
                    } label: { Label("订阅排序", systemImage: "arrow.up.arrow.down") }
                } label: { Image(systemName: "arrow.up.arrow.down.circle") }
                    .accessibilityLabel(Text("订阅排序"))
                Menu {
                    Button { showAddRemote = true } label: { Label("添加配置订阅", systemImage: "link.badge.plus") }
                    Button { showAddSub = true } label: { Label("添加节点订阅", systemImage: "tray.and.arrow.down") }
                    Button { showAddNode = true } label: { Label("添加节点", systemImage: "plus.viewfinder") }
                } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加"))
                    .accessibilityIdentifier("nodes.add")
            }
        }
        .navigationDestination(isPresented: $showAddNode) { AddNodeView() }
        .task {
            providerOV.reload()
            await offline.load()
            await model.reload()
            await providerOV.loadDeclared(manualActive ? nil : store.active, force: true)
        }
        .onChange(of: store.activeID) { _ in Task { await providerOV.loadDeclared(manualActive ? nil : store.active, force: true) } }
        .onAppear { mergeManual = CoreOverrides.load().mergeManual; refreshRowMeta() }
        .onReceive(nodeSubs.$subs) { refreshRowMeta(subs: $0) }
        .onReceive(store.$profiles) { refreshRowMeta(profiles: $0) }
        .onChange(of: vpn.isConnected) { _ in Task { await model.reload() } }
        .sheet(isPresented: $showAddSub, onDismiss: { refreshRowMeta(); Task { await model.reload() } }) { NodeSubEditor(sub: nil).environmentObject(store) }
        .sheet(item: $editingSub, onDismiss: { refreshRowMeta(); Task { await model.reload() } }) { s in NodeSubEditor(sub: s).environmentObject(store) }
        .sheet(item: $editingProfile, onDismiss: { refreshRowMeta() }) { p in ProfileSubEditor(profile: p).environmentObject(store) }
        .sheet(isPresented: $showAddRemote, onDismiss: {
            if let m = pendingMessage { pendingMessage = nil; message = m }
            Task { await ProfileInspector.shared.load(); await model.reload() }
        }) { AddRemoteSheet { msg in pendingMessage = msg }.environmentObject(store) }
        .sheet(item: $rulesFor) { t in
            NavigationStack {
                SubscriptionRulesView(profile: t.profile, rulesKey: t.key, previewPath: t.path)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("取消") { rulesFor = nil } } }
            }
            .environmentObject(store)
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .sheet(item: $iconTarget) { t in IconPickerSheet(title: t.title, current: t.current) { v in t.apply(v) } }
        .sheet(item: $editingProvider) { t in
            if let id = store.activeID {
                ProviderEditSheet(profileID: id, info: providerOV.declared.first { $0.name == t.name } ?? ProfileProviderInfo(name: t.name, vehicle: "")) {
                    await applyProviderChange()
                }
            }
        }
        .deleteConfirmation({ t in Text("删除节点集「\(t.name)」？") }, item: $confirmDeleteProvider,
                            message: { _ in Text("只从这个配置里移除：它不再加载，引用它的策略组改用其他节点（没有其他节点时用 DIRECT）。配置文件不会改动，更新配置也不会让它回来；可以在本页底部「恢复已删除的节点集」找回。") },
                            id: "provider.confirmDelete") { t in
            guard let id = store.activeID else { return }
            SnapshotStore.shared.capture(String(localized: "删除节点集前"))
            providerOV.update(id, t.name) { $0.deleted = true }
            Task { await applyProviderChange() }
        }
        .nodeSubDeleteConfirmation($confirmDeleteSub) { s in await nodeSubs.delete(s); await model.reload() }
        .profileDeleteConfirmation($confirmDeleteProfile, store: store)
    }

    /// r7 OPT-2: what the rows show from disk / defaults, read once per change of the lists.
    func refreshRowMeta(subs: [NodeSubscription]? = nil, profiles: [Profile]? = nil) {
        let subs = subs ?? nodeSubs.subs
        let profiles = profiles ?? store.profiles
        let fm = FileManager.default
        let d = Set(subs.filter { fm.fileExists(atPath: $0.cacheURL.path) }.map(\.id))
        let a = Set((subs.map(\.id) + profiles.map(\.id)).filter { UsageAlerts.rule(for: $0).enabled })
        if d != downloadedSubs { downloadedSubs = d }
        if a != alertIDs { alertIDs = a }
    }

    /// One subscription refreshed from a swipe / menu: spinner on the row, result in an alert only on failure.
    func refreshSub(_ s: NodeSubscription) async {
        if let e = await nodeSubs.refresh(s) { message = String(localized: "更新失败：\(e)") }
        await model.reload()
    }

    func refreshProfile(_ p: Profile) async {
        if let e = await store.refresh(p) { message = String(localized: "更新失败：\(e)") }
        await ProfileInspector.shared.load()
        await model.reload()
    }

    func toggleSub(_ s: NodeSubscription) async {
        guard var n = nodeSubs.subs.first(where: { $0.id == s.id }) else { return }
        n.enabled.toggle()
        await nodeSubs.save(n)
        await model.reload()
    }

    /// 停用 / 启用 a config subscription; the active profile cannot be disabled.
    func toggleProfile(_ p: Profile) {
        let cur = store.profiles.first { $0.id == p.id } ?? p
        if let e = store.setEnabled(cur, !cur.enabled) { message = e }
    }

    func activate(_ p: Profile) async {
        if let block = store.activationBlock(p) { message = block; return }
        if let e = await store.setActive(p) { message = String(localized: "已切换，但重载失败：\(e)") }
        await ProfileInspector.shared.load()
        await model.reload()
    }

    /// feat/subs-split: 停用 / 启用 a 节点集 of the current profile (override store; reversible).
    func toggleProvider(_ name: String) async {
        guard let id = store.activeID else { return }
        providerOV.update(id, name) { $0.disabled = $0.disabled == true ? nil : true }
        await applyProviderChange()
    }

    /// The core reloads (when connected), then the offline view and the declared list are read again.
    func applyProviderChange() async {
        // hotfix/sub-disabled-nodes: show the change right away; the core reload below can take a while (provider downloads).
        if vpn.isConnected {
            await ProfileInspector.shared.load()
            await model.reload()
        }
        if vpn.isConnected, let e = await VPNManager.shared.reload() { message = e }
        await ProfileInspector.shared.load()
        await model.reload()
        await providerOV.loadDeclared(manualActive ? nil : store.active, force: true)
    }

    func providerTitle(_ name: String) -> String {
        if let n = providerOverrides[name]?.name?.trimmingCharacters(in: .whitespaces), !n.isEmpty { return n }
        return name
    }

    /// 更新全部订阅: enabled remote profiles + node subscriptions + downloadable providers of the current profile.
    func updateAll() async {
        refreshing = true
        defer { refreshing = false }
        var errs = await store.refreshAll()
        errs += await nodeSubs.refreshAll()
        let keys = Set(httpProviders.keys.map { "proxy:" + $0 })
        if !keys.isEmpty {
            let r = await updater.updateAll(only: keys)
            if r.failed > 0 { errs.append(String(localized: "\(r.failed) 个配置内节点集更新失败")) }
        }
        await ProfileInspector.shared.load()
        await model.reload()
        message = errs.isEmpty ? String(localized: "订阅已全部更新") : errs.joined(separator: "\n")
    }

    @ViewBuilder
    func subscriptionRow(_ r: SubRow) -> some View {
        switch r {
        case .profile(let p):
            profileRow(p)
        case .nodeSub(let sub):
            let src = model.source(subID: sub.id)
            NavigationLink {
                NodeListView(scope: NodeListScope(title: sub.name, sourceIDs: [src?.id ?? NodeSource(kind: .subscription, name: sub.name, subID: sub.id).id],
                                                  emptyTitle: sub.enabled ? String(localized: "还没有节点") : String(localized: "订阅已停用"),
                                                  emptyMessage: sub.enabled ? (sub.lastError ?? String(localized: "更新订阅后显示节点。")) : String(localized: "启用订阅后，节点会加入配置。"),
                                                  subID: sub.id))
            } label: {
                SubscriptionRowLabel(icon: "tray.full", color: Theme.good, name: sub.name, kind: String(localized: "节点订阅"),
                                     count: src.map(model.count) ?? sub.count ?? 0, info: sub.userInfo, updated: sub.lastUpdated,
                                     error: sub.lastError, updating: nodeSubs.updating.contains(sub.id), disabled: !sub.enabled,
                                     downloaded: downloadedSubs.contains(sub.id),
                                     alerts: alertIDs.contains(sub.id), customIcon: sub.icon)
            }
            .accessibilityIdentifier("nodesub.row." + sub.name)
            // right swipe 更新
            .swipeActions(edge: .leading) {
                Button { Task { await refreshSub(sub) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                    .tint(.blue)
                    .disabled(!sub.enabled || nodeSubs.updating.contains(sub.id))
            }
            // feat/subs-split (user 11:55): left swipe = 复制链接 only; 禁用 / 删除 live in the long-press menu.
            .swipeActions(edge: .trailing) {
                Button { UIPasteboard.general.string = sub.url } label: { Label("复制链接", systemImage: "doc.on.doc") }.tint(.gray)
            }
            .contextMenu {
                Section {
                    Button { iconTarget = IconTarget(id: "sub:" + sub.id, title: sub.name, current: sub.icon) { v in nodeSubs.setIcon(sub.id, v?.isEmpty == true ? nil : v) } } label: {
                        Label("图标", systemImage: "photo")
                    }
                    Button { Task { await refreshSub(sub) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                        .disabled(!sub.enabled)
                    Button { editingSub = sub } label: { Label("编辑", systemImage: "pencil") }
                    if let p = store.active {
                        Button { rulesFor = RulesTarget(profile: p, key: sub.rulesKey, path: sub.cacheURL.path, title: sub.name) } label: {
                            Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle")
                        }
                    }
                    Button { Task { await toggleSub(sub) } } label: {
                        Label(LocalizedStringKey(sub.enabled ? "禁用" : "启用"), systemImage: sub.enabled ? "nosign" : "play.circle")
                    }
                    Button { UIPasteboard.general.string = sub.url } label: { Label("复制链接", systemImage: "doc.on.doc") }
                }
                Section {
                    Button(role: .destructive) { confirmDeleteSub = sub } label: { Label("删除", systemImage: "trash") }
                }
            }
        case .provider(let name, let s):
            providerRow(name, s)
        }
    }

    /// feat/subs-split: a 节点集 of the current profile, with the same actions as a node subscription. 停用 / 删除 /
    /// 编辑 / 图标 go to the override store (provider-overrides.json); the profile file is never rewritten.
    @ViewBuilder
    func providerRow(_ name: String, _ s: NodeSource?) -> some View {
        let ov = providerOverrides[name] ?? ProviderOverride()
        let disabled = ov.disabled == true
        let pv = httpProviders[name]
        let declared = providerOV.declared.first { $0.name == name }
        let key = "proxy:" + name
        let canUpdate = !disabled && pv != nil
        let link = pv?.url ?? declared?.url
        let title = providerTitle(name)
        let count = s.map(model.count) ?? 0
        NavigationLink {
            NodeListView(scope: NodeListScope(title: title, sourceIDs: [s?.id ?? NodeSource(kind: .provider, name: name).id],
                                              emptyTitle: disabled ? String(localized: "节点集已停用") : String(localized: "还没有下载"),
                                              emptyMessage: disabled ? String(localized: "启用后，节点会重新加入配置。") : String(localized: "连接一次，或在「节点与订阅」里右滑更新后显示节点。")))
        } label: {
            SubscriptionRowLabel(icon: "shippingbox", color: Theme.warn, name: title, kind: String(localized: "节点集 · 来自配置"),
                                 count: disabled ? nil : count, info: nil, updated: s?.updatedAt, error: disabled ? nil : updater.errors[key],
                                 updating: updater.busy.contains(key), disabled: disabled, downloaded: (s?.cached ?? false) || count > 0,
                                 customIcon: ov.icon)
        }
        .accessibilityIdentifier("provider.row." + name)
        .swipeActions(edge: .leading) {
            if canUpdate {
                Button { Task { await updater.update(key); await model.reload() } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
            }
        }
        .swipeActions(edge: .trailing) {
            if let link {
                Button { UIPasteboard.general.string = link } label: { Label("复制链接", systemImage: "doc.on.doc") }.tint(.gray)
            }
        }
        .contextMenu {
            Section {
                Button {
                    iconTarget = IconTarget(id: "provider:" + name, title: title, current: ov.icon) { v in
                        guard let id = store.activeID else { return }
                        providerOV.update(id, name) { $0.icon = v?.isEmpty == true ? nil : v }
                    }
                } label: { Label("图标", systemImage: "photo") }
                Button { Task { await updater.update(key); await model.reload() } } label: { Label("更新", systemImage: "arrow.clockwise") }
                    .disabled(!canUpdate)
                Button { editingProvider = ProviderTarget(name: name) } label: { Label("编辑", systemImage: "pencil") }
                Button { Task { await toggleProvider(name) } } label: {
                    Label(LocalizedStringKey(disabled ? "启用" : "禁用"), systemImage: disabled ? "play.circle" : "nosign")
                }
                if let link {
                    Button { UIPasteboard.general.string = link } label: { Label("复制链接", systemImage: "doc.on.doc") }
                }
            }
            Section {
                Button(role: .destructive) { confirmDeleteProvider = ProviderTarget(name: name) } label: { Label("删除", systemImage: "trash") }
            }
        }
    }

    /// A config subscription (remote profile). The active one opens its nodes; another one becomes the active
    /// profile on tap (as 订阅管理 did). Device report v0.19.11 「只有右滑更新，左滑无反应」: this row had no trailing
    /// swipe at all (only 更新); it now has 删除 / 停用 like every other subscription.
    @ViewBuilder
    func profileRow(_ p: Profile) -> some View {
        let active = p.id == store.activeID
        let label = SubscriptionRowLabel(icon: "doc.text", color: Theme.accent, name: p.displayName, kind: String(localized: "配置订阅"),
                                         count: count(.profile(p)), info: p.userInfo, updated: p.lastUpdated, error: nil,
                                         updating: store.updating.contains(p.id), disabled: !p.enabled, downloaded: true,
                                         active: active, alerts: alertIDs.contains(p.id))
        Group {
            if active, let src = activeProfileSource {
                NavigationLink {
                    NodeListView(scope: NodeListScope(title: p.displayName, sourceIDs: [src.id]))
                } label: { label }
            } else {
                Button { Task { await activate(p) } } label: { label.contentShape(Rectangle()) }
                    .buttonStyle(.plain)
            }
        }
        .accessibilityIdentifier("subs.profile." + p.name)
        .swipeActions(edge: .leading) {
            Button { Task { await refreshProfile(p) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                .tint(.blue)
                .disabled(!p.enabled || store.updating.contains(p.id))
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) { confirmDeleteProfile = p } label: { Label("删除", systemImage: "trash") }
            Button { toggleProfile(p) } label: {
                Label(LocalizedStringKey(p.enabled ? "停用" : "启用"), systemImage: p.enabled ? "pause.circle" : "play.circle")
            }
            .tint(p.enabled ? .orange : Theme.good)
        }
        .contextMenu {
            if !active {
                Button { Task { await activate(p) } } label: { Label("设为当前配置", systemImage: "checkmark.circle") }
                    .disabled(!p.enabled)
            }
            Button { Task { await refreshProfile(p) } } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                .disabled(!p.enabled)
            Button { toggleProfile(p) } label: {
                Label(LocalizedStringKey(p.enabled ? "停用" : "启用"), systemImage: p.enabled ? "pause.circle" : "play.circle")
            }
            .disabled(active && p.enabled)
            Button { editingProfile = p } label: { Label("编辑链接 / 名称 / UA / 间隔", systemImage: "pencil") }
            Button { rulesFor = RulesTarget(profile: p, title: p.name) } label: { Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle") }
            Button { UIPasteboard.general.string = p.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
            Button(role: .destructive) { confirmDeleteProfile = p } label: { Label("删除", systemImage: "trash") }
        }
    }
}

struct SourceIcon: View {
    let systemName: String
    let color: Color
    var body: some View {
        Image(systemName: systemName)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(color)
            .frame(width: 32, height: 32)
            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(color.opacity(0.15)))
            .accessibilityHidden(true)
    }
}

/// One subscription: name, a status line (expiry + used / total, or n 小时前更新, or 下载失败), count.
struct SubscriptionRowLabel: View {
    let icon: String
    let color: Color
    let name: String
    let kind: String
    let count: Int?
    let info: SubscriptionUserInfo?
    let updated: Date?
    let error: String?
    let updating: Bool
    let disabled: Bool
    let downloaded: Bool
    /// The active profile (config subscriptions only).
    var active = false
    var alerts = false
    /// feat/subs-split: the user's 图标 (image URL, "sf:<symbol>" or emoji); nil = the kind's symbol.
    var customIcon: String? = nil

    var body: some View {
        HStack(spacing: 12) {
            if let c = customIcon, !c.isEmpty {
                IconGlyph(value: c, size: 22)
                    .frame(width: 32, height: 32)
                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(color.opacity(0.15)))
                    .accessibilityHidden(true)
            } else {
                SourceIcon(systemName: icon, color: disabled ? .secondary : color)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(verbatim: name).font(.subheadline.weight(.semibold)).lineLimit(1)
                    if active { Image(systemName: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.accent).accessibilityLabel(Text("当前配置")) }
                    if alerts { Image(systemName: "bell.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("用量提醒")) }
                }
                status.font(.caption).lineLimit(1)
                if let info, info.total > 0 {
                    ProgressView(value: info.fraction)
                        .tint(info.fraction > 0.9 ? Theme.bad : info.fraction > 0.75 ? Theme.warn : Theme.accent)
                        .scaleEffect(x: 1, y: 0.6, anchor: .center)
                }
            }
            Spacer(minLength: 6)
            if updating {
                ProgressView().controlSize(.small)
            } else if let count {
                Text(verbatim: "\(count)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
            }
        }
        .opacity(disabled ? 0.6 : 1)
    }

    static let bytes: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f
    }()

    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f
    }()

    @ViewBuilder
    var status: some View {
        if disabled {
            Text("已停用").foregroundStyle(.secondary)
        } else if let error, !error.isEmpty {
            Label { Text("下载失败") + Text(verbatim: " · " + error) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                .foregroundStyle(Theme.bad)
        } else if !downloaded {
            Text("还没有下载").foregroundStyle(Theme.warn)
        } else if let info, info.total > 0 || info.expireDate != nil {
            Text(verbatim: usage(info)).foregroundStyle(.secondary)
        } else if let updated {
            Text("\(Self.relative.localizedString(for: updated, relativeTo: Date())) 更新").foregroundStyle(.secondary)
        } else {
            Text(verbatim: kind).foregroundStyle(.secondary)
        }
    }

    func usage(_ i: SubscriptionUserInfo) -> String {
        var parts: [String] = []
        if let d = i.expireDate { parts.append(d.formatted(date: .numeric, time: .omitted)) }
        if i.total > 0 { parts.append(Self.bytes.string(fromByteCount: i.used) + " / " + Self.bytes.string(fromByteCount: i.total)) }
        return parts.joined(separator: "  ")
    }
}
