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
    /// r7 OPT-3: read in onAppear only. A State initial value is evaluated on every init (CoreOverrides.load = a file
    /// and two Keychain reads), and LazyDestination re-creates this view whenever 工具 redraws.
    @State private var mergeManual = false
    @State private var parserURL = ResourceParserSetting.url
    @State private var refreshing = false
    @State private var message: String?
    /// v0.19.8 (user): swipe actions on subscription rows; 删除 asks first.
    @State private var confirmDeleteSub: NodeSubscription?
    @State private var confirmDeleteProfile: Profile?
    @State private var editingProfile: Profile?
    @State private var editingSub: NodeSubscription?
    @State private var showAddSub = false
    @State private var showAddRemote = false
    @State private var showAddNode = false
    @State private var pendingMessage: String?
    /// feat/subs-split: 节点集 (profile proxy-provider) actions.
    @State private var confirmDeleteProvider: ProviderTarget?
    @State private var editingProvider: ProviderTarget?
    /// r7 OPT-2: per-row file / defaults reads (cache file present, usage alerts on), refreshed when the lists change
    /// or a sheet closes — not on every redraw (each delay result during 全部测速 redraws this page).
    @State private var downloadedSubs: Set<String> = []
    @State private var alertIDs: Set<String> = []
    /// The last 更新 error of each config subscription (Profile keeps no error), shown on its row until the next try.
    @State private var profileErrors: [String: String] = [:]

    struct ProviderTarget: Identifiable {
        let name: String
        var id: String { name }
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
                if !configRows.isEmpty { Text("轻点编辑；右滑更新，左滑删除；开关启用或关闭；长按查看全部操作。") }
            }
            .listRowBackground(Theme.card)

            Section {
                if nodeRows.isEmpty {
                    EmptyStateRow(icon: "tray", title: "还没有节点订阅", message: "点右上角 + 添加节点订阅。")
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
                if !nodeRows.isEmpty { Text("轻点编辑；右滑更新，左滑删除；开关启用或关闭；长按查看全部操作。") }
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
        .sheet(item: $editingSub, onDismiss: { refreshRowMeta(); Task { await model.reload() } }) { s in
            NodeSubSheet(sub: s) { d in Task { await nodeSubs.delete(d); await model.reload() } }
                .environmentObject(store).environmentObject(vpn)
        }
        .sheet(item: $editingProfile, onDismiss: { refreshRowMeta() }) { p in
            ProfileSubSheet(profile: p, nodes: p.id == store.activeID ? activeProfileSource.map { NodeListScope(title: p.displayName, sourceIDs: [$0.id]) } : nil) { d in
                store.delete(d)
            }
            .environmentObject(store).environmentObject(vpn)
        }
        .sheet(isPresented: $showAddRemote, onDismiss: {
            if let m = pendingMessage { pendingMessage = nil; message = m }
            Task { await ProfileInspector.shared.load(); await model.reload() }
        }) { AddRemoteSheet { msg in pendingMessage = msg }.environmentObject(store) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .sheet(item: $editingProvider) { t in
            if let id = store.activeID {
                ProviderSubSheet(profileID: id, info: providerOV.declared.first { $0.name == t.name } ?? ProfileProviderInfo(name: t.name, vehicle: httpProviders[t.name] == nil ? "" : "http", url: httpProviders[t.name]?.url),
                                 status: providerStatus(t.name, model.sources.first { $0.kind == .provider && $0.name == t.name }),
                                 nodes: providerScope(t.name),
                                 onDelete: { deleteProvider(t.name) },
                                 onApply: { await applyProviderChange() })
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
        let e = await store.refresh(p)
        profileErrors[p.id] = e
        if let e { message = String(localized: "更新失败：\(e)") }
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

    /// feat/subs-split: 停用 / 启用 a 节点集 of the current profile (override store; reversible).
    func toggleProvider(_ name: String) async {
        guard let id = store.activeID else { return }
        providerOV.update(id, name) { $0.disabled = $0.disabled == true ? nil : true }
        await applyProviderChange()
    }

    /// The core reloads (when connected), then the offline view and the declared list are read again.
    func applyProviderChange() async {
        // hotfix/sub-disabled-nodes: show the change right away; the core reload below can take a while (provider downloads).
        // r7 OPT-4: only the node list here — ProfileInspector.load parses the whole profile and runs once, after the reload.
        if vpn.isConnected { await model.reload() }
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
            if r.failed > 0 { errs.append(String(localized: "\(r.failed) 个节点集更新失败")) }
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
            nodeSubRow(sub)
        case .provider(let name, let s):
            providerRow(name, s)
        }
    }

    /// Unified subscription row (SubscriptionKit): switch = 启用, right 更新, left 删除, tap = edit sheet.
    @ViewBuilder
    func nodeSubRow(_ sub: NodeSubscription) -> some View {
        let src = model.source(subID: sub.id)
        let (usage, fraction) = SubscriptionStatus.usage(sub.userInfo)
        let busy = nodeSubs.updating.contains(sub.id)
        SubscriptionRow(id: "nodesub.row." + sub.name, icon: "tray.full", color: Theme.good, customIcon: sub.icon, name: sub.name,
                        status: SubscriptionStatus(source: String(localized: "节点订阅"), updated: sub.lastUpdated,
                                                   interval: sub.updateIntervalHours * 3600, error: sub.lastError, disabled: !sub.enabled,
                                                   downloaded: downloadedSubs.contains(sub.id), usage: usage, usageFraction: fraction),
                        count: src.map(model.count) ?? sub.count ?? 0, updating: busy,
                        enabled: Binding(get: { sub.enabled }, set: { on in if on != sub.enabled { Task { await toggleSub(sub) } } }),
                        onTap: { editingSub = sub }) {
            if alertIDs.contains(sub.id) { Image(systemName: "bell.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("用量提醒")) }
        }
        .subscriptionActions(SubscriptionActions(
            update: sub.enabled && !busy ? { Task { await refreshSub(sub) } } : nil,
            edit: { editingSub = sub }, url: sub.url,
            enabled: sub.enabled, setEnabled: { _ in Task { await toggleSub(sub) } },
            delete: { confirmDeleteSub = sub }))
    }

    /// A 节点集 of the current profile, with the same actions as a node subscription. 停用 / 删除 / 编辑 go to the
    /// override store (provider-overrides.json); the profile file is never rewritten.
    func providerStatus(_ name: String, _ s: NodeSource?) -> SubscriptionStatus {
        let ov = providerOverrides[name] ?? ProviderOverride()
        let disabled = ov.disabled == true
        let declared = providerOV.declared.first { $0.name == name }
        let count = s.map(model.count) ?? 0
        let http = (declared?.vehicle ?? httpProviders[name]?.vehicle) == "http"
        return SubscriptionStatus(source: String(localized: "节点集"), remote: http, updated: s?.updatedAt,
                                  interval: ov.interval ?? declared?.interval ?? 0, error: disabled ? nil : updater.errors["proxy:" + name],
                                  disabled: disabled, downloaded: (s?.cached ?? false) || count > 0)
    }

    /// 删除 a 节点集 (override store; 恢复已删除的节点集 brings it back).
    func deleteProvider(_ name: String) {
        guard let id = store.activeID else { return }
        SnapshotStore.shared.capture(String(localized: "删除节点集前"))
        providerOV.update(id, name) { $0.deleted = true }
        Task { await applyProviderChange() }
    }

    /// The node list of a 节点集 (opened from its sheet).
    func providerScope(_ name: String) -> NodeListScope {
        let s = model.sources.first { $0.kind == .provider && $0.name == name }
        let disabled = providerOverrides[name]?.disabled == true
        return NodeListScope(title: providerTitle(name), sourceIDs: [s?.id ?? NodeSource(kind: .provider, name: name).id],
                             emptyTitle: disabled ? String(localized: "节点集已停用") : String(localized: "还没有下载"),
                             emptyMessage: disabled ? String(localized: "启用后，节点会重新加入配置。") : String(localized: "连接一次，或在「节点与订阅」里右滑更新后显示节点。"))
    }

    @ViewBuilder
    func providerRow(_ name: String, _ s: NodeSource?) -> some View {
        let ov = providerOverrides[name] ?? ProviderOverride()
        let disabled = ov.disabled == true
        let pv = httpProviders[name]
        let declared = providerOV.declared.first { $0.name == name }
        let key = "proxy:" + name
        let canUpdate = !disabled && pv != nil && !updater.busy.contains(key)
        let link = ov.url ?? pv?.url ?? declared?.url
        SubscriptionRow(id: "provider.row." + name, icon: "shippingbox", color: Theme.warn, customIcon: ov.icon, name: providerTitle(name),
                        status: providerStatus(name, s), count: disabled ? nil : (s.map(model.count) ?? 0),
                        updating: updater.busy.contains(key),
                        enabled: Binding(get: { !disabled }, set: { on in if on == disabled { Task { await toggleProvider(name) } } }),
                        onTap: { editingProvider = ProviderTarget(name: name) })
        .subscriptionActions(SubscriptionActions(
            update: canUpdate ? { Task { await updater.update(key); await model.reload() } } : nil,
            edit: { editingProvider = ProviderTarget(name: name) }, url: link,
            enabled: !disabled, setEnabled: { _ in Task { await toggleProvider(name) } },
            delete: { confirmDeleteProvider = ProviderTarget(name: name) }))
    }

    /// A config subscription (remote profile). The switch is its 停用 flag (the active profile can't be switched off);
    /// 设为当前配置 is in the sheet (and in 更多 → 配置). Tap opens the sheet like every other subscription.
    @ViewBuilder
    func profileRow(_ p: Profile) -> some View {
        let active = p.id == store.activeID
        let (usage, fraction) = SubscriptionStatus.usage(p.userInfo)
        let busy = store.updating.contains(p.id)
        SubscriptionRow(id: "subs.profile." + p.name, icon: "doc.text", color: Theme.accent, name: p.displayName,
                        status: SubscriptionStatus(source: String(localized: "配置订阅"), updated: p.lastUpdated,
                                                   interval: p.updateIntervalHours * 3600, error: profileErrors[p.id], disabled: !p.enabled,
                                                   downloaded: true, usage: usage, usageFraction: fraction),
                        count: count(.profile(p)), updating: busy,
                        enabled: Binding(get: { p.enabled }, set: { on in if on != p.enabled { toggleProfile(p) } }),
                        toggleDisabled: active && p.enabled,
                        onTap: { editingProfile = p }) {
            if active { Image(systemName: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.accent).accessibilityLabel(Text("当前配置")) }
            if alertIDs.contains(p.id) { Image(systemName: "bell.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("用量提醒")) }
        }
        .subscriptionActions(SubscriptionActions(
            update: p.enabled && !busy ? { Task { await refreshProfile(p) } } : nil,
            edit: { editingProfile = p }, url: p.url,
            enabled: p.enabled, setEnabled: { _ in toggleProfile(p) }, toggleDisabled: active && p.enabled,
            delete: { confirmDeleteProfile = p }))
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
