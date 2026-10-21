import SwiftUI

/// 更多 → 节点与订阅 (fb-subs-global, user 「还是分开的」): one page for nodes and subscriptions. 订阅 lists every
/// subscription — config subscriptions (remote profiles), node subscriptions and the providers of the current
/// profile — with the same swipes everywhere (right 更新, left 删除 / 停用) and context menus; then 本地节点,
/// 全部节点 and 筛选节点 (Loon's 所有节点 page in the main style). It replaces the separate 订阅管理 page.
struct NodeManagerView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var nodeSubs = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var updater = ProviderUpdater.shared
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

    var localCount: Int { model.nodes.filter { localIDs.contains($0.source.id) }.count }

    enum SubRow: Identifiable {
        case profile(Profile)
        case nodeSub(NodeSubscription)
        case provider(NodeSource)
        var id: String {
            switch self {
            case .profile(let p): return "profile:" + p.id
            case .provider(let s): return s.id
            case .nodeSub(let s): return "sub:" + s.id
            }
        }
        var name: String {
            switch self {
            case .profile(let p): return p.displayName
            case .provider(let s): return s.name
            case .nodeSub(let s): return s.name
            }
        }
    }

    var subRows: [SubRow] {
        var rows: [SubRow] = store.profiles.filter { $0.kind == .remote }.map { .profile($0) }
        rows += nodeSubs.subs.map { .nodeSub($0) }
        let ours = Set(nodeSubs.subs.map(\.name))
        rows += model.sources.filter { $0.kind == .provider && !ours.contains($0.name) }.map { .provider($0) }
        switch subSort {
        case "name": return rows.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case "count": return rows.sorted { (count($0) ?? -1) > (count($1) ?? -1) }
        default: return rows
        }
    }

    /// The active remote profile's own nodes (the core / offline inspector only knows the active profile).
    var activeProfileSource: NodeSource? {
        guard let s = model.source(.profile), s.remote else { return nil }
        return s
    }

    func count(_ r: SubRow) -> Int? {
        switch r {
        case .profile(let p): return p.id == store.activeID ? activeProfileSource.map(model.count) : nil
        case .provider(let s): return model.count(s)
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
                if subRows.isEmpty {
                    EmptyStateRow(icon: "tray", title: "还没有订阅", message: "点右上角 + 添加配置订阅或节点订阅。")
                }
                ForEach(subRows) { r in subscriptionRow(r) }
            } header: { Text("订阅 \(subRows.count)") } footer: {
                if !subRows.isEmpty { Text("右滑更新；左滑删除或停用；长按查看更多操作。") }
            }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink {
                    NodeListView(scope: NodeListScope(title: String(localized: "本地节点"), sourceIDs: localIDs,
                                                      emptyTitle: String(localized: "还没有本地节点"),
                                                      emptyMessage: String(localized: "点右上角 + 粘贴分享链接、扫码或选择协议填写。")))
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
            await offline.load()
            await model.reload()
        }
        .onAppear { mergeManual = CoreOverrides.load().mergeManual }
        .onChange(of: vpn.isConnected) { _ in Task { await model.reload() } }
        .sheet(isPresented: $showAddSub, onDismiss: { Task { await model.reload() } }) { NodeSubEditor(sub: nil).environmentObject(store) }
        .sheet(item: $editingSub, onDismiss: { Task { await model.reload() } }) { s in NodeSubEditor(sub: s).environmentObject(store) }
        .sheet(item: $editingProfile) { p in ProfileSubEditor(profile: p).environmentObject(store) }
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
        .nodeSubDeleteConfirmation($confirmDeleteSub) { s in await nodeSubs.delete(s); await model.reload() }
        .profileDeleteConfirmation($confirmDeleteProfile, store: store)
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
                                     downloaded: FileManager.default.fileExists(atPath: sub.cacheURL.path),
                                     alerts: UsageAlerts.rule(for: sub.id).enabled)
            }
            .accessibilityIdentifier("nodesub.row." + sub.name)
            // v0.19.8 (user 「在订阅上左滑/右滑要能更新或者删除该订阅」): right swipe 更新, left swipe 删除 / 停用.
            .swipeActions(edge: .leading) {
                Button { Task { await refreshSub(sub) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                    .tint(.blue)
                    .disabled(!sub.enabled || nodeSubs.updating.contains(sub.id))
            }
            .swipeActions(edge: .trailing) {
                Button(role: .destructive) { confirmDeleteSub = sub } label: { Label("删除", systemImage: "trash") }
                Button { Task { await toggleSub(sub) } } label: {
                    Label(LocalizedStringKey(sub.enabled ? "停用" : "启用"), systemImage: sub.enabled ? "pause.circle" : "play.circle")
                }
                .tint(sub.enabled ? .orange : Theme.good)
            }
            .contextMenu {
                Button { Task { await refreshSub(sub) } } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                    .disabled(!sub.enabled)
                Button { Task { await toggleSub(sub) } } label: {
                    Label(LocalizedStringKey(sub.enabled ? "停用" : "启用"), systemImage: sub.enabled ? "pause.circle" : "play.circle")
                }
                Button { editingSub = sub } label: { Label("编辑链接 / 名称 / UA / 间隔", systemImage: "pencil") }
                if let p = store.active {
                    Button { rulesFor = RulesTarget(profile: p, key: sub.rulesKey, path: sub.cacheURL.path, title: sub.name) } label: {
                        Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle")
                    }
                }
                Button { UIPasteboard.general.string = sub.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
                Button(role: .destructive) { confirmDeleteSub = sub } label: { Label("删除", systemImage: "trash") }
            }
        case .provider(let s):
            let pv = httpProviders[s.name]
            let key = "proxy:" + s.name
            NavigationLink {
                NodeListView(scope: NodeListScope(title: s.name, sourceIDs: [s.id],
                                                  emptyTitle: String(localized: "还没有下载"),
                                                  emptyMessage: String(localized: "连接一次，或在订阅 / 提供者页面更新后显示节点。")))
            } label: {
                SubscriptionRowLabel(icon: "shippingbox", color: Theme.warn, name: s.name, kind: String(localized: "节点集 · 来自配置"),
                                     count: model.count(s), info: nil, updated: s.updatedAt, error: updater.errors[key],
                                     updating: updater.busy.contains(key), disabled: false, downloaded: s.cached || model.count(s) > 0)
            }
            .accessibilityIdentifier("provider.row." + s.name)
            .swipeActions(edge: .leading) {
                if pv != nil {
                    Button { Task { await updater.update(key); await model.reload() } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
                }
            }
            // A provider belongs to the profile (delete / disable it there); the left swipe copies its link.
            .swipeActions(edge: .trailing) {
                if let u = pv?.url {
                    Button { UIPasteboard.general.string = u } label: { Label("复制链接", systemImage: "doc.on.doc") }.tint(.gray)
                }
            }
            .contextMenu {
                if pv != nil { Button { Task { await updater.update(key); await model.reload() } } label: { Label("更新", systemImage: "arrow.clockwise") } }
                if let u = pv?.url { Button { UIPasteboard.general.string = u } label: { Label("复制订阅链接", systemImage: "doc.on.doc") } }
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
                                         active: active, alerts: UsageAlerts.rule(for: p.id).enabled)
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

    var body: some View {
        HStack(spacing: 12) {
            SourceIcon(systemName: icon, color: disabled ? .secondary : color)
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
