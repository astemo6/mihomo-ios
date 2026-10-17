import SwiftUI

/// 更多 → 节点管理 (v0.16), structured like Loon's 所有节点 page in the main style: 本地节点 with its toggle,
/// one row per subscription (state, usage / expiry or last update, node count), then 全部节点 and 筛选节点.
/// Each row opens a NodeListView for that source.
struct NodeManagerView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var nodeSubs = NodeSubStore.shared
    @AppStorage("nodes.subSort") private var subSort = "config"
    @State private var mergeManual = CoreOverrides.load().mergeManual
    @State private var refreshing = false
    @State private var message: String?

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
        case profile(NodeSource)
        case nodeSub(NodeSubscription)
        case provider(NodeSource)
        var id: String {
            switch self {
            case .profile(let s), .provider(let s): return s.id
            case .nodeSub(let s): return "sub:" + s.id
            }
        }
        var name: String {
            switch self {
            case .profile(let s), .provider(let s): return s.name
            case .nodeSub(let s): return s.name
            }
        }
    }

    var subRows: [SubRow] {
        var rows: [SubRow] = []
        if let p = model.source(.profile), p.remote { rows.append(.profile(p)) }
        rows += nodeSubs.subs.map { .nodeSub($0) }
        rows += model.sources.filter { $0.kind == .provider }.map { .provider($0) }
        switch subSort {
        case "name": return rows.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case "count": return rows.sorted { count($0) > count($1) }
        default: return rows
        }
    }

    func count(_ r: SubRow) -> Int {
        switch r {
        case .profile(let s), .provider(let s): return model.count(s)
        case .nodeSub(let s): return model.source(subID: s.id).map(model.count) ?? s.count ?? 0
        }
    }

    var body: some View {
        List {
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
                if subRows.isEmpty {
                    EmptyStateRow(icon: "tray", title: "还没有订阅", message: "在 更多 → 订阅管理 添加配置订阅或节点订阅。") {
                        NavigationLink { SubscriptionsView() } label: { Text("订阅管理").font(.footnote.weight(.semibold)) }
                            .padding(.top, 2)
                    }
                }
                ForEach(subRows) { r in subscriptionRow(r) }
            } header: { Text("订阅 \(subRows.count)") }
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
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("节点管理")
        .refreshable { await model.reload() }
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
                NavigationLink { AddNodeView() } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加节点"))
            }
        }
        .task { await model.reload() }
        .onAppear { mergeManual = CoreOverrides.load().mergeManual }
        .onChange(of: vpn.isConnected) { _ in Task { await model.reload() } }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    /// 更新全部订阅: node subscriptions + remote profiles; one message with the failures.
    func updateAll() async {
        refreshing = true
        defer { refreshing = false }
        var errs = await nodeSubs.refreshAll()
        errs += await store.refreshAll()
        await ProfileInspector.shared.load()
        await model.reload()
        message = errs.isEmpty ? String(localized: "订阅已全部更新") : errs.joined(separator: "\n")
    }

    @ViewBuilder
    func subscriptionRow(_ r: SubRow) -> some View {
        switch r {
        case .profile(let s):
            let p = store.active
            NavigationLink {
                NodeListView(scope: NodeListScope(title: s.name, sourceIDs: [s.id]))
            } label: {
                SubscriptionRowLabel(icon: "doc.text", color: Theme.accent, name: s.name, kind: String(localized: "配置订阅"),
                                     count: model.count(s), info: p?.userInfo, updated: p?.lastUpdated, error: nil,
                                     updating: p.map { store.updating.contains($0.id) } ?? false, disabled: false, downloaded: true)
            }
        case .nodeSub(let sub):
            let src = model.source(subID: sub.id)
            NavigationLink {
                NodeListView(scope: NodeListScope(title: sub.name, sourceIDs: [src?.id ?? NodeSource(kind: .subscription, name: sub.name, subID: sub.id).id],
                                                  emptyTitle: sub.enabled ? String(localized: "还没有节点") : String(localized: "订阅已停用"),
                                                  emptyMessage: sub.enabled ? (sub.lastError ?? String(localized: "更新订阅后显示节点。")) : String(localized: "在订阅管理里启用后，节点会加入配置。"),
                                                  subID: sub.id))
            } label: {
                SubscriptionRowLabel(icon: "tray.full", color: Theme.good, name: sub.name, kind: String(localized: "节点订阅"),
                                     count: src.map(model.count) ?? sub.count ?? 0, info: sub.userInfo, updated: sub.lastUpdated,
                                     error: sub.lastError, updating: nodeSubs.updating.contains(sub.id), disabled: !sub.enabled,
                                     downloaded: FileManager.default.fileExists(atPath: sub.cacheURL.path))
            }
        case .provider(let s):
            NavigationLink {
                NodeListView(scope: NodeListScope(title: s.name, sourceIDs: [s.id],
                                                  emptyTitle: String(localized: "还没有下载"),
                                                  emptyMessage: String(localized: "连接一次，或在订阅 / 提供者页面更新后显示节点。")))
            } label: {
                SubscriptionRowLabel(icon: "shippingbox", color: Theme.warn, name: s.name, kind: String(localized: "节点集"),
                                     count: model.count(s), info: nil, updated: s.updatedAt, error: nil, updating: false,
                                     disabled: false, downloaded: s.cached || model.count(s) > 0)
            }
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
    let count: Int
    let info: SubscriptionUserInfo?
    let updated: Date?
    let error: String?
    let updating: Bool
    let disabled: Bool
    let downloaded: Bool

    var body: some View {
        HStack(spacing: 12) {
            SourceIcon(systemName: icon, color: disabled ? .secondary : color)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: name).font(.subheadline.weight(.semibold)).lineLimit(1)
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
            } else {
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
