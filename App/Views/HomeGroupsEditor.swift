import SwiftUI

// feat/home-groups: the 策略 header on Home (with the 编辑 pill) and the 编辑首页策略 sheet.

/// Header + cards. Hidden entirely when the resolved list is empty (the user unchecked every group).
struct HomePolicySection: View {
    let groups: [DashboardModel.HomeGroup]
    let live: Bool
    /// Every candidate group in order, needed to materialise the default on 从首页移除.
    let available: [String]
    @State private var editing = false
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Text("策略").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button { editing = true } label: {
                    Text("编辑")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 4)
                        .background(Capsule().fill(Theme.ink(0.08)))
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("编辑首页策略"))
            }
            .padding(.horizontal, 4)
            HomePolicyCards(groups: groups, live: live,
                            onRemove: { name in
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                withAnimation(.spring(response: 0.3)) { HomeGroupsStore.shared.remove(name, available: available) }
                            },
                            onEdit: { editing = true })
        }
        .sheet(isPresented: $editing) { HomeGroupsEditor().environmentObject(vpn) }
    }
}

/// 编辑首页策略: every policy group (live from the core when connected, from the profile otherwise) with a
/// checkmark; drag to reorder. Changes are saved immediately.
struct HomeGroupsEditor: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = HomeGroupsStore.shared

    struct Row: Identifiable, Equatable {
        var id: String { name }
        let name: String
        let kind: String
        let icon: String?
    }

    @State private var rows: [Row] = []
    @State private var checked: Set<String> = []
    @State private var loaded = false
    @State private var fromCore = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if loaded && rows.isEmpty {
                        EmptyStateRow(icon: "square.stack.3d.up", title: "没有可显示的策略组", message: "当前配置里没有策略组。")
                    } else if !loaded {
                        HStack { Spacer(); ProgressView(); Spacer() }
                    }
                    ForEach(rows) { r in row(r) }
                        .onMove { from, to in
                            rows.move(fromOffsets: from, toOffset: to)
                            save()
                        }
                        .deleteDisabled(true)
                } header: {
                    HStack {
                        Text("首页显示")
                        Spacer()
                        Text(verbatim: "\(checked.count) / \(HomeGroupsStore.maxCount)").monospacedDigit()
                    }
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("勾选要在首页显示的策略组，拖动调整顺序，最多 12 个。全部取消勾选则首页不显示策略卡片。")
                        if !store.isCustom() {
                            Text("当前为默认：显示前 4 个策略组。")
                        }
                        if fromCore { Text("列表来自运行中的内核。") } else { Text("未连接：列表来自当前配置文件。") }
                    }
                }
                .listRowBackground(Theme.card)

                if store.isCustom() {
                    Section {
                        Button("恢复默认") {
                            store.set(nil)
                            Task { await load() }
                        }
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .navigationTitle("编辑首页策略")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
            .task { await load() }
        }
    }

    @ViewBuilder
    func row(_ r: Row) -> some View {
        let on = checked.contains(r.name)
        let full = !on && checked.count >= HomeGroupsStore.maxCount
        let display = PolicyGroupDisplay(name: r.name, kind: r.kind, now: nil, members: [], selectable: false)
        Button {
            toggle(r.name)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: on ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .foregroundStyle(on ? Theme.accent : Color.secondary.opacity(full ? 0.3 : 0.6))
                    .accessibilityHidden(true)
                GroupIconView(group: r.name, profileIcon: r.icon, fallback: display.icon, size: 28)
                Text(r.name).font(.subheadline).lineLimit(1)
                Spacer(minLength: 6)
                Text(display.label)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Capsule().fill(Theme.ink(0.1)))
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("homegroups.row." + r.name)
        .opacity(full ? 0.5 : 1)
        .accessibilityAddTraits(on ? .isSelected : [])
    }

    private func toggle(_ name: String) {
        if checked.contains(name) {
            checked.remove(name)
        } else {
            guard checked.count < HomeGroupsStore.maxCount else {
                UINotificationFeedbackGenerator().notificationOccurred(.warning)
                return
            }
            checked.insert(name)
        }
        UISelectionFeedbackGenerator().selectionChanged()
        save()
    }

    private func save() {
        store.set(rows.map(\.name).filter { checked.contains($0) })
    }

    /// Candidates in order: the shown groups first (their Home order), then the rest in profile order.
    private func load() async {
        var all: [Row] = []
        fromCore = false
        if vpn.isConnected, let proxies = try? await ControllerClient.shared.proxies() {
            let order = proxies["GLOBAL"]?.all ?? []
            all = order.compactMap { n in
                guard let p = proxies[n], p.isGroup, p.hidden != true else { return nil }
                return Row(name: n, kind: PolicyGroupDisplay.kind(live: p.type), icon: p.icon)
            }
            fromCore = true
        }
        if !fromCore {
            let insp = ProfileInspector.shared
            // selftest: also reload when the inspector still holds another profile (switched since).
            if insp.result.groups.isEmpty || insp.profilePath != AppShared.activeProfileURL?.path { await insp.load() }
            all = insp.result.groups.filter { $0.hidden != true }.map { Row(name: $0.name, kind: $0.type, icon: $0.icon) }
        }
        let shown = store.resolved(available: all.map(\.name))
        let byName = Dictionary(all.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        rows = shown.compactMap { byName[$0] } + all.filter { !shown.contains($0.name) }
        checked = Set(shown)
        loaded = true
    }
}
