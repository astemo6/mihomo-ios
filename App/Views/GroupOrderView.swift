import SwiftUI

// feat/group-order: 排列策略组. Drag (or 置顶) the groups of the active profile; 保存 writes the order into the
// profile file (GroupOrder.save) and reloads the core when connected.

struct GroupOrderView: View {
    struct Row: Identifiable, Equatable {
        var id: String { name }
        let name: String
        let kind: String
        let icon: String?
        /// false = not in the profile file (added at runtime), keeps its place.
        let movable: Bool
    }

    /// The groups as the policy page lists them (display names, current order).
    let groups: [(name: String, kind: String, icon: String?)]
    /// Called with the new order after a successful save (optimistic update of the live list).
    var onSaved: (([String]) -> Void)? = nil

    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var rows: [Row] = []
    @State private var original: [String] = []
    @State private var saving = false
    @State private var message: String?
    @State private var keepsOrder = false

    private var profile: Profile? { store.active }
    private var changed: Bool { rows.map(\.name) != original }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(rows) { r in row(r).moveDisabled(!r.movable) }
                        .onMove { from, to in move(from, to) }
                        .deleteDisabled(true)
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("拖动或置顶来调整顺序。保存后写入配置文件，注释和其他内容保持不变，原文件备份为 .bak。")
                        if rows.contains(where: { !$0.movable }) {
                            Text("标有「运行时加入」的策略组不在配置文件中，位置保持不变。")
                        }
                        if profile?.kind == .remote {
                            Text("这是订阅配置：顺序也会单独保存，每次更新订阅后自动重新排列。")
                                .accessibilityIdentifier("grouporder.subhint")
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("grouporder.hint")
                }
                .listRowBackground(Theme.card)

                if let message {
                    Section { Text(message).font(.footnote).foregroundStyle(Theme.bad).accessibilityIdentifier("grouporder.message") }
                        .listRowBackground(Theme.card)
                }

                if profile?.kind == .remote && keepsOrder {
                    Section {
                        Button("不再保持此顺序") {
                            if let p = profile { GroupOrder.clearStoredOrder(p) }
                            keepsOrder = false
                        }
                    } footer: {
                        Text("下次更新订阅时恢复订阅自带的顺序。")
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .navigationTitle("排列策略组")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if saving {
                        ProgressView()
                    } else {
                        Button("保存") { Task { await save() } }
                            .disabled(!changed)
                            .accessibilityIdentifier("grouporder.save")
                    }
                }
            }
            .task { load() }
        }
    }

    @ViewBuilder
    func row(_ r: Row) -> some View {
        let display = PolicyGroupDisplay(name: r.name, kind: r.kind, now: nil, members: [], selectable: false)
        HStack(spacing: 12) {
            GroupIconView(group: r.name, profileIcon: r.icon, fallback: display.icon, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: FlagSafe.text(r.name)).font(.subheadline).lineLimit(1)
                if !r.movable {
                    Text("运行时加入").font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 6)
            Text(display.label)
                .font(.caption2.weight(.semibold))
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Capsule().fill(Theme.ink(0.1)))
                .foregroundStyle(.secondary)
            if r.movable {
                Button { toTop(r.name) } label: {
                    Image(systemName: "arrow.up.to.line").foregroundStyle(Theme.accent)
                }
                .buttonStyle(.borderless)
                .disabled(rows.first?.name == r.name)
                .accessibilityLabel(Text("置顶"))
                .accessibilityIdentifier("grouporder.top." + r.name)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("grouporder.row." + r.name)
    }

    private func load() {
        guard let p = profile else { return }
        let edits = GroupEditStore.get(p.id)
        let inFile = Set(GroupOrder.fileNames(p).map { GroupOrder.displayName(of: $0, edits: edits) })
        rows = groups.map { Row(name: $0.name, kind: $0.kind, icon: $0.icon, movable: inFile.contains($0.name)) }
        original = rows.map(\.name)
        keepsOrder = GroupOrder.hasStoredOrder(p)
    }

    /// Moves only movable rows; rows that are not in the file stay at their index.
    private func move(_ from: IndexSet, _ to: Int) {
        var all = rows
        all.move(fromOffsets: from, toOffset: to)
        rows = Self.pinFixed(original: rows, moved: all)
    }

    private func toTop(_ name: String) {
        guard let i = rows.firstIndex(where: { $0.name == name }) else { return }
        var all = rows
        let r = all.remove(at: i)
        all.insert(r, at: 0)
        withAnimation { rows = Self.pinFixed(original: rows, moved: all) }
    }

    /// Puts the non-movable rows back at their original indexes; the movable ones fill the rest in moved order.
    static func pinFixed(original: [Row], moved: [Row]) -> [Row] {
        var mov = moved.filter(\.movable).makeIterator()
        return original.map { $0.movable ? (mov.next() ?? $0) : $0 }
    }

    private func save() async {
        guard let p = profile else { return }
        saving = true
        defer { saving = false }
        let names = rows.map(\.name)
        let r = await GroupOrder.save(names, profile: p)
        guard r.saved else { message = r.message; return }
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onSaved?(names)
        if let m = r.message {
            // Written, but the reload failed: stay and say so.
            message = m
            original = names
            return
        }
        dismiss()
    }
}
