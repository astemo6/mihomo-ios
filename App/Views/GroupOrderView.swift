import SwiftUI
import UniformTypeIdentifiers

// feat/group-order: reordering 策略组 on the policy page, two ways (user 14:19 「两个都要」):
// 1. 编辑排序 above the group list switches the page into a reorder list (drag handles, 置顶) with 取消 / 完成;
// 2. in the normal list, long-press a group's header and drag it onto another group.
// Both save through GroupOrder.save: the first reorder of a profile writes into an 自定义 copy and switches to it
// (the original file is never rewritten); later reorders change the copy. Core reloaded when connected.

struct GroupOrderRow: Identifiable, Equatable {
    var id: String { name }
    let name: String
    let kind: String
    let icon: String?
    /// false = not in the profile file (added at runtime), keeps its place.
    let movable: Bool

    /// Display names of the active profile's file groups (after 策略组编辑 renames).
    @MainActor static func movableNames(_ p: Profile?) -> Set<String> {
        guard let p else { return [] }
        let edits = GroupEditStore.get(p.id)
        return Set(GroupOrder.fileNames(p).map { GroupOrder.displayName(of: $0, edits: edits) })
    }

    /// Puts the non-movable rows back at their original indexes; the movable ones fill the rest in moved order.
    static func pinFixed(original: [GroupOrderRow], moved: [GroupOrderRow]) -> [GroupOrderRow] {
        var mov = moved.filter(\.movable).makeIterator()
        return original.map { $0.movable ? (mov.next() ?? $0) : $0 }
    }

    /// `items` in `order` (names); items not in `order` keep their slot.
    static func arranged<T>(_ items: [T], by order: [String]?, name: (T) -> String) -> [T] {
        guard let order else { return items }
        let rank = Dictionary(order.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let listed = items.filter { rank[name($0)] != nil }.sorted { rank[name($0)]! < rank[name($1)]! }
        var it = listed.makeIterator()
        return items.map { rank[name($0)] != nil ? (it.next() ?? $0) : $0 }
    }
}

/// The reorder list shown in place of the cards while 编辑排序 is on.
struct GroupReorderList: View {
    @Binding var rows: [GroupOrderRow]
    let profile: Profile?
    var message: String?
    /// Called after 不再保持此顺序 rebuilt the copy (the page leaves reorder mode and re-reads the groups).
    var onCleared: (() -> Void)? = nil

    @State private var keepsOrder = false

    private var sourceIsRemote: Bool {
        guard let p = profile else { return false }
        return ProfileStore.shared.source(of: p)?.kind == .remote
    }

    private func sourceName(_ p: Profile) -> String {
        ProfileStore.shared.source(of: p)?.displayName ?? p.sourceName ?? ""
    }

    var body: some View {
        List {
            Section {
                ForEach(rows) { r in row(r).moveDisabled(!r.movable) }
                    .onMove { from, to in
                        var all = rows
                        all.move(fromOffsets: from, toOffset: to)
                        rows = GroupOrderRow.pinFixed(original: rows, moved: all)
                    }
                    .deleteDisabled(true)
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("拖动或置顶来调整顺序。")
                    if let p = profile, p.sourceID == nil {
                        Text("原配置不会被修改：首次保存时会自动复制出「\(GroupOrder.copyName(of: p))」，新顺序写入副本并切换到它。")
                    } else if let p = profile {
                        Text("这是「\(sourceName(p))」的副本，新顺序只写入这个副本（注释和其他内容不变，上一版备份为 .bak）。")
                        if sourceIsRemote {
                            Text("订阅更新时，副本会用订阅的新内容重新生成，并保持此顺序；新增的策略组保留订阅中的位置。")
                        }
                    }
                    if rows.contains(where: { !$0.movable }) {
                        Text("标有「运行时加入」的策略组不在配置文件中，位置保持不变。")
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

            if sourceIsRemote && keepsOrder {
                Section {
                    Button("不再保持此顺序") {
                        keepsOrder = false
                        if let p = profile { Task { _ = await GroupOrder.clearStoredOrder(p); onCleared?() } }
                    }
                    .accessibilityIdentifier("grouporder.clear")
                } footer: {
                    Text("副本立即恢复为订阅自带的顺序，之后的订阅更新也不再重新排列。")
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .environment(\.editMode, .constant(.active))
        .onAppear { if let p = profile { keepsOrder = GroupOrder.hasStoredOrder(p) } }
    }

    @ViewBuilder
    func row(_ r: GroupOrderRow) -> some View {
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
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
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

    private func toTop(_ name: String) {
        guard let i = rows.firstIndex(where: { $0.name == name }) else { return }
        var all = rows
        let r = all.remove(at: i)
        all.insert(r, at: 0)
        withAnimation { rows = GroupOrderRow.pinFixed(original: rows, moved: all) }
    }
}

/// Direct drag in the normal list: a card is a drop target; entering it moves the dragged group there, the drop
/// saves.
struct GroupDropDelegate: DropDelegate {
    let target: String
    let enter: (String) -> Void
    let drop: () -> Void

    func dropEntered(info: DropInfo) { enter(target) }
    func dropUpdated(info: DropInfo) -> DropProposal? { DropProposal(operation: .move) }
    func performDrop(info: DropInfo) -> Bool { drop(); return true }
}

/// Drops that land between cards (the list background) finish the drag too.
struct GroupListDropDelegate: DropDelegate {
    let drop: () -> Void
    func dropUpdated(info: DropInfo) -> DropProposal? { DropProposal(operation: .move) }
    func performDrop(info: DropInfo) -> Bool { drop(); return true }
}
