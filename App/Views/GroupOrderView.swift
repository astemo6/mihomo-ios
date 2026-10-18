import SwiftUI
import UniformTypeIdentifiers

// feat/group-order: reordering 策略组 on the policy page, two ways (user 14:19 「两个都要」):
// 1. 编辑排序 above the group list switches the page into a reorder list (drag handles, 置顶) with 取消 / 完成;
// 2. in the normal list, long-press a group's header and drag it onto another group.
// Both save through GroupOrder.save (written into the profile file, core reloaded when connected).

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

    @State private var keepsOrder = false

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
                    Text("拖动或置顶来调整顺序。保存后写入配置文件，注释和其他内容保持不变，原文件备份为 .bak。")
                    if rows.contains(where: { !$0.movable }) {
                        Text("标有「运行时加入」的策略组不在配置文件中，位置保持不变。")
                    }
                    if profile?.kind == .remote {
                        Text("这是订阅配置：顺序也会单独保存，每次更新订阅后自动重新排列。")
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
