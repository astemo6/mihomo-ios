import SwiftUI
import UniformTypeIdentifiers

// feat/long-press-reorder (user 2026-10-29 「正常情况下没法直接按住拖动吗」): long-press drag reorder for the
// lists that until now only reordered after tapping 排序 (edit mode): 重写 → 订阅 / 本地规则 / 本地脚本,
// 分流规则 → 订阅 (我添加的 + 配置里的规则集) / 本地规则 → 自定义, and the 节点列表 (per source section).
// The transport is the one Home (HomeReorderDrag) and 策略组 (OptionalDrag + GroupDropDelegate) already ship:
// .onDrag with an NSString provider, a per-row GroupDropDelegate, and a section-level GroupListDropDelegate.
// The dragged list is rearranged in a working copy while the finger moves and committed ONCE at the drop —
// the stores' save() reloads the core, so saving on every hover step (what edit-mode .onMove does) would
// reload repeatedly during a single drag. A session that ends without landing on a target commits through
// the same idle timer Home uses (scheduleCommit): 1.5 s after the last hover, so no stale copy can linger.

@MainActor
final class DragReorderState<Item: Identifiable>: ObservableObject where Item.ID == String {
    @Published private(set) var working: [Item]?
    private(set) var draggingID: String?
    /// Which list the working copy belongs to (the 节点列表 renders one list per source section through a
    /// single state; other pages pass nil). shown() only substitutes the copy for its own list.
    private var workingKey: String?
    private var commit: (([Item]) -> Void)?
    private var idleTask: Task<Void, Never>?

    /// The list to render: the working copy while a drag is live in this list, else the store's list.
    func shown(_ items: [Item], key: String? = nil) -> [Item] {
        working != nil && workingKey == key ? working! : items
    }

    func begin(_ id: String, from items: [Item], key: String? = nil, commit: @escaping ([Item]) -> Void) {
        idleTask?.cancel()
        draggingID = id
        working = items
        workingKey = key
        self.commit = commit
    }

    func hover(_ target: String) {
        guard let d = draggingID, d != target, var w = working,
              let from = w.firstIndex(where: { $0.id == d }),
              let to = w.firstIndex(where: { $0.id == target }) else { return }
        withAnimation(.easeInOut(duration: 0.15)) {
            w.move(fromOffsets: IndexSet(integer: from), toOffset: to > from ? to + 1 : to)
            working = w
        }
        idleTask?.cancel()
        idleTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard !Task.isCancelled else { return }
            self?.finish()
        }
    }

    func finish() {
        idleTask?.cancel()
        idleTask = nil
        if let w = working, let commit { commit(w) }
        working = nil
        workingKey = nil
        draggingID = nil
        commit = nil
    }
}

/// One row of a long-press-reorderable list: drag source + drop target + the dragged row dimmed (Home's cue).
/// `start` captures the list as it stands when the drag begins, plus how the new order is saved.
struct LongPressReorderRow<Item: Identifiable>: ViewModifier where Item.ID == String {
    let item: Item
    @ObservedObject var state: DragReorderState<Item>
    let enabled: Bool
    let start: () -> Void

    func body(content: Content) -> some View {
        content
            .opacity(state.draggingID == item.id ? 0.45 : 1)
            .modifier(OptionalDrag(provider: enabled ? {
                start()
                return NSItemProvider(object: item.id as NSString)
            } : nil))
            .onDrop(of: [UTType.text], delegate: GroupDropDelegate(target: item.id,
                        enter: { state.hover($0) }, drop: { state.finish() }))
    }
}
