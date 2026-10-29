import SwiftUI
import UniformTypeIdentifiers

// Long-press drag reorder for the lists that used to reorder only in edit mode (排序):
// 重写 subscriptions / local rules / local scripts, 分流规则 subscriptions and rule sets,
// 本地规则 custom rules, and the 节点列表 (user 2026-10-29: 「正常情况下没法直接按住拖动吗」).
//
// The transport is the one Home's cards already ship (HomeReorderDrag / HomeReorderDrop),
// including its hard-won lesson (rel 0.20.2, CI 40566844130 test96): per-row drop delegates
// in a List never see the drag — the rows regroup as the working copy moves, the delegates
// are rebuilt, the session enters none of them and the order stays put (and a session that
// ends without a drop leaves the row stuck dimmed). So: rows only START the drag (.onDrag)
// and report their frames; ONE section-wide drop target maps the finger's location to the
// row under it through those frames.
//
// While a session is live the list renders a working copy; hovering another row moves the
// dragged row into its place in the copy. Nothing is saved per hover step — the stores'
// save() reloads the core, so the order commits exactly once, at the drop, or from the
// idle timer when a session ends without one (finger lifted outside the section, or held
// still). A session can never be orphaned: the timer is armed at begin() too.

/// The type-erased session the section-wide drop target forwards to (a section can host
/// two drag domains of different item types, e.g. 分流规则's own lists + the profile's sets).
@MainActor
protocol DragReorderSession: AnyObject {
    var isActive: Bool { get }
    func absorb(_ frames: [String: CGRect])
    func update(location: CGPoint)
    func finish()
    func exit()
}

@MainActor
final class DragReorderState<Item: Identifiable>: ObservableObject, DragReorderSession where Item.ID == String {
    /// The named coordinate space the owning section anchors (rows measure their frames in
    /// it; states that share a section share the name — same anchor, same coordinates).
    let space: String
    @Published private(set) var working: [Item]?
    private(set) var draggingID: String?
    private var frames: [String: CGRect] = [:]
    private var commit: (([Item]) -> Void)?
    private var idleTask: Task<Void, Never>?

    init(space: String) { self.space = space }

    var isActive: Bool { working != nil }

    /// The list to render: the working copy while a drag is live in this list, else the
    /// store's list. `key` separates the lists that share one state (the 节点列表 renders
    /// one list per source section through a single state).
    func shown(_ items: [Item], key: String? = nil) -> [Item] {
        working != nil && workingKey == key ? working! : items
    }
    private var workingKey: String?

    func begin(_ id: String, from items: [Item], key: String? = nil, commit: @escaping ([Item]) -> Void) {
        draggingID = id
        working = items
        workingKey = key
        self.commit = commit
        armIdle(1.5)
    }

    func absorb(_ new: [String: CGRect]) { frames.merge(new) { $1 } }

    /// The finger moved (section coordinates): if it is over another row of the working
    /// copy, move the dragged row into that row's place.
    func update(location: CGPoint) {
        guard let w = working, let drag = draggingID,
              let from = w.firstIndex(where: { $0.id == drag }) else { return }
        // Only the working copy's own rows are candidates — frames of other sections that
        // share the state were measured in their own section's origin and must not match.
        let target = w.first { frames[$0.id]?.contains(location) == true }
        guard let t = target, t.id != drag, let to = w.firstIndex(where: { $0.id == t.id }) else {
            armIdle(1.5)
            return
        }
        withAnimation(.easeInOut(duration: 0.15)) { working = moved(w, from: from, to: to) }
        armIdle(1.5)
    }

    private func moved(_ w: [Item], from: Int, to: Int) -> [Item] {
        var w = w
        let it = w.remove(at: from)
        w.insert(it, at: to)
        return w
    }

    /// The drop landed: commit the working copy exactly once.
    func finish() {
        idleTask?.cancel()
        if let w = working, let commit { commit(w) }
        working = nil
        workingKey = nil
        draggingID = nil
        commit = nil
    }

    /// The finger left the section without dropping: commit what the hovers produced
    /// shortly after (Home's exit path), so the session cannot hang.
    func exit() { armIdle(0.6) }

    private func armIdle(_ seconds: Double) {
        idleTask?.cancel()
        idleTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.finish()
        }
    }
}

/// Row side of the transport: drag source + frame reporting + the dragged row's dimming.
/// The caller passes its begin() in `start` (it knows the store's list and how to commit).
struct LongPressReorderRow<Item: Identifiable>: ViewModifier where Item.ID == String {
    let item: Item
    @ObservedObject var state: DragReorderState<Item>
    let enabled: Bool
    let start: () -> Void

    func body(content: Content) -> some View {
        content
            .opacity(state.draggingID == item.id ? 0.45 : 1)
            .background(GeometryReader { g in
                Color.clear.preference(key: DragReorderFrameKey.self,
                                       value: [item.id: g.frame(in: .named(state.space))])
            })
            .modifier(OptionalDrag(provider: enabled ? {
                start()
                return NSItemProvider(object: item.id as NSString)
            } : nil))
    }
}

/// Row frames in the section's coordinate space, keyed by item id.
struct DragReorderFrameKey: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue()) { $1 }
    }
}

/// Section-wide drop target (HomeReorderDrop's shape): forwards the finger's location to
/// whichever session is live; the drop commits it, leaving the section schedules the commit.
struct DragReorderDropDelegate: DropDelegate {
    let sessions: [any DragReorderSession]
    private var active: (any DragReorderSession)? { sessions.first { $0.isActive } }
    func validateDrop(info: DropInfo) -> Bool { active != nil }
    func dropEntered(info: DropInfo) { active?.update(location: info.location) }
    func dropUpdated(info: DropInfo) -> DropProposal? {
        active?.update(location: info.location)
        return DropProposal(operation: .move)
    }
    func dropExited(info: DropInfo) { active?.exit() }
    func performDrop(info: DropInfo) -> Bool { active?.finish(); return true }
}

struct DragReorderTarget: ViewModifier {
    let sessions: [any DragReorderSession]
    let space: String
    func body(content: Content) -> some View {
        content
            .coordinateSpace(name: space)
            .onPreferenceChange(DragReorderFrameKey.self) { frames in
                for s in sessions { s.absorb(frames) }
            }
            .onDrop(of: [UTType.text], delegate: DragReorderDropDelegate(sessions: sessions))
    }
}

extension View {
    /// Attach the section-wide drop target for the given drag sessions (anchored in `space`).
    func dragReorderTarget(_ sessions: [any DragReorderSession], space: String) -> some View {
        modifier(DragReorderTarget(sessions: sessions, space: space))
    }
}
