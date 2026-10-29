import SwiftUI
import UniformTypeIdentifiers

// feat/panels: script panels on Home.
// - Order = PanelsModel.pinned ("panels.pinned"); every pinned id is shown (feat/fresh-reinstall: 「在首页隐藏」 removed,
//   「从首页移除」 unpins). Long-press-and-drag a card on Home to reorder (HomeReorderDrop); 编辑排序 stays as the fallback.
// - QX / Surge generic and interaction scripts can be pinned too: the engine turns each into a panel
//   with the id "task-<task id>" (home-panels.json / PUT /mitm/panels-home).
// - While disconnected, Home shows the last result of each panel from panel-cache.json (written by the
//   engine after every run) with its time.

/// One card on Home: the panel and whether it is live (connected) or the last cached result.
struct HomePanelEntry: Identifiable {
    var item: PanelItem
    var live: Bool
    var id: String { item.id }
}

/// A generic / interaction script pinned to Home as a panel.
struct TaskPanelPin: Codable, Hashable {
    var id: String          // task id
    var name: String
    var kind: String        // generic / interaction
    var interval: Int       // seconds, 0 = when Home opens / manual
    var params: String?     // interaction: the node passed as $environment.params
    var format: String?
    var panelID: String { HomePanelStore.taskPrefix + id }
}

@MainActor
final class HomePanelStore: ObservableObject {
    static let shared = HomePanelStore()
    static let taskPrefix = "task-"
    /// The retired 「在首页隐藏」 set; read once by `dropLegacyHidden` (its ids are unpinned), then deleted.
    static let legacyHiddenKey = "panels.home.hidden"
    private static let tasksKey = "panels.home.tasks"
    private static let namesKey = "panels.home.names"

    @Published var tasks: [TaskPanelPin] = {
        guard let d = AppShared.defaults.data(forKey: HomePanelStore.tasksKey) else { return [] }
        return (try? JSONDecoder().decode([TaskPanelPin].self, from: d)) ?? []
    }()
    /// Last results written by the engine (panel-cache.json), keyed by panel id.
    @Published var cached: [String: PanelItem] = [:]
    /// r7 (test67 en): bumped one main-queue turn after every reorder. The editor's 首页面板 section is keyed on it, so
    /// the List is rebuilt from `PanelsModel.pinned` once UIKit has finished its own row move. Without it a drag could
    /// save the new order (menu showed 上移 disabled on the new first row) while the table kept drawing the old order.
    @Published private(set) var orderRevision = 0
    /// Panel names seen while connected, so the editor can name pinned panels while disconnected.
    private var names: [String: String] = (AppShared.defaults.dictionary(forKey: HomePanelStore.namesKey) as? [String: String]) ?? [:]

    private var model: PanelsModel { PanelsModel.shared }
    static var homeURL: URL { EnginePaths.dir.appendingPathComponent("home-panels.json") }
    static var cacheURL: URL { EnginePaths.dir.appendingPathComponent("panel-cache.json") }

    var visibleIDs: [String] { model.pinned }

    /// feat/fresh-reinstall: 「在首页隐藏」 is gone. Ids that were hidden are unpinned (they were not on Home anyway) and
    /// the hidden key is removed from both stores. TernApp.init, after DefaultsMigration, before PanelsModel loads.
    /// Returns the unpinned ids.
    @discardableResult
    static func dropLegacyHidden(group: UserDefaults = AppShared.defaults, standard: UserDefaults = .standard) -> [String] {
        let hidden = Set((group.stringArray(forKey: legacyHiddenKey) ?? []) + (standard.stringArray(forKey: legacyHiddenKey) ?? []))
        if group.object(forKey: legacyHiddenKey) != nil { group.removeObject(forKey: legacyHiddenKey) }
        if standard.object(forKey: legacyHiddenKey) != nil { standard.removeObject(forKey: legacyHiddenKey) }
        guard !hidden.isEmpty, var pinned = group.stringArray(forKey: "panels.pinned") else { return [] }
        let removed = pinned.filter { hidden.contains($0) }
        guard !removed.isEmpty else { return [] }
        pinned.removeAll { hidden.contains($0) }
        group.set(pinned, forKey: "panels.pinned")
        return removed
    }

    // MARK: drag reorder on Home

    /// The id being dragged on Home (nil when no drag is in flight).
    @Published var dragging: String?
    private var commitWork: DispatchWorkItem?
    /// Last time a Home drag actually MOVED (hover travel / a reorder), and whether the current session has
    /// moved at all. A long-press that turns into a drag can end with the finger over the context menu, which
    /// would pick 「从首页移除」; the menu's remove ignores taps during / right after such a drag. But the
    /// context menu's OWN long press also starts a drag session (onDrag fires beginDrag), so the guard must
    /// key on movement, not on the session: a stationary press never moves, and stamping it poisoned the
    /// menu's remove for seconds (device 2026-10-29: long-press → 从首页移除 did nothing, repeatedly).
    private var lastDragActivity = Date.distantPast
    private var dragMoved = false

    /// Card frames in the Home section's coordinate space (not published: read only while dragging).
    var cardFrames: [String: CGRect] = [:]
    /// The card the last live move was made over; hovering it again does nothing (after a move the rows regroup and
    /// the same or the dragged card can slide under a still finger, which must not swap them back).
    private var lastHoverTarget: String?
    private var lastMoveAt = Date.distantPast
    /// The card the current drag session carries. Outlives `dragging` (the dimming): a session can end without
    /// performDrop / dropExited (cancelled drags, XCUITest's synthesized drags), so the order is also saved and the
    /// card un-dimmed once the finger has been still for a moment; moving again keeps reordering.
    private var dragID: String?

    /// Last finger location the section drop target reported. UIKit keeps calling dropSessionDidUpdate while the finger
    /// rests (and, in the simulator, after XCUITest lifts it while the session winds down); those calls carry the same
    /// point and must neither re-dim the card nor push the save back, or the card stays dimmed, the order is never
    /// saved, the app never idles and the next long-press opens no menu (rel 0.20.2 CI 40601214518 test96).
    private var lastHoverPoint: CGPoint?

    func beginDrag(_ id: String) {
        lastHoverTarget = nil
        lastHoverPoint = nil
        dragMoved = false
        dragID = id
        dragging = id
        scheduleCommit(after: 2.0) // a drag that never reaches Home does not leave the card dimmed
    }

    /// The drop landed: save and end the session.
    func endDrag() {
        commitDrag()
        dragID = nil
        lastHoverTarget = nil
        lastHoverPoint = nil
    }

    /// Section drop target moved to `p`: move the dragged card into the place of the card under the finger.
    func dragHover(at p: CGPoint) {
        guard let d = dragID else { return }
        if let q = lastHoverPoint, abs(q.x - p.x) < 3, abs(q.y - p.y) < 3 { return } // finger still: let the save run
        // Real travel only (a previous point exists and differs): the first hover of a stationary long
        // press — the context menu's — must not count as drag activity (see lastDragActivity).
        if lastHoverPoint != nil { dragMoved = true; lastDragActivity = Date() }
        lastHoverPoint = p
        if dragging != d { dragging = d }
        // Saved at the drop, on leaving Home, or 1 s after the finger stopped moving (session ended unseen).
        defer { scheduleCommit(after: 1.0) }
        guard let target = cardFrames.first(where: { $0.value.contains(p) })?.key else { return }
        if target == d {
            // Back over the dragged card itself (not right after a move): a later hover on the same card moves again.
            if Date().timeIntervalSince(lastMoveAt) > 0.35 { lastHoverTarget = nil }
            return
        }
        guard target != lastHoverTarget else { return }
        lastHoverTarget = target
        lastMoveAt = Date()
        dragMove(d, over: target)
    }

    /// Live reorder while a dragged card hovers `target`: the dragged id takes the target's place in the pinned order.
    /// Saved shortly after the last move (and at the drop), so hovering over many cards writes once.
    func dragMove(_ id: String, over target: String) {
        guard id != target, let from = model.pinned.firstIndex(of: id), let to = model.pinned.firstIndex(of: target) else { return }
        dragMoved = true
        lastDragActivity = Date()
        withAnimation(.easeInOut(duration: 0.2)) {
            model.pinned.move(fromOffsets: IndexSet(integer: from), toOffset: to > from ? to + 1 : to)
        }
        scheduleCommit()
    }

    func scheduleCommit(after delay: Double = 0.6) {
        commitWork?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.commitDrag() }
        commitWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: w)
    }

    func commitDrag() {
        commitWork?.cancel()
        commitWork = nil
        dragging = nil
        dragMoved = false // the session is over; the lastDragActivity window guards the just-ended drag
        savePinned()
        orderChanged()
    }

    func loadCache() {
        guard let d = try? Data(contentsOf: Self.cacheURL), let l = try? JSONDecoder().decode([PanelItem].self, from: d) else { return }
        cached = Dictionary(l.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
    }

    /// The panel to show for an id: live while connected, else the last cached result.
    func item(_ id: String, connected: Bool) -> HomePanelEntry? {
        if connected, let p = model.panels.first(where: { $0.id == id }) { return HomePanelEntry(item: p, live: true) }
        if var c = cached[id] {
            c.running = false
            return HomePanelEntry(item: c, live: false)
        }
        if let t = tasks.first(where: { $0.panelID == id }) {
            return HomePanelEntry(item: PanelItem(id: id, name: t.name, title: t.name, content: nil, style: nil, icon: t.kind == "interaction" ? "hand.tap" : "play.rectangle",
                              iconColor: nil, script: t.name, interval: t.interval, source: "", format: t.format ?? "surge", updated: nil, error: nil, running: false), live: false)
        }
        return nil
    }

    func name(_ id: String) -> String? {
        if let t = PanelOverrideStore.shared.map[id]?.title, !t.isEmpty { return t }
        return model.panels.first(where: { $0.id == id }).map { $0.title?.isEmpty == false ? $0.title! : $0.name }
            ?? cached[id].map { $0.title?.isEmpty == false ? $0.title! : $0.name }
            ?? tasks.first(where: { $0.panelID == id })?.name
            ?? names[id]
    }

    func rememberNames() {
        var changed = false
        for p in model.panels where model.pinned.contains(p.id) && names[p.id] != p.name {
            names[p.id] = p.name
            changed = true
        }
        if changed { AppShared.defaults.set(names, forKey: Self.namesKey) }
    }

    // MARK: editing

    func isTaskPinned(_ taskID: String) -> Bool { model.pinned.contains(Self.taskPrefix + taskID) }

    func pinTask(_ t: ScriptTaskState, params: String?) {
        let pin = TaskPanelPin(id: t.id, name: t.script.name, kind: t.kind, interval: 0, params: t.kind == "interaction" ? params : nil, format: t.format)
        tasks.removeAll { $0.id == t.id }
        tasks.append(pin)
        if !model.pinned.contains(pin.panelID) { model.pinned.append(pin.panelID) }
        savePinned()
    }

    /// v0.19 首页卡片: built-in tiles live in the same pinned list.
    func pinBuiltin(_ t: BuiltinTile) {
        if !model.pinned.contains(t.id) { model.pinned.append(t.id) }
        savePinned()
    }

    func unpin(_ id: String) {
        model.pinned.removeAll { $0 == id }
        savePinned()
    }

    /// 「从首页移除」 from a Home card's long-press menu: ignored while a drag that actually moved is in
    /// flight or within 1 s of one, so a press-and-drag that ends over the menu never removes the card.
    /// A stationary long press — the menu's own gesture — never moves, so its remove works at once.
    func unpinFromMenu(_ id: String) {
        guard canRemoveFromMenu else { return }
        unpin(id)
    }

    var canRemoveFromMenu: Bool {
        Self.removeAllowed(dragging: dragging != nil, dragMoved: dragMoved,
                           secondsSinceDragActivity: Date().timeIntervalSince(lastDragActivity))
    }

    /// The menu-remove guard, pure for tests: a moved drag blocks (in flight, or ≤ 1 s after it ended);
    /// an unmoved drag session — every context-menu long press starts one — never does.
    static func removeAllowed(dragging: Bool, dragMoved: Bool, secondsSinceDragActivity: TimeInterval) -> Bool {
        if dragging && dragMoved { return false }
        return secondsSinceDragActivity > 1.0
    }

    func move(from: IndexSet, to: Int) {
        model.pinned.move(fromOffsets: from, toOffset: to)
        savePinned()
        orderChanged()
    }

    /// The saved order as one string (UI-test accessibility value on the editor; Debug builds only).
    var orderToken: String { model.pinned.joined(separator: ",") }

    private func orderChanged() {
        DispatchQueue.main.async { self.orderRevision &+= 1 }
    }

    /// r7: non-drag reorder (editor ⋯ menu / VoiceOver actions). `by` = -1 up, +1 down.
    func canMove(_ id: String, by: Int) -> Bool {
        guard let i = model.pinned.firstIndex(of: id) else { return false }
        return model.pinned.indices.contains(i + by)
    }

    func step(_ id: String, by: Int) {
        guard let i = model.pinned.firstIndex(of: id), model.pinned.indices.contains(i + by) else { return }
        model.pinned.swapAt(i, i + by)
        savePinned()
        orderChanged()
    }

    func setInterval(_ taskID: String, _ seconds: Int) {
        guard let i = tasks.firstIndex(where: { $0.id == taskID }) else { return }
        tasks[i].interval = seconds
        sync()
    }

    private func savePinned() {
        AppShared.defaults.set(model.pinned, forKey: "panels.pinned")
        sync()
    }

    /// Saves the Home configuration (UserDefaults + home-panels.json for the next connect) and, while
    /// connected, hands it to the running engine.
    func sync() {
        // drop task pins that are no longer pinned
        // r7: assign only on a real change — a no-op publish here landed in the same update as the List's onMove.
        if tasks.contains(where: { !model.pinned.contains($0.panelID) }) { tasks.removeAll { !model.pinned.contains($0.panelID) } }
        if let d = try? JSONEncoder().encode(tasks) { AppShared.defaults.set(d, forKey: Self.tasksKey) }
        let body: [String: Any] = [
            "visible": visibleIDs.filter { !BuiltinTile.isBuiltin($0) }, // v0.19 tiles are app-drawn
            "tasks": tasks.map { t -> [String: Any] in
                var m: [String: Any] = ["id": t.id, "interval": t.interval]
                if let p = t.params { m["params"] = p }
                return m
            },
            "intervals": PanelOverrideStore.shared.intervals, // v0.17 磁贴编辑
        ]
        if let d = try? JSONSerialization.data(withJSONObject: body) { try? d.write(to: Self.homeURL, options: .atomic) }
        guard VPNManager.shared.isConnected else { return }
        Task {
            if let d = try? await ControllerClient.shared.send("/mitm/panels-home", method: "PUT", body: body),
               let l = try? JSONDecoder().decode([PanelItem].self, from: d) {
                PanelsModel.shared.panels = l
            }
        }
    }

    /// Runs visible script panels that never ran or whose interval (at least 60 s; 0 = once per minute
    /// at most, when Home opens) has passed.
    func refreshStaleVisible() async {
        let now = Date().timeIntervalSince1970
        let due = visibleIDs.filter { !BuiltinTile.isBuiltin($0) }.compactMap { id in model.panels.first { $0.id == id } }.filter { p in
            guard p.script != nil, !p.running else { return false }
            let every = Double(max(p.interval ?? 0, 60))
            return (p.updated ?? 0) == 0 || now - (p.updated ?? 0) > every
        }
        await withTaskGroup(of: Void.self) { g in
            for p in due { g.addTask { await PanelsModel.shared.refresh(p) } }
        }
    }
}

// MARK: - Home section

struct HomePanelsSection: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject var model = PanelsModel.shared
    @ObservedObject var home = HomePanelStore.shared
    @ObservedObject var overrides = PanelOverrideStore.shared
    @State private var editPanel: PanelItem?
    /// rel 0.20.2: 「从首页移除」 in the long-press menu asks first. A press-and-drag whose drag never starts (finger
    /// slides over the menu instead, e.g. dragging a low card upward through a menu shown above it) ends on a menu
    /// item; removing at once lost the card (CI 40593917038 en test96).
    @State private var confirmRemove: String?

    var body: some View {
        let items = home.visibleIDs.compactMap { home.item($0, connected: vpn.isConnected) }
        let rows = HomeRow.rows(home.visibleIDs, panel: { home.item($0, connected: vpn.isConnected) }, half: { overrides.isHalf($0) })
        VStack(spacing: 10) {
            if !model.pinned.isEmpty {
                HStack {
                    Text("面板").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
                    if !vpn.isConnected && !items.isEmpty {
                        Text("上次结果").font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("编辑") { HomeEditorRouter.shared.open(.panels) }.font(.footnote).buttonStyle(.borderless)
                }
                .padding(.horizontal, 4)
                .padding(.bottom, -6)
            }
            ForEach(rows) { row in
                switch row {
                case .single(let c):
                    cell(c)
                case .pair(let a, let b):
                    HStack(alignment: .top, spacing: 12) {
                        cell(a)
                        if let b { cell(b) } else { Color.clear.frame(maxWidth: .infinity) }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            if UITestSeed.enabled { // Debug UI tests only: the saved order, for the drag-reorder test
                Text(verbatim: home.orderToken).font(.system(size: 1)).opacity(0.02).frame(height: 1)
                    .accessibilityIdentifier("home.panels.order").accessibilityValue(Text(verbatim: home.orderToken))
            }
            // feat/egern-style: always offered — the analysis panels (策略 / 规则 / 主机名) are opt-in and added here.
            Group {
                Button { HomeEditorRouter.shared.open(.panels) } label: {
                    Label("添加首页卡片", systemImage: "plus.circle")
                        .font(.footnote.weight(.semibold))
                }
                .buttonStyle(.borderless)
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier("home.addTiles")
            }
            if vpn.isConnected && !model.panels.isEmpty {
                NavigationLink { PanelsView() } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "square.grid.2x2").foregroundStyle(Theme.accent)
                        Text("全部面板").font(.subheadline.weight(.semibold))
                        Text("\(model.panels.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                }
                .buttonStyle(.plain)
            }
        }
        // A drop anywhere in the section (between cards, on the header) ends the drag and saves the order.
        .onPreferenceChange(HomeCardFrameKey.self) { home.cardFrames = $0 }
        .onDrop(of: [UTType.text], delegate: HomeReorderDrop(
            update: { home.dragHover(at: $0) },
            exit: { if home.dragging != nil { home.scheduleCommit() } },
            drop: { home.endDrag() }))
        .coordinateSpace(name: HomeReorderDrag.space)
        .sheet(item: $editPanel) { p in PanelEditSheet(p: p) }
        .confirmationDialog(Text("从首页移除"), isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } }),
                            titleVisibility: .hidden) {
            Button(role: .destructive) {
                if let id = confirmRemove { home.unpin(id) }
                confirmRemove = nil
            } label: { Label("从首页移除", systemImage: "minus.circle") }
            Button("取消", role: .cancel) { confirmRemove = nil }
        }
        .task(id: vpn.isConnected) {
            home.loadCache()
            guard vpn.isConnected else { if !model.demo { model.panels = [] }; return }
            home.sync()
            await model.load()
            home.rememberNames()
            await home.refreshStaleVisible()
            // While Home is visible: pick up results (the engine also refreshes Home panels on their
            // interval in the background while connected).
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                if Task.isCancelled || !vpn.isConnected { break }
                if home.visibleIDs.isEmpty { continue }
                await model.load()
                await home.refreshStaleVisible()
            }
        }
    }
}

extension HomePanelsSection {
    @ViewBuilder
    func cell(_ c: HomeCell) -> some View {
        switch c {
        case .panel(let e):
            PanelCard(p: e.item, refreshing: e.live && (model.refreshing.contains(e.item.id) || e.item.running), offline: !e.live,
                      refreshFailure: e.live ? model.failure(for: e.item) : nil) {
                Task { await model.refresh(e.item) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .contextMenu {
                arrangeItems(e.item.id)
                Button { HomeEditorRouter.shared.open(.panels) } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                PanelEditButton { editPanel = e.item }
                Button(role: .destructive) { if home.canRemoveFromMenu { confirmRemove = e.item.id } } label: { Label("从首页移除", systemImage: "minus.circle") }
            }
            .modifier(HomeReorderDrag(id: e.item.id))
        case .tile(let t):
            tile(t)
        }
    }

    func tile(_ t: BuiltinTile) -> some View {
        BuiltinTileView(tile: t)
            .contextMenu {
                arrangeItems(t.id)
                Button { HomeEditorRouter.shared.open(.panels) } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                Button(role: .destructive) { if home.canRemoveFromMenu { confirmRemove = t.id } } label: { Label("从首页移除", systemImage: "minus.circle") }
            }
            .modifier(HomeReorderDrag(id: t.id))
    }

    /// fix/app-policy-ui #6 / #6a (user 2026-10-26 21:30 / 21:33): long-press on Home → 编辑排序 (the editor's drag /
    /// 上移下移 list — kept, this is one more way in) and 半宽 / 全宽 (two half-width cards share a row).
    @ViewBuilder
    func arrangeItems(_ id: String) -> some View {
        Button { HomeEditorRouter.shared.open(.panels) } label: { Label("编辑排序", systemImage: "line.3.horizontal") }
        if overrides.isHalf(id) {
            Button { withAnimation { overrides.setHalf(false, for: id) } } label: { Label("全宽显示", systemImage: "rectangle") }
        } else {
            Button { withAnimation { overrides.setHalf(true, for: id) } } label: { Label("半宽显示", systemImage: "rectangle.split.2x1") }
        }
        Divider()
    }
}

// MARK: - Home editing

struct HomePanelsEditor: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model = PanelsModel.shared
    @ObservedObject var home = HomePanelStore.shared
    @ObservedObject var overrides = PanelOverrideStore.shared

    static var intervals: [(Int, LocalizedStringKey)] { [(0, "打开首页时"), (300, "每 5 分钟"), (900, "每 15 分钟"), (1800, "每 30 分钟"), (3600, "每小时")] }
    /// v0.19.8: the list is always in edit mode (drag handles), which disables NavigationLink rows (device report:
    /// 「全部面板」/「脚本任务」 grey and dead). Buttons stay tappable; they push through navigationDestination.
    @State private var showPanels = false
    @State private var showScriptTasks = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if model.pinned.isEmpty {
                        EmptyStateRow(icon: "pin", title: "还没有固定的面板", message: "从下面的「内置卡片」添加，或在「面板」页长按面板、在脚本任务详情里点「固定到首页」。")
                    }
                    ForEach(model.pinned, id: \.self) { id in row(id) }
                        .onMove { home.move(from: $0, to: $1) }
                        .onDelete { s in s.map { model.pinned[$0] }.forEach(home.unpin) }
                } header: {
                    Text("首页面板")
                } footer: {
                    Text("拖动或用右侧菜单调整顺序、切换半宽（两张半宽卡片并排），左滑可从首页移除。在首页长按卡片并拖动也可以直接调整顺序。")
                        .modifier(UITestOrderValue(id: "homepanels.order", order: home.orderToken))
                }
                .listRowBackground(Theme.card)
                // r7: rebuilt from the saved order after every move (drag or 上移 / 下移), never a stale table.
                .id(home.orderRevision)

                Section {
                    let missing = BuiltinTile.allCases.filter { !model.pinned.contains($0.id) }
                    if missing.isEmpty {
                        Text("内置卡片都已添加。").font(.footnote).foregroundStyle(.secondary)
                    }
                    ForEach(missing) { t in
                        Button { home.pinBuiltin(t) } label: {
                            HStack(spacing: 10) {
                                Image(systemName: t.icon).foregroundStyle(Theme.accent).frame(width: 24)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(verbatim: t.title).font(.subheadline).foregroundStyle(.primary)
                                    Text(verbatim: t.caption).font(.caption2).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 6)
                                Image(systemName: "plus.circle.fill").foregroundStyle(Theme.good)
                            }
                        }
                        .accessibilityIdentifier("homepanels.add.\(t.rawValue)")
                    }
                } header: {
                    Text("内置卡片")
                } footer: {
                    Text("网速、流量、运行时长、出口 IP（默认打码）、内网 IP、内存和流媒体解锁，由 App 绘制，不需要模块。两张小卡片并排显示。")
                }
                .listRowBackground(Theme.card)

                HomeAnalysisEditorSection() // feat/home-analysis
                    .listRowBackground(Theme.card)

                Section {
                    Button { showPanels = true } label: { addRow("全部面板", icon: "square.grid.2x2", enabled: vpn.isConnected) }
                        .disabled(!vpn.isConnected)
                        .accessibilityIdentifier("homepanels.allPanels")
                    if !vpn.isConnected {
                        Text("需要连接后加载面板").font(.caption2).foregroundStyle(.secondary)
                    }
                    Button { showScriptTasks = true } label: { addRow("脚本任务", icon: "terminal", enabled: true) }
                        .accessibilityIdentifier("homepanels.scriptTasks")
                } header: {
                    Text("添加")
                } footer: {
                    Text("Surge [Panel] / Stash 面板在「面板」页长按固定；QX 的通用脚本和交互脚本在脚本任务详情里固定。连接期间首页面板按刷新间隔在后台更新（最短 5 分钟）。")
                }
                .listRowBackground(Theme.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .navigationTitle("编辑首页面板")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
            .navigationDestination(isPresented: $showPanels) { PanelsView().environment(\.editMode, .constant(.inactive)) }
            .navigationDestination(isPresented: $showScriptTasks) { ScriptTasksView().environment(\.editMode, .constant(.inactive)) }
        }
    }

    /// A navigation row drawn as a button (chevron like a NavigationLink).
    func addRow(_ title: LocalizedStringKey, icon: String, enabled: Bool) -> some View {
        HStack {
            Label(title, systemImage: icon).foregroundStyle(enabled ? Color.primary : Color.secondary)
            Spacer()
            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    @ViewBuilder
    func row(_ id: String) -> some View {
        if let t = BuiltinTile.from(id) {
            HStack(spacing: 10) {
                // r7: the row id sits on the icon (what tests always resolved it to): an id on the HStack is pushed
                // onto every child and would hide the 调整顺序 menu's own id.
                Image(systemName: t.icon).foregroundStyle(Theme.accent).frame(width: 24)
                    .accessibilityIdentifier("homepanels.row.\(t.rawValue)")
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: t.title).font(.subheadline).lineLimit(1)
                    HStack(spacing: 4) {
                        Text("内置卡片")
                        if overrides.isHalf(id) { Text(verbatim: "·"); Text("半宽") }
                    }
                    .font(.caption2).foregroundStyle(.secondary)
                    .accessibilityIdentifier("homepanels.width.\(t.rawValue)")
                }
                Spacer(minLength: 6)
                moveMenu(id, tag: t.rawValue)
            }
            .modifier(MoveActions(id: id))
        } else {
            panelRow(id)
        }
    }

    @ViewBuilder
    func panelRow(_ id: String) -> some View {
        let shown = home.item(id, connected: vpn.isConnected)?.item
        let task = home.tasks.first { $0.panelID == id }
        HStack(spacing: 10) {
            Image(systemName: PanelCard.symbol(PanelOverrideStore.shared.map[id]?.icon ?? shown?.icon))
                .foregroundStyle(Color(hex: shown?.iconColor) ?? Theme.accent)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(home.name(id) ?? String(localized: "不可用的面板")).font(.subheadline).lineLimit(1)
                    if overrides.isHalf(id) { Text("半宽").font(.caption2).foregroundStyle(.secondary) }
                }
                if let task {
                    Menu {
                        ForEach(Self.intervals.indices, id: \.self) { i in
                            let v = Self.intervals[i]
                            Button { home.setInterval(task.id, v.0) } label: {
                                if v.0 == task.interval { Label(v.1, systemImage: "checkmark") } else { Text(v.1) }
                            }
                        }
                    } label: {
                        HStack(spacing: 3) {
                            Image(systemName: "clock.arrow.circlepath")
                            Text(Self.intervals.first { $0.0 == task.interval }?.1 ?? "打开首页时")
                        }
                        .font(.caption2)
                    }
                    if let p = task.params, !p.isEmpty {
                        Text("节点：\(p)").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                } else if let s = shown?.source, !s.isEmpty {
                    Text(s).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            moveMenu(id, tag: id)
        }
        .modifier(MoveActions(id: id))
    }

    /// r7: 上移 / 下移 without dragging (drag handles stay the main way; this one also works with VoiceOver,
    /// Switch Control and in UI tests).
    func moveMenu(_ id: String, tag: String) -> some View {
        Menu {
            Button { withAnimation { home.step(id, by: -1) } } label: { Label("上移", systemImage: "arrow.up") }
                .disabled(!home.canMove(id, by: -1))
                .accessibilityIdentifier("homepanels.up.\(tag)")
            Button { withAnimation { home.step(id, by: 1) } } label: { Label("下移", systemImage: "arrow.down") }
                .disabled(!home.canMove(id, by: 1))
                .accessibilityIdentifier("homepanels.down.\(tag)")
            Divider()
            // fix/app-policy-ui #6: the card's width on Home.
            if PanelOverrideStore.shared.isHalf(id) {
                Button { withAnimation { PanelOverrideStore.shared.setHalf(false, for: id) } } label: { Label("全宽显示", systemImage: "rectangle") }
                    .accessibilityIdentifier("homepanels.full.\(tag)")
            } else {
                Button { withAnimation { PanelOverrideStore.shared.setHalf(true, for: id) } } label: { Label("半宽显示", systemImage: "rectangle.split.2x1") }
                    .accessibilityIdentifier("homepanels.half.\(tag)")
            }
        } label: {
            Image(systemName: "arrow.up.arrow.down.circle")
                .font(.body)
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(Text("调整顺序"))
        .accessibilityIdentifier("homepanels.move.\(tag)")
    }
}

/// feat/fresh-reinstall (user: reorder Home directly, like iOS widgets): long-press a card, then drag it — the context
/// menu preview lifts and becomes the drag (iOS 16+). rel 0.20.2 (CI 40566844130 test96): the drop target is the whole
/// Home section, which finds the card under the finger from the cards' measured frames. Per-card drop delegates were
/// rebuilt whenever the rows regrouped (a full-width card next to a half one), so the session never entered them and
/// the order stayed put; a session that ended without a drop also left `dragging` set (card stuck dimmed, 从首页移除 dead).
/// Hovering another card moves the dragged one into its place; the order is saved at the drop, or 0.6 s after the
/// finger leaves Home / stays still for 1 s.
struct HomeReorderDrag: ViewModifier {
    static let space = "home.panels.space"
    let id: String
    @ObservedObject private var home = HomePanelStore.shared
    func body(content: Content) -> some View {
        content
            .opacity(home.dragging == id ? 0.45 : 1)
            .background(GeometryReader { g in
                Color.clear.preference(key: HomeCardFrameKey.self, value: [id: g.frame(in: .named(Self.space))])
            })
            .onDrag {
                home.beginDrag(id)
                return NSItemProvider(object: id as NSString)
            }
    }
}

/// Frames of the Home cards in the section's coordinate space (for the section-wide drop target).
struct HomeCardFrameKey: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { $1 })
    }
}

/// Section-wide drop target: `update` gets the finger's location (section coordinates) on every move.
struct HomeReorderDrop: DropDelegate {
    let update: (CGPoint) -> Void
    let exit: () -> Void
    let drop: () -> Void
    func validateDrop(info: DropInfo) -> Bool { true }
    func dropEntered(info: DropInfo) { update(info.location) }
    func dropUpdated(info: DropInfo) -> DropProposal? { update(info.location); return DropProposal(operation: .move) }
    func dropExited(info: DropInfo) { exit() }
    func performDrop(info: DropInfo) -> Bool { drop(); return true }
}

/// r7: Debug UI-test builds only (-UITestSeed): exposes a list's saved order as the accessibility value of its footer,
/// so tests can check the model as well as the drawn rows. Release builds and normal Debug launches are unchanged.
struct UITestOrderValue: ViewModifier {
    let id: String
    let order: String
    @ViewBuilder
    func body(content: Content) -> some View {
        if UITestSeed.enabled {
            content.accessibilityIdentifier(id).accessibilityValue(Text(verbatim: order))
        } else {
            content
        }
    }
}

/// r7: VoiceOver rotor actions 上移 / 下移 on a pinned Home panel row.
private struct MoveActions: ViewModifier {
    @ObservedObject var home = HomePanelStore.shared
    let id: String
    func body(content: Content) -> some View {
        content
            .accessibilityAction(named: Text("上移")) { if home.canMove(id, by: -1) { home.step(id, by: -1) } }
            .accessibilityAction(named: Text("下移")) { if home.canMove(id, by: 1) { home.step(id, by: 1) } }
    }
}

// MARK: - Pin a QX / Surge generic or interaction script (task detail)

struct TaskPinSection: View {
    @ObservedObject var model = PanelsModel.shared
    @ObservedObject var home = HomePanelStore.shared
    let task: ScriptTaskState
    let node: String

    var body: some View {
        if task.kind == "generic" || task.kind == "interaction" {
            Section {
                if home.isTaskPinned(task.id) {
                    Button(role: .destructive) { home.unpin(HomePanelStore.taskPrefix + task.id) } label: {
                        Label("从首页移除", systemImage: "pin.slash")
                    }
                } else {
                    Button { home.pinTask(task, params: node) } label: { Label("固定到首页", systemImage: "pin") }
                        .disabled(task.kind == "interaction" && node.isEmpty)
                }
            } footer: {
                if task.kind == "interaction" {
                    if node.isEmpty {
                        Text("选择节点后可固定到首页。")
                    } else {
                        Text("首页面板显示脚本返回的标题和内容，脚本收到节点「\(node)」。")
                    }
                } else {
                    Text("首页面板显示脚本返回的标题和内容（$done 的 title / content 或 message）。")
                }
            }
            .listRowBackground(Theme.card)
        }
    }
}
