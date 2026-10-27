import SwiftUI
import Combine
import NetworkExtension
import UniformTypeIdentifiers

@MainActor
final class PolicyModel: ObservableObject {
    @Published var groups: [ProxyItem] = []
    @Published var all: [String: ProxyItem] = [:] { didSet { graphCache = nil } }
    /// r7: the live graph is built once per /proxies snapshot, not on every render and every row.
    private var graphCache: GroupGraph?
    @Published var testing: Set<String> = []
    @Published var error: String?

    func load() async {
        await SmartGroups.shared.refreshStatus()
        do {
            apply(try await ControllerClient.shared.proxies())
            error = nil
        } catch {
            // fix/nc-start-empty: leaving the page cancels the load — keep what is on screen, no red 「已取消」.
            if ControllerClient.isCancellation(error) { return }
            self.error = error.localizedDescription
        }
    }

    /// feat/policy-chain: url-test / fallback / load-balance switch nodes on their own, so the chain subtitle would
    /// go stale between pulls. While 策略 is on screen and connected, re-read /proxies every 10 s and publish only
    /// when some group's pick (now / fixed) or the group list changed — delay history alone does not re-render.
    func refreshSelections() async {
        guard let p = try? await ControllerClient.shared.proxies() else { return }
        func picks(_ m: [String: ProxyItem]) -> [String: String] {
            var out: [String: String] = [:]
            for (n, x) in m where x.isGroup { out[n] = (x.now ?? "") + "|" + (x.fixed ?? "") }
            return out
        }
        if picks(p) != picks(all) { apply(p) }
    }

    private func apply(_ p: [String: ProxyItem]) {
        // fix/nc-ui-smooth: publish only what changed. Coming back to 策略 (tab switch, sheet closed) re-reads
        // /proxies; an identical answer used to invalidate the whole page twice right in the transition.
        if p != all { all = p }
        // v0.19.8: the runtime's own group order (GLOBAL lists only its members once it is user-defined).
        var gs = LiveGroupOrder.names(p).compactMap { p[$0] }.filter { $0.isGroup && $0.hidden != true && $0.name != "GLOBAL" }
        if let g = p["GLOBAL"] { gs.append(g) }
        if let pending = pendingOrder, Date() < pending.until {
            if gs != groups { groups = gs }
            applyOrder(pending.names) // a reload still applying: keep the saved order on screen
        } else {
            pendingOrder = nil
            if gs != groups { groups = gs }
        }
    }

    /// v0.19.8: a saved order the core has not confirmed yet (a reload with providers can outlast the read that
    /// follows it; the page then showed the old order and the save looked like it did nothing).
    var pendingOrder: (names: [String], until: Date)?

    /// After an order save: shows it right away and re-reads the core until its group order matches (≤ 30 s).
    func confirmOrder(_ names: [String]) async {
        pendingOrder = (names, Date().addingTimeInterval(30))
        applyOrder(names)
        for _ in 0..<15 {
            await load()
            guard let p = try? await ControllerClient.shared.proxies() else { break }
            let live = LiveGroupOrder.names(p).filter { names.contains($0) }
            if live == names.filter({ p[$0] != nil }) { pendingOrder = nil; break }
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }
        pendingOrder = nil
        await load()
    }

    /// feat/group-order: shows a saved order right away (the core reload that follows confirms it).
    func applyOrder(_ names: [String]) {
        let rank = Dictionary(names.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let listed = groups.filter { rank[$0.name] != nil }.sorted { rank[$0.name]! < rank[$1.name]! }
        var it = listed.makeIterator()
        let next = groups.map { rank[$0.name] != nil ? (it.next() ?? $0) : $0 }
        if next != groups { groups = next }
    }

    /// Results of this session's live 测速 (0 = timeout), newest wins over the core's history.
    @Published var liveDelays: [String: Int] = [:]
    @Published var notice: String?

    /// hotfix/group-test-offline: live groups as a graph (members and the core's `now`), to show which node a member
    /// group is on.
    var graph: GroupGraph {
        if let c = graphCache { return c }
        var gs: [String: GroupGraph.Group] = [:]
        for (n, p) in all where p.isGroup {
            gs[n] = GroupGraph.Group(type: PolicyGroupDisplay.kind(live: p.type), members: p.all ?? [], now: p.now)
        }
        let a = all
        let g = GroupGraph(groups: gs, isTestable: { a[$0] != nil && a[$0]?.isGroup != true && !GroupGraph.builtins.contains($0) })
        graphCache = g
        return g
    }

    /// A member group's own measurement (the core dials /proxies/{group}/delay through the node it is on); without
    /// one yet, the measurement of the node the core has it on. Nodes: their own delay.
    func displayDelay(_ name: String, graph: GroupGraph) -> Int? {
        if let d = delay(of: name) { return d }
        return graph.follow(name).flatMap { delay(of: $0) }
    }

    func resolution(_ name: String, graph: GroupGraph) -> GroupGraph.Resolution? {
        guard let n = graph.follow(name) else { return nil }
        return GroupGraph.Resolution(node: n, delay: displayDelay(name, graph: graph), how: .selected)
    }

    func delay(of name: String) -> Int? {
        if let d = liveDelays[name] { return d }
        return all[name]?.lastDelay(for: NodeSettingsStore.testURL(for: name))
    }

    func select(_ group: ProxyItem, _ node: String) async {
        guard group.isSelectable else { return }
        do {
            try await ControllerClient.shared.select(group: group.name, node: node)
            await ControllerClient.shared.afterUserSwitch() // v0.19
            UISelectionFeedbackGenerator().selectionChanged()
            // fix/nc-ui-smooth: the selection file is written off the main thread (serial, in tap order).
            if group.name != "GLOBAL" { let g = group.name; UIBackgroundIO.run { ProfileInspector.rememberLiveSelection(group: g, node: node) } }
            await load()
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// 固定 / 解除固定 (v0.8) a member of a url-test / fallback group (core-native, PUT / DELETE /proxies/{group}).
    func pin(_ group: ProxyItem, _ node: String?) async {
        do {
            if let node { try await ControllerClient.shared.pin(group: group.name, node: node) }
            else { try await ControllerClient.shared.unpin(group: group.name) }
            UISelectionFeedbackGenerator().selectionChanged()
            await load()
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        } catch {
            self.error = String(localized: "固定失败：\(error.localizedDescription)")
        }
    }

    /// Live 测速 through the running core (each member is dialled through its own node), with the
    /// URL and timeout from 更多 → 测速.
    func test(_ group: ProxyItem) async {
        // v0.19.3: a second tap (group bolt during 全部测速, or 全部测速 twice) ran the same group's test again in
        // parallel and the first one to finish cleared the spinner while the other was still testing.
        guard !testing.contains(group.name) else { return }
        testing.insert(group.name)
        defer { testing.remove(group.name) }
        // v0.19.8: members as the running core has them right now (the list on screen can be older).
        let fresh = (try? await ControllerClient.shared.proxies())?[group.name]?.all ?? group.all ?? []
        let members = fresh.filter { !GroupGraph.builtins.contains($0) }
        // hotfix/group-test-offline: say so instead of a tap that does nothing (a group of only DIRECT / REJECT).
        guard !members.isEmpty else { notice = String(localized: "「\(group.name)」里没有可测速的节点"); return }
        var failure: String?
        // fix/app-policy-ui #2: each member's result is shown as it lands (batched ~120 ms); the previous result
        // stays until then. v0.15.2: still bounded (DelayStream.groupWidth at a time), never /group/delay.
        let buffer = DelayStreamBuffer { [weak self] got in self?.liveDelays.merge(got) { _, new in new } }
        do {
            let got = try await ControllerClient.shared.membersDelay(members, limit: DelayStream.groupWidth,
                                                                     onResult: { n, ms in await buffer.add(n, ms) })
            buffer.drain()
            var all = liveDelays
            for m in members { all[m] = got[m] ?? 0 }
            if all != liveDelays { liveDelays = all }
        } catch {
            buffer.drain()
            // The controller itself did not answer: say so instead of marking every node as timed out.
            failure = String(localized: "测速失败：\(error.localizedDescription)")
        }
        await load()
        if let failure { self.error = failure }
    }
}

/// One policy group as the card shows it, from the live controller or from the profile file.
struct PolicyGroupDisplay {
    var name: String
    var kind: String          // select / url-test / fallback / load-balance / relay / global
    var now: String?
    var members: [String]
    var selectable: Bool
    /// The profile's own `icon:` (Clash.Meta proxy-groups); the user's choice in group-icons.json wins.
    var profileIcon: String? = nil
    /// url-test / fallback member pinned in the core (v0.8), nil = automatic.
    var pinned: String? = nil

    var pinnable: Bool { kind == "url-test" || kind == "fallback" }

    /// v0.15 (QX rule): only automatic groups (url-test / fallback / load-balance) collapse; select stays.
    static func isAutomatic(_ kind: String) -> Bool { kind == "url-test" || kind == "fallback" || kind == "load-balance" }

    static func kind(live type: String) -> String {
        switch type {
        case "Selector": return "select"
        case "URLTest": return "url-test"
        case "Fallback": return "fallback"
        case "LoadBalance": return "load-balance"
        case "Relay": return "relay"
        default: return type.lowercased()
        }
    }

    var label: String {
        switch kind {
        case "select": return String(localized: "手动")
        case "url-test": return String(localized: "自动")
        case "fallback": return String(localized: "故障转移")
        case "load-balance": return String(localized: "负载均衡")
        case "relay": return String(localized: "链式")
        default: return kind
        }
    }

    var icon: String {
        switch kind {
        case "select": return "hand.tap.fill"
        case "url-test": return "bolt.badge.clock.fill"
        case "fallback": return "arrow.triangle.branch"
        case "load-balance": return "scalemass.fill"
        case "relay": return "link"
        default: return "globe"
        }
    }

    var hint: String {
        switch kind {
        case "url-test": return String(localized: "自动选择延迟最低的节点（当前：\(now ?? "—")）")
        case "fallback": return String(localized: "按顺序使用第一个可用节点（当前：\(now ?? "—")）")
        case "load-balance": return String(localized: "在节点间分配连接")
        default: return String(localized: "该策略组不可手动选择")
        }
    }
}

struct PolicyView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @StateObject private var model = PolicyModel()
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var expanded: Set<String> = []
    @ObservedObject private var smart = SmartGroups.shared
    @State private var chainGroup: ChainGroupTarget?
    @State private var share: ShareTarget?
    @State private var shareError: String?
    /// 排序 (v0.7): default = profile order; latency uses a snapshot so nodes don't jump while a test runs.
    @AppStorage("policy.sort") private var sortMode = "default"
    @AppStorage("policy.autoSort") private var autoSort = true
    /// v0.15: hide automatic groups (url-test / fallback / load-balance); select groups always stay. Persisted.
    @AppStorage("policy.collapseAuto") private var collapseAuto = false
    @State private var editHome = false
    @State private var sortDelays: [String: Int] = [:]
    /// r7: bumped whenever sortDelays is retaken, so the sort memo knows the latency snapshot changed.
    @State private var sortGen = 0
    /// r7: sorted member lists memoized by (group, members, sort mode, latency snapshot) — a reference held in
    /// @State so filling it never re-renders; re-sorting every group on every render was the cost on big profiles.
    @State private var sortMemo = PolicySortMemo()
    @State private var iconTarget: IconTarget?

    struct IconTarget: Identifiable { let id = UUID(); let name: String; let profileIcon: String? }
    struct ProbeTarget: Identifiable { let id = UUID(); let name: String }
    @State private var probeTarget: ProbeTarget?
    /// v0.11: QX event-interaction scripts offered in the node menu, and the run in flight.
    @State private var interactions: [ScriptTaskState] = []
    @State private var interaction: InteractionRequest?
    @ObservedObject private var probes = ProbeStore.shared
    /// v0.19.8: the group list follows the outbound mode (GLOBAL only in 全局, first there).
    /// Review 5: only the mode is mirrored; observing DashboardModel re-rendered every card each second.
    @State private var mode = DashboardModel.shared.mode

    struct ChainGroupTarget: Identifiable { let id = UUID(); let name: String }
    /// v0.9 策略组编辑 (name nil = new group).
    struct EditGroupTarget: Identifiable { let id = UUID(); let name: String? }
    @State private var editGroup: EditGroupTarget?
    /// feat/group-order: 编辑排序 mode (reorder list in place of the cards), direct drag in the normal list,
    /// and the message of a failed save.
    @State private var reorderMode = false
    @State private var reorderRows: [GroupOrderRow] = []
    @State private var reorderOriginal: [String] = []
    @State private var reorderSaving = false
    @State private var reorderMessage: String?
    @State private var movable: Set<String> = []
    @State private var dragOrder: [String]?
    @State private var dragging: String?
    @State private var dragSaving = false
    @State private var orderError: String?
    @State private var reorderLoading = false

    /// The groups in the order the page shows them (display names), for 排列策略组 / 置顶.
    private var orderGroups: [(name: String, kind: String, icon: String?)] {
        if vpn.isConnected {
            return model.groups.filter { $0.name != "GLOBAL" }.map { ($0.name, PolicyGroupDisplay.kind(live: $0.type), $0.icon) }
        }
        return offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map { ($0.name, $0.type, $0.icon) }
    }

    private func topAction(_ name: String) -> (() -> Void)? {
        guard name != "GLOBAL", store.active != nil else { return nil }
        return {
            Task {
                guard let p = store.active else { return }
                let names = orderGroups.map { $0.name }
                guard let i = names.firstIndex(of: name), i > 0 else { return }
                // Review 5: the whole-profile YAML parse runs off the main actor.
                let fileNames = await Task.detached(priority: .userInitiated) { GroupOrder.fileNames(p) }.value
                guard fileNames.contains(GroupOrder.fileName(of: name, edits: GroupEditStore.get(p.id))) else {
                    orderError = String(localized: "该策略组不在配置文件中（运行时加入），位置无法调整")
                    return
                }
                resetDrag()
                let r = await GroupOrder.moveToTop(name, current: names, profile: p)
                if r.saved, vpn.isConnected { var n = names; n.remove(at: i); n.insert(name, at: 0); await model.confirmOrder(n) }
                if let m = r.message { orderError = m }
            }
        }
    }

    /// v0.19.6: the file's group names are read off the main actor when the page appears / the profile changes
    /// (a YAML parse of the whole profile; noticeable on a profile with thousands of nodes and rules).
    private func refreshMovableAsync() async {
        guard let p = store.active else { movable = []; return }
        let names = await Task.detached(priority: .utility) { GroupOrder.fileNames(p) }.value
        guard store.active?.id == p.id else { return }
        let edits = GroupEditStore.get(p.id)
        movable = Set(names.map { GroupOrder.displayName(of: $0, edits: edits) })
    }

    /// Drops any drag override (a drag that never reached a drop, or a provider call outside a real drag).
    private func resetDrag() {
        guard !dragSaving else { return }
        dragging = nil
        dragOrder = nil
    }

    private func enterReorder() {
        guard !reorderLoading else { return }
        resetDrag()
        reorderLoading = true
        Task {
            // Review 5: the file's group names are parsed off the main actor (was refreshMovable on main).
            await refreshMovableAsync()
            reorderLoading = false
            showReorder()
        }
    }

    private func showReorder() {
        let gs = orderGroups
        reorderRows = gs.map { GroupOrderRow(name: $0.name, kind: $0.kind, icon: $0.icon, movable: movable.contains($0.name)) }
        reorderOriginal = gs.map { $0.name }
        reorderMessage = nil
        withAnimation { reorderMode = true }
    }

    private func finishReorder() async {
        let names = reorderRows.map(\.name)
        guard names != reorderOriginal, let p = store.active else { withAnimation { reorderMode = false }; return }
        reorderSaving = true
        defer { reorderSaving = false }
        let r = await GroupOrder.save(names, profile: p)
        guard r.saved else { reorderMessage = r.message; return }
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        if vpn.isConnected { Task { await model.confirmOrder(names) } }
        if let m = r.message { orderError = m }
        withAnimation { reorderMode = false }
    }

    /// Direct drag: long-press a card header (file groups only).
    private func dragAction(_ name: String) -> (() -> NSItemProvider)? {
        guard movable.contains(name), name != "GLOBAL" else { return nil }
        return {
            dragging = name
            dragOrder = orderGroups.map { $0.name }
            return NSItemProvider(object: name as NSString)
        }
    }

    private func dragEnter(_ target: String) {
        guard let d = dragging, d != target, movable.contains(target), var o = dragOrder,
              let from = o.firstIndex(of: d), let to = o.firstIndex(of: target) else { return }
        o.remove(at: from)
        o.insert(d, at: to)
        withAnimation(.spring(response: 0.3)) { dragOrder = o }
    }

    private func dragFinish() {
        guard dragging != nil else { return }
        dragging = nil
        guard let o = dragOrder, o != orderGroups.map({ $0.name }), let p = store.active else { dragOrder = nil; return }
        dragSaving = true
        Task {
            defer { dragSaving = false; dragging = nil; dragOrder = nil }
            let r = await GroupOrder.save(o, profile: p)
            if r.saved {
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                if vpn.isConnected { Task { await model.confirmOrder(o) } }
            }
            if let m = r.message { orderError = m }
        }
    }

    private func dropTarget(_ name: String) -> GroupDropDelegate {
        GroupDropDelegate(target: name, enter: { dragEnter($0) }, drop: { dragFinish() })
    }

    /// 策略组 header with 编辑排序 above the cards (and, on an 自定义 copy, where it was copied from).
    private var orderHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text("策略组").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button { enterReorder() } label: {
                    // Review 6 OPT-3: the profile's group names are parsed off main first; show that it is working.
                    HStack(spacing: 4) {
                        if reorderLoading { ProgressView().controlSize(.mini) }
                        Text("编辑排序")
                    }
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 4)
                        .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                        .background(Capsule().fill(Theme.ink(0.08)))
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("policy.editOrder")
            }
            orderSource
        }
        .padding(.horizontal, 4)
    }

    /// On an 自定义 copy: which profile it was copied from.
    @ViewBuilder private var orderSource: some View {
        if let p = store.active, p.sourceID != nil {
            let name = store.source(of: p)?.displayName ?? p.sourceName ?? ""
            HStack(spacing: 4) {
                Image(systemName: "doc.on.doc")
                Text("当前为副本，复制自「\(name)」")
                    .lineLimit(1)
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("policy.orderSource")
        }
    }

    /// Groups that can carry a 前置代理 (not GLOBAL; DIRECT/REJECT style built-ins have no members).
    private func chainAction(_ name: String) -> (() -> Void)? {
        guard name != "GLOBAL" else { return nil }
        return { chainGroup = ChainGroupTarget(name: name) }
    }

    private func shareNode(_ name: String) {
        Task {
            switch await NodeShare.link(named: name) {
            case .success(let l): share = ShareTarget(name: name, link: l)
            case .failure(let e): shareError = e.message
            }
        }
    }

    /// Takes the delays the latency sort uses (after a test when 测速后自动排序 is on, or when the sort changes).
    private func snapshotDelays() {
        if vpn.isConnected {
            var d: [String: Int] = [:]
            let graph = model.graph
            for g in model.groups { for m in g.all ?? [] { if let v = model.displayDelay(m, graph: graph) { d[m] = v } } }
            sortDelays = d
            sortGen &+= 1
        } else {
            // hotfix/group-test-offline: member groups sort by the node they resolve to.
            var d = offline.delays
            let graph = offline.graph
            for name in graph.groups.keys { if let v = offline.displayDelay(name, graph: graph) { d[name] = v } }
            sortDelays = d
            sortGen &+= 1
        }
    }

    private func afterTest() { if autoSort && sortMode == "latency" { snapshotDelays() } }

    private func ordered(_ members: [String]) -> [String] {
        if sortMode != "name" && sortMode != "latency" { return members }
        return sortMemo.value(members: members, mode: sortMode, gen: sortMode == "latency" ? sortGen : 0) { sortedNow($0) }
    }

    private func sortedNow(_ members: [String]) -> [String] {
        switch sortMode {
        case "name":
            return members.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        case "latency":
            var index: [String: Int] = [:]
            for (i, m) in members.enumerated() where index[m] == nil { index[m] = i }
            func key(_ m: String) -> (Int, Int, Int) {
                let i = index[m] ?? 0
                guard let d = sortDelays[m] else { return (2, 0, i) }
                return d > 0 ? (0, d, i) : (1, 0, i)
            }
            return members.sorted { key($0) < key($1) }
        default:
            return members
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if reorderMode {
                    GroupReorderList(rows: $reorderRows, profile: store.active, message: reorderMessage, onCleared: {
                        withAnimation { reorderMode = false }
                        Task { if vpn.isConnected { await model.load() } else { await offline.load() } }
                    })
                } else if vpn.isConnected { liveList } else { offlineList }
            }
            .background(Theme.bg.ignoresSafeArea())
            // fix/app-policy-ui #5b: 编辑排序 keeps the centred title (取消 takes the leading slot).
            .tabRootChrome(reorderMode ? LocalizedStringKey("编辑排序") : LocalizedStringKey("策略"), showsTitle: !reorderMode)
            .toolbar {
              if reorderMode {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { withAnimation { reorderMode = false } }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if reorderSaving {
                        ProgressView()
                    } else {
                        Button("完成") { Task { await finishReorder() } }
                            .fontWeight(.semibold)
                            .accessibilityIdentifier("grouporder.done")
                    }
                }
              } else {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button { editGroup = EditGroupTarget(name: nil) } label: { Image(systemName: "plus") }
                        .accessibilityLabel(Text("新建策略组"))
                    Button { withAnimation(.spring(response: 0.3)) { collapseAuto.toggle() } } label: {
                        Image(systemName: collapseAuto ? "rectangle.expand.vertical" : "rectangle.compress.vertical")
                    }
                    .accessibilityLabel(Text(collapseAuto ? "展开自动策略" : "折叠自动策略"))
                    Menu {
                        Picker("排序", selection: $sortMode) {
                            Label("配置顺序", systemImage: "list.number").tag("default")
                            Label("按延迟", systemImage: "speedometer").tag("latency")
                            Label("按名称", systemImage: "textformat").tag("name")
                        }
                        Toggle("测速后自动排序", isOn: $autoSort)
                        Divider()
                        Button { enterReorder() } label: { Label("编辑排序", systemImage: "line.3.horizontal") } // feat/group-order
                            .accessibilityIdentifier("policy.reorder")
                        Button { editHome = true } label: { Label("编辑首页策略", systemImage: "house") } // feat/home-groups
                    } label: { Image(systemName: "arrow.up.arrow.down") }
                    .accessibilityLabel(Text("排序"))
                    Button {
                        Task {
                            if vpn.isConnected {
                                for g in model.groups where g.name != "GLOBAL" { await model.test(g) }
                            } else {
                                await offline.test(groups: offline.result.groups.filter { $0.hidden != true })
                            }
                            afterTest()
                        }
                    } label: { Image(systemName: "bolt.fill") }
                    .accessibilityLabel(Text("全部测速"))
                }
              }
            }
        }
        .task(id: vpn.isConnected) {
            if vpn.isConnected { await model.load() } else { await offline.load() }
            snapshotDelays()
            interactions = vpn.isConnected ? await TaskCatalog.interactions() : []
            await refreshMovableAsync()
        }
        // feat/policy-chain: keep the chain subtitles current while connected (automatic groups switch by themselves).
        .task(id: vpn.isConnected) {
            guard vpn.isConnected else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                if Task.isCancelled || !vpn.isConnected { break }
                await model.refreshSelections()
            }
        }
        .modifier(InteractionRunner(request: $interaction))
        // hotfix/group-test-offline: a 测速 with nothing to dial says so instead of doing nothing.
        .overlay(alignment: .bottom) {
            if let n = offline.notice ?? model.notice {
                Label(n, systemImage: "speedometer")
                    .font(.footnote.weight(.semibold))
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Capsule().fill(Theme.cardHi))
                    .overlay(Capsule().stroke(Theme.ink(0.08)))
                    .padding(.bottom, 16)
                    .transition(.opacity)
                    .accessibilityIdentifier("policy.notice")
                    .task(id: n) {
                        try? await Task.sleep(nanoseconds: 3_000_000_000)
                        offline.notice = nil
                        model.notice = nil
                    }
            }
        }
        // Review 5: mirror only the outbound mode (fires with the current value on appear, then on every change).
        // fix/nc-ui-smooth: 全局 hides the rule groups / 规则 brings them back — animated, not a jump.
        .onReceive(DashboardModel.shared.$mode.removeDuplicates()) { m in
            if mode != m { withAnimation(.easeInOut(duration: 0.2)) { mode = m } }
        }
        .onChange(of: sortMode) { _ in snapshotDelays() }
        #if DEBUG
        // fix/nc-ui-smooth: UIPerfScenario (UI performance tests, -UIPerfProbe) expands / collapses a group like a tap.
        .onReceive(NotificationCenter.default.publisher(for: .uiPerfExpandGroup)) { n in
            guard let name = n.object as? String else { return }
            let on = (n.userInfo?["on"] as? Bool) ?? true
            let key = vpn.isConnected ? name : "offline:" + name
            withAnimation(.spring(response: 0.3)) { if on { expanded.insert(key) } else { expanded.remove(key) } }
        }
        #endif
        .sheet(item: $iconTarget) { t in GroupIconPicker(group: t.name, profileIcon: t.profileIcon) }
        // The order changed underneath (another save, a reload, a subscription update): no drag override survives it.
        .onChange(of: orderGroups.map { $0.name }) { _ in resetDrag() }
        .onChange(of: store.activeID) { _ in
            reorderMode = false
            resetDrag()
            Task { await refreshMovableAsync() }
            Task { if !vpn.isConnected { await offline.load() } }
        }
        .sheet(item: $chainGroup) { t in GroupChainSheet(group: t.name) }
        .sheet(item: $editGroup, onDismiss: { Task { if vpn.isConnected { await model.load() } else { await offline.load() } } }) { t in
            GroupEditorView(groupName: t.name).environmentObject(store).environmentObject(vpn)
        }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(item: $probeTarget) { t in NodeProbeSheet(policy: t.name) }
        .sheet(isPresented: $editHome) { HomeGroupsEditor().environmentObject(vpn) }
        .alert("编辑排序", isPresented: Binding(get: { orderError != nil }, set: { if !$0 { orderError = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(orderError ?? "") }
        .alert("分享节点", isPresented: Binding(get: { shareError != nil }, set: { if !$0 { shareError = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(shareError ?? "") }
    }

    /// Only url-test / fallback groups offer 智能选择.
    private func smartBinding(_ d: PolicyGroupDisplay) -> Binding<Bool>? {
        guard d.kind == "url-test" || d.kind == "fallback" else { return nil }
        return Binding(get: { smart.isSmart(d.name) }, set: { smart.set(d.name, smart: $0) })
    }

    private func binding(_ name: String) -> Binding<Bool> {
        Binding(get: { expanded.contains(name) },
                set: { v in if v { expanded.insert(name) } else { expanded.remove(name) } })
    }

    private func expandAuto() { withAnimation(.spring(response: 0.3)) { collapseAuto = false } }

    var liveList: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                PolicyModeBar()
                if let e = model.error { Text(e).font(.footnote).foregroundStyle(Theme.bad) }
                TestTargetCaption(live: true)
                orderHeader
                let graph = model.graph
                let liveAuto = model.groups.filter { PolicyGroupDisplay.isAutomatic(PolicyGroupDisplay.kind(live: $0.type)) }
                GlobalModeHiddenNote(count: PolicyModeFilter.hiddenCount(model.groups, mode: mode, name: { $0.name }, now: { $0.now }))
                ForEach(GroupOrderRow.arranged(PolicyModeFilter.apply(model.groups, mode: mode, name: { $0.name }, now: { $0.now }), by: dragOrder) { $0.name }) { g in
                  if collapseAuto && PolicyGroupDisplay.isAutomatic(PolicyGroupDisplay.kind(live: g.type)) {
                    if g.id == liveAuto.first?.id { CollapsedAutoRow(count: liveAuto.count) { expandAuto() } }
                  } else {
                    let fixed: String? = (g.fixed ?? "").isEmpty ? nil : g.fixed
                    let pinAction: ((String?) -> Void)? = (PolicyGroupDisplay.kind(live: g.type) == "url-test" || PolicyGroupDisplay.kind(live: g.type) == "fallback") && !smart.isSmart(g.name)
                        ? { n in Task { await model.pin(g, n) } } : nil
                    let d = PolicyGroupDisplay(name: g.name, kind: PolicyGroupDisplay.kind(live: g.type), now: g.now,
                                               members: ordered(g.all ?? []), selectable: g.isSelectable, profileIcon: g.icon,
                                               pinned: fixed)
                    let card = PolicyGroupCard(group: d,
                                    testing: model.testing.contains(g.name),
                                    expanded: binding(g.name),
                                    nodeType: { model.all[$0]?.type },
                                    nodeUDP: { model.all[$0]?.udp == true },
                                    delay: { model.displayDelay($0, graph: graph) },
                                    onTest: { Task { await model.test(g); afterTest() } },
                                    onSelect: { n in Task { await model.select(g, n) } },
                                    smart: smartBinding(d),
                                    smartInfo: smart.summary(g.name),
                                    via: smart.via(g.name),
                                    onChain: chainAction(g.name),
                                    onShare: { shareNode($0) },
                                    onIcon: { iconTarget = IconTarget(name: g.name, profileIcon: g.icon) },
                                    onEdit: { editGroup = EditGroupTarget(name: g.name) },
                                    onTop: topAction(g.name),
                                    onDrag: dragAction(g.name),
                                    onProbe: { probeTarget = ProbeTarget(name: $0) },
                                    badge: { probes.badge(for: $0) },
                                    onPin: pinAction,
                                    interactions: interactions.map { ($0.id, $0.script.name) },
                                    onInteract: { id, node in
                                        if let t = interactions.first(where: { $0.id == id }) { interaction = InteractionRequest(task: t, node: node) }
                                    },
                                    resolved: { model.resolution($0, graph: graph) },
                                    chain: graph.chain(from: g.name))
                    card.onDrop(of: [UTType.text], delegate: dropTarget(g.name))
                    // fix/nc-ui-smooth: members as lazy rows of this stack (only the rows on screen are built).
                    if expanded.contains(g.name) {
                        ForEach(0..<card.memberRowCount, id: \.self) { r in card.memberRow(r) }
                    }
                  }
                }
            }
            .padding(16)
            .onDrop(of: [UTType.text], delegate: GroupListDropDelegate(drop: { dragFinish() }))
        }
        .refreshable { await model.load() }
    }

    var offlineList: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                PolicyModeBar()
                HStack(spacing: 6) {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("未连接")
                    Spacer()
                    if offline.loading { ProgressView().controlSize(.small) }
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

                if AppShared.activeProfileURL == nil {
                    // feat/surge-ui: friendly empty state with the way out.
                    EmptyStateView(icon: "square.grid.2x2", title: "还没有可用的策略", message: "添加并选择一个配置后，策略组会显示在这里。",
                                   actionTitle: "前往配置", actionID: "policy.emptyAction") { ImportRouter.shared.showProfiles() }
                } else if let e = offline.result.error, offline.result.groups.isEmpty {
                    ErrorRow(message: e)
                } else {
                    let index = offline.nodeIndex
                    let groupNames = Set(offline.result.groups.map(\.name))
                    let graph = offline.graph
                    let profileGroups = offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }
                    let all = profileGroups + [offline.globalGroup]
                    let visible = PolicyModeFilter.apply(all, mode: mode, name: { $0.name }, now: { offline.current(of: $0) })
                    GlobalModeHiddenNote(count: mode == "global" ? all.count - visible.count : 0)
                    let offAuto = visible.filter { PolicyGroupDisplay.isAutomatic($0.type) }
                    if !visible.isEmpty { orderHeader }
                    ForEach(GroupOrderRow.arranged(visible, by: dragOrder) { $0.name }) { g in
                      if collapseAuto && PolicyGroupDisplay.isAutomatic(g.type) {
                        if g.id == offAuto.first?.id { CollapsedAutoRow(count: offAuto.count) { expandAuto() } }
                      } else {
                        let d = PolicyGroupDisplay(name: g.name, kind: g.type, now: offline.current(of: g),
                                                   members: ordered(offline.members(of: g)), selectable: g.type == "select", profileIcon: g.icon)
                        let card = PolicyGroupCard(group: d,
                                        testing: offline.testing.contains(g.name),
                                        expanded: binding("offline:" + g.name),
                                        nodeType: { name in
                                            if let t = index[name]?.type { return t }
                                            return groupNames.contains(name) ? "group" : nil
                                        },
                                        nodeUDP: { index[$0]?.udp == true },
                                        delay: { offline.displayDelay($0, graph: graph) },
                                        onTest: { Task { await offline.test(group: g); afterTest() } },
                                        onSelect: { n in
                                            offline.select(group: g.name, node: n)
                                            UISelectionFeedbackGenerator().selectionChanged()
                                        },
                                        smart: smartBinding(d),
                                        smartInfo: smart.isSmart(g.name) ? String(localized: "连接后按延迟与失败记录自动选择") : nil,
                                        via: smart.via(g.name),
                                        onChain: chainAction(g.name),
                                        onShare: { shareNode($0) },
                                        onIcon: { iconTarget = IconTarget(name: g.name, profileIcon: g.icon) },
                                        onEdit: { editGroup = EditGroupTarget(name: g.name) },
                                        onTop: topAction(g.name),
                                        onDrag: dragAction(g.name),
                                        resolved: { graph.groups[$0] != nil ? graph.resolve($0, delays: offline.delays) : nil },
                                        chain: graph.chain(from: g.name, delays: offline.delays))
                        card.onDrop(of: [UTType.text], delegate: dropTarget(g.name))
                        if expanded.contains("offline:" + g.name) {
                            ForEach(0..<card.memberRowCount, id: \.self) { r in card.memberRow(r) }
                        }
                      }
                    }
                    if !offline.result.groups.isEmpty {
                        TestTargetCaption(live: false)
                        Text("在这里选择的节点会保存到该配置，下次连接时生效。测速直接从本机发起（不经过代理）。节点集只显示已缓存的节点。")
                            .font(.caption2).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 4)
                    }
                }
            }
            .padding(16)
            .onDrop(of: [UTType.text], delegate: GroupListDropDelegate(drop: { dragFinish() }))
        }
        .refreshable { await offline.load() }
    }
}

/// r7: memo for PolicyView's sorted member lists. Keyed by the member list itself plus the sort mode and the
/// latency-snapshot generation; entries for a previous mode / snapshot are dropped when either changes.
final class PolicySortMemo {
    private var mode = ""
    private var gen = -1
    private var cache: [[String]: [String]] = [:]

    func value(members: [String], mode: String, gen: Int, compute: ([String]) -> [String]) -> [String] {
        if mode != self.mode || gen != self.gen { cache = [:]; self.mode = mode; self.gen = gen }
        if let c = cache[members] { return c }
        let v = compute(members)
        if cache.count > 512 { cache = [:] }
        cache[members] = v
        return v
    }
}

struct PolicyGroupCard: View {
    let group: PolicyGroupDisplay
    let testing: Bool
    @Binding var expanded: Bool
    let nodeType: (String) -> String?
    let nodeUDP: (String) -> Bool
    let delay: (String) -> Int?
    let onTest: () -> Void
    let onSelect: (String) -> Void
    var smart: Binding<Bool>? = nil
    var smartInfo: String? = nil
    /// 前置代理 of the group (nil = none) and the action that opens the picker.
    var via: String? = nil
    var onChain: (() -> Void)? = nil
    /// Share a member node (link + QR).
    var onShare: ((String) -> Void)? = nil
    /// Opens the group icon picker.
    var onIcon: (() -> Void)? = nil
    /// v0.9: opens the group editor.
    var onEdit: (() -> Void)? = nil
    /// feat/group-order: 置顶 (moves the group to the top of the profile's proxy-groups).
    var onTop: (() -> Void)? = nil
    /// feat/group-order: long-press drag of the header (nil = not draggable, e.g. a runtime group).
    var onDrag: (() -> NSItemProvider)? = nil
    /// v0.8 节点探测 sheet for a member (live only), and the 解锁 badge per member.
    var onProbe: ((String) -> Void)? = nil
    var badge: ((String) -> (ok: Int, total: Int)?)? = nil
    /// v0.8 固定 / 解除固定 (nil = not offered: not url-test / fallback, smart selection on, or offline).
    var onPin: ((String?) -> Void)? = nil
    /// v0.11: QX interaction scripts (id, name) run on a member with $environment.params = its name.
    var interactions: [(String, String)] = []
    var onInteract: ((String, String) -> Void)? = nil
    /// hotfix/group-test-offline: for a member that is a group, the node it resolves to (nil = not a group).
    var resolved: ((String) -> GroupGraph.Resolution?)? = nil
    /// feat/policy-chain: the whole path down to the final node (Egern 策略), shown as the subtitle. nil = the old
    /// 「当前 → 节点」 line.
    var chain: GroupGraph.Chain? = nil

    /// 「→ 节点」 for a selected node, 「最快 节点」 / 「可用 节点」 when the offline page picked it from measurements.
    static func resolutionText(_ r: GroupGraph.Resolution) -> String {
        let n = FlagSafe.text(r.node)
        switch r.how {
        case .selected: return "→ " + n
        case .fastest: return String(localized: "最快 \(n)")
        case .firstAvailable: return String(localized: "可用 \(n)")
        }
    }

    static let unprobeable: Set<String> = ["REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]

    static let nonShareable: Set<String> = ["group", "selector", "urltest", "url-test", "fallback", "loadbalance", "load-balance", "relay",
                                            "direct", "reject", "rejectdrop", "reject-drop", "compatible", "pass", "dns"]

    /// Long-press menu of the card header. 编辑策略组 is always offered (live or from the profile file, any mode).
    @ViewBuilder private var headerMenu: some View {
        if let onEdit { Button { onEdit() } label: { Label("编辑策略组", systemImage: "slider.horizontal.3") } }
        if let onIcon { Button { onIcon() } label: { Label("更换图标", systemImage: "photo") } }
        if let onTop { Button { onTop() } label: { Label("置顶", systemImage: "arrow.up.to.line") } }
    }

    var body: some View {
        // fix/app-policy-ui #1 / #4 (user 2026-10-26, IMG_3620/3621): the header row mirrors a 分流规则 订阅 row
        // (SubscriptionRow) — 32 pt icon, 12 pt to the text, name (+ tags) over two caption lines, 11 pt list-row
        // padding — so a collapsed group is exactly as tall as a rule row at every text size. The three buttons on
        // the right (设置 / 测速 / 展开, mis-taps) became one: 测速 with a 44 pt target; a tap anywhere else on the row
        // expands / collapses; 编辑策略组 is in the long-press menu and inside the expanded section (Surge / Egern).
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: PolicyRowMetrics.iconTextSpacing) {
                GroupIconView(group: group.name, profileIcon: group.profileIcon, fallback: group.icon, size: PolicyRowMetrics.iconSize)
                    .accessibilityIdentifier("policy.icon." + group.name)
                VStack(alignment: .leading, spacing: PolicyRowMetrics.lineSpacing) {
                    HStack(spacing: 4) {
                        Text(group.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            .accessibilityIdentifier("policy.card." + group.name)
                        Text(group.label)
                            .scaledFont(9, weight: .semibold) // r7 P3-4: follows Dynamic Type like the other badges
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                            .background(Capsule().fill(Theme.ink(0.1)))
                        if via != nil {
                            Image(systemName: "link").font(.caption2.weight(.bold)).foregroundStyle(Theme.accent)
                                .accessibilityLabel(Text("已设置前置代理"))
                        }
                        if group.pinned != nil {
                            Label("已固定", systemImage: "pin.fill")
                                .labelStyle(.titleAndIcon)
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .lineLimit(1)
                                .background(Capsule().fill(Theme.warn.opacity(0.18)))
                                .foregroundStyle(Theme.warn)
                        }
                        if smart?.wrappedValue == true {
                            Label("智能", systemImage: "sparkles")
                                .labelStyle(.titleAndIcon)
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .lineLimit(1)
                                .background(Capsule().fill(Theme.accent.opacity(0.18)))
                                .foregroundStyle(Theme.accent)
                        }
                    }
                    // Line 2 (= a rule row's link line): the path down to the node.
                    HStack(spacing: 6) {
                      if let chain {
                        // feat/policy-chain: 「日本节点 › 🇯🇵 东京 AZ JP01」; a long path gives way in the middle so the
                        // group's own pick and the final node both stay readable.
                        ChainLine(hops: PolicyChainText.parts(chain), font: .caption, label: PolicyChainText.text(chain))
                            .accessibilityIdentifier("policy.chain." + group.name)
                      } else {
                        Text(verbatim: FlagSafe.text(group.now ?? "—")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                      }
                        if chain == nil, let n = group.now, let r = resolved?(n), r.node != n {
                            Text(verbatim: Self.resolutionText(r)).font(.caption).foregroundStyle(.tertiary).lineLimit(1)
                                .accessibilityIdentifier("policy.via." + group.name)
                        }
                    }
                    // Line 3 (= a rule row's status line): delay of the current pick · member count.
                    HStack(spacing: 4) {
                        if let n = group.now, let d = delay(n) {
                            Text(Theme.delayText(d))
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(Theme.delayColor(d))
                                .accessibilityIdentifier("policy.delay." + group.name)
                            Text(verbatim: "·").font(.caption).foregroundStyle(.tertiary)
                        }
                        Text("\(group.members.count) 个成员").font(.caption).foregroundStyle(.secondary)
                    }
                    .lineLimit(1)
                }
                Spacer(minLength: 12)
                Button(action: onTest) {
                    Group {
                        if testing {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "speedometer").font(.body).foregroundStyle(.secondary)
                        }
                    }
                    .frame(width: PolicyRowMetrics.testTarget, height: PolicyRowMetrics.testTarget)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.trailing, -8) // the 44 pt target reaches into the card padding, the glyph stays aligned
                .accessibilityLabel(Text("测速"))
                .accessibilityIdentifier("policy.test." + group.name)
            }
            .padding(.vertical, PolicyRowMetrics.verticalPadding)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation(.spring(response: 0.3)) { expanded.toggle() } }
            .accessibilityAction(named: expanded ? Text("收起") : Text("展开")) { withAnimation(.spring(response: 0.3)) { expanded.toggle() } }
            // hotfix/group-longpress (device 2026-10-21 「长按策略组无法编辑」): the menu sat on the 34 pt icon only,
            // while the header's .onDrag (direct reorder) owned a long-press anywhere else, so it lifted the card
            // and showed nothing. The menu now covers the whole header; the drag still starts by moving the
            // finger out of the lifted menu preview (UIKit hands a context-menu lift over to the drag session).
            .contextMenu { headerMenu }
            .modifier(OptionalDrag(provider: onDrag))

            if expanded {
                if let smart {
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(isOn: smart) {
                            Label("智能选择", systemImage: "sparkles").font(.subheadline)
                        }
                        .tint(Theme.accent)
                        Text(smartInfo ?? String(localized: "开启后按近期延迟与失败记录综合评分，自动固定到最稳的节点；节点失效时会立即切走。"))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                }
                if let pinned = group.pinned, let onPin {
                    HStack(spacing: 8) {
                        Image(systemName: "pin.fill").font(.caption).foregroundStyle(Theme.warn)
                        Text("已固定到 \(pinned)").font(.subheadline).lineLimit(1)
                        Spacer()
                        Button("解除固定") { onPin(nil) }.font(.subheadline)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                } else if !group.selectable && smart?.wrappedValue != true {
                    Text(onPin != nil ? String(localized: "\(group.hint)。轻点节点可临时固定，自动选择暂停，直到解除固定。") : group.hint)
                        .font(.caption2).foregroundStyle(.secondary)
                }
                if let onEdit {
                    // fix/app-policy-ui #1: the header's 设置 button moved here (and stays in the long-press menu).
                    Button(action: onEdit) {
                        HStack(spacing: 8) {
                            Image(systemName: "slider.horizontal.3").font(.caption).foregroundStyle(.secondary)
                            Text("编辑策略组").font(.subheadline)
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("policy.edit." + group.name)
                }
                if let onChain {
                    Button(action: onChain) {
                        HStack(spacing: 8) {
                            Image(systemName: "link").font(.caption).foregroundStyle(via == nil ? Color.secondary : Theme.accent)
                            Text("前置代理").font(.subheadline)
                            Spacer()
                            Text(via ?? String(localized: "无")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                    }
                    .buttonStyle(.plain)
                }
                if let onIcon {
                    Button(action: onIcon) {
                        HStack(spacing: 8) {
                            Image(systemName: "photo").font(.caption).foregroundStyle(.secondary)
                            Text("图标").font(.subheadline)
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(.horizontal, 12)
        // fix/nc-ui-smooth: the members are rows of the page's LazyVStack (memberRow), not a grid inside this card —
        // a grid nested in one lazy row was built whole: expanding a 3000-node group built 3000 cells at once
        // (7 s of dropped frames in the simulator) and every later re-render of the page diffed them all again.
        // Expanded with members: the card continues into the rows below (square bottom corners, rows draw the rest).
        .padding(.bottom, expanded ? (group.members.isEmpty ? 12 : 2) : 0)
        .background(PolicyCardSegment(roundTop: true, roundBottom: !(expanded && !group.members.isEmpty)))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("policy.group." + group.name)
    }

    /// Rows of two member cells (LazyVGrid's former layout: 6 pt between the two columns).
    static let memberColumns = 2
    var memberRowCount: Int { (group.members.count + Self.memberColumns - 1) / Self.memberColumns }

    /// One row of members, drawn as the continuation of this card (the 8 pt gap of the page's LazyVStack above it is
    /// covered by its background). Only rows on screen are built.
    @ViewBuilder func memberRow(_ row: Int) -> some View {
        let first = row * Self.memberColumns
        let last = row == memberRowCount - 1
        HStack(alignment: .center, spacing: 6) {
            ForEach(first..<min(first + Self.memberColumns, group.members.count), id: \.self) { i in
                memberCell(group.members[i])
            }
            if first + 1 >= group.members.count {
                Color.clear.frame(maxWidth: .infinity, maxHeight: 1).accessibilityHidden(true)
            }
        }
        .padding(.horizontal, 12)
        .padding(.bottom, last ? 12 : 0)
        .background(PolicyCardSegment(roundTop: false, roundBottom: last).padding(.top, -PolicyCardSegment.rowGap))
    }

    @ViewBuilder private func memberCell(_ name: String) -> some View {
            NodeCell(name: name,
                     type: nodeType(name),
                     udp: nodeUDP(name),
                     delay: delay(name),
                     selected: group.now == name,
                     enabled: group.selectable || onPin != nil,
                     pinned: group.pinned == name,
                     badge: badge?(name),
                     via: resolved?(name).map(Self.resolutionText),
                     axID: "policy.member." + group.name + "." + name)
            .onTapGesture {
                if group.selectable { onSelect(name) }
                else if let onPin { onPin(group.pinned == name ? nil : name) }
            }
            .contextMenu {
                if let onProbe, !Self.unprobeable.contains(name) {
                    Button { onProbe(name) } label: { Label("出口与解锁检测", systemImage: "location.magnifyingglass") }
                }
                if let onPin {
                    if group.pinned == name {
                        Button { onPin(nil) } label: { Label("解除固定", systemImage: "pin.slash") }
                    } else {
                        Button { onPin(name) } label: { Label("固定此节点", systemImage: "pin") }
                    }
                }
                if let onShare, let t = nodeType(name), !Self.nonShareable.contains(t.lowercased()) {
                    Button { onShare(name) } label: { Label("分享节点", systemImage: "qrcode") }
                }
                if let onInteract, !interactions.isEmpty, !Self.unprobeable.contains(name) {
                    Menu {
                        ForEach(interactions, id: \.0) { it in
                            Button(it.1) { onInteract(it.0, name) }
                        }
                    } label: { Label("交互脚本", systemImage: "hand.tap") }
                }
            }

    }
}

/// fix/nc-ui-smooth: a piece of a 策略 group card. The header and the member rows below it are separate rows of the
/// page's LazyVStack; together they draw one card (continuous corners only at its top and bottom).
struct PolicyCardSegment: View {
    let roundTop: Bool
    let roundBottom: Bool
    /// The page LazyVStack's spacing, covered by each member row's background.
    static let rowGap: CGFloat = 8

    var body: some View {
        let r = Theme.radius
        ZStack {
            RoundedRectangle(cornerRadius: r, style: .continuous).fill(Theme.card)
            if !roundTop { Rectangle().fill(Theme.card).frame(height: r).frame(maxHeight: .infinity, alignment: .top) }
            if !roundBottom { Rectangle().fill(Theme.card).frame(height: r).frame(maxHeight: .infinity, alignment: .bottom) }
        }
        .accessibilityHidden(true)
    }
}

/// fix/app-policy-ui #4: the 策略 group row uses the metrics of a 分流规则 订阅 row (SubscriptionRow in an inset
/// List): 32 pt icon (SourceIcon), 12 pt icon–text spacing, 2 pt between lines, 11 pt vertical list-row padding.
enum PolicyRowMetrics {
    static let iconSize: CGFloat = 32
    static let iconTextSpacing: CGFloat = 12
    static let lineSpacing: CGFloat = 2
    static let verticalPadding: CGFloat = 11
    /// The 测速 button's hit target (Apple HIG minimum).
    static let testTarget: CGFloat = 44
}

struct NodeCell: View {
    let name: String
    let type: String?
    let udp: Bool
    let delay: Int?
    let selected: Bool
    let enabled: Bool
    var pinned: Bool = false
    var badge: (ok: Int, total: Int)? = nil
    /// hotfix/group-test-offline: a member group's current node (「→ 节点」 / 「最快 节点」), shown instead of 「策略组」.
    var via: String? = nil
    /// UI tests: `<axID>.delay` / `<axID>.via` on the delay and current-node texts.
    var axID: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(verbatim: FlagSafe.text(name))
                .font(.caption.weight(selected ? .semibold : .regular))
                .lineLimit(2)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .topLeading)
            HStack {
                if let via {
                    // Live member groups carry the core type (Selector / URLTest …), offline ones "group": both show
                    // the node they are on instead.
                    Text(verbatim: via).scaledFont(9, weight: .bold).foregroundStyle(.secondary).lineLimit(1)
                        .accessibilityIdentifier((axID ?? "node") + ".via")
                } else if let t = type {
                    if t == "group" {
                        Text("策略组").scaledFont(9, weight: .bold).foregroundStyle(.secondary)
                    } else {
                        ProtocolBadge(type: t)
                    }
                }
                if udp {
                    Text("UDP").scaledFont(9, weight: .bold).foregroundStyle(.secondary)
                }
                if let badge { UnlockBadge(ok: badge.ok, total: badge.total) }
                if pinned {
                    Image(systemName: "pin.fill").scaledFont(9, weight: .bold).foregroundStyle(Theme.warn)
                        .accessibilityLabel(Text("已固定"))
                }
                Spacer()
                Text(Theme.delayText(delay))
                    .scaledFont(11, weight: .semibold, monospacedDigit: true)
                    .foregroundStyle(Theme.delayColor(delay))
                    .accessibilityIdentifier((axID ?? "node") + ".delay")
            }
        }
        .padding(.horizontal, 9).padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(selected ? Theme.accent.opacity(0.16) : Theme.cardHi)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(selected ? Theme.accent : Color.clear, lineWidth: 1)
        )
        .opacity(enabled || selected ? 1 : 0.75)
    }
}

/// Which 测速 URL / timeout the bolt buttons use; set in 更多 → 测速.
struct TestTargetCaption: View {
    let live: Bool
    /// v0.17: a node with its own test URL (按节点设置) shows that one.
    var node: String? = nil
    var body: some View {
        let st = ControllerClient.testSettings
        let u = node.flatMap { NodeSettingsStore.customURL(for: $0) } ?? st.url
        let host = URL(string: u)?.host ?? u
        HStack(spacing: 6) {
            Image(systemName: "bolt.horizontal")
            Text(live ? "测速经由内核：\(host) · \(st.timeoutMs / 1000) 秒超时" : "离线测速：\(host) · \(st.timeoutMs / 1000) 秒超时")
                .lineLimit(1)
            Spacer()
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
    }
}

/// v0.15: compact stand-in for the automatic groups while 折叠自动策略 is on (tap to expand).
struct CollapsedAutoRow: View {
    let count: Int
    let onExpand: () -> Void
    var body: some View {
        Button(action: onExpand) {
            HStack(spacing: 10) {
                IconTile(symbol: "bolt.horizontal", tone: .accent)
                Text("\(count) 个自动策略已折叠").font(.subheadline)
                Spacer()
                Text("展开").font(.caption).foregroundStyle(.secondary)
                Image(systemName: "chevron.down").font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint(Text("展开自动策略"))
    }
}

/// v0.16: 规则 / 全局 / 直连 right above the policy cards, the same switch as Home's 出站模式 (DashboardModel.setMode:
/// saved in the overrides, applied live and connections reset while connected). Selection only, not a connection state.
/// v0.19.8 (user): 规则 / 直连 hide the GLOBAL card (it routes nothing then); 全局 shows it first.
/// fb-subs-global (user 「全局下，策略里下方的域名规则不需要显示」): in 全局 every connection goes through GLOBAL,
/// so the groups below it (the targets of the domain rules) route nothing. 全局 shows GLOBAL plus the group chain it
/// currently selects (GLOBAL → 节点选择 → …, so a node can still be picked inside it); 规则 shows them all again.
enum PolicyModeFilter {
    static func apply<T>(_ items: [T], mode: String, name: (T) -> String, now: (T) -> String? = { _ in nil }) -> [T] {
        let rest = items.filter { name($0) != "GLOBAL" }
        guard mode == "global" else { return rest }
        guard let global = items.first(where: { name($0) == "GLOBAL" }) else { return rest }
        var out = [global]
        var seen: Set<String> = ["GLOBAL"]
        var cur = now(global)
        while let c = cur, !seen.contains(c), let g = items.first(where: { name($0) == c }) {
            out.append(g)
            seen.insert(c)
            cur = now(g)
        }
        return out
    }

    /// How many groups 全局 hides (0 in the other modes).
    static func hiddenCount<T>(_ items: [T], mode: String, name: (T) -> String, now: (T) -> String? = { _ in nil }) -> Int {
        guard mode == "global", items.contains(where: { name($0) == "GLOBAL" }) else { return 0 }
        return items.count - apply(items, mode: mode, name: name, now: now).count
    }
}

/// 全局: one line saying the rule groups are hidden (not a connection state).
struct GlobalModeHiddenNote: View {
    let count: Int
    var body: some View {
        if count > 0 {
            Label("全局模式下所有连接走 GLOBAL，分流规则用的 \(count) 个策略组已隐藏；切回「规则」显示。", systemImage: "eye.slash")
                .font(.caption2).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 4)
                .accessibilityIdentifier("policy.globalHidden")
        }
    }
}

struct PolicyModeBar: View {
    @ObservedObject private var dash = DashboardModel.shared
    var body: some View {
        Picker("出站模式", selection: Binding(get: { dash.mode }, set: { m in Task { await dash.setMode(m) } })) {
            Text("规则").tag("rule")
            Text("全局").tag("global")
            Text("直连").tag("direct")
        }
        .pickerStyle(.segmented)
        .accessibilityIdentifier("policy.mode")
    }
}

/// feat/group-order: .onDrag only when a provider is given.
struct OptionalDrag: ViewModifier {
    let provider: (() -> NSItemProvider)?
    @ViewBuilder func body(content: Content) -> some View {
        if let provider { content.onDrag(provider) } else { content }
    }
}
