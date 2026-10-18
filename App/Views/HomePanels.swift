import SwiftUI

// feat/panels: script panels on Home.
// - Order = PanelsModel.pinned ("panels.pinned"); hidden ids stay pinned but are not shown on Home.
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
    private static let hiddenKey = "panels.home.hidden"
    private static let tasksKey = "panels.home.tasks"
    private static let namesKey = "panels.home.names"

    @Published var hidden: Set<String> = Set(UserDefaults.standard.stringArray(forKey: HomePanelStore.hiddenKey) ?? [])
    @Published var tasks: [TaskPanelPin] = {
        guard let d = UserDefaults.standard.data(forKey: HomePanelStore.tasksKey) else { return [] }
        return (try? JSONDecoder().decode([TaskPanelPin].self, from: d)) ?? []
    }()
    /// Last results written by the engine (panel-cache.json), keyed by panel id.
    @Published var cached: [String: PanelItem] = [:]
    /// Panel names seen while connected, so the editor can name pinned panels while disconnected.
    private var names: [String: String] = (UserDefaults.standard.dictionary(forKey: HomePanelStore.namesKey) as? [String: String]) ?? [:]

    private var model: PanelsModel { PanelsModel.shared }
    static var homeURL: URL { EnginePaths.dir.appendingPathComponent("home-panels.json") }
    static var cacheURL: URL { EnginePaths.dir.appendingPathComponent("panel-cache.json") }

    var visibleIDs: [String] { model.pinned.filter { !hidden.contains($0) } }

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
        if changed { UserDefaults.standard.set(names, forKey: Self.namesKey) }
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
        hidden.remove(t.id)
        savePinned()
    }

    func unpin(_ id: String) {
        model.pinned.removeAll { $0 == id }
        savePinned()
    }

    func setHidden(_ id: String, _ on: Bool) {
        if on { hidden.insert(id) } else { hidden.remove(id) }
        sync()
    }

    func move(from: IndexSet, to: Int) {
        model.pinned.move(fromOffsets: from, toOffset: to)
        savePinned()
    }

    func setInterval(_ taskID: String, _ seconds: Int) {
        guard let i = tasks.firstIndex(where: { $0.id == taskID }) else { return }
        tasks[i].interval = seconds
        sync()
    }

    private func savePinned() {
        UserDefaults.standard.set(model.pinned, forKey: "panels.pinned")
        sync()
    }

    /// Saves the Home configuration (UserDefaults + home-panels.json for the next connect) and, while
    /// connected, hands it to the running engine.
    func sync() {
        // drop pins / hidden ids that are no longer pinned
        tasks.removeAll { !model.pinned.contains($0.panelID) }
        hidden = hidden.filter { model.pinned.contains($0) }
        UserDefaults.standard.set(Array(hidden), forKey: Self.hiddenKey)
        if let d = try? JSONEncoder().encode(tasks) { UserDefaults.standard.set(d, forKey: Self.tasksKey) }
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
    @State private var editing = false
    @State private var editPanel: PanelItem?

    var body: some View {
        let items = home.visibleIDs.compactMap { home.item($0, connected: vpn.isConnected) }
        let rows = HomeRow.rows(home.visibleIDs) { home.item($0, connected: vpn.isConnected) }
        VStack(spacing: 14) {
            if !model.pinned.isEmpty {
                HStack {
                    Text("面板").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
                    if !vpn.isConnected && !items.isEmpty {
                        Text("上次结果").font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("编辑") { editing = true }.font(.footnote).buttonStyle(.borderless)
                }
                .padding(.horizontal, 4)
                .padding(.bottom, -6)
            }
            ForEach(rows) { row in
                switch row {
                case .panel(let e):
                    PanelCard(p: e.item, refreshing: e.live && (model.refreshing.contains(e.item.id) || e.item.running), offline: !e.live) {
                        Task { await model.refresh(e.item) }
                    }
                    .contextMenu {
                        Button { home.setHidden(e.item.id, true) } label: { Label("在首页隐藏", systemImage: "eye.slash") }
                        Button { editing = true } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                        PanelEditButton { editPanel = e.item }
                        Button(role: .destructive) { home.unpin(e.item.id) } label: { Label("取消固定", systemImage: "pin.slash") }
                    }
                case .wide(let t):
                    tile(t)
                case .pair(let a, let b):
                    HStack(alignment: .top, spacing: 12) {
                        tile(a)
                        if let b { tile(b) } else { Color.clear.frame(maxWidth: .infinity) }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            if model.pinned.isEmpty {
                // v0.19: the way in when nothing is pinned yet (built-in cards need no module).
                Button { editing = true } label: {
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
                    .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
                    .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
                }
                .buttonStyle(.plain)
            }
        }
        .sheet(isPresented: $editing) { HomePanelsEditor().environmentObject(vpn) }
        .sheet(item: $editPanel) { p in PanelEditSheet(p: p) }
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
    func tile(_ t: BuiltinTile) -> some View {
        BuiltinTileView(tile: t)
            .contextMenu {
                Button { home.setHidden(t.id, true) } label: { Label("在首页隐藏", systemImage: "eye.slash") }
                Button { editing = true } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                Button(role: .destructive) { home.unpin(t.id) } label: { Label("取消固定", systemImage: "pin.slash") }
            }
    }
}

// MARK: - Home editing

struct HomePanelsEditor: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model = PanelsModel.shared
    @ObservedObject var home = HomePanelStore.shared

    static var intervals: [(Int, LocalizedStringKey)] { [(0, "打开首页时"), (300, "每 5 分钟"), (900, "每 15 分钟"), (1800, "每 30 分钟"), (3600, "每小时")] }

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
                    Text("拖动调整顺序。关闭开关的面板保留固定，但不在首页显示，也不会在后台刷新。")
                }
                .listRowBackground(Theme.card)

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
                    Text("网速、流量、运行时长、出口 IP（默认打码）、内网 IP 和内存，由 App 绘制，不需要模块。两张小卡片并排显示。")
                }
                .listRowBackground(Theme.card)

                Section {
                    if vpn.isConnected {
                        NavigationLink { PanelsView() } label: { Label("全部面板", systemImage: "square.grid.2x2") }
                    }
                    NavigationLink { ScriptTasksView() } label: { Label("脚本任务", systemImage: "terminal") }
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
        }
    }

    @ViewBuilder
    func row(_ id: String) -> some View {
        if let t = BuiltinTile.from(id) {
            HStack(spacing: 10) {
                Image(systemName: t.icon).foregroundStyle(Theme.accent).frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: t.title).font(.subheadline).lineLimit(1)
                    Text("内置卡片").font(.caption2).foregroundStyle(.secondary)
                }
                Spacer(minLength: 6)
                Toggle("在首页显示", isOn: Binding(get: { !home.hidden.contains(id) }, set: { home.setHidden(id, !$0) }))
                    .labelsHidden()
            }
            .accessibilityIdentifier("homepanels.row.\(t.rawValue)")
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
                Text(home.name(id) ?? String(localized: "不可用的面板")).font(.subheadline).lineLimit(1)
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
            Toggle("在首页显示", isOn: Binding(get: { !home.hidden.contains(id) }, set: { home.setHidden(id, !$0) }))
                .labelsHidden()
        }
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
