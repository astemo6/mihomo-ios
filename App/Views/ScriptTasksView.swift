import SwiftUI

// MARK: - Models (/mitm/tasks, /mitm/panels, /mitm/notifications, replay)

struct ScriptTaskState: Decodable, Identifiable, Hashable {
    struct ScriptInfo: Decodable, Hashable {
        var name: String
        var path: String
        var timeout: Int?
    }
    var id: String
    var kind: String
    var cron: String?
    var event: String?
    var script: ScriptInfo
    var source: String
    var line: String
    var format: String?
    var nextRun: Double?
    var lastRun: Double?
    var lastOK: Bool?
    var lastResult: String?
    var duration: Int64?
    var running: Bool?
    // v0.11
    var icon: String?
    var disabledByLine: Bool?
    var enabled: Bool?
}

struct PanelItem: Decodable, Identifiable, Hashable {
    var id: String
    var name: String
    var title: String?
    var content: String?
    var style: String?
    var icon: String?
    var iconColor: String?
    var script: String?
    var interval: Int?
    var source: String
    var format: String
    var updated: Double?
    var error: String?
    var running: Bool
    var backgroundColor: String?
    /// v0.17: the module's interval when the user's override replaced it in the engine.
    var defaultInterval: Int? = nil
    var intervalOverridden: Bool? = nil
}

struct ScriptNotice: Decodable, Hashable {
    var time: Double
    var script: String
    var title: String
    var subtitle: String?
    var body: String?
    var url: String?
}

struct ReplayResult: Decodable {
    var id: Int64
    var status: Int
    var headers: [String: String]
    var body: String?
    var binary: Int?
    var length: Int
    var duration: Double
    var error: String?
    /// r7: the body was longer than the engine's cap and shows only its beginning.
    var truncated: Bool?
}

struct TaskRunResult: Decodable {
    var ok: Bool
    var error: String?
    var result: [String: JSONValue]?
}

/// A loosely typed JSON value ($done objects of UI scripts).
enum JSONValue: Decodable, Hashable {
    case string(String), number(Double), bool(Bool), other
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) { self = .string(s) }
        else if let d = try? c.decode(Double.self) { self = .number(d) }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else { self = .other }
    }
    var text: String? {
        switch self {
        case .string(let s): return s
        case .number(let d): return d.rounded() == d && abs(d) < 1e15 ? String(Int64(d)) : String(d)
        case .bool(let b): return b ? "true" : "false"
        case .other: return nil
        }
    }
}

/// One entry of a task's run log (engine task-history.json, v0.11).
struct TaskRunRecord: Decodable, Hashable {
    var time: Double
    var ok: Bool
    var duration: Int64
    var trigger: String
    var result: String?
    var logs: [String]?
}

/// Master switch + per-task on/off (engine task-prefs.json). The app owns this file; while connected
/// the extension is told too (PUT /mitm/tasks-prefs).
struct TaskPrefs: Codable, Equatable {
    var paused = false
    var enabled: [String: Bool]? = nil
    /// 2026-10-23 「也都要可以手动调顺序」: task ids in the user's order — the list order, and the order tasks due at the
    /// same moment are started in (bridge mitm.OrderTasks).
    var order: [String]? = nil
    /// Tasks of a subscription (module) the user deleted from the list: never run, hidden until 恢复已删除的任务. The
    /// module itself is not changed.
    var deleted: [String: Bool]? = nil

    static var url: URL { EnginePaths.dir.appendingPathComponent("task-prefs.json") }
    static func load() -> TaskPrefs {
        guard let d = try? Data(contentsOf: url), let p = try? JSONDecoder().decode(TaskPrefs.self, from: d) else { return TaskPrefs() }
        return p
    }
    func save(connected: Bool) {
        guard let d = try? JSONEncoder().encode(self) else { return }
        try? d.write(to: Self.url, options: .atomic)
        guard connected, let obj = try? JSONSerialization.jsonObject(with: d) else { return }
        Task { _ = try? await ControllerClient.shared.send("/mitm/tasks-prefs", method: "PUT", body: obj) }
    }
    func isOn(_ t: ScriptTaskState) -> Bool {
        if deleted?[t.id] == true { return false }
        if let v = enabled?[t.id] { return v }
        return t.disabledByLine != true
    }
}

enum TaskHistory {
    static var url: URL { EnginePaths.dir.appendingPathComponent("task-history.json") }
    static func load(_ id: String) -> [TaskRunRecord] {
        guard let d = try? Data(contentsOf: url), let m = try? JSONDecoder().decode([String: [TaskRunRecord]].self, from: d) else { return [] }
        return (m[id] ?? []).reversed()
    }
}

extension ControllerClient {
    func mitmTasks() async throws -> [ScriptTaskState] { try await get([ScriptTaskState].self, "/mitm/tasks") }
    func mitmRunTask(_ id: String, params: String? = nil) async throws -> TaskRunResult {
        let d = try await send("/mitm/tasks/\(ControllerClient.enc(id))/run", method: "POST", body: params.map { ["params": $0] }, timeout: 310)
        return try JSONDecoder().decode(TaskRunResult.self, from: d)
    }
    func mitmTaskHistory(_ id: String) async throws -> [TaskRunRecord] {
        try await get([TaskRunRecord].self, "/mitm/tasks/\(ControllerClient.enc(id))/history").reversed()
    }
    func mitmPanels() async throws -> [PanelItem] { try await get([PanelItem].self, "/mitm/panels") }
    func mitmRefreshPanel(_ id: String) async throws -> PanelItem {
        let d = try await send("/mitm/panels/\(ControllerClient.enc(id))/refresh", method: "POST", timeout: 70)
        return try JSONDecoder().decode(PanelItem.self, from: d)
    }
    func mitmNotifications() async throws -> [ScriptNotice] { try await get([ScriptNotice].self, "/mitm/notifications") }
    func mitmReplay(_ id: Int64, edit: [String: Any]?) async throws -> ReplayResult {
        let d = try await send("/mitm/requests/\(id)/replay", method: "POST", body: edit, timeout: 40)
        return try JSONDecoder().decode(ReplayResult.self, from: d)
    }
}

/// Notification history is a file in the App Group container, so it is readable while disconnected too.
enum NoticeHistory {
    static var url: URL { EnginePaths.dir.appendingPathComponent("notifications.json") }
    static func load() -> [ScriptNotice] {
        guard let d = try? Data(contentsOf: url), let l = try? JSONDecoder().decode([ScriptNotice].self, from: d) else { return [] }
        return l.reversed()
    }
    static func clear() { try? FileManager.default.removeItem(at: url) }
}

// MARK: - 任务（定时 / 网络变化 / 交互 / 通用）, v0.11 QX-style list

struct ScriptTasksView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var res = ResourceStore.shared
    @ObservedObject private var store = EngineStore.shared
    @State private var tasks: [ScriptTaskState] = []
    @State private var prefs = TaskPrefs.load()
    @State private var loaded = false
    @State private var runningID: String?
    @State private var message: String?
    @State private var detail: ScriptTaskState?
    @State private var pendingDelete: ScriptTaskState?
    @State private var editingModule: EngineModule?
    @State private var editingScript: EngineItem?
    @State private var updatingAll = false
    /// 调整顺序 (⋯ menu, 2026-10-23): edit mode with drag handles, the same as 重写 and 规则.
    @State private var editMode: EditMode = .inactive

    static let kinds = ["cron", "event", "interaction", "generic"]

    /// The tasks shown: 删除 ones hidden, in the user's order.
    var visible: [ScriptTaskState] {
        ManualOrder.apply(tasks.filter { prefs.deleted?[$0.id] != true }, order: prefs.order ?? []) { $0.id }
    }

    var deletedCount: Int { tasks.filter { prefs.deleted?[$0.id] == true }.count }

    var body: some View {
        let shown = visible
        return List {
            Section {
                Toggle(isOn: Binding(get: { !prefs.paused }, set: { prefs.paused = !$0; prefs.save(connected: vpn.isConnected) })) {
                    Label("自动运行", systemImage: "clock.badge.checkmark")
                }
                .disabled(tasks.isEmpty)
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(vpn.isConnected
                         ? "关闭后定时和网络变化脚本都不会自动运行，手动运行不受影响。"
                         : "任务在 VPN 扩展里运行：连接后按计划执行，断开时不运行。开关和运行记录断开时也可以查看。")
                    if !tasks.isEmpty {
                        Text("同一时间触发的任务按列表顺序启动。在 ⋯ 里选「调整顺序」后拖动排序。右滑更新或运行，左滑删除或编辑；长按查看全部操作。")
                    }
                }
            }
            .listRowBackground(Theme.card)

            ForEach(Self.kinds, id: \.self) { kind in
                let list = shown.filter { $0.kind == kind }
                if !list.isEmpty {
                    Section {
                        ForEach(list) { t in row(t) }
                            .onMove(perform: mover(kind))
                    } header: { Text(Self.title(kind)) } footer: {
                        if kind == "interaction" { Text("交互脚本在「策略」里长按节点运行，脚本收到所选节点的名称。") }
                    }
                    .listRowBackground(Theme.card)
                }
            }
            if deletedCount > 0 && !editMode.isEditing {
                Section {
                    Button {
                        prefs.deleted = nil
                        prefs.save(connected: vpn.isConnected)
                    } label: {
                        Label("恢复已删除的任务（\(deletedCount)）", systemImage: "arrow.uturn.backward")
                    }
                    .accessibilityIdentifier("tasks.restoreDeleted")
                }
                .listRowBackground(Theme.card)
            }
            if loaded && tasks.isEmpty {
                Section {
                    EmptyStateRow(icon: "clock.arrow.circlepath", title: "没有任务", message: "在模块或「脚本」里添加定时、网络变化或交互脚本，例如：") {
                        Text("签到 = type=cron,cronexp=\"0 8 * * *\",script-path=…\ncron \"0 8 * * *\" script-path=…, tag=签到\n0 8 * * * https://…/a.js, tag=签到\nevent-interaction https://…/b.js, tag=查询")
                            .font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .accessibilityIdentifier("scriptTasksView")
        .navigationTitle("定时任务") // ui-audit: same name as the 工具 card
        .navigationBarTitleDisplayMode(.inline)
        .environment(\.editMode, $editMode)
        .toolbar {
            if editMode.isEditing {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { withAnimation { editMode = .inactive } }
                        .accessibilityIdentifier("tasks.reorderDone")
                }
            } else {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    UpdateAllButton(busy: updatingAll || res.updatingAll, id: "tasks.updateAll") { Task { await updateAll() } }
                    Menu {
                        Button { withAnimation { editMode = .active } } label: { Label("调整顺序", systemImage: "arrow.up.arrow.down") }
                            .disabled(shown.count < 2)
                    } label: { Image(systemName: "ellipsis.circle") }
                        .accessibilityIdentifier("tasks.more")
                }
            }
        }
        .navigationDestination(isPresented: Binding(get: { detail != nil }, set: { if !$0 { detail = nil } })) {
            if let t = detail { TaskDetailView(task: t, prefs: $prefs) }
        }
        .sheet(item: $editingModule, onDismiss: { res.reload(); Task { await load() } }) { m in
            ModuleSubSheet(module: m) { d in store.deleteModule(d); res.reload() }
        }
        .sheet(item: $editingScript, onDismiss: { Task { await load() } }) { ScriptFormSheet(item: $0) }
        .deleteConfirmation({ t in Text("删除「\(t.script.name)」？") }, item: $pendingDelete,
                            message: { t in Self.isLocal(t) ? DeleteText.recoverable : Text("只从任务列表移除，它不再自动运行；订阅本身不会改动。可以在列表底部「恢复已删除的任务」找回。") },
                            id: "tasks.confirmDelete") { t in delete(t) }
        .refreshable { await load() }
        .task {
            await load()
            await res.reloadInBackground()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                // v0.12: the offline list only changes when modules change; poll only while connected.
                if VPNManager.shared.isConnected && !editMode.isEditing { await load() }
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    static func title(_ kind: String) -> LocalizedStringKey {
        switch kind {
        case "cron": return "定时"
        case "event": return "网络变化时"
        case "interaction": return "交互"
        default: return "通用"
        }
    }

    static func symbol(_ kind: String) -> String {
        switch kind {
        case "cron": return "clock"
        case "event": return "wifi"
        case "interaction": return "hand.tap"
        default: return "curlybraces"
        }
    }

    /// A task of the user's own script lines (engine.json `scripts`, source 用户): 删除 removes the line.
    static func isLocal(_ t: ScriptTaskState) -> Bool { t.source == "用户" }

    /// The task's remote script in the resource list (更新 / 更新于).
    func resource(_ t: ScriptTaskState) -> ResourceItem? {
        res.items.first { $0.kind == "script" && $0.url == t.script.path }
    }

    static func switchable(_ t: ScriptTaskState) -> Bool { t.kind == "cron" || t.kind == "event" }

    @ViewBuilder func row(_ t: ScriptTaskState) -> some View {
        let item = resource(t)
        let busy = t.running == true || runningID == t.id || (item.map { res.busy.contains($0.key) } ?? false)
        let on = prefs.isOn(t)
        let canSwitch = Self.switchable(t)
        let off = canSwitch && (!on || prefs.paused)
        let setter: ((Bool) -> Void)? = canSwitch ? { v in setOn(t, v) } : nil
        SubscriptionRow(id: "task.row." + t.script.name, icon: Self.symbol(t.kind), color: Theme.accent, customIcon: t.icon,
                        name: t.script.name,
                        status: SubscriptionStatus(source: Self.isLocal(t) ? "" : t.source, remote: item != nil,
                                                   updated: item.flatMap { $0.updatedAt > 0 ? Date(timeIntervalSince1970: $0.updatedAt) : nil },
                                                   interval: item?.interval ?? 0,
                                                   error: item?.error ?? (t.lastOK == false ? t.lastResult : nil),
                                                   disabled: canSwitch && !on,
                                                   downloaded: item.map { $0.updatedAt > 0 }),
                        details: details(t, off: off),
                        updating: busy,
                        enabled: canSwitch ? Binding(get: { prefs.isOn(t) }, set: { setOn(t, $0) }) : nil,
                        onTap: { detail = t }) {
            if let f = t.format { FormatBadge(format: f) }
        }
        .opacity(canSwitch && prefs.paused ? 0.55 : 1)
        .subscriptionActions(SubscriptionActions(
            update: item != nil && !busy ? { Task { await updateOne(t) } } : nil,
            edit: { edit(t) },
            url: item?.url ?? (t.script.path.hasPrefix("http") ? t.script.path : nil),
            enabled: canSwitch ? on : nil, setEnabled: setter,
            delete: { pendingDelete = t },
            extras: t.kind == "interaction" ? [] : [
                SubscriptionExtraAction(title: "运行", icon: "play.fill", disabled: !vpn.isConnected || busy) { run(t) },
            ]))
    }

    /// Schedule / next run, then the last run (「上次 X · N ms」).
    func details(_ t: ScriptTaskState, off: Bool) -> [String] {
        var out: [String] = []
        if let c = t.cron, !c.isEmpty {
            if let n = t.nextRun, n > 0, !off {
                out.append(c + " · " + String(localized: "下次 \(Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .shortened))"))
            } else {
                out.append(c)
            }
        }
        if let l = t.lastRun, l > 0 {
            let rel = Date(timeIntervalSince1970: l).formatted(.relative(presentation: .named))
            let dur = t.duration.map { " · \($0) ms" } ?? ""
            out.append((t.lastOK == true ? "✓ " : "✗ ") + String(localized: "上次 \(rel)\(dur)"))
        }
        return out
    }

    /// Drag handles only in 调整顺序 (no long-press drag that would fight the row's menu).
    func mover(_ kind: String) -> ((IndexSet, Int) -> Void)? {
        guard editMode.isEditing else { return nil }
        return { from, to in moveTasks(kind, from, to) }
    }

    func moveTasks(_ kind: String, _ from: IndexSet, _ to: Int) {
        let all = visible
        let section = all.filter { $0.kind == kind }
        let ordered = ManualOrder.moved(all, visible: section, from: from, to: to) { $0.id }
        prefs.order = ordered.map(\.id)
        prefs.save(connected: vpn.isConnected)
        tasks = ManualOrder.apply(tasks, order: prefs.order ?? []) { $0.id }
    }

    func setOn(_ t: ScriptTaskState, _ on: Bool) {
        var e = prefs.enabled ?? [:]
        // Store only what differs from the line's own enabled= so module edits keep working.
        if on == (t.disabledByLine != true) { e.removeValue(forKey: t.id) } else { e[t.id] = on }
        prefs.enabled = e.isEmpty ? nil : e
        prefs.save(connected: vpn.isConnected)
    }

    /// 编辑: a local script line opens its form; a subscription's task opens that subscription's sheet.
    func edit(_ t: ScriptTaskState) {
        if Self.isLocal(t), let it = store.config.scripts.first(where: { Self.sameLine($0.line, t.line) }) {
            editingScript = it
        } else if let m = store.config.modules.first(where: { $0.name == t.source }) {
            editingModule = m
        } else {
            detail = t
        }
    }

    static func sameLine(_ a: String, _ b: String) -> Bool {
        a.trimmingCharacters(in: .whitespacesAndNewlines) == b.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 删除: the user's own line is removed; a subscription's task is hidden (task-prefs.json `deleted`).
    func delete(_ t: ScriptTaskState) {
        if Self.isLocal(t), store.config.scripts.contains(where: { Self.sameLine($0.line, t.line) }) {
            store.config.scripts.removeAll { Self.sameLine($0.line, t.line) }
            store.save()
            tasks.removeAll { $0.id == t.id }
        } else {
            var d = prefs.deleted ?? [:]
            d[t.id] = true
            prefs.deleted = d
            prefs.save(connected: vpn.isConnected)
        }
        Task {
            try? await Task.sleep(nanoseconds: 600_000_000)
            await load()
        }
    }

    func updateOne(_ t: ScriptTaskState) async {
        guard let it = resource(t) else { return }
        await res.update(it)
        await load()
    }

    /// 全部更新: the remote scripts of the listed tasks.
    func updateAll() async {
        guard !updatingAll else { return }
        updatingAll = true
        defer { updatingAll = false }
        await res.reloadInBackground()
        let urls = Set(visible.map(\.script.path))
        let list = res.items.filter { $0.kind == "script" && $0.isRemote && $0.enabled && urls.contains($0.url) }
        let failed = await res.updateItems(list)
        res.message = nil
        message = failed == 0 ? String(localized: "已全部更新") : String(localized: "\(failed) 项更新失败，详见列表")
        await load()
    }

    func load() async {
        prefs = TaskPrefs.load()
        if vpn.isConnected, let l = try? await ControllerClient.shared.mitmTasks() {
            tasks = l
        } else {
            tasks = await TaskCatalog.offline()
        }
        loaded = true
    }

    func run(_ t: ScriptTaskState) {
        guard runningID == nil else { return }
        guard VPNManager.shared.isConnected else {
            message = String(localized: "连接后才能运行任务。")
            return
        }
        runningID = t.id
        Task {
            defer { runningID = nil }
            do {
                let r = try await ControllerClient.shared.mitmRunTask(t.id)
                if !r.ok { message = r.error ?? String(localized: "运行失败") }
            } catch { message = error.localizedDescription }
            await load()
        }
    }
}

/// The task list while disconnected: parsed from the scripts and enabled modules by NCEngineTaskList (the
/// Swift module parser, ids as the tunnel's script manifest has them), last results from the run log.
enum TaskCatalog {
    static func offline() async -> [ScriptTaskState] {
        let home = AppShared.homeURL.path
        let order = TaskPrefs.load().order ?? []
        let parsed = await Task.detached(priority: .userInitiated) { NCEngineTaskList.tasks(home: home, order: order) }.value
        var list = parsed.map { t in
            ScriptTaskState(id: t.id, kind: t.kind, cron: t.cron, event: t.event,
                            script: .init(name: t.name, path: t.path, timeout: t.script?.timeout ?? 30),
                            source: t.source, line: t.line, format: t.format.isEmpty ? nil : t.format,
                            icon: t.icon.isEmpty ? nil : t.icon, disabledByLine: t.disabledByLine ? true : nil)
        }
        for i in list.indices {
            if let last = TaskHistory.load(list[i].id).first {
                list[i].lastRun = last.time
                list[i].lastOK = last.ok
                list[i].duration = last.duration
                list[i].lastResult = last.result
            }
        }
        return list
    }

    /// Interaction tasks for the node menu (live list while connected).
    static func interactions() async -> [ScriptTaskState] {
        if let l = try? await ControllerClient.shared.mitmTasks() { return l.filter { $0.kind == "interaction" } }
        return []
    }
}

struct TaskIcon: View {
    let task: ScriptTaskState
    var body: some View {
        Group {
            if let ic = task.icon, !ic.isEmpty {
                RemoteIcon(url: ic, size: 30)
            } else {
                Image(systemName: ScriptTasksView.symbol(task.kind))
                    .font(.body.weight(.semibold))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 30, height: 30)
                    .background(Circle().fill(Theme.accent.opacity(0.14)))
            }
        }
        .accessibilityHidden(true)
    }
}

struct TaskDetailView: View {
    @EnvironmentObject var vpn: VPNManager
    let task: ScriptTaskState
    @Binding var prefs: TaskPrefs
    @State private var history: [TaskRunRecord] = []
    @State private var running = false
    @State private var result: TaskResultItem?
    @State private var message: String?
    @State private var nodes: [String] = []
    @State private var node = ""

    var body: some View {
        List {
            Section {
                HStack(spacing: 12) {
                    TaskIcon(task: task)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(task.script.name).font(.headline)
                        HStack(spacing: 6) {
                            KindBadge(kind: task.kind)
                            if let f = task.format { FormatBadge(format: f) }
                        }
                    }
                }
                if let c = task.cron, !c.isEmpty { info("计划", c, mono: true) }
                info("来源", task.source)
                info("脚本", task.script.path, mono: true)
                if let n = task.nextRun, n > 0, prefs.isOn(task), !prefs.paused {
                    info("下次运行", Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .shortened))
                }
            }
            .listRowBackground(Theme.card)

            Section {
                if task.kind == "interaction" {
                    if nodes.isEmpty {
                        Text(vpn.isConnected ? "正在读取节点…" : "连接后可以选择节点运行。").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Picker("节点", selection: $node) {
                            ForEach(nodes, id: \.self) { Text($0).tag($0) }
                        }
                    }
                }
                Button {
                    run()
                } label: {
                    HStack {
                        Label("立即运行", systemImage: "play.fill")
                        Spacer()
                        if running { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(!vpn.isConnected || running || (task.kind == "interaction" && node.isEmpty))
            } footer: {
                if !vpn.isConnected { Text("脚本在 VPN 扩展里运行，连接后才能运行。") }
            }
            .listRowBackground(Theme.card)

            TaskPinSection(task: task, node: node) // feat/panels

            Section {
                if history.isEmpty {
                    Text("还没有运行记录。每个任务保留最近 10 次。").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(history, id: \.self) { r in
                    TaskRunRow(record: r)
                }
            } header: { Text("运行记录") }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(task.script.name)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await loadHistory() }
        .task {
            await loadHistory()
            if task.kind == "interaction" { await loadNodes() }
        }
        .sheet(item: $result) { TaskResultSheet(item: $0) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    func info(_ title: LocalizedStringKey, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).font(.footnote).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).font(mono ? .caption.monospaced() : .footnote).multilineTextAlignment(.trailing).lineLimit(3).textSelection(.enabled)
        }
    }

    func loadHistory() async {
        if vpn.isConnected, let h = try? await ControllerClient.shared.mitmTaskHistory(task.id) {
            history = h
        } else {
            history = TaskHistory.load(task.id)
        }
    }

    func loadNodes() async {
        guard vpn.isConnected, let p = try? await ControllerClient.shared.proxies() else { return }
        let skip: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]
        nodes = p.values.filter { $0.all == nil && !skip.contains($0.name) && $0.hidden != true }.map(\.name).sorted()
        if node.isEmpty { node = nodes.first ?? "" }
    }

    func run() {
        running = true
        Task {
            defer { running = false }
            do {
                let r = try await ControllerClient.shared.mitmRunTask(task.id, params: task.kind == "interaction" ? node : nil)
                if !r.ok {
                    message = r.error ?? String(localized: "运行失败")
                } else if let item = TaskResultItem(title: task.script.name, result: r.result) {
                    result = item
                }
            } catch { message = error.localizedDescription }
            await loadHistory()
        }
    }
}

struct TaskRunRow: View {
    let record: TaskRunRecord
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: record.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                    .foregroundStyle(record.ok ? Theme.good : Theme.bad)
                Text(Date(timeIntervalSince1970: record.time).formatted(date: .abbreviated, time: .standard)).font(.footnote.monospacedDigit())
                Text(Self.trigger(record.trigger)).font(.caption2.weight(.semibold))
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                    .background(Capsule().fill(Theme.ink(0.08)))
                Spacer()
                Text("\(record.duration) ms").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
            }
            if let r = record.result, !r.isEmpty {
                Text(r).scaledFont(10, design: .monospaced).foregroundStyle(record.ok ? Color.secondary : Theme.bad).lineLimit(expanded ? nil : 2)
            }
            if let logs = record.logs, !logs.isEmpty {
                DisclosureGroup(isExpanded: $expanded) {
                    Text(logs.joined(separator: "\n"))
                        .scaledFont(10, design: .monospaced)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    Text("日志 \(logs.count) 行").font(.caption2)
                }
            }
        }
        .padding(.vertical, 2)
    }

    static func trigger(_ t: String) -> LocalizedStringKey {
        switch t {
        case "schedule": return "定时"
        case "event": return "网络变化"
        case "interaction": return "交互"
        default: return "手动"
        }
    }
}

/// What a UI script handed to $done: QX {title, message | htmlMessage}, Surge-style {title, content}.
struct TaskResultItem: Identifiable {
    let id = UUID()
    let title: String
    let message: String

    init?(title: String, result: [String: JSONValue]?) {
        guard let r = result else { return nil }
        let t = r["title"]?.text
        var m = r["message"]?.text ?? r["content"]?.text ?? r["body"]?.text
        if m == nil, let html = r["htmlMessage"]?.text { m = Self.plain(html) }
        guard let msg = m, !msg.isEmpty else { return nil }
        self.title = (t?.isEmpty == false ? t : nil) ?? title
        self.message = msg
    }

    /// HTML → readable text (UI scripts often answer with simple <br>/<p> markup).
    static func plain(_ html: String) -> String {
        var s = html.replacingOccurrences(of: "<br\\s*/?>", with: "\n", options: [.regularExpression, .caseInsensitive])
        s = s.replacingOccurrences(of: "</(p|div|li|tr|h[1-6])>", with: "\n", options: [.regularExpression, .caseInsensitive])
        s = s.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
        for (a, b) in [("&nbsp;", " "), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&amp;", "&")] {
            s = s.replacingOccurrences(of: a, with: b)
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

struct TaskResultSheet: View {
    let item: TaskResultItem
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            ScrollView {
                Text(item.message)
                    .font(.callout)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
                    .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                    .padding()
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(item.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

/// Runs a QX interaction script on a node (策略 → long-press a node).
struct InteractionRunner: ViewModifier {
    @Binding var request: InteractionRequest?
    @State private var result: TaskResultItem?
    @State private var message: String?

    func body(content: Content) -> some View {
        content
            .onChange(of: request?.id) { _ in
                guard let r = request else { return }
                Task {
                    defer { request = nil }
                    do {
                        let out = try await ControllerClient.shared.mitmRunTask(r.task.id, params: r.node)
                        if !out.ok { message = out.error ?? String(localized: "运行失败") }
                        else { result = TaskResultItem(title: r.task.script.name, result: out.result) ?? TaskResultItem(title: r.task.script.name, result: ["message": .string(String(localized: "已运行，脚本没有返回内容。"))]) }
                    } catch { message = error.localizedDescription }
                }
            }
            .sheet(item: $result) { TaskResultSheet(item: $0) }
            .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(message ?? "") }
    }
}

struct InteractionRequest: Identifiable, Equatable {
    let id = UUID()
    let task: ScriptTaskState
    let node: String
    static func == (a: InteractionRequest, b: InteractionRequest) -> Bool { a.id == b.id }
}

struct FormatBadge: View {
    let format: String
    var body: some View {
        Text(format.uppercased() == "QX" ? "QX" : format.capitalized)
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().stroke(Color.secondary.opacity(0.5)))
            .foregroundStyle(.secondary)
    }
}

// MARK: - Notification history

struct ScriptNoticesView: View {
    @State private var items: [ScriptNotice] = []
    var body: some View {
        List {
            if items.isEmpty {
                Text("还没有脚本通知。脚本调用 $notification.post / $notify 时，扩展会弹出本地通知并记录在这里（最近 100 条）。")
                    .font(.footnote).foregroundStyle(.secondary)
                    .listRowBackground(Theme.card)
            }
            ForEach(items, id: \.self) { n in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(n.title.isEmpty ? n.script : n.title).font(.subheadline.weight(.semibold)).lineLimit(1)
                        Spacer()
                        Text(Date(timeIntervalSince1970: n.time).formatted(date: .omitted, time: .shortened)).font(.caption2).foregroundStyle(.secondary)
                    }
                    if let s = n.subtitle, !s.isEmpty { Text(s).font(.caption) }
                    if let b = n.body, !b.isEmpty { Text(b).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    HStack {
                        Text(n.script).font(.caption2).foregroundStyle(.secondary)
                        if let u = n.url, let url = URL(string: u), !u.isEmpty {
                            Spacer()
                            Link(destination: url) { Label("打开链接", systemImage: "arrow.up.right.square").font(.caption2) }
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("脚本通知记录") // ui-audit: same name as the rows that open it
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(role: .destructive) { NoticeHistory.clear(); items = [] } label: { Image(systemName: "trash") }
                    .disabled(items.isEmpty)
            }
        }
        .onAppear { items = NoticeHistory.load() }
        .refreshable { items = NoticeHistory.load() }
    }
}
