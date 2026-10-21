import SwiftUI
import Libmihomo

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
    @State private var tasks: [ScriptTaskState] = []
    @State private var prefs = TaskPrefs.load()
    @State private var loaded = false
    @State private var runningID: String?
    @State private var message: String?

    static let kinds = ["cron", "event", "interaction", "generic"]

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { !prefs.paused }, set: { prefs.paused = !$0; prefs.save(connected: vpn.isConnected) })) {
                    Label("自动运行", systemImage: "clock.badge.checkmark")
                }
                .disabled(tasks.isEmpty)
            } footer: {
                Text(vpn.isConnected
                     ? "关闭后定时和网络变化脚本都不会自动运行，手动运行不受影响。"
                     : "任务在 VPN 扩展里运行：连接后按计划执行，断开时不运行。开关和运行记录断开时也可以查看。")
            }
            .listRowBackground(Theme.card)

            ForEach(Self.kinds, id: \.self) { kind in
                let list = tasks.filter { $0.kind == kind }
                if !list.isEmpty {
                    Section {
                        ForEach(list) { t in
                            NavigationLink { TaskDetailView(task: t, prefs: $prefs) } label: { row(t) }
                                .swipeActions(edge: .trailing) {
                                    if kind != "interaction" {
                                        Button { run(t) } label: { Label("运行", systemImage: "play.fill") }
                                            .tint(Theme.accent)
                                            .disabled(!vpn.isConnected)
                                    }
                                }
                        }
                    } header: { Text(Self.title(kind)) } footer: {
                        if kind == "interaction" { Text("交互脚本在「策略」里长按节点运行，脚本收到所选节点的名称。") }
                    }
                    .listRowBackground(Theme.card)
                }
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
        .navigationTitle("任务")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await load() }
        .task {
            await load()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                // v0.12: the offline list only changes when modules change; poll only while connected.
                if VPNManager.shared.isConnected { await load() }
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

    @ViewBuilder func row(_ t: ScriptTaskState) -> some View {
        HStack(spacing: 12) {
            TaskIcon(task: t)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(t.script.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                    if let f = t.format { FormatBadge(format: f) }
                }
                if let c = t.cron, !c.isEmpty {
                    HStack(spacing: 6) {
                        Text(c).scaledFont(11, design: .monospaced)
                        if let n = t.nextRun, n > 0, prefs.isOn(t), !prefs.paused {
                            Text("下次 \(Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
                if let l = t.lastRun, l > 0 {
                    HStack(spacing: 4) {
                        Image(systemName: t.lastOK == true ? "checkmark.circle" : "xmark.octagon")
                            .foregroundStyle(t.lastOK == true ? Theme.good : Theme.bad)
                        Text("上次 \(Date(timeIntervalSince1970: l).formatted(.relative(presentation: .named)))\(t.duration.map { " · \($0) ms" } ?? "")")
                            .foregroundStyle(.secondary)
                    }
                    .font(.caption2)
                } else {
                    Text(t.source).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            if t.running == true || runningID == t.id {
                ProgressView().controlSize(.small)
            } else if t.kind == "cron" || t.kind == "event" {
                Toggle("", isOn: Binding(get: { prefs.isOn(t) }, set: { setOn(t, $0) }))
                    .labelsHidden()
                    .accessibilityLabel(Text(t.script.name))
            }
        }
        .padding(.vertical, 2)
        .opacity((t.kind == "cron" || t.kind == "event") && (!prefs.isOn(t) || prefs.paused) ? 0.55 : 1)
    }

    func setOn(_ t: ScriptTaskState, _ on: Bool) {
        var e = prefs.enabled ?? [:]
        // Store only what differs from the line's own enabled= so module edits keep working.
        if on == (t.disabledByLine != true) { e.removeValue(forKey: t.id) } else { e[t.id] = on }
        prefs.enabled = e.isEmpty ? nil : e
        prefs.save(connected: vpn.isConnected)
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

/// The task list while disconnected: parsed from the scripts and enabled modules by the Go core (the same
/// parser the tunnel uses), last results from the run log.
enum TaskCatalog {
    static func offline() async -> [ScriptTaskState] {
        let home = EnginePaths.dir.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoEngineTaskList(home) }.value
        guard var list = try? JSONDecoder().decode([ScriptTaskState].self, from: Data(json.utf8)) else { return [] }
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
        .navigationTitle("脚本通知")
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
