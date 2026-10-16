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
    var lastOK: Bool
    var lastResult: String?
    var duration: Int64?
    var running: Bool
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
}

struct TaskRunResult: Decodable {
    var ok: Bool
    var error: String?
}

extension ControllerClient {
    func mitmTasks() async throws -> [ScriptTaskState] { try await get([ScriptTaskState].self, "/mitm/tasks") }
    func mitmRunTask(_ id: String) async throws -> TaskRunResult {
        let d = try await send("/mitm/tasks/\(ControllerClient.enc(id))/run", method: "POST", timeout: 310)
        return try JSONDecoder().decode(TaskRunResult.self, from: d)
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

// MARK: - 定时 / 事件 / 通用脚本

struct ScriptTasksView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var tasks: [ScriptTaskState] = []
    @State private var loaded = false
    @State private var runningID: String?
    @State private var message: String?

    var body: some View {
        List {
            if !vpn.isConnected {
                Section {
                    Label("定时与事件脚本在扩展里运行：连接后按计划执行，断开时不运行。", systemImage: "info.circle")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .listRowBackground(Theme.card)
            }
            ForEach(["cron", "event", "generic"], id: \.self) { kind in
                let list = tasks.filter { $0.kind == kind }
                if !list.isEmpty {
                    Section(header: Text(Self.title(kind))) {
                        ForEach(list) { t in row(t) }
                    }
                    .listRowBackground(Theme.card)
                }
            }
            if loaded && tasks.isEmpty && vpn.isConnected {
                Section {
                    EmptyStateRow(icon: "clock.arrow.circlepath", title: "没有定时 / 事件 / 通用脚本", message: "在模块或「脚本」里添加，例如：") {
                        Text("签到 = type=cron,cronexp=\"0 8 * * *\",script-path=…\ncron \"0 8 * * *\" script-path=…, tag=签到\n0 8 * * * https://…/a.js, tag=签到")
                            .font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("定时与事件")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await load() }
        .task {
            await load()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                await load()
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    static func title(_ kind: String) -> LocalizedStringKey {
        switch kind {
        case "cron": return "定时脚本"
        case "event": return "事件脚本（网络变化）"
        default: return "通用脚本"
        }
    }

    @ViewBuilder func row(_ t: ScriptTaskState) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                KindBadge(kind: t.kind)
                if let f = t.format { FormatBadge(format: f) }
                Text(t.script.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                Spacer()
                if t.running || runningID == t.id {
                    ProgressView().controlSize(.small)
                } else {
                    Button { run(t) } label: { Image(systemName: "play.circle.fill").font(.title3) }
                        .buttonStyle(.borderless)
                        .disabled(!vpn.isConnected)
                }
            }
            if let c = t.cron, !c.isEmpty {
                HStack(spacing: 8) {
                    Text(c).scaledFont(11, design: .monospaced)
                    if let n = t.nextRun, n > 0 {
                        Text("下次 \(Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            if let l = t.lastRun, l > 0 {
                HStack(spacing: 6) {
                    Image(systemName: t.lastOK ? "checkmark.circle" : "xmark.octagon")
                        .foregroundStyle(t.lastOK ? Theme.good : Theme.bad)
                    Text("上次 \(Date(timeIntervalSince1970: l).formatted(.relative(presentation: .named)))\(t.duration.map { " · \($0) ms" } ?? "")")
                        .font(.caption2).foregroundStyle(.secondary)
                }
                if let r = t.lastResult, !r.isEmpty {
                    Text(r).scaledFont(10, design: .monospaced).foregroundStyle(t.lastOK ? Color.secondary : Theme.bad).lineLimit(3)
                }
            }
            Text(t.source).font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    func load() async {
        guard vpn.isConnected else { loaded = true; return }
        if let l = try? await ControllerClient.shared.mitmTasks() { tasks = l }
        loaded = true
    }

    func run(_ t: ScriptTaskState) {
        runningID = t.id
        Task {
            defer { runningID = nil }
            do {
                let r = try await ControllerClient.shared.mitmRunTask(t.id)
                if !r.ok { message = r.error }
            } catch { message = error.localizedDescription }
            await load()
        }
    }
}

struct FormatBadge: View {
    let format: String
    var body: some View {
        Text(format.uppercased() == "QX" ? "QX" : format.capitalized)
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
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
