import SwiftUI
import Libmihomo

// QX-3: 请求列表 (QX "HTTP 请求" = cron / event script tasks) restyled after the recording: 56 pt task tiles,
// title + relative time, clock + cron line, script path; capsule [仓库 | 存储 | 开关 | +], 全部更新,
// bottom search capsule + log circle. Live state comes from the extension; offline the list is read
// from the modules and local script lines.

struct QXTaskItem: Identifiable, Hashable {
    let id: String
    let name: String
    let kind: String          // cron | event | generic
    let schedule: String
    let path: String
    let source: String
    var lastRun: Double? = nil
    var lastOK = true
    var running = false
    var lastResult: String? = nil
}

struct QXTaskListView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var live: [ScriptTaskState] = []
    @State private var loaded = false
    @State private var runningID: String?
    @State private var message: String?
    @State private var search = ""
    @State private var adding = false
    @FocusState private var searchFocused: Bool

    var offline: [QXTaskItem] {
        var out: [QXTaskItem] = []
        for it in (engine.config.scripts + engine.config.rules) where it.enabled {
            let d = EngineStore.describe(it.line, section: "script")
            guard ["cron", "event", "generic"].contains(d.kind) else { continue }
            if let p = ParsedEngineText.parse(LibmihomoEngineParseLine(it.line, "script")), let t = p.tasks?.first {
                out.append(QXTaskItem(id: it.id, name: t.name, kind: t.kind, schedule: t.cron ?? t.event ?? "", path: t.path, source: String(localized: "已保存")))
            }
        }
        for m in engine.config.modules where m.enabled {
            for (i, t) in (engine.moduleInfo[m.id]?.tasks ?? []).enumerated() {
                out.append(QXTaskItem(id: m.id + "#\(i)", name: t.name, kind: t.kind, schedule: t.cron ?? t.event ?? "", path: t.path, source: m.name))
            }
        }
        return out
    }

    var items: [QXTaskItem] {
        let base: [QXTaskItem]
        if vpn.isConnected && loaded {
            base = live.map {
                QXTaskItem(id: $0.id, name: $0.script.name, kind: $0.kind, schedule: $0.cron ?? $0.event ?? "", path: $0.script.path,
                           source: $0.source, lastRun: $0.lastRun, lastOK: $0.lastOK ?? true, running: $0.running ?? false, lastResult: $0.lastResult)
            }
        } else {
            base = offline
        }
        guard !search.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        let list = items
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "square.3.layers.3d") { nav.push(.dest(.taskGallery)) }
                    .accessibilityLabel(Text("任务仓库"))
                QXBarIcon(systemName: "externaldrive") { nav.push(.dest(.prefsStore)) }
                    .accessibilityLabel(Text("持久化存储"))
                QXBarIcon(systemName: engine.config.enabled ? "alarm" : "zzz", tint: engine.config.enabled ? .primary : .secondary) {
                    engine.config.enabled.toggle()
                    engine.save()
                }
                .accessibilityLabel(Text(engine.config.enabled ? LocalizedStringKey("停用脚本") : LocalizedStringKey("启用脚本")))
                QXBarIcon(systemName: "plus") { adding = true }
                    .accessibilityLabel(Text("添加任务"))
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .firstTextBaseline) {
                        QXLargeTitle(title: String(localized: "请求列表"))
                        QXPill(title: res.updatingAll ? String(localized: "更新中…") : String(localized: "全部更新")) {
                            Task { await res.updateAll() }
                        }
                        .disabled(res.updatingAll)
                    }
                    .padding(.bottom, 10)
                    if !engine.config.enabled {
                        Text("重写与脚本已停用，任务不会运行。点右上角的闹钟重新启用。")
                            .font(.footnote).foregroundStyle(Theme.warn).padding(.bottom, 8)
                    } else if !vpn.isConnected {
                        Text("任务在扩展里运行：连接后按计划执行，断开时不运行。下面是模块与本地脚本中的任务。")
                            .font(.footnote).foregroundStyle(.secondary).padding(.bottom, 8)
                    }
                    if list.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(search.isEmpty ? LocalizedStringKey("没有定时 / 事件 / 通用脚本") : LocalizedStringKey("没有匹配的任务")).font(.headline)
                            if search.isEmpty {
                                Text("点右上角 + 粘贴一行任务，例如：").font(.footnote).foregroundStyle(.secondary)
                                Text(verbatim: "0 8 * * * https://example.com/checkin.js, tag=签到\ncron \"0 8 * * *\" script-path=https://…, tag=签到")
                                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 20)
                    }
                    ForEach(list) { t in
                        row(t)
                        Divider().padding(.leading, 76)
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 110)
            }
            .overlay(alignment: .bottom) { bottomBar }
        }
        .task(id: vpn.isConnected) {
            await load()
            while !Task.isCancelled && vpn.isConnected {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                if Task.isCancelled { break }
                await load()
            }
        }
        .onAppear { engine.reparseModules() }
        .sheet(isPresented: $adding) { LineEditorSheet(title: String(localized: "添加任务"), scripts: true, item: nil) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    var bottomBar: some View {
        HStack(spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").font(.system(size: 18, weight: .semibold))
                TextField("搜索", text: $search).focused($searchFocused)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                if !search.isEmpty {
                    Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 18)
            .frame(height: 56)
            .background(Capsule().fill(Theme.card).shadow(color: .black.opacity(0.12), radius: 10, y: 3))
            Button { nav.push(.dest(.scriptLogs)) } label: {
                Image(systemName: "doc.text.magnifyingglass").font(.system(size: 20, weight: .semibold)).foregroundStyle(.primary)
                    .frame(width: 56, height: 56)
                    .background(Circle().fill(Theme.card).shadow(color: .black.opacity(0.12), radius: 10, y: 3))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(Text("运行日志"))
        }
        .padding(.horizontal, QXMetrics.inset)
        .padding(.bottom, 10)
    }

    func tile(_ t: QXTaskItem) -> some View {
        let failed = t.lastRun != nil && !t.lastOK
        let off = !engine.config.enabled || !vpn.isConnected
        let color: Color = failed ? Color(red: 0.47, green: 0.33, blue: 0.30) : (t.kind == "event" ? QXColor.rewrite : QXColor.activity)
        return ZStack {
            RoundedRectangle(cornerRadius: 14, style: .continuous).fill(off ? Color(red: 0.47, green: 0.33, blue: 0.30) : color)
            if t.running || runningID == t.id {
                ProgressView().tint(.white)
            } else {
                Image(systemName: off ? "zzz" : (failed ? "exclamationmark" : (t.kind == "event" ? "network" : (t.kind == "generic" ? "play.fill" : "minus"))))
                    .font(.system(size: 22, weight: .heavy)).foregroundStyle(.white.opacity(off ? 0.75 : 1))
            }
        }
        .frame(width: 56, height: 56)
    }

    func row(_ t: QXTaskItem) -> some View {
        HStack(alignment: .top, spacing: 16) {
            tile(t)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(verbatim: t.name).font(.system(size: 18)).lineLimit(1)
                    Spacer()
                    Text(verbatim: t.lastRun.map { QXNodeResourcesView.rel.localizedString(for: Date(timeIntervalSince1970: $0), relativeTo: Date()) } ?? t.source)
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                HStack(spacing: 6) {
                    Image(systemName: t.kind == "event" ? "network" : "clock").font(.system(size: 13))
                    Text(verbatim: t.schedule.isEmpty ? (t.kind == "generic" ? String(localized: "手动运行") : "—") : t.schedule)
                        .font(.system(size: 15, design: .monospaced))
                }
                .foregroundStyle(.secondary)
                Text(verbatim: t.path).font(.system(size: 15)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if let r = t.lastResult, !r.isEmpty, !t.lastOK {
                    Text(verbatim: r).font(.caption2.monospaced()).foregroundStyle(Theme.bad).lineLimit(2)
                }
            }
        }
        .padding(.vertical, 12)
        .contentShape(Rectangle())
        .contextMenu {
            if vpn.isConnected && live.contains(where: { $0.id == t.id }) {
                Button { run(t) } label: { Label("立即运行", systemImage: "play.fill") }
            }
            Button { UIPasteboard.general.string = t.path } label: { Label("拷贝脚本地址", systemImage: "doc.on.doc") }
            Button { nav.push(.dest(.scriptLogs)) } label: { Label("运行日志", systemImage: "text.alignleft") }
            Button { nav.push(.dest(.scripts)) } label: { Label("编辑", systemImage: "square.and.pencil") }
        }
    }

    func load() async {
        guard vpn.isConnected else { loaded = true; return }
        if let l = try? await ControllerClient.shared.mitmTasks() { live = l }
        loaded = true
    }

    func run(_ t: QXTaskItem) {
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
