import SwiftUI
import Libmihomo

// QX-3: 请求列表 (QX "HTTP 请求" = cron / event script tasks) restyled after the recording: 56 pt task tiles,
// title + relative time, clock + cron line, script path; capsule [仓库 | 存储 | 开关 | +], 全部更新,
// bottom search capsule + log circle. Live state comes from the extension; offline the list is read
// from the modules and local script lines.

// QX-5: the list is main's 任务 data (ScriptTaskState live / TaskCatalog offline), with main's TaskPrefs
// (自动运行 master switch + per-task on/off) and run history (TaskDetailView). As in QX, the tile itself
// is the task's switch (brown with a slashed alarm = off) and the alarm in the capsule is 自动运行.

struct QXTaskListView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var tasks: [ScriptTaskState] = []
    @State private var prefs = TaskPrefs.load()
    @State private var loaded = false
    @State private var runningID: String?
    @State private var message: String?
    @State private var search = ""
    @State private var adding = false
    @State private var result: TaskResultItem?
    @FocusState private var searchFocused: Bool

    static let offBrown = QXColor.taskOff

    var items: [ScriptTaskState] {
        guard !search.isEmpty else { return tasks }
        return tasks.filter { $0.script.name.localizedCaseInsensitiveContains(search) || $0.script.path.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        let list = items
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "square.3.layers.3d") { nav.push(.dest(.taskGallery)) }
                    .accessibilityLabel(Text("任务仓库"))
                QXBarIcon(systemName: "externaldrive") { nav.push(.dest(.prefsStore)) }
                    .accessibilityLabel(Text("持久化存储"))
                QXBarIcon(systemName: prefs.paused ? "alarm.waves.left.and.right" : "alarm", tint: prefs.paused ? .secondary : .primary) {
                    setPaused(!prefs.paused)
                }
                .overlay { if prefs.paused { Image(systemName: "line.diagonal").font(.system(size: 22, weight: .bold)).foregroundStyle(.secondary).allowsHitTesting(false) } }
                .accessibilityLabel(Text("自动运行"))
                .accessibilityValue(Text(prefs.paused ? LocalizedStringKey("已关闭") : LocalizedStringKey("已开启")))
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
                    masterRow.padding(.bottom, 8)
                    if !engine.config.enabled {
                        Text("重写与脚本已停用，任务不会运行。在设置页打开「重写」开关后恢复。")
                            .font(.footnote).foregroundStyle(QXColor.warning).padding(.bottom, 8)
                    } else if !vpn.isConnected {
                        Text("任务在扩展里运行：连接后按计划执行，断开时不运行。下面是模块与本地脚本中的任务。")
                            .font(.footnote).foregroundStyle(.secondary).padding(.bottom, 8)
                    }
                    if list.isEmpty && loaded {
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
                        Divider().overlay(QXPalette.separator).padding(.leading, 76)
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 110)
            }
            .refreshable { await load() }
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
        .sheet(isPresented: $adding, onDismiss: { Task { await load() } }) { LineEditorSheet(title: String(localized: "添加任务"), scripts: true, item: nil) }
        .sheet(item: $result) { r in
            NavigationStack {
                ScrollView { Text(verbatim: r.message).font(.footnote.monospaced()).textSelection(.enabled).padding() }
                    .navigationTitle(r.title).navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { result = nil } } }
            }
            .presentationDetents([.medium, .large])
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    /// 自动运行 (main v0.11 master switch): pauses every 定时 / 网络变化 task without touching the per-task switches.
    var masterRow: some View {
        HStack(spacing: 12) {
            Image(systemName: "alarm").font(.system(size: 17, weight: .semibold)).foregroundStyle(.white)
                .frame(width: 32, height: 32)
                .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(prefs.paused ? Self.offBrown : QXColor.activity))
            VStack(alignment: .leading, spacing: 2) {
                Text("自动运行").font(.system(size: 17, weight: .semibold))
                Text(prefs.paused ? LocalizedStringKey("已暂停全部定时与网络变化任务") : LocalizedStringKey("按计划运行已开启的任务；轻点任务图标单独开关"))
                    .font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: Binding(get: { !prefs.paused }, set: { setPaused(!$0) }))
                .labelsHidden().tint(QXColor.switchOn)
                .accessibilityLabel(Text("自动运行"))
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(QXPalette.card))
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
            .background(Capsule().fill(QXPalette.chrome).shadow(color: QXPalette.shadow(0.06), radius: 5, y: 2))
            .overlay(Capsule().stroke(QXPalette.hairline, lineWidth: 1))
            Button { nav.push(.dest(.scriptLogs)) } label: {
                Image(systemName: "doc.text.magnifyingglass").font(.system(size: 20, weight: .semibold)).foregroundStyle(.primary)
                    .frame(width: 56, height: 56)
                    .background(Circle().fill(QXPalette.chrome).shadow(color: QXPalette.shadow(0.06), radius: 5, y: 2))
                    .overlay(Circle().stroke(QXPalette.hairline, lineWidth: 1))
            }
            .buttonStyle(QXPressStyle())
            .accessibilityLabel(Text("运行日志"))
        }
        .padding(.horizontal, QXMetrics.inset)
        .padding(.bottom, 10)
    }

    func switchable(_ t: ScriptTaskState) -> Bool { t.kind == "cron" || t.kind == "event" }
    func isOn(_ t: ScriptTaskState) -> Bool { !switchable(t) || (prefs.isOn(t) && !prefs.paused) }

    func tile(_ t: ScriptTaskState) -> some View {
        let failed = (t.lastRun ?? 0) > 0 && t.lastOK == false
        let on = isOn(t) && engine.config.enabled
        let color: Color = !on ? Self.offBrown : (failed ? QXColor.red : (t.kind == "event" ? QXColor.rewrite : (t.kind == "interaction" ? QXColor.nodes : QXColor.activity)))
        return ZStack {
            RoundedRectangle(cornerRadius: 14, style: .continuous).fill(color)
            if t.running == true || runningID == t.id {
                ProgressView().tint(.white)
            } else if let ic = t.icon, !ic.isEmpty, on {
                RemoteIcon(url: ic, size: 34)
            } else {
                Image(systemName: !on ? "alarm" : (failed ? "exclamationmark" : (t.kind == "event" ? "network" : (t.kind == "interaction" ? "hand.tap.fill" : (t.kind == "generic" ? "play.fill" : "minus")))))
                    .font(.system(size: 22, weight: .heavy)).foregroundStyle(.white.opacity(on ? 1 : 0.8))
                    .overlay { if !on { Image(systemName: "line.diagonal").font(.system(size: 30, weight: .heavy)).foregroundStyle(.white.opacity(0.8)) } }
            }
        }
        .frame(width: 56, height: 56)
        .animation(QXMotion.spring, value: on)
    }

    func row(_ t: ScriptTaskState) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Button {
                if switchable(t) {
                    QXHaptics.toggle()
                    setOn(t, !prefs.isOn(t))
                } else if t.kind == "generic" {
                    run(t)
                }
            } label: { tile(t) }
            .buttonStyle(QXPressStyle(scale: 0.9))
            .disabled(prefs.paused && switchable(t))
            .accessibilityLabel(Text(verbatim: t.script.name))
            .accessibilityValue(Text(switchable(t) ? (prefs.isOn(t) ? LocalizedStringKey("已开启") : LocalizedStringKey("已关闭")) : LocalizedStringKey("运行")))
            NavigationLink {
                QXWrappedPage(title: t.script.name) { TaskDetailView(task: t, prefs: $prefs) }
            } label: {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(verbatim: t.script.name).font(.system(size: 18)).lineLimit(1).foregroundStyle(.primary)
                        Spacer()
                        Text(verbatim: t.lastRun.flatMap { $0 > 0 ? QXNodeResourcesView.rel.localizedString(for: Date(timeIntervalSince1970: $0), relativeTo: Date()) : nil } ?? t.source)
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    HStack(spacing: 6) {
                        Image(systemName: ScriptTasksView.symbol(t.kind)).font(.system(size: 13))
                        Text(verbatim: schedule(t)).font(.system(size: 15, design: .monospaced)).lineLimit(1)
                    }
                    .foregroundStyle(.secondary)
                    Text(verbatim: t.script.path).font(.system(size: 15)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    if let l = t.lastRun, l > 0 {
                        HStack(spacing: 4) {
                            Image(systemName: t.lastOK == true ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                .foregroundStyle(t.lastOK == true ? QXColor.success : QXColor.danger)
                            Text(verbatim: (t.lastOK == true ? String(localized: "上次成功") : String(localized: "上次失败")) + (t.duration.map { " · \($0) ms" } ?? ""))
                                .foregroundStyle(.secondary)
                            if t.lastOK != true, let r = t.lastResult, !r.isEmpty {
                                Text(verbatim: r).foregroundStyle(QXColor.danger).lineLimit(1)
                            }
                        }
                        .font(.caption2)
                    }
                    if let n = t.nextRun, n > 0, isOn(t), switchable(t) {
                        Text("下次 \(Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 12)
        .opacity(isOn(t) ? 1 : 0.62)
        .contextMenu {
            if vpn.isConnected && t.kind != "interaction" {
                Button { run(t) } label: { Label("立即运行", systemImage: "play.fill") }
            }
            if switchable(t) {
                Button { setOn(t, !prefs.isOn(t)) } label: {
                    Label(prefs.isOn(t) ? LocalizedStringKey("关闭此任务") : LocalizedStringKey("开启此任务"), systemImage: prefs.isOn(t) ? "alarm.waves.left.and.right" : "alarm")
                }
            }
            Button { UIPasteboard.general.string = t.script.path } label: { Label("拷贝脚本地址", systemImage: "doc.on.doc") }
            Button { UIPasteboard.general.string = t.line } label: { Label("拷贝任务行", systemImage: "text.quote") }
            Button { nav.push(.dest(.scriptLogs)) } label: { Label("运行日志", systemImage: "text.alignleft") }
        }
    }

    func schedule(_ t: ScriptTaskState) -> String {
        if let c = t.cron, !c.isEmpty { return c }
        switch t.kind {
        case "event": return t.event ?? "network-changed"
        case "interaction": return String(localized: "从节点长按菜单运行")
        default: return String(localized: "手动运行")
        }
    }

    func setOn(_ t: ScriptTaskState, _ on: Bool) {
        var e = prefs.enabled ?? [:]
        if on == (t.disabledByLine != true) { e.removeValue(forKey: t.id) } else { e[t.id] = on }
        prefs.enabled = e.isEmpty ? nil : e
        prefs.save(connected: vpn.isConnected)
    }

    func setPaused(_ p: Bool) {
        QXHaptics.toggle()
        withAnimation(QXMotion.spring) { prefs.paused = p }
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
        guard vpn.isConnected else { message = String(localized: "连接后才能运行任务。"); return }
        runningID = t.id
        Task {
            defer { runningID = nil }
            do {
                let r = try await ControllerClient.shared.mitmRunTask(t.id)
                if !r.ok { message = r.error ?? String(localized: "运行失败"); QXHaptics.warning() }
                else {
                    QXHaptics.success()
                    result = TaskResultItem(title: t.script.name, result: r.result)
                }
            } catch { message = error.localizedDescription }
            await load()
        }
    }
}
