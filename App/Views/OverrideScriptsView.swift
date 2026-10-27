import SwiftUI
import UniformTypeIdentifiers

// v0.19 覆写脚本: per-profile list, detail with the Bettbox switches, code editor, remote scripts.
// Engine and store: App/Core/OverrideScripts.swift.

struct OverrideScriptsView: View {
    let profile: Profile
    @ObservedObject private var store = OverrideScriptStore.shared
    @State private var showAddURL = false
    @State private var newScript: OverrideScript?
    @State private var message: String?
    @State private var status: (exists: Bool, fresh: Bool, at: Date?) = (false, false, nil)
    /// Review 5: deleting asks first and saves a snapshot (the .js file is removed with it).
    @State private var pendingDelete: [OverrideScript]?
    /// fix/nc-0.20.2: the shared 排序 / 完成 button (was the system 编辑 button).
    @State private var editMode: EditMode = .inactive

    var scripts: [OverrideScript] { store.scripts(profile.id) }

    var body: some View {
        List {
            Section {
                if scripts.isEmpty {
                    EmptyStateRow(icon: "curlybraces", title: "没有覆写脚本",
                                  message: "覆写脚本是一段 JavaScript：function main(config) { … return config }。生成运行配置时用它修改这个配置（加规则、改策略组、筛节点），兼容 Clash Verge / FlClash / Bettbox 的脚本。")
                }
                ForEach(scripts) { s in
                    NavigationLink { OverrideScriptDetailView(profile: profile, scriptID: s.id) } label: { OverrideScriptRow(script: s) }
                        .accessibilityIdentifier("scripts.row.\(s.name)")
                }
                .onMove(perform: editMode.isEditing ? { (from: IndexSet, to: Int) in store.move(profile.id, from: from, to: to); rerun() } : nil)
                .onDelete { idx in pendingDelete = idx.map { scripts[$0] } }
            } header: {
                Text("按顺序运行")
            } footer: {
                Text("连接或重载时，配置依次交给每个已开启脚本的 main(config)，结果再交给下一个；之后才应用本 App 的覆写（策略组编辑、节点订阅、DNS 等）。结果通过校验才会使用，脚本出错时不会连接。")
            }
            .listRowBackground(Theme.card)

            if !scripts.isEmpty {
                Section {
                    Button { run() } label: {
                        HStack {
                            Label("运行并校验", systemImage: "play.circle")
                            Spacer()
                            if store.running.contains(profile.id) { ProgressView().controlSize(.small) }
                        }
                    }
                    .disabled(store.running.contains(profile.id) || store.enabledCount(profile.id) == 0)
                    .accessibilityIdentifier("scripts.run")
                    if let r = store.lastResult[profile.id] { OverrideResultRow(result: r) }
                    if status.exists {
                        NavigationLink { OverrideOutputView(profile: profile) } label: {
                            HStack {
                                Label("查看生成的配置", systemImage: "doc.text.magnifyingglass")
                                Spacer()
                                if !status.fresh {
                                    Text("已过期").font(.caption2.weight(.semibold)).foregroundStyle(Theme.warn)
                                } else if let at = status.at {
                                    Text(at.formatted(date: .omitted, time: .shortened)).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .accessibilityIdentifier("scripts.output")
                    }
                } footer: {
                    if status.exists && !status.fresh {
                        Text("配置已变更，下次连接或重载时会重新运行脚本。")
                    }
                }
                .listRowBackground(Theme.card)
            }

            Section {
                Button { newLocal() } label: { Label("新建脚本", systemImage: "square.and.pencil") }
                    .accessibilityIdentifier("scripts.new")
                Button { showAddURL = true } label: { Label("从链接添加", systemImage: "link.badge.plus") }
                Button { paste() } label: { Label("从剪贴板粘贴", systemImage: "doc.on.clipboard") }
            } header: {
                Text("添加")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("覆写脚本")
        .navigationBarTitleDisplayMode(.inline)
        .environment(\.editMode, $editMode)
        .toolbar {
            if !scripts.isEmpty {
                ReorderToolbarButton(isEditing: editMode.isEditing, count: scripts.count, id: "scripts.reorder") {
                    withAnimation { editMode = editMode.isEditing ? .inactive : .active }
                }
            }
        }
        .sheet(isPresented: $showAddURL) { AddScriptURLSheet(profile: profile) }
        .sheet(item: $newScript) { s in
            OverrideScriptEditor(profile: profile, scriptID: s.id, isNew: true)
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .onAppear { status = OverrideScriptStore.status(profile) }
        .onChange(of: store.lastResult[profile.id]) { _ in status = OverrideScriptStore.status(profile) }
        .deleteConfirmation({ l in l.count == 1 ? Text("删除「\(l[0].name)」？") : Text("删除 \(l.count) 个脚本？") },
                            item: $pendingDelete, message: { _ in DeleteText.recoverable }) { l in
            Task {
                await SnapshotStore.shared.captureAsync(String(localized: "删除覆写脚本前"))
                for s in l { store.delete(profile.id, s.id) }
                await store.changed(profile)
            }
        }
    }

    func newLocal() {
        let n = scripts.count + 1
        newScript = store.add(profile.id, name: n == 1 ? "script.js" : "script-\(n).js", source: OverrideScriptStore.template)
    }

    func paste() {
        guard let text = UIPasteboard.general.string, text.contains("main") else { // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
            message = String(localized: "剪贴板里没有脚本（需要包含 main 函数）")
            return
        }
        Task {
            let r = await Task.detached(priority: .userInitiated) { JSOverrideEngine.declared(text) }.value
            if case .failure(let e) = r {
                message = e.text
                return
            }
            store.add(profile.id, name: "clipboard.js", source: text)
            await store.changed(profile)
        }
    }

    func run() { Task { await store.apply(profile, force: true) } }
    func rerun() { Task { await store.changed(profile) } }
}

struct OverrideScriptRow: View {
    let script: OverrideScript
    @ObservedObject private var store = OverrideScriptStore.shared

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: script.isRemote ? "link" : "curlybraces")
                .foregroundStyle(script.enabled ? Theme.accent : .secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: script.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                    .foregroundStyle(script.enabled ? .primary : .secondary)
                if !script.enabled {
                    Text("已关闭").font(.caption2).foregroundStyle(.secondary)
                } else if let e = script.lastError {
                    Text(e).font(.caption2).foregroundStyle(Theme.bad).lineLimit(2)
                } else if let ms = script.lastMillis, let at = script.lastRun {
                    Text("上次运行 \(at.formatted(date: .omitted, time: .shortened)) · \(ms) ms").font(.caption2).foregroundStyle(.secondary)
                } else {
                    Text(script.isRemote ? URL(string: script.url ?? "")?.host ?? "" : String(localized: "本地脚本"))
                        .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            if store.updating.contains(script.id) { ProgressView().controlSize(.small) }
        }
    }
}

struct OverrideResultRow: View {
    let result: OverrideChainResult
    var body: some View {
        if result.ok {
            VStack(alignment: .leading, spacing: 4) {
                Label("校验通过", systemImage: "checkmark.circle.fill").font(.subheadline.weight(.semibold)).foregroundStyle(Theme.good)
                Text("\(result.proxies) 个节点 · \(result.groups) 个策略组 · \(result.rules) 条规则 · \(result.millis) ms")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("scripts.result.ok")
        } else {
            VStack(alignment: .leading, spacing: 6) {
                ErrorRow(message: result.message)
                Button { UIPasteboard.general.string = result.message } label: { Label("复制错误", systemImage: "doc.on.doc") }
                    .font(.caption.weight(.semibold)).buttonStyle(.borderless)
            }
            .accessibilityIdentifier("scripts.result.error")
        }
    }
}

// MARK: - Detail

struct OverrideScriptDetailView: View {
    let profile: Profile
    let scriptID: String
    @ObservedObject private var store = OverrideScriptStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var declared: JSOverrideEngine.Declared?
    @State private var declareError: String?
    @State private var editing = false
    @State private var message: String?
    @State private var name = ""
    @State private var pending: Task<Void, Never>?
    @State private var confirmDelete = false

    var script: OverrideScript? { store.script(profile.id, scriptID) }

    static let intervals: [(Int, LocalizedStringKey)] = [(0, "仅手动"), (6, "每 6 小时"), (12, "每 12 小时"), (24, "每天"), (168, "每周")]

    var body: some View {
        Group {
            if let s = script { list(s) } else { EmptyStateView(icon: "curlybraces", title: "脚本已删除") }
        }
        .navigationTitle(script?.name ?? "")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $editing, onDismiss: loadDeclared) { OverrideScriptEditor(profile: profile, scriptID: scriptID, isNew: false) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .task { name = script?.name ?? ""; loadDeclared() }
        // Review 5: the name is saved when leaving the page, not only on Return.
        .onDisappear { if let s = script { rename(s) } }
        .confirmationDialog(Text("删除「\(script?.name ?? "")」？"), isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                Task {
                    await SnapshotStore.shared.captureAsync(String(localized: "删除覆写脚本前"))
                    store.delete(profile.id, scriptID)
                    rerun()
                    dismiss()
                }
            }
            Button("取消", role: .cancel) {}
        } message: { DeleteText.recoverable }
    }

    @ViewBuilder
    func list(_ s: OverrideScript) -> some View {
        List {
            Section {
                TextField("名称", text: $name)
                    .onSubmit { rename(s) }
                    .accessibilityIdentifier("script.name")
                Toggle("启用", isOn: Binding(get: { s.enabled }, set: { v in var x = s; x.enabled = v; store.update(profile.id, x); rerun() }))
                    .accessibilityIdentifier("script.enabled")
                if s.isRemote {
                    LabeledContent("来源") { Text(verbatim: URL(string: s.url ?? "")?.host ?? s.url ?? "").lineLimit(1) }
                    Picker("自动更新", selection: Binding(get: { s.updateIntervalHours }, set: { v in var x = s; x.updateIntervalHours = v; store.update(profile.id, x) })) {
                        ForEach(Self.intervals.indices, id: \.self) { i in Text(Self.intervals[i].1).tag(Self.intervals[i].0) }
                    }
                    Button { update(s) } label: {
                        HStack {
                            Label("立即更新", systemImage: "arrow.clockwise")
                            Spacer()
                            if store.updating.contains(s.id) { ProgressView().controlSize(.small) }
                            else if let d = s.lastUpdated { Text(d.formatted(.relative(presentation: .named))).font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                    .disabled(store.updating.contains(s.id))
                } else {
                    LabeledContent("来源") { Text("本地脚本") }
                }
            }
            .listRowBackground(Theme.card)

            switchSections(s)

            Section {
                Button { editing = true } label: {
                    Label(s.isRemote ? LocalizedStringKey("查看代码") : LocalizedStringKey("编辑代码"), systemImage: s.isRemote ? "doc.text" : "chevron.left.forwardslash.chevron.right")
                }
                .accessibilityIdentifier("script.edit")
                Button { UIPasteboard.general.string = OverrideScriptStore.content(s.id) } label: { Label("复制代码", systemImage: "doc.on.doc") }
                if s.isRemote, let u = s.url {
                    Button { UIPasteboard.general.string = u } label: { Label("复制链接", systemImage: "link") }
                }
            } header: {
                Text("代码")
            } footer: {
                if s.isRemote { Text("链接脚本按自动更新间隔重新下载；要修改，复制代码后新建本地脚本。") }
            }
            .listRowBackground(Theme.card)

            if s.lastRun != nil || s.lastError != nil {
                Section {
                    if let e = s.lastError {
                        VStack(alignment: .leading, spacing: 6) {
                            // One element whose label is the message (the VStack's id landed on the icon).
                            ErrorRow(message: e)
                                .accessibilityElement(children: .combine)
                                .accessibilityIdentifier("script.error")
                            Button { UIPasteboard.general.string = e } label: { Label("复制错误", systemImage: "doc.on.doc") }
                                .font(.caption.weight(.semibold)).buttonStyle(.borderless)
                        }
                    } else if let at = s.lastRun {
                        LabeledContent("上次运行") { Text("\(at.formatted(date: .omitted, time: .shortened)) · \(s.lastMillis ?? 0) ms").monospacedDigit() }
                    }
                    if let logs = s.logs, !logs.isEmpty {
                        NavigationLink { ScriptConsoleView(lines: logs) } label: {
                            LabeledContent("控制台输出") { Text("\(logs.count) 行").monospacedDigit() }
                        }
                    }
                } header: {
                    Text("运行结果")
                }
                .listRowBackground(Theme.card)
            }

            Section {
                Button(role: .destructive) { confirmDelete = true } label: { Label("删除脚本", systemImage: "trash") }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
    }

    @ViewBuilder
    func switchSections(_ s: OverrideScript) -> some View {
        if let e = declareError {
            Section { ErrorRow(message: e) } header: { Text("脚本选项") }
                .listRowBackground(Theme.card)
        } else if let d = declared, d.hasSwitches {
            if let split = d.split {
                Section {
                    ForEach(split.groups, id: \.self) { k in optionToggle(s, d, k) }
                } header: {
                    Text("策略组")
                } footer: {
                    Text("脚本声明的开关（Bettbox 兼容）。改动后立即重新生成配置。")
                }
                .listRowBackground(Theme.card)
                Section {
                    NavigationLink {
                        ScriptOtherOptionsView(profile: profile, scriptID: scriptID, keys: split.others, declared: d)
                    } label: {
                        LabeledContent("其他设置") { Text("\(split.others.count)").monospacedDigit() }
                    }
                    .accessibilityIdentifier("script.others")
                }
                .listRowBackground(Theme.card)
            } else {
                Section {
                    ForEach(d.keys, id: \.self) { k in optionToggle(s, d, k) }
                } header: {
                    Text("脚本选项")
                } footer: {
                    Text("脚本声明的开关（Bettbox 兼容）。改动后立即重新生成配置。")
                }
                .listRowBackground(Theme.card)
            }
        }
    }

    func optionToggle(_ s: OverrideScript, _ d: JSOverrideEngine.Declared, _ k: String) -> some View {
        ScriptOptionToggle(label: k, icon: d.icons[k], isOn: Binding(
            get: { s.options?[k] ?? d.values[k] ?? true },
            set: { v in setOption(k, v, d) }
        ))
    }

    func setOption(_ k: String, _ v: Bool, _ d: JSOverrideEngine.Declared) {
        guard var x = script else { return }
        var o = x.options ?? [:]
        // Store only what differs from the script's own default, so a script update changes the defaults.
        if d.values[k] == v { o.removeValue(forKey: k) } else { o[k] = v }
        x.options = o.isEmpty ? nil : o
        store.update(profile.id, x)
        // Several quick taps → one run.
        pending?.cancel()
        pending = Task {
            try? await Task.sleep(nanoseconds: 600_000_000)
            guard !Task.isCancelled else { return }
            await store.changed(profile)
        }
    }

    func loadDeclared() {
        let src = OverrideScriptStore.content(scriptID)
        Task {
            let r = await Task.detached(priority: .userInitiated) { JSOverrideEngine.declared(src) }.value
            switch r {
            case .success(let d):
                declared = d
                declareError = d.hasMain ? nil : String(localized: "没有找到 main 函数（需要 function main(config) { … return config }）")
            case .failure(let e):
                declared = nil
                declareError = e.text
            }
        }
    }

    func rename(_ s: OverrideScript) {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !n.isEmpty, n != s.name else { name = s.name; return }
        var x = s
        x.name = n
        store.update(profile.id, x)
    }

    func update(_ s: OverrideScript) {
        Task {
            if let e = await store.refresh(profile.id, s.id) { message = e; return }
            loadDeclared()
            await store.changed(profile)
        }
    }

    func rerun() { Task { await store.changed(profile) } }
}

struct ScriptOptionToggle: View {
    let label: String
    let icon: String?
    @Binding var isOn: Bool

    var iconURL: URL? {
        guard let icon, let u = URL(string: icon), u.scheme?.hasPrefix("http") == true else { return nil }
        // SVG is not drawn by AsyncImage; those fall back to the plain switch.
        let ext = u.pathExtension.lowercased()
        return ["png", "jpg", "jpeg", "webp", "gif"].contains(ext) ? u : nil
    }

    var body: some View {
        Toggle(isOn: $isOn) {
            HStack(spacing: 10) {
                if let u = iconURL {
                    AsyncImage(url: u) { img in img.resizable().scaledToFit() } placeholder: { Color.clear }
                        .frame(width: 22, height: 22)
                        .accessibilityHidden(true)
                }
                Text(verbatim: label)
            }
        }
        .accessibilityIdentifier("script.option.\(label)")
    }
}

struct ScriptOtherOptionsView: View {
    let profile: Profile
    let scriptID: String
    let keys: [String]
    let declared: JSOverrideEngine.Declared
    @ObservedObject private var store = OverrideScriptStore.shared
    @State private var pending: Task<Void, Never>?

    var body: some View {
        List {
            Section {
                ForEach(keys, id: \.self) { k in
                    ScriptOptionToggle(label: k, icon: declared.icons[k], isOn: Binding(
                        get: { store.script(profile.id, scriptID)?.options?[k] ?? declared.values[k] ?? true },
                        set: { v in set(k, v) }
                    ))
                }
            } footer: {
                Text("脚本里没有归入策略组的开关。改动后立即重新生成配置。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("其他设置")
        .navigationBarTitleDisplayMode(.inline)
    }

    func set(_ k: String, _ v: Bool) {
        guard var x = store.script(profile.id, scriptID) else { return }
        var o = x.options ?? [:]
        if declared.values[k] == v { o.removeValue(forKey: k) } else { o[k] = v }
        x.options = o.isEmpty ? nil : o
        store.update(profile.id, x)
        pending?.cancel()
        pending = Task {
            try? await Task.sleep(nanoseconds: 600_000_000)
            guard !Task.isCancelled else { return }
            await store.changed(profile)
        }
    }
}

struct ScriptConsoleView: View {
    let lines: [String]
    var body: some View {
        ScrollView {
            Text(verbatim: lines.joined(separator: "\n"))
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("控制台输出")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { UIPasteboard.general.string = lines.joined(separator: "\n") } label: { Image(systemName: "doc.on.doc") }
                    .accessibilityLabel(Text("复制"))
            }
        }
    }
}

// MARK: - Editor

struct OverrideScriptEditor: View {
    let profile: Profile
    let scriptID: String
    let isNew: Bool
    @ObservedObject private var store = OverrideScriptStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var name = ""
    @State private var error: String?
    @State private var errorLine: Int?
    @State private var saving = false
    @State private var loaded = false
    @State private var scrollToken = 0
    @State private var savedText = ""
    @State private var confirmDiscard = false

    var readOnly: Bool { store.script(profile.id, scriptID)?.isRemote ?? false }
    /// Unsaved code: swipe-down is blocked and 取消 asks first (review 5; was only for new scripts).
    var dirty: Bool { loaded && !readOnly && text != savedText }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if isNew {
                    TextField("名称", text: $name)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(.horizontal, 16).padding(.vertical, 10)
                        .background(Theme.card)
                        .accessibilityIdentifier("scripteditor.name")
                }
                if let error {
                    Button { scrollToken += 1 } label: {
                        ErrorRow(message: error).padding(.horizontal, 16).padding(.vertical, 8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    .background(Theme.bad.opacity(0.08))
                    .accessibilityIdentifier("scripteditor.error")
                }
                CodeEditor(text: $text, language: .javascript, editable: !readOnly, errorLine: errorLine, scrollToken: scrollToken)
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(isNew ? LocalizedStringKey("新建脚本") : (readOnly ? LocalizedStringKey("查看代码") : LocalizedStringKey("编辑代码")))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(readOnly ? LocalizedStringKey("完成") : LocalizedStringKey("取消")) {
                        if dirty { confirmDiscard = true } else { discard() }
                    }
                }
                if !readOnly {
                    ToolbarItem(placement: .confirmationAction) {
                        if saving { ProgressView() } else { Button("保存") { save() }.accessibilityIdentifier("scripteditor.save") }
                    }
                }
            }
            .interactiveDismissDisabled(isNew || dirty)
            .confirmationDialog("放弃修改？", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("放弃修改", role: .destructive) { discard() }
            }
            .onAppear {
                guard !loaded else { return }
                loaded = true
                text = OverrideScriptStore.content(scriptID)
                savedText = text
                name = store.script(profile.id, scriptID)?.name ?? ""
            }
        }
    }

    func discard() {
        if isNew { store.delete(profile.id, scriptID) }
        dismiss()
    }

    /// Checks the script parses and has main() before saving, then runs the profile's chain so a runtime
    /// error shows here too (with its line).
    func save() {
        saving = true
        let src = text
        Task {
            defer { saving = false }
            let r = await Task.detached(priority: .userInitiated) { JSOverrideEngine.declared(src) }.value
            switch r {
            case .failure(let e):
                error = e.text
                errorLine = e.line
                scrollToken += 1
                return
            case .success(let d) where !d.hasMain:
                error = String(localized: "没有找到 main 函数（需要 function main(config) { … return config }）")
                errorLine = nil
                return
            default: break
            }
            store.setContent(profile.id, scriptID, src)
            savedText = src
            if isNew, var s = store.script(profile.id, scriptID) {
                let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
                if !n.isEmpty { s.name = n; store.update(profile.id, s) }
            }
            let res = await store.apply(profile, force: true)
            if !res.ok, res.failedScriptID == scriptID, let s = store.script(profile.id, scriptID) {
                // Saved, but it fails at run time: stay so the line can be fixed.
                error = s.lastError ?? res.message
                errorLine = s.lastErrorLine
                scrollToken += 1
                return
            }
            if res.ok, profile.id == AppShared.activeProfileID, VPNManager.shared.isConnected {
                _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0)
            }
            dismiss()
        }
    }
}

// MARK: - Add from URL

struct AddScriptURLSheet: View {
    let profile: Profile
    @ObservedObject private var store = OverrideScriptStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    @State private var name = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://…/script.js", text: $url)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("名称（可选）", text: $name)
                } footer: {
                    Text("下载后检查是否有 main 函数；之后按自动更新间隔（默认每天）重新下载。")
                }
                .listRowBackground(Theme.card)
                if let error {
                    Section { ErrorRow(message: error) }.listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("从链接添加")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else { Button("添加") { add() }.disabled(url.isEmpty) }
                }
            }
        }
    }

    func add() {
        busy = true
        error = nil
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            defer { busy = false }
            do {
                let text = try await OverrideScriptStore.download(u)
                let r = await Task.detached(priority: .userInitiated) { JSOverrideEngine.declared(text) }.value
                switch r {
                case .failure(let e): error = e.text; return
                case .success(let d) where !d.hasMain:
                    error = String(localized: "没有找到 main 函数（需要 function main(config) { … return config }）")
                    return
                default: break
                }
                let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
                store.add(profile.id, name: n.isEmpty ? (URL(string: u)?.lastPathComponent ?? "script.js") : n, source: text, url: u)
                await store.changed(profile)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

// MARK: - Output

struct OverrideOutputView: View {
    let profile: Profile
    @State private var text = ""
    var body: some View {
        CodeEditor(text: $text, language: .yaml, editable: false)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("生成的配置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { UIPasteboard.general.string = text } label: { Image(systemName: "doc.on.doc") }
                        .accessibilityLabel(Text("复制"))
                }
            }
            .onAppear { text = NCOverrideOutput.storedYAML(home: AppShared.homeURL.path, profilePath: profile.fileURL.path) }
    }
}
