import SwiftUI

/// 工具 → 重写 → 脚本列表 (feat/loon-rewrite-ui, Loon 配置 → 脚本): every script of the enabled subscriptions
/// and the enabled local script lines in one list, one section per owner (本地 first). A row shows name,
/// type (http-request / http-response) and pattern; tap → source. Tasks (cron / event / …) are on 定时任务.
/// The switch on a row turns that script file off everywhere it is used (engine.json scriptResources,
/// the same setting the resource manager writes; bridge/mitm Config.scriptAllowed honours it).
struct ScriptListView: View {
    @ObservedObject private var store = EngineStore.shared
    @State private var groups: [ScriptListData.ScriptGroup] = []
    @State private var loaded = false
    @State private var search = ""
    @State private var viewing: ScriptListData.ScriptEntry?

    @MainActor private func reload() async {
        let cfg = store.config
        let info = store.moduleInfo
        let localTitle = String(localized: "本地")
        groups = await Task.detached(priority: .userInitiated) {
            ScriptListData.build(config: cfg, info: info, localTitle: localTitle)
        }.value
        loaded = true
    }

    private func matches(_ e: ScriptListData.ScriptEntry, _ g: ScriptListData.ScriptGroup) -> Bool {
        search.isEmpty || e.name.localizedCaseInsensitiveContains(search) || e.pattern.localizedCaseInsensitiveContains(search)
            || e.path.localizedCaseInsensitiveContains(search) || g.title.localizedCaseInsensitiveContains(search)
            || e.type.localizedCaseInsensitiveContains(search)
    }

    private func scriptOn(_ path: String) -> Bool {
        !(store.config.scriptResources?[path]?.disabled ?? false)
    }

    var body: some View {
        let shown: [ScriptListData.ScriptGroup] = groups.map { g in ScriptListData.ScriptGroup(id: g.id, title: g.title, entries: g.entries.filter { matches($0, g) }) }
            .filter { !$0.entries.isEmpty }
        List {
            if !store.config.scriptsEnabled {
                Section {
                    Toggle(isOn: Binding(get: { store.config.scriptsEnabled }, set: { store.config.scriptsEnabled = $0; store.save() })) {
                        Label("启用脚本", systemImage: "curlybraces")
                    }
                    .accessibilityIdentifier("scripts.enabled")
                } footer: { Text("脚本总开关已关闭，下面的脚本不会运行。") }
                .listRowBackground(Theme.card)
            }
            ForEach(shown) { g in
                Section {
                    ForEach(g.entries) { e in
                        HStack(spacing: 10) {
                            ScriptEntryRow(entry: e)
                                .contentShape(Rectangle())
                                .onTapGesture { viewing = e }
                            if !e.path.isEmpty {
                                Toggle("", isOn: Binding(get: { scriptOn(e.path) }, set: { store.setScriptPathEnabled(e.path, $0) }))
                                    .labelsHidden()
                                    .accessibilityLabel(Text(verbatim: e.name))
                                    .accessibilityIdentifier("scripts.toggle." + e.name)
                            }
                        }
                        .opacity(scriptOn(e.path) ? 1 : 0.5)
                        .accessibilityIdentifier("scripts.row." + e.name)
                    }
                } header: {
                    Text(verbatim: "\(g.title) \(g.entries.count)")
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .automatic), prompt: "搜索名称、URL 或模块")
        .overlay {
            if loaded && groups.isEmpty {
                EmptyStateView(icon: "curlybraces", title: "还没有脚本", message: "已启用的订阅和本地脚本行里的脚本会列在这里。")
                    .allowsHitTesting(false)
            } else if !loaded {
                ProgressView()
            }
        }
        .safeAreaInset(edge: .bottom) {
            if loaded && !groups.isEmpty {
                Text("轻点查看源码。开关停用的是这个脚本文件，用到它的规则和任务都不会运行。")
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 20).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.bar)
            }
        }
        .navigationTitle("脚本列表")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $viewing) { e in ScriptSourceView(title: e.name, path: e.path) }
        .task {
            try? await Task.sleep(nanoseconds: 350_000_000) // after the push animation
            if store.moduleInfo.isEmpty && !store.config.modules.isEmpty { await store.reparseModulesInBackground() }
            await reload()
        }
        .onReceive(store.$moduleInfo.dropFirst()) { _ in if loaded { Task { await reload() } } }
        .onChange(of: store.config.scripts) { _ in Task { await reload() } }
    }
}

struct ScriptEntryRow: View {
    let entry: ScriptListData.ScriptEntry
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                KindBadge(kind: entry.kind, phase: entry.phase)
                Text(verbatim: entry.name).font(.callout.weight(.semibold)).lineLimit(1)
            }
            Text(verbatim: entry.type).font(.caption2.monospaced()).foregroundStyle(.secondary)
            if !entry.pattern.isEmpty {
                Text(verbatim: entry.pattern).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Read-only source of one script (local file or cached / downloaded remote script).
struct ScriptSourceView: View {
    let title: String
    let path: String
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var error: String?
    @State private var loading = true

    var body: some View {
        NavigationStack {
            Group {
                if loading {
                    ProgressView()
                } else if let error {
                    EmptyStateView(icon: "exclamationmark.triangle", title: "读取脚本失败", message: error)
                } else {
                    CodeEditor(text: $code, language: .javascript, editable: false)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(Text(verbatim: title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { dismiss() } }
            }
            .task {
                let home = AppShared.homeURL.path
                let p = path
                let src = await Task.detached(priority: .userInitiated) { NCScriptSource.codeAndError(home: home, path: p) }.value
                if src.0.isEmpty {
                    error = src.1.isEmpty ? path : src.1
                } else {
                    code = src.0
                }
                loading = false
            }
        }
    }
}

/// Data for 脚本列表, built off the main thread (plain types: no actor isolation).
enum ScriptListData {
    struct ScriptEntry: Identifiable, Hashable {
        let id: String
        let name: String
        let kind: String     // script (http-*) / cron / event / generic / interaction
        let phase: String
        let type: String     // http-request / http-response / cron / event / generic / interaction
        let pattern: String
        let path: String
    }

    struct ScriptGroup: Identifiable, Hashable {
        let id: String
        let title: String
        let entries: [ScriptEntry]
    }

    static func entries(_ p: ParsedEngineText, prefix: String) -> [ScriptEntry] {
        var out: [ScriptEntry] = []
        for (i, r) in p.rules.enumerated() where r.kind == "script" {
            let path = r.path ?? ""
            let name = (r.script ?? "").isEmpty ? (URL(string: path)?.lastPathComponent ?? path) : (r.script ?? "")
            out.append(ScriptEntry(id: "\(prefix)#r\(i)", name: name, kind: "script", phase: r.phase,
                                   type: r.phase == "response" ? "http-response" : "http-request", pattern: r.pattern, path: path))
        }
        // Cron / event / interaction / generic tasks live only on 工具 → 定时任务 (user 2026-10-23: 「任务放错位置了，
        // 应该放在定时任务里」), so this list holds the request / response scripts alone.
        return out
    }

    /// Parses the local script lines (Go) and collects module scripts from the already parsed moduleInfo.
    static func build(config: EngineConfig, info: [String: ParsedEngineText], localTitle: String) -> [ScriptListData.ScriptGroup] {
        var out: [ScriptListData.ScriptGroup] = []
        var local: [ScriptEntry] = []
        for it in config.scripts where it.enabled {
            let p = NCEngineParser.parseLine(it.line, section: "script")
            local += entries(p, prefix: "local:" + it.id)
        }
        if !local.isEmpty { out.append(ScriptGroup(id: "local", title: localTitle, entries: local)) }
        for m in config.modules where m.enabled {
            guard let p = info[m.id] else { continue }
            let e = entries(p, prefix: m.id)
            if !e.isEmpty { out.append(ScriptGroup(id: m.id, title: m.name, entries: e)) }
        }
        return out
    }
}
