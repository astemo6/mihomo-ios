import SwiftUI

// 更多 → 模块与资源 → 模块库 (v0.15): browse and search modules from the index sources, preview what a
// module changes (rewrites, scripts, MitM hostnames, rules, tasks, panels, arguments) before adding it,
// and switch modules that are already added on or off right in the list.

struct ModuleGalleryView: View {
    @ObservedObject var gallery = ModuleGallery.shared
    @ObservedObject var store = EngineStore.shared
    @State private var query = ""
    @State private var source = "all"
    @State private var managing = false

    var items: [GalleryItem] {
        let base = source == "all" ? gallery.allItems : (gallery.indexes[source]?.items ?? [])
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return base }
        return base.filter { ($0.name + " " + $0.desc + " " + $0.category + " " + $0.author).lowercased().contains(q) }
    }

    /// Category → items, in index order.
    var grouped: [(String, [GalleryItem])] {
        var order: [String] = []
        var map: [String: [GalleryItem]] = [:]
        for it in items {
            let k = it.category
            if map[k] == nil { order.append(k) }
            map[k, default: []].append(it)
        }
        return order.map { ($0, map[$0]!) }
    }

    func sourceName(_ id: String) -> String { gallery.sources.first { $0.id == id }?.name ?? "" }

    var body: some View {
        List {
            Section {
                if gallery.sources.count > 1 {
                    Picker("来源", selection: $source) {
                        Text("全部来源").tag("all")
                        ForEach(gallery.sources) { s in Text(s.name).tag(s.id) }
                    }
                }
                ForEach(gallery.sources.filter { source == "all" || $0.id == source }) { s in
                    if let e = gallery.indexes[s.id]?.error, !e.isEmpty {
                        Label("\(s.name)：\(e)", systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.bad)
                    }
                }
            } footer: {
                Text("模块来自你添加的索引来源（GitHub 仓库或文件夹、JSON 列表、包含模块链接的网页或文本）。点模块先预览它会添加的重写、脚本和 MitM 主机名，确认后再添加。第三方模块由作者维护，请只添加信任的来源。")
            }
            .listRowBackground(Theme.card)

            if gallery.sources.isEmpty {
                Section {
                    EmptyStateRow(icon: "books.vertical", title: "还没有索引来源", message: "点右上角管理来源，添加一个模块索引链接。") {
                        Button("恢复默认来源") { gallery.restoreDefaults() }.font(.subheadline.weight(.semibold))
                    }
                }
                .listRowBackground(Theme.card)
            } else if items.isEmpty {
                Section {
                    if !gallery.loading.isEmpty {
                        HStack { ProgressView(); Text("正在载入索引…").foregroundStyle(.secondary) }
                    } else {
                        EmptyStateRow(icon: "magnifyingglass", title: query.isEmpty ? "没有模块" : "没有匹配的模块",
                                      message: query.isEmpty ? "下拉刷新索引，或在来源管理里检查链接。" : "换个关键词试试。")
                    }
                }
                .listRowBackground(Theme.card)
            }

            ForEach(grouped, id: \.0) { cat, list in
                Section {
                    ForEach(list) { it in
                        NavigationLink { ModulePreviewView(item: it) } label: {
                            GalleryRow(item: it, sourceName: source == "all" && gallery.sources.count > 1 ? sourceName(it.sourceID) : "")
                        }
                    }
                } header: {
                    Text(cat.isEmpty ? String(localized: "未分类") : cat) + Text(" · \(list.count)")
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("模块库")
        .searchable(text: $query, prompt: Text("搜索模块"))
        .refreshable { await gallery.refreshAll(force: true) }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { managing = true } label: { Image(systemName: "books.vertical") }
                    .accessibilityLabel(Text("管理来源"))
            }
        }
        .overlay(alignment: .top) {
            if !gallery.loading.isEmpty && !items.isEmpty { ProgressView().padding(.top, 4) }
        }
        .sheet(isPresented: $managing) { NavigationStack { GallerySourcesView() } }
        .task { await gallery.refreshAll(force: false) }
        .onChange(of: gallery.sources) { s in if source != "all" && !s.contains(where: { $0.id == source }) { source = "all" } }
    }
}

struct GalleryRow: View {
    @ObservedObject var store = EngineStore.shared
    let item: GalleryItem
    var sourceName = ""

    var installed: EngineModule? { store.config.modules.first { $0.url == item.url } }

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                    if !item.formatHint.isEmpty { SourceFormatBadge(format: item.formatHint) }
                }
                if !item.desc.isEmpty { Text(item.desc).font(.caption2).foregroundStyle(.secondary).lineLimit(2) }
                let meta = [item.author, sourceName].filter { !$0.isEmpty }.joined(separator: " · ")
                if !meta.isEmpty { Text(meta).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
            }
            Spacer()
            if let m = installed {
                Toggle("", isOn: Binding(get: { m.enabled }, set: { store.setModuleEnabled(m.id, $0) })).labelsHidden()
            }
        }
    }
}

struct ModulePreviewView: View {
    let item: GalleryItem
    @ObservedObject var store = EngineStore.shared
    @State private var preview: ModuleGallery.Preview?
    @State private var error: String?
    @State private var showText = false
    @State private var added = false

    var installed: EngineModule? { store.config.modules.first { $0.url == item.url } }

    var body: some View {
        List {
            Section {
                LabeledContent("名称", value: preview?.parsed.name.isEmpty == false ? preview!.parsed.name : item.name)
                if let f = preview?.parsed.format, !f.isEmpty { LabeledContent("格式") { SourceFormatBadge(format: f) } }
                if let d = preview?.parsed.desc, !d.isEmpty { Text(d).font(.caption).foregroundStyle(.secondary) }
                else if !item.desc.isEmpty { Text(item.desc).font(.caption).foregroundStyle(.secondary) }
                if !item.author.isEmpty { LabeledContent("作者", value: item.author) }
                Text(item.url).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(3)
            }
            .listRowBackground(Theme.card)

            if let e = error {
                Section { ErrorRow(message: e) }.listRowBackground(Theme.card)
            } else if let p = preview?.parsed {
                Section {
                    PreviewSummary(parsed: p)
                    if let m = installed {
                        Toggle("启用", isOn: Binding(get: { m.enabled }, set: { store.setModuleEnabled(m.id, $0) }))
                        NavigationLink { ModuleDetailView(moduleID: m.id) } label: { Label("模块设置", systemImage: "slider.horizontal.3") }
                    } else {
                        Button {
                            added = store.addPreviewedModule(url: item.url, text: preview!.text, name: p.name.isEmpty ? item.name : p.name)
                            ResourceStore.shared.reload()
                        } label: { Label("添加模块", systemImage: "plus.circle.fill").font(.body.weight(.semibold)) }
                        .disabled(isEmpty(p))
                    }
                    Button { showText = true } label: { Label("查看内容", systemImage: "doc.text") }
                } footer: {
                    if isEmpty(p) { Text("未识别到可用的重写、脚本或 MitM 内容") }
                    else if !p.hostnames.isEmpty && store.caTrusted != true { Text("包含 HTTPS 重写或脚本：需要在 MitM 页安装并信任证书后才会生效。") }
                }
                .listRowBackground(Theme.card)
                PreviewSections(parsed: p)
            } else {
                Section { HStack { ProgressView(); Text("正在下载模块…").foregroundStyle(.secondary) } }.listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(item.name)
        .navigationBarTitleDisplayMode(.inline)
        .task { await load() }
        .refreshable { await load() }
        .sheet(isPresented: $showText) {
            NavigationStack {
                ScrollView { Text(preview?.text ?? "").font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding() }
                    .background(Theme.bg.ignoresSafeArea())
                    .navigationTitle(item.name).navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("完成") { showText = false } } }
            }
        }
        .alert("已添加", isPresented: $added) { Button("好") {} } message: { Text("「\(item.name)」已添加并启用，正在运行时会自动重载。") }
    }

    func isEmpty(_ p: ParsedEngineText) -> Bool {
        p.rules.isEmpty && p.hostnames.isEmpty && p.coreRules.isEmpty && (p.tasks ?? []).isEmpty && (p.panels ?? []).isEmpty
    }

    func load() async {
        error = nil
        do { preview = try await ModuleGallery.preview(item.url) } catch { self.error = String(localized: "下载失败：\(error.localizedDescription)") }
    }
}

/// Count chips: rewrites / scripts / MitM hostnames / rules / tasks / panels.
struct PreviewSummary: View {
    let parsed: ParsedEngineText
    var body: some View {
        let scripts = parsed.rules.filter { $0.kind == "script" }.count
        let rewrites = parsed.rules.count - scripts
        let hosts = parsed.hostnames.filter { !$0.hasPrefix("-") }.count
        let chips: [(String, Int)] = [("重写", rewrites), ("脚本", scripts), ("MitM 主机", hosts), ("规则", parsed.coreRules.count),
                                      ("任务", (parsed.tasks ?? []).count), ("面板", (parsed.panels ?? []).count)].filter { $0.1 > 0 }
        if chips.isEmpty {
            Text("没有可用内容").font(.subheadline).foregroundStyle(.secondary)
        } else {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(chips, id: \.0) { c in
                        VStack(spacing: 2) {
                            Text("\(c.1)").font(.headline.monospacedDigit())
                            Text(LocalizedStringKey(c.0)).font(.caption2).foregroundStyle(.secondary)
                        }
                        .frame(minWidth: 56).padding(.vertical, 6).padding(.horizontal, 8)
                        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.cardHi))
                    }
                }
            }
        }
    }
}

/// What the module would add, section by section (first 50 lines each).
struct PreviewSections: View {
    let parsed: ParsedEngineText
    let cap = 50

    var body: some View {
        let scripts = parsed.rules.filter { $0.kind == "script" }
        let rewrites = parsed.rules.filter { $0.kind != "script" }
        if !rewrites.isEmpty {
            Section(header: Text("重写 · \(rewrites.count)")) {
                ForEach(Array(rewrites.prefix(cap).enumerated()), id: \.offset) { _, r in previewRule(r) }
                more(rewrites.count)
            }.listRowBackground(Theme.card)
        }
        if !scripts.isEmpty {
            Section(header: Text("脚本 · \(scripts.count)")) {
                ForEach(Array(scripts.prefix(cap).enumerated()), id: \.offset) { _, r in previewRule(r) }
                more(scripts.count)
            }.listRowBackground(Theme.card)
        }
        if !parsed.hostnames.isEmpty {
            Section(header: Text("MitM 主机名 · \(parsed.hostnames.count)")) {
                Text(parsed.hostnames.prefix(200).joined(separator: ", ")).font(.caption.monospaced()).textSelection(.enabled)
            }.listRowBackground(Theme.card)
        }
        if !parsed.coreRules.isEmpty {
            Section(header: Text("规则 · \(parsed.coreRules.count)")) {
                ForEach(Array(parsed.coreRules.prefix(cap).enumerated()), id: \.offset) { _, l in
                    Text(l).font(.caption.monospaced()).lineLimit(2)
                }
                more(parsed.coreRules.count)
            }.listRowBackground(Theme.card)
        }
        if let t = parsed.tasks, !t.isEmpty {
            Section(header: Text("任务 · \(t.count)")) {
                ForEach(Array(t.prefix(cap).enumerated()), id: \.offset) { _, task in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) { KindBadge(kind: task.kind); Text(task.name).font(.subheadline).lineLimit(1) }
                        Text(task.cron ?? task.event ?? task.path).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }.listRowBackground(Theme.card)
        }
        if let ps = parsed.panels, !ps.isEmpty {
            Section(header: Text("面板 · \(ps.count)")) {
                ForEach(Array(ps.enumerated()), id: \.offset) { _, p in
                    LabeledContent(p.title.isEmpty ? p.name : p.title, value: p.script ?? "")
                }
            }.listRowBackground(Theme.card)
        }
        if !parsed.arguments.isEmpty {
            Section {
                ForEach(parsed.arguments, id: \.key) { a in LabeledContent(a.desc?.isEmpty == false ? a.desc! : a.key, value: a.default) }
            } header: { Text("参数 · \(parsed.arguments.count)") } footer: { Text("添加后可以在模块设置里修改参数。") }
            .listRowBackground(Theme.card)
        }
        if !parsed.unsupported.isEmpty || !parsed.errors.isEmpty {
            Section(header: Text("暂不支持 · \(parsed.unsupported.count + parsed.errors.count)")) {
                ForEach(Array((parsed.errors + parsed.unsupported).prefix(cap).enumerated()), id: \.offset) { _, l in
                    Text(l).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                }
            }.listRowBackground(Theme.card)
        }
    }

    @ViewBuilder func previewRule(_ r: ParsedEngineText.Rule) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                KindBadge(kind: r.kind, phase: r.phase)
                Text(r.desc).font(.caption).lineLimit(1)
            }
            Text(r.pattern).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
        }
    }

    @ViewBuilder func more(_ n: Int) -> some View {
        if n > cap { Text("另外 \(n - cap) 条，点「查看内容」看全文").font(.caption2).foregroundStyle(.secondary) }
    }
}

struct GallerySourcesView: View {
    @ObservedObject var gallery = ModuleGallery.shared
    @Environment(\.dismiss) private var dismiss
    @State private var adding = false
    @State private var url = ""
    @State private var name = ""
    @State private var error: String?

    var body: some View {
        List {
            Section {
                ForEach(gallery.sources) { s in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(s.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            Spacer()
                            if gallery.loading.contains(s.id) { ProgressView() }
                            else if let i = gallery.indexes[s.id] { Text("\(i.items.count) 个模块").font(.caption).foregroundStyle(.secondary) }
                        }
                        Text(s.url).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                        if let e = gallery.indexes[s.id]?.error, !e.isEmpty {
                            Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.bad).lineLimit(2)
                        } else if let t = gallery.indexes[s.id]?.fetchedAt, t > 0 {
                            Text("更新于 \(Date(timeIntervalSince1970: t).formatted(.relative(presentation: .named)))").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { gallery.removeSource(s) } label: { Label("删除", systemImage: "trash") }
                    }
                    .swipeActions(edge: .leading) {
                        Button { Task { await gallery.refresh(s) } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(Theme.accent)
                    }
                }
                .onMove { from, to in gallery.sources.move(fromOffsets: from, toOffset: to); gallery.saveSources() }
                if gallery.sources.isEmpty { Text("没有来源").foregroundStyle(.secondary) }
            } footer: {
                Text("支持：GitHub 仓库或文件夹链接（列出其中的 .sgmodule / .plugin / .stoverride / .snippet 文件，子文件夹作为分类）、JSON 列表（name、url、desc、category）、包含模块链接或安装链接的网页、Markdown 或文本。")
            }
            .listRowBackground(Theme.card)
            Section {
                Button { url = ""; name = ""; adding = true } label: { Label("添加来源", systemImage: "plus") }
                Button { gallery.restoreDefaults() } label: { Label("恢复默认来源", systemImage: "arrow.uturn.backward") }
                    .disabled(ModuleGallery.defaultSources.allSatisfy { d in gallery.sources.contains { $0.url == d.url } })
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("索引来源")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            ToolbarItem(placement: .navigationBarLeading) { EditButton() }
        }
        .alert("添加来源", isPresented: $adding) {
            TextField("https://github.com/…", text: $url).textInputAutocapitalization(.never).autocorrectionDisabled()
            TextField("名称（可选）", text: $name)
            Button("添加") { error = gallery.addSource(url: url, name: name) }
            Button("取消", role: .cancel) {}
        }
        .alert("无法添加", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("好") { error = nil }
        } message: { Text(error ?? "") }
    }
}
