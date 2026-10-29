import SwiftUI
import UniformTypeIdentifiers
import UserNotifications

/// Form model for the rewrite editor (formerly shared with the old side's
/// mitm.RewriteForm, now converted natively by NCRewriteFormConverter):
/// one form <-> one canonical Surge-syntax line.
struct RewriteForm: Codable, Equatable {
    var type: String = "reject"
    var pattern: String = ""
    var phase: String? = "request"
    var action: String? = "reject"
    var target: String? = nil
    var headerOp: String? = "add"
    var headerName: String? = nil
    var headerValue: String? = nil
    var headerRegex: String? = nil
    var regex: String? = nil
    var replacement: String? = nil
    var data: String? = nil
    var dataType: String? = "text"
    var status: Int? = nil
    var contentType: String? = nil
    var headers: String? = nil
    var line: String? = nil
    var error: String? = nil
    var desc: String? = nil

    static func fromLine(_ line: String) -> RewriteForm {
        NCRewriteFormConverter.form(fromLine: line)
    }

    /// Canonical line + validation through the engine parser.
    func validated() -> RewriteForm {
        NCRewriteFormConverter.line(fromForm: self)
    }
}

/// 工具 → 重写 (Quantumult X style, user 2026-10-22): ONE page for everything that rewrites traffic. It replaced the
/// three cards 模块 / 重写 / 脚本:
///   • 启用复写 / 启用脚本 on top (separate switches since feat/loon-rewrite-ui),
///   • 订阅 — remote modules / plugins / rewrite_remote (and pasted ones), unified subscription rows (SubscriptionKit),
///   • 本地 — the user's own rewrite rules and script lines (engine.json `rules` / `scripts`), forms or text,
///   • MitM 主机名, 浏览 (全部重写规则, 模块库), 脚本工具 (调试台, 日志, 通知, 存储, 本地脚本文件).
/// Cron / event scripts run under 工具 → 定时任务; the profile's rule-providers are linked from 分流规则.
struct RewriteView: View {
    /// Official BoxJS Surge module (chavyleung/scripts): serves http(s)://boxjs.com from an http-request script.
    static let boxJSModule = "https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.surge.sgmodule"
    @ObservedObject var store = EngineStore.shared
    @ObservedObject var res = ResourceStore.shared
    @ObservedObject private var downloads = BackgroundDownloads.shared
    @State private var editing: EditTarget?
    @State private var rawMode = false
    @State private var rawText = ""
    @State private var rawIssues: [String] = []
    @State private var search = ""
    @State private var newHost = ""
    @State private var editMode: EditMode = .inactive
    /// feat/long-press-reorder: long-press drag in the normal list (排序 / edit mode stays as the fallback).
    @StateObject private var dragModules = DragReorderState<EngineModule>()
    @StateObject private var dragRules = DragReorderState<EngineItem>()
    @StateObject private var dragScripts = DragReorderState<EngineItem>()
    @State private var editingModule: EngineModule?
    /// fix/nc-0.20.2: 编辑订阅 (URL / 名称 / 自动更新 / 启用) from the row's swipe / long-press 编辑.
    @State private var editingSub: EngineModule?
    @State private var pendingDelete: EngineModule?
    @State private var addingURL = false
    @State private var url = ""
    @State private var pasting = false
    @State private var addingScript = false
    @State private var addingScriptLine = false
    @State private var editingScript: EngineItem?
    @State private var debugging: EngineItem?
    /// 订阅 category filter ("" = all) and category / author from the 模块库 indexes, keyed by normalized URL.
    @State private var categoryFilter = ""
    @State private var galleryMeta: [String: GalleryMeta] = [:]

    struct GalleryMeta: Hashable {
        var category: String
        var author: String
    }

    struct EditTarget: Identifiable {
        let id = UUID()
        let item: EngineItem?
        let type: String
        var phase: String = "request"
    }

    func matches(_ it: EngineItem) -> Bool {
        search.isEmpty || it.line.localizedCaseInsensitiveContains(search) || (it.note ?? "").localizedCaseInsensitiveContains(search)
    }

    var rules: [EngineItem] { store.config.rules.filter(matches) }
    var scripts: [EngineItem] { store.config.scripts.filter(matches) }
    var modules: [EngineModule] {
        store.config.modules.filter { m in
            (categoryFilter.isEmpty || category(of: m) == categoryFilter)
                && (search.isEmpty || m.name.localizedCaseInsensitiveContains(search) || m.url.localizedCaseInsensitiveContains(search)
                    || author(of: m).localizedCaseInsensitiveContains(search))
        }
    }

    /// The module's own #!category / #!tag, else the category it has in a 模块库 index.
    func category(of m: EngineModule) -> String {
        if let c = store.moduleInfo[m.id]?.category?.trimmingCharacters(in: .whitespaces), !c.isEmpty { return c }
        return m.url.isEmpty ? "" : (galleryMeta[ModuleGallery.normalizedURL(m.url)]?.category ?? "")
    }

    /// The module's own #!author, else its author in a 模块库 index.
    func author(of m: EngineModule) -> String {
        if let a = store.moduleInfo[m.id]?.author?.trimmingCharacters(in: .whitespaces), !a.isEmpty { return a }
        return m.url.isEmpty ? "" : (galleryMeta[ModuleGallery.normalizedURL(m.url)]?.author ?? "")
    }

    var moduleCategories: [String] {
        var seen = Set<String>()
        return store.config.modules.map { category(of: $0) }.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    @MainActor static func galleryMeta(_ g: ModuleGallery) -> [String: GalleryMeta] {
        var out: [String: GalleryMeta] = [:]
        for idx in g.indexes.values {
            for it in idx.items where !it.category.isEmpty || !it.author.isEmpty {
                for u in ModuleGallery.urls(of: it) {
                    let k = ModuleGallery.normalizedURL(u)
                    if out[k] == nil { out[k] = GalleryMeta(category: it.category, author: it.author) }
                }
            }
        }
        return out
    }

    var body: some View {
        Group {
            if rawMode { rawEditor } else { formList }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("重写")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .toolbar {
            if rawMode {
                ToolbarItem(placement: .navigationBarLeading) { Button("放弃修改") { rawMode = false; rawIssues = [] } }
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { applyRaw() } }
            } else if editMode.isEditing {
                ToolbarItem(placement: .navigationBarTrailing) {
                    ReorderToolbarButton(isEditing: true, id: "rewrite.reorder") { withAnimation { editMode = .inactive } }
                }
            } else {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    UpdateAllButton(busy: res.updatingAll, id: "rewrite.updateAll") { Task { await res.updateAll() } }
                    // fix/nc-0.20.2: the shared 排序 button (was ⋯ → 调整顺序).
                    ReorderToolbarButton(isEditing: false,
                                         count: canReorderModules ? max(store.config.modules.count, store.config.rules.count, store.config.scripts.count) : 0,
                                         id: "rewrite.reorder") { withAnimation { editMode = .active } }
                    Menu {
                        Button { rawText = Self.text(store.config); rawIssues = []; rawMode = true } label: { Label("以文本编辑本地规则", systemImage: "doc.plaintext") }
                    } label: { Image(systemName: "ellipsis.circle") }
                        .accessibilityIdentifier("rewrite.more")
                    addMenu
                }
            }
        }
        .environment(\.editMode, $editMode)
        .onChange(of: search) { q in if !q.isEmpty && editMode.isEditing { editMode = .inactive } }
        .sheet(item: $editing) { t in RewriteRuleEditor(target: t) }
        .sheet(item: $editingModule, onDismiss: { res.reload() }) { m in
            ModuleSubSheet(module: m) { d in store.deleteModule(d); res.reload() }
        }
        .sheet(isPresented: $addingURL) {
            ModuleSubscriptionSheet(initialURL: url) { f in Task { await store.addModule(fields: f); res.reload() } }
        }
        .sheet(item: $editingSub, onDismiss: { res.reload() }) { m in
            ModuleSubscriptionSheet(editing: m) { f in Task { await store.editModuleSubscription(m.id, fields: f); res.reload() } }
        }
        .sheet(isPresented: $pasting, onDismiss: { res.reload() }) { PasteModuleSheet() }
        .sheet(isPresented: $addingScript) { ScriptFormSheet(item: nil) }
        .sheet(isPresented: $addingScriptLine) { LineEditorSheet(title: "粘贴脚本行", scripts: true, item: nil) }
        .sheet(item: $editingScript) { ScriptFormSheet(item: $0) }
        .navigationDestination(isPresented: Binding(get: { debugging != nil }, set: { if !$0 { debugging = nil } })) {
            if let it = debugging { ScriptWorkbenchView(target: .item(it)) }
        }
        .deleteConfirmation({ m in Text("删除「\(m.name)」？") }, item: $pendingDelete, message: { _ in DeleteText.recoverable }) { m in
            store.deleteModule(m)
            res.reload()
        }
        .alert("提示", isPresented: Binding(get: { store.message != nil || res.message != nil }, set: { if !$0 { store.message = nil; res.message = nil } })) {
            Button("好") { store.message = nil; res.message = nil }
        } message: { Text(store.message ?? res.message ?? "") }
        .overlay { if store.busy.contains("add") { ProgressView("下载中…").padding().background(RoundedRectangle(cornerRadius: 12).fill(Theme.cardHi)) } }
        .task {
            // v0.19.8: no synchronous the old core parsing during the push animation.
            try? await Task.sleep(nanoseconds: 350_000_000)
            await store.reparseModulesInBackground()
            await res.reloadInBackground()
            galleryMeta = Self.galleryMeta(ModuleGallery.shared)
        }
        .onChange(of: store.config.modules) { _ in res.reload() }
        .onAppear { if !store.config.scripts.isEmpty { store.requestNotificationPermission() } }
    }

    var addMenu: some View {
        Menu {
            Section("订阅") {
                Button { url = ""; addingURL = true } label: { Label("从 URL 添加订阅", systemImage: "link") }
                Button { pasting = true } label: { Label("粘贴订阅内容", systemImage: "doc.on.clipboard") }
                Button { Task { await store.addModule(url: RewriteView.boxJSModule); res.reload() } } label: { Label("添加 BoxJS（需开启 MitM 并信任证书）", systemImage: "shippingbox") }
                    .disabled(store.config.modules.contains { $0.url == RewriteView.boxJSModule })
            }
            Section("本地重写") {
                Button { editing = EditTarget(item: nil, type: "reject") } label: { Label("拒绝请求（reject）", systemImage: "nosign") }
                Button { editing = EditTarget(item: nil, type: "redirect") } label: { Label("重定向（302 / 307）", systemImage: "arrowshape.turn.up.right") }
                Button { editing = EditTarget(item: nil, type: "header", phase: "request") } label: { Label("修改请求头", systemImage: "list.bullet.indent") }
                Button { editing = EditTarget(item: nil, type: "header", phase: "response") } label: { Label("修改响应头", systemImage: "list.bullet.indent") }
                Button { editing = EditTarget(item: nil, type: "body", phase: "response") } label: { Label("正则替换响应体", systemImage: "text.magnifyingglass") }
                Button { editing = EditTarget(item: nil, type: "body", phase: "request") } label: { Label("正则替换请求体", systemImage: "text.magnifyingglass") }
                Button { editing = EditTarget(item: nil, type: "maplocal") } label: { Label("本地映射（Map Local）", systemImage: "doc.richtext") }
                Button { editing = EditTarget(item: nil, type: "raw") } label: { Label("粘贴规则文本", systemImage: "doc.on.clipboard") }
            }
            Section("本地脚本") {
                Button { addingScript = true } label: { Label("新建 / 导入脚本", systemImage: "doc.badge.plus") }
                Button { addingScriptLine = true } label: { Label("粘贴脚本行", systemImage: "text.badge.plus") }
            }
        } label: { Image(systemName: "plus") }
        .accessibilityIdentifier("localmodule.add")
    }

    /// fix/nc-0.20.2: a download that failed while the VPN was off shows 「待重试（连接后自动下载）」 until it is fetched.
    func moduleStatus(_ m: EngineModule, item: ResourceItem?, info: ParsedEngineText?) -> SubscriptionStatus {
        var status = ModuleSubSheet.status(m, item: item, info: info)
        if let p = downloads.pendingModules[m.id], m.enabled { status.error = p }
        return status
    }

    @ViewBuilder
    func moduleRow(_ m: EngineModule) -> some View {
        let info = store.moduleInfo[m.id]
        let item = res.items.first { $0.key == "module:" + m.id }
        let remote = !m.url.isEmpty
        let busy = store.busy.contains(m.id) || res.busy.contains("module:" + m.id) || downloads.fetching.contains(m.id)
        let status = moduleStatus(m, item: item, info: info)
        SubscriptionRow(id: "module.row." + m.name, icon: remote ? "puzzlepiece.extension" : "doc.text", color: Theme.tone(0.55, 0.45, 1.0),
                        name: m.name, status: status, updating: busy,
                        enabled: Binding(get: { m.enabled }, set: { on in setModule(m, on) }),
                        onTap: { editingModule = m }) {
            if let f = info?.format, !f.isEmpty { SourceFormatBadge(format: f) }
        }
        .subscriptionActions(SubscriptionActions(
            update: remote && !busy ? { if let it = item { Task { await res.update(it) } } } : nil,
            edit: { if remote { editingSub = m } else { editingModule = m } }, url: remote ? m.url : nil,
            enabled: m.enabled, setEnabled: { on in setModule(m, on) },
            delete: { pendingDelete = m }))
    }

    /// 订阅 order = load order (mitm.Build: earlier subscriptions' rewrites and scripts match first). Moving is off
    /// while searching or with a category chip other than 全部 (a filtered list cannot place the hidden rows).
    var canReorderModules: Bool { search.isEmpty && categoryFilter.isEmpty }

    func moveModules(_ from: IndexSet, _ to: Int) {
        guard canReorderModules else { return }
        store.config.modules.move(fromOffsets: from, toOffset: to)
        store.save() // reloads the tunnel (debounced): the new order takes effect now
    }

    func setModule(_ m: EngineModule, _ on: Bool) {
        guard let i = store.config.modules.firstIndex(where: { $0.id == m.id }), store.config.modules[i].enabled != on else { return }
        store.config.modules[i].enabled = on
        store.save()
        res.reload()
    }

    var formList: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.enabled }, set: { store.config.enabled = $0; store.save() })) {
                    Label("启用复写", systemImage: "arrow.triangle.swap")
                }
                .accessibilityIdentifier("rewrite.enabled")
                Toggle(isOn: Binding(get: { store.config.scriptsEnabled }, set: { store.config.scriptsEnabled = $0; store.save() })) {
                    Label("启用脚本", systemImage: "curlybraces")
                }
                .accessibilityIdentifier("rewrite.scripts.enabled")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("复写包括 URL 重写、修改请求头和正文、本地映射；脚本包括请求 / 响应脚本和定时任务。两个开关分别控制订阅和本地的同类规则。")
                    EngineSwitchFooter()
                }
            }
            .listRowBackground(Theme.card)

            Section {
                if store.config.modules.isEmpty {
                    EmptyStateRow(icon: "puzzlepiece.extension", title: "还没有重写订阅", message: "点右上角 + 通过 URL 添加，或在模块库里选择。")
                }
                let cats = moduleCategories
                if !cats.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            GalleryChip(title: String(localized: "全部"), selected: categoryFilter.isEmpty) { categoryFilter = "" }
                            ForEach(cats, id: \.self) { c in
                                GalleryChip(title: ModuleGallery.categoryTitle(c), selected: categoryFilter == c) { categoryFilter = categoryFilter == c ? "" : c }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .listRowInsets(EdgeInsets(top: 6, leading: 12, bottom: 6, trailing: 12))
                    .accessibilityIdentifier("rewrite.subs.categories")
                    .onChange(of: cats) { cs in if !categoryFilter.isEmpty && !cs.contains(categoryFilter) { categoryFilter = "" } }
                    .onChange(of: categoryFilter) { c in if !c.isEmpty && editMode.isEditing { editMode = .inactive } }
                }
                ForEach(dragModules.shown(modules)) { m in
                    moduleRow(m)
                        .modifier(LongPressReorderRow(item: m, state: dragModules,
                                                      enabled: !editMode.isEditing && canReorderModules) {
                            dragModules.begin(m.id, from: modules) { w in
                                store.config.modules = w
                                store.save() // reloads the tunnel (debounced): the new order takes effect now
                            }
                        })
                }
                    .onMove(perform: editMode.isEditing && canReorderModules ? moveModules : nil)
            } header: {
                HStack {
                    Text("订阅 \(store.config.modules.count)")
                    Spacer()
                    if res.updatingAll { ProgressView().scaleEffect(0.7) }
                }
                .accessibilityIdentifier("rewrite.subs.header")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Surge 模块、Loon 插件、QX 引用（rewrite_remote）、Stash 覆写和 Egern 模块都是订阅，角标显示格式。轻点编辑；右滑更新，左滑删除或编辑；开关启用或关闭；长按查看全部操作。订阅引用的远程脚本和规则集随它一起更新。")
                    Text("订阅按列表顺序生效：越靠上越先匹配。长按一行直接拖动调整顺序，也可点右上角「排序」（搜索或筛选分类时不能排序）。")
                }
                .modifier(UITestOrderValue(id: "rewrite.subs.order", order: store.config.modules.map(\.name).joined(separator: " | ")))
            }
            .listRowBackground(Theme.card)
            .onDrop(of: [UTType.text], delegate: GroupListDropDelegate(drop: { dragModules.finish() }))

            Section {
                if store.config.rules.isEmpty && store.config.scripts.isEmpty {
                    EmptyStateRow(icon: "arrow.triangle.swap", title: "还没有本地规则", message: "点右上角 + 添加重写或脚本；Surge、Quantumult X、Loon 写法都能识别。")
                }
                ForEach(dragRules.shown(rules)) { it in
                    RuleRow(item: it) { on in
                        if let i = store.config.rules.firstIndex(where: { $0.id == it.id }) { store.config.rules[i].enabled = on; store.save() }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editing = EditTarget(item: it, type: "") }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { store.config.rules.removeAll { $0.id == it.id }; store.save() } label: { Label("删除", systemImage: "trash") }
                    }
                    .modifier(LongPressReorderRow(item: it, state: dragRules,
                                                  enabled: !editMode.isEditing && search.isEmpty) {
                        dragRules.begin(it.id, from: rules) { w in
                            store.config.rules = w
                            store.save()
                        }
                    })
                }
                .onMove(perform: editMode.isEditing && search.isEmpty ? { (from: IndexSet, to: Int) in
                    store.config.rules.move(fromOffsets: from, toOffset: to); store.save()
                } : nil)
                ForEach(dragScripts.shown(scripts)) { it in
                    RuleRow(item: it) { on in
                        if let i = store.config.scripts.firstIndex(where: { $0.id == it.id }) { store.config.scripts[i].enabled = on; store.save() }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editingScript = it }
                    .swipeActions(edge: .leading) {
                        Button { debugging = it } label: { Label("调试", systemImage: "play.fill") }.tint(Theme.accent)
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { store.config.scripts.removeAll { $0.id == it.id }; store.save() } label: { Label("删除", systemImage: "trash") }
                    }
                    .contextMenu {
                        Button { editingScript = it } label: { Label("编辑", systemImage: "pencil") }
                        Button { debugging = it } label: { Label("在调试台打开", systemImage: "play.fill") }
                    }
                    .modifier(LongPressReorderRow(item: it, state: dragScripts,
                                                  enabled: !editMode.isEditing && search.isEmpty) {
                        dragScripts.begin(it.id, from: scripts) { w in
                            store.config.scripts = w
                            store.save()
                        }
                    })
                }
                .onMove(perform: editMode.isEditing && search.isEmpty ? { (from: IndexSet, to: Int) in
                    store.config.scripts.move(fromOffsets: from, toOffset: to); store.save()
                } : nil)
            } header: { Text("本地 \(store.config.rules.count + store.config.scripts.count)") } footer: {
                Text("你自己的重写和脚本，与订阅一起生效、优先于它们。点 + 用表单添加，或在 ⋯ 里以文本编辑；重写按顺序匹配，长按可拖动调整顺序。")
            }
            .listRowBackground(Theme.card)
            .onDrop(of: [UTType.text], delegate: GroupListDropDelegate(drop: { dragRules.finish(); dragScripts.finish() }))

            Section {
                ForEach(store.config.hostnames, id: \.self) { h in
                    HStack {
                        Text(h).font(.system(.callout, design: .monospaced))
                        Spacer()
                        if h.hasPrefix("-") { Text("排除").font(.caption2).foregroundStyle(.secondary) }
                    }
                }
                .onDelete { idx in store.config.hostnames.remove(atOffsets: idx); store.save() }
                .onMove(perform: editMode.isEditing ? { (from: IndexSet, to: Int) in store.config.hostnames.move(fromOffsets: from, toOffset: to); store.save() } : nil)
                HStack {
                    TextField("example.com、*.example.com、-排除.com", text: $newHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.system(.callout, design: .monospaced))
                        .onSubmit(addHost)
                    Button("添加", action: addHost).disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: { Text("MitM 主机名 \(store.config.hostnames.count)") } footer: {
                Text("HTTPS 重写需要解密对应主机：在「HTTPS 解密」页开启解密并信任证书。支持 * 和 ? 通配、前缀 - 表示排除、:端口（默认 443）。")
            }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink { LazyDestination { AllRewritesView() } } label: {
                    MoreRow(id: "全部重写规则", title: "全部重写规则", subtitle: "所有订阅和本地的重写与脚本规则，平铺可搜索", symbol: "list.bullet.rectangle.portrait", tone: .neutral)
                }
                NavigationLink { LazyDestination { ScriptListView() } } label: {
                    MoreRow(id: "脚本列表", title: "脚本列表", subtitle: "订阅和本地的全部脚本，可查看源码、逐个停用", symbol: "curlybraces", tone: .orange)
                }
                NavigationLink { LazyDestination { ModuleGalleryView() } } label: {
                    MoreRow(id: "模块库", title: "模块库", subtitle: "浏览、搜索并预览索引来源里的模块", symbol: "books.vertical", tone: .blue)
                }
            } header: { Text("浏览") }
            .listRowBackground(Theme.card)

            Section("脚本工具") {
                NavigationLink { ScriptWorkbenchView(target: .scratch) } label: { Label("脚本调试台", systemImage: "play.rectangle") }
                NavigationLink { ScriptLogsView() } label: { Label("脚本日志", systemImage: "text.alignleft") }
                NavigationLink { ScriptNoticesView() } label: { Label("脚本通知记录", systemImage: "bell") }
                NavigationLink { StoreView() } label: { Label("持久化存储（$persistentStore / $prefs）", systemImage: "externaldrive") }
                NavigationLink { LocalScriptsView() } label: { Label("本地脚本文件", systemImage: "folder") }
                ScriptNotifyPermissionRow()
            }
            .listRowBackground(Theme.card)

            Section("语法速查") {
                SyntaxHelp()
                DisclosureGroup("兼容的脚本 API") {
                    Text("$request、$response、$done、$httpClient（get/post/put/delete/head/options/patch，支持 policy、binary-mode、insecure、auto-redirect）、$persistentStore（所有脚本共享）、$notification.post、$utils（geoip / ipasn / ipaso / ungzip）、$httpAPI（策略查询 / 切换、出站模式、重载配置）、$network、$script、$environment、$argument、console、setTimeout；Quantumult X：$task.fetch、$prefs、$notify；另提供 TextEncoder/TextDecoder、atob/btoa。脚本类型：http-request、http-response、cron（定时，连接期间执行）、event（network-changed）、generic（手动运行 / 面板）。Surge、Loon、Quantumult X、Stash、Egern（兼容写法）都能识别；暂不支持 Surge type=dns / type=rule 与 Egern 原生 ctx 脚本。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .automatic), prompt: "搜索订阅（名称、作者）和规则")
        .refreshable { await res.updateAll() }
    }

    var rawEditor: some View {
        VStack(spacing: 0) {
            if !rawIssues.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(rawIssues.prefix(6), id: \.self) { Text($0.hasPrefix("!") ? String($0.dropFirst()) : $0).font(.caption2) }
                    if rawIssues.count > 6 { Text("…还有 \(rawIssues.count - 6) 条").font(.caption2) }
                }
                .foregroundStyle(Theme.bad)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Theme.bad.opacity(0.12))
            }
            CodeEditor(text: $rawText, language: .conf)
            Text("每行一条规则；hostname = 行是 MitM 主机名；以 #off 开头的行是停用的规则。点「完成」校验并保存。")
                .font(.caption2).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Theme.card)
        }
        .onChange(of: rawText) { _ in rawIssues = [] }
    }

    func addHost() {
        let hosts = newHost.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        for h in hosts where !store.config.hostnames.contains(h) { store.config.hostnames.append(h) }
        newHost = ""
        store.save()
    }

    // MARK: text <-> store

    static func text(_ c: EngineConfig) -> String {
        var out = ["# 本地模块"]
        if !c.hostnames.isEmpty { out.append("hostname = " + c.hostnames.joined(separator: ", ")) }
        for r in c.rules {
            if let n = r.note, !n.isEmpty { out.append("# " + n.replacingOccurrences(of: "\n", with: " ")) }
            out.append((r.enabled ? "" : "#off ") + r.line)
        }
        return out.joined(separator: "\n") + "\n"
    }

    /// Parses the text back; validation through the engine parser (NCEngineParser). Errors block saving.
    func applyRaw() {
        var hosts: [String] = []
        var rules: [EngineItem] = []
        var scripts: [EngineItem] = []
        var pendingNote: String?
        var issues: [String] = []
        let old = store.config.rules
        var used = Set<String>()
        for raw in rawText.components(separatedBy: .newlines) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { pendingNote = nil; continue }
            var enabled = true
            if line.lowercased().hasPrefix("#off ") {
                enabled = false
                line = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
                let n = line.drop(while: { "#;/ ".contains($0) }).trimmingCharacters(in: .whitespaces)
                if n != "本地模块" && !n.isEmpty { pendingNote = n }
                continue
            } else if line.hasPrefix("[") {
                continue
            }
            if line.lowercased().hasPrefix("hostname"), let eq = line.firstIndex(of: "=") {
                for h in line[line.index(after: eq)...].split(separator: ",") {
                    let v = h.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "%APPEND%", with: "").replacingOccurrences(of: "%INSERT%", with: "").trimmingCharacters(in: .whitespaces)
                    if !v.isEmpty && !hosts.contains(v) { hosts.append(v) }
                }
                continue
            }
            let d = EngineStore.describe(line)
            if let e = d.error { issues.append("!" + e + "：" + String(line.prefix(80))) }
            // Keep id / note of an unchanged line.
            var item = EngineItem(enabled: enabled, line: line, note: pendingNote)
            if let o = old.first(where: { $0.line == line && !used.contains($0.id) }) {
                item.id = o.id
                if item.note == nil { item.note = o.note }
                used.insert(o.id)
            }
            pendingNote = nil
            if d.kind == "script" { scripts.append(item) } else { rules.append(item) }
        }
        if !issues.isEmpty { rawIssues = issues; return }
        store.config.rules = rules
        store.config.hostnames = hosts
        if !scripts.isEmpty { store.config.scripts.append(contentsOf: scripts) }
        store.save()
        rawMode = false
    }
}

/// Form editor for one rewrite rule; validation through the old core parsers.
struct RewriteRuleEditor: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var store = EngineStore.shared
    let target: RewriteView.EditTarget
    @State private var form = RewriteForm()
    @State private var checked = RewriteForm()
    @State private var note = ""
    @State private var loaded = false

    static let rejectActions: [(String, String)] = [
        ("reject", "reject（断开，返回 404）"), ("reject-200", "reject-200（空 200）"), ("reject-img", "reject-img（1×1 GIF）"),
        ("reject-dict", "reject-dict（空 JSON 对象 {}）"), ("reject-array", "reject-array（空 JSON 数组 []）"), ("reject-drop", "reject-drop（直接丢弃）"),
    ]

    var title: String {
        switch form.type {
        case "reject": return "拒绝请求"
        case "redirect": return "重定向"
        case "header": return form.phase == "response" ? "修改响应头" : "修改请求头"
        case "body": return form.phase == "response" ? "正则替换响应体" : "正则替换请求体"
        case "maplocal": return "本地映射"
        default: return "规则文本"
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                if form.type != "raw" {
                    Section {
                        TextField("^https?://api\\.example\\.com/v1/ad", text: $form.pattern, axis: .vertical)
                            .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    } header: { Text("URL 正则") } footer: { Text("匹配完整 URL（含 https://），JavaScript 正则语法。") }
                    .listRowBackground(Theme.card)
                }
                fields
                Section("备注") { TextField("可选", text: $note) }.listRowBackground(Theme.card)
                Section {
                    if let e = checked.error {
                        Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.bad)
                    } else if let d = checked.desc {
                        Label(CoreText.localize(d), systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.good)
                    }
                    if form.type != "raw", let l = checked.line, !l.isEmpty {
                        Text(l).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                } header: { Text("校验") }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(LocalizedStringKey(title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save(); dismiss() }.disabled(checked.error != nil || (checked.line ?? "").isEmpty)
                }
            }
            .onAppear(perform: load)
            .onChange(of: form) { _ in checked = form.validated() }
        }
    }

    @ViewBuilder
    var fields: some View {
        switch form.type {
        case "reject":
            Section("动作") {
                Picker("动作", selection: Binding(get: { form.action ?? "reject" }, set: { form.action = $0 })) {
                    ForEach(Self.rejectActions, id: \.0) { Text(LocalizedStringKey($0.1)).tag($0.0) }
                }
                .pickerStyle(.inline).labelsHidden()
            }
            .listRowBackground(Theme.card)
        case "redirect":
            Section {
                Picker("状态码", selection: Binding(get: { form.action == "307" ? "307" : "302" }, set: { form.action = $0 })) {
                    Text("302 临时跳转").tag("302")
                    Text("307 保留方法和请求体").tag("307")
                }
                .pickerStyle(.segmented)
                TextField("https://new.example.com/$1", text: opt(\.target))
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            } header: { Text("跳转到") } footer: { Text("可用 $1、$2 引用 URL 正则里的分组。") }
            .listRowBackground(Theme.card)
        case "header":
            Section {
                Picker("阶段", selection: Binding(get: { form.phase ?? "request" }, set: { form.phase = $0 })) {
                    Text("请求").tag("request")
                    Text("响应").tag("response")
                }
                .pickerStyle(.segmented)
                Picker("操作", selection: Binding(get: { form.headerOp ?? "add" }, set: { form.headerOp = $0 })) {
                    Text("添加").tag("add")
                    Text("替换").tag("replace")
                    Text("删除").tag("del")
                    Text("正则替换").tag("replace-regex")
                }
                TextField("头名，如 User-Agent", text: opt(\.headerName)).textInputAutocapitalization(.never).autocorrectionDisabled()
                if form.headerOp == "replace-regex" {
                    TextField("要替换的正则", text: opt(\.headerRegex)).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                if form.headerOp != "del" {
                    TextField("值", text: opt(\.headerValue)).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
            } header: { Text("头部") } footer: { Text("添加会追加一个同名头；替换只改已有的头（没有则不加）。") }
            .listRowBackground(Theme.card)
        case "body":
            Section {
                Picker("阶段", selection: Binding(get: { form.phase ?? "response" }, set: { form.phase = $0 })) {
                    Text("请求体").tag("request")
                    Text("响应体").tag("response")
                }
                .pickerStyle(.segmented)
                TextField("正则，如 \"ad\":\\s?true", text: opt(\.regex), axis: .vertical).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("替换为（可用 $1）", text: opt(\.replacement), axis: .vertical).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
            } header: { Text("替换") } footer: { Text("对整个内容做正则替换（自动解压 gzip / br），最大 2 MB。") }
            .listRowBackground(Theme.card)
        case "maplocal":
            Section {
                Picker("内容类型", selection: Binding(get: { form.dataType ?? "text" }, set: { form.dataType = $0 })) {
                    Text("文本").tag("text")
                    Text("Base64").tag("base64")
                    Text("文件 / URL").tag("file")
                    Text("1×1 GIF").tag("tiny-gif")
                }
                if form.dataType != "tiny-gif" {
                    TextField(form.dataType == "file" ? "本地脚本目录里的文件名或 https://…" : "{\"ok\":true}", text: opt(\.data), axis: .vertical)
                        .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                TextField("Content-Type，如 application/json", text: opt(\.contentType)).textInputAutocapitalization(.never).autocorrectionDisabled()
                HStack {
                    Text("状态码")
                    TextField("200", text: Binding(get: { form.status.map(String.init) ?? "" }, set: { form.status = Int($0) }))
                        .keyboardType(.numberPad).multilineTextAlignment(.trailing)
                }
                TextField("其他响应头：A:1|B:2", text: opt(\.headers)).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
            } header: { Text("返回内容") } footer: { Text("命中后直接由本机应答，不会请求服务器。") }
            .listRowBackground(Theme.card)
        default:
            Section {
                TextField("规则", text: opt(\.line), axis: .vertical)
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .lineLimit(3...10)
                if target.item == nil {
                    Button { form.line = UIPasteboard.general.string ?? "" } label: { Label("粘贴", systemImage: "doc.on.clipboard") } // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                }
            } header: { Text("规则文本") } footer: {
                Text(target.item == nil ? "一条 Surge / Quantumult X / Loon 重写行。多行请用「文本」模式。" : "这条规则的写法没有对应的表单（例如 JSON 操作或 jq），可以直接编辑文本。")
            }
            .listRowBackground(Theme.card)
        }
    }

    func opt(_ kp: WritableKeyPath<RewriteForm, String?>) -> Binding<String> {
        Binding(get: { form[keyPath: kp] ?? "" }, set: { form[keyPath: kp] = $0 })
    }

    func load() {
        guard !loaded else { return }
        loaded = true
        if let it = target.item {
            form = RewriteForm.fromLine(it.line)
            note = it.note ?? ""
        } else {
            form = RewriteForm(type: target.type, phase: target.phase)
            if target.type == "redirect" { form.action = "302" }
            if target.type == "body" { form.regex = ""; form.replacement = "" }
        }
        checked = form.validated()
    }

    func save() {
        guard checked.error == nil, let line = checked.line, !line.isEmpty else { return }
        let n = note.trimmingCharacters(in: .whitespaces)
        if let it = target.item, let i = store.config.rules.firstIndex(where: { $0.id == it.id }) {
            store.config.rules[i].line = line
            store.config.rules[i].note = n.isEmpty ? nil : n
        } else {
            store.config.rules.append(EngineItem(line: line, note: n.isEmpty ? nil : n))
            if !store.config.enabled { store.config.enabled = true }
        }
        store.save()
    }
}

/// 重写 → 脚本工具 → 允许脚本通知 (ui-audit): the old button only called requestAuthorization, which iOS answers
/// silently once the user has decided — after a 不允许 it did nothing at all. The row now shows the system
/// permission (未请求 / 已允许 / 已关闭); 未请求 asks, 已关闭 opens iOS Settings, 已允许 is informational.
struct ScriptNotifyPermissionRow: View {
    /// nil = not asked yet.
    @State private var allowed: Bool?
    @State private var loaded = false
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Button {
            if allowed == false {
                if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
            } else if allowed == nil {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in
                    Task { @MainActor in allowed = await NotificationAuth.allowed() }
                }
            }
        } label: {
            HStack {
                Label("允许脚本通知", systemImage: "bell.badge")
                Spacer()
                if loaded {
                    Text(LocalizedStringKey(allowed == nil ? "未请求" : allowed == true ? "已允许" : "已关闭"))
                        .foregroundStyle(allowed == false ? Theme.warn : Color.secondary)
                }
            }
        }
        .disabled(allowed == true)
        .accessibilityIdentifier("rewrite.notifyPermission")
        .task { allowed = await NotificationAuth.allowed(); loaded = true }
        .onChange(of: scenePhase) { p in
            if p == .active { Task { allowed = await NotificationAuth.allowed() } }
        }
    }
}
