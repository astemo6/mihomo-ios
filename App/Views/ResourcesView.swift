import SwiftUI
import UIKit
import Libmihomo

// 更多 → 模块 (id more.模块与资源): the one place for modules (every format, with badges) and the remote resources
// they and the custom rules use — rewrite sets, rule sets, scripts — each with an update interval,
// last update, enable switch and last error. Update-all at the top. No second screen elsewhere.

struct ModulesView: View {
    /// Official BoxJS Surge module (chavyleung/scripts): serves http(s)://boxjs.com from an http-request script.
    static let boxJSModule = "https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.surge.sgmodule"
    @ObservedObject var store = EngineStore.shared
    @ObservedObject var res = ResourceStore.shared
    @State private var filter = "all"
    @State private var adding = false
    @State private var url = ""
    @State private var pasting = false
    @State private var addingRuleSet = false
    /// Review 5: a full trailing swipe on a module / rule set asks first.
    @State private var pendingDelete: ResourceItem?

    var shown: [ResourceItem] {
        filter == "all" ? res.items : res.items.filter { $0.kind == filter }
    }

    func count(_ kind: String) -> Int { res.items.reduce(0) { $0 + ($1.kind == kind ? 1 : 0) } }

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.enabled }, set: { store.config.enabled = $0; store.save() })) {
                    Label("启用重写与脚本", systemImage: "puzzlepiece.extension")
                }
            }
            .listRowBackground(Theme.card)

            // feat/more-dedup: the one home for 重写 / 脚本 / 定时任务 / 规则集 (高级设置 no longer lists them).
            Section {
                NavigationLink { LazyDestination { LocalModuleView() } } label: {
                    MoreRow(id: "重写（本地模块）", title: "我的重写", subtitle: String(localized: "\(store.config.rules.count) 条重写 · \(store.config.hostnames.count) 个 MitM 主机名"),
                            symbol: "arrow.triangle.swap", tone: .orange)
                }
                NavigationLink { LazyDestination { ScriptsView() } } label: {
                    MoreRow(id: "脚本", title: "脚本", symbol: "curlybraces", tone: .purple)
                }
                NavigationLink { LazyDestination { ScriptTasksView() } } label: {
                    MoreRow(id: "任务", title: "定时任务", subtitle: "定时 · 网络变化 · 手动运行", symbol: "clock.arrow.circlepath", tone: .green)
                }
                NavigationLink { LazyDestination { ProvidersView() } } label: {
                    MoreRow(id: "规则集（配置）", title: "配置里的规则集", subtitle: "rule-providers", symbol: "list.bullet.rectangle", tone: .teal)
                }
            } header: { Text("我的") }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink { LazyDestination { ModuleGalleryView() } } label: {
                    MoreRow(id: "模块库", title: "模块库", subtitle: "浏览、搜索并预览索引来源里的模块", symbol: "books.vertical", tone: .blue)
                }
                NavigationLink { LazyDestination { AllRewritesView() } } label: {
                    MoreRow(id: "全部重写规则", title: "全部重写规则", subtitle: "所有模块的重写和脚本规则，平铺可搜索", symbol: "list.bullet.rectangle.portrait", tone: .neutral)
                }
            } header: { Text("浏览") }
            .listRowBackground(Theme.card)

            Section {
                Picker("类型", selection: $filter) {
                    Text("全部").tag("all")
                    Text("模块 \(count("module"))").tag("module")
                    Text("规则集 \(count("ruleset"))").tag("ruleset")
                    Text("脚本 \(count("script"))").tag("script")
                }
                .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                if shown.isEmpty {
                    EmptyStateRow(icon: filter == "ruleset" ? "list.bullet.rectangle" : "puzzlepiece.extension",
                                  title: filter == "ruleset" ? "没有规则集" : filter == "script" ? "没有远程脚本" : filter == "module" ? "没有模块" : "还没有模块或资源",
                                  message: filter == "ruleset" ? "点 + 添加远程规则集" : filter == "script" ? "启用的模块和脚本行引用的远程脚本会出现在这里。" : "点 + 通过 URL 导入模块")
                }
                ForEach(shown) { it in
                    NavigationLink {
                        if it.kind == "module", let id = it.refId { ModuleDetailView(moduleID: id) } else { ResourceDetailView(key: it.key) }
                    } label: { ResourceRow(item: it) }
                    .swipeActions(edge: .leading) {
                        if it.isRemote {
                            Button { Task { await res.update(it) } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(Theme.accent)
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        if it.kind == "module", let id = it.refId, store.config.modules.contains(where: { $0.id == id }) {
                            Button(role: .destructive) { pendingDelete = it } label: { Label("删除", systemImage: "trash") }
                        } else if it.kind == "ruleset", it.readOnly != true, it.refId != nil {
                            Button(role: .destructive) { pendingDelete = it } label: { Label("删除", systemImage: "trash") }
                        }
                    }
                }
            } header: {
                HStack {
                    Text(filter == "all" ? "全部 \(res.items.count)" : "\(shown.count) 项")
                    Spacer()
                    if res.updatingAll { ProgressView().scaleEffect(0.7) }
                }
            } footer: {
                Text("所有格式的模块都在这里：Surge .sgmodule、Quantumult X 重写、Loon .plugin、Stash .stoverride、Egern .yaml 模块和重写列表，角标显示来源格式。远程规则集（自定义规则里的 RULE-SET / filter_remote，以及模块引用的规则集）和模块引用的远程脚本也列在这里：每项可单独开关、设置更新间隔，失败原因显示在条目下方。打开 App 时自动更新到期的资源。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("模块")
        .refreshable { await res.updateAll() }
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button { Task { await res.updateAll() } } label: { Image(systemName: "arrow.clockwise") }
                    .disabled(res.updatingAll)
                    .accessibilityLabel(Text("全部更新"))
                Menu {
                    // v0.19.8 (user): opens empty; the clipboard is read only from the sheet's 粘贴 button.
                    Button { url = ""; adding = true } label: { Label("从 URL 导入模块", systemImage: "link") }
                    Button { pasting = true } label: { Label("粘贴模块内容", systemImage: "doc.on.clipboard") }
                    Button { addingRuleSet = true } label: { Label("添加远程规则集", systemImage: "list.bullet.rectangle") }
                    Divider()
                    Button { Task { await store.addModule(url: Self.boxJSModule); res.reload() } } label: { Label("添加 BoxJS（需开启 MitM 并信任证书）", systemImage: "shippingbox") }
                        .disabled(store.config.modules.contains { $0.url == Self.boxJSModule })
                } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $adding) {
            ModuleURLSheet(url: $url) { u in Task { await store.addModule(url: u); res.reload() } }
        }
        .alert("提示", isPresented: Binding(get: { store.message != nil || res.message != nil }, set: { if !$0 { store.message = nil; res.message = nil } })) {
            Button("好") { store.message = nil; res.message = nil }
        } message: { Text(store.message ?? res.message ?? "") }
        // v0.19.8: no synchronous Go parsing during the push / pop animation; the cached list shows at once and
        // the refreshed one replaces it a moment later.
        .task {
            try? await Task.sleep(nanoseconds: 350_000_000)
            await store.reparseModulesInBackground()
            await res.reloadInBackground()
        }
        .onChange(of: store.config.modules) { _ in res.reload() }
        .overlay { if store.busy.contains("add") { ProgressView("下载中…").padding().background(RoundedRectangle(cornerRadius: 12).fill(Theme.cardHi)) } }
        .sheet(isPresented: $pasting, onDismiss: { res.reload() }) { PasteModuleSheet() }
        .sheet(isPresented: $addingRuleSet) { AddRuleSetSheet() }
        .deleteConfirmation({ it in Text("删除「\(it.name)」？") }, item: $pendingDelete,
                            message: { it in it.kind == "module" ? DeleteText.recoverable : Text("会从自定义规则中删除这个规则集。") }) { it in
            guard let id = it.refId else { return }
            if it.kind == "module", let m = store.config.modules.first(where: { $0.id == id }) {
                store.deleteModule(m)
            } else if it.kind == "ruleset" {
                CustomRulesStore.shared.rules.removeAll { $0.id == id }
                CustomRulesStore.shared.save()
            }
            res.reload()
        }
    }
}

struct ResourceKindBadge: View {
    let kind: String
    var body: some View {
        let (t, c): (String, Color) = {
            switch kind {
            case "ruleset": return ("规则集", Theme.good)
            case "script": return ("脚本", Theme.accent)
            default: return ("模块", Theme.tone(0.55, 0.45, 1.0))
            }
        }()
        Text(LocalizedStringKey(t))
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(c.opacity(0.18)))
            .foregroundStyle(c)
    }
}

/// Source-format badge (SURGE / QX / LOON / STASH / EGERN / LIST / JS …).
struct SourceFormatBadge: View {
    let format: String
    var body: some View {
        let f = format.lowercased()
        let label: String = {
            switch f {
            case "qx": return "QX"
            case "domainset": return "DOMAIN-SET"
            case "list": return "LIST"
            case "js": return "JS"
            default: return f.uppercased()
            }
        }()
        Text(label)
            .scaledFont(8, weight: .bold)
            .padding(.horizontal, 4).padding(.vertical, 1)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(Theme.ink(0.1)))
    }
}

struct ResourceRow: View {
    @ObservedObject var res = ResourceStore.shared
    @ObservedObject var store = EngineStore.shared
    let item: ResourceItem

    var updatedText: String {
        if !item.isRemote { return String(localized: "本地") }
        if item.updatedAt == 0 { return String(localized: "尚未下载") }
        return String(localized: "更新于 \(Date(timeIntervalSince1970: item.updatedAt).formatted(.relative(presentation: .named)))")
    }

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    ResourceKindBadge(kind: item.kind)
                    Text(item.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                    if let f = item.format, !f.isEmpty { SourceFormatBadge(format: f) }
                }
                if item.kind == "module", let d = item.refId.flatMap({ store.moduleInfo[$0]?.desc }), !d.isEmpty {
                    Text(d).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                }
                if let d = item.detail, !d.isEmpty { Text(verbatim: GoText.localize(d)).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                if let o = item.owner, !o.isEmpty { Text("来自 \(o)").font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                HStack(spacing: 6) {
                    Text(updatedText)
                    if item.isRemote { Text("· 每 \(ResourceDetailView.intervalText(item.interval))") }
                    if item.isDue { Image(systemName: "clock.badge.exclamationmark").foregroundStyle(Theme.warn) }
                }
                .font(.caption2).foregroundStyle(.secondary)
                if let e = item.error, !e.isEmpty {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.bad).lineLimit(2)
                }
            }
            Spacer()
            if res.busy.contains(item.key) { ProgressView() }
            if item.readOnly == true {
                Image(systemName: "link").font(.caption).foregroundStyle(.secondary)
            } else {
                Toggle("", isOn: Binding(get: { item.enabled }, set: { res.setEnabled(item, $0) })).labelsHidden()
            }
        }
        .opacity(item.enabled ? 1 : 0.55)
    }
}

/// Update settings shared by the module detail page and the resource detail page.
struct ResourceUpdateSection: View {
    @ObservedObject var res = ResourceStore.shared
    let key: String

    var body: some View {
        if let it = res.items.first(where: { $0.key == key }), it.isRemote {
            Section("更新") {
                Text(it.url).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                if it.readOnly == true {
                    LabeledContent("更新间隔", value: ResourceDetailView.intervalText(it.interval))
                } else {
                    Picker("更新间隔", selection: Binding(get: { it.interval }, set: { res.setInterval(it, $0) })) {
                        ForEach(ResourceStore.intervals, id: \.1) { Text(LocalizedStringKey($0.0)).tag($0.1) }
                        if !ResourceStore.intervals.contains(where: { $0.1 == it.interval }) {
                            Text(ResourceDetailView.intervalText(it.interval)).tag(it.interval)
                        }
                    }
                }
                LabeledContent("上次更新", value: it.updatedAt == 0 ? String(localized: "尚未下载") : Date(timeIntervalSince1970: it.updatedAt).formatted(date: .abbreviated, time: .shortened))
                if let c = it.checkedAt, c > 0 {
                    LabeledContent("上次检查", value: Date(timeIntervalSince1970: c).formatted(date: .abbreviated, time: .shortened))
                }
                if let e = it.error, !e.isEmpty {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.bad)
                }
                Button { Task { await res.update(it) } } label: {
                    HStack { Label("立即更新", systemImage: "arrow.clockwise"); Spacer(); if res.busy.contains(it.key) { ProgressView() } }
                }
                .disabled(res.busy.contains(it.key))
            }
            .listRowBackground(Theme.card)
        }
    }
}

struct ResourceDetailView: View {
    let key: String
    @ObservedObject var res = ResourceStore.shared

    static func intervalText(_ s: Int) -> String {
        if s % 86400 == 0 { return String(localized: "\(s / 86400) 天") }
        if s % 3600 == 0 { return String(localized: "\(s / 3600) 小时") }
        return String(localized: "\(max(1, s / 60)) 分钟")
    }

    var item: ResourceItem? { res.items.first { $0.key == key } }

    var body: some View {
        List {
            if let it = item {
                Section {
                    HStack(spacing: 6) {
                        ResourceKindBadge(kind: it.kind)
                        Text(it.name).font(.headline)
                        if let f = it.format { SourceFormatBadge(format: f) }
                    }
                    if let d = it.detail, !d.isEmpty { LabeledContent("内容", value: GoText.localize(d)) }
                    if let o = it.owner, !o.isEmpty { LabeledContent("使用者", value: o) }
                    if it.readOnly != true {
                        Toggle("启用", isOn: Binding(get: { it.enabled }, set: { res.setEnabled(it, $0) }))
                    } else {
                        Text("由模块引用，随模块启用或停用。").font(.caption).foregroundStyle(.secondary)
                    }
                } footer: {
                    switch it.kind {
                    case "ruleset": Text("规则集保存在自定义规则里（更多 → 分流规则 → 自定义），这里管理它的下载与更新。Surge / Loon / QX 列表与 Egern YAML 规则集会转换为 mihomo 规则；不支持的行会被跳过。连接期间内核也会按间隔自动更新。")
                    case "script": Text("停用后，引用这个脚本的所有规则、定时任务和面板都不再运行（模块本身保持启用）。连接期间引擎会按间隔在后台刷新脚本。")
                    default: EmptyView()
                    }
                }
                .listRowBackground(Theme.card)
                ResourceUpdateSection(key: key)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(item?.name ?? String(localized: "资源"))
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct AddRuleSetSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var res = ResourceStore.shared
    @State private var url = ""
    @State private var policy = ""
    @State private var domainSet = false
    @State private var interval = 86400
    @State private var groups: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://…/rules.list", text: $url).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("策略", selection: $policy) {
                        ForEach(["DIRECT", "REJECT"] + groups, id: \.self) { Text($0).tag($0) }
                    }
                    Toggle("纯域名列表（DOMAIN-SET）", isOn: $domainSet)
                    Picker("更新间隔", selection: $interval) {
                        ForEach(ResourceStore.intervals, id: \.1) { Text(LocalizedStringKey($0.0)).tag($0.1) }
                    }
                } footer: {
                    Text("支持 Surge / Loon / Stash 规则列表、Quantumult X 分流列表、Egern YAML 规则集。添加后会写入自定义规则（置顶），并立即下载一次。")
                }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("添加规则集").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
                        let u = url, p = policy.isEmpty ? "DIRECT" : policy, d = domainSet, i = interval
                        dismiss()
                        Task { await res.addRuleSet(url: u, policy: p, domainSet: d, interval: i) }
                    }
                    .disabled(!url.hasPrefix("http"))
                }
            }
            .onAppear {
                guard let profile = AppShared.activeProfileURL?.path else { return }
                let home = AppShared.homeURL.path
                Task {
                    let g = await Task.detached { LibmihomoProfileGroups(home, profile) }.value
                    groups = (try? JSONDecoder().decode([String].self, from: Data(g.utf8))) ?? []
                    if policy.isEmpty { policy = groups.first ?? "DIRECT" }
                }
            }
        }
    }
}

/// 从 URL 导入模块 (v0.19.8: a sheet instead of an alert, so the URL field can carry a PasteButton; nothing is read
/// from the clipboard until 粘贴 is tapped).
struct ModuleURLSheet: View {
    @Binding var url: String
    let onImport: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("https://…/xxx.sgmodule", text: $url)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("moduleurl.field")
                        PasteButton(payloadType: String.self) { strings in
                            let t = (strings.first ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                            DispatchQueue.main.async {
                                if case .moduleURL(let u, _)? = ImportRouter.parse(t) { url = u } else { url = t }
                            }
                        }
                        .labelStyle(.iconOnly)
                        .buttonBorderShape(.capsule)
                        .accessibilityIdentifier("moduleurl.paste")
                    }
                } footer: {
                    Text("也可以粘贴 surge:/// loon:// stash:// quantumult-x:/// egern:/// 安装链接。")
                }
            }
            .navigationTitle("导入模块")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("导入") {
                        var u = url.trimmingCharacters(in: .whitespacesAndNewlines)
                        // Also accepts surge:/// loon:// stash:// quantumult-x:/// egern:/// install links.
                        if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { u = inner }
                        onImport(u)
                        dismiss()
                    }
                    .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .presentationDetents([.medium])
    }
}
