import SwiftUI
import UIKit
import Libmihomo

// 更多 → 模块与资源: the one place for modules (every format, with badges) and the remote resources
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
    /// QX shell: the page is drawn in QX chrome (back circle + capsule [全部更新 | +]) instead of a nav bar.
    var qx = false

    var shown: [ResourceItem] {
        filter == "all" ? res.items : res.items.filter { $0.kind == filter }
    }

    func count(_ kind: String) -> Int { res.items.filter { $0.kind == kind }.count }

    var body: some View {
        if qx {
            QXPage(title: String(localized: "模块与资源")) {
                QXCapsuleBar {
                    QXBarIcon(systemName: "arrow.triangle.2.circlepath", tint: res.updatingAll ? .secondary : .primary) {
                        Task { await res.updateAll() }
                    }
                    .disabled(res.updatingAll)
                    .accessibilityLabel(Text("全部更新"))
                    Menu { addMenu } label: {
                        Image(systemName: "plus").font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary).frame(width: 38, height: 40)
                    }
                    .accessibilityLabel(Text("添加"))
                }
            } content: {
                core.toolbar(.hidden, for: .navigationBar)
            }
        } else {
            core.toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button { Task { await res.updateAll() } } label: { Image(systemName: "arrow.clockwise") }
                        .disabled(res.updatingAll)
                        .accessibilityLabel(Text("全部更新"))
                    Menu { addMenu } label: { Image(systemName: "plus") }
                }
            }
        }
    }

    @ViewBuilder var addMenu: some View {
        Button {
            let clip = UIPasteboard.general.hasStrings ? (UIPasteboard.general.string ?? "") : ""
            let t = clip.trimmingCharacters(in: .whitespacesAndNewlines)
            if case .moduleURL(let u, _)? = ImportRouter.parse(t) { url = u } else { url = t.hasPrefix("http") ? t : "" }
            adding = true
        } label: { Label("从 URL 导入模块", systemImage: "link") }
        Button { pasting = true } label: { Label("粘贴模块内容", systemImage: "doc.on.clipboard") }
        Button { addingRuleSet = true } label: { Label("添加远程规则集", systemImage: "list.bullet.rectangle") }
        Divider()
        Button { Task { await store.addModule(url: Self.boxJSModule); res.reload() } } label: { Label("添加 BoxJS（需开启 MitM 并信任证书）", systemImage: "shippingbox") }
            .disabled(store.config.modules.contains { $0.url == Self.boxJSModule })
    }

    var core: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.enabled }, set: { store.config.enabled = $0; store.save() })) {
                    Label("启用重写与脚本", systemImage: "puzzlepiece.extension")
                }
                Picker("类型", selection: $filter) {
                    Text("全部").tag("all")
                    Text("模块 \(count("module"))").tag("module")
                    Text("规则集 \(count("ruleset"))").tag("ruleset")
                    Text("脚本 \(count("script"))").tag("script")
                }
                .pickerStyle(.segmented)
            } footer: {
                Text("所有格式的模块都在这里：Surge .sgmodule、Quantumult X 重写、Loon .plugin、Stash .stoverride、Egern .yaml 模块和重写列表，角标显示来源格式。远程规则集（自定义规则里的 RULE-SET / filter_remote，以及模块引用的规则集）和模块引用的远程脚本也列在这里：每项可单独开关、设置更新间隔，失败原因显示在条目下方。打开 App 时自动更新到期的资源。")
            }
            .listRowBackground(Theme.card)

            if filter == "all" || filter == "module" {
                Section {
                    NavigationLink { LocalModuleView() } label: {
                        HStack(spacing: 10) {
                            Image(systemName: "person.crop.square").foregroundStyle(Theme.accent)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("本地模块").font(.subheadline.weight(.semibold))
                                Text("\(store.config.rules.count) 条重写 · \(store.config.hostnames.count) 个 MitM 主机名").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("本地").scaledFont(9, weight: .bold)
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(Capsule().fill(Theme.good.opacity(0.18)))
                                .foregroundStyle(Theme.good)
                        }
                    }
                    NavigationLink { ModuleGalleryView() } label: {
                        HStack(spacing: 10) {
                            Image(systemName: "books.vertical").foregroundStyle(Theme.accent)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("模块库").font(.subheadline.weight(.semibold))
                                Text("浏览、搜索并预览索引来源里的模块").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }

            Section {
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
                        if it.kind == "module", let id = it.refId, let m = store.config.modules.first(where: { $0.id == id }) {
                            Button(role: .destructive) { store.deleteModule(m); res.reload() } label: { Label("删除", systemImage: "trash") }
                        } else if it.kind == "ruleset", it.readOnly != true, let id = it.refId {
                            Button(role: .destructive) {
                                CustomRulesStore.shared.rules.removeAll { $0.id == id }
                                CustomRulesStore.shared.save()
                                res.reload()
                            } label: { Label("删除", systemImage: "trash") }
                        }
                    }
                }
            } header: {
                HStack {
                    Text(filter == "all" ? "全部 \(res.items.count)" : "\(shown.count) 项")
                    Spacer()
                    if res.updatingAll { ProgressView().scaleEffect(0.7) }
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("模块与资源")
        .refreshable { await res.updateAll() }
        .alert("导入模块", isPresented: $adding) {
            TextField("https://…/xxx.sgmodule", text: $url).textInputAutocapitalization(.never).autocorrectionDisabled()
            Button("导入") {
                var u = url.trimmingCharacters(in: .whitespacesAndNewlines)
                // Also accepts surge:/// loon:// stash:// quantumult-x:/// egern:/// install links.
                if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { u = inner }
                Task { await store.addModule(url: u); res.reload() }
            }
            Button("取消", role: .cancel) {}
        }
        .alert("提示", isPresented: Binding(get: { store.message != nil || res.message != nil }, set: { if !$0 { store.message = nil; res.message = nil } })) {
            Button("好") { store.message = nil; res.message = nil }
        } message: { Text(store.message ?? res.message ?? "") }
        .onAppear { store.reparseModules(); res.reload() }
        .onChange(of: store.config.modules) { _ in res.reload() }
        .overlay { if store.busy.contains("add") { ProgressView("下载中…").padding().background(RoundedRectangle(cornerRadius: 12).fill(Theme.cardHi)) } }
        .sheet(isPresented: $pasting, onDismiss: { res.reload() }) { PasteModuleSheet() }
        .sheet(isPresented: $addingRuleSet) { AddRuleSetSheet() }
    }
}

struct ResourceKindBadge: View {
    let kind: String
    var body: some View {
        let (t, c): (String, Color) = {
            switch kind {
            case "ruleset": return ("规则集", Theme.good)
            case "script": return ("脚本", Theme.accent)
            default: return ("模块", Color.purple)
            }
        }()
        Text(LocalizedStringKey(t))
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
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
                if let d = item.detail, !d.isEmpty { Text(d).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
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
                    if let d = it.detail, !d.isEmpty { LabeledContent("内容", value: d) }
                    if let o = it.owner, !o.isEmpty { LabeledContent("使用者", value: o) }
                    if it.readOnly != true {
                        Toggle("启用", isOn: Binding(get: { it.enabled }, set: { res.setEnabled(it, $0) }))
                    } else {
                        Text("由模块引用，随模块启用或停用。").font(.caption).foregroundStyle(.secondary)
                    }
                } footer: {
                    switch it.kind {
                    case "ruleset": Text("规则集保存在自定义规则里（更多 → 规则 → 自定义），这里管理它的下载与更新。Surge / Loon / QX 列表与 Egern YAML 规则集会转换为 mihomo 规则；不支持的行会被跳过。连接期间内核也会按间隔自动更新。")
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
        .navigationTitle(item?.name ?? "资源")
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
