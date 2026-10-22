import SwiftUI
import UIKit
import Libmihomo

// 工具 → 模块 (id more.模块与资源): the one place for modules (every format, with badges), each with an update
// interval, last update, enable switch and last error. Update-all at the top.
// fix/modules-only (user device report 2026-10-22): the page lists modules only. The 全部 / 模块 / 规则集 / 脚本
// filter and the script / rule-set rows are gone; the remote scripts and rule sets a module references are
// updated with it (全部更新 here, the app's due check) and one by one in 更多 → 更新资源.

struct ModulesView: View {
    /// Official BoxJS Surge module (chavyleung/scripts): serves http(s)://boxjs.com from an http-request script.
    static let boxJSModule = "https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.surge.sgmodule"
    @ObservedObject var store = EngineStore.shared
    @ObservedObject var res = ResourceStore.shared
    @State private var adding = false
    @State private var url = ""
    @State private var pasting = false
    /// Review 5: a full trailing swipe on a module asks first.
    @State private var pendingDelete: ResourceItem?

    var modules: [ResourceItem] { res.items.filter { $0.kind == "module" } }

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.enabled }, set: { store.config.enabled = $0; store.save() })) {
                    Label("启用重写与脚本", systemImage: "puzzlepiece.extension")
                }
            }
            .listRowBackground(Theme.card)

            // feat/more-dedup: 重写 / 脚本 / 定时任务 are their own cards on the 工具 tab (Egern-style); 模块 keeps the
            // profile's rule-providers and the browse pages.
            Section {
                NavigationLink { LazyDestination { ProvidersView() } } label: {
                    MoreRow(id: "规则集（配置）", title: "配置里的规则集", subtitle: "rule-providers", symbol: "list.bullet.rectangle", tone: .teal)
                }
            } header: { Text("配置") }
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
                if modules.isEmpty {
                    EmptyStateRow(icon: "puzzlepiece.extension", title: "没有模块", message: "点 + 通过 URL 导入模块")
                }
                ForEach(modules) { it in
                    NavigationLink {
                        if let id = it.refId { ModuleDetailView(moduleID: id) }
                    } label: { ResourceRow(item: it) }
                    .accessibilityIdentifier("module.row.\(it.name)")
                    .swipeActions(edge: .leading) {
                        if it.isRemote {
                            Button { Task { await res.update(it) } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(Theme.accent)
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        if let id = it.refId, store.config.modules.contains(where: { $0.id == id }) {
                            Button(role: .destructive) { pendingDelete = it } label: { Label("删除", systemImage: "trash") }
                        }
                    }
                }
            } header: {
                HStack {
                    Text("\(modules.count) 项")
                    Spacer()
                    if res.updatingAll { ProgressView().scaleEffect(0.7) }
                }
                .accessibilityIdentifier("modules.header")
            } footer: {
                Text("所有格式的模块都在这里：Surge .sgmodule、Quantumult X 重写、Loon .plugin、Stash .stoverride、Egern .yaml 模块和重写列表，角标显示来源格式。模块引用的远程脚本和规则集随模块一起更新，也可以在 更多 → 更新资源 里单独更新。打开 App 时自动更新到期的模块和资源。")
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
        .deleteConfirmation({ it in Text("删除「\(it.name)」？") }, item: $pendingDelete,
                            message: { _ in DeleteText.recoverable }) { it in
            if let id = it.refId, let m = store.config.modules.first(where: { $0.id == id }) {
                store.deleteModule(m)
            }
            res.reload()
        }
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
                    if item.isRemote { Text("· 每 \(ResourceStore.intervalText(item.interval))") }
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
                    LabeledContent("更新间隔", value: ResourceStore.intervalText(it.interval))
                } else {
                    Picker("更新间隔", selection: Binding(get: { it.interval }, set: { res.setInterval(it, $0) })) {
                        ForEach(ResourceStore.intervals, id: \.1) { Text(LocalizedStringKey($0.0)).tag($0.1) }
                        if !ResourceStore.intervals.contains(where: { $0.1 == it.interval }) {
                            Text(ResourceStore.intervalText(it.interval)).tag(it.interval)
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
