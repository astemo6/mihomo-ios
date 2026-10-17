import SwiftUI

// QX preview 8: main v0.15.1's 模块库 (built-in curated index + index sources) and pinned script panels in the
// QX look. Data and behaviour are main's (ModuleGallery / BuiltinModuleIndex / EngineStore, PanelsModel /
// HomePanelStore + the engine's home-panels.json); this file is only the QX surface:
//   • 模块库: a QX page (large title, search field, category chips, grouped 64 pt cards, inline switch for added
//     modules) reached from 设置 → 重写 → 模块库 and from 引用资源 - 重写; tapping a module opens main's preview
//     (format picker, what it adds, arguments) in QX chrome.
//   • 面板: pinned panels as QX cards at the top of the home 节点 panel (section header with ▾ and 编辑),
//     a QX editor sheet (drag reorder, show / hide, unpin, refresh interval for pinned scripts) and a QX
//     全部面板 page (其他设置 → 脚本面板) where panels are pinned / unpinned.
// Colours come from QXTheme.swift only (QXColor.panelAccent / panelBackground map a script's own colour).

// MARK: - 模块库

struct QXModuleLibraryView: View {
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var gallery = ModuleGallery.shared
    @ObservedObject private var store = EngineStore.shared
    @State private var query = ""
    @State private var category = ""
    @State private var onlyAdded = false
    @State private var managing = false

    var searched: [GalleryItem] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return gallery.allItems }
        return gallery.allItems.filter { ($0.name + " " + $0.desc + " " + $0.category + " " + $0.author + " " + $0.url).lowercased().contains(q) }
    }

    var items: [GalleryItem] {
        searched.filter { it in
            (category.isEmpty || it.category == category)
                && (!onlyAdded || ModuleGallery.installed(it, in: store.config.modules) != nil)
        }
    }

    var categories: [String] {
        var seen = Set<String>()
        return searched.map(\.category).filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    var grouped: [(String, [GalleryItem])] {
        var order: [String] = []
        var map: [String: [GalleryItem]] = [:]
        for it in items {
            if map[it.category] == nil { order.append(it.category) }
            map[it.category, default: []].append(it)
        }
        return order.map { ($0, map[$0]!) }
    }

    var addedCount: Int { gallery.allItems.filter { ModuleGallery.installed($0, in: store.config.modules) != nil }.count }

    func sourceName(_ id: String) -> String { gallery.sources.first { $0.id == id }.map { gallery.displayName($0) } ?? "" }

    var body: some View {
        QXPage {
            QXCapsuleBar {
                if gallery.loading.isEmpty {
                    QXBarIcon(systemName: "arrow.clockwise") { Task { await gallery.refreshAll(force: true) } }
                        .accessibilityLabel(Text("刷新索引"))
                } else {
                    ProgressView().frame(width: 38, height: 40)
                }
                QXBarIcon(systemName: "books.vertical") { managing = true }
                    .accessibilityLabel(Text("管理来源"))
                QXBarIcon(systemName: "doc.badge.gearshape") { nav.push(.dest(.rewriteResources)) }
                    .accessibilityLabel(Text("引用资源 - 重写"))
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 9) {
                    QXLargeTitle(title: String(localized: "模块库"), count: "\(gallery.allItems.count)",
                                 caption: String(localized: "「内置精选」随 App 提供，也可以在右上角添加自己的索引来源。轻点模块先预览它会添加的重写、脚本和 MitM 主机名，确认后再添加；已添加的模块可以直接在这里开关。第三方模块由作者维护，请只添加信任的来源。"))
                        .padding(.bottom, 6)
                    QXSearchField(text: $query, prompt: String(localized: "搜索模块"))
                    QXChipBar(categories: categories, category: $category, onlyAdded: $onlyAdded, addedCount: addedCount)
                        .padding(.bottom, 4)
                    ForEach(gallery.sources) { s in
                        if let e = gallery.indexes[s.id]?.error, !e.isEmpty {
                            Label("\(gallery.displayName(s))：\(e)", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption).foregroundStyle(QXColor.danger).padding(.horizontal, 4)
                        }
                    }
                    if gallery.sources.isEmpty {
                        QXCard {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("还没有索引来源").font(QXType.rowTitle.weight(.semibold))
                                Text("点右上角管理来源，添加一个模块索引链接。").font(QXType.rowDetail).foregroundStyle(.secondary)
                                QXPill(title: String(localized: "恢复默认来源")) { gallery.restoreDefaults() }
                            }
                            .padding(16)
                        }
                    } else if items.isEmpty {
                        QXCard {
                            HStack(spacing: 10) {
                                if !gallery.loading.isEmpty {
                                    ProgressView()
                                    Text("正在载入索引…").font(QXType.rowTitle).foregroundStyle(.secondary)
                                } else {
                                    let filtered = !query.isEmpty || !category.isEmpty || onlyAdded
                                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                                    Text(filtered ? "没有匹配的模块" : "没有模块").font(QXType.rowTitle).foregroundStyle(.secondary)
                                }
                            }
                            .padding(.horizontal, 16)
                            .frame(minHeight: 64)
                        }
                    }
                    ForEach(grouped, id: \.0) { cat, list in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(verbatim: cat.isEmpty ? String(localized: "未分类") : cat).font(QXType.sectionTitle)
                            Text(verbatim: "\(list.count)").font(.subheadline).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 4)
                        .padding(.top, 18)
                        .padding(.bottom, 2)
                        ForEach(list) { it in
                            QXModuleCard(item: it, sourceName: gallery.sources.count > 1 ? sourceName(it.sourceID) : "") {
                                nav.push(.module(it.url))
                            }
                        }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.top, 1)
                .padding(.bottom, 50)
            }
            .refreshable { await gallery.refreshAll(force: true) }
        }
        .sheet(isPresented: $managing) { NavigationStack { GallerySourcesView() } }
        .task { await gallery.refreshAll(force: false) }
    }
}

/// One module: puzzle glyph, name + format chips + 已添加, description, author; switch when added, else chevron.
struct QXModuleCard: View {
    let item: GalleryItem
    var sourceName = ""
    let onOpen: () -> Void
    @ObservedObject private var store = EngineStore.shared

    var installed: EngineModule? { ModuleGallery.installed(item, in: store.config.modules) }

    var body: some View {
        QXCard {
            HStack(spacing: 13) {
                Image(systemName: "puzzlepiece.extension.fill")
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(installed?.enabled == true ? QXColor.rewrite : QXColor.rewrite.opacity(0.45))
                    .frame(width: 30, height: 36)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 5) {
                        Text(verbatim: item.name).font(QXType.rowTitle.weight(.semibold)).lineLimit(1)
                        ForEach(ModuleGallery.formats(of: item), id: \.self) { f in
                            QXChip(text: f.uppercased(), color: QXColor.rewriteOther, filled: false)
                        }
                        if installed != nil { QXChip(text: String(localized: "已添加"), color: QXColor.success, filled: false) }
                    }
                    if !item.desc.isEmpty {
                        Text(verbatim: item.desc).font(QXType.rowDetail).foregroundStyle(.secondary).lineLimit(2)
                    }
                    let meta = [item.author, sourceName].filter { !$0.isEmpty }.joined(separator: " · ")
                    if !meta.isEmpty { Text(verbatim: meta).font(.caption2).foregroundStyle(.tertiary).lineLimit(1) }
                }
                Spacer(minLength: 6)
                if let m = installed {
                    RoundedRectangle(cornerRadius: 1.5).fill(QXPalette.separator).frame(width: 3, height: 30)
                    Toggle("", isOn: Binding(get: { m.enabled }, set: { store.setModuleEnabled(m.id, $0) }))
                        .labelsHidden().tint(QXColor.rewrite)
                        .qxToggleHaptic(m.enabled)
                        .accessibilityLabel(Text(verbatim: item.name))
                } else {
                    Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .frame(minHeight: 64)
            .contentShape(Rectangle())
            .onTapGesture(perform: onOpen)
            .contextMenu {
                Button(action: onOpen) { Label("预览", systemImage: "eye") }
                Button { UIPasteboard.general.string = item.url } label: { Label("拷贝模块地址", systemImage: "link") }
                if let h = item.homepage, let u = URL(string: h) {
                    Link(destination: u) { Label("项目主页", systemImage: "safari") }
                }
            }
        }
    }
}

/// The module preview (main's ModulePreviewView) in QX chrome, looked up by URL.
struct QXModulePreviewPage: View {
    let url: String
    @ObservedObject private var gallery = ModuleGallery.shared
    var body: some View {
        let item = gallery.allItems.first { $0.url == url } ?? GalleryItem(name: URL(string: url)?.lastPathComponent ?? url, url: url)
        QXWrappedPage(title: item.name) {
            ModulePreviewView(item: item)
                .scrollContentBackground(.hidden)
                .background(QXPalette.bg)
        }
    }
}

/// QX-style search field (inset grey capsule).
struct QXSearchField: View {
    @Binding var text: String
    let prompt: String
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(prompt, text: $text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("清除"))
            }
        }
        .font(.subheadline)
        .padding(.horizontal, 14)
        .frame(height: 40)
        .background(Capsule().fill(QXPalette.card))
        .overlay(Capsule().stroke(QXMetrics.hairline, lineWidth: 1))
    }
}

/// 已添加 + 全部 + categories, QX capsules (selected = filled rewrite colour, white label).
struct QXChipBar: View {
    let categories: [String]
    @Binding var category: String
    @Binding var onlyAdded: Bool
    var addedCount = 0

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                chip(addedCount > 0 ? String(localized: "已添加") + " \(addedCount)" : String(localized: "已添加"),
                     icon: "checkmark.circle", on: onlyAdded) { onlyAdded.toggle() }
                chip(String(localized: "全部"), on: category.isEmpty) { category = "" }
                ForEach(categories, id: \.self) { c in
                    chip(c, on: category == c) { category = category == c ? "" : c }
                }
            }
            .padding(.vertical, 2)
            .padding(.horizontal, 2)
        }
        .onChange(of: categories) { cs in if !category.isEmpty && !cs.contains(category) { category = "" } }
    }

    private func chip(_ title: String, icon: String? = nil, on: Bool, _ action: @escaping () -> Void) -> some View {
        Button {
            QXHaptics.select()
            withAnimation(QXMotion.snappy) { action() }
        } label: {
            HStack(spacing: 4) {
                if let icon { Image(systemName: on ? icon + ".fill" : icon).font(.caption.weight(.semibold)) }
                Text(verbatim: title).font(.subheadline.weight(.semibold)).lineLimit(1)
            }
            .padding(.horizontal, 13)
            .frame(height: 32)
            .foregroundStyle(on ? QXPalette.onColor : Color.primary)
            .background(Capsule().fill(on ? QXColor.rewrite : QXPalette.card))
            .overlay(Capsule().stroke(on ? Color.clear : QXMetrics.hairline, lineWidth: 1))
        }
        .buttonStyle(QXPressStyle(scale: 0.95))
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

// MARK: - 面板 on the QX home (top of the 节点 panel)

struct QXHomePanelsSection: View {
    let active: Bool
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = PanelsModel.shared
    @ObservedObject private var home = HomePanelStore.shared
    @AppStorage("qx.panelsExpanded") private var expanded = true
    @State private var editing = false

    var body: some View {
        let items = home.visibleIDs.compactMap { home.item($0, connected: vpn.isConnected) }
        Group {
            if !model.pinned.isEmpty {
                QXSectionHeader(title: String(localized: "面板"), expanded: $expanded) {
                    if !vpn.isConnected && !items.isEmpty {
                        Text("上次结果").font(.caption).foregroundStyle(.secondary)
                    }
                    Button { editing = true } label: {
                        Image(systemName: "slider.horizontal.3").font(.system(size: 20, weight: .semibold)).foregroundStyle(QXColor.nodes)
                    }
                    .accessibilityLabel(Text("编辑首页面板"))
                }
                if expanded {
                    if items.isEmpty {
                        QXCard {
                            Text("固定的面板都已隐藏。轻点右侧按钮选择要显示的面板。")
                                .font(QXType.rowDetail).foregroundStyle(.secondary)
                                .padding(.horizontal, 16).frame(minHeight: 64)
                        }
                    }
                    ForEach(items) { e in
                        QXPanelCard(p: e.item, refreshing: e.live && (model.refreshing.contains(e.item.id) || e.item.running), offline: !e.live) {
                            Task { await model.refresh(e.item) }
                        }
                        .contextMenu {
                            if e.live && e.item.script != nil {
                                Button { Task { await model.refresh(e.item) } } label: { Label("刷新", systemImage: "arrow.clockwise") }
                            }
                            Button { home.setHidden(e.item.id, true) } label: { Label("在首页隐藏", systemImage: "eye.slash") }
                            Button { editing = true } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                            if let c = e.item.content, !c.isEmpty {
                                Button { UIPasteboard.general.string = c } label: { Label("拷贝内容", systemImage: "doc.on.doc") }
                            }
                            Button(role: .destructive) { home.unpin(e.item.id) } label: { Label("取消固定", systemImage: "pin.slash") }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $editing) { QXHomePanelsEditor().environmentObject(vpn).environmentObject(nav) }
        .task(id: TaskKey(connected: vpn.isConnected, active: active)) {
            home.loadCache()
            guard vpn.isConnected else { model.panels = []; return }
            home.sync()
            await model.load()
            home.rememberNames()
            guard active else { return }
            await home.refreshStaleVisible()
            // While the 节点 panel is on screen: pick up results (the engine also refreshes Home panels on their
            // interval in the background while connected).
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                if Task.isCancelled || !vpn.isConnected { break }
                if home.visibleIDs.isEmpty { continue }
                await model.load()
                await home.refreshStaleVisible()
            }
        }
    }

    private struct TaskKey: Equatable { let connected: Bool; let active: Bool }
}

/// A panel as a QX card: glyph in the panel colour, title, content lines, source · time; refresh at the right.
struct QXPanelCard: View {
    let p: PanelItem
    let refreshing: Bool
    var offline = false
    var pinned = false
    let onRefresh: () -> Void

    var accent: Color { QXColor.panelAccent(hex: p.iconColor, style: p.style) }

    var body: some View {
        QXCard {
            HStack(alignment: .center, spacing: 13) {
                Image(systemName: PanelCard.symbol(p.icon))
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(accent)
                    .frame(width: 30, height: 36)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 5) {
                        Text(verbatim: p.title?.isEmpty == false ? p.title! : p.name).font(QXType.rowTitle.weight(.semibold)).lineLimit(1)
                        if pinned {
                            Image(systemName: "pin.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("已固定"))
                        }
                    }
                    if let c = p.content, !c.isEmpty {
                        Text(verbatim: c).font(QXType.rowDetail).foregroundStyle(.secondary).lineLimit(6)
                    }
                    if let e = p.error, !e.isEmpty {
                        Text(verbatim: e).font(.caption2).foregroundStyle(QXColor.danger).lineLimit(3)
                    }
                    HStack(spacing: 4) {
                        if offline { Image(systemName: "clock").accessibilityLabel(Text("上次结果")) }
                        if let u = p.updated, u > 0 {
                            Text(Date(timeIntervalSince1970: u), style: .relative)
                        }
                        if !p.source.isEmpty {
                            Text(verbatim: (p.updated ?? 0) > 0 ? "· " + p.source : p.source).lineLimit(1)
                        }
                    }
                    .font(.caption2).foregroundStyle(.tertiary)
                }
                Spacer(minLength: 6)
                if p.script != nil && !offline {
                    RoundedRectangle(cornerRadius: 1.5).fill(QXPalette.separator).frame(width: 3, height: 30)
                    ZStack {
                        if refreshing {
                            ProgressView().controlSize(.small)
                        } else {
                            Button(action: onRefresh) {
                                Image(systemName: "arrow.clockwise").font(.system(size: 15, weight: .semibold)).foregroundStyle(.secondary)
                                    .frame(width: 32, height: 36).contentShape(Rectangle())
                            }
                            .buttonStyle(QXPressStyle(scale: 0.86))
                            .accessibilityLabel(Text("刷新"))
                        }
                    }
                    .frame(width: 32)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .frame(minHeight: 64, alignment: .leading)
        }
        .overlay {
            // A script's own backgroundColor tints the card (kept light so the text stays readable).
            if p.backgroundColor != nil {
                RoundedRectangle(cornerRadius: QXMetrics.cardRadius, style: .continuous)
                    .fill(QXColor.panelBackground(hex: p.backgroundColor)).allowsHitTesting(false)
            }
        }
    }
}

/// 编辑首页面板 in QX colours: drag to reorder, switch = shown on Home, swipe to unpin, interval for scripts.
struct QXHomePanelsEditor: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var model = PanelsModel.shared
    @ObservedObject private var home = HomePanelStore.shared

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if model.pinned.isEmpty {
                        Text("还没有固定的面板。在「全部面板」里长按面板，或在脚本任务详情里点「固定到首页」。")
                            .font(QXType.rowDetail).foregroundStyle(.secondary)
                    }
                    ForEach(model.pinned, id: \.self) { id in row(id) }
                        .onMove { home.move(from: $0, to: $1) }
                        .onDelete { s in s.map { model.pinned[$0] }.forEach(home.unpin) }
                } header: {
                    Text("首页面板")
                } footer: {
                    Text("拖动调整顺序。关闭开关的面板保留固定，但不在首页显示，也不会在后台刷新。")
                }
                .listRowBackground(QXPalette.card)

                Section {
                    NavigationLink { QXAllPanelsView() } label: { Label("全部面板", systemImage: "square.grid.2x2") }
                    Button {
                        dismiss()
                        nav.push(.dest(.tasks))
                    } label: { Label("脚本任务", systemImage: "terminal") }
                } header: {
                    Text("添加")
                } footer: {
                    Text("Surge [Panel] / Stash 面板在「全部面板」里长按固定；QX 的通用脚本和交互脚本在脚本任务详情里固定。连接期间首页面板按刷新间隔在后台更新（最短 5 分钟）。")
                }
                .listRowBackground(QXPalette.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(QXPalette.bg.ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .tint(QXColor.switchOn)
            .navigationTitle("编辑首页面板")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
        }
    }

    @ViewBuilder
    func row(_ id: String) -> some View {
        let shown = home.item(id, connected: vpn.isConnected)?.item
        let task = home.tasks.first { $0.panelID == id }
        HStack(spacing: 10) {
            Image(systemName: PanelCard.symbol(shown?.icon))
                .foregroundStyle(QXColor.panelAccent(hex: shown?.iconColor, style: shown?.style))
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(home.name(id) ?? String(localized: "不可用的面板")).font(QXType.rowTitle).lineLimit(1)
                if let task {
                    Menu {
                        ForEach(HomePanelsEditor.intervals.indices, id: \.self) { i in
                            let v = HomePanelsEditor.intervals[i]
                            Button { home.setInterval(task.id, v.0) } label: {
                                if v.0 == task.interval { Label(v.1, systemImage: "checkmark") } else { Text(v.1) }
                            }
                        }
                    } label: {
                        HStack(spacing: 3) {
                            Image(systemName: "clock.arrow.circlepath")
                            Text(HomePanelsEditor.intervals.first { $0.0 == task.interval }?.1 ?? "打开首页时")
                        }
                        .font(.caption2)
                    }
                    if let p = task.params, !p.isEmpty {
                        Text("节点：\(p)").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                } else if let s = shown?.source, !s.isEmpty {
                    Text(s).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            Toggle("在首页显示", isOn: Binding(get: { !home.hidden.contains(id) }, set: { home.setHidden(id, !$0) }))
                .labelsHidden()
                .tint(QXColor.switchOn)
        }
    }
}

/// 全部面板 (其他设置 → 脚本面板, and from the editor): every panel of the enabled modules as QX cards; long-press
/// pins / unpins. Disconnected: the last results of the pinned panels.
struct QXAllPanelsView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = PanelsModel.shared
    @ObservedObject private var home = HomePanelStore.shared
    @State private var editing = false

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "slider.horizontal.3") { editing = true }
                    .accessibilityLabel(Text("编辑首页面板"))
                if vpn.isConnected {
                    QXBarIcon(systemName: "arrow.clockwise") {
                        Task { for p in model.panels where p.script != nil { await model.refresh(p) } }
                    }
                    .accessibilityLabel(Text("全部刷新"))
                }
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 9) {
                    QXLargeTitle(title: String(localized: "脚本面板"), count: vpn.isConnected ? "\(model.panels.count)" : nil,
                                 caption: String(localized: "模块里的 Surge [Panel]、Stash 面板，以及固定到首页的通用 / 交互脚本。长按面板固定到首页或取消固定；首页的面板显示在「节点」页顶部。"))
                        .padding(.bottom, 6)
                    if vpn.isConnected {
                        if model.panels.isEmpty {
                            QXCard {
                                Text("已启用的模块里没有面板。").font(QXType.rowDetail).foregroundStyle(.secondary)
                                    .padding(.horizontal, 16).frame(minHeight: 64)
                            }
                        }
                        ForEach(model.panels) { p in
                            QXPanelCard(p: p, refreshing: model.refreshing.contains(p.id) || p.running, pinned: model.isPinned(p)) {
                                Task { await model.refresh(p) }
                            }
                            .contextMenu {
                                PanelPinButton(p: p)
                                if p.script != nil {
                                    Button { Task { await model.refresh(p) } } label: { Label("刷新", systemImage: "arrow.clockwise") }
                                }
                            }
                        }
                    } else {
                        QXCard {
                            Text("脚本在 VPN 扩展里运行，连接后才能刷新面板。下面是固定面板的上次结果。")
                                .font(QXType.rowDetail).foregroundStyle(.secondary)
                                .padding(.horizontal, 16).padding(.vertical, 12)
                        }
                        ForEach(model.pinned.compactMap { home.item($0, connected: false) }) { e in
                            QXPanelCard(p: e.item, refreshing: false, offline: true, pinned: true) {}
                                .contextMenu {
                                    Button(role: .destructive) { home.unpin(e.item.id) } label: { Label("取消固定", systemImage: "pin.slash") }
                                }
                        }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.top, 1)
                .padding(.bottom, 50)
            }
            .refreshable { await model.load() }
        }
        .sheet(isPresented: $editing) { QXHomePanelsEditor().environmentObject(vpn).environmentObject(QXNavigator.shared) }
        .task(id: vpn.isConnected) {
            home.loadCache()
            if vpn.isConnected {
                await model.load()
                home.rememberNames()
            }
        }
    }
}
