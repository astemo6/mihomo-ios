import SwiftUI

// QX-3: 重写规则 (the full ordered list, local rules editable) and 引用资源 - 重写 (modules as QX resources),
// both in QX chrome. Data stays in engine.json (local rules / scripts / modules).

enum QXRewriteStyle {
    /// Tag colour by type: scripts magenta, reject* light pink, the rest rewrite pink outline.
    static func color(_ kind: String) -> Color {
        let k = kind.uppercased()
        if k.hasPrefix("SCRIPT") || k == "SCRIPT" { return QXColor.rewrite }
        if k.hasPrefix("REJECT") { return Color(red: 0.96, green: 0.55, blue: 0.70) }
        return Color(red: 0.80, green: 0.25, blue: 0.55)
    }

    static func label(_ line: String) -> String {
        let k = QXRewritePanel.kind(of: line)
        return k == "RULE" ? "REWRITE" : k
    }
}

struct QXRewriteRulesView: View {
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var editing: LocalModuleView.EditTarget?
    @State private var editingLine: EngineItem?
    @State private var search = ""
    @State private var searching = false

    struct Row: Identifiable {
        let id: String
        let tag: String
        let text: String
        let source: String
        let time: String
        let local: EngineItem?
        let isScript: Bool
        let enabled: Bool
    }

    var rows: [Row] {
        var out: [Row] = []
        for it in engine.config.rules {
            out.append(Row(id: "r" + it.id, tag: QXRewriteStyle.label(it.line), text: it.line, source: String(localized: "已保存"),
                           time: String(localized: "本地"), local: it, isScript: false, enabled: it.enabled))
        }
        for it in engine.config.scripts {
            out.append(Row(id: "s" + it.id, tag: "SCRIPT", text: it.line, source: String(localized: "已保存"),
                           time: String(localized: "本地"), local: it, isScript: true, enabled: it.enabled))
        }
        for m in engine.config.modules where m.enabled {
            let t = m.updatedAt.map { QXNodeResourcesView.rel.localizedString(for: Date(timeIntervalSince1970: $0), relativeTo: Date()) }
                ?? (m.url.isEmpty ? String(localized: "本地") : String(localized: "需要更新"))
            for (i, r) in (engine.moduleInfo[m.id]?.rules ?? []).enumerated() {
                let line = r.line.isEmpty ? r.pattern : r.line
                out.append(Row(id: m.id + "#\(i)", tag: r.kind == "script" ? "SCRIPT" : QXRewriteStyle.label(line), text: line,
                               source: m.name, time: t, local: nil, isScript: r.kind == "script", enabled: true))
            }
        }
        guard !search.isEmpty else { return out }
        return out.filter { $0.text.localizedCaseInsensitiveContains(search) || $0.source.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        let list = rows
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "link") { nav.push(.dest(.rewriteResources)) }
                    .accessibilityLabel(Text("规则资源"))
                Menu {
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "reject") } label: { Label("拒绝请求（reject）", systemImage: "nosign") }
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "redirect") } label: { Label("重定向（302 / 307）", systemImage: "arrowshape.turn.up.right") }
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "header", phase: "request") } label: { Label("修改请求头", systemImage: "list.bullet.indent") }
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "header", phase: "response") } label: { Label("修改响应头", systemImage: "list.bullet.indent") }
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "body", phase: "response") } label: { Label("正则替换响应体", systemImage: "text.magnifyingglass") }
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "maplocal") } label: { Label("本地映射（Map Local）", systemImage: "doc.richtext") }
                    Divider()
                    Button { editing = LocalModuleView.EditTarget(item: nil, type: "raw") } label: { Label("粘贴规则文本", systemImage: "doc.on.clipboard") }
                    Button { nav.push(.dest(.scripts)) } label: { Label("脚本", systemImage: "curlybraces") }
                } label: {
                    Image(systemName: "plus").font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary).frame(width: 38, height: 40)
                }
                .accessibilityLabel(Text("添加"))
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .firstTextBaseline) {
                        QXLargeTitle(title: String(localized: "重写规则"), count: QXFmt.count(list.count))
                        QXPill(title: res.updatingAll ? String(localized: "更新中…") : String(localized: "全部更新")) {
                            Task { await res.updateAll() }
                        }
                        .disabled(res.updatingAll)
                    }
                    .padding(.bottom, 8)
                    Text("按加载顺序排列：先是本地规则（已保存），再按模块顺序。长按本地规则可编辑、停用或删除；模块中的规则在「规则资源」中管理。")
                        .font(.system(size: 16)).foregroundStyle(.secondary).padding(.bottom, 12)
                    if searching {
                        TextField("搜索", text: $search)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .padding(10).background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXPalette.card))
                            .padding(.bottom, 10)
                    }
                    if list.isEmpty {
                        Text(search.isEmpty ? LocalizedStringKey("还没有重写规则。点右上角 + 添加，或在「规则资源」中添加模块。") : LocalizedStringKey("没有匹配的规则"))
                            .foregroundStyle(.secondary).padding(.vertical, 20)
                    }
                    ForEach(list.prefix(1500)) { r in
                        row(r)
                        Divider()
                    }
                    if list.count > 1500 {
                        Text("另有 \(list.count - 1500) 条，请用搜索查看").font(.footnote).foregroundStyle(.secondary).padding(.vertical, 12)
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 100)
            }
            .overlay(alignment: .bottomTrailing) {
                QXCircleButton(systemName: searching ? "xmark" : "magnifyingglass") {
                    withAnimation { searching.toggle(); if !searching { search = "" } }
                }
                .padding(.trailing, 20).padding(.bottom, 16)
                .accessibilityLabel(Text("搜索"))
            }
        }
        .onAppear { engine.reparseModules() }
        .sheet(item: $editing) { t in RewriteRuleEditor(target: t) }
        .sheet(item: $editingLine) { it in LineEditorSheet(title: String(localized: "编辑"), scripts: engine.config.scripts.contains { $0.id == it.id }, item: it) }
    }

    func row(_ r: Row) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                QXChip(text: r.tag, color: QXRewriteStyle.color(r.tag))
                Text(verbatim: r.source).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !r.enabled { Text("已停用").font(.caption2).foregroundStyle(.secondary) }
                Spacer()
                Text(verbatim: r.time).font(.caption).foregroundStyle(.secondary)
            }
            Text(verbatim: r.text).font(.system(size: 15, design: .monospaced)).lineLimit(6)
                .foregroundStyle(r.enabled ? Color.primary : Color.secondary)
        }
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .contextMenu {
            Button { UIPasteboard.general.string = r.text } label: { Label("拷贝", systemImage: "doc.on.doc") }
            if let it = r.local {
                Button {
                    if r.isScript { editingLine = it } else { editing = LocalModuleView.EditTarget(item: it, type: RewriteForm.fromLine(it.line).type) }
                } label: { Label("编辑", systemImage: "square.and.pencil") }
                Button { setEnabled(it, script: r.isScript, !it.enabled) } label: {
                    Label(it.enabled ? LocalizedStringKey("停用") : LocalizedStringKey("启用"), systemImage: it.enabled ? "pause.circle" : "play.circle")
                }
                Button(role: .destructive) { delete(it, script: r.isScript) } label: { Label("删除", systemImage: "trash") }
            } else {
                Button { nav.push(.dest(.rewriteResources)) } label: { Label("规则资源", systemImage: "link") }
            }
        }
    }

    private func setEnabled(_ it: EngineItem, script: Bool, _ on: Bool) {
        if script, let i = engine.config.scripts.firstIndex(where: { $0.id == it.id }) { engine.config.scripts[i].enabled = on }
        else if let i = engine.config.rules.firstIndex(where: { $0.id == it.id }) { engine.config.rules[i].enabled = on }
        engine.save()
    }

    private func delete(_ it: EngineItem, script: Bool) {
        if script { engine.config.scripts.removeAll { $0.id == it.id } } else { engine.config.rules.removeAll { $0.id == it.id } }
        engine.save()
    }
}

// MARK: - 引用资源 - 重写

struct QXRewriteResourcesView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var adding = false
    @State private var url = ""
    @State private var pasting = false
    @State private var editing: QXResourceTarget?

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "magnifyingglass") { nav.push(.dest(.localRewrite)) }
                    .accessibilityLabel(Text("重写规则"))
                QXBarIcon(systemName: "doc.badge.gearshape") { nav.push(.dest(.allResources)) }
                    .accessibilityLabel(Text("模块与资源"))
                Menu {
                    Button {
                        let t = (UIPasteboard.general.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                        if case .moduleURL(let u, _)? = ImportRouter.parse(t) { url = u } else { url = t.hasPrefix("http") ? t : "" }
                        adding = true
                    } label: { Label("从 URL 导入模块", systemImage: "link") }
                    Button { pasting = true } label: { Label("粘贴模块内容", systemImage: "doc.on.clipboard") }
                } label: {
                    Image(systemName: "link.badge.plus").font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary).frame(width: 38, height: 40)
                }
                .accessibilityLabel(Text("添加"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .firstTextBaseline) {
                        QXLargeTitle(title: String(localized: "引用资源 - 重写"))
                        QXPill(title: res.updatingAll ? String(localized: "更新中…") : String(localized: "全部更新")) {
                            Task { await res.updateAll() }
                        }
                        .disabled(res.updatingAll)
                    }
                    Text("生效的重写规则除了下列选中的资源外，还包含本地规则，可点击右上方的搜索按钮查看所有规则加载完毕后的顺序。Surge / Loon / Stash / Egern 模块与 QX 重写片段都可以直接添加。")
                        .font(.system(size: 16)).foregroundStyle(.secondary)

                    QXCard {
                        VStack(spacing: 0) {
                            Button { nav.push(.dest(.localRewrite)) } label: {
                                resourceRow(checked: engine.config.enabled, title: String(localized: "已保存"),
                                            trailing: String(localized: "本地"),
                                            subtitle: String(localized: "\(engine.config.rules.count) 条重写 · \(engine.config.scripts.count) 个脚本"),
                                            counts: nil, format: nil)
                            }
                            .buttonStyle(.plain)
                            ForEach(engine.config.modules) { m in
                                Divider().padding(.leading, 56)
                                Button { toggle(m) } label: {
                                    resourceRow(checked: m.enabled, title: m.name,
                                                trailing: engine.busy.contains(m.id) ? String(localized: "更新中…") : updated(m),
                                                subtitle: m.url.isEmpty ? String(localized: "本地模块") : m.url,
                                                counts: counts(m), format: engine.moduleInfo[m.id]?.format)
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button { editing = QXResourceTarget(kind: .module(m.id)) } label: { Label("编辑", systemImage: "square.and.pencil") }
                                    if !m.url.isEmpty {
                                        Button { Task { await engine.updateModule(m); res.reload() } } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                                        Button { UIPasteboard.general.string = m.url } label: { Label("资源链接", systemImage: "link") }
                                    }
                                    Button { moveModule(m, by: -1) } label: { Label("上移", systemImage: "arrow.up") }
                                    Button { moveModule(m, by: 1) } label: { Label("下移", systemImage: "arrow.down") }
                                    Button { nav.push(.dest(.allResources)) } label: { Label("详情", systemImage: "info.circle") }
                                    Divider()
                                    Button(role: .destructive) { engine.deleteModule(m); res.reload() } label: { Label("删除", systemImage: "trash") }
                                }
                            }
                        }
                    }
                    if engine.config.modules.isEmpty {
                        Text("还没有模块。点右上角添加。").font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
                    }
                    Text("轻点切换启用，长按编辑（标签、地址、更新间隔）、更新、排序或删除。")
                        .font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 100)
            }
            .overlay(alignment: .bottom) { QXResourceSwitcher(current: 2).padding(.bottom, 10) }
        }
        .onAppear { engine.reparseModules(); res.reload() }
        .alert("导入模块", isPresented: $adding) {
            TextField("https://…/xxx.sgmodule", text: $url).textInputAutocapitalization(.never).autocorrectionDisabled()
            Button("导入") {
                var u = url.trimmingCharacters(in: .whitespacesAndNewlines)
                if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { u = inner }
                Task { await engine.addModule(url: u); res.reload() }
            }
            Button("取消", role: .cancel) {}
        }
        .alert("提示", isPresented: Binding(get: { engine.message != nil || res.message != nil }, set: { if !$0 { engine.message = nil; res.message = nil } })) {
            Button("好") { engine.message = nil; res.message = nil }
        } message: { Text(engine.message ?? res.message ?? "") }
        .sheet(isPresented: $pasting, onDismiss: { res.reload() }) { PasteModuleSheet() }
        .sheet(item: $editing) { t in QXResourceEditor(target: t).environmentObject(store) }
    }

    func updated(_ m: EngineModule) -> String {
        if m.url.isEmpty { return String(localized: "本地") }
        guard let t = m.updatedAt else { return String(localized: "需要更新") }
        return QXNodeResourcesView.rel.localizedString(for: Date(timeIntervalSince1970: t), relativeTo: Date())
    }

    func counts(_ m: EngineModule) -> String? {
        guard let p = engine.moduleInfo[m.id] else { return nil }
        let scripts = p.rules.filter { $0.kind == "script" }.count
        return String(localized: "\(p.rules.count - scripts) 重写 · \(scripts) 脚本 · \(p.hostnames.count) 主机")
    }

    func toggle(_ m: EngineModule) {
        guard let i = engine.config.modules.firstIndex(where: { $0.id == m.id }) else { return }
        engine.config.modules[i].enabled.toggle()
        engine.save()
        res.reload()
    }

    func moveModule(_ m: EngineModule, by d: Int) {
        guard let i = engine.config.modules.firstIndex(where: { $0.id == m.id }) else { return }
        let j = i + d
        guard engine.config.modules.indices.contains(j) else { return }
        engine.config.modules.swapAt(i, j)
        engine.save()
    }

    func resourceRow(checked: Bool, title: String, trailing: String, subtitle: String, counts: String?, format: String?) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: checked ? "checkmark.square.fill" : "square")
                .font(.system(size: 22)).foregroundStyle(checked ? QXColor.switchOn : Color.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(verbatim: title).font(.system(size: 18)).lineLimit(1)
                    if let f = format, !f.isEmpty { SourceFormatBadge(format: f) }
                    Spacer()
                    Text(verbatim: trailing).font(.caption).foregroundStyle(.secondary)
                }
                Text(verbatim: subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if let counts { Text(verbatim: counts).font(.caption2).foregroundStyle(.secondary) }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}

/// 模块与资源 (every module, rule set and remote script with badges) in QX chrome.
struct QXAllResourcesView: View {
    var body: some View {
        ModulesView(qx: true)
    }
}
