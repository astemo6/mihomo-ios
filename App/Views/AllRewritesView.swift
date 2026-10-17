import SwiftUI
import Libmihomo

/// v0.16 全部重写规则: every rewrite / script rule from 本地模块 and each imported module in one searchable
/// list (type, phase, description, source module). Disabled ones (switch off, module off, engine off) are dimmed.
/// Reached from 模块与资源 and 本地模块; read-only, a row opens its module.
struct AllRewritesView: View {
    @ObservedObject private var store = EngineStore.shared
    @State private var search = ""
    @State private var onlyEnabled = false
    @State private var localRows: [Row] = []

    struct Row: Identifiable, Hashable {
        let id: String
        let kind: String
        let phase: String
        let pattern: String
        let desc: String
        let source: String
        let moduleID: String?   // nil = 本地模块
        let enabled: Bool
    }

    private var moduleRows: [Row] {
        var out: [Row] = []
        for m in store.config.modules {
            guard let p = store.moduleInfo[m.id] else { continue }
            for (i, r) in p.rules.enumerated() {
                out.append(Row(id: "\(m.id)#\(i)", kind: r.kind, phase: r.phase, pattern: r.pattern, desc: r.desc,
                               source: m.name, moduleID: m.id, enabled: m.enabled && store.config.enabled))
            }
        }
        return out
    }

    private static func parseLocal(_ items: [EngineItem], engineOn: Bool) -> [Row] {
        var out: [Row] = []
        for it in items {
            guard let p = ParsedEngineText.parse(LibmihomoEngineParseLine(it.line, it.line.contains("type=") ? "script" : "")) else { continue }
            for (i, r) in p.rules.enumerated() {
                out.append(Row(id: "local:\(it.id)#\(i)", kind: r.kind, phase: r.phase, pattern: r.pattern, desc: r.desc,
                               source: String(localized: "本地模块"), moduleID: nil, enabled: it.enabled && engineOn))
            }
        }
        return out
    }

    private var rows: [Row] {
        var all = localRows + moduleRows
        if onlyEnabled { all = all.filter(\.enabled) }
        guard !search.isEmpty else { return all }
        return all.filter {
            $0.pattern.localizedCaseInsensitiveContains(search) || $0.desc.localizedCaseInsensitiveContains(search)
                || GoText.localize($0.desc).localizedCaseInsensitiveContains(search) || $0.source.localizedCaseInsensitiveContains(search)
                || $0.kind.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        let list = rows
        List {
            Section {
                Toggle("只看已启用", isOn: $onlyEnabled)
                    .accessibilityIdentifier("allrewrites.onlyEnabled")
            } footer: {
                if !store.config.enabled { Text("「重写与脚本」总开关已关闭，下面的规则都不会生效。") }
            }
            .listRowBackground(Theme.card)
            Section {
                ForEach(list) { r in
                    NavigationLink {
                        if let id = r.moduleID { ModuleDetailView(moduleID: id) } else { LocalModuleView() }
                    } label: { RewriteFlatRow(row: r) }
                    .listRowBackground(Theme.card)
                }
            } header: { Text("共 \(list.count) 条") }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, prompt: "搜索 URL、说明或模块")
        .overlay {
            if list.isEmpty && search.isEmpty && !onlyEnabled {
                EmptyStateView(icon: "arrow.triangle.swap", title: "还没有重写规则", message: "导入模块或在本地模块里添加。")
                    .allowsHitTesting(false)
            }
        }
        .navigationTitle("全部重写规则")
        .navigationBarTitleDisplayMode(.inline)
        .task(id: store.config.rules) { localRows = Self.parseLocal(store.config.rules, engineOn: store.config.enabled) }
        .onChange(of: store.config.enabled) { on in localRows = Self.parseLocal(store.config.rules, engineOn: on) }
    }
}

struct RewriteFlatRow: View {
    let row: AllRewritesView.Row
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                KindBadge(kind: row.kind, phase: row.phase)
                Text(LocalizedStringKey(row.phase == "response" ? "响应" : "请求"))
                    .scaledFont(9, weight: .bold)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(Capsule().fill(Theme.ink(0.08)))
                    .foregroundStyle(.secondary)
                Text(verbatim: GoText.localize(row.desc)).font(.caption.weight(.semibold)).lineLimit(1)
                Spacer(minLength: 4)
                if !row.enabled { Text("已停用").font(.caption2).foregroundStyle(.secondary) }
            }
            Text(verbatim: row.pattern).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(2)
            Label { Text(verbatim: row.source) } icon: {
                Image(systemName: row.moduleID == nil ? "person.crop.square" : "puzzlepiece.extension")
            }
            .font(.caption2).foregroundStyle(Theme.accent).lineLimit(1)
        }
        .padding(.vertical, 2)
        .opacity(row.enabled ? 1 : 0.5)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("allrewrites.row")
    }
}
