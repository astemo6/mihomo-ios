import SwiftUI
import Libmihomo

// 策略组编辑 (v0.9). Edits live in <home>/group-edits.json per profile (bridge/groupedits.go applies them
// when the runtime config is built); the profile file is never rewritten. 恢复原始 removes the edit.

struct GroupSpec: Codable, Hashable {
    var name: String
    var type: String = "select"
    var proxies: [String] = []
    var use: [String]? = nil
    var includeAll: Bool? = nil
    var filter: String? = nil
    var excludeFilter: String? = nil
    var url: String? = nil
    var interval: Int? = nil
    var tolerance: Int? = nil
    var lazy: Bool? = nil
    var strategy: String? = nil
    var icon: String? = nil
    var hidden: Bool? = nil
}

struct GroupEdit: Codable, Hashable {
    var deleted: Bool? = nil
    var spec: GroupSpec? = nil
}

struct GroupEdits: Codable, Hashable {
    var edits: [String: GroupEdit]? = nil
    var added: [GroupSpec]? = nil
}

enum GroupEditStore {
    static var url: URL { AppShared.homeURL.appendingPathComponent("group-edits.json") }

    static func all() -> [String: GroupEdits] {
        guard let d = try? Data(contentsOf: url) else { return [:] }
        return (try? JSONDecoder().decode([String: GroupEdits].self, from: d)) ?? [:]
    }

    static func get(_ profileID: String) -> GroupEdits { all()[profileID] ?? GroupEdits() }

    static func set(_ profileID: String, _ e: GroupEdits) {
        var m = all()
        let empty = (e.edits ?? [:]).isEmpty && (e.added ?? []).isEmpty
        m[profileID] = empty ? nil : e
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(m) { try? d.write(to: url, options: .atomic) }
    }

    static func json(_ e: GroupEdits) -> String {
        String(decoding: (try? JSONEncoder().encode(e)) ?? Data("{}".utf8), as: UTF8.self)
    }
}

/// The profile's own groups (before edits) plus provider / node names, from bridge GroupSpecs.
struct GroupSpecsResult: Decodable {
    var groups: [GroupSpec] = []
    var providers: [String] = []
    var proxies: [String] = []

    static func load(_ path: String) async -> GroupSpecsResult {
        let json = await Task.detached(priority: .userInitiated) { LibmihomoGroupSpecs(AppShared.homeURL.path, path) }.value
        return (try? JSONDecoder().decode(GroupSpecsResult.self, from: Data(json.utf8))) ?? GroupSpecsResult()
    }
}

struct GroupEditorView: View {
    /// Current (possibly renamed) name of the group; nil = new group.
    let groupName: String?
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @Environment(\.dismiss) private var dismiss

    @State private var specs = GroupSpecsResult()
    @State private var edits = GroupEdits()
    @State private var originalName: String?   // key in the profile; nil for an added group
    @State private var addedIndex: Int?
    @State private var spec = GroupSpec(name: "")
    @State private var loaded = false
    @State private var showAddMember = false
    @State private var message: String?
    @State private var confirmDelete = false
    @State private var saving = false

    static let types: [(String, String)] = [("select", "手动选择"), ("url-test", "自动选择（延迟最低）"), ("fallback", "故障转移"), ("load-balance", "负载均衡")]

    var profile: Profile? { store.active }

    var body: some View {
        NavigationStack {
            Form {
                if loaded { content } else { LoadingRow(text: "读取策略组…").listRowBackground(Theme.card) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(groupName == nil ? "新建策略组" : "编辑策略组")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if saving { ProgressView() } else { Button("保存") { Task { await save() } }.disabled(!loaded) }
                }
            }
            .sheet(isPresented: $showAddMember) {
                MemberPicker(candidates: candidates, chosen: Set(spec.proxies)) { picked in
                    spec.proxies.append(contentsOf: picked.filter { !spec.proxies.contains($0) })
                }
            }
            .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(message ?? "") }
            .confirmationDialog("删除策略组「\(spec.name)」？", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("删除", role: .destructive) { Task { await delete() } }
            } message: {
                Text(routedRules.isEmpty ? "其他策略组中对它的引用会一并移除。" : "有 \(routedRules.count) 条规则指向它，删除后改用第一个手动选择组。")
            }
        }
        .task { await load() }
    }

    // MARK: Sections

    @ViewBuilder var content: some View {
        Section {
            TextField("名称", text: $spec.name)
            Picker("类型", selection: $spec.type) {
                ForEach(Self.types, id: \.0) { t in Text(LocalizedStringKey(t.1)).tag(t.0) }
            }
            TextField("图标链接（可选）", text: Binding(get: { spec.icon ?? "" }, set: { spec.icon = $0.isEmpty ? nil : $0 }))
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
        }
        .listRowBackground(Theme.card)

        Section {
            ForEach(spec.proxies, id: \.self) { m in
                HStack {
                    Text(m).lineLimit(1)
                    Spacer()
                    Text(LocalizedStringKey(memberKind(m))).font(.caption2).foregroundStyle(.secondary)
                }
            }
            .onDelete { spec.proxies.remove(atOffsets: $0) }
            .onMove { spec.proxies.move(fromOffsets: $0, toOffset: $1) }
            Button { showAddMember = true } label: { Label("添加成员", systemImage: "plus.circle") }
        } header: {
            HStack { Text("成员 \(spec.proxies.count)"); Spacer(); EditButton().font(.caption) }
        } footer: {
            Text("成员可以是节点、其他策略组、DIRECT / REJECT。左滑删除，点「编辑」拖动排序。")
        }
        .listRowBackground(Theme.card)

        Section {
            if specs.providers.isEmpty {
                Text("当前配置没有节点集").font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(specs.providers.sorted(), id: \.self) { p in
                Toggle(p, isOn: Binding(get: { (spec.use ?? []).contains(p) }, set: { on in
                    var u = spec.use ?? []
                    if on { if !u.contains(p) { u.append(p) } } else { u.removeAll { $0 == p } }
                    spec.use = u.isEmpty ? nil : u
                }))
            }
            Toggle("包含全部节点", isOn: Binding(get: { spec.includeAll == true }, set: { spec.includeAll = $0 ? true : nil }))
            TextField("筛选（正则，保留匹配的节点）", text: Binding(get: { spec.filter ?? "" }, set: { spec.filter = $0.isEmpty ? nil : $0 }))
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .scaledFont(13, design: .monospaced)
            TextField("排除（正则）", text: Binding(get: { spec.excludeFilter ?? "" }, set: { spec.excludeFilter = $0.isEmpty ? nil : $0 }))
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .scaledFont(13, design: .monospaced)
            filterPreview
        } header: { Text("节点集与筛选") } footer: {
            Text("筛选作用于节点集和「包含全部节点」带来的节点；预览按已缓存的节点计算。")
        }
        .listRowBackground(Theme.card)

        if spec.type != "select" {
            Section("测速") {
                TextField("测速地址（留空用默认）", text: Binding(get: { spec.url ?? "" }, set: { spec.url = $0.isEmpty ? nil : $0 }))
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Stepper(value: Binding(get: { spec.interval ?? 300 }, set: { spec.interval = $0 }), in: 30...86400, step: 30) {
                    LabeledContent("间隔", value: "\(spec.interval ?? 300) 秒")
                }
                if spec.type == "url-test" {
                    Stepper(value: Binding(get: { spec.tolerance ?? 0 }, set: { spec.tolerance = $0 > 0 ? $0 : nil }), in: 0...1000, step: 10) {
                        LabeledContent("容差", value: "\(spec.tolerance ?? 0) ms")
                    }
                }
                Toggle("懒惰测速（仅在使用时测速）", isOn: Binding(get: { spec.lazy ?? true }, set: { spec.lazy = $0 }))
                if spec.type == "load-balance" {
                    Picker("策略", selection: Binding(get: { spec.strategy ?? "consistent-hashing" }, set: { spec.strategy = $0 })) {
                        Text("一致性哈希").tag("consistent-hashing")
                        Text("轮询").tag("round-robin")
                        Text("粘性会话").tag("sticky-sessions")
                    }
                }
            }
            .listRowBackground(Theme.card)
        }

        if groupName != nil {
            Section {
                if routedRules.isEmpty {
                    Text("没有规则直接指向这个策略组").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(Array(routedRules.prefix(30).enumerated()), id: \.offset) { _, r in
                    Text("\(r.type),\(r.payload)").scaledFont(11, design: .monospaced).lineLimit(1)
                }
                if routedRules.count > 30 { Text("另有 \(routedRules.count - 30) 条").font(.caption).foregroundStyle(.secondary) }
                NavigationLink { RulesView() } label: { Label("编辑规则", systemImage: "list.bullet.rectangle") }
            } header: { Text("指向此策略组的规则 \(routedRules.count)") }
            .listRowBackground(Theme.card)

            Section {
                Button { duplicate() } label: { Label("复制为新策略组", systemImage: "plus.square.on.square") }
                if let o = originalName, edits.edits?[o] != nil {
                    Button { Task { await restore() } } label: { Label("恢复原始", systemImage: "arrow.uturn.backward") }
                }
                Button(role: .destructive) { confirmDelete = true } label: { Label("删除策略组", systemImage: "trash") }
            }
            .listRowBackground(Theme.card)
        }
    }

    var filterPreview: some View {
        let names = previewNodes
        return VStack(alignment: .leading, spacing: 4) {
            Text("匹配 \(names.count) 个节点").font(.caption.weight(.semibold))
            if !names.isEmpty {
                Text(names.prefix(12).joined(separator: " · ")).font(.caption2).foregroundStyle(.secondary).lineLimit(3)
            }
        }
    }

    // MARK: Data

    var candidates: [String] {
        var out = ["DIRECT", "REJECT"]
        out += specs.groups.map(\.name).filter { $0 != spec.name && $0 != groupName }
        out += (edits.added ?? []).map(\.name).filter { $0 != spec.name }
        out += specs.proxies
        return out.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
    }

    func memberKind(_ m: String) -> String {
        if ["DIRECT", "REJECT", "REJECT-DROP", "PASS"].contains(m.uppercased()) { return "内置" }
        if specs.groups.contains(where: { $0.name == m }) || (edits.added ?? []).contains(where: { $0.name == m }) { return "策略组" }
        return "节点"
    }

    /// Nodes the group would get from `use` providers / include-all after filter + exclude-filter.
    var previewNodes: [String] {
        var pool: [String] = []
        if spec.includeAll == true { pool += offline.result.proxies.map(\.name) }
        for pv in offline.result.proxyProviders where spec.includeAll == true || (spec.use ?? []).contains(pv.name) {
            pool += (pv.proxies ?? []).map(\.name)
        }
        func matches(_ pattern: String?, _ s: String) -> Bool? {
            guard let p = pattern, !p.isEmpty else { return nil }
            // mihomo accepts several filters separated by backticks; any match counts.
            for part in p.split(separator: "`") {
                if let re = try? NSRegularExpression(pattern: String(part)),
                   re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil { return true }
            }
            return false
        }
        return pool.filter { n in
            if matches(spec.filter, n) == false { return false }
            if matches(spec.excludeFilter, n) == true { return false }
            return true
        }
    }

    var routedRules: [InspectRule] {
        let n = groupName ?? spec.name
        return offline.result.rules.filter { $0.proxy == n }
    }

    func load() async {
        guard let p = profile else { message = String(localized: "请先选择一个配置"); return }
        specs = await GroupSpecsResult.load(p.fileURL.path)
        edits = GroupEditStore.get(p.id)
        if let groupName {
            if let i = (edits.added ?? []).firstIndex(where: { $0.name == groupName }) {
                addedIndex = i
                spec = edits.added![i]
            } else if let hit = (edits.edits ?? [:]).first(where: { $0.value.spec?.name == groupName }), let s = hit.value.spec {
                originalName = hit.key
                spec = s
            } else if let s = specs.groups.first(where: { $0.name == groupName }) {
                originalName = groupName
                spec = s
            } else {
                spec = GroupSpec(name: groupName)
            }
        } else {
            spec = GroupSpec(name: String(localized: "新策略组"))
        }
        loaded = true
    }

    func candidate() -> GroupEdits {
        var e = edits
        var s = spec
        s.name = s.name.trimmingCharacters(in: .whitespaces)
        if let i = addedIndex {
            e.added?[i] = s
        } else if let orig = originalName {
            var m = e.edits ?? [:]
            m[orig] = GroupEdit(deleted: nil, spec: s)
            e.edits = m
        } else {
            e.added = (e.added ?? []) + [s]
        }
        return e
    }

    func save() async {
        guard let p = profile else { return }
        let name = spec.name.trimmingCharacters(in: .whitespaces)
        if name.isEmpty { message = String(localized: "名称不能为空"); return }
        SnapshotStore.shared.capture(String(localized: "编辑策略组前"))
        let clash = name != groupName && ((specs.groups.contains { $0.name == name } && name != originalName)
            || (edits.added ?? []).enumerated().contains { $0.element.name == name && $0.offset != addedIndex }
            || specs.proxies.contains(name))
        if clash {
            message = String(localized: "已有同名的策略组或节点")
            return
        }
        let e = candidate()
        await persist(e, profile: p)
    }

    func persist(_ e: GroupEdits, profile p: Profile) async {
        saving = true
        defer { saving = false }
        let json = GroupEditStore.json(e)
        let path = p.fileURL.path
        let err = await Task.detached(priority: .userInitiated) { LibmihomoGroupEditCheck(AppShared.homeURL.path, path, json) }.value
        if !err.isEmpty { message = err; return }
        GroupEditStore.set(p.id, e)
        if vpn.isConnected, let r = await VPNManager.shared.reload() {
            message = String(localized: "已保存，但重载失败：\(r)")
            return
        }
        await offline.load()
        dismiss()
    }

    func delete() async {
        guard let p = profile else { return }
        var e = edits
        if let i = addedIndex {
            e.added?.remove(at: i)
        } else if let orig = originalName {
            var m = e.edits ?? [:]
            m[orig] = GroupEdit(deleted: true, spec: nil)
            e.edits = m
        }
        await persist(e, profile: p)
    }

    func restore() async {
        guard let p = profile, let orig = originalName else { return }
        var e = edits
        e.edits?[orig] = nil
        await persist(e, profile: p)
    }

    func duplicate() {
        var s = spec
        var n = s.name + " " + String(localized: "副本")
        var i = 2
        let taken = Set(candidates + [spec.name])
        while taken.contains(n) { n = s.name + " " + String(localized: "副本") + " \(i)"; i += 1 }
        s.name = n
        edits.added = (edits.added ?? []) + [s]
        addedIndex = (edits.added?.count ?? 1) - 1
        originalName = nil
        spec = s
    }
}

/// Multi-select of members to add.
struct MemberPicker: View {
    let candidates: [String]
    let chosen: Set<String>
    let onAdd: ([String]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var picked: [String] = []
    @State private var search = ""

    var body: some View {
        NavigationStack {
            List {
                ForEach(candidates.filter { !chosen.contains($0) && (search.isEmpty || $0.localizedCaseInsensitiveContains(search)) }, id: \.self) { c in
                    Button {
                        if let i = picked.firstIndex(of: c) { picked.remove(at: i) } else { picked.append(c) }
                    } label: {
                        HStack {
                            Text(c).foregroundStyle(.primary).lineLimit(1)
                            Spacer()
                            if picked.contains(c) { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }
            .searchable(text: $search)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("添加成员").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加 \(picked.count)") { onAdd(picked); dismiss() }.disabled(picked.isEmpty)
                }
            }
        }
    }
}
