import SwiftUI
import Libmihomo

/// 节点管理 → 筛选节点 (v0.16): region filters from node names (the same patterns as 节点处理's region
/// sort, bridge/subrules.go regionDefs). Each region opens its node list and can be added to the active
/// profile as an automatic group (include-all + filter) through the existing 策略组编辑 store.
/// v0.15.4: every filter is editable per profile (name, keywords / regex, flag, group type, interval,
/// tolerance), custom filters can be added, filters deleted and reordered. Renaming a filter that is already
/// a 策略组 renames the group and every reference to it.

/// One filter (stored per profile in the App Group defaults, `regionfilters.<profile id>`).
struct RegionFilter: Codable, Hashable, Identifiable {
    var id: String
    var name: String
    var flag: String
    /// Keywords / regex without the (?i) prefix.
    var pattern: String
    var type: String = "url-test"
    var interval: Int = 300
    var tolerance: Int = 50

    /// mihomo `filter` (regexp2) and NSRegularExpression both understand this syntax.
    var filter: String { "(?i)" + pattern }

    static let types = ["url-test", "fallback", "load-balance", "select"]

    static func typeTitle(_ t: String) -> String {
        switch t {
        case "url-test": return String(localized: "自动选择（延迟最低）")
        case "fallback": return String(localized: "故障转移")
        case "load-balance": return String(localized: "负载均衡")
        default: return String(localized: "手动选择")
        }
    }
}

enum RegionFilterStore {
    private static let prefix = "regionfilters."

    static func key(_ profileID: String?) -> String { prefix + (profileID ?? "default") }

    static func defaults() -> [RegionFilter] {
        NodeFilterView.regions.map { RegionFilter(id: $0.code, name: $0.title, flag: $0.flag, pattern: $0.pattern) }
    }

    static func load(_ profileID: String?) -> [RegionFilter] {
        guard let d = AppShared.defaults.data(forKey: key(profileID)),
              let l = try? JSONDecoder().decode([RegionFilter].self, from: d) else { return defaults() }
        return l
    }

    static func save(_ l: [RegionFilter], _ profileID: String?) {
        if let d = try? JSONEncoder().encode(l) { AppShared.defaults.set(d, forKey: key(profileID)) }
    }
}

struct NodeFilterView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var filters: [RegionFilter] = []
    @State private var added: Set<String> = []
    @State private var busy: String?
    @State private var message: String?
    @State private var editing: RegionFilter?
    @State private var creating = false
    @Environment(\.editMode) private var editMode

    struct Region: Identifiable {
        let code: String
        let flag: String
        let pattern: String
        var id: String { code }
        var title: String {
            switch code {
            case "HK": return String(localized: "香港节点")
            case "TW": return String(localized: "台湾节点")
            case "JP": return String(localized: "日本节点")
            case "KR": return String(localized: "韩国节点")
            case "SG": return String(localized: "新加坡节点")
            case "US": return String(localized: "美国节点")
            case "GB": return String(localized: "英国节点")
            case "DE": return String(localized: "德国节点")
            case "FR": return String(localized: "法国节点")
            case "CA": return String(localized: "加拿大节点")
            case "AU": return String(localized: "澳大利亚节点")
            case "RU": return String(localized: "俄罗斯节点")
            default: return code
            }
        }
        var filter: String { "(?i)" + pattern }
    }

    static let regions: [Region] = [
        Region(code: "HK", flag: "🇭🇰", pattern: #"香港|深港|沪港|呼港|广港|京港|🇭🇰|Hong\s?Kong|(?<![A-Za-z])HKG?(?![A-Za-z])"#),
        Region(code: "TW", flag: "🇹🇼", pattern: #"台湾|台灣|臺灣|台北|新北|彰化|🇹🇼|Taiwan|(?<![A-Za-z])TWN?(?![A-Za-z])"#),
        Region(code: "JP", flag: "🇯🇵", pattern: #"日本|东京|東京|大阪|埼玉|名古屋|🇯🇵|Japan|Tokyo|Osaka|(?<![A-Za-z])JPN?(?![A-Za-z])"#),
        Region(code: "KR", flag: "🇰🇷", pattern: #"韩国|韓國|首尔|首爾|春川|🇰🇷|Korea|Seoul|(?<![A-Za-z])KO?R(?![A-Za-z])"#),
        Region(code: "SG", flag: "🇸🇬", pattern: #"新加坡|狮城|獅城|🇸🇬|Singapore|(?<![A-Za-z])SGP?(?![A-Za-z])"#),
        Region(code: "US", flag: "🇺🇸", pattern: #"美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|芝加哥|纽约|紐約|达拉斯|凤凰城|波特兰|🇺🇸|United\s?States|America|Los\s?Angeles|San\s?Jose|Silicon|Seattle|Chicago|New\s?York|(?<![A-Za-z])USA?(?![A-Za-z])"#),
        Region(code: "GB", flag: "🇬🇧", pattern: #"英国|英國|伦敦|倫敦|🇬🇧|United\s?Kingdom|Britain|London|(?<![A-Za-z])(UK|GB)(?![A-Za-z])"#),
        Region(code: "DE", flag: "🇩🇪", pattern: #"德国|德國|法兰克福|🇩🇪|Germany|Frankfurt|(?<![A-Za-z])DEU?(?![A-Za-z])"#),
        Region(code: "FR", flag: "🇫🇷", pattern: #"法国|法國|巴黎|🇫🇷|France|Paris|(?<![A-Za-z])FRA?(?![A-Za-z])"#),
        Region(code: "CA", flag: "🇨🇦", pattern: #"加拿大|多伦多|温哥华|蒙特利尔|🇨🇦|Canada|Toronto|Vancouver|(?<![A-Za-z])CAN?(?![A-Za-z])"#),
        Region(code: "AU", flag: "🇦🇺", pattern: #"澳大利亚|澳洲|悉尼|墨尔本|🇦🇺|Australia|Sydney|(?<![A-Za-z])AUS?(?![A-Za-z])"#),
        Region(code: "RU", flag: "🇷🇺", pattern: #"俄罗斯|俄羅斯|莫斯科|🇷🇺|Russia|Moscow|(?<![A-Za-z])RUS?(?![A-Za-z])"#),
    ]

    func count(_ f: RegionFilter) -> Int {
        NodeListScope(title: f.name, pattern: f.filter).filter(model.nodes).count
    }

    var editingList: Bool { editMode?.wrappedValue.isEditing == true }

    var body: some View {
        let counts = Dictionary(filters.map { ($0.id, count($0)) }, uniquingKeysWith: { a, _ in a })
        let withNodes = filters.filter { (counts[$0.id] ?? 0) > 0 }
        let without = filters.filter { (counts[$0.id] ?? 0) == 0 }
        List {
            if editingList {
                // Edit mode: every filter in its saved order, reorder + delete.
                Section {
                    ForEach(filters) { f in
                        HStack(spacing: 12) {
                            FlagGlyph(flag: f.flag)
                            Text(verbatim: f.name)
                            Spacer()
                            Text(verbatim: "\(counts[f.id] ?? 0)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                    .onMove { from, to in filters.move(fromOffsets: from, toOffset: to); persistFilters() }
                    .onDelete { idx in Task { await delete(idx.map { filters[$0] }) } }
                } header: { Text("全部筛选") } footer: {
                    Text("拖动排序，左滑删除。删除已加为策略组的筛选时，该策略组会一并移除。")
                }
                .listRowBackground(Theme.card)
            } else {
                Section {
                    if withNodes.isEmpty {
                        EmptyStateRow(icon: "globe.asia.australia", title: "没有识别到地区", message: "节点名称里没有常见的地区关键词或国旗。")
                    }
                    ForEach(withNodes) { f in regionRow(f, count: counts[f.id] ?? 0) }
                } header: { Text("按地区") } footer: {
                    Text("按节点名称里的地区关键词和国旗筛选。「加为策略组」会在当前配置里新建一个策略组（默认自动选择，延迟最低），包含所有匹配的节点，可在 策略 页使用。左滑或长按可编辑名称、关键词和策略组类型。")
                }
                .listRowBackground(Theme.card)
                if !without.isEmpty {
                    Section("没有节点的地区") {
                        ForEach(without) { f in
                            HStack(spacing: 12) {
                                FlagGlyph(flag: f.flag)
                                Text(verbatim: f.name).foregroundStyle(.secondary)
                                Spacer()
                                Text(verbatim: "0").font(.subheadline.monospacedDigit()).foregroundStyle(.tertiary)
                            }
                            .contentShape(Rectangle())
                            .contextMenu { Button { editing = f } label: { Label("编辑筛选", systemImage: "pencil") } }
                            .swipeActions(edge: .trailing) {
                                Button { editing = f } label: { Label("编辑筛选", systemImage: "pencil") }.tint(.gray)
                            }
                        }
                    }
                    .listRowBackground(Theme.card)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("筛选节点")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                EditButton()
                Button { creating = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加筛选"))
                    .accessibilityIdentifier("filters.add")
            }
        }
        .task {
            if model.nodes.isEmpty { await model.reload() }
            filters = RegionFilterStore.load(store.activeID)
            loadAdded()
        }
        .sheet(item: $editing) { f in
            RegionFilterEditor(filter: f, isNew: false, others: filters.filter { $0.id != f.id }, isGroup: added.contains(f.name)) { new in
                Task { await apply(old: f, new: new) }
            }
        }
        .sheet(isPresented: $creating) {
            RegionFilterEditor(filter: RegionFilter(id: UUID().uuidString, name: "", flag: "🏳️", pattern: ""), isNew: true, others: filters, isGroup: false) { new in
                filters.append(new)
                persistFilters()
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    func regionRow(_ f: RegionFilter, count: Int) -> some View {
        HStack(spacing: 12) {
            NavigationLink {
                NodeListView(scope: NodeListScope(title: f.name, pattern: f.filter))
            } label: {
                HStack(spacing: 12) {
                    FlagGlyph(flag: f.flag)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: f.name).font(.subheadline.weight(.semibold))
                        Text("\(count) 个节点").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .accessibilityIdentifier("filter." + f.id)
        .swipeActions(edge: .trailing) {
            Button { editing = f } label: { Label("编辑筛选", systemImage: "pencil") }.tint(.gray)
            if store.active != nil {
                if added.contains(f.name) {
                    Button(role: .destructive) { Task { await removeGroup(f) } } label: { Label("移除策略组", systemImage: "minus.circle") }
                } else {
                    Button { Task { await addGroup(f) } } label: { Label("加为策略组", systemImage: "plus.circle") }.tint(Theme.accent)
                }
            }
        }
        .contextMenu {
            Button { editing = f } label: { Label("编辑筛选", systemImage: "pencil") }
            if store.active != nil {
                if added.contains(f.name) {
                    Button(role: .destructive) { Task { await removeGroup(f) } } label: { Label("移除策略组", systemImage: "minus.circle") }
                } else {
                    Button { Task { await addGroup(f) } } label: { Label("加为策略组", systemImage: "plus.circle") }
                }
            }
        }
        .overlay(alignment: .trailing) {
            if busy == f.id {
                ProgressView().controlSize(.small).padding(.trailing, 24)
            } else if added.contains(f.name) {
                Text("已加为策略组").scaledFont(10, weight: .semibold).foregroundStyle(Theme.good).padding(.trailing, 24)
            }
        }
    }

    func persistFilters() { RegionFilterStore.save(filters, store.activeID) }

    func loadAdded() {
        guard let p = store.active else { added = []; return }
        added = Set((GroupEditStore.get(p.id).added ?? []).map(\.name))
    }

    func spec(for f: RegionFilter) -> GroupSpec {
        var spec = GroupSpec(name: f.name, type: f.type)
        spec.includeAll = true
        spec.filter = f.filter
        if f.type != "select" {
            spec.url = ControllerClient.testSettings.url
            spec.interval = f.interval
            if f.type == "url-test" { spec.tolerance = f.tolerance }
        }
        return spec
    }

    func nameTaken(_ name: String, except: String? = nil) -> Bool {
        name != except && (offline.result.groups.contains(where: { $0.name == name }) || model.nodes.contains(where: { $0.name == name }))
    }

    func addGroup(_ f: RegionFilter) async {
        guard let p = store.active else { return }
        if nameTaken(f.name) {
            message = String(localized: "已有同名的策略组或节点")
            return
        }
        var e = GroupEditStore.get(p.id)
        e.added = (e.added ?? []) + [spec(for: f)]
        _ = await persist(e, profile: p, busyID: f.id)
    }

    func removeGroup(_ f: RegionFilter) async {
        guard let p = store.active else { return }
        var e = GroupEditStore.get(p.id)
        e.added = (e.added ?? []).filter { $0.name != f.name }
        _ = await persist(e, profile: p, busyID: f.id)
    }

    /// Saves an edited filter; when it is a 策略组 the group follows (name, filter, type, interval, tolerance) and
    /// a rename is propagated to every reference.
    func apply(old: RegionFilter, new: RegionFilter) async {
        guard let i = filters.firstIndex(where: { $0.id == old.id }) else { return }
        let wasGroup = added.contains(old.name)
        if wasGroup, let p = store.active {
            let renamed = old.name != new.name
            var pinned: [String] = []
            if renamed { pinned = await NameRefs.selectionsUsing(old.name) }
            var e = GroupEditStore.get(p.id)
            e.added = (e.added ?? []).map { $0.name == old.name ? spec(for: new) : $0 }
            if renamed {
                // Other edited / added groups that list the old name as a member.
                e.added = e.added?.map { var g = $0; g.proxies = g.proxies.map { $0 == old.name ? new.name : $0 }; return g }
                if var ed = e.edits {
                    for k in Array(ed.keys) {
                        if var sp = ed[k]?.spec { sp.proxies = sp.proxies.map { $0 == old.name ? new.name : $0 }; ed[k]?.spec = sp }
                    }
                    e.edits = ed
                }
            }
            guard await persist(e, profile: p, busyID: old.id, reload: !renamed) else { return }
            if renamed {
                NameRefs.rename(old.name, to: new.name, profileID: p.id, isGroup: true)
                let path = p.fileURL.path, home = AppShared.homeURL.path, o = old.name, n = new.name
                let err = await Task.detached(priority: .userInitiated) { LibmihomoProfileRenameRefs(home, path, o, n) }.value
                if !err.isEmpty { message = err }
                if vpn.isConnected {
                    if let rr = await ReloadCoalescer.shared.reload(vpn, after: 0) { message = String(localized: "已保存，但重载失败：\(rr)") }
                    await NameRefs.reselect(pinned, new.name)
                }
                await offline.load()
                loadAdded()
            }
        }
        filters[i] = new
        persistFilters()
    }

    func delete(_ list: [RegionFilter]) async {
        for f in list where added.contains(f.name) { await removeGroup(f) }
        let ids = Set(list.map(\.id))
        filters.removeAll { ids.contains($0.id) }
        persistFilters()
    }

    @discardableResult
    func persist(_ e: GroupEdits, profile p: Profile, busyID: String, reload: Bool = true) async -> Bool {
        busy = busyID
        defer { busy = nil }
        SnapshotStore.shared.capture(String(localized: "编辑策略组前"))
        let json = GroupEditStore.json(e)
        let path = p.fileURL.path
        let err = await Task.detached(priority: .userInitiated) { LibmihomoGroupEditCheck(AppShared.homeURL.path, path, json) }.value
        if !err.isEmpty { message = err; return false }
        GroupEditStore.set(p.id, e)
        loadAdded()
        if reload, vpn.isConnected, let rr = await ReloadCoalescer.shared.reload(vpn, after: 0) {
            message = String(localized: "已保存，但重载失败：\(rr)")
        }
        await offline.load()
        return true
    }
}

/// Editor for one filter (an editor sheet, so it keeps 保存).
struct RegionFilterEditor: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State var filter: RegionFilter
    let isNew: Bool
    let others: [RegionFilter]
    let isGroup: Bool
    let onSave: (RegionFilter) -> Void
    @State private var originalName = ""

    var trimmedName: String { filter.name.trimmingCharacters(in: .whitespaces) }

    var nameError: String? {
        if trimmedName.isEmpty { return String(localized: "名称不能为空") }
        if others.contains(where: { $0.name == trimmedName }) { return String(localized: "已有同名的筛选") }
        if trimmedName != originalName,
           offline.result.groups.contains(where: { $0.name == trimmedName }) || model.nodes.contains(where: { $0.name == trimmedName }) {
            return String(localized: "已有同名的策略组或节点")
        }
        return nil
    }

    var patternError: String? {
        if filter.pattern.trimmingCharacters(in: .whitespaces).isEmpty { return String(localized: "关键词不能为空") }
        if (try? NSRegularExpression(pattern: filter.filter)) == nil { return String(localized: "正则表达式无效") }
        return nil
    }

    var matches: [ManagedNode] {
        patternError == nil ? NodeListScope(title: "", pattern: filter.filter).filter(model.nodes) : []
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("名称", text: $filter.name)
                        .accessibilityIdentifier("filter.name")
                    if let e = nameError, !(isNew && trimmedName.isEmpty) {
                        Text(e).font(.footnote).foregroundStyle(Theme.warn)
                    }
                    HStack {
                        Text("图标")
                        Spacer()
                        TextField("🏳️", text: $filter.flag)
                            .multilineTextAlignment(.trailing).frame(width: 80)
                            .accessibilityIdentifier("filter.flag")
                        FlagGlyph(flag: filter.flag)
                    }
                } footer: {
                    if isGroup { Text("已加为策略组：改名会同时改策略组名称，以及策略组成员、规则、首页卡片里对它的引用。") }
                }
                .listRowBackground(Theme.card)
                Section {
                    TextField("香港|HK|Hong Kong", text: $filter.pattern, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .lineLimit(2...6)
                        .accessibilityIdentifier("filter.pattern")
                    if let e = patternError { Text(e).font(.footnote).foregroundStyle(Theme.warn) }
                    else {
                        Text("匹配 \(matches.count) 个节点").font(.footnote).foregroundStyle(.secondary)
                    }
                } header: { Text("关键词（正则）") } footer: {
                    Text("用 | 分隔多个关键词，不区分大小写；支持正则表达式。")
                }
                .listRowBackground(Theme.card)
                Section {
                    Picker("类型", selection: $filter.type) {
                        ForEach(RegionFilter.types, id: \.self) { Text(verbatim: RegionFilter.typeTitle($0)).tag($0) }
                    }
                    if filter.type != "select" {
                        Stepper(value: $filter.interval, in: 30...3600, step: 30) {
                            HStack { Text("测速间隔"); Spacer(); Text("\(filter.interval) 秒").monospacedDigit().foregroundStyle(.secondary) }
                        }
                    }
                    if filter.type == "url-test" {
                        Stepper(value: $filter.tolerance, in: 0...500, step: 10) {
                            HStack { Text("容差"); Spacer(); Text("\(filter.tolerance) ms").monospacedDigit().foregroundStyle(.secondary) }
                        }
                    }
                } header: { Text("加为策略组时") }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(isNew ? "添加筛选" : "编辑筛选")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        var f = filter
                        f.name = trimmedName
                        f.pattern = f.pattern.trimmingCharacters(in: .whitespacesAndNewlines)
                        onSave(f)
                        dismiss()
                    }
                    .disabled(nameError != nil || patternError != nil)
                }
            }
            .onAppear { originalName = isNew ? "" : filter.name }
        }
    }
}
