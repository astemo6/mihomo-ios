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

    /// v0.15.4 节点来源 (Loon-style): every proxy-provider (配置里的订阅 / 节点订阅), or only the chosen
    /// ones by provider name, and / or the profile's own nodes. Default = everything (include-all).
    var allSubscriptions: Bool = true
    var subscriptions: [String] = []
    var includeLocal: Bool = true
    /// "regex" (built-in regions, filters saved before v0.15.4) or "keywords" (包含任一, matched literally).
    var kind: String = "regex"
    /// 排除关键词 (| separated, literal) → exclude-filter.
    var exclude: String = ""

    static func keywords(_ s: String) -> [String] {
        s.split(separator: "|").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// mihomo `filter` (regexp2): exactly what the generated group gets, so preview == core.
    var filter: String {
        if kind == "keywords" { return "(?i)" + Self.keywords(pattern).map { NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "|") }
        return "(?i)" + pattern
    }

    var excludeFilter: String? {
        let k = Self.keywords(exclude)
        return k.isEmpty ? nil : "(?i)" + k.map { NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "|")
    }

    var hasSources: Bool { includeLocal || allSubscriptions || !subscriptions.isEmpty }

    /// Sources → mihomo keys: all + local = include-all; all only = include-all-providers; chosen providers =
    /// use (+ include-all-proxies with local). Never include-all when only some subscriptions are chosen.
    func applySources(to spec: inout GroupSpec) {
        spec.filter = filter
        spec.excludeFilter = excludeFilter
        spec.includeAll = nil
        spec.includeAllProxies = nil
        spec.includeAllProviders = nil
        spec.use = nil
        if allSubscriptions && includeLocal {
            spec.includeAll = true
        } else if allSubscriptions {
            spec.includeAllProviders = true
        } else {
            if !subscriptions.isEmpty { spec.use = subscriptions }
            if includeLocal { spec.includeAllProxies = true }
        }
    }

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

extension RegionFilter {
    enum CodingKeys: String, CodingKey {
        case id, name, flag, pattern, type, interval, tolerance, allSubscriptions, subscriptions, includeLocal, kind, exclude
    }

    /// Filters saved before v0.15.4 have no source / kind keys.
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        flag = (try? c.decodeIfPresent(String.self, forKey: .flag)) ?? "🏳️"
        pattern = (try? c.decodeIfPresent(String.self, forKey: .pattern)) ?? ""
        type = (try? c.decodeIfPresent(String.self, forKey: .type)) ?? "url-test"
        interval = (try? c.decodeIfPresent(Int.self, forKey: .interval)) ?? 300
        tolerance = (try? c.decodeIfPresent(Int.self, forKey: .tolerance)) ?? 50
        allSubscriptions = (try? c.decodeIfPresent(Bool.self, forKey: .allSubscriptions)) ?? true
        subscriptions = (try? c.decodeIfPresent([String].self, forKey: .subscriptions)) ?? []
        includeLocal = (try? c.decodeIfPresent(Bool.self, forKey: .includeLocal)) ?? true
        kind = (try? c.decodeIfPresent(String.self, forKey: .kind)) ?? "regex"
        exclude = (try? c.decodeIfPresent(String.self, forKey: .exclude)) ?? ""
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

    /// v0.19.8: the 自定义 copy made by a group reorder gets the source's filters. It already got the source's
    /// 策略组编辑 (the filter groups included); without its filters a renamed filter fell back to the default name,
    /// no longer matched its group, and editing it renamed nothing.
    static func copy(from: String, to: String) {
        guard AppShared.defaults.data(forKey: key(to)) == nil, let d = AppShared.defaults.data(forKey: key(from)) else { return }
        AppShared.defaults.set(d, forKey: key(to))
    }

    /// A subscription (proxy-provider) was renamed (`new`) or removed (nil): filters of every profile that
    /// chose it, and groups that `use` it (策略组编辑 / 筛选节点 groups), follow.
    @MainActor
    static func renameSource(_ old: String, to new: String?) {
        guard old != new else { return }
        for (k, v) in AppShared.defaults.dictionaryRepresentation() where k.hasPrefix(prefix) {
            guard let d = v as? Data, var l = try? JSONDecoder().decode([RegionFilter].self, from: d) else { continue }
            var changed = false
            for i in l.indices where l[i].subscriptions.contains(old) {
                l[i].subscriptions = l[i].subscriptions.compactMap { $0 == old ? new : $0 }
                if !l[i].hasSources { l[i].allSubscriptions = true }
                changed = true
            }
            if changed, let nd = try? JSONEncoder().encode(l) { AppShared.defaults.set(nd, forKey: k) }
        }
        func fix(_ g: inout GroupSpec) -> Bool {
            guard let u = g.use, u.contains(old) else { return false }
            let nu = u.compactMap { $0 == old ? new : $0 }
            g.use = nu.isEmpty ? nil : nu
            if g.use == nil, g.proxies.isEmpty, g.includeAll != true, g.includeAllProxies != true, g.includeAllProviders != true {
                g.proxies = ["DIRECT"] // mihomo refuses a group with nothing in it
            }
            return true
        }
        for (pid, saved) in GroupEditStore.all() {
            var e = saved
            var changed = false
            if var a = e.added {
                for i in a.indices where fix(&a[i]) { changed = true }
                e.added = a
            }
            if var ed = e.edits {
                for key in Array(ed.keys) {
                    if var sp = ed[key]?.spec, fix(&sp) { ed[key]?.spec = sp; changed = true }
                }
                e.edits = ed
            }
            if changed { GroupEditStore.set(pid, e) }
        }
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
    @State private var previewMembers: [String: [String]] = [:]
    /// Review 5: removing a policy group from the profile asks first (swipe, menu, or deleting its filter).
    @State private var pendingRemoveGroup: RegionFilter?
    @State private var pendingDelete: [RegionFilter]?
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

    /// Until the core-side preview arrives (B16: bridge GroupPreview = what the group will contain).
    func count(_ f: RegionFilter) -> Int {
        if let n = previewMembers[f.id] { return n.count }
        return f.hasSources ? NodeListScope(title: f.name, pattern: f.filter).filter(model.nodes).count : 0
    }

    func refreshPreview() async {
        let list = filters
        guard !list.isEmpty, let r = await offline.preview(list.map { spec(for: $0) }) else { return }
        var m: [String: [String]] = [:]
        for (f, it) in zip(list, r) where it.error == nil {
            m[f.id] = (it.empty == true || !f.hasSources) ? [] : (it.members ?? [])
        }
        previewMembers = m
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
                            IconGlyph(value: f.flag, size: 26)
                            Text(verbatim: f.name)
                            Spacer()
                            Text(verbatim: "\(counts[f.id] ?? 0)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                    .onMove { from, to in filters.move(fromOffsets: from, toOffset: to); persistFilters() }
                    .onDelete { idx in
                        let list = idx.map { filters[$0] }
                        if list.contains(where: { added.contains($0.name) }) { pendingDelete = list } else { Task { await delete(list) } }
                    }
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
                                IconGlyph(value: f.flag, size: 26)
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
        .task(id: filters) { await refreshPreview() }
        .sheet(item: $editing) { f in
            RegionFilterEditor(filter: f, isNew: false, others: filters.filter { $0.id != f.id }, isGroup: added.contains(f.name),
                               profileGroup: added.contains(f.name) ? nil : offline.result.groups.first(where: { $0.name == f.name })?.name) { new in
                Task { await apply(old: f, new: new) }
            }
            .environmentObject(store).environmentObject(vpn)
        }
        .sheet(isPresented: $creating) {
            RegionFilterEditor(filter: RegionFilter(id: UUID().uuidString, name: "", flag: "🏳️", pattern: "", kind: "keywords"), isNew: true, others: filters, isGroup: false) { new in
                filters.append(new)
                persistFilters()
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .deleteConfirmation({ f in Text("移除策略组「\(f.name)」？") }, item: $pendingRemoveGroup,
                            message: { _ in Text("会从当前配置中删除这个策略组，筛选本身保留。") },
                            id: "filter.confirmRemove", actionTitle: "移除策略组") { f in
            Task { await removeGroup(f) }
        }
        .deleteConfirmation({ _ in Text("删除筛选？") }, item: $pendingDelete,
                            message: { _ in Text("删除已加为策略组的筛选时，该策略组会一并移除。") }) { list in
            Task { await delete(list) }
        }
    }

    func regionRow(_ f: RegionFilter, count: Int) -> some View {
        HStack(spacing: 12) {
            NavigationLink {
                // Review 6 OPT-1: built on push, not on every render (a Set of all members per region per render).
                LazyDestination {
                    NodeListView(scope: previewMembers[f.id].map { NodeListScope(title: f.name, names: Set($0)) }
                                 ?? NodeListScope(title: f.name, pattern: f.filter))
                }
            } label: {
                HStack(spacing: 12) {
                    IconGlyph(value: f.flag, size: 26)
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
                    Button(role: .destructive) { pendingRemoveGroup = f } label: { Label("移除策略组", systemImage: "minus.circle") }
                } else {
                    Button { Task { await addGroup(f) } } label: { Label("加为策略组", systemImage: "plus.circle") }.tint(Theme.accent)
                }
            }
        }
        .contextMenu {
            Button { editing = f } label: { Label("编辑筛选", systemImage: "pencil") }
            if store.active != nil {
                if added.contains(f.name) {
                    Button(role: .destructive) { pendingRemoveGroup = f } label: { Label("移除策略组", systemImage: "minus.circle") }
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
        f.applySources(to: &spec)
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
        // v0.19.8: the filter's flag becomes the group's icon (策略 / 首页), unless the user already chose one.
        if await persist(e, profile: p, busyID: f.id), GroupIconStore.shared.custom[f.name] == nil, !f.flag.isEmpty {
            GroupIconStore.shared.set(group: f.name, url: f.flag)
        }
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
        guard filters.contains(where: { $0.id == old.id }) else { return }
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
            // v0.19.8: the icon follows the flag (and the name).
            let icons = GroupIconStore.shared
            let followsFlag = icons.custom[old.name] == nil || icons.custom[old.name] == old.flag
            if renamed {
                if let err = await GroupRename.propagate(old: old.name, new: new.name, profile: p, inFile: false) { message = err }
            }
            if followsFlag || old.flag != new.flag { icons.set(group: new.name, url: new.flag) }
            if renamed {
                if vpn.isConnected {
                    if let rr = await ReloadCoalescer.shared.reload(vpn, after: 0) { message = String(localized: "已保存，但重载失败：\(rr)") }
                    await NameRefs.reselect(pinned, new.name)
                }
                await offline.load()
                loadAdded()
            }
        }
        // Review 6: looked up again after the awaits above (a filter deleted meanwhile shifted the indices).
        guard let i = filters.firstIndex(where: { $0.id == old.id }) else { return }
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
        await SnapshotStore.shared.captureAsync(String(localized: "编辑策略组前"))
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
    /// v0.19.8: a group of the current config with this filter's name that the filter does not control (from the
    /// profile itself, or made elsewhere). Device report: the user edited this filter to rename / re-icon that group
    /// and nothing happened; the editor now says so and opens the group's own editor.
    var profileGroup: String? = nil
    let onSave: (RegionFilter) -> Void
    @State private var originalName = ""
    @State private var matchCount: Int?
    @State private var pickingIcon = false
    @State private var editingGroup = false

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
        if filter.kind == "keywords" ? RegionFilter.keywords(filter.pattern).isEmpty : filter.pattern.trimmingCharacters(in: .whitespaces).isEmpty {
            return String(localized: "关键词不能为空")
        }
        if (try? NSRegularExpression(pattern: filter.filter)) == nil { return String(localized: "正则表达式无效") }
        if !filter.hasSources { return String(localized: "至少选择一个节点来源") }
        return nil
    }

    /// Profile proxy-providers + node subscriptions as the runtime names them (the names `use:` takes).
    var providerNames: [String] {
        var out = offline.result.proxyProviders.map(\.name)
        for n in filter.subscriptions where !out.contains(n) { out.append(n) }
        return out
    }

    func subscriptionBinding(_ name: String) -> Binding<Bool> {
        Binding(get: { filter.subscriptions.contains(name) }, set: { on in
            filter.subscriptions.removeAll { $0 == name }
            if on { filter.subscriptions.append(name) }
        })
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
                    // v0.19.8: the whole row opens the icon picker (flags drawn by FlagGlyph, emoji, symbols, URL).
                    Button { pickingIcon = true } label: {
                        HStack {
                            Text("图标").foregroundStyle(.primary)
                            Spacer()
                            IconGlyph(value: filter.flag, size: 28)
                            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .accessibilityIdentifier("filter.flag")
                } footer: {
                    if isGroup {
                        Text("已加为策略组：改名会同时改策略组名称，以及策略组成员、规则、首页卡片里对它的引用；图标也会用作策略组图标。")
                    } else if let g = profileGroup {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("当前配置里的策略组「\(g)」不是由这个筛选生成的，在这里改名或换图标不会改动它。")
                            Button("编辑策略组「\(g)」") { editingGroup = true }
                                .font(.footnote.weight(.semibold))
                                .accessibilityIdentifier("filter.editProfileGroup")
                        }
                    }
                }
                .listRowBackground(Theme.card)
                Section {
                    Toggle("本地节点", isOn: $filter.includeLocal)
                        .accessibilityIdentifier("filter.src.local")
                    Toggle("全部订阅", isOn: $filter.allSubscriptions)
                        .accessibilityIdentifier("filter.src.all")
                    if !filter.allSubscriptions {
                        if providerNames.isEmpty {
                            Text("当前配置没有订阅").font(.footnote).foregroundStyle(.secondary)
                        }
                        ForEach(providerNames, id: \.self) { n in
                            Toggle(isOn: subscriptionBinding(n)) { Text(verbatim: n) }
                                .accessibilityIdentifier("filter.src." + n)
                        }
                    }
                } header: { Text("节点来源") } footer: {
                    Text("本地节点 = 配置文件里的节点；订阅 = 配置里的节点集和节点订阅。只选部分订阅时，策略组用 use 只引用这些订阅。")
                }
                .listRowBackground(Theme.card)
                Section {
                    Picker("筛选方式", selection: $filter.kind) {
                        Text("关键词").tag("keywords")
                        Text("正则").tag("regex")
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("filter.kind")
                    TextField("香港|HK|Hong Kong", text: $filter.pattern, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .lineLimit(2...6)
                        .accessibilityIdentifier("filter.pattern")
                    TextField("排除关键词，例如 过期|剩余", text: $filter.exclude)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("filter.exclude")
                    if let e = patternError { Text(e).font(.footnote).foregroundStyle(Theme.warn) }
                    else if let n = matchCount {
                        Text("匹配 \(n) 个节点").font(.footnote).foregroundStyle(.secondary)
                            .accessibilityIdentifier("filter.matches")
                    }
                } header: { Text("筛选条件") } footer: {
                    Text(filter.kind == "keywords"
                         ? "节点名称包含任一关键词即匹配（用 | 分隔，不区分大小写）；包含任一排除关键词的节点不要。"
                         : "正则表达式，不区分大小写；包含任一排除关键词的节点不要。")
                }
                .task(id: filter) {
                    try? await Task.sleep(nanoseconds: 300_000_000)
                    guard !Task.isCancelled else { return }
                    guard patternError == nil else { matchCount = nil; return }
                    var spec = GroupSpec(name: "preview", type: "select")
                    filter.applySources(to: &spec)
                    if let r = await offline.preview([spec])?.first, r.error == nil {
                        matchCount = r.empty == true ? 0 : (r.members ?? []).count
                    } else {
                        matchCount = NodeListScope(title: "", pattern: filter.filter).filter(model.nodes).count
                    }
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
            .sheet(isPresented: $pickingIcon) {
                IconPickerSheet(title: trimmedName.isEmpty ? String(localized: "图标") : trimmedName, current: filter.flag, allowsReset: false) { v in
                    if let v, !v.isEmpty { filter.flag = v }
                }
            }
            .sheet(isPresented: $editingGroup) {
                if let g = profileGroup {
                    GroupEditorView(groupName: g).environmentObject(ProfileStore.shared).environmentObject(VPNManager.shared)
                }
            }
        }
    }
}
