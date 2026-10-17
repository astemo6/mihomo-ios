import SwiftUI
import Libmihomo

/// 节点管理 → 筛选节点 (v0.16): region filters from node names (the same patterns as 节点处理's region
/// sort, bridge/subrules.go regionDefs). Each region opens its node list and can be added to the active
/// profile as an automatic url-test group (include-all + filter) through the existing 策略组编辑 store.
struct NodeFilterView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = NodeManagerModel.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var added: Set<String> = []
    @State private var busy: String?
    @State private var message: String?

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
        /// mihomo `filter` (regexp2) and NSRegularExpression both understand this syntax.
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

    func count(_ r: Region) -> Int {
        let scope = NodeListScope(title: r.title, pattern: r.filter)
        return scope.filter(model.nodes).count
    }

    var body: some View {
        let counts = Dictionary(uniqueKeysWithValues: Self.regions.map { ($0.code, count($0)) })
        let withNodes = Self.regions.filter { (counts[$0.code] ?? 0) > 0 }
        let without = Self.regions.filter { (counts[$0.code] ?? 0) == 0 }
        List {
            Section {
                if withNodes.isEmpty {
                    EmptyStateRow(icon: "globe.asia.australia", title: "没有识别到地区", message: "节点名称里没有常见的地区关键词或国旗。")
                }
                ForEach(withNodes) { r in regionRow(r, count: counts[r.code] ?? 0) }
            } header: { Text("按地区") } footer: {
                Text("按节点名称里的地区关键词和国旗筛选。「加为策略组」会在当前配置里新建一个自动选择（延迟最低）策略组，包含所有匹配的节点，可在 策略 页使用，也可在策略组编辑里修改或删除。")
            }
            .listRowBackground(Theme.card)
            if !without.isEmpty {
                Section("没有节点的地区") {
                    ForEach(without) { r in
                        HStack(spacing: 12) {
                            Text(verbatim: r.flag).font(.title3)
                            Text(verbatim: r.title).foregroundStyle(.secondary)
                            Spacer()
                            Text(verbatim: "0").font(.subheadline.monospacedDigit()).foregroundStyle(.tertiary)
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("筛选节点")
        .task {
            if model.nodes.isEmpty { await model.reload() }
            loadAdded()
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    func regionRow(_ r: Region, count: Int) -> some View {
        HStack(spacing: 12) {
            NavigationLink {
                NodeListView(scope: NodeListScope(title: r.title, pattern: r.filter))
            } label: {
                HStack(spacing: 12) {
                    Text(verbatim: r.flag).font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: r.title).font(.subheadline.weight(.semibold))
                        Text("\(count) 个节点").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .swipeActions(edge: .trailing) {
            if store.active != nil {
                if added.contains(r.title) {
                    Button(role: .destructive) { Task { await removeGroup(r) } } label: { Label("移除策略组", systemImage: "minus.circle") }
                } else {
                    Button { Task { await addGroup(r) } } label: { Label("加为策略组", systemImage: "plus.circle") }.tint(Theme.accent)
                }
            }
        }
        .contextMenu {
            if store.active != nil {
                if added.contains(r.title) {
                    Button(role: .destructive) { Task { await removeGroup(r) } } label: { Label("移除策略组", systemImage: "minus.circle") }
                } else {
                    Button { Task { await addGroup(r) } } label: { Label("加为策略组", systemImage: "plus.circle") }
                }
            }
        }
        .overlay(alignment: .trailing) {
            if busy == r.code {
                ProgressView().controlSize(.small).padding(.trailing, 24)
            } else if added.contains(r.title) {
                Text("已加为策略组").scaledFont(10, weight: .semibold).foregroundStyle(Theme.good).padding(.trailing, 24)
            }
        }
    }

    func loadAdded() {
        guard let p = store.active else { added = []; return }
        added = Set((GroupEditStore.get(p.id).added ?? []).map(\.name))
    }

    func addGroup(_ r: Region) async {
        guard let p = store.active else { return }
        let name = r.title
        if offline.result.groups.contains(where: { $0.name == name }) || model.nodes.contains(where: { $0.name == name }) {
            message = String(localized: "已有同名的策略组或节点")
            return
        }
        var e = GroupEditStore.get(p.id)
        var spec = GroupSpec(name: name, type: "url-test")
        spec.includeAll = true
        spec.filter = r.filter
        spec.url = ControllerClient.testSettings.url
        spec.interval = 300
        spec.tolerance = 50
        e.added = (e.added ?? []) + [spec]
        await persist(e, profile: p, region: r)
    }

    func removeGroup(_ r: Region) async {
        guard let p = store.active else { return }
        var e = GroupEditStore.get(p.id)
        e.added = (e.added ?? []).filter { $0.name != r.title }
        await persist(e, profile: p, region: r)
    }

    func persist(_ e: GroupEdits, profile p: Profile, region r: Region) async {
        busy = r.code
        defer { busy = nil }
        SnapshotStore.shared.capture(String(localized: "编辑策略组前"))
        let json = GroupEditStore.json(e)
        let path = p.fileURL.path
        let err = await Task.detached(priority: .userInitiated) { LibmihomoGroupEditCheck(AppShared.homeURL.path, path, json) }.value
        if !err.isEmpty { message = err; return }
        GroupEditStore.set(p.id, e)
        loadAdded()
        if vpn.isConnected, let rr = await VPNManager.shared.reload() {
            message = String(localized: "已保存，但重载失败：\(rr)")
        }
        await offline.load()
    }
}
