import SwiftUI

// feat/more-search: the views behind 更多's search field — the destination registry, the grouped result list and
// one result row (Egern compact row: colour tile, highlighted title, breadcrumb subtitle).

extension SearchDestination: Identifiable {
    var id: String { rawValue }

    /// THE registry: the page each destination opens. Retarget an entry (a page renamed or merged) here only.
    /// Pages that need no arguments; `.tab` / `.onboarding` / `.systemSettings` destinations never build a page.
    @MainActor @ViewBuilder var page: some View {
        switch self {
        // 更多
        case .profiles: ProfilesView()
        case .sampleProfile: SampleProfileView()
        case .stats: StatsView()
        case .snapshots: SnapshotsView()
        case .backup: BackupView()
        case .webdav: WebDAVView()
        case .syncFolder: SyncFolderView()
        case .updateResources: UpdateResourcesView()
        case .storage: StorageView()
        case .appearance: AppearanceView()
        case .liveActivity: LiveActivitySettingsView()
        case .appIcon: AppIconView()
        case .launchTab: LaunchTabView()
        case .trafficScope: TrafficScopeView()
        case .advanced: AdvancedSettingsView()
        case .connection: ConnectionView()
        case .networkPolicy: NetworkPolicyView()
        case .geo: GeoView()
        case .coreSettings: SettingsView()
        case .speedTestSettings: SpeedTestSettingsView()
        case .geoChecker: GeoCheckerView()
        case .diagnostics: DiagnosticsView()
        case .about: AboutView()
        // 工具. PR #90 merged 模块 / 重写 / 脚本 into one QX-style 重写 page (subscriptions = modules, local rewrites,
        // local scripts); their entries all open it. 模块库 / 全部重写规则 / script tools are links on that page.
        case .nodes: NodeManagerView()
        case .rules: RulesView()
        case .modules, .rewrites, .scripts: RewriteView()
        case .moduleGallery: ModuleGalleryView()
        case .allRewrites: AllRewritesView()
        case .scriptLogs: ScriptLogsView()
        case .scriptNotices: ScriptNoticesView()
        case .scriptStore: StoreView()
        case .tasks: ScriptTasksView()
        case .mitm: MitMView()
        case .dns: DNSView()
        case .logs: LogsView()
        case .dnsLog: DNSLogView()
        case .analytics: AnalyticsView()
        case .netDiagnostics: ToolsView()
        case .netTest: NetTestView()
        case .unlock: UnlockView()
        case .lanInfo: LANDetailView()
        case .panels: PanelsView()
        // 首页 / 策略 (sheets bring their own NavigationStack)
        case .homePanels: HomePanelsEditor()
        case .homeGroups: HomeGroupsEditor()
        case .homeTab, .policyTab, .onboarding, .systemLanguage: EmptyView()
        }
    }

    /// Whether `page` is a real page (the unit test checks every entry against this).
    var buildsPage: Bool {
        switch presentation {
        case .push, .sheet: return true
        case .tab, .onboarding, .systemSettings: return false
        }
    }
}

/// The result sections shown in 更多's List while the search field has text.
struct SettingsSearchResults: View {
    let query: String
    let open: (SearchDestination) -> Void

    var body: some View {
        let hits = SettingsSearchIndex.search(query)
        if hits.isEmpty {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").font(.system(size: 34)).foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text("没有找到「\(query.trimmingCharacters(in: .whitespaces))」").font(.headline).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Text("试试其他关键词，例如 DNS、证书或订阅。").font(.footnote).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 28)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("search.empty")
            }
            .listRowBackground(Color.clear)
        } else {
            ForEach(SettingsSearchIndex.grouped(hits)) { group in
                Section {
                    ForEach(group.hits, id: \.entry.id) { hit in
                        Button { open(hit.entry.destination) } label: { SearchResultRow(hit: hit) }
                            .buttonStyle(.plain)
                    }
                } header: { Text(LocalizedStringKey(group.section)) }
                .listRowBackground(Theme.card)
            }
        }
    }
}

struct SearchResultRow: View {
    let hit: SettingsSearchIndex.Hit

    var title: String { SettingsSearchIndex.shown(hit.entry.title) }
    var breadcrumb: String { hit.entry.path.map(SettingsSearchIndex.shown).joined(separator: " › ") }

    var highlighted: AttributedString {
        var a = AttributedString(title)
        guard let r = hit.titleRange, r.lowerBound >= 0, r.upperBound <= title.count else { return a }
        let chars = a.characters
        let lo = chars.index(chars.startIndex, offsetBy: r.lowerBound)
        let hi = chars.index(chars.startIndex, offsetBy: r.upperBound)
        a[lo..<hi].foregroundColor = Theme.accent
        a[lo..<hi].font = .subheadline.weight(.semibold)
        return a
    }

    var body: some View {
        HStack(spacing: 12) {
            IconTile(symbol: hit.entry.symbol, tone: hit.entry.tone)
            VStack(alignment: .leading, spacing: 1) {
                Text(highlighted).font(.subheadline).foregroundStyle(.primary)
                Text(verbatim: breadcrumb).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            Image(systemName: chevron).font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(verbatim: "\(title), \(breadcrumb)"))
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("search.result." + hit.entry.id)
    }

    var chevron: String {
        switch hit.entry.destination.presentation {
        case .systemSettings: return "arrow.up.forward.app"
        default: return "chevron.right"
        }
    }
}
