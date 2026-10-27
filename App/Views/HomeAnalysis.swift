import SwiftUI

// feat/home-analysis (Egern 分析 tab, on 首页). Order on Home follows Egern's 分析:
//   全部连接 / 活跃连接 tiles → 网络 (the existing speed card + totals) → 策略 → 规则 → 主机名 → 面板.
//   策略: bytes per final policy (head of each connection's chain), stacked bar + legend
//   规则: hit counts of the busiest rules as rings, horizontal scroll
//   主机名: hostnames by bytes with mini bars
// Data: the same session data as 连接分析 (ConnectionAnalytics). P0-2: recorded in the tunnel (also while the app is in
// the background or killed) and copied in on DashboardModel's 2 s poll. Nothing is invented: VPN off → one empty state.
// Performance (fix/nav-jank rule, PR #75): nothing above these cards observes a store that publishes often.
// HomeAnalysisModel is not an ObservableObject; it copies a small, capped snapshot out of ConnectionAnalytics at
// most every 2 s, only while Home is on screen, the app is active and an analysis view is mounted, and publishes
// a field only when it changed. Each card mirrors just its own field (onReceive + @State), so a new sample
// re-renders that card only, never HomeView or the tab.

enum HomeAnalysisCard: String, CaseIterable, Identifiable {
    case connections, policies, rules, hosts, dns
    var id: String { rawValue }

    var title: String {
        switch self {
        case .connections: return String(localized: "连接数")
        case .policies: return String(localized: "策略")
        case .rules: return String(localized: "规则")
        case .hosts: return String(localized: "主机名")
        case .dns: return "DNS"
        }
    }

    var icon: String {
        switch self {
        case .connections: return "point.3.connected.trianglepath.dotted"
        case .policies: return "chart.bar.xaxis"
        case .rules: return "target"
        case .hosts: return "network"
        case .dns: return "globe"
        }
    }

    var caption: String {
        switch self {
        case .connections: return String(localized: "本次连接的全部连接与活跃连接数")
        case .policies: return String(localized: "本次连接各策略的流量占比")
        case .rules: return String(localized: "本次连接命中最多的规则")
        case .hosts: return String(localized: "本次连接流量最多的主机名")
        case .dns: return String(localized: "本次连接的 DNS 查询与上游占比")
        }
    }

    /// Removed (编辑首页面板 / context menu 「从首页移除」) and collapsed cards, stored as comma-separated raw values.
    /// `hiddenKey` applies to 连接数 only (on Home by default).
    static let hiddenKey = "home.analysis.hidden"
    /// feat/egern-style (user 2026-10-21 20:02 「首页新添加的那些显示做成可添加的面板 选择了才有」): 策略 / 规则 / 主机名
    /// are opt-in panels — off until added in 添加首页卡片, removed from their long-press menu or the editor.
    static let addedKey = "home.analysis.added"
    static let optIn: [HomeAnalysisCard] = [.policies, .rules, .hosts, .dns]
    var isOptIn: Bool { self != .connections }
    static let collapsedKey = "home.analysis.collapsed"

    static func set(_ raw: String) -> Set<HomeAnalysisCard> {
        Set(raw.split(separator: ",").compactMap { HomeAnalysisCard(rawValue: String($0)) })
    }

    static func raw(_ s: Set<HomeAnalysisCard>) -> String {
        allCases.filter { s.contains($0) }.map(\.rawValue).joined(separator: ",")
    }
}

// MARK: - Snapshot model

@MainActor
final class HomeAnalysisModel {
    static let shared = HomeAnalysisModel()

    struct Share: Equatable, Identifiable {
        let name: String
        let bytes: Int64
        var id: String { name }
    }

    struct ConnSnap: Equatable {
        var total = 0
        var active = 0
    }

    struct PolicySnap: Equatable {
        var top: [Share] = []
        var rest: Int64 = 0
        var total: Int64 = 0
    }

    struct RuleSnap: Equatable {
        var top: [ConnectionAnalytics.RuleHit] = []
        var count = 0
    }

    struct HostSnap: Equatable {
        var top: [Share] = []
        var count = 0
    }

    static let policyCount = 5
    static let ruleCount = 8
    static let hostCount = 6
    /// Never faster than this, whatever triggers a refresh.
    static let minInterval: TimeInterval = 2

    @Published private(set) var connections = ConnSnap()
    @Published private(set) var policies = PolicySnap()
    @Published private(set) var rules = RuleSnap()
    @Published private(set) var hosts = HostSnap()

    /// UI tests only (-UITestSeed -UITestDemoAnalytics): a private, synthetic ConnectionAnalytics instead of the
    /// live session. Never on a device run.
    static var demo: Bool { UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoAnalytics") }
    private lazy var demoSource: ConnectionAnalytics = UITestSeed.demoAnalytics()
    var source: ConnectionAnalytics { Self.demo ? demoSource : ConnectionAnalytics.shared }

    private var homeVisible = true
    private var appActive = true
    private var mounted = 0
    private var task: Task<Void, Never>?
    private var lastBuilt = Date.distantPast
    /// r7: ConnectionAnalytics.version of the last rebuild (and its source) — skip sorting when nothing changed.
    private var builtVersion = -1
    private var builtDemo = false

    func setHomeVisible(_ v: Bool) { homeVisible = v; update() }
    func setActive(_ v: Bool) { appActive = v; update() }
    func mount() { mounted += 1; update() }
    func unmount() { mounted = max(0, mounted - 1); update() }

    private var shouldRun: Bool { homeVisible && appActive && mounted > 0 }
    /// feat/home-drilldown: Home on screen and the app active (the DNS card polls only then).
    var homeActive: Bool { homeVisible && appActive }

    private func update() {
        if shouldRun {
            guard task == nil else { return }
            task = Task { [weak self] in
                while !Task.isCancelled {
                    self?.rebuildIfDue()
                    try? await Task.sleep(nanoseconds: UInt64(HomeAnalysisModel.minInterval * 1_000_000_000))
                }
            }
        } else {
            task?.cancel()
            task = nil
        }
    }

    private func rebuildIfDue() {
        let now = Date()
        guard now.timeIntervalSince(lastBuilt) >= Self.minInterval - 0.05 else { return }
        lastBuilt = now
        let a = source
        if a.version == builtVersion && builtDemo == Self.demo { return }
        builtVersion = a.version
        builtDemo = Self.demo

        let c = ConnSnap(total: a.totalConnections, active: a.activeConnections)
        if c != connections { connections = c }

        // 策略: final policy = head of the chain (ConnectionAnalytics.ingest uses chains.last).
        var p = PolicySnap()
        let pol = a.policies.filter { $0.value.total > 0 }
            .sorted { $0.value.total != $1.value.total ? $0.value.total > $1.value.total : $0.key < $1.key }
        p.total = pol.reduce(Int64(0)) { $0 + $1.value.total }
        p.top = pol.prefix(Self.policyCount).map { Share(name: $0.key, bytes: $0.value.total) }
        p.rest = pol.dropFirst(Self.policyCount).reduce(Int64(0)) { $0 + $1.value.total }
        if p != policies { policies = p }

        var r = RuleSnap()
        r.count = a.ruleCount
        r.top = Array(a.rules.values.sorted { $0.hits != $1.hits ? $0.hits > $1.hits : $0.id < $1.id }.prefix(Self.ruleCount))
        if r != rules { rules = r }

        // 主机名 (ConnectionAnalytics keeps at most ~1200)
        var h = HostSnap()
        let hs = a.hosts.filter { $0.value.total > 0 }
        h.count = a.hostCount
        h.top = hs.sorted { $0.value.total != $1.value.total ? $0.value.total > $1.value.total : $0.key < $1.key }
            .prefix(Self.hostCount).map { Share(name: $0.key, bytes: $0.value.total) }
        if h != hosts { hosts = h }
    }
}

// MARK: - Shared bits

/// Egern-style label above a card: title, optional summary, collapse chevron.
/// Without `open` the whole row is the collapse button (as before). With `open` (feat/home-drill-egern, P1: the card
/// and its title row both open the card's overview list) the title / summary part is a NavigationLink to that
/// overview, and collapsing is limited to the chevron's own small button, so the title row never steals a tap meant
/// for the card.
struct HomeSectionLabel: View {
    let title: String
    var summary: String? = nil
    var collapsed: Bool? = nil
    var id: String? = nil
    var toggle: (() -> Void)? = nil
    var open: (() -> AnyView)? = nil

    private var titleRow: some View {
        HStack(spacing: 6) {
            Text(verbatim: title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 6)
            if let summary {
                Text(verbatim: summary).font(.caption2.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    private var chevron: some View {
        Image(systemName: "chevron.down")
            .font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
            .rotationEffect(.degrees((collapsed ?? false) ? -90 : 0))
            .accessibilityHidden(true)
    }

    var body: some View {
        if let open, let toggle, !(collapsed ?? false) {
            HStack(spacing: 6) {
                NavigationLink { LazyDestination { open() } } label: {
                    titleRow.contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier((id ?? "home.analysis.header") + ".open")
                // Hit area a little larger than the glyph, without changing the row's height.
                Button(action: toggle) {
                    chevron
                        .frame(width: 36, height: 30)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.vertical, -8)
                .padding(.trailing, -10)
                .accessibilityLabel(Text(verbatim: title))
                .accessibilityValue(Text(LocalizedStringKey("展开")))
                .accessibilityIdentifier(id ?? "")
            }
            .padding(.horizontal, 6)
            .padding(.top, 4)
            .padding(.bottom, -4)
        } else {
            let row = HStack(spacing: 6) {
                titleRow
                if collapsed != nil { chevron }
            }
            .padding(.horizontal, 6)
            .padding(.top, 4)
            .padding(.bottom, -4)
            .contentShape(Rectangle())
            if let toggle {
                Button(action: toggle) { row }
                    .buttonStyle(.plain)
                    .accessibilityValue(Text(LocalizedStringKey((collapsed ?? false) ? "收起" : "展开")))
                    .accessibilityIdentifier(id ?? "")
            } else {
                row.accessibilityElement(children: .combine).accessibilityIdentifier(id ?? "")
            }
        }
    }
}

private struct AnalysisCardBox<Content: View>: View {
    /// feat/home-drilldown: the card opens a page — chevron in the corner.
    var chevron = false
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .padding(12)
            .padding(.trailing, chevron ? 10 : 0)
            .frame(maxWidth: .infinity, alignment: .leading)
            .overlay(alignment: .topTrailing) { if chevron { CardChevron().padding(12) } }
            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
            .contentShape(Rectangle())
    }
}

/// Context menu shared by every analysis card.
private struct AnalysisMenu: ViewModifier {
    let card: HomeAnalysisCard
    @AppStorage(HomeAnalysisCard.hiddenKey, store: AppShared.defaults) private var hiddenRaw = ""
    @AppStorage(HomeAnalysisCard.addedKey, store: AppShared.defaults) private var addedRaw = ""
    func body(content: Content) -> some View {
        content.contextMenu {
            if card.isOptIn {
                Button(role: .destructive) {
                    var s = HomeAnalysisCard.set(addedRaw)
                    s.remove(card)
                    withAnimation { addedRaw = HomeAnalysisCard.raw(s) }
                } label: { Label("从首页移除", systemImage: "minus.circle") }
            } else {
                // feat/fresh-reinstall: no 「在首页隐藏」 any more — 连接数 is removed (and added back in 编辑首页面板).
                Button(role: .destructive) {
                    var s = HomeAnalysisCard.set(hiddenRaw)
                    s.insert(card)
                    withAnimation { hiddenRaw = HomeAnalysisCard.raw(s) }
                } label: { Label("从首页移除", systemImage: "minus.circle") }
            }
            Button { HomeEditorRouter.shared.open(.panels) } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
        }
    }
}

private func toggleCollapsed(_ c: HomeAnalysisCard, _ raw: Binding<String>) {
    var s = HomeAnalysisCard.set(raw.wrappedValue)
    if s.contains(c) { s.remove(c) } else { s.insert(c) }
    withAnimation(.easeInOut(duration: 0.2)) { raw.wrappedValue = HomeAnalysisCard.raw(s) }
}

// MARK: - Top: 全部连接 / 活跃连接

struct HomeConnectionTiles: View {
    @EnvironmentObject var vpn: VPNManager
    @AppStorage(HomeAnalysisCard.hiddenKey, store: AppShared.defaults) private var hiddenRaw = ""
    @State private var snap = HomeAnalysisModel.shared.connections

    var body: some View {
        let live = vpn.isConnected || HomeAnalysisModel.demo
        if live && !HomeAnalysisCard.set(hiddenRaw).contains(.connections) {
            // feat/home-drilldown (Egern): each tile opens 连接 — all of them, or with 活跃 on.
            HStack(spacing: 10) {
                NavigationLink { LazyDestination { ConnectionsListView(filter: ConnFilter()) } } label: {
                    StatTile(icon: "point.3.connected.trianglepath.dotted", color: Theme.accent, title: "全部连接", value: "\(snap.total)", chevron: true)
                }
                .buttonStyle(PressableCardStyle())
                .accessibilityIdentifier("home.analysis.connections.all")
                NavigationLink { LazyDestination { ConnectionsListView(filter: ConnFilter(activeOnly: true)) } } label: {
                    StatTile(icon: "bolt.horizontal.fill", color: Theme.good, title: "活跃连接", value: "\(snap.active)", chevron: true)
                }
                .buttonStyle(PressableCardStyle())
                .accessibilityIdentifier("home.analysis.connections.active")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("home.analysis.connections")
            .modifier(AnalysisMenu(card: .connections))
            .onReceive(HomeAnalysisModel.shared.$connections.removeDuplicates()) { if $0 != snap { snap = $0 } }
            .onAppear { HomeAnalysisModel.shared.mount() }
            .onDisappear { HomeAnalysisModel.shared.unmount() }
        }
    }
}

// MARK: - Lower: 策略 / 规则 / 主机名

struct HomeAnalysisSection: View {
    @EnvironmentObject var vpn: VPNManager
    @AppStorage(HomeAnalysisCard.addedKey, store: AppShared.defaults) private var addedRaw = ""
    @AppStorage(HomeAnalysisCard.collapsedKey, store: AppShared.defaults) private var collapsedRaw = ""

    var body: some View {
        // Opt-in: only the panels the user added, in the fixed Egern order; nothing (not even the empty state) otherwise.
        let added = HomeAnalysisCard.set(addedRaw)
        let shown = HomeAnalysisCard.optIn.filter { added.contains($0) }
        let collapsed = HomeAnalysisCard.set(collapsedRaw)
        let live = vpn.isConnected || HomeAnalysisModel.demo
        if !shown.isEmpty {
            VStack(spacing: 10) {
                if live {
                    ForEach(shown) { c in
                        Group {
                            switch c {
                            case .policies: HomePolicyShareCard(collapsed: collapsed.contains(c)) { toggleCollapsed(c, $collapsedRaw) }
                            case .rules: HomeRuleHitsCard(collapsed: collapsed.contains(c)) { toggleCollapsed(c, $collapsedRaw) }
                            case .hosts: HomeTopHostsCard(collapsed: collapsed.contains(c)) { toggleCollapsed(c, $collapsedRaw) }
                            case .dns: HomeDNSCard(collapsed: collapsed.contains(c)) { toggleCollapsed(c, $collapsedRaw) }
                            case .connections: EmptyView()
                            }
                        }
                        .modifier(AnalysisMenu(card: c))
                    }
                } else {
                    // r7: the offline empty state stands for the added cards: the same long-press menu as the
                    // online cards (remove from Home / collapse / edit), applied to all of them.
                    let allCollapsed = shown.allSatisfy { collapsed.contains($0) }
                    HomeSectionLabel(title: String(localized: "流量分析"))
                    Card {
                        if allCollapsed {
                            Label("连接后开始统计", systemImage: "chart.bar.xaxis").font(.subheadline).foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } else {
                            EmptyStateRow(icon: "chart.bar.xaxis", title: "连接后开始统计",
                                          message: "开启代理后，这里会显示各策略的流量、规则命中次数和流量最多的主机名。")
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("home.analysis.empty")
                    .contextMenu {
                        Button(role: .destructive) {
                            var s = added
                            for c in shown { s.remove(c) }
                            withAnimation { addedRaw = HomeAnalysisCard.raw(s) }
                        } label: { Label("从首页移除", systemImage: "minus.circle") }
                        Button {
                            var s = collapsed
                            if allCollapsed { for c in shown { s.remove(c) } } else { for c in shown { s.insert(c) } }
                            withAnimation(.easeInOut(duration: 0.2)) { collapsedRaw = HomeAnalysisCard.raw(s) }
                        } label: {
                            Label(LocalizedStringKey(allCollapsed ? "展开" : "收起"), systemImage: allCollapsed ? "chevron.down" : "chevron.up")
                        }
                        Button { HomeEditorRouter.shared.open(.panels) } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
                    }
                }
            }
            .onAppear { HomeAnalysisModel.shared.mount() }
            .onDisappear { HomeAnalysisModel.shared.unmount() }
        }
    }
}

// MARK: 策略

struct HomePolicyShareCard: View {
    let collapsed: Bool
    let toggle: () -> Void
    @State private var snap = HomeAnalysisModel.shared.policies

    var body: some View {
        let total = max(snap.total, 1)
        let parts = Self.parts(snap)
        VStack(spacing: 10) {
            // Egern (user's reference recording, 2026-10-22): plain title, no summary.
            HomeSectionLabel(title: HomeAnalysisCard.policies.title,
                             collapsed: collapsed, id: "home.analysis.header.policies", toggle: toggle,
                             open: { AnyView(PolicyTrafficView()) })
            if !collapsed {
                // Egern (user's screenshot, 2026-10-22): 策略 → 策略 list (name, ↑↓) → that policy's connections → detail.
                NavigationLink { LazyDestination { PolicyTrafficView() } } label: {
                AnalysisCardBox(chevron: true) {
                    if parts.isEmpty {
                        Text("还没有流量").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        GeometryReader { geo in
                            HStack(spacing: 2) {
                                ForEach(Array(parts.enumerated()), id: \.offset) { _, p in
                                    Rectangle().fill(p.2)
                                        .frame(width: max(2, geo.size.width * CGFloat(Double(p.1) / Double(total)) - 2))
                                }
                            }
                            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        }
                        .frame(height: 10)
                        .accessibilityHidden(true)
                        // Egern: the total under the bar's right end, then the legend as wrapping 「● name」 items.
                        HStack {
                            Spacer()
                            Text(verbatim: Fmt.bytes(snap.total)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .padding(.top, -6)
                        FlowLayout(spacing: 10, lineSpacing: 4) {
                            ForEach(Array(parts.enumerated()), id: \.offset) { _, p in
                                HStack(spacing: 4) {
                                    Circle().fill(p.2).frame(width: 7, height: 7).accessibilityHidden(true)
                                    Text(verbatim: p.0).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                }
                                .accessibilityElement(children: .ignore)
                                .accessibilityLabel(Text(verbatim: "\(p.0), \(Fmt.bytes(p.1)), \(Int((Double(p.1) / Double(total) * 100).rounded()))%"))
                            }
                        }
                    }
                }
                }
                .buttonStyle(PressableCardStyle())
                .accessibilityIdentifier("home.analysis.policies")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$policies.removeDuplicates()) { if $0 != snap { snap = $0 } }
    }

    /// Top policies in palette order, then 其他 in the last (neutral) colour.
    static func parts(_ snap: HomeAnalysisModel.PolicySnap) -> [(String, Int64, Color)] {
        let colors = AnalyticsView.palette
        var out: [(String, Int64, Color)] = []
        for (i, p) in snap.top.enumerated() { out.append((RuleDisplay.policyName(p.name), p.bytes, colors[i % (colors.count - 1)])) }
        if snap.rest > 0 { out.append((String(localized: "其他"), snap.rest, colors.last ?? .gray)) }
        return out
    }

    /// fix/rule-labels: a policy's legend colour (raw policy name, as the snapshot keys it) — the 规则 card and 规则命中 put the
    /// same dot next to the policy a rule chose. Policies outside the top ones share 其他's neutral colour.
    static func color(of policy: String, in snap: HomeAnalysisModel.PolicySnap) -> Color {
        let colors = AnalyticsView.palette
        if let i = snap.top.firstIndex(where: { $0.name == policy }) { return colors[i % (colors.count - 1)] }
        return colors.last ?? .gray
    }
}

// MARK: 规则

struct HomeRuleHitsCard: View {
    let collapsed: Bool
    let toggle: () -> Void
    @State private var snap = HomeAnalysisModel.shared.rules
    /// fix/rule-labels: for the policy dot under each ring (same colours as the 策略 card legend).
    @State private var policies = HomeAnalysisModel.shared.policies
    /// r7 P3-4: card widths follow Dynamic Type with the caption2 / 9 pt texts inside (fixed 88 / 72 pt left only 「…」).
    @ScaledMetric(relativeTo: .caption2) private var ringCardWidth: CGFloat = 88
    @ScaledMetric(relativeTo: .caption2) private var moreCardWidth: CGFloat = 72

    var body: some View {
        let maxHits = max(snap.top.first?.hits ?? 1, 1)
        VStack(spacing: 10) {
            HomeSectionLabel(title: HomeAnalysisCard.rules.title,
                             collapsed: collapsed, id: "home.analysis.header.rules", toggle: toggle,
                             open: { AnyView(RuleHitsList()) })
            if !collapsed {
                Group {
                    if snap.top.isEmpty {
                        NavigationLink { LazyDestination { RuleHitsList() } } label: {
                            AnalysisCardBox(chevron: true) { Text("还没有命中记录").font(.footnote).foregroundStyle(.secondary) }
                        }
                        .buttonStyle(PressableCardStyle())
                    } else {
                        // Egern: one small card per rule, scrolling sideways.
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                // Egern (user's reference recording, 2026-10-22): a ring opens 连接 filtered by that
                                // rule (规则▾ chip on); the last tile 「查看全部」 opens the 规则 list (name, policy, hits).
                                ForEach(snap.top) { r in
                                    NavigationLink {
                                        LazyDestination { ConnectionsListView(filter: ConnFilter(rules: [r.rule])) }
                                    } label: { ring(r, maxHits: maxHits) }
                                    .buttonStyle(PressableCardStyle())
                                    .accessibilityIdentifier("home.analysis.rule")
                                }
                                NavigationLink { LazyDestination { RuleHitsList() } } label: {
                                    VStack(spacing: 6) {
                                        Image(systemName: "chevron.right.circle").font(.title3).foregroundStyle(Theme.accent)
                                        Text("查看全部").font(.caption)
                                    }
                                    .frame(width: moreCardWidth)
                                    .frame(maxHeight: .infinity)
                                    .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(PressableCardStyle())
                                .accessibilityIdentifier("home.analysis.rules.all")
                            }
                            .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .accessibilityIdentifier("home.analysis.rules")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$rules.removeDuplicates()) { if $0 != snap { snap = $0 } }
        .onReceive(HomeAnalysisModel.shared.$policies.removeDuplicates()) { if $0 != policies { policies = $0 } }
    }

    /// feat/egern-style: Egern's rule card — ring with the count, then (fix/rule-labels, 「下方的描述与 Egern 看齐」) the
    /// rule / rule-set name and the policy, each one line, as in Egern (RuleDisplay; the app's
    /// own engine rules read 「HTTP 明文（端口 80）」 · 重写 · 重写引擎, never 「((Network,tcp)…」 · AND · __MITM__).
    func ring(_ r: ConnectionAnalytics.RuleHit, maxHits: Int) -> some View {
        let parts = RuleDisplay.describe(r.rule, policy: r.policy)
        let policy = RuleDisplay.policyName(r.policy)
        return VStack(spacing: 4) {
            ZStack {
                Circle().stroke(Theme.ink(0.08), lineWidth: 4)
                Circle().trim(from: 0, to: CGFloat(Double(r.hits) / Double(maxHits)))
                    .stroke(Theme.accent, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text(verbatim: "\(r.hits)").font(.subheadline.weight(.semibold).monospacedDigit())
                    .minimumScaleFactor(0.5).lineLimit(1).padding(.horizontal, 5)
            }
            .frame(width: 48, height: 48)
            .padding(.bottom, 4)
            .accessibilityHidden(true)
            // Egern (user's reference recording, 2026-10-22): two lines only — the rule / rule-set name, then the
            // policy in grey. The rule type stays in the VoiceOver label.
            Text(verbatim: parts.primary).font(.caption2).lineLimit(1).truncationMode(.middle)
            Text(verbatim: policy).scaledFont(9).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .frame(width: ringCardWidth)
        .padding(.vertical, 10).padding(.horizontal, 6)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: [parts.primary, parts.type, policy].filter { !$0.isEmpty }.joined(separator: ", ")))
        .accessibilityValue(Text("\(r.hits) 次"))
    }
}

// MARK: 主机名

struct HomeTopHostsCard: View {
    let collapsed: Bool
    let toggle: () -> Void
    @State private var snap = HomeAnalysisModel.shared.hosts

    var body: some View {
        let maxB = max(snap.top.first?.bytes ?? 1, 1)
        VStack(spacing: 10) {
            HomeSectionLabel(title: HomeAnalysisCard.hosts.title,
                             collapsed: collapsed, id: "home.analysis.header.hosts", toggle: toggle,
                             open: { AnyView(Self.overview()) })
            if !collapsed {
                // feat/home-drilldown (Egern): 主机名 → every host with ↑↓ → that host's connections.
                NavigationLink { LazyDestination { Self.overview() } } label: {
                AnalysisCardBox(chevron: true) {
                    if snap.top.isEmpty {
                        Text("还没有流量").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        VStack(spacing: 8) {
                            // Egern: each host's bar in its own colour; no 「查看全部」 line (the card opens the list).
                            ForEach(Array(snap.top.enumerated()), id: \.element.id) { i, h in
                                HostBarRow(name: h.name, bytes: h.bytes, fraction: Double(h.bytes) / Double(maxB),
                                           color: AnalyticsView.palette[i % max(AnalyticsView.palette.count - 1, 1)])
                                    .accessibilityElement(children: .combine)
                            }
                        }
                    }
                }
                }
                .buttonStyle(PressableCardStyle())
                .accessibilityIdentifier("home.analysis.hosts")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$hosts.removeDuplicates()) { if $0 != snap { snap = $0 } }
    }

    /// The overview this card (and its title) opens: every host with ↑↓; a row opens that host's connections.
    /// Never a single host's connections straight from Home (P1, Egern's hierarchy).
    @MainActor static func overview() -> HostTrafficList {
        HostTrafficList(list: HomeAnalysisModel.shared.source.hostList)
    }
}

// MARK: - 编辑首页面板 section

/// 添加首页卡片 → 流量分析: every card has an add (+) / remove (−) button; 连接数 is on Home by default, 策略 / 规则 /
/// 主机名 / DNS are opt-in.
struct HomeAnalysisEditorSection: View {
    @AppStorage(HomeAnalysisCard.hiddenKey, store: AppShared.defaults) private var hiddenRaw = ""
    @AppStorage(HomeAnalysisCard.addedKey, store: AppShared.defaults) private var addedRaw = ""

    var body: some View {
        Section {
            ForEach(HomeAnalysisCard.allCases) { c in
                HStack(spacing: 10) {
                    Image(systemName: c.icon).foregroundStyle(Theme.accent).frame(width: 24)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: c.title).font(.subheadline).lineLimit(1)
                        Text(verbatim: c.caption).font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 6)
                    // feat/fresh-reinstall: one add (+) / remove (−) button for every card. 连接数 is on Home unless
                    // removed (home.analysis.hidden); the others are opt-in (home.analysis.added).
                    let on = c.isOptIn ? HomeAnalysisCard.set(addedRaw).contains(c) : !HomeAnalysisCard.set(hiddenRaw).contains(c)
                    Button {
                        if c.isOptIn {
                            var s = HomeAnalysisCard.set(addedRaw)
                            if on { s.remove(c) } else { s.insert(c) }
                            addedRaw = HomeAnalysisCard.raw(s)
                        } else {
                            var s = HomeAnalysisCard.set(hiddenRaw)
                            if on { s.insert(c) } else { s.remove(c) }
                            hiddenRaw = HomeAnalysisCard.raw(s)
                        }
                    } label: {
                        Image(systemName: on ? "minus.circle.fill" : "plus.circle.fill")
                            .font(.title3)
                            .foregroundStyle(on ? Theme.bad : Theme.good)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(Text(on ? "从首页移除" : "添加"))
                    .accessibilityIdentifier("homepanels.analysis.\(c.rawValue)")
                }
            }
        } header: {
            Text("流量分析")
        } footer: {
            Text("策略、规则、主机名和 DNS 卡片默认不显示，添加后才出现在首页，长按卡片可移除。轻点卡片查看详情。数据与「连接分析」相同：本次连接期间由隧道持续记录（App 在后台或被关闭时也记录），断开后清零。")
        }
    }
}

// MARK: - Quick add (Egern-style floating +)

/// Floating round + at the bottom right of Home. Every item opens a flow that already exists elsewhere:
/// 添加订阅 = 配置 → 添加订阅链接 (AddRemoteSheet), 扫描添加节点 = QRScannerSheet → 添加节点 (AddNodeView with the
/// scanned text), 添加节点 = AddNodeView, 添加规则 = 分流规则 → 自定义 (CustomRuleEditor), 导入配置 = the file picker
/// of 配置 → 从文件导入 (ImportRouter.pickFile).
struct HomeQuickAddButton: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    /// fix/app-policy-ui #5b: the + sits in Home's bar now (a plain bar glyph like the other tabs' +), not floating.
    var inBar = false

    enum Sheet: String, Identifiable {
        case subscription, scan, node, rule
        var id: String { rawValue }
    }
    @State private var sheet: Sheet?
    @State private var scanned: String?
    @State private var nodeText = ""
    @State private var message: String?
    @State private var pendingMessage: String?

    var body: some View {
        Menu {
            Button { sheet = .subscription } label: { Label("添加订阅", systemImage: "link.badge.plus") }
                .accessibilityIdentifier("home.quickAdd.subscription")
            Button { sheet = .scan } label: { Label("扫描添加节点", systemImage: "qrcode.viewfinder") }
                .accessibilityIdentifier("home.quickAdd.scan")
            Button { nodeText = ""; sheet = .node } label: { Label("添加节点", systemImage: "server.rack") }
                .accessibilityIdentifier("home.quickAdd.node")
            Button { sheet = .rule } label: { Label("添加规则", systemImage: "list.bullet.rectangle") }
                .accessibilityIdentifier("home.quickAdd.rule")
            Button { ImportRouter.shared.pickFile() } label: { Label("导入配置", systemImage: "square.and.arrow.down") }
                .accessibilityIdentifier("home.quickAdd.import")
        } label: {
            if inBar {
                Image(systemName: "plus")
            } else {
                Image(systemName: "plus")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Theme.onAccent)
                    .frame(width: 50, height: 50)
                    .background(Circle().fill(Theme.accent))
                    .shadow(color: .black.opacity(0.12), radius: 5, y: 2)
                    .contentShape(Circle())
            }
        }
        .menuOrder(.fixed) // 添加订阅 stays on top even though the menu opens upwards (Egern order)
        .accessibilityLabel(Text("快速添加"))
        .accessibilityIdentifier("home.quickAdd")
        .sheet(item: $sheet, onDismiss: afterSheet) { s in
            switch s {
            case .subscription:
                AddRemoteSheet { msg in pendingMessage = msg }
                    .environmentObject(store)
            case .scan:
                QRScannerSheet { code in
                    scanned = code
                    sheet = nil
                }
            case .node:
                NavigationStack {
                    AddNodeView(initialText: nodeText)
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("完成") { sheet = nil } } }
                }
                .environmentObject(store)
                .environmentObject(vpn)
            case .rule:
                CustomRuleEditor(rule: CustomRule(line: "")) { r in
                    let custom = CustomRulesStore.shared
                    custom.rules.insert(r, at: 0)
                    // r7 P3-1: a failed reload is shown here, once the editor has closed.
                    Task {
                        guard let e = await custom.saveAndReload() else { return }
                        if sheet == nil { message = e } else { pendingMessage = e }
                    }
                }
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    /// After the scanner closes with a code, the same 添加节点 page opens with it (format and count shown before adding).
    func afterSheet() {
        if let m = pendingMessage { pendingMessage = nil; message = m }
        if let code = scanned {
            scanned = nil
            guard !code.isEmpty else { return }
            nodeText = code
            // r7: this runs in the scanner sheet's onDismiss — the sheet is gone, so the next one is presented right
            // here (the 0.35 s timer could overlap another sheet opened meanwhile, or fire after the user left).
            if sheet == nil { sheet = .node }
        }
    }
}

/// Wrapping row (Egern's 策略 legend): items left to right, onto the next line when the width runs out.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8
    var lineSpacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0, maxX: CGFloat = 0
        for v in subviews {
            let sz = v.sizeThatFits(.unspecified)
            if x > 0 && x + sz.width > width { y += line + lineSpacing; x = 0; line = 0 }
            x += sz.width + spacing
            maxX = max(maxX, x - spacing)
            line = max(line, sz.height)
        }
        return CGSize(width: proposal.width ?? maxX, height: y + line)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for v in subviews {
            let sz = v.sizeThatFits(.unspecified)
            if x > bounds.minX && x + sz.width > bounds.maxX { y += line + lineSpacing; x = bounds.minX; line = 0 }
            v.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(width: min(sz.width, bounds.width), height: sz.height))
            x += sz.width + spacing
            line = max(line, sz.height)
        }
    }
}
