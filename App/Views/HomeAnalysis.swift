import SwiftUI

// feat/home-analysis (Egern 分析 tab, on 首页). Order on Home follows Egern's 分析:
//   全部连接 / 活跃连接 tiles → 网络 (the existing speed card + totals) → 策略 → 规则 → 主机名 → 面板.
//   策略: bytes per final policy (head of each connection's chain), stacked bar + legend
//   规则: hit counts of the busiest rules as rings, horizontal scroll
//   主机名: hostnames by bytes with mini bars
// Data: the same session data as 连接分析 (ConnectionAnalytics, fed by the /connections poll DashboardModel
// already runs). Nothing new is polled from the core and nothing is invented: VPN off → one empty state.
// Performance (fix/nav-jank rule, PR #75): nothing above these cards observes a store that publishes often.
// HomeAnalysisModel is not an ObservableObject; it copies a small, capped snapshot out of ConnectionAnalytics at
// most every 2 s, only while Home is on screen, the app is active and an analysis view is mounted, and publishes
// a field only when it changed. Each card mirrors just its own field (onReceive + @State), so a new sample
// re-renders that card only, never HomeView or the tab.

enum HomeAnalysisCard: String, CaseIterable, Identifiable {
    case connections, policies, rules, hosts
    var id: String { rawValue }

    var title: String {
        switch self {
        case .connections: return String(localized: "连接数")
        case .policies: return String(localized: "策略")
        case .rules: return String(localized: "规则")
        case .hosts: return String(localized: "主机名")
        }
    }

    var icon: String {
        switch self {
        case .connections: return "point.3.connected.trianglepath.dotted"
        case .policies: return "chart.bar.xaxis"
        case .rules: return "target"
        case .hosts: return "network"
        }
    }

    var caption: String {
        switch self {
        case .connections: return String(localized: "本次连接的全部连接与活跃连接数")
        case .policies: return String(localized: "本次连接各策略的流量占比")
        case .rules: return String(localized: "本次连接命中最多的规则")
        case .hosts: return String(localized: "本次连接流量最多的主机名")
        }
    }

    /// Hidden (编辑首页面板 / context menu) and collapsed cards, stored as comma-separated raw values.
    static let hiddenKey = "home.analysis.hidden"
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

    func setHomeVisible(_ v: Bool) { homeVisible = v; update() }
    func setActive(_ v: Bool) { appActive = v; update() }
    func mount() { mounted += 1; update() }
    func unmount() { mounted = max(0, mounted - 1); update() }

    private var shouldRun: Bool { homeVisible && appActive && mounted > 0 }

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
        r.count = a.rules.count
        r.top = Array(a.rules.values.sorted { $0.hits != $1.hits ? $0.hits > $1.hits : $0.id < $1.id }.prefix(Self.ruleCount))
        if r != rules { rules = r }

        // 主机名 (ConnectionAnalytics keeps at most ~1200)
        var h = HostSnap()
        let hs = a.hosts.filter { $0.value.total > 0 }
        h.count = hs.count
        h.top = hs.sorted { $0.value.total != $1.value.total ? $0.value.total > $1.value.total : $0.key < $1.key }
            .prefix(Self.hostCount).map { Share(name: $0.key, bytes: $0.value.total) }
        if h != hosts { hosts = h }
    }
}

// MARK: - Shared bits

/// Visibility read by both Home blocks (tiles at the top, 策略 / 规则 / 主机名 lower down).
struct HomeAnalysisVisibility {
    let hidden: Set<HomeAnalysisCard>
    let collapsed: Set<HomeAnalysisCard>
    var live: Bool
    func shows(_ c: HomeAnalysisCard) -> Bool { !hidden.contains(c) }
}

/// Egern-style label above a card: title, optional summary, collapse chevron (the whole row is the button).
struct HomeSectionLabel: View {
    let title: String
    var summary: String? = nil
    var collapsed: Bool? = nil
    var id: String? = nil
    var toggle: (() -> Void)? = nil

    var body: some View {
        let row = HStack(spacing: 6) {
            Text(verbatim: title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 6)
            if let summary {
                Text(verbatim: summary).font(.caption2.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
            }
            if let collapsed {
                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
                    .rotationEffect(.degrees(collapsed ? -90 : 0))
                    .accessibilityHidden(true)
            }
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

private struct AnalysisCardBox<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
    }
}

/// Context menu shared by every analysis card.
private struct AnalysisMenu: ViewModifier {
    let card: HomeAnalysisCard
    @Binding var editing: Bool
    @AppStorage(HomeAnalysisCard.hiddenKey) private var hiddenRaw = ""
    func body(content: Content) -> some View {
        content.contextMenu {
            Button {
                var s = HomeAnalysisCard.set(hiddenRaw)
                s.insert(card)
                hiddenRaw = HomeAnalysisCard.raw(s)
            } label: { Label("在首页隐藏", systemImage: "eye.slash") }
            Button { editing = true } label: { Label("编辑首页面板", systemImage: "slider.horizontal.3") }
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
    @AppStorage(HomeAnalysisCard.hiddenKey) private var hiddenRaw = ""
    @State private var snap = HomeAnalysisModel.shared.connections
    @State private var editing = false

    var body: some View {
        let live = vpn.isConnected || HomeAnalysisModel.demo
        if live && !HomeAnalysisCard.set(hiddenRaw).contains(.connections) {
            NavigationLink { LazyDestination { AnalyticsView() } } label: {
                HStack(spacing: 10) {
                    StatTile(icon: "point.3.connected.trianglepath.dotted", color: Theme.accent, title: "全部连接", value: "\(snap.total)")
                    StatTile(icon: "bolt.horizontal.fill", color: Theme.good, title: "活跃连接", value: "\(snap.active)")
                }
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("home.analysis.connections")
            .modifier(AnalysisMenu(card: .connections, editing: $editing))
            .onReceive(HomeAnalysisModel.shared.$connections.removeDuplicates()) { if $0 != snap { snap = $0 } }
            .onAppear { HomeAnalysisModel.shared.mount() }
            .onDisappear { HomeAnalysisModel.shared.unmount() }
            .sheet(isPresented: $editing) { HomePanelsEditor().environmentObject(vpn) }
        }
    }
}

// MARK: - Lower: 策略 / 规则 / 主机名

struct HomeAnalysisSection: View {
    @EnvironmentObject var vpn: VPNManager
    @AppStorage(HomeAnalysisCard.hiddenKey) private var hiddenRaw = ""
    @AppStorage(HomeAnalysisCard.collapsedKey) private var collapsedRaw = ""
    @State private var editing = false

    var body: some View {
        let hidden = HomeAnalysisCard.set(hiddenRaw)
        let shown = [HomeAnalysisCard.policies, .rules, .hosts].filter { !hidden.contains($0) }
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
                            case .connections: EmptyView()
                            }
                        }
                        .modifier(AnalysisMenu(card: c, editing: $editing))
                    }
                } else {
                    HomeSectionLabel(title: String(localized: "流量分析"))
                    Card {
                        EmptyStateRow(icon: "chart.bar.xaxis", title: "连接后开始统计",
                                      message: "开启代理后，这里会显示各策略的流量、规则命中次数和流量最多的主机名。")
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("home.analysis.empty")
                }
            }
            .onAppear { HomeAnalysisModel.shared.mount() }
            .onDisappear { HomeAnalysisModel.shared.unmount() }
            .sheet(isPresented: $editing) { HomePanelsEditor().environmentObject(vpn) }
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
            HomeSectionLabel(title: HomeAnalysisCard.policies.title, summary: snap.total > 0 ? Fmt.bytes(snap.total) : nil,
                             collapsed: collapsed, id: "home.analysis.header.policies", toggle: toggle)
            if !collapsed {
                AnalysisCardBox {
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
                        VStack(spacing: 6) {
                            ForEach(Array(parts.enumerated()), id: \.offset) { _, p in
                                HStack(spacing: 8) {
                                    Circle().fill(p.2).frame(width: 7, height: 7).accessibilityHidden(true)
                                    Text(verbatim: p.0).font(.footnote).lineLimit(1)
                                    Spacer()
                                    Text(verbatim: Fmt.bytes(p.1)).font(.caption.monospacedDigit())
                                    Text(Double(p.1) / Double(total), format: .percent.precision(.fractionLength(0)))
                                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                                        .frame(width: 40, alignment: .trailing)
                                }
                                .accessibilityElement(children: .combine)
                            }
                        }
                    }
                }
                .accessibilityIdentifier("home.analysis.policies")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$policies.removeDuplicates()) { if $0 != snap { snap = $0 } }
    }

    /// Top policies in palette order, then 其他 in the last (neutral) colour.
    static func parts(_ snap: HomeAnalysisModel.PolicySnap) -> [(String, Int64, Color)] {
        let colors = AnalyticsView.palette
        var out: [(String, Int64, Color)] = []
        for (i, p) in snap.top.enumerated() { out.append((p.name, p.bytes, colors[i % (colors.count - 1)])) }
        if snap.rest > 0 { out.append((String(localized: "其他"), snap.rest, colors.last ?? .gray)) }
        return out
    }
}

// MARK: 规则

struct HomeRuleHitsCard: View {
    let collapsed: Bool
    let toggle: () -> Void
    @State private var snap = HomeAnalysisModel.shared.rules

    var body: some View {
        let maxHits = max(snap.top.first?.hits ?? 1, 1)
        VStack(spacing: 10) {
            HomeSectionLabel(title: HomeAnalysisCard.rules.title, summary: snap.count > 0 ? String(localized: "\(snap.count) 条规则") : nil,
                             collapsed: collapsed, id: "home.analysis.header.rules", toggle: toggle)
            if !collapsed {
                Group {
                    if snap.top.isEmpty {
                        AnalysisCardBox { Text("还没有命中记录").font(.footnote).foregroundStyle(.secondary) }
                    } else {
                        // Egern: one small card per rule, scrolling sideways.
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(snap.top) { r in ring(r, maxHits: maxHits) }
                                if snap.count > snap.top.count {
                                    NavigationLink { LazyDestination { RuleHitsList() } } label: {
                                        VStack(spacing: 6) {
                                            Image(systemName: "chevron.right.circle").font(.title3).foregroundStyle(Theme.accent)
                                            Text("查看全部").font(.caption)
                                        }
                                        .frame(width: 72)
                                        .frame(maxHeight: .infinity)
                                        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .accessibilityIdentifier("home.analysis.rules")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$rules.removeDuplicates()) { if $0 != snap { snap = $0 } }
    }

    /// 「DomainKeyword(example)」 → (DOMAIN-KEYWORD, example); a rule without a payload keeps its name.
    static func split(_ rule: String) -> (type: String, payload: String?) {
        guard rule.hasSuffix(")"), let open = rule.firstIndex(of: "("), open > rule.startIndex else { return (rule, nil) }
        let type = String(rule[..<open])
        let payload = String(rule[rule.index(after: open)..<rule.index(before: rule.endIndex)])
        return (Theme.ruleTypeName(type), payload.isEmpty ? nil : payload)
    }

    /// feat/egern-style: Egern's rule card — ring with the count, the payload, the rule type and policy in small grey.
    /// The type and the payload are separate one-line texts (「DomainKeyword(example)」 clipped and wrapped before).
    func ring(_ r: ConnectionAnalytics.RuleHit, maxHits: Int) -> some View {
        let parts = Self.split(r.rule)
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
            Text(verbatim: parts.payload ?? parts.type).font(.caption2).lineLimit(1).truncationMode(.middle)
            if parts.payload != nil {
                Text(verbatim: parts.type).font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
                    .lineLimit(1).minimumScaleFactor(0.7)
            }
            Text(verbatim: r.policy).font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1)
        }
        .frame(width: 88)
        .padding(.vertical, 10).padding(.horizontal, 6)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "\(r.rule), \(r.policy)"))
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
            HomeSectionLabel(title: HomeAnalysisCard.hosts.title, summary: snap.count > 0 ? String(localized: "\(snap.count) 个主机名") : nil,
                             collapsed: collapsed, id: "home.analysis.header.hosts", toggle: toggle)
            if !collapsed {
                AnalysisCardBox {
                    if snap.top.isEmpty {
                        Text("还没有流量").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(snap.top) { h in
                                HostBarRow(name: h.name, bytes: h.bytes, fraction: Double(h.bytes) / Double(maxB))
                                    .accessibilityElement(children: .combine)
                            }
                        }
                        if snap.count > snap.top.count {
                            NavigationLink {
                                LazyDestination { HostTrafficList(list: HomeAnalysisModel.shared.source.hostList) }
                            } label: {
                                Text("查看全部").font(.caption)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
                .accessibilityIdentifier("home.analysis.hosts")
            }
        }
        .onReceive(HomeAnalysisModel.shared.$hosts.removeDuplicates()) { if $0 != snap { snap = $0 } }
    }
}

// MARK: - 编辑首页面板 section

/// Show / hide toggles for the analysis cards, inside the existing 编辑首页面板 sheet.
struct HomeAnalysisEditorSection: View {
    @AppStorage(HomeAnalysisCard.hiddenKey) private var hiddenRaw = ""

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
                    Toggle("在首页显示", isOn: Binding(
                        get: { !HomeAnalysisCard.set(hiddenRaw).contains(c) },
                        set: { on in
                            var s = HomeAnalysisCard.set(hiddenRaw)
                            if on { s.remove(c) } else { s.insert(c) }
                            hiddenRaw = HomeAnalysisCard.raw(s)
                        }))
                        .labelsHidden()
                        .accessibilityIdentifier("homepanels.analysis.\(c.rawValue)")
                }
            }
        } header: {
            Text("流量分析")
        } footer: {
            Text("数据与「连接分析」相同：本次连接期间、App 打开时采样，断开后清零。轻点标题可收起。")
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
            Image(systemName: "plus")
                .font(.title2.weight(.semibold))
                .foregroundStyle(Theme.onAccent)
                .frame(width: 50, height: 50)
                .background(Circle().fill(Theme.accent))
                .shadow(color: .black.opacity(0.12), radius: 5, y: 2)
                .contentShape(Circle())
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
                    custom.save()
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
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { sheet = .node }
        }
    }
}
