import SwiftUI

// QX rebuild (branch qx/rebuild): shared types for the Quantumult X style single-screen layout.
// The internal model is unchanged (mihomo YAML + override stores); this is presentation only.

/// The five panel tiles (QX: 节点 / 网络活动 / 分流规则 / 重写规则 / 日志).
enum QXPanel: String, CaseIterable, Identifiable {
    case nodes, activity, rules, rewrite, logs
    var id: String { rawValue }

    var title: String {
        switch self {
        case .nodes: return String(localized: "节点")
        case .activity: return String(localized: "网络活动")
        case .rules: return String(localized: "分流规则")
        case .rewrite: return String(localized: "重写规则")
        case .logs: return String(localized: "日志")
        }
    }

    var icon: String {
        switch self {
        case .nodes: return "server.rack"
        case .activity: return "list.clipboard.fill"
        case .rules: return "line.3.horizontal.decrease"
        case .rewrite: return "pencil"
        case .logs: return "text.alignleft"
        }
    }

    var color: Color {
        switch self {
        case .nodes: return QXColor.nodes
        case .activity: return QXColor.activity
        case .rules: return QXColor.rules
        case .rewrite: return QXColor.rewrite
        case .logs: return QXColor.logs
        }
    }

    /// Long-press on the tile opens the panel's resource page.
    var resourceRoute: QXRoute {
        switch self {
        case .nodes: return .dest(.nodeResources)
        case .activity: return .dest(.trafficStats)
        case .rules: return .dest(.filterResources)
        case .rewrite: return .dest(.rewriteResources)
        case .logs: return .dest(.logs)
        }
    }

    static let orderKey = "qx.panelOrder"
    static let defaultOrder = QXPanel.allCases.map(\.rawValue).joined(separator: ",")

    /// Saved order (面板 & 工具栏 → 排序); unknown entries dropped, missing ones appended.
    static func order(_ raw: String) -> [QXPanel] {
        var out: [QXPanel] = []
        for p in raw.split(separator: ",").compactMap({ QXPanel(rawValue: String($0)) }) where !out.contains(p) { out.append(p) }
        for p in QXPanel.allCases where !out.contains(p) { out.append(p) }
        return out
    }
}

/// QX-4 visual pass: metrics measured on the recording (600 px frame = 393 pt, 1 pt ≈ 1.53 px).
enum QXMetrics {
    /// Side inset of every QX list, page and the tile strip (frames 01/25/28: 28 px ≈ 18 pt).
    static let inset: CGFloat = 18
    /// Content cards (resource / policy / rule-set cards): 62 pt rows, ~22 pt continuous corners.
    static let cardRadius: CGFloat = 22
    /// Home tiles (frame 01: 163×100 px ≈ 107×66 pt, gap ≈ 9 pt, radius ≈ 20 pt).
    static let tileSize = CGSize(width: 107, height: 66)
    static let tileRadius: CGFloat = 20
    static let tileGap: CGFloat = 9
    /// Floating toolbar (frame 01: 60 pt high, 14 pt side insets, windmill circle 52 pt inside the capsule,
    /// bottom edge 19 pt above the screen edge).
    static let toolbarHeight: CGFloat = 60
    static let toolbarInset: CGFloat = 14
    static let toolbarBottom: CGFloat = 19
    static let windmillCircle: CGFloat = 52
    /// Page chrome circles and capsules (frame 28: 65 px ≈ 43 pt).
    static let circle: CGFloat = 43
    /// In-content large titles (frame 28: ≈ 24 pt bold) and section headers on Home (≈ 20 pt bold).
    static let largeTitle: CGFloat = 24
    static let sectionTitle: CGFloat = 20
    static let caption: CGFloat = 15
    /// Hairline that QX draws around white chrome (circles, capsules, the toolbar).
    static let hairline = QXPalette.hairline
}


/// Pages reachable from the settings page, tiles, toolbar and 其他设置. Existing views, re-homed.
enum QXDest: String, Hashable, CaseIterable {
    case addNode, manualNodes, nodeResources, providers
    case customRules, filterResources
    case localRewrite, rewriteResources, scripts
    case mitm, httpCapture, tasks
    case tools, unlock, analytics, stats, trafficStats, dnsLog, blocked, logs, backup
    case connection, dns, speedTest, coreSettings, geo, appIcon, diagnostics, about, notices, scriptLogs, panels, sessions, subscriptions
    case mitmAdvanced, allResources, prefsStore, snippets, reset
    case netTest, snapshots, storage, syncFolder
    case taskGallery, geoChecker
    case httpBackend
    case widgets

    @MainActor @ViewBuilder var view: some View {
        switch self {
        case .addNode: QXAddNodeView()
        case .manualNodes: ManualNodesView()
        case .nodeResources: QXNodeResourcesView()
        case .providers: ProvidersView()
        case .customRules: RulesView()
        case .filterResources: QXFilterResourcesView()
        case .localRewrite: QXRewriteRulesView()
        case .rewriteResources: QXRewriteResourcesView()
        case .scripts: QXScriptsPage()
        case .mitm: QXMitMView()
        case .httpCapture: QXHTTPCaptureView()
        case .tasks: QXTaskListView()
        case .tools: ToolsView()
        case .unlock: UnlockView()
        case .analytics: AnalyticsView()
        case .stats: StatsView()
        case .trafficStats: QXTrafficStatsView()
        case .dnsLog: QXDNSLogView()
        case .blocked: QXBlockedView()
        case .logs: LogsView()
        case .backup: QXWrappedPage(title: String(localized: "备份与恢复")) { BackupView() }
        case .connection: ConnectionView()
        case .dns: QXDNSPage()
        case .speedTest: SpeedTestSettingsView()
        case .coreSettings: SettingsView()
        case .geo: GeoView()
        case .appIcon: AppIconView()
        case .diagnostics: DiagnosticsView()
        case .about: AboutView()
        case .notices: ScriptNoticesView()
        case .scriptLogs: ScriptLogsView()
        case .panels: PanelsView()
        case .sessions: QXSessionListView()
        case .subscriptions: SubscriptionsView()
        case .mitmAdvanced: QXMitMAdvancedView()
        case .allResources: QXAllResourcesView()
        case .prefsStore: QXWrappedPage(title: String(localized: "持久化存储")) { StoreView() }
        case .snippets: QXSnippetsView()
        case .reset: QXResetView()
        case .netTest: QXWrappedPage(title: String(localized: "网络测试")) { NetTestView() }
        case .snapshots: QXWrappedPage(title: String(localized: "配置快照")) { SnapshotsView() }
        case .storage: QXWrappedPage(title: String(localized: "存储空间")) { StorageView() }
        case .syncFolder: QXWrappedPage(title: String(localized: "同步文件夹")) { SyncFolderView() }
        case .taskGallery: QXTaskGalleryView()
        case .geoChecker: QXGeoCheckerView()
        case .httpBackend: QXHTTPBackendView()
        case .widgets: QXWidgetsPage()
        }
    }
}

enum QXRoute: Hashable {
    case settings, otherSettings, panelSettings
    case group(String)
    case connection(String)
    case dest(QXDest)
}

/// Sheets the shell presents (pages that own a NavigationStack, and editors).
enum QXSheet: String, Identifiable {
    case profiles, editProfile, addRemote, runMode, classicHome, classicPolicy, classicRequests, onboarding, sample
    var id: String { rawValue }
}

@MainActor
final class QXNavigator: ObservableObject {
    static let shared = QXNavigator()
    @Published var path: [QXRoute] = []
    @Published var sheet: QXSheet?
    /// 网络活动: the toolbar's first button becomes search.
    @Published var activitySearch = false
    @Published var activityQuery = ""
    /// iPad: pushes land in the right-hand pane whose root is 设置.
    @Published var padLayout = false

    func push(_ r: QXRoute) { path.append(r) }
    func present(_ s: QXSheet) { sheet = s }
}

/// QX windmill: three blades; colour = run mode (rule: tri-colour, global: teal, direct: yellow).
struct QXWindmill: View {
    let mode: String
    var size: CGFloat = 30

    private var colors: [Color] {
        switch mode {
        case "global": return [QXColor.teal, QXColor.teal, QXColor.teal]
        case "direct": return [QXColor.yellow, QXColor.yellow, QXColor.yellow]
        default: return [QXColor.red, QXColor.yellow, QXColor.teal]
        }
    }

    var body: some View {
        ZStack {
            ForEach(0..<3, id: \.self) { i in
                QXBlade(angle: Double(i) * 120).fill(colors[i])
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

struct QXBlade: Shape {
    let angle: Double
    func path(in rect: CGRect) -> Path {
        let c = CGPoint(x: rect.midX, y: rect.midY)
        let r = min(rect.width, rect.height) / 2
        func pt(_ deg: Double, _ d: CGFloat) -> CGPoint {
            let a = (deg - 90) * .pi / 180
            return CGPoint(x: c.x + CGFloat(cos(a)) * d, y: c.y + CGFloat(sin(a)) * d)
        }
        var p = Path()
        p.move(to: pt(angle + 200, r * 0.12))
        p.addLine(to: pt(angle, r))
        p.addLine(to: pt(angle + 62, r * 0.48))
        p.closeSubpath()
        return p
    }
}

/// Funnel glyph for 分流 (SF Symbols has no plain funnel on iOS 16).
struct QXFunnel: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        let w = rect.width, h = rect.height
        p.move(to: CGPoint(x: rect.minX, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.minX + w * 0.62, y: rect.minY + h * 0.48))
        p.addLine(to: CGPoint(x: rect.minX + w * 0.62, y: rect.maxY))
        p.addLine(to: CGPoint(x: rect.minX + w * 0.38, y: rect.maxY - h * 0.14))
        p.addLine(to: CGPoint(x: rect.minX + w * 0.38, y: rect.minY + h * 0.48))
        p.closeSubpath()
        return p
    }
}

/// Panel glyph: the funnel is drawn, the rest are SF Symbols.
struct QXPanelGlyph: View {
    let panel: QXPanel
    var size: CGFloat = 22
    var color: Color = .white
    var body: some View {
        if panel == .rules {
            QXFunnel().fill(color).frame(width: size * 0.9, height: size * 0.9)
        } else {
            Image(systemName: panel.icon).font(.system(size: size, weight: .semibold)).foregroundStyle(color)
        }
    }
}

/// Rounded white (dark: card) row container used by every panel list.
struct QXCard<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: QXMetrics.cardRadius, style: .continuous).fill(QXPalette.card))
    }
}

/// Small coloured chip (rule type, policy, protocol).
struct QXChip: View {
    let text: String
    var color: Color
    var filled = true
    var body: some View {
        Text(verbatim: text)
            .scaledFont(10, weight: .bold)
            .lineLimit(1)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 5, style: .continuous).fill(filled ? color : color.opacity(0.14)))
            .foregroundStyle(filled ? Color.white : color)
    }
}

/// Section header like QX ("PROXY ▾", "自定义策略 ▾") with a trailing accessory.
struct QXSectionHeader<Trailing: View>: View {
    let title: String
    @Binding var expanded: Bool
    @ViewBuilder var trailing: Trailing
    var body: some View {
        HStack(spacing: 8) {
            Button {
                QXHaptics.select()
                withAnimation(.spring(response: 0.3)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Text(verbatim: title).font(.system(size: QXMetrics.sectionTitle, weight: .bold)).foregroundStyle(.primary)
                    Image(systemName: expanded ? "arrowtriangle.down.fill" : "arrowtriangle.right.fill")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(.primary)
                }
            }
            .buttonStyle(.plain)
            Spacer()
            trailing
        }
        .padding(.horizontal, 4)
        .padding(.top, 14)
    }
}

enum QXFmt {
    /// "999+" cap like QX.
    static func count(_ n: Int) -> String { n > 999 ? "999+" : "\(n)" }

    static let day: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MM/dd HH:mm:ss"
        return f
    }()

    /// Rule type as QX names it (HOST, HOST-SUFFIX …) from mihomo's live ("DomainSuffix") or YAML ("DOMAIN-SUFFIX") names.
    static func ruleType(_ t: String) -> String {
        let k = t.uppercased().filter { $0.isLetter || $0.isNumber }
        switch k {
        case "DOMAIN": return "HOST"
        case "DOMAINSUFFIX": return "HOST-SUFFIX"
        case "DOMAINKEYWORD": return "HOST-KEYWORD"
        case "DOMAINWILDCARD": return "HOST-WILDCARD"
        case "DOMAINREGEX": return "HOST-REGEX"
        case "IPCIDR": return "IP-CIDR"
        case "IPCIDR6": return "IP6-CIDR"
        case "IPASN": return "IP-ASN"
        case "SRCIPCIDR": return "SRC-IP"
        case "GEOIP": return "GEOIP"
        case "GEOSITE": return "GEOSITE"
        case "RULESET": return "RULE-SET"
        case "MATCH", "FINAL": return "FINAL"
        case "DSTPORT": return "DST-PORT"
        case "SRCPORT": return "SRC-PORT"
        case "PROCESSNAME": return "PROCESS"
        case "SUBRULES", "SUBRULE": return "SUB-RULE"
        default: return t.uppercased()
        }
    }

    static func isRuleSet(_ t: String) -> Bool { ruleType(t) == "RULE-SET" }
    static func isFinal(_ t: String) -> Bool { ruleType(t) == "FINAL" }

    /// "🇯🇵 东京 01": a leading flag emoji stays; nothing is added.
    static func protocolName(_ type: String) -> String {
        switch type.lowercased() {
        case "ss", "shadowsocks": return "SHADOWSOCKS"
        case "ssr", "shadowsocksr": return "SHADOWSOCKSR"
        case "hysteria2": return "HYSTERIA2"
        case "wireguard": return "WIREGUARD"
        default: return type.uppercased()
        }
    }
}

// MARK: - Page chrome (QX: no navigation bar; floating circle buttons, in-content large titles)

/// 44 pt glass circle with a symbol (back, close, actions).
struct QXCircleButton: View {
    let systemName: String
    var tint: Color = .primary
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(tint)
                .frame(width: QXMetrics.circle, height: QXMetrics.circle)
                .background(Circle().fill(QXPalette.chrome))
                .overlay(Circle().stroke(QXMetrics.hairline, lineWidth: 1))
                .shadow(color: QXPalette.shadow(0.05), radius: 6, y: 2)
                .contentShape(Circle())
        }
        .buttonStyle(QXPressStyle(scale: 0.9))
    }
}

/// Several actions grouped in one capsule (QX: `[layers | drive | alarm | +]`).
struct QXCapsuleBar<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        HStack(spacing: 4) { content }
            .padding(.horizontal, 8)
            .frame(height: QXMetrics.circle)
            .background(Capsule().fill(QXPalette.chrome))
            .overlay(Capsule().stroke(QXMetrics.hairline, lineWidth: 1))
            .shadow(color: QXPalette.shadow(0.05), radius: 6, y: 2)
    }
}

struct QXBarIcon: View {
    let systemName: String
    var tint: Color = .primary
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Image(systemName: systemName).font(.system(size: 18, weight: .medium)).foregroundStyle(tint).frame(width: 40, height: 40)
                .contentShape(Rectangle())
        }
        .buttonStyle(QXPressStyle(scale: 0.86))
    }
}

/// A pushed page in QX chrome: hidden nav bar, back circle top-left, optional centred inline title,
/// trailing accessory top-right; content scrolls under a fading top band.
struct QXPage<Content: View, Trailing: View>: View {
    var title: String? = nil
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var content: Content
    /// The root page of the iPad detail pane has nothing to go back to.
    var hideBack = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(QXPalette.bg.ignoresSafeArea())
            .safeAreaInset(edge: .top, spacing: 0) {
                ZStack {
                    if let title {
                        Text(verbatim: title).font(.headline).lineLimit(1).padding(.horizontal, 70)
                    }
                    HStack {
                        if !hideBack {
                            QXCircleButton(systemName: "chevron.left") { dismiss() }
                                .accessibilityLabel(Text("返回"))
                        }
                        Spacer()
                        trailing
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.top, 4)
                .padding(.bottom, 8)
                .background(
                    LinearGradient(colors: [QXPalette.bg, QXPalette.bg.opacity(0.92), QXPalette.bg.opacity(0)], startPoint: .top, endPoint: .bottom)
                        .ignoresSafeArea(edges: .top)
                )
            }
            .toolbar(.hidden, for: .navigationBar)
    }
}

extension QXPage where Trailing == EmptyView {
    init(title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.trailing = EmptyView()
        self.content = content()
    }
}

/// Bold in-content title with a grey count and an optional pill, then a grey explanation.
struct QXLargeTitle: View {
    let title: String
    var count: String? = nil
    var caption: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(verbatim: title).font(.system(size: QXMetrics.largeTitle, weight: .bold))
                if let count { Text(verbatim: count).font(.system(size: 15)).foregroundStyle(.secondary) }
            }
            if let caption {
                Text(verbatim: caption).font(.system(size: QXMetrics.caption)).foregroundStyle(.secondary).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Light-grey capsule with blue text ("全部更新", "添加").
struct QXPill: View {
    let title: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(verbatim: title).font(.system(size: 15, weight: .semibold)).foregroundStyle(QXColor.switchOn)
                .padding(.horizontal, 14).padding(.vertical, 5)
                .background(Capsule().fill(QXPalette.cardHi))
        }
        .buttonStyle(.plain)
    }
}

/// QX policy colours: DIRECT orange, REJECT red, anything else green.
enum QXPolicyColor {
    static func color(_ policy: String) -> Color {
        let p = policy.uppercased()
        if p.hasPrefix("REJECT") { return QXColor.red }
        if p == "DIRECT" { return QXColor.policyDirect }
        if p.isEmpty { return QXColor.policyNone }
        return QXColor.policyChip
    }
}

/// Floating segmented capsule of circles at the bottom (流量 | 流速, 节点 | 分流 | 重写).
struct QXBottomSegment: View {
    let icons: [String]
    @Binding var selection: Int
    var body: some View {
        // Frame 28: 183×55 pt capsule, 23 pt circles ~68 pt apart; selected = black disc, others grey rings.
        HStack(spacing: 30) {
            ForEach(Array(icons.enumerated()), id: \.offset) { i, icon in
                Button {
                    if selection != i { QXHaptics.select() }
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) { selection = i }
                } label: {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(selection == i ? Color(UIColor.systemBackground) : QXPalette.ring)
                        .frame(width: 32, height: 32)
                        .background(Circle().fill(selection == i ? Color.primary : Color.clear))
                        .overlay(Circle().stroke(selection == i ? Color.clear : QXPalette.ring, lineWidth: 1.5))
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 56)
        .background(Capsule().fill(QXPalette.chrome).shadow(color: QXPalette.shadow(0.10), radius: 12, y: 4))
        .overlay(Capsule().stroke(QXMetrics.hairline, lineWidth: 1))
    }
}

/// Hidden navigation bars must keep the interactive swipe-back.
extension UINavigationController: UIGestureRecognizerDelegate {
    override open func viewDidLoad() {
        super.viewDidLoad()
        interactivePopGestureRecognizer?.delegate = self
    }

    public func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
        viewControllers.count > 1
    }
}
