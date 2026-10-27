import SwiftUI
import UIKit

@main
struct TernApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vpn = VPNManager.shared
    @StateObject private var router = ImportRouter.shared
    @StateObject private var store = ProfileStore.shared
    // fix/nav-jank: singletons that publish often (speed every second, the memory stream, IP lookups) are held
    // without observing. As @StateObject the App re-evaluated its scene on every tick; views that show these
    // values observe them themselves.
    private let dash = DashboardModel.shared
    private let ipinfo = IPInfoModel.shared
    @Environment(\.scenePhase) private var phase

    init() {
        EgernDensity.applyBars()
        // test/selftest: simulator UI tests only (-UITestSeed); wipes the demo container before any store loads.
        UITestSeed.resetIfNeeded()
        // Bundled geo databases → core home, so profile validation in the app never downloads them either.
        DispatchQueue.global(qos: .utility).async { GeoBootstrap.install() }
        // fix/nc-storage-other: crashed-prepare staging dirs and orphaned atomic-write temp files (older than 10 min).
        DispatchQueue.global(qos: .background).async { StorageScan.sweepOnLaunch() }
        // r7 B28: scripts' $environment.language follows the UI language (read by the engine on its next load).
        DispatchQueue.global(qos: .utility).async { EngineConfig.stampLanguage() }
        // feat/jsc-engine: `-TernJSCSelfTest` runs one the old JS engine-vs-JavaScriptCore conformance case and logs it.
        JSCScriptEngine.selfTestIfRequested()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vpn)
                .environmentObject(store)
                .environmentObject(dash)
                .environmentObject(ipinfo)
                .environmentObject(router)
                // Imports are presented by ImportRouter from the topmost view controller (v0.8.1): a root
                // .sheet was silently dropped while onboarding, another sheet or the file picker was up.
                .onOpenURL { router.handle(url: $0) }
                .tint(Theme.accent)
                // v0.9: 更多 → 设置 → 外观 (跟随系统 / 浅色 / 深色), applied to every window.
                .onAppear {
                    AppAppearance.apply()
                    // fix/nc-0.20.2: import / module downloads outside the sheets, retried on connect / foreground.
                    BackgroundDownloads.shared.start()
                }
                .onChange(of: phase) { p in
                    if p == .background { LiveActivityController.shared.didEnterBackground(); ScheduledUpdates.scheduleBackground() }
                    if p == .active {
                        Task { await vpn.load() }
                        // v0.14: due subscriptions + usage alerts + the opt-in update notification.
                        Task { await ScheduledUpdates.run() }
                        Task { await ResourceStore.shared.updateDueIfNeeded() }
                        Task { await ProviderUpdater.shared.autoUpdateIfNeeded() }
                        ipinfo.scheduleRefresh(after: 0.3)
                    }
                }
        }
    }
}

/// The five top-level sections: a TabView on iPhone (compact width), a NavigationSplitView sidebar on
/// iPad / regular width. Each section keeps its own NavigationStack, so the views are identical.
enum AppSection: Int, CaseIterable, Identifiable {
    /// feat/more-dedup (user 2026-10-21 18:06): the 配置 tab became 工具 (Egern-style cards); 配置管理 is a row
    /// at the top of 更多. Raw value 3 kept, so a stored 开始标签页 of 3 now opens 工具.
    case home, policy, requests, tools, more
    var id: Int { rawValue }
    var title: String {
        switch self {
        case .home: return "首页"
        case .policy: return "策略"
        case .requests: return "请求"
        case .tools: return "工具"
        case .more: return "更多"
        }
    }
    var icon: String {
        switch self {
        // feat/egern-style: thin outline symbols (the tab bar no longer forces .fill, see RootView).
        case .home: return "gauge.with.dots.needle.33percent"
        case .policy: return "paperplane"
        case .requests: return "arrow.left.arrow.right"
        case .tools: return "wrench.and.screwdriver"
        case .more: return "gearshape"
        }
    }
    @ViewBuilder var view: some View {
        switch self {
        case .home: HomeView()
        case .policy: PolicyView()
        case .requests: RequestsView()
        case .tools: ToolsTabView()
        case .more: MoreView()
        }
    }
}

struct RootView: View {
    @EnvironmentObject var vpn: VPNManager
    /// fix/nav-jank (「动画有卡顿」): not observed. As an @EnvironmentObject every speed / memory / connection
    /// tick re-rendered the TabView and every tab under it, including NavigationStacks mid push / pop, which
    /// dropped frames and made large titles snap. Only start / stop / setActive are needed here.
    private var dash: DashboardModel { DashboardModel.shared }
    @EnvironmentObject var router: ImportRouter
    @EnvironmentObject var store: ProfileStore
    @Environment(\.horizontalSizeClass) private var hSize
    @Environment(\.scenePhase) private var phase
    @State private var showOnboarding = false

    var body: some View {
        Group {
            if hSize == .regular {
                SplitRootView()
            } else {
                TabView(selection: $router.selectedTab) {
                    ForEach(AppSection.allCases) { s in
                        s.view
                            .tabItem { Label(LocalizedStringKey(s.title), systemImage: s.icon).environment(\.symbolVariants, .none) }
                            .tag(s.rawValue)
                    }
                }
            }
        }
        // feat/egern-style: dense Egern lists — 15 pt body text, 40 pt minimum rows, compact section gaps.
        .modifier(EgernDensity())
        .overlay(alignment: .bottomLeading) { UITestReadyMarker() }
        .overlay(alignment: .bottomTrailing) { UIPerfProbeMarker() } // fix/nc-ui-smooth: Debug + -UIPerfProbe only
        .fullScreenCover(isPresented: $showOnboarding) {
            OnboardingView { showOnboarding = false }
                .environmentObject(vpn)
                .environmentObject(store)
        }
        .onChange(of: vpn.status) { s in
            if s == .connected { dash.start() } else if s == .disconnected || s == .invalid { dash.stop() }
            if s == .connected { LiveActivityController.shared.statusChanged(connected: true) }
            else if s == .disconnected || s == .invalid { LiveActivityController.shared.statusChanged(connected: false) }
        }
        .onChange(of: phase) { p in
            // v0.19.8 (user): no clipboard banner; the clipboard is read only from an explicit 粘贴 action.
            if p == .background { SyncFolder.shared.autoPushIfNeeded() }
            // fix/bg-chart: Home's polling stops off screen and resumes without replaying missed samples.
            dash.setActive(p == .active)
            if p == .active { Task { await LiveActivityController.shared.endIfTunnelDown() } } // r7
        }
        .onAppear {
            // First run only; people upgrading with profiles already set up never see it (更多 → 新手引导 shows it again).
            if !Onboarding.isDone {
                if store.profiles.isEmpty { showOnboarding = true } else { Onboarding.isDone = true }
            }
            if vpn.isConnected { dash.start() }
            // Cold launch from 「用 Tern 打开」: if onOpenURL did not deliver the document, do it now.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { router.drainColdLaunchURLs() }
        }
    }
}

/// iPad: sidebar with the five sections; the detail column hosts the same section views.
struct SplitRootView: View {
    @EnvironmentObject var router: ImportRouter
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        NavigationSplitView {
            List(selection: Binding<Int?>(get: { router.selectedTab }, set: { if let v = $0 { router.selectedTab = v } })) {
                Section {
                    ForEach(AppSection.allCases) { s in
                        Label(LocalizedStringKey(s.title), systemImage: s.icon).tag(s.rawValue)
                    }
                }
                Section {
                    HStack(spacing: 8) {
                        Circle().fill(vpn.isConnected ? Theme.good : Color.secondary).frame(width: 8, height: 8)
                        Text(vpn.isConnected ? "已连接" : "未连接").font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("Tern")
        } detail: {
            (AppSection(rawValue: router.selectedTab) ?? .home).view
                .id(router.selectedTab)
        }
        .navigationSplitViewStyle(.balanced)
    }
}

enum Theme {
    // v0.9: every colour adapts to light / dark (更多 → 设置 → 外观). Dark values are the v0.1–v0.8 palette;
    // light values keep the same hues, darkened where they carry text or thin strokes on white (≥ 3:1).
    static func dyn(_ light: UIColor, _ dark: UIColor) -> Color {
        Color(UIColor { $0.userInterfaceStyle == .dark ? dark : light })
    }
    static func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> UIColor {
        UIColor(red: r, green: g, blue: b, alpha: a)
    }
    /// Same hue for both modes, darkened in light mode (badges, chart series).
    static func tone(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> Color {
        dyn(rgb(r * 0.78, g * 0.78, b * 0.78), rgb(r, g, b))
    }

    /// feat/egern-style: corner radius of every card (Egern's subtle ~10–12 pt, was 18).
    static let radius: CGFloat = 12

    static let accent = dyn(rgb(0.0, 0.47, 0.78), rgb(0.29, 0.78, 0.96))
    /// feat/egern-style: the light-mode accent in both appearances, for solid tiles under a white symbol.
    static let accentSolid = Color(rgb(0.0, 0.47, 0.78))
    static let bg = dyn(rgb(0.949, 0.953, 0.969), rgb(0.04, 0.043, 0.063))
    static let card = dyn(rgb(1, 1, 1), rgb(0.09, 0.10, 0.13))
    static let cardHi = dyn(rgb(0.918, 0.925, 0.945), rgb(0.13, 0.14, 0.18))
    static let up = dyn(rgb(0.86, 0.42, 0.0), rgb(1.0, 0.62, 0.26))
    static let down = accent
    static let good = dyn(rgb(0.09, 0.60, 0.29), rgb(0.25, 0.85, 0.48))
    static let warn = dyn(rgb(0.78, 0.50, 0.0), rgb(1.0, 0.78, 0.2))
    static let bad = dyn(rgb(0.84, 0.19, 0.19), rgb(1.0, 0.36, 0.36))
    /// Hairline strokes, tracks and chip fills: white on dark, black on light (`Theme.ink(0.06)`).
    static func ink(_ alpha: Double) -> Color {
        dyn(UIColor(white: 0, alpha: alpha * 0.9), UIColor(white: 1, alpha: alpha))
    }
    /// Neutral grey for "other" chart series.
    static let neutral = dyn(UIColor(white: 0.60, alpha: 1), UIColor(white: 0.45, alpha: 1))
    /// Text on a filled accent / status capsule.
    static let onAccent = dyn(.white, .black)

    static func delayColor(_ d: Int?) -> Color {
        guard let d, d > 0 else { return .secondary }
        if d < 200 { return good }
        if d < 500 { return warn }
        return bad
    }

    /// Colour per protocol for node badges.
    static func protocolColor(_ type: String) -> Color {
        switch type.lowercased() {
        case "shadowsocks", "ss", "shadowsocksr", "ssr": return tone(0.55, 0.45, 1.0)
        case "vmess": return tone(0.25, 0.6, 1.0)
        case "vless": return tone(0.2, 0.8, 0.85)
        case "trojan": return tone(1.0, 0.45, 0.45)
        case "hysteria", "hysteria2", "tuic": return tone(1.0, 0.62, 0.2)
        case "wireguard": return tone(0.35, 0.85, 0.45)
        case "snell", "anytls", "mieru", "brook": return tone(1.0, 0.4, 0.75)
        case "socks5", "http", "ssh": return neutral
        case "tailscale", "zerotier", "easytier": return accent
        case "direct": return good
        case "reject", "rejectdrop": return bad
        default: return .secondary
        }
    }

    /// v0.16: rule type chips (规则, 请求, 自定义规则). Categories share the protocol badge hues; MATCH is neutral.
    static func ruleTypeColor(_ type: String) -> Color? {
        let t = type.uppercased()
        if t == "MATCH" || t == "FINAL" { return neutral }
        if t.hasPrefix("GEOSITE") { return tone(0.55, 0.45, 1.0) }
        if t.hasPrefix("DOMAIN") || t.hasPrefix("HOST") { return tone(0.25, 0.6, 1.0) }
        if t.hasPrefix("RULE-SET") || t == "RULESET" || t.hasPrefix("RULE_SET") { return tone(1.0, 0.62, 0.2) }
        if t.hasPrefix("IP") || t.hasPrefix("GEOIP") || t.hasPrefix("SRC-IP") || t.hasPrefix("SRC-GEOIP") || t.hasPrefix("DST-IP") { return tone(0.35, 0.85, 0.45) }
        if t == "AND" || t == "OR" || t == "NOT" || t == "SUB-RULE" { return tone(0.2, 0.8, 0.85) }
        if t.hasPrefix("PROCESS") || t.hasPrefix("UID") || t.hasPrefix("USER-AGENT") || t.hasPrefix("URL-REGEX") { return tone(1.0, 0.4, 0.75) }
        if t.hasSuffix("PORT") || t == "NETWORK" || t.hasPrefix("IN-") || t == "DSCP" || t.hasPrefix("PROTOCOL") { return tone(1.0, 0.45, 0.45) }
        return nil
    }

    /// Controller connection rules come as the old core type names ("DomainSuffix", "GeoIP"); shown with the profile spelling.
    static func ruleTypeName(_ raw: String) -> String {
        let known: [String: String] = [
            "domain": "DOMAIN", "domainsuffix": "DOMAIN-SUFFIX", "domainkeyword": "DOMAIN-KEYWORD", "domainregex": "DOMAIN-REGEX",
            "domainwildcard": "DOMAIN-WILDCARD", "geosite": "GEOSITE", "geoip": "GEOIP", "srcgeoip": "SRC-GEOIP",
            "ipcidr": "IP-CIDR", "ipcidr6": "IP-CIDR6", "srcipcidr": "SRC-IP-CIDR", "ipsuffix": "IP-SUFFIX", "srcipsuffix": "SRC-IP-SUFFIX",
            "ipasn": "IP-ASN", "srcipasn": "SRC-IP-ASN", "ruleset": "RULE-SET", "match": "MATCH", "and": "AND", "or": "OR", "not": "NOT",
            "subrules": "SUB-RULE", "processname": "PROCESS-NAME", "processpath": "PROCESS-PATH", "processnameregex": "PROCESS-NAME-REGEX",
            "processpathregex": "PROCESS-PATH-REGEX", "dstport": "DST-PORT", "srcport": "SRC-PORT", "inport": "IN-PORT", "network": "NETWORK",
            "intype": "IN-TYPE", "inuser": "IN-USER", "inname": "IN-NAME", "uid": "UID", "dscp": "DSCP",
        ]
        let key = raw.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
        return known[key] ?? raw.uppercased()
    }

    /// Policy chip colour: DIRECT good, REJECT bad, everything else the accent.
    static func policyColor(_ name: String) -> Color {
        let n = name.uppercased()
        if n == "DIRECT" { return good }
        if n.hasPrefix("REJECT") { return bad }
        return accent
    }

    static func delayText(_ d: Int?) -> String {
        guard let d else { return "—" }
        return d > 0 ? "\(d) ms" : String(localized: "超时")
    }
}

struct Card<Content: View>: View {
    var padding: CGFloat = 12
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .egernCard()
    }
}

extension View {
    /// feat/egern-style: the one card surface — flat `Theme.card`, `Theme.radius` corners, no border or shadow
    /// (Egern's white cards on the grouped background).
    func egernCard(_ radius: CGFloat = Theme.radius) -> some View {
        background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(Theme.card))
    }
}

struct ProtocolBadge: View {
    let type: String
    var body: some View {
        let c = Theme.protocolColor(type)
        Text(ProxyItem.label(for: type))
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(Capsule().fill(c.opacity(0.18)))
            .foregroundStyle(c)
            .lineLimit(1)
    }
}

struct NotConnectedPlaceholder: View {
    var text = "连接后可查看"
    @ObservedObject private var vpn = VPNManager.shared
    @ObservedObject private var store = ProfileStore.shared
    /// feat/surge-ui: the empty page offers the next step — 连接, or 添加配置 when there is nothing to connect with.
    var body: some View {
        if store.profiles.isEmpty {
            EmptyStateView(icon: "bolt.horizontal.circle", title: text, message: "还没有配置，先添加一个订阅或配置文件。",
                           actionTitle: "添加配置", actionID: "empty.addProfile") { ImportRouter.shared.showProfiles() }
        } else {
            EmptyStateView(icon: "bolt.horizontal.circle", title: text, message: vpn.status == .connecting ? "正在连接…" : "开启 VPN 后这里会实时更新。",
                           actionTitle: vpn.isConnected || vpn.status == .connecting ? nil : "连接", actionID: "empty.connect") {
                Task { await vpn.toggle() }
            }
        }
    }
}

/// feat/egern-style (user 2026-10-21 「所以你的整体风格可向它看齐」): Egern's compact density for every page.
/// Text without an explicit font is 15 pt (`.subheadline`, still Dynamic Type), list rows may be 40 pt, grouped
/// sections sit closer together, and the navigation bar titles are a size smaller (28 pt large, 16 pt inline).
struct EgernDensity: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        let c = content
            .font(.subheadline)
            .environment(\.defaultMinListRowHeight, 40)
        if #available(iOS 17.0, *) {
            c.listSectionSpacing(.compact)
        } else {
            c
        }
    }

    /// UIKit bars cannot be styled from SwiftUI; done once at launch.
    static func applyBars() {
        let large = UIFont.systemFont(ofSize: 28, weight: .bold)
        let inline = UIFont.systemFont(ofSize: 16, weight: .semibold)
        let nav = UINavigationBar.appearance()
        nav.largeTitleTextAttributes = [.font: UIFontMetrics(forTextStyle: .largeTitle).scaledFont(for: large)]
        nav.titleTextAttributes = [.font: UIFontMetrics(forTextStyle: .headline).scaledFont(for: inline)]
        let item = UITabBarItem.appearance()
        item.setTitleTextAttributes([.font: UIFont.systemFont(ofSize: 10, weight: .regular)], for: .normal)
    }
}
