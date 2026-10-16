import SwiftUI

@main
struct MihomoApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vpn = VPNManager.shared
    @StateObject private var router = ImportRouter.shared
    @StateObject private var store = ProfileStore.shared
    @StateObject private var dash = DashboardModel.shared
    @StateObject private var ipinfo = IPInfoModel.shared
    @Environment(\.scenePhase) private var phase

    init() {
        // Bundled geo databases → core home, so profile validation in the app never downloads them either.
        DispatchQueue.global(qos: .utility).async { GeoBootstrap.install() }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vpn)
                .environmentObject(store)
                .environmentObject(dash)
                .environmentObject(ipinfo)
                .environmentObject(router)
                .onOpenURL { router.handle(url: $0) }
                .sheet(item: $router.pending) { a in
                    ImportSheet(action: a)
                        .environmentObject(store)
                        .preferredColorScheme(.dark)
                }
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .onChange(of: phase) { p in
                    if p == .active {
                        Task { await vpn.load() }
                        Task { await store.autoUpdateIfNeeded() }
                        Task { await ResourceStore.shared.updateDueIfNeeded() }
                        ipinfo.scheduleRefresh(after: 0.3)
                    }
                }
        }
    }
}

/// The five top-level sections: a TabView on iPhone (compact width), a NavigationSplitView sidebar on
/// iPad / regular width. Each section keeps its own NavigationStack, so the views are identical.
enum AppSection: Int, CaseIterable, Identifiable {
    case home, policy, requests, profiles, more
    var id: Int { rawValue }
    var title: String {
        switch self {
        case .home: return "首页"
        case .policy: return "策略"
        case .requests: return "请求"
        case .profiles: return "配置"
        case .more: return "更多"
        }
    }
    var icon: String {
        switch self {
        case .home: return "gauge.with.dots.needle.67percent"
        case .policy: return "square.grid.2x2.fill"
        case .requests: return "arrow.left.arrow.right"
        case .profiles: return "doc.text.fill"
        case .more: return "ellipsis.circle.fill"
        }
    }
    @ViewBuilder var view: some View {
        switch self {
        case .home: HomeView()
        case .policy: PolicyView()
        case .requests: RequestsView()
        case .profiles: ProfilesView()
        case .more: MoreView()
        }
    }
}

struct RootView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var dash: DashboardModel
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
                        s.view.tabItem { Label(LocalizedStringKey(s.title), systemImage: s.icon) }.tag(s.rawValue)
                    }
                }
            }
        }
        .overlay(alignment: .top) { PasteBanner() }
        .fullScreenCover(isPresented: $showOnboarding) {
            OnboardingView { showOnboarding = false }
                .environmentObject(vpn)
                .environmentObject(store)
        }
        .onChange(of: vpn.status) { s in
            if s == .connected { dash.start() } else if s == .disconnected || s == .invalid { dash.stop() }
        }
        .onChange(of: phase) { p in
            if p == .active { ClipboardWatcher.shared.didBecomeActive() } else if p == .background { ClipboardWatcher.shared.didLeave() }
        }
        .onAppear {
            // First run only; people upgrading with profiles already set up never see it (更多 → 新手引导 shows it again).
            if !Onboarding.isDone {
                if store.profiles.isEmpty { showOnboarding = true } else { Onboarding.isDone = true }
            }
            if vpn.isConnected { dash.start() }
            ClipboardWatcher.shared.didBecomeActive()
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
            .navigationTitle("Mihomo")
        } detail: {
            (AppSection(rawValue: router.selectedTab) ?? .home).view
                .id(router.selectedTab)
        }
        .navigationSplitViewStyle(.balanced)
    }
}

enum Theme {
    static let accent = Color(red: 0.29, green: 0.78, blue: 0.96)
    static let bg = Color(red: 0.04, green: 0.043, blue: 0.063)
    static let card = Color(red: 0.09, green: 0.10, blue: 0.13)
    static let cardHi = Color(red: 0.13, green: 0.14, blue: 0.18)
    static let up = Color(red: 1.0, green: 0.62, blue: 0.26)
    static let down = Color(red: 0.29, green: 0.78, blue: 0.96)
    static let good = Color(red: 0.25, green: 0.85, blue: 0.48)
    static let warn = Color(red: 1.0, green: 0.78, blue: 0.2)
    static let bad = Color(red: 1.0, green: 0.36, blue: 0.36)
    static let connectedGradient = LinearGradient(colors: [Color(red: 0.16, green: 0.52, blue: 0.98), Color(red: 0.36, green: 0.86, blue: 0.95)], startPoint: .topLeading, endPoint: .bottomTrailing)
    static let idleGradient = LinearGradient(colors: [Color(white: 0.16), Color(white: 0.12)], startPoint: .topLeading, endPoint: .bottomTrailing)

    static func delayColor(_ d: Int?) -> Color {
        guard let d, d > 0 else { return .secondary }
        if d < 200 { return good }
        if d < 500 { return warn }
        return bad
    }

    /// Colour per protocol for node badges.
    static func protocolColor(_ type: String) -> Color {
        switch type.lowercased() {
        case "shadowsocks", "ss", "shadowsocksr", "ssr": return Color(red: 0.55, green: 0.45, blue: 1.0)
        case "vmess": return Color(red: 0.25, green: 0.6, blue: 1.0)
        case "vless": return Color(red: 0.2, green: 0.8, blue: 0.85)
        case "trojan": return Color(red: 1.0, green: 0.45, blue: 0.45)
        case "hysteria", "hysteria2", "tuic": return Color(red: 1.0, green: 0.62, blue: 0.2)
        case "wireguard": return Color(red: 0.35, green: 0.85, blue: 0.45)
        case "snell", "anytls", "mieru": return Color(red: 1.0, green: 0.4, blue: 0.75)
        case "socks5", "http", "ssh": return Color(white: 0.7)
        case "direct": return good
        case "reject", "rejectdrop": return bad
        default: return .secondary
        }
    }

    static func delayText(_ d: Int?) -> String {
        guard let d else { return "—" }
        return d > 0 ? "\(d) ms" : "超时"
    }
}

struct Card<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.white.opacity(0.06)))
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
    var body: some View {
        EmptyStateView(icon: "bolt.horizontal.circle", title: text)
    }
}
