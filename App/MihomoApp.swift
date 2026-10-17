import SwiftUI
import UIKit

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
                // Imports are presented by ImportRouter from the topmost view controller (v0.8.1): a root
                // .sheet was silently dropped while onboarding, another sheet or the file picker was up.
                .onOpenURL { router.handle(url: $0) }
                .tint(Theme.accent)
                // v0.9: 更多 → 设置 → 外观 (跟随系统 / 浅色 / 深色), applied to every window.
                .onAppear { AppAppearance.apply() }
                .onChange(of: phase) { p in
                    if p == .active {
                        Task { await vpn.load() }
                        Task { await store.autoUpdateIfNeeded() }
                        Task { await NodeSubStore.shared.autoUpdateIfNeeded() }
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
            if p == .active { ClipboardWatcher.shared.didBecomeActive() } else if p == .background {
                ClipboardWatcher.shared.didLeave()
                SyncFolder.shared.autoPushIfNeeded()
            }
        }
        .onAppear {
            // First run only; people upgrading with profiles already set up never see it (更多 → 新手引导 shows it again).
            if !Onboarding.isDone {
                if store.profiles.isEmpty { showOnboarding = true } else { Onboarding.isDone = true }
            }
            if vpn.isConnected { dash.start() }
            ClipboardWatcher.shared.didBecomeActive()
            // Cold launch from 「用 Mihomo 打开」: if onOpenURL did not deliver the document, do it now.
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
            .navigationTitle("Mihomo")
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

    static let accent = dyn(rgb(0.0, 0.47, 0.78), rgb(0.29, 0.78, 0.96))
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
    static let connectedGradient = LinearGradient(colors: [Color(red: 0.16, green: 0.52, blue: 0.98), Color(red: 0.36, green: 0.86, blue: 0.95)], startPoint: .topLeading, endPoint: .bottomTrailing)
    static let idleGradient = LinearGradient(colors: [cardHi, card], startPoint: .topLeading, endPoint: .bottomTrailing)

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
        case "snell", "anytls", "mieru": return tone(1.0, 0.4, 0.75)
        case "socks5", "http", "ssh": return neutral
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
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
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
