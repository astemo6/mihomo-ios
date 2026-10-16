import SwiftUI

@main
struct MihomoApp: App {
    @StateObject private var vpn = VPNManager.shared
    @StateObject private var store = ProfileStore.shared
    @StateObject private var dash = DashboardModel.shared
    @StateObject private var ipinfo = IPInfoModel.shared
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vpn)
                .environmentObject(store)
                .environmentObject(dash)
                .environmentObject(ipinfo)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .onChange(of: phase) { p in
                    if p == .active {
                        Task { await vpn.load() }
                        Task { await store.autoUpdateIfNeeded() }
                        ipinfo.scheduleRefresh(after: 0.3)
                    }
                }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var dash: DashboardModel

    var body: some View {
        TabView {
            HomeView()
                .tabItem { Label("首页", systemImage: "gauge.with.dots.needle.67percent") }
            PolicyView()
                .tabItem { Label("策略", systemImage: "square.grid.2x2.fill") }
            RequestsView()
                .tabItem { Label("请求", systemImage: "arrow.left.arrow.right") }
            ProfilesView()
                .tabItem { Label("配置", systemImage: "doc.text.fill") }
            MoreView()
                .tabItem { Label("更多", systemImage: "ellipsis.circle.fill") }
        }
        .onChange(of: vpn.status) { s in
            if s == .connected { dash.start() } else if s == .disconnected || s == .invalid { dash.stop() }
        }
        .onAppear { if vpn.isConnected { dash.start() } }
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
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(Capsule().fill(c.opacity(0.18)))
            .foregroundStyle(c)
            .lineLimit(1)
    }
}

struct NotConnectedPlaceholder: View {
    var text = "连接后可查看"
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "bolt.horizontal.circle").font(.system(size: 44)).foregroundStyle(.secondary)
            Text(text).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.top, 80)
    }
}
