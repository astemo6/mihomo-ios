import SwiftUI

/// v0.19 内网 IP 详情 (from the Home 内网 IP card and 更多 → 网络工具): LAN addresses, router, system DNS,
/// network type / Wi-Fi name, 打开路由器后台, and the 局域网共享 address to copy.
struct LANDetailView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var wifi = WiFiInfo.shared
    @Environment(\.openURL) private var openURL
    @State private var info = LocalNetworkInfo()
    @State private var loaded = false
    @State private var copied: String?

    /// v0.19.1: read once per load (was CoreOverrides.load() on every render: Keychain reads, and possibly
    /// an overrides.json write, on the main thread each time the page redrew).
    @State private var overrides = CoreOverrides()

    var body: some View {
        List {
            networkSection
            interfacesSection
            routerSection
            dnsSection
            shareSection
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("内网 IP")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await load() }
        .task { await load() }
        .onAppear { overrides = CoreOverrides.load() } // back from 连接方式
        .overlay(alignment: .bottom) {
            if let copied {
                Text("已复制 \(copied)")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(Capsule().fill(Theme.good))
                    .foregroundStyle(Theme.onAccent)
                    .padding(.bottom, 20)
                    .transition(.opacity)
            }
        }
    }

    func load() async {
        overrides = CoreOverrides.load()
        if UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoLAN") {
            info = Self.demo
        } else {
            info = await LocalNetwork.read()
            await wifi.refresh()
        }
        loaded = true
    }

    func copy(_ s: String) {
        UIPasteboard.general.string = s
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        withAnimation { copied = s }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { withAnimation { if copied == s { copied = nil } } }
    }

    var typeText: String {
        switch info.pathType {
        case "wifi": return "Wi-Fi"
        case "cellular": return String(localized: "蜂窝网络")
        case "wired": return String(localized: "有线网络")
        case "other": return String(localized: "其他")
        default: return String(localized: "无网络")
        }
    }

    var networkSection: some View {
        Section {
            LabeledContent("网络类型") {
                HStack(spacing: 6) {
                    Text(verbatim: typeText)
                    if info.expensive { tag("计费网络") }
                    if info.constrained { tag("低数据模式") }
                }
            }
            .accessibilityIdentifier("lan.type")
            if info.pathType == "wifi" || info.interfaces.contains(where: { $0.name == "en0" }) {
                LabeledContent("Wi-Fi 名称") {
                    if let s = wifi.ssid, !s.isEmpty { Text(verbatim: s) } else { Text("读不到").foregroundStyle(.secondary) }
                }
            }
        } header: {
            Text("网络")
        } footer: {
            if (info.pathType == "wifi") && (wifi.ssid ?? "").isEmpty && wifi.checked {
                Text("iOS 只在描述文件包含 wifi-info 且已安装 VPN 配置或允许精确定位时提供 Wi-Fi 名称（可在「按网络切换策略」里允许读取）。")
            }
        }
        .listRowBackground(Theme.card)
    }

    func tag(_ t: LocalizedStringKey) -> some View {
        Text(t).font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Capsule().fill(Theme.warn.opacity(0.18)))
            .foregroundStyle(Theme.warn)
    }

    var interfacesSection: some View {
        Section {
            if info.interfaces.isEmpty {
                Text(loaded ? LocalizedStringKey("没有局域网地址") : LocalizedStringKey("正在读取…")).foregroundStyle(.secondary)
            }
            ForEach(info.interfaces) { i in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(LocalizedStringKey(i.kind)).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        Text(verbatim: i.name).font(.caption2.monospaced()).foregroundStyle(.secondary)
                        Spacer()
                        if let s = i.subnet { Text(verbatim: s).font(.caption2.monospaced()).foregroundStyle(.secondary) }
                    }
                    ForEach(i.ipv4 + i.ipv6, id: \.self) { a in
                        HStack {
                            Text(verbatim: a).font(.body.monospaced()).lineLimit(1).minimumScaleFactor(0.6)
                                .textSelection(.enabled)
                            Spacer()
                            Button { copy(a) } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(Text("复制"))
                        }
                    }
                }
                .padding(.vertical, 2)
                .accessibilityIdentifier("lan.iface.\(i.name)")
            }
        } header: {
            Text("本机地址")
        }
        .listRowBackground(Theme.card)
    }

    var routerSection: some View {
        Section {
            LabeledContent("网关 / 路由器") {
                HStack(spacing: 6) {
                    Text(verbatim: info.gateway ?? "—").font(.body.monospaced())
                    if info.gatewayGuessed { Text("推测").font(.caption2).foregroundStyle(.secondary) }
                }
            }
            .accessibilityIdentifier("lan.gateway")
            if let g = info.gateway, let url = URL(string: "http://\(g.contains(":") ? "[\(g)]" : g)") {
                Button { openURL(url) } label: { Label("打开路由器后台", systemImage: "safari") }
                    .accessibilityIdentifier("lan.openRouter")
                Button { copy(g) } label: { Label("复制网关地址", systemImage: "doc.on.doc") }
            }
        } header: {
            Text("路由器")
        } footer: {
            Text(info.gatewayGuessed ? LocalizedStringKey("系统没有给出 Wi-Fi 网关，按子网推测为第一个地址。") : LocalizedStringKey("在浏览器中打开 http://网关地址；登录信息一般印在路由器背面。"))
        }
        .listRowBackground(Theme.card)
    }

    var dnsSection: some View {
        Section {
            if info.dns.isEmpty {
                Text(loaded ? LocalizedStringKey("没有读到 DNS 服务器") : LocalizedStringKey("正在读取…")).foregroundStyle(.secondary)
            }
            ForEach(info.dns, id: \.self) { d in
                HStack {
                    Text(verbatim: d).font(.body.monospaced())
                    Spacer()
                    Button { copy(d) } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(Text("复制"))
                }
            }
        } header: {
            Text("系统 DNS")
        } footer: {
            if vpn.isConnected {
                Text("代理连接时，系统 DNS 指向隧道（由内核接管），这里显示的是隧道的地址，不是路由器下发的 DNS。")
            } else {
                Text("当前网络下发给本机的 DNS 服务器。")
            }
        }
        .listRowBackground(Theme.card)
    }

    var shareSection: some View {
        let o = overrides
        let lan = info.interfaces.filter { $0.name == "en0" || $0.name.hasPrefix("bridge") }.compactMap { i in i.ipv4.first.map { ShareAddr(iface: i, ip: $0) } }
        return Section {
            if o.allowLan {
                if lan.isEmpty {
                    Text("没有检测到 Wi-Fi 或个人热点地址。").foregroundStyle(.secondary)
                }
                ForEach(lan) { pair in
                    let addr = "\(pair.ip):\(o.mixedPort)"
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(LocalizedStringKey(pair.iface.kind)).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                            Text(verbatim: addr).font(.body.monospaced())
                        }
                        Spacer()
                        Button { copy(addr) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(Text("复制"))
                    }
                    .accessibilityIdentifier("lan.share.\(pair.iface.name)")
                }
                if (!o.lanAuth.username.isEmpty && !o.lanAuth.password.isEmpty) || o.lanUsers.contains(where: { !$0.username.isEmpty && !$0.password.isEmpty }) {
                    Label("需要用户名和密码", systemImage: "lock").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                NavigationLink { ConnectionView() } label: {
                    LabeledContent("局域网共享") { Text("未开启") }
                }
                .accessibilityIdentifier("lan.share.off")
            }
        } header: {
            Text("局域网共享")
        } footer: {
            if o.allowLan {
                Text("其他设备把 HTTP 或 SOCKS5 代理设为这个地址即可使用本机的规则和节点（连接后生效）。")
            } else {
                Text("在「连接方式」中开启后，同一网络的设备可以通过本机上网。")
            }
        }
        .listRowBackground(Theme.card)
    }

    struct ShareAddr: Identifiable {
        var iface: LocalInterface
        var ip: String
        var id: String { iface.name + ip }
    }

    /// Simulator UI tests (-UITestDemoLAN): fixed documentation addresses.
    static let demo = LocalNetworkInfo(
        interfaces: [LocalInterface(name: "en0", ipv4: ["192.0.2.23"], ipv6: ["fe80::1c2b:3a4d:5e6f:7081"], subnet: "192.0.2.0/24"),
                     LocalInterface(name: "pdp_ip0", ipv4: ["198.51.100.77"], subnet: nil)],
        gateway: "192.0.2.1", gatewayGuessed: false, dns: ["192.0.2.1", "2001:db8::53"], pathType: "wifi", expensive: false, constrained: false)
}
