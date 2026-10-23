import SwiftUI
import Darwin

/// 更多 → 连接方式 (v0.7): one page for how the tunnel is built — mode, QUIC, IPv6, tunnel scope,
/// routes and the proxy skip list, on-demand rules (with trusted Wi-Fi), LAN sharing, and resetting the
/// VPN configuration. Everything is stored in overrides.json / the App Group defaults; the extension reads
/// it at the next connect, so a change needs one reconnect.
/// v0.15.4: no 保存 button — every change is applied 0.5 s after the last edit (invalid routes are not).
struct ConnectionView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var o = CoreOverrides.load()
    @State private var saved = CoreOverrides.load()
    @State private var onDemand = OnDemandSettings.load()
    @State private var savedOnDemand = OnDemandSettings.load()
    @StateObject private var debounce = Debouncer()
    @State private var status: String?
    @State private var lanAddresses: [LANInfo.Address] = []
    @State private var lanStatus: String?
    @State private var confirmReset = false
    @State private var resetting = false
    @State private var needsReconnect = false
    @State private var ssidHint: String?
    @State private var ssidAddTick = 0

    var body: some View {
        Form {
            modeSection
            if !o.isProxyOnly { trafficSection }
            if !o.isProxyOnly { scopeSection }
            routesSection
            onDemandSection
            lanSection
            saveSection
            resetSection
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("连接方式")
        .onAppear {
            // Coming back from a sub page (其他用户): save its edits before re-reading the file.
            debounce.flush()
            // Review 5: an invalid route line blocks apply(); re-reading then threw away every unsaved
            // edit on the page. Keep the user's text until it is fixed (the banner says what is wrong).
            if !hasInvalid {
                o = CoreOverrides.load()
                saved = o
                onDemand = OnDemandSettings.load()
                savedOnDemand = onDemand
            }
            lanAddresses = LANInfo.addresses()
        }
        .onChange(of: o) { _ in debounce.schedule { apply() } }
        .onChange(of: onDemand) { _ in debounce.schedule { apply() } }
        .onDisappear { debounce.flush() }
        .confirmationDialog("重置 VPN 配置？", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("重置", role: .destructive) { reset() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("会断开连接，从系统中删除本 App 的 VPN 配置并重新创建。iOS 会再次询问是否允许添加 VPN 配置。配置文件、规则和设置不受影响。")
        }
    }

    // MARK: Sections

    var modeSection: some View {
        Section {
            Picker("模式", selection: $o.tunnelMode) {
                Text("TUN（推荐）").tag("tun")
                Text("VPN 混合").tag("mix")
                Text("仅代理").tag("proxy")
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } header: { Text("连接方式") } footer: {
            VStack(alignment: .leading, spacing: 6) {
                switch o.tunnelMode {
                case "mix":
                    Text("TUN 之外再设置系统 HTTP / HTTPS 代理（指向本机 \(String(o.mixedPort)) 端口）。遵守系统代理的 App 直接把域名交给内核，其余流量仍经过 TUN。适合个别在 TUN 下异常的 App。")
                case "proxy":
                    Text("只设置系统 HTTP / HTTPS 代理（指向本机 \(String(o.mixedPort)) 端口），不接管路由和 DNS。")
                    Text("取舍：更省电、内存更低；但不遵守系统代理的 App（很多游戏、部分即时通讯、所有 UDP / QUIC）会直连；DNS 由系统解析，按 IP 的规则与 Fake-IP 不生效；MitM 只对走代理的 HTTPS 生效。")
                default:
                    Text("所有 App 的 TCP / UDP 流量和 DNS 都经过内核（NEPacketTunnelFlow），规则、Fake-IP、MitM 全部可用。")
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    @ViewBuilder var trafficSection: some View {
        Section {
            Picker("阻止 QUIC", selection: $o.blockQUIC) {
                Text("关").tag("off")
                Text("仅非直连").tag("nondirect")
                Text("始终").tag("always")
            }
        } header: { Text("流量") } footer: {
            switch o.blockQUIC {
            case "off":
                Text("不拦截 QUIC（mihomo 原生行为）：规则选中的节点不支持 UDP 时，QUIC 会改为直连，绕过你的规则。")
            case "always":
                Text("拒绝所有 QUIC（UDP 443），App 自动改用 TCP，规则与 MitM 对它们都生效。")
            default:
                Text("默认。规则选择直连、或节点支持 UDP 时 QUIC 照常可用；本该走代理但节点不支持 UDP 的 QUIC 被拒绝，App 改用 TCP 并按规则走代理，不会偷偷直连。")
            }
        }
        .listRowBackground(Theme.card)
        ipv6Section
    }

    /// v0.8: IPv6 关 / 自动 / 总是 + IP 优先级 for nodes.
    var ipv6Section: some View {
        Section {
            Picker("IPv6", selection: $o.ipv6Mode) {
                Text("关").tag("off")
                Text("自动").tag("auto")
                Text("总是").tag("always")
            }
            Picker("节点 IP 优先", selection: $o.ipPreference) {
                Text("默认（双栈）").tag("dual")
                Text("IPv4 优先").tag("ipv4-prefer")
                Text("IPv6 优先").tag("ipv6-prefer")
                Text("仅 IPv4").tag("ipv4")
                Text("仅 IPv6").tag("ipv6")
            }
        } header: { Text("IPv6") } footer: {
            switch o.ipv6Mode {
            case "auto":
                Text("每次连接时检查当前 Wi-Fi 或蜂窝网络是否有公网 IPv6 地址，有才给隧道和内核开启 IPv6。切换网络后需要重新连接。「节点 IP 优先」只作用于没有自己写 ip-version 的节点（含节点集）。")
            case "always":
                Text("隧道和内核始终开启 IPv6（AAAA 解析与 IPv6 路由）。当前网络没有 IPv6 时，可能出现部分连接变慢。「节点 IP 优先」只作用于没有自己写 ip-version 的节点（含节点集）。")
            default:
                Text("隧道只接管 IPv4，内核不解析 AAAA。「节点 IP 优先」只作用于没有自己写 ip-version 的节点（含节点集）。")
            }
        }
        .listRowBackground(Theme.card)
    }

    var scopeSection: some View {
        Section {
            Toggle("FaceTime 走代理", isOn: $o.faceTimeProxy).accessibilityIdentifier("conn.facetime")
            Toggle("接管所有网络流量", isOn: o.faceTimeProxy ? .constant(true) : $o.includeAllNetworks)
                .disabled(o.faceTimeProxy).accessibilityIdentifier("conn.includeAll")
            if o.includeAllNetworks || o.faceTimeProxy {
                Toggle("排除局域网", isOn: $o.excludeLocalNetworks)
                if #available(iOS 16.4, *) {
                    Toggle("排除推送通知（APNs）", isOn: $o.excludeAPNs)
                    Toggle("排除运营商服务（电话、短信、VoLTE）", isOn: $o.excludeCellularServices)
                }
                if #available(iOS 17.4, *) {
                    Toggle("排除设备间通信（AirDrop、CarPlay 等）", isOn: $o.excludeDeviceCommunication)
                }
            }
        } header: { Text("隧道范围") } footer: {
            Text(o.faceTimeProxy
                 ? "FaceTime 走代理：自动接管所有网络流量，并把 FaceTime 的音视频（UDP 3478–3497 / 16384–16402）交给主代理组，节点需要支持 UDP。来电响铃走推送通知（APNs）：保持排除时这部分直连，关闭排除则也走代理。更改后重新连接生效。"
                 : o.includeAllNetworks
                 ? "开启后系统把几乎所有流量（包括其他 App 自行绕过 VPN 的连接）都交给隧道；连接中断时这些流量会被阻断，直到重新连接。下面的排除项保留常用的系统服务。更改后立即写入 VPN 配置。"
                 : "关闭（默认）：按下方的路由接管流量，系统服务可以绕过隧道。")
        }
        .listRowBackground(Theme.card)
    }

    var routesSection: some View {
        Section {
            if !o.isProxyOnly {
                NavigationLink {
                    CIDRListEditor(title: "接管的路由", lines: $o.includedRoutes, defaults: CoreOverrides.defaultIncludedRoutes,
                                   placeholder: "0.0.0.0/0",
                                   note: "进入隧道的目标网段。IPv6 网段只在开启 IPv6 时生效。留空等于全部（0.0.0.0/0 与 ::/0）。")
                } label: { countRow("接管的路由", o.includedRoutes) }
                NavigationLink {
                    CIDRListEditor(title: "排除的路由", lines: $o.excludedRoutes, defaults: CoreOverrides.defaultExcludedRoutes,
                                   placeholder: "192.168.0.0/16",
                                   note: "这些网段不进入隧道，直接走系统网络。默认排除私有网段、链路本地和组播，保证局域网设备、打印机和投屏可用。")
                } label: { countRow("排除的路由", o.excludedRoutes) }
            }
            if o.isProxyOnly || o.isMixed {
                NavigationLink {
                    CIDRListEditor(title: "跳过代理", lines: $o.skipProxy, defaults: CoreOverrides.defaultSkipProxy,
                                   placeholder: "*.local", validateCIDR: false,
                                   note: "系统代理不处理的主机或网段，每行一个：域名、*.通配、IP 或 CIDR。")
                } label: { countRow("跳过代理", o.skipProxy) }
            }
        } header: { Text("路由") }
        .listRowBackground(Theme.card)
    }

    var onDemandSection: some View {
        Section {
            Picker("按需连接", selection: $onDemand.mode) {
                ForEach(OnDemandSettings.Mode.allCases) { Text($0.title).tag($0) }
            }
            if onDemand.mode == .always || onDemand.mode == .wifi {
                LinesField(title: "受信任的 Wi-Fi（在这些网络下断开）", placeholder: "Home-WiFi", lines: $onDemand.trustedSSIDs)
                    .id("trusted-\(ssidAddTick)")
                addCurrentSSIDButton { onDemand.trustedSSIDs.append($0) }
            }
            if onDemand.mode == .ssid {
                LinesField(title: "只在这些 Wi-Fi 下连接", placeholder: "Office-WiFi", lines: $onDemand.onlySSIDs)
                    .id("only-\(ssidAddTick)")
                addCurrentSSIDButton { onDemand.onlySSIDs.append($0) }
                Toggle("蜂窝网络下也连接", isOn: $onDemand.ssidCellular)
                if onDemand.onlySSIDs.isEmpty {
                    Text(onDemand.ssidCellular ? "还没有填写 Wi-Fi 名称：只在蜂窝网络下自动连接。" : "还没有填写 Wi-Fi 名称：不会自动连接。")
                        .font(.caption).foregroundStyle(Theme.warn)
                }
            }
            NavigationLink { NetworkPolicyView() } label: {
                Label("按网络切换策略", systemImage: "arrow.triangle.branch")
            }
            .accessibilityIdentifier("connection.networkPolicy")
            if vpn.onDemandPaused {
                Label("已暂停：你在 App 里手动断开了。下次手动连接后恢复。", systemImage: "pause.circle")
                    .font(.footnote).foregroundStyle(Theme.warn)
            }
        } header: { Text("按需连接") } footer: {
            Text("由系统在网络变化时自动连接：「始终」任何网络都连接；「仅 Wi-Fi」在蜂窝网络下断开；「仅蜂窝网络」在 Wi-Fi 下断开；「仅指定 Wi-Fi」只在列出的 Wi-Fi 下连接，其余网络断开。Wi-Fi 名称（SSID）由系统匹配，区分大小写，每行一个。在 App 里手动断开会暂停按需连接，直到你再次手动连接。")
        }
        .listRowBackground(Theme.card)
    }

    /// 「添加当前 Wi-Fi」: reads the SSID (VPN configuration or location permission lets iOS answer).
    @ViewBuilder func addCurrentSSIDButton(_ add: @escaping (String) -> Void) -> some View {
        Button {
            Task {
                await WiFiInfo.shared.refresh()
                if let s = WiFiInfo.shared.ssid {
                    if !onDemand.trustedSSIDs.contains(s) && !onDemand.onlySSIDs.contains(s) { add(s); ssidAddTick += 1 }
                    ssidHint = nil
                } else {
                    ssidHint = String(localized: "读不到当前 Wi-Fi 名称。请手动输入，或在「按网络切换策略」里允许读取。")
                }
            }
        } label: { Label("添加当前 Wi-Fi", systemImage: "wifi") }
        if let ssidHint { Text(ssidHint).font(.caption).foregroundStyle(Theme.warn) }
    }

    var lanSection: some View {
        Section {
            Toggle(isOn: Binding(get: { o.allowLan }, set: { setLan($0) })) {
                Label("局域网共享", systemImage: "wifi.router")
            }
            .accessibilityIdentifier("conn.allowLan")
            if o.allowLan {
                if lanAddresses.isEmpty {
                    Text("没有检测到 Wi-Fi 或个人热点地址。连上 Wi-Fi（或打开个人热点）后返回此页。").font(.caption).foregroundStyle(Theme.warn)
                }
                ForEach(lanAddresses, id: \.self) { a in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(LocalizedStringKey(a.label)).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                        HStack {
                            Text(verbatim: "\(a.ip):\(o.mixedPort)").font(.body.monospaced()).textSelection(.enabled)
                            Spacer()
                            Button { UIPasteboard.general.string = "\(a.ip):\(o.mixedPort)" } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(Text("复制"))
                        }
                        Text(a.subnet.map { String(localized: "HTTP 与 SOCKS5 代理共用此端口 · 子网 \($0)") } ?? String(localized: "HTTP 与 SOCKS5 代理共用此端口"))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Toggle("仅允许局域网设备", isOn: $o.lanLocalOnly)
                TextField("用户名（可选）", text: $o.lanAuth.username)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("密码（可选）", text: $o.lanAuth.password)
                if lanAuthIncomplete {
                    Text("用户名和密码都填写才会启用认证。").font(.caption).foregroundStyle(Theme.warn)
                }
                if o.lanAuth.username.contains(":") {
                    // mihomo splits "user:pass" at the first ':', so this user could never sign in (v0.19.1).
                    Text("用户名不能包含冒号").font(.caption).foregroundStyle(Theme.warn)
                }
                NavigationLink { LanUsersView(users: $o.lanUsers, mainUser: o.lanAuth.password.isEmpty ? "" : o.lanAuth.username) } label: {
                    LabeledContent("其他用户") { Text("\(LanUsersView.validCount(o.lanUsers, mainUser: o.lanAuth))").monospacedDigit() }
                }
                .accessibilityIdentifier("lan.users")
                if !vpn.isConnected {
                    Text("连接后生效。").font(.caption).foregroundStyle(.secondary)
                }
                if let lanStatus { Text(lanStatus).font(.caption).foregroundStyle(.secondary) }
            }
        } header: { Text("局域网共享") } footer: {
            Text("开启后，同一 Wi-Fi 或连接本机个人热点的设备，把 HTTP 或 SOCKS5 代理设为上面的地址，就能通过本机的规则和节点上网。「仅允许局域网设备」只接受私有地址（10/8、172.16/12、192.168/16、链路本地、IPv6 ULA）的连接。设置用户名和密码后，其他设备需要认证；本机自己的系统代理不需要。iOS 可能在锁屏或 App 长时间处于后台时挂起网络扩展，共享会随之中断；只在可信的网络中开启。")
        }
        .listRowBackground(Theme.card)
    }

    @ViewBuilder var saveSection: some View {
        if hasInvalid || status != nil || (needsReconnect && vpn.isConnected) {
        Section {
            if hasInvalid {
                Text("路由列表里有无效的行，修改前不会应用。").font(.footnote).foregroundStyle(Theme.warn)
            }
            AutoApplyFooter(status: status)
            if needsReconnect && vpn.isConnected {
                Button {
                    needsReconnect = false
                    Task { await vpn.restart(safeMode: false); status = String(localized: "已重新连接") }
                } label: { Label("立即重新连接", systemImage: "arrow.clockwise") }
            }
        }
        .listRowBackground(Theme.card)
        }
    }

    var resetSection: some View {
        Section {
            // feat/egern-style: a plain blue action row like Egern's 重置 VPN 配置 (the dialog still confirms).
            Button { confirmReset = true } label: {
                HStack {
                    Text("重置 VPN 配置").foregroundStyle(Theme.accent)
                    Spacer()
                    if resetting { ProgressView().controlSize(.small) }
                }
            }
            .disabled(resetting)
        } footer: {
            Text("系统里的 VPN 配置损坏、连不上或提示配置无效时使用。")
        }
        .listRowBackground(Theme.card)
    }

    // MARK: Helpers

    var lanAuthIncomplete: Bool {
        let u = o.lanAuth.username.trimmingCharacters(in: .whitespaces), p = o.lanAuth.password
        return u.isEmpty != p.isEmpty
    }

    var hasInvalid: Bool {
        !RouteSpec.invalid(o.includedRoutes).isEmpty || !RouteSpec.invalid(o.excludedRoutes).isEmpty
    }

    func countRow(_ title: String, _ lines: [String]) -> some View {
        HStack {
            Text(LocalizedStringKey(title))
            Spacer()
            Text("\(lines.count) 条").font(.caption).foregroundStyle(RouteSpec.invalid(lines).isEmpty || title == "跳过代理" ? Color.secondary : Theme.warn)
        }
    }

    /// The LAN toggle applies at once (reload); the rest goes through apply().
    func setLan(_ on: Bool) {
        o.allowLan = on
        var cur = CoreOverrides.load()
        cur.allowLan = on
        cur.save()
        saved.allowLan = on
        lanAddresses = LANInfo.addresses()
        lanStatus = nil
        guard vpn.isConnected else { return }
        let port = o.mixedPort
        Task {
            if let e = await ReloadCoalescer.shared.reload(vpn) { lanStatus = String(localized: "重载失败：\(e)") }
            else { lanStatus = on ? String(localized: "已开启，正在监听 \(String(port)) 端口") : String(localized: "已关闭") }
        }
    }

    func apply() {
        guard !hasInvalid else { return }
        // Only this page's fields; everything else stays as the other pages saved it.
        var cur = CoreOverrides.load()
        let old = cur
        cur.tunnelMode = o.tunnelMode
        cur.blockQUIC = o.blockQUIC
        cur.ipv6Mode = o.ipv6Mode
        cur.ipPreference = o.ipPreference
        cur.includeAllNetworks = o.includeAllNetworks
        cur.excludeLocalNetworks = o.excludeLocalNetworks
        cur.excludeAPNs = o.excludeAPNs
        cur.excludeCellularServices = o.excludeCellularServices
        cur.excludeDeviceCommunication = o.excludeDeviceCommunication
        cur.faceTimeProxy = o.faceTimeProxy
        cur.includedRoutes = o.includedRoutes
        cur.excludedRoutes = o.excludedRoutes
        cur.skipProxy = o.skipProxy
        cur.allowLan = o.allowLan
        cur.lanLocalOnly = o.lanLocalOnly
        cur.lanAuth = CoreOverrides.LanAuth(username: o.lanAuth.username.trimmingCharacters(in: .whitespaces), password: o.lanAuth.password)
        cur.lanUsers = o.lanUsers // v0.19 局域网多用户 (was not saved)
        let onDemandChanged = onDemand != savedOnDemand
        // r7 R7A-2: nothing changed on the page, but the VPN configuration may still carry another scope (restored
        // backup, older build) — re-apply it then instead of returning, so the page can always fix it.
        guard cur != old || onDemandChanged else {
            Task {
                if await vpn.syncTunnelScope() {
                    status = vpn.isConnected ? String(localized: "隧道范围已同步，重新连接后生效") : String(localized: "隧道范围已同步")
                }
            }
            return
        }
        cur.save()
        savedOnDemand = onDemand
        saved = cur
        // Needs a new tunnel (network settings / VPN configuration) vs. a core reload.
        let reconnect = old.tunnelMode != cur.tunnelMode || old.ipv6Mode != cur.ipv6Mode || old.includedRoutes != cur.includedRoutes
            || old.excludedRoutes != cur.excludedRoutes || old.skipProxy != cur.skipProxy
            || old.includeAllNetworks != cur.includeAllNetworks || old.excludeLocalNetworks != cur.excludeLocalNetworks
            || old.excludeAPNs != cur.excludeAPNs || old.excludeCellularServices != cur.excludeCellularServices
            || old.excludeDeviceCommunication != cur.excludeDeviceCommunication || old.faceTimeProxy != cur.faceTimeProxy
        // tunnelMode too: 仅代理 never carries includeAllNetworks (VPNManager.applyScope).
        let scopeChanged = old.tunnelMode != cur.tunnelMode
            || old.includeAllNetworks != cur.includeAllNetworks || old.excludeLocalNetworks != cur.excludeLocalNetworks
            || old.excludeAPNs != cur.excludeAPNs || old.excludeCellularServices != cur.excludeCellularServices
            || old.excludeDeviceCommunication != cur.excludeDeviceCommunication || old.faceTimeProxy != cur.faceTimeProxy
        let reload = old.blockQUIC != cur.blockQUIC || old.ipPreference != cur.ipPreference || old.lanLocalOnly != cur.lanLocalOnly || old.lanAuth != cur.lanAuth || old.lanUsers != cur.lanUsers
        let settings = onDemand
        Task {
            if scopeChanged, let e = await vpn.applyTunnelScope() {
                status = String(localized: "隧道范围保存失败：\(e)")
                return
            }
            if onDemandChanged, let e = await vpn.applyOnDemand(settings) {
                status = String(localized: "按需连接保存失败：\(e)")
                return
            }
            if vpn.isConnected && reconnect {
                needsReconnect = true
                status = String(localized: "已保存。连接方式、路由和隧道范围在重新连接后生效。")
            } else if vpn.isConnected && reload {
                status = (await ReloadCoalescer.shared.reload(vpn)).map { String(localized: "重载失败：\($0)") } ?? String(localized: "已保存并重载")
            } else {
                status = String(localized: "已保存")
            }
        }
    }

    func reset() {
        resetting = true
        status = nil
        Task {
            let e = await vpn.resetConfiguration()
            resetting = false
            status = e.map { String(localized: "重置失败：\($0)") } ?? String(localized: "已重新创建 VPN 配置")
        }
    }
}

/// One-per-line editor for CIDR lists (or plain host lists) with validation and 恢复默认.
struct CIDRListEditor: View {
    let title: String
    @Binding var lines: [String]
    let defaults: [String]
    let placeholder: String
    var validateCIDR = true
    let note: String
    @State private var text = ""

    private var parsed: [String] {
        text.components(separatedBy: CharacterSet(charactersIn: "\n,")).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
    private var invalid: [String] { validateCIDR ? RouteSpec.invalid(parsed) : [] }

    var body: some View {
        Form {
            Section {
                TextField(placeholder, text: $text, axis: .vertical)
                    .font(.body.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .keyboardType(validateCIDR ? .numbersAndPunctuation : .URL)
                    .lineLimit(4...20)
                    .onChange(of: text) { _ in lines = parsed }
                if !invalid.isEmpty {
                    Label("无效：\(invalid.joined(separator: ", "))", systemImage: "exclamationmark.triangle")
                        .font(.footnote).foregroundStyle(Theme.warn)
                }
            } footer: { Text(LocalizedStringKey(note)) }
            .listRowBackground(Theme.card)
            Section {
                Button("恢复默认") { text = defaults.joined(separator: "\n") }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(LocalizedStringKey(title))
        .onAppear { text = lines.joined(separator: "\n") }
    }
}

/// The phone's LAN addresses other devices can reach (Wi-Fi and Personal Hotspot).
enum LANInfo {
    struct Address: Hashable {
        let iface: String
        let ip: String
        var subnet: String? = nil
        var label: String { iface.hasPrefix("bridge") ? "个人热点" : "Wi-Fi" }
    }

    static func addresses() -> [Address] {
        var out: [Address] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let ifa = cur.pointee
            p = ifa.ifa_next
            guard let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            let flags = Int32(ifa.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            let name = String(cString: ifa.ifa_name)
            guard name == "en0" || name.hasPrefix("bridge") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: host)
                guard !ip.hasPrefix("169.254.") else { continue }
                var subnet: String?
                if let nm = ifa.ifa_netmask {
                    let mask = nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                    let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                    let net = addr & mask
                    let bits = mask.nonzeroBitCount
                    subnet = "\(net >> 24 & 255).\(net >> 16 & 255).\(net >> 8 & 255).\(net & 255)/\(bits)"
                }
                out.append(Address(iface: name, ip: ip, subnet: subnet))
            }
        }
        return out
    }
}

/// v0.19 局域网多用户: extra username / password pairs for 局域网共享 (each device or person its own login).
struct LanUsersView: View {
    @Binding var users: [CoreOverrides.LanAuth]
    /// The 连接方式 user: an extra user with the same name is ignored by the core (v0.19.1: now warned).
    var mainUser: String = ""

    /// Extra users the core will accept (same rules as bridge lanCredentials).
    static func validCount(_ users: [CoreOverrides.LanAuth], mainUser: CoreOverrides.LanAuth) -> Int {
        var seen = Set<String>()
        if !mainUser.username.isEmpty && !mainUser.password.isEmpty {
            seen.insert(mainUser.username)
            seen.insert(mainUser.username.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        var n = 0
        for u in users {
            let name = u.username.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, !u.password.isEmpty, !name.contains(":"), !seen.contains(name) else { continue }
            seen.insert(name)
            n += 1
        }
        return n
    }

    var body: some View {
        List {
            Section {
                if users.isEmpty {
                    Text("还没有其他用户。").foregroundStyle(.secondary)
                }
                ForEach(users.indices, id: \.self) { i in
                    VStack(alignment: .leading, spacing: 6) {
                        TextField("用户名", text: Binding(get: { users.indices.contains(i) ? users[i].username : "" },
                                                        set: { if users.indices.contains(i) { users[i].username = $0 } }))
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("lan.user.\(i).name")
                        SecureField("密码", text: Binding(get: { users.indices.contains(i) ? users[i].password : "" },
                                                        set: { if users.indices.contains(i) { users[i].password = $0 } }))
                            .accessibilityIdentifier("lan.user.\(i).password")
                        if let w = warning(i) { Text(w).font(.caption).foregroundStyle(Theme.warn) }
                    }
                    .padding(.vertical, 2)
                }
                .onDelete { users.remove(atOffsets: $0) }
                Button { users.append(CoreOverrides.LanAuth()) } label: { Label("添加用户", systemImage: "person.badge.plus") }
                    .accessibilityIdentifier("lan.users.add")
            } footer: {
                Text("除了「连接方式」里的用户名和密码，这些账号也可以使用局域网共享（HTTP 与 SOCKS5 都需要认证）。用户名不能包含冒号，重复的用户名只保留第一个。这些密码保存在 App 的配置文件中，连接后生效。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("其他用户")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { if !users.isEmpty { EditButton() } }
    }

    func warning(_ i: Int) -> String? {
        guard users.indices.contains(i) else { return nil }
        let u = users[i]
        let name = u.username.trimmingCharacters(in: .whitespaces)
        if name.isEmpty && u.password.isEmpty { return nil }
        if name.contains(":") { return String(localized: "用户名不能包含冒号") }
        if name.isEmpty || u.password.isEmpty { return String(localized: "用户名和密码都填写才会生效") }
        let main = mainUser.trimmingCharacters(in: .whitespacesAndNewlines)
        if (!main.isEmpty && main == name) || users.prefix(i).contains(where: { $0.username.trimmingCharacters(in: .whitespaces) == name }) {
            return String(localized: "用户名重复，不会生效")
        }
        return nil
    }
}
