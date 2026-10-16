import SwiftUI
import Darwin

/// 连接方式与按需连接: tunnel mode (packet tunnel vs proxy-only) and NEOnDemandRules.
struct ConnectionView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var tunnelMode = CoreOverrides.load().tunnelMode
    @State private var onDemand = OnDemandSettings.load()
    @State private var status: String?
    @State private var allowLan = CoreOverrides.load().allowLan
    @State private var lanAddresses: [LANInfo.Address] = []
    @State private var lanStatus: String?

    var body: some View {
        Form {
            Section {
                Picker("模式", selection: $tunnelMode) {
                    Text("全局隧道（推荐）").tag("tun")
                    Text("仅代理").tag("proxy")
                }
                .pickerStyle(.inline)
                .labelsHidden()
            } header: { Text("连接方式") } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if tunnelMode == "tun" {
                        Text("所有 App 的 TCP / UDP 流量和 DNS 都经过内核（NEPacketTunnelFlow），规则、Fake-IP、MitM 全部可用。")
                    } else {
                        Text("只设置系统 HTTP / HTTPS 代理（指向本机 \(CoreOverrides.load().mixedPort) 端口），不接管路由和 DNS。")
                        Text("取舍：更省电、内存更低；但不遵守系统代理的 App（很多游戏、部分即时通讯、所有 UDP / QUIC）会直连；DNS 由系统解析，按 IP 的规则与 Fake-IP 不生效；MitM 只对走代理的 HTTPS 生效。")
                    }
                    Text("切换后需断开并重新连接。")
                }
            }
            .listRowBackground(Theme.card)

            Section {
                Picker("按需连接", selection: $onDemand.mode) {
                    ForEach(OnDemandSettings.Mode.allCases) { Text($0.title).tag($0) }
                }
                if vpn.onDemandPaused {
                    Label("已暂停：你在 App 里手动断开了。下次手动连接后恢复。", systemImage: "pause.circle")
                        .font(.footnote).foregroundStyle(Theme.warn)
                }
            } header: { Text("按需连接") } footer: {
                Text("由系统在网络变化时自动连接：「始终」任何网络都连接；「仅 Wi-Fi」在蜂窝网络下断开；「仅蜂窝网络」在 Wi-Fi 下断开。在 App 里手动断开会暂停按需连接，直到你再次手动连接。")
            }
            .listRowBackground(Theme.card)

            lanSection

            Section {
                Button { apply() } label: { HStack { Spacer(); Text("保存").bold(); Spacer() } }
                if let status { Text(status).font(.footnote).foregroundStyle(.secondary) }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("连接方式")
        .onAppear { lanAddresses = LANInfo.addresses() }
    }

    var port: Int { CoreOverrides.load().mixedPort }

    var lanSection: some View {
        Section {
            Toggle(isOn: Binding(get: { allowLan }, set: { setLan($0) })) {
                Label("局域网共享", systemImage: "wifi.router")
            }
            if allowLan {
                if lanAddresses.isEmpty {
                    Text("没有检测到 Wi-Fi 或个人热点地址。连上 Wi-Fi（或打开个人热点）后返回此页。").font(.caption).foregroundStyle(Theme.warn)
                }
                ForEach(lanAddresses, id: \.self) { a in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(LocalizedStringKey(a.label)).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                        HStack {
                            Text("\(a.ip):\(String(port))").font(.body.monospaced()).textSelection(.enabled)
                            Spacer()
                            Button { UIPasteboard.general.string = "\(a.ip):\(port)" } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                        }
                        Text("HTTP 与 SOCKS5 代理共用此端口").font(.caption2).foregroundStyle(.secondary)
                    }
                }
                if !vpn.isConnected {
                    Text("连接后生效。").font(.caption).foregroundStyle(.secondary)
                }
                if let lanStatus { Text(lanStatus).font(.caption).foregroundStyle(.secondary) }
            }
        } header: { Text("局域网共享") } footer: {
            Text("开启后，同一 Wi-Fi 或连接本机个人热点的设备，把 HTTP 或 SOCKS5 代理设为上面的地址，就能通过本机的规则和节点上网。iOS 可能在锁屏或 App 长时间处于后台时挂起网络扩展，共享会随之中断；只在可信的网络中开启。")
        }
        .listRowBackground(Theme.card)
    }

    func setLan(_ on: Bool) {
        allowLan = on
        var o = CoreOverrides.load()
        o.allowLan = on
        o.save()
        lanAddresses = LANInfo.addresses()
        lanStatus = nil
        guard vpn.isConnected else { return }
        Task {
            if let e = await vpn.reload() { lanStatus = String(localized: "重载失败：\(e)") }
            else { lanStatus = on ? String(localized: "已开启，正在监听 \(port) 端口") : String(localized: "已关闭") }
        }
    }

    func apply() {
        var o = CoreOverrides.load()
        let modeChanged = o.tunnelMode != tunnelMode
        o.tunnelMode = tunnelMode
        o.save()
        let settings = onDemand
        Task {
            if let e = await vpn.applyOnDemand(settings) {
                status = "按需连接保存失败：\(e)"
            } else if modeChanged && vpn.isConnected {
                status = "已保存。连接方式将在重新连接后生效。"
            } else {
                status = "已保存"
            }
        }
    }
}


/// The phone's LAN addresses other devices can reach (Wi-Fi and Personal Hotspot).
enum LANInfo {
    struct Address: Hashable {
        let iface: String
        let ip: String
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
                if !ip.hasPrefix("169.254.") { out.append(Address(iface: name, ip: ip)) }
            }
        }
        return out
    }
}
