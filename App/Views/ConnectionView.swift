import SwiftUI

/// 连接方式与按需连接: tunnel mode (packet tunnel vs proxy-only) and NEOnDemandRules.
struct ConnectionView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var tunnelMode = CoreOverrides.load().tunnelMode
    @State private var onDemand = OnDemandSettings.load()
    @State private var newSSID = ""
    @State private var status: String?

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
                if onDemand.mode != .off && onDemand.mode != .cellular {
                    ForEach(onDemand.excludedSSIDs, id: \.self) { Text($0) }
                        .onDelete { onDemand.excludedSSIDs.remove(atOffsets: $0) }
                    HStack {
                        TextField("不自动连接的 Wi-Fi 名称（SSID）", text: $newSSID).autocorrectionDisabled()
                        Button {
                            let t = newSSID.trimmingCharacters(in: .whitespaces)
                            if !t.isEmpty, !onDemand.excludedSSIDs.contains(t) { onDemand.excludedSSIDs.append(t) }
                            newSSID = ""
                        } label: { Image(systemName: "plus.circle.fill") }
                    }
                }
            } header: { Text("按需连接") } footer: {
                Text("由系统在网络变化时自动连接：「始终」任何网络都连接；「仅 Wi-Fi」在蜂窝网络下断开；「仅蜂窝网络」在 Wi-Fi 下断开；列出的 Wi-Fi 上不连接（例如家里）。在 App 里手动断开会暂停按需连接，直到你再次手动连接。")
            }
            .listRowBackground(Theme.card)

            Section {
                Button { apply() } label: { HStack { Spacer(); Text("保存").bold(); Spacer() } }
                if let status { Text(status).font(.footnote).foregroundStyle(.secondary) }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("连接方式")
    }

    func apply() {
        var o = CoreOverrides.load()
        let modeChanged = o.tunnelMode != tunnelMode
        o.tunnelMode = tunnelMode
        o.save()
        Task {
            if let e = await vpn.applyOnDemand(onDemand) {
                status = "按需连接保存失败：\(e)"
            } else if modeChanged && vpn.isConnected {
                status = "已保存。连接方式将在重新连接后生效。"
            } else {
                status = "已保存"
            }
        }
    }
}
