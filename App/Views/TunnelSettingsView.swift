import SwiftUI

/// 更多 → 高级设置 → 隧道 (feat/tunnel-include-options): the NETunnelProviderProtocol scope switches, one section
/// each with its own explanation, modeled on the reference app's 高级设置 → 隧道. The 包含… switches are the inverse of
/// the stored exclude* values (same keys as the old 连接方式 → 隧道范围 switches, so saved choices carry over). The
/// switches keep each other consistent through CoreOverrides.set… (AppShared.swift); FaceTime 走代理 lives here too.
/// Every change is written 0.5 s after the last edit, then into the iOS VPN configuration (VPNManager.applyScope);
/// it takes effect on the next connection.
struct TunnelSettingsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var o = CoreOverrides.load()
    @StateObject private var debounce = Debouncer()
    @State private var status: String?
    @State private var needsReconnect = false

    /// Private ranges 「排除的路由」 keeps out of the tunnel by default (they win over 包含本地网络).
    static let localRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]

    var body: some View {
        Form {
            if o.isProxyOnly {
                Section {
                    Text("当前为「仅代理」模式：以下选项在 TUN 或 VPN 混合模式下生效。")
                        .font(.footnote).foregroundStyle(Theme.warn)
                }
                .listRowBackground(Theme.card)
            }
            includeAllSection
            localSection
            apnsSection
            if #available(iOS 16.4, *) { cellularSection }
            if #available(iOS 17.4, *) { deviceSection }
            enforceRoutesSection
            faceTimeSection
            statusSection
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("隧道")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .onAppear {
            debounce.flush()
            o = CoreOverrides.load()
        }
        .onChange(of: o) { _ in debounce.schedule { apply() } }
        .onDisappear { debounce.flush() }
    }

    // MARK: Sections

    var includeAllSection: some View {
        Section {
            Toggle("包含所有网络", isOn: Binding(get: { o.includeAllShown }, set: { o.setIncludeAllNetworks($0) }))
                .disabled(o.faceTimeProxy)
                .accessibilityIdentifier("tunnel.includeAll")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("开启后可能导致 Tern 连接或重连失败，以及更新 Tern 时卡住（更新前请先断开）；开启时会关闭「兼容性增强模式」，关闭时也会关闭「包含 APNs」。")
                if o.faceTimeProxy {
                    Text("「FaceTime 走代理」开启时始终包含所有网络。")
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    var localSection: some View {
        Section {
            Toggle("包含本地网络", isOn: Binding(get: { o.includeLocalNetworks }, set: { o.excludeLocalNetworks = !$0 }))
                .accessibilityIdentifier("tunnel.includeLocal")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("开启后，发往路由器、NAS、打印机等本地网络地址的流量会进入 Tern 隧道。「排除的路由」优先生效，且默认已包含各私有网段，需在 连接方式 → 路由 →「排除的路由」中一并移除对应的条目。")
                if o.includeLocalNetworks && excludesLocalRanges {
                    Text("「排除的路由」里仍有私有网段，这些地址的流量不会进入隧道。")
                        .foregroundStyle(Theme.warn)
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    var apnsSection: some View {
        Section {
            Toggle("包含 APNs", isOn: Binding(get: { o.includeAPNs }, set: { o.setIncludeAPNs($0) }))
                .accessibilityIdentifier("tunnel.includeAPNs")
        } footer: {
            Text("开启「包含所有网络」时，Apple 推送通知（APNs）默认不经过 Tern；开启本选项后改为按规则分流，通知可能延迟。开启时会同时开启「包含所有网络」。")
        }
        .listRowBackground(Theme.card)
    }

    var cellularSection: some View {
        Section {
            Toggle("包含蜂窝网络服务", isOn: Binding(get: { o.includeCellularServices }, set: { o.excludeCellularServices = !$0 }))
                .accessibilityIdentifier("tunnel.includeCellular")
        } footer: {
            Text("开启后，VoLTE、Wi-Fi 通话、彩信、可视语音信箱等蜂窝服务的流量会进入 Tern 隧道。")
        }
        .listRowBackground(Theme.card)
    }

    var deviceSection: some View {
        Section {
            Toggle("包含设备通信", isOn: Binding(get: { o.includeDeviceCommunication }, set: { o.excludeDeviceCommunication = !$0 }))
                .accessibilityIdentifier("tunnel.includeDevice")
        } footer: {
            Text("开启后，与通过 USB 或 Wi-Fi 连接的设备之间的通信会进入 Tern 隧道。")
        }
        .listRowBackground(Theme.card)
    }

    var enforceRoutesSection: some View {
        Section {
            Toggle("兼容性增强模式", isOn: Binding(get: { o.enforceRoutes && !o.includeAllShown }, set: { o.setEnforceRoutes($0) }))
                .disabled(o.faceTimeProxy)
                .accessibilityIdentifier("tunnel.enforceRoutes")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("使用拆分路由改善 Tern 连接期间的 HomeKit 实时视频兼容性；开启时会关闭「包含所有网络」和「包含 APNs」。")
                if o.faceTimeProxy {
                    Text("需先关闭「FaceTime 走代理」。")
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    var faceTimeSection: some View {
        Section {
            Toggle("FaceTime 走代理", isOn: Binding(get: { o.faceTimeProxy }, set: { o.setFaceTimeProxy($0) }))
                .accessibilityIdentifier("tunnel.facetime")
        } header: { Text(verbatim: "FaceTime") } footer: {
            Text("开启后自动包含所有网络，并把 FaceTime 的音视频（UDP 3478–3497 / 16384–16402）交给主代理组，节点需要支持 UDP。来电响铃走 Apple 推送：「包含 APNs」关闭时这部分直连，开启则也走代理。开启时会关闭「兼容性增强模式」。")
        }
        .listRowBackground(Theme.card)
    }

    @ViewBuilder var statusSection: some View {
        if status != nil || (needsReconnect && vpn.isConnected) {
            Section {
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

    // MARK: Helpers

    var excludesLocalRanges: Bool {
        let ex = Set(o.excludedRoutes.map { $0.trimmingCharacters(in: .whitespaces) })
        return Self.localRanges.contains { ex.contains($0) }
    }

    func apply() {
        // Only this page's fields; everything else stays as the other pages saved it.
        var cur = CoreOverrides.load()
        let old = cur
        cur.includeAllNetworks = o.includeAllNetworks
        cur.excludeLocalNetworks = o.excludeLocalNetworks
        cur.excludeAPNs = o.excludeAPNs
        cur.excludeCellularServices = o.excludeCellularServices
        cur.excludeDeviceCommunication = o.excludeDeviceCommunication
        cur.enforceRoutes = o.enforceRoutes
        cur.faceTimeProxy = o.faceTimeProxy
        // r7 R7A-2: nothing changed, but the VPN configuration may still carry another scope — re-apply it then.
        guard cur != old else {
            Task {
                if await vpn.syncTunnelScope() {
                    status = vpn.isConnected ? String(localized: "隧道范围已同步，重新连接后生效") : String(localized: "隧道范围已同步")
                }
            }
            return
        }
        cur.save()
        Task {
            if let e = await vpn.applyTunnelScope() {
                status = String(localized: "隧道范围保存失败：\(e)")
                return
            }
            if vpn.isConnected {
                needsReconnect = true
                status = String(localized: "已保存。隧道设置在重新连接后生效。")
            } else {
                status = String(localized: "已保存")
            }
        }
    }
}
