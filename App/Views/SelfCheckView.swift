import SwiftUI

/// 设置 → 诊断与反馈 → 一键自检 (feat/nc-e2e): runs SelfCheck step by step with live status, then offers the
/// 诊断包 (selfcheck.txt first). In the simulator every step that needs the VPN shows 「需要真机」.
struct SelfCheckView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var check = SelfCheck()
    @State private var share: ShareItem?

    var body: some View {
        List {
            Section {
                Button {
                    Task { await check.run(vpn: vpn) }
                } label: {
                    HStack {
                        Label(check.finished ? LocalizedStringKey("再次自检") : LocalizedStringKey("开始自检"), systemImage: "stethoscope").font(.body.weight(.semibold))
                        Spacer()
                        if check.running { ProgressView() }
                    }
                }
                .disabled(check.running)
                .accessibilityIdentifier("selfcheck.run")
            } footer: {
                Text("依次检查：启动 VPN、内核接口、加载数量、策略组测延迟、经隧道访问网址、MitM 与证书信任、脚本日志、断开重连后的 Fake-IP。会断开并重新连接 VPN 两次。")
            }
            .listRowBackground(Theme.card)

            Section {
                ForEach(check.steps) { s in
                    HStack(alignment: .top, spacing: 10) {
                        icon(s.state).frame(width: 22)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(verbatim: s.title).font(.subheadline.weight(.semibold))
                            if !s.detail.isEmpty {
                                Text(verbatim: s.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("selfcheck.step.\(s.id)")
                }
            } header: { Text("步骤") }
            .listRowBackground(Theme.card)

            if check.finished {
                Section {
                    Text(verbatim: check.summaryLine).font(.subheadline.weight(.semibold))
                        .accessibilityIdentifier("selfcheck.summary")
                    if let url = check.bundleURL {
                        Button { share = ShareItem(url: url) } label: {
                            Label("分享诊断包", systemImage: "square.and.arrow.up")
                        }
                        .accessibilityIdentifier("selfcheck.share")
                    }
                    if let e = check.bundleError { ErrorRow(message: e) }
                } header: { Text("结果") } footer: {
                    Text("诊断包里的 selfcheck.txt 是这次自检的结果，服务器地址、密码和订阅链接已脱敏。")
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("一键自检")
        .sheet(item: $share) { ActivityView(items: [$0.url]) }
    }

    @ViewBuilder private func icon(_ st: SelfCheck.State) -> some View {
        switch st {
        case .pending: Image(systemName: "circle").foregroundStyle(.secondary)
        case .running: ProgressView()
        case .pass: Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.good)
        case .fail: Image(systemName: "xmark.octagon.fill").foregroundStyle(Theme.bad)
        case .skip: Image(systemName: "minus.circle").foregroundStyle(.secondary)
        case .needsDevice: Image(systemName: "iphone").foregroundStyle(.secondary)
        }
    }
}
