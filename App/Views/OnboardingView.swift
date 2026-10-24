import SwiftUI

/// First run: three short steps in the project's dark cards — import a profile, allow the VPN
/// configuration, optionally install the MitM certificate. Every step can be skipped; 更多 → 关于 can
/// show it again.
enum Onboarding {
    private static let key = "onboardingDone.v1"
    static var isDone: Bool {
        get { UserDefaults.standard.bool(forKey: key) }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }
}

struct OnboardingView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @ObservedObject var engine = EngineStore.shared
    let onFinish: () -> Void

    @State private var step = 0
    @State private var url = ""
    @State private var busy = false
    @State private var message: String?
    @State private var isError = false
    @State private var showSample = false

    private let steps = 3

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                StepDots(count: steps, current: step)
                Spacer()
                Button("跳过") { finish() }
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch step {
                    case 0: profileStep
                    case 1: vpnStep
                    default: certStep
                    }
                    if let message {
                        if isError { ErrorRow(message: message) } else {
                            Label(message, systemImage: "checkmark.circle.fill").font(.footnote).foregroundStyle(Theme.good)
                        }
                    }
                }
                .padding(20)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
            }

            HStack(spacing: 12) {
                if step > 0 {
                    Button { go(step - 1) } label: {
                        Text("上一步").frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .buttonStyle(.bordered)
                }
                Button {
                    if step < steps - 1 { go(step + 1) } else { finish() }
                } label: {
                    Text(step < steps - 1 ? "下一步" : "开始使用").bold().frame(maxWidth: .infinity).padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(20)
            .frame(maxWidth: 560)
        }
        .background(Theme.bg.ignoresSafeArea())
        .tint(Theme.accent)
        .interactiveDismissDisabled(busy)
    }

    // MARK: Steps

    private var profileStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepHeader(icon: "doc.badge.plus", title: "导入配置", text: "粘贴订阅链接，或从剪贴板导入配置 / 节点链接。也可以稍后在「更多 → 配置」添加。")
            if let p = store.active ?? store.profiles.first {
                Card { Label { Text("已有配置：\(p.name)") } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.good) } }
            }
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    TextField("https://… 订阅链接", text: $url)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
                    HStack(spacing: 12) {
                        Button {
                            Task { await addURL() }
                        } label: {
                            HStack {
                                if busy { ProgressView() }
                                Text("添加订阅").bold()
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy || !url.lowercased().hasPrefix("http"))
                        Spacer(minLength: 0)
                        PasteButton(payloadType: String.self) { items in
                            guard let text = items.first else { return }
                            Task { await importPasted(text) }
                        }
                        .labelStyle(.titleAndIcon)
                        .buttonBorderShape(.capsule)
                        .disabled(busy)
                    }
                }
            }
            Button { showSample = true } label: {
                Label("还不熟悉配置写法？看看示例配置", systemImage: "text.book.closed").font(.footnote.weight(.semibold))
            }
            .accessibilityIdentifier("onboarding.sample")
            .sheet(isPresented: $showSample) {
                NavigationStack {
                    SampleProfileView()
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { showSample = false } } }
                }
                .environmentObject(store)
            }
        }
    }

    private var vpnStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepHeader(icon: "lock.shield", title: "允许 VPN 配置", text: "Tern 通过系统的 VPN（网络扩展）接管流量。点下面的按钮后，iOS 会询问是否「添加 VPN 配置」，选择「允许」并验证面容 / 密码。")
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    if vpn.hasConfiguration {
                        Label("已添加 VPN 配置", systemImage: "checkmark.circle.fill").foregroundStyle(Theme.good)
                    } else {
                        Button {
                            Task {
                                busy = true
                                defer { busy = false }
                                if let err = await vpn.installConfiguration() { show(err, error: true) } else { show(String(localized: "已添加 VPN 配置"), error: false) }
                            }
                        } label: {
                            HStack {
                                if busy { ProgressView() }
                                Text("允许添加 VPN 配置").bold()
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    }
                    Text("只在你打开开关时连接；配置和日志都保存在本机。").font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var certStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepHeader(icon: "lock.open", title: "MitM 证书（可选）", text: "只有用到 HTTPS 重写、脚本或 BoxJS 时才需要。证书在本机生成，私钥不会离开这台设备。")
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    if engine.caInfo.exists {
                        Label(engine.caTrusted == true ? "证书已安装并完全信任" : "证书已生成", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(engine.caTrusted == true ? Theme.good : Theme.warn)
                    }
                    Button {
                        if !engine.caInfo.exists { engine.generateCA() }
                        if engine.caInfo.exists { engine.installViaSafari() }
                    } label: {
                        Text(engine.caInfo.exists ? "安装证书（通过 Safari）" : "生成并安装证书").bold()
                    }
                    .buttonStyle(.borderedProminent)
                    VStack(alignment: .leading, spacing: 6) {
                        StepLine(n: 1, text: "Safari 提示下载描述文件时选「允许」")
                        StepLine(n: 2, text: "设置 → 已下载描述文件 → 安装")
                        StepLine(n: 3, text: "设置 → 通用 → 关于本机 → 证书信任设置 → 打开完全信任")
                    }
                    Text("不需要的话直接点「开始使用」，以后在 工具 → HTTPS 解密 中设置。").font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .task { await engine.refreshCAInBackground() } // fix/nav-jank: off main
    }

    // MARK: Actions

    private func go(_ s: Int) {
        message = nil
        withAnimation(.easeInOut(duration: 0.2)) { step = s }
    }

    private func finish() {
        Onboarding.isDone = true
        onFinish()
    }

    private func show(_ text: String, error: Bool) {
        message = text
        isError = error
    }

    private func addURL() async {
        busy = true
        defer { busy = false }
        do {
            let p = try await store.addRemote(url: url, name: "", userAgent: "clash.meta", intervalHours: 24)
            show(String(localized: "已添加订阅：") + p.name, error: false)
            url = ""
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func importPasted(_ raw: String) async {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { show(String(localized: "剪贴板为空"), error: true); return }
        if !s.contains("\n"), !s.contains(" "), s.hasPrefix("http://") || s.hasPrefix("https://") {
            url = s
            await addURL()
            return
        }
        // Surge / QX configs, modules and import links go through the shared import sheet (v0.8.1), which
        // presents over this onboarding cover and explains anything it cannot import.
        if let a = ImportRouter.route(text: s) {
            switch a {
            case .nodesText, .profileURL: break
            default:
                await MainActor.run { ImportRouter.shared.run(a) }
                return
            }
        }
        busy = true
        defer { busy = false }
        do {
            if s.contains("proxies:") || s.contains("proxy-providers:") {
                let p = try await store.addLocal(name: String(localized: "剪贴板导入"), text: s)
                show(String(localized: "已导入配置：") + p.name, error: false)
            } else {
                let n = try await store.addManualNodes(text: s)
                show(String(localized: "已添加 \(n) 个节点到「本地节点」"), error: false)
            }
        } catch {
            show(error.localizedDescription, error: true)
        }
    }
}

private struct StepHeader: View {
    let icon: String
    let title: String
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: icon)
                .font(.title2.weight(.semibold))
                .foregroundStyle(Theme.accent)
                .frame(width: 52, height: 52)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Theme.accent.opacity(0.14)))
                .accessibilityHidden(true)
            Text(LocalizedStringKey(title)).font(.title2.weight(.bold))
            Text(LocalizedStringKey(text)).font(.subheadline).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 8)
    }
}

private struct StepLine: View {
    let n: Int
    let text: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(n)").font(.caption.weight(.bold).monospacedDigit()).foregroundStyle(Theme.accent)
                .frame(minWidth: 18)
            Text(LocalizedStringKey(text)).font(.footnote).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct StepDots: View {
    let count: Int
    let current: Int
    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<count, id: \.self) { i in
                Capsule()
                    .fill(i == current ? Theme.accent : Theme.ink(0.2))
                    .frame(width: i == current ? 22 : 8, height: 8)
            }
        }
        .accessibilityElement()
        .accessibilityLabel(Text("第 \(current + 1) 步，共 \(count) 步"))
        .animation(.easeInOut(duration: 0.2), value: current)
    }
}
