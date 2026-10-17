import SwiftUI
import UniformTypeIdentifiers

// QX preview 5: first run and the no-profile state in QX style. A welcome page (spinning windmill, what is
// new compared with Quantumult X: new protocols, widgets, no resource parser), the four import entry points
// (订阅链接 / 粘贴 / 文件 / 二维码) that the empty 节点 panel shows too, then the VPN permission.

/// The four ways in, as QX colour capsules. Everything ends in the shared import flow (ImportRouter) or in
/// ProfileStore.addRemote, so a QX / Surge config, a module or node links all land where they belong.
struct QXImportEntries: View {
    var columns = 2
    var onImported: ((String) -> Void)? = nil
    @EnvironmentObject var store: ProfileStore
    @State private var askURL = false
    @State private var url = ""
    @State private var importing = false
    @State private var scanning = false
    @State private var busy = false
    @State private var message: String?
    @State private var isError = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            QXActionGrid(color: QXColor.nodes, items: [
                QXActionSpec(title: String(localized: "订阅链接"), icon: "link.badge.plus") { askURL = true },
                QXActionSpec(title: String(localized: "从剪贴板"), icon: "doc.on.clipboard") { pasteboard() },
                QXActionSpec(title: String(localized: "从文件"), icon: "folder") { importing = true },
                QXActionSpec(title: String(localized: "扫描二维码"), icon: "qrcode.viewfinder") { scanning = true },
            ], columns: columns)
            if busy {
                HStack(spacing: 8) { ProgressView(); Text("正在导入…").font(.footnote).foregroundStyle(.secondary) }
            } else if let message {
                Label(message, systemImage: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.footnote).foregroundStyle(isError ? QXColor.danger : QXColor.success)
            }
        }
        .alert("订阅链接", isPresented: $askURL) {
            TextField("https://…", text: $url)
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            Button("取消", role: .cancel) { url = "" }
            Button("添加") { Task { await addURL(url) } }
        } message: {
            Text("Clash / mihomo 订阅、Quantumult X 或 Surge 配置链接、节点订阅都可以，格式会自动识别。")
        }
        .onChange(of: importing) { on in
            // v0.13.1 / QX preview 6: UIKit document picker in copy mode (every file selectable), read before presenting.
            guard on else { return }
            importing = false
            ImportRouter.shared.pickFile()
        }
        .sheet(isPresented: $scanning) {
            QRScannerSheet { code in
                scanning = false
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { route(code) }
            }
        }
    }

    private func pasteboard() {
        guard let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else {
            show(String(localized: "剪贴板为空"), error: true)
            return
        }
        route(s)
    }

    private func route(_ s: String) {
        if !s.contains("\n"), !s.contains(" "), s.hasPrefix("http://") || s.hasPrefix("https://"),
           ImportRouter.route(text: s).map({ if case .profileURL = $0 { return true } else { return false } }) ?? true {
            Task { await addURL(s) }
            return
        }
        ImportRouter.shared.handle(pasted: s)
    }

    private func addURL(_ raw: String) async {
        let u = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        url = ""
        guard u.lowercased().hasPrefix("http") else { show(String(localized: "链接无效"), error: true); return }
        busy = true
        defer { busy = false }
        do {
            let p = try await store.addRemote(url: u, name: "", userAgent: "clash.meta", intervalHours: 24)
            show(String(localized: "已添加订阅：") + p.name, error: false)
            QXHaptics.success()
            onImported?(p.name)
        } catch {
            QXHaptics.warning()
            show(error.localizedDescription, error: true)
        }
    }

    private func show(_ t: String, error: Bool) {
        withAnimation(QXMotion.snappy) { message = t; isError = error }
    }
}

/// Shown in the 节点 panel while there is no profile (QX: an empty home with the import entry points).
struct QXEmptyProfileCard: View {
    @EnvironmentObject var nav: QXNavigator
    var body: some View {
        QXCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    QXSpinningWindmill(mode: "rule", size: 38, spinning: true, speed: 0.25)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("还没有配置").font(.system(size: 20, weight: .bold))
                        Text("导入订阅或配置后，节点和策略会显示在这里。").font(.system(size: 14)).foregroundStyle(.secondary)
                    }
                }
                QXImportEntries()
                HStack(spacing: 10) {
                    QXPill(title: String(localized: "示例配置")) { nav.present(.sample) }
                    QXPill(title: String(localized: "新手引导")) { nav.present(.onboarding) }
                }
            }
            .padding(16)
        }
    }
}

/// First run (and 设置 → 新手引导): QX-style welcome.
struct QXWelcomeView: View {
    let onFinish: () -> Void
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @State private var vpnBusy = false
    @State private var vpnMessage: String?
    @Environment(\.horizontalSizeClass) private var hSize

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack {
                    Spacer()
                    Button("跳过") { finish() }.font(.system(size: 16)).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 12) {
                    QXSpinningWindmill(mode: "rule", size: 64, spinning: true, speed: 0.3)
                        .frame(width: 92, height: 92)
                        .background(Circle().fill(QXPalette.chrome))
                        .overlay(Circle().stroke(QXPalette.hairline, lineWidth: 1))
                    Text("欢迎使用 Mihomo").font(.system(size: 30, weight: .bold))
                    Text("Quantumult X 的界面，mihomo 内核。下面三点是和 QX 不一样的地方。")
                        .font(.system(size: QXMetrics.caption)).foregroundStyle(.secondary).lineSpacing(3)
                }
                VStack(spacing: 10) {
                    highlight(icon: "sparkles", color: QXColor.nodes, title: String(localized: "新协议优先"),
                              text: String(localized: "VLESS Reality / Vision、Hysteria2、TUIC v5、AnyTLS、ShadowTLS、WireGuard、Mieru、Snell…内核每日跟进上游；「添加 → 节点」按协议选择。"))
                    highlight(icon: "square.grid.2x2.fill", color: QXColor.rewrite, title: String(localized: "小组件与实时活动"),
                              text: String(localized: "主屏幕、锁屏、控制中心开关和灵动岛：长按主屏幕 → 左上角 ＋ → 搜索 Mihomo；实时活动在 设置 → 其他设置 → 通知 中打开。"))
                    highlight(icon: "wand.and.stars", color: QXColor.mitm, title: String(localized: "不需要资源解析器"),
                              text: String(localized: "Clash YAML、分享链接、Base64、SIP008、sing-box JSON、Surge / QX / Loon 节点行都能直接识别。"))
                }
                VStack(alignment: .leading, spacing: 10) {
                    Text("导入配置").font(.system(size: QXMetrics.largeTitle, weight: .bold))
                    if let p = store.active ?? store.profiles.first {
                        Label { Text("已有配置：\(p.name)") } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(QXColor.success) }
                            .font(.system(size: 15))
                    }
                    QXImportEntries(columns: hSize == .regular ? 4 : 2)
                }
                VStack(alignment: .leading, spacing: 10) {
                    Text("允许 VPN 配置").font(.system(size: QXMetrics.largeTitle, weight: .bold))
                    Text("Mihomo 通过系统的 VPN（网络扩展）接管流量。点下面的按钮后，iOS 会询问是否「添加 VPN 配置」，选择「允许」。")
                        .font(.system(size: QXMetrics.caption)).foregroundStyle(.secondary).lineSpacing(3)
                    if vpn.hasConfiguration {
                        Label("已添加 VPN 配置", systemImage: "checkmark.circle.fill").foregroundStyle(QXColor.success).font(.system(size: 15))
                    } else {
                        QXActionGrid(color: QXColor.switchOn, items: [
                            QXActionSpec(title: vpnBusy ? String(localized: "请稍候…") : String(localized: "允许添加 VPN 配置"), icon: "lock.shield") {
                                guard !vpnBusy else { return }
                                Task {
                                    vpnBusy = true
                                    defer { vpnBusy = false }
                                    vpnMessage = await vpn.installConfiguration()
                                }
                            },
                        ], columns: 1)
                        if let vpnMessage { Text(verbatim: vpnMessage).font(.footnote).foregroundStyle(QXColor.danger) }
                    }
                }
                Button { finish() } label: {
                    Text("开始使用").font(.system(size: 18, weight: .semibold)).foregroundStyle(Color(UIColor.systemBackground))
                        .frame(maxWidth: .infinity, minHeight: 56)
                        .background(Capsule().fill(Color.primary))
                }
                .buttonStyle(QXPressStyle(scale: 0.97, haptic: true))
                .padding(.top, 4)
            }
            .padding(.horizontal, QXMetrics.inset + 4)
            .padding(.vertical, 20)
            .frame(maxWidth: 620)
            .frame(maxWidth: .infinity)
        }
        .background(QXPalette.bg.ignoresSafeArea())
    }

    private func highlight(icon: String, color: Color, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon).font(.system(size: 20, weight: .semibold)).foregroundStyle(.white)
                .frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 13, style: .continuous).fill(color))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(verbatim: title).font(.system(size: 17, weight: .semibold))
                    QXChip(text: String(localized: "新"), color: color)
                }
                Text(verbatim: text).font(.system(size: 14)).foregroundStyle(.secondary).lineSpacing(2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: QXMetrics.cardRadius, style: .continuous).fill(QXPalette.card))
        .accessibilityElement(children: .combine)
    }

    private func finish() {
        Onboarding.isDone = true
        onFinish()
    }
}
