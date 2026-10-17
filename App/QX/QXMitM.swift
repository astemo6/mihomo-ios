import SwiftUI
import UniformTypeIdentifiers

// QX-3: MitM in QX chrome. 主机名 list, 证书 buttons that open QX-style action sheets with a status-tinted
// header (生成证书: red when a CA already exists; 配置证书: green when installed + trusted, orange when not),
// advanced engine switches. The same sheets are used from the 设置 page's MitM buttons.

enum QXCertSheet: String, Identifiable {
    case generate, configure
    var id: String { rawValue }
}

/// A QX action sheet: a card with a tinted header (title + message) and actions, then a separate 取消 card.
struct QXTintedActionSheet: View {
    struct Action: Identifiable {
        let id = UUID()
        let title: String
        var destructive = false
        let run: () -> Void
    }

    let tint: Color
    let title: String
    let message: String
    let actions: [Action]
    let onCancel: () -> Void

    var body: some View {
        ZStack(alignment: .bottom) {
            Color.black.opacity(0.28).ignoresSafeArea()
                .onTapGesture(perform: onCancel)
            VStack(spacing: 8) {
                VStack(spacing: 0) {
                    VStack(spacing: 8) {
                        Text(verbatim: title).font(.system(size: 15, weight: .semibold)).foregroundStyle(tint)
                            .multilineTextAlignment(.center)
                        Text(verbatim: message).font(.system(size: 14)).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal, 18).padding(.vertical, 16)
                    .frame(maxWidth: .infinity)
                    ForEach(actions) { a in
                        Divider()
                        Button {
                            onCancel()
                            a.run()
                        } label: {
                            Text(verbatim: a.title).font(.system(size: 19))
                                .foregroundStyle(a.destructive ? QXColor.red : QXColor.switchOn)
                                .frame(maxWidth: .infinity, minHeight: 56)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.regularMaterial)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .fill(LinearGradient(colors: [tint.opacity(0.22), tint.opacity(0.06)], startPoint: .top, endPoint: .bottom))
                        )
                )
                Button(action: onCancel) {
                    Text("取消").font(.system(size: 19, weight: .semibold)).foregroundStyle(QXColor.switchOn)
                        .frame(maxWidth: .infinity, minHeight: 56)
                        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(QXPalette.card))
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 10)
            .padding(.bottom, 8)
            .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}

/// Attaches the 生成证书 / 配置证书 sheets plus the p12 / share / import flows they need.
struct QXCertSheets: ViewModifier {
    @Binding var sheet: QXCertSheet?
    @ObservedObject private var store = EngineStore.shared
    @State private var share: ShareItem?
    @State private var askP12 = false
    @State private var p12Password = ""
    @State private var importing = false
    @State private var importURL: URL?
    @State private var importPassword = ""
    @State private var askImportPassword = false
    @State private var confirmRegen = false

    var caTitle: String {
        let subject = store.caInfo.subject ?? "Mihomo MitM CA"
        if let d = store.caInfo.notAfter, !d.isEmpty { return "\(subject) (\(d))" }
        return subject
    }

    func body(content: Content) -> some View {
        content
            .overlay {
                if let s = sheet {
                    sheetView(s).zIndex(10)
                }
            }
            .animation(.spring(response: 0.32, dampingFraction: 0.9), value: sheet)
            .sheet(item: $share) { ActivityView(items: [$0.url]) }
            .alert("导出 p12", isPresented: $askP12) {
                SecureField("设置密码", text: $p12Password)
                Button("导出") { if let u = store.p12File(password: p12Password) { share = ShareItem(url: u) }; p12Password = "" }
                Button("取消", role: .cancel) { p12Password = "" }
            } message: { Text("p12 包含私钥，请妥善保管，切勿分享给他人。") }
            .fileImporter(isPresented: $importing, allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data, .data]) { r in
                if case .success(let u) = r { importURL = u; askImportPassword = true }
            }
            .alert("导入 p12", isPresented: $askImportPassword) {
                SecureField("密码", text: $importPassword)
                Button("导入") { if let u = importURL { store.importP12(u, password: importPassword) }; importPassword = "" }
                Button("取消", role: .cancel) { importPassword = "" }
            }
            .confirmationDialog("重新生成证书？", isPresented: $confirmRegen, titleVisibility: .visible) {
                Button("重新生成", role: .destructive) { store.generateCA() }
            } message: { Text("旧证书将失效，需要重新安装并信任新的描述文件。") }
            .alert("提示", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
                Button("好") { store.message = nil }
            } message: { Text(store.message ?? "") }
            .onChange(of: sheet) { s in if s != nil { store.refreshCA() } }
    }

    @ViewBuilder func sheetView(_ s: QXCertSheet) -> some View {
        let close = { sheet = nil }
        switch s {
        case .generate:
            if store.caInfo.exists {
                QXTintedActionSheet(
                    tint: QXColor.red, title: caTitle,
                    message: String(localized: "已存在有效的证书，无需重新生成。重新生成后旧证书立即失效，需要重新安装并信任新的描述文件；也可以从 p12 备份恢复原来的证书。"),
                    actions: [
                        .init(title: String(localized: "重新生成"), destructive: true) { confirmRegen = true },
                        .init(title: String(localized: "从 p12 导入")) { importing = true },
                    ],
                    onCancel: close)
            } else {
                QXTintedActionSheet(
                    tint: QXColor.mitm, title: String(localized: "生成 CA 证书"),
                    message: String(localized: "证书与私钥只保存在本机 App Group 容器内。生成后到「配置证书」安装并信任。"),
                    actions: [
                        .init(title: String(localized: "生成证书")) { store.generateCA(); sheet = .configure },
                        .init(title: String(localized: "从 p12 导入")) { importing = true },
                    ],
                    onCancel: close)
            }
        case .configure:
            if !store.caInfo.exists {
                QXTintedActionSheet(
                    tint: QXColor.warning, title: String(localized: "尚未生成证书"),
                    message: String(localized: "请先生成证书，再安装并信任。"),
                    actions: [.init(title: String(localized: "生成证书")) { store.generateCA(); sheet = .configure }],
                    onCancel: close)
            } else if store.caTrusted == true {
                QXTintedActionSheet(
                    tint: QXColor.mitm, title: caTitle,
                    message: String(localized: "1、证书已安装。\n2、证书已信任。\n\n如需在其他设备上使用（例如 Apple Watch），请点「下载证书」或分享描述文件。"),
                    actions: [
                        .init(title: String(localized: "下载证书")) { store.installViaSafari() },
                        .init(title: String(localized: "导出证书")) { if let u = store.certFile() { share = ShareItem(url: u) } },
                        .init(title: String(localized: "导出 p12（含私钥）")) { askP12 = true },
                    ],
                    onCancel: close)
            } else {
                QXTintedActionSheet(
                    tint: QXColor.warning, title: caTitle,
                    message: String(localized: "1、点「下载证书」，在 Safari 中允许下载描述文件，然后打开 设置 → 已下载描述文件 → 安装。\n2、打开 设置 → 通用 → 关于本机 → 证书信任设置，打开此证书的完全信任。\n\n完成后回到本页，状态会变为已信任。"),
                    actions: [
                        .init(title: String(localized: "下载证书")) { store.installViaSafari() },
                        .init(title: String(localized: "分享描述文件")) { if let u = store.mobileConfigFile() { share = ShareItem(url: u) } },
                        .init(title: String(localized: "导出证书")) { if let u = store.certFile() { share = ShareItem(url: u) } },
                    ],
                    onCancel: close)
            }
        }
    }
}

extension View {
    func qxCertSheets(_ sheet: Binding<QXCertSheet?>) -> some View { modifier(QXCertSheets(sheet: sheet)) }
}

// MARK: - MitM page

struct QXMitMView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var store = EngineStore.shared
    @State private var newHost = ""
    @State private var certSheet: QXCertSheet?
    @State private var status: MitMStatus?
    @State private var showModuleHosts = false

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "record.circle") { nav.push(.dest(.httpCapture)) }
                    .accessibilityLabel(Text("HTTP 抓取"))
                QXBarIcon(systemName: "slider.horizontal.3") { nav.push(.dest(.mitmAdvanced)) }
                    .accessibilityLabel(Text("高级"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(verbatim: "MitM").font(.system(size: QXMetrics.largeTitle, weight: .bold))
                        Text(verbatim: "\(store.config.hostnames.count + store.moduleHostnames.count)").font(.system(size: 17)).foregroundStyle(.secondary)
                        Spacer()
                        Toggle("", isOn: Binding(get: { store.config.mitm }, set: { store.config.mitm = $0; store.save() }))
                            .labelsHidden().tint(QXColor.mitm)
                            .disabled(!store.caInfo.exists)
                            .accessibilityLabel(Text("MitM"))
                    }
                    Text("MitM 根证书用于 HTTPS 解析。只有配置了主机名的请求才会被解析，主机名按加载顺序匹配：先本地，再按模块顺序。")
                        .font(.system(size: 16)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

                    certCard
                    QXActionGrid(color: QXColor.mitm, items: [
                        QXActionSpec(title: String(localized: "生成证书"), icon: "person.text.rectangle") { certSheet = .generate },
                        QXActionSpec(title: String(localized: "配置证书"), icon: "gearshape.2") { certSheet = .configure },
                    ])

                    hostSection
                    if !store.moduleHostnames.isEmpty { moduleHostSection }
                    optionsSection
                    if let s = status, vpn.isConnected { statusSection(s) }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 60)
            }
        }
        .qxCertSheets($certSheet)
        .onAppear { store.refreshCA() }
        .task { if vpn.isConnected { status = try? await ControllerClient.shared.mitmStatus() } }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in store.refreshCA() }
    }

    var certCard: some View {
        let trusted = store.caTrusted == true
        let tint: Color = !store.caInfo.exists ? Color.secondary : (trusted ? QXColor.mitm : QXColor.warning)
        return QXCard {
            HStack(spacing: 14) {
                Image(systemName: !store.caInfo.exists ? "seal" : (trusted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"))
                    .font(.system(size: 26)).foregroundStyle(tint).frame(width: 34)
                VStack(alignment: .leading, spacing: 3) {
                    Text(verbatim: store.caInfo.exists ? (store.caInfo.subject ?? "CA") : String(localized: "尚未生成证书"))
                        .font(.system(size: 17, weight: .semibold)).lineLimit(1)
                    Text(!store.caInfo.exists ? LocalizedStringKey("点「生成证书」创建本机专用的根证书。")
                         : (trusted ? LocalizedStringKey("已安装并完全信任") : LocalizedStringKey("未信任：点「配置证书」查看安装步骤")))
                        .font(.footnote).foregroundStyle(tint)
                    if store.caInfo.exists, let d = store.caInfo.notAfter, !d.isEmpty {
                        Text("有效期至 \(d)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
                Button { store.refreshCA() } label: { Image(systemName: "arrow.clockwise").font(.system(size: 15, weight: .semibold)) }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel(Text("刷新"))
            }
            .padding(16)
        }
    }

    var hostSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("主机名").font(.system(size: 24, weight: .bold))
                Text(verbatim: "\(store.config.hostnames.count)").font(.system(size: 15)).foregroundStyle(.secondary)
                Spacer()
                QXPill(title: String(localized: "粘贴")) {
                    newHost = (UIPasteboard.general.string ?? "").replacingOccurrences(of: "hostname", with: "")
                        .replacingOccurrences(of: "=", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
            QXCard {
                VStack(spacing: 0) {
                    ForEach(Array(store.config.hostnames.enumerated()), id: \.element) { i, h in
                        if i > 0 { Divider().padding(.leading, 16) }
                        HStack {
                            Text(verbatim: h).font(.system(size: 16, design: .monospaced)).lineLimit(1)
                                .foregroundStyle(h.hasPrefix("-") ? Color.secondary : Color.primary)
                            Spacer()
                            if h.hasPrefix("-") { QXChip(text: String(localized: "排除"), color: Color.secondary, filled: false) }
                            if h == "*" { QXChip(text: String(localized: "全部"), color: QXColor.warning, filled: false) }
                        }
                        .padding(.horizontal, 16).padding(.vertical, 13)
                        .contentShape(Rectangle())
                        .contextMenu {
                            Button { UIPasteboard.general.string = h } label: { Label("拷贝", systemImage: "doc.on.doc") }
                            if i > 0 {
                                Button { move(i, by: -1) } label: { Label("上移", systemImage: "arrow.up") }
                            }
                            if i < store.config.hostnames.count - 1 {
                                Button { move(i, by: 1) } label: { Label("下移", systemImage: "arrow.down") }
                            }
                            Button {
                                let x = h.hasPrefix("-") ? String(h.dropFirst()) : "-" + h
                                store.config.hostnames[i] = x
                                store.save()
                            } label: { Label(h.hasPrefix("-") ? LocalizedStringKey("取消排除") : LocalizedStringKey("改为排除"), systemImage: "minus.circle") }
                            Button(role: .destructive) {
                                store.config.hostnames.remove(at: i)
                                store.save()
                            } label: { Label("删除", systemImage: "trash") }
                        }
                    }
                    if !store.config.hostnames.isEmpty { Divider().padding(.leading, 16) }
                    HStack(spacing: 10) {
                        TextField("example.com、*.example.com、-排除.com", text: $newHost)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(.system(size: 15, design: .monospaced))
                            .onSubmit(addHost)
                        QXPill(title: String(localized: "添加"), action: addHost)
                            .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 10)
                }
            }
            Text("通配符 * 和 ? 可用于主机名，前缀 - 用来排除某主机名，例如 -*.io 或 *.exa?ple.com；单独的 * 匹配所有主机名。可一次粘贴多个，用逗号分隔。长按条目可排序或删除。")
                .font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
        }
    }

    var moduleHostSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button { withAnimation(.spring(response: 0.3)) { showModuleHosts.toggle() } } label: {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("来自模块").font(.system(size: 24, weight: .bold)).foregroundStyle(.primary)
                    Text(verbatim: "\(store.moduleHostnames.count)").font(.system(size: 15)).foregroundStyle(.secondary)
                    Image(systemName: showModuleHosts ? "arrowtriangle.down.fill" : "arrowtriangle.right.fill")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(.primary)
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            if showModuleHosts {
                QXCard {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(store.moduleHostnames.prefix(400).enumerated()), id: \.offset) { i, h in
                            if i > 0 { Divider().padding(.leading, 16) }
                            Text(verbatim: h).font(.system(size: 14, design: .monospaced)).foregroundStyle(.secondary)
                                .lineLimit(1).padding(.horizontal, 16).padding(.vertical, 10)
                        }
                    }
                }
            }
        }
    }

    var optionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("选项").font(.system(size: 24, weight: .bold))
            QXCard {
                VStack(spacing: 0) {
                    toggleRow(String(localized: "跳过服务器证书校验"), Binding(get: { store.config.skipCertVerify }, set: { store.config.skipCertVerify = $0; store.save() }))
                    Divider().padding(.leading, 16)
                    toggleRow(String(localized: "对客户端启用 HTTP/2"), Binding(get: { store.config.h2 ?? true }, set: { store.config.h2 = $0; store.save() }))
                    Divider().padding(.leading, 16)
                    toggleRow(String(localized: "记录请求 / 响应内容"), Binding(get: { store.config.captureBodies ?? true }, set: { store.config.captureBodies = $0; store.save() }))
                    Divider().padding(.leading, 16)
                    Button { nav.push(.dest(.mitmAdvanced)) } label: {
                        HStack {
                            Text("QUIC、证书导出与运行状态").foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 14)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            EngineSwitchFooter().font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
        }
    }

    func statusSection(_ s: MitMStatus) -> some View {
        QXCard {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Circle().fill(s.running ? QXColor.mitm : Color.secondary).frame(width: 8, height: 8)
                    Text(s.running ? LocalizedStringKey("引擎运行中") : LocalizedStringKey("引擎未运行")).font(.subheadline.weight(.semibold))
                    Spacer()
                    Text("规则 \(s.rules) · 脚本 \(s.scripts)").font(.caption).foregroundStyle(.secondary)
                }
                if !s.pinned.isEmpty {
                    Text("已临时放行（握手失败）：\(s.pinned.joined(separator: ", "))").font(.caption).foregroundStyle(.secondary).lineLimit(3)
                }
                ForEach(s.errors, id: \.self) { e in Text(verbatim: e).font(.caption).foregroundStyle(QXColor.warning) }
            }
            .padding(16)
        }
    }

    private func toggleRow(_ title: String, _ b: Binding<Bool>) -> some View {
        Toggle(isOn: b) { Text(verbatim: title) }
            .tint(QXColor.mitm)
            .padding(.horizontal, 16).padding(.vertical, 8)
    }

    private func move(_ i: Int, by d: Int) {
        let j = i + d
        guard store.config.hostnames.indices.contains(j) else { return }
        store.config.hostnames.swapAt(i, j)
        store.save()
    }

    func addHost() {
        let hosts = newHost.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        for h in hosts where !store.config.hostnames.contains(h) { store.config.hostnames.append(h) }
        newHost = ""
        store.save()
    }
}

/// The classic MitM page (QUIC exceptions, every export, run status) in QX chrome.
struct QXMitMAdvancedView: View {
    var body: some View {
        QXPage(title: String(localized: "MitM 高级")) {
            MitMView()
                .toolbar(.hidden, for: .navigationBar)
        }
    }
}
