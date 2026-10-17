import SwiftUI
import NetworkExtension
import UniformTypeIdentifiers

// QX 设置 (windmill tap): headed sections with an explanation and big colour capsule buttons leading into
// the existing pages; then 面板 & 工具栏 and 其他设置 (everything else we have beyond QX).

struct QXActionSpec: Identifiable {
    let id = UUID()
    let title: String
    let icon: String
    let action: () -> Void
}

struct QXActionGrid: View {
    let color: Color
    let items: [QXActionSpec]
    /// 2 on iPhone (QX); 3 on iPad regular width.
    var columns = 2
    var body: some View {
        // Frame 25: 2 columns, 61 pt capsules 13 pt apart, white glyph + 17–18 pt semibold label, soft colour shadow.
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 13), count: columns), spacing: 13) {
            ForEach(items) { it in
                Button(action: it.action) {
                    HStack(spacing: 10) {
                        Image(systemName: it.icon).font(.system(size: 18, weight: .semibold)).frame(width: 24)
                        Text(verbatim: it.title).font(.system(size: 18, weight: .semibold)).lineLimit(1).minimumScaleFactor(0.7)
                        Spacer(minLength: 0)
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 18)
                    .frame(maxWidth: .infinity, minHeight: 60)
                    .background(Capsule().fill(color))
                    .overlay(Capsule().stroke(QXPalette.hairline, lineWidth: 1))
                    .shadow(color: QXPalette.glow(color), radius: 8, y: 4)
                }
                .buttonStyle(QXPressStyle(scale: 0.96, haptic: true))
            }
        }
    }
}

struct QXSettingsSection<Trailing: View>: View {
    let title: String
    var count: String? = nil
    let caption: String
    let color: Color
    let items: [QXActionSpec]
    @ViewBuilder var trailing: Trailing
    @Environment(\.horizontalSizeClass) private var hSize

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(verbatim: title).font(.system(size: QXMetrics.largeTitle + 2, weight: .bold))
                if let count { Text(verbatim: count).font(.system(size: 15)).foregroundStyle(.secondary) }
                Spacer()
                trailing
            }
            Text(verbatim: caption).font(.system(size: QXMetrics.caption)).foregroundStyle(.secondary).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            QXActionGrid(color: color, items: items, columns: hSize == .regular ? 3 : 2).padding(.top, 6)
        }
    }
}

extension QXSettingsSection where Trailing == EmptyView {
    init(title: String, count: String? = nil, caption: String, color: Color, items: [QXActionSpec]) {
        self.title = title; self.count = count; self.caption = caption; self.color = color; self.items = items
        self.trailing = EmptyView()
    }
}

struct QXSettingsView: View {
    /// iPad: root of the detail pane (no back circle).
    var isRoot = false
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var nodes = QXNodesModel.shared
    @ObservedObject private var rules = QXRulesModel.shared
    @ObservedObject private var insp = ProfileInspector.shared
    @State private var importing = false
    @State private var certSheet: QXCertSheet?
    @State private var snippetType = false
    @State private var snippet: QXSnippetKind?

    var nodeCount: Int { nodes.index.keys.filter { !QXNodesModel.builtins.contains($0) }.count }
    var ruleCount: Int { rules.total > 0 ? rules.total : insp.result.rules.count }
    var rewriteCount: Int {
        engine.config.rules.count + engine.config.scripts.count
            + engine.config.modules.filter(\.enabled).reduce(0) { $0 + (engine.moduleInfo[$1.id]?.rules.count ?? 0) }
    }
    var mitmCount: Int {
        engine.config.hostnames.count
            + engine.config.modules.filter(\.enabled).reduce(0) { $0 + (engine.moduleInfo[$1.id]?.hostnames.count ?? 0) }
    }

    var body: some View {
        QXPage(title: String(localized: "设置"), trailing: {
            QXCircleButton(systemName: "link") { nav.present(.profiles) }
                .accessibilityLabel(Text("配置"))
        }, content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 40) {
                    QXSettingsSection(title: String(localized: "节点"), count: "\(nodeCount)",
                                      caption: String(localized: "网络流量可经由节点转发到最终目的地。"),
                                      color: QXColor.nodes, items: [
                        QXActionSpec(title: String(localized: "添加"), icon: "plus.rectangle.on.rectangle") { nav.push(.dest(.addNode)) },
                        QXActionSpec(title: String(localized: "节点资源"), icon: "link") { nav.push(.dest(.nodeResources)) },
                    ])
                    QXSettingsSection(title: String(localized: "分流"), count: QXFmt.count(ruleCount),
                                      caption: String(localized: "规则分流模式下，网络请求的走向由分流规则中所匹配到的策略决定。靠前的规则优先级更高，可点击“分流规则”查看顺序。MATCH（FINAL）规则对应的策略会在其他规则都未命中时使用。"),
                                      color: QXColor.rules, items: [
                        QXActionSpec(title: String(localized: "分流规则"), icon: "line.3.horizontal.decrease") { nav.push(.dest(.customRules)) },
                        QXActionSpec(title: String(localized: "规则资源"), icon: "link") { nav.push(.dest(.filterResources)) },
                    ])
                    QXSettingsSection(title: String(localized: "重写"), count: "\(rewriteCount)",
                                      caption: String(localized: "重写用于修改 HTTP 或 HTTPS 请求与响应。该规则按加载顺序进行匹配，可点击“重写规则”查看加载顺序。"),
                                      color: QXColor.rewrite, items: [
                        QXActionSpec(title: String(localized: "重写规则"), icon: "pencil") { nav.push(.dest(.localRewrite)) },
                        QXActionSpec(title: String(localized: "规则资源"), icon: "link") { nav.push(.dest(.rewriteResources)) },
                    ]) {
                        Toggle("", isOn: Binding(get: { engine.config.enabled }, set: { engine.config.enabled = $0; engine.save() }))
                            .qxToggleHaptic(engine.config.enabled)
                            .labelsHidden().tint(QXColor.rewrite)
                            .accessibilityLabel(Text("重写"))
                    }
                    QXSettingsSection(title: "MitM", count: "\(mitmCount)",
                                      caption: String(localized: "MitM 根证书用于 HTTPS 解析。只有配置了主机名的请求才会被 MitM 模块进行解析。主机名按加载顺序进行匹配，可点击“主机名”查看加载顺序。"),
                                      color: QXColor.mitm, items: [
                        QXActionSpec(title: String(localized: "主机名"), icon: "at") { nav.push(.dest(.mitm)) },
                        QXActionSpec(title: String(localized: "生成证书"), icon: "person.text.rectangle") { certSheet = .generate },
                        QXActionSpec(title: String(localized: "配置证书"), icon: "gearshape.2") { certSheet = .configure },
                    ]) {
                        Toggle("", isOn: Binding(get: { engine.config.mitm }, set: { engine.config.mitm = $0; engine.save() }))
                            .qxToggleHaptic(engine.config.mitm)
                            .labelsHidden().tint(QXColor.mitm)
                            .accessibilityLabel(Text("MitM"))
                    }
                    QXSettingsSection(title: String(localized: "工具 & 分析"),
                                      caption: String(localized: "以下 HTTP 请求相关工具大多用于 web 开发及测试；网络工具、解锁检测与连接分析是本 App 额外提供的。"),
                                      color: QXColor.tools, items: [
                        QXActionSpec(title: String(localized: "HTTP 请求"), icon: "text.line.last.and.arrowtriangle.forward") { nav.push(.dest(.tasks)) },
                        QXActionSpec(title: String(localized: "HTTP 抓取"), icon: "record.circle") { nav.push(.dest(.httpCapture)) },
                        QXActionSpec(title: String(localized: "HTTP Backend"), icon: "server.rack") { nav.push(.dest(.httpBackend)) },
                        QXActionSpec(title: String(localized: "网络工具"), icon: "stethoscope") { nav.push(.dest(.tools)) },
                        QXActionSpec(title: String(localized: "网络测试"), icon: "speedometer") { nav.push(.dest(.netTest)) },
                        QXActionSpec(title: String(localized: "解锁检测"), icon: "checkmark.seal") { nav.push(.dest(.unlock)) },
                        QXActionSpec(title: String(localized: "连接分析"), icon: "chart.pie") { nav.push(.dest(.analytics)) },
                    ])
                    QXSettingsSection(title: String(localized: "配置文件"),
                                      caption: String(localized: "完整的配置文件（mihomo YAML）保存在本地，包含节点详情、分流规则、策略、引用链接等信息；重写与 MitM 保存在模块中。"),
                                      color: QXColor.profile, items: [
                        QXActionSpec(title: String(localized: "配置片段"), icon: "doc.on.doc") { snippetType = true },
                        QXActionSpec(title: String(localized: "编辑"), icon: "square.and.pencil") { nav.present(.editProfile) },
                        QXActionSpec(title: String(localized: "导入配置"), icon: "square.and.arrow.down") { importing = true },
                        QXActionSpec(title: String(localized: "导出配置"), icon: "square.and.arrow.up") { exportProfile() },
                        QXActionSpec(title: String(localized: "下载配置"), icon: "tray.and.arrow.down") { nav.present(.addRemote) },
                        QXActionSpec(title: String(localized: "示例配置"), icon: "doc.text") { nav.present(.sample) },
                        QXActionSpec(title: String(localized: "初始化"), icon: "arrow.counterclockwise") { nav.push(.dest(.reset)) },
                        QXActionSpec(title: String(localized: "备份与恢复"), icon: "externaldrive") { nav.push(.dest(.backup)) },
                        QXActionSpec(title: String(localized: "配置快照"), icon: "clock.arrow.circlepath") { nav.push(.dest(.snapshots)) },
                        QXActionSpec(title: String(localized: "同步文件夹"), icon: "folder.badge.gearshape") { nav.push(.dest(.syncFolder)) },
                        QXActionSpec(title: String(localized: "存储空间"), icon: "internaldrive") { nav.push(.dest(.storage)) },
                        QXActionSpec(title: String(localized: "配置管理"), icon: "doc.text.magnifyingglass") { nav.present(.profiles) },
                    ])
                    VStack(spacing: 12) {
                        bottomButton(String(localized: "面板 & 工具栏")) { nav.push(.panelSettings) }
                        bottomButton(String(localized: "其他设置")) { nav.push(.otherSettings) }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.top, 8)
                .padding(.bottom, 50)
            }
        }, hideBack: isRoot)
        .task {
            if nodes.index.isEmpty { await nodes.load() }
            if rules.total == 0 { await rules.load() }
            engine.reparseModules()
        }
        .qxCertSheets($certSheet)
        .confirmationDialog("片段类型", isPresented: $snippetType, titleVisibility: .visible) {
            Button("节点") { snippet = .nodes }
            Button("分流") { snippet = .filter }
            Button("重写") { snippet = .rewrite }
            Button("管理片段") { nav.push(.dest(.snippets)) }
        }
        .sheet(item: $snippet) { k in QXSnippetEditor(kind: k).environmentObject(store) }
        .fileImporter(isPresented: $importing, allowedContentTypes: [UTType(filenameExtension: "yaml") ?? .plainText, UTType(filenameExtension: "yml") ?? .plainText,
                                                                    UTType(filenameExtension: "conf") ?? .plainText, .plainText, .text, .data]) { result in
            if case .success(let url) = result {
                // Let the document picker finish dismissing before the import sheet is presented.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { ImportRouter.shared.handle(url: url) }
            }
        }
    }

    private func bottomButton(_ title: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(verbatim: title).font(.system(size: 18, weight: .semibold)).foregroundStyle(QXColor.switchOn)
                .frame(maxWidth: .infinity, minHeight: 60)
                .background(Capsule().fill(QXPalette.cardHi))
        }
        .buttonStyle(.plain)
    }

    private func exportProfile() {
        guard let p = store.active else { nav.present(.profiles); return }
        let name = "mihomo_" + Self.stamp.string(from: Date()) + ".yaml"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try? store.content(of: p).write(to: url, atomically: true, encoding: .utf8)
        let vc = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        guard let root = UIApplication.shared.connectedScenes.compactMap({ ($0 as? UIWindowScene)?.keyWindow }).first?.rootViewController else { return }
        var top = root
        while let p = top.presentedViewController { top = p }
        vc.popoverPresentationController?.sourceView = top.view
        top.present(vc, animated: true)
    }

    static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMddHHmmss"
        return f
    }()
}

// MARK: - 其他设置

struct QXOtherSettingsView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var vpn: VPNManager
    @AppStorage(AppAppearance.key) private var appearance = AppAppearance.system.rawValue
    @ObservedObject private var live = LiveActivityController.shared

    var body: some View {
        QXPage(title: String(localized: "其他设置")) {
            List {
                Section {
                    modeRow("global", String(localized: "全部代理"))
                    modeRow("direct", String(localized: "全部直连"))
                    modeRow("rule", String(localized: "规则分流"))
                    row(String(localized: "出站接口 / 连接方式"), "point.3.filled.connected.trianglepath.dotted", .connection)
                } header: { header("模式") } footer: { Text("网络请求的处理流程由运行模式决定。长按首页右下角的风车也可以切换。") }
                .listRowBackground(QXPalette.card)

                Section {
                    ForEach(AppAppearance.allCases) { a in
                        Button { appearance = a.rawValue; AppAppearance.apply(a) } label: {
                            HStack {
                                Label(a.title, systemImage: a.icon).foregroundStyle(.primary)
                                Spacer()
                                if appearance == a.rawValue { Image(systemName: "checkmark").foregroundStyle(QXColor.switchOn) }
                            }
                        }
                    }
                    if UIApplication.shared.supportsAlternateIcons { row(String(localized: "应用图标"), "app.badge", .appIcon) }
                } header: { header("外观") }
                .listRowBackground(QXPalette.card)

                Section {
                    Toggle(isOn: $live.enabled) {
                        Label("实时活动与灵动岛", systemImage: "bell.badge").foregroundStyle(.primary)
                    }
                    .tint(QXColor.switchOn)
                    if live.enabled && !live.systemAllowed {
                        Text("系统设置中关闭了 Mihomo 的实时活动。").font(.caption).foregroundStyle(Theme.warn)
                    }
                } header: { header("通知") } footer: {
                    Text("连接时在锁定屏幕和灵动岛显示连接状态、已连接时长、当前节点和速度。需要带小组件的 IPA（-widget）。时长一直走；App 关闭时，速度和节点在系统允许后台刷新时更新，也可以点实时活动上的刷新按钮（iOS 17 及以上）。")
                }
                .listRowBackground(QXPalette.card)

                Section {
                    row(String(localized: "DNS"), "network", .dns)
                    row(String(localized: "出口位置查询"), "location.viewfinder", .geoChecker)
                    row(String(localized: "测速"), "bolt.horizontal", .speedTest)
                    row(String(localized: "内核设置"), "slider.horizontal.3", .coreSettings)
                } header: { header("VPN") } footer: { Text("IPv6、局域网共享（HTTP / SOCKS5 代理服务器）、排除路由与按需连接在「出站接口 / 连接方式」中设置。") }
                .listRowBackground(QXPalette.card)

                Section {
                    row(String(localized: "订阅管理"), "tray.full", .subscriptions)
                    row(String(localized: "提供者（规则集 / 节点集）"), "shippingbox", .providers)
                    row(String(localized: "模块与资源"), "puzzlepiece.extension", .rewriteResources)
                    row(String(localized: "脚本"), "curlybraces", .scripts)
                    row(String(localized: "地理与规则库"), "globe.asia.australia", .geo)
                } header: { header("资源") }
                .listRowBackground(QXPalette.card)

                Section {
                    row(String(localized: "按日流量"), "chart.bar.xaxis", .stats)
                    row(String(localized: "日志"), "text.alignleft", .logs)
                    row(String(localized: "脚本通知"), "bell", .notices)
                    row(String(localized: "脚本面板"), "rectangle.grid.2x2", .panels)
                    sheetRow(String(localized: "经典首页（流量图表）"), "gauge.with.dots.needle.67percent", .classicHome)
                    sheetRow(String(localized: "经典策略页"), "square.grid.2x2", .classicPolicy)
                    sheetRow(String(localized: "经典请求页"), "arrow.left.arrow.right", .classicRequests)
                } header: { header("更多") }
                .listRowBackground(QXPalette.card)

                Section {
                    Button { nav.push(.dest(.diagnostics)) } label: {
                        HStack {
                            Label("诊断", systemImage: "waveform.path.ecg").foregroundStyle(.primary)
                            Spacer()
                            Text(AppShared.containerOK ? "App Group 正常" : "App Group 异常")
                                .font(.caption).foregroundStyle(AppShared.containerOK ? Theme.good : Theme.bad)
                        }
                    }
                    sheetRow(String(localized: "新手引导"), "sparkles", .onboarding)
                    row(String(localized: "关于 / 开源许可"), "info.circle", .about)
                } header: { header("关于") }
                .listRowBackground(QXPalette.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
    }

    private func header(_ t: LocalizedStringKey) -> some View {
        Text(t).font(.system(size: 22, weight: .bold)).foregroundStyle(.primary).textCase(nil).padding(.leading, -4)
    }

    private func modeRow(_ mode: String, _ title: String) -> some View {
        Button {
            Task { await dash.setMode(mode) }
            UISelectionFeedbackGenerator().selectionChanged()
        } label: {
            HStack(spacing: 12) {
                QXWindmill(mode: mode, size: 22)
                Text(verbatim: title).foregroundStyle(.primary)
                Spacer()
                if dash.mode == mode { Image(systemName: "checkmark").foregroundStyle(QXColor.switchOn) }
            }
        }
        .accessibilityAddTraits(dash.mode == mode ? .isSelected : [])
    }

    private func row(_ title: String, _ icon: String, _ d: QXDest) -> some View {
        Button { nav.push(.dest(d)) } label: {
            HStack {
                Label(title, systemImage: icon).foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
        }
    }

    private func sheetRow(_ title: String, _ icon: String, _ s: QXSheet) -> some View {
        Button { nav.present(s) } label: {
            HStack {
                Label(title, systemImage: icon).foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.up").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
        }
    }
}

// MARK: - 面板 & 工具栏

struct QXPanelSettingsView: View {
    @AppStorage(QXPanel.orderKey) private var orderRaw = QXPanel.defaultOrder
    @AppStorage("qx.panelStyle") private var style = "large"
    @AppStorage("qx.toolbarStyle") private var toolbarStyle = "rounded"
    @AppStorage(QXToolbar.hiddenKey) private var hiddenRaw = ""
    @State private var order: [QXPanel] = []

    static let tools: [(id: String, title: String)] = [
        ("1", String(localized: "编辑 / 搜索")), ("2", String(localized: "添加节点 / 规则")), ("3", String(localized: "流量统计")),
        ("4", String(localized: "DNS 缓存")), ("5", String(localized: "构造请求")),
    ]

    var body: some View {
        QXPage(title: String(localized: "面板 & 工具栏")) {
            List {
                Section {
                    ForEach(order) { p in
                        HStack(spacing: 14) {
                            QXPanelGlyph(panel: p, size: 17)
                                .frame(width: 40, height: 40)
                                .background(Circle().fill(p.color))
                            Text(verbatim: p.title)
                        }
                    }
                    .onMove { from, to in
                        order.move(fromOffsets: from, toOffset: to)
                        orderRaw = order.map(\.rawValue).joined(separator: ",")
                    }
                } header: { header("排序") }
                .listRowBackground(QXPalette.card)

                Section {
                    Picker("面板样式", selection: $style) {
                        Text("大").tag("large")
                        Text("小").tag("small")
                        Text("线条").tag("line")
                    }
                    Picker("工具栏样式", selection: $toolbarStyle) {
                        Text("圆角").tag("rounded")
                        Text("默认").tag("square")
                    }
                } header: { header("样式") }
                .listRowBackground(QXPalette.card)

                Section {
                    ForEach(Self.tools, id: \.id) { t in
                        Toggle(isOn: Binding(get: { !hidden.contains(t.id) }, set: { on in setHidden(t.id, !on) })) {
                            HStack {
                                Text(verbatim: String(localized: "工具 \(t.id)"))
                                Spacer()
                                Text(verbatim: t.title).foregroundStyle(.secondary)
                            }
                        }
                        .tint(QXColor.switchOn)
                    }
                } header: { header("工具栏") } footer: {
                    Text("工具栏只显示开启的工具；与工具对应的备选功能在长按时弹出。风车（设置）始终显示，长按切换运行模式。")
                }
                .listRowBackground(QXPalette.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .environment(\.editMode, .constant(.active))
        }
        .onAppear { order = QXPanel.order(orderRaw) }
    }

    var hidden: Set<String> { Set(hiddenRaw.split(separator: ",").map(String.init)) }

    private func setHidden(_ id: String, _ hide: Bool) {
        var h = hidden
        if hide { h.insert(id) } else { h.remove(id) }
        hiddenRaw = h.sorted().joined(separator: ",")
    }

    private func header(_ t: LocalizedStringKey) -> some View {
        Text(t).font(.system(size: 22, weight: .bold)).foregroundStyle(.primary).textCase(nil).padding(.leading, -4)
    }
}

// MARK: - 引用资源 - 节点 / 分流

/// Bottom 3-way switch between the three resource pages (replaces the current page in the stack).
struct QXResourceSwitcher: View {
    let current: Int
    @EnvironmentObject var nav: QXNavigator
    @State private var sel = 0
    var body: some View {
        QXBottomSegment(icons: ["server.rack", "line.3.horizontal.decrease", "pencil"], selection: $sel)
            .onAppear { sel = current }
            .onChange(of: sel) { s in
                guard s != current, !nav.path.isEmpty else { return }
                let d: QXDest = s == 0 ? .nodeResources : (s == 1 ? .filterResources : .rewriteResources)
                nav.path[nav.path.count - 1] = .dest(d)
            }
    }
}

struct QXNodeResourcesView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var nodes = QXNodesModel.shared
    @ObservedObject private var insp = ProfileInspector.shared
    @State private var busy = false
    @State private var message: String?
    @State private var editing: QXResourceTarget?
    @ObservedObject private var subs = NodeSubStore.shared

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "doc.badge.gearshape") { nav.push(.dest(.subscriptions)) }
                    .accessibilityLabel(Text("订阅管理"))
                QXBarIcon(systemName: "link.badge.plus") { nav.present(.addRemote) }
                    .accessibilityLabel(Text("添加订阅链接"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .firstTextBaseline) {
                        QXLargeTitle(title: String(localized: "引用资源 - 节点"))
                        QXPill(title: busy ? String(localized: "更新中…") : String(localized: "全部更新")) { Task { await updateAll() } }
                            .disabled(busy)
                    }
                    Text("勾选的是当前使用的配置；节点集（proxy-providers）属于当前配置，连接后可单独更新。本地节点在「设置 → 节点 → 添加」中管理。")
                        .font(.system(size: 16)).foregroundStyle(.secondary)
                    if let message { Text(verbatim: message).font(.footnote).foregroundStyle(.secondary) }

                    Text("订阅与配置").font(.headline).padding(.top, 6)
                    QXCard {
                        VStack(spacing: 0) {
                            ForEach(Array(store.profiles.enumerated()), id: \.element.id) { i, p in
                                if i > 0 { Divider().padding(.leading, 56) }
                                Button { Task { if let e = await store.setActive(p) { message = e } } } label: {
                                    resourceRow(checked: p.id == store.activeID, title: p.name,
                                                trailing: p.lastUpdated.map { Self.rel.localizedString(for: $0, relativeTo: Date()) } ?? (p.kind == .remote ? String(localized: "需要更新") : String(localized: "本地")),
                                                subtitle: p.kind == .remote ? Self.redact(p.url ?? "") : String(localized: "本地配置"))
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    if p.kind == .remote {
                                        Button { editing = QXResourceTarget(kind: .profile(p.id)) } label: { Label("编辑", systemImage: "square.and.pencil") }
                                        Button { Task { if let e = await store.refresh(p) { message = e } } } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                                        Button { UIPasteboard.general.string = p.url } label: { Label("拷贝链接", systemImage: "doc.on.doc") }
                                    }
                                    Button { nav.present(.profiles) } label: { Label("管理配置", systemImage: "square.and.pencil") }
                                }
                            }
                            if store.profiles.isEmpty {
                                Text("还没有配置").foregroundStyle(.secondary).padding(16)
                            }
                        }
                    }

                    if !subs.subs.isEmpty {
                        Text("节点订阅").font(.headline).padding(.top, 6)
                        QXCard {
                            VStack(spacing: 0) {
                                ForEach(Array(subs.subs.enumerated()), id: \.element.id) { i, sub in
                                    if i > 0 { Divider().padding(.leading, 56) }
                                    Button { editing = QXResourceTarget(kind: .nodeSub(sub.id)) } label: {
                                        resourceRow(checked: sub.enabled, title: sub.name,
                                                    trailing: subs.updating.contains(sub.id) ? String(localized: "更新中…")
                                                        : (sub.lastUpdated.map { Self.rel.localizedString(for: $0, relativeTo: Date()) } ?? String(localized: "需要更新")),
                                                    subtitle: sub.lastError ?? (Self.redact(sub.url) + (sub.count.map { " · " + String(localized: "\($0) 个节点") } ?? "")))
                                    }
                                    .buttonStyle(.plain)
                                    .contextMenu {
                                        Button { editing = QXResourceTarget(kind: .nodeSub(sub.id)) } label: { Label("编辑", systemImage: "square.and.pencil") }
                                        Button { Task { if let e = await subs.refresh(sub) { message = e } } } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                                        Button { var x = sub; x.enabled.toggle(); Task { await subs.save(x) } } label: {
                                            Label(sub.enabled ? LocalizedStringKey("停用") : LocalizedStringKey("启用"), systemImage: sub.enabled ? "pause.circle" : "play.circle")
                                        }
                                        Button { UIPasteboard.general.string = sub.url } label: { Label("资源链接", systemImage: "link") }
                                        Button(role: .destructive) { Task { await subs.delete(sub) } } label: { Label("删除", systemImage: "trash") }
                                    }
                                }
                            }
                        }
                    }

                    let providers = insp.result.proxyProviders.filter { pv in !subs.subs.contains { $0.name == pv.name } }
                    if !providers.isEmpty {
                        Text("节点集").font(.headline).padding(.top, 6)
                        QXCard {
                            VStack(spacing: 0) {
                                ForEach(Array(providers.enumerated()), id: \.element.id) { i, p in
                                    if i > 0 { Divider().padding(.leading, 56) }
                                    resourceRow(checked: true, title: p.name,
                                                trailing: p.cachedDate.map { Self.rel.localizedString(for: $0, relativeTo: Date()) } ?? String(localized: "需要更新"),
                                                subtitle: p.url.map { Self.redact($0) } ?? (p.path ?? ""))
                                    .contextMenu {
                                        if vpn.isConnected {
                                            Button { Task { await nodes.updateProvider(p.name); await insp.load() } } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                                        }
                                        Button { UIPasteboard.general.string = p.name } label: { Label("拷贝名称", systemImage: "doc.on.doc") }
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 100)
            }
            .overlay(alignment: .bottom) { QXResourceSwitcher(current: 0).padding(.bottom, 10) }
        }
        .task { await insp.load() }
        .sheet(item: $editing, onDismiss: { Task { await insp.load() } }) { t in QXResourceEditor(target: t).environmentObject(store) }
    }

    func resourceRow(checked: Bool, title: String, trailing: String, subtitle: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: checked ? "checkmark.square.fill" : "square")
                .font(.system(size: 22)).foregroundStyle(checked ? QXColor.switchOn : Color.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(verbatim: title).font(.system(size: 18)).lineLimit(1)
                    Spacer()
                    Text(verbatim: trailing).font(.caption).foregroundStyle(.secondary)
                }
                Text(verbatim: subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }

    private func updateAll() async {
        busy = true
        defer { busy = false }
        var errs = await store.refreshAll()
        errs += await subs.refreshAll()
        if vpn.isConnected {
            for p in insp.result.proxyProviders where p.vehicle.uppercased() == "HTTP" { await nodes.updateProvider(p.name) }
        }
        await insp.load()
        message = errs.isEmpty ? String(localized: "已全部更新") : errs.joined(separator: "\n")
    }

    static let rel: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f
    }()

    /// Subscription links carry tokens: show scheme + host + a hint only.
    static func redact(_ s: String) -> String {
        guard let u = URL(string: s), let host = u.host else { return s.isEmpty ? "" : "…" }
        return "\(u.scheme ?? "https")://\(host)/…"
    }
}

struct QXFilterResourcesView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var insp = ProfileInspector.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var adding = false
    @State private var busy = false
    @State private var message: String?
    @State private var editing: QXResourceTarget?

    /// Policy each profile rule-provider is used with (first RULE-SET line naming it).
    var policies: [String: String] {
        var out: [String: String] = [:]
        for r in insp.result.rules where QXFmt.isRuleSet(r.type) && out[r.payload] == nil { out[r.payload] = r.proxy }
        return out
    }

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "magnifyingglass") { nav.push(.dest(.customRules)) }
                    .accessibilityLabel(Text("分流规则"))
                QXBarIcon(systemName: "link.badge.plus") { adding = true }
                    .accessibilityLabel(Text("添加规则集"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .firstTextBaseline) {
                        QXLargeTitle(title: String(localized: "引用资源 - 分流"))
                        QXPill(title: busy ? String(localized: "更新中…") : String(localized: "全部更新")) { Task { await updateAll() } }
                            .disabled(busy)
                    }
                    Text("生效的分流规则除了下列资源外，还包含配置文件与「分流规则」中的本地规则，可点击右上方的搜索按钮查看。")
                        .font(.system(size: 16)).foregroundStyle(.secondary)
                    if let message { Text(verbatim: message).font(.footnote).foregroundStyle(.secondary) }

                    let pol = policies
                    let providers = insp.result.ruleProviders
                    if !providers.isEmpty {
                        Text("配置中的规则集").font(.headline).padding(.top, 6)
                        QXCard {
                            VStack(spacing: 0) {
                                ForEach(Array(providers.enumerated()), id: \.element.id) { i, p in
                                    if i > 0 { Divider().padding(.leading, 56) }
                                    row(checked: true, title: p.name, policy: pol[p.name] ?? "",
                                        trailing: p.cachedDate.map { QXNodeResourcesView.rel.localizedString(for: $0, relativeTo: Date()) } ?? String(localized: "需要更新"),
                                        subtitle: p.url ?? p.path ?? "")
                                    .contextMenu {
                                        if vpn.isConnected {
                                            Button { Task { try? await ControllerClient.shared.updateRuleProvider(p.name); await insp.load() } } label: {
                                                Label("更新", systemImage: "arrow.triangle.2.circlepath")
                                            }
                                        }
                                        if let u = p.url { Button { UIPasteboard.general.string = u } label: { Label("拷贝链接", systemImage: "doc.on.doc") } }
                                    }
                                }
                            }
                        }
                    }
                    let sets = res.items.filter { $0.kind == "ruleset" }
                    Text("我添加的规则集").font(.headline).padding(.top, 6)
                    QXCard {
                        VStack(spacing: 0) {
                            if sets.isEmpty {
                                Text("还没有。点右上角添加。").foregroundStyle(.secondary).padding(16)
                            }
                            ForEach(Array(sets.enumerated()), id: \.element.id) { i, it in
                                if i > 0 { Divider().padding(.leading, 56) }
                                Button { res.setEnabled(it, !it.enabled) } label: {
                                    row(checked: it.enabled, title: it.name, policy: it.detail ?? "",
                                        trailing: it.updatedAt > 0 ? QXNodeResourcesView.rel.localizedString(for: Date(timeIntervalSince1970: it.updatedAt), relativeTo: Date()) : String(localized: "需要更新"),
                                        subtitle: it.error ?? it.url)
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    if let id = it.refId {
                                        Button { editing = QXResourceTarget(kind: .ruleSet(id)) } label: { Label("编辑", systemImage: "square.and.pencil") }
                                    }
                                    Button { Task { await res.update(it) } } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                                    Button { UIPasteboard.general.string = it.url } label: { Label("拷贝链接", systemImage: "doc.on.doc") }
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 100)
            }
            .overlay(alignment: .bottom) { QXResourceSwitcher(current: 1).padding(.bottom, 10) }
        }
        .task { await insp.load(); res.reload() }
        .sheet(isPresented: $adding) { AddRuleSetSheet() }
        .sheet(item: $editing, onDismiss: { res.reload() }) { t in QXResourceEditor(target: t).environmentObject(store) }
    }

    func row(checked: Bool, title: String, policy: String, trailing: String, subtitle: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: checked ? "checkmark.square.fill" : "square")
                .font(.system(size: 22)).foregroundStyle(checked ? QXColor.switchOn : Color.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(verbatim: title).font(.system(size: 18)).lineLimit(1)
                    if !policy.isEmpty { QXChip(text: policy, color: QXPolicyColor.color(policy)) }
                    Spacer()
                    Text(verbatim: trailing).font(.caption).foregroundStyle(.secondary)
                }
                Text(verbatim: subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
    }

    private func updateAll() async {
        busy = true
        defer { busy = false }
        if vpn.isConnected {
            for p in insp.result.ruleProviders where p.vehicle.uppercased() == "HTTP" {
                try? await ControllerClient.shared.updateRuleProvider(p.name)
            }
        }
        await res.updateAll()
        await insp.load()
        message = String(localized: "已全部更新")
    }
}

// MARK: - 示例配置

struct QXSampleConfigView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var text = QXSampleConfigView.sample

    var body: some View {
        NavigationStack {
            CodeEditor(text: $text, language: .yaml, editable: false)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle("示例配置")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } }
                    ToolbarItem(placement: .primaryAction) {
                        Button { UIPasteboard.general.string = text } label: { Image(systemName: "doc.on.doc") }
                            .accessibilityLabel(Text("复制"))
                    }
                }
        }
    }

    static let sample = """
    # Mihomo 示例配置（mihomo / Clash Meta YAML）
    # 本 App 只使用一种内部格式：mihomo YAML。Quantumult X / Surge / Loon 的配置在导入时会被转换。
    # 以 # 开头的行是注释。

    # 运行模式：rule（规则分流）/ global（全部代理）/ direct（全部直连）
    mode: rule
    log-level: info
    ipv6: false

    # 节点（QX: [server_local]）
    proxies:
      - name: "🇯🇵 东京 01"
        type: ss
        server: example.com
        port: 8388
        cipher: 2022-blake3-aes-128-gcm
        password: "base64-key"
        udp: true

    # 节点资源（QX: [server_remote]）：订阅链接，按间隔自动更新
    proxy-providers:
      机场:
        type: http
        url: "https://example.com/sub"
        interval: 86400
        path: ./providers/airport.yaml
        health-check:
          enable: true
          url: https://www.gstatic.com/generate_204
          interval: 600

    # 策略（QX: [policy]）
    # select = static，url-test = url-latency-benchmark，fallback = available，load-balance = round-robin / dest-hash
    proxy-groups:
      - name: PROXY
        type: select
        proxies: [自动选择, "🇯🇵 东京 01", DIRECT]
        use: [机场]
      - name: 自动选择
        type: url-test
        use: [机场]
        filter: "(?i)日本|JP"        # QX: server-tag-regex
        url: https://www.gstatic.com/generate_204
        interval: 600
        tolerance: 50

    # 规则资源（QX: [filter_remote]）
    rule-providers:
      AI:
        type: http
        behavior: classical
        format: text
        url: "https://example.com/AI.list"
        path: ./ruleset/ai.list
        interval: 86400

    # 分流规则（QX: [filter_local]），从上到下匹配，MATCH = FINAL
    rules:
      - RULE-SET,AI,PROXY
      - DOMAIN-SUFFIX,apple.com,DIRECT          # QX: host-suffix
      - DOMAIN-KEYWORD,google,PROXY             # QX: host-keyword
      - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
      - GEOIP,CN,DIRECT
      - MATCH,PROXY

    # DNS（QX: [dns]）
    dns:
      enable: true
      enhanced-mode: fake-ip
      nameserver:
        - https://doh.pub/dns-query
        - 223.5.5.5

    # 重写与 MitM（QX: [rewrite_local] / [mitm]）不写在这里：
    # 在「设置 → 重写 / MitM」中添加模块（支持 QX 片段、Surge 模块、Loon 插件）。
    """
}
