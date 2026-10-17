import SwiftUI
import UniformTypeIdentifiers

/// QX root on iPhone: header (exit location + switch), panel tiles, the selected panel's content, and the
/// floating toolbar with the windmill. Everything else is pushed from here (settings page, resource pages)
/// or presented as a sheet (pages that own a NavigationStack, editors, the run-mode sheet).
struct QXShell: View {
    /// iPad / regular width (QX-4): home on the left, the pushed pages in a detail pane on the right.
    var pad = false
    @StateObject private var nav = QXNavigator.shared
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var ipinfo: IPInfoModel
    @EnvironmentObject var router: ImportRouter

    var body: some View {
        Group {
            if pad { padBody } else { phoneBody }
        }
        .environmentObject(nav)
        .onAppear { nav.padLayout = pad }
        .onChange(of: pad) { nav.padLayout = $0 }
        .sheet(item: $nav.sheet) { s in
            QXSheetView(sheet: s)
                .environmentObject(vpn)
                .environmentObject(store)
                .environmentObject(dash)
                .environmentObject(ipinfo)
                .environmentObject(router)
                .environmentObject(nav)
        }
    }
}

extension QXShell {
    var phoneBody: some View {
        NavigationStack(path: $nav.path) {
            QXHome()
                .toolbar(.hidden, for: .navigationBar)
                .navigationDestination(for: QXRoute.self) { r in
                    QXRouteView(route: r)
                }
        }
    }

    /// Regular width: the QX single page stays whole on the left (header, all tiles visible as a grid, panel
    /// content, toolbar + windmill); the right pane starts at 设置 (3-column buttons) and hosts every push.
    /// The windmill pops the right pane back to 设置 instead of pushing it.
    var padBody: some View {
        GeometryReader { g in
            HStack(spacing: 0) {
                QXHome(pad: true)
                    .frame(width: min(max(g.size.width * 0.42, 360), 500))
                Rectangle().fill(Color.primary.opacity(0.08)).frame(width: 1).ignoresSafeArea()
                NavigationStack(path: $nav.path) {
                    QXSettingsView(isRoot: true)
                        .navigationDestination(for: QXRoute.self) { r in
                            QXRouteView(route: r)
                        }
                }
                .frame(maxWidth: .infinity)
            }
        }
        .background(Theme.bg.ignoresSafeArea())
    }
}

struct QXRouteView: View {
    let route: QXRoute
    var body: some View {
        switch route {
        case .settings: QXSettingsView()
        case .otherSettings: QXOtherSettingsView()
        case .panelSettings: QXPanelSettingsView()
        case .group(let name): QXGroupDetailView(name: name)
        case .connection(let id): QXConnectionDetailView(id: id)
        case .dest(let d): d.view
        }
    }
}

struct QXSheetView: View {
    let sheet: QXSheet
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        switch sheet {
        case .profiles:
            ProfilesView()
        case .editProfile:
            if let p = store.active {
                YAMLEditorView(title: p.kind == .remote ? "查看配置" : "编辑配置", initialName: p.name, initialText: store.content(of: p), profile: p)
            } else {
                NavigationStack {
                    EmptyStateView(icon: "doc.badge.plus", title: "还没有配置", message: "先在「设置 → 配置文件」中添加订阅或导入配置。")
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } } }
                }
            }
        case .addRemote:
            QXSubscriptionEditor()
        case .runMode:
            QXRunModeSheet()
                .presentationDetents([.medium, .large])
        case .classicHome:
            HomeView()
        case .classicPolicy:
            PolicyView()
        case .classicRequests:
            RequestsView()
        case .onboarding:
            OnboardingView { dismiss() }
        case .sample:
            QXSampleConfigView()
        }
    }
}

// MARK: - Home

struct QXHome: View {
    var pad = false
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @AppStorage("qx.panel") private var selectedRaw = QXPanel.nodes.rawValue
    @AppStorage(QXPanel.orderKey) private var orderRaw = QXPanel.defaultOrder

    var selected: QXPanel { QXPanel(rawValue: selectedRaw) ?? .nodes }
    var order: [QXPanel] { QXPanel.order(orderRaw) }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 12) {
                QXHeader()
                    .padding(.horizontal, QXMetrics.inset)
                    .padding(.top, 6)
                QXPanelStrip(selected: $selectedRaw, order: order, grid: pad)
                if vpn.safeModeActive && vpn.status != .disconnected && vpn.status != .invalid {
                    SafeModeCard().padding(.horizontal, 16)
                }
            }
            .padding(.bottom, 12)
            .background(Theme.header.ignoresSafeArea(edges: .top))
            Divider()
            TabView(selection: $selectedRaw) {
                ForEach(order) { p in
                    QXPanelContent(panel: p, active: p == selected)
                        .tag(p.rawValue)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
            .background(Theme.bg)
        }
        .background(Theme.bg.ignoresSafeArea())
        .overlay(alignment: .bottom) {
            // Frame 01: the bar's bottom edge sits ~19 pt above the screen edge, over the home-indicator area.
            QXToolbar(panel: selected)
                .padding(.horizontal, QXMetrics.toolbarInset)
                .padding(.bottom, QXMetrics.toolbarBottom)
                .ignoresSafeArea(.container, edges: .bottom)
        }
        .onChange(of: selectedRaw) { _ in
            UISelectionFeedbackGenerator().selectionChanged()
            if selected != .activity { nav.activitySearch = false }
        }
        .alert("连接失败", isPresented: Binding(get: { vpn.lastError != nil && vpn.showErrorAlert }, set: { if !$0 { vpn.showErrorAlert = false } })) {
            if vpn.canOfferSafeMode {
                Button("以安全模式连接") {
                    vpn.showErrorAlert = false
                    Task { await vpn.restart(safeMode: true) }
                }
            }
            Button("好", role: .cancel) { vpn.showErrorAlert = false }
        } message: {
            Text(vpn.canOfferSafeMode
                 ? (vpn.lastError ?? "") + "\n\n" + String(localized: "安全模式只用配置文件本身连接：暂停模块、重写、脚本、MitM、自定义规则和智能选择，便于判断问题出在哪里。")
                 : (vpn.lastError ?? ""))
        }
    }
}

struct QXPanelContent: View {
    let panel: QXPanel
    let active: Bool
    var body: some View {
        switch panel {
        case .nodes: QXNodesPanel(active: active)
        case .activity: QXActivityPanel(active: active)
        case .rules: QXRulesPanel(active: active)
        case .rewrite: QXRewritePanel(active: active)
        case .logs: QXLogPanel(active: active)
        }
    }
}

// MARK: - Header

/// Flag + exit location large, "TIME ZONE · ASN · IP" small, and the switch. Tap refreshes, long-press copies.
struct QXHeader: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var ip: IPInfoModel
    @EnvironmentObject var nav: QXNavigator
    @State private var copied = false
    @State private var showError = false

    var body: some View {
        let on = vpn.isConnected
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(verbatim: ip.exit?.flag ?? "🌐").font(.system(size: 24))
                    Text(verbatim: ip.exit?.placeText ?? (IPInfoFetcher.disabled ? (on ? String(localized: "已连接") : String(localized: "未连接"))
                                                          : (ip.loading ? String(localized: "正在查询…") : (ip.failed ? String(localized: "查询失败") : "—"))))
                        .font(.system(size: 24, weight: .bold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                }
                Text(verbatim: (ip.exit?.detailText ?? (on ? String(localized: "出口 · 代理") : String(localized: "出口 · 本机网络"))).uppercased())
                    .font(.system(size: 13, weight: .medium).monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                ip.scheduleRefresh()
            }
            .onLongPressGesture(minimumDuration: 0.45) {
                ip.copy()
                withAnimation(.spring()) { copied = true }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { withAnimation { copied = false } }
            }
            .accessibilityElement(children: .combine)
            .accessibilityHint(Text("轻点刷新，长按复制"))
            Spacer(minLength: 8)
            if vpn.lastError != nil {
                Button { showError = true } label: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warn)
                }
                .accessibilityLabel(Text("连接失败"))
            }
            if vpn.status == .connecting || vpn.status == .disconnecting || vpn.status == .reasserting {
                ProgressView().controlSize(.small)
            }
            Toggle("", isOn: Binding(
                get: { on || vpn.status == .connecting },
                set: { _ in Task { await vpn.toggle() } }
            ))
            .labelsHidden()
            .tint(QXColor.switchOn)
            .disabled(vpn.isBusy || vpn.status == .disconnecting)
            .accessibilityLabel(Text("代理"))
        }
        .overlay(alignment: .topTrailing) {
            if copied {
                Text("已复制")
                    .font(.caption2.bold())
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Theme.good))
                    .foregroundStyle(.black)
                    .offset(y: -10)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .alert("连接失败", isPresented: $showError) {
            Button("诊断") { nav.push(.dest(.diagnostics)) }
            Button("好", role: .cancel) {}
        } message: { Text(vpn.lastError ?? "") }
        .onAppear { if ip.exit == nil && !ip.loading { ip.scheduleRefresh() } }
    }
}

// MARK: - Panel tiles

struct QXPanelStrip: View {
    @Binding var selected: String
    let order: [QXPanel]
    /// iPad: every tile visible at once in a wrapping grid instead of a horizontal strip.
    var grid = false
    @EnvironmentObject var nav: QXNavigator
    @AppStorage("qx.panelStyle") private var style = "large"

    var body: some View {
        if grid && style != "line" {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: style == "small" ? 56 : 96, maximum: 160), spacing: QXMetrics.tileGap)],
                      spacing: QXMetrics.tileGap) {
                ForEach(order) { p in
                    QXTile(panel: p, selected: p.rawValue == selected, small: style == "small", flexible: true)
                        .onTapGesture { withAnimation(.spring(response: 0.3)) { selected = p.rawValue } }
                        .onLongPressGesture(minimumDuration: 0.4) { open(p) }
                }
            }
            .padding(.horizontal, QXMetrics.inset)
            .padding(.vertical, 6)
        } else if style == "line" {
            HStack(spacing: 8) {
                ForEach(order) { p in
                    Capsule()
                        .fill(p.color.opacity(p.rawValue == selected ? 1 : 0.45))
                        .frame(height: p.rawValue == selected ? 10 : 7)
                        .contentShape(Rectangle().inset(by: -10))
                        .onTapGesture { withAnimation(.spring(response: 0.3)) { selected = p.rawValue } }
                        .onLongPressGesture(minimumDuration: 0.4) { open(p) }
                        .accessibilityLabel(Text(p.title))
                }
            }
            .padding(.horizontal, QXMetrics.inset)
            .padding(.vertical, 6)
        } else {
            ScrollViewReader { proxy in
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: QXMetrics.tileGap) {
                        ForEach(order) { p in
                            QXTile(panel: p, selected: p.rawValue == selected, small: style == "small")
                                .id(p.rawValue)
                                .onTapGesture { withAnimation(.spring(response: 0.3)) { selected = p.rawValue } }
                                .onLongPressGesture(minimumDuration: 0.4) { open(p) }
                        }
                    }
                    .padding(.horizontal, QXMetrics.inset)
                    .padding(.vertical, 6)
                }
                .onChange(of: selected) { s in withAnimation { proxy.scrollTo(s, anchor: .center) } }
            }
        }
    }

    private func open(_ p: QXPanel) {
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        nav.push(p.resourceRoute)
    }
}

struct QXTile: View {
    let panel: QXPanel
    let selected: Bool
    var small = false
    /// iPad grid: fill the grid cell's width.
    var flexible = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            VStack(spacing: small ? 0 : 5) {
                QXPanelGlyph(panel: panel, size: 20)
                if !small {
                    Text(verbatim: panel.title)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
                Capsule()
                    .fill(Color.white.opacity(selected ? 0.85 : 0))
                    .frame(width: 22, height: 3)
                    .padding(.top, small ? 4 : 0)
            }
            .frame(width: flexible ? nil : (small ? 56 : QXMetrics.tileSize.width), height: small ? 56 : QXMetrics.tileSize.height)
            .frame(maxWidth: flexible ? .infinity : nil)
            .padding(.top, 4)
            if !small {
                ZStack {
                    Circle().strokeBorder(Color.white.opacity(0.5), style: StrokeStyle(lineWidth: 1.4, dash: [2, 2]))
                    Circle().fill(Color.white.opacity(0.5)).frame(width: 5, height: 5)
                }
                .frame(width: 15, height: 15)
                .padding(8)
                .accessibilityHidden(true)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: small ? 16 : QXMetrics.tileRadius, style: .continuous)
                .fill(panel.color)
        )
        // Frame 01: flat solid tiles with a soft drop shadow; the selected one is marked only by the underline.
        .shadow(color: .black.opacity(0.10), radius: 6, y: 3)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(panel.title))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityHint(Text("长按打开资源页"))
    }
}

// MARK: - Toolbar

struct QXToolbar: View {
    static let hiddenKey = "qx.hiddenTools"
    let panel: QXPanel
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var vpn: VPNManager
    @AppStorage("qx.toolbarStyle") private var toolbarStyle = "rounded"
    @AppStorage(QXToolbar.hiddenKey) private var hiddenRaw = ""
    @State private var spin = false

    private func shown(_ id: String) -> Bool { !hiddenRaw.split(separator: ",").contains(Substring(id)) }

    var body: some View {
        HStack(spacing: 0) {
            // 1. 编辑 (网络活动 / 分流 / 重写 / 日志: 搜索)
            if shown("1") {
            Button {
                if panel == .activity {
                    withAnimation { nav.activitySearch.toggle() }
                } else if panel == .rules {
                    nav.push(.dest(.customRules))
                } else if panel == .rewrite {
                    nav.push(.dest(.localRewrite))
                } else if panel == .logs {
                    nav.push(.dest(.logs))
                } else {
                    nav.present(.editProfile)
                }
            } label: { icon(panel == .nodes ? "square.and.pencil" : "magnifyingglass") }
            .accessibilityLabel(Text(panel == .nodes ? LocalizedStringKey("编辑配置") : LocalizedStringKey("搜索")))
            }

            // 2. ＋ (context add; long-press = menu)
            if shown("2") {
            Menu {
                Button { nav.present(.addRemote) } label: { Label("添加订阅链接", systemImage: "link.badge.plus") }
                Button { nav.present(.profiles) } label: { Label("导入配置", systemImage: "square.and.arrow.down") }
                Button { nav.push(.dest(.addNode)) } label: { Label("添加节点", systemImage: "plus.viewfinder") }
                Button { nav.push(.dest(.customRules)) } label: { Label("添加分流规则", systemImage: "line.3.horizontal.decrease") }
                Button { nav.push(.dest(.localRewrite)) } label: { Label("添加重写", systemImage: "pencil") }
                Button { nav.push(.dest(.rewriteResources)) } label: { Label("添加模块 / 规则集", systemImage: "puzzlepiece.extension") }
            } label: {
                icon("plus")
            } primaryAction: {
                switch panel {
                case .nodes: nav.push(.dest(.addNode))
                case .rules: nav.push(.dest(.customRules))
                case .rewrite: nav.push(.dest(.localRewrite))
                case .activity, .logs: nav.present(.profiles)
                }
            }
            .accessibilityLabel(Text("添加"))
            }

            // 3. 流量统计 (long-press: 按日统计 / 连接分析)
            if shown("3") {
            Menu {
                Button { nav.push(.dest(.stats)) } label: { Label("按日流量", systemImage: "chart.bar.xaxis") }
                Button { nav.push(.dest(.analytics)) } label: { Label("连接分析", systemImage: "chart.pie") }
            } label: { icon("chart.bar") } primaryAction: { nav.push(.dest(.trafficStats)) }
            .accessibilityLabel(Text("流量统计"))
            }

            // 4. DNS 缓存 (long-press: DNS 设置 / 网络工具)
            if shown("4") {
            Menu {
                Button { nav.push(.dest(.dns)) } label: { Label("DNS 设置", systemImage: "network") }
                Button { nav.push(.dest(.tools)) } label: { Label("网络工具", systemImage: "stethoscope") }
            } label: { icon("globe") } primaryAction: { nav.push(.dest(.dnsLog)) }
            .accessibilityLabel(Text("DNS 缓存"))
            }

            // 5. 构造请求 = HTTP 请求任务列表 (long-press: 脚本记录 / HTTP 抓取 / 通知)
            if shown("5") {
            Menu {
                Button { nav.push(.dest(.scriptLogs)) } label: { Label("脚本记录", systemImage: "curlybraces") }
                Button { nav.push(.dest(.httpCapture)) } label: { Label("HTTP 抓取", systemImage: "record.circle") }
                Button { nav.push(.dest(.notices)) } label: { Label("脚本通知", systemImage: "bell") }
            } label: { icon("text.line.last.and.arrowtriangle.forward") } primaryAction: { nav.push(.dest(.tasks)) }
            .accessibilityLabel(Text("HTTP 请求"))
            }

            // 6. Windmill: a circle inside the capsule's trailing end (frame 01).
            windmill
        }
        .padding(.leading, 6)
        .padding(.trailing, (QXMetrics.toolbarHeight - QXMetrics.windmillCircle) / 2)
        .frame(height: QXMetrics.toolbarHeight)
        .background(
            RoundedRectangle(cornerRadius: toolbarStyle == "rounded" ? QXMetrics.toolbarHeight / 2 : 16, style: .continuous)
                .fill(Theme.card)
                .shadow(color: .black.opacity(0.10), radius: 14, y: 4)
        )
        .overlay(
            RoundedRectangle(cornerRadius: toolbarStyle == "rounded" ? QXMetrics.toolbarHeight / 2 : 16, style: .continuous)
                .stroke(QXMetrics.hairline, lineWidth: 1)
        )
    }

    // 6. Windmill: tap = 设置, long-press = 运行模式
    private var windmill: some View {
            QXWindmill(mode: dash.mode, size: 30)
                .rotationEffect(.degrees(spin ? 360 : 0))
                .animation(spin ? .linear(duration: 6).repeatForever(autoreverses: false) : .default, value: spin)
                .onAppear { spin = vpn.isConnected }
                .onChange(of: vpn.isConnected) { on in spin = on }
                .frame(width: QXMetrics.windmillCircle, height: QXMetrics.windmillCircle)
                .background(Circle().fill(Theme.card))
                .overlay(Circle().stroke(Color.primary.opacity(0.09), lineWidth: 1))
                .contentShape(Circle())
                .onTapGesture {
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    if nav.padLayout { nav.path = [] } else { nav.push(.settings) }
                }
                .onLongPressGesture(minimumDuration: 0.4) {
                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    nav.present(.runMode)
                }
                .accessibilityElement()
                .accessibilityLabel(Text("设置"))
                .accessibilityHint(Text("长按切换运行模式"))
                .accessibilityAddTraits(.isButton)
    }

    private func icon(_ name: String) -> some View {
        Image(systemName: name)
            .font(.system(size: 22, weight: .light))
            .foregroundStyle(.primary)
            .frame(maxWidth: .infinity, minHeight: 50)
            .contentShape(Rectangle())
    }
}

// MARK: - Run mode sheet (windmill long-press)

struct QXRunModeSheet: View {
    @EnvironmentObject var dash: DashboardModel
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var engine = EngineStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var updating = false
    @State private var result: String?

    var modeName: String {
        switch dash.mode {
        case "global": return String(localized: "全局代理")
        case "direct": return String(localized: "全局直连")
        default: return String(localized: "规则分流")
        }
    }

    var body: some View {
        VStack(spacing: 22) {
            HStack(spacing: 10) {
                chip("MitM", on: engine.config.mitm) { engine.config.mitm.toggle(); engine.save() }
                chip(String(localized: "重写"), on: engine.config.enabled) { engine.config.enabled.toggle(); engine.save() }
                chip(String(localized: "HTTP 抓取"), on: engine.config.captureBodies ?? true) {
                    engine.config.captureBodies = !(engine.config.captureBodies ?? true); engine.save()
                }
            }
            .padding(.top, 24)

            Text("运行模式 · \(modeName)")
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 14).padding(.vertical, 7)
                .background(Capsule().fill(Theme.cardHi))

            HStack(spacing: 18) {
                modeButton("global", String(localized: "全局代理"))
                modeButton("direct", String(localized: "全局直连"))
                modeButton("rule", String(localized: "规则分流"))
            }

            Button {
                Task { await updateAll() }
            } label: {
                HStack(spacing: 8) {
                    if updating { ProgressView().controlSize(.small) } else { Image(systemName: "arrow.triangle.2.circlepath") }
                    Text("一键更新").font(.body.weight(.semibold))
                }
                .frame(maxWidth: .infinity, minHeight: 50)
                .background(RoundedRectangle(cornerRadius: 25, style: .continuous).fill(Theme.cardHi))
            }
            .buttonStyle(.plain)
            .disabled(updating)
            .padding(.horizontal, 24)
            if let result {
                Text(verbatim: result).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(.horizontal, 24)
            } else {
                Text("更新全部订阅、规则集、模块与节点集。").font(.footnote).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity)
        .background(Theme.bg.ignoresSafeArea())
    }

    private func chip(_ title: String, on: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Text(verbatim: title).font(.subheadline.weight(.semibold))
                Text(on ? LocalizedStringKey("已开启") : LocalizedStringKey("已关闭")).font(.caption2)
            }
            .foregroundStyle(on ? Color.white : Color.primary)
            .frame(maxWidth: .infinity, minHeight: 52)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(on ? QXColor.switchOn : Theme.cardHi))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 0)
    }

    private func modeButton(_ mode: String, _ title: String) -> some View {
        Button {
            Task { await dash.setMode(mode) }
            UISelectionFeedbackGenerator().selectionChanged()
        } label: {
            VStack(spacing: 8) {
                QXWindmill(mode: mode, size: 34)
                    .frame(width: 72, height: 72)
                    .background(Circle().fill(Theme.card))
                    .overlay(Circle().stroke(dash.mode == mode ? QXColor.switchOn : Color.primary.opacity(0.08), lineWidth: dash.mode == mode ? 2.5 : 1))
                Text(verbatim: title).font(.footnote.weight(dash.mode == mode ? .semibold : .regular)).foregroundStyle(.primary)
            }
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(dash.mode == mode ? .isSelected : [])
    }

    /// 一键更新: subscriptions, rule sets / scripts in the resource manager, modules, and (connected) every provider.
    private func updateAll() async {
        updating = true
        defer { updating = false }
        result = nil
        let errs = await store.refreshAll()
        await ResourceStore.shared.updateAll()
        await engine.updateAllModules()
        var providerFails = 0
        if vpn.isConnected {
            let c = ControllerClient.shared
            for p in (try? await c.proxyProviders()) ?? [] where p.vehicleType == "HTTP" {
                do { try await c.updateProxyProvider(p.name) } catch { providerFails += 1 }
            }
            for p in (try? await c.ruleProviders()) ?? [] where p.vehicleType == "HTTP" {
                do { try await c.updateRuleProvider(p.name) } catch { providerFails += 1 }
            }
        }
        if errs.isEmpty && providerFails == 0 {
            result = String(localized: "已全部更新")
        } else {
            var lines = errs
            if providerFails > 0 { lines.append(String(localized: "\(providerFails) 个提供者更新失败")) }
            result = lines.joined(separator: "\n")
        }
        UINotificationFeedbackGenerator().notificationOccurred(errs.isEmpty ? .success : .warning)
    }
}
