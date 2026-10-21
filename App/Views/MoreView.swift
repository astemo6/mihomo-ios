import SwiftUI
import Combine
import NetworkExtension
import Libmihomo

struct MoreView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var router = ImportRouter.shared
    @State private var showOnboarding = false
    @AppStorage(LaunchTab.key) private var launchRaw = 0
    /// fix/nav-jank: the 首页流量统计 row reads the stored setting instead of observing DashboardModel, which
    /// publishes every second and rebuilt this list and every pushed page (LazyDestination closures are never
    /// equal) during push / pop.
    @AppStorage(TrafficScope.key, store: AppShared.defaults) private var scopeRaw = TrafficScope.all.rawValue

    /// Every node 节点与订阅 lists (全部节点); nil before the list loaded. (Kept for callers; feat/surge-ui
    /// no longer shows the count on the 更多 row.)
    static func nodeTotal(_ nodes: [ManagedNode]) -> Int? { nodes.isEmpty ? nil : nodes.count }

    /// feat/surge-ui (user 「现在的感觉有点专业工具风」): calmer 更多 — short section headers, one tile per row,
    /// plain-language titles with the technical term as a small subtitle, no counters on the top level,
    /// expert pages under 高级设置. Row ids stay `more.<old zh-Hans key>` so UI tests and muscle memory hold.
    var body: some View {
        NavigationStack {
            List {
                // feat/more-dedup (user 2026-10-21 18:06): the 配置 tab is gone; 配置管理 is the first row here and the
                // tool-type pages (节点与订阅, 规则, 模块, logs, network tools) are cards on the 工具 tab.
                Section {
                    NavigationLink { LazyDestination { ProfilesView() } } label: {
                        MoreRow(id: "配置", title: "配置", symbol: "doc.text.fill", tone: .blue,
                                value: store.active?.displayName ?? String(localized: "未选择"))
                    }
                }
                .listRowBackground(Theme.card)

                Section("已保存数据") {
                    NavigationLink { LazyDestination { StatsView() } } label: {
                        MoreRow(id: "流量统计", title: "流量统计", symbol: "chart.bar.fill", tone: .red)
                    }
                    NavigationLink { LazyDestination { SnapshotsView() } } label: {
                        MoreRow(id: "配置快照", title: "配置快照", symbol: "clock.arrow.circlepath", tone: .purple)
                    }
                    NavigationLink { LazyDestination { BackupView() } } label: {
                        MoreRow(id: "备份与恢复", title: "备份与恢复", symbol: "externaldrive.badge.icloud", tone: .blue)
                    }
                    NavigationLink { LazyDestination { UpdateResourcesView() } } label: {
                        MoreRow(id: "更新资源", title: "更新资源", subtitle: "订阅 · 模块 · 规则集 · 脚本", symbol: "arrow.triangle.2.circlepath", tone: .green)
                    }
                    NavigationLink { LazyDestination { StorageView() } } label: {
                        MoreRow(id: "存储空间", title: "存储空间", symbol: "internaldrive", tone: .neutral)
                    }
                }
                .listRowBackground(Theme.card)

                Section("外观") {
                    NavigationLink { LazyDestination { AppearanceView() } } label: {
                        MoreRow(id: "外观", title: "深色与浅色", symbol: "circle.lefthalf.filled", tone: .accent)
                    }
                    if UIApplication.shared.supportsAlternateIcons {
                        NavigationLink { LazyDestination { AppIconView() } } label: {
                            MoreRow(id: "App 图标", title: "App 图标", symbol: "app.badge", tone: .orange)
                        }
                    }
                    NavigationLink { LazyDestination { LaunchTabView() } } label: {
                        MoreRow(id: "开始标签页", title: "开始标签页", symbol: "rectangle.stack", tone: .green, value: (AppSection(rawValue: launchRaw) ?? .home).title)
                    }
                    NavigationLink { LazyDestination { TrafficScopeView() } } label: {
                        MoreRow(id: "首页流量统计", title: "首页流量统计", symbol: "arrow.up.arrow.down", tone: .teal, value: (TrafficScope(rawValue: scopeRaw) ?? .all).title)
                    }
                }
                .listRowBackground(Theme.card)

                Section {
                    NavigationLink { LazyDestination { AdvancedSettingsView() } } label: {
                        MoreRow(id: "高级设置", title: "高级设置", subtitle: "连接方式 · 内核 · 测速", symbol: "gearshape.2", tone: .neutral)
                    }
                } header: { Text("高级") }
                .listRowBackground(Theme.card)

                Section("帮助") {
                    Button { showOnboarding = true } label: {
                        MoreRow(id: "新手引导", title: "新手引导", symbol: "sparkles", tone: .accent)
                    }
                    .foregroundStyle(.primary)
                    NavigationLink { LazyDestination { DiagnosticsView() } } label: {
                        MoreRow(id: "诊断", title: "诊断与反馈", symbol: "waveform.path.ecg", tone: .red,
                                value: AppShared.containerOK ? nil : "共享容器异常", valueColor: Theme.bad)
                    }
                    NavigationLink { LazyDestination { AboutView() } } label: {
                        MoreRow(id: "关于 / 开源许可", title: "关于", symbol: "info.circle", tone: .neutral)
                    }
                }
                .listRowBackground(Theme.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("更多")
            .navigationDestination(isPresented: $router.openProfiles) { ProfilesView() }
            .fullScreenCover(isPresented: $showOnboarding) {
                OnboardingView { showOnboarding = false }
                    .environmentObject(vpn)
                    .environmentObject(store)
            }
        }
    }
}

/// A 更多 / 高级设置 row. `id` is the stable zh-Hans key behind `more.<id>` (UI tests); `needsVPN` greys the
/// row with 「需开启 VPN」 while disconnected (still tappable: the page shows why and offers 连接).
struct MoreRow: View {
    @ObservedObject private var vpn = VPNManager.shared
    let id: String
    let title: String
    var subtitle: String? = nil
    let symbol: String
    var tone: TileTone = .accent
    var value: String? = nil
    var valueColor: Color = .secondary
    var needsVPN = false

    var body: some View {
        let off = needsVPN && !vpn.isConnected
        TileRow(title: title, subtitle: subtitle, symbol: symbol, tone: tone,
                value: off ? "需开启 VPN" : value, valueColor: valueColor, dimmed: off)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("more." + id)
    }
}

/// feat/surge-ui: the expert pages that used to fill 更多, grouped by what they change.
/// feat/more-dedup: 重写 / 脚本 / 定时任务 / 规则集 live only on 工具 → 模块, 节点集 only on 节点与订阅;
/// this page keeps what changes how the tunnel itself works.
struct AdvancedSettingsView: View {
    @ObservedObject var engine = EngineStore.shared
    // fix/nav-jank: the values are there on the first frame. They used to be filled in onAppear, so 连接方式 /
    // DNS got their trailing text mid-push and the rows re-laid out while sliding in.
    @State private var connLabel: String
    @State private var dnsLabel: String

    init() {
        let l = Self.labels()
        _connLabel = State(initialValue: l.conn)
        _dnsLabel = State(initialValue: l.dns)
    }

    static func labels() -> (conn: String, dns: String) {
        let o = CoreOverrides.load()
        let conn = o.isProxyOnly ? String(localized: "仅代理") : o.isMixed ? String(localized: "VPN 混合") : "TUN"
        let dns = DNSOverrideSettings.load().enabled ? String(localized: "自定义") : String(localized: "配置文件")
        return (conn, dns)
    }

    /// Back from 连接方式 / DNS: only a changed value is written (no update when nothing changed).
    func refreshLabels() {
        let l = Self.labels()
        if connLabel != l.conn { connLabel = l.conn }
        if dnsLabel != l.dns { dnsLabel = l.dns }
    }

    var body: some View {
        List {
            Section("网络") {
                NavigationLink { LazyDestination { ConnectionView() } } label: {
                    MoreRow(id: "连接方式", title: "连接方式", symbol: "point.3.filled.connected.trianglepath.dotted", tone: .blue, value: connLabel)
                }
            }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink { LazyDestination { GeoView() } } label: {
                    MoreRow(id: "地理与规则库", title: "地理数据库", subtitle: "GeoIP · GeoSite", symbol: "globe.asia.australia", tone: .green)
                }
            } header: { Text("数据") } footer: {
                Text("HTTPS 解密、DNS、模块、重写、脚本和规则都在「工具」标签页。")
            }
            .listRowBackground(Theme.card)

            Section("内核与测速") {
                NavigationLink { LazyDestination { SettingsView() } } label: {
                    MoreRow(id: "内核设置", title: "内核设置", symbol: "slider.horizontal.3", tone: .neutral)
                }
                NavigationLink { LazyDestination { SpeedTestSettingsView() } } label: {
                    MoreRow(id: "测速", title: "测速设置", symbol: "bolt.horizontal", tone: .orange)
                }
                NavigationLink { LazyDestination { GeoCheckerView() } } label: {
                    MoreRow(id: "出口信息查询", title: "出口信息来源", symbol: "mappin.and.ellipse", tone: .pink)
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("高级设置")
        .onAppear { refreshLabels() }
    }
}

/// 更多 → 首页流量统计 (feat/traffic-scope): what Home's speed, totals, tiles and the Live Activity count.
struct TrafficScopeView: View {
    @ObservedObject private var dash = DashboardModel.shared

    var body: some View {
        List {
            Section {
                ForEach(TrafficScope.allCases) { s in
                    Button { dash.scope = s } label: {
                        HStack(spacing: 12) {
                            IconTile(symbol: s == .all ? "globe" : "paperplane", tone: dash.scope == s ? .accent : .neutral)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(LocalizedStringKey(s.title)).foregroundStyle(.primary)
                                Text(s == .all ? "经过 Tern 的所有流量，包括直连" : "只算经代理节点发出的流量，不含直连和拒绝")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if dash.scope == s {
                                Image(systemName: "checkmark").font(.body.weight(.semibold)).foregroundStyle(Theme.accent)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(dash.scope == s ? .isSelected : [])
                    .accessibilityIdentifier("trafficScope.\(s.rawValue)")
                }
            } footer: {
                Text("用于首页的网速、总上传 / 总下载、首页卡片和实时活动。选「仅代理流量」时，数字旁会标「仅代理」。「流量统计」页的每日记录不受影响。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("首页流量统计")
    }
}

/// 更多 → 开始标签页: which tab the app opens on (UI tests always start on 首页).
enum LaunchTab {
    static let key = "ui.launchTab"
    static var current: AppSection {
        AppSection(rawValue: UserDefaults.standard.integer(forKey: key)) ?? .home
    }
    static var initial: Int { UITestSeed.enabled ? 0 : current.rawValue }
}

struct LaunchTabView: View {
    @AppStorage(LaunchTab.key) private var raw = 0

    var body: some View {
        List {
            Section {
                ForEach(AppSection.allCases) { s in
                    Button { raw = s.rawValue } label: {
                        HStack(spacing: 12) {
                            IconTile(symbol: s.icon, tone: raw == s.rawValue ? .accent : .neutral)
                            Text(LocalizedStringKey(s.title)).foregroundStyle(.primary)
                            Spacer()
                            if raw == s.rawValue {
                                Image(systemName: "checkmark").font(.body.weight(.semibold)).foregroundStyle(Theme.accent)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(raw == s.rawValue ? .isSelected : [])
                    .accessibilityIdentifier("launchTab.\(s.rawValue)")
                }
            } footer: { Text("下次打开 App 时从这里开始。") }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("开始标签页")
    }
}

// MARK: - Logs

@MainActor
final class LogsModel: ObservableObject {
    @Published var lines: [LogLine] = []
    @Published var paused = false
    private var task: Task<Void, Never>?
    static let limit = 1000

    init() {
        if UITestSeed.enabled { seedDemo() }
    }

    /// v0.19.8: the history the extension kept since the tunnel started (GET /hark/logs) first, then the live
    /// stream; before this the page was empty until something new was logged while it was open.
    func start(level: String) {
        task?.cancel()
        task = Task { [weak self] in
            var join = LogJoin(history: [])
            if let h = try? await ControllerClient.shared.harkLogs(kind: "general", level: level), let self, !Task.isCancelled {
                let logs = h.logs ?? []
                let old = logs.map { LogLine(level: $0.type, message: $0.payload, time: Date(timeIntervalSince1970: Double($0.time) / 1000)) }
                let seen = Set(logs.map(\.payload))
                self.lines = Array((old + self.lines.filter { !seen.contains($0.message) }).suffix(Self.limit))
                join = LogJoin(history: logs)
            }
            while !Task.isCancelled {
                for await l in ControllerClient.shared.stream("/logs", query: [URLQueryItem(name: "level", value: level)], as: LogPayload.self) {
                    guard let self else { return }
                    if self.paused || join.isDuplicate(l.payload) { continue }
                    self.lines.append(LogLine(level: l.type, message: l.payload, time: Date()))
                    if self.lines.count > Self.limit { self.lines.removeFirst(self.lines.count - Self.limit) }
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    /// 清空: the page and the extension's history (otherwise the next open brings the lines back).
    func clear() {
        lines.removeAll()
        Task { try? await ControllerClient.shared.harkClearLogs(kind: "general") }
    }

    /// Synthetic lines for the simulator UI tests (documentation names and addresses only).
    private func seedDemo() {
        let t = Date()
        let demo: [(String, String)] = [
            ("info", "[TCP] 198.18.0.1:50001 --> www.example.com:443 match DomainSuffix(example.com) using Proxy[Demo HK]"),
            ("info", "[UDP] 198.18.0.1:50002 --> 192.0.2.53:53 match GeoIP(private) using DIRECT"),
            ("warning", "[Provider] uitest-provider pull error: context deadline exceeded"),
            ("error", "[Core] demo error line"),
        ]
        lines = demo.enumerated().map { i, d in LogLine(level: d.0, message: d.1, time: t.addingTimeInterval(Double(i - demo.count))) }
    }
}

struct LogsView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = LogsModel()
    @State private var level = "info"
    @State private var search = ""

    var shown: [LogLine] {
        guard !search.isEmpty else { return model.lines }
        return model.lines.filter { $0.message.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        Group {
            if !vpn.isConnected && model.lines.isEmpty { NotConnectedPlaceholder() } else {
                VStack(spacing: 0) {
                    Picker("级别", selection: $level) {
                        Text("调试").tag("debug")
                        Text("信息").tag("info")
                        Text("警告").tag("warning")
                        Text("错误").tag("error")
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 12).padding(.top, 12)
                    Text("从连接开始记录，最多保留最近 2000 条。")
                        .font(.caption2).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        .accessibilityIdentifier("logs.hint")
                    ScrollViewReader { proxy in
                        List(shown) { l in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(l.level.uppercased()).scaledFont(9, weight: .bold).foregroundStyle(color(l.level))
                                    Text(l.time.formatted(date: .omitted, time: .standard)).scaledFont(9, monospacedDigit: true).foregroundStyle(.secondary)
                                }
                                Text(l.message).scaledFont(11, design: .monospaced).textSelection(.enabled)
                            }
                            .id(l.id)
                            .listRowBackground(Theme.card)
                            .accessibilityIdentifier("logs.line")
                        }
                        .listStyle(.plain)
                        .scrollContentBackground(.hidden)
                        // The last id, not the count: at the 1000-line cap every append is followed by a removeFirst.
                        .onChange(of: model.lines.last?.id) { _ in
                            if !model.paused, let last = shown.last { proxy.scrollTo(last.id, anchor: .bottom) }
                        }
                    }
                }
                .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "过滤日志")
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("日志")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button { model.paused.toggle() } label: { Image(systemName: model.paused ? "play.fill" : "pause.fill") }
                Button { model.clear() } label: { Image(systemName: "trash") }
                    .accessibilityLabel(Text("清空"))
                    .accessibilityIdentifier("logs.clear")
                Button { UIPasteboard.general.string = model.lines.map { "[\($0.level)] \($0.message)" }.joined(separator: "\n") } label: { Image(systemName: "doc.on.doc") }
            }
        }
        .onAppear { if vpn.isConnected { model.start(level: level) } }
        .onDisappear { model.stop() }
        .onChange(of: level) { l in model.lines.removeAll(); model.start(level: l) }
    }

    func color(_ l: String) -> Color {
        switch l {
        case "error": return Theme.bad
        case "warning": return Theme.warn
        case "debug": return .secondary
        default: return Theme.accent
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var o = CoreOverrides.load()
    @AppStorage(ControllerClient.closeOnSwitchKey, store: AppShared.defaults) private var closeOnSwitch = true
    @State private var portText = ""
    @State private var status: String?
    @StateObject private var debounce = Debouncer()

    private var portInvalid: Bool { Int(portText).map { !(1024...65535).contains($0) } ?? true }

    var body: some View {
        Form {
            Section {
                Picker("日志级别", selection: $o.logLevel) {
                    Text("静默").tag("silent")
                    Text("错误").tag("error")
                    Text("警告").tag("warning")
                    Text("信息").tag("info")
                    Text("调试").tag("debug")
                }
                Toggle("域名嗅探（Sniffer）", isOn: $o.sniffer)
            } header: { Text("内核") } footer: {
                Text("这些选项会覆盖配置文件里的同名字段。DNS 模式在「工具 → DNS」中设置，IPv6 与局域网共享在「更多 → 高级设置 → 连接方式」中设置。")
            }
            .listRowBackground(Theme.card)

            Section {
                Toggle("切换节点或模式时断开所有连接", isOn: $closeOnSwitch)
                    .accessibilityIdentifier("settings.closeOnSwitch")
                Toggle("网络变化时清空 DNS 缓存", isOn: $o.flushDNSOnNetworkChange)
                    .accessibilityIdentifier("settings.flushDNS")
            } header: { Text("连接") } footer: {
                Text("断开后，App 会经由新选的节点或模式重新连接；关闭则已有连接保持原来的节点直到结束。Wi-Fi 与蜂窝网络切换或换了 Wi-Fi 时清空 DNS 缓存，避免沿用上一个网络的解析结果。")
            }
            .listRowBackground(Theme.card)

            Section {
                Stepper(value: $o.memoryLimitMB, in: CoreOverrides.memoryLimitRange, step: 1) {
                    HStack {
                        Text("内核内存上限")
                        Spacer()
                        Text("\(o.memoryLimitMB) MB").monospacedDigit().foregroundStyle(.secondary)
                    }
                }
                Picker("隧道 MTU", selection: $o.tunMTU) {
                    ForEach(CoreOverrides.mtuChoices, id: \.self) { Text(String($0)).tag($0) }
                }
            } header: { Text("性能") } footer: {
                Text("iOS 限制网络扩展约 50 MB 内存。内存上限是 Go 运行时的软上限（默认 \(CoreOverrides.defaultMemoryLimitMB) MB）：调低更稳但更费电，调高可容纳更多连接。接近系统上限时扩展会先释放内存，再关闭连接。MTU 默认 4064，遇到个别网络异常可改为 1500。两项都在重新连接后生效。")
            }
            .listRowBackground(Theme.card)

            Section("外部控制器") {
                HStack {
                    Text("端口")
                    Spacer()
                    TextField("9090", text: $portText).keyboardType(.numberPad).multilineTextAlignment(.trailing).frame(width: 90)
                        .accessibilityIdentifier("settings.port")
                }
                if portInvalid {
                    Label("端口应为 1024–65535，修改前不会应用。", systemImage: "exclamationmark.triangle")
                        .font(.footnote).foregroundStyle(Theme.warn)
                }
                HStack {
                    Text("密钥")
                    Spacer()
                    Text(String(o.secret.prefix(6)) + "••••").font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                }
                Button("重新生成密钥") { o.secret = CoreOverrides.randomSecret() }
                Text("仅监听 127.0.0.1。").font(.caption).foregroundStyle(.secondary)
            }
            .listRowBackground(Theme.card)

            if status != nil {
                Section { AutoApplyFooter(status: status) }
                    .listRowBackground(Theme.card)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("内核设置")
        .onAppear {
            debounce.flush()
            o = CoreOverrides.load()
            // Review 6: a port that is not valid yet is never saved; keep what the user typed instead of resetting it.
            if portText.isEmpty || !portInvalid { portText = String(o.controllerPort) }
        }
        // v0.15.4: applied on change (debounced), no 保存 button.
        .onChange(of: o) { _ in debounce.schedule { apply() } }
        .onChange(of: portText) { _ in debounce.schedule { apply() } }
        .onDisappear { debounce.flush() }
    }

    func apply() {
        // Only this page's fields; everything else stays as the other pages saved it.
        let old = CoreOverrides.load()
        var cur = old
        cur.logLevel = o.logLevel
        cur.sniffer = o.sniffer
        cur.memoryLimitMB = o.memoryLimitMB
        cur.tunMTU = o.tunMTU
        cur.secret = o.secret
        cur.flushDNSOnNetworkChange = o.flushDNSOnNetworkChange // v0.19 (was not saved)
        if !portInvalid, let p = Int(portText) { cur.controllerPort = p }
        guard cur != old else { return }
        cur.save()
        ControllerClient.shared.invalidateCredentials() // v0.19.2 (port / secret are cached for 3 s)
        Task {
            if vpn.isConnected {
                let reconnect = old.controllerPort != cur.controllerPort || old.secret != cur.secret || old.tunMTU != cur.tunMTU || old.memoryLimitMB != cur.memoryLimitMB
                if let err = await ReloadCoalescer.shared.reload(vpn) { status = String(localized: "重载失败：\(err)") }
                else if reconnect { status = String(localized: "已保存。端口 / 密钥 / IPv6 / MTU / 内存上限在断开后重新连接时生效。") }
                else { status = String(localized: "已保存并重载") }
            } else {
                status = String(localized: "已保存，下次连接生效")
            }
        }
    }
}

// MARK: - Diagnostics

struct DiagnosticsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var startupLog = StartupLog.read()
    @State private var exporting = false
    @State private var share: ShareItem?
    @State private var exportError: String?
    @State private var copied = false

    var body: some View {
        let group = AppShared.appGroup
        List {
            TunnelMemorySection()
            Section {
                Button {
                    Task { await exportBundle() }
                } label: {
                    HStack {
                        Label("导出诊断包", systemImage: "square.and.arrow.up").font(.body.weight(.semibold))
                        Spacer()
                        if exporting { ProgressView() }
                    }
                }
                .disabled(exporting)
                Button {
                    Task {
                        UIPasteboard.general.string = await DiagnosticsExporter.summaryText(vpn: vpn)
                        copied = true
                    }
                } label: {
                    Label(copied ? "已复制" : "复制为文本", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .disabled(exporting)
                if let exportError { ErrorRow(message: exportError) }
            } header: { Text("反馈") } footer: {
                Text("一个 zip：App / 扩展 / 内核版本、App Group 状态、启动日志、内核最近日志、内存采样、实际生效的配置和启用的模块。服务器地址、密码、UUID、密钥、订阅链接和令牌都已替换，可以放心发送。")
            }
            .listRowBackground(Theme.card)

            Section {
                LabeledContent("应用版本", value: DiagnosticsExporter.version(of: .main))
                LabeledContent("隧道扩展版本", value: DiagnosticsExporter.version(of: DiagnosticsExporter.tunnelBundle))
                LabeledContent("主程序 ID", value: AppShared.mainAppBundleID)
                LabeledContent("隧道扩展 ID", value: AppShared.tunnelBundleID)
                LabeledContent("内核打包方式", value: FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appendingPathComponent("Frameworks/Libmihomo.framework/Libmihomo").path) ? String(localized: "共享框架（测试版）") : String(localized: "静态链接"))
                LabeledContent("App Group", value: group)
                LabeledContent("来源", value: GoText.localize(AppShared.appGroupSource))
                LabeledContent("共享容器") {
                    Text(AppShared.containerOK ? "正常" : "不可用").foregroundStyle(AppShared.containerOK ? Theme.good : Theme.bad)
                }
                if let w = AppShared.appGroupWarning { Text(w).font(.footnote).foregroundStyle(Theme.bad) } // r7 B05
                let groups = AppShared.provisionedAppGroups()
                LabeledContent("描述文件中的组", value: groups.isEmpty ? String(localized: "（未找到 embedded.mobileprovision）") : groups.sorted().joined(separator: "\n"))
                LabeledContent("VPN 状态", value: vpn.statusText)
                LabeledContent("上次断开原因", value: TunnelStopReason.last() ?? "—")
                let co = CoreOverrides.load()
                LabeledContent("连接方式", value: co.isProxyOnly ? String(localized: "仅代理（NEProxySettings）") : co.isMixed ? String(localized: "VPN 混合（PacketFlowBridge + NEProxySettings）") : String(localized: "全局隧道（PacketFlowBridge）"))
                if vpn.safeModeActive { LabeledContent("安全模式", value: String(localized: "开启")) }
            } header: { Text("签名与容器") } footer: {
                Text("重签名后描述文件会替换 entitlements。App、扩展和小组件会记住第一次使用的 App Group，之后优先用它，其次是已有配置的组；共享容器不可用时扩展无法读取配置，连接会失败。")
            }
            .listRowBackground(Theme.card)
            if let e = vpn.lastError {
                Section("最近错误") { ErrorRow(message: e) }.listRowBackground(Theme.card)
            }
            Section {
                if startupLog.isEmpty {
                    EmptyStateRow(icon: "text.alignleft", title: "暂无启动日志", message: "连接一次后生成。")
                } else {
                    ScrollView(.horizontal) {
                        Text(startupLog)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 360)
                }
                HStack {
                    Button("复制启动日志") { UIPasteboard.general.string = startupLog }.disabled(startupLog.isEmpty)
                    Spacer()
                    Button("刷新") { startupLog = StartupLog.read() }
                }
                .buttonStyle(.borderless)
            } header: { Text("启动日志") } footer: {
                Text("记录每次连接的阶段与耗时：网络设置、数据包桥接、内核启动开始 / 结束、内存占用和错误。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("诊断")
        // fix/nav-jank: init already read it for the first frame; the re-read (two files) runs off main.
        .task {
            let s = await Task.detached(priority: .utility) { StartupLog.read() }.value
            if s != startupLog { startupLog = s }
        }
        .sheet(item: $share) { ActivityView(items: [$0.url]) }
    }

    private func exportBundle() async {
        exporting = true
        exportError = nil
        defer { exporting = false }
        do {
            let url = try await DiagnosticsExporter.export(vpn: vpn)
            share = ShareItem(url: url)
        } catch {
            exportError = String(localized: "导出失败：") + error.localizedDescription
        }
    }
}

// MARK: - About

struct AboutView: View {
    var appVersion: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }

    struct Credit: Identifiable {
        var id: String { name }
        let name: String
        let note: String
        let license: String
        let url: String
    }

    static let credits: [Credit] = [
        Credit(name: "mihomo", note: "代理内核（MetaCubeX）", license: "GPL-3.0", url: "https://github.com/MetaCubeX/mihomo"),
        Credit(name: "TokenPLS/Hako", note: "iOS 客户端设计参考：NetworkExtension 内存控制与 GC 节奏（现 ProjectClash/Clash-Legacy）", license: "GPL-3.0", url: "https://github.com/ProjectClash/Clash-Legacy"),
        Credit(name: "Hako-Adapter", note: "PacketFlowBridge 思路：socketpair 连接 NEPacketTunnelFlow 与内核（现 ProjectClash/Clash-Adapter-Legacy）", license: "GPL-3.0", url: "https://github.com/ProjectClash/Clash-Adapter-Legacy"),
        Credit(name: "ProjectClash", note: "Hako / Hako-Adapter 的维护者，后续项目 Clash-Adapter", license: "GPL-3.0", url: "https://github.com/ProjectClash"),
        Credit(name: "MetaCubeX/meta-rules-dat", note: "内置 GeoIP / GeoSite / ASN 数据库", license: "见上游仓库", url: "https://github.com/MetaCubeX/meta-rules-dat"),
        Credit(name: "goja · gojq · regexp2", note: "脚本、jq 与正则引擎", license: "MIT", url: "https://github.com/dop251/goja"),
    ]

    var body: some View {
        List {
            Section {
                LabeledContent("应用版本", value: appVersion)
                LabeledContent("内核", value: LibmihomoVersion())
            }
            .listRowBackground(Theme.card)
            Section {
                Text("本应用以 GNU General Public License v3.0 发布，与 mihomo 内核许可一致。你可以在 GPL-3.0 的条款下自由使用、修改和再分发本软件及其源代码。本软件不提供任何担保。")
                    .font(.footnote)
                Link("本项目源代码", destination: URL(string: "https://github.com/astemo6/mihomo-ios")!)
                Link("GNU GPL v3.0 全文", destination: URL(string: "https://www.gnu.org/licenses/gpl-3.0.html")!)
            } header: { Text("开源许可") }
            .listRowBackground(Theme.card)
            Section {
                ForEach(Self.credits) { c in
                    Link(destination: URL(string: c.url)!) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(c.name).font(.subheadline.weight(.semibold)).foregroundStyle(.primary)
                                Spacer()
                                Text(LocalizedStringKey(c.license)).font(.caption2.weight(.bold)).foregroundStyle(Theme.accent)
                            }
                            Text(LocalizedStringKey(c.note)).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            } header: { Text("致谢") } footer: {
                Text("PacketFlowBridge 与内存守护参考了 TokenPLS/Hako 与 Hako-Adapter（现 ProjectClash）的设计，均为 GPL-3.0；本项目的实现是独立编写的，同样以 GPL-3.0 发布。完整说明见仓库中的 NOTICE。")
            }
            .listRowBackground(Theme.card)
            Section("说明") {
                Text("仅供个人学习与合法用途。请遵守当地法律法规。").font(.footnote).foregroundStyle(.secondary)
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("关于")
    }
}


// MARK: - App icon

struct AppIconView: View {
    static let icons: [(name: String?, title: String, preview: String)] = [
        (nil, "航线（默认）", "IconPreview-Default"),
        ("AppIcon-Night", "夜航", "IconPreview-Night"),
        ("AppIcon-Sky", "晴空", "IconPreview-Sky"),
    ]
    /// A name that is not in `icons` is a leftover from an icon set an older build shipped (石墨 / 极光 before the
    /// Tern icons); iOS then draws the primary icon, so the picker shows 默认 as selected.
    @State private var current = AppIconView.known(UIApplication.shared.alternateIconName)
    @State private var error: String?

    static func known(_ name: String?) -> String? {
        icons.contains { $0.name == name } ? name : nil
    }

    var body: some View {
        List {
            Section {
                ForEach(Self.icons, id: \.preview) { icon in
                    Button { set(icon.name) } label: {
                        HStack(spacing: 14) {
                            Image(icon.preview)
                                .resizable().scaledToFit()
                                .frame(width: 56, height: 56)
                                .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
                                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(Theme.ink(0.1)))
                            Text(LocalizedStringKey(icon.title)).foregroundStyle(.primary)
                            Spacer()
                            if current == icon.name { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                        }
                    }
                }
            } footer: {
                if let error { Text(error).foregroundStyle(Theme.bad) } else { Text("切换后系统会弹出一次确认提示。") }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("App 图标")
    }

    func set(_ name: String?) {
        guard name != current || UIApplication.shared.alternateIconName != name else { return }
        let stale = UIApplication.shared.alternateIconName.map { Self.known($0) == nil } ?? false
        apply(name, resetFirst: stale)
    }

    /// The system keeps the alternate icon name across updates even when the new build no longer has that icon
    /// (v0.19.13: 石墨 / 极光 were replaced by 夜航 / 晴空). If the stored name is stale, or the first attempt fails,
    /// go back to the primary icon once and then retry, so the request is not made on top of a missing icon.
    private func apply(_ name: String?, resetFirst: Bool, retried: Bool = false) {
        if resetFirst && name != nil {
            UIApplication.shared.setAlternateIconName(nil) { _ in
                DispatchQueue.main.async { apply(name, resetFirst: false, retried: true) }
            }
            return
        }
        UIApplication.shared.setAlternateIconName(name) { err in
            DispatchQueue.main.async {
                if let err {
                    if !retried && name != nil {
                        apply(name, resetFirst: true)
                        return
                    }
                    let ns = err as NSError
                    error = "\(ns.localizedDescription) (\(ns.domain) \(ns.code))"
                    current = Self.known(UIApplication.shared.alternateIconName)
                } else { current = name; error = nil }
            }
        }
    }
}

/// 更多 → 测速: the URL and timeout every manual latency test uses (live through the core, offline from
/// the app), and whether the profile's group health checks should use the same URL.
struct SpeedTestSettingsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var choice = CoreOverrides.defaultTestURL
    @State private var custom = ""
    @State private var timeoutSec = 5
    @State private var overrideHC = false
    @State private var status: String?
    @StateObject private var debounce = Debouncer()

    private static let customTag = "__custom__"

    private var effectiveURL: String {
        choice == Self.customTag ? custom.trimmingCharacters(in: .whitespaces) : choice
    }
    private var customInvalid: Bool { choice == Self.customTag && !CoreOverrides.isValidTestURL(custom) }

    var body: some View {
        Form {
            Section {
                Picker("测速地址", selection: $choice) {
                    ForEach(CoreOverrides.testURLPresets, id: \.self) { u in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(LocalizedStringKey(CoreOverrides.testURLLabels[u] ?? (URL(string: u)?.host ?? u)))
                            Text(verbatim: u).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        }
                        .tag(u)
                    }
                    Text("自定义").tag(Self.customTag)
                }
                .pickerStyle(.inline)
                .labelsHidden()
                if choice == Self.customTag {
                    TextField("https://example.com/generate_204", text: $custom)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                    if customInvalid && !custom.isEmpty {
                        Label("请输入以 http:// 或 https:// 开头的完整地址", systemImage: "exclamationmark.triangle")
                            .font(.footnote).foregroundStyle(Theme.warn)
                    }
                }
            } header: { Text("测速地址") } footer: {
                Text("策略页的测速都用这个地址：连接时经由内核通过各节点访问，未连接时从本机直接测试。地址应快速返回 204 或 200。")
            }
            .listRowBackground(Theme.card)

            Section {
                Stepper(value: $timeoutSec, in: 1...30) {
                    HStack {
                        Text("超时")
                        Spacer()
                        Text("\(timeoutSec) 秒").monospacedDigit().foregroundStyle(.secondary)
                    }
                }
            } footer: { Text("超过这个时间仍未返回的节点显示为「超时」。默认 5 秒。") }
            .listRowBackground(Theme.card)

            Section {
                Toggle("健康检查也使用此地址", isOn: $overrideHC)
            } footer: {
                Text("默认关闭：自动选择 / 故障转移策略组和节点集按配置文件里的地址做健康检查。开启后统一改用上面的地址，重新连接或重载后生效。")
            }
            .listRowBackground(Theme.card)

            if status != nil {
                Section { AutoApplyFooter(status: status) }
                    .listRowBackground(Theme.card)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("测速")
        .onAppear {
            // Review 6: an invalid custom URL is not saved; re-reading on every appearance replaced it with the preset.
            debounce.flush()
            if !customInvalid { loadValues() }
        }
        // v0.15.4: applied on change (debounced), no 保存 button; an invalid custom URL is not applied.
        .onChange(of: choice) { _ in debounce.schedule { save() } }
        .onChange(of: custom) { _ in debounce.schedule { save() } }
        .onChange(of: timeoutSec) { _ in debounce.schedule { save() } }
        .onChange(of: overrideHC) { _ in debounce.schedule { save() } }
        .onDisappear { debounce.flush() }
    }

    private func loadValues() {
        let o = CoreOverrides.load()
        if CoreOverrides.testURLPresets.contains(o.testURL) {
            choice = o.testURL
        } else {
            choice = Self.customTag
            custom = o.testURL
        }
        timeoutSec = max(1, min(30, o.testTimeoutMs / 1000))
        overrideHC = o.overrideHealthCheck
    }

    private func save() {
        guard CoreOverrides.isValidTestURL(effectiveURL) else { return }
        // Only this page's fields; everything else stays as the other pages saved it.
        var o = CoreOverrides.load()
        let old = o
        o.testURL = effectiveURL
        o.testTimeoutMs = timeoutSec * 1000
        o.overrideHealthCheck = overrideHC
        guard o != old else { return }
        o.save()
        let healthCheckChanged = old.overrideHealthCheck != o.overrideHealthCheck || (o.overrideHealthCheck && old.testURL != o.testURL)
        guard vpn.isConnected, healthCheckChanged else {
            status = String(localized: "已保存")
            return
        }
        Task {
            if let err = await ReloadCoalescer.shared.reload(vpn) {
                status = String(localized: "重载失败：\(err)")
            } else {
                status = String(localized: "已保存并重载")
            }
        }
    }
}
