import SwiftUI

// feat/more-dedup (user 2026-10-21 18:06, modelled on Egern's 工具 page): the 工具 tab replaces the old 配置 tab.
// Large rounded cards — colored square icon, title, a row of small icon + count stats — for every tool-type
// page (节点与订阅, 分流规则, 模块, 重写, 脚本, 定时任务, HTTPS 解密, DNS, logs and network tools). Settings-type
// pages stay in 更多; 配置管理 is the first row of 更多. Card ids keep the old `more.<zh-Hans key>` so UI tests
// and deep links hold. Counts are a snapshot taken when the tab appears (nothing here observes a
// frequently-publishing store, see fix/nav-jank).

/// One small stat under a card title: an SF Symbol and a short value ("3", "13/15", "已信任").
struct ToolStat: Hashable {
    var symbol: String
    var value: String
    /// Spoken label, e.g. 「订阅 3」.
    var label: String
    var tint: Color? = nil
}

/// The numbers the cards show, read once per appearance off the stores' current values.
struct ToolStats: Equatable {
    var profileSubs = 0
    var nodeSubs = 0
    var nodes = 0
    var nodesTested = 0
    var nodesAlive = 0
    var profileRules = 0
    var ruleProviders = 0
    var customRules = 0
    var customRulesOn = 0
    var modules = 0
    var modulesOn = 0
    var engineOn = false
    var rewrites = 0
    var rewritesOn = 0
    var moduleRewrites = 0
    var hostnames = 0
    var scripts = 0
    var scriptsOn = 0
    var moduleScripts = 0
    var tasksPaused = false
    var mitmOn = false
    var caExists = false
    var caTrusted: Bool?
    var dnsCustom = false
    var dnsServers = 0

    @MainActor static func current() -> ToolStats {
        var s = ToolStats()
        let ps = ProfileStore.shared
        s.profileSubs = ps.profiles.filter { $0.kind == .remote }.count
        s.nodeSubs = NodeSubStore.shared.subs.count
        let insp = ProfileInspector.shared
        let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
        let names = Set(insp.nodeIndex.keys).subtracting(builtins)
        s.nodes = names.count
        let measured = names.compactMap { insp.delays[$0] }
        s.nodesTested = measured.count
        s.nodesAlive = measured.filter { $0 > 0 }.count
        s.profileRules = insp.result.rules.count
        s.ruleProviders = insp.result.ruleProviders.count
        let cr = CustomRulesStore.shared.rules
        s.customRules = cr.count
        s.customRulesOn = cr.filter(\.enabled).count
        let es = EngineStore.shared
        let cfg = es.config
        s.engineOn = cfg.enabled
        s.modules = cfg.modules.count
        s.modulesOn = cfg.modules.filter(\.enabled).count
        s.rewrites = cfg.rules.count
        s.rewritesOn = cfg.rules.filter(\.enabled).count
        s.scripts = cfg.scripts.count
        s.scriptsOn = cfg.scripts.filter(\.enabled).count
        let mc = es.enabledModuleCounts
        s.moduleRewrites = mc.rewrites
        s.moduleScripts = mc.scripts
        s.hostnames = cfg.hostnames.filter { !$0.hasPrefix("-") }.count + mc.hosts
        s.tasksPaused = TaskPrefs.load().paused
        s.mitmOn = cfg.mitm
        s.caExists = es.caInfo.exists
        s.caTrusted = es.caTrusted
        let dns = DNSOverrideSettings.load()
        s.dnsCustom = dns.enabled
        s.dnsServers = dns.nameserver.count + dns.foreign.count
        return s
    }
}

struct ToolsTabView: View {
    var body: some View {
        NavigationStack { ToolsList() }
    }
}

struct ToolsList: View {
    @State private var stats = ToolStats.current()
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        List {
            Section {
                card("节点与订阅", "节点与订阅", "server.rack", .blue, stats: nodeStats) { NodeManagerView() }
                card("规则", "分流规则", "arrow.triangle.branch", .orange, stats: [
                    ToolStat(symbol: "list.bullet", value: "\(stats.profileRules)", label: String(localized: "配置规则 \(stats.profileRules)")),
                    ToolStat(symbol: "square.stack.3d.up", value: "\(stats.ruleProviders)", label: String(localized: "规则集 \(stats.ruleProviders)")),
                    ToolStat(symbol: "pencil.line", value: "\(stats.customRulesOn)/\(stats.customRules)", label: String(localized: "自定义规则 \(stats.customRulesOn)/\(stats.customRules)")),
                ]) { RulesView() }
            }
            .listRowBackground(Theme.card)

            Section {
                card("模块与资源", "模块", "puzzlepiece.extension", .green, stats: [
                    ToolStat(symbol: "puzzlepiece", value: "\(stats.modulesOn)/\(stats.modules)", label: String(localized: "已启用模块 \(stats.modulesOn)/\(stats.modules)")),
                ] + engineOffStat) { ModulesView() }
                card("重写（本地模块）", "重写", "arrow.triangle.swap", .red, stats: [
                    ToolStat(symbol: "pencil", value: "\(stats.rewritesOn)/\(stats.rewrites)", label: String(localized: "我的重写 \(stats.rewritesOn)/\(stats.rewrites)")),
                    ToolStat(symbol: "puzzlepiece", value: "\(stats.moduleRewrites)", label: String(localized: "模块重写 \(stats.moduleRewrites)")),
                    ToolStat(symbol: "globe", value: "\(stats.hostnames)", label: String(localized: "MitM 主机名 \(stats.hostnames)")),
                ]) { LocalModuleView() }
                card("脚本", "脚本", "curlybraces", .purple, stats: [
                    ToolStat(symbol: "doc.text", value: "\(stats.scriptsOn)/\(stats.scripts)", label: String(localized: "我的脚本 \(stats.scriptsOn)/\(stats.scripts)")),
                    ToolStat(symbol: "puzzlepiece", value: "\(stats.moduleScripts)", label: String(localized: "模块脚本 \(stats.moduleScripts)")),
                ]) { ScriptsView() }
                card("任务", "定时任务", "clock.arrow.circlepath", .teal, stats: [
                    stats.tasksPaused
                        ? ToolStat(symbol: "pause.circle", value: String(localized: "已暂停"), label: String(localized: "自动运行已暂停"), tint: Theme.warn)
                        : ToolStat(symbol: "play.circle", value: String(localized: "自动运行"), label: String(localized: "自动运行")),
                ]) { ScriptTasksView() }
            }
            .listRowBackground(Theme.card)

            Section {
                card("MitM", "HTTPS 解密", "lock.open", .accent, stats: [
                    ToolStat(symbol: "power", value: stats.mitmOn ? String(localized: "已开启") : String(localized: "关闭"),
                             label: stats.mitmOn ? String(localized: "HTTPS 解密已开启") : String(localized: "HTTPS 解密关闭"),
                             tint: stats.mitmOn ? Theme.good : nil),
                    ToolStat(symbol: "globe", value: "\(stats.hostnames)", label: String(localized: "MitM 主机名 \(stats.hostnames)")),
                    certStat,
                ]) { MitMView() }
                card("DNS", "DNS", "network", .orange, stats: [
                    ToolStat(symbol: "gearshape", value: stats.dnsCustom ? String(localized: "自定义") : String(localized: "配置文件"),
                             label: stats.dnsCustom ? String(localized: "DNS 自定义") : String(localized: "DNS 使用配置文件")),
                ] + (stats.dnsCustom ? [ToolStat(symbol: "server.rack", value: "\(stats.dnsServers)", label: String(localized: "DNS 服务器 \(stats.dnsServers)"))] : [])) { DNSView() }
            }
            .listRowBackground(Theme.card)

            Section {
                card("日志", "运行日志", "text.alignleft", .neutral, stats: [], needsVPN: true) { LogsView() }
                card("DNS 日志", "域名解析记录", "globe", .blue, stats: [], needsVPN: true) { DNSLogView() }
                card("连接分析", "连接分析", "chart.pie", .teal, stats: [], needsVPN: true) { AnalyticsView() }
            } header: { Text("运行状态") } footer: {
                if !vpn.isConnected { Text("开启 VPN 后可查看。实时请求在「请求」标签页。") }
            }
            .listRowBackground(Theme.card)

            Section("网络") {
                card("网络工具（Ping / TCP / DNS）", "网络诊断", "stethoscope", .green, caption: "Ping · TCP · DNS") { ToolsView() }
                card("网络测试（带宽 / NAT 类型）", "网速测试", "speedometer", .orange, caption: "带宽 · NAT 类型") { NetTestView() }
                card("解锁检测", "流媒体解锁", "play.tv", .pink, caption: "Netflix · YouTube · ChatGPT …") { UnlockView() }
                card("内网 IP 与路由器", "局域网信息", "wifi.router", .teal, caption: "内网 IP · 路由器") { LANDetailView() }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("工具")
        .onAppear { refresh() }
        .task {
            // The offline node / rule counts come from the profile inspector; load it once if nothing did yet.
            if ProfileInspector.shared.profilePath != AppShared.activeProfileURL?.path {
                await ProfileInspector.shared.load()
                refresh()
            }
        }
    }

    func refresh() {
        let s = ToolStats.current()
        if s != stats { stats = s }
    }

    var nodeStats: [ToolStat] {
        var out = [
            ToolStat(symbol: "link", value: "\(stats.profileSubs)", label: String(localized: "配置订阅 \(stats.profileSubs)")),
            ToolStat(symbol: "tray.2", value: "\(stats.nodeSubs)", label: String(localized: "节点订阅 \(stats.nodeSubs)")),
            ToolStat(symbol: "circle.grid.2x2", value: "\(stats.nodes)", label: String(localized: "节点 \(stats.nodes)")),
        ]
        if stats.nodesTested > 0 {
            out.append(ToolStat(symbol: "checkmark.circle", value: "\(stats.nodesAlive)/\(stats.nodesTested)",
                                label: String(localized: "可用 \(stats.nodesAlive)/\(stats.nodesTested)")))
        }
        return out
    }

    var engineOffStat: [ToolStat] {
        stats.engineOn ? [] : [ToolStat(symbol: "power", value: String(localized: "重写与脚本已关闭"), label: String(localized: "重写与脚本已关闭"), tint: Theme.warn)]
    }

    var certStat: ToolStat {
        if !stats.caExists { return ToolStat(symbol: "seal", value: String(localized: "未生成证书"), label: String(localized: "未生成证书")) }
        if stats.caTrusted == true { return ToolStat(symbol: "checkmark.seal", value: String(localized: "已信任"), label: String(localized: "证书已信任"), tint: Theme.good) }
        return ToolStat(symbol: "xmark.seal", value: String(localized: "未信任"), label: String(localized: "证书未信任"), tint: Theme.warn)
    }

    @ViewBuilder
    func card<D: View>(_ id: String, _ title: String, _ symbol: String, _ tone: TileTone, stats: [ToolStat] = [],
                       caption: String? = nil, needsVPN: Bool = false, @ViewBuilder destination: @escaping () -> D) -> some View {
        NavigationLink { LazyDestination { destination() } } label: {
            ToolCard(id: id, title: title, symbol: symbol, tone: tone, stats: stats, caption: caption, needsVPN: needsVPN)
        }
    }
}

/// One Egern-style card: a solid colored square icon, the title, and a row of small stats (or a caption).
struct ToolCard: View {
    @ObservedObject private var vpn = VPNManager.shared
    let id: String
    let title: String
    let symbol: String
    var tone: TileTone = .accent
    var stats: [ToolStat] = []
    var caption: String? = nil
    var needsVPN = false

    var body: some View {
        let off = needsVPN && !vpn.isConnected
        HStack(spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill((off ? Theme.neutral : tone.color).gradient))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(LocalizedStringKey(title)).font(.headline).foregroundStyle(off ? Color.secondary : Color.primary)
                if off {
                    Text("需开启 VPN").font(.footnote).foregroundStyle(.secondary)
                } else if !stats.isEmpty {
                    HStack(spacing: 12) {
                        ForEach(stats, id: \.self) { s in
                            HStack(spacing: 4) {
                                Image(systemName: s.symbol).font(.caption)
                                Text(verbatim: s.value).font(.subheadline.monospacedDigit()).lineLimit(1)
                            }
                            .foregroundStyle(s.tint ?? Color.secondary)
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel(Text(verbatim: s.label))
                        }
                    }
                    .minimumScaleFactor(0.8)
                } else if let caption {
                    Text(LocalizedStringKey(caption)).font(.footnote).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 4)
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("more." + id)
    }
}
