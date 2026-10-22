import SwiftUI

// feat/more-dedup (user 2026-10-21 18:06, modelled on Egern's 工具 page): the 工具 tab replaces the old 配置 tab.
// Large rounded cards — colored square icon, title, a row of small icon + count stats — for every tool-type
// page (节点与订阅, 分流规则, 重写 (QX-style: subscriptions + local rules + scripts), 定时任务, HTTPS 解密, DNS, logs and network tools). Settings-type
// pages stay in 更多; 配置管理 is the first row of 更多. Card ids keep the old `more.<zh-Hans key>` so UI tests
// and deep links hold. Counts are a snapshot taken when the tab appears, computed off the main thread (nothing here observes a
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
    /// 重写 card: enabled local rewrites + local scripts + the rules of enabled subscriptions.
    var rewriteRules: Int { rewritesOn + scriptsOn + moduleRewrites + moduleScripts }
    var tasksPaused = false
    var mitmOn = false
    var caExists = false
    var caTrusted: Bool?
    var dnsCustom = false
    var dnsServers = 0

    /// r7: the stores' current values are copied on the main actor (copy-on-write, cheap); the counting,
    /// filtering and the two small settings-file reads (task prefs, DNS override) run off the main thread.
    @MainActor static func current() async -> ToolStats {
        let profiles = ProfileStore.shared.profiles
        let nodeSubs = NodeSubStore.shared.subs.count
        let insp = ProfileInspector.shared
        let result = insp.result
        let delays = insp.delays
        let customRules = CustomRulesStore.shared.rules
        let es = EngineStore.shared
        let cfg = es.config
        let moduleInfo = es.moduleInfo
        let caExists = es.caInfo.exists
        let caTrusted = es.caTrusted
        return await Task.detached(priority: .userInitiated) {
            ToolStats.compute(profiles: profiles, nodeSubs: nodeSubs, result: result, delays: delays, customRules: customRules,
                    cfg: cfg, moduleInfo: moduleInfo, caExists: caExists, caTrusted: caTrusted)
        }.value
    }

    static func compute(profiles: [Profile], nodeSubs: Int, result: InspectResult, delays: [String: Int],
                        customRules: [CustomRule], cfg: EngineConfig, moduleInfo: [String: ParsedEngineText],
                        caExists: Bool, caTrusted: Bool?) -> ToolStats {
        var s = ToolStats()
        s.profileSubs = profiles.filter { $0.kind == .remote }.count
        s.nodeSubs = nodeSubs
        // Same node set as ProfileInspector.nodeIndex (profile proxies + cached provider nodes), minus built-ins.
        let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
        var names = Set(result.proxies.map(\.name))
        for pv in result.proxyProviders { for p in pv.proxies ?? [] { names.insert(p.name) } }
        names.subtract(builtins)
        s.nodes = names.count
        let measured = names.compactMap { delays[$0] }
        s.nodesTested = measured.count
        s.nodesAlive = measured.filter { $0 > 0 }.count
        s.profileRules = result.rules.count
        s.ruleProviders = result.ruleProviders.count
        s.customRules = customRules.count
        s.customRulesOn = customRules.filter(\.enabled).count
        s.engineOn = cfg.enabled
        s.modules = cfg.modules.count
        s.modulesOn = cfg.modules.filter(\.enabled).count
        s.rewrites = cfg.rules.count
        s.rewritesOn = cfg.rules.filter(\.enabled).count
        s.scripts = cfg.scripts.count
        s.scriptsOn = cfg.scripts.filter(\.enabled).count
        // Same totals as EngineStore.enabledModuleCounts.
        var mr = 0, ms = 0, mh = 0
        for m in cfg.modules where m.enabled {
            guard let p = moduleInfo[m.id] else { continue }
            ms += p.rules.filter { $0.kind == "script" }.count
            mr += p.rules.filter { $0.kind != "script" }.count
            mh += p.hostnames.filter { !$0.hasPrefix("-") }.count
        }
        s.moduleRewrites = mr
        s.moduleScripts = ms
        s.hostnames = cfg.hostnames.filter { !$0.hasPrefix("-") }.count + mh
        s.tasksPaused = TaskPrefs.load().paused
        s.mitmOn = cfg.mitm
        s.caExists = caExists
        s.caTrusted = caTrusted
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
    @State private var stats = ToolStats()
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        List {
            // Egern-style: every tool is its own rounded card (one section per card).
            Group {
                cardSection { card("节点与订阅", "节点与订阅", "server.rack", .blue, stats: nodeStats) { NodeManagerView() } }
                cardSection {
                    card("规则", "分流规则", "arrow.triangle.branch", .orange, stats: [
                        ToolStat(symbol: "list.bullet", value: "\(stats.profileRules)", label: String(localized: "配置规则 \(stats.profileRules)")),
                        ToolStat(symbol: "square.stack.3d.up", value: "\(stats.ruleProviders)", label: String(localized: "规则集 \(stats.ruleProviders)")),
                        ToolStat(symbol: "pencil.line", value: "\(stats.customRulesOn)/\(stats.customRules)", label: String(localized: "自定义规则 \(stats.customRulesOn)/\(stats.customRules)")),
                    ]) { RulesView() }
                }
                // QX-style (user 2026-10-22): one 重写 card replaced 模块 / 重写 / 脚本 — subscriptions, local rules and
                // script tools are on one page.
                cardSection {
                    card("重写", "重写", "arrow.triangle.swap", .red, stats: [
                        ToolStat(symbol: "link", value: "\(stats.modulesOn)/\(stats.modules)", label: String(localized: "订阅 \(stats.modulesOn)/\(stats.modules)")),
                        ToolStat(symbol: "list.bullet", value: "\(stats.rewriteRules)", label: String(localized: "规则 \(stats.rewriteRules)")),
                        ToolStat(symbol: "globe", value: "\(stats.hostnames)", label: String(localized: "MitM 主机名 \(stats.hostnames)")),
                    ] + engineOffStat) { RewriteView() }
                }
                cardSection {
                    card("任务", "定时任务", "clock.arrow.circlepath", .teal, stats: [
                        stats.tasksPaused
                            ? ToolStat(symbol: "pause.circle", value: String(localized: "已暂停"), label: String(localized: "自动运行已暂停"), tint: Theme.warn)
                            : ToolStat(symbol: "play.circle", value: String(localized: "自动运行"), label: String(localized: "自动运行")),
                    ]) { ScriptTasksView() }
                }
                cardSection {
                    card("MitM", "HTTPS 解密", "lock.open", .accent, stats: [
                        ToolStat(symbol: "power", value: stats.mitmOn ? String(localized: "已开启") : String(localized: "关闭"),
                                 label: stats.mitmOn ? String(localized: "HTTPS 解密已开启") : String(localized: "HTTPS 解密关闭"),
                                 tint: stats.mitmOn ? Theme.good : nil),
                        ToolStat(symbol: "globe", value: "\(stats.hostnames)", label: String(localized: "MitM 主机名 \(stats.hostnames)")),
                        certStat,
                    ]) { MitMView() }
                }
                cardSection {
                    card("DNS", "DNS", "network", .orange, stats: [
                        ToolStat(symbol: "gearshape", value: stats.dnsCustom ? String(localized: "自定义") : String(localized: "配置文件"),
                                 label: stats.dnsCustom ? String(localized: "DNS 自定义") : String(localized: "DNS 使用配置文件")),
                    ] + (stats.dnsCustom ? [ToolStat(symbol: "server.rack", value: "\(stats.dnsServers)", label: String(localized: "DNS 服务器 \(stats.dnsServers)"))] : [])) { DNSView() }
                }
            }
            Group {
                Section {
                    card("日志", "运行日志", "text.alignleft", .neutral, needsVPN: true) { LogsView() }
                } header: { Text("运行状态") }
                cardSection { card("DNS 日志", "域名解析记录", "globe", .blue, needsVPN: true) { DNSLogView() } }
                Section {
                    card("连接分析", "连接分析", "chart.pie", .teal, needsVPN: true) { AnalyticsView() }
                } footer: {
                    if !vpn.isConnected { Text("开启 VPN 后可查看。实时请求在「请求」标签页。") }
                }
                Section {
                    card("网络工具（Ping / TCP / DNS）", "网络诊断", "stethoscope", .green, caption: "Ping · TCP · DNS") { ToolsView() }
                } header: { Text("网络") }
                cardSection { card("网络测试（带宽 / NAT 类型）", "网速测试", "speedometer", .orange, caption: "带宽 · NAT 类型") { NetTestView() } }
                cardSection { card("解锁检测", "流媒体解锁", "play.tv", .pink, caption: "Netflix · YouTube · ChatGPT …") { UnlockView() } }
                cardSection { card("内网 IP 与路由器", "局域网信息", "wifi.router", .teal, caption: "内网 IP · 路由器") { LANDetailView() } }
            }
            .listRowBackground(Theme.card)
        }
        .compactSectionSpacing()
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .tabRootChrome("工具")
        .onAppear { Task { await refresh() } }
        .task {
            // The offline node / rule counts come from the profile inspector; load it once if nothing did yet.
            if ProfileInspector.shared.profilePath != AppShared.activeProfileURL?.path {
                await ProfileInspector.shared.load()
                await refresh()
            }
        }
    }

    func cardSection<C: View>(@ViewBuilder _ c: () -> C) -> some View {
        Section { c() }.listRowBackground(Theme.card)
    }

    func refresh() async {
        let s = await ToolStats.current()
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
        // feat/egern-style: Egern's compact tool card — 30 pt solid tile, 15 pt title, a line of tiny icon + count stats.
        HStack(spacing: 12) {
            IconTile(symbol: symbol, tone: tone, dimmed: off, size: 30)
            VStack(alignment: .leading, spacing: 3) {
                Text(LocalizedStringKey(title)).font(.subheadline).foregroundStyle(off ? Color.secondary : Color.primary)
                if off {
                    Text("需开启 VPN").font(.caption2).foregroundStyle(.secondary)
                } else if !stats.isEmpty {
                    // r7 P3-4: one line while it fits; otherwise (long ru values, accessibility sizes) two per line
                    // instead of truncating every value.
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 10) { ForEach(stats, id: \.self) { statView($0) } }
                            .fixedSize(horizontal: true, vertical: false)
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(stride(from: 0, to: stats.count, by: 2)), id: \.self) { i in
                                HStack(spacing: 10) {
                                    statView(stats[i])
                                    if i + 1 < stats.count { statView(stats[i + 1]) }
                                }
                            }
                        }
                    }
                } else if let caption {
                    Text(LocalizedStringKey(caption)).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 4)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("more." + id)
    }

    func statView(_ s: ToolStat) -> some View {
        HStack(spacing: 3) {
            Image(systemName: s.symbol).scaledFont(9, weight: .medium)
            Text(verbatim: s.value).font(.caption2.monospacedDigit()).lineLimit(1)
        }
        .foregroundStyle(s.tint ?? Color.secondary)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: s.label))
    }
}

extension View {
    /// Egern-like gap between the one-card sections (iOS 17+; iOS 16 keeps the default spacing).
    @ViewBuilder func compactSectionSpacing() -> some View {
        if #available(iOS 17.0, *) { self.listSectionSpacing(10) } else { self }
    }
}
