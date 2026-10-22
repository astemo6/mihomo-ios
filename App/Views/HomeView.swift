import SwiftUI
import NetworkExtension

struct HomeView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    /// Review 5: the root mirrors only what it uses (mode, the live group cards). Observing DashboardModel
    /// rebuilt the whole page every second for the speed fields; the cards that show them observe it themselves.
    @State private var mode = DashboardModel.shared.mode
    @State private var liveGroups = DashboardModel.shared.homeGroups
    @State private var liveAvailable = DashboardModel.shared.availableGroups
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var homeGroups = HomeGroupsStore.shared
    /// r7 P2-1: the 编辑首页面板 / 编辑首页策略 sheets live here. A card that opened one is often removed by the edit
    /// itself (last analysis card removed, 连接数 hidden, VPN state flips live ↔ offline cards), which dismissed a
    /// sheet attached to it mid-edit.
    @ObservedObject private var editor = HomeEditorRouter.shared

    /// v0.8: the same cards while disconnected, from the profile file (selection saved for the next connect).
    /// feat/home-groups: the user's chosen groups for this profile (default = the first four).
    var offlineAvailable: [String] { offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name) }

    var offlineCards: [DashboardModel.HomeGroup] {
        _ = homeGroups.revision
        let groups = offline.result.groups.filter { $0.hidden != true }
        let byName = Dictionary(groups.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        // v0.19.8: a profile-defined GLOBAL only as the first card in 全局 mode.
        let names = (mode == "global" && byName["GLOBAL"] != nil ? ["GLOBAL"] : [])
            + homeGroups.resolved(available: offlineAvailable)
        return names.compactMap { byName[$0] }.map { g -> DashboardModel.HomeGroup in
            var chain = [g.name]
            var cur = g
            while let n = offline.current(of: cur), chain.count < 6, !chain.contains(n) {
                chain.append(n)
                guard let next = byName[n] else { break }
                cur = next
            }
            // r7 P3-5: stopped while still on a group that has a current member = cut (6 hops or a loop).
            let cut = chain.last.flatMap { byName[$0] }.flatMap { offline.current(of: $0) } != nil
            return DashboardModel.HomeGroup(name: g.name, icon: g.icon, kind: g.type, chain: chain, delay: chain.last.flatMap { offline.delays[$0] }, cut: cut)
        }
    }

    var disconnected: Bool { vpn.status == .disconnected || vpn.status == .invalid }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 10) {
                    if store.profiles.isEmpty { HomeEmptyCard() }
                    if vpn.safeModeActive && vpn.status != .disconnected && vpn.status != .invalid { SafeModeCard() }
                    if vpn.isConnected && !liveGroups.isEmpty {
                        HomePolicySection(groups: liveGroups, live: true, available: liveAvailable)
                    } else if disconnected && !offlineCards.isEmpty {
                        HomePolicySection(groups: offlineCards, live: false, available: offlineAvailable)
                    }
                    ModeCard()
                    // feat/home-analysis: Egern 分析 order — 连接数 tiles, 网络, 策略, 规则, 主机名, then 面板.
                    HomeConnectionTiles()
                    HomeSectionLabel(title: String(localized: "网络"), id: "home.section.network")
                    TrafficCard()
                    StatsGrid()
                    HomeAnalysisSection()
                    HomePanelsSection() // feat/panels

                    if let err = vpn.lastError {
                        Card {
                            VStack(alignment: .leading, spacing: 10) {
                                ErrorRow(message: err)
                                if vpn.canOfferSafeMode {
                                    Button {
                                        Task { await vpn.restart(safeMode: true) }
                                    } label: {
                                        Label("以安全模式连接", systemImage: "shield.lefthalf.filled")
                                            .font(.footnote.weight(.semibold))
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .background(alignment: .top) { TabRootScrollProbe() }
                .padding(.bottom, 80) // room for the floating + (feat/home-analysis)
            }
            .overlay(alignment: .bottomTrailing) {
                HomeQuickAddButton().padding(.trailing, 20).padding(.bottom, 16)
            }
            .background(Theme.bg.ignoresSafeArea())
            // fix/tab-top-spacing: no page title (the tab bar names it). The Quantumult X-style exit header (flag +
            // place, VPN switch; 运营商 · ASN · IP) is pinned where the other tabs have their slim bar row and never
            // scrolls away; scrolled cards pass under its bar material (replaces the r7 B07 status-bar strip).
            .tabRootChrome("首页") { ExitHeader() }
            // fix/nav-jank: speed / memory / connection fields publish only while Home is showing.
            .onAppear { DashboardModel.shared.setHomeVisible(true) }
            .onDisappear { DashboardModel.shared.setHomeVisible(false) }
            .task(id: "\(store.activeID ?? "")|\(disconnected)") { if disconnected { await offline.load() } }
            .onReceive(DashboardModel.shared.$mode.removeDuplicates()) { if $0 != mode { mode = $0 } }
            .onReceive(DashboardModel.shared.$homeGroups.removeDuplicates()) { if $0 != liveGroups { liveGroups = $0 } }
            .onReceive(DashboardModel.shared.$availableGroups.removeDuplicates()) { if $0 != liveAvailable { liveAvailable = $0 } }
            .sheet(item: $editor.sheet) { which in
                switch which {
                case .panels: HomePanelsEditor().environmentObject(vpn).environmentObject(store)
                case .groups: HomeGroupsEditor().environmentObject(vpn).environmentObject(store)
                }
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
}

/// r7 P2-1: which Home editor sheet is open. Cards only call `open`; HomeView (always on screen while Home is)
/// presents the sheet, so removing the card that opened it no longer closes it.
@MainActor
final class HomeEditorRouter: ObservableObject {
    static let shared = HomeEditorRouter()
    enum Sheet: String, Identifiable {
        case panels, groups
        var id: String { rawValue }
    }
    @Published var sheet: Sheet?
    func open(_ s: Sheet) { sheet = s }
}

/// feat/surge-ui: first-run Home without any profile — one sentence and the way to add one, instead of
/// empty policy cards and zero counters.
struct HomeEmptyCard: View {
    var body: some View {
        Card {
            EmptyStateRow(icon: "tray.and.arrow.down", title: "还没有配置", message: "添加一个订阅或配置文件，就可以开始使用了。") {
                Button { ImportRouter.shared.showProfiles() } label: {
                    Text("添加配置").font(.footnote.weight(.semibold))
                }
                .buttonStyle(.borderless)
                .padding(.top, 2)
                .accessibilityIdentifier("home.addProfile")
            }
        }
    }
}

/// Shown only while a safe-mode connection runs: what is off, and the way back.
struct SafeModeCard: View {
    @EnvironmentObject var vpn: VPNManager
    var body: some View {
        Card {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "shield.lefthalf.filled").font(.title3).foregroundStyle(Theme.warn).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("安全模式").font(.subheadline.weight(.semibold))
                    Text("模块、重写、脚本、MitM、自定义规则和智能选择已暂停。").font(.footnote).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("恢复正常连接") { Task { await vpn.restart(safeMode: false) } }
                        .font(.footnote.weight(.semibold))
                        .buttonStyle(.borderless)
                        .padding(.top, 2)
                }
                Spacer(minLength: 0)
            }
        }
    }
}

/// feat/egern-style: Egern's settings row — 「出站模式」 on the left, the current mode with ⌃⌄ on the right (menu picker).
struct ModeCard: View {
    /// r7: only the mode is mirrored (as PolicyView does); observing DashboardModel re-rendered this card every second.
    @State private var mode = DashboardModel.shared.mode
    var body: some View {
        HStack(spacing: 12) {
            IconTile(symbol: "arrow.triangle.branch", tone: .orange)
            Text("出站模式")
            Spacer(minLength: 8)
            Picker("出站模式", selection: Binding(get: { mode }, set: { m in mode = m; Task { await DashboardModel.shared.setMode(m) } })) {
                Text("规则模式").tag("rule")
                Text("全局模式").tag("global")
                Text("直连模式").tag("direct")
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .tint(Color.secondary)
            .accessibilityIdentifier("home.mode")
        }
        .padding(.leading, 12).padding(.trailing, 4).padding(.vertical, 4)
        .frame(minHeight: 44)
        .egernCard()
        .onReceive(DashboardModel.shared.$mode.removeDuplicates()) { m in if mode != m { mode = m } }
    }
}

struct TrafficCard: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SpeedLabel(icon: "arrow.up", color: Theme.up, title: "上传", value: dash.up)
                    Spacer()
                    SpeedLabel(icon: "arrow.down", color: Theme.down, title: "下载", value: dash.down)
                }
                TrafficChart(up: dash.upHistory, down: dash.downHistory)
                    .frame(height: 56)
                    .overlay(alignment: .topTrailing) { TrafficScopeCaption() }
            }
        }
    }
}

/// feat/traffic-scope: a quiet 「仅代理」 tag on speed views while 首页流量统计 = 仅代理流量 (nothing otherwise).
struct TrafficScopeCaption: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        if dash.scope == .proxy {
            Text("仅代理").font(.caption2).foregroundStyle(.secondary)
                .accessibilityIdentifier("home.trafficScope.proxy")
        }
    }
}

struct SpeedLabel: View {
    let icon: String, color: Color, title: String, value: Int64
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon).font(.system(size: 10, weight: .bold)).foregroundStyle(.white)
                .frame(width: 18, height: 18).background(Circle().fill(color))
            VStack(alignment: .leading, spacing: 0) {
                Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
                Text(Fmt.speed(value)).font(.subheadline.weight(.medium).monospacedDigit())
            }
        }
    }
}

struct TrafficChart: View {
    let up: [Int64]
    let down: [Int64]
    var body: some View {
        GeometryReader { geo in
            let maxV = max(Double((up + down).max() ?? 1), 1024)
            ZStack {
                area(down, maxV, geo.size).fill(LinearGradient(colors: [Theme.down.opacity(0.45), Theme.down.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                line(down, maxV, geo.size).stroke(Theme.down, lineWidth: 1.6)
                area(up, maxV, geo.size).fill(LinearGradient(colors: [Theme.up.opacity(0.35), Theme.up.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                line(up, maxV, geo.size).stroke(Theme.up, lineWidth: 1.4)
            }
        }
    }

    private func points(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> [CGPoint] {
        guard v.count > 1 else { return [] }
        let step = size.width / CGFloat(v.count - 1)
        return v.enumerated().map { i, x in
            CGPoint(x: CGFloat(i) * step, y: size.height - CGFloat(Double(x) / maxV) * size.height * 0.92)
        }
    }

    private func line(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> Path {
        Path { p in
            let pts = points(v, maxV, size)
            guard let f = pts.first else { return }
            p.move(to: f)
            pts.dropFirst().forEach { p.addLine(to: $0) }
        }
    }

    private func area(_ v: [Int64], _ maxV: Double, _ size: CGSize) -> Path {
        Path { p in
            let pts = points(v, maxV, size)
            guard let f = pts.first, let l = pts.last else { return }
            p.move(to: CGPoint(x: f.x, y: size.height))
            pts.forEach { p.addLine(to: $0) }
            p.addLine(to: CGPoint(x: l.x, y: size.height))
            p.closeSubpath()
        }
    }
}

struct StatsGrid: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
            // feat/traffic-scope: titles say when only proxy traffic is counted.
            StatTile(icon: "arrow.up.circle.fill", color: Theme.up, title: dash.scope == .proxy ? "总上传（仅代理）" : "总上传", value: Fmt.bytes(dash.uploadTotal))
            StatTile(icon: "arrow.down.circle.fill", color: Theme.down, title: dash.scope == .proxy ? "总下载（仅代理）" : "总下载", value: Fmt.bytes(dash.downloadTotal))
        }
    }
}

struct StatTile: View {
    let icon: String, color: Color, title: String, value: String
    var body: some View {
        // feat/egern-style: Egern's 全部连接 / 活跃连接 tile — title on top, a small number under it.
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 3) {
                Text(LocalizedStringKey(title)).font(.subheadline).lineLimit(1).minimumScaleFactor(0.8)
                Text(value).font(.caption.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            Image(systemName: icon).font(.system(size: 13, weight: .semibold)).foregroundStyle(color).accessibilityHidden(true)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
    }
}


/// Flag + exit location large, the chosen detail items (运营商 · ASN · IP by default) small. Shared by the Home header and 节点探测 (v0.8).
struct ExitInfoRow: View {
    let info: IPInfo?
    let loading: Bool
    let failed: Bool
    let placeholder: String
    /// Third line with the operator (节点探测 shows it; Home keeps two lines).
    var showOrg = false
    /// Items of the small line; nil = the user's 首页副标题显示 choice (Home). 节点探测 passes the legacy set.
    var fields: Set<ExitDetailField>? = nil
    /// feat/egern-style: the Home header's smaller type (26 pt flag, headline place, caption2 details).
    var compact = false
    @AppStorage(ExitDetailField.storageKey, store: AppShared.defaults) private var storedFields = ExitDetailField.defaultValue

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Text(info?.flag ?? "🌐")
                .font(.system(size: compact ? 26 : 34))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: compact ? 1 : 3) {
                Text(info?.placeText ?? (loading ? String(localized: "正在查询…") : (failed ? String(localized: "查询失败") : "—")))
                    .font(compact ? Font.headline : Font.title3.weight(.bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                let detail = info?.detailText(fields: fields ?? ExitDetailField.parse(storedFields)) ?? placeholder
                if !detail.isEmpty {
                    Text(verbatim: detail)
                        .font((compact ? Font.caption2 : Font.caption).monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                        .accessibilityIdentifier("home.exit.detail")
                }
                if showOrg, info?.customSubtitle == nil, let org = info?.org, !org.isEmpty {
                    Text(org).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
    }
}

/// Home header, Quantumult X style (fix/tab-top-spacing, user 2026-10-22 + QX reference video): pinned at the top of
/// 首页 by TabRootChrome (never scrolls away). Row 1: flag + exit location, large semibold, with the VPN switch on the
/// right. Row 2: small grey 「运营商 · ASN · IP」 (首页副标题显示) behind a status dot (green = connected). Unknown values
/// show the existing placeholders (正在查询… / 查询失败 / — and 出口 · 本机网络 / 代理), never invented ones.
/// Tap refreshes the exit info, long-press copies it (as the old IP card did).
struct ExitHeader: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var ip: IPInfoModel
    @AppStorage(ExitDetailField.storageKey, store: AppShared.defaults) private var storedFields = ExitDetailField.defaultValue
    @State private var copied = false

    var body: some View {
        let on = vpn.isConnected
        let info = ip.exit
        let place = info?.placeText ?? (ip.loading ? String(localized: "正在查询…") : (ip.failed ? String(localized: "查询失败") : "—"))
        let placeholder = on ? String(localized: "出口 · 代理") : String(localized: "出口 · 本机网络")
        let detail = info?.detailText(fields: ExitDetailField.parse(storedFields)) ?? placeholder
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(info?.flag ?? "🌐")
                        .scaledFont(19, relativeTo: .title3)
                        .accessibilityHidden(true)
                    Text(place)
                        .scaledFont(20, weight: .semibold, relativeTo: .title3)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
                HStack(spacing: 4) {
                    Circle()
                        .fill(on ? Theme.good : Color.secondary.opacity(0.6))
                        .frame(width: 6, height: 6)
                        .accessibilityHidden(true)
                    if !detail.isEmpty {
                        Text(verbatim: detail)
                            .font(.caption2.monospacedDigit())
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)
                            .accessibilityIdentifier("home.exit.detail")
                    }
                }
                .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
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
            .accessibilityValue(Text(vpn.statusText))
            .accessibilityIdentifier("home.exit.place")
            .accessibilityHint(Text("轻点刷新，长按复制"))
            .overlay(alignment: .topTrailing) {
                if copied {
                    Text("已复制")
                        .font(.caption2.bold())
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                        .background(Capsule().fill(Theme.good))
                        .foregroundStyle(Theme.onAccent)
                        .transition(.scale.combined(with: .opacity))
                }
            }
            HomePowerSwitch()
        }
        .onAppear { if ip.exit == nil && !ip.loading { ip.scheduleRefresh() } }
    }
}

/// The VPN switch in the pinned Home header (QX: a plain switch on the right of the exit location). Same action and
/// accessibility id as the old 启动 / 停止 capsule.
struct HomePowerSwitch: View {
    @ObservedObject private var vpn = VPNManager.shared

    var body: some View {
        let busy = vpn.isBusy || vpn.status == .connecting || vpn.status == .disconnecting
        let on = vpn.isConnected || vpn.status == .connecting
        Toggle("", isOn: Binding(get: { on }, set: { want in
            guard want != on else { return }
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            Task { await vpn.toggle() }
        }))
        .labelsHidden()
        .tint(Theme.good)
        .disabled(busy)
        .accessibilityLabel(Text(vpn.isConnected ? "停止" : "启动"))
        .accessibilityValue(Text(vpn.isConnected ? "已连接" : "未连接"))
        .accessibilityIdentifier("home.power")
    }
}

/// Home policy cards (v0.7): icon, group name and the resolved chain (PROXY ➤ 🇯🇵 node). Tap opens a
/// quick picker for selectable groups.
struct HomePolicyCards: View {
    let groups: [DashboardModel.HomeGroup]
    /// false = disconnected: cards come from the profile and the picker saves for the next connect (v0.8).
    var live = true
    /// feat/home-groups long-press actions (nil = not offered).
    var onRemove: ((String) -> Void)? = nil
    var onEdit: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(groups.enumerated()), id: \.element.id) { i, g in
                if i > 0 { Divider().overlay(Theme.ink(0.06)).padding(.leading, 52) }
                NavigationLink {
                    if live { GroupQuickPicker(group: g.name) } else { OfflineGroupPicker(group: g.name) }
                } label: {
                    HStack(spacing: 12) {
                        GroupIconView(group: g.name, profileIcon: g.icon, fallback: PolicyGroupDisplay(name: g.name, kind: g.kind, now: nil, members: [], selectable: false).icon, size: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(g.name).font(.subheadline).lineLimit(1)
                            // feat/egern-style: Egern chain 「日本节点 › 🇯🇵 东京」; middle hops give way, the final node stays.
                            // r7 P3-5: same display as 策略 (PolicyChainText): region flag on the final node, 「…」 when cut.
                            ChainLine(hops: PolicyChainText.homeParts(g.chain, cut: g.cut))
                        }
                        Spacer(minLength: 6)
                        if let d = g.delay {
                            Text(Theme.delayText(d)).font(.caption2.monospacedDigit()).foregroundStyle(Theme.delayColor(d))
                        }
                        Image(systemName: "chevron.right").font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("home.card." + g.name)
                .contextMenu {
                    if let onRemove {
                        Button(role: .destructive) { onRemove(g.name) } label: { Label("从首页移除", systemImage: "minus.circle") }
                    }
                    if let onEdit {
                        Button { onEdit() } label: { Label("编辑首页策略", systemImage: "slider.horizontal.3") }
                    }
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
    }
}

/// Members of one group from the profile file while disconnected; select groups save the choice for the next
/// connect (the same store as 策略's offline list).
struct OfflineGroupPicker: View {
    let group: String
    @ObservedObject private var insp = ProfileInspector.shared

    var body: some View {
        List {
            if let g = insp.result.groups.first(where: { $0.name == group }) ?? (group == "GLOBAL" ? insp.globalGroup : nil) {
                let selectable = g.type == "select"
                Section {
                    ForEach(insp.members(of: g), id: \.self) { m in
                        Button {
                            guard selectable else { return }
                            insp.select(group: g.name, node: m)
                            UISelectionFeedbackGenerator().selectionChanged()
                        } label: {
                            HStack {
                                Text(verbatim: FlagSafe.text(m)).lineLimit(1)
                                Spacer()
                                if let d = insp.delays[m] {
                                    Text(Theme.delayText(d)).font(.caption.monospacedDigit()).foregroundStyle(Theme.delayColor(d))
                                }
                                if insp.current(of: g) == m { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                            }
                        }
                        .foregroundStyle(.primary)
                    }
                } footer: {
                    Text(selectable ? String(localized: "未连接：选择会保存到该配置，下次连接时生效。")
                                    : PolicyGroupDisplay(name: g.name, kind: g.type, now: insp.current(of: g), members: [], selectable: false).hint)
                }
                .listRowBackground(Theme.card)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(group)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // v0.19.8 (user): 测速 for this group, like the 策略 tab's bolt (offline = direct from the app).
            ToolbarItem(placement: .topBarTrailing) {
                if insp.testing.contains(group) {
                    ProgressView().accessibilityIdentifier("grouppicker.testing")
                } else {
                    Button {
                        guard let g = insp.result.groups.first(where: { $0.name == group }) ?? (group == "GLOBAL" ? insp.globalGroup : nil) else { return }
                        Task { await insp.test(group: g) }
                    } label: { Image(systemName: "bolt.fill") }
                    .accessibilityLabel(Text("测速"))
                    .accessibilityIdentifier("grouppicker.test")
                }
            }
        }
    }
}

/// Members of one live group; selectable groups switch on tap.
struct GroupQuickPicker: View {
    let group: String
    @State private var item: ProxyItem?
    @State private var all: [String: ProxyItem] = [:]
    @State private var error: String?
    /// v0.19.8 测速 in this page: results of this run (0 = timeout), shown over the core's history.
    @State private var tested: [String: Int] = [:]
    @State private var testing = false

    var body: some View {
        List {
            if let error { ErrorRow(message: error).listRowBackground(Theme.card) }
            if let item {
                if !item.isSelectable {
                    Text(PolicyGroupDisplay(name: item.name, kind: PolicyGroupDisplay.kind(live: item.type), now: item.now, members: [], selectable: false).hint)
                        .font(.footnote).foregroundStyle(.secondary).listRowBackground(Theme.card)
                }
                ForEach(item.all ?? [], id: \.self) { m in
                    Button {
                        guard item.isSelectable else { return }
                        Task { await select(m) }
                    } label: {
                        HStack {
                            Text(verbatim: FlagSafe.text(m)).lineLimit(1)
                            Spacer()
                            if let d = tested[m] ?? all[m]?.lastDelay(for: NodeSettingsStore.testURL(for: m)) {
                                Text(Theme.delayText(d)).font(.caption.monospacedDigit()).foregroundStyle(Theme.delayColor(d))
                            }
                            if item.now == m { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                        }
                    }
                    .foregroundStyle(.primary)
                    .listRowBackground(Theme.card)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(group)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if testing {
                    ProgressView().accessibilityIdentifier("grouppicker.testing")
                } else {
                    Button { Task { await test() } } label: { Image(systemName: "bolt.fill") }
                        .accessibilityLabel(Text("测速"))
                        .accessibilityIdentifier("grouppicker.test")
                        .disabled(item == nil)
                }
            }
        }
        .task { await load() }
    }

    /// The same path as the 策略 tab (PolicyModel.test): members as the core has them now, 10 at a time, provider
    /// nodes through their provider.
    func test() async {
        guard !testing else { return }
        testing = true
        defer { testing = false }
        let live = (try? await ControllerClient.shared.proxies()) ?? all
        let members = (live[group]?.all ?? item?.all ?? []).filter { !["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"].contains($0) }
        do {
            let got = try await ControllerClient.shared.membersDelay(members)
            for m in members { tested[m] = got[m] ?? 0 }
            error = nil
        } catch {
            self.error = String(localized: "测速失败：\(error.localizedDescription)")
        }
        await load()
    }

    func load() async {
        do {
            all = try await ControllerClient.shared.proxies()
            item = all[group]
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    func select(_ node: String) async {
        do {
            try await ControllerClient.shared.select(group: group, node: node)
            await ControllerClient.shared.afterUserSwitch() // v0.19
            UISelectionFeedbackGenerator().selectionChanged()
            if group != "GLOBAL" { ProfileInspector.rememberLiveSelection(group: group, node: node) }
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
            await load()
            await DashboardModel.shared.refreshSelectedNode()
        } catch { self.error = error.localizedDescription }
    }
}
