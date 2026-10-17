import SwiftUI
import NetworkExtension

struct HomeView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var dash: DashboardModel
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var homeGroups = HomeGroupsStore.shared

    /// v0.8: the same cards while disconnected, from the profile file (selection saved for the next connect).
    /// feat/home-groups: the user's chosen groups for this profile (default = the first four).
    var offlineAvailable: [String] { offline.result.groups.filter { $0.hidden != true }.map(\.name) }

    var offlineCards: [DashboardModel.HomeGroup] {
        _ = homeGroups.revision
        let groups = offline.result.groups.filter { $0.hidden != true }
        let byName = Dictionary(groups.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        return homeGroups.resolved(available: groups.map(\.name)).compactMap { byName[$0] }.map { g -> DashboardModel.HomeGroup in
            var chain = [g.name]
            var cur = g
            while let n = offline.current(of: cur), chain.count < 6, !chain.contains(n) {
                chain.append(n)
                guard let next = byName[n] else { break }
                cur = next
            }
            return DashboardModel.HomeGroup(name: g.name, icon: g.icon, kind: g.type, chain: chain, delay: chain.last.flatMap { offline.delays[$0] })
        }
    }

    var disconnected: Bool { vpn.status == .disconnected || vpn.status == .invalid }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    // v0.7: exit-location header (QX reference, in our card style) with the plain toggle.
                    ExitHeader()
                    if vpn.safeModeActive && vpn.status != .disconnected && vpn.status != .invalid { SafeModeCard() }
                    if vpn.isConnected && !dash.homeGroups.isEmpty {
                        HomePolicySection(groups: dash.homeGroups, live: true, available: dash.availableGroups)
                    } else if disconnected && !offlineCards.isEmpty {
                        HomePolicySection(groups: offlineCards, live: false, available: offlineAvailable)
                    }
                    ModeCard()
                    TrafficCard()
                    StatsGrid()
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
                .padding(.bottom, 24)
            }
            .background(Theme.bg.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .task(id: "\(store.activeID ?? "")|\(disconnected)") { if disconnected { await offline.load() } }
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

struct ConnectCard: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var dash: DashboardModel

    var body: some View {
        let on = vpn.isConnected
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    // v0.6.1: plain state text + a small dot; no accent fill or glow when connected.
                    HStack(spacing: 6) {
                        Circle()
                            .fill(on ? Theme.good : Color.secondary.opacity(0.6))
                            .frame(width: 7, height: 7)
                            .accessibilityHidden(true)
                        Text(on ? "代理已开启" : "代理未开启")
                            .font(.headline)
                    }
                    if on, let d = vpn.connectedDate {
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in
                            Text("已运行 \(Fmt.duration(ctx.date.timeIntervalSince(d)))")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text(vpn.statusText).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { on || vpn.status == .connecting },
                    set: { _ in Task { await vpn.toggle() } }
                ))
                .labelsHidden()
                .tint(Theme.good)
                .scaleEffect(1.25)
                .disabled(vpn.isBusy || vpn.status == .disconnecting)
            }
            Divider().overlay(Theme.ink(0.08))
            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 3) {
                    Label("配置", systemImage: "doc.text").font(.caption2).foregroundStyle(.secondary)
                    Text(verbatim: store.active?.displayName ?? String(localized: "未选择")).font(.subheadline.weight(.semibold)).lineLimit(1)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 3) {
                    Label("当前节点", systemImage: "point.3.connected.trianglepath.dotted").font(.caption2).foregroundStyle(.secondary)
                    Text(on ? dash.selectedNode : "—").font(.subheadline.weight(.semibold)).lineLimit(1)
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
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

struct ModeCard: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("出站模式").font(.caption).foregroundStyle(.secondary)
                Picker("出站模式", selection: Binding(get: { dash.mode }, set: { m in Task { await dash.setMode(m) } })) {
                    Text("规则").tag("rule")
                    Text("全局").tag("global")
                    Text("直连").tag("direct")
                }
                .pickerStyle(.segmented)
            }
        }
    }
}

struct TrafficCard: View {
    @EnvironmentObject var dash: DashboardModel
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    SpeedLabel(icon: "arrow.up", color: Theme.up, title: "上传", value: dash.up)
                    Spacer()
                    SpeedLabel(icon: "arrow.down", color: Theme.down, title: "下载", value: dash.down)
                }
                TrafficChart(up: dash.upHistory, down: dash.downHistory)
                    .frame(height: 72)
            }
        }
    }
}

struct SpeedLabel: View {
    let icon: String, color: Color, title: String, value: Int64
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon).font(.caption.bold()).foregroundStyle(color)
                .frame(width: 24, height: 24).background(Circle().fill(color.opacity(0.15)))
            VStack(alignment: .leading, spacing: 0) {
                Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
                Text(Fmt.speed(value)).font(.system(.headline, design: .rounded).monospacedDigit())
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
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
            StatTile(icon: "arrow.up.circle.fill", color: Theme.up, title: "总上传", value: Fmt.bytes(dash.uploadTotal))
            StatTile(icon: "arrow.down.circle.fill", color: Theme.down, title: "总下载", value: Fmt.bytes(dash.downloadTotal))
        }
    }
}

struct StatTile: View {
    let icon: String, color: Color, title: String, value: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.title3).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
                Text(value).font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Theme.ink(0.06)))
    }
}


/// Flag + exit location large, "time zone · ASN · IP" small. Shared by the Home header and 节点探测 (v0.8).
struct ExitInfoRow: View {
    let info: IPInfo?
    let loading: Bool
    let failed: Bool
    let placeholder: String
    /// Third line with the operator (节点探测 shows it; Home keeps two lines).
    var showOrg = false

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Text(info?.flag ?? "🌐")
                .font(.system(size: 34))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(info?.placeText ?? (loading ? String(localized: "正在查询…") : (failed ? String(localized: "查询失败") : "—")))
                    .font(.title3.weight(.bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Text(info?.detailText ?? placeholder)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
                if showOrg, let org = info?.org, !org.isEmpty {
                    Text(org).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
    }
}

/// Home header (v0.7): flag + exit location large, "time zone · ASN · IP" small, a plain toggle, and one
/// status line. Tap refreshes the exit info, long-press copies it (as the old IP card did).
struct ExitHeader: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var ip: IPInfoModel
    @State private var copied = false

    var body: some View {
        let on = vpn.isConnected
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                ExitInfoRow(info: ip.exit, loading: ip.loading, failed: ip.failed,
                            placeholder: on ? String(localized: "出口 · 代理") : String(localized: "出口 · 本机网络"))
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
                Toggle("", isOn: Binding(
                    get: { on || vpn.status == .connecting },
                    set: { _ in Task { await vpn.toggle() } }
                ))
                .labelsHidden()
                .tint(Theme.good)
                .disabled(vpn.isBusy || vpn.status == .disconnecting)
                .accessibilityLabel(Text("代理"))
            }
            Divider().overlay(Theme.ink(0.08))
            HStack(spacing: 6) {
                Circle()
                    .fill(on ? Theme.good : Color.secondary.opacity(0.6))
                    .frame(width: 7, height: 7)
                    .accessibilityHidden(true)
                if on, let d = vpn.connectedDate {
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        Text("\(vpn.statusText) · \(Fmt.duration(ctx.date.timeIntervalSince(d)))")
                            .font(.caption.monospacedDigit())
                    }
                } else {
                    Text(vpn.statusText).font(.caption)
                }
                Spacer()
                Label(store.active?.displayName ?? String(localized: "未选择"), systemImage: "doc.text")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
        .overlay(alignment: .topTrailing) {
            if copied {
                Text("已复制")
                    .font(.caption2.bold())
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Theme.good))
                    .foregroundStyle(Theme.onAccent)
                    .offset(x: -8, y: -8)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .onAppear { if ip.exit == nil && !ip.loading { ip.scheduleRefresh() } }
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
                if i > 0 { Divider().overlay(Theme.ink(0.06)).padding(.leading, 56) }
                NavigationLink {
                    if live { GroupQuickPicker(group: g.name) } else { OfflineGroupPicker(group: g.name) }
                } label: {
                    HStack(spacing: 12) {
                        GroupIconView(group: g.name, profileIcon: g.icon, fallback: PolicyGroupDisplay(name: g.name, kind: g.kind, now: nil, members: [], selectable: false).icon, size: 32)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(g.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            Text(g.chain.dropFirst().joined(separator: " ➤ "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer(minLength: 6)
                        if let d = g.delay {
                            Text(Theme.delayText(d)).font(.caption2.monospacedDigit()).foregroundStyle(Theme.delayColor(d))
                        }
                        Image(systemName: "chevron.right").font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 11)
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
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.ink(0.06)))
    }
}

/// Members of one group from the profile file while disconnected; select groups save the choice for the next
/// connect (the same store as 策略's offline list).
struct OfflineGroupPicker: View {
    let group: String
    @ObservedObject private var insp = ProfileInspector.shared

    var body: some View {
        List {
            if let g = insp.result.groups.first(where: { $0.name == group }) {
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
    }
}

/// Members of one live group; selectable groups switch on tap.
struct GroupQuickPicker: View {
    let group: String
    @State private var item: ProxyItem?
    @State private var all: [String: ProxyItem] = [:]
    @State private var error: String?

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
                            if let d = all[m]?.lastDelay(for: NodeSettingsStore.testURL(for: m)) {
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
        .task { await load() }
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
            UISelectionFeedbackGenerator().selectionChanged()
            if group != "GLOBAL" { ProfileInspector.rememberLiveSelection(group: group, node: node) }
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
            await load()
            await DashboardModel.shared.refreshSelectedNode()
        } catch { self.error = error.localizedDescription }
    }
}
