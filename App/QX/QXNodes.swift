import SwiftUI
import NetworkExtension
import Libmihomo

// QX 节点 panel: PROXY (node resources: 已保存 + each proxy-provider) and 自定义策略 (every visible policy
// group with its resolved chain). Live from the controller when connected, from the profile file otherwise.

struct QXGroup: Identifiable, Hashable {
    var id: String { name }
    /// QX url-latency-benchmark family: the groups the collapsed 自定义策略 section hides.
    static func isAutomatic(_ g: QXGroup) -> Bool {
        ["url-test", "fallback", "load-balance", "smart", "urltest", "loadbalance"].contains(g.kind.lowercased())
    }
    let name: String
    /// select / url-test / fallback / load-balance / relay
    let kind: String
    let icon: String?
    let now: String?
    let members: [String]
    let selectable: Bool
    let pinned: String?
    /// group → … → leaf node, following `now`.
    let chain: [String]

    var display: PolicyGroupDisplay {
        PolicyGroupDisplay(name: name, kind: kind, now: now, members: members, selectable: selectable, profileIcon: icon, pinned: pinned)
    }
}

struct QXResource: Identifiable, Hashable {
    var id: String { (isSaved ? "saved:" : "provider:") + name }
    let name: String
    let nodes: [String]
    let info: SubscriptionUserInfo?
    let isSaved: Bool
    let updated: Date?
}

@MainActor
final class QXNodesModel: ObservableObject {
    static let shared = QXNodesModel()

    @Published var proxies: [String: ProxyItem] = [:]
    @Published var providers: [ProviderItem] = []
    @Published var liveDelays: [String: Int] = [:]
    @Published var testing: Set<String> = []
    @Published var error: String?
    /// Offline node index (type, udp, feature badges), refreshed with the inspector.
    @Published private(set) var index: [String: InspectProxy] = [:]

    private let insp = ProfileInspector.shared
    static let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]

    var live: Bool { VPNManager.shared.isConnected && !proxies.isEmpty }

    func load() async {
        if VPNManager.shared.isConnected {
            do {
                proxies = QXHidden.clean(try await ControllerClient.shared.proxies())
                providers = QXHidden.clean((try? await ControllerClient.shared.proxyProviders()) ?? [])
                error = nil
            } catch {
                self.error = error.localizedDescription
            }
        } else {
            proxies = [:]
            providers = []
            error = nil
        }
        await insp.load()
        index = insp.nodeIndex
    }

    /// Live refresh of selections only (no inspector reload).
    func refreshLive() async {
        guard VPNManager.shared.isConnected, let raw = try? await ControllerClient.shared.proxies() else { return }
        let p = QXHidden.clean(raw)
        if p != proxies { proxies = p }
    }

    // MARK: lookups

    func type(of n: String) -> String? {
        if let t = proxies[n]?.type { return t }
        if let t = index[n]?.type { return t }
        if groupNames.contains(n) { return "group" }
        return nil
    }
    func udp(of n: String) -> Bool { proxies[n]?.udp ?? index[n]?.udp ?? false }
    func features(of n: String) -> [String] { index[n]?.features ?? [] }

    func delay(of n: String) -> Int? {
        if live {
            if let d = liveDelays[n] { return d }
            return proxies[n]?.lastDelay(for: ControllerClient.testSettings.url)
        }
        return insp.delays[n]
    }

    var groupNames: Set<String> {
        if live { return Set(proxies.values.filter(\.isGroup).map(\.name)) }
        return Set(insp.result.groups.map(\.name))
    }

    /// QX's built-in PROXY: a profile group named PROXY (QX imports create one), else mihomo's GLOBAL.
    var proxyGroupName: String {
        if live {
            if let g = proxies.values.first(where: { $0.isGroup && $0.name.uppercased() == "PROXY" }) { return g.name }
            return "GLOBAL"
        }
        if let g = insp.result.groups.first(where: { $0.name.uppercased() == "PROXY" }) { return g.name }
        return "GLOBAL"
    }

    var proxySelection: String? {
        if live { return QXHidden.visible(proxies[proxyGroupName]?.now) }
        if let g = insp.result.groups.first(where: { $0.name == proxyGroupName }) { return QXHidden.visible(insp.current(of: g)) }
        return QXHidden.visible(insp.result.selected[proxyGroupName])
    }

    // MARK: groups

    func groups() -> [QXGroup] {
        if live {
            let order = proxies["GLOBAL"]?.all ?? []
            var seen = Set<String>()
            var out: [QXGroup] = []
            for name in order {
                guard let p = proxies[name], p.isGroup, p.hidden != true, !seen.contains(name) else { continue }
                seen.insert(name)
                out.append(liveGroup(p))
            }
            return out
        }
        let gs = insp.result.groups.filter { $0.hidden != true }
        return gs.map { offlineGroup($0) }
    }

    func group(named name: String) -> QXGroup? {
        if live { return proxies[name].map { liveGroup($0) } }
        return insp.result.groups.first { $0.name == name }.map { offlineGroup($0) }
    }

    private func liveGroup(_ p: ProxyItem) -> QXGroup {
        var chain = [p.name]
        var cur = p.name
        while let n = QXHidden.visible(proxies[cur]?.now), chain.count < 6, !chain.contains(n) { chain.append(n); cur = n }
        let fixed: String? = (p.fixed ?? "").isEmpty ? nil : p.fixed
        return QXGroup(name: p.name, kind: PolicyGroupDisplay.kind(live: p.type), icon: p.icon, now: QXHidden.visible(p.now),
                       members: (p.all ?? []).filter { !QXHidden.names.contains($0) },
                       selectable: p.isSelectable, pinned: fixed, chain: chain)
    }

    private func offlineGroup(_ g: InspectGroup) -> QXGroup {
        let byName = Dictionary(insp.result.groups.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        var chain = [g.name]
        var cur = g
        while let n = QXHidden.visible(insp.current(of: cur)), chain.count < 6, !chain.contains(n) {
            chain.append(n)
            guard let next = byName[n] else { break }
            cur = next
        }
        return QXGroup(name: g.name, kind: g.type, icon: g.icon, now: QXHidden.visible(insp.current(of: g)),
                       members: insp.members(of: g).filter { !QXHidden.names.contains($0) },
                       selectable: g.type == "select", pinned: nil, chain: chain)
    }

    // MARK: resources

    func resources(profile: Profile?) -> [QXResource] {
        var out: [QXResource] = []
        let providerSource: [(String, [String], SubscriptionUserInfo?, Date?)]
        if live {
            providerSource = providers.map { p in
                let info = p.subscriptionInfo.map { s in
                    SubscriptionUserInfo(upload: s.Upload ?? 0, download: s.Download ?? 0, total: s.Total ?? 0, expire: s.Expire ?? 0)
                }
                let date = p.updatedAt.flatMap { ConnectionItem.iso.date(from: $0) ?? ConnectionItem.isoNoFrac.date(from: $0) }
                return (p.name, (p.proxies ?? []).map(\.name), info, date)
            }
        } else {
            providerSource = insp.result.proxyProviders.map { ($0.name, ($0.proxies ?? []).map(\.name), nil, $0.cachedDate) }
        }
        let providerNodes = Set(providerSource.flatMap { $0.1 })
        var saved = insp.result.proxies.map(\.name).filter { !Self.builtins.contains($0) }
        if live {
            // Nodes the core knows that are neither groups nor provider nodes (e.g. merged manual nodes).
            let known = Set(saved)
            let extra = proxies.values.filter { !$0.isGroup && !Self.builtins.contains($0.name) && !providerNodes.contains($0.name) && !known.contains($0.name) }
                .map(\.name).sorted()
            saved.append(contentsOf: extra)
        }
        let remote = profile?.kind == .remote
        out.append(QXResource(name: remote ? (profile?.name ?? String(localized: "已保存")) : String(localized: "已保存"),
                              nodes: saved, info: remote ? profile?.userInfo : nil, isSaved: true, updated: profile?.lastUpdated))
        for (name, nodes, info, date) in providerSource {
            out.append(QXResource(name: name, nodes: nodes, info: info, isSaved: false, updated: date))
        }
        return out
    }

    // MARK: actions

    func select(group: String, node: String) async {
        if live {
            do {
                try await ControllerClient.shared.select(group: group, node: node)
                UISelectionFeedbackGenerator().selectionChanged()
                if group != "GLOBAL" { ProfileInspector.rememberLiveSelection(group: group, node: node) }
                NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
                await refreshLive()
                await DashboardModel.shared.refreshSelectedNode()
            } catch {
                self.error = error.localizedDescription
            }
        } else {
            insp.select(group: group, node: node)
            UISelectionFeedbackGenerator().selectionChanged()
            objectWillChange.send()
        }
    }

    func pin(group: String, node: String?) async {
        guard live else { return }
        do {
            if let node { try await ControllerClient.shared.pin(group: group, node: node) } else { try await ControllerClient.shared.unpin(group: group) }
            UISelectionFeedbackGenerator().selectionChanged()
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
            await refreshLive()
        } catch {
            self.error = String(localized: "固定失败：\(error.localizedDescription)")
        }
    }

    /// Latency test of a group's members (live: inside the core; offline: direct from the app).
    func test(group name: String) async {
        testing.insert(name)
        defer { testing.remove(name) }
        if live {
            let members = (proxies[name]?.all ?? []).filter { !Self.builtins.contains($0) }
            do {
                switch try await ControllerClient.shared.groupDelay(name) {
                case .measured(let got): for m in members { liveDelays[m] = got[m] ?? 0 }
                case .allTimedOut: for m in members { liveDelays[m] = 0 }
                }
            } catch {
                self.error = String(localized: "测速失败：\(error.localizedDescription)")
            }
            await refreshLive()
        } else if let g = insp.result.groups.first(where: { $0.name == name }) {
            await insp.test(group: g)
        } else {
            await test(nodes: insp.result.proxies.map(\.name), key: name)
        }
    }

    /// Latency test of a list of nodes (a node resource, or one node). 6 at a time.
    func test(nodes: [String], key: String) async {
        testing.insert(key)
        defer { testing.remove(key) }
        let names = nodes.filter { !Self.builtins.contains($0) }
        let isLive = live
        let home = AppShared.homeURL.path
        let path = insp.profilePath ?? AppShared.activeProfileURL?.path ?? ""
        let st = ControllerClient.testSettings
        var idx = 0
        while idx < names.count {
            let batch = Array(names[idx..<min(idx + 6, names.count)])
            idx += batch.count
            let got = await withTaskGroup(of: (String, Int).self, returning: [(String, Int)].self) { tg in
                for n in batch {
                    tg.addTask {
                        if isLive {
                            let ms = (try? await ControllerClient.shared.proxyDelay(n)) ?? 0
                            return (n, ms)
                        }
                        return (n, Int(LibmihomoTestDelayByName(home, path, n, st.url, st.timeoutMs)))
                    }
                }
                var out: [(String, Int)] = []
                for await r in tg { out.append(r) }
                return out
            }
            for (n, ms) in got {
                if isLive { liveDelays[n] = ms } else { insp.delays[n] = ms }
            }
        }
    }

    func updateProvider(_ name: String) async {
        guard live else { return }
        do {
            try await ControllerClient.shared.updateProxyProvider(name)
            await load()
        } catch {
            self.error = String(localized: "更新失败：\(error.localizedDescription)")
        }
    }
}

// MARK: - Panel

struct QXNodesPanel: View {
    let active: Bool
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = QXNodesModel.shared
    @ObservedObject private var insp = ProfileInspector.shared
    @ObservedObject private var smart = SmartGroups.shared
    @AppStorage("qx.proxyExpanded") private var proxyExpanded = true
    @AppStorage("qx.policyExpanded") private var policyExpanded = true
    @State private var expanded: Set<String> = []
    @State private var iconTarget: QXIconTarget?
    @State private var chainTarget: QXNameTarget?
    @State private var probeTarget: QXNameTarget?
    @State private var share: ShareTarget?
    @State private var editTarget: QXEditTarget?
    @State private var sorting = false
    @State private var bgTarget: QXNameTarget?
    @State private var resEdit: QXResourceTarget?
    @State private var prefsTick = 0
    @ObservedObject private var nodeSubs = NodeSubStore.shared

    var body: some View {
        let _ = prefsTick
        let groups = QXPolicyPrefs.sorted(model.groups(), profile: store.activeID ?? "")
        let proxyName = model.proxyGroupName
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 9) {
                if let e = model.error {
                    ErrorRow(message: e).padding(.horizontal, 4)
                }
                if AppShared.activeProfileURL == nil {
                    QXEmptyProfileCard()
                }
                // QX preview 8: pinned script panels (main v0.15.1) as QX cards above PROXY.
                QXHomePanelsSection(active: active)
                QXSectionHeader(title: "PROXY", expanded: $proxyExpanded) {
                    Menu {
                        Button { Task { await testAllResources() } } label: { Label("全部测速", systemImage: "bolt.fill") }
                        Button { nav.push(.dest(.speedTest)) } label: { Label("测速设置", systemImage: "speedometer") }
                        Button { nav.push(.dest(.nodeResources)) } label: { Label("节点资源", systemImage: "link") }
                    } label: {
                        Image(systemName: "waveform.path.ecg.rectangle")
                            .font(.system(size: 22))
                            .foregroundStyle(QXColor.nodes)
                    }
                    .accessibilityLabel(Text("节点资源"))
                }
                if proxyExpanded {
                    ForEach(model.resources(profile: store.active)) { r in
                        QXResourceCard(resource: r,
                                       expanded: expanded.contains(r.id),
                                       selection: model.proxySelection,
                                       testing: model.testing.contains(r.id),
                                       onToggle: { toggle(r.id) },
                                       onTest: { Task { await model.test(nodes: r.nodes, key: r.id) } },
                                       onSelect: { n in Task { await model.select(group: proxyName, node: n) } },
                                       onProbe: vpn.isConnected ? { probeTarget = QXNameTarget(name: $0) } : nil,
                                       onShare: { shareNode($0) },
                                       onUpdate: r.isSaved ? (store.active?.kind == .remote ? { refreshProfile() } : nil)
                                                           : (vpn.isConnected ? { Task { await model.updateProvider(r.name) } } : nil),
                                       link: r.isSaved ? store.active?.url : insp.result.proxyProviders.first(where: { $0.name == r.name })?.url,
                                       onEdit: editAction(r))
                    }
                }

                QXSectionHeader(title: String(localized: "自定义策略"), expanded: $policyExpanded) {
                    Button { editTarget = QXEditTarget(name: nil) } label: {
                        Image(systemName: "sum")
                            .font(.system(size: 22, weight: .semibold))
                            .foregroundStyle(QXColor.policyChip)
                            .overlay(alignment: .bottomTrailing) {
                                Image(systemName: "plus.circle.fill").font(.system(size: 11)).foregroundStyle(QXColor.policyChip)
                                    .background(Circle().fill(QXPalette.bg)).offset(x: 6, y: 4)
                            }
                    }
                    .accessibilityLabel(Text("添加策略"))
                }
                // Frame 01: last PROXY card → 自定义策略 card 82 pt (we had 56).
                .padding(.top, 8)
                // Quantumult X: collapsing 自定义策略 hides only the automatic (url-latency-benchmark) groups —
                // url-test, fallback, load-balance (and smart); static / select groups stay (state persisted in
                // qx.policyExpanded).
                let listed = groups.filter { ($0.name != proxyName || proxyName == "GLOBAL") && (policyExpanded || !QXGroup.isAutomatic($0)) }
                let hiddenAuto = policyExpanded ? 0 : groups.filter { ($0.name != proxyName || proxyName == "GLOBAL") && QXGroup.isAutomatic($0) }.count
                Group {
                    ForEach(listed) { g in
                        QXPolicyRow(group: g,
                                    testing: model.testing.contains(g.name),
                                    smart: smart.isSmart(g.name),
                                    onTest: { Task { await model.test(group: g.name) } },
                                    onOpen: { nav.push(.group(g.name)) },
                                    onEdit: g.name == "GLOBAL" ? nil : { editTarget = QXEditTarget(name: g.name) },
                                    onIcon: { iconTarget = QXIconTarget(name: g.name, profileIcon: g.icon) },
                                    onChain: g.name == "GLOBAL" ? nil : { chainTarget = QXNameTarget(name: g.name) },
                                    onProbe: vpn.isConnected ? { probeTarget = QXNameTarget(name: g.name) } : nil,
                                    onSort: { sorting = true },
                                    onBackground: { bgTarget = QXNameTarget(name: g.name) },
                                    background: QXPolicyPrefs.background(g.name))
                    }
                    if hiddenAuto > 0 {
                        Text("已收起 \(hiddenAuto) 个自动测速策略（url-test / fallback / load-balance），轻点 ▶ 展开。")
                            .font(.caption2).foregroundStyle(.secondary).padding(.horizontal, 4)
                    }
                    if groups.isEmpty && AppShared.activeProfileURL != nil {
                        Text(insp.loading ? LocalizedStringKey("正在读取配置…") : LocalizedStringKey("这个配置没有策略组。"))
                            .font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
                    }
                }
                TestTargetCaption(live: vpn.isConnected).padding(.top, 6)
                if !vpn.isConnected {
                    Text("未连接：显示的是配置文件中的内容，选择会在下次连接时生效；测速直接从本机发起。")
                        .font(.caption2).foregroundStyle(.secondary).padding(.horizontal, 4)
                }
            }
            .padding(.horizontal, QXMetrics.inset)
            .padding(.bottom, 110)
        }
        .refreshable { await model.load() }
        .task(id: "\(active)|\(vpn.isConnected)|\(store.activeID ?? "")") {
            guard active else { return }
            await model.load()
            while !Task.isCancelled && vpn.isConnected {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                if Task.isCancelled { break }
                await model.refreshLive()
            }
        }
        .sheet(item: $iconTarget) { t in GroupIconPicker(group: t.name, profileIcon: t.profileIcon) }
        .sheet(item: $chainTarget) { t in GroupChainSheet(group: t.name) }
        .sheet(item: $probeTarget) { t in NodeProbeSheet(policy: t.name) }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(item: $editTarget, onDismiss: { Task { await model.load() } }) { t in
            QXPolicyEditor(groupName: t.name).environmentObject(store).environmentObject(vpn)
        }
        .sheet(isPresented: $sorting) {
            QXPolicySortSheet(profileID: store.activeID ?? "", names: groups.map(\.name)) { prefsTick += 1 }
        }
        .sheet(item: $bgTarget) { t in QXPolicyBackgroundSheet(group: t.name) { prefsTick += 1 } }
        .sheet(item: $resEdit, onDismiss: { Task { await model.load() } }) { t in QXResourceEditor(target: t).environmentObject(store) }
    }

    /// 编辑 on a resource card: the remote config itself, or one of our node subscriptions.
    private func editAction(_ r: QXResource) -> (() -> Void)? {
        if r.isSaved {
            guard let p = store.active, p.kind == .remote else { return nil }
            return { resEdit = QXResourceTarget(kind: .profile(p.id)) }
        }
        guard let s = nodeSubs.subs.first(where: { $0.name == r.name }) else { return nil }
        return { resEdit = QXResourceTarget(kind: .nodeSub(s.id)) }
    }

    private func toggle(_ id: String) {
        withAnimation(QXMotion.spring) {
            if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
        }
    }

    private func testAllResources() async {
        for r in model.resources(profile: store.active) where !r.nodes.isEmpty {
            await model.test(nodes: r.nodes, key: r.id)
        }
    }

    private func refreshProfile() {
        guard let p = store.active else { return }
        Task {
            if let e = await store.refresh(p) { model.error = e } else { await model.load() }
        }
    }

    private func shareNode(_ name: String) {
        Task {
            switch await NodeShare.link(named: name) {
            case .success(let l): share = ShareTarget(name: name, link: l)
            case .failure(let e): model.error = e.message
            }
        }
    }
}

struct QXIconTarget: Identifiable { let id = UUID(); let name: String; let profileIcon: String? }
struct QXNameTarget: Identifiable { let id = UUID(); let name: String }
/// Policy editor target (nil name = new policy, QX Σ+).
struct QXEditTarget: Identifiable { let id = UUID(); let name: String? }

// MARK: - Resource card

struct QXResourceCard: View {
    let resource: QXResource
    let expanded: Bool
    let selection: String?
    let testing: Bool
    let onToggle: () -> Void
    let onTest: () -> Void
    let onSelect: (String) -> Void
    var onProbe: ((String) -> Void)? = nil
    var onShare: ((String) -> Void)? = nil
    var onUpdate: (() -> Void)? = nil
    /// Remote URL of the resource (subscription / provider), for 资源链接.
    var link: String? = nil
    var onEdit: (() -> Void)? = nil
    @ObservedObject private var model = QXNodesModel.shared

    var body: some View {
        QXCard {
            LazyVStack(spacing: 0) {
                // QX-5 size check (frame 01, 600 px = 393 pt): card 62 pt high, 9 pt apart, glyph centred 31 pt
                // from the card edge, title at 59 pt, 30 pt grey bar before the count.
                HStack(spacing: 13) {
                    Button(action: onTest) {
                        ZStack {
                            if testing { ProgressView().controlSize(.small) } else {
                                Image(systemName: "server.rack").font(.system(size: 19, weight: .semibold)).foregroundStyle(QXColor.nodes)
                            }
                        }
                        .frame(width: 30, height: 36)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("测速"))
                    Text(verbatim: resource.name).font(QXType.rowTitle).lineLimit(1)
                    Spacer(minLength: 6)
                    if let info = resource.info {
                        VStack(alignment: .trailing, spacing: 1) {
                            if let d = info.expireDate {
                                Text(verbatim: QXFmt.day.string(from: d)).font(.system(size: 12, weight: .medium, design: .rounded).monospacedDigit()).foregroundStyle(.secondary)
                            }
                            Text(verbatim: Fmt.bytes(info.used)).font(.system(size: 14, weight: .semibold, design: .rounded).monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                    RoundedRectangle(cornerRadius: 1.5).fill(QXPalette.separator).frame(width: 3, height: 30)
                    Text(verbatim: "\(resource.nodes.count)").font(.system(size: 15).monospacedDigit()).foregroundStyle(.secondary)
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .frame(minHeight: 64)   // QX preview 7: 63.7–64.3 pt in frame 01 (simulator had 62)
                .contentShape(Rectangle())
                .onTapGesture(perform: onToggle)
                .contextMenu {
                    if let onEdit { Button(action: onEdit) { Label("编辑", systemImage: "square.and.pencil") } }
                    Button(action: onTest) { Label("测速", systemImage: "bolt") }
                    if let onUpdate { Button(action: onUpdate) { Label("更新", systemImage: "arrow.clockwise") } }
                    Button { UIPasteboard.general.string = resource.name } label: { Label("拷贝名称", systemImage: "doc.on.doc") }
                    if let link, !link.isEmpty {
                        Button { UIPasteboard.general.string = link } label: { Label("资源链接", systemImage: "link") }
                    }
                }

                if expanded {
                    if resource.nodes.isEmpty {
                        Text("没有节点（节点集未下载时，连接后或在节点资源中更新）。")
                            .font(.footnote).foregroundStyle(.secondary)
                            .padding(.horizontal, 16).padding(.bottom, 14)
                    }
                    ForEach(resource.nodes, id: \.self) { n in
                        Divider().padding(.leading, 16)
                        QXNodeRow(name: n, selected: selection == n, pinned: false)
                            .contentShape(Rectangle())
                            .onTapGesture { onSelect(n) }
                            .contextMenu {
                                Button { Task { await model.test(nodes: [n], key: n) } } label: { Label("测速", systemImage: "bolt") }
                                if let onProbe { Button { onProbe(n) } label: { Label("出口与解锁检测", systemImage: "location.magnifyingglass") } }
                                if let onShare { Button { onShare(n) } label: { Label("分享节点", systemImage: "qrcode") } }
                                Button { UIPasteboard.general.string = n } label: { Label("拷贝名称", systemImage: "doc.on.doc") }
                            }
                    }
                }
            }
        }
    }
}

// MARK: - Node row (QX: name, PROTOCOL + feature badges, latency)

struct QXNodeRow: View {
    let name: String
    let selected: Bool
    let pinned: Bool
    var enabled = true
    /// QX preview 8: policy-detail rows are their own 64 pt cards like the home policy / resource cards.
    var minHeight: CGFloat? = nil
    @ObservedObject private var model = QXNodesModel.shared
    @ObservedObject private var probes = ProbeStore.shared

    var body: some View {
        let type = model.type(of: name)
        let d = model.delay(of: name)
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: name)
                    .font(QXType.rowTitle.weight(selected ? .semibold : .regular))
                    .foregroundStyle(selected ? QXColor.switchOn : Color.primary)
                    .lineLimit(1)
                HStack(spacing: 4) {
                    if let type {
                        Text(verbatim: type == "group" ? String(localized: "策略组") : QXFmt.protocolName(type))
                            .scaledFont(11, weight: .semibold)
                            .foregroundStyle(.secondary)
                    }
                    QXFeatureBadges(features: model.features(of: name), udp: model.udp(of: name))
                    if let b = probes.badge(for: name) { UnlockBadge(ok: b.ok, total: b.total) }
                    if pinned {
                        Image(systemName: "pin.fill").scaledFont(10, weight: .bold).foregroundStyle(QXColor.warning)
                            .accessibilityLabel(Text("已固定"))
                    }
                }
            }
            Spacer(minLength: 6)
            if selected {
                Image(systemName: "checkmark").font(.system(size: 14, weight: .bold)).foregroundStyle(QXColor.switchOn)
            }
            Text(verbatim: d.map { $0 > 0 ? "\($0)" : String(localized: "超时") } ?? "—")
                .font(.system(size: 14, weight: .semibold, design: .rounded).monospacedDigit())
                .foregroundStyle(QXColor.delay(d))
                .frame(minWidth: 36, alignment: .trailing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, minHeight == nil ? 10 : 8)
        .frame(minHeight: minHeight)
        .opacity(enabled || selected ? 1 : 0.6)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// QX letter badges: A VMess AEAD, F TFO, U UDP, W WebSocket, S TLS (hollow = verification off), P pinning,
/// N ALPN, V Vision, R Reality, G gRPC, H h2, M mux, E ECH.
struct QXFeatureBadges: View {
    let features: [String]
    let udp: Bool

    var items: [(String, Bool)] {
        var out: [(String, Bool)] = []
        let f = Set(features)
        if f.contains("aead") { out.append(("A", true)) }
        if f.contains("tfo") { out.append(("F", true)) }
        if udp || f.contains("uot") { out.append(("U", true)) }
        if f.contains("ws") { out.append(("W", true)) }
        if f.contains("grpc") { out.append(("G", true)) }
        if f.contains("h2") { out.append(("H", true)) }
        if f.contains("tls") { out.append(("S", !f.contains("skip-cert"))) }
        if f.contains("pin") { out.append(("P", true)) }
        if f.contains("alpn") { out.append(("N", true)) }
        if f.contains("vision") { out.append(("V", true)) }
        if f.contains("reality") { out.append(("R", true)) }
        if f.contains("mux") { out.append(("M", true)) }
        if f.contains("ech") { out.append(("E", true)) }
        return out
    }

    var body: some View {
        HStack(spacing: 2) {
            ForEach(items, id: \.0) { item in
                Text(verbatim: item.0)
                    .font(.system(size: 9, weight: .heavy, design: .rounded))
                    .frame(width: 13, height: 13)
                    .foregroundStyle(item.1 ? Color(UIColor.systemBackground) : Color.secondary)
                    .background(RoundedRectangle(cornerRadius: 3, style: .continuous).fill(item.1 ? Color.secondary : Color.clear))
                    .overlay(RoundedRectangle(cornerRadius: 3, style: .continuous).stroke(Color.secondary, lineWidth: item.1 ? 0 : 1))
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Policy row

struct QXPolicyRow: View {
    let group: QXGroup
    let testing: Bool
    let smart: Bool
    let onTest: () -> Void
    let onOpen: () -> Void
    var onEdit: (() -> Void)? = nil
    let onIcon: () -> Void
    var onChain: (() -> Void)? = nil
    var onProbe: (() -> Void)? = nil
    var onSort: (() -> Void)? = nil
    var onBackground: (() -> Void)? = nil
    var background: Color? = nil

    var statusIcon: String {
        if group.pinned != nil { return "pin.fill" }
        switch group.kind {
        case "select": return "checkmark"
        case "url-test": return smart ? "sparkles" : "chart.bar.fill"
        case "fallback": return "arrow.triangle.branch"
        case "load-balance": return "scalemass.fill"
        case "relay": return "link"
        default: return "globe"
        }
    }

    var body: some View {
        QXCard {
            // QX-5 size check (frames 01 / 07): 62 pt card, 37 pt icon 12 pt from the edge, title at 59 pt
            // (17 pt regular), 13 pt grey chain, 30 pt bar, ~18 pt grey status disc, chevron.
            HStack(spacing: 10) {
                Button(action: onTest) {
                    ZStack {
                        GroupIconView(group: group.name, profileIcon: group.icon, fallback: group.display.icon, size: 37)
                        if testing {
                            Circle().fill(.ultraThinMaterial).frame(width: 37, height: 37)
                            ProgressView().controlSize(.small)
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("测速"))
                VStack(alignment: .leading, spacing: 3) {
                    Text(verbatim: group.name).font(QXType.rowTitle).lineLimit(1)
                    Text(verbatim: group.chain.dropFirst().joined(separator: " ➤ ").isEmpty ? group.display.label : group.chain.dropFirst().joined(separator: " ➤ "))
                        .font(QXType.rowDetail)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 6)
                RoundedRectangle(cornerRadius: 1.5).fill(QXPalette.separator).frame(width: 3, height: 30)
                    .padding(.leading, 4)
                Image(systemName: statusIcon)
                    .font(.system(size: 9, weight: .heavy))
                    .foregroundStyle(Color(UIColor.systemBackground))
                    .frame(width: 18, height: 18)
                    .padding(.horizontal, 4)
                    .background(Circle().fill(Color.secondary.opacity(0.75)))
                    .accessibilityLabel(Text(group.display.label))
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
            }
            .padding(.leading, 12)
            .padding(.trailing, 16)
            .padding(.vertical, 6)
            .frame(minHeight: 64)   // QX preview 7: 63.7–64.3 pt in frame 01 (simulator had 62)
            .background {
                if let background {
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .fill(LinearGradient(colors: [background.opacity(0.30), background.opacity(0.10)], startPoint: .leading, endPoint: .trailing))
                }
            }
            .contentShape(Rectangle())
            .onTapGesture(perform: onOpen)
            .contextMenu {
                if let onSort { Button(action: onSort) { Label("排序", systemImage: "line.3.horizontal") } }
                if let onEdit { Button(action: onEdit) { Label("编辑", systemImage: "square.and.pencil") } }
                Button(action: onOpen) { Label("节点", systemImage: "list.bullet") }
                Button(action: onTest) { Label("测速", systemImage: "bolt") }
                Button(action: onIcon) { Label("图标", systemImage: "square.grid.2x2") }
                if let onBackground { Button(action: onBackground) { Label("背景", systemImage: "paintpalette") } }
                if let onChain { Button(action: onChain) { Label("前置代理", systemImage: "link") } }
                if let onProbe {
                    Divider()
                    Button(action: onProbe) { Label("GeoIP 查询", systemImage: "location.viewfinder") }
                    Button(action: onProbe) { Label("流媒体-解锁查询", systemImage: "checkmark.seal") }
                }
            }
        }
    }
}

// MARK: - Group detail (tap a policy)

struct QXGroupDetailView: View {
    let name: String
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var model = QXNodesModel.shared
    @ObservedObject private var smart = SmartGroups.shared
    @AppStorage("policy.sort") private var sortMode = "default"
    @State private var iconTarget: QXIconTarget?
    @State private var chainTarget: QXNameTarget?
    @State private var probeTarget: QXNameTarget?
    @State private var share: ShareTarget?
    @State private var editing: QXEditTarget?
    @EnvironmentObject var store: ProfileStore

    func ordered(_ members: [String]) -> [String] {
        switch sortMode {
        case "name": return members.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        case "latency":
            var index: [String: Int] = [:]
            for (i, m) in members.enumerated() where index[m] == nil { index[m] = i }
            func key(_ m: String) -> (Int, Int, Int) {
                let i = index[m] ?? 0
                guard let d = model.delay(of: m) else { return (2, 0, i) }
                return d > 0 ? (0, d, i) : (1, 0, i)
            }
            return members.sorted { key($0) < key($1) }
        default: return members
        }
    }

    var body: some View {
        QXPage(title: name) {
            QXCapsuleBar {
                Menu {
                    Picker("排序", selection: $sortMode) {
                        Label("配置顺序", systemImage: "list.number").tag("default")
                        Label("按延迟", systemImage: "speedometer").tag("latency")
                        Label("按名称", systemImage: "textformat").tag("name")
                    }
                } label: {
                    Image(systemName: "arrow.up.arrow.down").font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary).frame(width: 38, height: 40)
                }
                .accessibilityLabel(Text("排序"))
                if model.testing.contains(name) {
                    ProgressView().frame(width: 38, height: 40)
                } else {
                    QXBarIcon(systemName: "bolt.fill", tint: QXColor.nodes) { Task { await model.test(group: name) } }
                        .accessibilityLabel(Text("测速"))
                }
                if name != "GLOBAL" {
                    QXBarIcon(systemName: "square.and.pencil") { editing = QXEditTarget(name: name) }
                        .accessibilityLabel(Text("编辑"))
                }
            }
        } content: {
        ScrollView {
                // QX preview 8 (density): page inset 18 pt, cards 9 pt apart, each node its own 64 pt card with the
                // policy-row title / detail type — the same rhythm as the home PROXY / 自定义策略 cards (frame 01/06).
                LazyVStack(alignment: .leading, spacing: 9) {
                    if let e = model.error { ErrorRow(message: e) }
                    if let g = model.group(named: name) {
                        header(g).padding(.bottom, 9)
                        let pinAction = (g.kind == "url-test" || g.kind == "fallback") && model.live && !smart.isSmart(g.name)
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text("节点").font(.headline)
                            Text(verbatim: "\(g.members.count)").font(.subheadline).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 4)
                        ForEach(ordered(g.members), id: \.self) { m in
                                QXCard {
                                    QXNodeRow(name: m, selected: g.now == m, pinned: g.pinned == m, enabled: g.selectable || pinAction, minHeight: 64)
                                        .contentShape(Rectangle())
                                        .onTapGesture {
                                            if g.selectable { Task { await model.select(group: g.name, node: m) } }
                                            else if pinAction { Task { await model.pin(group: g.name, node: g.pinned == m ? nil : m) } }
                                        }
                                        .contextMenu {
                                            Button { Task { await model.test(nodes: [m], key: m) } } label: { Label("测速", systemImage: "bolt") }
                                            if vpn.isConnected && !PolicyGroupCard.unprobeable.contains(m) {
                                                Button { probeTarget = QXNameTarget(name: m) } label: { Label("出口与解锁检测", systemImage: "location.magnifyingglass") }
                                            }
                                            if pinAction {
                                                if g.pinned == m {
                                                    Button { Task { await model.pin(group: g.name, node: nil) } } label: { Label("解除固定", systemImage: "pin.slash") }
                                                } else {
                                                    Button { Task { await model.pin(group: g.name, node: m) } } label: { Label("固定此节点", systemImage: "pin") }
                                                }
                                            }
                                            if let t = model.type(of: m), !PolicyGroupCard.nonShareable.contains(t.lowercased()) {
                                                Button { shareNode(m) } label: { Label("分享节点", systemImage: "qrcode") }
                                            }
                                        }
                                }
                        }
                        if !g.selectable {
                            Text(pinAction ? String(localized: "\(g.display.hint)。轻点节点可临时固定，自动选择暂停，直到解除固定。") : g.display.hint)
                                .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 4)
                        }
                        TestTargetCaption(live: vpn.isConnected)
                    } else {
                        EmptyStateView(icon: "questionmark.folder", title: "找不到这个策略")
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.top, 1)
                .padding(.bottom, 30)
            }
        }
        .task { if model.proxies.isEmpty && model.index.isEmpty { await model.load() } else { await model.refreshLive() } }
        .refreshable { await model.load() }
        .sheet(item: $iconTarget) { t in GroupIconPicker(group: t.name, profileIcon: t.profileIcon) }
        .sheet(item: $chainTarget) { t in GroupChainSheet(group: t.name) }
        .sheet(item: $probeTarget) { t in NodeProbeSheet(policy: t.name) }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(item: $editing, onDismiss: { Task { await model.load() } }) { t in
            QXPolicyEditor(groupName: t.name).environmentObject(store).environmentObject(vpn)
        }
    }

    @ViewBuilder func header(_ g: QXGroup) -> some View {
        QXCard {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 14) {
                    GroupIconView(group: g.name, profileIcon: g.icon, fallback: g.display.icon, size: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(verbatim: g.name).font(.title3.weight(.bold)).lineLimit(1)
                            QXChip(text: g.display.label, color: QXColor.policyChip)
                        }
                        Text(verbatim: g.chain.dropFirst().joined(separator: " ➤ "))
                            .font(.footnote).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 0)
                }
                if g.kind == "url-test" || g.kind == "fallback" {
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(isOn: Binding(get: { smart.isSmart(g.name) }, set: { smart.set(g.name, smart: $0) })) {
                            Label("智能选择", systemImage: "sparkles").font(.subheadline)
                        }
                        .tint(QXColor.switchOn)
                        Text(smart.summary(g.name) ?? String(localized: "开启后按近期延迟与失败记录综合评分，自动固定到最稳的节点；节点失效时 mihomo 会立即切走。"))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                HStack(spacing: 10) {
                    detailButton(String(localized: "图标"), "square.grid.2x2") { iconTarget = QXIconTarget(name: g.name, profileIcon: g.icon) }
                    if g.name != "GLOBAL" {
                        detailButton(smart.via(g.name).map { String(localized: "前置：\($0)") } ?? String(localized: "前置代理"), "link") { chainTarget = QXNameTarget(name: g.name) }
                    }
                    if vpn.isConnected {
                        detailButton(String(localized: "解锁检测"), "checkmark.seal") { probeTarget = QXNameTarget(name: g.name) }
                    }
                }
            }
            .padding(16)
        }
    }

    private func detailButton(_ title: String, _ icon: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon)
                .font(.footnote.weight(.semibold))
                .lineLimit(1)
                .frame(maxWidth: .infinity, minHeight: 36)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXPalette.cardHi))
        }
        .buttonStyle(.plain)
    }

    private func shareNode(_ name: String) {
        Task {
            switch await NodeShare.link(named: name) {
            case .success(let l): share = ShareTarget(name: name, link: l)
            case .failure(let e): model.error = e.message
            }
        }
    }
}


/// QX preview 7: internal outbounds never appear as a node or a selection in QX rows / subtitles. The core
/// fix for groups picking up __MITM__ (include-all / filter) is in bridge (hotfix v0.14.1); this only keeps
/// the UI clean when a core still reports it (ControllerClient.proxies() hides it from `all`, not from `now`).
enum QXHidden {
    static let names: Set<String> = ["__MITM__", PolicyProbe.group]
    static func visible(_ n: String?) -> String? {
        guard let n, !n.isEmpty, !names.contains(n) else { return nil }
        return n
    }
    static func clean(_ p: [String: ProxyItem]) -> [String: ProxyItem] {
        var out = p
        for n in names { out.removeValue(forKey: n) }
        for (k, v) in out {
            var v2 = v
            var changed = false
            if let now = v.now, names.contains(now) { v2.now = nil; changed = true }
            if v.all?.contains(where: { names.contains($0) }) == true { v2.all = v.all?.filter { !names.contains($0) }; changed = true }
            if changed { out[k] = v2 }
        }
        return out
    }
    static func clean(_ p: [ProviderItem]) -> [ProviderItem] {
        p.map { pv in
            guard pv.proxies?.contains(where: { names.contains($0.name) }) == true else { return pv }
            var x = pv
            x.proxies = pv.proxies?.filter { !names.contains($0.name) }
            return x
        }
    }
}
