import SwiftUI
import NetworkExtension

@MainActor
final class PolicyModel: ObservableObject {
    @Published var groups: [ProxyItem] = []
    @Published var all: [String: ProxyItem] = [:]
    @Published var testing: Set<String> = []
    @Published var error: String?

    func load() async {
        await SmartGroups.shared.refreshStatus()
        do {
            let p = try await ControllerClient.shared.proxies()
            all = p
            let order = p["GLOBAL"]?.all ?? []
            var gs = order.compactMap { p[$0] }.filter { $0.isGroup && $0.hidden != true }
            if let g = p["GLOBAL"] { gs.append(g) }
            groups = gs
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Results of this session's live 测速 (0 = timeout), newest wins over the core's history.
    @Published var liveDelays: [String: Int] = [:]

    func delay(of name: String) -> Int? {
        if let d = liveDelays[name] { return d }
        return all[name]?.lastDelay(for: ControllerClient.testSettings.url)
    }

    func select(_ group: ProxyItem, _ node: String) async {
        guard group.isSelectable else { return }
        do {
            try await ControllerClient.shared.select(group: group.name, node: node)
            UISelectionFeedbackGenerator().selectionChanged()
            if group.name != "GLOBAL" { ProfileInspector.rememberLiveSelection(group: group.name, node: node) }
            await load()
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// 固定 / 解除固定 (v0.8) a member of a url-test / fallback group (core-native, PUT / DELETE /proxies/{group}).
    func pin(_ group: ProxyItem, _ node: String?) async {
        do {
            if let node { try await ControllerClient.shared.pin(group: group.name, node: node) }
            else { try await ControllerClient.shared.unpin(group: group.name) }
            UISelectionFeedbackGenerator().selectionChanged()
            await load()
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        } catch {
            self.error = String(localized: "固定失败：\(error.localizedDescription)")
        }
    }

    /// Live 测速 through the running core (each member is dialled through its own node), with the
    /// URL and timeout from 更多 → 测速.
    func test(_ group: ProxyItem) async {
        testing.insert(group.name)
        defer { testing.remove(group.name) }
        let members = (group.all ?? []).filter { $0 != "DIRECT" && $0 != "REJECT" && $0 != "REJECT-DROP" && $0 != "PASS" && $0 != "COMPATIBLE" }
        var failure: String?
        do {
            switch try await ControllerClient.shared.groupDelay(group.name) {
            case .measured(let got):
                for m in members { liveDelays[m] = got[m] ?? 0 }
            case .allTimedOut:
                for m in members { liveDelays[m] = 0 }
            }
        } catch {
            // The controller itself did not answer: say so instead of marking every node as timed out.
            failure = String(localized: "测速失败：\(error.localizedDescription)")
        }
        await load()
        if let failure { self.error = failure }
    }
}

/// One policy group as the card shows it, from the live controller or from the profile file.
struct PolicyGroupDisplay {
    var name: String
    var kind: String          // select / url-test / fallback / load-balance / relay / global
    var now: String?
    var members: [String]
    var selectable: Bool
    /// The profile's own `icon:` (mihomo proxy-groups); the user's choice in group-icons.json wins.
    var profileIcon: String? = nil
    /// url-test / fallback member pinned in the core (v0.8), nil = automatic.
    var pinned: String? = nil

    var pinnable: Bool { kind == "url-test" || kind == "fallback" }

    static func kind(live type: String) -> String {
        switch type {
        case "Selector": return "select"
        case "URLTest": return "url-test"
        case "Fallback": return "fallback"
        case "LoadBalance": return "load-balance"
        case "Relay": return "relay"
        default: return type.lowercased()
        }
    }

    var label: String {
        switch kind {
        case "select": return String(localized: "手动")
        case "url-test": return String(localized: "自动")
        case "fallback": return String(localized: "故障转移")
        case "load-balance": return String(localized: "负载均衡")
        case "relay": return String(localized: "链式")
        default: return kind
        }
    }

    var icon: String {
        switch kind {
        case "select": return "hand.tap.fill"
        case "url-test": return "bolt.badge.clock.fill"
        case "fallback": return "arrow.triangle.branch"
        case "load-balance": return "scalemass.fill"
        case "relay": return "link"
        default: return "globe"
        }
    }

    var hint: String {
        switch kind {
        case "url-test": return String(localized: "自动选择延迟最低的节点（当前：\(now ?? "—")）")
        case "fallback": return String(localized: "按顺序使用第一个可用节点（当前：\(now ?? "—")）")
        case "load-balance": return String(localized: "在节点间分配连接")
        default: return String(localized: "该策略组不可手动选择")
        }
    }
}

struct PolicyView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @StateObject private var model = PolicyModel()
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var expanded: Set<String> = []
    @ObservedObject private var smart = SmartGroups.shared
    @State private var chainGroup: ChainGroupTarget?
    @State private var share: ShareTarget?
    @State private var shareError: String?
    /// 排序 (v0.7): default = profile order; latency uses a snapshot so nodes don't jump while a test runs.
    @AppStorage("policy.sort") private var sortMode = "default"
    @AppStorage("policy.autoSort") private var autoSort = true
    @State private var sortDelays: [String: Int] = [:]
    @State private var iconTarget: IconTarget?

    struct IconTarget: Identifiable { let id = UUID(); let name: String; let profileIcon: String? }
    struct ProbeTarget: Identifiable { let id = UUID(); let name: String }
    @State private var probeTarget: ProbeTarget?
    @ObservedObject private var probes = ProbeStore.shared

    struct ChainGroupTarget: Identifiable { let id = UUID(); let name: String }

    /// Groups that can carry a 前置代理 (not GLOBAL; DIRECT/REJECT style built-ins have no members).
    private func chainAction(_ name: String) -> (() -> Void)? {
        guard name != "GLOBAL" else { return nil }
        return { chainGroup = ChainGroupTarget(name: name) }
    }

    private func shareNode(_ name: String) {
        Task {
            switch await NodeShare.link(named: name) {
            case .success(let l): share = ShareTarget(name: name, link: l)
            case .failure(let e): shareError = e.message
            }
        }
    }

    /// Takes the delays the latency sort uses (after a test when 测速后自动排序 is on, or when the sort changes).
    private func snapshotDelays() {
        if vpn.isConnected {
            var d: [String: Int] = [:]
            for g in model.groups { for m in g.all ?? [] { if let v = model.delay(of: m) { d[m] = v } } }
            sortDelays = d
        } else {
            sortDelays = offline.delays
        }
    }

    private func afterTest() { if autoSort && sortMode == "latency" { snapshotDelays() } }

    private func ordered(_ members: [String]) -> [String] {
        switch sortMode {
        case "name":
            return members.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        case "latency":
            var index: [String: Int] = [:]
            for (i, m) in members.enumerated() where index[m] == nil { index[m] = i }
            func key(_ m: String) -> (Int, Int, Int) {
                let i = index[m] ?? 0
                guard let d = sortDelays[m] else { return (2, 0, i) }
                return d > 0 ? (0, d, i) : (1, 0, i)
            }
            return members.sorted { key($0) < key($1) }
        default:
            return members
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if vpn.isConnected { liveList } else { offlineList }
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("策略")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Menu {
                        Picker("排序", selection: $sortMode) {
                            Label("配置顺序", systemImage: "list.number").tag("default")
                            Label("按延迟", systemImage: "speedometer").tag("latency")
                            Label("按名称", systemImage: "textformat").tag("name")
                        }
                        Toggle("测速后自动排序", isOn: $autoSort)
                    } label: { Image(systemName: "arrow.up.arrow.down") }
                    .accessibilityLabel(Text("排序"))
                    Button {
                        Task {
                            if vpn.isConnected {
                                for g in model.groups where g.name != "GLOBAL" { await model.test(g) }
                            } else {
                                for g in offline.result.groups where g.hidden != true { await offline.test(group: g) }
                            }
                            afterTest()
                        }
                    } label: { Image(systemName: "bolt.fill") }
                    .accessibilityLabel(Text("全部测速"))
                }
            }
        }
        .task(id: vpn.isConnected) {
            if vpn.isConnected { await model.load() } else { await offline.load() }
            snapshotDelays()
        }
        .onChange(of: sortMode) { _ in snapshotDelays() }
        .sheet(item: $iconTarget) { t in GroupIconPicker(group: t.name, profileIcon: t.profileIcon) }
        .onChange(of: store.activeID) { _ in Task { if !vpn.isConnected { await offline.load() } } }
        .sheet(item: $chainGroup) { t in GroupChainSheet(group: t.name) }
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(item: $probeTarget) { t in NodeProbeSheet(policy: t.name) }
        .alert("分享节点", isPresented: Binding(get: { shareError != nil }, set: { if !$0 { shareError = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(shareError ?? "") }
    }

    /// Only url-test / fallback groups offer 智能选择.
    private func smartBinding(_ d: PolicyGroupDisplay) -> Binding<Bool>? {
        guard d.kind == "url-test" || d.kind == "fallback" else { return nil }
        return Binding(get: { smart.isSmart(d.name) }, set: { smart.set(d.name, smart: $0) })
    }

    private func binding(_ name: String) -> Binding<Bool> {
        Binding(get: { expanded.contains(name) },
                set: { v in if v { expanded.insert(name) } else { expanded.remove(name) } })
    }

    var liveList: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                if let e = model.error { Text(e).font(.footnote).foregroundStyle(Theme.bad) }
                TestTargetCaption(live: true)
                ForEach(model.groups) { g in
                    let fixed = (g.fixed ?? "").isEmpty ? nil : g.fixed
                    let d = PolicyGroupDisplay(name: g.name, kind: PolicyGroupDisplay.kind(live: g.type), now: g.now,
                                               members: ordered(g.all ?? []), selectable: g.isSelectable, profileIcon: g.icon,
                                               pinned: fixed)
                    PolicyGroupCard(group: d,
                                    testing: model.testing.contains(g.name),
                                    expanded: binding(g.name),
                                    nodeType: { model.all[$0]?.type },
                                    nodeUDP: { model.all[$0]?.udp == true },
                                    delay: { model.delay(of: $0) },
                                    onTest: { Task { await model.test(g); afterTest() } },
                                    onSelect: { n in Task { await model.select(g, n) } },
                                    smart: smartBinding(d),
                                    smartInfo: smart.summary(g.name),
                                    via: smart.via(g.name),
                                    onChain: chainAction(g.name),
                                    onShare: { shareNode($0) },
                                    onIcon: { iconTarget = IconTarget(name: g.name, profileIcon: g.icon) },
                                    onProbe: { probeTarget = ProbeTarget(name: $0) },
                                    badge: { probes.badge(for: $0) },
                                    onPin: d.pinnable && !smart.isSmart(g.name) ? { n in Task { await model.pin(g, n) } } : nil)
                }
            }
            .padding(16)
        }
        .refreshable { await model.load() }
    }

    var offlineList: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("未连接 · 来自配置文件")
                    Spacer()
                    if offline.loading { ProgressView().controlSize(.small) }
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

                if AppShared.activeProfileURL == nil {
                    NotConnectedPlaceholder(text: "请先在「配置」中添加并选择一个配置")
                } else if let e = offline.result.error, offline.result.groups.isEmpty {
                    ErrorRow(message: e)
                } else {
                    let index = offline.nodeIndex
                    let groupNames = Set(offline.result.groups.map(\.name))
                    ForEach(offline.result.groups.filter { $0.hidden != true }) { g in
                        let d = PolicyGroupDisplay(name: g.name, kind: g.type, now: offline.current(of: g),
                                                   members: ordered(offline.members(of: g)), selectable: g.type == "select", profileIcon: g.icon)
                        PolicyGroupCard(group: d,
                                        testing: offline.testing.contains(g.name),
                                        expanded: binding("offline:" + g.name),
                                        nodeType: { name in
                                            if let t = index[name]?.type { return t }
                                            return groupNames.contains(name) ? "group" : nil
                                        },
                                        nodeUDP: { index[$0]?.udp == true },
                                        delay: { offline.delays[$0] },
                                        onTest: { Task { await offline.test(group: g); afterTest() } },
                                        onSelect: { n in
                                            offline.select(group: g.name, node: n)
                                            UISelectionFeedbackGenerator().selectionChanged()
                                        },
                                        smart: smartBinding(d),
                                        smartInfo: smart.isSmart(g.name) ? String(localized: "连接后按延迟与失败记录自动选择") : nil,
                                        via: smart.via(g.name),
                                        onChain: chainAction(g.name),
                                        onShare: { shareNode($0) },
                                        onIcon: { iconTarget = IconTarget(name: g.name, profileIcon: g.icon) })
                    }
                    if !offline.result.groups.isEmpty {
                        TestTargetCaption(live: false)
                        Text("在这里选择的节点会保存到该配置，下次连接时生效。测速直接从本机发起（不经过代理）。节点集只显示已缓存的节点。")
                            .font(.caption2).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 4)
                    }
                }
            }
            .padding(16)
        }
        .refreshable { await offline.load() }
    }
}

struct PolicyGroupCard: View {
    let group: PolicyGroupDisplay
    let testing: Bool
    @Binding var expanded: Bool
    let nodeType: (String) -> String?
    let nodeUDP: (String) -> Bool
    let delay: (String) -> Int?
    let onTest: () -> Void
    let onSelect: (String) -> Void
    var smart: Binding<Bool>? = nil
    var smartInfo: String? = nil
    /// 前置代理 of the group (nil = none) and the action that opens the picker.
    var via: String? = nil
    var onChain: (() -> Void)? = nil
    /// Share a member node (link + QR).
    var onShare: ((String) -> Void)? = nil
    /// Opens the group icon picker.
    var onIcon: (() -> Void)? = nil
    /// v0.8 节点探测 sheet for a member (live only), and the 解锁 badge per member.
    var onProbe: ((String) -> Void)? = nil
    var badge: ((String) -> (ok: Int, total: Int)?)? = nil
    /// v0.8 固定 / 解除固定 (nil = not offered: not url-test / fallback, smart selection on, or offline).
    var onPin: ((String?) -> Void)? = nil

    static let unprobeable: Set<String> = ["REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]

    static let nonShareable: Set<String> = ["group", "selector", "urltest", "url-test", "fallback", "loadbalance", "load-balance", "relay",
                                            "direct", "reject", "rejectdrop", "reject-drop", "compatible", "pass", "dns"]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                GroupIconView(group: group.name, profileIcon: group.profileIcon, fallback: group.icon, size: 34)
                    .contextMenu {
                        if let onIcon { Button { onIcon() } label: { Label("更换图标", systemImage: "photo") } }
                    }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(group.name).font(.headline).lineLimit(1)
                        Text(group.label)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Capsule().fill(Color.white.opacity(0.1)))
                        if via != nil {
                            Image(systemName: "link").font(.caption2.weight(.bold)).foregroundStyle(Theme.accent)
                                .accessibilityLabel(Text("已设置前置代理"))
                        }
                        if group.pinned != nil {
                            Label("已固定", systemImage: "pin.fill")
                                .labelStyle(.titleAndIcon)
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Capsule().fill(Theme.warn.opacity(0.18)))
                                .foregroundStyle(Theme.warn)
                        }
                        if smart?.wrappedValue == true {
                            Label("智能", systemImage: "sparkles")
                                .labelStyle(.titleAndIcon)
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Capsule().fill(Theme.accent.opacity(0.18)))
                                .foregroundStyle(Theme.accent)
                        }
                    }
                    HStack(spacing: 6) {
                        Text(group.now ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        if let n = group.now, let d = delay(n) {
                            Text(Theme.delayText(d))
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(Theme.delayColor(d))
                        }
                    }
                }
                Spacer()
                Button(action: onTest) {
                    if testing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "speedometer").foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
                Image(systemName: "chevron.down")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(expanded ? 180 : 0))
            }
            .contentShape(Rectangle())
            .onTapGesture { withAnimation(.spring(response: 0.3)) { expanded.toggle() } }

            if expanded {
                if let smart {
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(isOn: smart) {
                            Label("智能选择", systemImage: "sparkles").font(.subheadline)
                        }
                        .tint(Theme.accent)
                        Text(smartInfo ?? String(localized: "开启后按近期延迟与失败记录综合评分，自动固定到最稳的节点；节点失效时 mihomo 会立即切走。"))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                }
                if let pinned = group.pinned, let onPin {
                    HStack(spacing: 8) {
                        Image(systemName: "pin.fill").font(.caption).foregroundStyle(Theme.warn)
                        Text("已固定到 \(pinned)").font(.subheadline).lineLimit(1)
                        Spacer()
                        Button("解除固定") { onPin(nil) }.font(.subheadline)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                } else if !group.selectable && smart?.wrappedValue != true {
                    Text(onPin != nil ? String(localized: "\(group.hint)。轻点节点可临时固定，自动选择暂停，直到解除固定。") : group.hint)
                        .font(.caption2).foregroundStyle(.secondary)
                }
                if let onChain {
                    Button(action: onChain) {
                        HStack(spacing: 8) {
                            Image(systemName: "link").font(.caption).foregroundStyle(via == nil ? Color.secondary : Theme.accent)
                            Text("前置代理").font(.subheadline)
                            Spacer()
                            Text(via ?? String(localized: "无")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                    }
                    .buttonStyle(.plain)
                }
                if let onIcon {
                    Button(action: onIcon) {
                        HStack(spacing: 8) {
                            Image(systemName: "photo").font(.caption).foregroundStyle(.secondary)
                            Text("图标").font(.subheadline)
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                    }
                    .buttonStyle(.plain)
                }
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                    ForEach(group.members, id: \.self) { name in
                        NodeCell(name: name,
                                 type: nodeType(name),
                                 udp: nodeUDP(name),
                                 delay: delay(name),
                                 selected: group.now == name,
                                 enabled: group.selectable || onPin != nil,
                                 pinned: group.pinned == name,
                                 badge: badge?(name))
                        .onTapGesture {
                            if group.selectable { onSelect(name) }
                            else if let onPin { onPin(group.pinned == name ? nil : name) }
                        }
                        .contextMenu {
                            if let onProbe, !Self.unprobeable.contains(name) {
                                Button { onProbe(name) } label: { Label("出口与解锁检测", systemImage: "location.magnifyingglass") }
                            }
                            if let onPin {
                                if group.pinned == name {
                                    Button { onPin(nil) } label: { Label("解除固定", systemImage: "pin.slash") }
                                } else {
                                    Button { onPin(name) } label: { Label("固定此节点", systemImage: "pin") }
                                }
                            }
                            if let onShare, let t = nodeType(name), !Self.nonShareable.contains(t.lowercased()) {
                                Button { onShare(name) } label: { Label("分享节点", systemImage: "qrcode") }
                            }
                        }
                    }
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.white.opacity(0.06)))
    }
}

struct NodeCell: View {
    let name: String
    let type: String?
    let udp: Bool
    let delay: Int?
    let selected: Bool
    let enabled: Bool
    var pinned: Bool = false
    var badge: (ok: Int, total: Int)? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(name)
                .font(.footnote.weight(selected ? .semibold : .regular))
                .lineLimit(2)
                .frame(maxWidth: .infinity, minHeight: 34, alignment: .topLeading)
            HStack {
                if let t = type {
                    if t == "group" {
                        Text("策略组").scaledFont(9, weight: .bold).foregroundStyle(.secondary)
                    } else {
                        ProtocolBadge(type: t)
                    }
                }
                if udp {
                    Text("UDP").scaledFont(9, weight: .bold).foregroundStyle(.secondary)
                }
                if let badge { UnlockBadge(ok: badge.ok, total: badge.total) }
                if pinned {
                    Image(systemName: "pin.fill").scaledFont(9, weight: .bold).foregroundStyle(Theme.warn)
                        .accessibilityLabel(Text("已固定"))
                }
                Spacer()
                Text(Theme.delayText(delay))
                    .scaledFont(11, weight: .semibold, monospacedDigit: true)
                    .foregroundStyle(Theme.delayColor(delay))
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(selected ? Theme.accent.opacity(0.22) : Theme.cardHi)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(selected ? Theme.accent : Color.clear, lineWidth: 1.2)
        )
        .opacity(enabled || selected ? 1 : 0.75)
    }
}

/// Which 测速 URL / timeout the bolt buttons use; set in 更多 → 测速.
struct TestTargetCaption: View {
    let live: Bool
    var body: some View {
        let st = ControllerClient.testSettings
        let host = URL(string: st.url)?.host ?? st.url
        HStack(spacing: 6) {
            Image(systemName: "bolt.horizontal")
            Text(live ? "测速经由内核：\(host) · \(st.timeoutMs / 1000) 秒超时" : "离线测速：\(host) · \(st.timeoutMs / 1000) 秒超时")
                .lineLimit(1)
            Spacer()
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
    }
}
