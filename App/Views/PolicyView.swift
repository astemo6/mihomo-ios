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

    func delay(of name: String) -> Int? { all[name]?.lastDelay }

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

    func test(_ group: ProxyItem) async {
        testing.insert(group.name)
        defer { testing.remove(group.name) }
        _ = try? await ControllerClient.shared.groupDelay(group.name, url: group.testUrl ?? ControllerClient.testURL)
        await load()
    }
}

/// One policy group as the card shows it, from the live controller or from the profile file.
struct PolicyGroupDisplay {
    var name: String
    var kind: String          // select / url-test / fallback / load-balance / relay / global
    var now: String?
    var members: [String]
    var selectable: Bool

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

    var body: some View {
        NavigationStack {
            Group {
                if vpn.isConnected { liveList } else { offlineList }
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("策略")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task {
                            if vpn.isConnected {
                                for g in model.groups where g.name != "GLOBAL" { await model.test(g) }
                            } else {
                                for g in offline.result.groups where g.hidden != true { await offline.test(group: g) }
                            }
                        }
                    } label: { Image(systemName: "bolt.fill") }
                }
            }
        }
        .task(id: vpn.isConnected) {
            if vpn.isConnected { await model.load() } else { await offline.load() }
        }
        .onChange(of: store.activeID) { _ in Task { if !vpn.isConnected { await offline.load() } } }
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
                ForEach(model.groups) { g in
                    let d = PolicyGroupDisplay(name: g.name, kind: PolicyGroupDisplay.kind(live: g.type), now: g.now,
                                               members: g.all ?? [], selectable: g.isSelectable)
                    PolicyGroupCard(group: d,
                                    testing: model.testing.contains(g.name),
                                    expanded: binding(g.name),
                                    nodeType: { model.all[$0]?.type },
                                    nodeUDP: { model.all[$0]?.udp == true },
                                    delay: { model.delay(of: $0) },
                                    onTest: { Task { await model.test(g) } },
                                    onSelect: { n in Task { await model.select(g, n) } },
                                    smart: smartBinding(d),
                                    smartInfo: smart.summary(g.name))
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
                    Text(e).font(.footnote).foregroundStyle(Theme.bad).frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    let index = offline.nodeIndex
                    let groupNames = Set(offline.result.groups.map(\.name))
                    ForEach(offline.result.groups.filter { $0.hidden != true }) { g in
                        let d = PolicyGroupDisplay(name: g.name, kind: g.type, now: offline.current(of: g),
                                                   members: offline.members(of: g), selectable: g.type == "select")
                        PolicyGroupCard(group: d,
                                        testing: offline.testing.contains(g.name),
                                        expanded: binding("offline:" + g.name),
                                        nodeType: { name in
                                            if let t = index[name]?.type { return t }
                                            return groupNames.contains(name) ? "group" : nil
                                        },
                                        nodeUDP: { index[$0]?.udp == true },
                                        delay: { offline.delays[$0] },
                                        onTest: { Task { await offline.test(group: g) } },
                                        onSelect: { n in
                                            offline.select(group: g.name, node: n)
                                            UISelectionFeedbackGenerator().selectionChanged()
                                        },
                                        smart: smartBinding(d),
                                        smartInfo: smart.isSmart(g.name) ? String(localized: "连接后按延迟与失败记录自动选择") : nil)
                    }
                    if !offline.result.groups.isEmpty {
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: group.icon)
                    .font(.headline)
                    .foregroundStyle(Theme.accent)
                    .frame(width: 34, height: 34)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.accent.opacity(0.15)))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(group.name).font(.headline).lineLimit(1)
                        Text(group.label)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Capsule().fill(Color.white.opacity(0.1)))
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
                if !group.selectable && smart?.wrappedValue != true {
                    Text(group.hint).font(.caption2).foregroundStyle(.secondary)
                }
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                    ForEach(group.members, id: \.self) { name in
                        NodeCell(name: name,
                                 type: nodeType(name),
                                 udp: nodeUDP(name),
                                 delay: delay(name),
                                 selected: group.now == name,
                                 enabled: group.selectable)
                        .onTapGesture { if group.selectable { onSelect(name) } }
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

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(name)
                .font(.footnote.weight(selected ? .semibold : .regular))
                .lineLimit(2)
                .frame(maxWidth: .infinity, minHeight: 34, alignment: .topLeading)
            HStack {
                if let t = type {
                    if t == "group" {
                        Text("策略组").font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                    } else {
                        ProtocolBadge(type: t)
                    }
                }
                if udp {
                    Text("UDP").font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                }
                Spacer()
                Text(Theme.delayText(delay))
                    .font(.system(size: 11, weight: .semibold).monospacedDigit())
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
