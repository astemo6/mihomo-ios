import SwiftUI
import NetworkExtension

@MainActor
final class PolicyModel: ObservableObject {
    @Published var groups: [ProxyItem] = []
    @Published var all: [String: ProxyItem] = [:]
    @Published var testing: Set<String> = []
    @Published var error: String?

    func load() async {
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

struct PolicyView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = PolicyModel()
    @State private var expanded: Set<String> = []

    var body: some View {
        NavigationStack {
            Group {
                if !vpn.isConnected {
                    NotConnectedPlaceholder(text: "连接后可查看和切换策略组")
                } else {
                    ScrollView {
                        LazyVStack(spacing: 12) {
                            if let e = model.error { Text(e).font(.footnote).foregroundStyle(Theme.bad) }
                            ForEach(model.groups) { g in
                                GroupCard(group: g, model: model, expanded: Binding(
                                    get: { expanded.contains(g.name) },
                                    set: { v in if v { expanded.insert(g.name) } else { expanded.remove(g.name) } }
                                ))
                            }
                        }
                        .padding(16)
                    }
                    .refreshable { await model.load() }
                }
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("策略")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { for g in model.groups where g.name != "GLOBAL" { await model.test(g) } }
                    } label: { Image(systemName: "bolt.fill") }
                    .disabled(!vpn.isConnected)
                }
            }
        }
        .task(id: vpn.isConnected) { if vpn.isConnected { await model.load() } }
    }
}

struct GroupCard: View {
    let group: ProxyItem
    @ObservedObject var model: PolicyModel
    @Binding var expanded: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.headline)
                    .foregroundStyle(Theme.accent)
                    .frame(width: 34, height: 34)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.accent.opacity(0.15)))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(group.name).font(.headline).lineLimit(1)
                        Text(group.typeLabel)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Capsule().fill(Color.white.opacity(0.1)))
                    }
                    HStack(spacing: 6) {
                        Text(group.now ?? "—").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        if let n = group.now {
                            Text(Theme.delayText(model.delay(of: n)))
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(Theme.delayColor(model.delay(of: n)))
                        }
                    }
                }
                Spacer()
                Button {
                    Task { await model.test(group) }
                } label: {
                    if model.testing.contains(group.name) {
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
                if !group.isSelectable {
                    Text(statusHint).font(.caption2).foregroundStyle(.secondary)
                }
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                    ForEach(group.all ?? [], id: \.self) { name in
                        NodeCell(name: name,
                                 node: model.all[name],
                                 selected: group.now == name,
                                 enabled: group.isSelectable)
                        .onTapGesture { Task { await model.select(group, name) } }
                    }
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.white.opacity(0.06)))
    }

    var icon: String {
        switch group.type {
        case "Selector": return "hand.tap.fill"
        case "URLTest": return "bolt.badge.clock.fill"
        case "Fallback": return "arrow.triangle.branch"
        case "LoadBalance": return "scalemass.fill"
        case "Relay": return "link"
        default: return "globe"
        }
    }

    var statusHint: String {
        switch group.type {
        case "URLTest": return "自动选择延迟最低的节点（当前：\(group.now ?? "—")）"
        case "Fallback": return "按顺序使用第一个可用节点（当前：\(group.now ?? "—")）"
        case "LoadBalance": return "在节点间分配连接"
        default: return "该策略组不可手动选择"
        }
    }
}

struct NodeCell: View {
    let name: String
    let node: ProxyItem?
    let selected: Bool
    let enabled: Bool

    var body: some View {
        let d = node?.lastDelay
        VStack(alignment: .leading, spacing: 6) {
            Text(name)
                .font(.footnote.weight(selected ? .semibold : .regular))
                .lineLimit(2)
                .frame(maxWidth: .infinity, minHeight: 34, alignment: .topLeading)
            HStack {
                if let t = node?.type { ProtocolBadge(type: t) }
                if node?.udp == true {
                    Text("UDP").font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                }
                Spacer()
                Text(Theme.delayText(d))
                    .font(.system(size: 11, weight: .semibold).monospacedDigit())
                    .foregroundStyle(Theme.delayColor(d))
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
