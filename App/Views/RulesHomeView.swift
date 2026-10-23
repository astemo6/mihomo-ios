import SwiftUI

// MARK: - 规则 (Loon-style, 2026-10-22)
//
// User: 「不要体现配置里的规则集，参考 Loon」「按订阅与本地的分开」「命中统计放下一级里」.
// Top: Final (the profile's MATCH policy) and 本地规则 (→ LocalRulesView: the profile's own rules, local custom
// rules and the hit statistics). Below: 订阅 — every remote rule list in one place, the profile's rule-providers
// and the lists the user added (custom RULE-SET / DOMAIN-SET / filter_remote). + adds a 订阅.

struct RulesView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var custom = CustomRulesStore.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @State private var live: [RuleItem] = []
    @State private var liveProviders: [String: ProviderItem] = [:]
    @State private var search = ""
    @State private var adding = false
    @State private var editing: CustomRule?
    @State private var updatingLive: Set<String> = []
    @State private var liveErrors: [String: String] = [:]

    /// One RULE-SET rule of the running / saved profile.
    struct SetRule: Hashable { var name: String; var policy: String }

    var ruleTriples: [(type: String, payload: String, proxy: String)] {
        vpn.isConnected
            ? live.map { ($0.type, $0.payload, $0.proxy) }
            : offline.result.rules.map { ($0.type, $0.payload, $0.proxy) }
    }

    var finalPolicy: String? {
        ruleTriples.last { ["MATCH", "FINAL"].contains($0.type.uppercased()) }?.proxy
    }

    var localCount: Int {
        // The rule list already contains the applied custom rules (review 0.19.18 N1: they were counted twice).
        ruleTriples.filter { LocalRulesView.isLocal(type: $0.type, payload: $0.payload, proxy: $0.proxy) }.count
    }

    var providersByName: [String: InspectProvider] {
        var m: [String: InspectProvider] = [:]
        for p in offline.result.ruleProviders { m[p.name] = p }
        return m
    }

    /// The profile's rule sets in rule order, minus the ones that came from the user's own 订阅 (shown with those).
    var profileSets: [SetRule] {
        let mine = Set(custom.remoteRules.compactMap { CustomRulesStore.remoteURL($0.line) })
        let byName = providersByName
        var seen = Set<String>()
        var out: [SetRule] = []
        for r in ruleTriples where r.type.uppercased() == "RULE-SET" && !r.proxy.hasPrefix("__") && !r.payload.hasPrefix("__") {
            if let u = byName[r.payload]?.url, mine.contains(u) { continue }
            if seen.insert(r.payload).inserted { out.append(SetRule(name: r.payload, policy: r.proxy)) }
        }
        return out
    }

    func matches(_ parts: String...) -> Bool {
        if search.isEmpty { return true }
        let q = search.lowercased()
        return parts.contains { $0.lowercased().contains(q) }
    }

    var body: some View {
        let sets = profileSets.filter { matches($0.name, $0.policy, providersByName[$0.name]?.url ?? "") }
        let mine = custom.remoteRules.filter { matches($0.line) }
        return List {
            Section {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(verbatim: "Final").font(.headline)
                        Text("兜底").font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Capsule().fill(Theme.warn.opacity(0.18)))
                            .foregroundStyle(Theme.warn)
                    }
                    Spacer()
                    if let f = finalPolicy, !f.isEmpty { PolicyChip(name: f) }
                }
                .padding(.vertical, 4)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("rules.final")
                NavigationLink { LocalRulesView() } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("本地规则").font(.headline)
                        Text(verbatim: "\(localCount)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
                .accessibilityIdentifier("rules.local")
            } footer: {
                Text("兜底规则会在其他规则都没有匹配时使用。命中统计在「本地规则」里。")
            }
            .listRowBackground(Theme.card)

            Section {
                if mine.isEmpty && sets.isEmpty {
                    Text(search.isEmpty ? "还没有规则订阅。点右上角 + 添加远程规则列表（Surge / QX / Loon / Clash 格式）。" : "没有匹配的订阅")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(mine) { r in customRow(r) }
                ForEach(sets, id: \.self) { s in profileRow(s) }
            } header: {
                Text("订阅 \(mine.count + sets.count)")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("规则")
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if updater.running || !updatingLive.isEmpty {
                    ProgressView()
                } else {
                    Button { Task { await updateAll() } } label: { Image(systemName: "arrow.triangle.2.circlepath") }
                        .accessibilityLabel(Text("全部更新"))
                        .accessibilityIdentifier("rules.updateAll")
                }
            }
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { adding = true } label: { Image(systemName: "plus.circle") }
                    .accessibilityLabel(Text("添加规则订阅"))
                    .accessibilityIdentifier("rules.addSet")
            }
        }
        .task(id: vpn.isConnected) { await load() }
        .refreshable { await load() }
        .sheet(isPresented: $adding) {
            CustomRuleEditor(rule: CustomRule(line: "RULE-SET,,")) { r in custom.rules.insert(r, at: 0); custom.save() }
        }
        .sheet(item: $editing) { r in
            CustomRuleEditor(rule: r) { nr in
                if let i = custom.rules.firstIndex(where: { $0.id == nr.id }) { custom.rules[i] = nr; custom.save() }
            }
        }
        .alert("提示", isPresented: Binding(get: { custom.message != nil }, set: { if !$0 { custom.message = nil } })) {
            Button("好") { custom.message = nil }
        } message: { Text(custom.message ?? "") }
    }

    // MARK: rows

    /// A 订阅 the user added: tap to edit, check to enable, swipe to delete or move.
    @ViewBuilder
    func customRow(_ r: CustomRule) -> some View {
        let url = CustomRulesStore.remoteURL(r.line) ?? r.line
        let provider = offline.result.ruleProviders.first { $0.url == url }
        let check = custom.checks[r.id]
        SubscriptionCard(
            name: provider?.name ?? Self.displayName(url),
            url: url,
            policy: check?.policy ?? RuleFormFields.parse(r.line)?.policy,
            updated: provider?.cachedDate,
            count: provider.flatMap { $0.count >= 0 ? $0.count : nil },
            error: check?.error ?? provider.flatMap { updater.errors[$0.id] },
            enabled: r.enabled,
            onToggle: { on in
                if let i = custom.rules.firstIndex(where: { $0.id == r.id }) { custom.rules[i].enabled = on; custom.save() }
            }
        )
        .contentShape(Rectangle())
        .onTapGesture { editing = r }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) { custom.rules.removeAll { $0.id == r.id }; custom.save() } label: { Label("删除", systemImage: "trash") }
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            let subset = custom.remoteRules
            if custom.canStepSubset(subset, r.id, by: 1) {
                Button { withAnimation { custom.stepSubset(subset, r.id, by: 1) } } label: { Label("下移", systemImage: "arrow.down") }
                    .tint(Theme.accent.opacity(0.75))
            }
            if custom.canStepSubset(subset, r.id, by: -1) {
                Button { withAnimation { custom.stepSubset(subset, r.id, by: -1) } } label: { Label("上移", systemImage: "arrow.up") }
                    .tint(Theme.accent)
            }
        }
    }

    /// A rule set that comes with the profile: tap for its contents, swipe to update now.
    @ViewBuilder
    func profileRow(_ s: SetRule) -> some View {
        let p = providersByName[s.name]
        let lp = liveProviders[s.name]
        let liveDate = lp?.updatedAt.flatMap { ConnectionItem.iso.date(from: $0) ?? ConnectionItem.isoNoFrac.date(from: $0) }
        let card = SubscriptionCard(
            name: s.name,
            url: p?.url ?? "",
            policy: s.policy,
            updated: liveDate ?? p?.cachedDate,
            count: lp?.ruleCount ?? p.flatMap { $0.count >= 0 ? $0.count : nil },
            error: liveErrors[s.name] ?? p.flatMap { updater.errors[$0.id] },
            enabled: nil,
            busy: updatingLive.contains(s.name) || (p.map { updater.busy.contains($0.id) } ?? false),
            onToggle: nil
        )
        Group {
            if let p {
                NavigationLink { OfflineProviderDetail(p: p) } label: { card }
            } else {
                card
            }
        }
        .swipeActions(edge: .leading) {
            Button { Task { await update(s.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                .tint(Theme.accent)
        }
        .contextMenu {
            Button { Task { await update(s.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
            if let u = p?.url, !u.isEmpty {
                Button { UIPasteboard.general.string = u } label: { Label("复制链接", systemImage: "doc.on.doc") }
            }
        }
    }

    static func displayName(_ url: String) -> String {
        guard let u = URL(string: url) else { return url }
        let last = u.deletingPathExtension().lastPathComponent
        return last.isEmpty || last == "/" ? (u.host ?? url) : last
    }

    // MARK: data

    func load() async {
        await offline.load()
        if vpn.isConnected {
            if let r = try? await ControllerClient.shared.rules() { live = r }
            if let ps = try? await ControllerClient.shared.ruleProviders() {
                var m: [String: ProviderItem] = [:]
                for p in ps { m[p.name] = p }
                liveProviders = m
            }
        }
        await custom.recheck()
    }

    func update(_ name: String) async {
        if vpn.isConnected {
            updatingLive.insert(name)
            do { try await ControllerClient.shared.updateRuleProvider(name); liveErrors[name] = nil }
            catch { liveErrors[name] = error.localizedDescription }
            updatingLive.remove(name)
            await load()
        } else if let p = providersByName[name], p.vehicle == "http" {
            await updater.update(p.id)
            await offline.load()
        }
    }

    func updateAll() async {
        if vpn.isConnected {
            for p in liveProviders.values where p.vehicleType == "HTTP" { await update(p.name) }
        } else {
            _ = await updater.updateAll(only: Set(offline.result.ruleProviders.map(\.id)))
            await offline.load()
        }
    }
}

/// Loon-style 订阅 card: check (when it can be turned off), name + last update, URL, policy, error.
struct SubscriptionCard: View {
    let name: String
    let url: String
    let policy: String?
    let updated: Date?
    let count: Int?
    let error: String?
    let enabled: Bool?
    var busy: Bool = false
    let onToggle: ((Bool) -> Void)?

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            if let enabled, let onToggle {
                Button { onToggle(!enabled) } label: {
                    Image(systemName: enabled ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundStyle(enabled ? Theme.accent : Color.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text(enabled ? "已启用" : "已停用"))
            }
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(verbatim: name).font(.headline).lineLimit(1)
                    Spacer(minLength: 6)
                    if busy {
                        ProgressView().controlSize(.small)
                    } else if let updated {
                        Text(updated.formatted(.relative(presentation: .named))).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                if !url.isEmpty {
                    Text(verbatim: url).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                HStack(spacing: 6) {
                    if let policy, !policy.isEmpty { PolicyChip(name: policy) }
                    if let count { Text("\(count) 条").font(.caption2).foregroundStyle(.secondary) }
                }
                if let error, !error.isEmpty {
                    Text("更新失败：\(error)").font(.caption2).foregroundStyle(Theme.warn).lineLimit(2)
                }
            }
        }
        .padding(.vertical, 4)
        .opacity(enabled == false ? 0.55 : 1)
    }
}
