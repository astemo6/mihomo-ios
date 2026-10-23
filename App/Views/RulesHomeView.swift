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
    @ObservedObject private var providerOV = ProviderOverrideStore.shared
    @ObservedObject private var profiles = ProfileStore.shared
    @State private var editingSet: SetRule?
    @State private var confirmDeleteSet: SetRule?
    @State private var live: [RuleItem] = []
    @State private var liveProviders: [String: ProviderItem] = [:]
    @State private var search = ""
    @State private var adding = false
    @State private var editing: CustomRule?
    @State private var updatingLive: Set<String> = []
    @State private var liveErrors: [String: String] = [:]

    /// One RULE-SET rule of the running / saved profile.
    struct SetRule: Hashable, Identifiable { var name: String; var policy: String; var id: String { name } }

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
        for r in ruleTriples where LocalRulesView.isRuleSet(r.type) && !r.proxy.hasPrefix("__") && !r.payload.hasPrefix("__") {
            if let u = byName[r.payload]?.url, mine.contains(u) { continue }
            if seen.insert(r.payload).inserted { out.append(SetRule(name: r.payload, policy: r.proxy)) }
        }
        // 停用 rule sets are not in the runtime any more; keep them listed (dimmed) so they can be turned on again.
        for (k, o) in setOverrides where o.disabled == true && o.deleted != true {
            let name = String(k.dropFirst(5))
            if seen.insert(name).inserted { out.append(SetRule(name: name, policy: o.policy ?? o.shownPolicy ?? "")) }
        }
        return out
    }

    /// The `rule:<name>` overrides of the active profile (停用 / 删除 / 编辑 of its rule sets).
    var setOverrides: [String: ProviderOverride] {
        providerOV.overrides(profiles.activeID).filter { $0.key.hasPrefix("rule:") }
    }

    func setOverride(_ name: String) -> ProviderOverride { setOverrides[ProviderOverride.ruleKey(name)] ?? ProviderOverride() }

    var deletedSetCount: Int { setOverrides.values.filter { $0.deleted == true }.count }

    func changeSet(_ s: SetRule, _ change: @escaping (inout ProviderOverride) -> Void) {
        guard let id = profiles.activeID else { return }
        let url = providersByName[s.name]?.url
        providerOV.update(id, ProviderOverride.ruleKey(s.name)) { o in
            if o.shownPolicy == nil, !s.policy.isEmpty { o.shownPolicy = s.policy }
            if o.shownURL == nil, let url, !url.isEmpty { o.shownURL = url }
            change(&o)
        }
        Task { await applySetChange() }
    }

    func applySetChange() async {
        if vpn.isConnected, let e = await VPNManager.shared.reload() { custom.message = e }
        await load()
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
                if deletedSetCount > 0, let id = profiles.activeID {
                    Button {
                        providerOV.restoreDeleted(id, ruleSets: true)
                        Task { await applySetChange() }
                    } label: {
                        Label("恢复已删除的规则集（\(deletedSetCount)）", systemImage: "arrow.uturn.backward")
                    }
                    .accessibilityIdentifier("rules.restoreDeletedSets")
                }
            } header: {
                Text("订阅 \(mine.count + sets.count)")
            } footer: {
                Text("轻点查看内容；右滑更新或编辑，左滑删除；圆圈启用或停用；长按查看全部操作。")
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
        .sheet(item: $editingSet) { s in
            RuleSetOverrideEditor(name: s.name,
                                  url: setOverride(s.name).url ?? providersByName[s.name]?.url ?? setOverride(s.name).shownURL ?? "",
                                  policy: s.policy) { url, policy in
                changeSet(s) { o in
                    let original = providersByName[s.name]?.url ?? o.shownURL ?? ""
                    o.url = url.isEmpty || url == original ? nil : url
                    o.policy = policy.isEmpty || policy == (o.shownPolicy ?? s.policy) ? nil : policy
                }
            }
            .environmentObject(vpn)
        }
        .alert("删除这个规则集？", isPresented: Binding(get: { confirmDeleteSet != nil }, set: { if !$0 { confirmDeleteSet = nil } })) {
            Button("删除", role: .destructive) {
                if let s = confirmDeleteSet { changeSet(s) { $0.deleted = true } }
                confirmDeleteSet = nil
            }
            Button("取消", role: .cancel) { confirmDeleteSet = nil }
        } message: {
            Text("只从当前配置里移除：它和用到它的规则不再加载，配置文件不会改动。可以在列表底部「恢复已删除的规则集」找回。")
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
        .contextMenu {
            Button { Task { await updateCustom(url, provider: provider?.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
            Button { UIPasteboard.general.string = url } label: { Label("复制链接", systemImage: "doc.on.doc") }
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            Button { Task { await updateCustom(url, provider: provider?.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                .tint(Theme.good)
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
        let ov = setOverride(s.name)
        let off = ov.disabled == true
        let card = SubscriptionCard(
            name: s.name,
            url: p?.url ?? ov.url ?? ov.shownURL ?? "",
            policy: s.policy,
            updated: liveDate ?? p?.cachedDate,
            count: off ? nil : (lp?.ruleCount ?? p.flatMap { $0.count >= 0 ? $0.count : nil }),
            error: liveErrors[s.name] ?? p.flatMap { updater.errors[$0.id] },
            enabled: !off,
            busy: updatingLive.contains(s.name) || (p.map { updater.busy.contains($0.id) } ?? false),
            onToggle: { on in changeSet(s) { $0.disabled = on ? nil : true } }
        )
        Group {
            if let p {
                NavigationLink { OfflineProviderDetail(p: p) } label: { card }
            } else {
                card
            }
        }
        .swipeActions(edge: .leading) {
            if !off {
                Button { Task { await update(s.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                    .tint(Theme.accent)
            }
            Button { editingSet = s } label: { Label("编辑", systemImage: "pencil") }
                .tint(.indigo)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) { confirmDeleteSet = s } label: { Label("删除", systemImage: "trash") }
        }
        .contextMenu {
            if !off {
                Button { Task { await update(s.name) } } label: { Label("更新", systemImage: "arrow.clockwise") }
            }
            Button { editingSet = s } label: { Label("编辑", systemImage: "pencil") }
            Button { changeSet(s) { $0.disabled = off ? nil : true } } label: {
                Label(LocalizedStringKey(off ? "启用" : "停用"), systemImage: off ? "play.circle" : "pause.circle")
            }
            if let u = p?.url ?? ov.shownURL, !u.isEmpty {
                Button { UIPasteboard.general.string = u } label: { Label("复制链接", systemImage: "doc.on.doc") }
            }
            Button(role: .destructive) { confirmDeleteSet = s } label: { Label("删除", systemImage: "trash") }
        }
        .accessibilityIdentifier("rules.set.\(s.name)")
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

    /// A 订阅 the user added (user 2026-10-23: rule sets update here, not in 更多 → 更新资源): the app's own copy
    /// (ResourceStore) first, then the core's provider when connected.
    func updateCustom(_ url: String, provider: String?) async {
        let res = ResourceStore.shared
        if let it = res.items.first(where: { $0.kind == "ruleset" && $0.url == url }) { await res.update(it); res.message = nil }
        if let provider { await update(provider) } else { await load() }
    }

    func updateAll() async {
        let res = ResourceStore.shared
        for it in res.items where it.kind == "ruleset" && it.isRemote && it.enabled { await res.update(it) }
        res.message = nil
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


/// 编辑 a rule set of the profile (user 2026-10-23): its link and the policy of its RULE-SET rules, kept in the
/// override store — the profile file is not rewritten.
struct RuleSetOverrideEditor: View {
    let name: String
    @State var url: String
    @State var policy: String
    let onSave: (String, String) -> Void
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @State private var policies: [String] = []

    init(name: String, url: String, policy: String, onSave: @escaping (String, String) -> Void) {
        self.name = name
        _url = State(initialValue: url)
        _policy = State(initialValue: policy)
        self.onSave = onSave
    }

    var choices: [String] {
        var out = policies + ["DIRECT", "REJECT", "REJECT-DROP"]
        if !policy.isEmpty && !out.contains(policy) { out.insert(policy, at: 0) }
        return out
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(verbatim: name).foregroundStyle(.secondary)
                } header: { Text("名称") }
                Section {
                    TextField("https://example.com/rules.yaml", text: $url, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                } header: { Text("链接") }
                Section {
                    Picker("策略", selection: $policy) {
                        ForEach(choices, id: \.self) { Text(verbatim: $0).tag($0) }
                    }
                } footer: {
                    Text("修改保存在 Tern 里，配置文件不会改动；更新配置后仍然有效。")
                }
            }
            .navigationTitle("编辑规则集")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        onSave(url.trimmingCharacters(in: .whitespacesAndNewlines), policy)
                        dismiss()
                    }
                }
            }
            .task {
                var names: [String] = []
                if vpn.isConnected, let p = try? await ControllerClient.shared.proxies() {
                    names = LiveGroupOrder.names(p).filter { p[$0]?.isGroup == true && p[$0]?.hidden != true && $0 != "GLOBAL" }
                }
                if names.isEmpty {
                    names = ProfileInspector.shared.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name)
                }
                policies = names
            }
        }
    }
}
