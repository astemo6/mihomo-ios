import SwiftUI

// MARK: - 规则 (Loon-style, 2026-10-22)
//
// User: 「不要体现配置里的规则集，参考 Loon」「按订阅与本地的分开」「命中统计放下一级里」.
// Top: Final (the profile's MATCH policy) and 本地规则 (→ LocalRulesView: the profile's own rules, local custom
// rules and the hit statistics). Below: 订阅 — every remote rule list in one place, the profile's rule-providers
// and the lists the user added (custom RULE-SET / DOMAIN-SET / filter_remote). + adds a 订阅.
//
// 2026-10-23 (「这个规则要能手动调顺序」「三个路径…逻辑要保持一致」): rows are SubscriptionKit rows (switch on the
// right, the same swipes and menu as 重写 / 任务). fix/app-policy-ui #3 (2026-10-26): ⋯ → 编辑排序 opens the same
// reorder list as 策略 → 编辑排序 (RuleSetReorderList); the order is the matching priority — the profile's rule sets
// via provider-overrides.json `#rule-order` (NCRuntimeSteps.applyRuleSetOrder on every runtime build), the user's
// own lists via rules.json order.

struct RulesView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var custom = CustomRulesStore.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @ObservedObject private var res = ResourceStore.shared
    @ObservedObject private var providerOV = ProviderOverrideStore.shared
    @ObservedObject private var profiles = ProfileStore.shared
    @ObservedObject private var profileRules = ProfileRulesStore.shared
    @State private var editingFinal = false
    @State private var editingSet: SetRule?
    @State private var confirmDeleteSet: SetRule?
    @State private var confirmDeleteCustom: CustomRule?
    @State private var detail: InspectProvider?
    @State private var live: [RuleItem] = []
    @State private var liveProviders: [String: ProviderItem] = [:]
    @State private var search = ""
    @State private var adding = false
    @State private var editing: CustomRule?
    @State private var updatingLive: Set<String> = []
    @State private var liveErrors: [String: String] = [:]
    @State private var updatingAll = false
    /// fix/app-policy-ui #3: ⋯ → 编辑排序 swaps the page for RuleSetReorderList (as 策略 → 编辑排序), 取消 / 完成.
    @State private var ordering = false
    @State private var orderMine: [RuleOrderRow] = []
    @State private var orderSets: [RuleOrderRow] = []
    @State private var orderMineOriginal: [String] = []
    @State private var orderSetsOriginal: [String] = []
    @State private var orderSaving = false
    @State private var orderMessage: String?

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

    /// The Final the user chose (`#final`), when it differs from the profile's.
    var finalEdited: Bool {
        guard let p = providerOV.finalPolicy(profiles.activeID) else { return false }
        return p != profileRules.finalInfo.original
    }

    func saveFinal(_ policy: String?) {
        guard let id = profiles.activeID else { return }
        providerOV.setFinalPolicy(id, policy == profileRules.finalInfo.original ? nil : policy)
        Task { await applySetChange() }
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

    /// The profile's rule sets in matching order, minus the ones that came from the user's own 订阅 (shown with
    /// those). The saved order is applied here too, so a drag shows at once (the runtime follows after the reload).
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
        for (k, o) in setOverrides.sorted(by: { $0.key < $1.key }) where o.disabled == true && o.deleted != true {
            let name = String(k.dropFirst(5))
            if seen.insert(name).inserted { out.append(SetRule(name: name, policy: o.policy ?? o.shownPolicy ?? "")) }
        }
        return ManualOrder.apply(out, order: savedOrder) { $0.name }
    }

    /// The `rule:<name>` overrides of the active profile (停用 / 删除 / 编辑 of its rule sets).
    var setOverrides: [String: ProviderOverride] {
        providerOV.overrides(profiles.activeID).filter { $0.key.hasPrefix("rule:") }
    }

    /// The rule-set order the user arranged (provider-overrides.json, applied by the bridge).
    var savedOrder: [String] {
        providerOV.overrides(profiles.activeID)[ProviderOverride.ruleOrderKey]?.order ?? []
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

    /// 编辑排序: the 订阅 as they are listed now (no search filter).
    func enterOrder() {
        guard profiles.activeID != nil || !custom.remoteRules.isEmpty else { return }
        orderMine = custom.remoteRules.map { r in
            let url = CustomRulesStore.remoteURL(r.line) ?? r.line
            let name = offline.result.ruleProviders.first { $0.url == url }?.name ?? Self.displayName(url)
            return RuleOrderRow(id: r.id, name: name, policy: RuleFormFields.parse(r.line)?.policy ?? "", disabled: !r.enabled)
        }
        orderSets = profileSets.map { RuleOrderRow(id: $0.name, name: $0.name, policy: $0.policy, disabled: setOverride($0.name).disabled == true) }
        orderMineOriginal = orderMine.map(\.id)
        orderSetsOriginal = orderSets.map(\.id)
        orderMessage = nil
        search = ""
        withAnimation { ordering = true }
    }

    /// 完成: the rule-set order goes to `#rule-order` (applied to the runtime's rules on every build), the user's
    /// lists to rules.json; one core reload.
    func finishOrder() async {
        let sets = RuleSetOrderPlan.setOrder(orderSets, original: orderSetsOriginal)
        let mine = RuleSetOrderPlan.mineOrder(orderMine, original: orderMineOriginal)
        guard sets != nil || mine != nil else { withAnimation { ordering = false }; return }
        orderSaving = true
        defer { orderSaving = false }
        if let sets, let id = profiles.activeID {
            providerOV.update(id, ProviderOverride.ruleOrderKey) { $0.order = sets }
        }
        var err: String?
        if let mine {
            err = await custom.setRemoteOrder(mine) // saves + reloads (the rule-set order rides along)
            await load()
        } else {
            if vpn.isConnected, let e = await VPNManager.shared.reload(hot: true) { err = e }
            await load()
        }
        UINotificationFeedbackGenerator().notificationOccurred(err == nil ? .success : .error)
        if let err { custom.message = err }
        withAnimation { ordering = false }
    }

    func applySetChange() async {
        if vpn.isConnected, let e = await VPNManager.shared.reload(hot: true) { custom.message = e }
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
        return Group {
          if ordering {
            RuleSetReorderList(mine: $orderMine, sets: $orderSets, message: orderMessage)
          } else {
            mainList(sets: sets, mine: mine)
          }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("分流规则")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索")
        .navigationBarBackButtonHidden(ordering)
        .onChange(of: search) { q in if !q.isEmpty && ordering { withAnimation { ordering = false } } }
        .toolbar {
            if ordering {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { withAnimation { ordering = false } }
                        .accessibilityIdentifier("rules.orderCancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    if orderSaving {
                        ProgressView()
                    } else {
                        Button("完成") { Task { await finishOrder() } }
                            .fontWeight(.semibold)
                            .accessibilityIdentifier("rules.orderDone")
                    }
                }
            } else {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    UpdateAllButton(busy: updatingAll || updater.running || !updatingLive.isEmpty, id: "rules.updateAll") {
                        Task { await updateAll() }
                    }
                    Menu {
                        Button { enterOrder() } label: { Label("编辑排序", systemImage: "line.3.horizontal") }
                            .accessibilityIdentifier("rules.reorder")
                    } label: { Image(systemName: "ellipsis.circle") }
                        .accessibilityIdentifier("rules.more")
                    Button { adding = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel(Text("添加规则订阅"))
                        .accessibilityIdentifier("rules.addSet")
                }
            }
        }
        .navigationDestination(isPresented: Binding(get: { detail != nil }, set: { if !$0 { detail = nil } })) {
            if let p = detail { OfflineProviderDetail(p: p) }
        }
        .task(id: vpn.isConnected) { await load() }
        .sheet(isPresented: $adding) {
            CustomRuleEditor(rule: CustomRule(line: "RULE-SET,,")) { r in custom.rules.insert(r, at: 0); custom.save() }
        }
        .sheet(isPresented: $editingFinal) {
            PolicyPickerSheet(title: Text(verbatim: "Final"), current: finalPolicy ?? profileRules.finalInfo.policy,
                              original: profileRules.finalInfo.original,
                              footer: "修改保存在 Tern 里，配置文件不会改动；更新配置后仍然有效。") { saveFinal($0) }
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
        .deleteConfirmation({ _ in Text("删除这个规则集？") }, item: $confirmDeleteSet,
                            message: { _ in Text("只从当前配置里移除：它和用到它的规则不再加载，配置文件不会改动。可以在列表底部「恢复已删除的规则集」找回。") },
                            id: "rules.confirmDeleteSet") { s in
            changeSet(s) { $0.deleted = true }
        }
        .deleteConfirmation({ r in Text("删除「\(Self.displayName(CustomRulesStore.remoteURL(r.line) ?? r.line))」？") }, item: $confirmDeleteCustom,
                            message: { _ in DeleteText.recoverable }, id: "rules.confirmDeleteSub") { r in
            custom.rules.removeAll { $0.id == r.id }
            custom.save()
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

    @ViewBuilder
    func mainList(sets: [SetRule], mine: [CustomRule]) -> some View {
        List {
            Section {
                // User 2026-10-23 「Final 指向无法修改」: tap → policy picker; kept as an override (`#final`).
                Button { editingFinal = true } label: {
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(verbatim: "Final").font(.headline).foregroundStyle(.primary)
                            HStack(spacing: 6) {
                                Text("兜底").font(.caption2.weight(.semibold))
                                    .padding(.horizontal, 6).padding(.vertical, 1)
                                    .background(Capsule().fill(Theme.warn.opacity(0.18)))
                                    .foregroundStyle(Theme.warn)
                                if finalEdited { ModifiedTag() }
                            }
                        }
                        Spacer()
                        if let f = finalPolicy, !f.isEmpty { PolicyChip(name: f) }
                        Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(profiles.activeID == nil)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.isButton)
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
                ForEach(sets) { s in profileRow(s) }
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
                VStack(alignment: .leading, spacing: 4) {
                    Text("顺序就是匹配优先级：越靠上越先匹配。在 ⋯ 里选「编辑排序」调整顺序。")
                    Text("轻点查看内容；右滑更新，左滑删除或编辑；开关启用或关闭；长按查看全部操作。")
                }
                .modifier(UITestOrderValue(id: "rules.sets.order", order: sets.map(\.name).joined(separator: " | ")))
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .refreshable { await load() }
    }

    // MARK: rows (SubscriptionKit: the same row and actions as 重写 → 订阅 and 任务)

    /// A 订阅 the user added (rules.json): 删除 removes it.
    @ViewBuilder
    func customRow(_ r: CustomRule) -> some View {
        let url = CustomRulesStore.remoteURL(r.line) ?? r.line
        let provider = offline.result.ruleProviders.first { $0.url == url }
        let item = res.items.first { $0.kind == "ruleset" && $0.url == url }
        let check = custom.checks[r.id]
        let name = provider?.name ?? Self.displayName(url)
        let lp = provider.flatMap { liveProviders[$0.name] }
        let busy = (provider.map { updatingLive.contains($0.name) || updater.busy.contains($0.id) } ?? false)
            || (item.map { res.busy.contains($0.key) } ?? false)
        SubscriptionRow(id: "rules.sub." + name, icon: "list.bullet.rectangle", color: Theme.accent, name: name,
                        status: SubscriptionStatus(source: "", remote: true,
                                                   updated: Self.liveDate(lp) ?? provider?.cachedDate ?? item.flatMap { $0.updatedAt > 0 ? Date(timeIntervalSince1970: $0.updatedAt) : nil },
                                                   interval: r.interval ?? item?.interval ?? 0,
                                                   error: check?.error ?? provider.flatMap { updater.errors[$0.id] } ?? item?.error,
                                                   disabled: !r.enabled,
                                                   downloaded: provider?.cached),
                        details: [url],
                        count: r.enabled ? (lp?.ruleCount ?? provider.flatMap { $0.count >= 0 ? $0.count : nil }) : nil,
                        updating: busy,
                        enabled: Binding(get: { r.enabled }, set: { on in setCustom(r, on) }),
                        onTap: { editing = r }) {
            if let p = check?.policy ?? RuleFormFields.parse(r.line)?.policy, !p.isEmpty { PolicyChip(name: p) }
        }
        .subscriptionActions(SubscriptionActions(
            update: r.enabled && !busy ? { Task { await updateCustom(url, provider: provider?.name) } } : nil,
            edit: { editing = r }, url: url,
            enabled: r.enabled, setEnabled: { on in setCustom(r, on) },
            delete: { confirmDeleteCustom = r }))
    }

    func setCustom(_ r: CustomRule, _ on: Bool) {
        guard let i = custom.rules.firstIndex(where: { $0.id == r.id }), custom.rules[i].enabled != on else { return }
        custom.rules[i].enabled = on
        custom.save()
    }

    /// A rule set of the profile: 删除 / 关闭 / 编辑 are overrides (provider-overrides.json), the profile file is not touched.
    @ViewBuilder
    func profileRow(_ s: SetRule) -> some View {
        let p = providersByName[s.name]
        let lp = liveProviders[s.name]
        let ov = setOverride(s.name)
        let off = ov.disabled == true
        let url = ov.url ?? p?.url ?? ov.shownURL ?? ""
        let remote = p.map { $0.vehicle.lowercased() == "http" } ?? !url.isEmpty
        let busy = updatingLive.contains(s.name) || (p.map { updater.busy.contains($0.id) } ?? false)
        SubscriptionRow(id: "rules.set." + s.name, icon: "list.bullet.rectangle", color: Theme.accent, name: s.name,
                        status: SubscriptionStatus(source: "", remote: remote, updated: Self.liveDate(lp) ?? p?.cachedDate,
                                                   interval: p?.interval ?? 0,
                                                   error: liveErrors[s.name] ?? p.flatMap { updater.errors[$0.id] },
                                                   disabled: off, downloaded: p?.cached),
                        details: url.isEmpty ? [] : [url],
                        count: off ? nil : (lp?.ruleCount ?? p.flatMap { $0.count >= 0 ? $0.count : nil }),
                        updating: busy,
                        enabled: Binding(get: { !off }, set: { on in changeSet(s) { $0.disabled = on ? nil : true } }),
                        onTap: { if let p { detail = p } else { editingSet = s } }) {
            if !s.policy.isEmpty { PolicyChip(name: s.policy) }
        }
        .subscriptionActions(SubscriptionActions(
            update: !off && remote && !busy ? { Task { await update(s.name) } } : nil,
            edit: { editingSet = s }, url: url.isEmpty ? nil : url,
            enabled: !off, setEnabled: { on in changeSet(s) { $0.disabled = on ? nil : true } },
            delete: { confirmDeleteSet = s }))
    }

    static func liveDate(_ lp: ProviderItem?) -> Date? {
        lp?.updatedAt.flatMap { ConnectionItem.iso.date(from: $0) ?? ConnectionItem.isoNoFrac.date(from: $0) }
    }

    static func displayName(_ url: String) -> String {
        guard let u = URL(string: url) else { return url }
        let last = u.deletingPathExtension().lastPathComponent
        return last.isEmpty || last == "/" ? (u.host ?? url) : last
    }

    // MARK: data

    func load() async {
        await offline.load()
        await profileRules.load()
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
        if let it = res.items.first(where: { $0.kind == "ruleset" && $0.url == url }) { await res.update(it); res.message = nil }
        if let provider { await update(provider) } else { await load() }
    }

    func updateAll() async {
        guard !updatingAll else { return }
        updatingAll = true
        defer { updatingAll = false }
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
