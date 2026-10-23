import SwiftUI
import Libmihomo

// 规则 (live from the controller, or offline from the profile), 自定义规则 (rules.json, Surge / QX /
// Loon / mihomo syntax with live validation) and 提供者 (live, or offline from the cache files).

// MARK: - Custom rules store

struct CustomRule: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var line: String
    var enabled: Bool = true
    var interval: Int? = nil
}

/// Result of LibmihomoCheckRuleLine / CheckCustomRules (bridge/customrules.go ruleCheck).
struct RuleCheck: Decodable, Hashable {
    var id: String?
    var line: String?
    var enabled: Bool?
    var rule: String?
    var policy: String?
    var error: String?
    var note: String?
    var unresolved: String?
}

@MainActor
final class CustomRulesStore: ObservableObject {
    static let shared = CustomRulesStore()

    @Published var rules: [CustomRule] = []
    @Published var checks: [String: RuleCheck] = [:]
    @Published var message: String?
    /// r7: bumped one main-queue turn after a reorder; the custom rules section is keyed on it so the List redraws from
    /// `rules` after UIKit's own row move (same staleness guard as 编辑首页面板).
    @Published private(set) var orderRevision = 0

    static var url: URL { AppShared.homeURL.appendingPathComponent("rules.json") }

    private struct File: Codable { var rules: [CustomRule] }

    init() { load() }

    func load() {
        if let d = try? Data(contentsOf: Self.url), let f = try? JSONDecoder().decode(File.self, from: d) {
            rules = f.rules
        }
    }

    func save() {
        Task { if let e = await saveAndReload() { message = e } }
    }

    /// r7: non-drag reorder (swipe / VoiceOver). `by` = -1 up, +1 down.
    func canStep(_ id: CustomRule.ID, by: Int) -> Bool {
        guard let i = rules.firstIndex(where: { $0.id == id }) else { return false }
        return rules.indices.contains(i + by)
    }

    func step(_ id: CustomRule.ID, by: Int) {
        guard let i = rules.firstIndex(where: { $0.id == id }), rules.indices.contains(i + by) else { return }
        rules.swapAt(i, i + by)
        save()
        orderChanged()
    }

    func move(from: IndexSet, to: Int) {
        rules.move(fromOffsets: from, toOffset: to)
        save()
        orderChanged()
    }

    /// The saved order (rule lines joined with " | "), for the Debug UI-test accessibility value.
    var orderToken: String { localRules.map(\.line).joined(separator: " | ") }

    // Loon-style 规则 (2026-10-22 「按订阅与本地的分开」): remote lists are 订阅 on the 规则 page, the rest are 本地规则.
    /// The list URL of a remote custom rule (RULE-SET / DOMAIN-SET / QX filter_remote / bare URL), nil for a local rule.
    nonisolated static func remoteURL(_ line: String) -> String? {
        for f in line.split(separator: ",").prefix(2) {
            let t = f.trimmingCharacters(in: .whitespaces)
            if t.lowercased().hasPrefix("http://") || t.lowercased().hasPrefix("https://") { return t }
        }
        return nil
    }
    var remoteRules: [CustomRule] { rules.filter { Self.remoteURL($0.line) != nil } }
    var localRules: [CustomRule] { rules.filter { Self.remoteURL($0.line) == nil } }

    /// Reorder inside one subset (本地 or 订阅): the subset's members keep the slots they occupy in `rules`.
    private func applySubsetOrder(_ newOrder: [CustomRule]) {
        let ids = Set(newOrder.map(\.id))
        var it = newOrder.makeIterator()
        rules = rules.map { ids.contains($0.id) ? (it.next() ?? $0) : $0 }
        save()
        orderChanged()
    }

    func moveSubset(_ subset: [CustomRule], from: IndexSet, to: Int) {
        var list = subset
        list.move(fromOffsets: from, toOffset: to)
        applySubsetOrder(list)
    }

    func canStepSubset(_ subset: [CustomRule], _ id: CustomRule.ID, by: Int) -> Bool {
        guard let i = subset.firstIndex(where: { $0.id == id }) else { return false }
        return subset.indices.contains(i + by)
    }

    func stepSubset(_ subset: [CustomRule], _ id: CustomRule.ID, by: Int) {
        guard let i = subset.firstIndex(where: { $0.id == id }), subset.indices.contains(i + by) else { return }
        var list = subset
        list.swapAt(i, i + by)
        applySubsetOrder(list)
    }

    private func orderChanged() {
        DispatchQueue.main.async { self.orderRevision &+= 1 }
    }

    /// r7 P3-1: the same write + recheck + reload, with the reload error returned to the caller instead of parked in
    /// `message` (only 分流规则 shows that; a rule added from Home's quick add surfaced there much later).
    func saveAndReload() async -> String? {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(File(rules: rules)) { try? d.write(to: Self.url, options: .atomic) }
        await recheck()
        if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload(hot: true) { return String(localized: "重载失败：\(e)") }
        return nil
    }

    func recheck() async {
        guard let path = AppShared.activeProfileURL?.path else { checks = [:]; return }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .utility) { LibmihomoCheckCustomRules(home, path) }.value
        let list = (try? JSONDecoder().decode([RuleCheck].self, from: Data(json.utf8))) ?? []
        var out: [String: RuleCheck] = [:]
        for c in list { if let id = c.id { out[id] = c } }
        checks = out
    }

    nonisolated static func check(line: String) async -> RuleCheck? {
        guard let path = AppShared.activeProfileURL?.path else { return nil }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoCheckRuleLine(home, path, line) }.value
        return try? JSONDecoder().decode(RuleCheck.self, from: Data(json.utf8))
    }
}

// MARK: - 本地规则 (the profile's own rules + local custom rules, with hit statistics)

struct LocalRulesView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var custom = CustomRulesStore.shared
    @ObservedObject private var prof = ProfileRulesStore.shared
    @ObservedObject private var providerOV = ProviderOverrideStore.shared
    @ObservedObject private var profiles = ProfileStore.shared
    @State private var live: [RuleItem] = []
    @State private var search = ""
    @State private var tab = 0
    @State private var editing: CustomRule?
    @State private var adding = false
    /// User 2026-10-23 「本地规则点进去无法修改」: 配置规则 rows are edited / 停用 / 删除 like 自定义 rows, kept as
    /// overrides (provider-overrides.json `#profile-rules`, bridge/profileruleoverrides.go).
    @State private var editingProfile: ProfileRuleItem?
    @State private var confirmDeleteProfile: ProfileRuleItem?
    @State private var confirmRestoreAll = false
    @ObservedObject private var hits = RuleHitsStore.shared
    @AppStorage("rules.sortByHits") private var sortByHits = false
    @State private var confirmReset = false

    struct Row: Hashable { var item: ProfileRuleItem; var session: Int? }

    /// The profile's own rules (not the rule sets, not the Final), in the profile's order = matching priority.
    var rows: [Row] {
        var sessions: [String: Int] = [:]
        if vpn.isConnected {
            for r in live { if let n = r.extra?.hitCount, sessions[RuleHitsStore.norm(r.type, r.payload, r.proxy)] == nil { sessions[RuleHitsStore.norm(r.type, r.payload, r.proxy)] = n } }
        }
        var all = prof.items
            .filter { !$0.isDeleted && Self.isLocal(type: $0.type, payload: $0.payload, proxy: $0.proxy) }
            .map { Row(item: $0, session: sessions[RuleHitsStore.norm($0.type, $0.payload, $0.proxy)]) }
        if !search.isEmpty {
            let q = search.lowercased()
            all = all.filter { r in
                [r.item.payload, r.item.type, r.item.proxy, r.item.line].contains { $0.lowercased().contains(q) }
            }
        }
        if sortByHits {
            // Review 5: one lookup per row (each builds a normalized key), not two per comparison.
            let total = Dictionary(uniqueKeysWithValues: all.map { ($0.item.position, hits.entry($0.item.type, $0.item.payload, $0.item.proxy)?.total ?? 0) })
            all.sort { a, b in
                let ta = total[a.item.position] ?? 0, tb = total[b.item.position] ?? 0
                return ta != tb ? ta > tb : a.item.position < b.item.position
            }
        }
        return all
    }

    var deletedProfileCount: Int {
        prof.items.filter { $0.isDeleted && Self.isLocal(type: $0.type, payload: $0.payload, proxy: $0.proxy) }.count
    }

    /// A 本地 rule: not a rule set (those are 订阅 on 规则), not the final MATCH (shown as Final there), and not the
    /// engine's own MitM plumbing (`__MITM__` hop, `__mitm_hosts` set) that the user never wrote.
    nonisolated static func isLocal(type: String, payload: String, proxy: String) -> Bool {
        // The running core reports rule sets as "RuleSet", the profile as "RULE-SET" (user 2026-10-23: 订阅
        // 规则集 showed up under 本地规则 while connected).
        let t = type.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
        if t == "RULESET" || t == "MATCH" || t == "FINAL" { return false }
        if proxy.hasPrefix("__") || payload.contains("__mitm") || payload.contains("__MITM") { return false }
        return true
    }

    var localCustom: [CustomRule] { custom.localRules }

    nonisolated static func isRuleSet(_ type: String) -> Bool {
        type.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "") == "RULESET"
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text("配置规则").tag(0)
                Text("自定义 \(localCustom.count)").tag(1)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16).padding(.vertical, 8)
            if tab == 0 { profileRules } else { customRules }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("本地规则")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if tab == 1 {
                    Button { adding = true } label: { Image(systemName: "plus") }
                        .accessibilityIdentifier("rules.add")
                } else {
                    Menu {
                        Picker("排序", selection: $sortByHits) {
                            Label("配置顺序", systemImage: "list.number").tag(false)
                            Label("命中最多", systemImage: "chart.bar.fill").tag(true)
                        }
                        Button(role: .destructive) { confirmReset = true } label: { Label("重置全部命中计数", systemImage: "arrow.counterclockwise") }
                            .disabled(hits.entries.isEmpty)
                        Divider()
                        Button { confirmRestoreAll = true } label: { Label("全部恢复配置原样", systemImage: "arrow.uturn.backward") }
                            .disabled(prof.modifiedCount == 0 || profiles.activeID == nil)
                    } label: { Image(systemName: "ellipsis.circle") }
                    .accessibilityLabel(Text("更多"))
                    .accessibilityIdentifier("rules.profile.more")
                }
            }
        }
        .task(id: vpn.isConnected) { await load() }
        .sheet(isPresented: $adding) { CustomRuleEditor(rule: CustomRule(line: "")) { r in custom.rules.insert(r, at: 0); custom.save() } }
        .sheet(item: $editing) { r in
            CustomRuleEditor(rule: r) { nr in
                if let i = custom.rules.firstIndex(where: { $0.id == nr.id }) { custom.rules[i] = nr; custom.save() }
            }
        }
        .confirmationDialog("重置全部规则的命中计数？", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("重置", role: .destructive) { hits.reset(nil) }
        }
        .sheet(item: $editingProfile) { it in
            CustomRuleEditor(rule: CustomRule(line: it.line), title: "编辑规则", allowRemote: false,
                             restore: it.isEdited ? { changeProfile(it) { $0.line = nil } } : nil) { nr in
                let l = nr.line.trimmingCharacters(in: .whitespacesAndNewlines)
                let same = l == it.rule || l == it.original.trimmingCharacters(in: .whitespacesAndNewlines)
                changeProfile(it) { $0.line = same ? nil : l }
            }
        }
        .deleteConfirmation({ _ in Text("删除这条规则？") }, item: $confirmDeleteProfile,
                            message: { _ in Text("只从当前配置里移除，配置文件不会改动。可以在列表底部「恢复已删除的规则」找回。") },
                            id: "rules.confirmDeleteProfileRule") { it in
            changeProfile(it) { $0.deleted = true }
        }
        .confirmationDialog("全部规则恢复配置原样？", isPresented: $confirmRestoreAll, titleVisibility: .visible) {
            Button("恢复", role: .destructive) {
                guard let id = profiles.activeID else { return }
                providerOV.restoreAllProfileRules(id)
                Task { await applyProfileChange() }
            }
        } message: { Text("撤销对配置规则的所有修改、停用和删除。") }
        .alert("提示", isPresented: Binding(get: { custom.message != nil }, set: { if !$0 { custom.message = nil } })) {
            Button("好") { custom.message = nil }
        } message: { Text(custom.message ?? "") }
    }

    func load() async {
        await prof.load()
        if vpn.isConnected, let r = try? await ControllerClient.shared.rules() { live = r } else { await offline.load() }
        await hits.refresh()
        await custom.recheck()
    }

    /// One profile rule's override (编辑 / 停用 / 删除 / 恢复), then the normal reload.
    func changeProfile(_ it: ProfileRuleItem, _ change: @escaping (inout ProfileRuleOverride) -> Void) {
        guard let id = profiles.activeID else { return }
        providerOV.updateProfileRule(id, rule: it.rule, index: it.index) { change(&$0) }
        Task { await applyProfileChange() }
    }

    func applyProfileChange() async {
        await prof.load()
        if vpn.isConnected {
            if let e = await VPNManager.shared.reload(hot: true) { custom.message = String(localized: "重载失败：\(e)") }
            if let r = try? await ControllerClient.shared.rules() { live = r }
        }
        await offline.load()
    }

    var profileRules: some View {
        let rows = self.rows // built once per render (it was evaluated for the list and again for the overlay)
        return List {
            if !hits.entries.isEmpty, search.isEmpty {
                RuleHitsSummary(store: hits).listRowBackground(Color.clear)
            }
            if let e = prof.error {
                Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.warn)
                    .listRowBackground(Color.clear)
            }
            ForEach(rows, id: \.item.position) { r in profileRow(r) }
            if !rows.isEmpty || deletedProfileCount > 0 {
                VStack(alignment: .leading, spacing: 8) {
                    if deletedProfileCount > 0, let id = profiles.activeID {
                        Button {
                            providerOV.restoreDeletedProfileRules(id)
                            Task { await applyProfileChange() }
                        } label: {
                            Label("恢复已删除的规则（\(deletedProfileCount)）", systemImage: "arrow.uturn.backward")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("rules.restoreDeletedProfileRules")
                    }
                    Text("顺序就是匹配优先级。轻点编辑；左滑删除或编辑；开关启用或停用；长按查看全部操作。")
                    Text("修改保存在 Tern 里，配置文件不会改动；更新配置后仍然有效。")
                }
                .font(.footnote).foregroundStyle(.secondary)
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索规则")
        .refreshable { await load() }
        .overlay {
            if rows.isEmpty && search.isEmpty && prof.loaded && deletedProfileCount == 0 {
                EmptyStateView(icon: "list.bullet.rectangle", title: AppShared.activeProfileURL == nil ? "没有选择配置" : "没有规则")
            }
        }
    }

    /// A rule of the profile: the same row actions as 自定义 / the SubscriptionKit rows (switch on the right; left swipe
    /// 删除 · 编辑; long press 编辑 · 停用/启用 · 恢复配置原样 · 复制规则 · 删除).
    func profileRow(_ r: Row) -> some View {
        let it = r.item
        let h = hits.entry(it.type, it.payload, it.proxy)
        let setOn: (Bool) -> Void = { on in changeProfile(it) { $0.disabled = on ? nil : true } }
        return HStack(alignment: .top, spacing: 10) {
            Text("\(it.position + 1)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 30, alignment: .trailing)
            VStack(alignment: .leading, spacing: 3) {
                Text(it.payload.isEmpty ? it.type : it.payload).font(.system(.footnote, design: .monospaced)).lineLimit(2)
                    .accessibilityIdentifier("rules.profile.row.\(it.position)")
                HStack(spacing: 6) {
                    RuleTypeTag(type: Theme.ruleTypeName(it.type))
                    if let o = it.options, !o.isEmpty { Text(verbatim: o).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                    if it.isEdited { ModifiedTag() }
                    Spacer()
                    if !it.proxy.isEmpty { PolicyChip(name: it.proxy) }
                }
                if let e = it.error, !e.isEmpty {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.warn).lineLimit(3)
                }
                if h != nil || (r.session ?? 0) > 0 { RuleHitLine(entry: h, session: r.session) }
            }
            Toggle("", isOn: Binding(get: { !it.isDisabled }, set: setOn)).labelsHidden()
                .disabled(profiles.activeID == nil)
                .accessibilityIdentifier("rules.profile.toggle.\(it.position)")
        }
        .opacity(it.isDisabled ? 0.55 : 1)
        .contentShape(Rectangle())
        .onTapGesture { editingProfile = it }
        .listRowBackground(Theme.card)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            // Not role: .destructive — that removes the row at once, even when the confirmation is cancelled.
            Button { confirmDeleteProfile = it } label: { Label("删除", systemImage: "trash") }.tint(.red)
            Button { editingProfile = it } label: { Label("编辑", systemImage: "pencil") }.tint(.gray)
        }
        .contextMenu {
            Button { editingProfile = it } label: { Label("编辑", systemImage: "pencil") }
            Button { setOn(it.isDisabled) } label: {
                Label(LocalizedStringKey(it.isDisabled ? "启用" : "停用"), systemImage: it.isDisabled ? "play.circle" : "pause.circle")
            }
            if it.isEdited || it.isDisabled {
                Button { changeProfile(it) { $0.line = nil; $0.disabled = nil } } label: { Label("恢复配置原样", systemImage: "arrow.uturn.backward") }
            }
            Button { UIPasteboard.general.string = it.isEdited ? it.line : it.original } label: { Label("复制规则", systemImage: "doc.on.doc") }
            if h != nil {
                Button(role: .destructive) { hits.reset(h?.key) } label: { Label("重置此规则的命中计数", systemImage: "arrow.counterclockwise") }
            }
            Divider()
            Button(role: .destructive) { confirmDeleteProfile = it } label: { Label("删除", systemImage: "trash") }
        }
        .accessibilityAction(named: Text("编辑")) { editingProfile = it }
    }

    var customRules: some View {
        List {
            Section {
                if localCustom.isEmpty {
                    Text("点右上角 + 添加。自定义规则排在配置规则之前，可以直接粘贴 Surge / Quantumult X / Loon / mihomo 写法；远程规则列表在上一页的「订阅」里添加。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(localCustom) { r in
                    CustomRuleRow(rule: r, check: custom.checks[r.id]) { on in
                        if let i = custom.rules.firstIndex(where: { $0.id == r.id }) { custom.rules[i].enabled = on; custom.save() }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editing = r }
                    // r7: 上移 / 下移 without the long-press drag (swipe right, or VoiceOver actions).
                    .swipeActions(edge: .leading, allowsFullSwipe: false) {
                        if custom.canStepSubset(localCustom, r.id, by: 1) {
                            Button { withAnimation { custom.stepSubset(localCustom, r.id, by: 1) } } label: { Label("下移", systemImage: "arrow.down") }
                                .tint(Theme.accent.opacity(0.75))
                        }
                        if custom.canStepSubset(localCustom, r.id, by: -1) {
                            Button { withAnimation { custom.stepSubset(localCustom, r.id, by: -1) } } label: { Label("上移", systemImage: "arrow.up") }
                                .tint(Theme.accent)
                        }
                    }
                    // Explicit swipeActions turn off the Delete swipe synthesized by onDelete: keep it here.
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            custom.rules.removeAll { $0.id == r.id }; custom.save()
                        } label: { Label("删除", systemImage: "trash") }
                    }
                    .accessibilityAction(named: Text("上移")) { custom.stepSubset(localCustom, r.id, by: -1) }
                    .accessibilityAction(named: Text("下移")) { custom.stepSubset(localCustom, r.id, by: 1) }
                }
                .onDelete { offs in
                    let ids = Set(offs.map { localCustom[$0].id })
                    custom.rules.removeAll { ids.contains($0.id) }; custom.save()
                }
                .onMove { custom.moveSubset(localCustom, from: $0, to: $1) }
            } footer: {
                Text("策略名会对应到当前配置的策略组；找不到时使用第一个手动选择组并标黄。远程列表通过内核下载并转换为 mihomo 规则集；QX filter_remote 没有 force-policy 时整份列表走 proxy（第一个手动选择组）。")
                    .modifier(UITestOrderValue(id: "rules.custom.order", order: custom.orderToken))
            }
            .listRowBackground(Theme.card)
            .id(custom.orderRevision)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
    }
}

/// v0.16: rule types are tinted by category (Theme.ruleTypeColor); other tags (provider vehicle / behavior) stay neutral.
struct RuleTypeTag: View {
    let type: String
    /// fix/rule-labels: the profile spelling (DOMAIN-SUFFIX, AND) when `type` is a human name (「域名后缀」) — picks the
    /// tint and keeps the `ruletype.<TYPE>` accessibility id stable.
    var key: String? = nil
    var body: some View {
        if let c = Theme.ruleTypeColor(key ?? type) {
            Text(verbatim: type).font(.caption2.weight(.semibold))
                .padding(.horizontal, 5).padding(.vertical, 1)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(c.opacity(0.16)))
                .foregroundStyle(c)
                .lineLimit(1).fixedSize()
                .accessibilityIdentifier("ruletype." + (key ?? type))
        } else {
            Text(verbatim: type).font(.caption2.weight(.semibold))
                .padding(.horizontal, 5).padding(.vertical, 1)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(Theme.ink(0.1)))
                .lineLimit(1).fixedSize()
        }
    }
}

/// v0.16: the policy a rule sends traffic to, as a chip on the right of the row.
struct PolicyChip: View {
    let name: String
    var body: some View {
        let c = Theme.policyColor(name)
        Text(verbatim: name).font(.caption.weight(.medium))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(c.opacity(0.14)))
            .foregroundStyle(c)
            .lineLimit(1).truncationMode(.middle)
            .accessibilityIdentifier("policychip." + name)
    }
}

struct CustomRuleRow: View {
    let rule: CustomRule
    let check: RuleCheck?
    let onToggle: (Bool) -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text(rule.line).scaledFont(12, design: .monospaced).lineLimit(3)
                if let c = check, (c.error ?? "").isEmpty, let r = c.rule, !r.isEmpty {
                    HStack(spacing: 6) {
                        RuleTypeTag(type: Theme.ruleTypeName(String(r.split(separator: ",").first ?? Substring(r)).trimmingCharacters(in: .whitespaces)))
                        Spacer(minLength: 4)
                        if let p = c.policy, !p.isEmpty { PolicyChip(name: p) }
                    }
                }
                RuleCheckLine(check: check)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { rule.enabled }, set: onToggle)).labelsHidden()
        }
        .opacity(rule.enabled ? 1 : 0.55)
    }
}

struct RuleCheckLine: View {
    let check: RuleCheck?
    var body: some View {
        if let c = check {
            if let e = c.error, !e.isEmpty {
                Label(e, systemImage: "xmark.octagon.fill").font(.caption2).foregroundStyle(Theme.bad)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    if let r = c.rule, !r.isEmpty {
                        Label(r, systemImage: "checkmark.circle.fill").scaledFont(10, design: .monospaced).foregroundStyle(Theme.good).lineLimit(2)
                    }
                    if let u = c.unresolved, !u.isEmpty {
                        Label("配置里没有策略「\(u)」，改用 \(c.policy ?? "第一个手动组")", systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.warn)
                    }
                    if let n = c.note, !n.isEmpty { Text(n).font(.caption2).foregroundStyle(.secondary) }
                }
            }
        }
    }
}

/// v0.19.8: one rule type of the structured editor.
struct RuleKind: Identifiable, Hashable {
    enum Group: String, CaseIterable { case domain, ip, other }
    let id: String          // the mihomo rule type
    let group: Group
    let caption: String
    let placeholder: String
    var isIP = false
    var keyboard: UIKeyboardType = .asciiCapable
    var noValue = false

    static var all: [RuleKind] { [
        RuleKind(id: "DOMAIN-SUFFIX", group: .domain, caption: String(localized: "域名及其所有子域名"), placeholder: "google.com"),
        RuleKind(id: "DOMAIN", group: .domain, caption: String(localized: "完全相同的域名"), placeholder: "www.google.com"),
        RuleKind(id: "DOMAIN-KEYWORD", group: .domain, caption: String(localized: "域名里包含这个关键词"), placeholder: "openai"),
        RuleKind(id: "DOMAIN-REGEX", group: .domain, caption: String(localized: "域名匹配正则表达式"), placeholder: "^ad\\..*"),
        RuleKind(id: "GEOSITE", group: .domain, caption: String(localized: "域名分类（GeoSite）"), placeholder: "netflix"),
        RuleKind(id: "IP-CIDR", group: .ip, caption: String(localized: "IPv4 网段"), placeholder: "192.168.0.0/16", isIP: true, keyboard: .numbersAndPunctuation),
        RuleKind(id: "IP-CIDR6", group: .ip, caption: String(localized: "IPv6 网段"), placeholder: "2001:db8::/32", isIP: true, keyboard: .numbersAndPunctuation),
        RuleKind(id: "IP-ASN", group: .ip, caption: String(localized: "IP 所属的自治系统编号"), placeholder: "13335", isIP: true, keyboard: .numberPad),
        RuleKind(id: "GEOIP", group: .ip, caption: String(localized: "IP 所属的国家或地区代码"), placeholder: "CN", isIP: true),
        RuleKind(id: "PROCESS-NAME", group: .other, caption: String(localized: "发起连接的进程名"), placeholder: "Telegram"),
        RuleKind(id: "DST-PORT", group: .other, caption: String(localized: "目标端口"), placeholder: "443", keyboard: .numberPad),
        RuleKind(id: "NETWORK", group: .other, caption: String(localized: "网络类型：tcp 或 udp"), placeholder: "udp"),
        RuleKind(id: "RULE-SET", group: .other, caption: String(localized: "远程规则列表（Surge / QX / Clash 格式）"), placeholder: "https://example.com/rules.list", keyboard: .URL),
        RuleKind(id: "MATCH", group: .other, caption: String(localized: "其余所有连接（最后一条）"), placeholder: "", noValue: true),
    ] }

    static func groupTitle(_ g: Group) -> String {
        switch g {
        case .domain: return String(localized: "域名")
        case .ip: return "IP"
        case .other: return String(localized: "进程与其他")
        }
    }

    /// Surge / QX spellings → the mihomo type the form shows.
    static let aliases: [String: String] = [
        "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "HOST-REGEX": "DOMAIN-REGEX",
        "IP6-CIDR": "IP-CIDR6", "IP-CIDR6": "IP-CIDR6", "FINAL": "MATCH", "PROCESS": "PROCESS-NAME", "DEST-PORT": "DST-PORT",
    ]
}

/// v0.19.8: the fields of the structured editor, two-way with the rule line.
struct RuleFormFields: Equatable {
    var type = "DOMAIN-SUFFIX"
    var value = ""
    var policy = ""
    var noResolve = false

    var kind: RuleKind? { RuleKind.all.first { $0.id == type } }

    var line: String {
        let k = kind
        if k?.noValue == true { return "\(type),\(policy)" }
        var parts = [type, value.trimmingCharacters(in: .whitespaces), policy]
        if k?.isIP == true && noResolve { parts.append("no-resolve") }
        return parts.joined(separator: ",")
    }

    /// nil when the line is not one the form can show (remote QX filter_remote lines, logical rules, …): text mode.
    static func parse(_ line: String) -> RuleFormFields? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, !first.isEmpty else { return nil }
        var t = first.uppercased()
        t = RuleKind.aliases[t] ?? t
        guard let k = RuleKind.all.first(where: { $0.id == t }) else { return nil }
        var f = RuleFormFields(type: t)
        if k.noValue {
            guard parts.count == 2 else { return nil }
            f.policy = parts[1]
            return f
        }
        guard parts.count >= 3, parts.count <= 4 else { return nil }
        f.value = parts[1]
        f.policy = parts[2]
        if parts.count == 4 {
            guard parts[3].lowercased() == "no-resolve" else { return nil }
            f.noResolve = true
        }
        // QX spells built-in policies in lower case.
        if ["direct", "reject", "proxy"].contains(f.policy) { f.policy = f.policy == "proxy" ? f.policy : f.policy.uppercased() }
        return f
    }
}

struct CustomRuleEditor: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject private var vpn = VPNManager.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State var rule: CustomRule
    /// 自定义规则, or 编辑规则 for a rule of the profile (2026-10-23).
    var title: LocalizedStringKey = "自定义规则"
    /// false for a rule of the profile: remote lists are 订阅 (bridge convertEditedRule refuses them too).
    var allowRemote = true
    /// 恢复配置原样 (a profile rule the user edited): drops the edit.
    var restore: (() -> Void)? = nil
    let onSave: (CustomRule) -> Void
    @State private var check: RuleCheck?
    @State private var checking = false
    /// v0.19.8 (user: QX-like form, 「不要照抄」): type / value / policy fields; 文本模式 shows the raw line.
    @State private var form = RuleFormFields()
    @State private var textMode = false
    @State private var targets = PolicyTargets()

    static let examples = [
        "DOMAIN-SUFFIX,google.com,Proxy",
        "DOMAIN-KEYWORD,openai,Proxy",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "host-suffix, apple.com, direct          (Quantumult X)",
        "RULE-SET,https://example.com/ad.list,REJECT          (Surge)",
        "DOMAIN-SET,https://example.com/cdn.txt,DIRECT          (Surge)",
        "https://example.com/x.list, tag=x, force-policy=Proxy          (QX filter_remote)",
    ]

    static let builtins = ["DIRECT", "REJECT", "REJECT-DROP"]

    /// The groups, built-in policies and the profile's own nodes; a policy the line names that is none of them stays
    /// selectable (first).
    var policyChoices: [String] {
        var out = targets.all
        if !form.policy.isEmpty && !out.contains(form.policy) { out.insert(form.policy, at: 0) }
        return out
    }

    var remoteRefused: Bool { !allowRemote && rule.line.contains("://") }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("编辑方式", selection: Binding(get: { textMode }, set: { setTextMode($0) })) {
                        Text("表单").tag(false)
                        Text("文本模式").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("rule.mode")
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())

                if textMode { textSections } else { formSections }

                if let restore {
                    Section {
                        Button {
                            restore()
                            dismiss()
                        } label: { Label("恢复配置原样", systemImage: "arrow.uturn.backward") }
                            .accessibilityIdentifier("rule.restore")
                    }
                    .listRowBackground(Theme.card)
                }

                if allowRemote && rule.line.contains("://") {
                    Section("远程列表更新间隔") {
                        Picker("间隔", selection: Binding(get: { rule.interval ?? 86400 }, set: { rule.interval = $0 })) {
                            Text("6 小时").tag(21600)
                            Text("12 小时").tag(43200)
                            Text("1 天").tag(86400)
                            Text("7 天").tag(604800)
                        }
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        rule.line = rule.line.trimmingCharacters(in: .whitespacesAndNewlines)
                        onSave(rule)
                        dismiss()
                    }
                    .disabled(!canSave)
                    .accessibilityIdentifier("rule.save")
                }
            }
            .task(id: rule.line) {
                let line = rule.line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !line.isEmpty else { check = nil; return }
                try? await Task.sleep(nanoseconds: 300_000_000)
                if Task.isCancelled { return }
                checking = true
                let c = await CustomRulesStore.check(line: line)
                checking = false
                if !Task.isCancelled { check = c }
            }
            .task { await loadPolicies() }
            .onAppear {
                if let f = RuleFormFields.parse(rule.line) { form = f }
                else if !rule.line.trimmingCharacters(in: .whitespaces).isEmpty { textMode = true }
                if form.policy.isEmpty { form.policy = targets.groups.first ?? "DIRECT" }
                if !textMode && rule.line.isEmpty { rule.line = form.line }
            }
            .onChange(of: form) { f in if !textMode { rule.line = f.line } }
        }
    }

    var canSave: Bool {
        let line = rule.line.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || check?.error?.isEmpty == false || remoteRefused { return false }
        if !textMode, form.kind?.noValue != true, form.value.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    @ViewBuilder var formSections: some View {
        Section {
            Picker("类型", selection: $form.type) {
                ForEach(RuleKind.Group.allCases, id: \.self) { g in
                    Section(RuleKind.groupTitle(g)) {
                        ForEach(RuleKind.all.filter { $0.group == g }) { k in Text(verbatim: k.id).tag(k.id) }
                    }
                }
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("rule.type")
            if let k = form.kind { Text(k.caption).font(.caption).foregroundStyle(.secondary) }
            if form.kind?.noValue != true {
                TextField(form.kind?.placeholder ?? "", text: $form.value)
                    .font(.body.monospaced())
                    .keyboardType(form.kind?.keyboard ?? .asciiCapable)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("rule.value")
            }
            if form.kind?.isIP == true {
                Toggle("不解析域名（no-resolve）", isOn: $form.noResolve)
            }
        } header: { Text("匹配") }
        .listRowBackground(Theme.card)

        Section {
            Picker("策略", selection: $form.policy) {
                let known = Set(targets.all)
                ForEach(policyChoices.filter { !known.contains($0) }, id: \.self) { Text(verbatim: $0).tag($0) }
                if !targets.groups.isEmpty {
                    Section("策略组") { ForEach(targets.groups, id: \.self) { Text(verbatim: $0).tag($0) } }
                }
                Section("内置策略") { ForEach(targets.builtins, id: \.self) { Text(verbatim: $0).tag($0) } }
                if !targets.nodes.isEmpty {
                    Section("节点") { ForEach(targets.nodes, id: \.self) { Text(verbatim: $0).tag($0) } }
                }
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("rule.policy")
        } header: { Text("策略") } footer: {
            Text("策略组来自当前配置；找不到时使用第一个手动选择组并标黄。")
        }
        .listRowBackground(Theme.card)

        Section {
            Text(verbatim: rule.line).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                .accessibilityIdentifier("rule.line")
            if checking { ProgressView().controlSize(.small) } else { RuleCheckLine(check: check) }
            if remoteRefused { RemoteRefusedLine() }
        } header: { Text("规则") } footer: { Text("实时校验：显示转换后的 mihomo 规则和对应的策略组。") }
        .listRowBackground(Theme.card)
    }

    @ViewBuilder var textSections: some View {
        Section {
            TextField("规则", text: $rule.line, axis: .vertical)
                .scaledFont(13, design: .monospaced)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .lineLimit(1...5)
                .accessibilityIdentifier("rule.text")
            if checking { ProgressView().controlSize(.small) } else { RuleCheckLine(check: check) }
            if remoteRefused { RemoteRefusedLine() }
        } header: { Text("规则") } footer: {
            Text("可以粘贴 Surge / QX / Clash 规则；切回表单时会填入各个字段。输入时实时校验：显示转换后的 mihomo 规则和对应的策略组。")
        }
        .listRowBackground(Theme.card)
        Section("示例（轻点填入）") {
            ForEach(allowRemote ? Self.examples : Self.examples.filter { !$0.contains("://") }, id: \.self) { ex in
                Button {
                    rule.line = ex.components(separatedBy: "          ").first ?? ex
                } label: {
                    Text(ex).scaledFont(11, design: .monospaced).foregroundStyle(.secondary)
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    /// Switching to the form parses the line; a line the form cannot show stays in text mode.
    func setTextMode(_ on: Bool) {
        if on {
            // An empty form (no value typed yet) opens an empty text field instead of a half line like
            // "DOMAIN-SUFFIX,,Proxy" that the pasted rule would be appended to.
            if form.kind?.noValue != true && form.value.trimmingCharacters(in: .whitespaces).isEmpty { rule.line = "" }
            textMode = true
            return
        }
        if let f = RuleFormFields.parse(rule.line) {
            form = f
            textMode = false
            rule.line = f.line
        } else if rule.line.trimmingCharacters(in: .whitespaces).isEmpty {
            textMode = false
            rule.line = form.line
        } else {
            check = RuleCheck(error: String(localized: "这条规则无法用表单编辑（例如远程列表的 QX 写法或逻辑规则），请在文本模式里修改。"))
        }
    }

    func loadPolicies() async {
        targets = await PolicyTargets.load()
        if form.policy.isEmpty || (rule.line.isEmpty && !textMode) { form.policy = targets.groups.first ?? "DIRECT" }
    }
}

struct RemoteRefusedLine: View {
    var body: some View {
        Label("远程规则列表请在「订阅」里添加", systemImage: "xmark.octagon.fill").font(.caption2).foregroundStyle(Theme.bad)
    }
}

// MARK: - Providers

struct OfflineProviderRow: View {
    let p: InspectProvider
    var error: String? = nil

    var cacheSummary: String {
        var parts: [String] = [String(localized: "已缓存")]
        if p.count >= 0 {
            parts.append(p.kind == "proxy" ? String(localized: "\(p.count) 个节点") : String(localized: "\(p.count) 条"))
        } else {
            parts.append(String(localized: "二进制格式"))
        }
        if let s = p.size { parts.append(Fmt.bytes(s)) }
        if let d = p.cachedDate { parts.append(d.formatted(.relative(presentation: .named))) }
        return parts.joined(separator: " · ")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(p.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                RuleTypeTag(type: p.vehicle.uppercased())
                if let b = p.behavior, !b.isEmpty { RuleTypeTag(type: b) }
            }
            if p.cached {
                Text(cacheSummary).font(.caption2).foregroundStyle(.secondary)
            } else {
                Text(p.vehicle == "inline" ? "内联" : "尚未下载 · 轻点右侧按钮下载").font(.caption2).foregroundStyle(Theme.warn)
            }
            if let error {
                Text(error).font(.caption2).foregroundStyle(Theme.bad).lineLimit(2)
            }
            if let u = p.url, !u.isEmpty {
                Text(u).scaledFont(9, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
    }
}

struct OfflineProviderDetail: View {
    let p: InspectProvider
    var body: some View {
        List {
            Section {
                LabeledContent("类型", value: p.kind == "proxy" ? String(localized: "节点集") : String(localized: "规则集"))
                LabeledContent("来源", value: p.vehicle)
                if let b = p.behavior, !b.isEmpty { LabeledContent("行为", value: b) }
                if let f = p.format, !f.isEmpty { LabeledContent("格式", value: f) }
                if let i = p.interval, i > 0 { LabeledContent("更新间隔", value: String(localized: "\(i / 3600) 小时")) }
                if let u = p.url, !u.isEmpty {
                    Text(u).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let c = p.cachePath, !c.isEmpty {
                    LabeledContent("缓存文件", value: (c as NSString).lastPathComponent)
                }
            }
            .listRowBackground(Theme.card)
            if let nodes = p.proxies, !nodes.isEmpty {
                Section("缓存的节点 \(nodes.count)") {
                    ForEach(nodes, id: \.name) { n in
                        HStack { Text(n.name).font(.footnote).lineLimit(1); Spacer(); ProtocolBadge(type: n.type) }
                    }
                }
                .listRowBackground(Theme.card)
            }
            if let lines = p.preview, !lines.isEmpty {
                Section("缓存内容（前 \(lines.count) 行）") {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                        Text(l).scaledFont(10, design: .monospaced)
                    }
                }
                .listRowBackground(Theme.card)
            }
            if !p.cached && p.vehicle != "inline" {
                Text("还没有缓存。在列表里点更新即可由 App 直接下载；连接后内核也会下载。").font(.footnote).foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(p.name)
    }
}

// MARK: - v0.14 rule hit counters (saved by the extension in <home>/rule-hits.json)

@MainActor
final class RuleHitsStore: ObservableObject {
    static let shared = RuleHitsStore()

    struct Entry: Decodable, Hashable {
        var type: String
        var payload: String
        var proxy: String
        var total: Int
        var day: String?
        var today: Int?
        var lastHit: Int64?
        var key: String { "\(type),\(payload),\(proxy)" }
        var todayCount: Int { day == RuleHitsStore.dayString(Date()) ? (today ?? 0) : 0 }
        var lastHitDate: Date? { (lastHit ?? 0) > 0 ? Date(timeIntervalSince1970: TimeInterval(lastHit!)) : nil }
    }
    private struct File: Decodable { var since: Int64?; var rules: [String: Entry]? }

    @Published private(set) var entries: [String: Entry] = [:]
    @Published private(set) var since: Date?
    private var byNorm: [String: Entry] = [:]

    static var url: URL { AppShared.homeURL.appendingPathComponent("rule-hits.json") }

    nonisolated static func dayString(_ d: Date) -> String {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: d)
    }

    /// Live rules say "DomainSuffix", the offline inspector may say "DOMAIN-SUFFIX": compare without case / dashes.
    nonisolated static func norm(_ t: String, _ p: String, _ x: String) -> String {
        t.lowercased().filter { $0.isLetter || $0.isNumber } + "\u{1}" + p + "\u{1}" + x
    }

    func entry(_ type: String, _ payload: String, _ proxy: String) -> Entry? { byNorm[Self.norm(type, payload, proxy)] }

    var total: Int { entries.values.reduce(0) { $0 + $1.total } }
    var today: Int { entries.values.reduce(0) { $0 + $1.todayCount } }
    var top: [Entry] { entries.values.sorted { $0.total > $1.total }.prefix(5).map { $0 } }

    /// Asks a running tunnel to save its counters first, then reads the file.
    func refresh() async {
        if VPNManager.shared.isConnected { _ = await VPNManager.shared.send(.flushStats, timeout: 3) }
        load()
    }

    func load() {
        guard let d = try? Data(contentsOf: Self.url), let f = try? JSONDecoder().decode(File.self, from: d) else {
            entries = [:]; byNorm = [:]; since = nil; return
        }
        entries = f.rules ?? [:]
        var m: [String: Entry] = [:]
        for e in entries.values { m[Self.norm(e.type, e.payload, e.proxy)] = e }
        byNorm = m
        since = (f.since ?? 0) > 0 ? Date(timeIntervalSince1970: TimeInterval(f.since!)) : nil
    }

    /// key nil = all rules.
    func reset(_ key: String?) {
        let err = LibmihomoResetRuleHits(AppShared.homeURL.path, key ?? "")
        if !err.isEmpty { return }
        load()
    }
}

struct RuleHitLine: View {
    let entry: RuleHitsStore.Entry?
    let session: Int?

    var body: some View {
        HStack(spacing: 8) {
            if let e = entry {
                Label("累计 \(Fmt.count(e.total))", systemImage: "chart.bar.fill")
                if e.todayCount > 0 { Text("今天 \(Fmt.count(e.todayCount))") }
                if let d = e.lastHitDate { Text(d.formatted(.relative(presentation: .named))) }
            }
            if let s = session, s > 0 { Text("本次 \(Fmt.count(s))") }
        }
        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary).labelStyle(.titleAndIcon).lineLimit(1)
    }
}

struct RuleHitsSummary: View {
    @ObservedObject var store: RuleHitsStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("命中统计", systemImage: "chart.bar.xaxis").font(.caption.weight(.semibold))
                Spacer()
                if let d = store.since { Text("自 \(d.formatted(date: .abbreviated, time: .omitted)) 起").font(.caption2).foregroundStyle(.secondary) }
            }
            HStack(spacing: 16) {
                VStack(alignment: .leading) { Text(Fmt.count(store.total)).font(.headline.monospacedDigit()); Text("累计").font(.caption2).foregroundStyle(.secondary) }
                VStack(alignment: .leading) { Text(Fmt.count(store.today)).font(.headline.monospacedDigit()); Text("今天").font(.caption2).foregroundStyle(.secondary) }
                VStack(alignment: .leading) { Text("\(store.entries.count)").font(.headline.monospacedDigit()); Text("条规则有命中").font(.caption2).foregroundStyle(.secondary) }
            }
            let maxTotal = max(store.top.first?.total ?? 1, 1)
            ForEach(store.top, id: \.key) { e in
                HStack(spacing: 8) {
                    Text(e.payload.isEmpty ? e.type : e.payload).font(.caption2.monospaced()).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                    GeometryReader { g in
                        Capsule().fill(Theme.accent.opacity(0.7)).frame(width: max(g.size.width * CGFloat(e.total) / CGFloat(maxTotal), 3))
                    }
                    .frame(width: 70, height: 5)
                    Text(Fmt.count(e.total)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 44, alignment: .trailing)
                }
            }
            Text("连接时每 30 秒保存一次，断开、重载配置后继续累计。长按规则可单独重置。").font(.caption2).foregroundStyle(.secondary)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Theme.card))
    }
}
