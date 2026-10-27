import Foundation

/// feat/subs-split (user 2026-10-21 「节点订阅里…没有禁用、删除选项」): the user's 停用 / 删除 / 编辑 / 图标 of the
/// proxy-providers (节点集) a profile declares. Kept per profile in <home>/provider-overrides.json — the override
/// store, never written into the profile — and applied by the retired bridge buildRuntime.
/// Keyed by the provider's name in the profile, so updating the profile keeps them.
/// - 停用: not loaded, removed from every group's `use:` (a group left empty gets DIRECT); reversible.
/// - 删除: the same, and the row is hidden; 恢复已删除的节点集 brings it back (updating the profile does not).
/// - name / icon are display only: the core keeps the profile's name so groups and rules that name it still work.
struct ProviderOverride: Codable, Hashable {
    var disabled: Bool? = nil
    var deleted: Bool? = nil
    var name: String? = nil
    var icon: String? = nil
    var url: String? = nil
    var interval: Int? = nil
    var filter: String? = nil
    var excludeFilter: String? = nil
    /// Rule sets only (key `rule:<name>`, user 2026-10-23 「对应的还要有删除，禁用，修改功能」): the policy of the profile's
    /// RULE-SET rules.
    var policy: String? = nil
    /// Display only (app side): what a 停用 rule set showed before it left the runtime, so its row stays listed.
    var shownPolicy: String? = nil
    var shownURL: String? = nil
    /// Only on the entry keyed `ruleOrderKey` (user 2026-10-23 「这个规则要能手动调顺序」): the profile's rule sets in the
    /// order the user arranged them on 规则 → 订阅 = matching priority, top first (bridge applyRuleSetOrder).
    var order: [String]? = nil
    /// Only on the entry keyed `profileRulesKey` (user 2026-10-23 「本地规则点进去无法修改」): the user's 编辑 / 停用 /
    /// 删除 of the profile's own rules. The `finalKey` entry uses `policy`.
    var rules: [ProfileRuleOverride]? = nil

    var isEmpty: Bool {
        disabled != true && deleted != true && (name ?? "").isEmpty && icon == nil && (url ?? "").isEmpty
            && (interval ?? 0) <= 0 && (filter ?? "").isEmpty && (excludeFilter ?? "").isEmpty && (policy ?? "").isEmpty
            && (order ?? []).isEmpty && (rules ?? []).isEmpty
    }

    static func ruleKey(_ name: String) -> String { "rule:" + name }
    /// Never a provider name the other lists act on (bridge ruleOrderKey).
    static let ruleOrderKey = "#rule-order"
    /// The profile's own rules (bridge profileRulesKey) and its Final / MATCH policy (bridge finalRuleKey).
    static let profileRulesKey = "#profile-rules"
    static let finalKey = "#final"
}

/// One profile rule the user changed, keyed by the rule's text as bridge ProfileRules reports it (`rule`) and which
/// occurrence of that text it is (`index`), so a profile update keeps it while the rule is still there.
struct ProfileRuleOverride: Codable, Hashable {
    var rule: String
    var index: Int
    var line: String? = nil
    var disabled: Bool? = nil
    var deleted: Bool? = nil

    var isEmpty: Bool { (line ?? "").isEmpty && disabled != true && deleted != true }
}

/// One proxy-provider as the profile declares it (bridge ProfileProviders), before the overrides.
struct ProfileProviderInfo: Decodable, Hashable {
    var name: String
    var vehicle: String
    var url: String? = nil
    var interval: Int? = nil
    var filter: String? = nil
    var excludeFilter: String? = nil
}

@MainActor
final class ProviderOverrideStore: ObservableObject {
    static let shared = ProviderOverrideStore()

    /// profile id → provider name → override.
    @Published private(set) var all: [String: [String: ProviderOverride]] = [:]
    /// The active profile's providers as declared (for 停用 rows that are not in the runtime, and the editor).
    @Published private(set) var declared: [ProfileProviderInfo] = []
    private var declaredFor: String?

    static var url: URL { AppShared.homeURL.appendingPathComponent("provider-overrides.json") }

    init() { reload() }

    func reload() {
        if let d = try? Data(contentsOf: Self.url), let m = try? JSONDecoder().decode([String: [String: ProviderOverride]].self, from: d) {
            all = m
        } else {
            all = [:]
        }
    }

    func overrides(_ profileID: String?) -> [String: ProviderOverride] {
        guard let profileID else { return [:] }
        return all[profileID] ?? [:]
    }

    func get(_ profileID: String?, _ name: String) -> ProviderOverride { overrides(profileID)[name] ?? ProviderOverride() }

    func set(_ profileID: String, _ name: String, _ o: ProviderOverride) {
        var m = all[profileID] ?? [:]
        m[name] = o.isEmpty ? nil : o
        all[profileID] = m.isEmpty ? nil : m
        write()
    }

    func update(_ profileID: String, _ name: String, _ change: (inout ProviderOverride) -> Void) {
        var o = get(profileID, name)
        change(&o)
        set(profileID, name, o)
    }

    /// fix/nc-0.20.2: a new 自定义 copy (first 策略组 reorder, GroupOrder.save) keeps the source profile's
    /// 节点集 / 规则集 overrides (停用 / 删除 / 编辑), the rule-set order (`#rule-order`) and the profile-rule edits;
    /// before, they stayed keyed by the source id, so the copy came up with the rule sets in the profile's own order.
    /// Entries the copy already has are kept.
    func copy(from: String, to: String) {
        guard from != to, let src = all[from], !src.isEmpty else { return }
        var m = all[to] ?? [:]
        for (k, v) in src where m[k] == nil { m[k] = v }
        all[to] = m
        write()
    }

    /// 恢复已删除的节点集 (ruleSets false) / 恢复已删除的规则集 (true): clears 删除 on those providers of the profile
    /// (other edits stay). Rule-set entries are keyed `rule:<name>`.
    func restoreDeleted(_ profileID: String, ruleSets: Bool = false) {
        guard var m = all[profileID] else { return }
        for (k, var v) in m where v.deleted == true && k.hasPrefix("rule:") == ruleSets {
            v.deleted = nil
            m[k] = v.isEmpty ? nil : v
        }
        all[profileID] = m.isEmpty ? nil : m
        write()
    }

    // MARK: 配置规则 / Final

    /// Changes the override of one profile rule (an override left empty is removed).
    func updateProfileRule(_ profileID: String, rule: String, index: Int, _ change: (inout ProfileRuleOverride) -> Void) {
        update(profileID, ProviderOverride.profileRulesKey) { o in
            var list = o.rules ?? []
            var r = list.first { $0.rule == rule && $0.index == index } ?? ProfileRuleOverride(rule: rule, index: index)
            change(&r)
            list.removeAll { $0.rule == rule && $0.index == index }
            if !r.isEmpty { list.append(r) }
            o.rules = list.isEmpty ? nil : list
        }
    }

    /// 恢复已删除的规则: clears 删除 on the profile's rules (other edits stay).
    func restoreDeletedProfileRules(_ profileID: String) {
        update(profileID, ProviderOverride.profileRulesKey) { o in
            let list = (o.rules ?? []).map { r -> ProfileRuleOverride in var r = r; r.deleted = nil; return r }.filter { !$0.isEmpty }
            o.rules = list.isEmpty ? nil : list
        }
    }

    /// 全部恢复配置原样: every 编辑 / 停用 / 删除 of the profile's rules goes (the Final has its own 恢复).
    func restoreAllProfileRules(_ profileID: String) {
        update(profileID, ProviderOverride.profileRulesKey) { $0.rules = nil }
    }

    func finalPolicy(_ profileID: String?) -> String? {
        let p = overrides(profileID)[ProviderOverride.finalKey]?.policy ?? ""
        return p.isEmpty ? nil : p
    }

    /// nil = the profile's own Final.
    func setFinalPolicy(_ profileID: String, _ policy: String?) {
        update(profileID, ProviderOverride.finalKey) { $0.policy = (policy ?? "").isEmpty ? nil : policy }
    }

    func loadDeclared(_ profile: Profile?, force: Bool = false) async {
        guard let profile else { declared = []; declaredFor = nil; return }
        let path = profile.fileURL.path
        if !force && declaredFor == path { return }
        let json = await Task.detached(priority: .userInitiated) { NCProfileRulesPort.profileProviders(home: AppShared.homeURL.path, profilePath: path) }.value
        declared = (try? JSONDecoder().decode([ProfileProviderInfo].self, from: Data(json.utf8))) ?? []
        declaredFor = path
    }

    private func write() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(all) { try? d.write(to: Self.url, options: .atomic) }
    }
}
