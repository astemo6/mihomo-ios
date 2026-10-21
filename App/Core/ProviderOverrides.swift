import Foundation
import Libmihomo

/// feat/subs-split (user 2026-10-21 「节点订阅里…没有禁用、删除选项」): the user's 停用 / 删除 / 编辑 / 图标 of the
/// proxy-providers (节点集) a profile declares. Kept per profile in <home>/provider-overrides.json — the override
/// store, never written into the profile — and applied by bridge/provideroverrides.go in buildRuntime.
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

    var isEmpty: Bool {
        disabled != true && deleted != true && (name ?? "").isEmpty && icon == nil && (url ?? "").isEmpty
            && (interval ?? 0) <= 0 && (filter ?? "").isEmpty && (excludeFilter ?? "").isEmpty
    }
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

    /// 恢复已删除的节点集: clears 删除 on every provider of the profile (other edits stay).
    func restoreDeleted(_ profileID: String) {
        guard var m = all[profileID] else { return }
        for (k, var v) in m where v.deleted == true {
            v.deleted = nil
            m[k] = v.isEmpty ? nil : v
        }
        all[profileID] = m.isEmpty ? nil : m
        write()
    }

    func loadDeclared(_ profile: Profile?, force: Bool = false) async {
        guard let profile else { declared = []; declaredFor = nil; return }
        let path = profile.fileURL.path
        if !force && declaredFor == path { return }
        let json = await Task.detached(priority: .userInitiated) { LibmihomoProfileProviders(AppShared.homeURL.path, path) }.value
        declared = (try? JSONDecoder().decode([ProfileProviderInfo].self, from: Data(json.utf8))) ?? []
        declaredFor = path
    }

    private func write() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(all) { try? d.write(to: Self.url, options: .atomic) }
    }
}
