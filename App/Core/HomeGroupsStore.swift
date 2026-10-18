import Foundation

/// feat/home-groups: which policy groups the Home cards show, chosen by the user, per profile.
///
/// - Stored in the App Group defaults under `home.groups.<profile id>` as an ordered list of group names.
/// - No entry = the default (the first `defaultCount` non-hidden groups, the behaviour before this feature),
///   so existing users see no change until they edit.
/// - An empty list = the user unchecked everything: the Home section is hidden.
/// - Names that are no longer in the profile are skipped silently. When none of the saved names exist any
///   more (e.g. the groups were renamed), Home falls back to the default fill.
@MainActor
final class HomeGroupsStore: ObservableObject {
    static let shared = HomeGroupsStore()
    static let maxCount = 12
    static let defaultCount = 4
    private static let prefix = "home.groups."

    /// Bumped on every change so Home / the dashboard recompute.
    @Published private(set) var revision = 0

    nonisolated static var activeKey: String { AppShared.activeProfileID ?? "default" }

    nonisolated static func saved(profile: String = activeKey) -> [String]? {
        AppShared.defaults.stringArray(forKey: prefix + profile)
    }

    /// true when the user has edited the selection for this profile.
    func isCustom(profile: String = activeKey) -> Bool { Self.saved(profile: profile) != nil }

    /// The groups to show, in order. `available` = the non-hidden top-level groups in profile / GLOBAL order.
    nonisolated static func resolve(saved: [String]?, available: [String]) -> [String] {
        guard let saved else { return Array(available.prefix(defaultCount)) }
        if saved.isEmpty { return [] }
        let known = Set(available)
        var seen = Set<String>()
        let kept = saved.filter { known.contains($0) && seen.insert($0).inserted }
        if kept.isEmpty { return Array(available.prefix(defaultCount)) }
        return Array(kept.prefix(maxCount))
    }

    func resolved(available: [String], profile: String = activeKey) -> [String] {
        Self.resolve(saved: Self.saved(profile: profile), available: available)
    }

    /// nil = back to the default.
    func set(_ names: [String]?, profile: String = activeKey) {
        let key = Self.prefix + profile
        if let names {
            var seen = Set<String>()
            let clean = names.filter { !$0.isEmpty && seen.insert($0).inserted }
            AppShared.defaults.set(Array(clean.prefix(Self.maxCount)), forKey: key)
        } else {
            AppShared.defaults.removeObject(forKey: key)
        }
        revision += 1
        if VPNManager.shared.isConnected {
            Task { await DashboardModel.shared.refreshSelectedNode() }
        }
    }

    /// 从首页移除: the shown list minus `name` (materialises the default the first time).
    func remove(_ name: String, available: [String]) {
        var cur = resolved(available: available)
        cur.removeAll { $0 == name }
        set(cur)
    }

    /// Called when a profile is deleted.
    /// feat/group-order: an 自定义 copy starts with its source's Home selection.
    nonisolated static func copy(from: String, to: String) {
        guard let v = AppShared.defaults.stringArray(forKey: prefix + from), AppShared.defaults.object(forKey: prefix + to) == nil else { return }
        AppShared.defaults.set(v, forKey: prefix + to)
    }

    nonisolated static func forget(profile: String) {
        AppShared.defaults.removeObject(forKey: prefix + profile)
    }
}
