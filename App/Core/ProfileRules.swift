import Foundation

// 规则 → 本地规则 → 配置规则 and 规则 → Final (user 2026-10-23 「本地规则点进去无法修改」「Final 指向无法修改」).
// The profile's own rules come from bridge ProfileRules (the profile as the runtime build starts from it, with the
// user's overrides from provider-overrides.json `#profile-rules` / `#final`); the edits are stored through
// ProviderOverrideStore and applied by bridge/profileruleoverrides.go. The profile file is never rewritten.

/// One rule of the profile (bridge profileRuleItem).
struct ProfileRuleItem: Decodable, Hashable, Identifiable {
    var position: Int
    /// Override key: the rule's text and which occurrence of it this is.
    var rule: String
    var index: Int
    var original: String
    /// What the editor opens: the user's edit, else the original.
    var line: String
    var edited: Bool?
    var disabled: Bool?
    var deleted: Bool?
    /// The edit could not be used (the original stays in the runtime).
    var error: String?
    var type: String
    var payload: String
    var proxy: String
    var options: String?

    var id: Int { position }
    var isEdited: Bool { edited == true }
    var isDisabled: Bool { disabled == true }
    var isDeleted: Bool { deleted == true }
    var isModified: Bool { isEdited || isDisabled || isDeleted }
}

struct ProfileFinalInfo: Decodable, Hashable {
    var policy: String = ""
    var original: String = ""
    var edited: Bool? = nil
}

private struct ProfileRulesResult: Decodable {
    var rules: [ProfileRuleItem] = []
    var finalInfo: ProfileFinalInfo = ProfileFinalInfo()
    var stale: Int = 0
    var error: String? = nil
}

@MainActor
final class ProfileRulesStore: ObservableObject {
    static let shared = ProfileRulesStore()

    @Published private(set) var items: [ProfileRuleItem] = []
    @Published private(set) var finalInfo = ProfileFinalInfo()
    /// Saved overrides whose rule the profile no longer has.
    @Published private(set) var stale = 0
    @Published private(set) var error: String?
    @Published private(set) var loaded = false
    private var seq = 0

    var deletedCount: Int { items.filter(\.isDeleted).count }
    var modifiedCount: Int { items.filter(\.isModified).count + stale }

    /// Reads the profile off the main thread (a large profile takes a moment to parse).
    func load() async {
        seq += 1
        let mine = seq
        guard let path = AppShared.activeProfileURL?.path else {
            items = []; finalInfo = ProfileFinalInfo(); stale = 0; error = nil; loaded = true
            return
        }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .userInitiated) { NCProfileRulesPort.profileRules(home: home, profilePath: path) }.value
        guard mine == seq else { return }
        let r = (try? JSONDecoder().decode(ProfileRulesResult.self, from: Data(json.utf8))) ?? ProfileRulesResult()
        items = r.rules
        finalInfo = r.finalInfo
        stale = r.stale
        error = (r.error ?? "").isEmpty ? nil : r.error
        loaded = true
    }
}

/// The targets a rule can send traffic to, for the policy pickers of 配置规则 and Final: the profile's groups (live
/// order when connected), the built-in policies, and the profile's own nodes (a rule cannot name a node that only a
/// 节点集 / subscription provides — the core checks rule targets before providers load).
struct PolicyTargets: Equatable {
    var groups: [String] = []
    var builtins: [String] = PolicyTargets.builtinNames
    var nodes: [String] = []

    static let builtinNames = ["DIRECT", "REJECT", "REJECT-DROP"]

    var all: [String] { groups + builtins + nodes }

    @MainActor
    static func load() async -> PolicyTargets {
        var groups: [String] = []
        if VPNManager.shared.isConnected, let p = try? await ControllerClient.shared.proxies() {
            groups = LiveGroupOrder.names(p).filter { p[$0]?.isGroup == true && p[$0]?.hidden != true && $0 != "GLOBAL" }
        }
        let offline = ProfileInspector.shared
        if offline.result.groups.isEmpty && offline.result.proxies.isEmpty { await offline.load() }
        if groups.isEmpty {
            groups = offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name)
        }
        let skip = Set(groups).union(ManagedNode.hidden)
        var seen = Set<String>()
        let nodes = offline.result.proxies.map(\.name).filter { !skip.contains($0) && !$0.hasPrefix("__") && seen.insert($0).inserted }
        return PolicyTargets(groups: groups, nodes: nodes)
    }
}
