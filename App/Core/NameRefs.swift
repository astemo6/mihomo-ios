import Foundation
import Libmihomo

/// v0.15.4: a node or group renamed / deleted in 节点管理 or 筛选节点 is also renamed in what the app keeps
/// outside the profile file: 策略组编辑 (group-edits.json), 按网络切换策略 (netpolicy.json), Home cards,
/// 智能选择 (groups.json) and, while connected, the core's current selections.
@MainActor
enum NameRefs {
    /// `new == nil` removes the references (a deleted node).
    static func rename(_ old: String, to new: String?, profileID: String, isGroup: Bool) {
        // v0.17 按节点设置 (test URL, remark) follow the node.
        if !isGroup { NodeSettingsStore.shared.rename(old, to: new) }
        // 策略组编辑
        var e = GroupEditStore.get(profileID)
        func fix(_ s: inout GroupSpec) {
            if isGroup, s.name == old, let new { s.name = new }
            s.proxies = s.proxies.compactMap { $0 == old ? new : $0 }
        }
        if var edits = e.edits {
            for k in Array(edits.keys) {
                guard var ed = edits[k] else { continue }
                if var sp = ed.spec { fix(&sp); ed.spec = sp }
                if isGroup, k == old, let new { edits.removeValue(forKey: k); edits[new] = ed } else { edits[k] = ed }
            }
            e.edits = edits
        }
        if var added = e.added {
            for i in added.indices { fix(&added[i]) }
            e.added = added
        }
        GroupEditStore.set(profileID, e)

        // 按网络切换策略
        var all = NetworkPolicyStore.loadAll()
        if var rules = all[profileID] {
            for i in rules.indices {
                if isGroup, rules[i].group == old, let new { rules[i].group = new }
                if rules[i].wifi == old { rules[i].wifi = new }
                if rules[i].cellular == old { rules[i].cellular = new }
                if let s = rules[i].ssids {
                    var m: [String: String] = [:]
                    for (k, v) in s { if v == old { if let new { m[k] = new } } else { m[k] = v } }
                    rules[i].ssids = m.isEmpty ? nil : m
                }
            }
            all[profileID] = rules
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let d = try? enc.encode(all) { try? d.write(to: NetworkPolicyStore.url, options: .atomic) }
        }

        guard isGroup else { return }
        // Home cards
        if let saved = HomeGroupsStore.saved(profile: profileID), saved.contains(old) {
            HomeGroupsStore.shared.set(saved.compactMap { $0 == old ? new : $0 }, profile: profileID)
        }
        // 智能选择
        if AppShared.activeProfileID == profileID, SmartGroups.shared.isSmart(old) {
            SmartGroups.shared.set(old, smart: false)
            if let new { SmartGroups.shared.set(new, smart: true) }
        }
    }

    /// Groups whose current member is `old` (read before a reload, re-selected with the new name after).
    static func selectionsUsing(_ old: String) async -> [String] {
        guard VPNManager.shared.isConnected, let p = try? await ControllerClient.shared.proxies() else { return [] }
        return p.filter { $0.value.isGroup && $0.value.now == old }.map(\.key)
    }

    static func reselect(_ groups: [String], _ new: String) async {
        for g in groups { try? await ControllerClient.shared.select(group: g, node: new) }
    }
}
