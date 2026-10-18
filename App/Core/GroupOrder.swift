import Foundation
import Libmihomo

/// feat/group-order: the user's 策略组 order. The order is written into the active profile file itself
/// (bridge ReorderGroups: only the proxy-groups sequence moves, comments and everything else stay, validated,
/// atomic, previous file kept as <file>.bak). Groups that are not in the file (策略组编辑 new groups, merged
/// 手动节点 / node-subscription groups, __MITM__) keep their place. A subscription profile is overwritten on every
/// update, so its order is also kept in group-edits.json ("order") and re-applied after each download.
@MainActor
enum GroupOrder {
    struct Result: Decodable {
        var changed: Bool?
        var order: [String]?
        var method: String?
        var error: String?
    }

    /// Group names written in the profile file (the ones that can move).
    nonisolated static func fileNames(_ p: Profile) -> [String] {
        let json = LibmihomoProfileGroupNames(p.fileURL.path)
        return (try? JSONDecoder().decode([String].self, from: Data(json.utf8))) ?? []
    }

    /// Display name → name in the file, for groups renamed in 策略组编辑.
    static func fileName(of display: String, edits: GroupEdits) -> String {
        for (orig, e) in edits.edits ?? [:] where e.spec?.name == display && e.deleted != true { return orig }
        return display
    }

    /// Display name of a file group (after a 策略组编辑 rename).
    static func displayName(of file: String, edits: GroupEdits) -> String {
        if let n = edits.edits?[file]?.spec?.name, !n.trimmingCharacters(in: .whitespaces).isEmpty { return n }
        return file
    }

    static func hasStoredOrder(_ p: Profile) -> Bool { !(GroupEditStore.get(p.id).order ?? []).isEmpty }

    static func clearStoredOrder(_ p: Profile) {
        var e = GroupEditStore.get(p.id)
        e.order = nil
        GroupEditStore.set(p.id, e)
    }

    /// Saves `names` (display names, in the new order) for profile `p`, reloads the core when connected and
    /// refreshes the offline view. `saved` false = nothing written (message says why); a message with
    /// `saved` true = written, but the core reload failed.
    static func save(_ names: [String], profile p: Profile) async -> (saved: Bool, message: String?) {
        var edits = GroupEditStore.get(p.id)
        let order = names.map { fileName(of: $0, edits: edits) }
        guard let data = try? JSONEncoder().encode(order) else { return (false, nil) }
        let json = String(decoding: data, as: UTF8.self)
        let home = AppShared.homeURL.path, path = p.fileURL.path
        SnapshotStore.shared.capture(String(localized: "排列策略组前"))
        let out = await Task.detached(priority: .userInitiated) { LibmihomoReorderGroups(home, path, json) }.value
        let r = (try? JSONDecoder().decode(Result.self, from: Data(out.utf8))) ?? Result(error: out)
        if let e = r.error, !e.isEmpty { return (false, GoText.localize(e)) }
        if p.kind == .remote {
            let keep = r.order ?? order
            if edits.order != keep {
                edits.order = keep
                GroupEditStore.set(p.id, edits)
            }
        } else if edits.order != nil {
            edits.order = nil
            GroupEditStore.set(p.id, edits)
        }
        if r.changed == true {
            ProfileStore.shared.objectWillChange.send()
            if p.id == AppShared.activeProfileID, VPNManager.shared.isConnected,
               let msg = await VPNManager.shared.reload() {
                await ProfileInspector.shared.load()
                return (true, String(localized: "已保存，但重载失败：\(msg)"))
            }
        }
        await ProfileInspector.shared.load()
        return (true, nil)
    }

    /// 置顶: moves `name` to the front of `current` and saves.
    static func moveToTop(_ name: String, current: [String], profile p: Profile) async -> (saved: Bool, message: String?) {
        guard let i = current.firstIndex(of: name), i > 0 else { return (false, nil) }
        var n = current
        n.remove(at: i)
        n.insert(name, at: 0)
        return await save(n, profile: p)
    }

    /// After a subscription download replaced the file: puts the stored order back (no-op without one).
    nonisolated static func reapply(_ p: Profile) async {
        let home = AppShared.homeURL.path, path = p.fileURL.path
        let out = await Task.detached(priority: .utility) { LibmihomoGroupOrderReapply(home, path) }.value
        if let r = try? JSONDecoder().decode(Result.self, from: Data(out.utf8)), let e = r.error, !e.isEmpty {
            StartupLog.write("group order reapply: \(e)", tag: "app")
        }
    }
}
