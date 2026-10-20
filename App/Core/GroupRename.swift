import Foundation
import Libmihomo

/// v0.19.8: everything outside group-edits.json that names a policy group, moved in one place when a group is
/// renamed — from 策略组编辑 (profile groups and added groups alike) and from 筛选节点 (a filter that is a 策略组).
/// Device report: renaming in those editors left the old name in other places, so the group looked unrenamed.
@MainActor
enum GroupRename {
    /// Call after the edit set holding the new name was saved. `inFile`: the group is one of the profile's own
    /// groups (bridge applyGroupEdits renames its members / rules at runtime); otherwise (an added group) the
    /// profile file's references to the old name are rewritten. Returns an error text or nil.
    static func propagate(old: String, new: String, profile p: Profile, inFile: Bool) async -> String? {
        guard old != new, !old.isEmpty, !new.isEmpty else { return nil }
        // Other edited / added groups that list it, 按网络切换策略, Home cards, 智能选择.
        NameRefs.rename(old, to: new, profileID: p.id, isGroup: true)
        // 策略 → 更换图标 / 筛选节点 flag.
        GroupIconStore.shared.rename(old, to: new)
        // Offline selection made for the old name (applied by the core on the next connect).
        if let sel = ProfileInspector.shared.result.selected[old] {
            _ = LibmihomoSaveSelection(p.fileURL.path, new, sel)
        }
        guard !inFile else { return nil }
        let path = p.fileURL.path, home = AppShared.homeURL.path
        let err = await Task.detached(priority: .userInitiated) { LibmihomoProfileRenameRefs(home, path, old, new) }.value
        return err.isEmpty ? nil : err
    }
}
