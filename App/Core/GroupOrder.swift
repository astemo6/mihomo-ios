import Foundation
import Libmihomo

/// feat/group-order: the user's 策略组 order. A reorder never rewrites the profile the user imported or subscribed
/// to (user 2026-10-18: 「应该是自动复制一个配置文件出来，在复制的配置文件上更新」): the first reorder of a profile
/// writes the new order into an 自定义 copy (「<name> (自定义)」, bridge GroupOrderCopy), gives the copy the
/// source's per-profile settings and switches to it; later reorders change only the copy (bridge ReorderGroups:
/// only the proxy-groups sequence moves, comments and everything else stay, validated, atomic, previous copy kept
/// as <file>.bak). The copy's order is kept in group-edits.json ("order"); when its source subscription updates,
/// the copy is regenerated from the fresh content with that order (GroupOrderRegenerate), so the subscription
/// profile stays a pristine mirror. Groups that are not in the file (策略组编辑 new groups, merged 手动节点 /
/// node-subscription groups, __MITM__) keep their place.
@MainActor
enum GroupOrder {
    struct Result: Decodable {
        var changed: Bool?
        var order: [String]?
        var method: String?
        var error: String?
    }

    /// `saved` false = nothing written (message says why); a message with `saved` true = written, but the core
    /// reload failed. `copy` = the 自定义 copy that was created / updated and is now the active profile.
    struct SaveResult {
        var saved: Bool
        var message: String? = nil
        var copy: Profile? = nil
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

    /// Name of the 自定义 copy of `p`.
    static func copyName(of p: Profile) -> String { String(localized: "\(p.displayName) (自定义)") }

    static func hasStoredOrder(_ p: Profile) -> Bool { !(GroupEditStore.get(p.id).order ?? []).isEmpty }

    private static func decode(_ out: String) -> Result {
        (try? JSONDecoder().decode(Result.self, from: Data(out.utf8))) ?? Result(error: out)
    }

    private static func storeOrder(_ order: [String]?, for id: String) {
        var e = GroupEditStore.get(id)
        guard e.order != order else { return }
        e.order = order
        GroupEditStore.set(id, e)
    }

    /// 不再保持此顺序 on a copy: forgets the saved order; a copy of a subscription is rebuilt from the
    /// subscription right away (its own order), and later updates keep that order too.
    static func clearStoredOrder(_ p: Profile) async -> String? {
        storeOrder(nil, for: p.id)
        guard let src = ProfileStore.shared.source(of: p), src.kind == .remote else { return nil }
        let changed = await regenerate(p, from: src)
        ProfileStore.shared.objectWillChange.send()
        var msg: String?
        if changed, p.id == AppShared.activeProfileID, VPNManager.shared.isConnected,
           let m = await VPNManager.shared.reload() {
            msg = String(localized: "已保存，但重载失败：\(m)")
        }
        await ProfileInspector.shared.load()
        return msg
    }

    /// Saves `names` (display names, in the new order) for profile `p`: into `p` itself when it is an 自定义
    /// copy, otherwise into its copy (created on the first reorder), which then becomes the active profile.
    /// Reloads the core when connected and refreshes the offline view.
    static func save(_ names: [String], profile p: Profile) async -> SaveResult {
        let edits = GroupEditStore.get(p.id)
        let order = names.map { fileName(of: $0, edits: edits) }
        guard let data = try? JSONEncoder().encode(order) else { return SaveResult(saved: false) }
        let json = String(decoding: data, as: UTF8.self)
        let home = AppShared.homeURL.path
        let store = ProfileStore.shared
        SnapshotStore.shared.capture(String(localized: "排列策略组前"))

        if p.sourceID != nil {
            // Already a copy: reorder it in place.
            let path = p.fileURL.path
            let r = decode(await Task.detached(priority: .userInitiated) { LibmihomoReorderGroups(home, path, json) }.value)
            if let e = r.error, !e.isEmpty { return SaveResult(saved: false, message: GoText.localize(e)) }
            storeOrder(r.order ?? order, for: p.id)
            if r.changed == true {
                store.objectWillChange.send()
                if p.id == AppShared.activeProfileID, VPNManager.shared.isConnected,
                   let msg = await VPNManager.shared.reload() {
                    await ProfileInspector.shared.load()
                    return SaveResult(saved: true, message: String(localized: "已保存，但重载失败：\(msg)"))
                }
            }
            await ProfileInspector.shared.load()
            return SaveResult(saved: true)
        }

        // An original profile: write the order into its 自定义 copy (the existing one, or a new one).
        let existing = store.orderCopy(of: p)
        var c = existing ?? Profile(name: copyName(of: p), kind: .local)
        if existing == nil {
            c.sourceID = p.id
            c.sourceName = p.displayName
            c.userInfo = p.userInfo
            c.lastUpdated = p.lastUpdated
        }
        let src = p.fileURL.path, dst = c.fileURL.path
        let r = decode(await Task.detached(priority: .userInitiated) { LibmihomoGroupOrderCopy(home, src, dst, json) }.value)
        if let e = r.error, !e.isEmpty { return SaveResult(saved: false, message: GoText.localize(e)) }
        guard r.changed == true else { return SaveResult(saved: true) } // same order as the source: no copy needed
        if existing == nil {
            let from = p.id, to = c.id
            let err = await Task.detached(priority: .userInitiated) { LibmihomoCopyProfileSettings(home, from, to) }.value
            if !err.isEmpty { StartupLog.write("group order copy settings: \(err)", tag: "app") }
            HomeGroupsStore.copy(from: p.id, to: c.id)
            store.insertCopy(c, after: p)
        }
        storeOrder(r.order ?? order, for: c.id)
        let msg = await store.setActive(c)
        await ProfileInspector.shared.load()
        return SaveResult(saved: true, message: msg.map { String(localized: "已保存，但重载失败：\($0)") }, copy: c)
    }

    /// 置顶: moves `name` to the front of `current` and saves.
    static func moveToTop(_ name: String, current: [String], profile p: Profile) async -> SaveResult {
        guard let i = current.firstIndex(of: name), i > 0 else { return SaveResult(saved: false) }
        var n = current
        n.remove(at: i)
        n.insert(name, at: 0)
        return await save(n, profile: p)
    }

    /// After the source subscription was updated: rebuilds copy `c` from the fresh source content with the copy's
    /// saved order. Returns whether the copy file changed.
    @discardableResult
    nonisolated static func regenerate(_ c: Profile, from src: Profile) async -> Bool {
        let home = AppShared.homeURL.path, s = src.fileURL.path, d = c.fileURL.path
        let out = await Task.detached(priority: .utility) { LibmihomoGroupOrderRegenerate(home, s, d) }.value
        let r = (try? JSONDecoder().decode(Result.self, from: Data(out.utf8))) ?? Result(error: out)
        if let e = r.error, !e.isEmpty { StartupLog.write("group order regenerate: \(e)", tag: "app") }
        return r.changed == true
    }
}
