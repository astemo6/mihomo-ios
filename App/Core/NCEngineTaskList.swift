import Foundation

/// B6 (nc-dego-rest): bridge/engine.go EngineTaskList in Swift — the cron / event / generic / interaction tasks of
/// the user's scripts and enabled modules (NCMitmBuild, #112 on the #111 parser), in the user's order
/// (mitm.OrderTasks / ReorderSlots), for the 任务 list while disconnected.
enum NCEngineTaskList {

    /// home: the core home (engine/engine.json and engine/modules live under it); order: task ids from the app's
    /// task-prefs.json (TaskPrefs.order).
    static func tasks(home: String, order: [String]) -> [NCEngineTask] {
        let cfg = NCEngineConfig.load(home: home)
        let rs = NCMitmBuild.build(home: home, cfg: cfg)
        return reorderSlots(rs.tasks, key: { $0.id }, order: order)
    }

    /// mitm ReorderSlots: the items named in `order` are sorted among the positions they already occupy;
    /// everything else stays where it is; items sharing a name keep their relative order.
    static func reorderSlots<T>(_ items: [T], key: (T) -> String?, order: [String]) -> [T] {
        var out = items
        if order.isEmpty || items.count < 2 { return out }
        var rank: [String: Int] = [:]
        for (i, n) in order.enumerated() where rank[n] == nil { rank[n] = i }
        var slots: [Int] = []
        var picked: [T] = []
        var ranks: [Int] = []
        for (i, it) in items.enumerated() {
            guard let n = key(it), let r = rank[n] else { continue }
            slots.append(i)
            picked.append(it)
            ranks.append(r)
        }
        if slots.count < 2 { return out }
        // stable sort of the picked items by rank
        let idx = picked.indices.sorted { a, b in ranks[a] != ranks[b] ? ranks[a] < ranks[b] : a < b }
        for (k, s) in slots.enumerated() { out[s] = picked[idx[k]] }
        return out
    }
}
