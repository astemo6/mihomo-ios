import Foundation
import Combine

// v0.17 按节点设置 (parity #11, Shadowrocket): a latency test URL and a remark per node, kept in the app's
// own override store (node-settings.json next to overrides.json) keyed by node name. Nothing is written
// into profile files, so config write-back (editable config nodes, .bak, validation) is untouched and a
// subscription refresh keeps the settings as long as the node keeps its name. Renames done in the app
// (NameRefs.rename) move the entry; deletes drop it.
//
// The URL is used by every manual test of that node: single-node 测速 (live /proxies/{name}/delay and the
// offline LibmihomoNodeTestDelay / TestDelay paths), group 测速 (membersDelay per member, offline
// TestDelayByName per member) and for reading the node's last delay back from the core's per-URL history.
// The core's own url-test / fallback health checks keep the group's URL (they are not ours to change).

struct NodeSetting: Codable, Hashable {
    var testURL: String?
    var note: String?

    var isEmpty: Bool {
        (testURL ?? "").trimmingCharacters(in: .whitespaces).isEmpty && (note ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

final class NodeSettingsStore: ObservableObject {
    static let shared = NodeSettingsStore()

    @Published private(set) var map: [String: NodeSetting] = [:]
    private static let lock = NSLock()
    private static var cache: [String: NodeSetting] = [:]

    static var url: URL { AppShared.homeURL.appendingPathComponent("node-settings.json") }

    private init() { reload() }

    func reload() {
        var m: [String: NodeSetting] = [:]
        if let d = try? Data(contentsOf: Self.url), let v = try? JSONDecoder().decode([String: NodeSetting].self, from: d) { m = v }
        Self.lock.lock(); Self.cache = m; Self.lock.unlock()
        publish(m)
    }

    private func publish(_ m: [String: NodeSetting]) {
        if Thread.isMainThread { map = m } else { DispatchQueue.main.async { self.map = m } }
    }

    // MARK: Reads (any thread)

    static func setting(for name: String) -> NodeSetting? {
        _ = shared // loads node-settings.json once
        lock.lock(); defer { lock.unlock() }
        return cache[name]
    }

    /// The node's own test URL when it is set and valid.
    static func customURL(for name: String) -> String? {
        guard let u = setting(for: name)?.testURL?.trimmingCharacters(in: .whitespaces), !u.isEmpty,
              CoreOverrides.isValidTestURL(u) else { return nil }
        return u
    }

    /// The URL a manual test of this node uses: its own, else 更多 → 测速 (直连测试地址 for DIRECT).
    static func testURL(for name: String) -> String {
        if let u = customURL(for: name) { return u }
        if name == "DIRECT", let u = ControllerClient.directTestURL { return u }
        return ControllerClient.testSettings.url
    }

    static func note(for name: String) -> String? {
        let n = setting(for: name)?.note?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return n.isEmpty ? nil : n
    }

    // MARK: Writes

    func set(_ s: NodeSetting?, for name: String) throws {
        var m = Self.snapshot()
        if let s, !s.isEmpty {
            var c = s
            c.testURL = c.testURL?.trimmingCharacters(in: .whitespaces)
            if c.testURL?.isEmpty == true { c.testURL = nil }
            c.note = c.note?.trimmingCharacters(in: .whitespacesAndNewlines)
            if c.note?.isEmpty == true { c.note = nil }
            m[name] = c
        } else {
            m.removeValue(forKey: name)
        }
        try write(m)
    }

    /// Follows a node rename / delete made in the app (new == nil → removed).
    func rename(_ old: String, to new: String?) {
        var m = Self.snapshot()
        guard let s = m.removeValue(forKey: old) else { return }
        if let new, !new.isEmpty, m[new] == nil { m[new] = s }
        try? write(m)
    }

    private static func snapshot() -> [String: NodeSetting] {
        _ = shared
        lock.lock(); defer { lock.unlock() }
        return cache
    }

    private func write(_ m: [String: NodeSetting]) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(m).write(to: Self.url, options: .atomic)
        Self.lock.lock(); Self.cache = m; Self.lock.unlock()
        publish(m)
    }
}
