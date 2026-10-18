import Foundation
import CryptoKit

// v0.10 配置快照: before an import, edit, update, delete or restore the app saves the user's
// configuration files (the same set as a backup, without the MitM CA) into <container>/snapshots.
// Identical states are not saved twice. A snapshot can be compared with the current state and restored.

struct SnapshotMeta: Codable, Identifiable, Hashable {
    var id: String
    var date: Date
    var reason: String
    var files: Int
    var bytes: Int
    var hash: String
    var pinned: Bool = false
}

struct SnapshotDiff {
    struct FileChange: Identifiable {
        enum Kind { case added, removed, changed }
        var path: String
        var title: String
        var kind: Kind
        var plus = 0
        var minus = 0
        var id: String { path }
    }
    var changes: [FileChange] = []
    var isEmpty: Bool { changes.isEmpty }
}

@MainActor
final class SnapshotStore: ObservableObject {
    static let shared = SnapshotStore()

    @Published private(set) var list: [SnapshotMeta] = []
    @Published var autoEnabled: Bool {
        didSet { AppShared.defaults.set(!autoEnabled, forKey: "snapshots.disabled") }
    }

    static let maxCount = 20
    static let maxBytes = 40 << 20

    var dir: URL { AppShared.ensureDir(AppShared.containerURL.appendingPathComponent("snapshots", isDirectory: true)) }
    private var indexURL: URL { dir.appendingPathComponent("index.json") }
    func fileURL(_ id: String) -> URL { dir.appendingPathComponent("\(id).json") }

    init() {
        autoEnabled = !AppShared.defaults.bool(forKey: "snapshots.disabled")
        load()
    }

    func load() {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        if let d = try? Data(contentsOf: indexURL), let l = try? dec.decode([SnapshotMeta].self, from: d) {
            list = l.sorted { $0.date > $1.date }
        }
    }

    private func persist() {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        if let d = try? enc.encode(list) { try? d.write(to: indexURL, options: .atomic) }
    }

    var totalBytes: Int { list.reduce(0) { $0 + $1.bytes } }

    // MARK: Capture

    /// The user's configuration right now: container-relative path → content.
    nonisolated static func currentFiles() -> [String: Data] {
        let root = AppShared.containerURL
        let fm = FileManager.default
        var out: [String: Data] = [:]
        for rel in BackupManager.items(includeCA: false) {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                for n in (try? fm.contentsOfDirectory(atPath: u.path)) ?? [] where !n.hasPrefix(".") {
                    let f = u.appendingPathComponent(n)
                    var sub: ObjCBool = false
                    if fm.fileExists(atPath: f.path, isDirectory: &sub), !sub.boolValue, let d = try? Data(contentsOf: f) {
                        out[rel + "/" + n] = d
                    }
                }
            } else if let d = try? Data(contentsOf: u) {
                out[rel] = d
            }
        }
        return out
    }

    nonisolated static func hash(_ files: [String: Data]) -> String {
        var h = SHA256()
        for k in files.keys.sorted() {
            h.update(data: Data(k.utf8))
            h.update(data: Data([0]))
            h.update(data: files[k] ?? Data())
            h.update(data: Data([0]))
        }
        return h.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Saves a snapshot unless automatic snapshots are off (manual ones always save) or nothing changed
    /// since the newest snapshot. Returns the snapshot, or nil when skipped.
    @discardableResult
    func capture(_ reason: String, manual: Bool = false) -> SnapshotMeta? {
        guard manual || autoEnabled else { return nil }
        let files = Self.currentFiles()
        guard !files.isEmpty else { return nil }
        let h = Self.hash(files)
        if let newest = list.first, newest.hash == h { return nil }
        var b = BackupFile()
        b.files = files.mapValues { $0.base64EncodedString() }
        if let v = AppShared.defaults.string(forKey: "activeProfileID") { b.defaults["activeProfileID"] = v }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        guard let data = try? enc.encode(b) else { return nil }
        let id = String(Int(Date().timeIntervalSince1970 * 1000))
        guard (try? data.write(to: fileURL(id), options: .atomic)) != nil else { return nil }
        let meta = SnapshotMeta(id: id, date: Date(), reason: reason, files: files.count, bytes: data.count, hash: h)
        list.insert(meta, at: 0)
        prune()
        persist()
        return meta
    }

    /// Keeps at most maxCount snapshots and maxBytes on disk; pinned snapshots are never removed.
    private func prune() {
        var total = 0
        var keep: [SnapshotMeta] = []
        var unpinned = 0
        for m in list {
            if m.pinned { keep.append(m); total += m.bytes; continue }
            if unpinned < Self.maxCount && (total + m.bytes <= Self.maxBytes || keep.isEmpty) {
                keep.append(m); total += m.bytes; unpinned += 1
            } else {
                try? FileManager.default.removeItem(at: fileURL(m.id))
            }
        }
        list = keep
    }

    func delete(_ m: SnapshotMeta) {
        try? FileManager.default.removeItem(at: fileURL(m.id))
        list.removeAll { $0.id == m.id }
        persist()
    }

    /// Deletes all but the newest `keep` unpinned snapshots. Returns freed bytes.
    @discardableResult
    func deleteOld(keep: Int) -> Int {
        var freed = 0
        var n = 0
        for m in list where !m.pinned {
            n += 1
            if n > keep { freed += m.bytes; try? FileManager.default.removeItem(at: fileURL(m.id)); list.removeAll { $0.id == m.id } }
        }
        persist()
        return freed
    }

    func togglePin(_ m: SnapshotMeta) {
        guard let i = list.firstIndex(where: { $0.id == m.id }) else { return }
        list[i].pinned.toggle()
        persist()
    }

    func files(of m: SnapshotMeta) -> [String: Data]? {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        guard let d = try? Data(contentsOf: fileURL(m.id)), let b = try? dec.decode(BackupFile.self, from: d) else { return nil }
        return b.files.compactMapValues { Data(base64Encoded: $0) }
    }

    // MARK: Diff

    /// Readable name for a container-relative path (profile names from the snapshot's or the current index).
    static func title(_ path: String, names: [String: String]) -> String {
        if path.hasPrefix("profiles/") {
            let id = (path as NSString).lastPathComponent.replacingOccurrences(of: ".yaml", with: "")
            return String(localized: "配置「\(names[id] ?? id)」")
        }
        let known: [String: String] = [
            "profiles.json": String(localized: "配置列表"),
            "mihomo/overrides.json": String(localized: "内核设置"),
            "mihomo/dns.json": "DNS",
            "mihomo/localdns.json": String(localized: "本地 DNS 映射"),
            "mihomo/group-icons.json": String(localized: "策略组图标"),
            "mihomo/rules.json": String(localized: "自定义规则"),
            "mihomo/subscriptions.json": String(localized: "订阅处理"),
            "mihomo/groups.json": String(localized: "智能选择"),
            "mihomo/netpolicy.json": String(localized: "按网络切换策略"),
            "mihomo/node-subscriptions.json": String(localized: "节点订阅"),
            "mihomo/group-edits.json": String(localized: "策略组编辑"),
            "mihomo/engine/engine.json": String(localized: "MitM / 重写设置"),
            "mihomo/engine/store.json": String(localized: "脚本存储"),
        ]
        if let k = known[path] { return k }
        if path.hasPrefix("mihomo/engine/modules/") { return String(localized: "模块 \((path as NSString).lastPathComponent)") }
        if path.hasPrefix("mihomo/engine/scripts/") { return String(localized: "脚本 \((path as NSString).lastPathComponent)") }
        return path
    }

    static func profileNames(_ files: [String: Data]) -> [String: String] {
        guard let d = files["profiles.json"], let l = try? JSONDecoder().decode([Profile].self, from: d) else { return [:] }
        return Dictionary(l.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
    }

    /// Line counts added / removed between two texts (multiset of lines; good enough for a summary).
    nonisolated static func lineDelta(_ a: Data, _ b: Data) -> (plus: Int, minus: Int) {
        let la = String(decoding: a, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
        let lb = String(decoding: b, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
        var count: [Substring: Int] = [:]
        for l in la { count[l, default: 0] += 1 }
        var plus = 0
        for l in lb {
            if let c = count[l], c > 0 { count[l] = c - 1 } else { plus += 1 }
        }
        let minus = count.values.reduce(0, +)
        return (plus, minus)
    }

    /// What restoring `m` would change compared to the current files (from = current, to = snapshot).
    func diff(_ m: SnapshotMeta) -> SnapshotDiff? {
        guard let snap = files(of: m) else { return nil }
        let cur = Self.currentFiles()
        var names = Self.profileNames(cur)
        names.merge(Self.profileNames(snap)) { a, _ in a }
        var out = SnapshotDiff()
        for path in Set(cur.keys).union(snap.keys).sorted() {
            let t = Self.title(path, names: names)
            switch (cur[path], snap[path]) {
            case (nil, let s?):
                out.changes.append(.init(path: path, title: t, kind: .added, plus: Self.lineDelta(Data(), s).plus))
            case (let c?, nil):
                // Restore writes files only; a file that is not in the snapshot stays (shown for information).
                out.changes.append(.init(path: path, title: t, kind: .removed, minus: Self.lineDelta(c, Data()).minus))
            case (let c?, let s?) where c != s:
                let d = Self.lineDelta(c, s)
                out.changes.append(.init(path: path, title: t, kind: .changed, plus: d.plus, minus: d.minus))
            default: break
            }
        }
        return out
    }

    // MARK: Restore

    /// Saves the current state first ("恢复前"), then writes the snapshot's files and reloads the stores.
    func restore(_ m: SnapshotMeta) throws -> Int {
        guard let d = try? Data(contentsOf: fileURL(m.id)) else {
            throw NSError(domain: "Snapshot", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "快照文件不存在")])
        }
        capture(String(localized: "恢复快照前"), manual: true)
        let n = try BackupManager.restore(d)
        Self.reloadStores()
        return n
    }

    static func reloadStores() {
        let store = ProfileStore.shared
        store.load()
        store.activeID = AppShared.activeProfileID
        EngineStore.shared.config = EngineConfig.load()
        EngineStore.shared.reparseModules()
        CustomRulesStore.shared.load()
        // v0.19.1: override scripts are part of a snapshot / backup (override-scripts/index.json). Without this
        // the store kept the pre-restore list and its next save wrote that list over the restored index.
        OverrideScriptStore.shared.load()
        Task { if VPNManager.shared.isConnected { _ = await VPNManager.shared.reload() } }
    }
}
