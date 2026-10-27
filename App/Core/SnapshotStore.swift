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
        return h.finalize().ncHex
    }

    // MARK: v0.19.8 dedupe
    //
    // Device report: three identical 「编辑策略组前」 snapshots in the same minute. Two causes: (1) each save in the
    // group editor captures again, and the file it just wrote (group-edits.json) makes the next state differ, so
    // every save in a row became a snapshot of its own; (2) JSONEncoder writes dictionaries in a per-launch random
    // key order and some stores stamp times / usage counters, so the raw bytes of an unchanged configuration
    // differ and the raw-byte hash never matched. Now the comparison hash covers only what the user configured
    // (JSON re-serialized with sorted keys, volatile keys and files left out), and a capture with the same reason
    // within `coalesceWindow` of the newest snapshot is skipped: that snapshot already holds the state before the
    // first edit of the series.

    static let coalesceWindow: TimeInterval = 60

    /// Files that change on their own (live order, caches, logs, the scripts' key-value store).
    nonisolated static func isVolatile(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent.lowercased()
        if name == "runtime-groups.json" || name.hasSuffix(".log") || name.contains("cache") { return true }
        if path.contains("/logs/") || path.hasPrefix("logs/") { return true }
        return path == "tern/engine/store.json"
    }

    /// JSON keys that are timestamps or counters, not configuration.
    nonisolated static let volatileKeys: Set<String> = ["lastUpdated", "updatedAt", "lastUsed", "lastChecked", "lastRun", "lastFetched", "timestamp", "userInfo"]

    nonisolated static func normalizedJSON(_ obj: Any) -> Any {
        if let d = obj as? [String: Any] {
            var out: [String: Any] = [:]
            for (k, v) in d where !volatileKeys.contains(k) { out[k] = normalizedJSON(v) }
            return out
        }
        if let a = obj as? [Any] { return a.map(normalizedJSON) }
        return obj
    }

    /// Hash of what the user configured: volatile files skipped, JSON files compared by content (sorted keys,
    /// volatile keys dropped), other files by bytes.
    nonisolated static func contentHash(_ files: [String: Data]) -> String {
        var norm: [String: Data] = [:]
        for (k, v) in files where !isVolatile(k) {
            if k.hasSuffix(".json"), let obj = try? JSONSerialization.jsonObject(with: v, options: [.fragmentsAllowed]),
               let d = try? JSONSerialization.data(withJSONObject: normalizedJSON(obj), options: [.sortedKeys, .fragmentsAllowed]) {
                norm[k] = d
            } else {
                norm[k] = v
            }
        }
        return hash(norm)
    }

    /// true when a new automatic capture should be skipped.
    nonisolated static func shouldSkip(newest: SnapshotMeta?, reason: String, contentHash h: String, manual: Bool, now: Date = Date()) -> Bool {
        guard let newest else { return false }
        if newest.hash == h { return true }
        return !manual && newest.reason == reason && now.timeIntervalSince(newest.date) < coalesceWindow && now >= newest.date
    }

    /// Saves a snapshot unless automatic snapshots are off (manual ones always save), nothing the user configured
    /// changed since the newest snapshot, or the newest has the same reason and is under a minute old.
    /// Returns the snapshot, or nil when skipped.
    @discardableResult
    func capture(_ reason: String, manual: Bool = false) -> SnapshotMeta? {
        guard manual || autoEnabled else { return nil }
        let files = Self.currentFiles()
        guard !files.isEmpty else { return nil }
        let h = Self.contentHash(files)
        if Self.shouldSkip(newest: list.first, reason: reason, contentHash: h, manual: manual) { return nil }
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

    /// Review 5 P2-13: the same as capture(_:manual:), with the file reads, hashing, encoding and the write
    /// off the main actor (seconds on big profiles). Only the index update runs on main.
    @discardableResult
    func captureAsync(_ reason: String, manual: Bool = false) async -> SnapshotMeta? {
        guard manual || autoEnabled else { return nil }
        let newest = list.first
        let active = AppShared.defaults.string(forKey: "activeProfileID")
        let dir = self.dir
        let made = await Task.detached(priority: .userInitiated) { () -> SnapshotMeta? in
            let files = SnapshotStore.currentFiles()
            guard !files.isEmpty else { return nil }
            let h = SnapshotStore.contentHash(files)
            if SnapshotStore.shouldSkip(newest: newest, reason: reason, contentHash: h, manual: manual) { return nil }
            var b = BackupFile()
            b.files = files.mapValues { $0.base64EncodedString() }
            if let active { b.defaults["activeProfileID"] = active }
            let enc = JSONEncoder()
            enc.dateEncodingStrategy = .iso8601
            guard let data = try? enc.encode(b) else { return nil }
            let id = String(Int(Date().timeIntervalSince1970 * 1000))
            guard (try? data.write(to: dir.appendingPathComponent("\(id).json"), options: .atomic)) != nil else { return nil }
            return SnapshotMeta(id: id, date: Date(), reason: reason, files: files.count, bytes: data.count, hash: h)
        }.value
        guard let meta = made else { return nil }
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

    /// v0.19.8 配置快照 multi-select: deletes the given snapshots (pinned ones too: the page warns first).
    /// Returns the freed bytes.
    @discardableResult
    func delete(ids: Set<String>) -> Int {
        var freed = 0
        for m in list where ids.contains(m.id) {
            freed += m.bytes
            try? FileManager.default.removeItem(at: fileURL(m.id))
        }
        list.removeAll { ids.contains($0.id) }
        persist()
        return freed
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
        return Self.decodedFiles(b)
    }

    /// The snapshot's files by current path (snapshots taken before the rename keep the old storage dir in their
    /// keys; mapped so a diff compares like with like instead of listing every settings file as removed + added).
    nonisolated static func decodedFiles(_ b: BackupFile) -> [String: Data] {
        var out: [String: Data] = [:]
        for (k, v) in b.files { if let d = Data(base64Encoded: v) { out[LegacyImport.mapPath(k)] = d } }
        return out
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
            "tern/overrides.json": String(localized: "内核设置"),
            "tern/dns.json": "DNS",
            "tern/localdns.json": String(localized: "本地 DNS 映射"),
            "tern/group-icons.json": String(localized: "策略组图标"),
            "tern/rules.json": String(localized: "自定义规则"),
            "tern/subscriptions.json": String(localized: "订阅处理"),
            "tern/groups.json": String(localized: "智能选择"),
            "tern/netpolicy.json": String(localized: "按网络切换策略"),
            "tern/node-subscriptions.json": String(localized: "节点订阅"),
            "tern/group-edits.json": String(localized: "策略组编辑"),
            "tern/provider-overrides.json": String(localized: "节点集设置"),
            "tern/engine/engine.json": String(localized: "MitM / 重写设置"),
            "tern/engine/store.json": String(localized: "脚本存储"),
            "tern/secrets.json": String(localized: "密钥与密码"), // r7 B01
            "tern/node-settings.json": String(localized: "节点设置"), // r7 R7A-11
        ]
        if let k = known[path] { return k }
        if path.hasPrefix("tern/engine/modules/") { return String(localized: "模块 \((path as NSString).lastPathComponent)") }
        if path.hasPrefix("tern/engine/scripts/") { return String(localized: "脚本 \((path as NSString).lastPathComponent)") }
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

    /// Review 5 P2-13: diff(_:) with the decode and the line diffs off the main actor (a snapshot can be up to
    /// the 40 MB cap). Titles are filled in on main.
    func diffAsync(_ m: SnapshotMeta) async -> SnapshotDiff? {
        let url = fileURL(m.id)
        typealias Raw = (path: String, kind: SnapshotDiff.FileChange.Kind, plus: Int, minus: Int)
        let r = await Task.detached(priority: .userInitiated) { () -> (raw: [Raw], cur: [String: Data], snap: [String: Data])? in
            let dec = JSONDecoder()
            dec.dateDecodingStrategy = .iso8601
            guard let d = try? Data(contentsOf: url), let b = try? dec.decode(BackupFile.self, from: d) else { return nil }
            let snap = SnapshotStore.decodedFiles(b)
            let cur = SnapshotStore.currentFiles()
            var raw: [Raw] = []
            for path in Set(cur.keys).union(snap.keys).sorted() {
                switch (cur[path], snap[path]) {
                case (nil, let s?): raw.append((path, SnapshotDiff.FileChange.Kind.added, SnapshotStore.lineDelta(Data(), s).plus, 0))
                case (let c?, nil): raw.append((path, SnapshotDiff.FileChange.Kind.removed, 0, SnapshotStore.lineDelta(c, Data()).minus))
                case (let c?, let s?) where c != s:
                    let dl = SnapshotStore.lineDelta(c, s)
                    raw.append((path, SnapshotDiff.FileChange.Kind.changed, dl.plus, dl.minus))
                default: break
                }
            }
            // Only profiles.json is needed for the names.
            return (raw, cur.filter { $0.key == "profiles.json" }, snap.filter { $0.key == "profiles.json" })
        }.value
        guard let r else { return nil }
        var names = Self.profileNames(r.cur)
        names.merge(Self.profileNames(r.snap)) { a, _ in a }
        var out = SnapshotDiff()
        out.changes = r.raw.map { .init(path: $0.path, title: Self.title($0.path, names: names), kind: $0.kind, plus: $0.plus, minus: $0.minus) }
        return out
    }

    /// Review 5 P2-13: restore(_:) with the capture and the file writes off the main actor.
    func restoreAsync(_ m: SnapshotMeta) async throws -> Int {
        let url = fileURL(m.id)
        guard let d = await Task.detached(priority: .userInitiated, operation: { try? Data(contentsOf: url) }).value else {
            throw NSError(domain: "Snapshot", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "快照文件不存在")])
        }
        await captureAsync(String(localized: "恢复快照前"), manual: true)
        let n = try await Task.detached(priority: .userInitiated) { try BackupManager.restore(d) }.value
        Self.reloadStores()
        return n
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

    /// r7 (review7 R7A-1): how each backup / snapshot / sync item reaches the app after a restore. Every in-memory
    /// store that caches one of these files and writes its whole list back MUST be reloaded in reloadStores(),
    /// otherwise its next save silently undoes the restore (v0.19.1 override scripts, r7 node subscriptions /
    /// 节点集设置 / 智能选择 / group icons). UnitTests ReloadCoverageTests fails on any item missing here.
    static let reloadCoverage: [String: String] = [
        "profiles.json": "ProfileStore.load",
        "profiles": "ProfileStore.load (files read on use)",
        "tern/overrides.json": "read on use (CoreOverrides.load) + tunnel scope sync",
        "tern/secrets.json": "read on use (CoreOverrides.load)",
        "tern/dns.json": "read on use (DNS page loads on appear)",
        "tern/localdns.json": "read on use (DNS page loads on appear)",
        "tern/group-icons.json": "GroupIconStore.reload",
        "tern/rules.json": "CustomRulesStore.load",
        "tern/subscriptions.json": "read on use",
        "tern/groups.json": "SmartGroups.load",
        "tern/netpolicy.json": "read on use (NetworkPolicyStore.loadAll)",
        "tern/node-subscriptions.json": "NodeSubStore.load",
        "tern/node-settings.json": "NodeSettingsStore.reload",
        "tern/group-edits.json": "read on use",
        "tern/provider-overrides.json": "ProviderOverrideStore.reload",
        "tern/engine/engine.json": "EngineStore.config",
        "tern/engine/store.json": "read on use",
        "tern/engine/modules": "EngineStore.reparseModules",
        "tern/engine/scripts": "read on use",
        "tern/override-scripts": "OverrideScriptStore.load",
        "tern/engine/ca": "read on use",
        "traffic-history.json": "read on use (TrafficHistory.load)",
    ]

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
        // r7 R7A-1: the same for 节点订阅, 节点集设置, 智能选择, group icons and per-node settings.
        NodeSubStore.shared.load()
        ProviderOverrideStore.shared.reload()
        SmartGroups.shared.load()
        GroupIconStore.shared.reload()
        NodeSettingsStore.shared.reload()
        Task { @MainActor in
            // r7 R7A-2: the restored 连接方式 scope must reach the iOS VPN configuration too.
            let scopeChanged = await VPNManager.shared.syncTunnelScope()
            await ProviderOverrideStore.shared.loadDeclared(ProfileStore.shared.active, force: true)
            await NodeManagerModel.shared.reload(force: true)
            if VPNManager.shared.isConnected {
                if scopeChanged {
                    // Routes / includeAllNetworks only apply on a new connection.
                    await VPNManager.shared.reconnectForScope()
                } else {
                    _ = await VPNManager.shared.reload()
                }
            }
        }
    }
}
