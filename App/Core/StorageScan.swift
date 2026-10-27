import Foundation
import Darwin

/// fix/nc-storage-other: the 存储空间 page's disk accounting, pure Foundation (unit-tested in StorageScanTests).
///
/// The page used to sum `.fileSizeKey` (LOGICAL size) of every regular file once per category and show
/// 其他 = size(container) + size(tmp) − Σ categories. That over-reports in three ways this type removes:
/// - logical size: a sparse / preallocated / compressed file counts its length, not the blocks it holds →
///   bytes are the ALLOCATED size (`.totalFileAllocatedSizeKey`, then `.fileAllocatedSizeKey`, then
///   st_blocks × 512, the logical size only when the volume reports none);
/// - hard links (the runtime prep's staging backups `<stage>/.old/N` are links to the live files) and any other
///   second name of one inode count once (dedupe by st_dev + st_ino);
/// - symbolic links are never followed or counted.
/// One walk of the container classifies every file into exactly one category, so 其他 is the files no
/// category claims — an exact sum, not a difference — and can be broken down by path.
enum StorageScan {
    // MARK: categories

    enum Kind: String, CaseIterable {
        case profiles, providers, geo, snapshots, logs, icons, stats, other
    }

    static let providerDirs = ["rules", "ruleset", "proxies", "providers", "rule-providers", "proxy-providers"]
    static let geoExt: Set<String> = ["metadb", "dat", "mmdb"]
    static let logFiles: Set<String> = ["startup-log.txt", "startup-log.prev.txt", "tunnel-last-error.txt", "tunnel-last-stop.txt"]
    static let statsFiles: Set<String> = ["traffic-history.json", "analytics-history.json", "tern/probe-results.json"]

    /// Category of one container-relative path (no leading slash). Mirrors the paths the page always used.
    static func classify(_ rel: String) -> Kind {
        let parts = rel.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard let first = parts.first else { return .other }
        if parts.count > 1 {
            switch first {
            case "profiles", "nodesubs": return .profiles
            case "snapshots": return .snapshots
            case "icon-cache": return .icons
            default: break
            }
        }
        if logFiles.contains(rel) { return .logs }
        if statsFiles.contains(rel) { return .stats }
        if first == "tern" {
            if parts.count > 2 {
                if parts[1] == "nodesubs" { return .profiles }
                if parts[1] == "diag" { return .logs }
                if providerDirs.contains(parts[1]) { return .providers }
            }
            if parts.count == 2, geoExt.contains((parts[1] as NSString).pathExtension.lowercased()) { return .geo }
        }
        return .other
    }

    // MARK: leftovers (safe to delete)

    /// A temp file younger than this may still be in the middle of an atomic write.
    static let orphanAge: TimeInterval = 10 * 60

    /// Whether `rel` is a leftover nothing reads, so deleting it changes nothing for the user:
    /// - staging directories of a crashed / killed runtime prepare (`tern/.nativecore-stage-*`, also the
    ///   hard-link backups inside them), older than `orphanAge`;
    /// - orphaned atomic-write temp files (`.<name>.tmp…` from writeAtomic / Tailscale / the old old bridge,
    ///   Foundation's `.<name>.nosync…`, `<geo>.download`), older than `orphanAge`;
    /// - files only the removed old core used: `tern/cache.db` (bbolt), `tern/tunnel-stats.json`, `tern/ui/`
    ///   (external-ui; NativeCore strips external-ui from the runtime config);
    /// - `Library/Caches/` of the group container (system caches, rebuilt on demand).
    static func isLeftover(_ rel: String, age: TimeInterval) -> Bool {
        if rel == "tern/cache.db" || rel == "tern/tunnel-stats.json" || rel.hasPrefix("tern/ui/") { return true }
        if rel.hasPrefix("Library/Caches/") { return true }
        guard age >= orphanAge else { return false }
        if rel.hasPrefix("tern/" + PrepTransaction.stagePrefix) { return true }
        let name = (rel as NSString).lastPathComponent
        if name.hasPrefix("."), name.contains(".tmp") || name.contains(".nosync") { return true }
        if name.hasSuffix(".download") { return true }
        return false
    }

    /// What to remove for a leftover file: its staging directory / ui dir as a whole, else the file itself.
    static func leftoverRoot(_ rel: String) -> String {
        let parts = rel.split(separator: "/").map(String.init)
        if parts.count > 2, parts[0] == "tern", parts[1].hasPrefix(PrepTransaction.stagePrefix) || parts[1] == "ui" {
            return parts[0] + "/" + parts[1]
        }
        return rel
    }

    // MARK: walking

    struct File {
        let rel: String
        let bytes: Int64
        /// Seconds since the last modification (at scan time).
        let age: TimeInterval
    }

    static let sizeKeys: Set<URLResourceKey> = [.totalFileAllocatedSizeKey, .fileAllocatedSizeKey]

    /// Bytes a regular file holds on disk.
    static func allocatedBytes(path: String, st: stat) -> Int64 {
        if let v = try? URL(fileURLWithPath: path).resourceValues(forKeys: sizeKeys) {
            if let t = v.totalFileAllocatedSize { return Int64(t) }
            if let a = v.fileAllocatedSize { return Int64(a) }
        }
        if st.st_blocks > 0 { return Int64(st.st_blocks) * 512 }
        return Int64(st.st_size)
    }

    fileprivate struct FileID: Hashable { let dev: Int64; let ino: UInt64 }

    /// Walks `roots` once; regular files only, symlinks skipped (never followed), each inode counted once
    /// across all roots. `rel` is relative to its own root.
    final class Walker {
        private var seen = Set<FileID>()
        private let now = Date().timeIntervalSince1970
        init() {}

        func walk(_ root: URL, _ visit: (File) -> Void) {
            let base = root.path
            var st = stat()
            guard lstat(base, &st) == 0 else { return }
            if (st.st_mode & S_IFMT) == S_IFLNK { return }
            if (st.st_mode & S_IFMT) == S_IFREG {
                if let f = file(path: base, rel: (base as NSString).lastPathComponent, st: st) { visit(f) }
                return
            }
            guard (st.st_mode & S_IFMT) == S_IFDIR, let e = FileManager.default.enumerator(atPath: base) else { return }
            while let item = e.nextObject() as? String {
                let full = (base as NSString).appendingPathComponent(item)
                var s = stat()
                guard lstat(full, &s) == 0 else { continue }
                switch s.st_mode & S_IFMT {
                case S_IFLNK:
                    e.skipDescendants()
                case S_IFREG:
                    if let f = file(path: full, rel: item, st: s) { visit(f) }
                default:
                    break
                }
            }
        }

        func size(_ root: URL) -> Int64 {
            var total: Int64 = 0
            walk(root) { total += $0.bytes }
            return total
        }

        private func file(path: String, rel: String, st: stat) -> File? {
            let id = FileID(dev: Int64(st.st_dev), ino: UInt64(st.st_ino))
            guard seen.insert(id).inserted else { return nil }
            let mtime = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
            return File(rel: rel, bytes: StorageScan.allocatedBytes(path: path, st: st), age: max(0, now - mtime))
        }
    }

    // MARK: result

    struct PathUsage: Identifiable, Equatable {
        var id: String { path }
        let path: String
        let bytes: Int64
        let isDirectory: Bool
        /// Every file under it is a leftover (the row may offer 清除).
        let clearable: Bool
    }

    struct Summary {
        var bytes: [Kind: Int64] = [:]
        /// Container files of 其他 (container-relative).
        var other: [File] = []
        /// Provider cache files (absolute), for the unused-provider check.
        var providerFiles: [URL] = []
        var containerBytes: Int64 = 0
        var tmpBytes: Int64 = 0
        var total: Int64 { containerBytes + tmpBytes }
        /// Leftover files (container-relative) and their bytes.
        var leftovers: [File] = []
        var leftoverBytes: Int64 { leftovers.reduce(0) { $0 + $1.bytes } }
    }

    /// One pass over the container (and the app's tmp, kept as its own category).
    static func scan(container: URL, tmp: URL?) -> Summary {
        var s = Summary()
        let w = Walker()
        w.walk(container) { f in
            let k = classify(f.rel)
            s.bytes[k, default: 0] += f.bytes
            s.containerBytes += f.bytes
            if k == .providers { s.providerFiles.append(container.appendingPathComponent(f.rel)) }
            if k == .other {
                s.other.append(f)
                if isLeftover(f.rel, age: f.age) { s.leftovers.append(f) }
            }
        }
        if let tmp { s.tmpBytes = w.size(tmp) }
        return s
    }

    /// The largest subpaths of `files` (relative paths), at most `limit`. Starts from the top-level entries
    /// and keeps opening the largest directory while it holds at least half of the bytes (up to depth 5), so a
    /// single runaway directory shows its own children instead of just "Clash.Meta".
    static func topPaths(_ files: [File], limit: Int = 5, leftover: (File) -> Bool = { StorageScan.isLeftover($0.rel, age: $0.age) }) -> [PathUsage] {
        let total = files.reduce(Int64(0)) { $0 + $1.bytes }
        guard total > 0 else { return [] }
        func buckets(under prefix: [String]) -> [PathUsage] {
            var bytes: [String: Int64] = [:]
            var isDir: [String: Bool] = [:]
            var allSafe: [String: Bool] = [:]
            for f in files {
                let parts = f.rel.split(separator: "/").map(String.init)
                guard parts.count > prefix.count, Array(parts.prefix(prefix.count)) == prefix else { continue }
                let key = parts.prefix(prefix.count + 1).joined(separator: "/")
                bytes[key, default: 0] += f.bytes
                if parts.count > prefix.count + 1 { isDir[key] = true }
                allSafe[key] = (allSafe[key] ?? true) && leftover(f)
            }
            return bytes.map { PathUsage(path: $0.key, bytes: $0.value, isDirectory: isDir[$0.key] ?? false, clearable: allSafe[$0.key] ?? false) }
        }
        var list = buckets(under: [])
        var opened = Set<String>()
        for _ in 0..<5 {
            guard let big = list.max(by: { $0.bytes < $1.bytes }), big.isDirectory, !opened.contains(big.path),
                  big.bytes * 2 >= total else { break }
            opened.insert(big.path)
            let kids = buckets(under: big.path.split(separator: "/").map(String.init))
            guard !kids.isEmpty else { break }
            list.removeAll { $0.path == big.path }
            list += kids
        }
        return Array(list.sorted { $0.bytes != $1.bytes ? $0.bytes > $1.bytes : $0.path < $1.path }.prefix(limit))
    }

    // MARK: cleanup

    /// Deletes the leftovers under `prefix` ("" = all) in `container`, re-checked against `isLeftover` now.
    /// Returns the bytes the deleted files held.
    @discardableResult
    static func removeLeftovers(container: URL, under prefix: String = "", autoOnly: Bool = false) -> Int64 {
        let fm = FileManager.default
        var roots = Set<String>()
        var freed: Int64 = 0
        let w = Walker()
        w.walk(container) { f in
            guard prefix.isEmpty || f.rel == prefix || f.rel.hasPrefix(prefix + "/") else { return }
            guard classify(f.rel) == .other, isLeftover(f.rel, age: f.age) else { return }
            if autoOnly && !isAutoSweepable(f.rel, age: f.age) { return }
            roots.insert(leftoverRoot(f.rel))
            freed += f.bytes
        }
        for r in roots.sorted() { try? fm.removeItem(at: container.appendingPathComponent(r)) }
        return freed
    }

    /// The subset removed without asking (app launch): crashed staging and orphaned temp files only — never the
    /// old-core files or caches, which go through the page's button.
    static func isAutoSweepable(_ rel: String, age: TimeInterval) -> Bool {
        guard age >= orphanAge, isLeftover(rel, age: age) else { return false }
        if rel == "tern/cache.db" || rel == "tern/tunnel-stats.json" || rel.hasPrefix("tern/ui/") || rel.hasPrefix("Library/Caches/") {
            return false
        }
        return true
    }

    /// App launch: drop crashed-prepare staging dirs and orphaned temp files (background, low priority).
    /// Runs under the runtime prep's lock so it never races a prepare in this process.
    static func sweepOnLaunch() {
        guard AppShared.containerOK else { return }
        let container = AppShared.containerURL
        let home = AppShared.homeURL.path
        let key = (home as NSString).appendingPathComponent(".nativecore-prepare.lock")
        let freed = NCPathLock.shared.withLock(for: key) {
            removeLeftovers(container: container, autoOnly: true)
        }
        if freed > 0 { StartupLog.write("storage: removed \(freed) bytes of stale staging / temp files", tag: "app") }
    }
}
