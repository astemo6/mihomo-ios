import Foundation

// DIVERGENCES:
// 1. Validation Backend:
//    - Go (bridge/profilenodes.go): Calls `validateProfileBytes` which drives Go mihomo core's
//      `buildRuntime` and `executor.ParseWithBytes`.
//    - Swift (NCProfileNodes): Uses `NCYAML.parse` and `NCRuntimeBuilder.build` in pure Swift to validate
//      YAML syntax, config structure, proxy schemas, and runtime generation.
//    - Impact: Pure Swift validation with zero Cgo/Go dependency; preserves the same tolerance for
//      pre-existing errors (errors already present in the unedited file do not block the edit).
// 2. File Lock Mapping:
//    - Go: `sync.Map` of `*sync.Mutex` keyed by `filepath.Clean(path)` in `bridge/filelock.go`.
//    - Swift: `NCFileLock` with `NSLock` keyed by `(path as NSString).standardizingPath`.
//    - Impact: 1:1 equivalent serialization of read-modify-write calls within the app process.
// 3. LastError Threading:
//    - Go: Global `setLastError` / `LastError` strings in bridge.
//    - Swift: `NCProfileNodes.lastError` protected by `NSLock`.
//    - Impact: Thread-safe error storage for functions returning "" on failure.

/// In-process path mutex to serialize read-modify-write cycles for each profile file.
/// Maps bridge/filelock.go 1:1 using standardized paths.
final class NCFileLock {
    static let shared = NCFileLock()
    private let mutex = NSLock()
    private var locks: [String: NSLock] = [:]

    func withLock<T>(for path: String, _ body: () throws -> T) rethrows -> T {
        let cleanPath = (path as NSString).standardizingPath
        mutex.lock()
        let lock: NSLock
        if let existing = locks[cleanPath] {
            lock = existing
        } else {
            let newLock = NSLock()
            locks[cleanPath] = newLock
            lock = newLock
        }
        mutex.unlock()

        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// Pure Swift implementation of profile node operations matching bridge/profilenodes.go specifications.
enum NCProfileNodes {

    // MARK: - Last Error Support

    private static let errorLock = NSLock()
    private static var _lastError: String = ""

    static var lastError: String {
        get {
            errorLock.lock()
            defer { errorLock.unlock() }
            return _lastError
        }
        set {
            errorLock.lock()
            defer { errorLock.unlock() }
            _lastError = newValue
        }
    }

    private static func setLastError(_ err: String) {
        lastError = err
    }

    static let builtinTargets: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]

    static func serverlessType(_ t: String) -> Bool {
        switch t.trimmingCharacters(in: .whitespaces).lowercased() {
        case "tailscale", "zerotier", "easytier":
            return true
        default:
            return false
        }
    }

    // MARK: - ProfileNodeGet

    /// Returns the full proxy entry (JSON) named `name` in the profile file, or "" (sets `lastError`).
    static func get(path: String, name: String) -> String {
        guard let doc = loadDoc(path) else {
            setLastError("读取配置文件失败")
            return ""
        }
        guard let json = doc.getProxyJSON(name: name) else {
            setLastError("配置文件里没有这个节点")
            return ""
        }
        return json
    }

    // MARK: - ProfileNodeUpsert

    /// Replaces the entry named `oldName` (or appends a new one when `oldName` is "") with `nodeJSON`.
    /// A rename is applied to every reference in the file. Returns "" or an error message.
    static func upsert(homeDir: String, path: String, nodeJSON: String, oldName: String) -> String {
        return NCFileLock.shared.withLock(for: path) {
            guard let data = nodeJSON.data(using: .utf8),
                  let rawNode = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return "无效的节点 JSON"
            }
            guard var node = normalizeJSON(rawNode) as? [String: Any] else {
                return "无效的节点结构"
            }

            let name = ((node["name"] as? String) ?? "").trimmingCharacters(in: .whitespaces)
            let type = ((node["type"] as? String) ?? "").trimmingCharacters(in: .whitespaces)
            let server = ((node["server"] as? String) ?? "").trimmingCharacters(in: .whitespaces)

            if name.isEmpty || type.isEmpty || (server.isEmpty && !serverlessType(type)) {
                return "名称、类型、服务器不能为空"
            }
            node["name"] = name

            // Basic proxy validation
            if let portVal = node["port"] {
                let portInt: Int?
                if let p = portVal as? Int { portInt = p }
                else if let p = portVal as? Int64 { portInt = Int(p) }
                else if let p = portVal as? NSNumber { portInt = p.intValue }
                else { portInt = nil }
                if let p = portInt, (p <= 0 || p > 65535) {
                    return "端口必须在 1-65535 之间"
                }
            }

            guard let orig = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let text = String(data: orig, encoding: .utf8) else {
                return "无法读取配置文件"
            }
            let doc = NCProfileYAML(text: text)

            let isRename = !oldName.isEmpty && name != oldName
            let isNew = oldName.isEmpty
            if (isNew || isRename) && (doc.allNames().contains(name) || builtinTargets.contains(name)) {
                return "已有同名的节点或策略组"
            }

            if isNew {
                _ = doc.upsertProxy(node: node, oldName: nil)
            } else {
                guard doc.findProxy(name: oldName) != nil else {
                    return "配置文件里没有这个节点"
                }
                _ = doc.upsertProxy(node: node, oldName: oldName)
                if isRename {
                    _ = doc.renameRefs(oldName: oldName, newName: name)
                }
            }

            return commit(home: homeDir, path: path, orig: orig, doc: doc)
        }
    }

    // MARK: - ProfileNodeDuplicate

    /// Inserts a copy of `name` right after it (not added to any group).
    /// Returns the new name, or "" (sets `lastError`).
    static func duplicate(homeDir: String, path: String, name: String, suffix: String) -> String {
        return NCFileLock.shared.withLock(for: path) {
            guard let orig = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let text = String(data: orig, encoding: .utf8) else {
                setLastError("无法读取配置文件")
                return ""
            }
            let doc = NCProfileYAML(text: text)
            guard doc.findProxy(name: name) != nil else {
                setLastError("配置文件里没有这个节点")
                return ""
            }

            let sfx = suffix.isEmpty ? "copy" : suffix
            let names = doc.allNames()
            var nn = "\(name) \(sfx)"
            var k = 2
            while names.contains(nn) {
                nn = "\(name) \(sfx) \(k)"
                k += 1
            }

            guard doc.duplicateProxy(name: name, newName: nn) != nil else {
                setLastError("复制节点失败")
                return ""
            }

            let err = commit(home: homeDir, path: path, orig: orig, doc: doc)
            if !err.isEmpty {
                setLastError(err)
                return ""
            }
            return nn
        }
    }

    // MARK: - ProfileNodeDeleteCheck

    struct DeleteCheckResult: Codable {
        var groups: [String]?
        var emptyGroups: [String]?
        var rules: Int?
        var dialers: [String]?
        var error: String?
    }

    /// Returns deleteCheck JSON for deleting `name` from the profile file.
    static func deleteCheck(path: String, name: String) -> String {
        guard let orig = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let text = String(data: orig, encoding: .utf8) else {
            let res = DeleteCheckResult(error: "无法读取配置文件")
            return (try? String(data: JSONEncoder().encode(res), encoding: .utf8)) ?? "{}"
        }
        let doc = NCProfileYAML(text: text)
        guard doc.findProxy(name: name) != nil else {
            let res = DeleteCheckResult(error: "配置文件里没有这个节点")
            return (try? String(data: JSONEncoder().encode(res), encoding: .utf8)) ?? "{}"
        }

        let empty = doc.emptyAfterDelete(name: name)
        let st = doc.renameRefs(oldName: name, newName: "")

        let res = DeleteCheckResult(
            groups: st.groups.isEmpty ? nil : st.groups,
            emptyGroups: empty.isEmpty ? nil : empty,
            rules: st.rules,
            dialers: st.dialers.isEmpty ? nil : st.dialers,
            error: nil
        )
        if let data = try? JSONEncoder().encode(res), let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "{}"
    }

    // MARK: - ProfileNodeDelete

    /// Removes `name` from the profile: the entry, group members (a group left with no member
    /// gets DIRECT), rules that target it and dialer-proxy references. Returns "" or an error message.
    static func delete(homeDir: String, path: String, name: String) -> String {
        return NCFileLock.shared.withLock(for: path) {
            guard let orig = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let text = String(data: orig, encoding: .utf8) else {
                return "无法读取配置文件"
            }
            let doc = NCProfileYAML(text: text)
            guard doc.findProxy(name: name) != nil else {
                return "配置文件里没有这个节点"
            }

            let empty = doc.emptyAfterDelete(name: name)
            _ = doc.deleteProxy(name: name)
            _ = doc.renameRefs(oldName: name, newName: "")

            for g in empty {
                doc.appendDirectToGroup(name: g)
            }

            return commit(home: homeDir, path: path, orig: orig, doc: doc)
        }
    }

    // MARK: - ProfileRenameRefs

    /// Renames references to a group or node (members, dialer-proxy, rules) without touching
    /// the entry itself. Returns "" or an error message.
    static func renameRefs(homeDir: String, path: String, oldName: String, newName: String) -> String {
        return NCFileLock.shared.withLock(for: path) {
            if oldName.isEmpty || newName.isEmpty || oldName == newName {
                return ""
            }
            guard let orig = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let text = String(data: orig, encoding: .utf8) else {
                return "无法读取配置文件"
            }
            let doc = NCProfileYAML(text: text)
            let st = doc.renameRefs(oldName: oldName, newName: newName)
            if st.groups.isEmpty && st.rules == 0 && st.dialers.isEmpty {
                return ""
            }
            return commit(home: homeDir, path: path, orig: orig, doc: doc)
        }
    }

    // MARK: - ProfileNodeUndo

    /// Restores `<path>.bak` (the file before the last node edit). Returns "" or an error message.
    static func undo(path: String) -> String {
        return NCFileLock.shared.withLock(for: path) {
            let bakPath = path + ".bak"
            guard let b = try? Data(contentsOf: URL(fileURLWithPath: bakPath)) else {
                return "没有可以撤销的修改"
            }
            let cur = try? Data(contentsOf: URL(fileURLWithPath: path))
            do {
                try writeAtomic(b, to: path)
                if let cur = cur {
                    _ = try? writeAtomic(cur, to: bakPath)
                }
                return ""
            } catch {
                return error.localizedDescription
            }
        }
    }

    // MARK: - ProfileHasNode

    /// Reports whether the profile file itself defines `name`.
    static func hasNode(path: String, name: String) -> Bool {
        guard let doc = loadDoc(path) else { return false }
        return doc.hasProxy(name: name)
    }

    // MARK: - Bridge Compatibility Aliases

    static func ProfileNodeGet(_ path: String, _ name: String) -> String {
        get(path: path, name: name)
    }

    static func ProfileNodeUpsert(_ homeDir: String, _ path: String, _ nodeJSON: String, _ oldName: String) -> String {
        upsert(homeDir: homeDir, path: path, nodeJSON: nodeJSON, oldName: oldName)
    }

    static func ProfileNodeDuplicate(_ homeDir: String, _ path: String, _ name: String, _ suffix: String) -> String {
        duplicate(homeDir: homeDir, path: path, name: name, suffix: suffix)
    }

    static func ProfileNodeDeleteCheck(_ path: String, _ name: String) -> String {
        deleteCheck(path: path, name: name)
    }

    static func ProfileNodeDelete(_ homeDir: String, _ path: String, _ name: String) -> String {
        delete(homeDir: homeDir, path: path, name: name)
    }

    static func ProfileNodeUndo(_ path: String) -> String {
        undo(path: path)
    }

    static func ProfileRenameRefs(_ homeDir: String, _ path: String, _ oldName: String, _ newName: String) -> String {
        renameRefs(homeDir: homeDir, path: path, oldName: oldName, newName: newName)
    }

    static func ProfileHasNode(_ path: String, _ name: String) -> Bool {
        hasNode(path: path, name: name)
    }

    // MARK: - Internal Helpers

    private static func loadDoc(_ path: String) -> NCProfileYAML? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        return NCProfileYAML(text: text)
    }

    private static func normalizeJSON(_ v: Any) -> Any {
        switch v {
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                return n.boolValue
            }
            let d = n.doubleValue
            if d.isFinite && d == floor(d) && d >= Double(Int64.min) && d <= Double(Int64.max) {
                return Int64(d)
            }
            return d
        case let d as Double:
            if d.isFinite && d == floor(d) && d >= Double(Int64.min) && d <= Double(Int64.max) {
                return Int64(d)
            }
            return d
        case let dict as [String: Any]:
            return dict.mapValues { normalizeJSON($0) }
        case let list as [Any]:
            return list.map { normalizeJSON($0) }
        default:
            return v
        }
    }

    private static func commit(home: String, path: String, orig: Data, doc: NCProfileYAML) -> String {
        guard let newData = doc.data() else {
            return "文档编码失败"
        }

        if let newErr = validateProfileBytes(home: home, path: path, data: newData) {
            if let preErr = validateProfileBytes(home: home, path: path, data: orig) {
                if preErr != newErr {
                    return newErr
                }
            } else {
                return newErr
            }
        }

        do {
            try writeAtomic(orig, to: path + ".bak")
            try writeAtomic(newData, to: path)
            return ""
        } catch {
            return error.localizedDescription
        }
    }

    private static func validateProfileBytes(home: String, path: String, data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8), NCYAML.parse(text) != nil else {
            return "YAML 解析失败"
        }
        if !home.isEmpty && !path.isEmpty {
            let req = NCRuntimeBuilder.Request.load(home: home, profilePath: path)
            do {
                _ = try NCRuntimeBuilder.build(profile: data, req: req, fd: 0)
            } catch {
                return error.localizedDescription
            }
        }
        return nil
    }

    private static func writeAtomic(_ data: Data, to path: String) throws {
        let tmp = path + ".tmp"
        try data.write(to: URL(fileURLWithPath: tmp))
        let fm = FileManager.default
        if fm.fileExists(atPath: path) {
            _ = try? fm.removeItem(atPath: path)
        }
        try fm.moveItem(atPath: tmp, toPath: path)
    }
}
