import Foundation

/// Thread-safe path locking for manual node file operations.
final class NCPathLock {
    static let shared = NCPathLock()
    private let mutex = NSLock()
    private var locks: [String: NSLock] = [:]

    func withLock<T>(for path0: String, _ body: () throws -> T) rethrows -> T {
        // the retired bridge keys by filepath.Clean(path): one lock per file however the path is spelled.
        let path = (path0 as NSString).standardizingPath
        mutex.lock()
        let lock: NSLock
        if let existing = locks[path] {
            lock = existing
        } else {
            let newLock = NSLock()
            locks[path] = newLock
            lock = newLock
        }
        mutex.unlock()

        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// Pure Swift manual node profile manager matching the retired bridge.
enum NCManualNodes {

    static let manualGroupName = "手动节点"

    // MARK: - List

    /// Returns the proxies of the manual profile as a list of dictionaries.
    static func list(path: String) -> [[String: Any]] {
        return NCPathLock.shared.withLock(for: path) {
            loadProxies(path: path)
        }
    }

    /// Returns the proxies of the manual profile as a JSON array string.
    static func listJSON(path: String) -> String {
        let ps = list(path: path)
        if let data = try? JSONSerialization.data(withJSONObject: ps),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "[]"
    }

    // MARK: - Add

    /// Parses text and appends all recognized nodes to the manual profile.
    /// Returns (count, error). If count < 0, error describes the reason.
    static func addText(path: String, text: String) -> (count: Int32, error: String) {
        return NCPathLock.shared.withLock(for: path) {
            let newProxies = NCSubscriptionParser.parseToDictionaries(text)
            guard !newProxies.isEmpty else {
                return (-1, "未识别到节点")
            }

            var cur = loadProxies(path: path)
            var names: [String: Bool] = [:]
            for p in cur {
                if let n = p["name"] as? String, !n.isEmpty {
                    names[n] = true
                }
            }

            for var p in newProxies {
                let origName = (p["name"] as? String) ?? "\(p["type"] ?? "node") \(p["server"] ?? "")"
                var n = origName
                var i = 2
                while names[n] == true {
                    n = "\(origName) \(i)"
                    i += 1
                }
                p["name"] = n
                names[n] = true
                cur.append(p)
            }

            do {
                try writeManual(path: path, proxies: cur)
                return (Int32(newProxies.count), "")
            } catch {
                return (-1, error.localizedDescription)
            }
        }
    }

    // MARK: - Upsert

    /// Inserts or replaces (by oldName) a node given as a JSON string. Returns "" on success, or error message.
    static func upsert(path: String, nodeJSON: String, oldName: String) -> String {
        guard let data = nodeJSON.data(using: .utf8),
              let node = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return "无效的节点 JSON"
        }
        return upsert(path: path, node: node, oldName: oldName.isEmpty ? nil : oldName)
    }

    /// Inserts or replaces (by oldName) a node given as a dictionary. Returns "" on success, or error message.
    static func upsert(path: String, node: [String: Any], oldName: String?) -> String {
        let name = (node["name"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        let typ = (node["type"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        let server = (node["server"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""

        if name.isEmpty || typ.isEmpty || (server.isEmpty && !serverlessType(typ)) {
            return "名称、类型、服务器不能为空"
        }

        // Clean numbers for YAML neatness (e.g. 443.0 -> 443)
        var cleaned = node
        for (k, v) in node {
            if let num = v as? NSNumber {
                if CFGetTypeID(num) == CFBooleanGetTypeID() {
                    cleaned[k] = num.boolValue
                } else if num.doubleValue.isFinite && num.doubleValue == floor(num.doubleValue) {
                    cleaned[k] = num.int64Value
                }
            }
        }

        return NCPathLock.shared.withLock(for: path) {
            var cur = loadProxies(path: path)
            var replaced = false

            for (idx, p) in cur.enumerated() {
                let n = (p["name"] as? String) ?? ""
                if let old = oldName, !old.isEmpty {
                    if n == old {
                        cur[idx] = cleaned
                        replaced = true
                        break
                    }
                } else if n == name {
                    cur[idx] = cleaned
                    replaced = true
                    break
                }
            }

            if !replaced {
                cur.append(cleaned)
            }

            do {
                try writeManual(path: path, proxies: cur)
                return ""
            } catch {
                return error.localizedDescription
            }
        }
    }

    // MARK: - Delete

    /// Removes a node by name. Returns "" on success, or error message.
    /// If name is "", writes an empty manual profile if none exists.
    static func delete(path: String, name: String) -> String {
        return NCPathLock.shared.withLock(for: path) {
            let cur = loadProxies(path: path)
            let out: [[String: Any]]
            if name.isEmpty {
                out = cur
            } else {
                out = cur.filter { ($0["name"] as? String) != name }
            }

            do {
                try writeManual(path: path, proxies: out)
                return ""
            } catch {
                return error.localizedDescription
            }
        }
    }

    // MARK: - Write Manual File

    /// Writes proxies into the manual-nodes.yaml profile with standard select group and rules.
    static func writeManual(path: String, proxies: [[String: Any]]) throws {
        var names: [Any] = []
        for p in proxies {
            if let n = p["name"] {
                names.append(n)
            }
        }

        var groupProxies = names
        groupProxies.append("DIRECT")

        let group: [String: Any] = [
            "name": manualGroupName,
            "type": "select",
            "proxies": groupProxies
        ]

        let rules: [String] = [
            "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH," + manualGroupName
        ]

        let cfg: [String: Any] = [
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": [group],
            "rules": rules
        ]

        let yaml = NCYAMLEmitter.emit(cfg)
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try yaml.write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: - Internal Helpers

    private static func loadProxies(path: String) -> [[String: Any]] {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8),
              let root = NCYAML.parse(text) else {
            return []
        }
        guard let pxList = root.object?["proxies"]?.array else {
            return []
        }
        return pxList.compactMap { $0.object?.mapValues { $0.rawAny } }
    }

    private static func serverlessType(_ t: String) -> Bool {
        switch t.trimmingCharacters(in: .whitespaces).lowercased() {
        case "tailscale", "zerotier", "easytier":
            return true
        default:
            return false
        }
    }
}
