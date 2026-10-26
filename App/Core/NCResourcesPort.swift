import Foundation

/// nc-integrate B4: bridge/resources.go (ResourceList / ResourceStore / ResourceSetError) in Swift — the rows of
/// 模块与资源 (modules / rewrite sets of engine.json, remote rule sets of rules.json and of enabled modules, remote
/// scripts) with their cache files, the validated write of a downloaded resource and the last-error record
/// (<home>/resources-state.json).
///
/// Reused Swift: NCEngineConfig (mitm LoadConfig / ModulePath), NCEngineRuleset.parseText / parseLine (mitm
/// Ruleset), NCRuntimeSteps.remoteCoreRules / readCustomRules, NCRuleValidator.parseQXRemote / providerNameFor,
/// NCEngineRuleset.convertRuleLine (mitm ConvertRuleLine), NCScriptSource.cachePath (mitm CachePath),
/// NCProviderPorts.convertListText (convertListTo).
///
/// Divergence: Swift's NCEngineTask does not keep a task script's script-update-interval, so a remote script
/// first referenced by a cron / event task is listed with mitm's default 86400 s.
enum NCResourcesPort {

    // MARK: - resources-state.json

    private static let stateLock = NSLock()

    static func statePath(_ home: String) -> String { (home as NSString).appendingPathComponent("resources-state.json") }

    static func readState(_ home: String) -> [String: [String: Any]] {
        guard let b = FileManager.default.contents(atPath: statePath(home)),
              let o = try? JSONSerialization.jsonObject(with: b) as? [String: Any] else { return [:] }
        return o.compactMapValues { $0 as? [String: Any] }
    }

    /// bridge setResState.
    static func setState(home: String, key: String, error: String) {
        stateLock.lock()
        defer { stateLock.unlock() }
        var m = readState(home)
        var s: [String: Any] = ["checkedAt": Date().timeIntervalSince1970.rounded(.down)]
        if !error.isEmpty { s["error"] = error }
        m[key] = s
        if let b = try? JSONSerialization.data(withJSONObject: m, options: [.prettyPrinted, .sortedKeys]) {
            try? b.write(to: URL(fileURLWithPath: statePath(home)), options: .atomic)
        }
    }

    // MARK: - helpers

    static func ruleSetPath(home: String, url: String, kind: String) -> String {
        (home as NSString).appendingPathComponent("ruleset/" + NCRuleValidator.providerNameFor(url: url, kind: kind) + ".txt")
    }

    /// bridge countLines: newlines in the file (0 when missing). Counted on the bytes, no String copy.
    static func countLines(_ p: String) -> Int {
        guard let b = FileManager.default.contents(atPath: p) else { return 0 }
        return b.reduce(0) { $1 == 0x0A ? $0 + 1 : $0 }
    }

    /// bridge remoteOfLine: (url, kind, policy, interval) of a custom-rule line with a remote list.
    static func remoteOfLine(_ line0: String) -> (url: String, kind: String, policy: String, interval: Int)? {
        let line = line0.trimmingCharacters(in: .whitespaces)
        if case let (sp, ok)? = NCRuleValidator.parseQXRemote(line), ok {
            return (sp.url, "list", sp.policy, sp.interval)
        }
        let (c, err) = NCEngineRuleset.convertRuleLine(line)
        if err == nil && !c.remoteURL.isEmpty { return (c.remoteURL, c.remoteKind, c.policy, 0) }
        return nil
    }

    static func isRemoteURL(_ p: String) -> Bool { p.hasPrefix("http://") || p.hasPrefix("https://") }

    /// bridge listName: the last path component of a URL.
    static func listName(_ u: String) -> String {
        var s = u
        if let i = s.firstIndex(where: { $0 == "?" || $0 == "#" }) { s = String(s[..<i]) }
        if s.hasSuffix("/") { s.removeLast() }
        if let i = s.lastIndex(of: "/"), s.index(after: i) < s.endIndex { s = String(s[s.index(after: i)...]) }
        return s
    }

    // MARK: - ResourceList

    private final class Ref {
        var owners: [String] = []
        var interval: Int
        var listKind = ""
        var policy = ""
        init(interval: Int) { self.interval = interval }
    }

    /// bridge listResources.
    static func list(home: String) -> [[String: Any]] {
        let cfg = NCEngineConfig.load(home: home)
        let st = readState(home)
        var out: [[String: Any]] = []
        func add(_ it0: [String: Any]) {
            var it = it0
            if let s = st[it["key"] as? String ?? ""] {
                if let c = s["checkedAt"] as? Double, c != 0 { it["checkedAt"] = c }
                if let e = s["error"] as? String, !e.isEmpty { it["error"] = e }
            }
            if (it["interval"] as? Int ?? 0) <= 0 { it["interval"] = 86400 }
            out.append(it)
        }
        func set(_ it: inout [String: Any], _ k: String, _ v: String) { if !v.isEmpty { it[k] = v } }

        var moduleSets: [String: Ref] = [:]
        var scripts: [String: Ref] = [:]
        var scriptOrder: [String] = []
        func note(_ m: inout [String: Ref], _ key: String, _ owner: String, _ interval: Int) -> Ref {
            let r: Ref
            if let x = m[key] { r = x } else { r = Ref(interval: interval); m[key] = r }
            if !r.owners.contains(owner) { r.owners.append(owner) }
            return r
        }
        func noteScript(_ path: String, _ owner: String, _ interval: Int) {
            if scripts[path] == nil { scriptOrder.append(path) }
            _ = note(&scripts, path, owner, interval)
        }

        for m in cfg.modules {
            let path = NCEngineConfig.modulePath(home: home, id: m.id)
            var it: [String: Any] = ["key": "module:" + m.id, "kind": "module", "name": m.name, "url": m.url,
                                     "enabled": m.enabled, "interval": m.interval ?? 0, "updatedAt": mtime(path)]
            set(&it, "refId", m.id)
            var detail = ""
            if let b = FileManager.default.contents(atPath: path) {
                let sub = NCEngineRuleset()
                sub.parseText(String(decoding: b, as: UTF8.self), source: m.name, args: m.args ?? [:])
                set(&it, "format", sub.format)
                detail = "\(sub.rules.count + sub.tasks.count) 条规则/脚本 · \(sub.hostnames.count) 个主机"
                if m.enabled {
                    for r in NCRuntimeSteps.remoteCoreRules(sub.coreRules) {
                        if case let (u, kind, pol, _)? = remoteOfLine(r) {
                            let rf = note(&moduleSets, "ruleset:" + kind + "|" + u, m.name, 0)
                            rf.listKind = kind; rf.policy = pol
                        }
                    }
                    for r in sub.rules where r.kind == "script" {
                        if let sc = r.script, isRemoteURL(sc.path) { noteScript(sc.path, m.name, sc.updateInterval) }
                    }
                    for t in sub.tasks where isRemoteURL(t.path) { noteScript(t.path, m.name, 86400) }
                }
            } else if !m.url.isEmpty {
                detail = "未下载"
            }
            if m.url.isEmpty { detail = ("本地 · " + detail).trimmingCharacters(in: .whitespaces) }
            set(&it, "detail", detail)
            add(it)
        }

        var seenSet = Set<String>()
        for r in NCRuntimeSteps.readCustomRules(home: home) {
            guard case let (u, kind, pol, iv0)? = remoteOfLine(r.line) else { continue }
            let key = "ruleset:" + kind + "|" + u
            seenSet.insert(key)
            let iv = (r.interval ?? 0) > 0 ? r.interval! : iv0
            let p = ruleSetPath(home: home, url: u, kind: kind)
            var detail = "→ " + pol
            let n = countLines(p)
            if n > 0 { detail += " · \(n) 条" }
            var it: [String: Any] = ["key": key, "kind": "ruleset", "name": listName(u), "url": u, "enabled": r.enabled,
                                     "interval": iv, "updatedAt": mtime(p), "detail": detail]
            set(&it, "format", kind); set(&it, "listKind", kind); set(&it, "refId", r.id)
            if let o = moduleSets[key] { set(&it, "owner", o.owners.joined(separator: "、")) }
            add(it)
        }
        for key in moduleSets.keys.sorted() where !seenSet.contains(key) {
            let o = moduleSets[key]!
            let rest = String(key.dropFirst("ruleset:".count))
            let bar = rest.firstIndex(of: "|") ?? rest.endIndex
            let kind = String(rest[..<bar])
            let u = bar < rest.endIndex ? String(rest[rest.index(after: bar)...]) : ""
            let p = ruleSetPath(home: home, url: u, kind: kind)
            var detail = "→ " + o.policy
            let n = countLines(p)
            if n > 0 { detail += " · \(n) 条" }
            var it: [String: Any] = ["key": key, "kind": "ruleset", "name": listName(u), "url": u, "enabled": true,
                                     "readOnly": true, "interval": 0, "updatedAt": mtime(p), "detail": detail]
            set(&it, "format", kind); set(&it, "listKind", kind); set(&it, "owner", o.owners.joined(separator: "、"))
            add(it)
        }

        for s in cfg.scripts where s.enabled {
            let sub = NCEngineRuleset()
            sub.parseLine(s.line, section: "script", source: "用户")
            for r in sub.rules where r.kind == "script" {
                if let sc = r.script, isRemoteURL(sc.path) { noteScript(sc.path, "脚本", sc.updateInterval) }
            }
            for t in sub.tasks where isRemoteURL(t.path) { noteScript(t.path, "脚本", 86400) }
        }
        let res = cfg.scriptResources ?? [:]
        for u in res.keys.sorted() where scripts[u] == nil && isRemoteURL(u) {
            // Go ranged over the map (random order); sorted here so the list is stable.
            scripts[u] = Ref(interval: 0)
            scriptOrder.append(u)
        }
        for u in scriptOrder {
            guard let o = scripts[u] else { continue }
            var it: [String: Any] = ["key": "script:" + u, "kind": "script", "name": listName(u), "url": u, "format": "js",
                                     "enabled": true, "interval": o.interval,
                                     "updatedAt": mtime(NCScriptSource.cachePath(home: home, url: u))]
            set(&it, "owner", o.owners.joined(separator: "、"))
            if let r = res[u] {
                it["enabled"] = !r.disabled
                if r.interval > 0 { it["interval"] = r.interval }
            }
            add(it)
        }
        return out
    }

    static func mtime(_ p: String) -> Double { NCProviderPorts.mtime(p) }

    /// bridge ResourceList.
    static func resourceList(home: String) -> String {
        let s = ncJSONString(list(home: home))
        return s.isEmpty ? "[]" : s
    }

    // MARK: - ResourceStore

    struct StoreError: Error { let message: String }

    static func looksLikeHTML(_ b: Data) -> Bool {
        let t = String(decoding: b.prefix(256), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return t.hasPrefix("<!doctype html") || t.hasPrefix("<html")
    }

    /// bridge storeResource: validates and writes the bytes for key; a short summary.
    static func store(home: String, key: String, data: Data) throws -> String {
        if data.allSatisfy({ $0 == 0x20 || ($0 >= 0x09 && $0 <= 0x0D) }) { throw StoreError(message: "内容为空") }
        if looksLikeHTML(data) { throw StoreError(message: "下载到的是网页而不是资源文件（链接可能失效或需要登录）") }
        let colon = key.firstIndex(of: ":") ?? key.endIndex
        let kind = String(key[..<colon])
        let rest = colon < key.endIndex ? String(key[key.index(after: colon)...]) : ""
        func write(_ p: String, _ d: Data) throws {
            try? FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent,
                                                     withIntermediateDirectories: true)
            try d.write(to: URL(fileURLWithPath: p), options: .atomic)
        }
        switch kind {
        case "module":
            let cfg = NCEngineConfig.load(home: home)
            guard let mod = cfg.modules.last(where: { $0.id == rest }) else { throw StoreError(message: "模块不存在") }
            let sub = NCEngineRuleset()
            sub.parseText(String(decoding: data, as: UTF8.self), source: mod.name, args: mod.args ?? [:])
            if sub.rules.count + sub.hostnames.count + sub.coreRules.count + sub.tasks.count + sub.panels.count == 0 {
                throw StoreError(message: "未识别到可用的重写、脚本、规则或 MitM 内容")
            }
            try write(NCEngineConfig.modulePath(home: home, id: rest), data)
            return "\(sub.rules.count + sub.tasks.count) 条规则/脚本，\(sub.hostnames.count) 个主机"
        case "ruleset":
            guard let bar = rest.firstIndex(of: "|") else { throw StoreError(message: "无效的规则集") }
            let lk = String(rest[..<bar]), u = String(rest[rest.index(after: bar)...])
            let r = NCProviderPorts.convertListText(data, kind: lk)
            if r.ok == 0 { throw StoreError(message: "没有可用的规则（格式无法识别）") }
            try write(ruleSetPath(home: home, url: u, kind: lk), Data(r.text.utf8))
            var msg = "\(r.ok) 条规则"
            if r.skipped > 0 { msg += "，\(r.skipped) 条不支持已跳过" }
            return msg
        case "script":
            try write(NCScriptSource.cachePath(home: home, url: rest), data)
            return "\((data.count + 1023) / 1024) KB"
        default:
            throw StoreError(message: "未知资源类型")
        }
    }

    /// bridge ResourceStore: {"ok": bool, "message": "…", "error": "…"}; records the result.
    static func resourceStore(home: String, key: String, data: Data) -> String {
        do {
            let msg = try store(home: home, key: key, data: data)
            setState(home: home, key: key, error: "")
            return ncJSONString(["ok": true, "message": msg] as [String: Any])
        } catch {
            let e = (error as? StoreError)?.message ?? error.localizedDescription
            setState(home: home, key: key, error: e)
            return ncJSONString(["ok": false, "message": "", "error": e] as [String: Any])
        }
    }

    /// fix/nc-ruleset-fast: the cache file `store` writes for key (the file the conditional-GET validators describe);
    /// nil for an unknown key shape.
    static func cachePath(home: String, key: String) -> String? {
        guard let colon = key.firstIndex(of: ":") else { return nil }
        let kind = String(key[..<colon]), rest = String(key[key.index(after: colon)...])
        switch kind {
        case "module": return rest.isEmpty ? nil : NCEngineConfig.modulePath(home: home, id: rest)
        case "ruleset":
            guard let bar = rest.firstIndex(of: "|") else { return nil }
            return ruleSetPath(home: home, url: String(rest[rest.index(after: bar)...]), kind: String(rest[..<bar]))
        case "script": return rest.isEmpty ? nil : NCScriptSource.cachePath(home: home, url: rest)
        default: return nil
        }
    }

    /// bridge ResourceSetError.
    static func resourceSetError(home: String, key: String, message: String) {
        setState(home: home, key: key, error: message)
    }
}
