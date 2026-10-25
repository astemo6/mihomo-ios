import Foundation
import CryptoKit

/// Pure Swift implementation of policy group editing operations (去 Go 第 B5 批).
/// Replaces bridge/groupedits.go and bridge/groupmembers.go functions:
/// - GroupSpecs
/// - GroupEditCheck
/// - GroupPreview
enum NCGroupEditing {

    // MARK: - GroupSpecs

    /// Returns the profile's own group specs (before user's edits, with node subscriptions merged)
    /// for the group editor: {"groups":[GroupSpec], "providers":[String], "proxies":[String], "chains":[String]}.
    static func specs(home: URL, profilePath: String) -> GroupSpecsResult {
        let profileURL = URL(fileURLWithPath: profilePath)
        let profileID = profileURL.deletingPathExtension().lastPathComponent
        let chains = enabledChainNames(home: home)

        guard let content = try? String(contentsOf: profileURL, encoding: .utf8),
              let docVal = NCYAML.parse(content),
              case .object(var raw) = docVal else {
            return GroupSpecsResult(groups: [], providers: [], proxies: [], chains: chains)
        }

        // Merge enabled node subscriptions as proxy-providers and into default/chosen group `use:`
        mergeNodeSubs(raw: &raw, home: home)

        // Groups
        var gs: [GroupSpec] = []
        if let groups = raw["proxy-groups"]?.array {
            for gVal in groups {
                if let gObj = gVal.object {
                    gs.append(specFromGroup(gObj))
                }
            }
        }

        // Providers
        var deletedProviders = Set<String>()
        let ovURL = home.appendingPathComponent("provider-overrides.json")
        if let ovData = try? Data(contentsOf: ovURL),
           let allOverrides = try? JSONDecoder().decode([String: [String: ProviderOverride]].self, from: ovData),
           let profOverrides = allOverrides[profileID] {
            for (name, ov) in profOverrides where ov.deleted == true {
                deletedProviders.insert(name)
            }
        }

        var pv: [String] = []
        if let pp = raw["proxy-providers"]?.object {
            for name in pp.keys {
                if !deletedProviders.contains(name) {
                    pv.append(name)
                }
            }
            pv.sort()
        }

        // Proxies (nodes in profile)
        var px: [String] = []
        if let proxies = raw["proxies"]?.array {
            for p in proxies {
                if let name = p["name"]?.string, !name.isEmpty {
                    px.append(name)
                }
            }
        }

        return GroupSpecsResult(groups: gs, providers: pv, proxies: px, chains: chains)
    }

    /// JSON string export for bridge compatibility.
    static func groupSpecsJSON(home: URL, profilePath: String) -> String {
        let r = specs(home: home, profilePath: profilePath)
        guard let data = try? JSONEncoder().encode(r),
              let str = String(data: data, encoding: .utf8) else {
            return "{\"groups\":[],\"providers\":[],\"proxies\":[],\"chains\":[]}"
        }
        return str
    }

    // MARK: - GroupEditCheck

    /// Validates candidate group edits for the profile:
    /// - Checks JSON / YAML decode
    /// - Checks name collisions in added groups
    /// - Checks for groups left with no members
    /// - Checks for cycle references among groups
    /// - Checks that proxy members actually exist (member existence)
    /// Returns empty string if valid, or a descriptive reason if invalid.
    static func editCheck(home: URL, profilePath: String, edits: GroupEdits) -> String {
        let profileURL = URL(fileURLWithPath: profilePath)
        guard let content = try? String(contentsOf: profileURL, encoding: .utf8),
              let docVal = NCYAML.parse(content),
              case .object(var raw) = docVal else {
            return "无法读取或解析配置文件"
        }

        let groups = raw["proxy-groups"]?.array?.compactMap { $0.object } ?? []
        var renames: [String: String] = [:]
        var deleted = Set<String>()
        var kept: [[String: NCJSONValue]] = []

        // Apply edits / deletions to existing groups
        for g in groups {
            guard let name = g["name"]?.string else {
                kept.append(g)
                continue
            }
            if let ed = edits.edits?[name] {
                if ed.deleted == true {
                    deleted.insert(name)
                    continue
                }
                if let spec = ed.spec {
                    var s = spec
                    if s.name.trimmingCharacters(in: .whitespaces).isEmpty { s.name = name }
                    let updated = writeSpec(to: g, spec: s)
                    if s.name != name {
                        renames[name] = s.name
                    }
                    kept.append(updated)
                    continue
                }
            }
            kept.append(g)
        }

        var existing = Set(kept.compactMap { $0["name"]?.string })

        // GLOBAL edit when not present in file
        if let ed = edits.edits?["GLOBAL"], ed.deleted != true, let spec = ed.spec, !existing.contains("GLOBAL") {
            var s = spec
            s.name = "GLOBAL"
            let g = writeSpec(to: [:], spec: s)
            kept.append(g)
            existing.insert("GLOBAL")
        }

        // Added groups
        for s in edits.added ?? [] {
            let trimmed = s.name.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || existing.contains(trimmed) {
                return "新建的策略组「\(trimmed)」与已有名称重复，已跳过"
            }
            let g = writeSpec(to: [:], spec: s)
            kept.append(g)
            existing.insert(trimmed)
        }

        // Propagate deletions and renames to group proxies
        for i in 0..<kept.count {
            if let px = kept[i]["proxies"]?.array {
                var newPx: [NCJSONValue] = []
                for p in px {
                    guard let pName = p.string else { continue }
                    if deleted.contains(pName) { continue }
                    let finalName = renames[pName] ?? pName
                    newPx.append(.string(finalName))
                }
                if newPx.isEmpty {
                    kept[i].removeValue(forKey: "proxies")
                } else {
                    kept[i]["proxies"] = .array(newPx)
                }
            }
        }

        // Empty group check
        for g in kept {
            let name = g["name"]?.string ?? ""
            let proxies = g["proxies"]?.array ?? []
            let use = g["use"]?.array ?? []
            let includeAll = g["include-all"]?.bool == true
            let includeAllProxies = g["include-all-proxies"]?.bool == true
            let includeAllProviders = g["include-all-providers"]?.bool == true
            if proxies.isEmpty && use.isEmpty && !includeAll && !includeAllProxies && !includeAllProviders {
                return "策略组「\(name)」没有任何成员"
            }
        }

        // Cycle check over group -> group members
        var groupProxyMap: [String: [String]] = [:]
        for g in kept {
            if let n = g["name"]?.string {
                groupProxyMap[n] = g["proxies"]?.array?.compactMap { $0.string } ?? []
            }
        }

        var state: [String: Int] = [:] // 0 = unvisited, 1 = visiting, 2 = visited
        func visit(_ n: String) -> String? {
            if state[n] == 1 { return n }
            if state[n] == 2 { return nil }
            state[n] = 1
            for m in groupProxyMap[n] ?? [] {
                if groupProxyMap[m] != nil {
                    if let c = visit(m) { return c }
                }
            }
            state[n] = 2
            return nil
        }

        for n in groupProxyMap.keys {
            if let c = visit(n) {
                return "策略组「\(c)」形成了循环引用"
            }
        }

        // Member existence check
        var knownMembers: Set<String> = builtinMembers
        for n in groupProxyMap.keys { knownMembers.insert(n) }
        if let pxList = raw["proxies"]?.array {
            for p in pxList {
                if let n = p["name"]?.string, !n.isEmpty {
                    knownMembers.insert(n)
                }
            }
        }
        for ch in enabledChainNames(home: home) {
            knownMembers.insert(ch)
        }

        for (gName, members) in groupProxyMap {
            for m in members {
                if !knownMembers.contains(m) {
                    return "修改后的配置无法使用：代理或策略组「\(m)」不存在"
                }
            }
        }

        return ""
    }

    /// JSON overload for GroupEditCheck
    static func editCheck(home: URL, profilePath: String, editsJSON: String) -> String {
        guard let data = editsJSON.data(using: .utf8),
              let edits = try? JSONDecoder().decode(GroupEdits.self, from: data) else {
            return "编辑数据格式错误"
        }
        return editCheck(home: home, profilePath: profilePath, edits: edits)
    }

    /// Replaces the fields managed by the group editor in a group dict, leaving other fields intact.
    static func writeSpec(to dict: [String: NCJSONValue], spec: GroupSpec) -> [String: NCJSONValue] {
        var g = dict
        g["name"] = .string(spec.name)
        g["type"] = .string(spec.type)
        if spec.proxies.isEmpty {
            g.removeValue(forKey: "proxies")
        } else {
            g["proxies"] = .array(spec.proxies.map { .string($0) })
        }
        if let use = spec.use, !use.isEmpty {
            g["use"] = .array(use.map { .string($0) })
        } else {
            g.removeValue(forKey: "use")
        }
        if spec.includeAll == true { g["include-all"] = .bool(true) } else { g.removeValue(forKey: "include-all") }
        if spec.includeAllProxies == true && spec.includeAll != true {
            g["include-all-proxies"] = .bool(true)
        } else {
            g.removeValue(forKey: "include-all-proxies")
        }
        if spec.includeAllProviders == true && spec.includeAll != true {
            g["include-all-providers"] = .bool(true)
        } else {
            g.removeValue(forKey: "include-all-providers")
        }
        if let et = spec.excludeType, !et.isEmpty { g["exclude-type"] = .string(et) } else { g.removeValue(forKey: "exclude-type") }
        if let f = spec.filter, !f.isEmpty { g["filter"] = .string(f) } else { g.removeValue(forKey: "filter") }
        if let ef = spec.excludeFilter, !ef.isEmpty { g["exclude-filter"] = .string(ef) } else { g.removeValue(forKey: "exclude-filter") }
        let auto = spec.type.lowercased() != "select"
        if auto, let u = spec.url, !u.isEmpty { g["url"] = .string(u) } else { g.removeValue(forKey: "url") }
        if auto, let i = spec.interval, i > 0 { g["interval"] = .number(Double(i)) } else { g.removeValue(forKey: "interval") }
        if spec.type.lowercased() == "url-test", let t = spec.tolerance, t > 0 { g["tolerance"] = .number(Double(t)) } else { g.removeValue(forKey: "tolerance") }
        if auto, let l = spec.lazy { g["lazy"] = .bool(l) } else { g.removeValue(forKey: "lazy") }
        if spec.type.lowercased() == "load-balance", let st = spec.strategy, !st.isEmpty { g["strategy"] = .string(st) } else { g.removeValue(forKey: "strategy") }
        if let icon = spec.icon, !icon.isEmpty { g["icon"] = .string(icon) } else { g.removeValue(forKey: "icon") }
        if spec.hidden == true { g["hidden"] = .bool(true) } else { g.removeValue(forKey: "hidden") }
        return g
    }

    /// Lists enabled proxy chains that have at least 2 hops.
    static func enabledChainNames(home: URL) -> [String] {
        let url = home.appendingPathComponent("proxy-chains.json")
        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode([ProxyChain].self, from: data) else {
            return []
        }
        var out: [String] = []
        var seen = Set<String>()
        for c in list {
            let n = c.name.trimmingCharacters(in: .whitespaces)
            if c.enabled && !n.isEmpty && c.members.count >= 2 && !seen.contains(n) {
                seen.insert(n)
                out.append(n)
            }
        }
        return out
    }

    private static func specFromGroup(_ g: [String: NCJSONValue]) -> GroupSpec {
        var s = GroupSpec(name: g["name"]?.string ?? "")
        s.type = g["type"]?.string?.lowercased() ?? "select"
        s.proxies = g["proxies"]?.array?.compactMap { $0.string } ?? []
        if let use = g["use"]?.array?.compactMap({ $0.string }), !use.isEmpty {
            s.use = use
        }
        s.includeAll = g["include-all"]?.bool
        s.includeAllProxies = g["include-all-proxies"]?.bool
        s.includeAllProviders = g["include-all-providers"]?.bool
        s.excludeType = g["exclude-type"]?.string
        s.filter = g["filter"]?.string
        s.excludeFilter = g["exclude-filter"]?.string
        s.url = g["url"]?.string
        s.interval = g["interval"]?.int
        s.tolerance = g["tolerance"]?.int
        s.lazy = g["lazy"]?.bool
        s.strategy = g["strategy"]?.string
        s.icon = g["icon"]?.string
        s.hidden = g["hidden"]?.bool
        return s
    }

    private static let builtinMembers: Set<String> = [
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE"
    ]

    /// Default policy groups that accept node subscriptions (select with real nodes, and url-test).
    private static func isDefaultSubGroup(_ g: [String: NCJSONValue]) -> Bool {
        if g["hidden"]?.bool == true { return false }
        let name = g["name"]?.string ?? ""
        if name == "MIHOMO-PROBE" { return false }
        let type = g["type"]?.string?.lowercased() ?? ""
        switch type {
        case "url-test":
            return true
        case "select":
            if let use = g["use"]?.array, !use.isEmpty { return true }
            if g["include-all"]?.bool == true || g["include-all-proxies"]?.bool == true || g["include-all-providers"]?.bool == true {
                return true
            }
            if let px = g["proxies"]?.array {
                for p in px {
                    if let s = p.string, !builtinMembers.contains(s.uppercased()) {
                        return true
                    }
                }
            }
            return false
        default:
            return false
        }
    }

    /// Merges enabled node subscriptions into raw config proxy-providers and group `use:`.
    private static func mergeNodeSubs(raw: inout [String: NCJSONValue], home: URL) {
        let subsURL = home.appendingPathComponent("node-subscriptions.json")
        guard let data = try? Data(contentsOf: subsURL),
              let subs = try? JSONDecoder().decode([NodeSubscription].self, from: data),
              !subs.isEmpty else {
            return
        }

        var pp = raw["proxy-providers"]?.object ?? [:]
        var groups = raw["proxy-groups"]?.array?.compactMap { $0.object } ?? []
        guard !groups.isEmpty else { return }

        var added = false
        for s in subs {
            guard s.enabled && !s.id.isEmpty else { continue }
            let cachePath = home.appendingPathComponent("nodesubs/\(s.id).yaml").path
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: cachePath),
                  let size = attrs[.size] as? NSNumber, size.int64Value > 0 else {
                continue
            }

            let baseName = s.name.trimmingCharacters(in: .whitespaces).isEmpty ? "订阅" : s.name.trimmingCharacters(in: .whitespaces)
            var provName = baseName
            var idx = 2
            while pp[provName] != nil {
                provName = "\(baseName) \(idx)"
                idx += 1
            }

            pp[provName] = .object([
                "type": .string("file"),
                "path": .string("./nodesubs/\(s.id).yaml")
            ])
            added = true

            let want = Set(s.groups ?? [])
            var hit = false
            for i in 0..<groups.count {
                let gName = groups[i]["name"]?.string ?? ""
                if (!want.isEmpty && want.contains(gName)) || (want.isEmpty && isDefaultSubGroup(groups[i])) {
                    var currentUse = groups[i]["use"]?.array?.compactMap { $0.string } ?? []
                    currentUse.append(provName)
                    groups[i]["use"] = .array(currentUse.map { .string($0) })
                    hit = true
                }
            }
            if !hit {
                for i in 0..<groups.count {
                    if isDefaultSubGroup(groups[i]) {
                        var currentUse = groups[i]["use"]?.array?.compactMap { $0.string } ?? []
                        currentUse.append(provName)
                        groups[i]["use"] = .array(currentUse.map { .string($0) })
                    }
                }
            }
        }

        if added {
            raw["proxy-providers"] = .object(pp)
            raw["proxy-groups"] = .array(groups.map { .object($0) })
        }
    }
}
