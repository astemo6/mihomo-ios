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

    // MARK: - Helpers for GroupSpecs

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
