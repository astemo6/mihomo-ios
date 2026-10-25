import Foundation

/// B5 (nc-dego-rest): 前置代理 / 代理链 candidates and the group 前置代理 store in Swift — ports of
/// bridge/chain.go ChainCandidates + SetGroupChain and bridge/proxychains.go ProxyChainCandidates, plus
/// bridge/inspect.go SaveSelection. The runtime config is built with NCRuntimeBuilder (#112) and the loop check
/// walks NCChainGraph (#112, the chain.go graph), so the candidate lists match what a connect would build.
enum NCChainCandidates {

    /// bridge chainCandidate (JSON tags name / type / group — the views decode ChainCandidate from these).
    struct Candidate: Codable, Hashable {
        var name: String
        var type: String
        var group: Bool
    }

    /// bridge boolOf: a YAML bool or a truthy string ("1", "true", "yes", "on").
    static func boolOf(_ v: NCJSONValue?) -> Bool {
        switch v {
        case .bool(let b)?: return b
        case .string(let s)?:
            switch s.trimmingCharacters(in: .whitespaces).lowercased() {
            case "1", "true", "yes", "on": return true
            default: return false
            }
        default: return false
        }
    }

    /// The runtime tree buildRuntime(readRuntimeProfile(…), o, 0) yields; an empty tree when the build fails
    /// (Go ignores the error and unmarshals nothing).
    private static func runtimeTree(home: String, profilePath: String, req: NCRuntimeBuilder.Request) -> [String: NCJSONValue] {
        let profile = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) ?? Data()
        guard let r = try? NCRuntimeBuilder.build(profile: profile, req: req, fd: 0) else { return [:] }
        return r.raw
    }

    /// bridge ChainCandidates: the policies that can be the 前置代理 of a node (kind "node") or a group (kind
    /// "group") without forming a loop, and the current one.
    static func candidates(home: String, profilePath: String, kind: String, name: String) -> (current: String, candidates: [Candidate]) {
        var req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        req.settings.home = "" // Go: o.home = "" — no custom rules (and the other home-gated steps, as in Go)
        var cur = ""
        if kind == "group" {
            cur = req.chains[name] ?? ""
            req.chains.removeValue(forKey: name)
        }
        let raw = runtimeTree(home: home, profilePath: profilePath, req: req)
        let g = NCChainGraph(raw)
        let target: String
        if kind == "group" {
            target = "g:" + name
        } else {
            target = "p:" + name
            if var p = g.proxies[name] {
                cur = p.str("dialer-proxy")
                p.removeValue(forKey: "dialer-proxy")
                g.proxies[name] = p
            }
        }
        var out: [Candidate] = []
        for n in g.order where n != name {
            let k = g.key(n)
            if g.reach(k).contains(target) { continue }
            let isGroup = k.hasPrefix("g:")
            let type = isGroup ? (g.groups[n]?.str("type") ?? "") : (g.proxies[n]?.str("type") ?? "")
            out.append(Candidate(name: n, type: type, group: isGroup))
        }
        return (cur, out)
    }

    /// bridge SetGroupChain: stores (via non-empty) or clears the 前置代理 of a group for the profile in
    /// <home>/groups.json {"<profile id>": {"dialer": {"Group": "Via"}}}. Returns "" or an error.
    static func setGroupChain(home: String, profilePath: String, group: String, via: String) -> String {
        if !via.isEmpty {
            let c = candidates(home: home, profilePath: profilePath, kind: "group", name: group)
            if !c.candidates.contains(where: { $0.name == via }) {
                return "「\(via)」不能作为「\(group)」的前置代理（不存在或会形成循环）"
            }
        }
        let path = URL(fileURLWithPath: home).appendingPathComponent("groups.json").path
        return NCPathLock.shared.withLock(for: path) { () -> String in
            // Unknown keys of groups.json and of each profile entry are kept (Go's struct dropped them).
            var all: [String: Any] = [:]
            if let d = FileManager.default.contents(atPath: path),
               let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] {
                all = o
            }
            let id = NCRuntimeFiles.profileID(fromPath: profilePath)
            var s = all[id] as? [String: Any] ?? [:]
            var dialer = s["dialer"] as? [String: String] ?? [:]
            if via.isEmpty {
                dialer.removeValue(forKey: group)
            } else {
                dialer[group] = via
            }
            if dialer.isEmpty { s.removeValue(forKey: "dialer") } else { s["dialer"] = dialer }
            all[id] = s
            do {
                let b = try JSONSerialization.data(withJSONObject: all, options: [.prettyPrinted, .sortedKeys])
                try NCRuntimeFiles.writeAtomic(b, to: path)
            } catch {
                return error.localizedDescription
            }
            return ""
        }
    }

    /// bridge ProxyChainCandidates: the profile's visible groups, then its proxies, without the chains of
    /// proxy-chains.json (a chain can use any of them).
    static func proxyChainCandidates(home: String, profilePath: String) -> [Candidate] {
        var req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        req.noProxyChains = true
        let raw = runtimeTree(home: home, profilePath: profilePath, req: req)
        var out: [Candidate] = []
        for x in raw.list("proxy-groups") {
            guard case .object(let g) = x else { continue }
            let n = g.str("name")
            if n.isEmpty || n == NCRuntimeSteps.probeGroup || n == "GLOBAL" || boolOf(g["hidden"]) { continue }
            out.append(Candidate(name: n, type: g.str("type"), group: true))
        }
        for x in raw.list("proxies") {
            guard case .object(let p) = x else { continue }
            let n = p.str("name")
            if !n.isEmpty { out.append(Candidate(name: n, type: p.str("type"), group: false)) }
        }
        return out
    }
}

/// bridge/inspect.go selections: <profile>.selected.json next to the profile (group → node chosen in the app
/// while disconnected; applied by the core on the next connect).
enum NCProfileSelections {
    /// bridge selectionsPath: the profile path without its extension + ".selected.json".
    static func path(for profilePath: String) -> String {
        (profilePath as NSString).deletingPathExtension + ".selected.json"
    }

    static func read(_ profilePath: String) -> [String: String] {
        guard let d = FileManager.default.contents(atPath: path(for: profilePath)),
              let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [:] }
        return m
    }

    /// bridge SaveSelection: records group → node (node "" removes the entry). Returns "" or an error.
    @discardableResult
    static func save(_ profilePath: String, group: String, node: String) -> String {
        let p = path(for: profilePath)
        return NCPathLock.shared.withLock(for: p) { () -> String in
            var m = read(profilePath)
            if node.isEmpty { m.removeValue(forKey: group) } else { m[group] = node }
            do {
                let enc = JSONEncoder()
                enc.outputFormatting = [.prettyPrinted, .sortedKeys]
                try NCRuntimeFiles.writeAtomic(try enc.encode(m), to: p)
            } catch {
                return error.localizedDescription
            }
            return ""
        }
    }
}
