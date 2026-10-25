import Foundation

/// E-B1 stage 3d: ports of bridge/groupmembers.go (the offline
/// member expansion, needed by the dial graph) and bridge/chain.go
/// (group 前置代理 + the loop guard). Regexes are ICU where Go uses
/// regexp2; group filters compile case-sensitively unless the
/// pattern carries (?i), as in the core.

// MARK: - Member pool (groupmembers.go)

struct NCMemberPool {
    var proxies: [String] = []                 // profile proxies in YAML order
    var types: [String: String] = [:]          // node / group name -> YAML type
    var providers: [String: [String]] = [:]     // provider -> node names

    static func adapterTypeName(_ name: String, _ yamlType: String) -> String {
        switch name.uppercased() {
        case "DIRECT": return "Direct"
        case "REJECT": return "Reject"
        case "REJECT-DROP": return "RejectDrop"
        case "COMPATIBLE": return "Compatible"
        case "PASS": return "Pass"
        case "PASS-RULE": return "PassRule"
        default: break
        }
        switch yamlType.lowercased() {
        case "ss": return "Shadowsocks"
        case "ssr": return "ShadowsocksR"
        case "gost-relay": return "GostRelay"
        case "select": return "Selector"
        case "url-test": return "URLTest"
        case "fallback": return "Fallback"
        case "load-balance": return "LoadBalance"
        case "": return "Unknown"
        default: return yamlType
        }
    }

    private static func compileRegs(_ s: String) -> [NSRegularExpression]? {
        if s.isEmpty { return [] }
        var out: [NSRegularExpression] = []
        for f in s.split(separator: "`", omittingEmptySubsequences: false) {
            guard let re = try? NSRegularExpression(pattern: String(f)) else { return nil }
            out.append(re)
        }
        return out
    }

    private static func match(_ re: NSRegularExpression, _ s: String) -> Bool {
        re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// groupMembers: (members, isOnlyFallback). A filter that does
    /// not compile yields ([fallback], true) like Go's error path —
    /// the chain graph ignores the error return.
    func groupMembers(_ g: [String: NCJSONValue]) -> (members: [String], empty: Bool) {
        var fallback = g.str("empty-fallback")
        if fallback.isEmpty { fallback = "COMPATIBLE" }
        guard let filterRegs = Self.compileRegs(g.str("filter")) else {
            return ([fallback], true)
        }
        guard let excludeRegs = Self.compileRegs(g.str("exclude-filter")) else {
            return ([fallback], true)
        }
        let excludeTypes: [String]? = g.str("exclude-type").isEmpty
            ? nil : g.str("exclude-type").split(separator: "|").map(String.init)
        let includeAll = g.boolOf("include-all")
        let includeProviders = includeAll || g.boolOf("include-all-providers")
        let includeProxies = includeAll || g.boolOf("include-all-proxies")
        var use = g.strList("use")
        if includeProviders {
            use = providers.keys.sorted()
        }
        var proxies = g.strList("proxies")
        var parseFallback = false
        if includeProxies {
            let all = self.proxies.sorted()
            if !filterRegs.isEmpty {
                for p in all {
                    for r in filterRegs where Self.match(r, p) {
                        proxies.append(p)
                    }
                }
            } else {
                proxies.append(contentsOf: all)
            }
            if proxies.isEmpty && use.isEmpty {
                proxies = [fallback]
                parseFallback = true
            }
        }
        var list: [String] = []
        var nProviders = 0
        if !proxies.isEmpty {
            nProviders += 1
            list.append(contentsOf: proxies)
        }
        for u in use {
            guard let nodes = providers[u] else { continue }
            nProviders += 1
            if filterRegs.isEmpty {
                list.append(contentsOf: nodes)
                continue
            }
            var seen = Set<String>()
            for r in filterRegs {
                for n in nodes where !seen.contains(n) && Self.match(r, n) {
                    seen.insert(n)
                    list.append(n)
                }
            }
        }
        if nProviders > 1 && filterRegs.count > 1 {
            var re: [String] = []
            var seen = Set<String>()
            for r in filterRegs {
                for n in list where !seen.contains(n) && Self.match(r, n) {
                    seen.insert(n)
                    re.append(n)
                }
            }
            for n in list where !seen.contains(n) {
                seen.insert(n)
                re.append(n)
            }
            list = re
        }
        if !excludeRegs.isEmpty {
            list = list.filter { n in !excludeRegs.contains { Self.match($0, n) } }
        }
        if let excludeTypes {
            list = list.filter { n in
                let t = Self.adapterTypeName(n, types[n] ?? "")
                return !excludeTypes.contains { $0.lowercased() == t.lowercased() }
            }
        }
        if list.isEmpty { return ([fallback], true) }
        if parseFallback && list.count == 1 && list[0] == fallback { return (list, true) }
        var seen = Set<String>()
        return (list.filter { seen.insert($0).inserted }, false)
    }
}

// MARK: - Chain graph (chain.go)

private final class NCChainGraph {
    var proxies: [String: [String: NCJSONValue]] = [:]
    var groups: [String: [String: NCJSONValue]] = [:]
    var providers: [String: [String: NCJSONValue]] = [:]
    var order: [String] = [] // proxies, then groups

    init(_ raw: [String: NCJSONValue]) {
        for p in raw.list("proxies") {
            if case .object(let m) = p {
                let n = m.str("name")
                if !n.isEmpty {
                    proxies[n] = m
                    order.append(n)
                }
            }
        }
        for x in raw.list("proxy-groups") {
            if case .object(let m) = x {
                let n = m.str("name")
                if !n.isEmpty {
                    groups[n] = m
                    order.append(n)
                }
            }
        }
        for (n, x) in raw.map("proxy-providers") {
            if case .object(let m) = x { providers[n] = m }
        }
    }

    /// Write the (possibly mutated) proxy / provider maps back into
    /// the tree by name — Go mutates shared maps in place.
    func flush(_ raw: inout [String: NCJSONValue]) {
        var list = raw.list("proxies")
        for i in list.indices {
            if case .object(let m) = list[i], let updated = proxies[m.str("name")] {
                list[i] = .object(updated)
            }
        }
        if raw["proxies"] != nil || !list.isEmpty {
            raw["proxies"] = .array(list)
        }
        var pp = raw.map("proxy-providers")
        for (n, m) in providers { pp[n] = .object(m) }
        if raw["proxy-providers"] != nil || !providers.isEmpty {
            raw["proxy-providers"] = .object(pp)
        }
    }

    func key(_ name: String) -> String {
        if proxies[name] != nil { return "p:" + name }
        if groups[name] != nil { return "g:" + name }
        return ""
    }

    func edges(_ key: String) -> [String] {
        let kind = String(key.prefix(2))
        let name = String(key.dropFirst(2))
        var out: [String] = []
        func add(_ n: String) {
            if proxies[n] != nil { out.append("p:" + n) }
            else if groups[n] != nil { out.append("g:" + n) }
        }
        switch kind {
        case "p:":
            if let p = proxies[name] {
                let d = p.str("dialer-proxy")
                if !d.isEmpty { add(d) }
            }
        case "g:":
            guard let m = groups[name] else { break }
            for x in m.list("proxies") { add(x.strValue) }
            if NCRuntimeSteps.truthy(m["include-all"]) || NCRuntimeSteps.truthy(m["include-all-proxies"]) {
                var pm = m
                pm.removeValue(forKey: "use")
                pm.removeValue(forKey: "include-all")
                pm.removeValue(forKey: "include-all-providers")
                pm["include-all-proxies"] = .bool(true)
                var pool = NCMemberPool()
                pool.proxies = proxies.keys.sorted() // Go iterates a map; edges feed a set
                for (n, p) in proxies { pool.types[n] = p.str("type") }
                for (n, gm) in groups { pool.types[n] = gm.str("type") }
                let (ms, _) = pool.groupMembers(pm)
                var explicit = Set<String>()
                for x in m.list("proxies") { explicit.insert(x.strValue) }
                for n in ms where proxies[n] != nil && !explicit.contains(n) {
                    out.append("p:" + n)
                }
            }
            var uses = m.list("use").map { $0.strValue }
            if NCRuntimeSteps.truthy(m["include-all"]) || NCRuntimeSteps.truthy(m["include-all-providers"]) {
                uses = Array(providers.keys)
            }
            for x in uses where providers[x] != nil {
                out.append("v:" + x)
            }
        case "v:":
            if let pv = providers[name] {
                let d = pv.map("override").str("dialer-proxy")
                if !d.isEmpty { add(d) }
            }
        default: break
        }
        return out
    }

    func reach(_ start: String) -> Set<String> {
        var seen = Set<String>()
        var stack = [start]
        while let k = stack.popLast() {
            if seen.contains(k) { continue }
            seen.insert(k)
            stack.append(contentsOf: edges(k))
        }
        return seen
    }

    func loopsThrough(_ via: String, _ target: String) -> Bool {
        let k = key(via)
        if k.isEmpty { return false }
        return reach(k).contains(target)
    }
}

extension NCRuntimeSteps {

    private static let builtinPolicies: Set<String> =
        ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]

    /// bridge applyChains: group chains, then the loop guard.
    static func applyChains(
        _ raw: inout [String: NCJSONValue],
        chains: [String: String]
    ) -> [String] {
        applyGroupChains(&raw, chains: chains) + breakChainLoops(&raw)
    }

    /// bridge applyGroupChains.
    static func applyGroupChains(
        _ raw: inout [String: NCJSONValue],
        chains: [String: String]
    ) -> [String] {
        if chains.isEmpty { return [] }
        var warns: [String] = []
        for group in chains.keys.sorted() {
            let via = chains[group]!
            let g = NCChainGraph(raw)
            guard let gm = g.groups[group], !via.isEmpty else { continue }
            if g.key(via).isEmpty && via != "DIRECT" {
                warns.append("策略组「\(group)」的前置代理「\(via)」不存在，已忽略")
                continue
            }
            if via == group || g.loopsThrough(via, "g:" + group) {
                warns.append("策略组「\(group)」的前置代理「\(via)」会形成循环，已忽略")
                continue
            }
            var skipped = 0
            for x in gm.list("proxies") {
                let n = x.strValue
                guard var p = g.proxies[n], n != via else { continue }
                if g.loopsThrough(via, "p:" + n) {
                    skipped += 1
                    continue
                }
                p["dialer-proxy"] = .string(via)
                g.proxies[n] = p
            }
            for x in gm.list("use") {
                let name = x.strValue
                guard var pv = g.providers[name] else { continue }
                if g.loopsThrough(via, "v:" + name) {
                    skipped += 1
                    continue
                }
                var ov = pv.map("override")
                ov["dialer-proxy"] = .string(via)
                pv["override"] = .object(ov)
                g.providers[name] = pv
            }
            if skipped > 0 {
                warns.append("策略组「\(group)」：\(skipped) 个成员会与前置代理「\(via)」形成循环，已跳过")
            }
            g.flush(&raw)
        }
        return warns
    }

    /// bridge breakChainLoops.
    static func breakChainLoops(_ raw: inout [String: NCJSONValue]) -> [String] {
        var warns: [String] = []
        let g = NCChainGraph(raw)
        for n in g.order {
            guard var p = g.proxies[n] else { continue }
            let d = p.str("dialer-proxy")
            if d.isEmpty { continue }
            if builtinPolicies.contains(d.uppercased()) { continue }
            if g.key(d).isEmpty {
                p.removeValue(forKey: "dialer-proxy")
                g.proxies[n] = p
                warns.append("节点「\(n)」的前置代理「\(d)」不存在，已忽略")
                continue
            }
            if d == n || g.loopsThrough(d, "p:" + n) {
                p.removeValue(forKey: "dialer-proxy")
                g.proxies[n] = p
                warns.append("节点「\(n)」的前置代理「\(d)」会形成循环，已忽略")
            }
        }
        for (n, pv) in g.providers {
            var pv = pv
            var ov = pv.map("override")
            let d = ov.str("dialer-proxy")
            if d.isEmpty || builtinPolicies.contains(d.uppercased()) { continue }
            if g.key(d).isEmpty || g.loopsThrough(d, "v:" + n) {
                ov.removeValue(forKey: "dialer-proxy")
                pv["override"] = .object(ov)
                g.providers[n] = pv
                warns.append("节点集「\(n)」的前置代理「\(d)」无效或会形成循环，已忽略")
            }
        }
        g.flush(&raw)
        return warns
    }
}
