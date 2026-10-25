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

    static func compileRegs(_ s: String) -> [NSRegularExpression]? {
        if s.isEmpty { return [] }
        var out: [NSRegularExpression] = []
        for f in s.split(separator: "`", omittingEmptySubsequences: false) {
            guard let re = try? NSRegularExpression(pattern: String(f)) else { return nil }
            out.append(re)
        }
        return out
    }

    static func match(_ re: NSRegularExpression, _ s: String) -> Bool {
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

    static let builtinPolicies: Set<String> =
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

// MARK: - Proxy chains (proxychains.go)

private final class NCChainBuild {
    var proxies: [String: [String: NCJSONValue]] = [:]   // profile's own inline proxies
    var groups: [String: [String: NCJSONValue]] = [:]    // groups before chains
    var providers: [String: [String: NCJSONValue]] = [:]
    var provOrder: [String] = []
    var taken: Set<String> = []
    var generated: Set<String> = []
    var aliases: Set<String> = []
    // per chain
    var newGroups: [NCJSONValue] = []
    var newProviders: [String: NCJSONValue] = [:]
    var udp = false
    var alias = ""
    var err = ""

    func unique(_ base: String) -> String {
        var n = base
        var i = 2
        while taken.contains(n) {
            n = "\(base) #\(i)"
            i += 1
        }
        taken.insert(n)
        return n
    }

    func providerName(_ hop: Int, _ base: String) -> String {
        var n = "\(NCRuntimeSteps.generatedProviderPrefix)\(alias)/\(hop)/\(base)"
        var i = 2
        while providers[n] != nil || newProviders[n] != nil {
            n = "\(NCRuntimeSteps.generatedProviderPrefix)\(alias)/\(hop)/\(base)-\(i)"
            i += 1
        }
        return n
    }

    func hopOverride(_ base: [String: NCJSONValue], _ via: String) -> [String: NCJSONValue] {
        var ov = base
        ov["dialer-proxy"] = .string(via)
        ov["udp"] = .bool(udp)
        return ov
    }

    func copyGroup(
        _ g: [String: NCJSONValue], name: String, via: String,
        hop: Int, hidden: Bool, depth: Int
    ) -> Bool {
        if depth > 4 {
            err = "策略组「\(g.str("name"))」嵌套太深"
            return false
        }
        var c: [String: NCJSONValue] = [:]
        let skip: Set<String> = ["name", "proxies", "use", "include-all", "include-all-proxies",
                                 "include-all-providers", "hidden", "dialer-proxy"]
        for (k, v) in g where !skip.contains(k) { c[k] = v }
        c["name"] = .string(name)
        if hidden { c["hidden"] = .bool(true) }
        var payload: [NCJSONValue] = []
        var seen = Set<String>()
        var explicitNodes: [String] = []
        func addNode(_ n: String, explicit: Bool) {
            if seen.contains(n) { return }
            guard var cp = proxies[n] else { return }
            seen.insert(n)
            cp.removeValue(forKey: "dialer-proxy")
            payload.append(.object(cp))
            if explicit { explicitNodes.append(n) }
        }
        var members: [NCJSONValue] = []
        for m in g.strList("proxies") {
            switch true {
            case NCRuntimeSteps.builtinPolicies.contains(m.uppercased()):
                members.append(.string(m))
            case generated.contains(m) || aliases.contains(m):
                continue // another chain inside a later hop: skipped
            case proxies[m] != nil:
                addNode(m, explicit: true)
            case groups[m] != nil:
                let sub = unique(alias + " › " + m)
                let subHidden = groups[m]?.str("type").lowercased() != "select"
                if !copyGroup(groups[m]!, name: sub, via: via, hop: hop, hidden: subHidden, depth: depth + 1) {
                    return false
                }
                members.append(.string(sub))
            default:
                continue
            }
        }
        let includeAll = g.boolOf("include-all")
        if includeAll || g.boolOf("include-all-proxies") {
            let regs = NCMemberPool.compileRegsPublic(g.str("filter")) ?? []
            for n in proxies.keys.sorted() {
                let ok = regs.isEmpty || regs.contains { NCMemberPool.matchPublic($0, n) }
                if ok { addNode(n, explicit: false) }
            }
        }
        var use: [NCJSONValue] = []
        if !payload.isEmpty {
            let pn = providerName(hop, "nodes")
            newProviders[pn] = .object([
                "type": .string("inline"),
                "payload": .array(payload),
                "override": .object(hopOverride([:], via)),
            ])
            use.append(.string(pn))
        }
        var uses = g.strList("use")
        if includeAll || g.boolOf("include-all-providers") {
            uses = provOrder
        }
        for u in uses {
            guard var cp = providers[u] else { continue }
            cp["override"] = .object(hopOverride(cp.map("override"), via))
            if cp.str("type").lowercased() == "http" {
                cp["interval"] = .number(0)
            }
            let pn = providerName(hop, u)
            newProviders[pn] = .object(cp)
            use.append(.string(pn))
        }
        if let f = c.str("filter").isEmpty ? nil : c.str("filter"), !explicitNodes.isEmpty {
            let quoted = explicitNodes.map {
                Self.quoteMeta($0).replacingOccurrences(of: "`", with: "\\x60")
            }
            c["filter"] = .string(f + "`^(?:" + quoted.joined(separator: "|") + ")$")
        }
        if members.isEmpty && use.isEmpty {
            err = "策略组「\(g.str("name"))」里没有可用的节点"
            return false
        }
        if !members.isEmpty { c["proxies"] = .array(members) }
        if !use.isEmpty { c["use"] = .array(use) }
        generated.insert(name)
        newGroups.append(.object(c))
        return true
    }

    /// Go regexp.QuoteMeta.
    static func quoteMeta(_ s: String) -> String {
        var out = ""
        for ch in s {
            if "\\.+*?()|[]{}^$".contains(ch) { out.append("\\") }
            out.append(ch)
        }
        return out
    }

    func hop(_ m: String, _ via: String, _ name: String, _ k: Int, _ hidden0: Bool) -> Bool {
        var hidden = hidden0
        if let g = groups[m] {
            if hidden && g.str("type").lowercased() == "select" {
                hidden = false
            }
            return copyGroup(g, name: name, via: via, hop: k, hidden: hidden, depth: 0)
        }
        let synthetic: [String: NCJSONValue] = [
            "name": .string(m), "type": .string("select"),
            "proxies": .array([.string(m)]),
        ]
        return copyGroup(synthetic, name: name, via: via, hop: k, hidden: hidden, depth: 0)
    }
}

extension NCRuntimeSteps {

    static let generatedProviderPrefix = "tern.chain/"

    /// bridge applyProxyChains. build=false （安全模式） only clears references.
    static func applyProxyChains(
        _ raw: inout [String: NCJSONValue],
        chains: [NCProxyChain],
        build: Bool
    ) -> [String] {
        if chains.isEmpty { return [] }
        let b = NCChainBuild()
        for p in raw.list("proxies") {
            if case .object(let m) = p {
                let n = m.str("name")
                if !n.isEmpty {
                    b.proxies[n] = m
                    b.taken.insert(n)
                }
            }
        }
        for x in raw.list("proxy-groups") {
            if case .object(let g) = x {
                let n = g.str("name")
                if !n.isEmpty {
                    b.groups[n] = g
                    b.taken.insert(n)
                }
            }
        }
        for (n, x) in raw.map("proxy-providers") {
            if case .object(let m) = x {
                b.providers[n] = m
                b.provOrder.append(n)
            }
        }
        b.provOrder.sort()
        for n in builtinPolicies { b.taken.insert(n) }

        var warns: [String] = []
        var dead = Set<String>()
        var built = 0
        for ch in chains {
            let alias = ch.name.trimmingCharacters(in: .whitespaces)
            if alias.isEmpty { continue }
            if b.aliases.contains(alias) || dead.contains(alias) {
                warns.append("代理链「\(alias)」重名，只用第一条")
                continue
            }
            if b.taken.contains(alias) {
                warns.append("代理链「\(alias)」与已有的节点或策略组同名，未启用")
                continue
            }
            if !build || !ch.enabled {
                dead.insert(alias)
                continue
            }
            func fail(_ why: String) {
                warns.append("代理链「\(alias)」未启用：\(why)")
                dead.insert(alias)
            }
            let members = ch.members
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            if members.count < 2 {
                fail("至少需要两个节点或策略组")
                continue
            }
            var bad = ""
            for m in members {
                if b.aliases.contains(m) || b.generated.contains(m) || m == alias {
                    bad = "不能包含代理链「\(m)」"
                    break
                }
                if b.proxies[m] == nil && b.groups[m] == nil {
                    bad = "当前配置里没有「\(m)」"
                    break
                }
                if m == probeGroup {
                    bad = "不能使用「\(m)」"
                    break
                }
            }
            if !bad.isEmpty {
                fail(bad)
                continue
            }
            b.alias = alias
            b.udp = ch.udp
            b.err = ""
            b.newGroups = []
            b.newProviders = [:]
            b.taken.insert(alias)
            var prev = members[0]
            var ok = true
            for k in 1..<members.count {
                var name = alias
                if k < members.count - 1 {
                    name = b.unique("\(alias) › \(k + 1) \(members[k])")
                }
                if !b.hop(members[k], prev, name, k, name != alias) {
                    ok = false
                    break
                }
                prev = name
            }
            if !ok {
                b.taken.remove(alias)
                fail(b.err)
                continue
            }
            // Commit, then the entry-hop loop check.
            let oldGroups = raw["proxy-groups"]
            let oldProviders = raw["proxy-providers"]
            var pp = raw.map("proxy-providers")
            for (n, v) in b.newProviders { pp[n] = v }
            raw["proxy-providers"] = .object(pp)
            raw["proxy-groups"] = .array(raw.list("proxy-groups") + b.newGroups)
            let graph = NCChainGraph(raw)
            if graph.reach(graph.key(members[0])).contains("g:" + alias) {
                raw["proxy-groups"] = oldGroups
                if oldProviders == nil {
                    raw.removeValue(forKey: "proxy-providers")
                } else {
                    raw["proxy-providers"] = oldProviders
                }
                for x in b.newGroups {
                    if case .object(let m) = x { b.generated.remove(m.str("name")) }
                }
                b.taken.remove(alias)
                fail("「\(members[0])」已经经过这条链，会形成循环")
                continue
            }
            b.aliases.insert(alias)
            built += 1
        }

        if built > 0 {
            var groups = raw.list("proxy-groups")
            for gi in groups.indices {
                guard case .object(var g) = groups[gi] else { continue }
                let name = g.str("name")
                if b.generated.contains(name) || b.aliases.contains(name) { continue }
                let all = g.boolOf("include-all")
                if !all && !g.boolOf("include-all-providers") { continue }
                g.removeValue(forKey: "include-all")
                g.removeValue(forKey: "include-all-providers")
                if all { g["include-all-proxies"] = .bool(true) }
                if !b.provOrder.isEmpty {
                    g["use"] = .array(b.provOrder.map { NCJSONValue.string($0) })
                } else {
                    g.removeValue(forKey: "use")
                }
                groups[gi] = .object(g)
            }
            raw["proxy-groups"] = .array(groups)
        }
        if !dead.isEmpty {
            warns += dropPolicyRefs(&raw, names: dead)
        }
        return warns
    }

    /// bridge dropPolicyRefs.
    static func dropPolicyRefs(
        _ raw: inout [String: NCJSONValue],
        names: Set<String>
    ) -> [String] {
        var warns: [String] = []
        var groups = raw.list("proxy-groups")
        for gi in groups.indices {
            guard case .object(var g) = groups[gi] else { continue }
            let l = g.list("proxies")
            if l.isEmpty { continue }
            var kept = l.filter { !names.contains($0.strValue) }
            if kept.count == l.count { continue }
            if kept.isEmpty && g.list("use").isEmpty
                && !g.boolOf("include-all") && !g.boolOf("include-all-proxies")
                && !g.boolOf("include-all-providers") {
                kept = [.string("DIRECT")]
            }
            g["proxies"] = .array(kept)
            groups[gi] = .object(g)
        }
        raw["proxy-groups"] = .array(groups)
        func fix(_ list: [NCJSONValue]) -> [NCJSONValue] {
            var out: [NCJSONValue] = []
            for v in list {
                var v = v
                if case .string(let s) = v {
                    var parts = splitTopLevel(s)
                    let idx = rulePolicyIndex(parts)
                    if idx >= 0 && names.contains(parts[idx].trimmingCharacters(in: .whitespaces)) {
                        if parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "match" {
                            parts[idx] = "DIRECT"
                            v = .string(parts.joined(separator: ","))
                        } else {
                            warns.append("规则「\(s)」指向未启用的代理链，已跳过")
                            continue
                        }
                    }
                }
                out.append(v)
            }
            return out
        }
        if raw["rules"] != nil { raw["rules"] = .array(fix(raw.list("rules"))) }
        if case .object(var sr) = raw["sub-rules"] ?? .null {
            for k in sr.keys {
                if case .array(let l) = sr[k] ?? .null { sr[k] = .array(fix(l)) }
            }
            raw["sub-rules"] = .object(sr)
        }
        return warns
    }
}
