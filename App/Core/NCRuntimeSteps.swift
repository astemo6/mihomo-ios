import Foundation

/// E-B1 stage 3: the buildRuntimeWith satellite steps, ported file by
/// file from the bridge. Each step mutates the config tree in place
/// and returns the warnings the Go side logged (the builder surfaces
/// them through NSLog at prepare time, like the core log).
/// This file: bridge/profileruleoverrides.go (the profile's own rule
/// and Final overrides) plus the mitm helpers it uses
/// (ProfileNames / ResolvePolicy, bridge/mitm/rules.go).

enum NCRuntimeSteps {

    // MARK: - mitm ProfileNames / ResolvePolicy

    /// mitm ProfileNames: group and proxy names and the first select
    /// group of the tree (the "__MITM__" placeholder excluded).
    static func profileNames(_ raw: [String: NCJSONValue]) -> (groups: [String], proxies: [String], firstSelect: String) {
        var groups: [String] = []
        var proxies: [String] = []
        var firstSelect = ""
        for g in raw.list("proxy-groups") {
            guard case .object(let m) = g else { continue }
            let n = m.str("name")
            if n.isEmpty || n == "__MITM__" { continue }
            groups.append(n)
            if firstSelect.isEmpty && m.str("type").lowercased() == "select" { firstSelect = n }
        }
        for p in raw.list("proxies") {
            guard case .object(let m) = p else { continue }
            let n = m.str("name")
            if !n.isEmpty && n != "__MITM__" { proxies.append(n) }
        }
        return (groups, proxies, firstSelect)
    }

    /// mitm ResolvePolicy.
    static func resolvePolicy(_ name: String, groups: [String], proxies: [String], firstSelect: String) -> String? {
        let n = name.trimmingCharacters(in: .whitespaces)
        let u = n.uppercased()
        switch true {
        case u == "DIRECT": return "DIRECT"
        case u == "REJECT-DROP": return "REJECT-DROP"
        case u.hasPrefix("REJECT"): return "REJECT"
        case u == "PASS": return "PASS"
        default: break
        }
        for g in groups where g == n { return g }
        for g in groups where g.lowercased() == n.lowercased() { return g }
        for p in proxies where p.lowercased() == n.lowercased() { return p }
        if (u == "PROXY" || u == "PROXIES") && !firstSelect.isEmpty { return firstSelect }
        return nil
    }

    // MARK: - Rule text helpers

    /// bridge splitRuleTop: split on commas outside parentheses
    /// (depth never goes negative, unlike the mitm variant).
    static func splitRuleTop(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var start = s.startIndex
        var i = s.startIndex
        while i < s.endIndex {
            switch s[i] {
            case "(": depth += 1
            case ")": if depth > 0 { depth -= 1 }
            case "," where depth == 0:
                out.append(String(s[start..<i]).trimmingCharacters(in: .whitespaces))
                start = s.index(after: i)
            default: break
            }
            i = s.index(after: i)
        }
        out.append(String(s[start...]).trimmingCharacters(in: .whitespaces))
        return out
    }

    /// bridge profileRuleKey.
    static func profileRuleKey(_ rule: String) -> String {
        splitRuleTop(rule.trimmingCharacters(in: .whitespaces)).joined(separator: ",")
    }

    static func isMatchRule(_ rule: String) -> Bool {
        let t = rule.trimmingCharacters(in: .whitespaces)
            .split(separator: ",", maxSplits: 1).first.map(String.init) ?? ""
        let u = t.uppercased()
        return u == "MATCH" || u == "FINAL"
    }

    /// bridge splitRule (inspect.go): the policy a rule names.
    static func ruleTargetOf(_ rule: String) -> String {
        let t = (rule.trimmingCharacters(in: .whitespaces)
            .split(separator: ",", maxSplits: 1).first.map(String.init) ?? "").uppercased()
        let parts = splitRuleTop(rule)
        switch t {
        case "MATCH", "FINAL":
            return parts.count > 1 ? parts[1] : ""
        case "AND", "OR", "NOT", "SUB-RULE":
            return parts.count > 2 ? parts[2] : ""
        default:
            break
        }
        // splitRule's generic case: payload is the first field after the
        // type, the policy the second (plain comma split, not top-level).
        let line = rule.trimmingCharacters(in: .whitespaces)
        guard let comma = line.firstIndex(of: ",") else { return "" }
        let rest = String(line[line.index(after: comma)...])
        let fields = rest.split(separator: ",", omittingEmptySubsequences: false)
        return fields.count > 1 ? String(fields[1]).trimmingCharacters(in: .whitespaces) : ""
    }

    // MARK: - Profile rule overrides (profileruleoverrides.go)

    private struct RuleRef: Hashable {
        var key: String
        var index: Int
    }

    /// mitm-converted edited rule, or an error message.
    static func convertEditedRule(_ raw: [String: NCJSONValue], line line0: String) -> (rule: String?, error: String?) {
        let line = line0.trimmingCharacters(in: .whitespaces)
        if line.isEmpty { return (nil, "规则为空") }
        let t = (line.split(separator: ",", maxSplits: 1).first.map(String.init) ?? "")
            .trimmingCharacters(in: .whitespaces).uppercased()
        if t == "SUB-RULE" {
            return (splitRuleTop(line).joined(separator: ","), nil)
        }
        let (conv, err) = NCEngineRuleset.convertRuleLine(line)
        if let err { return (nil, err) }
        if conv.rule.isEmpty {
            if !conv.unsupported.isEmpty { return (nil, conv.unsupported) }
            return (nil, "不是有效的规则")
        }
        if !conv.remoteURL.isEmpty { return (nil, "远程规则列表请在「订阅」里添加") }
        let (groups, proxies, first) = profileNames(raw)
        let pol = resolvePolicy(conv.policy, groups: groups, proxies: proxies, firstSelect: first)
            ?? conv.policy.trimmingCharacters(in: .whitespaces)
        if pol.isEmpty { return (nil, "缺少策略") }
        return (conv.format(pol), nil)
    }

    /// bridge applyProfileRuleOverrides: applies "#profile-rules" and
    /// "#final". Returns (edited map newRule -> originalRule, warnings).
    static func applyProfileRuleOverrides(
        _ raw: inout [String: NCJSONValue],
        ov: [String: NCProviderOverride]?
    ) -> (edited: [String: String], warnings: [String]) {
        guard let ov, !ov.isEmpty else { return ([:], []) }
        let final = (ov["#final"]?.policy ?? "").trimmingCharacters(in: .whitespaces)
        let ruleOverrides = ov["#profile-rules"]?.rules ?? []
        if ruleOverrides.isEmpty && final.isEmpty { return ([:], []) }
        var warnings: [String] = []
        var edited: [String: String] = [:]
        let rules = raw.list("rules")
        var out: [NCJSONValue] = []
        if !ruleOverrides.isEmpty {
            // planProfileRules inlined: key each override by (rule key, occurrence).
            var byRef: [RuleRef: NCProfileRuleOverride] = [:]
            for r in ruleOverrides {
                let k = profileRuleKey(r.rule)
                if k.isEmpty || r.index < 0 { continue }
                byRef[RuleRef(key: k, index: r.index)] = r
            }
            var seen: [String: Int] = [:]
            for rv in rules {
                guard case .string(let r) = rv else {
                    out.append(rv)
                    continue
                }
                let k = profileRuleKey(r)
                let n = seen[k] ?? 0
                seen[k] = n + 1
                var outRule = r
                if let o = byRef[RuleRef(key: k, index: n)] {
                    if o.deleted == true || o.disabled == true {
                        continue
                    }
                    if let line = o.line, !line.trimmingCharacters(in: .whitespaces).isEmpty,
                       profileRuleKey(line) != k {
                        let (conv, err) = convertEditedRule(raw, line: line)
                        if let err {
                            warnings.append("规则「\(r)」的修改无法使用（\(err)），已使用配置里的规则")
                        } else if let conv {
                            outRule = conv
                        }
                    }
                }
                if outRule != r { edited[outRule] = r }
                out.append(.string(outRule))
            }
        } else {
            out = rules
        }
        if !final.isEmpty {
            let (groups, proxies, first) = profileNames(raw)
            let resolved = resolvePolicy(final, groups: groups, proxies: proxies, firstSelect: first) ?? final
            let nr = "MATCH," + resolved
            var last = -1
            for i in out.indices.reversed() {
                if case .string(let s) = out[i], isMatchRule(s) { last = i; break }
            }
            if last >= 0 {
                if case .string(let old) = out[last], profileRuleKey(old) != nr {
                    var orig = old
                    if let o = edited[old] {
                        orig = o
                        edited.removeValue(forKey: old)
                    }
                    edited[nr] = orig
                    out[last] = .string(nr)
                }
            } else {
                edited[nr] = ""
                out.append(.string(nr))
            }
        }
        raw["rules"] = .array(out)
        return (edited, warnings)
    }

    // MARK: - Provider overrides (provideroverrides.go)

    static let providerLostKey = "x-tern-lost-provider"

    /// bridge providerSourceURL.
    static func providerSourceURL(_ m: [String: NCJSONValue]) -> String {
        let u = m.str("url")
        if let url = URL(string: u),
           url.host == "127.0.0.1", url.path.hasSuffix("/convert"),
           let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let q = comps.queryItems?.first(where: { $0.name == "url" })?.value, !q.isEmpty {
            return q
        }
        let x = m.str("x-source")
        return x.isEmpty ? u : x
    }

    /// bridge setProviderURL.
    static func setProviderURL(_ m: inout [String: NCJSONValue], _ nu: String) {
        let u = m.str("url")
        var handled = false
        if let url = URL(string: u), url.host == "127.0.0.1", url.path.hasSuffix("/convert"),
           var comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let items = comps.queryItems, items.contains(where: { $0.name == "url" && !($0.value ?? "").isEmpty }) {
            comps.queryItems = items.map { $0.name == "url" ? URLQueryItem(name: "url", value: nu) : $0 }
            if let s = comps.string {
                m["url"] = .string(s)
                handled = true
            }
        }
        if !handled { m["url"] = .string(nu) }
        if m["x-source"] != nil { m["x-source"] = .string(nu) }
    }

    /// bridge pathForURL: ./proxies/a.yaml -> ./proxies/a-<sha256[:4] hex>.yaml
    static func pathForURL(_ p: String, _ u: String) -> String {
        let sum = NCRuntimeFiles.sha256Hex(Data(u.utf8))
        let h = String(sum.prefix(8))
        let ext = (p as NSString).pathExtension
        if ext.isEmpty { return p + "-" + h }
        return (p as NSString).deletingPathExtension + "-" + h + "." + ext
    }

    /// bridge validProviderFilter (regexp2 there, ICU here — a
    /// compile check only; .NET-only constructs are the known gap).
    static func validProviderFilter(_ f: String) -> Bool {
        (try? NSRegularExpression(pattern: f)) != nil
    }

    /// bridge applyProviderOverridesDeferred.
    static func applyProviderOverridesDeferred(
        _ raw: inout [String: NCJSONValue],
        ov: [String: NCProviderOverride]?
    ) -> (removed: [String], warnings: [String]) {
        guard let ov, !ov.isEmpty else { return ([], []) }
        guard case .object(var pp) = raw["proxy-providers"] ?? .null, !pp.isEmpty else { return ([], []) }
        var warnings: [String] = []
        var removed: [String] = []
        for name in ov.keys.sorted() {
            let o = ov[name]!
            guard let v = pp[name] else { continue }
            if o.disabled == true || o.deleted == true {
                pp.removeValue(forKey: name)
                removed.append(name)
                continue
            }
            guard case .object(var m) = v else { continue }
            if let u0 = o.url {
                let u = u0.trimmingCharacters(in: .whitespaces)
                if !u.isEmpty && m.str("type").lowercased() == "http" {
                    if let url = URL(string: u), (url.scheme == "http" || url.scheme == "https"),
                       let host = url.host, !host.isEmpty {
                        let changed = u != providerSourceURL(m)
                        setProviderURL(&m, u)
                        let p = m.str("path")
                        if changed && !p.isEmpty {
                            m["path"] = .string(pathForURL(p, u))
                        }
                    } else {
                        warnings.append("节点集「\(name)」的自定义链接无效，已使用配置里的链接")
                    }
                }
            }
            if let interval = o.interval, interval > 0 {
                m["interval"] = .number(Double(interval))
            }
            for (key, f0) in [("filter", o.filter), ("exclude-filter", o.excludeFilter)] {
                guard let f0 else { continue }
                let f = f0.trimmingCharacters(in: .whitespaces)
                if f.isEmpty { continue }
                if validProviderFilter(f) {
                    m[key] = .string(f)
                } else {
                    warnings.append("节点集「\(name)」的筛选表达式无效，已忽略")
                }
            }
            pp[name] = .object(m)
        }
        raw["proxy-providers"] = .object(pp)
        if removed.isEmpty { return ([], warnings) }
        let gone = Set(removed)
        var groups = raw.list("proxy-groups")
        for gi in groups.indices {
            guard case .object(var g) = groups[gi] else { continue }
            var had = false
            let use = g.strList("use")
            if !use.isEmpty {
                var kept: [NCJSONValue] = []
                for u in use {
                    if gone.contains(u) { had = true } else { kept.append(.string(u)) }
                }
                if had {
                    if kept.isEmpty { g.removeValue(forKey: "use") } else { g["use"] = .array(kept) }
                }
            }
            let onlyProviders = g.boolOf("include-all-providers") && !g.boolOf("include-all") && !g.boolOf("include-all-proxies")
            if had || onlyProviders {
                g[providerLostKey] = .bool(true)
            }
            groups[gi] = .object(g)
        }
        raw["proxy-groups"] = .array(groups)
        return (removed, warnings)
    }

    /// bridge fillEmptyProviderGroups.
    static func fillEmptyProviderGroups(_ raw: inout [String: NCJSONValue]) {
        let pp = raw.map("proxy-providers")
        var groups = raw.list("proxy-groups")
        for gi in groups.indices {
            guard case .object(var g) = groups[gi] else { continue }
            guard g[providerLostKey] != nil else { continue }
            g.removeValue(forKey: providerLostKey)
            let onlyProviders = g.boolOf("include-all-providers") && !g.boolOf("include-all") && !g.boolOf("include-all-proxies")
            if g.list("proxies").isEmpty && g.list("use").isEmpty
                && !g.boolOf("include-all") && !g.boolOf("include-all-proxies")
                && (!onlyProviders || pp.isEmpty) {
                g["proxies"] = .array([.string("DIRECT")])
            }
            groups[gi] = .object(g)
        }
        raw["proxy-groups"] = .array(groups)
    }

    // MARK: - Rule-provider overrides (ruleprovideroverrides.go)

    /// mitm ReorderSlots (order.go): the named items are sorted among
    /// the positions they already occupy; everything else stays.
    static func reorderSlots(
        _ items: [NCJSONValue],
        key: (NCJSONValue) -> String?,
        order: [String]
    ) -> [NCJSONValue] {
        var out = items
        if order.isEmpty || items.count < 2 { return out }
        var rank: [String: Int] = [:]
        for (i, n) in order.enumerated() where rank[n] == nil { rank[n] = i }
        var slots: [Int] = []
        var picked: [NCJSONValue] = []
        var ranks: [Int] = []
        for (i, it) in items.enumerated() {
            guard let n = key(it), let r = rank[n] else { continue }
            slots.append(i)
            picked.append(it)
            ranks.append(r)
        }
        if slots.count < 2 { return out }
        let idx = picked.indices.sorted { ranks[$0] < ranks[$1] } // stable sort
        for (k, s) in slots.enumerated() { out[s] = picked[idx[k]] }
        return out
    }

    /// bridge ruleSetNameOf.
    static func ruleSetNameOf(_ rule: String) -> (name: String, simple: Bool) {
        let parts = rule.split(separator: ",", omittingEmptySubsequences: false)
        if parts.count >= 2,
           String(parts[0]).trimmingCharacters(in: .whitespaces).lowercased() == "rule-set" {
            return (String(parts[1]).trimmingCharacters(in: .whitespaces), true)
        }
        return ("", false)
    }

    /// bridge ruleMentionsSet.
    static func ruleMentionsSet(_ rule: String, _ name: String) -> Bool {
        let r = rule.replacingOccurrences(of: " ", with: "")
        return r.contains("(RULE-SET,\(name))") || r.contains("(RULE-SET,\(name),")
    }

    /// bridge applyRuleSetOrder.
    static func applyRuleSetOrder(_ raw: inout [String: NCJSONValue], order: [String]?) {
        guard let order, order.count >= 2 else { return }
        let rules = raw.list("rules")
        if rules.count < 2 { return }
        raw["rules"] = .array(reorderSlots(rules, key: { v in
            if case .string(let r) = v {
                let (n, simple) = ruleSetNameOf(r)
                return simple ? n : nil
            }
            return nil
        }, order: order))
    }

    /// bridge applyRuleProviderOverrides.
    static func applyRuleProviderOverrides(
        _ raw: inout [String: NCJSONValue],
        ov: [String: NCProviderOverride]?
    ) -> (removed: [String], warnings: [String]) {
        guard let ov, !ov.isEmpty else { return ([], []) }
        guard case .object(var rp) = raw["rule-providers"] ?? .null, !rp.isEmpty else { return ([], []) }
        var warnings: [String] = []
        var removed: [String] = []
        defer { applyRuleSetOrder(&raw, order: ov["#rule-order"]?.order) }
        let names = ov.keys.filter { $0.hasPrefix("rule:") }
            .map { String($0.dropFirst("rule:".count)) }.sorted()
        var gone = Set<String>()
        var policy: [String: String] = [:]
        for name in names {
            let o = ov["rule:" + name]!
            guard let v = rp[name] else { continue }
            if o.disabled == true || o.deleted == true {
                rp.removeValue(forKey: name)
                gone.insert(name)
                removed.append(name)
                continue
            }
            if let p = o.policy?.trimmingCharacters(in: .whitespaces), !p.isEmpty {
                policy[name] = p
            }
            guard case .object(var m) = v else { continue }
            if let u0 = o.url {
                let u = u0.trimmingCharacters(in: .whitespaces)
                if !u.isEmpty && m.str("type").lowercased() == "http" {
                    if let url = URL(string: u), (url.scheme == "http" || url.scheme == "https"),
                       let host = url.host, !host.isEmpty {
                        let changed = u != providerSourceURL(m)
                        setProviderURL(&m, u)
                        let p = m.str("path")
                        if changed && !p.isEmpty { m["path"] = .string(pathForURL(p, u)) }
                    } else {
                        warnings.append("规则集「\(name)」的自定义链接无效，已使用配置里的链接")
                    }
                }
            }
            if let interval = o.interval, interval > 0 {
                m["interval"] = .number(Double(interval))
            }
            rp[name] = .object(m)
        }
        raw["rule-providers"] = .object(rp)
        if gone.isEmpty && policy.isEmpty { return (removed, warnings) }
        var kept: [NCJSONValue] = []
        for rv in raw.list("rules") {
            guard case .string(let r0) = rv else {
                kept.append(rv)
                continue
            }
            var r = r0
            let (name, simple) = ruleSetNameOf(r)
            if simple {
                if gone.contains(name) { continue }
                if let p = policy[name] {
                    var parts = r.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
                    if parts.count >= 3 {
                        parts[2] = p
                        r = parts.joined(separator: ",")
                    }
                }
                kept.append(.string(r))
                continue
            }
            var drop = false
            for n in gone where ruleMentionsSet(r, n) { drop = true; break }
            if !drop { kept.append(.string(r)) }
        }
        if raw["rules"] != nil { raw["rules"] = .array(kept) }
        return (removed, warnings)
    }

    /// bridge checkEditedRuleTargets.
    static func checkEditedRuleTargets(
        _ raw: inout [String: NCJSONValue],
        edited: [String: String]
    ) -> [String] {
        if edited.isEmpty { return [] }
        var warnings: [String] = []
        var targets: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
        let (groups, proxies, _) = profileNames(raw)
        for n in groups { targets.insert(n) }
        for n in proxies { targets.insert(n) }
        for p in raw.list("proxies") {
            if case .object(let m) = p {
                let n = m.str("name")
                if !n.isEmpty { targets.insert(n) }
            }
        }
        let subRules = raw.map("sub-rules")
        var out: [NCJSONValue] = []
        var changed = false
        for rv in raw.list("rules") {
            guard case .string(let r) = rv, let orig = edited[r] else {
                out.append(rv)
                continue
            }
            let tg = ruleTargetOf(r)
            var okTarget = targets.contains(tg)
            let type = (r.trimmingCharacters(in: .whitespaces)
                .split(separator: ",", maxSplits: 1).first.map(String.init) ?? "")
            if type.lowercased() == "sub-rule" {
                okTarget = subRules[tg] != nil
            }
            if okTarget {
                out.append(rv)
                continue
            }
            changed = true
            warnings.append("规则「\(r)」的策略「\(tg)」不存在，已使用配置里的规则")
            if !orig.isEmpty { out.append(.string(orig)) }
        }
        if changed { raw["rules"] = .array(out) }
        return warnings
    }
}
