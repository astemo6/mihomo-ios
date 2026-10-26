import CryptoKit
import Foundation

/// E-B1 stage 3: the buildRuntimeWith satellite steps, ported file by
/// file from the bridge. Each step mutates the config tree in place
/// and returns the warnings the old side logged (the builder surfaces
/// them through NSLog at prepare time, like the core log).
/// This file: the retired bridge (the profile's own rule
/// and Final overrides) plus the mitm helpers it uses
///.

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

    // MARK: - Manual nodes + node subscriptions (diag.go / nodesubs.go)

    static let manualGroupName = "手动节点"
    static let probeGroup = "TERN-PROBE"

    /// bridge mergeManualNodes.
    static func mergeManualNodes(_ raw: inout [String: NCJSONValue], manualPath: String) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: manualPath)),
              let text = String(data: data, encoding: .utf8),
              let root = NCYAML.parse(text),
              case .object(let man) = root else { return }
        let nodes = man.list("proxies").compactMap { v -> [String: NCJSONValue]? in
            if case .object(let m) = v { return m }
            return nil
        }
        if nodes.isEmpty { return }
        var groups = raw.list("proxy-groups")
        for g in groups {
            if case .object(let m) = g, m.str("name") == manualGroupName { return }
        }
        var existing = Set<String>()
        var list = raw.list("proxies")
        for p in list {
            if case .object(let m) = p { existing.insert(m.str("name")) }
        }
        var names: [NCJSONValue] = []
        for var n in nodes {
            var name = n.str("name")
            if name.isEmpty { continue }
            if existing.contains(name) {
                name += " (手动)"
                n["name"] = .string(name)
            }
            list.append(.object(n))
            names.append(.string(name))
        }
        raw["proxies"] = .array(list)
        let mg: NCJSONValue = .object([
            "name": .string(manualGroupName),
            "type": .string("select"),
            "proxies": .array(names),
        ])
        for gi in groups.indices {
            guard case .object(var m) = groups[gi] else { continue }
            if m.str("type").lowercased() == "select" {
                m["proxies"] = .array([.string(manualGroupName)] + m.list("proxies"))
                groups[gi] = .object(m)
                break
            }
        }
        raw["proxy-groups"] = .array(groups + [mg])
    }

    private struct NCNodeSub: Decodable {
        var id: String = ""
        var name: String = ""
        var url: String = ""
        var enabled: Bool = false
        var groups: [String]? = nil
    }

    /// bridge defaultSubGroup.
    static func defaultSubGroup(_ g: [String: NCJSONValue]) -> Bool {
        if g.boolOf("hidden") || g.str("name") == probeGroup { return false }
        switch g.str("type").lowercased() {
        case "url-test":
            return true
        case "select":
            if g[providerLostKey] != nil { return true }
            if !g.list("use").isEmpty || g.boolOf("include-all") || g.boolOf("include-all-proxies")
                || g.boolOf("include-all-providers") { return true }
            let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
            for m in g.strList("proxies") where !builtins.contains(m.uppercased()) {
                return true
            }
        default: break
        }
        return false
    }

    /// bridge uniqueProviderName.
    static func uniqueProviderName(_ base: String, taken: (String) -> Bool) -> String {
        if !taken(base) { return base }
        var i = 2
        while true {
            let c = "\(base)-\(i)"
            if !taken(c) { return c }
            i += 1
        }
    }

    /// bridge mergeNodeSubs. subForKey returns the 节点处理 rules of
    /// "nodesub-<id>" from subscriptions.json.
    static func mergeNodeSubs(
        _ raw: inout [String: NCJSONValue],
        home: String,
        subForKey: (String) -> NCSubRules?
    ) {
        let subs = NCRuntimeFiles.readJSON([NCNodeSub].self, home: home, file: "node-subscriptions.json") ?? []
        if subs.isEmpty { return }
        var pp = raw.map("proxy-providers")
        var groups = raw.list("proxy-groups")
        var added = false
        for s in subs {
            if !s.enabled || s.id.isEmpty { continue }
            let path = (home as NSString).appendingPathComponent("nodesubs/\(s.id).yaml")
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? NSNumber, size.intValue > 0 else { continue }
            let trimmed = s.name.trimmingCharacters(in: .whitespaces)
            let name = uniqueProviderName(trimmed.isEmpty ? "订阅" : trimmed) { pp[$0] != nil }
            var p: [String: NCJSONValue] = [
                "type": .string("file"),
                "path": .string("./nodesubs/\(s.id).yaml"),
                "health-check": .object([
                    "enable": .bool(true),
                    "url": .string("https://www.gstatic.com/generate_204"),
                    "interval": .number(600),
                    "lazy": .bool(true),
                ]),
            ]
            if let r = subForKey("nodesub-" + s.id), r.enabled {
                var tmp: [String: NCJSONValue] = ["proxy-providers": .object([name: .object(p)])]
                _ = applySubRules(&tmp, r)
                if case .object(let tpp) = tmp["proxy-providers"] ?? .null,
                   case .object(let np) = tpp[name] ?? .null {
                    p = np
                }
            }
            pp[name] = .object(p)
            added = true
            let want = Set(s.groups ?? [])
            var hit = false
            for gi in groups.indices {
                guard case .object(var g) = groups[gi] else { continue }
                if (!want.isEmpty && want.contains(g.str("name")))
                    || (want.isEmpty && defaultSubGroup(g)) {
                    g["use"] = .array(g.list("use") + [.string(name)])
                    groups[gi] = .object(g)
                    hit = true
                }
            }
            if !hit {
                for gi in groups.indices {
                    guard case .object(var g) = groups[gi] else { continue }
                    if defaultSubGroup(g) {
                        g["use"] = .array(g.list("use") + [.string(name)])
                        groups[gi] = .object(g)
                    }
                }
            }
        }
        if added {
            raw["proxy-providers"] = .object(pp)
            raw["proxy-groups"] = .array(groups)
        }
    }

    /// bridge pruneDanglingUse: returns the changed group names.
    static func pruneDanglingUse(_ raw: inout [String: NCJSONValue]) -> [String] {
        let pp = raw.map("proxy-providers")
        var changed: [String] = []
        var groups = raw.list("proxy-groups")
        for gi in groups.indices {
            guard case .object(var g) = groups[gi] else { continue }
            let use = g.strList("use")
            if use.isEmpty { continue }
            let kept = use.filter { pp[$0] != nil }
            if kept.count == use.count { continue }
            changed.append(g.str("name"))
            if kept.isEmpty {
                g.removeValue(forKey: "use")
            } else {
                g["use"] = .array(kept.map { NCJSONValue.string($0) })
            }
            if kept.isEmpty && g.list("proxies").isEmpty
                && !g.boolOf("include-all") && !g.boolOf("include-all-proxies")
                && !g.boolOf("include-all-providers") {
                g["proxies"] = .array([.string("DIRECT")])
            }
            groups[gi] = .object(g)
        }
        raw["proxy-groups"] = .array(groups)
        return changed
    }

    // MARK: - Group edits (groupedits.go)

    /// groupedits.go splitTopLevel: top-level comma split, parts
    /// untrimmed (callers rejoin with ",").
    static func splitTopLevel(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var start = s.startIndex
        var i = s.startIndex
        while i < s.endIndex {
            switch s[i] {
            case "(": depth += 1
            case ")": if depth > 0 { depth -= 1 }
            case "," where depth == 0:
                out.append(String(s[start..<i]))
                start = s.index(after: i)
            default: break
            }
            i = s.index(after: i)
        }
        out.append(String(s[start...]))
        return out
    }

    static func rulePolicyIndex(_ parts: [String]) -> Int {
        if parts.count < 2 { return -1 }
        if parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "match" { return 1 }
        if parts.count < 3 { return -1 }
        return 2
    }

    /// bridge mapRulePolicies: rewrite the policy field of every rule
    /// in rules and sub-rules through f.
    static func mapRulePolicies(_ raw: inout [String: NCJSONValue], _ f: (String) -> String) {
        func fix(_ list: [NCJSONValue]) -> [NCJSONValue] {
            var list = list
            for i in list.indices {
                guard case .string(let s) = list[i] else { continue }
                var parts = splitTopLevel(s)
                let idx = rulePolicyIndex(parts)
                if idx >= 0 {
                    let p = parts[idx].trimmingCharacters(in: .whitespaces)
                    let n = f(p)
                    if n != p {
                        parts[idx] = n
                        list[i] = .string(parts.joined(separator: ","))
                    }
                }
            }
            return list
        }
        if raw["rules"] != nil { raw["rules"] = .array(fix(raw.list("rules"))) }
        if case .object(var sr) = raw["sub-rules"] ?? .null {
            for k in sr.keys {
                if case .array(let l) = sr[k] ?? .null { sr[k] = .array(fix(l)) }
            }
            raw["sub-rules"] = .object(sr)
        }
    }

    /// bridge applyGroupEdits.
    static func applyGroupEdits(
        _ raw: inout [String: NCJSONValue],
        _ e: GroupEdits?
    ) -> [String] {
        guard let e, (e.edits?.isEmpty == false) || (e.added?.isEmpty == false) else { return [] }
        var warn: [String] = []
        var renames: [String: String] = [:]
        var deleted = Set<String>()
        var kept: [NCJSONValue] = []
        for gv in raw.list("proxy-groups") {
            guard case .object(var g) = gv else {
                kept.append(gv)
                continue
            }
            let name = g.str("name")
            guard let ed = e.edits?[name] else {
                kept.append(.object(g))
                continue
            }
            if ed.deleted == true {
                deleted.insert(name)
                continue
            }
            if var s = ed.spec {
                if s.name.trimmingCharacters(in: .whitespaces).isEmpty { s.name = name }
                g = NCGroupEditing.writeSpec(to: g, spec: s)
                if s.name != name { renames[name] = s.name }
            }
            kept.append(.object(g))
        }
        var existing = Set<String>()
        for gv in kept {
            if case .object(let g) = gv { existing.insert(g.str("name")) }
        }
        if let ed = e.edits?["GLOBAL"], ed.deleted != true, var s = ed.spec, !existing.contains("GLOBAL") {
            s.name = "GLOBAL"
            let g = NCGroupEditing.writeSpec(to: [:], spec: s)
            kept.append(.object(g))
            existing.insert("GLOBAL")
        }
        for s in e.added ?? [] {
            if s.name.trimmingCharacters(in: .whitespaces).isEmpty || existing.contains(s.name) {
                warn.append("新建的策略组「\(s.name)」与已有名称重复，已跳过")
                continue
            }
            let g = NCGroupEditing.writeSpec(to: [:], spec: s)
            kept.append(.object(g))
            existing.insert(s.name)
        }
        var fallback = "DIRECT"
        for gv in kept {
            if case .object(let g) = gv, g.str("type").lowercased() == "select" {
                fallback = g.str("name")
                break
            }
        }
        for ki in kept.indices {
            guard case .object(var g) = kept[ki] else { continue }
            let hadKey = g["proxies"] != nil
            var px: [String] = []
            for p in g.strList("proxies") {
                if deleted.contains(p) { continue }
                px.append(renames[p] ?? p)
            }
            if hadKey || !px.isEmpty {
                if px.isEmpty {
                    g.removeValue(forKey: "proxies")
                } else {
                    g["proxies"] = .array(px.map { NCJSONValue.string($0) })
                }
            }
            kept[ki] = .object(g)
        }
        mapRulePolicies(&raw) { p in
            if let n = renames[p] { return n }
            if deleted.contains(p) {
                warn.append("规则指向已删除的策略组「\(p)」，改用「\(fallback)」")
                return fallback
            }
            return p
        }
        raw["proxy-groups"] = .array(kept)
        warn += renameGroupRefs(&raw, renames: renames, deleted: deleted)
        return warn
    }

    /// bridge renameGroupRefs.
    static func renameGroupRefs(
        _ raw: inout [String: NCJSONValue],
        renames: [String: String],
        deleted: Set<String>
    ) -> [String] {
        if renames.isEmpty && deleted.isEmpty { return [] }
        var warn: [String] = []
        func fix(_ m: inout [String: NCJSONValue], _ key: String, _ owner: String) {
            guard case .string(let v) = m[key] ?? .null, !v.isEmpty else { return }
            if let n = renames[v] {
                m[key] = .string(n)
            } else if deleted.contains(v) {
                m.removeValue(forKey: key)
                warn.append("「\(owner)」的 \(key) 指向已删除的策略组「\(v)」，已移除")
            }
        }
        var proxies = raw.list("proxies")
        for i in proxies.indices {
            if case .object(var m) = proxies[i] {
                fix(&m, "dialer-proxy", m.str("name"))
                proxies[i] = .object(m)
            }
        }
        raw["proxies"] = .array(proxies)
        var groups = raw.list("proxy-groups")
        for i in groups.indices {
            if case .object(var m) = groups[i] {
                fix(&m, "dialer-proxy", m.str("name"))
                groups[i] = .object(m)
            }
        }
        raw["proxy-groups"] = .array(groups)
        var pp = raw.map("proxy-providers")
        for name in pp.keys {
            if case .object(var pv) = pp[name] ?? .null,
               case .object(var ov) = pv["override"] ?? .null {
                fix(&ov, "dialer-proxy", name)
                pv["override"] = .object(ov)
                pp[name] = .object(pv)
            }
        }
        raw["proxy-providers"] = .object(pp)
        var listeners = raw.list("listeners")
        for i in listeners.indices {
            if case .object(var m) = listeners[i] {
                fix(&m, "proxy", m.str("name"))
                listeners[i] = .object(m)
            }
        }
        raw["listeners"] = .array(listeners)
        guard case .object(var dns) = raw["dns"] ?? .null else { return warn }
        func fixServer(_ s: String) -> String {
            guard let hashIdx = s.lastIndex(of: "#") else { return s }
            let frag = String(s[s.index(after: hashIdx)...])
            let name: String
            let rest: String
            let hasRest: Bool
            if let amp = frag.firstIndex(of: "&") {
                name = String(frag[..<amp])
                rest = String(frag[frag.index(after: amp)...])
                hasRest = true
            } else {
                name = frag
                rest = ""
                hasRest = false
            }
            if name.contains("=") { return s }
            let head = String(s[...hashIdx]) // includes '#'
            let base = String(s[..<hashIdx])
            if let n = renames[name] {
                return hasRest ? head + n + "&" + rest : head + n
            }
            if deleted.contains(name) {
                warn.append("DNS 服务器「\(base)」指定的策略组「\(name)」已删除，已改为按默认出站")
                return hasRest ? head + rest : base
            }
            return s
        }
        func fixList(_ v: NCJSONValue) -> NCJSONValue {
            switch v {
            case .string(let s): return .string(fixServer(s))
            case .array(let l):
                return .array(l.map { if case .string(let s) = $0 { return .string(fixServer(s)) }; return $0 })
            default: return v
            }
        }
        for k in ["nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver", "default-nameserver"] {
            if let v = dns[k] { dns[k] = fixList(v) }
        }
        if case .object(var np) = dns["nameserver-policy"] ?? .null {
            for k in np.keys {
                if let v = np[k] { np[k] = fixList(v) }
            }
            dns["nameserver-policy"] = .object(np)
        }
        raw["dns"] = .object(dns)
        return warn
    }

    /// bridge runtimeGroupNames.
    static func runtimeGroupNames(_ raw: [String: NCJSONValue]) -> [String] {
        var out: [String] = []
        for gv in raw.list("proxy-groups") {
            if case .object(let g) = gv {
                let n = g.str("name")
                if !n.isEmpty && n != probeGroup { out.append(n) }
            }
        }
        return out
    }

    // MARK: - Own-policy providers + Tailscale (ownpolicy.go / tailscale.go)

    /// bridge truthyAny (chain.go).
    static func truthy(_ v: NCJSONValue?) -> Bool {
        switch v {
        case .bool(let b): return b
        case .string(let s): return s == "true"
        default: return false
        }
    }

    private struct OwnPolicyPart: Decodable {
        var policy: String = ""
        var file: String = ""
        var count: Int = 0
    }

    /// bridge expandOwnPolicyProviders.
    static func expandOwnPolicyProviders(_ raw: inout [String: NCJSONValue], home: String) {
        let rp0 = raw.map("rule-providers")
        if rp0.isEmpty || home.isEmpty { return }
        var rp = rp0
        struct Exp { var dir: String; var parts: [OwnPolicyPart] }
        var exps: [String: Exp] = [:]
        for (name, v) in rp {
            guard case .object(let m) = v, truthy(m["x-own-policy"]) else { continue }
            var p = m.str("path")
            if p.isEmpty { continue }
            if !(p as NSString).isAbsolutePath {
                p = (home as NSString).appendingPathComponent(p)
            }
            let sidecar = p + ".policies.json"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: sidecar)),
                  let parts = try? JSONDecoder().decode([OwnPolicyPart].self, from: data),
                  !parts.isEmpty else { continue }
            exps[name] = Exp(dir: (p as NSString).deletingLastPathComponent, parts: parts)
        }
        let rules = raw.list("rules")
        if exps.isEmpty || rules.isEmpty { return }
        var known: [String: String] = [:]
        var groups = raw.list("proxy-groups")
        for g in groups {
            if case .object(let m) = g {
                let n = m.str("name")
                if !n.isEmpty { known[n.lowercased()] = n }
            }
        }
        for p in raw.list("proxies") {
            if case .object(let m) = p {
                let n = m.str("name")
                if !n.isEmpty && known[n.lowercased()] == nil { known[n.lowercased()] = n }
            }
        }
        func resolve(_ pol: String, _ fallback: String) -> String {
            let lp = pol.trimmingCharacters(in: .whitespaces).lowercased()
            switch true {
            case lp == "proxy": return fallback
            case lp == "direct": return "DIRECT"
            case lp == "reject-drop": return "REJECT-DROP"
            case lp.hasPrefix("reject"): return "REJECT"
            default: break
            }
            if let n = known[lp] { return n }
            var members: [NCJSONValue] = []
            let fu = fallback.uppercased()
            if fu != "DIRECT" && !fu.hasPrefix("REJECT") {
                members.append(.string(fallback))
            }
            members.append(.string("DIRECT"))
            groups.append(.object([
                "name": .string(pol), "type": .string("select"), "proxies": .array(members),
            ]))
            known[lp] = pol
            return pol
        }
        var out: [NCJSONValue] = []
        for r in rules {
            guard case .string(let s) = r else {
                out.append(r)
                continue
            }
            let f = s.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard f.count >= 3,
                  f[0].trimmingCharacters(in: .whitespaces).lowercased() == "rule-set",
                  let e = exps[f[1].trimmingCharacters(in: .whitespaces)] else {
                out.append(r)
                continue
            }
            let name = f[1].trimmingCharacters(in: .whitespaces)
            let fallback = f[2].trimmingCharacters(in: .whitespaces)
            let rest = f.count > 3 ? "," + f[3...].joined(separator: ",") : ""
            for p in e.parts {
                let pn = name + "#" + p.policy
                rp[pn] = .object([
                    "type": .string("file"),
                    "behavior": .string("classical"),
                    "format": .string("text"),
                    "path": .string((e.dir as NSString).appendingPathComponent(p.file)),
                ])
                out.append(.string("RULE-SET," + pn + "," + resolve(p.policy, fallback) + rest))
            }
            out.append(r)
        }
        raw["rules"] = .array(out)
        raw["proxy-groups"] = .array(groups)
        raw["rule-providers"] = .object(rp)
    }

    /// bridge tailscaleStateDir.
    static func tailscaleStateDir(_ name: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data(name.utf8))
        let hash8 = digest.ncHex.prefix(8)
        var base = ""
        var inUnsafeRun = false
        for ch in name {
            if ch.isASCII && (ch.isLetter || ch.isNumber || ch == "." || ch == "_" || ch == "-") {
                base.append(ch)
                inUnsafeRun = false
            } else if !inUnsafeRun {
                base.append("_")
                inUnsafeRun = true
            }
        }
        base = base.trimmingCharacters(in: CharacterSet(charactersIn: "_."))
        if base.count > 24 { base = String(base.prefix(24)) }
        if base.isEmpty { base = "node" }
        return "tailscale/" + base + "-" + hash8
    }

    /// bridge normalizeTailscale: returns the node count.
    @discardableResult
    static func normalizeTailscale(_ raw: inout [String: NCJSONValue], home: String) -> Int {
        var n = 0
        var proxies = raw.list("proxies")
        for i in proxies.indices {
            guard case .object(var m) = proxies[i],
                  m.str("type").lowercased() == "tailscale" else { continue }
            n += 1
            let name = m.str("name")
            var dir = m.str("state-dir").trimmingCharacters(in: .whitespaces)
            if dir.isEmpty {
                dir = tailscaleStateDir(name)
            } else if (dir as NSString).isAbsolutePath {
                let clean = (dir as NSString).standardizingPath
                let homeClean = (home as NSString).standardizingPath
                if home.isEmpty || !(clean + "/").hasPrefix(homeClean + "/") {
                    dir = tailscaleStateDir(name)
                }
            } else {
                let c = (dir as NSString).standardizingPath
                if c == ".." || c.hasPrefix("../") {
                    dir = tailscaleStateDir(name)
                }
            }
            m["state-dir"] = .string(dir)
            if m.str("hostname").trimmingCharacters(in: .whitespaces).isEmpty {
                m["hostname"] = .string("mihomo-ios")
            }
            proxies[i] = .object(m)
        }
        raw["proxies"] = .array(proxies)
        return n
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
