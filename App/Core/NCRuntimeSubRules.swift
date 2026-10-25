import Foundation

/// E-B1 stage 3b: port of bridge/subrules.go's runtime half —
/// applySubRules (per-subscription node processing: include /
/// exclude / dedupe / rename / region sort, forwarded to providers
/// as filter + override rules) with fixReferences.
///
/// Engine notes: Go matches user regexes with regexp2 (.NET) under a
/// 1 s timeout; here NSRegularExpression (ICU) stands in — the
/// patterns involved are simple, but .NET-only template forms in
/// rename replacements (${name}, $$ for a literal $) are not expanded
/// by ICU templates. Region detection scans the same 44-pattern
/// table in order with ICU instead of Go's literal fast path; the
/// fast path only skips regions that provably cannot match, so the
/// first-match result is the same.

// MARK: - Region detection

private let ncRegionDefs: [(code: String, pattern: String)] = [
    ("HK", #"香港|深港|沪港|呼港|广港|京港|🇭🇰|Hong\s?Kong|(?<![A-Za-z])HKG?(?![A-Za-z])"#),
    ("MO", #"澳门|澳門|🇲🇴|Macau|Macao|(?<![A-Za-z])MO(?![A-Za-z])"#),
    ("TW", #"台湾|台灣|臺灣|台北|新北|彰化|🇹🇼|Taiwan|(?<![A-Za-z])TWN?(?![A-Za-z])"#),
    ("JP", #"日本|东京|東京|大阪|埼玉|名古屋|🇯🇵|Japan|Tokyo|Osaka|(?<![A-Za-z])JPN?(?![A-Za-z])"#),
    ("SG", #"新加坡|狮城|獅城|🇸🇬|Singapore|(?<![A-Za-z])SGP?(?![A-Za-z])"#),
    ("KR", #"韩国|韓國|首尔|首爾|春川|🇰🇷|Korea|Seoul|(?<![A-Za-z])KO?R(?![A-Za-z])"#),
    ("US", #"美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|芝加哥|纽约|紐約|达拉斯|凤凰城|波特兰|🇺🇸|United\s?States|America|Los\s?Angeles|San\s?Jose|Silicon|Seattle|Chicago|New\s?York|(?<![A-Za-z])USA?(?![A-Za-z])"#),
    ("CA", #"加拿大|多伦多|温哥华|蒙特利尔|🇨🇦|Canada|Toronto|Vancouver|(?<![A-Za-z])CAN?(?![A-Za-z])"#),
    ("GB", #"英国|英國|伦敦|倫敦|🇬🇧|United\s?Kingdom|Britain|London|(?<![A-Za-z])(UK|GB)(?![A-Za-z])"#),
    ("DE", #"德国|德國|法兰克福|🇩🇪|Germany|Frankfurt|(?<![A-Za-z])DEU?(?![A-Za-z])"#),
    ("FR", #"法国|法國|巴黎|🇫🇷|France|Paris|(?<![A-Za-z])FRA?(?![A-Za-z])"#),
    ("NL", #"荷兰|荷蘭|阿姆斯特丹|🇳🇱|Netherlands|Amsterdam|(?<![A-Za-z])NLD?(?![A-Za-z])"#),
    ("RU", #"俄罗斯|俄羅斯|莫斯科|🇷🇺|Russia|Moscow|(?<![A-Za-z])RUS?(?![A-Za-z])"#),
    ("IN", #"印度(?!尼)|孟买|🇮🇳|India|Mumbai|(?<![A-Za-z])IND(?![A-Za-z])"#),
    ("AU", #"澳大利亚|澳洲|悉尼|墨尔本|🇦🇺|Australia|Sydney|(?<![A-Za-z])AUS?(?![A-Za-z])"#),
    ("TR", #"土耳其|伊斯坦布尔|🇹🇷|Turkey|Türkiye|Istanbul|(?<![A-Za-z])TUR?(?![A-Za-z])"#),
    ("MY", #"马来西亚|馬來西亞|吉隆坡|🇲🇾|Malaysia|(?<![A-Za-z])MYS?(?![A-Za-z])"#),
    ("TH", #"泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|(?<![A-Za-z])THA?(?![A-Za-z])"#),
    ("VN", #"越南|胡志明|河内|🇻🇳|Vietnam|(?<![A-Za-z])VNM?(?![A-Za-z])"#),
    ("PH", #"菲律宾|菲律賓|马尼拉|🇵🇭|Philippines|Manila|(?<![A-Za-z])PHL?(?![A-Za-z])"#),
    ("ID", #"印尼|印度尼西亚|雅加达|🇮🇩|Indonesia|Jakarta|(?<![A-Za-z])IDN(?![A-Za-z])"#),
    ("AR", #"阿根廷|🇦🇷|Argentina|(?<![A-Za-z])ARG(?![A-Za-z])"#),
    ("BR", #"巴西|圣保罗|🇧🇷|Brazil|(?<![A-Za-z])BRA(?![A-Za-z])"#),
    ("IT", #"意大利|義大利|米兰|🇮🇹|Italy|Milan|(?<![A-Za-z])ITA(?![A-Za-z])"#),
    ("ES", #"西班牙|马德里|🇪🇸|Spain|Madrid|(?<![A-Za-z])ESP(?![A-Za-z])"#),
    ("CH", #"瑞士|苏黎世|🇨🇭|Switzerland|Zurich|(?<![A-Za-z])CHE(?![A-Za-z])"#),
    ("SE", #"瑞典|🇸🇪|Sweden|(?<![A-Za-z])SWE(?![A-Za-z])"#),
    ("PL", #"波兰|波蘭|🇵🇱|Poland|(?<![A-Za-z])POL(?![A-Za-z])"#),
    ("UA", #"乌克兰|烏克蘭|🇺🇦|Ukraine|(?<![A-Za-z])UKR(?![A-Za-z])"#),
    ("IE", #"爱尔兰|愛爾蘭|🇮🇪|Ireland|(?<![A-Za-z])IRL(?![A-Za-z])"#),
    ("IL", #"以色列|🇮🇱|Israel|(?<![A-Za-z])ISR(?![A-Za-z])"#),
    ("AE", #"阿联酋|迪拜|🇦🇪|Dubai|Emirates|(?<![A-Za-z])UAE(?![A-Za-z])"#),
    ("ZA", #"南非|🇿🇦|South\s?Africa"#),
    ("NG", #"尼日利亚|🇳🇬|Nigeria"#),
    ("EG", #"埃及|🇪🇬|Egypt"#),
    ("MX", #"墨西哥|🇲🇽|Mexico"#),
    ("CL", #"智利|🇨🇱|Chile"#),
    ("NZ", #"新西兰|紐西蘭|🇳🇿|New\s?Zealand"#),
    ("KZ", #"哈萨克|🇰🇿|Kazakhstan"#),
    ("PK", #"巴基斯坦|🇵🇰|Pakistan"#),
    ("BD", #"孟加拉|🇧🇩|Bangladesh"#),
    ("KH", #"柬埔寨|🇰🇭|Cambodia"#),
    ("MN", #"蒙古|🇲🇳|Mongolia"#),
    ("CN", #"中国|中國|回国|回國|国内|國內|🇨🇳|China|(?<![A-Za-z])CHN(?![A-Za-z])"#),
]

private let ncRegionRegexes: [NSRegularExpression?] = ncRegionDefs.map {
    try? NSRegularExpression(pattern: $0.pattern, options: [.caseInsensitive])
}

func ncFlagOf(_ code: String) -> String {
    if code.count != 2 { return "" }
    var out = ""
    for scalar in code.uppercased().unicodeScalars {
        guard let v = UnicodeScalar(0x1F1E6 + (scalar.value - 65)) else { return "" }
        out.unicodeScalars.append(v)
    }
    return out
}

private func ncFirstFlag(_ s: String) -> String {
    let scalars = Array(s.unicodeScalars)
    func isRI(_ v: UInt32) -> Bool { v >= 0x1F1E6 && v <= 0x1F1FF }
    var i = 0
    while i + 1 < scalars.count {
        if isRI(scalars[i].value) && isRI(scalars[i + 1].value) {
            var str = ""
            str.unicodeScalars.append(scalars[i])
            str.unicodeScalars.append(scalars[i + 1])
            return str
        }
        i += 1
    }
    return ""
}

func ncStripFlagEmojis(_ s: String) -> String {
    var out = ""
    for scalar in s.unicodeScalars {
        let v = scalar.value
        if (v >= 0x1F1E6 && v <= 0x1F1FF) || v == 0xFE0F || v == 0x1F3F3 || v == 0x1F3F4
            || (v >= 0xE0020 && v <= 0xE007F) { continue }
        out.unicodeScalars.append(scalar)
    }
    return out.trimmingCharacters(in: .whitespaces)
}

/// Go detectRegion: (ISO code, table index or table count).
func ncDetectRegion(_ name: String) -> (code: String, index: Int) {
    if !ncFirstFlag(name).isEmpty {
        let f = ncFirstFlag(name)
        for (i, d) in ncRegionDefs.enumerated() where ncFlagOf(d.code) == f {
            return (d.code, i)
        }
    }
    let range = NSRange(name.startIndex..., in: name)
    for (i, re) in ncRegionRegexes.enumerated() {
        if let re, re.firstMatch(in: name, range: range) != nil {
            return (ncRegionDefs[i].code, i)
        }
    }
    return ("", ncRegionDefs.count)
}

// MARK: - Matchers

private struct NCNameMatcher {
    var regex: NSRegularExpression? = nil
    var keywords: [String] = []
    var isEmpty: Bool { regex == nil && keywords.isEmpty }
    func match(_ name: String) -> Bool {
        if let regex {
            return regex.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil
        }
        let ln = name.lowercased()
        return keywords.contains { ln.contains($0) }
    }
}

private func ncSplitKeywords(_ s: String) -> [String] {
    s.split(whereSeparator: { $0 == "|" || $0 == "\n" || $0 == "\r" })
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
        .map { $0.lowercased() }
}

/// Returns (matcher, error message). nil matcher + nil error = empty expr.
private func ncNewMatcher(_ expr0: String, regex: Bool) -> (NCNameMatcher?, String?) {
    let expr = expr0.trimmingCharacters(in: .whitespaces)
    if expr.isEmpty { return (nil, nil) }
    if regex {
        do {
            let re = try NSRegularExpression(pattern: expr, options: [.caseInsensitive])
            return (NCNameMatcher(regex: re), nil)
        } catch {
            return (nil, "正则无效：\(error.localizedDescription)")
        }
    }
    return (NCNameMatcher(keywords: ncSplitKeywords(expr)), nil)
}

/// regexp2.Escape, approximated with the .NET escape set.
func ncRegexEscape(_ s: String) -> String {
    var out = ""
    for ch in s {
        if "\\.+*?()|[]{}^$#".contains(ch) {
            out.append("\\")
            out.append(ch)
        } else if ch == " " {
            out.append("\\ ")
        } else if ch == "-" {
            out.append("\\-")
        } else {
            out.append(ch)
        }
    }
    return out
}

/// Go providerFilter.
private func ncProviderFilter(_ expr0: String, regex: Bool) -> String {
    let expr = expr0.trimmingCharacters(in: .whitespaces)
    if expr.isEmpty { return "" }
    if regex { return "(?i)" + expr }
    let ks = ncSplitKeywords(expr).map { ncRegexEscape($0) }
    return "(?i)(" + ks.joined(separator: "|") + ")"
}

// MARK: - Compiled pipeline

private struct NCCompiledSub {
    var r: NCSubRules
    var inc: NCNameMatcher? = nil
    var exc: NCNameMatcher? = nil
    var renames: [NSRegularExpression] = []
    var renamePatterns: [String] = []
    var repl: [String] = []
    var errs: [String] = []

    init(_ r: NCSubRules) {
        self.r = r
        let (inc, e1) = ncNewMatcher(r.include ?? "", regex: r.regex == true)
        self.inc = inc
        if let e1 { errs.append("保留：" + e1) }
        let (exc, e2) = ncNewMatcher(r.exclude ?? "", regex: r.regex == true)
        self.exc = exc
        if let e2 { errs.append("排除：" + e2) }
        for rn in r.renames ?? [] {
            if rn.enabled == false || rn.pattern.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            do {
                renames.append(try NSRegularExpression(pattern: rn.pattern))
                renamePatterns.append(rn.pattern)
                repl.append(rn.replace)
            } catch {
                errs.append("重命名「\(rn.pattern)」：正则无效：\(error.localizedDescription)")
            }
        }
    }

    func rename(_ name: String) -> String {
        var n = name
        if r.stripFlags == true || r.addFlag == true {
            n = ncStripFlagEmojis(n)
        }
        for p in r.stripPrefixes ?? [] where !p.isEmpty {
            if n.hasPrefix(p) {
                // Go: TrimLeftFunc(unicode.IsSpace) — leading side only.
                n = String(n.dropFirst(p.count).drop(while: { $0.isWhitespace }))
            }
        }
        for (i, re) in renames.enumerated() {
            n = re.stringByReplacingMatches(in: n, range: NSRange(n.startIndex..., in: n), withTemplate: repl[i])
        }
        n = n.trimmingCharacters(in: .whitespaces)
        if r.addFlag == true {
            let (code, _) = ncDetectRegion(name + " " + n)
            let f = ncFlagOf(code)
            if !f.isEmpty { n = f + " " + n }
        }
        if let prefix = r.prefix, !prefix.isEmpty { n = prefix + n }
        if n.isEmpty { n = name }
        return n
    }
}

private func ncDedupeKey(_ p: [String: NCJSONValue]) -> String {
    var cred = ""
    for k in ["uuid", "password", "auth-str", "auth", "private-key", "psk", "username"] {
        let v = p.str(k)
        if !v.isEmpty { cred += k + "=" + v + ";" }
    }
    // Go fmt.Sprint(p["port"]). NCValueCoercion.sprint renders integral
    // values as integers only inside Int64 range: the old
    // `n == floor(n) ? String(Int64(n))` trapped on a subscription node
    // with `port: 1e30` or `.inf` (floor(inf) == inf).
    var port = ""
    if let v = p["port"], case .number = v {
        port = NCValueCoercion.sprint(v)
    } else if case .string(let s)? = p["port"] {
        port = s
    }
    return p.str("type").lowercased() + "|" + p.str("server").lowercased() + "|" + port + "|" + cred
}

private func ncNaturalLess(_ a: String, _ b: String) -> Bool {
    let ra = Array(a), rb = Array(b)
    var i = 0, j = 0
    while i < ra.count && j < rb.count {
        let ca = ra[i], cb = rb[j]
        if ca.isNumber && cb.isNumber {
            let si = i
            while i < ra.count && ra[i].isNumber { i += 1 }
            let sj = j
            while j < rb.count && rb[j].isNumber { j += 1 }
            let na = String(ra[si..<i]).drop(while: { $0 == "0" })
            let nb = String(rb[sj..<j]).drop(while: { $0 == "0" })
            if na.count != nb.count { return na.count < nb.count }
            if na != nb { return String(na) < String(nb) }
            continue
        }
        if ca != cb { return ca < cb }
        i += 1
        j += 1
    }
    return (ra.count - i) < (rb.count - j)
}

// MARK: - applySubRules + fixReferences

extension NCRuntimeSteps {

    /// bridge applySubRules: returns the compile errors (warnings).
    static func applySubRules(_ raw: inout [String: NCJSONValue], _ r: NCSubRules?) -> [String] {
        guard let r, r.enabled else { return [] }
        let c = NCCompiledSub(r)
        let proxies = raw.list("proxies")
        if !proxies.isEmpty {
            // processNodes over the proxy maps.
            var nodes: [[String: NCJSONValue]] = proxies.compactMap {
                if case .object(let m) = $0 { return m }
                return nil
            }
            var renamed: [String: String] = [:]
            var removed = Set<String>()
            var seenKey = Set<String>()
            struct Item { var nodeIdx: Int; var name: String; var region: Int }
            var items: [Item] = []
            for (idx, p) in nodes.enumerated() {
                let orig = p.str("name")
                var reason = ""
                if let inc = c.inc, !inc.isEmpty, !inc.match(orig) {
                    reason = "未匹配保留规则"
                } else if let exc = c.exc, !exc.isEmpty, exc.match(orig) {
                    reason = "匹配排除规则"
                }
                if reason.isEmpty && r.dedupe == true {
                    let k = ncDedupeKey(p)
                    if seenKey.contains(k) { reason = "重复节点" }
                    seenKey.insert(k)
                }
                if !reason.isEmpty {
                    removed.insert(orig)
                    continue
                }
                let newName = c.rename(orig)
                let (_, regionIdx) = ncDetectRegion(orig + " " + newName)
                items.append(Item(nodeIdx: idx, name: newName, region: regionIdx))
            }
            // Go sort.SliceStable: Swift's sort is not stable, so ties keep input order via nodeIdx.
            switch r.sort ?? "" {
            case "name":
                items.sort {
                    if ncNaturalLess($0.name, $1.name) { return true }
                    if ncNaturalLess($1.name, $0.name) { return false }
                    return $0.nodeIdx < $1.nodeIdx
                }
            case "region":
                items.sort {
                    if $0.region != $1.region { return $0.region < $1.region }
                    if ncNaturalLess($0.name, $1.name) { return true }
                    if ncNaturalLess($1.name, $0.name) { return false }
                    return $0.nodeIdx < $1.nodeIdx
                }
            default: break
            }
            var used: [String: Int] = [:]
            var out: [NCJSONValue] = []
            for it in items {
                let base = it.name
                var n = base
                var k = 1
                while (used[n] ?? 0) > 0 {
                    n = "\(base) \(k + 1)"
                    k += 1
                }
                used[n, default: 0] += 1
                let orig = nodes[it.nodeIdx].str("name")
                if n != orig { renamed[orig] = n }
                nodes[it.nodeIdx]["name"] = .string(n)
                out.append(.object(nodes[it.nodeIdx]))
            }
            raw["proxies"] = .array(out)
            fixReferences(&raw, renamed: renamed, removed: removed)
        }
        if case .object(var pp) = raw["proxy-providers"] ?? .null {
            for name in pp.keys.sorted() {
                guard case .object(var m) = pp[name] ?? .null else { continue }
                let incF = ncProviderFilter(r.include ?? "", regex: r.regex == true)
                if !incF.isEmpty && c.inc != nil {
                    var f = incF
                    let old = m.str("filter")
                    if !old.isEmpty { f = "(?=.*(" + old + "))" + f }
                    m["filter"] = .string(f)
                }
                let excF = ncProviderFilter(r.exclude ?? "", regex: r.regex == true)
                if !excF.isEmpty && c.exc != nil {
                    var f = excF
                    let old = m.str("exclude-filter")
                    if !old.isEmpty { f = old + "|" + f }
                    m["exclude-filter"] = .string(f)
                }
                var ov = m.map("override")
                var pn: [NCJSONValue] = []
                if r.stripFlags == true || r.addFlag == true {
                    pn.append(.object([
                        "pattern": .string("[\\U0001F1E6-\\U0001F1FF]{2}\\s*"),
                        "target": .string(""),
                    ]))
                }
                for p in r.stripPrefixes ?? [] where !p.isEmpty {
                    pn.append(.object([
                        "pattern": .string("^" + ncRegexEscape(p) + "\\s*"),
                        "target": .string(""),
                    ]))
                }
                for (i, pat) in c.renamePatterns.enumerated() {
                    pn.append(.object(["pattern": .string(pat), "target": .string(c.repl[i])]))
                }
                if !pn.isEmpty {
                    ov["proxy-name"] = .array(ov.list("proxy-name") + pn)
                }
                if let prefix = r.prefix, !prefix.isEmpty {
                    ov["additional-prefix"] = .string(prefix + ov.str("additional-prefix"))
                }
                if !ov.isEmpty { m["override"] = .object(ov) }
                pp[name] = .object(m)
            }
            raw["proxy-providers"] = .object(pp)
        }
        return c.errs
    }

    /// bridge fixReferences.
    static func fixReferences(
        _ raw: inout [String: NCJSONValue],
        renamed: [String: String],
        removed: Set<String>
    ) {
        if renamed.isEmpty && removed.isEmpty { return }
        func mapName(_ s: String) -> String? {
            if removed.contains(s) { return nil }
            if let n = renamed[s] { return n }
            return s
        }
        var groupNames = Set<String>()
        var groups = raw.list("proxy-groups")
        for g in groups {
            if case .object(let m) = g { groupNames.insert(m.str("name")) }
        }
        for gi in groups.indices {
            guard case .object(var m) = groups[gi] else { continue }
            guard m["proxies"] != nil else { continue }
            var out: [NCJSONValue] = []
            for p in m.list("proxies") {
                // Go reads members with fmt.Sprint; strings dominate.
                let s: String
                switch p {
                case .string(let v): s = v
                case .number: s = NCValueCoercion.sprint(p) // was String(Int64(n)): traps on 1e30 / inf
                default: s = p.strValue
                }
                if groupNames.contains(s) {
                    out.append(p)
                    continue
                }
                if let n = mapName(s) { out.append(.string(n)) }
            }
            let empty = out.isEmpty && m.strList("use").isEmpty
                && !m.boolOf("include-all") && !m.boolOf("include-all-proxies")
                && !m.boolOf("include-all-providers")
            if empty { out.append(.string("DIRECT")) }
            m["proxies"] = .array(out)
            groups[gi] = .object(m)
        }
        raw["proxy-groups"] = .array(groups)
        // dialer-proxy on proxies.
        var proxies = raw.list("proxies")
        for pi in proxies.indices {
            guard case .object(var p) = proxies[pi] else { continue }
            let d = p.str("dialer-proxy")
            if !d.isEmpty && !groupNames.contains(d) {
                if let n = mapName(d) {
                    p["dialer-proxy"] = .string(n)
                } else {
                    p.removeValue(forKey: "dialer-proxy")
                }
                proxies[pi] = .object(p)
            }
        }
        raw["proxies"] = .array(proxies)
        // Rule policies.
        var rules = raw.list("rules")
        for i in rules.indices {
            guard case .string(let line) = rules[i] else { continue }
            var parts = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            var idx = parts.count - 1
            if idx > 0 && parts[idx].trimmingCharacters(in: .whitespaces).lowercased() == "no-resolve" {
                idx -= 1
            }
            if idx <= 0 { continue }
            let pol = parts[idx].trimmingCharacters(in: .whitespaces)
            if groupNames.contains(pol) { continue }
            if let n = renamed[pol] {
                parts[idx] = n
                rules[i] = .string(parts.joined(separator: ","))
            } else if removed.contains(pol) {
                parts[idx] = "DIRECT"
                rules[i] = .string(parts.joined(separator: ","))
            }
        }
        raw["rules"] = .array(rules)
    }
}

// MARK: - SubPreview (bridge subrules.go SubPreview + processNodes rows)

/// nc-integrate B3: bridge SubPreview — runs a 节点处理 rule set against the profile without saving. Inline nodes
/// get the full pipeline (filter → dedupe → rename → sort → unique suffix); cached provider nodes get filter +
/// rename only, as the core applies to providers. Returns the previewResult JSON the view decodes.
enum NCSubPreview {

    private struct Row {
        var original: String
        var name: String
        var type: String
        var region = ""
        var kept = false
        var reason = ""
        var source = ""
        var json: [String: Any] {
            var d: [String: Any] = ["original": original, "name": name, "type": type, "kept": kept]
            if !region.isEmpty { d["region"] = region }
            if !reason.isEmpty { d["reason"] = reason }
            if !source.isEmpty { d["source"] = source }
            return d
        }
    }

    /// bridge compiledSub.processNodes, rows only (the preview never writes the nodes back).
    private static func rows(_ c: NCCompiledSub, _ nodes: [[String: NCJSONValue]]) -> [Row] {
        var rows: [Row] = []
        var seenKey = Set<String>()
        struct Item { var row: Int; var region: Int }
        var items: [Item] = []
        for p in nodes {
            let orig = ncStr(p["name"])
            var row = Row(original: orig, name: orig, type: ncStr(p["type"]).lowercased())
            if let inc = c.inc, !inc.isEmpty, !inc.match(orig) {
                row.reason = "未匹配保留规则"
            } else if let exc = c.exc, !exc.isEmpty, exc.match(orig) {
                row.reason = "匹配排除规则"
            }
            if row.reason.isEmpty && c.r.dedupe == true {
                let k = ncDedupeKey(p)
                if seenKey.contains(k) { row.reason = "重复节点" }
                seenKey.insert(k)
            }
            if !row.reason.isEmpty { rows.append(row); continue }
            row.kept = true
            row.name = c.rename(orig)
            let (code, idx) = ncDetectRegion(orig + " " + row.name)
            row.region = code
            rows.append(row)
            items.append(Item(row: rows.count - 1, region: idx))
        }
        func less(_ a: Item, _ b: Item) -> Bool {
            if ncNaturalLess(rows[a.row].name, rows[b.row].name) { return true }
            if ncNaturalLess(rows[b.row].name, rows[a.row].name) { return false }
            return a.row < b.row
        }
        switch c.r.sort ?? "" {
        case "name": items.sort(by: less)
        case "region": items.sort { $0.region != $1.region ? $0.region < $1.region : less($0, $1) }
        default: break
        }
        var used: [String: Int] = [:]
        for it in items {
            let base = rows[it.row].name
            var n = base
            var k = 1
            while (used[n] ?? 0) > 0 { n = "\(base) \(k + 1)"; k += 1 }
            used[n, default: 0] += 1
            rows[it.row].name = n
        }
        return rows
    }

    static func preview(home: String, profilePath: String, rulesJSON: String) -> String {
        var nodesOut: [[String: Any]] = []
        var providers: [String] = []
        var errors: [String] = []
        func result() -> String {
            let kept = nodesOut.filter { ($0["kept"] as? Bool) == true }.count
            return ncJSONString(["nodes": nodesOut, "total": nodesOut.count, "kept": kept,
                                 "providers": providers, "errors": errors] as [String: Any])
        }
        var r: NCSubRules
        do {
            var obj = (try JSONSerialization.jsonObject(with: Data(rulesJSON.utf8)) as? [String: Any]) ?? [:]
            obj["enabled"] = true
            r = try JSONDecoder().decode(NCSubRules.self, from: JSONSerialization.data(withJSONObject: obj))
        } catch {
            errors.append(error.localizedDescription)
            return result()
        }
        r.enabled = true
        var raw: [String: NCJSONValue] = [:]
        if let b = FileManager.default.contents(atPath: profilePath) {
            // Go: readOverrides(home) with o.home = "" and MergeManual off — no profile attachments
            // (sub rules, chains, overrides), no manual nodes.
            var settings = NCRuntimeSettings.load(home: home)
            settings.home = ""
            settings.core.mergeManual = false
            let req = NCRuntimeBuilder.Request(settings: settings, profileID: "", sub: nil, chains: [:])
            do {
                raw = try NCRuntimeBuilder.build(profile: b, req: req, fd: 0).raw
            } catch let e as NCRuntimeBuilder.BuildError {
                errors.append(e.message)
            } catch {
                errors.append(error.localizedDescription)
            }
        } else {
            errors.append("无法读取配置文件: " + (profilePath as NSString).lastPathComponent)
        }
        let c = NCCompiledSub(r)
        errors += c.errs
        nodesOut += rows(c, ncProxiesOf(raw)).map(\.json)
        var pr = NCSubRules()
        pr.enabled = true
        pr.include = r.include; pr.exclude = r.exclude; pr.regex = r.regex
        pr.stripPrefixes = r.stripPrefixes
        pr.stripFlags = (r.stripFlags == true) || (r.addFlag == true)
        pr.renames = r.renames; pr.prefix = r.prefix
        let cc = NCCompiledSub(pr)
        for pv in NCProfileInspectorPort.inspectProviders(homeDir: home, kind: "proxy", raw: raw["proxy-providers"]) {
            providers.append(pv.name)
            let pn: [[String: NCJSONValue]] = (pv.proxies ?? []).map { (p: InspectProxy) -> [String: NCJSONValue] in
                var m: [String: NCJSONValue] = ["name": .string(p.name), "type": .string(p.type),
                                                "server": .string(p.server ?? "")]
                m["port"] = .number(Double(p.port ?? 0))
                return m
            }
            nodesOut += rows(cc, pn).map { (row0: Row) -> [String: Any] in
                var row = row0
                row.source = pv.name
                return row.json
            }
        }
        return result()
    }
}
