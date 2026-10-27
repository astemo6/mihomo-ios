import Foundation

/// nc-integrate B3: the app-side provider downloads in Swift — ports of the retired bridge (ProviderPlan,
/// ProviderStore, MigrateProfileProviders), the converters ProviderStore uses (customrules convertListTo /
/// convertNodesText, mitm/rules ConvertListLine, mitm/egern IsEgernRuleSet / ConvertEgernRuleSet,
/// ownpolicy splitOwnPolicyList, runtimejson marshalProxiesYAML).
///
/// Reused Swift: NCRuntimeBuilder (runtime tree), NCEngineRuleset.convertRuleLine / splitTop (= mitm ConvertRuleLine / splitTop),
/// NCRuntimeSteps.providerConvert / uniqueProviderName, NCRuleValidator.prettyProviderName,
/// NCProfileInspectorPort.parseProviderNodes / parseRuleCache, NCSubscriptionParser (= parseNodeText).
///
/// Divergences: the old core streamed list conversion from a stream; here the downloaded Data is scanned line by line
/// in place (one UTF-8 decode of the download, no per-line arrays kept). MigrateProfileProviders re-emits the
/// profile with NCYAML.emit as the old core re-marshalled it with the reference YAML library (comments dropped in both).
enum NCProviderPorts {

    // MARK: - mitm ConvertListLine

    /// bridge mitm.ConvertListLine: one Surge / Loon / Stash / QX list line as a Clash.Meta classical line, or nil.
    static func convertListLine(_ line: String, kind: String) -> String? {
        var l = line.trimmingCharacters(in: .whitespaces)
        if l.isEmpty || l.hasPrefix("#") || l.hasPrefix(";") || l.hasPrefix("//") || l == "payload:" { return nil }
        if l.hasPrefix("- ") { l = String(l.dropFirst(2)) }
        l = l.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        if kind == "domainset" {
            return l.hasPrefix(".") ? "+" + l : l
        }
        let parts = NCEngineRuleset.splitTop(l)
        if parts.count < 2 {
            if case let (v4, masked)? = maskedPrefix(l) {
                return (v4 ? "IP-CIDR," : "IP-CIDR6,") + masked + ",no-resolve"
            }
            if case let (v4, a)? = normalizedAddr(l) {
                return v4 ? "IP-CIDR," + a + "/32,no-resolve" : "IP-CIDR6," + a + "/128,no-resolve"
            }
            if !l.contains(" ") && !l.contains(",") && l.contains(".") { return "DOMAIN," + l }
            return nil
        }
        let t = parts[0].uppercased()
        let withPol: String
        if t == "AND" || t == "OR" || t == "NOT" {
            withPol = parts[0] + "," + parts[1] + ",X"
        } else {
            let opts = parts.dropFirst(2).filter { $0.caseInsensitiveCompare("no-resolve") == .orderedSame }
            withPol = ([parts[0], parts[1], "X"] + opts).joined(separator: ",")
        }
        let (c, err) = NCEngineRuleset.convertRuleLine(withPol) // mitm ConvertRuleLine
        guard err == nil, !c.rule.isEmpty, c.type != "MATCH", c.remoteURL.isEmpty else { return nil }
        return c.rule + c.options
    }

    /// netip.ParseAddr + Addr.String(): (isV4, canonical text) or nil.
    static func normalizedAddr(_ s: String) -> (Bool, String)? {
        if s.contains("%") { return nil }
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 { return (true, ntop(AF_INET, &v4, 16)) }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 { return (false, ntop(AF_INET6, &v6, 46)) }
        return nil
    }

    /// netip.ParsePrefix + Masked().String(): (isV4, "addr/bits") or nil.
    static func maskedPrefix(_ s: String) -> (Bool, String)? {
        guard let slash = s.firstIndex(of: "/") else { return nil }
        let a = String(s[..<slash]), b = String(s[s.index(after: slash)...])
        guard !b.isEmpty, b.allSatisfy({ $0.isASCII && $0.isNumber }), let bits = Int(b), !a.contains("%") else { return nil }
        var v4 = in_addr()
        if inet_pton(AF_INET, a, &v4) == 1 {
            guard bits <= 32 else { return nil }
            var x = UInt32(bigEndian: v4.s_addr)
            x = bits == 0 ? 0 : x & (UInt32.max << UInt32(32 - bits))
            v4.s_addr = x.bigEndian
            return (true, ntop(AF_INET, &v4, 16) + "/\(bits)")
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, a, &v6) == 1 {
            guard bits <= 128 else { return nil }
            withUnsafeMutableBytes(of: &v6) { p in
                for i in 0..<16 {
                    let keep = max(0, min(8, bits - i * 8))
                    p[i] &= keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
                }
            }
            return (false, ntop(AF_INET6, &v6, 46) + "/\(bits)")
        }
        return nil
    }

    private static func ntop<T>(_ af: Int32, _ addr: inout T, _ len: Int) -> String {
        var buf = [CChar](repeating: 0, count: len)
        _ = inet_ntop(af, &addr, &buf, socklen_t(len))
        return String(cString: buf)
    }

    // MARK: - mitm Egern rule sets

    static let egernSetTypes: [String: String] = [
        "domain_set": "DOMAIN", "domain_suffix_set": "DOMAIN-SUFFIX", "domain_keyword_set": "DOMAIN-KEYWORD",
        "domain_regex_set": "DOMAIN-REGEX", "domain_wildcard_set": "DOMAIN-WILDCARD", "ip_cidr_set": "IP-CIDR",
        "ip_cidr6_set": "IP-CIDR6", "geoip_set": "GEOIP", "asn_set": "IP-ASN", "dest_port_set": "DST-PORT",
        "protocol_set": "NETWORK",
    ]

    /// bridge mitm.IsEgernRuleSet (first meaningful line is a `*_set:` key).
    static func isEgernRuleSet(_ text: String) -> Bool {
        var result = false
        forEachLine(text) { l in
            let t = l.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("#") || t == "no_resolve: true" || t == "no_resolve: false" { return true }
            if !t.hasPrefix("-"), let c = t.firstIndex(of: ":") {
                let k = String(t[..<c])
                result = egernSetTypes[k] != nil || k.hasSuffix("_set")
            }
            return false
        }
        return result
    }

    /// bridge mitm.ConvertEgernRuleSet: (classical lines, skipped entries).
    static func convertEgernRuleSet(_ text: String) -> (lines: [String], skipped: Int) {
        guard case .object(let doc)? = NCYAML.parse(text) else { return ([], 0) }
        let noResolve = ncBool(doc["no_resolve"]) || (doc["no_resolve"]?.number.map { $0 != 0 } ?? false)
        var out: [String] = []
        var skipped = 0
        for k in doc.keys.sorted() {
            let items: [NCJSONValue] = doc[k]?.array ?? []
            guard let t = egernSetTypes[k] else { skipped += items.count; continue }
            for it in items {
                var v = ncStr(it).trimmingCharacters(in: .whitespaces)
                if v.isEmpty { continue }
                switch k {
                case "asn_set":
                    v = v.uppercased(); if v.hasPrefix("AS") { v = String(v.dropFirst(2)) }
                case "dest_port_set":
                    v = v.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: ",", with: "/")
                case "protocol_set":
                    v = v.uppercased()
                    if v != "TCP" && v != "UDP" { skipped += 1; continue }
                default: break
                }
                var line = t + "," + v
                if noResolve && (t == "IP-CIDR" || t == "IP-CIDR6" || t == "GEOIP" || t == "IP-ASN") { line += ",no-resolve" }
                out.append(line)
            }
        }
        return (out, skipped)
    }

    // MARK: - convertListTo / convertNodesText

    /// Calls body for each "\n"-separated line ("\r" stripped) until it returns false. No line array is built.
    static func forEachLine(_ text: String, _ body: (Substring) -> Bool) {
        var start = text.startIndex
        while start < text.endIndex {
            let end = text[start...].firstIndex(of: "\n") ?? text.endIndex
            var line = text[start..<end]
            if line.hasSuffix("\r") { line = line.dropLast() }
            if !body(line) { return }
            if end == text.endIndex { return }
            start = text.index(after: end)
        }
    }

    /// bridge convertListText / convertListTo: (Clash.Meta text, converted lines, skipped lines).
    static func convertListText(_ data: Data, kind: String) -> (text: String, ok: Int, skipped: Int) {
        var text = String(decoding: data, as: UTF8.self)
        if text.hasPrefix("\u{FEFF}") { text.removeFirst() }
        var out = ""
        out.reserveCapacity(min(data.count, 16 << 20))
        var ok = 0, skipped = 0
        var decided = false
        var head: [Substring] = []
        var egern: (lines: [String], skipped: Int)? = nil
        func emit(_ line: Substring) {
            guard let l = convertListLine(String(line), kind: kind) else {
                let t = line.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty && !t.hasPrefix("#") && !t.hasPrefix(";") && !t.hasPrefix("//") && t != "payload:" { skipped += 1 }
                return
            }
            out += l
            out += "\n"
            ok += 1
        }
        forEachLine(text) { line in
            if decided { emit(line); return true }
            head.append(line)
            let t = line.trimmingCharacters(in: .whitespaces)
            if !t.isEmpty && !t.hasPrefix("#") && t != "no_resolve: true" && t != "no_resolve: false" {
                decided = true
                if isEgernRuleSet(head.joined(separator: "\n")) {
                    egern = convertEgernRuleSet(text)
                    return false
                }
                for h in head { emit(h) }
                head = []
            }
            return true
        }
        if let e = egern {
            return (e.lines.isEmpty ? "" : e.lines.joined(separator: "\n") + "\n", e.lines.count, e.skipped)
        }
        for h in head { emit(h) }
        return (out, ok, skipped)
    }

    /// bridge convertNodesText: Clash YAML passes through (count -1); anything else is parsed as a node list and
    /// written as a proxy-provider YAML (one JSON flow line per node). nil when no node is recognised.
    static func convertNodesText(_ data: Data) -> (data: Data, count: Int)? {
        if data.range(of: Data("proxies:".utf8)) != nil { return (data, -1) }
        var text = String(decoding: data, as: UTF8.self)
        if text.hasPrefix("\u{FEFF}") { text.removeFirst() }
        let ps = NCSubscriptionParser.parse(text.trimmingCharacters(in: .whitespacesAndNewlines))
        if ps.isEmpty { return nil }
        return (marshalProxiesYAML(ps.map { p -> [String: Any] in
            var d = p.fields.mapValues { $0.rawAny }
            d["name"] = p.name
            d["type"] = p.type
            return d
        }), ps.count)
    }

    /// bridge marshalProxiesYAML.
    static func marshalProxiesYAML(_ list: [[String: Any]]) -> Data {
        if list.isEmpty { return Data("proxies: []\n".utf8) }
        var buf = Data("proxies:\n".utf8)
        for p in list {
            guard let j = try? JSONSerialization.data(withJSONObject: p, options: [.sortedKeys, .withoutEscapingSlashes]) else {
                return Data(NCYAML.emit(["proxies": list]).utf8)
            }
            buf.append(contentsOf: Array("  - ".utf8))
            buf.append(j)
            buf.append(0x0A)
        }
        return buf
    }

    // MARK: - ownpolicy

    static let ownPolicyMaxParts = 32

    /// bridge lineOwnPolicy.
    static func lineOwnPolicy(_ line: Substring) -> String {
        var l = line.trimmingCharacters(in: .whitespaces)
        if l.hasPrefix("- ") { l = String(l.dropFirst(2)) }
        l = l.trimmingCharacters(in: .whitespaces)
        let parts = l.split(separator: ",", omittingEmptySubsequences: false)
        if parts.count < 3 { return "" }
        switch parts[0].trimmingCharacters(in: .whitespaces).uppercased() {
        case "AND", "OR", "NOT": return ""
        default: break
        }
        for p0 in parts.dropFirst(2) {
            let p = p0.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
            if p.isEmpty || p.caseInsensitiveCompare("no-resolve") == .orderedSame || p.contains("=") { continue }
            return p
        }
        return ""
    }

    /// bridge splitOwnPolicyList: one converted file per policy (<base>.own<i>.txt) and <cache>.policies.json.
    static func splitOwnPolicyList(cachePath: String, data: Data) throws -> Int {
        struct Bucket { var policy: String; var lines: [String] }
        var order: [Bucket] = []
        var byKey: [String: Int] = [:]
        let text = String(decoding: data, as: UTF8.self)
        forEachLine(text) { raw in
            let pol = lineOwnPolicy(raw)
            if pol.isEmpty { return true }
            guard let rule = convertListLine(String(raw), kind: "list") else { return true }
            var key = pol
            let lp = pol.lowercased()
            if lp == "proxy" || lp == "direct" || lp.hasPrefix("reject") { key = lp }
            if let i = byKey[key] {
                order[i].lines.append(rule)
            } else if order.count < ownPolicyMaxParts {
                byKey[key] = order.count
                order.append(Bucket(policy: pol, lines: [rule]))
            }
            return true
        }
        let side = cachePath + ".policies.json"
        if order.isEmpty {
            try? FileManager.default.removeItem(atPath: side)
            return 0
        }
        let dir = (cachePath as NSString).deletingLastPathComponent
        let base = ((cachePath as NSString).lastPathComponent as NSString).deletingPathExtension
        var parts: [[String: Any]] = []
        for (i, b) in order.enumerated() {
            let f = base + ".own\(i).txt"
            try Data((b.lines.joined(separator: "\n") + "\n").utf8)
                .write(to: URL(fileURLWithPath: (dir as NSString).appendingPathComponent(f)), options: .atomic)
            parts.append(["policy": b.policy, "file": f, "count": b.lines.count])
        }
        let j = try JSONSerialization.data(withJSONObject: parts)
        try j.write(to: URL(fileURLWithPath: side), options: .atomic)
        return parts.count
    }

    // MARK: - ProviderPlan

    /// bridge ProviderPlan: the HTTP providers of the runtime config with what to download and where to write.
    static func providerPlan(home: String, profilePath: String) -> String {
        guard let b = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) else { return "[]" }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        guard let raw = (try? NCRuntimeBuilder.build(profile: b, req: req, fd: 0))?.raw else { return "[]" }
        var out: [[String: Any]] = []
        for (kind, key) in [("rule", "rule-providers"), ("proxy", "proxy-providers")] {
            for (name, v) in raw.map(key) {
                guard case .object(let m) = v, ncStr(m["type"]).lowercased() == "http" else { continue }
                let path = ncProviderCachePath(home: home, kind: kind, m)
                let u = ncStr(m["url"])
                var dl = u, convert = ""
                if let pu = URLComponents(string: u), pu.host == "127.0.0.1",
                   pu.path.hasSuffix("/rules/convert") || pu.path.hasSuffix("/nodes/convert") {
                    let q = pu.queryItems ?? []
                    dl = q.first { $0.name == "url" }?.value ?? ""
                    convert = q.first { $0.name == "kind" }?.value ?? ""
                    if pu.path.hasSuffix("/nodes/convert") { convert = "nodes" }
                }
                if convert.isEmpty { convert = ncStr(m["x-convert"]) } // fix/nc-ruleset-convert: runtime keeps the source URL
                if NCRuntimeSteps.truthy(m["x-own-policy"]) && convert == "list" { convert = "list-split" }
                let xs = ncStr(m["x-source"])
                if dl.isEmpty || path.isEmpty { continue }
                var t: [String: Any] = ["kind": kind, "name": name, "url": dl, "source": xs.isEmpty ? dl : xs,
                                        "convert": convert, "path": path, "interval": ncInt(m["interval"]),
                                        "updated": mtime(path)]
                let fmt = ncStr(m["format"])
                if !fmt.isEmpty { t["format"] = fmt }
                // fix/nc-open-6-10 #10: the provider's own User-Agent (Clash.Meta `header`), e.g. QuanX for QX imports.
                if case .object(let h)? = m["header"] {
                    for (k, v) in h where k.lowercased() == "user-agent" {
                        if case .array(let a) = v, case .string(let ua)? = a.first, !ua.isEmpty { t["userAgent"] = ua }
                        else if case .string(let ua) = v, !ua.isEmpty { t["userAgent"] = ua }
                    }
                }
                out.append(t)
            }
        }
        out.sort {
            let ka = $0["kind"] as? String ?? "", kb = $1["kind"] as? String ?? ""
            if ka != kb { return ka > kb }
            return ($0["name"] as? String ?? "") < ($1["name"] as? String ?? "")
        }
        let s = ncJSONString(out)
        return s.isEmpty ? "[]" : s
    }

    /// bridge mtime: whole seconds of the modification time, 0 when missing.
    static func mtime(_ p: String) -> Double {
        guard let d = (try? FileManager.default.attributesOfItem(atPath: p))?[.modificationDate] as? Date else { return 0 }
        return d.timeIntervalSince1970.rounded(.down)
    }

    // MARK: - ProviderStore

    /// bridge ProviderStore: converts the download like the core's converter and writes it to cachePath (inside
    /// home). Returns {"count": n, "error": "…"}.
    static func providerStore(home: String, kind: String, cachePath: String, convert: String, data: Data) -> String {
        func res(_ n: Int, _ e: String) -> String { ncJSONString(["count": n, "error": e]) }
        // fix/nc-0.20.2: lexical containment (NSString.standardizingPath strips "/private" only for existing files, so a
        // not-yet-downloaded cache under /private/var/… never matched the existing home → 「路径不在内核目录内」).
        if !NCPathContainment.isInside(home: home, cachePath, allowHomeItself: false) { return res(0, "路径不在内核目录内") }
        if data.allSatisfy({ $0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D || $0 == 0x0B || $0 == 0x0C }) {
            return res(0, "下载内容为空")
        }
        var out = data
        var n = -1
        let dir = (cachePath as NSString).deletingLastPathComponent
        if convert == "nodes" {
            guard let r = convertNodesText(data) else { return res(0, "没有识别到节点") }
            out = r.data; n = r.count
            if n < 0 { n = NCProfileInspectorPort.parseProviderNodes(data: out, source: "").count }
        } else if convert == "list-split" {
            let r = convertListText(data, kind: "list")
            if r.ok == 0 { return res(0, "列表里没有可用的规则") }
            out = Data(r.text.utf8); n = r.ok
            do {
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                _ = try splitOwnPolicyList(cachePath: cachePath, data: data)
            } catch { return res(0, error.localizedDescription) }
        } else if !convert.isEmpty {
            let r = convertListText(data, kind: convert)
            if r.ok == 0 { return res(0, "列表里没有可用的规则") }
            out = Data(r.text.utf8); n = r.ok
        } else if kind == "proxy" {
            n = NCProfileInspectorPort.parseProviderNodes(data: data, source: "").count
            if n == 0 { return res(0, "没有识别到节点") }
        } else {
            n = NCProfileInspectorPort.parseRuleCache(data: data, format: "").count
        }
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try out.write(to: URL(fileURLWithPath: cachePath), options: .atomic)
        } catch { return res(0, error.localizedDescription) }
        return res(n, "")
    }

    // MARK: - MigrateProfileProviders

    /// bridge MigrateProfileProviders: "convert+<kind>:<url>" providers keep the source URL (+ x-convert),
    /// custom-<hash> rule providers get readable names and RULE-SET references follow. Changed count or -1.
    static func migrateProfileProviders(_ profilePath: String) -> Int {
        NCPathLock.shared.withLock(for: profilePath) { () -> Int in
            guard let b = FileManager.default.contents(atPath: profilePath),
                  b.range(of: Data("convert+".utf8)) != nil else { return 0 }
            guard case .object(var raw)? = NCYAML.parse(String(decoding: b, as: UTF8.self)) else { return -1 }
            var changed = 0
            var renames: [String: String] = [:]
            if case .object(var pp)? = raw["proxy-providers"] {
                for (k, v) in pp {
                    guard case .object(var m) = v else { continue }
                    let (kind, src) = NCRuntimeSteps.providerConvert(m)
                    if !kind.isEmpty && ncStr(m["url"]).hasPrefix("convert+") {
                        m["url"] = .string(src); m["x-convert"] = .string(kind)
                        pp[k] = .object(m); changed += 1
                    }
                }
                raw["proxy-providers"] = .object(pp)
            }
            if case .object(var rp)? = raw["rule-providers"] {
                for n in rp.keys.sorted() {
                    guard case .object(var m)? = rp[n], ncStr(m["url"]).hasPrefix("convert+") else { continue }
                    let (kind, src) = NCRuntimeSteps.providerConvert(m)
                    m["url"] = .string(src); m["x-convert"] = .string(kind)
                    changed += 1
                    if n.hasPrefix("custom-") {
                        let nn = NCRuntimeSteps.uniqueProviderName(
                            NCRuleValidator.prettyProviderName(u: src, tag: "")) { rp[$0] != nil }
                        rp[nn] = .object(m)
                        rp.removeValue(forKey: n)
                        renames[n] = nn
                    } else {
                        rp[n] = .object(m)
                    }
                }
                raw["rule-providers"] = .object(rp)
            }
            if changed == 0 { return 0 }
            func fixList(_ v: NCJSONValue?) -> NCJSONValue? {
                guard case .array(let rl)? = v else { return v }
                return .array(rl.map { if case .string(let s) = $0 { return .string(fixRuleSetRefs(s, renames)) }; return $0 })
            }
            if raw["rules"] != nil { raw["rules"] = fixList(raw["rules"]) }
            if case .object(var sr)? = raw["sub-rules"] {
                for k in sr.keys { sr[k] = fixList(sr[k]) }
                raw["sub-rules"] = .object(sr)
            }
            let out = Data(NCYAML.emit(NCJSONValue.object(raw)).utf8)
            do { try out.write(to: URL(fileURLWithPath: profilePath), options: .atomic) } catch { return -1 }
            return changed
        }
    }

    private static let ruleSetRefRE = try! NSRegularExpression(pattern: #"RULE-SET\s*,\s*([^,()]+)"#)

    /// bridge ruleSetRefRE.ReplaceAllStringFunc: renames RULE-SET,<old> (also inside logical rules).
    static func fixRuleSetRefs(_ r: String, _ renames: [String: String]) -> String {
        if renames.isEmpty { return r }
        let ns = r as NSString
        var out = r
        for m in ruleSetRefRE.matches(in: r, range: NSRange(location: 0, length: ns.length)).reversed() {
            let g = ns.substring(with: m.range(at: 1))
            guard let nn = renames[g.trimmingCharacters(in: .whitespaces)] else { continue }
            // the old core replaces once — the first occurrence of the captured text in the match.
            let whole = ns.substring(with: m.range)
            guard let rr = whole.range(of: g) else { continue }
            let replaced = whole.replacingCharacters(in: rr, with: nn)
            out = (out as NSString).replacingCharacters(in: m.range, with: replaced)
        }
        return out
    }
}
