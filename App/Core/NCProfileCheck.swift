import Foundation

/// B1 (Go-zero): the profile editor's live check — Swift port of bridge/profilecheck.go (ProfileCheck,
/// checkProfileText, locate, firstBadLine) and bridge/robust.go FriendlyError. Parses the edited text the way a
/// connect does (YAML, the profile's overrides, NCRuntimeBuilder, then NCConfigValidator — mihomo's
/// executor.ParseWithBytes in Go) and points at the line / column of the problem in the user's text.
///
/// DIVERGENCES: yaml.v3 gave a node tree with positions and its own error text ("line N: …"); NCYAML now
/// records the line for the failures it can localize (unclosed flow / quote, see NCYAMLError) and otherwise
/// firstBadLine (the same binary search Go used to refine yaml.v3's line) supplies it — either way the line
/// is carried in the error message itself (「YAML 格式错误：第 N 行：无法解析」), not only in Result.line,
/// and locate() finds the item in the text with a line scanner over the top-level block (column = the
/// item's first key, as yaml.v3's mapping node reports it).
enum NCProfileCheck {

    struct Result: Codable, Equatable {
        var ok = false
        var error: String?
        var line: Int?
        var column: Int?
        var nodes = 0
        var groups = 0
        var rules = 0
        var providers = 0
    }

    /// bridge ProfileCheck: JSON {ok, error, line, column, nodes, groups, rules, providers}.
    static func check(home: String, profilePath: String, text: String) -> Result {
        let parsed = NCYAML.parseWithError(text)
        guard parsed.value != nil || isBlank(text) else {
            // Carry the line in the message itself, not only in Result.line: other surfaces
            // (save / import errors) show the text without the editor's line chip.
            let bad = firstBadLine(text)
            let l = parsed.error?.line ?? (bad > 0 ? bad : nil)
            var r = Result(error: l.map { "YAML 格式错误：第 \($0) 行：无法解析" } ?? "YAML 格式错误：无法解析")
            if let l { r.line = l }
            return r
        }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        let built: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])
        do {
            built = try NCRuntimeBuilder.build(profile: Data(text.utf8), req: req, fd: 0)
        } catch let e as NCRuntimeBuilder.BuildError {
            return Result(error: friendlyError(e.message))
        } catch {
            return Result(error: friendlyError(error.localizedDescription))
        }
        do {
            let cfg = try NCConfigValidator.parse(built.raw)
            let nodes = built.raw["proxies"]?.array?.count ?? 0
            let groups = (built.raw["proxy-groups"]?.array ?? []).filter { $0["name"]?.string != probeGroup }.count
            return Result(ok: true, nodes: nodes, groups: groups, rules: cfg.rules, providers: cfg.providers)
        } catch {
            let msg = (error as? NCConfigValidator.ParseError)?.message ?? error.localizedDescription
            var r = Result(error: friendlyError(msg))
            if let loc = locate(text: text, rt: built.raw, msg: msg) {
                r.line = loc.0
                r.column = loc.1
                r.error = "第 \(loc.0) 行：\(friendlyError(msg))"
            }
            return r
        }
    }

    static func checkJSON(home: String, profilePath: String, text: String) -> String {
        let enc = JSONEncoder()
        guard let d = try? enc.encode(check(home: home, profilePath: profilePath, text: text)),
              let s = String(data: d, encoding: .utf8) else { return "{\"ok\":false}" }
        return s
    }

    /// bridge ProbeGroup (probe.go): never counted as a user group.
    static let probeGroup = "TERN-PROBE"

    private static func isBlank(_ text: String) -> Bool {
        text.split(separator: "\n").allSatisfy {
            let t = $0.trimmingCharacters(in: .whitespaces)
            return t.isEmpty || t.hasPrefix("#") || t == "---"
        }
    }

    // MARK: - firstBadLine

    /// The line a YAML failure message should carry: the parser's own recorded line when it has
    /// one, else firstBadLine's. Shared by the other YAML error surfaces (builder / override /
    /// group-order / profile-node validation) so every "YAML 解析失败" reads the same.
    static func errorLine(_ text: String) -> Int? {
        if let e = NCYAML.parseWithError(text).error { return e.line }
        let l = firstBadLine(text)
        return l > 0 ? l : nil
    }

    /// Prefixes a YAML error message with 「第 N 行：」 when a line can be determined.
    static func withLine(_ base: String, _ text: String) -> String {
        guard let l = errorLine(text) else { return base }
        return "第 \(l) 行：\(base)"
    }

    /// The first line whose prefix (lines 1…n) no longer parses: ~log2(lines) parses.
    static func firstBadLine(_ text: String) -> Int {
        var lines: [Substring] = []
        var start = text.startIndex
        while start < text.endIndex {
            let end = text[start...].firstIndex(of: "\n").map { text.index(after: $0) } ?? text.endIndex
            lines.append(text[start..<end])
            start = end
        }
        func bad(_ n: Int) -> Bool {
            let s = lines[0..<n].joined()
            return NCYAML.parse(s) == nil && !isBlank(s)
        }
        var lo = 1, hi = lines.count
        guard hi > 0, bad(hi) else { return 0 }
        while lo < hi {
            let mid = (lo + hi) / 2
            if bad(mid) { hi = mid } else { lo = mid + 1 }
        }
        return lo
    }

    // MARK: - locate

    private static func firstMatch(_ pattern: String, _ s: String) -> [String]? {
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return (0..<m.numberOfRanges).map { i in
            Range(m.range(at: i), in: s).map { String(s[$0]) } ?? ""
        }
    }

    private static func nthName(_ rt: [String: NCJSONValue], _ key: String, _ idx: Int) -> String {
        let l = rt[key]?.array ?? []
        guard idx >= 0, idx < l.count else { return "" }
        return NCConfigValidator.scalar(l[idx]["name"]) ?? ""
    }

    /// bridge locate: (line, column), 1-based, of the item the error is about.
    static func locate(text: String, rt: [String: NCJSONValue], msg: String) -> (Int, Int)? {
        let doc = TextDoc(text)
        if let m = firstMatch(#"^proxy (\d+):"#, msg), let i = Int(m[1]) {
            return doc.itemNamed(block: "proxies", name: nthName(rt, "proxies", i))
        }
        if let m = firstMatch(#"^proxy group\[\d+\]: ([^:]+):"#, msg), let r = doc.itemNamed(block: "proxy-groups", name: m[1]) {
            return r
        }
        if let m = firstMatch(#"^proxy group(?:\[| )(\d+)\]?:"#, msg), let i = Int(m[1]) {
            return doc.itemNamed(block: "proxy-groups", name: nthName(rt, "proxy-groups", i))
        }
        if let m = firstMatch(#"^proxy (.+) is the duplicate name"#, msg) {
            return doc.itemNamed(block: "proxies", name: m[1])
        }
        if let m = firstMatch(#"^proxy group (.+): the duplicate name"#, msg) {
            return doc.itemNamed(block: "proxy-groups", name: m[1])
        }
        if let m = firstMatch(#"proxy group (\S+) can't contains"#, msg) {
            return doc.itemNamed(block: "proxy-groups", name: m[1])
        }
        if let m = firstMatch(#"^parse proxy provider (\S+) error"#, msg) {
            return doc.mapKey(block: "proxy-providers", key: m[1])
        }
        if let m = firstMatch(#"^(?:rules|sub-rule)\[\d+\] \[(.*?)\] error"#, msg) {
            let want = m[1].replacingOccurrences(of: " ", with: "")
            for k in ["rules", "sub-rules"] {
                if let r = doc.scalar(block: k, equalsNoSpace: want) { return r }
            }
        }
        return nil
    }

    /// Line scanner over the user's text: top-level blocks and the items inside them.
    struct TextDoc {
        let lines: [String]
        init(_ text: String) { lines = text.components(separatedBy: "\n") }

        static func unquote(_ s0: String) -> String {
            var s = s0.trimmingCharacters(in: .whitespaces)
            if let hash = s.range(of: " #") { s = String(s[..<hash.lowerBound]).trimmingCharacters(in: .whitespaces) }
            if s.count >= 2, (s.hasPrefix("\"") && s.hasSuffix("\"")) || (s.hasPrefix("'") && s.hasSuffix("'")) {
                s = String(s.dropFirst().dropLast())
            }
            return s
        }

        /// Line range (0-based, end exclusive) of the top-level `key:` block's body.
        func block(_ key: String) -> Range<Int>? {
            guard let start = lines.firstIndex(where: { $0.hasPrefix(key + ":") || $0.hasPrefix("\"\(key)\":") }) else { return nil }
            var end = start + 1
            while end < lines.count {
                let l = lines[end]
                if let f = l.first, f != " ", f != "\t", f != "#", f != "-", !l.trimmingCharacters(in: .whitespaces).isEmpty { break }
                end += 1
            }
            return start..<end
        }

        /// The item whose `name` is name: (line, column of the item's first key).
        func itemNamed(block key: String, name: String) -> (Int, Int)? {
            guard !name.isEmpty, let r = block(key) else { return nil }
            var itemStart: (Int, Int)?
            for i in r {
                let l = lines[i]
                let trimmed = l.drop(while: { $0 == " " })
                let indent = l.count - trimmed.count
                if trimmed.hasPrefix("- ") {
                    let after = trimmed.dropFirst(2).drop(while: { $0 == " " })
                    let gap = trimmed.dropFirst(2).count - after.count
                    itemStart = (i + 1, indent + 2 + gap + 1)
                    if after.hasPrefix("{") {
                        // flow item: {name: x, ...}
                        if let m = after.range(of: #"name\s*:\s*("[^"]*"|'[^']*'|[^,}]+)"#, options: .regularExpression) {
                            let v = String(after[m]).split(separator: ":", maxSplits: 1).last.map(String.init) ?? ""
                            if Self.unquote(v) == name { return (i + 1, indent + 3) }
                        }
                        continue
                    }
                    if after.hasPrefix("name:"), Self.unquote(String(after.dropFirst(5))) == name { return itemStart }
                } else if trimmed.hasPrefix("name:"), Self.unquote(String(trimmed.dropFirst(5))) == name {
                    return itemStart ?? (i + 1, indent + 1)
                }
            }
            return nil
        }

        /// The key line of `key:` inside a top-level mapping block.
        func mapKey(block b: String, key: String) -> (Int, Int)? {
            guard let r = block(b) else { return nil }
            for i in r.dropFirst() {
                let l = lines[i]
                let trimmed = l.drop(while: { $0 == " " })
                for k in [key + ":", "\"\(key)\":", "'\(key)':"] where trimmed.hasPrefix(k) {
                    return (i + 1, l.count - trimmed.count + 1)
                }
            }
            return nil
        }

        /// A sequence scalar equal to want once spaces are removed.
        func scalar(block b: String, equalsNoSpace want: String) -> (Int, Int)? {
            guard let r = block(b) else { return nil }
            for i in r {
                let l = lines[i]
                let trimmed = l.drop(while: { $0 == " " })
                guard trimmed.hasPrefix("- ") else { continue }
                let v = Self.unquote(String(trimmed.dropFirst(2)))
                if v.replacingOccurrences(of: " ", with: "") == want {
                    return (i + 1, l.count - trimmed.count + 3)
                }
            }
            return nil
        }
    }

    // MARK: - FriendlyError (bridge/robust.go)

    private static let errHints: [(String, String)] = [
        (#"(?i)yaml:|unmarshal|mapping values are not allowed|did not find expected"#, "配置文件格式错误（YAML）"),
        (#"(?i)(rule[- ]?provider|ruleset|rule set)"#, "规则集加载失败"),
        (#"(?i)(proxy[- ]?provider)"#, "节点集（proxy-provider）加载失败"),
        (#"(?i)(geosite|geoip|mmdb|metadb|asn\.mmdb|geodata).*(download|not found|no such file|invalid|failed)|(download|can't download).*(geo|mmdb)"#,
         "地理数据库缺失或损坏，且下载失败（可在 更多 → 高级设置 → 地理数据库 更新，或打开国内镜像）"),
        (#"(?i)(proxy group|proxy-group|group).*(not found|doesn't exist|does not exist)|'proxies' missing|use or proxies missing"#,
         "策略组引用了不存在的节点或策略组"),
        (#"(?i)(proxy|proxies) ?\d*:.*(missing|invalid|unsupported|not support)|parse proxy|unsupport proxy type"#,
         "有节点无法解析（协议参数缺失或不支持）"),
        (#"(?i)rules\[\d+\]|rule .*(invalid|not found|unsupported)|payload"#, "规则写法有误或引用了不存在的策略"),
        (#"(?i)address already in use|bind:"#, "本地端口被占用（仅代理模式 / 局域网共享的端口或控制器端口）"),
        (#"(?i)tun|file-descriptor|gvisor"#, "隧道初始化失败"),
        (#"(?i)dns|nameserver"#, "DNS 设置有误"),
        (#"(?i)i/o timeout|context deadline|timeout"#, "网络超时"),
    ]

    /// bridge FriendlyError: a Chinese reason before a core error; Chinese messages pass through.
    static func friendlyError(_ msg: String) -> String {
        if msg.isEmpty { return "" }
        if msg.unicodeScalars.contains(where: { $0.value >= 0x4E00 && $0.value <= 0x9FFF }) { return msg }
        for (p, hint) in errHints where firstMatch(p, msg) != nil {
            return hint + "：" + msg
        }
        return "配置无效：" + msg
    }
}
