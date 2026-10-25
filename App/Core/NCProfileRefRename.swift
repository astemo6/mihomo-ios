import Foundation

/// B5 (nc-dego-rest): bridge/profilenodes.go ProfileRenameRefs in Swift — renames every reference to a group or
/// node in a profile file (group members, group / node dialer-proxy, the policy of rules and sub-rules) without
/// touching the entry itself. Used when a group that lives outside the file (策略组编辑 added groups) is renamed.
///
/// Go edited a yaml.v3 node tree and re-encoded the whole document (comments kept, layout normalised). Swift has
/// no comment-keeping YAML tree, so the edit is made on the text: only the scalars that change are rewritten,
/// in their own quoting style, so every other byte of the file — comments, order, indentation — stays. The
/// result is then checked: parsed again it must equal the parsed original with the rename applied to the tree.
/// When a construct the text editor does not handle (multi-line flow collections, block scalars, anchors whose
/// alias moves…) makes that check fail, the expected tree is written with NCYAMLEmitter instead (comments and
/// key order are lost then — Go lost the layout too); the previous file is kept as <file>.bak either way.
enum NCProfileRefRename {

    struct Stats {
        var groups: [String] = []
        var rules = 0
        var dialers: [String] = []
        var touched: Bool { !groups.isEmpty || rules > 0 || !dialers.isEmpty }
    }

    // MARK: - Entry point (bridge ProfileRenameRefs)

    /// Returns "" or an error message.
    static func profileRenameRefs(home: String, path: String, old: String, new: String) -> String {
        NCPathLock.shared.withLock(for: path) { () -> String in
            if old.isEmpty || new.isEmpty || old == new { return "" }
            guard let orig = FileManager.default.contents(atPath: path) else {
                return "读取配置失败: " + (path as NSString).lastPathComponent
            }
            let text = String(decoding: orig, as: UTF8.self)
            guard case .object(var tree)? = NCYAML.parse(text) else {
                return "配置文件不是 YAML 映射"
            }
            let st = renameTree(&tree, old: old, new: new)
            if !st.touched { return "" }
            let expected = NCJSONValue.object(tree)
            var out = renameText(text, old: old, new: new)
            if NCYAML.parse(out) != expected {
                out = NCYAMLEmitter.emit(expected)
                if NCYAML.parse(out) != expected {
                    return "无法改写配置中「\(old)」的引用"
                }
            }
            return commit(home: home, path: path, orig: orig, new: Data(out.utf8))
        }
    }

    /// bridge commit: validate the edited bytes the way a connect builds them (an error the unedited file already
    /// has does not block the edit), keep <path>.bak, write atomically.
    /// The check is the full one: NCRuntimeBuilder.build + NCConfigValidator (Go's buildRuntime +
    /// parseRuntimeCached), cached by runtime bytes like Go's.
    static func commit(home: String, path: String, orig: Data, new: Data) -> String {
        if let e = buildError(home: home, path: path, bytes: new) {
            let pre = buildError(home: home, path: path, bytes: orig)
            if pre == nil || pre != e { return e }
        }
        do {
            try NCRuntimeFiles.writeAtomic(orig, to: path + ".bak")
            try NCRuntimeFiles.writeAtomic(new, to: path)
        } catch {
            return error.localizedDescription
        }
        return ""
    }

    /// The runtime build error for these profile bytes, nil when it builds.
    static func buildError(home: String, path: String, bytes: Data) -> String? {
        NCConfigValidator.validate(home: home, path: path, profile: bytes)
    }

    // MARK: - Tree rename (bridge yamlDoc.renameRefs, new non-empty)

    /// A scalar's text as yaml.v3 holds it in Node.Value (strings, numbers, bools).
    static func scalarText(_ v: NCJSONValue) -> String? {
        switch v {
        case .string(let s): return s
        case .bool(let b): return b ? "true" : "false"
        case .number(let d):
            if d.isFinite, d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
            return String(d)
        default: return nil
        }
    }

    static func renameTree(_ raw: inout [String: NCJSONValue], old: String, new: String) -> Stats {
        var st = Stats()
        if case .array(var groups)? = raw["proxy-groups"] {
            for i in groups.indices {
                guard case .object(var g) = groups[i] else { continue }
                let gname = g.str("name")
                if case .array(var members)? = g["proxies"] {
                    var hit = false
                    for j in members.indices where scalarText(members[j]) == old {
                        members[j] = .string(new)
                        hit = true
                    }
                    if hit {
                        g["proxies"] = .array(members)
                        st.groups.append(gname)
                    }
                }
                if let d = g["dialer-proxy"], scalarText(d) == old {
                    g["dialer-proxy"] = .string(new)
                    st.dialers.append(gname)
                }
                groups[i] = .object(g)
            }
            raw["proxy-groups"] = .array(groups)
        }
        if case .array(var proxies)? = raw["proxies"] {
            for i in proxies.indices {
                guard case .object(var p) = proxies[i] else { continue }
                if let d = p["dialer-proxy"], scalarText(d) == old {
                    p["dialer-proxy"] = .string(new)
                    st.dialers.append(p.str("name"))
                    proxies[i] = .object(p)
                }
            }
            raw["proxies"] = .array(proxies)
        }
        func renameSeq(_ seq: inout [NCJSONValue]) {
            for i in seq.indices {
                guard case .string(let r) = seq[i], let n = renameRule(r, old: old, new: new) else { continue }
                seq[i] = .string(n)
                st.rules += 1
            }
        }
        if case .array(var rules)? = raw["rules"] {
            renameSeq(&rules)
            raw["rules"] = .array(rules)
        }
        if case .object(var sub)? = raw["sub-rules"] {
            for (k, v) in sub {
                guard case .array(var seq) = v else { continue }
                renameSeq(&seq)
                sub[k] = .array(seq)
            }
            raw["sub-rules"] = .object(sub)
        }
        return st
    }

    /// bridge ysplitRule: commas outside parentheses.
    static func splitRule(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var cur = ""
        for ch in s {
            switch ch {
            case "(": depth += 1; cur.append(ch)
            case ")": depth -= 1; cur.append(ch)
            case "," where depth == 0:
                out.append(cur)
                cur = ""
            default: cur.append(ch)
            }
        }
        out.append(cur)
        return out
    }

    /// bridge ruleTarget: the policy field (last one, skipping no-resolve / src).
    static func ruleTarget(_ parts: [String]) -> Int {
        var i = parts.count - 1
        while i > 1 {
            let p = parts[i].trimmingCharacters(in: .whitespaces)
            if p == "no-resolve" || p == "src" { i -= 1; continue }
            break
        }
        return i
    }

    /// The renamed rule line, nil when its policy is not `old`.
    static func renameRule(_ r: String, old: String, new: String) -> String? {
        var parts = splitRule(r)
        guard parts.count >= 2 else { return nil }
        let ti = ruleTarget(parts)
        guard parts[ti].trimmingCharacters(in: .whitespaces) == old else { return nil }
        parts[ti] = new
        return parts.joined(separator: ",")
    }

    // MARK: - Text rename (format-keeping)

    private enum Section { case other, proxies, groups, rules }

    /// Rewrites the referencing scalars in the text. Best effort: whatever it cannot handle stays unchanged and
    /// the caller's tree comparison catches it.
    static func renameText(_ text: String, old: String, new: String) -> String {
        var lines = text.components(separatedBy: "\n")
        var section = Section.other
        var itemDash = -1          // column of the "- " of the current section's items
        var keyCol = -1            // column of the current item's keys
        var listUnderKey = false   // inside a block `proxies:` list of a group
        for li in lines.indices {
            var chars = Array(lines[li])
            let hadCR = chars.last == "\r"
            if hadCR { chars.removeLast() }
            let indent = chars.prefix(while: { $0 == " " }).count
            if indent >= chars.count { continue } // blank
            if chars[indent] == "#" { continue }
            let isDash = chars[indent] == "-" && (indent + 1 == chars.count || chars[indent + 1] == " ")
            var edits: [(Range<Int>, String)] = []

            if indent == 0 && !isDash {
                // top-level key
                guard let (key, valStart) = parseKey(chars, at: 0) else { section = .other; continue }
                switch key {
                case "proxies": section = .proxies
                case "proxy-groups": section = .groups
                case "rules", "sub-rules": section = .rules
                default: section = .other
                }
                itemDash = -1; keyCol = -1; listUnderKey = false
                _ = valStart
                continue
            }

            switch section {
            case .other:
                continue
            case .rules:
                guard isDash else { continue }
                let start = indent + 2
                if let sc = blockScalar(chars, from: start), let n = renameRule(sc.value, old: old, new: new) {
                    edits.append((sc.range, encode(n, like: sc.quote, inFlow: false)))
                }
            case .proxies, .groups:
                let isGroups = section == .groups
                if isDash && (itemDash < 0 || indent <= itemDash) && !(listUnderKey && indent > itemDash) {
                    // a new item
                    itemDash = indent
                    listUnderKey = false
                    var c = indent + 1
                    while c < chars.count && chars[c] == " " { c += 1 }
                    keyCol = c
                    if c < chars.count && chars[c] == "{" {
                        if let (node, _) = FlowParser(chars).parse(at: c) {
                            edits += flowItemEdits(node, isGroup: isGroups, old: old, new: new)
                        }
                    } else if let (key, vs) = parseKey(chars, at: c) {
                        handleKey(key, chars, vs, isGroup: isGroups, old: old, new: new, edits: &edits, listUnderKey: &listUnderKey)
                    }
                } else if isGroups && listUnderKey && isDash && indent > itemDash && indent >= keyCol {
                    // member line of a block `proxies:` list
                    if let sc = blockScalar(chars, from: indent + 2), sc.value == old {
                        edits.append((sc.range, encode(new, like: sc.quote, inFlow: false)))
                    }
                } else if !isDash && indent == keyCol {
                    listUnderKey = false
                    if let (key, vs) = parseKey(chars, at: indent) {
                        handleKey(key, chars, vs, isGroup: isGroups, old: old, new: new, edits: &edits, listUnderKey: &listUnderKey)
                    }
                }
            }
            if edits.isEmpty { continue }
            for (r, s) in edits.sorted(by: { $0.0.lowerBound > $1.0.lowerBound }) {
                chars.replaceSubrange(r, with: Array(s))
            }
            lines[li] = String(chars) + (hadCR ? "\r" : "")
        }
        return lines.joined(separator: "\n")
    }

    /// A group / proxy key line: `proxies:` (block list follows), `proxies: [..]`, `dialer-proxy: X`.
    private static func handleKey(_ key: String, _ chars: [Character], _ vs: Int, isGroup: Bool, old: String, new: String,
                                  edits: inout [(Range<Int>, String)], listUnderKey: inout Bool) {
        var v = vs
        while v < chars.count && chars[v] == " " { v += 1 }
        let empty = v >= chars.count || chars[v] == "#"
        switch key {
        case "proxies" where isGroup:
            if empty {
                listUnderKey = true
            } else if chars[v] == "[", let (node, _) = FlowParser(chars).parse(at: v), case .seq(let items) = node {
                for it in items {
                    if case .scalar(let r, let val, let q) = it, val == old {
                        edits.append((r, encode(new, like: q, inFlow: true)))
                    }
                }
            }
        case "dialer-proxy":
            if !empty, let sc = blockScalar(chars, from: v), sc.value == old {
                edits.append((sc.range, encode(new, like: sc.quote, inFlow: false)))
            }
        default:
            break
        }
    }

    private static func flowItemEdits(_ node: FlowNode, isGroup: Bool, old: String, new: String) -> [(Range<Int>, String)] {
        guard case .map(let entries) = node else { return [] }
        var out: [(Range<Int>, String)] = []
        for (k, v) in entries {
            guard let v else { continue }
            if k == "dialer-proxy", case .scalar(let r, let val, let q) = v, val == old {
                out.append((r, encode(new, like: q, inFlow: true)))
            }
            if isGroup, k == "proxies", case .seq(let items) = v {
                for it in items {
                    if case .scalar(let r, let val, let q) = it, val == old {
                        out.append((r, encode(new, like: q, inFlow: true)))
                    }
                }
            }
        }
        return out
    }

    // MARK: scalars

    /// A block-context scalar starting at `from` (after "- " or "key: "): its range (comment and trailing blanks
    /// excluded), decoded value and quote style. nil for collections, block scalars, anchors / aliases / tags.
    static func blockScalar(_ c: [Character], from: Int) -> (range: Range<Int>, value: String, quote: Character?)? {
        var i = from
        while i < c.count && c[i] == " " { i += 1 }
        guard i < c.count else { return nil }
        let first = c[i]
        if first == "\"" || first == "'" {
            guard let (val, end) = quoted(c, at: i) else { return nil }
            // only blanks or a comment may follow
            var j = end
            while j < c.count && (c[j] == " " || c[j] == "\t") { j += 1 }
            if j < c.count && c[j] != "#" { return nil }
            return (i..<end, val, first)
        }
        if "[{|>&*!".contains(first) || first == "#" { return nil }
        var end = i
        var j = i
        while j < c.count {
            if c[j] == "#" && j > i && (c[j - 1] == " " || c[j - 1] == "\t") { break }
            j += 1
            if c[j - 1] != " " && c[j - 1] != "\t" { end = j }
        }
        let val = String(c[i..<end])
        if val.isEmpty { return nil }
        return (i..<end, val, nil)
    }

    /// A quoted scalar at `at` ('…' or "…"): decoded value and the index after the closing quote.
    static func quoted(_ c: [Character], at: Int) -> (String, Int)? {
        let q = c[at]
        var i = at + 1
        var out = ""
        while i < c.count {
            let ch = c[i]
            if q == "'" {
                if ch == "'" {
                    if i + 1 < c.count && c[i + 1] == "'" { out.append("'"); i += 2; continue }
                    return (out, i + 1)
                }
                out.append(ch); i += 1
            } else {
                if ch == "\"" { return (out, i + 1) }
                if ch == "\\" {
                    guard i + 1 < c.count else { return nil }
                    let e = c[i + 1]
                    i += 2
                    switch e {
                    case "n": out.append("\n")
                    case "t": out.append("\t")
                    case "r": out.append("\r")
                    case "0": out.append("\0")
                    case "\\": out.append("\\")
                    case "\"": out.append("\"")
                    case "/": out.append("/")
                    case " ": out.append(" ")
                    case "u", "x", "U":
                        let n = e == "x" ? 2 : (e == "u" ? 4 : 8)
                        guard i + n <= c.count, let v = UInt32(String(c[i..<(i + n)]), radix: 16),
                              let s = Unicode.Scalar(v) else { return nil }
                        out.unicodeScalars.append(s)
                        i += n
                    default: return nil
                    }
                    continue
                }
                out.append(ch); i += 1
            }
        }
        return nil
    }

    /// Encodes value in the original token's style; a plain token becomes double-quoted when the value would not
    /// read back as the same string.
    static func encode(_ value: String, like quote: Character?, inFlow: Bool) -> String {
        switch quote {
        case "'"?:
            if value.contains("\n") { return doubleQuoted(value) }
            return "'" + value.replacingOccurrences(of: "'", with: "''") + "'"
        case "\""?:
            return doubleQuoted(value)
        default:
            return needsQuote(value, inFlow: inFlow) ? doubleQuoted(value) : value
        }
    }

    static func doubleQuoted(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\t": out += "\\t"
            case "\r": out += "\\r"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04X", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    static func needsQuote(_ s: String, inFlow: Bool) -> Bool {
        guard let f = s.first, let l = s.last else { return true }
        if f == " " || l == " " || l == ":" { return true }
        if "-?:,[]{}#&*!|>'\"%@`".contains(f) { return true }
        if s.contains(": ") || s.contains(" #") || s.contains("\t") || s.contains("\n") { return true }
        if inFlow && s.contains(where: { ",[]{}".contains($0) }) { return true }
        let low = s.lowercased()
        if ["true", "false", "yes", "no", "on", "off", "null", "~", "y", "n"].contains(low) { return true }
        if Double(s) != nil || s.hasPrefix("0x") || s.hasPrefix("0o") { return true }
        return false
    }

    /// `key:` at column `at` (plain or quoted key): the key and the index after the colon.
    static func parseKey(_ c: [Character], at: Int) -> (String, Int)? {
        guard at < c.count else { return nil }
        if c[at] == "\"" || c[at] == "'" {
            guard let (k, end) = quoted(c, at: at) else { return nil }
            var j = end
            while j < c.count && c[j] == " " { j += 1 }
            guard j < c.count, c[j] == ":" else { return nil }
            return (k, j + 1)
        }
        var j = at
        while j < c.count {
            if c[j] == ":" && (j + 1 == c.count || c[j + 1] == " " || c[j + 1] == "\t") {
                let k = String(c[at..<j]).trimmingCharacters(in: .whitespaces)
                return k.isEmpty ? nil : (k, j + 1)
            }
            if c[j] == "#" && j > at && c[j - 1] == " " { return nil }
            j += 1
        }
        return nil
    }

    // MARK: flow collections (single line)

    indirect enum FlowNode {
        case scalar(Range<Int>, String, Character?)
        case seq([FlowNode])
        case map([(String, FlowNode?)])
    }

    struct FlowParser {
        let c: [Character]
        init(_ c: [Character]) { self.c = c }

        func ws(_ i: inout Int) { while i < c.count && (c[i] == " " || c[i] == "\t") { i += 1 } }

        /// Parses the collection or scalar at i; nil when it does not close on this line.
        func parse(at start: Int) -> (FlowNode, Int)? {
            var i = start
            ws(&i)
            guard i < c.count else { return nil }
            if c[i] == "[" {
                i += 1
                var items: [FlowNode] = []
                while true {
                    ws(&i)
                    guard i < c.count else { return nil }
                    if c[i] == "]" { return (.seq(items), i + 1) }
                    guard let (n, e) = parse(at: i) else { return nil }
                    items.append(n)
                    i = e
                    ws(&i)
                    guard i < c.count else { return nil }
                    if c[i] == "," { i += 1; continue }
                    if c[i] == "]" { return (.seq(items), i + 1) }
                    return nil
                }
            }
            if c[i] == "{" {
                i += 1
                var entries: [(String, FlowNode?)] = []
                while true {
                    ws(&i)
                    guard i < c.count else { return nil }
                    if c[i] == "}" { return (.map(entries), i + 1) }
                    guard let (kn, ke) = scalar(at: i, key: true), case .scalar(_, let k, _) = kn else { return nil }
                    i = ke
                    ws(&i)
                    var val: FlowNode? = nil
                    if i < c.count && c[i] == ":" {
                        i += 1
                        ws(&i)
                        if i < c.count && c[i] != "," && c[i] != "}" {
                            guard let (v, ve) = parse(at: i) else { return nil }
                            val = v
                            i = ve
                        }
                    }
                    entries.append((k, val))
                    ws(&i)
                    guard i < c.count else { return nil }
                    if c[i] == "," { i += 1; continue }
                    if c[i] == "}" { return (.map(entries), i + 1) }
                    return nil
                }
            }
            return scalar(at: i, key: false)
        }

        func scalar(at start: Int, key: Bool) -> (FlowNode, Int)? {
            guard start < c.count else { return nil }
            if c[start] == "\"" || c[start] == "'" {
                guard let (v, e) = NCProfileRefRename.quoted(c, at: start) else { return nil }
                return (.scalar(start..<e, v, c[start]), e)
            }
            if "&*!|>".contains(c[start]) { return nil }
            var i = start
            var end = start
            while i < c.count {
                let ch = c[i]
                if ch == "," || ch == "]" || ch == "}" { break }
                if ch == ":" && (i + 1 == c.count || " ,]}".contains(c[i + 1]) || key) { break }
                if ch == "#" && i > start && c[i - 1] == " " { return nil }
                i += 1
                if ch != " " && ch != "\t" { end = i }
            }
            return (.scalar(start..<end, String(c[start..<end]), nil), end)
        }
    }
}
