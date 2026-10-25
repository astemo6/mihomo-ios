import Foundation

/// A YAML subset parser producing NCJSONValue, sufficient for mihomo configs
/// (the generated runtime.yaml and typical hand-written ones): block maps and
/// sequences, flow collections, single/double-quoted and plain scalars,
/// comments, literal/folded block scalars, anchors and aliases. It is NOT a
/// general YAML 1.2 implementation (no tags, no multi-document streams beyond
/// the first document, no complex keys).
///
/// Purpose: let the native core load runtime.yaml directly, retiring the Go
/// NativeConfigJSON export (integration happens once the core is verified).
enum NCYAML {
    static func parse(_ text: String) -> NCJSONValue? {
        var parser = Parser(text: text)
        return parser.parseDocument()
    }

    /// Emit an arbitrary object (dictionary, array, primitive, or NCJSONValue) as a YAML string.
    static func emit(_ value: Any) -> String {
        NCYAMLEmitter.emit(value)
    }

    private struct Line {
        var indent: Int
        var content: String // trailing spaces trimmed, comment-stripped
        var raw: String // for block scalars (comments NOT stripped inside them)
    }

    private struct Parser {
        private var lines: [Line] = []
        private var anchors: [String: NCJSONValue] = [:]

        init(text: String) {
            for rawLine in text.components(separatedBy: "\n") {
                let raw = rawLine.hasSuffix("\r") ? String(rawLine.dropLast()) : rawLine
                let indent = raw.prefix(while: { $0 == " " }).count
                let content = String(raw.dropFirst(indent))
                lines.append(Line(indent: indent, content: Self.stripComment(content), raw: raw))
            }
        }

        /// Cut " #..." comments when not inside quotes.
        private static func stripComment(_ s: String) -> String {
            var inSingle = false
            var inDouble = false
            var prev: Character = " "
            var out = ""
            for ch in s {
                if ch == "'" && prev != "\\" { inSingle.toggle() }
                if ch == "\"" && prev != "\\" && !inSingle { inDouble.toggle() }
                if ch == "#", !inSingle, !inDouble, prev == " " || prev == "\t" {
                    return out.trimmingCharacters(in: .whitespaces)
                }
                out.append(ch)
                prev = ch
            }
            return out.trimmingCharacters(in: .whitespaces)
        }

        mutating func parseDocument() -> NCJSONValue? {
            var i = 0
            // Skip blanks and document markers.
            while i < lines.count, lines[i].content.isEmpty || lines[i].content == "---" || lines[i].content.hasPrefix("%") {
                i += 1
            }
            guard i < lines.count else { return nil }
            let value = parseBlock(&i, indent: lines[i].indent)
            return value
        }

        /// Parse a block node starting at lines[i] with the given indent.
        private mutating func parseBlock(_ i: inout Int, indent: Int) -> NCJSONValue? {
            guard i < lines.count else { return nil }
            let line = lines[i]
            if line.content.hasPrefix("- ") || line.content == "-" {
                return parseSequence(&i, indent: indent)
            }
            if Self.splitKeyValue(line.content) != nil {
                return parseMapping(&i, indent: indent)
            }
            // Lone scalar (possibly flow).
            i += 1
            return parseInline(line.content, blockIndent: indent, i: &i)
        }

        private mutating func parseSequence(_ i: inout Int, indent: Int) -> NCJSONValue {
            var items: [NCJSONValue] = []
            while i < lines.count {
                let line = lines[i]
                if line.content.isEmpty { i += 1; continue }
                guard line.indent == indent, line.content.hasPrefix("-") else { break }
                let rest: String
                if line.content == "-" {
                    rest = ""
                } else if line.content.hasPrefix("- ") {
                    rest = String(line.content.dropFirst(2))
                } else {
                    break
                }
                let itemIndent = indent + 2
                if rest.isEmpty {
                    i += 1
                    if i < lines.count, lines[i].indent >= itemIndent || (lines[i].indent > indent && !lines[i].content.isEmpty) {
                        if let v = parseBlock(&i, indent: lines[i].indent) { items.append(v) }
                    } else {
                        items.append(.null)
                    }
                } else if Self.splitKeyValue(rest) != nil || rest.hasPrefix("- ") {
                    // Inline start of a nested block (usually a map): rewrite the
                    // current line as if the content began at itemIndent.
                    lines[i] = Line(indent: itemIndent, content: rest, raw: rest)
                    if let v = parseBlock(&i, indent: itemIndent) { items.append(v) }
                } else {
                    i += 1
                    items.append(parseInline(rest, blockIndent: itemIndent, i: &i) ?? .null)
                }
            }
            return .array(items)
        }

        private mutating func parseMapping(_ i: inout Int, indent: Int) -> NCJSONValue {
            var obj: [String: NCJSONValue] = [:]
            while i < lines.count {
                let line = lines[i]
                if line.content.isEmpty { i += 1; continue }
                guard line.indent == indent, let (key, valueText) = Self.splitKeyValue(line.content) else { break }
                i += 1
                if valueText.isEmpty {
                    // Value is a nested block (or null).
                    var j = i
                    while j < lines.count, lines[j].content.isEmpty { j += 1 }
                    if j < lines.count, lines[j].indent > indent {
                        i = j
                        obj[key] = parseBlock(&i, indent: lines[j].indent) ?? .null
                    } else if j < lines.count, lines[j].indent == indent, lines[j].content.hasPrefix("-") {
                        // Block sequences may sit at the same indent as the key.
                        i = j
                        obj[key] = parseSequence(&i, indent: indent)
                    } else {
                        obj[key] = .null
                    }
                } else {
                    obj[key] = parseInline(valueText, blockIndent: indent, i: &i) ?? .null
                }
            }
            return .object(obj)
        }

        /// Split "key: value" / "key:" honoring quoted keys. Returns nil for scalars.
        private static func splitKeyValue(_ s: String) -> (key: String, value: String)? {
            if s.hasPrefix("\"") || s.hasPrefix("'") {
                let quote: Character = s.first!
                var idx = s.index(after: s.startIndex)
                var key = ""
                while idx < s.endIndex {
                    let ch = s[idx]
                    if ch == quote {
                        let after = s.index(after: idx)
                        if after < s.endIndex, s[after] == ":" {
                            let rest = s[s.index(after: after)...].trimmingCharacters(in: .whitespaces)
                            return (key, rest)
                        }
                        if quote == "'" { key.append(ch); idx = after; continue }
                        return nil
                    }
                    if quote == "\"", ch == "\\", s.index(after: idx) < s.endIndex {
                        idx = s.index(after: idx)
                        key.append(s[idx])
                        idx = s.index(after: idx)
                        continue
                    }
                    key.append(ch)
                    idx = s.index(after: idx)
                }
                return nil
            }
            var depth = 0
            var idx = s.startIndex
            while idx < s.endIndex {
                let ch = s[idx]
                if ch == "[" || ch == "{" { depth += 1 }
                if ch == "]" || ch == "}" { depth -= 1 }
                if ch == ":", depth == 0 {
                    let after = s.index(after: idx)
                    if after == s.endIndex || s[after] == " " {
                        let key = String(s[s.startIndex..<idx]).trimmingCharacters(in: .whitespaces)
                        let value = after == s.endIndex ? "" : String(s[after...]).trimmingCharacters(in: .whitespaces)
                        if !key.isEmpty { return (key, value) }
                        return nil
                    }
                }
                idx = s.index(after: idx)
            }
            return nil
        }

        /// Parse an inline value: anchors, block scalars, flow, or scalar.
        private mutating func parseInline(_ text: String, blockIndent: Int, i: inout Int) -> NCJSONValue? {
            var t = text
            // Anchor: &name <value>
            if t.hasPrefix("&") {
                let parts = t.split(separator: " ", maxSplits: 1)
                let name = String(parts[0].dropFirst())
                t = parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : ""
                let value = t.isEmpty ? NCJSONValue.null : (parseInline(t, blockIndent: blockIndent, i: &i) ?? .null)
                anchors[name] = value
                return value
            }
            // Alias: *name
            if t.hasPrefix("*") {
                return anchors[String(t.dropFirst())] ?? .null
            }
            // Block scalars: |, >, with chomping indicators.
            if t == "|" || t == ">" || t.hasPrefix("|-") || t.hasPrefix(">-") || t.hasPrefix("|+") || t.hasPrefix(">+") {
                return .string(parseBlockScalar(folded: t.hasPrefix(">"), parentIndent: blockIndent, i: &i))
            }
            // Flow collections only: a block-context plain scalar may contain ',' / ']' / '}' (rules such as
            // "DOMAIN-SUFFIX,google.com,Proxy"), which the flow scalar reader would cut at the first comma.
            // Quoted scalars go through scalar(), which reuses the flow string reader.
            if t.hasPrefix("[") || t.hasPrefix("{") {
                var rest = Substring(t)
                if let value = parseFlow(&rest) {
                    return value
                }
            }
            return Self.scalar(t)
        }

        private mutating func parseBlockScalar(folded: Bool, parentIndent: Int, i: inout Int) -> String {
            var collected: [String] = []
            var blockIndent: Int? = nil
            while i < lines.count {
                let line = lines[i]
                if line.raw.trimmingCharacters(in: .whitespaces).isEmpty {
                    // Blank lines belong to the block if more block lines follow;
                    // keep tentatively.
                    collected.append("")
                    i += 1
                    continue
                }
                if blockIndent == nil {
                    guard line.indent > parentIndent else { break }
                    blockIndent = line.indent
                }
                guard let bi = blockIndent, line.indent >= bi else { break }
                collected.append(String(line.raw.dropFirst(min(bi, line.raw.count))))
                i += 1
            }
            // Trailing tentative blanks are clip-chomped to a single newline.
            while collected.last == "" { collected.removeLast() }
            let body = folded ? collected.joined(separator: " ") : collected.joined(separator: "\n")
            return collected.isEmpty ? "" : body + "\n"
        }

        /// Flow value parser over a substring cursor.
        private mutating func parseFlow(_ s: inout Substring) -> NCJSONValue? {
            skipSpaces(&s)
            guard let ch = s.first else { return nil }
            switch ch {
            case "[":
                s = s.dropFirst()
                var arr: [NCJSONValue] = []
                skipSpaces(&s)
                if s.first == "]" { s = s.dropFirst(); return .array(arr) }
                while true {
                    if let v = parseFlow(&s) { arr.append(v) }
                    skipSpaces(&s)
                    if s.first == "," { s = s.dropFirst(); continue }
                    if s.first == "]" { s = s.dropFirst() }
                    break
                }
                return .array(arr)
            case "{":
                s = s.dropFirst()
                var obj: [String: NCJSONValue] = [:]
                skipSpaces(&s)
                if s.first == "}" { s = s.dropFirst(); return .object(obj) }
                while true {
                    skipSpaces(&s)
                    // key up to ':' outside quotes/flow
                    var keyText = ""
                    while let c = s.first, c != ":" {
                        keyText.append(c)
                        s = s.dropFirst()
                    }
                    guard s.first == ":" else { break }
                    s = s.dropFirst()
                    let key = Self.scalar(keyText.trimmingCharacters(in: .whitespaces)).string ?? keyText.trimmingCharacters(in: .whitespaces)
                    if let v = parseFlow(&s) { obj[key] = v }
                    skipSpaces(&s)
                    if s.first == "," { s = s.dropFirst(); continue }
                    if s.first == "}" { s = s.dropFirst() }
                    break
                }
                return .object(obj)
            case "\"", "'":
                let quote = ch
                s = s.dropFirst()
                var out = ""
                while let c = s.first {
                    s = s.dropFirst()
                    if c == quote {
                        if quote == "'", s.first == "'" { out.append("'"); s = s.dropFirst(); continue }
                        break
                    }
                    if quote == "\"", c == "\\", let esc = s.first {
                        s = s.dropFirst()
                        switch esc {
                        case "n": out.append("\n")
                        case "t": out.append("\t")
                        case "r": out.append("\r")
                        case "\"": out.append("\"")
                        case "\\": out.append("\\")
                        case "0": out.append("\0")
                        default: out.append(esc)
                        }
                        continue
                    }
                    out.append(c)
                }
                return .string(out)
            default:
                // Plain flow scalar: up to , ] } at this level.
                var text = ""
                var depth = 0
                while let c = s.first {
                    if depth == 0, c == "," || c == "]" || c == "}" { break }
                    if c == "[" || c == "{" { depth += 1 }
                    if c == "]" || c == "}" { depth -= 1 }
                    text.append(c)
                    s = s.dropFirst()
                }
                return Self.scalar(text.trimmingCharacters(in: .whitespaces))
            }
        }

        private func skipSpaces(_ s: inout Substring) {
            while let c = s.first, c == " " || c == "\t" || c == "\n" { s = s.dropFirst() }
        }

        /// YAML plain-scalar typing.
        private static func scalar(_ t: String) -> NCJSONValue {
            switch t {
            case "", "~", "null", "Null", "NULL": return .null
            case "true", "True", "TRUE": return .bool(true)
            case "false", "False", "FALSE": return .bool(false)
            default: break
            }
            if (t.hasPrefix("\"") && t.hasSuffix("\"") && t.count >= 2) || (t.hasPrefix("'") && t.hasSuffix("'") && t.count >= 2) {
                var sub = Substring(t)
                var parser = Parser(text: "")
                // Reuse the flow string parser for quoted top-level scalars.
                if let v = parser.parseFlow(&sub) { return v }
            }
            if let n = numberValue(t) { return .number(n) }
            return .string(t)
        }

        private static func numberValue(_ t: String) -> Double? {
            if let v = Int64(t) { return Double(v) }
            if t.hasPrefix("0x"), let v = Int64(t.dropFirst(2), radix: 16) { return Double(v) }
            if t.hasPrefix("0o"), let v = Int64(t.dropFirst(2), radix: 8) { return Double(v) }
            // Only treat as Double if it looks numeric (avoid "1.2.3" hosts etc).
            let numeric = CharacterSet(charactersIn: "0123456789+-.eE")
            guard !t.isEmpty, t.unicodeScalars.allSatisfy({ numeric.contains($0) }), t.contains(".") || t.contains("e") || t.contains("E") else { return nil }
            return Double(t)
        }
    }
}
