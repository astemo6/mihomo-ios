import Foundation

// DIVERGENCES:
// 1. YAML Node Engine:
//    - the old core: Uses go.yaml.in/yaml/v3 AST (yaml.Node tree) where all comments and
//      formatting styles (flow vs block) are parsed into AST nodes, and serialized back out with yaml.Encoder.
//    - Swift (NCProfileYAML): Uses a line/block-based document editor that locates sections (`proxies:`,
//      `proxy-groups:`, `rules:`, `sub-rules:`) and entries by line structure. For modified/inserted proxy entries,
//      it updates mapping fields in place, preserving original key order, untouched keys, and comments.
//      Flow-style entries are detected and preserved.
//    - Impact: Comments, custom spacing, and formatting outside touched entries are 100% preserved bit-for-bit
//      without any AST re-serialization reformatting side-effects.
// 2. Flow Style Proxy Handling:
//    - the old core: Uses yaml.FlowStyle bitmask on yaml.Node.
//    - Swift: Detects flow-style proxy entries (`- { ... }`) and preserves flow-style mapping formatting on updates.
//    - Impact: Flow-style entries remain flow-style; block-style entries remain block-style.
// 3. Line endings / BOM (rv2):
//    - the old core: yaml.v3 re-encodes the whole document with LF endings.
//    - Swift: the dominant line ending of the input (CRLF or LF) and a leading UTF-8 BOM are kept on output, so an
//      edit to a uniformly-CRLF file changes only the touched lines. Mixed-ending files are written with the
//      dominant ending.
// 4. Scalar quoting (rv2): formatYAMLString follows yaml.v3's encoder choice — plain when the string re-reads as
//    the same !!str, double-quoted when it would resolve to another type (bool / null / int / float / timestamp /
//    YAML 1.1 bool / base-60) or contains control or line-break characters, single-quoted otherwise. Divergence: a
//    multi-line string is double-quoted with `\n` escapes instead of yaml.v3's block literal (`|-`), since the
//    line editor emits single-line values; it reads back as the identical string.

/// A comment- and order-preserving YAML document editor for profile node operations.
/// Operates at the line/block structure level to inspect, insert, update, and delete proxy entries
/// and update group / rule references without destroying comments or key order in untouched sections.
final class NCProfileYAML {

    private(set) var lines: [String]
    /// Line terminator written by `text()`: the dominant one in the input ("\r\n" or "\n").
    private let newline: String
    /// Leading UTF-8 BOM of the input, re-emitted by `text()`.
    private let bom: String

    init(text: String) {
        var body = text
        if body.unicodeScalars.first == "\u{FEFF}" {
            bom = "\u{FEFF}"
            body = String(body.unicodeScalars.dropFirst())
        } else {
            bom = ""
        }
        // Split by "\n", remembering whether each break was CRLF so `text()` writes the same ending back
        // (review rv2: edits used to turn every CRLF into LF despite the "untouched bytes preserved" contract).
        // Note: Swift treats "\r\n" as ONE Character, so split on unicode scalars, not Characters.
        var out: [String] = []
        var crlf = 0, lf = 0
        var cur = String.UnicodeScalarView()
        let scalars = Array(body.unicodeScalars)
        var i = 0
        while i < scalars.count {
            let c = scalars[i]
            if c == "\r" && i + 1 < scalars.count && scalars[i + 1] == "\n" {
                out.append(String(cur)); cur = String.UnicodeScalarView(); crlf += 1; i += 2; continue
            }
            if c == "\n" {
                out.append(String(cur)); cur = String.UnicodeScalarView(); lf += 1; i += 1; continue
            }
            cur.append(c)
            i += 1
        }
        out.append(String(cur))
        self.lines = out
        self.newline = crlf > lf ? "\r\n" : "\n"
    }

    convenience init?(contentsOf fileURL: URL) {
        guard let data = try? Data(contentsOf: fileURL),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        self.init(text: text)
    }

    func text() -> String {
        bom + lines.joined(separator: newline)
    }

    func data() -> Data? {
        text().data(using: .utf8)
    }

    // MARK: - Section & Block Boundaries

    /// Finds a top-level YAML key (indent 0) such as "proxies:", "proxy-groups:", "rules:".
    /// Returns headerLine index and the line range of section content.
    func findTopLevelSection(_ name: String) -> (headerLine: Int, contentRange: Range<Int>)? {
        let prefix = "\(name):"
        for i in 0..<lines.count {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") || trimmed.isEmpty { continue }

            // Check if top-level (0 leading spaces)
            let indent = line.prefix(while: { $0 == " " }).count
            if indent == 0 && (trimmed == prefix || trimmed.hasPrefix(prefix + " ") || trimmed.hasPrefix(prefix + "#") || trimmed.hasPrefix(prefix + "\t")) {
                let headerLine = i
                // Content extends until next top-level non-comment, non-empty key (indent 0 with ':') or EOF
                var end = lines.count
                for j in (headerLine + 1)..<lines.count {
                    let nextLine = lines[j]
                    let nextTrimmed = nextLine.trimmingCharacters(in: .whitespaces)
                    if nextTrimmed.isEmpty || nextTrimmed.hasPrefix("#") { continue }
                    let nextIndent = nextLine.prefix(while: { $0 == " " }).count
                    if nextIndent == 0 && nextTrimmed.contains(":") {
                        end = j
                        break
                    }
                }
                return (headerLine, (headerLine + 1)..<end)
            }
        }
        return nil
    }

    // MARK: - Proxy Entry Representation

    struct ProxyEntry {
        var index: Int
        var name: String
        var lineRange: Range<Int>
        var dict: [String: Any]
        var isFlowStyle: Bool
        var baseIndent: Int
    }

    /// Lists all proxy entries under `proxies:`.
    func listProxies() -> [ProxyEntry] {
        guard let section = findTopLevelSection("proxies") else { return [] }

        // If the header itself is flow-empty: proxies: []
        let headerTrimmed = lines[section.headerLine].trimmingCharacters(in: .whitespaces)
        if headerTrimmed.replacingOccurrences(of: " ", with: "") == "proxies:[]" {
            return []
        }

        var entries: [ProxyEntry] = []
        var itemStarts: [Int] = []
        var listIndent = 2

        for i in section.contentRange {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            let indent = line.prefix(while: { $0 == " " }).count
            if trimmed.hasPrefix("- ") || trimmed == "-" {
                if itemStarts.isEmpty {
                    listIndent = indent
                }
                if indent == listIndent {
                    itemStarts.append(i)
                }
            }
        }

        let bounds = entryBounds(itemStarts: itemStarts, section: section, listIndent: listIndent)
        for (idx, startLine) in itemStarts.enumerated() {
            let actualStart = bounds[idx].lowerBound
            let nextStart = bounds[idx].upperBound

            let entryLines = Array(lines[startLine..<nextStart])
            let entryText = entryLines.joined(separator: "\n")
            var dict: [String: Any] = [:]
            if let parsed = NCYAML.parse(entryText) {
                if let array = parsed.array, let first = array.first?.object {
                    dict = first.mapValues { $0.rawAny }
                } else if let obj = parsed.object {
                    dict = obj.mapValues { $0.rawAny }
                }
            }

            let name = (dict["name"] as? String) ?? (dict["name"] as? NSNumber)?.stringValue ?? ""
            let firstTrimmed = lines[startLine].trimmingCharacters(in: .whitespaces)
            let isFlow = firstTrimmed.hasPrefix("- {") && firstTrimmed.contains("}")

            entries.append(ProxyEntry(
                index: idx,
                name: name,
                lineRange: actualStart..<nextStart,
                dict: dict,
                isFlowStyle: isFlow,
                baseIndent: listIndent
            ))
        }

        return entries
    }

    /// Line ranges of list entries, comment-aware (review rv2 #11).
    ///
    /// Each entry starts at its first leading comment line (comments directly above the dash line at an indent
    /// <= the list indent, with no blank line in between) and ends right before the NEXT entry's leading
    /// comments — previously it ended at the next dash line, so deleting / replacing entry A also deleted or
    /// moved entry B's leading comment. The last entry ends after its last content line (or a comment indented
    /// deeper than the list), so trailing blank lines / column-0 comments that introduce the next top-level key
    /// stay outside every entry.
    private func entryBounds(itemStarts: [Int], section: (headerLine: Int, contentRange: Range<Int>), listIndent: Int) -> [Range<Int>] {
        var starts: [Int] = []
        for (idx, startLine) in itemStarts.enumerated() {
            let floor = idx == 0 ? section.headerLine + 1 : itemStarts[idx - 1] + 1
            var actualStart = startLine
            while actualStart > floor {
                let prev = lines[actualStart - 1]
                let prevTrimmed = prev.trimmingCharacters(in: .whitespaces)
                let prevIndent = prev.prefix(while: { $0 == " " }).count
                if prevTrimmed.hasPrefix("#") && prevIndent <= listIndent {
                    actualStart -= 1
                } else {
                    break
                }
            }
            starts.append(actualStart)
        }
        var out: [Range<Int>] = []
        for idx in 0..<starts.count {
            var end: Int
            if idx + 1 < starts.count {
                end = starts[idx + 1]
            } else {
                end = section.contentRange.upperBound
                while end > itemStarts[idx] + 1 {
                    let l = lines[end - 1]
                    let t = l.trimmingCharacters(in: .whitespaces)
                    let ind = l.prefix(while: { $0 == " " }).count
                    if t.isEmpty || (t.hasPrefix("#") && ind <= listIndent) {
                        end -= 1
                    } else {
                        break
                    }
                }
            }
            out.append(starts[idx]..<max(end, itemStarts[idx] + 1))
        }
        return out
    }

    /// Finds a proxy entry by name.
    func findProxy(name: String) -> ProxyEntry? {
        listProxies().first { $0.name == name }
    }

    /// Checks if a proxy entry exists.
    func hasProxy(name: String) -> Bool {
        findProxy(name: name) != nil
    }

    /// Returns JSON string of a proxy entry, or nil if not found.
    func getProxyJSON(name: String) -> String? {
        guard let entry = findProxy(name: name),
              let data = try? JSONSerialization.data(withJSONObject: entry.dict),
              let json = String(data: data, encoding: .utf8) else {
            return nil
        }
        return json
    }

    /// Collects all proxy and proxy-group names defined in this file.
    func allNames() -> Set<String> {
        var names = Set<String>()
        for p in listProxies() {
            if !p.name.isEmpty { names.insert(p.name) }
        }
        for g in listGroups() {
            if !g.name.isEmpty { names.insert(g.name) }
        }
        return names
    }

    // MARK: - Proxy Manipulation

    static let leadKeys = ["name", "type", "server", "port"]

    private static func leadRank(_ k: String) -> (Int, String) {
        if let idx = leadKeys.firstIndex(of: k) {
            return (idx, k)
        }
        return (leadKeys.count, k)
    }

    /// Upserts a proxy entry. If oldName is nil or empty, appends a new proxy.
    /// If oldName is provided, replaces the existing proxy in place.
    func upsertProxy(node: [String: Any], oldName: String?) -> Bool {
        if let oldName = oldName, !oldName.isEmpty {
            guard let entry = findProxy(name: oldName) else {
                return false
            }
            let updatedLines = formatUpdatedEntry(
                originalLines: Array(lines[entry.lineRange]),
                want: node,
                isFlow: entry.isFlowStyle,
                baseIndent: entry.baseIndent
            )
            lines.replaceSubrange(entry.lineRange, with: updatedLines)
            return true
        } else {
            // Append new proxy to `proxies:`
            if let section = findTopLevelSection("proxies") {
                let formatted = formatNewEntry(node: node, baseIndent: 2)
                let headerTrimmed = lines[section.headerLine].trimmingCharacters(in: .whitespaces)
                if headerTrimmed.replacingOccurrences(of: " ", with: "") == "proxies:[]" {
                    // Replace "proxies: []" with "proxies:" and item
                    lines[section.headerLine] = "proxies:"
                    lines.insert(contentsOf: formatted, at: section.headerLine + 1)
                } else if let last = listProxies().last {
                    // Insert right after the last entry (before trailing blank lines / comments that belong to
                    // the next top-level key).
                    lines.insert(contentsOf: formatted, at: last.lineRange.upperBound)
                } else {
                    // Insert at end of proxies content range
                    var insertPos = section.contentRange.upperBound
                    // Back up past empty lines
                    while insertPos > section.headerLine + 1 && lines[insertPos - 1].trimmingCharacters(in: .whitespaces).isEmpty {
                        insertPos -= 1
                    }
                    lines.insert(contentsOf: formatted, at: insertPos)
                }
            } else {
                // Section doesn't exist, append section and entry
                var newSection: [String] = []
                if !lines.isEmpty && !lines.last!.trimmingCharacters(in: .whitespaces).isEmpty {
                    newSection.append("")
                }
                newSection.append("proxies:")
                newSection.append(contentsOf: formatNewEntry(node: node, baseIndent: 2))
                lines.append(contentsOf: newSection)
            }
            return true
        }
    }

    /// Duplicates proxy named `name` with `newName`, inserting right after it.
    func duplicateProxy(name: String, newName: String) -> String? {
        guard let entry = findProxy(name: name) else { return nil }

        var duplicateLines = Array(lines[entry.lineRange])
        if entry.isFlowStyle {
            // `- { name: A, ... }` has no `name:` line to rewrite; re-emit the flow mapping with the new name.
            var d = entry.dict
            d["name"] = newName
            duplicateLines = formatUpdatedEntry(originalLines: duplicateLines, want: d, isFlow: true, baseIndent: entry.baseIndent)
        } else {
            // Update name in duplicateLines
            duplicateLines = updateNameInEntryLines(duplicateLines, newName: newName)
        }

        let insertPos = entry.lineRange.upperBound
        lines.insert(contentsOf: duplicateLines, at: insertPos)
        return newName
    }

    /// Deletes proxy named `name`.
    func deleteProxy(name: String) -> Bool {
        guard let entry = findProxy(name: name) else { return false }
        lines.removeSubrange(entry.lineRange)
        return true
    }

    // MARK: - Entry Formatting Helpers

    private func formatNewEntry(node: [String: Any], baseIndent: Int) -> [String] {
        let fieldIndent = baseIndent + 2
        var keys = Array(node.keys)
        keys.sort { Self.leadRank($0) < Self.leadRank($1) }

        var out: [String] = []
        for (i, k) in keys.enumerated() {
            guard let val = node[k] else { continue }
            let valStr = Self.formatYAMLValue(val, indent: fieldIndent + 2)
            let ks = Self.formatYAMLString(k)
            // A nested map is emitted as a flow mapping on the key line (formatYAMLValue returns `{ ... }`);
            // the old "key:" + bare "{...}" line pair was not valid block YAML.
            if i == 0 {
                out.append(String(repeating: " ", count: baseIndent) + "- \(ks): \(valStr)")
            } else {
                out.append(String(repeating: " ", count: fieldIndent) + "\(ks): \(valStr)")
            }
        }
        return out
    }

    private func formatUpdatedEntry(originalLines: [String], want: [String: Any], isFlow: Bool, baseIndent: Int) -> [String] {
        if isFlow {
            // Re-emit flow style: - { k: v, ... }
            var keys = Array(want.keys)
            keys.sort { Self.leadRank($0) < Self.leadRank($1) }
            var pairs: [String] = []
            for k in keys {
                if let v = want[k] {
                    pairs.append("\(Self.formatYAMLString(k, flow: true)): \(Self.formatYAMLValue(v, indent: 0, flow: true))")
                }
            }
            let flowLine = String(repeating: " ", count: baseIndent) + "- { " + pairs.joined(separator: ", ") + " }"
            // Keep the entry's leading comment lines and trailing blank / comment lines (rv2 #11: they used to be
            // dropped together with the old flow line).
            guard let dash = originalLines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("-") }) else {
                return [flowLine]
            }
            var tail = originalLines.count
            while tail > dash + 1 {
                let t = originalLines[tail - 1].trimmingCharacters(in: .whitespaces)
                if t.isEmpty || t.hasPrefix("#") { tail -= 1 } else { break }
            }
            return Array(originalLines[0..<dash]) + [flowLine] + Array(originalLines[tail...])
        }

        let fieldIndent = baseIndent + 2

        // Locate dash line
        var dashLineIdx = 0
        for (i, line) in originalLines.enumerated() {
            if line.trimmingCharacters(in: .whitespaces).hasPrefix("-") {
                dashLineIdx = i
                break
            }
        }

        let preamble = Array(originalLines[0..<dashLineIdx])

        // Parse fields
        struct Field {
            var key: String
            var comments: [String]
            var keyLine: String
            var childLines: [String]
        }

        var fields: [Field] = []
        var currentComments: [String] = []
        var currentField: Field?

        for i in dashLineIdx..<originalLines.count {
            let line = originalLines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let indent = line.prefix(while: { $0 == " " }).count

            if trimmed.hasPrefix("#") || trimmed.isEmpty {
                if currentField != nil && indent > fieldIndent {
                    currentField?.childLines.append(line)
                } else {
                    currentComments.append(line)
                }
                continue
            }

            if i == dashLineIdx {
                // First line: starts with "- "
                let afterDash = trimmed.dropFirst().trimmingCharacters(in: .whitespaces)
                if afterDash.contains(":") {
                    let k = afterDash.components(separatedBy: ":")[0].trimmingCharacters(in: .whitespaces)
                    currentField = Field(key: k, comments: currentComments, keyLine: line, childLines: [])
                    currentComments = []
                }
                continue
            }

            // Subsequent field line
            if indent == fieldIndent && trimmed.contains(":") && !trimmed.hasPrefix("-") {
                let k = trimmed.components(separatedBy: ":")[0].trimmingCharacters(in: .whitespaces)
                if let cf = currentField {
                    fields.append(cf)
                }
                currentField = Field(key: k, comments: currentComments, keyLine: line, childLines: [])
                currentComments = []
            } else {
                if currentField != nil {
                    currentField?.childLines.append(line)
                } else {
                    currentComments.append(line)
                }
            }
        }
        if let cf = currentField {
            fields.append(cf)
        }

        // Update fields with want
        var resultFields: [Field] = []
        var seen = Set<String>()

        for var f in fields {
            guard let newVal = want[f.key] else {
                continue // removed key
            }
            seen.insert(f.key)

            // Extract inline comment if any
            // Inline comment: a `#` preceded by whitespace and outside quotes (a bare firstIndex(of: "#") cut
            // values such as `password: "a#b"` in half).
            let split = Self.splitInlineComment(f.keyLine)
            let kl = split.content
            let commentPart = split.comment
            if let colonIdx = kl.firstIndex(of: ":") {
                let prefix = String(kl[...colonIdx])
                if let mapVal = newVal as? [String: Any] {
                    f.keyLine = prefix + commentPart
                    f.childLines = []
                    let subKeys = Array(mapVal.keys).sorted()
                    for sk in subKeys {
                        if let sv = mapVal[sk] {
                            let svStr = Self.formatYAMLValue(sv, indent: fieldIndent + 4)
                            f.childLines.append(String(repeating: " ", count: fieldIndent + 2) + "\(Self.formatYAMLString(sk)): \(svStr)")
                        }
                    }
                } else {
                    let formatted = Self.formatYAMLValue(newVal, indent: fieldIndent + 2)
                    f.keyLine = prefix + " " + formatted + commentPart
                    f.childLines = []
                }
            }
            resultFields.append(f)
        }

        // Add remaining new keys from want
        var rest = want.keys.filter { !seen.contains($0) }
        rest.sort { Self.leadRank($0) < Self.leadRank($1) }
        for k in rest {
            guard let newVal = want[k] else { continue }
            if let mapVal = newVal as? [String: Any] {
                var cl: [String] = []
                let subKeys = Array(mapVal.keys).sorted()
                for sk in subKeys {
                    if let sv = mapVal[sk] {
                        let svStr = Self.formatYAMLValue(sv, indent: fieldIndent + 4)
                        cl.append(String(repeating: " ", count: fieldIndent + 2) + "\(Self.formatYAMLString(sk)): \(svStr)")
                    }
                }
                resultFields.append(Field(
                    key: k,
                    comments: [],
                    keyLine: String(repeating: " ", count: fieldIndent) + "\(Self.formatYAMLString(k)):",
                    childLines: cl
                ))
            } else {
                let formatted = Self.formatYAMLValue(newVal, indent: fieldIndent + 2)
                resultFields.append(Field(
                    key: k,
                    comments: [],
                    keyLine: String(repeating: " ", count: fieldIndent) + "\(Self.formatYAMLString(k)): \(formatted)",
                    childLines: []
                ))
            }
        }

        // Assemble output lines
        var out = preamble
        for (i, f) in resultFields.enumerated() {
            out.append(contentsOf: f.comments)
            var kl = f.keyLine
            let klTrimmed = kl.trimmingCharacters(in: .whitespaces)
            if i == 0 {
                // Must have "- "
                if !klTrimmed.hasPrefix("-") {
                    kl = String(repeating: " ", count: baseIndent) + "- " + klTrimmed
                }
            } else {
                // Must not have "- "
                if klTrimmed.hasPrefix("-") {
                    let clean = klTrimmed.dropFirst().trimmingCharacters(in: .whitespaces)
                    kl = String(repeating: " ", count: fieldIndent) + clean
                }
            }
            out.append(kl)
            out.append(contentsOf: f.childLines)
        }
        out.append(contentsOf: currentComments)
        return out
    }

    private func updateNameInEntryLines(_ entryLines: [String], newName: String) -> [String] {
        var out: [String] = []
        let formattedName = Self.formatYAMLString(newName)
        var renamed = false
        for line in entryLines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Only the entry's own `name:` (first one) — a nested `name:` under e.g. an opts map stays.
            if !renamed && (trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:")) {
                renamed = true
                // Extract inline comment if any (quote-aware, see splitInlineComment)
                let split = Self.splitInlineComment(line)
                let commentPart = split.comment
                let cleanLine = split.content
                if let colonIdx = cleanLine.firstIndex(of: ":") {
                    let prefix = String(cleanLine[...colonIdx])
                    out.append(prefix + " " + formattedName + commentPart)
                    continue
                }
            }
            out.append(line)
        }
        return out
    }

    static func formatYAMLValue(_ val: Any, indent: Int, flow: Bool = false) -> String {
        switch val {
        case is NSNull:
            return "null"
        case let n as NSNumber where CFGetTypeID(n) == CFBooleanGetTypeID():
            return n.boolValue ? "true" : "false"
        case let b as Bool:
            return b ? "true" : "false"
        case let n as Int:
            return "\(n)"
        case let n as Int64:
            return "\(n)"
        case let n as Double:
            return formatYAMLDouble(n)
        case let s as String:
            return formatYAMLString(s, flow: flow)
        case let a as [Any]:
            let items = a.map { formatYAMLValue($0, indent: indent, flow: true) }
            return "[" + items.joined(separator: ", ") + "]"
        case let m as [String: Any]:
            var pairs: [String] = []
            for (k, v) in m.sorted(by: { $0.key < $1.key }) {
                pairs.append("\(formatYAMLString(k, flow: true)): \(formatYAMLValue(v, indent: indent, flow: true))")
            }
            return "{ " + pairs.joined(separator: ", ") + " }"
        case let n as NSNumber:
            return formatYAMLDouble(n.doubleValue)
        default:
            return formatYAMLString("\(val)", flow: flow)
        }
    }

    /// yaml.v3 float spelling; integral values within Int64 range print without a fraction (the old
    /// `Int64(n)` trapped for integral values beyond Int64, e.g. 1e20).
    static func formatYAMLDouble(_ n: Double) -> String {
        if n.isNaN { return ".nan" }
        if n.isInfinite { return n < 0 ? "-.inf" : ".inf" }
        if n == n.rounded(.towardZero) && n >= -9.2e18 && n <= 9.2e18 {
            return "\(Int64(n))"
        }
        return "\(n)"
    }

    // MARK: - Scalar quoting (yaml.v3 equivalent)

    /// Formats a string scalar the way yaml.v3's encoder chooses its style (encode.go stringv + libyaml
    /// yaml_emitter_analyze_scalar / select_scalar_style):
    ///  - "" -> `""`
    ///  - contains a line break or a non-printable character (control chars, tab, DEL, BOM, NEL, LS, PS) ->
    ///    double-quoted with escapes (yaml.v3 uses a `|-` literal for multi-line block values; a double-quoted
    ///    scalar reads back as the identical string and keeps the entry on one line — see DIVERGENCES 4)
    ///  - would resolve to a non-string as a plain scalar (null, bool incl. YAML 1.1 y/yes/on/off..., int incl.
    ///    0x/0o/0b/underscores, float incl. .inf/.nan, base-60, timestamp, merge key `<<`) -> double-quoted
    ///  - plain style not allowed (leading indicator, leading/trailing space, ": " / " #" / trailing ":",
    ///    flow indicators `,[]{}` when `flow`, document markers) -> single-quoted (`'` doubled)
    ///  - otherwise plain.
    /// Every value written by the line editor goes through here, so an editor-supplied value can never break
    /// the line structure or inject a key (review rv2: `\n`/control chars/leading `-`,`?`,`:` were written raw).
    static func formatYAMLString(_ s: String, flow: Bool = false) -> String {
        if s.isEmpty { return "\"\"" }
        if needsDoubleQuotes(s) || resolvesToNonString(s) {
            return doubleQuoted(s)
        }
        if plainAllowed(s, flow: flow) {
            return s
        }
        return "'" + s.replacingOccurrences(of: "'", with: "''") + "'"
    }

    private static func isPrintable(_ v: UInt32) -> Bool {
        // libyaml IS_PRINTABLE (0x0A is handled as a break by the caller).
        return (v >= 0x20 && v <= 0x7E) || v == 0x85 || (v >= 0xA0 && v <= 0xD7FF) ||
            (v >= 0xE000 && v <= 0xFFFD && v != 0xFEFF) || (v >= 0x10000 && v <= 0x10FFFF)
    }

    private static func isBreak(_ v: UInt32) -> Bool {
        v == 0x0A || v == 0x0D || v == 0x85 || v == 0x2028 || v == 0x2029
    }

    private static func needsDoubleQuotes(_ s: String) -> Bool {
        for u in s.unicodeScalars {
            let v = u.value
            if isBreak(v) || !isPrintable(v) { return true }
        }
        return false
    }

    /// gate round 1: the four scalar-shape patterns were compiled on every call (up to 4 compiles per digit-led string
    /// scalar, e.g. every IP server address on a profile save). Compiled once; NSRegularExpression is thread-safe.
    private static let compiledLock = NSLock()
    private static var compiled: [String: NSRegularExpression] = [:]
    private static func regex(_ pattern: String) -> NSRegularExpression? {
        compiledLock.lock(); defer { compiledLock.unlock() }
        if let re = compiled[pattern] { return re }
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        compiled[pattern] = re   // bounded: only the fixed literal patterns below reach here
        return re
    }

    private static func fullMatch(_ pattern: String, _ s: String) -> Bool {
        guard let re = regex(pattern) else { return false }
        let r = NSRange(s.startIndex..., in: s)
        guard let m = re.firstMatch(in: s, options: [.anchored], range: r) else { return false }
        return m.range.location == 0 && m.range.length == r.length
    }

    /// yaml.v3 resolve() (+ isOldBool / isBase60Float in stringv): true when the plain scalar `s` would not
    /// read back as a !!str.
    static func resolvesToNonString(_ s: String) -> Bool {
        let nullOrBool: Set<String> = [
            "~", "null", "Null", "NULL",
            "true", "True", "TRUE", "false", "False", "FALSE",
            // YAML 1.1 booleans (yaml.v3 isOldBool) and merge key
            "y", "Y", "yes", "Yes", "YES", "on", "On", "ON",
            "n", "N", "no", "No", "NO", "off", "Off", "OFF", "<<",
            ".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF", "-.inf", "-.Inf", "-.INF",
            ".nan", ".NaN", ".NAN",
        ]
        if nullOrBool.contains(s) { return true }
        guard let first = s.unicodeScalars.first else { return true }
        let hint = "+-.0123456789"
        guard hint.unicodeScalars.contains(first) else { return false }
        // int: strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 0, 64) (+ ParseUint) — any base prefix.
        let noUnderscore = s.replacingOccurrences(of: "_", with: "")
        if fullMatch("[-+]?(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|[0-9]+)", noUnderscore) { return true }
        // float: yamlStyleFloat
        if fullMatch("[-+]?(\\.[0-9]+|[0-9]+(\\.[0-9]*)?)([eE][-+]?[0-9]+)?", s) { return true }
        // base-60 float (isBase60Float)
        if fullMatch("[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\\.[0-9_]*)?", s) { return true }
        // timestamp (parseTimestamp accepts these layouts); quoting a near-miss is harmless
        if fullMatch("[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}([Tt ].*)?", s) { return true }
        return false
    }

    /// libyaml yaml_emitter_analyze_scalar, plain branch. `flow` = the scalar sits inside `[...]` / `{...}`.
    static func plainAllowed(_ s: String, flow: Bool) -> Bool {
        let u = Array(s.unicodeScalars)
        guard let first = u.first, let last = u.last else { return false }
        if first == " " || last == " " { return false }
        if s.hasPrefix("---") || s.hasPrefix("...") { return false }
        let followedBySpace: (Int) -> Bool = { i in i + 1 >= u.count || u[i + 1] == " " }
        // leading indicators
        if "#,[]{}&*!|>'\"%@`".unicodeScalars.contains(first) { return false }
        if first == "?" || first == ":" {
            if flow || followedBySpace(0) { return false }
        }
        if first == "-" && followedBySpace(0) { return false }
        for i in 0..<u.count {
            let c = u[i]
            if flow && ",?[]{}".unicodeScalars.contains(c) { return false }
            if c == ":" {
                if flow || followedBySpace(i) { return false }
            }
            if c == "#" && i > 0 && u[i - 1] == " " { return false }
        }
        return true
    }

    /// libyaml yaml_emitter_write_double_quoted escapes.
    static func doubleQuoted(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            let v = u.value
            switch v {
            case 0x00: out += "\\0"
            case 0x07: out += "\\a"
            case 0x08: out += "\\b"
            case 0x09: out += "\\t"
            case 0x0A: out += "\\n"
            case 0x0B: out += "\\v"
            case 0x0C: out += "\\f"
            case 0x0D: out += "\\r"
            case 0x1B: out += "\\e"
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x85: out += "\\N"
            case 0x2028: out += "\\L"
            case 0x2029: out += "\\P"
            default:
                if isPrintable(v) {
                    out.unicodeScalars.append(u)
                } else if v <= 0xFF {
                    out += String(format: "\\x%02X", v)
                } else if v <= 0xFFFF {
                    out += String(format: "\\u%04X", v)
                } else {
                    out += String(format: "\\U%08X", v)
                }
            }
        }
        return out + "\""
    }

    /// Undoes single / double quoting of a whole scalar (best effort, for rule lines read back for editing).
    static func unquoteScalar(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.count >= 2 && t.hasPrefix("'") && t.hasSuffix("'") {
            return String(t.dropFirst().dropLast()).replacingOccurrences(of: "''", with: "'")
        }
        if t.count >= 2 && t.hasPrefix("\"") && t.hasSuffix("\""),
           let v = NCYAML.parse("k: " + t)?.object?["k"], case .string(let str) = v {
            return str
        }
        return t
    }

    /// A one-line flow-mapping list item (`- {name: G, proxies: [a, b], dialer-proxy: x}`): renames `oldName` in its
    /// `proxies` flow list (when `members`) and its `dialer-proxy` value, or drops it when `newName` is empty.
    /// Returns nil when the line is not such an item or nothing in it refers to `oldName` (the line is then kept
    /// byte for byte); `name` is the item's own `name`.
    static func renameInFlowMapping(_ line: String, oldName: String, newName: String, members: Bool = true)
        -> (line: String, name: String, member: Bool, dialer: Bool)? {
        let split = splitInlineComment(line)
        let content = split.content
        let t = content.trimmingCharacters(in: .whitespaces)
        guard t.hasPrefix("- {") || t.hasPrefix("{"), t.hasSuffix("}"),
              let open = content.firstIndex(of: "{"), let close = content.lastIndex(of: "}"), open < close else { return nil }
        let items = splitFlowItems(String(content[content.index(after: open)..<close]))
        var out: [String] = []
        var name = "", member = false, dialer = false
        for item in items {
            guard let colon = item.range(of: ":") else { out.append(item); continue }
            let key = unquoteScalar(String(item[..<colon.lowerBound]))
            let value = String(item[colon.upperBound...]).trimmingCharacters(in: .whitespaces)
            switch key {
            case "name":
                name = unquoteScalar(value)
                out.append(item)
            case "proxies" where members && value.hasPrefix("[") && value.hasSuffix("]"):
                let list = splitFlowItems(String(value.dropFirst().dropLast()))
                var hit = false
                var newList: [String] = []
                for m in list {
                    if unquoteScalar(m) == oldName {
                        hit = true
                        if !newName.isEmpty { newList.append(formatYAMLString(newName, flow: true)) }
                    } else { newList.append(m) }
                }
                if hit { member = true; out.append("proxies: [" + newList.joined(separator: ", ") + "]") } else { out.append(item) }
            case "dialer-proxy" where unquoteScalar(value) == oldName:
                dialer = true
                if !newName.isEmpty { out.append("dialer-proxy: " + formatYAMLString(newName, flow: true)) }
            default:
                out.append(item)
            }
        }
        guard member || dialer else { return nil }
        let rebuilt = String(content[..<open]) + "{" + out.joined(separator: ", ") + "}" + String(content[content.index(after: close)...])
        return (rebuilt + split.comment, name, member, dialer)
    }

    /// Splits the inside of a flow sequence on top-level commas, honoring quoted scalars
    /// (`''` doubling, `\"` escapes) and nested `[]` / `{}`. A member whose name contains a
    /// comma (`"a,b"`) stays one item; returns the raw item texts (quotes preserved, trimmed) —
    /// compare/write them through unquoteScalar / formatYAMLString(flow: true). The naive
    /// components(separatedBy: ",") split this replaces broke such names in listGroups/renameRefs.
    static func splitFlowItems(_ inner: String) -> [String] {
        var items: [String] = []
        var cur = ""
        var depth = 0
        var inSingle = false
        var inDouble = false
        let chars = Array(inner)
        var i = 0
        func flush() {
            let t = cur.trimmingCharacters(in: .whitespaces)
            if !t.isEmpty { items.append(t) }
            cur = ""
        }
        while i < chars.count {
            let c = chars[i]
            if inSingle {
                cur.append(c)
                if c == "'" {
                    if i + 1 < chars.count, chars[i + 1] == "'" { cur.append("'"); i += 1 } else { inSingle = false }
                }
            } else if inDouble {
                cur.append(c)
                if c == "\\", i + 1 < chars.count { cur.append(chars[i + 1]); i += 1 }
                else if c == "\"" { inDouble = false }
            } else if c == "'" { inSingle = true; cur.append(c) }
            else if c == "\"" { inDouble = true; cur.append(c) }
            else if c == "[" || c == "{" { depth += 1; cur.append(c) }
            else if c == "]" || c == "}" { depth -= 1; cur.append(c) }
            else if c == ",", depth == 0 { flush() }
            else { cur.append(c) }
            i += 1
        }
        flush()
        return items
    }

    /// Splits a line into its content and an inline comment. A comment starts at a `#` that follows whitespace
    /// (or starts the line) and is outside a quoted scalar; quotes only open at the start of a value (after
    /// whitespace, `:`, `-`, `[`, `{`, `,`), so `it's` does not open one. `comment` keeps the whitespace that
    /// separated it from the content.
    static func splitInlineComment(_ line: String) -> (content: String, comment: String) {
        let chars = Array(line)
        var inSingle = false, inDouble = false
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if inDouble {
                if c == "\\" { i += 2; continue }
                if c == "\"" { inDouble = false }
            } else if inSingle {
                if c == "'" {
                    if i + 1 < chars.count && chars[i + 1] == "'" { i += 2; continue }
                    inSingle = false
                }
            } else {
                let prev: Character? = i > 0 ? chars[i - 1] : nil
                let opener = prev == nil || prev == " " || prev == "\t" || prev == ":" || prev == "-" ||
                    prev == "[" || prev == "{" || prev == ","
                if (c == "\"" || c == "'") && opener {
                    if c == "\"" { inDouble = true } else { inSingle = true }
                } else if c == "#" && (prev == nil || prev == " " || prev == "\t") {
                    var j = i
                    while j > 0 && (chars[j - 1] == " " || chars[j - 1] == "\t") { j -= 1 }
                    return (String(chars[0..<j]), String(chars[j...]))
                }
            }
            i += 1
        }
        return (line, "")
    }

    // MARK: - Proxy Groups & References

    struct GroupInfo {
        var name: String
        var lineRange: Range<Int>
        var proxies: [String]
        var isProxiesFlowStyle: Bool
        var proxiesLineIndex: Int?
        var keepsMembers: Bool
    }

    func listGroups() -> [GroupInfo] {
        guard let section = findTopLevelSection("proxy-groups") else { return [] }

        var itemStarts: [Int] = []
        var listIndent = 2
        for i in section.contentRange {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let indent = line.prefix(while: { $0 == " " }).count
            if trimmed.hasPrefix("- ") || trimmed == "-" {
                if itemStarts.isEmpty { listIndent = indent }
                if indent == listIndent { itemStarts.append(i) }
            }
        }

        var groups: [GroupInfo] = []
        let bounds = entryBounds(itemStarts: itemStarts, section: section, listIndent: listIndent)
        for (idx, startLine) in itemStarts.enumerated() {
            let nextStart = bounds[idx].upperBound
            var name = ""
            var proxies: [String] = []
            var isFlow = false
            var proxiesLineIdx: Int?
            var keepsMembers = false

            var inProxiesBlock = false
            var proxiesIndent = 0

            for j in startLine..<nextStart {
                let line = lines[j]
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                let indent = line.prefix(while: { $0 == " " }).count

                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                // Group name
                if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:") {
                    let clean = trimmed.hasPrefix("- name:") ? String(trimmed.dropFirst(7)) : String(trimmed.dropFirst(5))
                    name = Self.unquoteScalar(clean)
                }

                // Check use / include-all
                if trimmed.hasPrefix("use:") {
                    let rest = trimmed.dropFirst(4).trimmingCharacters(in: .whitespaces)
                    if rest != "[]" && !rest.isEmpty { keepsMembers = true }
                }
                for k in ["include-all", "include-all-proxies", "include-all-providers"] {
                    if trimmed.hasPrefix("\(k):") {
                        let rest = trimmed.dropFirst(k.count + 1).trimmingCharacters(in: .whitespaces).lowercased()
                        if rest == "true" { keepsMembers = true }
                    }
                }

                // Check proxies list
                if trimmed.hasPrefix("proxies:") {
                    proxiesLineIdx = j
                    let rest = trimmed.dropFirst(8).trimmingCharacters(in: .whitespaces)
                    if rest.hasPrefix("[") && rest.hasSuffix("]") {
                        isFlow = true
                        let inner = String(rest.dropFirst().dropLast())
                        if !inner.isEmpty {
                            proxies = Self.splitFlowItems(inner).map { Self.unquoteScalar($0) }
                        }
                        inProxiesBlock = false
                    } else {
                        isFlow = false
                        inProxiesBlock = true
                        proxiesIndent = 0
                    }
                    continue
                }

                if inProxiesBlock {
                    if trimmed.hasPrefix("- ") {
                        if proxiesIndent == 0 { proxiesIndent = indent }
                        if indent == proxiesIndent {
                            let member = Self.unquoteScalar(String(trimmed.dropFirst(2)))
                            proxies.append(member)
                        } else {
                            inProxiesBlock = false
                        }
                    } else {
                        inProxiesBlock = false
                    }
                }
            }

            groups.append(GroupInfo(
                name: name,
                lineRange: bounds[idx],
                proxies: proxies,
                isProxiesFlowStyle: isFlow,
                proxiesLineIndex: proxiesLineIdx,
                keepsMembers: keepsMembers
            ))
        }

        return groups
    }

    /// Checks which groups would be left with no members after deleting `name`.
    func emptyAfterDelete(name: String) -> [String] {
        var out: [String] = []
        for g in listGroups() {
            if g.keepsMembers || g.proxiesLineIndex == nil { continue }
            var left = 0
            var had = false
            for m in g.proxies {
                if m == name {
                    had = true
                } else {
                    left += 1
                }
            }
            if had && left == 0 {
                out.append(g.name)
            }
        }
        return out
    }

    struct RenameStats {
        var groups: [String] = []
        var rules: Int = 0
        var dialers: [String] = []
    }

    /// Renames all references to `oldName` in proxy-groups, proxies dialer-proxy, rules, sub-rules.
    /// If `newName` is empty, references are deleted.
    func renameRefs(oldName: String, newName: String) -> RenameStats {
        var st = RenameStats()

        // 1. Process proxy-groups
        if let section = findTopLevelSection("proxy-groups") {
            var i = section.contentRange.lowerBound
            var currentGroup = ""

            while i < section.contentRange.upperBound && i < lines.count {
                let line = lines[i]
                let trimmed = line.trimmingCharacters(in: .whitespaces)

                if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:") {
                    let clean = trimmed.hasPrefix("- name:") ? String(trimmed.dropFirst(7)) : String(trimmed.dropFirst(5))
                    currentGroup = Self.unquoteScalar(clean)
                }

                // A one-line flow-mapping group (`- {name: Auto, type: url-test, proxies: [a, b]}`): the block-style
                // checks below never see its `proxies:` / `dialer-proxy:` (test10: a renamed node stayed in such a
                // group → "proxy group[0]: Auto: '<old>' not found" and the save was refused).
                if let r = Self.renameInFlowMapping(line, oldName: oldName, newName: newName) {
                    if !r.name.isEmpty && r.member && !st.groups.contains(r.name) { st.groups.append(r.name) }
                    if !r.name.isEmpty && r.dialer && !st.dialers.contains(r.name) { st.dialers.append(r.name) }
                    lines[i] = r.line
                    i += 1
                    continue
                }

                // Group dialer-proxy
                if trimmed.hasPrefix("dialer-proxy:") {
                    let rest = Self.unquoteScalar(Self.splitInlineComment(String(trimmed.dropFirst(13))).content)
                    if rest == oldName {
                        if !currentGroup.isEmpty && !st.dialers.contains(currentGroup) {
                            st.dialers.append(currentGroup)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = line.prefix(while: { $0 == " " }) + "dialer-proxy: "
                            lines[i] = String(prefix) + Self.formatYAMLString(newName) + Self.splitInlineComment(line).comment
                        }
                    }
                }

                // Flow proxies list
                if trimmed.hasPrefix("proxies:") && trimmed.contains("[") && trimmed.contains("]") {
                    let prefix = String(line.prefix(while: { $0 == " " })) + "proxies: "
                    if let leftBracket = trimmed.firstIndex(of: "["), let rightBracket = trimmed.lastIndex(of: "]") {
                        let inner = String(trimmed[trimmed.index(after: leftBracket)..<rightBracket])
                        let members = Self.splitFlowItems(inner)
                        var hit = false
                        var newMembers: [String] = []
                        for m in members {
                            if Self.unquoteScalar(m) == oldName {
                                hit = true
                                if !newName.isEmpty {
                                    newMembers.append(Self.formatYAMLString(newName, flow: true))
                                }
                            } else {
                                newMembers.append(m)
                            }
                        }
                        if hit {
                            if !currentGroup.isEmpty && !st.groups.contains(currentGroup) {
                                st.groups.append(currentGroup)
                            }
                            lines[i] = prefix + "[" + newMembers.joined(separator: ", ") + "]"
                        }
                    }
                }

                // Block proxies list member
                if trimmed.hasPrefix("- ") {
                    let member = Self.unquoteScalar(Self.splitInlineComment(String(trimmed.dropFirst(2))).content)
                    if member == oldName {
                        if !currentGroup.isEmpty && !st.groups.contains(currentGroup) {
                            st.groups.append(currentGroup)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = String(line.prefix(while: { $0 == " " })) + "- "
                            lines[i] = String(prefix) + Self.formatYAMLString(newName) + Self.splitInlineComment(line).comment
                        }
                    }
                }

                i += 1
            }
        }

        // 2. Process dialer-proxy in proxies
        if let section = findTopLevelSection("proxies") {
            var i = section.contentRange.lowerBound
            var currentProxy = ""

            while i < section.contentRange.upperBound && i < lines.count {
                let line = lines[i]
                let trimmed = line.trimmingCharacters(in: .whitespaces)

                if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:") {
                    let clean = trimmed.hasPrefix("- name:") ? String(trimmed.dropFirst(7)) : String(trimmed.dropFirst(5))
                    currentProxy = Self.unquoteScalar(clean)
                }

                // One-line flow-mapping proxy (`- {name: a, ..., dialer-proxy: b}`).
                if let r = Self.renameInFlowMapping(line, oldName: oldName, newName: newName, members: false) {
                    if !r.name.isEmpty && r.dialer && !st.dialers.contains(r.name) { st.dialers.append(r.name) }
                    lines[i] = r.line
                    i += 1
                    continue
                }

                if trimmed.hasPrefix("dialer-proxy:") {
                    let rest = Self.unquoteScalar(Self.splitInlineComment(String(trimmed.dropFirst(13))).content)
                    if rest == oldName {
                        if !currentProxy.isEmpty && !st.dialers.contains(currentProxy) {
                            st.dialers.append(currentProxy)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = line.prefix(while: { $0 == " " }) + "dialer-proxy: "
                            lines[i] = String(prefix) + Self.formatYAMLString(newName) + Self.splitInlineComment(line).comment
                        }
                    }
                }
                i += 1
            }
        }

        // 3. Process rules and sub-rules
        for secName in ["rules", "sub-rules"] {
            guard let section = findTopLevelSection(secName) else { continue }
            var i = section.contentRange.lowerBound
            while i < section.contentRange.upperBound && i < lines.count {
                let line = lines[i]
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("- ") {
                    // rv2: strip an inline comment and the scalar's own quotes before splitting, and re-quote the
                    // rewritten rule as a whole (a quoted rule used to lose its closing quote, and a new name with
                    // `#`, `: ` or a line break was written raw).
                    let split = Self.splitInlineComment(String(trimmed.dropFirst(2)))
                    let ruleStr = Self.unquoteScalar(split.content)
                    var parts = Self.ysplitRule(ruleStr)
                    if parts.count >= 2 {
                        let ti = Self.ruleTarget(parts)
                        if parts[ti].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) == oldName {
                            st.rules += 1
                            if newName.isEmpty {
                                lines.remove(at: i)
                                continue
                            } else {
                                parts[ti] = newName
                                let prefix = line.prefix(while: { $0 == " " }) + "- "
                                lines[i] = String(prefix) + Self.formatYAMLString(parts.joined(separator: ",")) + split.comment
                            }
                        }
                    }
                }
                i += 1
            }
        }

        return st
    }

    /// Appends "DIRECT" to an empty group's proxies list.
    func appendDirectToGroup(name: String) {
        guard let section = findTopLevelSection("proxy-groups") else { return }
        var currentGroup = ""
        var i = section.contentRange.lowerBound
        while i < section.contentRange.upperBound && i < lines.count {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:") {
                let clean = trimmed.hasPrefix("- name:") ? String(trimmed.dropFirst(7)) : String(trimmed.dropFirst(5))
                currentGroup = Self.unquoteScalar(clean)
            }

            if currentGroup == name && trimmed.hasPrefix("proxies:") {
                if trimmed.contains("[") && trimmed.contains("]") {
                    let prefix = String(line.prefix(while: { $0 == " " })) + "proxies: "
                    lines[i] = prefix + "[DIRECT]"
                } else {
                    let indent = line.prefix(while: { $0 == " " }).count + 2
                    let directLine = String(repeating: " ", count: indent) + "- DIRECT"
                    lines.insert(directLine, at: i + 1)
                }
                return
            }
            i += 1
        }
    }

    // MARK: - Rule Utilities

    /// Splits rule line by commas outside parentheses (logic rules: AND,((DOMAIN,a),(NETWORK,UDP)),Target).
    static func ysplitRule(_ s: String) -> [String] {
        var out: [String] = []
        var depth = 0
        var start = s.startIndex
        var idx = s.startIndex

        while idx < s.endIndex {
            let ch = s[idx]
            switch ch {
            case "(": depth += 1
            case ")": depth -= 1
            case ",":
                if depth == 0 {
                    out.append(String(s[start..<idx]))
                    start = s.index(after: idx)
                }
            default: break
            }
            idx = s.index(after: idx)
        }
        out.append(String(s[start...]))
        return out
    }

    /// Returns index of rule line's target field (last field before no-resolve / src).
    static func ruleTarget(_ parts: [String]) -> Int {
        var i = parts.count - 1
        while i > 1 {
            let p = parts[i].trimmingCharacters(in: .whitespaces)
            if p == "no-resolve" || p == "src" {
                i -= 1
                continue
            }
            break
        }
        return i
    }
}
