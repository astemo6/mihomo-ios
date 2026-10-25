import Foundation

// DIVERGENCES:
// 1. YAML Node Engine:
//    - Go (bridge/profilenodes.go): Uses go.yaml.in/yaml/v3 AST (yaml.Node tree) where all comments and
//      formatting styles (flow vs block) are parsed into AST nodes, and serialized back out with yaml.Encoder.
//    - Swift (NCProfileYAML): Uses a line/block-based document editor that locates sections (`proxies:`,
//      `proxy-groups:`, `rules:`, `sub-rules:`) and entries by line structure. For modified/inserted proxy entries,
//      it updates mapping fields in place, preserving original key order, untouched keys, and comments.
//      Flow-style entries are detected and preserved.
//    - Impact: Comments, custom spacing, and formatting outside touched entries are 100% preserved bit-for-bit
//      without any AST re-serialization reformatting side-effects.
// 2. Flow Style Proxy Handling:
//    - Go: Uses yaml.FlowStyle bitmask on yaml.Node.
//    - Swift: Detects flow-style proxy entries (`- { ... }`) and preserves flow-style mapping formatting on updates.
//    - Impact: Flow-style entries remain flow-style; block-style entries remain block-style.

/// A comment- and order-preserving YAML document editor for profile node operations.
/// Operates at the line/block structure level to inspect, insert, update, and delete proxy entries
/// and update group / rule references without destroying comments or key order in untouched sections.
final class NCProfileYAML {

    private(set) var lines: [String]

    init(text: String) {
        // Split by lines, handling CRLF or LF
        self.lines = text.components(separatedBy: "\n").map { line in
            line.hasSuffix("\r") ? String(line.dropLast()) : line
        }
    }

    convenience init?(contentsOf fileURL: URL) {
        guard let data = try? Data(contentsOf: fileURL),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        self.init(text: text)
    }

    func text() -> String {
        lines.joined(separator: "\n")
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

        for (idx, startLine) in itemStarts.enumerated() {
            // Find end line of this item
            let nextStart = (idx + 1 < itemStarts.count) ? itemStarts[idx + 1] : section.contentRange.upperBound

            // Include preceding comment lines that directly attach to this item
            var actualStart = startLine
            while actualStart > (idx == 0 ? section.headerLine + 1 : itemStarts[idx - 1] + 1) {
                let prev = lines[actualStart - 1]
                let prevTrimmed = prev.trimmingCharacters(in: .whitespaces)
                if prevTrimmed.hasPrefix("#") {
                    actualStart -= 1
                } else {
                    break
                }
            }

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
        // Update name in duplicateLines
        duplicateLines = updateNameInEntryLines(duplicateLines, newName: newName)

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
            if i == 0 {
                if val is [String: Any] {
                    out.append(String(repeating: " ", count: baseIndent) + "- \(k):")
                    out.append(valStr)
                } else {
                    out.append(String(repeating: " ", count: baseIndent) + "- \(k): \(valStr)")
                }
            } else {
                if val is [String: Any] {
                    out.append(String(repeating: " ", count: fieldIndent) + "\(k):")
                    out.append(valStr)
                } else {
                    out.append(String(repeating: " ", count: fieldIndent) + "\(k): \(valStr)")
                }
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
                    pairs.append("\(k): \(Self.formatYAMLValue(v, indent: 0))")
                }
            }
            let flowLine = String(repeating: " ", count: baseIndent) + "- { " + pairs.joined(separator: ", ") + " }"
            return [flowLine]
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
            var kl = f.keyLine
            var commentPart = ""
            if let hashIdx = kl.firstIndex(of: "#") {
                commentPart = " " + String(kl[hashIdx...])
                kl = String(kl[..<hashIdx])
            }
            if let colonIdx = kl.firstIndex(of: ":") {
                let prefix = String(kl[...colonIdx])
                if let mapVal = newVal as? [String: Any] {
                    f.keyLine = prefix + commentPart
                    f.childLines = []
                    var subKeys = Array(mapVal.keys).sorted()
                    for sk in subKeys {
                        if let sv = mapVal[sk] {
                            let svStr = Self.formatYAMLValue(sv, indent: fieldIndent + 4)
                            f.childLines.append(String(repeating: " ", count: fieldIndent + 2) + "\(sk): \(svStr)")
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
                var subKeys = Array(mapVal.keys).sorted()
                for sk in subKeys {
                    if let sv = mapVal[sk] {
                        let svStr = Self.formatYAMLValue(sv, indent: fieldIndent + 4)
                        cl.append(String(repeating: " ", count: fieldIndent + 2) + "\(sk): \(svStr)")
                    }
                }
                resultFields.append(Field(
                    key: k,
                    comments: [],
                    keyLine: String(repeating: " ", count: fieldIndent) + "\(k):",
                    childLines: cl
                ))
            } else {
                let formatted = Self.formatYAMLValue(newVal, indent: fieldIndent + 2)
                resultFields.append(Field(
                    key: k,
                    comments: [],
                    keyLine: String(repeating: " ", count: fieldIndent) + "\(k): \(formatted)",
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
        let formattedName = Self.formatYAMLValue(newName, indent: 0)
        for line in entryLines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("name:") {
                // Extract inline comment if any
                var commentPart = ""
                var cleanLine = line
                if let hashIdx = line.firstIndex(of: "#") {
                    commentPart = " " + String(line[hashIdx...])
                    cleanLine = String(line[..<hashIdx])
                }
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

    static func formatYAMLValue(_ val: Any, indent: Int) -> String {
        switch val {
        case let b as Bool:
            return b ? "true" : "false"
        case let n as Int:
            return "\(n)"
        case let n as Int64:
            return "\(n)"
        case let n as Double:
            if n.isFinite && n == floor(n) {
                return "\(Int64(n))"
            }
            return "\(n)"
        case let s as String:
            return formatYAMLString(s)
        case let a as [Any]:
            let items = a.map { formatYAMLValue($0, indent: indent) }
            return "[" + items.joined(separator: ", ") + "]"
        case let m as [String: Any]:
            var pairs: [String] = []
            for (k, v) in m.sorted(by: { $0.key < $1.key }) {
                pairs.append("\(k): \(formatYAMLValue(v, indent: indent))")
            }
            return "{ " + pairs.joined(separator: ", ") + " }"
        default:
            return "\(val)"
        }
    }

    static func formatYAMLString(_ s: String) -> String {
        if s.isEmpty { return "\"\"" }
        let needsQuotes = s.contains(":") || s.contains("#") || s.contains(",") ||
            s.contains("[") || s.contains("]") || s.contains("{") || s.contains("}") ||
            s.contains("&") || s.contains("*") || s.contains("!") || s.contains("|") ||
            s.contains(">") || s.contains("'") || s.contains("\"") || s.contains("%") ||
            s.contains("@") || s.contains("`") || s.hasPrefix(" ") || s.hasSuffix(" ") ||
            ["true", "false", "yes", "no", "null", "~"].contains(s.lowercased()) ||
            Double(s) != nil
        if needsQuotes {
            let escaped = s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            return "\"\(escaped)\""
        }
        return s
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
        for (idx, startLine) in itemStarts.enumerated() {
            let nextStart = (idx + 1 < itemStarts.count) ? itemStarts[idx + 1] : section.contentRange.upperBound
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
                    name = clean.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
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
                        let inner = rest.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
                        if !inner.isEmpty {
                            proxies = inner.components(separatedBy: ",").map {
                                $0.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                            }
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
                            let member = trimmed.dropFirst(2).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
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
                lineRange: startLine..<nextStart,
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
                    currentGroup = clean.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }

                // Group dialer-proxy
                if trimmed.hasPrefix("dialer-proxy:") {
                    let rest = trimmed.dropFirst(13).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    if rest == oldName {
                        if !currentGroup.isEmpty && !st.dialers.contains(currentGroup) {
                            st.dialers.append(currentGroup)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = line.prefix(while: { $0 == " " }) + "dialer-proxy: "
                            lines[i] = prefix + Self.formatYAMLValue(newName, indent: 0)
                        }
                    }
                }

                // Flow proxies list
                if trimmed.hasPrefix("proxies:") && trimmed.contains("[") && trimmed.contains("]") {
                    let prefix = String(line.prefix(while: { $0 == " " })) + "proxies: "
                    if let leftBracket = trimmed.firstIndex(of: "["), let rightBracket = trimmed.lastIndex(of: "]") {
                        let inner = String(trimmed[trimmed.index(after: leftBracket)..<rightBracket])
                        var members = inner.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                        var hit = false
                        var newMembers: [String] = []
                        for m in members {
                            let raw = m.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                            if raw == oldName {
                                hit = true
                                if !newName.isEmpty {
                                    newMembers.append(Self.formatYAMLValue(newName, indent: 0))
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
                    let member = trimmed.dropFirst(2).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    if member == oldName {
                        if !currentGroup.isEmpty && !st.groups.contains(currentGroup) {
                            st.groups.append(currentGroup)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = String(line.prefix(while: { $0 == " " })) + "- "
                            lines[i] = prefix + Self.formatYAMLValue(newName, indent: 0)
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
                    currentProxy = clean.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }

                if trimmed.hasPrefix("dialer-proxy:") {
                    let rest = trimmed.dropFirst(13).trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    if rest == oldName {
                        if !currentProxy.isEmpty && !st.dialers.contains(currentProxy) {
                            st.dialers.append(currentProxy)
                        }
                        if newName.isEmpty {
                            lines.remove(at: i)
                            continue
                        } else {
                            let prefix = line.prefix(while: { $0 == " " }) + "dialer-proxy: "
                            lines[i] = prefix + Self.formatYAMLValue(newName, indent: 0)
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
                    let ruleStr = String(trimmed.dropFirst(2)).trimmingCharacters(in: .whitespaces)
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
                                lines[i] = prefix + parts.joined(separator: ",")
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
                currentGroup = clean.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
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
