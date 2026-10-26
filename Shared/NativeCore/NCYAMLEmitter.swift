import Foundation

/// A minimal YAML emitter for mihomo configurations and proxy nodes:
/// emits block mappings, sequences, and scalars (strings, numbers, booleans, null)
/// compatible with both Go's yaml.v3 and NCYAML.
enum NCYAMLEmitter {

    /// Emit an arbitrary object (dictionary, array, primitive, or NCJSONValue) as a YAML string.
    static func emit(_ value: Any) -> String {
        var out = ""
        emitValue(value, indent: 0, out: &out)
        if !out.hasSuffix("\n") {
            out.append("\n")
        }
        return out
    }

    // MARK: - Value Emission

    private static func emitValue(_ value: Any, indent: Int, out: inout String) {
        if let jsonVal = value as? NCJSONValue {
            emitJSONValue(jsonVal, indent: indent, out: &out)
            return
        }

        switch value {
        case is NSNull:
            out.append("null")
        case let b as Bool:
            out.append(b ? "true" : "false")
        case let num as NSNumber:
            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                out.append(num.boolValue ? "true" : "false")
            } else {
                emitNumber(num.doubleValue, out: &out)
            }
        case let s as String:
            out.append(formatString(s))
        case let dict as [String: Any]:
            emitDictionary(dict, indent: indent, out: &out)
        case let dict as [String: NCJSONValue]:
            emitDictionary(dict.mapValues { $0.rawAny }, indent: indent, out: &out)
        case let list as [Any]:
            emitList(list, indent: indent, out: &out)
        case let list as [NCJSONValue]:
            emitList(list.map { $0.rawAny }, indent: indent, out: &out)
        default:
            out.append(formatString(String(describing: value)))
        }
    }

    private static func emitJSONValue(_ value: NCJSONValue, indent: Int, out: inout String) {
        switch value {
        case .null:
            out.append("null")
        case .bool(let b):
            out.append(b ? "true" : "false")
        case .number(let n):
            emitNumber(n, out: &out)
        case .string(let s):
            out.append(formatString(s))
        case .array(let a):
            emitList(a.map { $0.rawAny }, indent: indent, out: &out)
        case .object(let o):
            emitDictionary(o.mapValues { $0.rawAny }, indent: indent, out: &out)
        }
    }

    private static func emitNumber(_ d: Double, out: inout String) {
        if d.isFinite && d == floor(d) && d >= Double(Int64.min) && d < Double(Int64.max) {
            out.append(String(Int64(d)))
        } else {
            out.append(String(d))
        }
    }

    // MARK: - Dictionary

    private static func emitDictionary(_ dict: [String: Any], indent: Int, out: inout String) {
        guard !dict.isEmpty else {
            out.append("{}")
            return
        }

        let keys = sortedKeys(dict)
        let pad = String(repeating: " ", count: indent)

        for (idx, key) in keys.enumerated() {
            guard let val = dict[key] else { continue }
            // fix/nc-e2e-real (E2E replay 40268229079: a QX import kept 1 of 9 proxies, 0 of 29 groups, 0 of 85
            // rules): every key after the first of a NESTED mapping was written at column 0 (only the first got
            // `pad`), e.g. a ws node's `ws-opts: {headers: {Host}, path}` emitted `path:` as a top-level key, which
            // ended `proxies:` after the first node and everything below it (the NCYAML parser stops at the
            // indented line that follows). Every key of a nested mapping starts on its own line at `pad`.
            if idx > 0 && !out.hasSuffix("\n") && !out.isEmpty {
                out.append("\n")
            }
            if (idx > 0 || indent > 0) && out.hasSuffix("\n") {
                out.append(pad)
            }

            out.append(formatKey(key))
            out.append(":")

            if isComplexCollection(val) {
                out.append("\n")
                emitComplexChild(val, indent: indent + 2, out: &out)
            } else {
                out.append(" ")
                emitValue(val, indent: indent + 2, out: &out)
                out.append("\n")
            }
        }
    }

    private static func emitComplexChild(_ val: Any, indent: Int, out: inout String) {
        if let jsonVal = val as? NCJSONValue {
            switch jsonVal {
            case .object(let o):
                emitDictionary(o.mapValues { $0.rawAny }, indent: indent, out: &out)
            case .array(let a):
                emitList(a.map { $0.rawAny }, indent: indent, out: &out)
            default:
                let pad = String(repeating: " ", count: indent)
                out.append(pad)
                emitJSONValue(jsonVal, indent: indent, out: &out)
                out.append("\n")
            }
            return
        }

        if let d = val as? [String: Any] {
            emitDictionary(d, indent: indent, out: &out)
        } else if let l = val as? [Any] {
            emitList(l, indent: indent, out: &out)
        } else {
            let pad = String(repeating: " ", count: indent)
            out.append(pad)
            emitValue(val, indent: indent, out: &out)
            out.append("\n")
        }
    }

    // MARK: - List

    private static func emitList(_ list: [Any], indent: Int, out: inout String) {
        guard !list.isEmpty else {
            out.append("[]")
            return
        }

        let pad = String(repeating: " ", count: indent)

        for item in list {
            if out.hasSuffix("\n") || out.isEmpty {
                out.append(pad)
            }
            out.append("- ")

            if let dict = asDictionary(item), !dict.isEmpty {
                // First key of dictionary starts right after "- "
                emitDictionaryInSequence(dict, indent: indent + 2, out: &out)
            } else if let sublist = asList(item), !sublist.isEmpty {
                out.append("\n")
                emitList(sublist, indent: indent + 2, out: &out)
            } else {
                emitValue(item, indent: indent + 2, out: &out)
                out.append("\n")
            }
        }
    }

    private static func emitDictionaryInSequence(_ dict: [String: Any], indent: Int, out: inout String) {
        let keys = sortedKeys(dict)
        let pad = String(repeating: " ", count: indent)

        for (idx, key) in keys.enumerated() {
            guard let val = dict[key] else { continue }
            if idx > 0 {
                out.append(pad)
            }
            out.append(formatKey(key))
            out.append(":")

            if isComplexCollection(val) {
                out.append("\n")
                emitComplexChild(val, indent: indent + 2, out: &out)
            } else {
                out.append(" ")
                emitValue(val, indent: indent + 2, out: &out)
                out.append("\n")
            }
        }
    }

    // MARK: - Helpers

    private static func isComplexCollection(_ val: Any) -> Bool {
        if let j = val as? NCJSONValue {
            switch j {
            case .object(let o): return !o.isEmpty
            case .array(let a): return !a.isEmpty
            default: return false
            }
        }
        if let d = val as? [String: Any] { return !d.isEmpty }
        if let l = val as? [Any] { return !l.isEmpty }
        return false
    }

    private static func asDictionary(_ val: Any) -> [String: Any]? {
        if let j = val as? NCJSONValue {
            if case .object(let o) = j { return o.mapValues { $0.rawAny } }
            return nil
        }
        return val as? [String: Any]
    }

    private static func asList(_ val: Any) -> [Any]? {
        if let j = val as? NCJSONValue {
            if case .array(let a) = j { return a.map { $0.rawAny } }
            return nil
        }
        return val as? [Any]
    }

    private static func formatKey(_ s: String) -> String {
        if needsQuotes(s) {
            return quoteString(s)
        }
        return s
    }

    private static func formatString(_ s: String) -> String {
        if needsQuotes(s) {
            return quoteString(s)
        }
        return s
    }

    private static func quoteString(_ s: String) -> String {
        var escaped = ""
        for ch in s {
            switch ch {
            case "\\": escaped.append("\\\\")
            case "\"": escaped.append("\\\"")
            case "\n": escaped.append("\\n")
            case "\r": escaped.append("\\r")
            case "\t": escaped.append("\\t")
            default: escaped.append(ch)
            }
        }
        return "\"\(escaped)\""
    }

    private static func needsQuotes(_ s: String) -> Bool {
        if s.isEmpty { return true }
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        if trimmed.count != s.count { return true }

        let lower = s.lowercased()
        if lower == "true" || lower == "false" || lower == "yes" || lower == "no"
            || lower == "null" || lower == "~" || lower == "on" || lower == "off" {
            return true
        }

        // Looks like a number?
        if Double(s) != nil { return true }
        if s.hasPrefix("0x") || s.hasPrefix("0o") || s.hasPrefix("0b") { return true }

        // Contains characters that require quotes in YAML
        if s.contains("\n") || s.contains("\r") || s.contains("\t") || s.contains(": ") || s.contains(" #") || s.hasSuffix(":") {
            return true
        }

        // Special leading characters
        if let first = s.first {
            switch first {
            case "-", "?", ":", ",", "[", "]", "{", "}", "#", "&", "*", "!", "|", ">", "'", "\"", "%", "@", "`":
                return true
            default:
                break
            }
        }

        return false
    }

    /// Prefer readable top-level / proxy / group key order, then alphabetical.
    private static let keyPriorities: [String: Int] = [
        // Root config
        "mode": 10,
        "proxies": 20,
        "proxy-groups": 30,
        "rules": 40,
        // Node fields
        "name": 1,
        "type": 2,
        "server": 3,
        "port": 4,
        "cipher": 5,
        "password": 6,
        "uuid": 7,
        "alterId": 8,
        "network": 9,
        "tls": 10,
        "servername": 11,
        "sni": 12,
        "flow": 13,
        "udp": 14,
        // Group fields
        "url": 15,
        "interval": 16,
        "tolerance": 17,
    ]

    private static func sortedKeys(_ dict: [String: Any]) -> [String] {
        dict.keys.sorted { a, b in
            let pa = keyPriorities[a] ?? 100
            let pb = keyPriorities[b] ?? 100
            if pa != pb { return pa < pb }
            return a < b
        }
    }
}

extension NCJSONValue {
    var rawAny: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let b): return b
        case .number(let n): return n
        case .string(let s): return s
        case .array(let a): return a.map { $0.rawAny }
        case .object(let o): return o.mapValues { $0.rawAny }
        }
    }
}
