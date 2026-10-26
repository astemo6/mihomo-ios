// Native MitM stage 3b — JSON exactly as the Go body rules see and write it.
//
// Go (bridge/mitm/handler.go applyBodyRule) decodes a body with encoding/json + UseNumber (r6limits.go
// decodeJSONNumber: one value, only whitespace after it), edits the value tree (Loon json ops: jsonEdit; legacy jq
// step lists: setpath / delpaths), and encodes it with encodeJSON (json.Encoder, SetEscapeHTML(false), no trailing newline).
// This file reproduces that byte for byte:
//
//   - strings and object keys are kept as raw UTF-8 bytes (Swift String equality / ordering is Unicode-canonical,
//     Go's is bytewise: "é" and "e\u{301}" are two keys in Go);
//   - numbers keep their literal text (json.Number is written back verbatim);
//   - objects are written with keys sorted bytewise (Go sorts map keys), duplicates resolved last-wins;
//   - strings are escaped like encoding/json's appendString without HTML escaping (\b \f \n \r \t, \u00XX for the
//     other control bytes, \" \\, \u2028 / \u2029).
//
// Anything where Go would do something Swift does not reproduce returns nil from the parser (the caller hands the
// request back to Go): syntax errors, invalid UTF-8 or lone surrogate escapes (Go silently substitutes U+FFFD),
// nesting deeper than 512 (Go allows 10000).

import Foundation

indirect enum BodyJSON: Equatable {
    case null
    case bool(Bool)
    case number([UInt8])            // the literal as written
    case string([UInt8])            // UTF-8 bytes (decoded escapes)
    case array([BodyJSON])
    case object([[UInt8]: BodyJSON])
    case deleted                    // delpaths marker (never encoded)

    // MARK: parse (encoding/json + UseNumber, then "only whitespace after the value")

    static func parse(_ data: Data) -> BodyJSON? {
        let bytes = [UInt8](data)
        var p = Parser(b: bytes)
        p.skipWS()
        guard let v = p.value(depth: 0) else { return nil }
        p.skipWS()
        return p.i == bytes.count ? v : nil
    }

    static func parse(_ s: String) -> BodyJSON? { parse(Data(s.utf8)) }

    private struct Parser {
        let b: [UInt8]
        var i = 0
        static let maxDepth = 512

        mutating func skipWS() {
            while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 }
        }

        mutating func lit(_ s: StaticString) -> Bool {
            let n = s.utf8CodeUnitCount
            guard i + n <= b.count else { return false }
            let p = s.utf8Start
            for k in 0..<n where b[i + k] != p[k] { return false }
            i += n
            return true
        }

        mutating func value(depth: Int) -> BodyJSON? {
            guard i < b.count else { return nil }
            switch b[i] {
            case UInt8(ascii: "{"):
                guard depth < Self.maxDepth else { return nil }
                i += 1
                var m: [[UInt8]: BodyJSON] = [:]
                skipWS()
                if i < b.count && b[i] == UInt8(ascii: "}") { i += 1; return .object(m) }
                while true {
                    skipWS()
                    guard i < b.count, b[i] == UInt8(ascii: "\""), let k = string() else { return nil }
                    skipWS()
                    guard i < b.count, b[i] == UInt8(ascii: ":") else { return nil }
                    i += 1
                    skipWS()
                    guard let v = value(depth: depth + 1) else { return nil }
                    m[k] = v
                    skipWS()
                    guard i < b.count else { return nil }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "}") { i += 1; return .object(m) }
                    return nil
                }
            case UInt8(ascii: "["):
                guard depth < Self.maxDepth else { return nil }
                i += 1
                var a: [BodyJSON] = []
                skipWS()
                if i < b.count && b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
                while true {
                    skipWS()
                    guard let v = value(depth: depth + 1) else { return nil }
                    a.append(v)
                    skipWS()
                    guard i < b.count else { return nil }
                    if b[i] == UInt8(ascii: ",") { i += 1; continue }
                    if b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
                    return nil
                }
            case UInt8(ascii: "\""):
                return string().map { .string($0) }
            case UInt8(ascii: "t"): return lit("true") ? .bool(true) : nil
            case UInt8(ascii: "f"): return lit("false") ? .bool(false) : nil
            case UInt8(ascii: "n"): return lit("null") ? .null : nil
            default:
                return number()
            }
        }

        static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

        /// -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?
        mutating func number() -> BodyJSON? {
            let start = i
            if i < b.count && b[i] == UInt8(ascii: "-") { i += 1 }
            guard i < b.count, Self.isDigit(b[i]) else { return nil }
            if b[i] == UInt8(ascii: "0") { i += 1 } else { while i < b.count && Self.isDigit(b[i]) { i += 1 } }
            if i < b.count && b[i] == UInt8(ascii: ".") {
                i += 1
                guard i < b.count, Self.isDigit(b[i]) else { return nil }
                while i < b.count && Self.isDigit(b[i]) { i += 1 }
            }
            if i < b.count && (b[i] == UInt8(ascii: "e") || b[i] == UInt8(ascii: "E")) {
                i += 1
                if i < b.count && (b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-")) { i += 1 }
                guard i < b.count, Self.isDigit(b[i]) else { return nil }
                while i < b.count && Self.isDigit(b[i]) { i += 1 }
            }
            return .number(Array(b[start..<i]))
        }

        static func hexVal(_ c: UInt8) -> UInt32? {
            switch c {
            case 0x30...0x39: return UInt32(c - 0x30)
            case 0x41...0x46: return UInt32(c - 0x41 + 10)
            case 0x61...0x66: return UInt32(c - 0x61 + 10)
            default: return nil
            }
        }

        mutating func hex4() -> UInt32? {
            guard i + 4 <= b.count else { return nil }
            var v: UInt32 = 0
            for k in 0..<4 {
                guard let h = Self.hexVal(b[i + k]) else { return nil }
                v = v << 4 | h
            }
            i += 4
            return v
        }

        static func appendUTF8(_ out: inout [UInt8], _ c: UInt32) {
            switch c {
            case 0..<0x80: out.append(UInt8(c))
            case 0x80..<0x800:
                out.append(UInt8(0xC0 | (c >> 6))); out.append(UInt8(0x80 | (c & 0x3F)))
            case 0x800..<0x10000:
                out.append(UInt8(0xE0 | (c >> 12))); out.append(UInt8(0x80 | ((c >> 6) & 0x3F))); out.append(UInt8(0x80 | (c & 0x3F)))
            default:
                out.append(UInt8(0xF0 | (c >> 18))); out.append(UInt8(0x80 | ((c >> 12) & 0x3F)))
                out.append(UInt8(0x80 | ((c >> 6) & 0x3F))); out.append(UInt8(0x80 | (c & 0x3F)))
            }
        }

        /// A string at b[i] == '"'. nil: syntax error, a control byte, invalid UTF-8 or a lone surrogate escape.
        mutating func string() -> [UInt8]? {
            i += 1
            var out: [UInt8] = []
            while i < b.count {
                let c = b[i]
                if c == UInt8(ascii: "\"") { i += 1; return out }
                if c < 0x20 { return nil }
                if c == UInt8(ascii: "\\") {
                    i += 1
                    guard i < b.count else { return nil }
                    let e = b[i]
                    i += 1
                    switch e {
                    case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(e)
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0C)
                    case UInt8(ascii: "n"): out.append(0x0A)
                    case UInt8(ascii: "r"): out.append(0x0D)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"):
                        guard let u = hex4() else { return nil }
                        if u >= 0xD800 && u < 0xDC00 {
                            guard i + 6 <= b.count, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") else { return nil }
                            i += 2
                            guard let l = hex4(), l >= 0xDC00 && l < 0xE000 else { return nil }
                            Self.appendUTF8(&out, 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00))
                        } else if u >= 0xDC00 && u < 0xE000 {
                            return nil
                        } else {
                            Self.appendUTF8(&out, u)
                        }
                    default: return nil
                    }
                    continue
                }
                if c < 0x80 { out.append(c); i += 1; continue }
                guard let n = Self.utf8Len(b, i) else { return nil }
                out.append(contentsOf: b[i..<(i + n)])
                i += n
            }
            return nil
        }

        /// Length of the valid UTF-8 sequence at b[i] (nil: invalid, Go's utf8.DecodeRune would give RuneError/1).
        static func utf8Len(_ b: [UInt8], _ i: Int) -> Int? {
            let c = b[i]
            func cont(_ k: Int, _ lo: UInt8 = 0x80, _ hi: UInt8 = 0xBF) -> Bool { i + k < b.count && b[i + k] >= lo && b[i + k] <= hi }
            switch c {
            case 0xC2...0xDF: return cont(1) ? 2 : nil
            case 0xE0: return cont(1, 0xA0) && cont(2) ? 3 : nil
            case 0xE1...0xEC, 0xEE...0xEF: return cont(1) && cont(2) ? 3 : nil
            case 0xED: return cont(1, 0x80, 0x9F) && cont(2) ? 3 : nil
            case 0xF0: return cont(1, 0x90) && cont(2) && cont(3) ? 4 : nil
            case 0xF1...0xF3: return cont(1) && cont(2) && cont(3) ? 4 : nil
            case 0xF4: return cont(1, 0x80, 0x8F) && cont(2) && cont(3) ? 4 : nil
            default: return nil
            }
        }
    }

    /// Valid UTF-8 the way Go's utf8.Valid sees it.
    static func validUTF8(_ b: [UInt8]) -> Bool {
        var i = 0
        while i < b.count {
            if b[i] < 0x80 { i += 1; continue }
            guard let n = Parser.utf8Len(b, i) else { return false }
            i += n
        }
        return true
    }

    // MARK: encode (encodeJSON: json.Encoder, SetEscapeHTML(false), trailing newline trimmed)

    /// nil when the tree still holds a delete marker (never happens after a completed delpaths).
    func encoded() -> Data? {
        var out: [UInt8] = []
        out.reserveCapacity(1024)
        guard encode(into: &out) else { return nil }
        return Data(out)
    }

    private static let hex: [UInt8] = Array("0123456789abcdef".utf8)

    static func encodeString(_ s: [UInt8], into out: inout [UInt8]) {
        out.append(UInt8(ascii: "\""))
        var i = 0
        while i < s.count {
            let c = s[i]
            if c < 0x80 {
                switch c {
                case UInt8(ascii: "\\"), UInt8(ascii: "\""): out.append(UInt8(ascii: "\\")); out.append(c)
                case 0x08: out.append(UInt8(ascii: "\\")); out.append(UInt8(ascii: "b"))
                case 0x0C: out.append(UInt8(ascii: "\\")); out.append(UInt8(ascii: "f"))
                case 0x0A: out.append(UInt8(ascii: "\\")); out.append(UInt8(ascii: "n"))
                case 0x0D: out.append(UInt8(ascii: "\\")); out.append(UInt8(ascii: "r"))
                case 0x09: out.append(UInt8(ascii: "\\")); out.append(UInt8(ascii: "t"))
                case 0..<0x20:
                    out.append(contentsOf: [UInt8(ascii: "\\"), UInt8(ascii: "u"), UInt8(ascii: "0"), UInt8(ascii: "0"), hex[Int(c >> 4)], hex[Int(c & 0xF)]])
                default: out.append(c)
                }
                i += 1
                continue
            }
            guard let n = Parser.utf8Len(s, i) else {
                out.append(contentsOf: Array("\\ufffd".utf8)) // unreachable for parsed input; Go's rule
                i += 1
                continue
            }
            // U+2028 / U+2029 = E2 80 A8 / E2 80 A9
            if n == 3 && c == 0xE2 && s[i + 1] == 0x80 && (s[i + 2] == 0xA8 || s[i + 2] == 0xA9) {
                out.append(contentsOf: Array("\\u202".utf8))
                out.append(s[i + 2] == 0xA8 ? UInt8(ascii: "8") : UInt8(ascii: "9"))
            } else {
                out.append(contentsOf: s[i..<(i + n)])
            }
            i += n
        }
        out.append(UInt8(ascii: "\""))
    }

    /// Go's map key order: bytewise (strings.Compare).
    static func keyLess(_ a: [UInt8], _ b: [UInt8]) -> Bool { a.lexicographicallyPrecedes(b) }

    private func encode(into out: inout [UInt8]) -> Bool {
        switch self {
        case .null: out.append(contentsOf: Array("null".utf8))
        case .bool(let v): out.append(contentsOf: Array((v ? "true" : "false").utf8))
        case .number(let n): out.append(contentsOf: n.isEmpty ? [UInt8(ascii: "0")] : n)
        case .string(let s): Self.encodeString(s, into: &out)
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (k, v) in a.enumerated() {
                if k > 0 { out.append(UInt8(ascii: ",")) }
                guard v.encode(into: &out) else { return false }
            }
            out.append(UInt8(ascii: "]"))
        case .object(let m):
            out.append(UInt8(ascii: "{"))
            for (k, key) in m.keys.sorted(by: Self.keyLess).enumerated() {
                if k > 0 { out.append(UInt8(ascii: ",")) }
                Self.encodeString(key, into: &out)
                out.append(UInt8(ascii: ":"))
                guard m[key]!.encode(into: &out) else { return false }
            }
            out.append(UInt8(ascii: "}"))
        case .deleted: return false
        }
        return true
    }
}

/// One path component (string key or array index) as Go exported it.
enum BodyJSONKey: Decodable, Equatable {
    case key([UInt8])
    case index(Int)

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let i = try? c.decode(Int.self) { self = .index(i); return }
        self = .key(Array(try c.decode(String.self).utf8))
    }
}

// MARK: - Loon json ops (handler.go jsonEdit)

enum BodyJSONEdit {
    /// jsonEdit(v, p, op, val), Go semantics.
    static func edit(_ v: BodyJSON, _ p: ArraySlice<BodyJSONKey>, _ op: String, _ val: BodyJSON) -> BodyJSON {
        guard let first = p.first else {
            return (op == "replace" || op == "add") ? val : v
        }
        switch first {
        case .key(let key):
            guard case .object(var m) = v else { return v }
            if p.count == 1 {
                switch op {
                case "del": m.removeValue(forKey: key)
                case "replace": if m[key] != nil { m[key] = val }
                case "add": m[key] = val
                default: break
                }
                return .object(m)
            }
            if let child = m[key] {
                m[key] = edit(child, p.dropFirst(), op, val)
            } else if op == "add" {
                m[key] = edit(.object([:]), p.dropFirst(), op, val)
            }
            return .object(m)
        case .index(let key):
            guard case .array(var a) = v, key >= 0, key < a.count else { return v }
            if p.count == 1 {
                if op == "del" { a.remove(at: key) } else { a[key] = val }
                return .array(a)
            }
            a[key] = edit(a[key], p.dropFirst(), op, val)
            return .array(a)
        }
    }
}

// MARK: - legacy jq step lists (snapshots without `jqx`; full jq filters run in NativeJQ.swift)

enum BodyJQ {
    struct Failure: Error {}
    static let maxIndex = 0x20000000

    /// update(v, path, n): n == .deleted marks for delpaths. Throws where jq errors.
    static func update(_ v: BodyJSON, _ path: ArraySlice<BodyJSONKey>, _ n: BodyJSON) throws -> BodyJSON {
        guard let first = path.first else { return n }
        let deleting = n == .deleted
        switch first {
        case .key(let k):
            var m: [[UInt8]: BodyJSON]
            switch v {
            case .null: m = [:]
            case .object(let o): m = o
            case .deleted: return v
            default: throw Failure()
            }
            let x = m[k]
            if x == nil && deleting {
                if case .null = v { return .null }
                return v
            }
            m[k] = try update(x ?? .null, path.dropFirst(), n)
            return .object(m)
        case .index(let i0):
            var a: [BodyJSON]
            switch v {
            case .null: a = []
            case .array(let arr): a = arr
            case .deleted: return v
            default: throw Failure()
            }
            var i = i0
            // clampIndex(i, -1, len)
            var j = i
            if j < 0 { j += a.count; if j < 0 { j = -1 } }
            if j > a.count { j = a.count }
            if j < 0 {
                if deleting { if case .null = v { return .null }; return v }
                throw Failure()
            }
            var x = BodyJSON.null
            if j < a.count {
                i = j
                x = a[i]
            } else {
                if deleting { if case .null = v { return .null }; return v }
                if i >= maxIndex { throw Failure() }
            }
            let u = try update(x, path.dropFirst(), n)
            if i >= a.count { a.append(contentsOf: repeatElement(BodyJSON.null, count: i + 1 - a.count)) }
            a[i] = u
            return .array(a)
        }
    }

    /// deleteEmpty: drops the markers left by delpaths.
    static func deleteEmpty(_ v: BodyJSON) -> BodyJSON {
        switch v {
        case .deleted: return .null
        case .object(let m):
            var o: [[UInt8]: BodyJSON] = [:]
            for (k, w) in m where w != .deleted { o[k] = deleteEmpty(w) }
            return .object(o)
        case .array(let a):
            return .array(a.filter { $0 != .deleted }.map(deleteEmpty))
        default:
            return v
        }
    }

    static func setpath(_ v: BodyJSON, _ path: [BodyJSONKey], _ n: BodyJSON) throws -> BodyJSON {
        try update(v, path[...], n)
    }

    static func delpaths(_ v: BodyJSON, _ paths: [[BodyJSONKey]]) throws -> BodyJSON {
        if paths.isEmpty { return v }
        var u = v
        for p in paths { u = try update(u, p[...], .deleted) }
        return deleteEmpty(u)
    }

    // MARK: P |= map(select(C)) (_modify with getpath, map = [.[] | f], select = if f then . else empty end)

    indirect enum Cond {
        case or(Cond, Cond), and(Cond, Cond), not(Cond)
        case eq([BodyJSONKey], BodyJSON), ne([BodyJSONKey], BodyJSON)
        case truthy([BodyJSONKey])
        case has([BodyJSONKey], [UInt8])

        init?(_ c: RWSnapJQCond) {
            switch c.k {
            case "or", "and":
                guard let a = c.a.flatMap(Cond.init), let b = c.b.flatMap(Cond.init) else { return nil }
                self = c.k == "or" ? .or(a, b) : .and(a, b)
            case "not":
                guard let a = c.a.flatMap(Cond.init) else { return nil }
                self = .not(a)
            case "eq", "ne":
                guard let vs = c.v, let v = BodyJSON.parse(vs) else { return nil }
                switch v {
                case .string, .bool, .null: break
                default: return nil // numbers compare numerically in jq
                }
                self = c.k == "eq" ? .eq(c.p ?? [], v) : .ne(c.p ?? [], v)
            case "truthy": self = .truthy(c.p ?? [])
            case "has":
                guard let k = c.key else { return nil }
                self = .has(c.p ?? [], Array(k.utf8))
            default: return nil
            }
        }
    }

    /// `.a.b` / `.[n]` on a value: null for null / missing / out of range; an error for any other type.
    static func get(_ v: BodyJSON, _ p: [BodyJSONKey]) throws -> BodyJSON {
        var cur = v
        for k in p {
            switch (k, cur) {
            case (_, .null): cur = .null
            case (.key(let s), .object(let m)): cur = m[s] ?? .null
            case (.index(let i), .array(let a)):
                let j = i < 0 ? i + a.count : i
                cur = (j >= 0 && j < a.count) ? a[j] : .null
            default: throw Failure()
            }
        }
        return cur
    }

    static func truthy(_ v: BodyJSON) -> Bool {
        switch v {
        case .null, .bool(false): return false
        default: return true
        }
    }

    static func eval(_ c: Cond, _ x: BodyJSON) throws -> Bool {
        switch c {
        case .or(let a, let b): return try eval(a, x) || eval(b, x)
        case .and(let a, let b): return try eval(a, x) && eval(b, x)
        case .not(let a): return !(try eval(a, x))
        case .eq(let p, let v): return try get(x, p) == v
        case .ne(let p, let v): return try get(x, p) != v
        case .truthy(let p): return truthy(try get(x, p))
        case .has(let p, let k):
            switch try get(x, p) {
            case .object(let m): return m[k] != nil
            case .null: return false
            default: throw Failure()
            }
        }
    }

    static func filter(_ v: BodyJSON, _ path: [BodyJSONKey], _ c: Cond) throws -> BodyJSON {
        guard case .array(let a) = try get(v, path) else { throw Failure() } // map over an object / null / scalar: Go
        let kept = try a.filter { try eval(c, $0) }
        return try setpath(v, path, .array(kept))
    }
}
