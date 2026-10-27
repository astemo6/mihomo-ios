// Native jq (fix/nc-jq-full) — a pure-Swift jq interpreter for body rewrites:
//   Surge  http-request-jq / http-response-jq <regex> '<filter>' | jq-path="<url>"
//   Loon   <regex> request-body-json-jq / response-body-json-jq '<filter>' | jq-path="<url>"
//   QX     <regex> url jsonjq-request-body / jsonjq-response-body '<filter>' | jq-path=<url>
//   Egern  body_rewrites: - request_jq / response_jq: {match, filter}   (filter may be a URL of a .jq file)
//
// Semantics follow the real jq 1.7.1 CLI (`jq -c`), which is the oracle the unit-test fixtures were generated with
// (UnitTests/NativeCoreJQFixtures.json): object keys keep insertion order, number literals keep their canonical
// literal text until arithmetic touches them ("1.000" stays "1.000", "1e2" prints "1E+2"), computed doubles print
// with jq's shortest-digits format (1e+17, 0.30000000000000004), `|= empty` deletes, `//` does not swallow errors,
// errors raised downstream of a `try` are not caught by it, string offsets of indices/index are byte offsets.
//
// Memory: the body is parsed once into JQValue (copy-on-write arrays / ordered objects), the filter runs as a
// callback-driven generator (no output buffering except where jq semantics need it: `[...]`, reduce state,
// path lists of assignments), and only the first output is encoded. Programs are compiled once per rule and shared.
//
// This file: values, ordering, JSON in/out, number formatting, the parser. NativeJQEval.swift: evaluation + builtins.

import Foundation

// MARK: - Values

struct JQObject {
    var keys: [String] = []
    var dict: [String: JQValue] = [:]

    init() {}
    subscript(_ k: String) -> JQValue? { dict[k] }
    var count: Int { keys.count }

    mutating func set(_ k: String, _ v: JQValue) {
        if dict.updateValue(v, forKey: k) == nil { keys.append(k) }
    }

    mutating func remove(_ k: String) {
        if dict.removeValue(forKey: k) != nil, let i = keys.firstIndex(of: k) { keys.remove(at: i) }
    }

    var sortedKeys: [String] { keys.sorted { JQValue.bytesLess($0, $1) } }
}

enum JQValue {
    case null
    case bool(Bool)
    /// value, canonical literal text (only while the number is unchanged since it was parsed)
    case number(Double, String?)
    case string(String)
    case array([JQValue])
    case object(JQObject)

    static func num(_ d: Double) -> JQValue { .number(d, nil) }
    static func num(_ i: Int) -> JQValue { .number(Double(i), nil) }

    var typeName: String {
        switch self {
        case .null: return "null"
        case .bool: return "boolean"
        case .number: return "number"
        case .string: return "string"
        case .array: return "array"
        case .object: return "object"
        }
    }

    var truthy: Bool {
        switch self {
        case .null, .bool(false): return false
        default: return true
        }
    }

    /// jq kind order: null < false < true < number < string < array < object
    var rank: Int {
        switch self {
        case .null: return 0
        case .bool(let b): return b ? 2 : 1
        case .number: return 3
        case .string: return 4
        case .array: return 5
        case .object: return 6
        }
    }

    static func bytesLess(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }

    static func bytesCmp(_ a: String, _ b: String) -> Int {
        var ia = a.utf8.makeIterator(), ib = b.utf8.makeIterator()
        while true {
            switch (ia.next(), ib.next()) {
            case (nil, nil): return 0
            case (nil, _): return -1
            case (_, nil): return 1
            case (let x?, let y?): if x != y { return x < y ? -1 : 1 }
            }
        }
    }

    /// jv_cmp
    static func cmp(_ a: JQValue, _ b: JQValue) -> Int {
        let ra = a.rank, rb = b.rank
        if ra != rb { return ra < rb ? -1 : 1 }
        switch (a, b) {
        case (.number(let x, _), .number(let y, _)):
            if x.isNaN { return -1 }
            if y.isNaN { return 1 }
            return x < y ? -1 : (x == y ? 0 : 1)
        case (.string(let x), .string(let y)):
            return bytesCmp(x, y)
        case (.array(let x), .array(let y)):
            var i = 0
            while i < x.count && i < y.count {
                let c = cmp(x[i], y[i])
                if c != 0 { return c }
                i += 1
            }
            return x.count == y.count ? 0 : (x.count < y.count ? -1 : 1)
        case (.object(let x), .object(let y)):
            let kx = x.sortedKeys, ky = y.sortedKeys
            let c = cmp(.array(kx.map { .string($0) }), .array(ky.map { .string($0) }))
            if c != 0 { return c }
            for k in kx {
                let c2 = cmp(x[k]!, y[k]!)
                if c2 != 0 { return c2 }
            }
            return 0
        default:
            return 0
        }
    }

    static func equal(_ a: JQValue, _ b: JQValue) -> Bool { cmp(a, b) == 0 }
}

// MARK: - Errors

struct JQError: Error {
    let value: JQValue
    init(_ value: JQValue) { self.value = value }
    init(_ msg: String) { value = .string(msg) }

    var message: String {
        if case .string(let s) = value { return s }
        return JQOut.dump(value) + " (not a string)"
    }
}

/// `break $label` / limit / first: unwinds to the label instance with this id.
struct JQBreak: Error { let id: Int }
/// An error raised downstream of a `try`, carried through its body untouched.
struct JQPass: Error { let id: Int; let inner: JQError }
/// Budget / depth exhaustion: never caught by try.
struct JQAbort: Error { let reason: String }
/// A syntax / compile error.
struct JQCompileError: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}

// MARK: - Numbers

enum JQNum {
    /// decNumber to-scientific-string of a JSON / jq number literal (what jq 1.7 prints for an unchanged literal).
    static func canonical(_ t: [UInt8]) -> String? {
        var i = 0
        var neg = false
        if i < t.count && t[i] == UInt8(ascii: "-") { neg = true; i += 1 }
        var intPart: [UInt8] = []
        while i < t.count, t[i] >= 0x30 && t[i] <= 0x39 { intPart.append(t[i]); i += 1 }
        var frac: [UInt8] = []
        if i < t.count && t[i] == UInt8(ascii: ".") {
            i += 1
            while i < t.count, t[i] >= 0x30 && t[i] <= 0x39 { frac.append(t[i]); i += 1 }
        }
        if intPart.isEmpty && frac.isEmpty { return nil }
        var exp = 0
        if i < t.count && (t[i] == UInt8(ascii: "e") || t[i] == UInt8(ascii: "E")) {
            i += 1
            var eneg = false
            if i < t.count && (t[i] == UInt8(ascii: "+") || t[i] == UInt8(ascii: "-")) { eneg = t[i] == UInt8(ascii: "-"); i += 1 }
            var any = false
            while i < t.count, t[i] >= 0x30 && t[i] <= 0x39 {
                any = true
                if exp < 100_000_000 { exp = exp * 10 + Int(t[i] - 0x30) }
                i += 1
            }
            if !any { return nil }
            if eneg { exp = -exp }
        }
        if i != t.count { return nil }
        var coef = intPart + frac
        while coef.count > 1 && coef[0] == 0x30 { coef.removeFirst() }
        if coef.isEmpty { coef = [0x30] }
        let e = exp - frac.count
        let c = String(decoding: coef, as: UTF8.self)
        var out = neg ? "-" : ""
        if e == 0 { return out + c }
        let ae = e + coef.count - 1
        if e < 0 && ae >= -6 {
            let n = coef.count
            if n > -e {
                out += String(c.prefix(n + e)) + "." + String(c.suffix(-e))
            } else {
                out += "0." + String(repeating: "0", count: -e - n) + c
            }
            return out
        }
        out += String(c.prefix(1))
        if coef.count > 1 { out += "." + String(c.dropFirst()) }
        out += "E" + (ae >= 0 ? "+" : "-") + String(abs(ae))
        return out
    }

    /// jq's dtoa format for a computed double.
    static func format(_ d: Double) -> String {
        if d.isNaN { return "null" }
        if d.isInfinite { return d > 0 ? "1.7976931348623157e+308" : "-1.7976931348623157e+308" }
        if d == 0 { return d.sign == .minus ? "-0" : "0" }
        let s = "\(Swift.abs(d))"
        var mant = Substring(s)
        var exp = 0
        if let e = s.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mant = s[s.startIndex..<e]
            exp = Int(s[s.index(after: e)...]) ?? 0
        }
        var digits: [UInt8] = []
        var point = -1
        for c in mant.utf8 {
            if c == UInt8(ascii: ".") { point = digits.count } else { digits.append(c) }
        }
        if point < 0 { point = digits.count }
        var decpt = point + exp
        while let f = digits.first, f == 0x30, digits.count > 1 { digits.removeFirst(); decpt -= 1 }
        while let l = digits.last, l == 0x30, digits.count > 1 { digits.removeLast() }
        let nd = digits.count
        let ds = String(decoding: digits, as: UTF8.self)
        var out = d < 0 ? "-" : ""
        if decpt <= -4 || decpt > nd + 15 {
            out += String(ds.prefix(1))
            if nd > 1 { out += "." + String(ds.dropFirst()) }
            let x = decpt - 1
            out += "e" + (x < 0 ? "-" : "+")
            let ax = Swift.abs(x)
            out += ax < 10 ? "0\(ax)" : "\(ax)"
        } else if decpt <= 0 {
            out += "0." + String(repeating: "0", count: -decpt) + ds
        } else if decpt >= nd {
            out += ds + String(repeating: "0", count: decpt - nd)
        } else {
            out += String(ds.prefix(decpt)) + "." + String(ds.dropFirst(decpt))
        }
        return out
    }

    /// Double → Int without trapping (NaN → 0, clamped).
    static func toInt(_ d: Double) -> Int {
        if d.isNaN { return 0 }
        if d >= 9.0e18 { return 9_000_000_000_000_000_000 }
        if d <= -9.0e18 { return -9_000_000_000_000_000_000 }
        return Int(d)
    }
}

// MARK: - JSON output (jq -c)

enum JQOut {
    static func dump(_ v: JQValue) -> String {
        var b: [UInt8] = []
        b.reserveCapacity(256)
        dump(v, into: &b)
        return String(decoding: b, as: UTF8.self)
    }

    static func dumpData(_ v: JQValue) -> Data {
        var b: [UInt8] = []
        b.reserveCapacity(4096)
        dump(v, into: &b)
        return Data(b)
    }

    private static let hex: [UInt8] = Array("0123456789abcdef".utf8)

    static func string(_ s: String, into b: inout [UInt8]) {
        b.append(0x22)
        for c in s.utf8 {
            switch c {
            case 0x22: b.append(0x5C); b.append(0x22)
            case 0x5C: b.append(0x5C); b.append(0x5C)
            case 0x08: b.append(0x5C); b.append(UInt8(ascii: "b"))
            case 0x0C: b.append(0x5C); b.append(UInt8(ascii: "f"))
            case 0x0A: b.append(0x5C); b.append(UInt8(ascii: "n"))
            case 0x0D: b.append(0x5C); b.append(UInt8(ascii: "r"))
            case 0x09: b.append(0x5C); b.append(UInt8(ascii: "t"))
            case 0..<0x20, 0x7F:
                b.append(contentsOf: [0x5C, UInt8(ascii: "u"), 0x30, 0x30, hex[Int(c >> 4)], hex[Int(c & 0xF)]])
            default: b.append(c)
            }
        }
        b.append(0x22)
    }

    static func dump(_ v: JQValue, into b: inout [UInt8]) {
        switch v {
        case .null: b.append(contentsOf: [0x6E, 0x75, 0x6C, 0x6C])
        case .bool(let x): b.append(contentsOf: Array((x ? "true" : "false").utf8))
        case .number(let d, let lit):
            if let lit { b.append(contentsOf: Array(lit.utf8)) } else { b.append(contentsOf: Array(JQNum.format(d).utf8)) }
        case .string(let s): string(s, into: &b)
        case .array(let a):
            b.append(UInt8(ascii: "["))
            for (i, e) in a.enumerated() {
                if i > 0 { b.append(UInt8(ascii: ",")) }
                dump(e, into: &b)
            }
            b.append(UInt8(ascii: "]"))
        case .object(let o):
            b.append(UInt8(ascii: "{"))
            for (i, k) in o.keys.enumerated() {
                if i > 0 { b.append(UInt8(ascii: ",")) }
                string(k, into: &b)
                b.append(UInt8(ascii: ":"))
                dump(o.dict[k]!, into: &b)
            }
            b.append(UInt8(ascii: "}"))
        }
    }

    /// jv_dump_string_trunc (error messages): at most 11 bytes + "..." when longer than 14.
    static func trunc(_ v: JQValue) -> String {
        let s = Array(dump(v).utf8)
        if s.count <= 14 { return String(decoding: s, as: UTF8.self) }
        return String(decoding: s[0..<11], as: UTF8.self) + "..."
    }

    static func typed(_ v: JQValue) -> String { "\(v.typeName) (\(trunc(v)))" }
}

// MARK: - JSON input

struct JQJSONParser {
    let b: [UInt8]
    var i = 0
    static let maxDepth = 2000

    init(_ bytes: [UInt8]) { b = bytes }

    static func parse(_ data: Data) throws -> JQValue {
        var p = JQJSONParser([UInt8](data))
        return try p.document()
    }

    static func parse(_ s: String) throws -> JQValue {
        var p = JQJSONParser(Array(s.utf8))
        return try p.document()
    }

    mutating func document() throws -> JQValue {
        skipWS()
        let v = try value(0)
        skipWS()
        if i != b.count { throw JQError("Unexpected extra JSON values") }
        return v
    }

    mutating func skipWS() {
        while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 }
    }

    func fail(_ m: String) -> JQError { JQError("\(m) at offset \(i)") }

    mutating func lit(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard i + u.count <= b.count, Array(b[i..<(i + u.count)]) == u else { return false }
        i += u.count
        return true
    }

    mutating func value(_ depth: Int) throws -> JQValue {
        guard i < b.count else { throw fail("Unfinished JSON term") }
        switch b[i] {
        case UInt8(ascii: "{"):
            guard depth < Self.maxDepth else { throw fail("Exceeds depth limit for parsing") }
            i += 1
            var o = JQObject()
            skipWS()
            if i < b.count && b[i] == UInt8(ascii: "}") { i += 1; return .object(o) }
            while true {
                skipWS()
                guard i < b.count, b[i] == 0x22 else { throw fail("Object keys must be strings") }
                let k = try string()
                skipWS()
                guard i < b.count, b[i] == UInt8(ascii: ":") else { throw fail("Objects must consist of key:value pairs") }
                i += 1
                skipWS()
                o.set(k, try value(depth + 1))
                skipWS()
                guard i < b.count else { throw fail("Unfinished JSON term") }
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                if b[i] == UInt8(ascii: "}") { i += 1; return .object(o) }
                throw fail("Expected separator between values")
            }
        case UInt8(ascii: "["):
            guard depth < Self.maxDepth else { throw fail("Exceeds depth limit for parsing") }
            i += 1
            var a: [JQValue] = []
            skipWS()
            if i < b.count && b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
            while true {
                skipWS()
                a.append(try value(depth + 1))
                skipWS()
                guard i < b.count else { throw fail("Unfinished JSON term") }
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                if b[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
                throw fail("Expected separator between values")
            }
        case 0x22:
            return .string(try string())
        case UInt8(ascii: "t"): if lit("true") { return .bool(true) }; throw fail("Invalid literal")
        case UInt8(ascii: "f"): if lit("false") { return .bool(false) }; throw fail("Invalid literal")
        case UInt8(ascii: "n"):
            if lit("null") { return .null }
            if lit("nan") { return .num(Double.nan) }
            throw fail("Invalid literal")
        default:
            return try number()
        }
    }

    static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    mutating func number() throws -> JQValue {
        let start = i
        if i < b.count && b[i] == UInt8(ascii: "-") { i += 1 }
        guard i < b.count, Self.isDigit(b[i]) else { throw fail("Invalid numeric literal") }
        if b[i] == 0x30 { i += 1 } else { while i < b.count && Self.isDigit(b[i]) { i += 1 } }
        if i < b.count && b[i] == UInt8(ascii: ".") {
            i += 1
            guard i < b.count, Self.isDigit(b[i]) else { throw fail("Invalid numeric literal") }
            while i < b.count && Self.isDigit(b[i]) { i += 1 }
        }
        if i < b.count && (b[i] == UInt8(ascii: "e") || b[i] == UInt8(ascii: "E")) {
            i += 1
            if i < b.count && (b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-")) { i += 1 }
            guard i < b.count, Self.isDigit(b[i]) else { throw fail("Invalid numeric literal") }
            while i < b.count && Self.isDigit(b[i]) { i += 1 }
        }
        let t = Array(b[start..<i])
        let d = Double(String(decoding: t, as: UTF8.self)) ?? 0
        return .number(d, JQNum.canonical(t))
    }

    static func hexVal(_ c: UInt8) -> UInt32? {
        switch c {
        case 0x30...0x39: return UInt32(c - 0x30)
        case 0x41...0x46: return UInt32(c - 0x41 + 10)
        case 0x61...0x66: return UInt32(c - 0x61 + 10)
        default: return nil
        }
    }

    mutating func hex4() throws -> UInt32 {
        guard i + 4 <= b.count else { throw fail("Invalid escape") }
        var v: UInt32 = 0
        for k in 0..<4 {
            guard let h = Self.hexVal(b[i + k]) else { throw fail("Invalid escape") }
            v = v << 4 | h
        }
        i += 4
        return v
    }

    static func appendScalar(_ out: inout [UInt8], _ c: UInt32) {
        let u = Unicode.Scalar(c) ?? Unicode.Scalar(0xFFFD)!
        out.append(contentsOf: Array(String(Character(u)).utf8))
    }

    mutating func string() throws -> String {
        i += 1
        var out: [UInt8] = []
        var start = i
        while i < b.count {
            let c = b[i]
            if c == 0x22 {
                out.append(contentsOf: b[start..<i])
                i += 1
                return String(decoding: out, as: UTF8.self)
            }
            if c == 0x5C {
                out.append(contentsOf: b[start..<i])
                i += 1
                guard i < b.count else { throw fail("Unfinished string") }
                let e = b[i]
                i += 1
                switch e {
                case 0x22, 0x5C, UInt8(ascii: "/"): out.append(e)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    let u = try hex4()
                    if u >= 0xD800 && u < 0xDC00 {
                        if i + 6 <= b.count, b[i] == 0x5C, b[i + 1] == UInt8(ascii: "u") {
                            let save = i
                            i += 2
                            let l = try hex4()
                            if l >= 0xDC00 && l < 0xE000 {
                                Self.appendScalar(&out, 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00))
                            } else {
                                Self.appendScalar(&out, 0xFFFD)
                                i = save
                            }
                        } else {
                            Self.appendScalar(&out, 0xFFFD)
                        }
                    } else if u >= 0xDC00 && u < 0xE000 {
                        Self.appendScalar(&out, 0xFFFD)
                    } else {
                        Self.appendScalar(&out, u)
                    }
                default: throw fail("Invalid escape")
                }
                start = i
                continue
            }
            if c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D { throw fail("Invalid string: control characters from U+0000 through U+001F must be escaped") }
            i += 1
        }
        throw fail("Unfinished string")
    }
}

// MARK: - AST

final class JQFuncDef {
    let name: String
    let params: [(name: String, isVar: Bool)]
    let body: JQNode
    var key: String { "\(name)/\(params.count)" }
    init(name: String, params: [(name: String, isVar: Bool)], body: JQNode) {
        self.name = name; self.params = params; self.body = body
    }
}

enum JQBinOp { case add, sub, mul, div, mod, eq, ne, lt, le, gt, ge }
enum JQAssignOp { case set, update, arith(JQBinOp), alt }

enum JQStrPart { case lit(String), interp(JQNode) }

enum JQObjKey {
    case name(String)
    case variable(String)
    case expr(JQNode)
    case loc(Int)
}

struct JQObjEntry {
    let key: JQObjKey
    let value: JQNode?
}

indirect enum JQPattern {
    case variable(String)
    case array([JQPattern])
    case object([(key: JQObjKey, pattern: JQPattern?)])
}

indirect enum JQNode {
    case identity
    case recurseAll
    case literal(JQValue)
    case index(JQNode, JQNode)
    case slice(JQNode, JQNode?, JQNode?)
    case iterate(JQNode)
    case optional(JQNode)
    case pipe(JQNode, JQNode)
    case comma(JQNode, JQNode)
    case neg(JQNode)
    case binop(JQBinOp, JQNode, JQNode)
    case and(JQNode, JQNode)
    case or(JQNode, JQNode)
    case alt(JQNode, JQNode)
    case assign(JQAssignOp, JQNode, JQNode)
    case ifte([(JQNode, JQNode)], JQNode?)
    case tryCatch(JQNode, JQNode?)
    case reduce(JQNode, JQPattern, JQNode, JQNode)
    case foreach(JQNode, JQPattern, JQNode, JQNode, JQNode?)
    case funcDef(JQFuncDef, JQNode)
    case call(String, [JQNode])
    case variable(String)
    case bind(JQNode, JQPattern, JQNode)
    case label(String, JQNode)
    case breakLabel(String)
    case array(JQNode?)
    case object([JQObjEntry])
    case string([JQStrPart], String?)
    case format(String)
    case loc(Int)
}

// MARK: - Parser

struct JQParser {
    let s: [UInt8]
    var i = 0
    var depth = 0

    static let keywords: Set<String> = ["def", "if", "then", "elif", "else", "end", "as", "reduce", "foreach", "try", "catch",
                                        "label", "import", "include", "and", "or", "__loc__"]

    init(_ src: String) { s = Array(src.utf8) }

    static func parse(_ src: String) throws -> JQNode {
        var p = JQParser(src)
        let n = try p.pipe()
        p.ws()
        if p.i < p.s.count { throw p.err("unexpected input") }
        return n
    }

    func err(_ m: String) -> JQCompileError {
        var line = 1
        for k in 0..<min(i, s.count) where s[k] == 0x0A { line += 1 }
        let near = String(decoding: s[min(i, s.count)..<min(i + 16, s.count)], as: UTF8.self)
        return JQCompileError(message: "syntax error: \(m) at line \(line) near '\(near)'")
    }

    var line: Int {
        var l = 1
        for k in 0..<min(i, s.count) where s[k] == 0x0A { l += 1 }
        return l
    }

    func peek(_ o: Int = 0) -> UInt8? { i + o < s.count ? s[i + o] : nil }

    mutating func ws() {
        while i < s.count {
            let c = s[i]
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1; continue }
            if c == UInt8(ascii: "#") {
                while i < s.count && s[i] != 0x0A { i += 1 }
                continue
            }
            break
        }
    }

    static func isIdentStart(_ c: UInt8) -> Bool { (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F }
    static func isIdent(_ c: UInt8) -> Bool { isIdentStart(c) || (c >= 0x30 && c <= 0x39) }
    static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    func startsWith(_ t: String) -> Bool {
        let u = Array(t.utf8)
        guard i + u.count <= s.count else { return false }
        for k in 0..<u.count where s[i + k] != u[k] { return false }
        return true
    }

    mutating func eat(_ t: String) -> Bool {
        ws()
        if startsWith(t) { i += t.utf8.count; return true }
        return false
    }

    mutating func expect(_ t: String) throws {
        if !eat(t) { throw err("expected '\(t)'") }
    }

    func peekKeyword(_ kw: String) -> Bool {
        guard startsWith(kw) else { return false }
        let j = i + kw.utf8.count
        return j >= s.count || !Self.isIdent(s[j])
    }

    mutating func keyword(_ kw: String) -> Bool {
        ws()
        if peekKeyword(kw) { i += kw.utf8.count; return true }
        return false
    }

    mutating func ident() -> String? {
        guard let c = peek(), Self.isIdentStart(c) else { return nil }
        let st = i
        while i < s.count && (Self.isIdent(s[i]) || (s[i] == UInt8(ascii: ":") && i + 1 < s.count && s[i + 1] == UInt8(ascii: ":"))) {
            if s[i] == UInt8(ascii: ":") { i += 2 } else { i += 1 }
        }
        return String(decoding: s[st..<i], as: UTF8.self)
    }

    mutating func enter() throws {
        depth += 1
        if depth > 400 { throw err("nesting too deep") }
    }

    // pipe: def … ; pipe | comma ('|' pipe)?
    mutating func pipe() throws -> JQNode {
        try enter(); defer { depth -= 1 }
        ws()
        if peekKeyword("def") {
            i += 3
            let d = try funcDefRest()
            let rest = try pipe()
            return .funcDef(d, rest)
        }
        let lhs = try comma()
        ws()
        if peek() == UInt8(ascii: "|") && peek(1) != UInt8(ascii: "=") {
            i += 1
            return .pipe(lhs, try pipe())
        }
        return lhs
    }

    mutating func funcDefRest() throws -> JQFuncDef {
        ws()
        guard let name = ident(), !Self.keywords.contains(name) else { throw err("function name") }
        var params: [(name: String, isVar: Bool)] = []
        if eat("(") {
            repeat {
                ws()
                if peek() == UInt8(ascii: "$") {
                    i += 1
                    guard let n = ident() else { throw err("parameter") }
                    params.append((n, true))
                } else {
                    guard let n = ident(), !Self.keywords.contains(n) else { throw err("parameter") }
                    params.append((n, false))
                }
            } while eat(";")
            try expect(")")
        }
        try expect(":")
        let body = try pipe()
        try expect(";")
        return JQFuncDef(name: name, params: params, body: body)
    }

    mutating func comma() throws -> JQNode {
        var lhs = try alt()
        while true {
            ws()
            if peek() == UInt8(ascii: ",") { i += 1; lhs = .comma(lhs, try alt()) } else { return lhs }
        }
    }

    mutating func alt() throws -> JQNode {
        let lhs = try assign()
        ws()
        if startsWith("//") && !startsWith("//=") {
            i += 2
            return .alt(lhs, try alt())
        }
        return lhs
    }

    mutating func assign() throws -> JQNode {
        let lhs = try orExpr()
        ws()
        let ops: [(String, JQAssignOp)] = [("|=", .update), ("+=", .arith(.add)), ("-=", .arith(.sub)), ("*=", .arith(.mul)),
                                           ("/=", .arith(.div)), ("%=", .arith(.mod)), ("//=", .alt)]
        for (t, op) in ops where startsWith(t) {
            i += t.utf8.count
            return .assign(op, lhs, try orExpr())
        }
        if peek() == UInt8(ascii: "=") && peek(1) != UInt8(ascii: "=") {
            i += 1
            return .assign(.set, lhs, try orExpr())
        }
        return lhs
    }

    mutating func orExpr() throws -> JQNode {
        var lhs = try andExpr()
        while keyword("or") { lhs = .or(lhs, try andExpr()) }
        return lhs
    }

    mutating func andExpr() throws -> JQNode {
        var lhs = try compare()
        while keyword("and") { lhs = .and(lhs, try compare()) }
        return lhs
    }

    mutating func compare() throws -> JQNode {
        let lhs = try additive()
        ws()
        let ops: [(String, JQBinOp)] = [("==", .eq), ("!=", .ne), ("<=", .le), (">=", .ge), ("<", .lt), (">", .gt)]
        for (t, op) in ops where startsWith(t) {
            i += t.utf8.count
            return .binop(op, lhs, try additive())
        }
        return lhs
    }

    mutating func additive() throws -> JQNode {
        var lhs = try multiplicative()
        while true {
            ws()
            if peek() == UInt8(ascii: "+") && peek(1) != UInt8(ascii: "=") {
                i += 1; lhs = .binop(.add, lhs, try multiplicative())
            } else if peek() == UInt8(ascii: "-") && peek(1) != UInt8(ascii: "=") {
                i += 1; lhs = .binop(.sub, lhs, try multiplicative())
            } else {
                return lhs
            }
        }
    }

    mutating func multiplicative() throws -> JQNode {
        var lhs = try unary()
        while true {
            ws()
            if peek() == UInt8(ascii: "*") && peek(1) != UInt8(ascii: "=") {
                i += 1; lhs = .binop(.mul, lhs, try unary())
            } else if peek() == UInt8(ascii: "/") && peek(1) != UInt8(ascii: "=") && peek(1) != UInt8(ascii: "/") {
                i += 1; lhs = .binop(.div, lhs, try unary())
            } else if peek() == UInt8(ascii: "%") && peek(1) != UInt8(ascii: "=") {
                i += 1; lhs = .binop(.mod, lhs, try unary())
            } else {
                return lhs
            }
        }
    }

    mutating func unary() throws -> JQNode {
        ws()
        if peek() == UInt8(ascii: "-") {
            i += 1
            try enter(); defer { depth -= 1 }
            return .neg(try postfix(allowAs: true))
        }
        return try postfix(allowAs: true)
    }

    mutating func postfix(allowAs: Bool) throws -> JQNode {
        try enter(); defer { depth -= 1 }
        var cur = try term()
        while true {
            let save = i
            ws()
            guard let c = peek() else { break }
            if c == UInt8(ascii: "[") {
                i += 1
                cur = try bracket(cur)
            } else if c == UInt8(ascii: "?") && !startsWith("?//") {
                i += 1
                cur = .optional(cur)
            } else if c == UInt8(ascii: ".") && peek(1) == UInt8(ascii: "[") {
                i += 1
            } else if c == UInt8(ascii: "."), let n = peek(1), Self.isIdentStart(n) || n == 0x22 {
                i += 1
                cur = .index(cur, try fieldKey())
            } else {
                i = save
                break
            }
        }
        if allowAs && keyword("as") {
            let pat = try pattern()
            ws()
            if startsWith("?//") { throw err("?// destructuring alternatives are not supported") }
            try expect("|")
            let body = try pipe()
            return .bind(cur, pat, body)
        }
        return cur
    }

    /// after '.', a field name or a string
    mutating func fieldKey() throws -> JQNode {
        if peek() == 0x22 {
            let parts = try stringLiteral()
            if parts.count == 1, case .lit(let t) = parts[0] { return .literal(.string(t)) }
            if parts.isEmpty { return .literal(.string("")) }
            return .string(parts, nil)
        }
        guard let n = ident() else { throw err("field name") }
        return .literal(.string(n))
    }

    mutating func bracket(_ cur: JQNode) throws -> JQNode {
        ws()
        if peek() == UInt8(ascii: "]") { i += 1; return .iterate(cur) }
        if peek() == UInt8(ascii: ":") {
            i += 1
            let to = try pipe()
            try expect("]")
            return .slice(cur, nil, to)
        }
        let e = try pipe()
        ws()
        if peek() == UInt8(ascii: ":") {
            i += 1
            ws()
            if peek() == UInt8(ascii: "]") { i += 1; return .slice(cur, e, nil) }
            let to = try pipe()
            try expect("]")
            return .slice(cur, e, to)
        }
        try expect("]")
        return .index(cur, e)
    }

    mutating func numberLiteral() throws -> JQNode {
        let st = i
        while i < s.count && Self.isDigit(s[i]) { i += 1 }
        if i < s.count && s[i] == UInt8(ascii: ".") {
            i += 1
            while i < s.count && Self.isDigit(s[i]) { i += 1 }
        }
        if i < s.count && (s[i] == UInt8(ascii: "e") || s[i] == UInt8(ascii: "E")) {
            var j = i + 1
            if j < s.count && (s[j] == UInt8(ascii: "+") || s[j] == UInt8(ascii: "-")) { j += 1 }
            if j < s.count && Self.isDigit(s[j]) {
                i = j
                while i < s.count && Self.isDigit(s[i]) { i += 1 }
            }
        }
        let t = Array(s[st..<i])
        var text = String(decoding: t, as: UTF8.self)
        if text.hasPrefix(".") { text = "0" + text }
        guard let d = Double(text.hasSuffix(".") ? String(text.dropLast()) : text) else { throw err("number") }
        return .literal(.number(d, JQNum.canonical(t)))
    }

    mutating func term() throws -> JQNode {
        ws()
        guard let c = peek() else { throw err("unexpected end") }
        switch c {
        case UInt8(ascii: "."):
            if peek(1) == UInt8(ascii: ".") { i += 2; return .recurseAll }
            if let n = peek(1), Self.isIdentStart(n) || n == 0x22 {
                i += 1
                return .index(.identity, try fieldKey())
            }
            if let n = peek(1), Self.isDigit(n) { return try numberLiteral() }
            i += 1
            return .identity
        case 0x30...0x39:
            return try numberLiteral()
        case 0x22:
            let parts = try stringLiteral()
            return Self.stringNode(parts, nil)
        case UInt8(ascii: "@"):
            i += 1
            guard let name = ident() else { throw err("format name") }
            ws()
            if peek() == 0x22 {
                let parts = try stringLiteral()
                return .string(parts, name)
            }
            return .format(name)
        case UInt8(ascii: "("):
            i += 1
            let e = try pipe()
            try expect(")")
            return e
        case UInt8(ascii: "["):
            i += 1
            ws()
            if peek() == UInt8(ascii: "]") { i += 1; return .array(nil) }
            let e = try pipe()
            try expect("]")
            return .array(e)
        case UInt8(ascii: "{"):
            i += 1
            return try objectLiteral()
        case UInt8(ascii: "$"):
            i += 1
            if peekKeyword("__loc__") { i += 7; return .loc(line) }
            guard let n = ident() else { throw err("variable name") }
            return .variable(n)
        default:
            break
        }
        guard Self.isIdentStart(c) else { throw err("unexpected character") }
        let st = i
        let name = ident()!
        switch name {
        case "if": return try ifRest()
        case "try":
            let body = try postfix(allowAs: false)
            var handler: JQNode? = nil
            if keyword("catch") { handler = try postfix(allowAs: false) }
            return .tryCatch(body, handler)
        case "reduce":
            let src = try postfix(allowAs: false)
            guard keyword("as") else { throw err("expected 'as'") }
            let pat = try pattern()
            try expect("(")
            let ini = try pipe()
            try expect(";")
            let upd = try pipe()
            try expect(")")
            return .reduce(src, pat, ini, upd)
        case "foreach":
            let src = try postfix(allowAs: false)
            guard keyword("as") else { throw err("expected 'as'") }
            let pat = try pattern()
            try expect("(")
            let ini = try pipe()
            try expect(";")
            let upd = try pipe()
            var ext: JQNode? = nil
            if eat(";") { ext = try pipe() }
            try expect(")")
            return .foreach(src, pat, ini, upd, ext)
        case "label":
            try expect("$")
            guard let n = ident() else { throw err("label name") }
            try expect("|")
            return .label(n, try pipe())
        case "def":
            let d = try funcDefRest()
            return .funcDef(d, try pipe())
        case "break":
            try expect("$")
            guard let n = ident() else { throw err("label name") }
            return .breakLabel(n)
        case "true", "false", "null":
            ws()
            if peek() != UInt8(ascii: "(") {
                return .literal(name == "null" ? .null : .bool(name == "true"))
            }
        case "import", "include":
            throw err("modules are not supported")
        default:
            break
        }
        if Self.keywords.contains(name) { i = st; throw err("unexpected keyword '\(name)'") }
        ws()
        var args: [JQNode] = []
        if peek() == UInt8(ascii: "(") {
            i += 1
            repeat { args.append(try pipe()) } while eat(";")
            try expect(")")
        }
        return .call(name, args)
    }

    static func stringNode(_ parts: [JQStrPart], _ fmt: String?) -> JQNode {
        if fmt == nil {
            if parts.isEmpty { return .literal(.string("")) }
            if parts.count == 1, case .lit(let t) = parts[0] { return .literal(.string(t)) }
        }
        return .string(parts, fmt)
    }

    mutating func ifRest() throws -> JQNode {
        var branches: [(JQNode, JQNode)] = []
        let c = try pipe()
        guard keyword("then") else { throw err("expected 'then'") }
        let t = try pipe()
        branches.append((c, t))
        while true {
            if keyword("elif") {
                let c2 = try pipe()
                guard keyword("then") else { throw err("expected 'then'") }
                branches.append((c2, try pipe()))
                continue
            }
            if keyword("else") {
                let e = try pipe()
                guard keyword("end") else { throw err("expected 'end'") }
                return .ifte(branches, e)
            }
            guard keyword("end") else { throw err("expected 'end'") }
            return .ifte(branches, nil)
        }
    }

    mutating func objectLiteral() throws -> JQNode {
        var entries: [JQObjEntry] = []
        ws()
        if peek() == UInt8(ascii: "}") { i += 1; return .object(entries) }
        while true {
            ws()
            guard let c = peek() else { throw err("unterminated object") }
            var key: JQObjKey
            if c == UInt8(ascii: "$") {
                i += 1
                if peekKeyword("__loc__") { i += 7; key = .loc(line) } else {
                    guard let n = ident() else { throw err("variable name") }
                    key = .variable(n)
                }
            } else if c == 0x22 {
                let parts = try stringLiteral()
                if parts.isEmpty { key = .name("") } else if parts.count == 1, case .lit(let t) = parts[0] { key = .name(t) } else { key = .expr(.string(parts, nil)) }
            } else if c == UInt8(ascii: "@") {
                i += 1
                guard let f = ident() else { throw err("format") }
                ws()
                guard peek() == 0x22 else { throw err("object key") }
                key = .expr(.string(try stringLiteral(), f))
            } else if c == UInt8(ascii: "(") {
                i += 1
                let e = try pipe()
                try expect(")")
                key = .expr(e)
            } else if Self.isIdentStart(c) {
                key = .name(ident()!)
            } else if Self.isDigit(c) {
                throw err("object keys must be strings")
            } else {
                throw err("object key")
            }
            var value: JQNode? = nil
            ws()
            if peek() == UInt8(ascii: ":") {
                i += 1
                value = try objectValue()
            }
            entries.append(JQObjEntry(key: key, value: value))
            ws()
            if peek() == UInt8(ascii: ",") { i += 1; continue }
            if peek() == UInt8(ascii: "}") { i += 1; return .object(entries) }
            throw err("expected ',' or '}' in object")
        }
    }

    /// object values: no top-level comma (jq ExpD), pipes allowed
    mutating func objectValue() throws -> JQNode {
        var lhs = try alt()
        while true {
            ws()
            if peek() == UInt8(ascii: "|") && peek(1) != UInt8(ascii: "=") {
                i += 1
                lhs = .pipe(lhs, try alt())
            } else {
                return lhs
            }
        }
    }

    mutating func pattern() throws -> JQPattern {
        ws()
        guard let c = peek() else { throw err("pattern") }
        if c == UInt8(ascii: "$") {
            i += 1
            guard let n = ident() else { throw err("variable name") }
            return .variable(n)
        }
        if c == UInt8(ascii: "[") {
            i += 1
            var ps: [JQPattern] = []
            ws()
            if peek() == UInt8(ascii: "]") { throw err("empty array pattern") }
            repeat { ps.append(try pattern()) } while eat(",")
            try expect("]")
            return .array(ps)
        }
        if c == UInt8(ascii: "{") {
            i += 1
            var es: [(key: JQObjKey, pattern: JQPattern?)] = []
            repeat {
                ws()
                guard let k = peek() else { throw err("pattern") }
                if k == UInt8(ascii: "$") {
                    i += 1
                    guard let n = ident() else { throw err("variable name") }
                    var sub: JQPattern? = nil
                    if eat(":") { sub = try pattern() }
                    es.append((.variable(n), sub))
                } else {
                    var key: JQObjKey
                    if k == 0x22 {
                        let parts = try stringLiteral()
                        if parts.isEmpty { key = .name("") } else if parts.count == 1, case .lit(let t) = parts[0] { key = .name(t) } else { key = .expr(.string(parts, nil)) }
                    } else if k == UInt8(ascii: "(") {
                        i += 1
                        let e = try pipe()
                        try expect(")")
                        key = .expr(e)
                    } else if let n = ident() {
                        key = .name(n)
                    } else {
                        throw err("object pattern key")
                    }
                    try expect(":")
                    es.append((key, try pattern()))
                }
            } while eat(",")
            try expect("}")
            return .object(es)
        }
        throw err("pattern")
    }

    /// at '"'
    mutating func stringLiteral() throws -> [JQStrPart] {
        i += 1
        var parts: [JQStrPart] = []
        var buf: [UInt8] = []
        func flush() {
            if !buf.isEmpty { parts.append(.lit(String(decoding: buf, as: UTF8.self))); buf.removeAll() }
        }
        while i < s.count {
            let c = s[i]
            if c == 0x22 {
                i += 1
                flush()
                return parts
            }
            if c == 0x5C {
                i += 1
                guard i < s.count else { break }
                let e = s[i]
                i += 1
                switch e {
                case 0x22, 0x5C, UInt8(ascii: "/"): buf.append(e)
                case UInt8(ascii: "b"): buf.append(0x08)
                case UInt8(ascii: "f"): buf.append(0x0C)
                case UInt8(ascii: "n"): buf.append(0x0A)
                case UInt8(ascii: "r"): buf.append(0x0D)
                case UInt8(ascii: "t"): buf.append(0x09)
                case UInt8(ascii: "u"):
                    func hex4() throws -> UInt32 {
                        guard i + 4 <= s.count else { throw err("bad \\u escape") }
                        var v: UInt32 = 0
                        for k in 0..<4 {
                            guard let h = JQJSONParser.hexVal(s[i + k]) else { throw err("bad \\u escape") }
                            v = v << 4 | h
                        }
                        i += 4
                        return v
                    }
                    let u = try hex4()
                    if u >= 0xD800 && u < 0xDC00, i + 6 <= s.count, s[i] == 0x5C, s[i + 1] == UInt8(ascii: "u") {
                        i += 2
                        let l = try hex4()
                        if l >= 0xDC00 && l < 0xE000 {
                            JQJSONParser.appendScalar(&buf, 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00))
                        } else {
                            JQJSONParser.appendScalar(&buf, 0xFFFD)
                            JQJSONParser.appendScalar(&buf, l)
                        }
                    } else {
                        JQJSONParser.appendScalar(&buf, u)
                    }
                case UInt8(ascii: "("):
                    flush()
                    let e = try pipe()
                    try expect(")")
                    parts.append(.interp(e))
                default:
                    throw err("invalid escape")
                }
                continue
            }
            buf.append(c)
            i += 1
        }
        throw err("unterminated string")
    }
}
