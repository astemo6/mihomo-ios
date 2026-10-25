// App/Core/NCRewriteICU.swift
// E-B1b stage 1: Port of Go regexp2 (.NET) regex portability analysis and ICU translation to Swift.
//
// Sources:
//   - bridge/mitm/rewriteicu.go (lines 1..1044: rx2Translate, rx2Parser, atom sets, template parsing)
//   - bridge/mitm/rewritesnap.go (snapRegexOf, hasNamedGroup, snapRegex, portableRegex, requiredLiteral, portableRepl)
//   - bridge/mitm/parse.go (dropJSIdentityEscapes)
//   - bridge/mitm/bodylimits.go (compileURLRe)
//
// Alignment with PacketTunnel decoding model:
//   - NCSnapRegex matches PacketTunnel/NativeMitM/Rewrite/RewriteSnapshot.swift: RWSnapRegex
//     JSON keys: p, ok, icu, slots, lit, fold, groups, named, empty.
//   - NCSnapTemplate matches PacketTunnel/NativeMitM/Rewrite/RewriteSnapshot.swift: RWSnapTemplate
//     JSON keys: s, r.
//   - Optional fields set to nil are omitted during JSON encoding, exactly aligning with Go's omitempty.
//     In Go, Empty/Fold/Named are bool+omitempty (omitted when false). In Swift, Bool? is used where false is
//     represented as nil so that JSONEncoder does not emit the key. Groups is non-optional and always emitted.
//
// DIVERGENCES:
//   1. Regexp2 Object vs Pure Text Derivation:
//      - Go behavior: rx2Translate and snapRegexOf receive an already-compiled *regexp2.Regexp object and query
//        GetGroupNumbers(), GetGroupNames(), GroupNumberFromName(), and internal capture tables (rx2Internals).
//      - Swift behavior: Swift has no regexp2 runtime. All group numbers, names, and slot allocations are
//        derived purely from pattern text via rx2Parser during AST traversal. Unnamed groups are assigned
//        1..u in source order, followed by named groups (u+1)..(u+m) in source order, matching regexp2's exact
//        numbering rules.
//      - Impact: Identical group numbering and slot mapping for all valid patterns without needing a .NET regex engine.
//
//   2. RE2 Equivalence Check in rx2AtomSet:
//      - Go behavior: When re2 == true (URL matchers), Go compiles atomRE2 with Go's regexp package (RE2) and
//        asserts that RE2 matches the identical subset of characters over 0x20..0x7E as regexp2.
//      - Swift behavior: Swift has no RE2 engine. We enforce the RE2 syntax restriction rules (rejecting `[:`,
//        `\Q`, `\x{`, `(?P`, `\C`, `(?U`, `\p` without `{`, and class subtraction `-[`) and evaluate character
//        membership using NSRegularExpression.
//      - Impact: On printable ASCII (0x20..0x7E), standard regex character classes, escapes, and literals match
//        identically between RE2 and ICU. Any subtle Unicode property category difference between RE2 and ICU
//        on non-ASCII input is gated away because Swift gates inputs to ASCII.
//
//   3. Empty String Matching (Empty flag):
//      - Go behavior: Go evaluates Empty by running cre.MatchString("") with RE2, or re.MatchString("") with regexp2.
//      - Swift behavior: Evaluated via NSRegularExpression test match against "" using the translated ICU pattern
//        (or original pattern with dropped JS escapes). If uncompilable, defaults conservatively to true.
//      - Impact: Approximates Go's empty-string check without requiring a separate RE2/regexp2 runtime.
//
//   4. Pattern Validity / Compilation Failure:
//      - Go behavior: compileRe compiles with regexp2, falling back to dropJSIdentityEscapes. Failure returns
//        &SnapRegex{P: p} with OK=false, Groups=0.
//      - Swift behavior: Validated via NSRegularExpression compilation (with dropJSIdentityEscapes and class
//        subtraction normalization) combined with rx2Parser's own syntax failure paths.
//      - Impact: Uncompilable patterns return NCSnapRegex with ok=false and groups=0, matching Go.
//
//   5. Replacement Error Detection in snapTemplate:
//      - Go behavior: Calls re.Replace("", repl, -1, -1) to verify regexp2's replacement parsing.
//      - Swift behavior: parseReplacementTemplate parses the replacement string, validating greedy decimal group
//        references against Int32.max overflow (ErrCaptureGroupOutOfRange) and $_ rejection.
//      - Impact: Produces identical (NCSnapTemplate?, Bool) output, where the second return indicates tperr.

import Foundation

// MARK: - Snapshot Models

/// NCSnapRegex is one compiled pattern. JSON keys align with Go SnapRegex and PacketTunnel RWSnapRegex.
struct NCSnapRegex: Codable, Equatable {
    var p: String                       // "p": the pattern as regexp2 compiled it
    var ok: Bool                        // "ok": Swift can match it on ASCII input via ICU
    var icu: String?                    // "icu": explicit ICU translation (rewriteicu.go); nil when omitted
    var slots: [Int]?                   // "slots": regexp2 capture slot -> ICU group index (nil when identity)
    var lit: String?                    // "lit": every match contains this literal ("" / nil when none known)
    var fold: Bool?                     // "fold": lit is compared ASCII case-insensitively (nil when false)
    var groups: Int                     // "groups": numbered capture groups (always emitted)
    var named: Bool?                    // "named": pattern has named capture groups (nil when false)
    var empty: Bool?                    // "empty": can match the empty string (nil when false)

    enum CodingKeys: String, CodingKey {
        case p
        case ok
        case icu
        case slots
        case lit
        case fold
        case groups
        case named
        case empty
    }

    init(
        p: String,
        ok: Bool = false,
        icu: String? = nil,
        slots: [Int]? = nil,
        lit: String? = nil,
        fold: Bool? = nil,
        groups: Int = 0,
        named: Bool? = nil,
        empty: Bool? = nil
    ) {
        self.p = p
        self.ok = ok
        self.icu = icu
        self.slots = slots
        self.lit = lit
        self.fold = fold
        self.groups = groups
        self.named = named
        self.empty = empty
    }
}

/// NCSnapTemplate is a replacement program (regexp2 syntax.ReplacerData).
/// JSON keys align with Go SnapTemplate and PacketTunnel RWSnapTemplate.
struct NCSnapTemplate: Codable, Equatable {
    var s: [String]?                    // "s": string literals table (nil when omitted)
    var r: [Int]                        // "r": replacement instructions (always emitted)

    enum CodingKeys: String, CodingKey {
        case s
        case r
    }

    init(s: [String]? = nil, r: [Int]) {
        self.s = s
        self.r = r
    }
}

// MARK: - NCRewriteICU Public Interface

enum NCRewriteICU {
    /// snapRegex describes a compiled rule pattern: re2 = URL matcher requires RE2 equivalence,
    /// replace = captures / match positions are used.
    static func snapRegex(pattern: String, re2: Bool, replace: Bool) -> NCSnapRegex {
        // A pathological pattern is reported as not portable (the rule then stays on the slow path / is skipped);
        // it must never take the whole runtime preparation down.
        if pattern.unicodeScalars.count > rx2MaxPattern {
            return NCSnapRegex(p: pattern, ok: false, groups: 0)
        }
        let valid = isValidRegexPattern(pattern)
        if !valid {
            return NCSnapRegex(p: pattern, ok: false, groups: 0)
        }
        let (lit, fold) = requiredLiteral(pattern)
        var sr = NCSnapRegex(
            p: pattern,
            ok: false,
            lit: lit.isEmpty ? nil : lit,
            fold: fold ? true : nil,
            groups: 0
        )
        let t = rx2Translate(pattern: pattern, re2: re2, replace: replace)
        if t.why.isEmpty {
            sr.ok = true
            sr.icu = t.icu
            sr.groups = t.slots.count - 1
            var identity = true
            for (i, v) in t.slots.enumerated() {
                if v != i {
                    identity = false
                    break
                }
            }
            if !identity {
                sr.slots = t.slots
            }
        } else {
            let scan = scanGroupCountAndNamed(pattern)
            sr.groups = scan.groups
        }
        let scanNamed = scanGroupCountAndNamed(pattern).named
        if scanNamed {
            sr.named = true
        }
        // Note: Go runs cre.MatchString("") / re.MatchString(""). In Swift, this is approximated
        // using NSRegularExpression on the translated ICU pattern or the source pattern.
        sr.empty = matchesEmptyString(pattern: pattern, icu: sr.icu) ? true : nil
        return sr
    }

    /// Convenience overload describing pattern p with auto-detected re2 and replace=true (Go snapRegex(p)).
    static func snapRegex(_ pattern: String) -> NCSnapRegex {
        snapRegex(pattern: pattern, re2: isCompileURLRe(pattern), replace: true)
    }

    /// portableRegex: the pattern uses only syntax that regexp2 (.NET), RE2, and ICU read alike on
    /// printable-ASCII input. Conservative: anything unusual is false. groups counts capturing groups.
    static func portableRegex(_ p: String) -> (ok: Bool, named: Bool, groups: Int) {
        if p.isEmpty {
            return (false, false, 0)
        }
        let bytes = Array(p.utf8)
        for b in bytes {
            if b < 0x20 || b > 0x7E {
                return (false, false, 0)
            }
        }
        var named = false
        var groups = 0
        var inClass = false
        var classStart = 0
        var i = 0
        while i < bytes.count {
            let c = bytes[i]
            if c == UInt8(ascii: "\\") {
                if i + 1 >= bytes.count {
                    return (false, named, groups)
                }
                let d = bytes[i + 1]
                i += 1
                switch d {
                case UInt8(ascii: "d"), UInt8(ascii: "D"), UInt8(ascii: "w"), UInt8(ascii: "W"),
                     UInt8(ascii: "s"), UInt8(ascii: "S"), UInt8(ascii: "t"), UInt8(ascii: "n"),
                     UInt8(ascii: "r"), UInt8(ascii: "f"):
                    break
                case UInt8(ascii: "b"), UInt8(ascii: "B"), UInt8(ascii: "A"), UInt8(ascii: "z"),
                     UInt8(ascii: "Z"), UInt8(ascii: "G"):
                    if inClass {
                        return (false, named, groups) // \b in class is backspace in .NET
                    }
                case UInt8(ascii: "x"):
                    if i + 2 >= bytes.count || !isHexByte(bytes[i + 1]) || !isHexByte(bytes[i + 2]) {
                        return (false, named, groups)
                    }
                    i += 2
                case UInt8(ascii: "u"):
                    if i + 4 >= bytes.count || !isHexByte(bytes[i + 1]) || !isHexByte(bytes[i + 2]) ||
                       !isHexByte(bytes[i + 3]) || !isHexByte(bytes[i + 4]) {
                        return (false, named, groups)
                    }
                    i += 4
                case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                     UInt8(ascii: "0")...UInt8(ascii: "9"):
                    return (false, named, groups) // backrefs, \p, \k, \c, \e, \v, \h, octal ...
                default:
                    break // escaped punctuation: literal in all three
                }
                i += 1
                continue
            }
            if inClass {
                switch c {
                case UInt8(ascii: "]"):
                    if i > classStart {
                        inClass = false
                    } else {
                        return (false, named, groups) // []...] / [^]...]
                    }
                case UInt8(ascii: "["):
                    return (false, named, groups) // nested set (ICU) / subtraction (.NET)
                case UInt8(ascii: "&"), UInt8(ascii: "-"), UInt8(ascii: "~"):
                    if i + 1 < bytes.count && bytes[i + 1] == c {
                        return (false, named, groups) // ICU set operators && -- ~~
                    }
                default:
                    break
                }
                i += 1
                continue
            }
            switch c {
            case UInt8(ascii: "["):
                inClass = true
                classStart = i + 1
                if i + 1 < bytes.count && bytes[i + 1] == UInt8(ascii: "^") {
                    classStart = i + 2
                }
            case UInt8(ascii: "("):
                if i + 1 < bytes.count && bytes[i + 1] == UInt8(ascii: "?") {
                    let rest = bytes[(i + 2)...]
                    if hasBytePrefix(rest, ":") || hasBytePrefix(rest, "=") || hasBytePrefix(rest, "!") ||
                       hasBytePrefix(rest, "<=") || hasBytePrefix(rest, "<!") || hasBytePrefix(rest, ">") {
                        // Non-capturing or assertion
                    } else if hasBytePrefix(rest, "<") {
                        var j = rest.startIndex + 1
                        while j < rest.endIndex && isWordByte(bytes[j]) {
                            j += 1
                        }
                        if j == rest.startIndex + 1 || j >= rest.endIndex || bytes[j] != UInt8(ascii: ">") ||
                           (bytes[rest.startIndex + 1] >= UInt8(ascii: "0") && bytes[rest.startIndex + 1] <= UInt8(ascii: "9")) {
                            return (false, named, groups)
                        }
                        named = true
                        groups += 1
                    } else {
                        // inline flags (?i) (?i-s:...): only i, m, s
                        var j = rest.startIndex
                        while j < rest.endIndex && (bytes[j] == UInt8(ascii: "i") || bytes[j] == UInt8(ascii: "m") ||
                                                    bytes[j] == UInt8(ascii: "s") || bytes[j] == UInt8(ascii: "-")) {
                            j += 1
                        }
                        if j == rest.startIndex || j >= rest.endIndex || (bytes[j] != UInt8(ascii: ")") && bytes[j] != UInt8(ascii: ":")) {
                            return (false, named, groups)
                        }
                    }
                } else {
                    groups += 1
                }
            case UInt8(ascii: "{"):
                var j = i + 1
                while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                    j += 1
                }
                if j == i + 1 {
                    return (false, named, groups)
                }
                if j < bytes.count && bytes[j] == UInt8(ascii: ",") {
                    j += 1
                    while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                        j += 1
                    }
                }
                if j >= bytes.count || bytes[j] != UInt8(ascii: "}") {
                    return (false, named, groups)
                }
                i = j
                if i + 1 < bytes.count && bytes[i + 1] == UInt8(ascii: "+") {
                    return (false, named, groups)
                }
            case UInt8(ascii: "}"):
                return (false, named, groups)
            case UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "?"):
                if i + 1 < bytes.count && bytes[i + 1] == UInt8(ascii: "+") {
                    return (false, named, groups) // possessive (ICU only)
                }
            default:
                break
            }
            i += 1
        }
        if inClass {
            return (false, named, groups)
        }
        return (true, named, groups)
    }

    /// requiredLiteral returns a literal every match of p contains (the longest such run of top-level literal
    /// characters), fold true when it must be compared case-insensitively. Conservative: "" when unsure.
    static func requiredLiteral(_ p: String) -> (lit: String, fold: Bool) {
        if p.contains("(?#") {
            return ("", false) // .NET comment groups may hold unbalanced parentheses
        }
        var fold = false
        let bytes = Array(p.utf8)
        var i = 0
        while i + 2 < bytes.count {
            if bytes[i] == UInt8(ascii: "\\") {
                i += 2
                continue
            }
            if bytes[i] == UInt8(ascii: "(") && bytes[i + 1] == UInt8(ascii: "?") {
                var j = i + 2
                while j < bytes.count && (isWordByte(bytes[j]) || bytes[j] == UInt8(ascii: "-")) {
                    if bytes[j] == UInt8(ascii: "i") {
                        fold = true
                    }
                    if bytes[j] == UInt8(ascii: "x") {
                        return ("", false)
                    }
                    j += 1
                }
            }
            i += 1
        }
        var best: [UInt8] = []
        var cur: [UInt8] = []
        func end() {
            if cur.count > best.count {
                best = cur
            }
            cur.removeAll()
        }
        var depth = 0
        var inClass = false

        func skipQuant(_ idx: Int) -> Int {
            if idx + 1 >= bytes.count || bytes[idx + 1] != UInt8(ascii: "{") {
                return idx
            }
            var j = idx + 2
            let d = j
            while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                j += 1
            }
            if j == d {
                return idx
            }
            if j < bytes.count && bytes[j] == UInt8(ascii: ",") {
                j += 1
                while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                    j += 1
                }
            }
            if j < bytes.count && bytes[j] == UInt8(ascii: "}") {
                return j
            }
            return idx
        }

        func skipEscape(_ idx: Int) -> Int {
            if idx + 1 >= bytes.count {
                return idx
            }
            switch bytes[idx + 1] {
            case UInt8(ascii: "x"):
                return min(idx + 3, bytes.count - 1)
            case UInt8(ascii: "u"):
                return min(idx + 5, bytes.count - 1)
            case UInt8(ascii: "c"):
                return min(idx + 2, bytes.count - 1)
            case UInt8(ascii: "p"), UInt8(ascii: "P"), UInt8(ascii: "k"):
                var j = idx + 1
                while j < bytes.count {
                    let b = bytes[j]
                    if b == UInt8(ascii: "}") || b == UInt8(ascii: ">") || b == UInt8(ascii: "'") {
                        return j
                    }
                    j += 1
                }
                return bytes.count - 1
            default:
                return idx + 1
            }
        }

        i = 0
        while i < bytes.count {
            let c = bytes[i]
            if inClass {
                if c == UInt8(ascii: "\\") {
                    i += 1
                } else if c == UInt8(ascii: "]") {
                    inClass = false
                    if depth == 0 {
                        i = skipQuant(i)
                    }
                }
                i += 1
                continue
            }
            if depth > 0 {
                switch c {
                case UInt8(ascii: "\\"):
                    if i + 1 < bytes.count && isWordByte(bytes[i + 1]) {
                        i = skipEscape(i)
                    } else {
                        i += 1
                    }
                case UInt8(ascii: "["):
                    inClass = true
                case UInt8(ascii: "("):
                    depth += 1
                case UInt8(ascii: ")"):
                    depth -= 1
                    if depth == 0 {
                        i = skipQuant(i)
                    }
                default:
                    break
                }
                i += 1
                continue
            }
            // top level
            var lit: UInt8 = 0
            var isLit = false
            switch c {
            case UInt8(ascii: "\\"):
                if i + 1 >= bytes.count {
                    return ("", false)
                }
                let d = bytes[i + 1]
                if isWordByte(d) {
                    i = skipEscape(i)
                } else {
                    i += 1
                }
                if !isWordByte(d) && d >= 0x20 && d <= 0x7E {
                    lit = d
                    isLit = true
                }
            case UInt8(ascii: "|"):
                return ("", false)
            case UInt8(ascii: "("):
                end()
                depth += 1
                i += 1
                continue
            case UInt8(ascii: "["):
                end()
                inClass = true
                i += 1
                continue
            case UInt8(ascii: "."), UInt8(ascii: "^"), UInt8(ascii: "$"), UInt8(ascii: ")"),
                 UInt8(ascii: "{"), UInt8(ascii: "}"), UInt8(ascii: "]"), UInt8(ascii: "*"),
                 UInt8(ascii: "+"), UInt8(ascii: "?"):
                break
            default:
                if c >= 0x20 && c <= 0x7E {
                    lit = c
                    isLit = true
                }
            }
            if !isLit {
                end()
                i = skipQuant(i)
                i += 1
                continue
            }
            let q: UInt8 = (i + 1 < bytes.count) ? bytes[i + 1] : 0
            switch q {
            case UInt8(ascii: "?"), UInt8(ascii: "*"):
                end()
            case UInt8(ascii: "{"):
                var j = i + 2
                var n = 0
                var digits = false
                while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                    if n < 1_000_000 { n = n * 10 + Int(bytes[j] - UInt8(ascii: "0")) } // a{99999999999999999999}: no Int overflow trap
                    digits = true
                    j += 1
                }
                if j < bytes.count && bytes[j] == UInt8(ascii: ",") {
                    j += 1
                    while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                        j += 1
                    }
                }
                if !digits || j >= bytes.count || bytes[j] != UInt8(ascii: "}") {
                    return ("", false)
                }
                if n >= 1 {
                    cur.append(lit)
                }
                end()
                i = j
            case UInt8(ascii: "+"):
                cur.append(lit)
                end()
            default:
                cur.append(lit)
            }
            i += 1
        }
        end()
        if best.count < 3 {
            return ("", false)
        }
        var bestStr = String(decoding: best, as: UTF8.self)
        if fold {
            bestStr = bestStr.lowercased()
        }
        return (bestStr, fold)
    }

    /// snapTemplate parses a replacement as regexp2.Replace does.
    /// Returns (template, tperr). If regexp2 would return an error on Replace, returns (nil, true).
    static func snapTemplate(pattern: String, repl: String) -> (NCSnapTemplate?, Bool) {
        if pattern.isEmpty || pattern.unicodeScalars.count > rx2MaxPattern {
            return (nil, false)
        }
        let ps = rx2Parser(p: Array(pattern.unicodeScalars), re2: false, replace: true)
        ps.alternation(rx2Flags(), 0)
        var unnamedCount = 0
        var capnames: [String: Int] = [:]
        var seen: Set<String> = []
        for g in ps.groups {
            if g.name.isEmpty {
                unnamedCount += 1
            } else {
                if seen.contains(g.name) {
                    return (nil, false)
                }
                seen.insert(g.name)
            }
        }
        var namedNum = unnamedCount
        for g in ps.groups where !g.name.isEmpty {
            namedNum += 1
            capnames[g.name] = namedNum
        }
        return parseReplacementTemplate(repl: repl, unnamedCount: unnamedCount, capnames: capnames)
    }

}

// MARK: - Parser & Translation Internal Types

private struct rx2Flags {
    var i: Bool = false
    var m: Bool = false
    var s: Bool = false
    var n: Bool = false
}

private final class rx2Group {
    var name: String = ""
    var icu: Int = 0
    var closed: Bool = false

    init(name: String = "", icu: Int = 0, closed: Bool = false) {
        self.name = name
        self.icu = icu
        self.closed = closed
    }
}

private struct rx2Ref {
    var at: Int
    var num: Int
    var name: String
    var ci: Bool
}

private struct rx2Translation {
    var icu: String = ""
    var slots: [Int] = []
    var why: String = ""
}

private let atomNone = 0
private let atomFlags = 1
private let atomChar = 2
private let atomZero = 3
private let atomGroup = 4
private let atomGroupNull = 5
private let atomGroupCapNull = 6

/// Guards against pathological input (never seen in real modules): the parser recurses per group level.
private let rx2MaxPattern = 16 << 10
private let rx2MaxDepth = 64

private let cacheLock = NSLock()
private var rx2Cache: [String: rx2Translation] = [:]
private var rx2Sets: [String: [Bool]] = [:]

// MARK: - Translation Orchestration

private func rx2Translate(pattern p: String, re2: Bool, replace: Bool) -> rx2Translation {
    let key = "\(re2)\(replace)\(p)"
    cacheLock.lock()
    if let t = rx2Cache[key] {
        cacheLock.unlock()
        return t
    }
    cacheLock.unlock()
    let t = rx2TranslateUncached(p: p, re2: re2, replace: replace)
    cacheLock.lock()
    if rx2Cache.count > 8192 {
        rx2Cache.removeAll()
    }
    rx2Cache[key] = t
    cacheLock.unlock()
    return t
}

private func rx2TranslateUncached(p: String, re2: Bool, replace: Bool) -> rx2Translation {
    if p.isEmpty {
        return rx2Translation(why: "no pattern")
    }
    if re2 {
        for bad in ["[:", "\\Q", "\\x{", "(?P", "\\C", "(?U"] {
            if p.contains(bad) {
                return rx2Translation(why: "re2 syntax " + bad)
            }
        }
        let pBytes = Array(p.utf8)
        var i = 0
        while i + 2 < pBytes.count {
            if pBytes[i] == UInt8(ascii: "\\") {
                if (pBytes[i + 1] == UInt8(ascii: "p") || pBytes[i + 1] == UInt8(ascii: "P")) && pBytes[i + 2] != UInt8(ascii: "{") {
                    return rx2Translation(why: "re2 \\p")
                }
                i += 1
            }
            i += 1
        }
    }
    if p.contains("\\p{") || p.contains("\\P{") {
        if p.contains("|") || p.contains("?") || p.contains("*") || p.contains("{0") || p.contains("\\P{") {
            return rx2Translation(why: "unicode category in a union")
        }
    }
    if p.unicodeScalars.count > rx2MaxPattern {
        return rx2Translation(why: "pattern too long")
    }
    let ps = rx2Parser(p: Array(p.unicodeScalars), re2: re2, replace: replace)
    ps.alternation(rx2Flags(), 0)
    if ps.why.isEmpty && ps.pos < ps.p.count {
        ps.fail("unbalanced )")
    }
    if ps.why.isEmpty && ps.capInLook && !ps.refs.isEmpty {
        ps.fail("capture in look-around with backreferences")
    }
    if !ps.why.isEmpty {
        return rx2Translation(why: ps.why)
    }

    var n = 0
    var seen: Set<String> = []
    var nameToNum: [String: Int] = [:]
    for g in ps.groups {
        if g.name.isEmpty {
            n += 1
            ps.byNum[n] = g
            continue
        }
        if seen.contains(g.name) {
            return rx2Translation(why: "duplicate group name")
        }
        seen.insert(g.name)
    }
    // Number named groups after unnamed groups in order of appearance
    var namedNum = n
    for g in ps.groups where !g.name.isEmpty {
        namedNum += 1
        nameToNum[g.name] = namedNum
        ps.byNum[namedNum] = g
    }
    let totalGroups = ps.groups.count
    var slots = [Int](repeating: 0, count: totalGroups + 1)
    slots[0] = 0
    // build #374 crash (EXC_BREAKPOINT): this was `for s in 1...totalGroups`, and a ClosedRange with
    // upperBound < lowerBound traps — i.e. every pattern WITHOUT a capture group (`^https?://ad\.x\.com/`, the
    // most common rewrite shape) crashed runtime preparation. Go's `for s := 1; s <= n; s++` simply does not run.
    var s = 1
    while s <= totalGroups {
        guard let g = ps.byNum[s] else {
            return rx2Translation(why: "group numbering")
        }
        slots[s] = g.icu
        s += 1
    }
    // Backreferences: placeholders -> ICU indices
    var out = ps.b
    for i in stride(from: ps.refs.count - 1, through: 0, by: -1) {
        let r = ps.refs[i]
        let g: rx2Group?
        if !r.name.isEmpty {
            if let num = nameToNum[r.name] {
                g = ps.byNum[num]
            } else {
                g = nil
            }
        } else {
            g = ps.byNum[r.num]
        }
        guard let group = g, group.closed else {
            return rx2Translation(why: "backreference")
        }
        var ref = "\\\(group.icu)"
        if r.ci {
            ref = "(?i:\(ref))"
        } else {
            ref = "(?:\(ref))"
        }
        // r.at is a UTF-8 offset into the emitted ICU text (b is ASCII by construction; limitedBy never traps).
        guard r.at >= 0, let idx = out.utf8.index(out.utf8.startIndex, offsetBy: r.at, limitedBy: out.utf8.endIndex) else {
            return rx2Translation(why: "backreference position")
        }
        out.insert(contentsOf: ref, at: idx)
    }
    return rx2Translation(icu: out, slots: slots, why: "")
}

// MARK: - rx2Parser

private final class rx2Parser {
    var p: [UnicodeScalar]
    var pos: Int = 0
    var b: String = ""
    var groups: [rx2Group] = []
    var byNum: [Int: rx2Group] = [:]
    var re2: Bool
    var replace: Bool
    var why: String = ""
    var inLB: Int = 0
    var inLA: Int = 0
    var capInLook: Bool = false
    var unnamed: Int = 0
    var refs: [rx2Ref] = []

    init(p: [UnicodeScalar], re2: Bool, replace: Bool) {
        self.p = p
        self.re2 = re2
        self.replace = replace
    }

    func fail(_ why: String) {
        if self.why.isEmpty {
            self.why = why
        }
    }

    func peek() -> UnicodeScalar? {
        if pos < p.count {
            return p[pos]
        }
        return nil
    }

    func hasPrefix(_ s: String) -> Bool {
        let r = Array(s.unicodeScalars)
        if pos + r.count > p.count {
            return false
        }
        for i in 0..<r.count {
            if p[pos + i] != r[i] {
                return false
            }
        }
        return true
    }

    func alternation(_ fIn: rx2Flags, _ depth: Int) {
        var f = fIn
        while why.isEmpty {
            f = sequence(f, depth)
            if !why.isEmpty {
                return
            }
            guard let c = peek() else { return }
            if c == "|" {
                pos += 1
                b.append("|")
                continue
            }
            if c == ")" {
                if depth == 0 {
                    fail("unbalanced )")
                }
                return
            }
            return
        }
    }

    func sequence(_ fIn: rx2Flags, _ depth: Int) -> rx2Flags {
        var f = fIn
        while why.isEmpty && pos < p.count {
            guard let c = peek() else { break }
            if c == "|" || c == ")" {
                return f
            }
            let start = b.utf8.count
            let (kind, nf) = atom(f, depth)
            if !why.isEmpty {
                return f
            }
            if kind == atomFlags {
                f = nf
                continue
            }
            if kind == atomNone {
                continue
            }
            let atomText = rx2Tail(b, start)
            quantifier(kind, atomText)
        }
        return f
    }

    func quantifier(_ kind: Int, _ atomText: String) {
        guard let c = peek() else { return }
        var q = ""
        switch c {
        case "*", "+", "?":
            q = String(c)
            pos += 1
        case "{":
            var j = pos + 1
            let d1 = j
            while j < p.count && p[j] >= "0" && p[j] <= "9" {
                j += 1
            }
            if j == d1 {
                return
            }
            if j < p.count && p[j] == "," {
                j += 1
                while j < p.count && p[j] >= "0" && p[j] <= "9" {
                    j += 1
                }
            }
            if j >= p.count || p[j] != "}" {
                return
            }
            q = scalarSubstring(p[pos...j])
            pos = j + 1
        default:
            return
        }
        if kind == atomZero {
            fail("quantified zero-width atom")
            return
        }
        let unbounded = q == "*" || q == "+" || q.hasSuffix(",}")
        let repeats = q != "?" && q != "{0}" && q != "{1}" && q != "{0,1}" && q != "{1,1}"
        if repeats && (kind == atomGroupCapNull || (replace && kind == atomGroupNull)) {
            fail("repeat of a nullable group")
            return
        }
        if unbounded && kind == atomGroupNull {
            fail("unbounded repeat of a nullable group")
            return
        }
        _ = atomText
        b.append(q)
        if peek() == "?" {
            pos += 1
            b.append("?")
        }
        if let c2 = peek(), c2 == "*" || c2 == "+" || c2 == "?" || (c2 == "{" && looksQuant()) {
            fail("nested quantifier")
        }
    }

    func looksQuant() -> Bool {
        var j = pos + 1
        let d = j
        while j < p.count && p[j] >= "0" && p[j] <= "9" {
            j += 1
        }
        return j > d
    }

    func atom(_ f: rx2Flags, _ depth: Int) -> (Int, rx2Flags) {
        guard pos < p.count else {
            fail("unexpected end")
            return (0, f)
        }
        let c = p[pos]
        switch c {
        case "(":
            return group(f, depth)
        case "[":
            let end = classEnd(pos)
            if end < 0 {
                fail("class")
                return (0, f)
            }
            let text = scalarSubstring(p[pos...end])
            pos = end + 1
            emitSet(text, f)
            return (atomChar, f)
        case ".":
            pos += 1
            emitSet(".", f)
            return (atomChar, f)
        case "^":
            pos += 1
            if f.m {
                b.append("(?:\\A|(?<=\\x0a))")
            } else {
                b.append("\\A")
            }
            return (atomZero, f)
        case "$":
            pos += 1
            if f.m {
                b.append("(?=\\x0a|\\z)")
            } else {
                b.append("(?=\\x0a?\\z)")
            }
            return (atomZero, f)
        case "\\":
            return escape(f)
        case "*", "+", "?":
            fail("quantifier without atom")
            return (0, f)
        case "{":
            if looksQuant() {
                fail("quantifier without atom")
                return (0, f)
            }
        case "#", " ", "\t", "\n", "\r", "\u{0C}", "\u{0B}":
            break
        default:
            break
        }
        pos += 1
        emitSet(rx2Lit(c), f)
        return (atomChar, f)
    }

    func escape(_ f: rx2Flags) -> (Int, rx2Flags) {
        if pos + 1 >= p.count {
            fail("trailing backslash")
            return (0, f)
        }
        let d = p[pos + 1]
        switch d {
        case "b", "B":
            pos += 2
            let w = rx2SetText(setOf("\\w", rx2Flags()) ?? [])
            if d == "b" {
                b.append("(?:(?<=\(w))(?!\(w))|(?<!\(w))(?=\(w)))")
            } else {
                b.append("(?:(?<=\(w))(?=\(w))|(?<!\(w))(?!\(w)))")
            }
            return (atomZero, f)
        case "A":
            pos += 2
            b.append("\\A")
            return (atomZero, f)
        case "z":
            pos += 2
            b.append("\\z")
            return (atomZero, f)
        case "Z":
            pos += 2
            b.append("(?=\\x0a?\\z)")
            return (atomZero, f)
        case "G":
            fail("\\G")
            return (0, f)
        case "w", "W", "s", "S", "d", "D":
            pos += 2
            emitSet("\\" + String(d), f)
            return (atomChar, f)
        case "p", "P":
            var j = pos + 2
            if j >= p.count || p[j] != "{" {
                fail("\\p")
                return (0, f)
            }
            while j < p.count && p[j] != "}" {
                j += 1
            }
            if j >= p.count {
                fail("\\p")
                return (0, f)
            }
            let text = scalarSubstring(p[pos...j])
            pos = j + 1
            emitSet(text, f)
            return (atomChar, f)
        case "1"..."9":
            if inLB > 0 {
                fail("backreference in look-behind")
                return (0, f)
            }
            if pos + 2 < p.count && p[pos + 2] >= "0" && p[pos + 2] <= "9" {
                fail("multi-digit backreference")
                return (0, f)
            }
            pos += 2
            refs.append(rx2Ref(at: b.utf8.count, num: Int(d.value - UnicodeScalar("0").value), name: "", ci: f.i))
            return (atomGroupCapNull, f)
        case "k":
            if inLB > 0 {
                fail("backreference in look-behind")
                return (0, f)
            }
            let j = pos + 2
            if j >= p.count || (p[j] != "<" && p[j] != "'") {
                fail("\\k")
                return (0, f)
            }
            let close: UnicodeScalar = (p[j] == "'") ? "'" : ">"
            var k = j + 1
            while k < p.count && p[k] != close {
                k += 1
            }
            if k >= p.count {
                fail("\\k")
                return (0, f)
            }
            let name = scalarSubstring(p[(j + 1)..<k])
            if name.isEmpty || (name.unicodeScalars.first! >= "0" && name.unicodeScalars.first! <= "9") {
                fail("\\k number")
                return (0, f)
            }
            pos = k + 1
            refs.append(rx2Ref(at: b.utf8.count, num: -1, name: name, ci: f.i))
            return (atomGroupCapNull, f)
        case "x":
            if pos + 3 >= p.count || !isHexRune(p[pos + 2]) || !isHexRune(p[pos + 3]) {
                fail("\\x")
                return (0, f)
            }
            let text = scalarSubstring(p[pos...pos+3])
            pos += 4
            emitSet(text, f)
            return (atomChar, f)
        case "u":
            if pos + 5 >= p.count {
                fail("\\u")
                return (0, f)
            }
            for k in 2..<6 {
                if !isHexRune(p[pos + k]) {
                    fail("\\u")
                    return (0, f)
                }
            }
            let text = scalarSubstring(p[pos...pos+5])
            pos += 6
            emitSet(text, f)
            return (atomChar, f)
        case "c":
            if pos + 2 >= p.count || !(p[pos + 2] >= "a" && p[pos + 2] <= "z" || p[pos + 2] >= "A" && p[pos + 2] <= "Z") {
                fail("\\c")
                return (0, f)
            }
            let text = scalarSubstring(p[pos...pos+2])
            pos += 3
            emitSet(text, f)
            return (atomChar, f)
        case "t", "n", "r", "f", "v", "e", "a":
            pos += 2
            emitSet("\\" + String(d), f)
            return (atomChar, f)
        case "a"..."z", "A"..."Z", "0"..."9", "_":
            fail("\\\(d)")
            return (0, f)
        default:
            pos += 2
            emitSet(rx2Lit(d), f)
            return (atomChar, f)
        }
    }

    func classEnd(_ i: Int) -> Int {
        var j = i + 1
        if j < p.count && p[j] == "^" {
            j += 1
        }
        var first = true
        while j < p.count {
            let c = p[j]
            if c == "\\" {
                if j + 1 < p.count && (p[j + 1] == "p" || p[j + 1] == "P") {
                    var k = j + 2
                    while k < p.count && p[k] != "}" {
                        k += 1
                    }
                    j = k + 1
                } else {
                    j += 2
                }
                first = false
                continue
            } else if c == "]" && !first {
                return j
            } else if c == "[" && j + 1 < p.count && p[j + 1] == ":" {
                return -1
            } else if c == "-" && !first && j + 1 < p.count && p[j + 1] == "[" {
                if re2 {
                    return -1
                }
                let k = classEnd(j + 1)
                if k < 0 || k + 1 >= p.count || p[k + 1] != "]" {
                    return -1
                }
                return k + 1
            }
            first = false
            j += 1
        }
        return -1
    }

    func group(_ f: rx2Flags, _ depth: Int) -> (Int, rx2Flags) {
        if depth >= rx2MaxDepth {
            fail("nesting too deep")
            return (0, f)
        }
        pos += 1 // '('
        var inner = f
        var kind = ""
        var g: rx2Group?
        if peek() == "?" {
            pos += 1
            if hasPrefix(":") {
                pos += 1
                kind = "(?:"
            } else if hasPrefix("=") || hasPrefix("!") {
                kind = "(?" + String(peek()!)
                pos += 1
            } else if hasPrefix("<=") || hasPrefix("<!") {
                kind = "(?" + scalarSubstring(p[pos..<pos+2])
                pos += 2
            } else if hasPrefix(">") {
                pos += 1
                kind = "(?>"
            } else if hasPrefix("#") {
                while pos < p.count && p[pos] != ")" {
                    pos += 1
                }
                if pos >= p.count {
                    fail("comment")
                    return (0, f)
                }
                pos += 1
                return (atomNone, f)
            } else if hasPrefix("(") {
                fail("conditional")
                return (0, f)
            } else if hasPrefix("<") || hasPrefix("'") {
                let close: UnicodeScalar = (peek() == "'") ? "'" : ">"
                var k = pos + 1
                while k < p.count && p[k] != close {
                    let pk = p[k]
                    if !(pk == "_" || (pk >= "0" && pk <= "9") || (pk >= "a" && pk <= "z") || (pk >= "A" && pk <= "Z")) {
                        fail("group name")
                        return (0, f)
                    }
                    k += 1
                }
                if k >= p.count || k == pos + 1 {
                    fail("group name")
                    return (0, f)
                }
                let name = scalarSubstring(p[(pos + 1)..<k])
                if let first = name.unicodeScalars.first, first >= "0" && first <= "9" {
                    fail("numbered group name")
                    return (0, f)
                }
                pos = k + 1
                g = rx2Group(name: name)
                kind = "("
            } else {
                // flags: (?imsnx-imsnx) or (?imsnx-imsnx: ...)
                var on = true
                var nf = f
                while pos < p.count && p[pos] != ")" && p[pos] != ":" {
                    switch p[pos] {
                    case "-": on = false
                    case "i": nf.i = on
                    case "m": nf.m = on
                    case "s": nf.s = on
                    case "n": nf.n = on
                    default:
                        fail("inline option")
                        return (0, f)
                    }
                    pos += 1
                }
                if pos >= p.count {
                    fail("inline option")
                    return (0, f)
                }
                if p[pos] == ")" {
                    pos += 1
                    return (atomFlags, nf)
                }
                pos += 1 // ':'
                inner = nf
                kind = "(?:"
            }
        } else if f.n {
            kind = "(?:"
        } else {
            g = rx2Group()
            kind = "("
        }
        let lb = kind == "(?<=" || kind == "(?<!"
        let la = kind == "(?=" || kind == "(?!"
        if let g = g {
            if inLB > 0 || inLA > 0 {
                if replace {
                    fail("capture in look-around")
                    return (0, f)
                }
                capInLook = true
            }
            groups.append(g)
            g.icu = groups.count
        }
        if lb { inLB += 1 }
        if la { inLA += 1 }
        b.append(kind)
        let start = b.utf8.count
        let refsBefore = refs.count
        let groupsBefore = groups.count
        alternation(inner, depth + 1)
        if !why.isEmpty {
            return (0, f)
        }
        if peek() != ")" {
            fail("unclosed group")
            return (0, f)
        }
        pos += 1
        let body = rx2Tail(b, start)
        b.append(")")
        if lb { inLB -= 1 }
        if la { inLA -= 1 }
        if let g = g {
            g.closed = true
        }
        switch kind {
        case "(?=", "(?!", "(?<=", "(?<!":
            return (atomZero, f)
        default:
            break
        }
        let hasCap = refs.count > refsBefore || groups.count > groupsBefore || g != nil
        if rx2Nullable(body, refs.count > refsBefore) {
            if hasCap {
                return (atomGroupCapNull, f)
            }
            return (atomGroupNull, f)
        }
        return (atomGroup, f)
    }

    func emitSet(_ atom: String, _ f: rx2Flags) {
        guard let set = setOf(atom, f) else { return }
        b.append(rx2SetText(set))
    }

    func setOf(_ atom: String, _ f: rx2Flags) -> [Bool]? {
        let (set, why) = rx2AtomSet(atom, rx2RE2Text(atom), f, re2)
        if !why.isEmpty {
            fail(why)
            return nil
        }
        return set
    }
}

/// The text emitted since UTF-8 offset `start` ("" when the offset is past the end — never traps).
private func rx2Tail(_ b: String, _ start: Int) -> String {
    guard start >= 0, let i = b.utf8.index(b.utf8.startIndex, offsetBy: start, limitedBy: b.utf8.endIndex) else { return "" }
    return String(b[i...])
}

// MARK: - Character Set & Atom Evaluation

private func rx2Lit(_ c: UnicodeScalar) -> String {
    if c.value < 0x10000 {
        return String(format: "\\u%04X", c.value)
    }
    return String(c) // astral: never matches ASCII input except via folding
}

private func rx2RE2Text(_ atom: String) -> String {
    if atom.count == 6 && atom.hasPrefix("\\u") {
        let hex = String(atom.dropFirst(2))
        return "\\x{" + hex + "}"
    }
    return atom
}

private func rx2AtomSet(_ atom: String, _ atomRE2: String, _ f: rx2Flags, _ re2: Bool) -> ([Bool]?, String) {
    var on = ""
    var off = ""
    if f.i { on += "i" } else { off += "i" }
    if f.s { on += "s" } else { off += "s" }
    var flags = "(?" + on
    if !off.isEmpty {
        flags += "-" + off
    }
    flags += ")"
    let key = "\(re2)|\(flags)|\(atom)"
    cacheLock.lock()
    if let s = rx2Sets[key] {
        cacheLock.unlock()
        return (s, "")
    }
    cacheLock.unlock()

    // Fast-path known .NET ASCII sets:
    // . matches all ASCII in singleline (s) mode; all ASCII except \n (10) otherwise (matches \r in .NET)
    if atom == "." {
        var set = [Bool](repeating: false, count: 128)
        for c in 0..<128 {
            set[c] = f.s ? true : (c != 10)
        }
        cacheLock.lock()
        if rx2Sets.count > 8192 { rx2Sets.removeAll() }
        rx2Sets[key] = set
        cacheLock.unlock()
        return (set, "")
    }

    // Standard character class escapes on ASCII:
    if atom == "\\d" || atom == "\\D" || atom == "\\w" || atom == "\\W" || atom == "\\s" || atom == "\\S" {
        var set = [Bool](repeating: false, count: 128)
        for c in 0..<128 {
            let ok: Bool
            switch atom {
            case "\\d": ok = (c >= 48 && c <= 57)
            case "\\D": ok = !(c >= 48 && c <= 57)
            case "\\w": ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c == 95)
            case "\\W": ok = !((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c == 95))
            case "\\s": ok = (c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32)
            case "\\S": ok = !(c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32)
            default: ok = false
            }
            set[c] = ok
        }
        cacheLock.lock()
        if rx2Sets.count > 8192 { rx2Sets.removeAll() }
        rx2Sets[key] = set
        cacheLock.unlock()
        return (set, "")
    }

    // Adapt .NET-specific syntax for ICU/NSRegularExpression:
    // 1) Class subtraction: .NET [a-z-[aeiou]] -> ICU [a-z--[aeiou]]
    var icuAtom = atom.replacingOccurrences(of: "-[", with: "--[")
    // 2) Leading literal ]: []...] -> [\]...], [^]...] -> [^\]...]
    if icuAtom.hasPrefix("[]") {
        icuAtom = "[\\]" + icuAtom.dropFirst(2)
    } else if icuAtom.hasPrefix("[^]") {
        icuAtom = "[^\\]" + icuAtom.dropFirst(3)
    }

    var options: NSRegularExpression.Options = []
    if f.i { options.insert(.caseInsensitive) }
    if f.s { options.insert(.dotMatchesLineSeparators) }

    let pattern = "\\A(?:" + icuAtom + ")\\z"
    guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
        return (nil, "atom " + atom)
    }

    var set = [Bool](repeating: false, count: 128)
    for c in 0..<128 {
        let s = String(UnicodeScalar(c)!)
        let range = NSRange(location: 0, length: s.utf16.count)
        let ok = regex.firstMatch(in: s, options: [], range: range) != nil
        set[c] = ok
    }

    if re2 {
        // Go asserts equivalence against RE2 for URL matching.
        // In Swift, syntax restrictions ([: \Q \x{ (?P \C (?U \p -[) are pre-validated,
        // and standard character classes match identically over printable ASCII 0x20..0x7E.
        if atomRE2.contains("-[") || (atomRE2.contains("\\p") && !atomRE2.contains("\\p{")) {
            return (nil, "re2 atom " + atom)
        }
    }

    cacheLock.lock()
    if rx2Sets.count > 8192 {
        rx2Sets.removeAll()
    }
    rx2Sets[key] = set
    cacheLock.unlock()
    return (set, "")
}

private func rx2SetText(_ set: [Bool]) -> String {
    var ranges: [(Int, Int)] = []
    for c in 0..<128 {
        if c >= set.count || !set[c] {
            continue
        }
        if let last = ranges.last, last.1 == c - 1 {
            ranges[ranges.count - 1].1 = c
        } else {
            ranges.append((c, c))
        }
    }
    if ranges.isEmpty {
        return "(?!)"
    }
    if ranges.count == 1 && ranges[0].0 == ranges[0].1 {
        return rx2Char(ranges[0].0)
    }
    var b = "["
    for r in ranges {
        b.append(rx2Char(r.0))
        if r.1 > r.0 {
            if r.1 > r.0 + 1 {
                b.append("-")
            }
            b.append(rx2Char(r.1))
        }
    }
    b.append("]")
    return b
}

private func rx2Char(_ c: Int) -> String {
    if (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) {
        return String(UnicodeScalar(c)!)
    }
    return String(format: "\\x%02x", c)
}

private func rx2Nullable(_ body: String, _ hasRef: Bool) -> Bool {
    if hasRef {
        return true
    }
    let s = rx2StripZero(body)
    guard let re = try? NSRegularExpression(pattern: "\\A(?:" + s + ")\\z", options: []) else {
        return true // unsure
    }
    return re.firstMatch(in: "", options: [], range: NSRange(location: 0, length: 0)) != nil
}

private func rx2StripZero(_ s: String) -> String {
    var b = ""
    let r = Array(s.unicodeScalars)
    var i = 0
    while i < r.count {
        if r[i] == "\\" && i + 1 < r.count {
            if r[i + 1] == "A" || r[i + 1] == "z" {
                i += 2
                continue
            }
            b.append(Character(r[i]))
            b.append(Character(r[i + 1]))
            i += 2
            continue
        }
        if r[i] == "[" { // copy a set verbatim
            var j = i + 1
            while j < r.count && r[j] != "]" {
                if r[j] == "\\" {
                    j += 1
                }
                j += 1
            }
            let end = min(j, r.count - 1)
            b.append(scalarSubstring(r[i...end]))
            i = j + 1
            continue
        }
        if r[i] == "(" && i + 2 < r.count && r[i + 1] == "?" &&
           (r[i + 2] == "=" || r[i + 2] == "!" || (r[i + 2] == "<" && i + 3 < r.count && (r[i + 3] == "=" || r[i + 3] == "!"))) {
            var depth = 0
            var j = i
            while j < r.count {
                if r[j] == "\\" {
                    j += 2
                    continue
                }
                if r[j] == "[" {
                    j += 1
                    while j < r.count && r[j] != "]" {
                        if r[j] == "\\" {
                            j += 1
                        }
                        j += 1
                    }
                    j += 1
                    continue
                }
                if r[j] == "(" {
                    depth += 1
                } else if r[j] == ")" {
                    depth -= 1
                    if depth == 0 {
                        break
                    }
                }
                j += 1
            }
            i = j + 1
            continue
        }
        if r[i] == "(" && i + 2 < r.count && r[i + 1] == "?" && r[i + 2] == ">" {
            b.append("(?:")
            i += 3
            continue
        }
        b.append(Character(r[i]))
        i += 1
    }
    return b.replacingOccurrences(of: "(?i:", with: "(?:")
}

// MARK: - Replacement Template Parser

/// Parses replacement text exactly as regexp2 syntax.NewReplacerData does.
/// Returns (NCSnapTemplate?, tperr).
private func parseReplacementTemplate(repl: String, unnamedCount: Int, capnames: [String: Int]) -> (NCSnapTemplate?, Bool) {
    if repl.contains("$_") {
        return (nil, false) // $_ not reproduced on native path (Go rx2Template)
    }
    let capsize = 1 + unnamedCount + capnames.count
    let bytes = Array(repl.utf8)
    // Literal text is collected as UTF-8 bytes: appending each byte as its own Character turned every non-ASCII
    // replacement (中文 / emoji in a 302 target or header value) into Latin-1 mojibake.
    var sb: [UInt8] = []
    var strings: [String] = []
    var rules: [Int] = []

    func flushSb() {
        if !sb.isEmpty {
            rules.append(strings.count)
            strings.append(String(decoding: sb, as: UTF8.self))
            sb = []
        }
    }

    var i = 0
    while i < bytes.count {
        let c = bytes[i]
        if c != UInt8(ascii: "$") {
            sb.append(c)
            i += 1
            continue
        }
        if i + 1 >= bytes.count {
            // Trailing '$' is literal
            sb.append(UInt8(ascii: "$"))
            i += 1
            continue
        }
        let backpos = i
        var angled = false
        var nextPos = i + 1
        var ch = bytes[nextPos]
        if ch == UInt8(ascii: "{") && nextPos + 1 < bytes.count {
            angled = true
            nextPos += 1
            ch = bytes[nextPos]
        }

        if ch >= UInt8(ascii: "0") && ch <= UInt8(ascii: "9") {
            var j = nextPos
            var capnum = 0
            var overflow = false
            let maxDiv10 = Int.max / 10
            let maxMod10 = Int.max % 10
            while j < bytes.count && bytes[j] >= UInt8(ascii: "0") && bytes[j] <= UInt8(ascii: "9") {
                let digit = Int(bytes[j] - UInt8(ascii: "0"))
                if capnum > maxDiv10 || (capnum == maxDiv10 && digit > maxMod10) {
                    overflow = true
                } else {
                    capnum = capnum * 10 + digit
                }
                j += 1
            }
            if overflow || capnum > Int32.max {
                return (nil, true) // ErrCaptureGroupOutOfRange
            }
            if angled {
                if j < bytes.count && bytes[j] == UInt8(ascii: "}") {
                    if capnum >= 0 && capnum < capsize {
                        flushSb()
                        rules.append(-5 - capnum)
                        i = j + 1
                        continue
                    }
                }
            } else {
                if capnum >= 0 && capnum < capsize {
                    flushSb()
                    rules.append(-5 - capnum)
                    i = j
                    continue
                }
            }
        } else if angled && isWordByte(ch) {
            var j = nextPos
            while j < bytes.count && isWordByte(bytes[j]) {
                j += 1
            }
            if j < bytes.count && bytes[j] == UInt8(ascii: "}") {
                let nameSlice = bytes[nextPos..<j]
                let name = String(decoding: nameSlice, as: UTF8.self)
                if let slot = capnames[name] {
                    flushSb()
                    rules.append(-5 - slot)
                    i = j + 1
                    continue
                }
            }
        } else if !angled {
            var recognized = false
            var rule = 0
            switch ch {
            case UInt8(ascii: "$"):
                sb.append(UInt8(ascii: "$"))
                i = nextPos + 1
                recognized = true
            case UInt8(ascii: "&"):
                rule = -5 // slot 0 (entire match)
                recognized = true
            case UInt8(ascii: "`"):
                rule = -4 // replaceLeftPortion
                recognized = true
            case UInt8(ascii: "'"):
                rule = -3 // replaceRightPortion
                recognized = true
            case UInt8(ascii: "+"):
                rule = -2 // replaceLastGroup
                recognized = true
            case UInt8(ascii: "_"):
                return (nil, false) // replaceWholeString
            default:
                break
            }
            if recognized {
                if ch != UInt8(ascii: "$") {
                    flushSb()
                    rules.append(rule)
                    i = nextPos + 1
                }
                continue
            }
        }

        // Unrecognized $: literalize '$' and advance to character after '$'
        sb.append(UInt8(ascii: "$"))
        i = backpos + 1
    }
    flushSb()
    let sList = strings.isEmpty ? nil : strings
    return (NCSnapTemplate(s: sList, r: rules), false)
}

// MARK: - Validation & Helper Utilities

private func dropJSIdentityEscapes(_ p: String) -> String {
    var out = ""
    let chars = Array(p)
    var i = 0
    while i < chars.count {
        if chars[i] == "\\" && i + 1 < chars.count {
            if chars[i + 1] == "_" {
                out.append("_")
            } else {
                out.append(chars[i])
                out.append(chars[i + 1])
            }
            i += 2
            continue
        }
        out.append(chars[i])
        i += 1
    }
    return out
}

private func isCompileURLRe(_ p: String) -> Bool {
    if p.isEmpty || p.contains("-[") {
        return false
    }
    var esc = false
    for c in p.utf8 {
        if esc {
            if c == UInt8(ascii: "b") || c == UInt8(ascii: "B") {
                return false
            }
            esc = false
            continue
        }
        if c == UInt8(ascii: "\\") {
            esc = true
        }
    }
    if p.contains("(?=") || p.contains("(?!") || p.contains("(?<=") || p.contains("(?<!") ||
       p.contains("(?>") || p.contains("(?(") || p.contains("\\Z") || p.contains("\\G") ||
       p.contains("\\k") {
        return false
    }
    var inClass = false
    let bytes = Array(p.utf8)
    var i = 0
    while i < bytes.count {
        let b = bytes[i]
        if inClass {
            if b == UInt8(ascii: "\\") {
                i += 2
                continue
            }
            if b == UInt8(ascii: "]") {
                inClass = false
            }
            i += 1
            continue
        }
        if b == UInt8(ascii: "[") {
            inClass = true
            i += 1
            continue
        }
        if b == UInt8(ascii: "\\") && i + 1 < bytes.count {
            let next = bytes[i + 1]
            if next >= UInt8(ascii: "1") && next <= UInt8(ascii: "9") {
                return false
            }
            i += 2
            continue
        }
        i += 1
    }
    guard (try? NSRegularExpression(pattern: p, options: [])) != nil else {
        return false
    }
    return true
}

private func isValidRegexPattern(_ p: String) -> Bool {
    if (try? NSRegularExpression(pattern: p, options: [])) != nil {
        return true
    }
    let q = dropJSIdentityEscapes(p)
    if (try? NSRegularExpression(pattern: q, options: [])) != nil {
        return true
    }
    let sub = q.replacingOccurrences(of: "-[", with: "--[")
    if (try? NSRegularExpression(pattern: sub, options: [])) != nil {
        return true
    }
    return false
}

private func matchesEmptyString(pattern p: String, icu: String?) -> Bool {
    if let icu = icu, let re = try? NSRegularExpression(pattern: "\\A(?:" + icu + ")\\z", options: []) {
        return re.firstMatch(in: "", options: [], range: NSRange(location: 0, length: 0)) != nil
    }
    if let re = try? NSRegularExpression(pattern: "\\A(?:" + p + ")\\z", options: []) {
        return re.firstMatch(in: "", options: [], range: NSRange(location: 0, length: 0)) != nil
    }
    let q = dropJSIdentityEscapes(p).replacingOccurrences(of: "-[", with: "--[")
    if let re = try? NSRegularExpression(pattern: "\\A(?:" + q + ")\\z", options: []) {
        return re.firstMatch(in: "", options: [], range: NSRange(location: 0, length: 0)) != nil
    }
    return true
}

private func scanGroupCountAndNamed(_ p: String) -> (groups: Int, named: Bool) {
    let pr = NCRewriteICU.portableRegex(p)
    if pr.ok {
        return (pr.groups, pr.named)
    }
    // Fallback: parse via rx2Parser directly to extract group count and named presence
    let ps = rx2Parser(p: Array(p.unicodeScalars), re2: false, replace: false)
    ps.alternation(rx2Flags(), 0)
    let named = ps.groups.contains { !$0.name.isEmpty && Int($0.name) == nil }
    return (ps.groups.count, named)
}

// MARK: - Byte / Rune Primitives

private func isHexByte(_ c: UInt8) -> Bool {
    (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9")) ||
    (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "f")) ||
    (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "F"))
}

private func isWordByte(_ c: UInt8) -> Bool {
    (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9")) ||
    (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z")) ||
    (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z")) ||
    c == UInt8(ascii: "_")
}

private func isHexRune(_ c: UnicodeScalar) -> Bool {
    (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F")
}

private func hasBytePrefix(_ slice: ArraySlice<UInt8>, _ prefix: String) -> Bool {
    let pBytes = prefix.utf8
    if slice.count < pBytes.count { return false }
    var sIdx = slice.startIndex
    for pb in pBytes {
        if slice[sIdx] != pb { return false }
        sIdx += 1
    }
    return true
}

private func scalarSubstring(_ scalars: ArraySlice<UnicodeScalar>) -> String {
    var s = ""
    s.unicodeScalars.append(contentsOf: scalars)
    return s
}
