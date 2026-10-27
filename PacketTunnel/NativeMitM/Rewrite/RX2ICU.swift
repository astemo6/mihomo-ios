// Native MitM (native-only) — regexp2 (.NET) and RE2 patterns translated to a Unicode-faithful ICU pattern.
//
// Why this exists: the snapshot translation (App/Core/NCRewriteICU.swift, a port of the old core's rewriteicu) spells every
// character class out as an explicit ASCII set — exact on ASCII input only, and it refuses whatever the old core could not
// prove equal on ASCII (x mode, \p in unions, capture in look-ahead, multi-digit back-references …). Body rules on
// regexp2's path (look-around, \b, $, back-references) were not exported at all ("regexp2"), so the native-only tunnel
// skipped them. With the old core gone the native engine is the only engine, so this translator re-states regexp2's (and,
// for the old core's RE2 body fast path, RE2's) semantics with explicit ICU pieces that mean the same on any input:
//
//   regexp2 (RegexOptions.None)            ICU emitted
//   .            any but \n                [^\x{A}]            (s: [\x{0}-\x{10FFFF}])
//   ^ / $        \A / end or before final \n   \A / (?=\x{A}?\z)  (m: (?:\A|(?<=\x{A})) / (?=\x{A}|\z))
//   \Z \z \A     —                         (?=\x{A}?\z) \z \A
//   \d \w \s     Unicode Nd / L Mn Nd Pc / [\t-\r\x85\p{Z}]   \p{Nd} / [\p{L}\p{Mn}\p{Nd}\p{Pc}] / [\x{9}-\x{D}\x{85}\p{Z}]
//   \b \B        IsWordChar (\w + ZWJ/ZWNJ)  explicit look-arounds over that set
//   (?i)         ToLower(input) == ToLower(pattern)   explicit case sets (ASCII exact incl. K/İ; others: Swift's
//                                                    simple mappings, (?i:…) for non-ASCII classes)
//   (?<n>…) \k<n>  regexp2 numbering (unnamed first, then named)   plain ICU groups + slots (regexp2 number → ICU)
//   (?x)         whitespace / # comments dropped while parsing
//   look-ahead / look-behind / atomic / lazy quantifiers: ICU's own (same backtracking semantics); an unbounded
//   look-behind ICU refuses is a compile failure → the rule stays skipped.
//
// Refused (the rule is skipped, as before): conditionals, balancing / numbered groups, \G, duplicate names, POSIX
// [: classes, block names (\p{IsGreek}), captures or back-references inside a look-behind, repeats of something
// that can match empty with captures (engines differ in what such an iteration captures), quantified zero-width
// atoms, back-references to groups not yet closed. Memory: the translation is a String per rule, the
// NSRegularExpression is compiled lazily by RWRegex, nothing is cached here.
// (需同步 feat/nc-kernel: none — Rewrite is not part of NativeCore.)

import Foundation

enum RX2ICU {
    enum Dialect { case regexp2, re2 }

    struct Translation {
        let icu: String
        /// regexp2 group number → ICU group index (slots[0] == 0).
        let slots: [Int]
        /// Capturing groups (ICU and regexp2 alike).
        let groups: Int
        /// Named groups → regexp2 group number.
        let names: [String: Int]
        var identity: Bool { slots.enumerated().allSatisfy { $0.offset == $0.element } }
    }

    /// The translation, or nil with the reason.
    static func translate(_ p: String, dialect: Dialect = .regexp2) -> (Translation?, String) {
        if p.isEmpty { return (nil, "no pattern") }
        if p.unicodeScalars.count > maxPattern { return (nil, "pattern too long") }
        let ps = Parser(Array(p.unicodeScalars), dialect)
        _ = ps.alternation(Flags(), 0)
        if ps.why.isEmpty && ps.pos < ps.p.count { ps.fail("unbalanced )") }
        if !ps.why.isEmpty { return (nil, ps.why) }
        return ps.finish()
    }

    /// RWSnapRegex for a translated pattern (lit / fold: the snapshot's literal prefilter, kept as given).
    static func snapRegex(_ p: String, lit: String? = nil, fold: Bool? = nil, dialect: Dialect = .regexp2) -> RWSnapRegex? {
        guard let t = translate(p, dialect: dialect).0 else { return nil }
        return RWSnapRegex(p: p, ok: true, icu: t.icu, slots: t.identity ? nil : t.slots, lit: lit, fold: fold,
                           groups: t.groups, named: t.names.isEmpty ? nil : true, empty: nil)
    }

    /// regexp2.Replace's reading of a replacement (non-ECMAScript): literals, $$, $&, $0…$n / ${n} (greedy digits,
    /// literal when no such group), ${name}, $` $' $+; "$" + anything else is literal. tperr: regexp2 rejects it
    /// (group number overflow). nil template without tperr: a form not reproduced natively ($_).
    static func template(_ repl: String, _ t: Translation) -> (RWSnapTemplate?, Bool) {
        if repl.contains("$_") { return (nil, false) }
        let capsize = t.groups + 1
        let bytes = Array(repl.utf8)
        var sb: [UInt8] = []
        var strings: [String] = []
        var rules: [Int] = []
        func flush() {
            if sb.isEmpty { return }
            rules.append(strings.count)
            strings.append(String(decoding: sb, as: UTF8.self))
            sb = []
        }
        func isWord(_ c: UInt8) -> Bool {
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
        }
        var i = 0
        while i < bytes.count {
            let c = bytes[i]
            if c != UInt8(ascii: "$") || i + 1 >= bytes.count { sb.append(c); i += 1; continue }
            var angled = false
            var at = i + 1
            var ch = bytes[at]
            if ch == UInt8(ascii: "{") && at + 1 < bytes.count { angled = true; at += 1; ch = bytes[at] }
            if ch >= 0x30 && ch <= 0x39 {
                var j = at
                var n = 0
                while j < bytes.count && bytes[j] >= 0x30 && bytes[j] <= 0x39 {
                    if n > (Int(Int32.max) - Int(bytes[j] - 0x30)) / 10 { return (nil, true) } // ErrCaptureGroupOutOfRange
                    n = n * 10 + Int(bytes[j] - 0x30)
                    j += 1
                }
                if angled {
                    if j < bytes.count && bytes[j] == UInt8(ascii: "}") && n < capsize {
                        flush(); rules.append(-5 - n); i = j + 1; continue
                    }
                } else if n < capsize {
                    flush(); rules.append(-5 - n); i = j; continue
                }
            } else if angled && isWord(ch) {
                var j = at
                while j < bytes.count && isWord(bytes[j]) { j += 1 }
                if j < bytes.count && bytes[j] == UInt8(ascii: "}"), let g = t.names[String(decoding: bytes[at..<j], as: UTF8.self)] {
                    flush(); rules.append(-5 - g); i = j + 1; continue
                }
            } else if !angled {
                var rule: Int?
                switch ch {
                case UInt8(ascii: "$"): sb.append(ch); i = at + 1; continue
                case UInt8(ascii: "&"): rule = -5
                case UInt8(ascii: "`"): rule = -4
                case UInt8(ascii: "'"): rule = -3
                case UInt8(ascii: "+"): rule = -2
                default: break
                }
                if let r = rule { flush(); rules.append(r); i = at + 1; continue }
            }
            sb.append(UInt8(ascii: "$"))
            i += 1
        }
        flush()
        return (RWSnapTemplate(s: strings.isEmpty ? nil : strings, r: rules), false)
    }

    // MARK: - internals

    static let maxPattern = 16 << 10
    static let maxDepth = 64

    struct Flags { var i = false, m = false, s = false, n = false, x = false }

    /// What an atom (or a sequence of them) can do: match empty, hold captures / back-references, be zero-width.
    struct Info { var nullable = true, caps = false, zero = false }

    static func hex(_ v: UInt32) -> String { "\\x{" + String(v, radix: 16, uppercase: true) + "}" }

    /// regexp2 \w (L, Mn, Nd, Pc) as ICU set members; IsWordChar (for \b) adds ZWNJ / ZWJ.
    static let wordMembers = "\\p{L}\\p{Mn}\\p{Nd}\\p{Pc}"
    static let boundaryWord = "[\\p{L}\\p{Mn}\\p{Nd}\\p{Pc}\\x{200C}\\x{200D}]"
    /// .NET \s: [\f\n\r\t\v\x85\p{Z}].
    static let spaceMembers = "\\x{9}-\\x{D}\\x{85}\\p{Z}"
    static let categories: Set<String> = ["L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No",
                                          "P", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "S", "Sm", "Sc", "Sk", "So",
                                          "Z", "Zs", "Zl", "Zp", "C", "Cc", "Cf", "Cs", "Co", "Cn"]

    /// the old core unicode.ToLower for one scalar (simple mapping; Swift's full mapping when it is a single scalar).
    static func lower(_ c: UInt32) -> UInt32 {
        if c < 0x80 { return (c >= 0x41 && c <= 0x5A) ? c + 32 : c }
        if c == 0x130 { return 0x69 }
        if c == 0x212A { return 0x6B }
        guard let s = Unicode.Scalar(c) else { return c }
        let m = s.properties.lowercaseMapping.unicodeScalars
        return m.count == 1 ? m.first!.value : c
    }

    /// Every scalar x with lower(x) == lower(c) that the ASCII / table rules know of (regexp2 IgnoreCase), or the
    /// RE2 fold orbit for the RE2 dialect.
    static func caseSet(_ c: UInt32, _ d: Dialect) -> [UInt32] {
        if d == .re2 {
            guard c < 0x80 else { return [] } // non-ASCII: caller falls back to (?i:)
            let l = lower(c)
            guard l >= 0x61 && l <= 0x7A else { return [c] }
            var out: [UInt32] = [l, l - 32]
            if l == 0x6B { out.append(0x212A) }
            if l == 0x73 { out.append(0x17F) }
            return out
        }
        let l = lower(c)
        var out: [UInt32] = [l]
        if l >= 0x61 && l <= 0x7A {
            out.append(l - 32)
            if l == 0x6B { out.append(0x212A) }
            if l == 0x69 { out.append(0x130) }
            return out
        }
        if l < 0x80 { return out }
        if let s = Unicode.Scalar(l) {
            for m in [s.properties.uppercaseMapping, s.properties.titlecaseMapping] {
                let u = m.unicodeScalars
                if u.count == 1, let v = u.first?.value, v != l, lower(v) == l, !out.contains(v) { out.append(v) }
            }
        }
        switch l {
        case 0x3C9: out.append(0x2126)
        case 0xE5: out.append(0x212B)
        case 0xDF: out.append(0x1E9E)
        default: break
        }
        if c != l && !out.contains(c) && lower(c) == l { out.append(c) }
        return out
    }

    final class Group {
        let name: String?
        let icu: Int
        var closed = false
        init(name: String?, icu: Int) { self.name = name; self.icu = icu }
    }

    struct Ref {
        var at: Int          // UTF-8 offset in the emitted text
        var digits: Int?     // \N
        var name: String?    // \k<name>
        var ci: Bool
        var closed: Set<Int> // ICU groups closed when the reference was read
    }

    /// One parsed class: ICU members, negation, subtraction, whether it is pure ASCII ranges (case expansion).
    struct ClassItem { var lo: UInt32; var hi: UInt32 }

    final class Parser {
        let p: [Unicode.Scalar]
        let d: Dialect
        var pos = 0
        var out = ""
        var why = ""
        var groups: [Group] = []
        var refs: [Ref] = []
        var inLB = 0

        init(_ p: [Unicode.Scalar], _ d: Dialect) { self.p = p; self.d = d }

        func fail(_ w: String) { if why.isEmpty { why = w } }
        func peek(_ k: Int = 0) -> UInt32? { pos + k < p.count ? p[pos + k].value : nil }
        func at(_ c: Character, _ k: Int = 0) -> Bool {
            guard let v = peek(k), let s = c.unicodeScalars.first else { return false }
            return v == s.value
        }

        // MARK: structure

        func alternation(_ f0: Flags, _ depth: Int) -> Info {
            var f = f0
            var info = Info(nullable: false, caps: false, zero: true)
            var first = true
            while why.isEmpty {
                let (si, nf) = sequence(f, depth)
                f = nf
                if first { info = si; first = false } else {
                    info.nullable = info.nullable || si.nullable
                    info.caps = info.caps || si.caps
                    info.zero = info.zero && si.zero
                }
                if !why.isEmpty { return info }
                if at("|") { pos += 1; out += "|"; continue }
                if at(")") && depth == 0 { fail("unbalanced )") }
                return info
            }
            return info
        }

        func skipBlanks(_ f: Flags) {
            guard f.x else { return }
            while let c = peek() {
                if c == 0x20 || (c >= 0x09 && c <= 0x0D) { pos += 1; continue }
                if c == 0x23 { // # comment to end of line
                    while let e = peek(), e != 0x0A { _ = e; pos += 1 }
                    continue
                }
                return
            }
        }

        func sequence(_ f0: Flags, _ depth: Int) -> (Info, Flags) {
            var f = f0
            var info = Info(nullable: true, caps: false, zero: true)
            while why.isEmpty {
                skipBlanks(f)
                guard let c = peek(), c != 0x7C, c != 0x29 else { break } // | )
                let (a, kind, nf) = atom(f, depth)
                if !why.isEmpty { break }
                if kind == .flags { f = nf; continue }
                if kind == .none { continue }
                let q = quantifier(f, a)
                if !why.isEmpty { break }
                info.nullable = info.nullable && q.nullable
                info.caps = info.caps || q.caps
                info.zero = info.zero && q.zero
            }
            return (info, f)
        }

        enum Kind { case none, flags, atom }

        /// Reads a quantifier after an atom (emitted already) and returns what the quantified atom can do.
        func quantifier(_ f: Flags, _ a: Info) -> Info {
            skipBlanks(f)
            guard let c = peek() else { return a }
            var lo = 1, hi: Int? = 1
            var text = ""
            switch c {
            case 0x2A: lo = 0; hi = nil; text = "*"; pos += 1
            case 0x2B: lo = 1; hi = nil; text = "+"; pos += 1
            case 0x3F: lo = 0; hi = 1; text = "?"; pos += 1
            case 0x7B:
                guard let br = braces(pos) else { return a }
                lo = br.0; hi = br.1
                text = String(String.UnicodeScalarView(p[pos...br.2]))
                pos = br.2 + 1
            default:
                return a
            }
            if a.zero { fail("quantified zero-width atom"); return a }
            if let h = hi, h < lo { fail("quantifier range"); return a }
            let repeats = hi == nil || hi! > 1
            if repeats && a.nullable && a.caps { fail("repeat of a nullable group"); return a }
            if hi == nil && a.nullable { fail("unbounded repeat of a nullable group"); return a }
            out += text
            if at("?") { pos += 1; out += "?" }
            if let c2 = peek(), c2 == 0x2A || c2 == 0x2B || c2 == 0x3F || (c2 == 0x7B && braces(pos) != nil) {
                fail("nested quantifier")
                return a
            }
            var q = a
            if lo == 0 { q.nullable = true }
            return q
        }

        /// {n} {n,} {n,m} starting at i: (n, m or nil, index of '}').
        func braces(_ i: Int) -> (Int, Int?, Int)? {
            var j = i + 1
            var n = 0, digits = 0
            while j < p.count, let v = digit(p[j]) { n = min(n * 10 + v, 1_000_000); digits += 1; j += 1 }
            if digits == 0 || j >= p.count { return nil }
            if p[j] == "}" { return (n, n, j) }
            guard p[j] == "," else { return nil }
            j += 1
            var m = 0, md = 0
            while j < p.count, let v = digit(p[j]) { m = min(m * 10 + v, 1_000_000); md += 1; j += 1 }
            guard j < p.count, p[j] == "}" else { return nil }
            return (n, md == 0 ? nil : m, j)
        }

        func digit(_ s: Unicode.Scalar) -> Int? { (s.value >= 0x30 && s.value <= 0x39) ? Int(s.value - 0x30) : nil }

        // MARK: atoms

        func atom(_ f: Flags, _ depth: Int) -> (Info, Kind, Flags) {
            let char = Info(nullable: false, caps: false, zero: false)
            let zero = Info(nullable: true, caps: false, zero: true)
            guard let c = peek() else { fail("unexpected end"); return (char, .none, f) }
            switch c {
            case 0x28: // (
                return group(f, depth)
            case 0x5B: // [
                pos += 1
                guard let cls = charClass(f, nested: false) else { return (char, .none, f) }
                out += cls
                return (char, .atom, f)
            case 0x2E: // .
                pos += 1
                out += f.s ? "[\\x{0}-\\x{10FFFF}]" : "[^\\x{A}]"
                return (char, .atom, f)
            case 0x5E: // ^
                pos += 1
                out += f.m ? "(?:\\A|(?<=\\x{A}))" : "\\A"
                return (zero, .atom, f)
            case 0x24: // $
                pos += 1
                if d == .re2 { out += f.m ? "(?=\\x{A}|\\z)" : "\\z" } else { out += f.m ? "(?=\\x{A}|\\z)" : "(?=\\x{A}?\\z)" }
                return (zero, .atom, f)
            case 0x5C: // backslash
                return escape(f)
            case 0x2A, 0x2B, 0x3F:
                fail("quantifier without atom")
                return (char, .none, f)
            case 0x7B:
                if braces(pos) != nil { fail("quantifier without atom"); return (char, .none, f) }
            default:
                break
            }
            pos += 1
            out += literal(c, f)
            return (char, .atom, f)
        }

        func literal(_ c: UInt32, _ f: Flags) -> String {
            guard f.i else { return RX2ICU.hex(c) }
            let set = RX2ICU.caseSet(c, d)
            if set.isEmpty { return "(?i:" + RX2ICU.hex(c) + ")" }
            if set.count == 1 { return RX2ICU.hex(set[0]) }
            return "[" + set.map(RX2ICU.hex).joined() + "]"
        }

        func escape(_ f: Flags) -> (Info, Kind, Flags) {
            let char = Info(nullable: false, caps: false, zero: false)
            let zero = Info(nullable: true, caps: false, zero: true)
            guard let e = peek(1), let es = Unicode.Scalar(e) else { fail("trailing backslash"); return (char, .none, f) }
            switch es {
            case "b", "B":
                pos += 2
                let w = d == .re2 ? "[0-9A-Za-z_]" : RX2ICU.boundaryWord
                out += es == "b" ? "(?:(?<=\(w))(?!\(w))|(?<!\(w))(?=\(w)))" : "(?:(?<=\(w))(?=\(w))|(?<!\(w))(?!\(w)))"
                return (zero, .atom, f)
            case "A": pos += 2; out += "\\A"; return (zero, .atom, f)
            case "z": pos += 2; out += "\\z"; return (zero, .atom, f)
            case "Z":
                if d == .re2 { fail("\\Z"); return (char, .none, f) }
                pos += 2; out += "(?=\\x{A}?\\z)"; return (zero, .atom, f)
            case "G": fail("\\G"); return (char, .none, f)
            case "k":
                if d == .re2 { fail("\\k"); return (char, .none, f) }
                guard inLB == 0 else { fail("backreference in look-behind"); return (char, .none, f) }
                guard let open = peek(2), open == 0x3C || open == 0x27 else { fail("\\k"); return (char, .none, f) }
                let close: UInt32 = open == 0x27 ? 0x27 : 0x3E
                var k = pos + 3
                while k < p.count && p[k].value != close { k += 1 }
                guard k < p.count, k > pos + 3 else { fail("\\k"); return (char, .none, f) }
                let name = String(String.UnicodeScalarView(p[(pos + 3)..<k]))
                pos = k + 1
                if let n = Int(name) { refs.append(Ref(at: out.utf8.count, digits: n, name: nil, ci: f.i, closed: closedSet())) } else {
                    refs.append(Ref(at: out.utf8.count, digits: nil, name: name, ci: f.i, closed: closedSet()))
                }
                return (Info(nullable: true, caps: true, zero: false), .atom, f)
            case "1"..."9":
                if d == .re2 { fail("backreference"); return (char, .none, f) }
                guard inLB == 0 else { fail("backreference in look-behind"); return (char, .none, f) }
                var k = pos + 1
                var n = 0
                while k < p.count, let v = digit(p[k]) { n = min(n * 10 + v, 1_000_000); k += 1 }
                pos = k
                refs.append(Ref(at: out.utf8.count, digits: n, name: nil, ci: f.i, closed: closedSet()))
                return (Info(nullable: true, caps: true, zero: false), .atom, f)
            default:
                break
            }
            if let set = shorthand(es) {
                pos += 2
                out += set
                return (char, .atom, f)
            }
            if es == "p" || es == "P" {
                guard let set = property() else { return (char, .none, f) }
                out += set
                return (char, .atom, f)
            }
            guard let v = scalarEscape(inClass: false) else { return (char, .none, f) }
            out += literal(v, f)
            return (char, .atom, f)
        }

        func closedSet() -> Set<Int> { Set(groups.filter(\.closed).map(\.icu)) }

        /// \d \D \w \W \s \S \p{..} \P{..} as one ICU atom (a set); pos is not moved for \d…\S (caller moves).
        func shorthand(_ e: Unicode.Scalar) -> String? {
            switch e {
            case "d": return d == .re2 ? "[0-9]" : "\\p{Nd}"
            case "D": return d == .re2 ? "[^0-9]" : "\\P{Nd}"
            case "w": return d == .re2 ? "[0-9A-Za-z_]" : "[" + RX2ICU.wordMembers + "]"
            case "W": return d == .re2 ? "[^0-9A-Za-z_]" : "[^" + RX2ICU.wordMembers + "]"
            case "s": return d == .re2 ? "[\\x{9}\\x{A}\\x{C}\\x{D}\\x{20}]" : "[" + RX2ICU.spaceMembers + "]"
            case "S": return d == .re2 ? "[^\\x{9}\\x{A}\\x{C}\\x{D}\\x{20}]" : "[^" + RX2ICU.spaceMembers + "]"
            default: return nil
            }
        }

        /// \p{Name} / \P{Name} at pos (pos moved past it), or nil (failed).
        func property() -> String? {
            guard let e = peek(1), e == 0x70 || e == 0x50 else { return nil }
            guard at("{", 2) else { fail("\\p"); return nil }
            var k = pos + 3
            while k < p.count && p[k] != "}" { k += 1 }
            guard k < p.count, k > pos + 3 else { fail("\\p"); return nil }
            let name = String(String.UnicodeScalarView(p[(pos + 3)..<k]))
            let okName: Bool
            if d == .re2 {
                okName = name.unicodeScalars.allSatisfy { ($0.value >= 0x41 && $0.value <= 0x5A) || ($0.value >= 0x61 && $0.value <= 0x7A) || $0 == "_" }
                    && name != "Any"
            } else {
                okName = RX2ICU.categories.contains(name)
            }
            guard okName else { fail("\\p{\(name)}"); return nil }
            pos = k + 1
            return (e == 0x70 ? "\\p{" : "\\P{") + name + "}"
        }

        /// A single-scalar escape at pos (\t \n \xHH \uHHHH \cX octal, escaped punctuation); pos moved past it.
        func scalarEscape(inClass: Bool) -> UInt32? {
            guard let e = peek(1), let es = Unicode.Scalar(e) else { fail("trailing backslash"); return nil }
            func hexAt(_ i: Int, _ n: Int) -> UInt32? {
                guard i + n <= p.count else { return nil }
                var v: UInt32 = 0
                for k in i..<(i + n) {
                    guard let h = hexValue(p[k]) else { return nil }
                    v = v * 16 + h
                }
                return v
            }
            switch es {
            case "t": pos += 2; return 0x09
            case "n": pos += 2; return 0x0A
            case "r": pos += 2; return 0x0D
            case "f": pos += 2; return 0x0C
            case "v": pos += 2; return 0x0B
            case "a": pos += 2; return 0x07
            case "e":
                if d == .re2 { fail("\\e"); return nil }
                pos += 2; return 0x1B
            case "b":
                guard inClass, d == .regexp2 else { fail("\\b"); return nil }
                pos += 2; return 0x08
            case "x":
                if d == .re2 && at("{", 2) {
                    var k = pos + 3
                    var v: UInt32 = 0
                    while k < p.count, let h = hexValue(p[k]) { v = min(v &* 16 &+ h, 0x110000); k += 1 }
                    guard k < p.count, p[k] == "}", k > pos + 3, v <= 0x10FFFF else { fail("\\x{"); return nil }
                    pos = k + 1
                    return v
                }
                guard let v = hexAt(pos + 2, 2) else { fail("\\x"); return nil }
                pos += 4; return v
            case "u":
                if d == .re2 { fail("\\u"); return nil }
                guard let v = hexAt(pos + 2, 4) else { fail("\\u"); return nil }
                pos += 6; return v
            case "c":
                if d == .re2 { fail("\\c"); return nil }
                guard let l = peek(2), (l >= 0x41 && l <= 0x5A) || (l >= 0x61 && l <= 0x7A) else { fail("\\c"); return nil }
                pos += 3
                return (l | 0x20) - 0x60
            case "0":
                if d == .re2 { fail("octal"); return nil }
                // \0 + up to two more octal digits (.NET ScanOctal: at most 3 digits)
                var k = pos + 1
                var v: UInt32 = 0, n = 0
                while k < p.count, n < 3, p[k].value >= 0x30, p[k].value <= 0x37 { v = v * 8 + (p[k].value - 0x30); k += 1; n += 1 }
                pos = k
                return v
            default:
                break
            }
            // \_: regexp2 rejects it and the old core compiled the pattern with it dropped (dropJSIdentityEscapes) — a literal _
            if e == 0x5F && d == .regexp2 { pos += 2; return e }
            if (e >= 0x30 && e <= 0x39) || (e >= 0x41 && e <= 0x5A) || (e >= 0x61 && e <= 0x7A) || e == 0x5F {
                fail("\\\(es)")
                return nil
            }
            pos += 2
            return e
        }

        func hexValue(_ s: Unicode.Scalar) -> UInt32? {
            switch s.value {
            case 0x30...0x39: return s.value - 0x30
            case 0x41...0x46: return s.value - 0x41 + 10
            case 0x61...0x66: return s.value - 0x61 + 10
            default: return nil
            }
        }

        // MARK: classes

        /// A character class after its '['; pos ends past the closing ']'. nested: a .NET subtraction operand.
        func charClass(_ f: Flags, nested: Bool) -> String? {
            var neg = false
            if at("^") { neg = true; pos += 1 }
            var ranges: [ClassItem] = []
            var sets: [String] = []
            var sub: String?
            var first = true
            while true {
                guard let c = peek() else { fail("class"); return nil }
                if c == 0x5D && !first { pos += 1; break } // ]
                first = false
                if c == 0x5B { // [
                    if at(":", 1) { fail("posix class"); return nil }
                    if d == .re2 { fail("nested class"); return nil }
                }
                if c == 0x2D && at("[", 1) && d == .regexp2 && !(ranges.isEmpty && sets.isEmpty) { // -[ subtraction
                    pos += 2
                    guard let s = charClass(f, nested: true) else { return nil }
                    sub = s
                    guard at("]") else { fail("subtraction must be last"); return nil }
                    pos += 1
                    break
                }
                // one element: a scalar (possibly a range start) or a set
                var lo: UInt32
                if c == 0x5C {
                    guard let e = peek(1), let es = Unicode.Scalar(e) else { fail("class"); return nil }
                    if let s = shorthand(es) {
                        pos += 2
                        sets.append(s)
                        if at("-") && !at("]", 1) && !(at("[", 1) && d == .regexp2) { fail("class range from a set"); return nil }
                        continue
                    }
                    if e == 0x70 || e == 0x50 {
                        guard let s = property() else { return nil }
                        sets.append(s)
                        if at("-") && !at("]", 1) && !(at("[", 1) && d == .regexp2) { fail("class range from a set"); return nil }
                        continue
                    }
                    guard let v = scalarEscape(inClass: true) else { return nil }
                    lo = v
                } else {
                    lo = c
                    pos += 1
                }
                var hi = lo
                if at("-") && !at("]", 1) && !(at("[", 1) && d == .regexp2), peek(1) != nil {
                    pos += 1
                    guard let c2 = peek() else { fail("class"); return nil }
                    if c2 == 0x5C {
                        guard let e = peek(1), let es = Unicode.Scalar(e) else { fail("class"); return nil }
                        if shorthand(es) != nil || e == 0x70 || e == 0x50 { fail("class range to a set"); return nil }
                        guard let v = scalarEscape(inClass: true) else { return nil }
                        hi = v
                    } else if c2 == 0x5B && at(":", 1) {
                        fail("posix class"); return nil
                    } else {
                        hi = c2
                        pos += 1
                    }
                    if hi < lo { fail("class range order"); return nil }
                }
                ranges.append(ClassItem(lo: lo, hi: hi))
            }
            return emitClass(neg: neg, ranges: ranges, sets: sets, sub: sub, f)
        }

        func emitClass(neg: Bool, ranges: [ClassItem], sets: [String], sub: String?, _ f: Flags) -> String {
            func member(_ r: ClassItem) -> String { r.lo == r.hi ? RX2ICU.hex(r.lo) : RX2ICU.hex(r.lo) + "-" + RX2ICU.hex(r.hi) }
            var rs = ranges
            var approx = false
            if f.i && !ranges.isEmpty {
                if ranges.allSatisfy({ $0.hi < 0x80 }) && sub == nil {
                    // regexp2: x matches when ToLower(x) is in C ∪ lower(C); RE2: the fold orbit of every member
                    var extra: [ClassItem] = []
                    var hasK = false, hasI = false, hasS = false
                    for r in ranges {
                        let ul = max(r.lo, 0x41), uh = min(r.hi, 0x5A)
                        if ul <= uh { extra.append(ClassItem(lo: ul + 32, hi: uh + 32)) }
                        let ll = max(r.lo, 0x61), lh = min(r.hi, 0x7A)
                        if ll <= lh { extra.append(ClassItem(lo: ll - 32, hi: lh - 32)) }
                        func covers(_ u: UInt32) -> Bool { (r.lo <= u && u <= r.hi) || (r.lo <= u - 32 && u - 32 <= r.hi) }
                        if covers(0x6B) { hasK = true }
                        if covers(0x69) { hasI = true }
                        if covers(0x73) { hasS = true }
                    }
                    rs += extra
                    if hasK { rs.append(ClassItem(lo: 0x212A, hi: 0x212A)) }
                    if d == .regexp2 && hasI { rs.append(ClassItem(lo: 0x130, hi: 0x130)) }
                    if d == .re2 && hasS { rs.append(ClassItem(lo: 0x17F, hi: 0x17F)) }
                } else {
                    approx = true
                }
            }
            let body = rs.map(member).joined() + sets.joined()
            var cls: String
            if let s = sub {
                cls = "[[" + (neg ? "^" : "") + body + "]--" + s + "]"
            } else {
                cls = "[" + (neg ? "^" : "") + body + "]"
            }
            if approx { cls = "(?i:" + cls + ")" }
            return cls
        }

        // MARK: groups

        func group(_ f: Flags, _ depth: Int) -> (Info, Kind, Flags) {
            let none = Info(nullable: true, caps: false, zero: false)
            guard depth < RX2ICU.maxDepth else { fail("nesting too deep"); return (none, .none, f) }
            pos += 1 // (
            var inner = f
            var open = ""
            var g: Group?
            var look = 0 // 1 look-ahead, 2 look-behind
            if at("?") {
                pos += 1
                if at(":") { pos += 1; open = "(?:" }
                else if at("=") || at("!") { open = at("=") ? "(?=" : "(?!"; pos += 1; look = 1 }
                else if at("<") && (at("=", 1) || at("!", 1)) {
                    if d == .re2 { fail("look-behind"); return (none, .none, f) }
                    open = at("=", 1) ? "(?<=" : "(?<!"; pos += 2; look = 2
                }
                else if at(">") {
                    if d == .re2 { fail("atomic group"); return (none, .none, f) }
                    pos += 1; open = "(?>"
                }
                else if at("#") {
                    if d == .re2 { fail("comment"); return (none, .none, f) }
                    while let c = peek(), c != 0x29 { _ = c; pos += 1 }
                    guard at(")") else { fail("comment"); return (none, .none, f) }
                    pos += 1
                    return (none, .none, f)
                }
                else if at("(") { fail("conditional"); return (none, .none, f) }
                else if at("<") || at("'") || (d == .re2 && at("P") && at("<", 1)) {
                    if d == .re2 && at("P") { pos += 1 }
                    let close: UInt32 = at("'") ? 0x27 : 0x3E
                    var k = pos + 1
                    while k < p.count && p[k].value != close {
                        let v = p[k].value
                        guard (v >= 0x30 && v <= 0x39) || (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A) || v == 0x5F else {
                            fail("group name"); return (none, .none, f)
                        }
                        k += 1
                    }
                    guard k < p.count, k > pos + 1 else { fail("group name"); return (none, .none, f) }
                    let name = String(String.UnicodeScalarView(p[(pos + 1)..<k]))
                    if let first = name.unicodeScalars.first, first.value >= 0x30 && first.value <= 0x39 { fail("numbered group"); return (none, .none, f) }
                    if groups.contains(where: { $0.name == name }) { fail("duplicate group name"); return (none, .none, f) }
                    pos = k + 1
                    g = Group(name: name, icu: groups.count + 1)
                    open = "("
                } else {
                    var on = true
                    var nf = f
                    while let c = peek(), c != 0x29, c != 0x3A {
                        switch c {
                        case 0x2D: on = false
                        case 0x69: nf.i = on
                        case 0x6D: nf.m = on
                        case 0x73: nf.s = on
                        case 0x6E:
                            if d == .re2 { fail("inline option"); return (none, .none, f) }
                            nf.n = on
                        case 0x78:
                            if d == .re2 { fail("inline option"); return (none, .none, f) }
                            nf.x = on
                        default: fail("inline option"); return (none, .none, f)
                        }
                        pos += 1
                    }
                    guard let c = peek() else { fail("inline option"); return (none, .none, f) }
                    pos += 1
                    if c == 0x29 { return (none, .flags, nf) }
                    inner = nf
                    open = "(?:"
                }
            } else if f.n && d == .regexp2 {
                open = "(?:"
            } else {
                g = Group(name: nil, icu: groups.count + 1)
                open = "("
            }
            if let gg = g {
                if inLB > 0 { fail("capture in look-behind"); return (none, .none, f) }
                groups.append(gg)
            }
            if look == 2 { inLB += 1 }
            out += open
            let capsBefore = groups.count, refsBefore = refs.count
            var info = alternation(inner, depth + 1)
            if !why.isEmpty { return (none, .none, f) }
            guard at(")") else { fail("unclosed group"); return (none, .none, f) }
            pos += 1
            out += ")"
            if look == 2 { inLB -= 1 }
            g?.closed = true
            if look != 0 { return (Info(nullable: true, caps: false, zero: true), .atom, f) }
            info.caps = info.caps || g != nil || groups.count > capsBefore || refs.count > refsBefore
            info.zero = info.zero && !info.caps && info.nullable
            // a group of zero-width atoms only ((?:^)) is zero-width; anything else counts as an atom
            return (info, .atom, f)
        }

        // MARK: numbering and back-references

        func finish() -> (Translation?, String) {
            var num: [Int: Group] = [:]
            var names: [String: Int] = [:]
            var n = 0
            if d == .re2 {
                for g in groups { n += 1; num[n] = g; if let nm = g.name { names[nm] = n } }
            } else {
                for g in groups where g.name == nil { n += 1; num[n] = g }
                for g in groups { if let nm = g.name { n += 1; num[n] = g; names[nm] = n } }
            }
            var slots = [0]
            var s = 1
            while s <= n { slots.append(num[s]!.icu); s += 1 }
            var text = out
            for r in refs.reversed() {
                let g: Group?
                if let nm = r.name { g = names[nm].flatMap { num[$0] } } else if let k = r.digits { g = num[k] } else { g = nil }
                guard let gg = g else { return (nil, "backreference") }
                guard r.closed.contains(gg.icu) else { return (nil, "backreference to an open group") }
                let ref = r.ci ? "(?i:\\\(gg.icu))" : "(?:\\\(gg.icu))"
                guard r.at >= 0, let idx = text.utf8.index(text.utf8.startIndex, offsetBy: r.at, limitedBy: text.utf8.endIndex) else {
                    return (nil, "backreference position")
                }
                text.insert(contentsOf: ref, at: idx)
            }
            return (Translation(icu: text, slots: slots, groups: n, names: names), "")
        }
    }
}
