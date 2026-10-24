// Native MitM stage 3a — one rule pattern on NSRegularExpression (ICU), used only where Go said ICU reads it
// like Go does (RWSnapRegex.ok) and only on printable-ASCII input. Compiled lazily: a rule whose required literal
// is not in the URL is ruled out without a regex (and without compiling one), which keeps both the per-request
// cost and the resident memory of thousands of module rules small.
//
// Replacements follow regexp2's non-ECMAScript rules (the Go path's Replace): $$, $&, $n / ${n} with greedy
// digits (a missing group leaves the text literal), any other "$" literal. Go marks templates using $` $' $+ $_,
// ${name} or a pattern with named groups as not portable; those never reach expand().

import Foundation

final class RWRegex {
    enum Match { case yes, no, unknown }

    let src: RWSnapRegex
    private let lit: String
    private let fold: Bool
    private let lock = NSLock()
    private var compiled: NSRegularExpression?
    private var tried = false

    init(_ src: RWSnapRegex) {
        self.src = src
        lit = src.lit ?? ""
        fold = src.fold ?? false
    }

    /// The compiled expression; nil when ICU rejects it or its group count differs from Go's (then: Go decides).
    private var regex: NSRegularExpression? {
        lock.lock(); defer { lock.unlock() }
        if !tried {
            tried = true
            if src.ok, let re = try? NSRegularExpression(pattern: src.p, options: []), re.numberOfCaptureGroups == src.groups {
                compiled = re
            }
        }
        return compiled
    }

    /// Could the URL contain a match at all? false is exact (every match contains the literal).
    func literalAllows(_ s: String) -> Bool {
        if lit.isEmpty { return true }
        return RWAscii.contains(fold ? RWAscii.lower(s) : s, lit)
    }

    /// Whether the pattern matches s (s is printable ASCII). unknown: only Go can tell.
    func match(_ s: String) -> Match {
        if !literalAllows(s) { return .no }
        guard src.ok, let re = regex else { return .unknown }
        let ns = s as NSString
        return re.firstMatch(in: s, options: [], range: NSRange(location: 0, length: ns.length)) != nil ? .yes : .no
    }

    /// regexp2 Replace(s, template, -1, 1): the first match replaced. nil: cannot do it like Go.
    func replaceFirst(_ s: String, template: String) -> String? {
        guard src.ok, let re = regex else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, options: [], range: NSRange(location: 0, length: ns.length)) else { return s }
        guard let rep = expand(template, m, ns) else { return nil }
        let r = m.range
        return ns.substring(to: r.location) + rep + ns.substring(from: r.location + r.length)
    }

    /// regexp2 Replace(s, template, -1, -1): every match replaced. Only for patterns that cannot match empty
    /// (Go guarantees: RWSnapRegex.empty false), where ICU and .NET walk matches alike.
    func replaceAll(_ s: String, template: String) -> String? {
        guard src.ok, src.empty != true, let re = regex else { return nil }
        let ns = s as NSString
        var out = ""
        var at = 0
        for m in re.matches(in: s, options: [], range: NSRange(location: 0, length: ns.length)) {
            if m.range.length == 0 { return nil }
            guard let rep = expand(template, m, ns) else { return nil }
            out += ns.substring(with: NSRange(location: at, length: m.range.location - at))
            out += rep
            at = m.range.location + m.range.length
        }
        out += ns.substring(from: at)
        return out
    }

    private func group(_ m: NSTextCheckingResult, _ g: Int, _ ns: NSString) -> [UInt8] {
        guard g <= m.numberOfRanges - 1 else { return [] }
        let r = m.range(at: g)
        if r.location == NSNotFound { return [] }
        return Array(ns.substring(with: r).utf8)
    }

    /// Expands a .NET replacement template for match m. nil: a form Swift does not reproduce.
    func expand(_ template: String, _ m: NSTextCheckingResult, _ ns: NSString) -> String? {
        let t = Array(template.utf8)
        let groups = src.groups
        var out = [UInt8]()
        var i = 0
        let dollar = UInt8(ascii: "$")
        while i < t.count {
            let c = t[i]
            if c != dollar { out.append(c); i += 1; continue }
            if i + 1 >= t.count { out.append(dollar); i += 1; continue }
            var j = i + 1
            var angled = false
            if t[j] == UInt8(ascii: "{") && t.count - j > 1 { angled = true; j += 1 }
            let ch = t[j]
            if RWAscii.isDigit(ch) {
                var k = j
                var num = 0
                while k < t.count && RWAscii.isDigit(t[k]) {
                    if k - j >= 9 { return nil } // regexp2 reports an out-of-range group: an error on the Go path
                    num = num * 10 + Int(t[k] - 0x30)
                    k += 1
                }
                if !angled {
                    if num <= groups { out += group(m, num, ns); i = k; continue }
                } else if k < t.count && t[k] == UInt8(ascii: "}") {
                    if num <= groups { out += group(m, num, ns); i = k + 1; continue }
                }
            } else if angled {
                if ch >= 0x80 || RWAscii.isTokenByte(ch) && (ch == UInt8(ascii: "_") || (ch | 0x20) >= 0x61 && (ch | 0x20) <= 0x7A) {
                    return nil // ${name}: Go keeps such templates
                }
            } else {
                switch ch {
                case dollar: out.append(dollar); i = j + 1; continue
                case UInt8(ascii: "&"): out += group(m, 0, ns); i = j + 1; continue
                case UInt8(ascii: "`"), UInt8(ascii: "'"), UInt8(ascii: "+"), UInt8(ascii: "_"): return nil
                default: break
                }
            }
            out.append(dollar) // unrecognised: a literal "$", scanning goes on right after it
            i += 1
        }
        return String(decoding: out, as: UTF8.self)
    }
}
