// Native MitM stage 3 — one rule pattern on NSRegularExpression (ICU).
//
// Swift compiles the explicit ICU translation Go made of the regexp2 pattern (bridge/mitm/rewriteicu.go): every
// character class / literal is an explicit set of ASCII code points, anchors are spelled out, capture groups are
// unnamed and renumbered (`slots` maps regexp2's capture slots to ICU group indices). The translation is exact
// for ASCII input only, so every input is checked to be ASCII first (anything else: .unknown → Go decides).
// Compiled lazily: a rule whose required literal is not in the URL is ruled out without a regex (and without
// compiling one), which keeps both the per-request cost and the resident memory of thousands of module rules
// small.
//
// Replacements run the program Go parsed with regexp2's own replacement parser (RWSnapTemplate): literals,
// capture slots, $` $' $+ $_ — so templates mean exactly what regexp2.Replace makes of them.

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

    /// The pattern Swift compiles: Go's ICU translation (older snapshots: the pattern itself when Go marked it
    /// portable).
    var icuPattern: String? {
        guard src.ok else { return nil }
        return src.icu ?? src.p
    }

    /// The compiled expression; nil when ICU rejects it or its group count differs from Go's (then: Go decides).
    var regex: NSRegularExpression? {
        lock.lock(); defer { lock.unlock() }
        if !tried {
            tried = true
            if let p = icuPattern, let re = try? NSRegularExpression(pattern: p, options: []), re.numberOfCaptureGroups == src.groups {
                compiled = re
            }
        }
        return compiled
    }

    /// Whether ICU accepted the pattern (compiles it now).
    var compiles: Bool { regex != nil }

    static func isASCII(_ s: String) -> Bool { s.utf8.allSatisfy { $0 < 0x80 } }

    /// Gap C5 (astemo6/Muse NativeCore): the Go-free tunnel has no Go to decide for non-ASCII input, so the ICU
    /// translation runs on it too (regexp2 also matches runes; differences are limited to classes Go spelled out
    /// as ASCII sets meeting non-ASCII text). The Go-backed app build keeps answering unknown.
    #if TERN_NO_GO
    static let lenient = true
    #else
    static let lenient = false
    #endif
    static func inputOK(_ s: String) -> Bool { lenient || isASCII(s) }

    /// Could the URL contain a match at all? false is exact (every match contains the literal).
    func literalAllows(_ s: String) -> Bool {
        if lit.isEmpty { return true }
        return RWAscii.contains(fold ? RWAscii.lower(s) : s, lit)
    }

    /// Whether the pattern matches s. unknown: only Go can tell (not translatable, ICU refused, non-ASCII input).
    func match(_ s: String) -> Match {
        if !literalAllows(s) { return .no }
        guard src.ok, RWRegex.inputOK(s), let re = regex else { return .unknown }
        switch RWRegex.first(re, s) {
        case .timeout: return .unknown
        case .none: return .no
        case .match: return .yes
        }
    }

    enum First { case none, match(NSTextCheckingResult), timeout }

    /// Time budget for one ICU search: a pathological pattern must not stall the tunnel (Go's regexp2 has its
    /// own 200 ms MatchTimeout, after which it reports no match — such inputs go to Go, which decides).
    static var timeLimit: TimeInterval = 0.05

    /// The first match, searched with progress callbacks so the search can be abandoned after timeLimit.
    static func first(_ re: NSRegularExpression, _ s: String) -> First {
        let ns = s as NSString
        let deadline = Date().addingTimeInterval(timeLimit)
        var found: NSTextCheckingResult?
        var timedOut = false
        re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: ns.length)) { m, _, stop in
            if let m = m {
                found = m
                stop.pointee = true
            } else if Date() > deadline {
                timedOut = true
                stop.pointee = true
            }
        }
        if let m = found { return .match(m) }
        return timedOut ? .timeout : .none
    }

    /// Every match (nil: the time budget ran out).
    static func all(_ re: NSRegularExpression, _ s: String) -> [NSTextCheckingResult]? {
        let ns = s as NSString
        let deadline = Date().addingTimeInterval(timeLimit)
        var out: [NSTextCheckingResult] = []
        var timedOut = false
        re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: ns.length)) { m, _, stop in
            if let m = m {
                out.append(m)
            } else if Date() > deadline {
                timedOut = true
                stop.pointee = true
            }
        }
        return timedOut ? nil : out
    }

    /// regexp2 Replace(s, template, -1, 1): the first match replaced. nil: cannot do it like Go.
    func replaceFirst(_ s: String, _ tp: RWSnapTemplate) -> String? {
        guard src.ok, RWRegex.inputOK(s), let re = regex else { return nil }
        let ns = s as NSString
        let m: NSTextCheckingResult
        switch RWRegex.first(re, s) {
        case .timeout: return nil
        case .none: return s
        case .match(let x): m = x
        }
        guard let rep = run(tp, m, ns) else { return nil }
        let r = m.range
        return ns.substring(to: r.location) + rep + ns.substring(from: r.location + r.length)
    }

    /// regexp2 Replace(s, template, -1, -1): every match replaced (ICU walks matches, empty ones included, the way
    /// regexp2 does — held to it by NativeMitmRegexFixtures).
    func replaceAll(_ s: String, _ tp: RWSnapTemplate) -> String? {
        guard src.ok, RWRegex.inputOK(s), let re = regex else { return nil }
        let ns = s as NSString
        var out = ""
        var at = 0
        guard let ms = RWRegex.all(re, s) else { return nil }
        if ms.isEmpty { return s }
        for m in ms {
            guard let rep = run(tp, m, ns) else { return nil }
            out += ns.substring(with: NSRange(location: at, length: m.range.location - at))
            out += rep
            at = m.range.location + m.range.length
        }
        out += ns.substring(from: at)
        return out
    }

    /// ICU group index of regexp2 capture slot `slot`.
    private func icuGroup(_ slot: Int) -> Int? {
        if let s = src.slots {
            return slot >= 0 && slot < s.count ? s[slot] : nil
        }
        return slot >= 0 && slot <= src.groups ? slot : nil
    }

    private func group(_ m: NSTextCheckingResult, slot: Int, _ ns: NSString) -> String? {
        guard let g = icuGroup(slot), g < m.numberOfRanges else { return nil }
        let r = m.range(at: g)
        if r.location == NSNotFound { return "" }
        return ns.substring(with: r)
    }

    /// regexp2 replacementImpl over the parsed template. nil: a slot Swift cannot map.
    func run(_ tp: RWSnapTemplate, _ m: NSTextCheckingResult, _ ns: NSString) -> String? {
        var out = ""
        let strings = tp.s ?? []
        let capsize = (src.slots?.count) ?? (src.groups + 1)
        for r in tp.r {
            if r >= 0 {
                guard r < strings.count else { return nil }
                out += strings[r]
            } else if r < -4 {
                guard let g = group(m, slot: -5 - r, ns) else { return nil }
                out += g
            } else {
                switch r {
                case -4: out += ns.substring(to: m.range.location)
                case -3: out += ns.substring(from: m.range.location + m.range.length)
                case -2:
                    guard let g = group(m, slot: capsize - 1, ns) else { return nil }
                    out += g
                case -1: out += ns as String
                default: return nil
                }
            }
        }
        return out
    }
}
