import Foundation
import Security

/// feat/nc-selfcheck-2: the pure part of 一键自检 — parsing what the extension writes into the startup log, comparing
/// config counts across layers, picking nodes to test, turning a rewrite pattern into a probe URL, describing a
/// network error and laying out selfcheck.txt. No I/O, no actors: UnitTests/SelfCheckLogicTests covers it.
enum SelfCheckLogic {

    // MARK: startup log

    /// The current tunnel session of StartupLog.read() (the part before 「--- 上一次 ---」).
    static func currentSession(_ log: String) -> String {
        log.components(separatedBy: "\n--- 上一次 ---\n").first ?? log
    }

    /// The newest line containing `needle`, with the "HH:mm:ss.SSS [tag] " prefix removed.
    static func lastLine(_ log: String, containing needle: String) -> String? {
        log.split(separator: "\n").last { $0.contains(needle) }.map { stripStamp(String($0)) }
    }

    static func lines(_ log: String, containing needle: String) -> [String] {
        log.split(separator: "\n").filter { $0.contains(needle) }.map { stripStamp(String($0)) }
    }

    /// "12:52:02.778 [ext] msg" → "msg" (lines without the stamp are returned unchanged).
    static func stripStamp(_ line: String) -> String {
        let b = Array(line.utf8)
        guard b.count > 13, b[2] == UInt8(ascii: ":"), b[5] == UInt8(ascii: ":"), b[8] == UInt8(ascii: "."), b[12] == UInt8(ascii: " ") else { return line }
        var rest = Substring(line).dropFirst(13)
        if rest.hasPrefix("["), let close = rest.firstIndex(of: "]") {
            rest = rest[rest.index(after: close)...]
            if rest.hasPrefix(" ") { rest = rest.dropFirst() }
        }
        return String(rest)
    }

    struct CoreCounts: Equatable {
        var proxies = 0, providerNodes = 0, providers = 0, groups = 0, rules = 0, ignoredRules = 0
    }

    /// NativeCoreEngine.statsLine: "native core (src): 9 proxies + 33 from 1 provider(s), 31 groups, 91 rules (2 ignored), …".
    static func parseCoreStats(_ line: String) -> CoreCounts? {
        guard let m = firstMatch(#"(\d+) proxies \+ (-?\d+) from (\d+) provider\(s\), (\d+) groups, (\d+) rules \((\d+) ignored\)"#, line),
              m.count == 6 else { return nil }
        return CoreCounts(proxies: m[0], providerNodes: max(0, m[1]), providers: m[2], groups: m[3], rules: m[4], ignoredRules: m[5])
    }

    /// "native rewrite snapshot: 288 rules, 312 MitM hosts, on true".
    static func parseRewriteSnapshot(_ line: String) -> (rules: Int, hosts: Int, on: Bool)? {
        guard let m = firstMatch(#"native rewrite snapshot: (\d+) rules, (\d+) MitM hosts"#, line), m.count == 2 else { return nil }
        return (m[0], m[1], line.contains("on true"))
    }

    /// "native scripts: 125 script rule(s), 3 unloadable; prelude ok; JSC interruptible".
    static func parseScripts(_ line: String) -> (scripts: Int, unloadable: Int)? {
        guard let m = firstMatch(#"(\d+) script rule\(s\), (\d+) unloadable"#, line), m.count == 2 else { return nil }
        return (m[0], m[1])
    }

    /// "native tasks: 11 task(s), 2 panel(s)".
    static func parseTasks(_ line: String) -> Int? {
        firstMatch(#"(\d+) task\(s\)"#, line)?.first
    }

    /// NCDataPlane.statsLine ("native: packets in 185, tcp accepted 3, sessions 0, dns queries 4, …") → label → value.
    /// Only the `native: packets …` segment of a diagnostics / +15 s line is read (up to the next ";").
    static func parsePlaneCounters(_ line: String) -> [String: Int] {
        guard let r = line.range(of: "native: packets") else { return [:] }
        var seg = line[line.index(r.lowerBound, offsetBy: 8)...]
        if let semi = seg.firstIndex(of: ";") { seg = seg[..<semi] }
        var out: [String: Int] = [:]
        for piece in seg.components(separatedBy: ", ") {
            guard let m = firstMatchStrings(#"^\s*([a-z][a-z \-]*?) (\d+)"#, piece), m.count == 2, let v = Int(m[1]) else { continue }
            out[m[0]] = v
        }
        return out
    }

    /// "rule set: fetch failed host/…/file — reason" lines → (name, reason), newest reason per name, in first-seen order.
    static func ruleSetFailures(_ log: String) -> [(name: String, reason: String)] {
        var order: [String] = []
        var reason: [String: String] = [:]
        for l in lines(log, containing: "rule set: fetch failed ") {
            guard let r = l.range(of: "rule set: fetch failed ") else { continue }
            let rest = l[r.upperBound...]
            let parts = rest.components(separatedBy: " — ")
            let name = parts[0].trimmingCharacters(in: .whitespaces)
            if reason[name] == nil { order.append(name) }
            reason[name] = parts.count > 1 ? parts[1...].joined(separator: " — ") : "?"
        }
        return order.map { ($0, reason[$0] ?? "?") }
    }

    // MARK: config integrity

    /// One quantity seen at several layers (配置 → App 构建 → 运行时文件 → 内核). `nil` = that layer does not report it.
    /// `strictFrom`: layers before this index are references (only "had some, next has none" counts as lost);
    /// from it on, every drop counts. `tolerance`: a drop up to this fraction of the previous layer is not a loss
    /// (provider nodes: the tunnel may have downloaded a newer subscription than the App's cache).
    struct Metric {
        var name: String
        var layers: [(String, Int?)]
        var strictFrom = 0
        var tolerance = 0.0
    }

    struct Comparison: Equatable {
        var lost: [String] = []
        var table: [String] = []
    }

    static func compare(_ metrics: [Metric]) -> Comparison {
        var out = Comparison()
        for m in metrics {
            let known: [(Int, String, Int)] = m.layers.enumerated().compactMap { e -> (Int, String, Int)? in e.element.1.map { (e.offset, e.element.0, $0) } }
            guard !known.isEmpty else { continue }
            let row = known.map { "\($0.1) \($0.2)" }.joined(separator: " → ")
            out.table.append("\(m.name)：\(row)")
            var lostHere = false
            if known.count > 1 {
                for k in 1..<known.count {
                    let (ia, _, a) = known[k - 1]
                    let b = known[k].2
                    if ia < m.strictFrom {
                        if a > 0 && b == 0 { lostHere = true }
                    } else if Double(b) < Double(a) * (1 - m.tolerance) {
                        lostHere = true
                    }
                }
            }
            if lostHere { out.lost.append("\(m.name)：\(row)") }
        }
        return out
    }

    // MARK: delay

    /// Names that broke routing before: spaces, brackets, emoji, "/", "%", "+", "&", "?", "#".
    static func isTricky(_ name: String) -> Bool {
        name.unicodeScalars.contains { s in
            " []()（）【】/%+&?#|".unicodeScalars.contains(s) || s.properties.isEmojiPresentation || (s.value >= 0x1F1E6 && s.value <= 0x1F1FF)
        }
    }

    /// Up to `max` names, tricky ones first (one with "/" and one with an emoji/flag when there are any), stable order.
    static func sample(_ names: [String], max n: Int) -> [String] {
        guard n > 0 else { return [] }
        var picked: [String] = []
        func take(_ p: (String) -> Bool) {
            if picked.count < n, let x = names.first(where: { !picked.contains($0) && p($0) }) { picked.append(x) }
        }
        take { $0.contains("/") }
        take { $0.unicodeScalars.contains { $0.properties.isEmojiPresentation || ($0.value >= 0x1F1E6 && $0.value <= 0x1F1FF) } }
        take { $0.contains(" ") && ($0.contains("[") || $0.contains("(") || $0.contains("【")) }
        for x in names where picked.count < n && !picked.contains(x) && isTricky(x) { picked.append(x) }
        for x in names where picked.count < n && !picked.contains(x) { picked.append(x) }
        return picked
    }

    /// The newest `[delay] <name>: …` payload, without the "[delay] <name>: " head.
    static func delayLine(for name: String, in payloads: [String]) -> String? {
        let head = "[delay] \(name): "
        return payloads.last { $0.hasPrefix(head) }.map { String($0.dropFirst(head.count)) }
    }

    /// "timeout at stage ws after 5000 ms …" / "failed at stage tls (…)" → "ws" / "tls"; nil for a success line.
    static func delayStage(_ tail: String) -> String? {
        guard let r = tail.range(of: " at stage ") ?? (tail.hasPrefix("at stage ") ? tail.range(of: "at stage ") : nil) else { return nil }
        return tail[r.upperBound...].split(whereSeparator: { $0 == " " || $0 == "(" || $0 == "," }).first.map(String.init)
    }


    struct DelayFailure: Equatable {
        var stage: String
        var reason: String
        var nodes: [String]
    }

    /// Every failed `[delay]` line → (stage, reason) with the distinct nodes that hit it, most nodes first. Build 419:
    /// "ws · handshake failed: ws upgrade refused" ×25 and "tls · -9824: 握手失败" ×8 were hidden behind one count.
    static func delayFailures(_ payloads: [String]) -> [DelayFailure] {
        var order: [String] = []
        var map: [String: DelayFailure] = [:]
        for p in payloads where p.hasPrefix("[delay] ") {
            let body = p.dropFirst(8)
            var name = "", stage = "", reason = ""
            if let r = body.range(of: ": failed at stage ") ?? body.range(of: ": timeout at stage ") {
                name = String(body[..<r.lowerBound])
                let timeout = body[r].contains("timeout")
                var rest = body[r.upperBound...]
                if let bar = rest.range(of: " | ") { rest = rest[..<bar.lowerBound] }
                let st = rest.prefix { $0 != " " && $0 != "(" }
                stage = String(st)
                rest = rest.dropFirst(st.count)
                var paren = ""
                if let o = rest.firstIndex(of: "("), let c = rest.lastIndex(of: ")"), o < c {
                    paren = String(rest[rest.index(after: o)..<c])
                }
                if timeout {
                    reason = String(localized: "超时") + (paren.isEmpty ? "" : "（\(paren)）")
                } else {
                    reason = paren.isEmpty ? String(localized: "失败") : paren
                }
            } else if let r = body.range(of: ": not in the running config (404)") {
                name = String(body[..<r.lowerBound]); stage = "route"; reason = String(localized: "404 不在运行配置")
            } else if let r = body.range(of: ": tcp handshake to ") {
                name = String(body[..<r.lowerBound]); stage = "tcp"
                reason = body[r.upperBound...].range(of: "failed (").map { String(body[$0.upperBound...].dropLast()) } ?? String(localized: "失败")
            } else { continue }
            if reason.count > 90 { reason = String(reason.prefix(90)) + "…" }
            let key = stage + "\u{1}" + reason
            if map[key] == nil { order.append(key); map[key] = DelayFailure(stage: stage, reason: reason, nodes: []) }
            if !map[key]!.nodes.contains(name) { map[key]!.nodes.append(name) }
        }
        return order.compactMap { map[$0] }.enumerated()
            .sorted { $0.element.nodes.count != $1.element.nodes.count ? $0.element.nodes.count > $1.element.nodes.count : $0.offset < $1.offset }
            .map(\.element)
    }

    /// Up to `top` lines "stage · reason：N 个节点（例：a、b、c）".
    static func delayFailureLines(_ f: [DelayFailure], top: Int = 6) -> [String] {
        var out = f.prefix(top).map { x -> String in
            let ex = x.nodes.prefix(3).joined(separator: "、") + (x.nodes.count > 3 ? "…" : "")
            return String(localized: "\(x.stage) · \(x.reason)：\(x.nodes.count) 个节点（例：\(ex)）")
        }
        if f.count > top { out.append(String(localized: "…另有 \(f.count - top) 种失败原因")) }
        return out
    }

    /// Why the fetch step's requests failed, from the data-plane counter deltas around them. nil = counters look fine.
    static func fetchDiagnosis(before b: [String: Int], after a: [String: Int], tun: Bool) -> String? {
        func d(_ k: String) -> Int { (a[k] ?? 0) - (b[k] ?? 0) }
        let counters = "packets in +\(d("packets in")) · tcp accepted +\(d("tcp accepted")) · dns queries +\(d("dns queries")) / replies +\(d("dns replies")) / failed +\(d("dns failed"))"
        if tun && d("tcp accepted") == 0 {
            var s = String(localized: "隧道未收到 TCP 连接（tcp accepted \(a["tcp accepted"] ?? 0)，本次 +0）")
            if d("dns queries") == 0 { s += String(localized: "，DNS 查询也没有进入隧道") }
            else if d("dns replies") == 0 { s += String(localized: "，DNS 没有应答") }
            return s + "：" + counters
        }
        if d("dns queries") > 0 && d("dns replies") == 0 { return String(localized: "隧道收到 DNS 查询但没有应答：") + counters }
        if d("dns failed") > 0 && d("dns failed") >= d("dns replies") { return String(localized: "DNS 上游失败：") + counters }
        if d("tcp accepted") > 0 && d("relay ok") == 0 && d("direct") == 0 {
            return String(localized: "隧道收到 \(d("tcp accepted")) 个 TCP 连接，但没有一个转发成功（relay failed +\(d("relay failed"))，rejected +\(d("rejected"))）：") + counters
        }
        return nil
    }

    // MARK: rewrite probe

    /// A concrete https URL a rewrite rule pattern matches, or nil when the pattern has no literal scheme+host prefix.
    /// `^https?://ad\.example\.com/api/v\d/ad` → https://ad.example.com/api/v1/ad. The host must be literal (a host with
    /// regex in it — wildcards, groups, classes — is not probed); the path is synthesized from the regex (`\d`→1, `\w`→a,
    /// classes → a member, groups → first branch, `+`/`{n}` honoured, optional parts left out, retried with them in).
    /// fix/nc-diag-439 (B): the URL is only returned when the rule's own regex matches it — the old literal-prefix cut
    /// produced `…/kprime/v` for `…\/kprime\/v\d\/popups…`, which the rule never matches, so the self-check fired a
    /// request at the real server and reported "rule not hit".
    static func probeURL(fromPattern p: String) -> URL? {
        var s = Substring(p)
        if s.hasPrefix("^") { s = s.dropFirst() }
        var rest: Substring?
        for pre in ["https?://", "https?:\\/\\/", "https://", "https:\\/\\/", "http(s)?://", "(https?)://", "http(s)?:\\/\\/", "(https?):\\/\\/", "https?+:\\/\\/", "https?+://"] where s.hasPrefix(pre) {
            rest = s.dropFirst(pre.count); break
        }
        guard let rest else { return nil }
        // literal host
        var host = ""
        var i = rest.startIndex
        var pathStart: Substring.Index? = nil
        while i < rest.endIndex {
            let c = rest[i]
            if c == "\\" {
                let n = rest.index(after: i)
                guard n < rest.endIndex else { return nil }
                let e = rest[n]
                if e == "/" { pathStart = i; break }
                if e == "." || e == "-" { host.append(e); i = rest.index(after: n); continue }
                return nil // \d \w … inside the host
            }
            if c == "/" { pathStart = i; break }
            if c == "$" || c == ":" { pathStart = i; break }
            if c == "." || c == "-" || c.isLetter || c.isNumber { host.append(c); i = rest.index(after: i); continue }
            return nil // ^$*+?()[]{}| in the host
        }
        guard !host.isEmpty, host.contains("."), !host.hasPrefix("."), !host.hasSuffix("."),
              host.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }) else { return nil }
        if host.split(separator: ".").allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil } // bare IPv4
        let pathPattern = pathStart.map { String(rest[$0...]) } ?? ""
        guard let re = try? NSRegularExpression(pattern: p) else { return nil }
        func matches(_ u: String) -> Bool { re.firstMatch(in: u, range: NSRange(u.startIndex..., in: u)) != nil }
        for includeOptional in [false, true] {
            guard var path = RegexExample.generate(pathPattern, includeOptional: includeOptional) else { continue }
            if path.hasPrefix(":") { continue } // a port in the pattern: not probed
            if path.isEmpty { path = "/" }
            guard path.hasPrefix("/") else { continue }
            let url = "https://" + host + path
            if matches(url), let u = URL(string: url) { return u }
            // `…\.com` with no path in the pattern: also try the bare host
            if pathPattern.isEmpty, matches("https://" + host), let u = URL(string: "https://" + host + "/") { return u }
        }
        return nil
    }

    /// A small regex → example-string generator (ICU / JS syntax subset used by rewrite rules). nil when it meets a
    /// construct it cannot produce (backreferences, unbalanced groups).
    enum RegexExample {
        static func generate(_ pattern: String, includeOptional: Bool) -> String? {
            let chars = Array(pattern)
            var pos = 0
            return alternation(chars, &pos, includeOptional, depth: 0)
        }

        /// Reads one alternation up to `)` or the end; returns the first branch's example.
        private static func alternation(_ c: [Character], _ pos: inout Int, _ opt: Bool, depth: Int) -> String? {
            guard depth < 16 else { return nil }
            var first: String? = nil
            var cur = ""
            var branchDone = false
            while pos < c.count {
                let ch = c[pos]
                if ch == ")" { break }
                if ch == "|" {
                    if first == nil { first = cur }
                    branchDone = true
                    cur = ""
                    pos += 1
                    continue
                }
                guard let (atom, next) = atom(c, pos, opt, depth: depth) else { return nil }
                pos = next
                // quantifier
                var minRep = 1, maxRep = 1
                if pos < c.count {
                    switch c[pos] {
                    case "?": minRep = 0; maxRep = 1; pos += 1
                    case "*": minRep = 0; maxRep = 2; pos += 1
                    case "+": minRep = 1; maxRep = 2; pos += 1
                    case "{":
                        if let close = c[pos...].firstIndex(of: "}") {
                            let body = String(c[(pos + 1)..<close]).split(separator: ",", omittingEmptySubsequences: false)
                            if let n = Int(body.first ?? "") {
                                minRep = n
                                maxRep = body.count > 1 ? (Int(body[1]) ?? n + 1) : n
                                pos = close + 1
                            }
                        }
                    default: break
                    }
                    if pos < c.count, c[pos] == "?" || c[pos] == "+" { pos += 1 } // lazy / possessive
                }
                let reps = minRep > 0 ? minRep : (opt ? min(1, maxRep) : 0)
                if !branchDone || first == nil { cur += String(repeating: atom, count: reps) }
            }
            return first ?? cur
        }

        /// One atom at `pos`: its example text and the index after it.
        private static func atom(_ c: [Character], _ pos: Int, _ opt: Bool, depth: Int) -> (String, Int)? {
            let ch = c[pos]
            switch ch {
            case "^", "$": return ("", pos + 1)
            case ".": return ("a", pos + 1)
            case "\\":
                guard pos + 1 < c.count else { return nil }
                let e = c[pos + 1]
                switch e {
                case "d": return ("1", pos + 2)
                case "w": return ("a", pos + 2)
                case "s": return ("%20", pos + 2)
                case "S", "D": return ("a", pos + 2)
                case "W": return ("-", pos + 2)
                case "b", "B", "A", "z", "Z", "G": return ("", pos + 2)
                case "1", "2", "3", "4", "5", "6", "7", "8", "9": return nil
                default: return (String(e), pos + 2)
                }
            case "[":
                var i = pos + 1
                var negated = false
                if i < c.count, c[i] == "^" { negated = true; i += 1 }
                var members: [Character] = []
                var first = true
                while i < c.count, c[i] != "]" || first {
                    first = false
                    if c[i] == "\\", i + 1 < c.count {
                        switch c[i + 1] {
                        case "d": members.append("1")
                        case "w": members.append("a")
                        default: members.append(c[i + 1])
                        }
                        i += 2
                        continue
                    }
                    members.append(c[i])
                    i += 1
                }
                guard i < c.count else { return nil }
                let pick: Character
                if negated {
                    pick = ["a", "1", "x", "z"].first { !members.contains($0) } ?? "-"
                } else {
                    pick = members.first { $0 != "-" } ?? "a"
                }
                return (String(pick), i + 1)
            case "(":
                var i = pos + 1
                if i < c.count, c[i] == "?" {
                    // (?: … ) (?<name> … ) keep; look-arounds produce nothing
                    if i + 1 < c.count, c[i + 1] == "=" || c[i + 1] == "!" {
                        guard let close = matchingParen(c, pos) else { return nil }
                        return ("", close + 1)
                    }
                    if i + 2 < c.count, c[i + 1] == "<", c[i + 2] == "=" || c[i + 2] == "!" {
                        guard let close = matchingParen(c, pos) else { return nil }
                        return ("", close + 1)
                    }
                    if i + 1 < c.count, c[i + 1] == ":" || c[i + 1] == ">" { i += 2 }
                    else if i + 1 < c.count, c[i + 1] == "<" || c[i + 1] == "P" {
                        guard let gt = c[i...].firstIndex(of: ">") else { return nil }
                        i = gt + 1
                    } else { i += 1 }
                }
                var p = i
                guard let inner = alternation(c, &p, opt, depth: depth + 1), p < c.count, c[p] == ")" else { return nil }
                return (inner, p + 1)
            case ")", "|": return nil
            default:
                return (String(ch), pos + 1)
            }
        }

        private static func matchingParen(_ c: [Character], _ open: Int) -> Int? {
            var depth = 0
            var i = open
            var inClass = false
            while i < c.count {
                let ch = c[i]
                if ch == "\\" { i += 2; continue }
                if inClass { if ch == "]" { inClass = false }; i += 1; continue }
                if ch == "[" { inClass = true }
                else if ch == "(" { depth += 1 }
                else if ch == ")" { depth -= 1; if depth == 0 { return i } }
                i += 1
            }
            return nil
        }
    }

    /// fix/nc-diag-439 (B): a 5xx the native MitM produced itself carries its reason in the body
    /// ("Tern native MitM: <error>") — shown instead of a bare 502.
    static func mitmErrorNote(status: Int, body: Data) -> String {
        guard status >= 500, body.count < 4096, let t = String(data: body, encoding: .utf8),
              let r = t.range(of: "Tern native MitM: ") else { return "" }
        let why = t[r.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        return why.isEmpty ? "" : String(localized: "（MitM 返回：") + String(why.prefix(160)) + "）"
    }

    /// Patterns that only match plain http:// (port 80) — the TUN path does not run them through the rewrite engine.
    static func isPlainHTTPOnly(_ p: String) -> Bool {
        var s = Substring(p)
        if s.hasPrefix("^") { s = s.dropFirst() }
        return s.hasPrefix("http://") || s.hasPrefix("http:\\/\\/")
    }

    /// MitM host pattern ("*.example.com", "api.example.com", "-skip.example.com") matches host.
    static func hostMatches(_ pattern: String, _ host: String) -> Bool {
        var p = pattern.lowercased()
        if p.hasPrefix("-") { return false }
        if let colon = p.lastIndex(of: ":"), p[p.index(after: colon)...].allSatisfy(\.isNumber) { p = String(p[..<colon]) }
        let h = host.lowercased()
        if p == h || p == "*" { return true }
        if !p.contains("*") && !p.contains("?") { return false }
        let re = "^" + NSRegularExpression.escapedPattern(for: p).replacingOccurrences(of: "\\*", with: ".*").replacingOccurrences(of: "\\?", with: ".") + "$"
        return h.range(of: re, options: .regularExpression) != nil
    }


    // MARK: certificate signature

    /// DER TLV at `i` → (tag, content range, end). Definite lengths only (X.509 DER).
    private static func tlv(_ b: [UInt8], _ i: Int) -> (tag: UInt8, start: Int, end: Int)? {
        guard i + 2 <= b.count else { return nil }
        let tag = b[i]
        var len = Int(b[i + 1])
        var p = i + 2
        if len & 0x80 != 0 {
            let n = len & 0x7f
            guard n >= 1, n <= 4, p + n <= b.count else { return nil }
            len = 0
            for k in 0..<n { len = (len << 8) | Int(b[p + k]) }
            p += n
        }
        guard p + len <= b.count else { return nil }
        return (tag, p, p + len)
    }

    /// The signed part, algorithm and signature of an X.509 certificate.
    static func certSignatureParts(_ der: Data) -> (tbs: Data, algorithm: SecKeyAlgorithm?, algorithmName: String, signature: Data)? {
        let b = [UInt8](der)
        guard let cert = tlv(b, 0), cert.tag == 0x30,
              let tbs = tlv(b, cert.start), tbs.tag == 0x30,
              let alg = tlv(b, tbs.end), alg.tag == 0x30,
              let oid = tlv(b, alg.start), oid.tag == 0x06,
              let sig = tlv(b, alg.end), sig.tag == 0x03, sig.end > sig.start else { return nil }
        let o = Array(b[oid.start..<oid.end])
        let ecPrefix: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03]
        let rsaPrefix: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01]
        var a: SecKeyAlgorithm?
        var name = o.map { String($0) }.joined(separator: ".")
        if o.count == 8, Array(o.prefix(7)) == ecPrefix {
            switch o[7] {
            case 2: a = .ecdsaSignatureMessageX962SHA256; name = "ecdsa-with-SHA256"
            case 3: a = .ecdsaSignatureMessageX962SHA384; name = "ecdsa-with-SHA384"
            case 4: a = .ecdsaSignatureMessageX962SHA512; name = "ecdsa-with-SHA512"
            default: break
            }
        } else if o.count == 9, Array(o.prefix(8)) == rsaPrefix {
            switch o[8] {
            case 5: a = .rsaSignatureMessagePKCS1v15SHA1; name = "sha1WithRSA"
            case 11: a = .rsaSignatureMessagePKCS1v15SHA256; name = "sha256WithRSA"
            case 12: a = .rsaSignatureMessagePKCS1v15SHA384; name = "sha384WithRSA"
            case 13: a = .rsaSignatureMessagePKCS1v15SHA512; name = "sha512WithRSA"
            default: break
            }
        }
        // BIT STRING: first content byte = unused bits (0 for signatures).
        let sigBytes = Data(b[(sig.start + 1)..<sig.end])
        // The signed bytes are the whole tbsCertificate TLV (tag + length + content), which starts at cert.start.
        return (Data(b[cert.start..<tbs.end]), a, name, sigBytes)
    }

    /// nil = cannot tell (unknown algorithm / not a certificate); true / false = the self-signature verifies or not.
    static func verifySelfSignature(_ der: Data) -> (ok: Bool?, why: String) {
        guard let parts = certSignatureParts(der), let cert = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(cert) else { return (nil, "not a certificate") }
        guard let alg = parts.algorithm else { return (nil, "unsupported algorithm \(parts.algorithmName)") }
        guard SecKeyIsAlgorithmSupported(key, .verify, alg) else { return (nil, "key does not support \(parts.algorithmName)") }
        var err: Unmanaged<CFError>?
        let ok = SecKeyVerifySignature(key, alg, parts.tbs as CFData, parts.signature as CFData, &err)
        if !ok, let e = err?.takeRetainedValue() { return (false, "\(parts.algorithmName): \((e as Error).localizedDescription)") }
        return (ok, parts.algorithmName)
    }

    // MARK: errors / urls

    /// A URL for display: "host/…/last" (no query, no user info), like the tunnel's rule-set log names.
    static func shortURL(_ s: String) -> String {
        guard let c = URLComponents(string: s.trimmingCharacters(in: .whitespacesAndNewlines)), let h = c.host, !h.isEmpty else {
            return s.count > 60 ? String(s.prefix(60)) + "…" : s
        }
        let last = c.path.split(separator: "/").last.map(String.init) ?? ""
        return last.isEmpty ? h : h + "/…/" + last
    }

    /// One readable cause for a failed request: HTTP code, DNS, TLS, timeout, refused, offline — with domain + code.
    static func describe(_ error: Error) -> String {
        let ns = error as NSError
        if ns.domain == NSURLErrorDomain {
            let what: String
            switch ns.code {
            case NSURLErrorTimedOut: what = String(localized: "超时")
            case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed: what = String(localized: "DNS 解析失败")
            case NSURLErrorCannotConnectToHost: what = String(localized: "连接被拒绝")
            case NSURLErrorNetworkConnectionLost: what = String(localized: "连接中断")
            case NSURLErrorNotConnectedToInternet: what = String(localized: "没有网络")
            case NSURLErrorSecureConnectionFailed: what = String(localized: "TLS 握手失败")
            case NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateHasUnknownRoot,
                 NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected, NSURLErrorClientCertificateRequired:
                what = String(localized: "TLS 证书不被信任")
            case NSURLErrorBadServerResponse: what = String(localized: "服务器响应无效")
            case NSURLErrorCancelled: what = String(localized: "已取消")
            case NSURLErrorAppTransportSecurityRequiresSecureConnection: what = String(localized: "ATS 拒绝明文 HTTP")
            default: what = ns.localizedDescription
            }
            return "\(what)（\(ns.domain) \(ns.code)）"
        }
        let d = error.localizedDescription
        return d.count > 120 ? String(d.prefix(120)) + "…" : d
    }

    // MARK: memory

    struct MemorySample: Equatable {
        var label: String
        var footprint: Double // MB
        var peak: Double      // MB
        var available: Double // MB, -1 unknown
    }

    /// The extension's .memoryStats JSON (footprint / peak / available in bytes) → sample.
    static func memorySample(_ data: Data?, label: String) -> MemorySample? {
        guard let data, let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let fp = (o["footprint"] as? NSNumber)?.doubleValue else { return nil }
        let mb = 1_048_576.0
        let peak = (o["peak"] as? NSNumber)?.doubleValue ?? fp
        let avail = (o["available"] as? NSNumber)?.doubleValue ?? -1
        return MemorySample(label: label, footprint: fp / mb, peak: peak / mb, available: avail >= 0 ? avail / mb : -1)
    }

    /// (state ok?, detail). Limit ≈ footprint + available (os_proc_available_memory). Fails at ≥ 90 % of the limit
    /// or under 4 MB left.
    static func memoryVerdict(_ samples: [MemorySample]) -> (ok: Bool, detail: String) {
        guard !samples.isEmpty else { return (true, "") }
        let f = { (v: Double) in String(format: "%.1f", v) }
        let limit = samples.compactMap { $0.available >= 0 ? $0.footprint + $0.available : nil }.max()
        let peak = max(samples.map(\.peak).max() ?? 0, samples.map(\.footprint).max() ?? 0)
        let minAvail = samples.compactMap { $0.available >= 0 ? $0.available : nil }.min()
        var ok = true
        var head: String
        if let limit, limit > 0 {
            head = String(localized: "峰值 \(f(peak)) MB / 上限约 \(f(limit)) MB（\(Int(peak / limit * 100))%）")
            if peak >= limit * 0.9 { ok = false }
        } else {
            head = String(localized: "峰值 \(f(peak)) MB（系统没有给出上限）")
        }
        if let minAvail {
            head += " · " + String(localized: "最少剩余 \(f(minAvail)) MB")
            if minAvail < 4 { ok = false }
        }
        if !ok { head = String(localized: "隧道内存接近系统上限：") + head }
        let series = samples.map { "\($0.label) \(f($0.footprint))" }.joined(separator: " · ")
        return (ok, head + "\n" + String(localized: "各步骤后（MB）：") + series)
    }

    // MARK: report

    struct ReportStep {
        var mark: String // PASS FAIL KNOWN SKIP SKIP(需要真机) -
        var title: String
        var detail: String
    }

    /// selfcheck.txt: header, summary, then every FAIL with its one-line cause (the detail's first line), then KNOWN,
    /// then every step with its full detail.
    static func report(header: String, summary: String, steps: [ReportStep]) -> String {
        var out = [header, summary, ""]
        let fails = steps.filter { $0.mark == "FAIL" }
        let known = steps.filter { $0.mark == "KNOWN" }
        if !fails.isEmpty {
            out.append(String(localized: "== 失败（先看这里）=="))
            for s in fails { out.append("FAIL \(s.title)：\(firstLine(s.detail))") }
            out.append("")
        }
        if !known.isEmpty {
            out.append(String(localized: "== 已知缺口 =="))
            for s in known { out.append("KNOWN \(s.title)：\(firstLine(s.detail))") }
            out.append("")
        }
        out.append(String(localized: "== 详情 =="))
        for s in steps {
            out.append("[\(s.mark)] \(s.title)")
            if !s.detail.isEmpty { out.append("    " + s.detail.replacingOccurrences(of: "\n", with: "\n    ")) }
        }
        return out.joined(separator: "\n") + "\n"
    }

    static func firstLine(_ s: String) -> String {
        let l = s.split(separator: "\n", maxSplits: 1).first.map(String.init) ?? "-"
        return l.count > 200 ? String(l.prefix(200)) + "…" : l
    }

    /// At most `n` lines, then "…另 k 项".
    static func capped(_ lines: [String], _ n: Int) -> [String] {
        lines.count <= n ? lines : Array(lines.prefix(n)) + [String(localized: "…另 \(lines.count - n) 项")]
    }

    // MARK: regex helpers

    private static func firstMatchStrings(_ pattern: String, _ s: String) -> [String]? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }

    private static func firstMatch(_ pattern: String, _ s: String) -> [Int]? {
        firstMatchStrings(pattern, s)?.compactMap { Int($0) }
    }
}
