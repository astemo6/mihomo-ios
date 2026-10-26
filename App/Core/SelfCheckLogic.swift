import Foundation

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
            let known = m.layers.enumerated().compactMap { i, l in l.1.map { (i, l.0, $0) } }
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

    // MARK: rewrite probe

    /// A concrete https URL a rewrite rule pattern matches, or nil when the pattern has no literal scheme+host prefix.
    /// `^https?://ad\.example\.com/api/v1/ad` → https://ad.example.com/api/v1/ad. Stops at the first regex meta
    /// character after the host; a host with regex in it (wildcards, groups, classes) is not used.
    static func probeURL(fromPattern p: String) -> URL? {
        var s = Substring(p)
        if s.hasPrefix("^") { s = s.dropFirst() }
        for pre in ["https?://", "https?:\\/\\/", "https://", "https:\\/\\/", "http(s)?://", "(https?)://"] where s.hasPrefix(pre) {
            s = s.dropFirst(pre.count)
            return literalURL(host: s)
        }
        return nil
    }

    private static func literalURL(host rest: Substring) -> URL? {
        var out = ""
        var i = rest.startIndex
        var inHost = true
        while i < rest.endIndex {
            let c = rest[i]
            if c == "\\" {
                let n = rest.index(after: i)
                guard n < rest.endIndex else { break }
                let e = rest[n]
                if ".-/_~=&:".contains(e) || e == "?" {
                    if e == "/" { inHost = false }
                    out.append(e); i = rest.index(after: n); continue
                }
                break // \d \w \S … : end of the literal part
            }
            if "^$*+?()[]{}|".contains(c) { break }
            if c == "." && !inHost { break } // unescaped "." in the path = any character
            if c == "/" { inHost = false }
            out.append(c)
            i = rest.index(after: i)
        }
        let host = out.split(separator: "/", maxSplits: 1).first.map(String.init) ?? ""
        guard !host.isEmpty, host.contains("."), host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }),
              !host.hasPrefix("."), !host.hasSuffix(".") else { return nil }
        if host.split(separator: ".").allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil } // bare IPv4
        return URL(string: "https://" + (out.contains("/") ? out : out + "/"))
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
