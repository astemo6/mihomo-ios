import Foundation

extension NCCanonicalConfig {
    /// Compiles the canonical MitM, rewrite, and script rules into an RWSnapshot
    /// that NativeRewriteEngine evaluates.
    func buildRewriteSnapshot(gen: Int64 = 1) -> RWSnapshot {
        var inc: [RWSnapHost] = []
        var exc: [RWSnapHost] = []

        for raw in mitm.hostnames {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            if trimmed.hasPrefix("-") {
                let pat = String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
                let (host, port) = Self.parseHostPort(pat)
                exc.append(RWSnapHost(pat: host, port: port))
            } else {
                let (host, port) = Self.parseHostPort(trimmed)
                inc.append(RWSnapHost(pat: host, port: port))
            }
        }

        var snapRules: [RWSnapRule] = []
        var idx = 0

        for r in rewrites {
            var rule = RWSnapRule(i: idx, kind: r.kind, phase: r.phase)
            rule.re = RWSnapRegex(p: r.pattern, ok: true, groups: 1)
            rule.action = r.action
            rule.target = r.target

            if r.kind == "url" {
                // Review M1: 302 / 307 / header need the replacement compiled into a
                // template, or the engine skips the rule ("redirect/rewrite template").
                // groups = the pattern's real capture count so $N resolves.
                let compiled = try? NSRegularExpression(pattern: r.pattern, options: [])
                rule.re = RWSnapRegex(p: r.pattern, ok: compiled != nil, groups: compiled?.numberOfCaptureGroups ?? 0)
                let a = r.action ?? ""
                if a == "302" || a == "307" || a == "header" {
                    rule.tp = Self.replacementTemplate(r.target ?? "", groups: compiled?.numberOfCaptureGroups ?? 0)
                }
                rule.targetOK = true
            } else if r.kind == "header" {
                let op = r.extra["op"] ?? "replace"
                let name = r.extra["header"] ?? ""
                rule.headers = [RWSnapHeaderOp(op: op, name: name, value: r.target)]
                rule.opsOK = true
            } else if r.kind == "maplocal" {
                let status = Int(r.extra["status"] ?? "200") ?? 200
                let bodyData = r.target?.data(using: .utf8)
                rule.local = RWSnapLocal(status: status, headers: [], body: bodyData, file: nil)
            }
            snapRules.append(rule)
            idx += 1
        }

        for s in scripts {
            let phase = s.type == "http-response" ? "response" : "request"
            var rule = RWSnapRule(i: idx, kind: "script", phase: phase)
            rule.re = RWSnapRegex(p: s.pattern, ok: true, groups: 1)
            rule.script = RWSnapScript(name: s.name, type: s.type, requiresBody: s.requiresBody)
            snapRules.append(rule)
            idx += 1
        }

        return RWSnapshot(
            version: 1,
            gen: gen,
            on: mitm.enabled || !mitm.hostnames.isEmpty,
            capture: mitm.captureBodies,
            inc: inc,
            exc: exc,
            rules: snapRules,
            total: snapRules.count,
            portable: snapRules.count
        )
    }

    /// A Surge / Loon URL replacement ($1, ${1}, $&, $$) as an RWSnapTemplate:
    /// r >= 0 -> literal s[r]; r <= -5 -> capture slot -5-r. A `$` that names no
    /// existing group stays literal (regexp2 does the same).
    static func replacementTemplate(_ repl: String, groups: Int) -> RWSnapTemplate {
        var lits: [String] = []
        var refs: [Int] = []
        var lit = ""
        func flush() {
            if !lit.isEmpty {
                lits.append(lit)
                refs.append(lits.count - 1)
                lit = ""
            }
        }
        func slot(_ n: Int) {
            flush()
            refs.append(-5 - n)
        }
        let c = Array(repl)
        var i = 0
        while i < c.count {
            let ch = c[i]
            if ch != "$" || i + 1 >= c.count {
                lit.append(ch)
                i += 1
                continue
            }
            let d = c[i + 1]
            if d == "$" {
                lit.append("$")
                i += 2
            } else if d == "&" {
                slot(0)
                i += 2
            } else if d.isASCII, d.isNumber {
                var j = i + 1
                while j < c.count && c[j].isASCII && c[j].isNumber { j += 1 }
                // longest prefix of the digits that names an existing group
                var k = j
                var found = -1
                while k > i + 1 {
                    if let n = Int(String(c[(i + 1)..<k])), n <= groups { found = n; break }
                    k -= 1
                }
                if found >= 0 {
                    slot(found)
                    i = k
                } else {
                    lit.append(contentsOf: c[i..<j])
                    i = j
                }
            } else if d == "{", let close = c[(i + 2)...].firstIndex(of: "}"),
                      let n = Int(String(c[(i + 2)..<close])), n >= 0, n <= groups {
                slot(n)
                i = close + 1
            } else {
                lit.append("$")
                i += 1
            }
        }
        flush()
        return RWSnapTemplate(s: lits.isEmpty ? nil : lits, r: refs)
    }

    private static func parseHostPort(_ pat: String) -> (String, Int?) {
        if let colon = pat.lastIndex(of: ":"),
           let port = Int(pat[pat.index(after: colon)...]) {
            return (String(pat[..<colon]), port)
        }
        return (pat, nil)
    }
}
