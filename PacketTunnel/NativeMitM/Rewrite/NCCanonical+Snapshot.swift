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

    private static func parseHostPort(_ pat: String) -> (String, Int?) {
        if let colon = pat.lastIndex(of: ":"),
           let port = Int(pat[pat.index(after: colon)...]) {
            return (String(pat[..<colon]), port)
        }
        return (pat, nil)
    }
}
