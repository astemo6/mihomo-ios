// Native MitM stage 3b — body rewrites (regex / Loon json / jq) in Swift, for requests the native rewrite
// engine forwards itself (switch `nativeMitmBody`, default OFF; it only acts when `nativeMitmRewrite` is on too).
//
// What the old core does for a body rule is replayed
// on the rules the old core exported as portable (bodysnap.go): the request body is read whole (≤ 256 KB, known length),
// the response body is read whole (≤ 256 KB announced length), decoded (NativeBodyDecode), every matching rule
// applied in rule order with header rules in between, and the result sent with Content-Length — the same bytes,
// status and headers the old flow API would produce (UnitTests/NativeMitmBodyTests.swift replays old-core-generated
// cases byte for byte).
//
// The moment anything is uncertain — the body is not UTF-8 for a regex, not JSON for a json / jq rule, a jq step
// would error, an encoding is not decoded exactly like the old core, the body is larger than 256 KB, a regex runs too long —
// the result is .handBack and NativeRewriteDriver gives the exchange to the old flow ("adopt").

import Foundation

// MARK: - Switch

enum NativeBodyRuntime {
    /// App-group key; default OFF. Needs `nativeMitmRewrite` on as well (the body rules ride on its decisions).
    static let defaultsKey = "nativeMitmBody"
    /// Bodies above this (raw or decoded) are left to the old core.
    static let maxBody = 256 << 10
    /// A regex body rewrite slower than this is abandoned and the exchange handed to the old core (RE2 is linear; ICU
    /// backtracks).
    static var regexBudget: TimeInterval = 0.25

    static var override: Bool?

    private static let lock = NSLock()
    private static var cached: Bool?
    private static var readAt: TimeInterval = 0

    /// Explicit app-group value, else ON while selective native mode is installed (feat/selective-native).
    static var enabled: Bool {
        if let o = override { return o }
        lock.lock()
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = NativeMitmRuntime.explicitSwitch(defaultsKey)
        }
        let explicit = cached
        lock.unlock()
        return NativeMitmRuntime.engineSwitch(explicit: explicit)
    }
}

// MARK: - Snapshot additions (bodysnap.go)

struct RWSnapReplPart: Decodable {
    var l: String?
    var g: Int
}

struct RWSnapBodyOp: Decodable {
    var icu: String?
    var parts: [RWSnapReplPart]?
    var skip: Bool?
    /// native-only (lane regexp2): an op the snapshot could not spell as explicit ICU is exported as its source — the
    /// pattern `p` and the raw replacement `repl` (regexp2's path: Replace(body, repl, -1, -1)), or with `re2` the
    /// RE2 pattern of the old core's fast path and its parsed `parts`. RX2ICU translates it when the rule is built.
    var p: String?
    var repl: String?
    var re2: Bool?
}

struct RWSnapJSONOp: Decodable {
    var op: String
    var path: [BodyJSONKey]
    var v: String
}

struct RWSnapJQStep: Decodable {
    var op: String
    var path: [BodyJSONKey]?
    var paths: [[BodyJSONKey]]?
    var v: String?
    var cond: RWSnapJQCond?
}

/// A select() condition (bodysnap.go SnapJQCond).
final class RWSnapJQCond: Decodable {
    var k: String
    var a: RWSnapJQCond?
    var b: RWSnapJQCond?
    var p: [BodyJSONKey]?
    var v: String?
    var key: String?
}

// MARK: - A compiled body rule

final class NativeBodyRule {
    enum Part { case lit(String), group(Int) }
    enum RegexOp { case skip, replace(NSRegularExpression, [Part]), rx2(RWRegex, RWSnapTemplate) }
    enum JQStep { case set([BodyJSONKey], BodyJSON), del([[BodyJSONKey]]), filter([BodyJSONKey], BodyJQ.Cond) }

    let index: Int
    let kind: String
    private(set) var regexOps: [RegexOp] = []
    private(set) var jsonOps: [(op: String, path: [BodyJSONKey], value: BodyJSON)] = []
    private(set) var jqSteps: [JQStep] = []
    /// fix/nc-jq-full: the full jq filter (NativeJQ), compiled once per rule
    private(set) var jqProgram: NativeJQ.Program?

    /// nil: the old core did not mark the rule portable, or Swift cannot build it exactly (then the old core handles the request).
    init?(_ r: RWSnapRule) {
        guard r.bodyOK == true else { return nil }
        index = r.i
        kind = r.kind
        switch r.kind {
        case "body":
            for op in r.body ?? [] {
                if op.skip == true { regexOps.append(.skip); continue }
                if (op.icu ?? "").isEmpty, let src = op.p, !src.isEmpty {
                    guard let built = NativeBodyRule.sourceOp(src, op) else { return nil }
                    regexOps.append(built)
                    continue
                }
                guard let icu = op.icu, !icu.isEmpty, let re = try? NSRegularExpression(pattern: icu, options: []) else { return nil }
                var parts: [Part] = []
                for p in op.parts ?? [] {
                    if p.g < 0 { parts.append(.lit(p.l ?? "")) } else {
                        guard p.g <= re.numberOfCaptureGroups else { return nil }
                        parts.append(.group(p.g))
                    }
                }
                regexOps.append(.replace(re, parts))
            }
        case "json":
            for op in r.jsonOps ?? [] {
                guard let v = BodyJSON.parse(op.v) else { return nil }
                jsonOps.append((op.op, op.path, v))
            }
        case "jq":
            if let src = r.jqx {
                do {
                    jqProgram = try NativeJQ.compile(src)
                } catch {
                    NativeBodyRule.warn("jq rule #\(r.i) not loaded (\(error)) — its bodies pass through unchanged")
                    return nil
                }
                break
            }
            for s in r.jq ?? [] {
                switch s.op {
                case "set":
                    guard let vs = s.v, let v = BodyJSON.parse(vs) else { return nil }
                    jqSteps.append(.set(s.path ?? [], v))
                case "del":
                    jqSteps.append(.del(s.paths ?? []))
                case "filter":
                    guard let c = s.cond.flatMap(BodyJQ.Cond.init) else { return nil }
                    jqSteps.append(.filter(s.path ?? [], c))
                default:
                    return nil
                }
            }
        default:
            return nil
        }
    }

    /// A source-exported op (see RWSnapBodyOp.p): regexp2 → RWRegex + regexp2's replacement program; RE2 → an
    /// ICU expression with the old core's parsed parts. nil: RX2ICU / ICU refuse it (the rule stays skipped).
    static func sourceOp(_ p: String, _ op: RWSnapBodyOp) -> RegexOp? {
        if op.re2 == true {
            guard let t = RX2ICU.translate(p, dialect: .re2).0,
                  let re = try? NSRegularExpression(pattern: t.icu, options: []), re.numberOfCaptureGroups == t.groups else { return nil }
            var parts: [Part] = []
            for x in op.parts ?? [] {
                if x.g < 0 { parts.append(.lit(x.l ?? "")) } else {
                    guard x.g <= t.groups else { return nil }
                    parts.append(.group(x.g))
                }
            }
            return .replace(re, parts)
        }
        guard let t = RX2ICU.translate(p).0 else { return nil }
        let src = RWSnapRegex(p: p, ok: true, icu: t.icu, slots: t.identity ? nil : t.slots, lit: nil, fold: nil,
                              groups: t.groups, named: t.names.isEmpty ? nil : true, empty: nil)
        let rx = RWRegex(src)
        guard rx.compiles else { return nil }
        // a replacement regexp2 rejects makes the old core's rule fail (skipped): the same here
        guard case (let tp?, false) = RX2ICU.template(op.repl ?? "", t) else { return nil }
        return .rx2(rx, tp)
    }

    /// skipped: the rule did not apply (jq: body not JSON / filter error / no output) — the body stays as it was and
    /// the rule is not listed as matched (a warning goes to the log).
    enum Applied { case body(Data), handBack(String), skipped(String) }

    static func warn(_ line: String) {
        NCDiagLimiter.shared.line("[Rewrite] \(line)", level: "warning")
    }

    /// applyBodyRule(rule, body) where the old core succeeds; .handBack where the old core would fail (it then skips the rule — a
    /// result Swift does not reproduce) or where Swift cannot be sure.
    func apply(_ body: Data) -> Applied {
        switch kind {
        case "body": return applyRegex(body)
        case "json":
            guard var v = BodyJSON.parse(body) else { return .handBack("not json") }
            for op in jsonOps { v = BodyJSONEdit.edit(v, op.path[...], op.op, op.value) }
            guard let out = v.encoded() else { return .handBack("encode") }
            return .body(out)
        case "jq":
            if let prog = jqProgram {
                switch NativeJQ.apply(prog, body: body) {
                case .body(let out):
                    return .body(out)
                case .skip(let why):
                    NativeRewriteEngine.noteSkip("jq: " + why)
                    NativeBodyRule.warn("jq rule #\(index) skipped, body passed through: \(why)")
                    return .skipped(why)
                }
            }
            guard var v = BodyJSON.parse(body) else { return .handBack("not json") }
            do {
                for s in jqSteps {
                    switch s {
                    case .set(let p, let n): v = try BodyJQ.setpath(v, p, n)
                    case .del(let ps): v = try BodyJQ.delpaths(v, ps)
                    case .filter(let p, let c): v = try BodyJQ.filter(v, p, c)
                    }
                }
            } catch {
                return .handBack("jq error")
            }
            guard let out = v.encoded() else { return .handBack("encode") }
            return .body(out)
        default:
            return .handBack("kind")
        }
    }

    /// the old core's regexp ReplaceAll(body, template) for each op in turn (RE2 matches are never empty here: the old core only takes
    /// the RE2 path for non-nullable patterns and the old core marks nullable ones not portable).
    private func applyRegex(_ body: Data) -> Applied {
        let bytes = [UInt8](body)
        guard BodyJSON.validUTF8(bytes) else { return .handBack("not utf-8") }
        var s = String(decoding: bytes, as: UTF8.self)
        let deadline = Date().addingTimeInterval(NativeBodyRuntime.regexBudget)
        for op in regexOps {
            if case .rx2(let rx, let tp) = op {
                // regexp2 Replace(s, repl, -1, -1): every match, empty ones included, walked like regexp2 does
                guard let re = rx.regex else { return .handBack("regex") }
                let ns = s as NSString
                var out = ""
                var last = 0
                var slow = false, bad = false
                re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: ns.length)) { m, _, stop in
                    if Date() > deadline { slow = true; stop.pointee = true; return }
                    guard let m = m else { return }
                    guard let rep = rx.run(tp, m, ns) else { bad = true; stop.pointee = true; return }
                    out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
                    out += rep
                    last = m.range.location + m.range.length
                }
                if slow { return .handBack("regex time") }
                if bad { return .handBack("replacement") }
                out += ns.substring(from: last)
                s = out
                continue
            }
            guard case .replace(let re, let parts) = op else { continue }
            let ns = s as NSString
            var out = ""
            var last = 0
            var slow = false
            var empty = false
            re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: ns.length)) { m, _, stop in
                if Date() > deadline { slow = true; stop.pointee = true; return }
                guard let m = m else { return }
                let r = m.range
                if r.length == 0 { empty = true; stop.pointee = true; return }
                out += ns.substring(with: NSRange(location: last, length: r.location - last))
                for p in parts {
                    switch p {
                    case .lit(let l): out += l
                    case .group(let g):
                        let gr = m.range(at: g)
                        if gr.location != NSNotFound { out += ns.substring(with: gr) }
                    }
                }
                last = r.location + r.length
            }
            if slow { return .handBack("regex time") }
            if empty { return .handBack("empty match") }
            out += ns.substring(from: last)
            s = out
        }
        return .body(Data(s.utf8))
    }
}

// MARK: - Request body (handler.go requestPhase, body rules on a request Swift forwards)

struct NativeRequestBodyPlan {
    var rules: [NativeBodyRule]
    var length: Int64
}

enum NativeRequestBodyResult {
    /// The body to send (the old core: setBody after each rule; mode read, or none when it ended up empty).
    case body(Data)
    case handBack(String)
}

enum NativeBodyExec {
    static func request(_ plan: NativeRequestBodyPlan, body: Data) -> NativeRequestBodyResult {
        if Int64(body.count) != plan.length || body.count > NativeBodyRuntime.maxBody { return .handBack("request body length") }
        var b = body
        for r in plan.rules {
            switch r.apply(b) {
            case .body(let nb): b = nb
            case .handBack(let why): return .handBack(why)
            case .skipped: continue
            }
        }
        return .body(b)
    }

    struct Response {
        var status: Int
        var headers: [[String]]     // decision headers (no Content-Length / Transfer-Encoding)
        var length: Int64
        var body: Data
        var note: String?
        var logHeaders: [[String]]  // resp.Header at ent.Response (Content-Length set)
        var rules: [Int]            // ent.Match order
    }

    enum ResponseResult { case native(Response), handBack(String) }

    /// Whether the response head lets Swift take the body (else the exchange is handed to the old core before any byte).
    static func responseHeadOK(status: Int, headers: [[String]], length: Int64, method: String) -> String? {
        let h = CanonicalHeader(pairs: headers)
        if status == 101 { return "upgrade" }
        if method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status) { return "no body" }
        if !h.values("Transfer-Encoding").isEmpty { return "chunked" }
        var cl = length
        let clh = h.get("Content-Length")
        if !clh.isEmpty {
            guard let n = Int64(RWAscii.trimSpace(clh)), n >= 0 else { return "content-length" }
            cl = n
        }
        if cl <= 0 { return "empty or unknown length" }
        if cl > Int64(NativeBodyRuntime.maxBody) { return "large body" }
        return nil
    }

    /// runResponse + modifyResponse for a plan of header and body rules, on the whole raw (still encoded) body.
    static func response(_ steps: [RewriteDecision.ResponseStep], status: Int, headers: [[String]], length: Int64,
                         raw: Data) -> ResponseResult {
        var h = CanonicalHeader(pairs: headers)
        var contentLength = length
        if !h.values("Transfer-Encoding").isEmpty { return .handBack("chunked") }
        let clh = h.get("Content-Length")
        if !clh.isEmpty, let n = Int64(RWAscii.trimSpace(clh)), n >= 0 { contentLength = n }
        guard contentLength == Int64(raw.count), raw.count > 0, raw.count <= NativeBodyRuntime.maxBody else { return .handBack("body length") }
        h.removeHopByHop()
        var body = Data()
        var loaded = false
        var rules: [Int] = []
        func setBody(_ b: Data) {
            body = b
            h.set("Content-Length", String(b.count))
            h.del("Content-Encoding")
            h.del("Transfer-Encoding")
        }
        for step in steps {
            switch step {
            case .header(let ops, let i):
                rules.append(i)
                guard NativeRewriteEngine.apply(ops, to: &h, firstLine: "HTTP/1.1 " + NetStatus.status(status)) else { return .handBack("header op input") }
            case .body(let rule):
                if !loaded {
                    loaded = true
                    let enc = h.get("Content-Encoding")
                    switch NativeBodyDecode.decode(enc, raw, limit: NativeBodyRuntime.maxBody) {
                    case .decoded(let d):
                        if d.count != raw.count || !h.get("Content-Encoding").isEmpty { h.del("Content-Encoding") }
                        body = d
                    case .unsupported(let why):
                        return .handBack("decode: \(why)")
                    }
                }
                switch rule.apply(body) {
                case .body(let nb):
                    rules.append(rule.index)
                    setBody(nb)
                case .handBack(let why):
                    return .handBack(why)
                case .skipped:
                    break
                }
            }
        }
        guard loaded else { return .handBack("no body rule") }
        setBody(body)
        let logHeaders = h.sortedPairs
        h.del("Content-Length")
        h.del("Transfer-Encoding")
        let ct = h.get("Content-Type")
        let media = RWAscii.lower(RWAscii.trimSpace(String(ct.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")))
        return .native(Response(status: status, headers: h.sortedPairs, length: Int64(body.count), body: body,
                                note: media == "text/event-stream" ? "flush" : nil, logHeaders: logHeaders, rules: rules))
    }
}
