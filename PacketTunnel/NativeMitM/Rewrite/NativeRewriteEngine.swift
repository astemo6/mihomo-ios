// Native MitM stage 3a — the rewrite decision engine in Swift.
//
// Evaluates the Ruleset snapshot Go exports (RewriteSnapshot.swift) for one HTTP/1.1 request on a decrypted
// connection and reproduces what the Go flow API (bridge/mitm/flow.go FlowBegin / FlowResponse, i.e. handler.go
// requestPhase + flowOutbound and modifyResponse) would answer:
//
//   1. URL rewrite, first match: reject / reject-200 / reject-img / reject-dict / reject-array → local answer,
//      reject-drop → drop, 302 / 307 → local redirect (regexp2 replacement), header → the request goes on to the
//      rewritten URL.
//   2. Map Local, first match: the inline answer Go precomputed (text / json / base64 / tiny-gif).
//   3. Request header rewrites (add / del / replace / replace-regex, Host handled like Go) in rule order.
//   4. Response rules against the final URL: header rewrites are applied natively to the upstream's head.
//   5. The outbound request exactly as httputil.ReverseProxy would send it (hop-by-hop headers, Te: trailers,
//      Upgrade, Forwarded / X-Forwarded-*), the body passed through untouched.
//
// Everything else is .go(reason): the session asks the Go flow as before. That covers any script (request or
// response — the JSC host runs it through Go), body / jq / json rewrites, Map Local from a file, QX url-and-header
// conditions and raw header regex, any pattern / replacement Go did not mark portable or ICU will not compile, and
// any input Swift cannot prove Go reads the same way (non-ASCII or odd request targets, hosts, Content-Length…).
// Deferring is always correct; deciding natively must be identical — UnitTests/NativeMitmRewriteTests.swift
// replays Go-generated decisions (bridge/mitm/rewritesnap_test.go) to hold it to that.

import Foundation

/// A request head as the flow API receives it (FlowHead).
struct RewriteRequest {
    var method: String
    var target: String
    var host: String          // Host header value the session saw ("" none)
    var headers: [[String]]   // wire order, duplicates kept (Host / Transfer-Encoding may be included)
    var length: Int64         // >= 0 Content-Length, -1 chunked / unknown
    var connHost: String
    var connPort: Int
    var tls: Bool = true
}

/// What a native decision tells the request log (bridge/mitm/nativerecord.go): what Go's requestPhase would have
/// written into the Entry up to the decision.
struct RewriteLog {
    var rules: [Int] = []          // Ruleset indices in Go's Match order
    var url = ""                   // the URL at the decision (after a header URL rewrite)
    var host = ""                  // r.Host as the request arrived (Go strips the port)
    var method = ""
    var tls = true
    var headers: [[String]] = []   // local: the response headers Go logs; forward: r.Header after the request rules
}

/// What the native engine decided.
enum RewriteDecision {
    struct Local {
        var status: Int
        var headers: [[String]]
        var body: Data
        var bodyMode: FlowBodyMode   // .none or .read (pull `body`)
        var length: Int64
        var log = RewriteLog()
        /// The local body's full length / bytes (Entry.Bytes; captured when capture is on). `body` is what is sent.
        var logBody = Data()
    }
    struct Forward {
        var method: String
        var url: String
        var host: String
        var headers: [[String]]
        var bodyMode: FlowBodyMode   // .none or .client (.read: the native request body plan produces it)
        var length: Int64
        var response: ResponsePlan
        var log = RewriteLog()
        /// stage 3b: request body rules Swift runs once the body is in (length > 0); nil none.
        var requestBody: NativeRequestBodyPlan?
    }
    /// Header operations of the response-phase header rules that matched, in order (applied to the upstream head),
    /// and those rules' indices (logged at the response).
    struct ResponsePlan {
        var ops: [[RWSnapHeaderOp]] = []
        var rules: [Int] = []
        /// stage 3b: header and body rules in Go's order; hasBody → NativeBodyExec.response, not respond().
        var steps: [ResponseStep] = []
        var hasBody = false
    }
    enum ResponseStep {
        case header([RWSnapHeaderOp], Int)
        case body(NativeBodyRule)
    }

    case go(String)
    case drop(RewriteLog)
    case local(Local)
    case forward(Forward)

    var isNative: Bool { if case .go = self { return false }; return true }
}

/// The response decision for a natively forwarded request (FlowResponse's respond / upgrade).
struct RewriteResponse {
    var action: FlowDecision.Action   // .respond or .upgrade
    var status: Int
    var headers: [[String]]
    var bodyMode: FlowBodyMode        // .upstream or .none
    var length: Int64
    var note: String?
    /// resp.Header as modifyResponse leaves it for ent.Response (Content-Length still there).
    var logHeaders: [[String]] = []
}

final class NativeRewriteEngine {
    private struct Rule {
        let snap: RWSnapRule
        let re: RWRegex?
        let kind: String
        let phase: String
    }

    let generation: Int64
    let on: Bool
    let capture: Bool
    private let rules: [Rule]
    private let inc: [(pat: String, port: Int)]
    private let exc: [(pat: String, port: Int)]
    /// Rules whose patterns (and ops) Swift can evaluate / all rules (diagnostics).
    let portable: Int, total: Int
    /// stage 3b: compiled body rules by Ruleset index (nil entry: not portable), built on first use.
    private let bodyLock = NSLock()
    private var bodyRules: [Int: NativeBodyRule?] = [:]

    private func bodyRule(_ r: Rule) -> NativeBodyRule? {
        bodyLock.lock(); defer { bodyLock.unlock() }
        if let c = bodyRules[r.snap.i] { return c }
        let c = NativeBodyRule(r.snap)
        bodyRules[r.snap.i] = c
        return c
    }

    init(snapshot s: RWSnapshot) {
        generation = s.gen ?? 0
        on = s.on
        capture = s.capture
        rules = (s.rules ?? []).map { Rule(snap: $0, re: $0.re.map(RWRegex.init), kind: $0.kind, phase: $0.phase) }
        inc = (s.inc ?? []).map { (pat: $0.pat, port: $0.port ?? 0) }
        exc = (s.exc ?? []).map { (pat: $0.pat, port: $0.port ?? 0) }
        portable = s.portable ?? 0
        total = s.total ?? rules.count
    }

    convenience init?(json: String) {
        guard let s = RWSnapshot.decode(json) else { return nil }
        self.init(snapshot: s)
    }

    // MARK: - MitM host matching (config.go HostMatcher)

    func intercepts(host: String, port: Int) -> Bool {
        var h = RWAscii.lower(host)
        if h.hasSuffix(".") { h.removeLast() }
        for p in exc where NativeRewriteEngine.glob(p.pat, h) && (p.port == 0 || p.port == port) { return false }
        for p in inc {
            let want = p.port == 0 ? 443 : p.port
            if port != want && !(p.port == 0 && port == 0) { continue }
            if NativeRewriteEngine.glob(p.pat, h) { return true }
        }
        return false
    }

    /// config.go globMatch: * and ? on bytes.
    static func glob(_ pat: String, _ s: String) -> Bool {
        if pat == "*" || pat == s { return true }
        let p = Array(pat.utf8), t = Array(s.utf8)
        var px = 0, sx = 0, nextPx = -1, nextSx = -1
        while px < p.count || sx < t.count {
            if px < p.count {
                let c = p[px]
                if c == UInt8(ascii: "*") { nextPx = px; nextSx = sx + 1; px += 1; continue }
                if c == UInt8(ascii: "?") { if sx < t.count { px += 1; sx += 1; continue } }
                else if sx < t.count && t[sx] == c { px += 1; sx += 1; continue }
            }
            if nextSx > 0 && nextSx <= t.count { px = nextPx; sx = nextSx; continue }
            return false
        }
        return true
    }

    // MARK: - Request phase

    private struct Req {
        var method: String
        var header: GoHeader
        var host: String          // r.Host
        var contentLength: Int64
        var path: String          // request-target path (proven to be Go's EscapedPath)
        var query: String?        // raw query (nil: no "?")
        var scheme: String
    }

    /// bodies: stage 3b body rules may be run natively (NativeBodyRuntime.enabled); false = stage 3a behaviour.
    func decide(_ q: RewriteRequest, bodies: Bool = false) -> RewriteDecision {
        let bodies = bodies && !capture
        // ---- FlowHead.request + requestURL, only where Swift can prove Go builds the same request ----
        let method = q.method.isEmpty ? "GET" : q.method
        if !method.utf8.allSatisfy(RWAscii.isTokenByte) { return .go("method") }
        let target = q.target.isEmpty ? "/" : q.target
        guard let split = NativeRewriteEngine.splitTarget(target) else { return .go("target") }
        let (path, query) = split
        for kv in q.headers where kv.count == 2 {
            if !RWAscii.isPrintable(kv[0]) || kv[1].utf8.contains(where: { $0 == 0x0D || $0 == 0x0A || $0 == 0 }) { return .go("header bytes") }
        }
        var h = GoHeader(pairs: q.headers)
        var host = q.host
        let hv = h.get("Host")
        if !hv.isEmpty { host = hv }
        h.del("Host")
        if host.isEmpty {
            host = q.connHost
            if q.connPort != 0 && q.connPort != 443 && q.connPort != 80 { host += ":\(q.connPort)" }
        }
        guard NativeRewriteEngine.plainHost(host) else { return .go("host") }
        var cl = q.length
        var chunked = false
        if !h.values("Transfer-Encoding").isEmpty {
            h.del("Transfer-Encoding")
            chunked = true
            cl = -1
        }
        let clh = h.get("Content-Length")
        if !clh.isEmpty && !chunked {
            guard let n = Int64(RWAscii.trimSpace(clh)), n >= 0 else { return .go("content-length") }
            cl = n
        }
        if cl < 0 && !chunked && (method == "GET" || method == "HEAD") { cl = 0 }
        let scheme = q.tls ? "https" : "http"
        var urlHost = host
        if let c = host.lastIndex(of: ":") {
            let port = host[host.index(after: c)...]
            if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") { urlHost = String(host[..<c]) }
        }
        var r = Req(method: method, header: h, host: host, contentLength: cl, path: path, query: query, scheme: scheme)
        var log = RewriteLog(rules: [], url: "", host: host, method: method, tls: q.tls, headers: [])
        var u = scheme + "://" + urlHost + path + (query.map { "?" + $0 } ?? "")
        if u.utf8.count > 8192 || !RWAscii.isVisible(u) { return .go("url") }

        let active = on ? rules : []

        // ---- 1. URL rewrite: first match wins ----
        for rule in active where rule.kind == "url" {
            switch matches(rule, u) {
            case .unknown(let why): return .go(why)
            case .no: continue
            case .yes: break
            }
            let action = rule.snap.action ?? ""
            log.rules.append(rule.snap.i)
            log.url = u
            switch action {
            case "reject-drop":
                return .drop(log)
            case "reject", "reject-200", "reject-img", "reject-dict", "reject-array":
                var status = 404, ctype = "text/plain", body = Data()
                switch action {
                case "reject-200": status = 200
                case "reject-img": status = 200; ctype = "image/gif"; body = NativeRewriteEngine.tinyGIF
                case "reject-dict": status = 200; ctype = "application/json"; body = Data("{}".utf8)
                case "reject-array": status = 200; ctype = "application/json"; body = Data("[]".utf8)
                default: break
                }
                var lh = GoHeader()
                lh.set("Content-Type", ctype)
                // ent.Local(status, w.Header(), …): the writer's header after writeLocal
                var wh = lh
                wh.del("Content-Encoding"); wh.del("Transfer-Encoding"); wh.set("Content-Length", String(body.count))
                log.headers = wh.sortedPairs
                return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: status, header: lh, body: body), log, body)
            case "302", "307":
                guard rule.snap.targetOK == true, let re = rule.re,
                      let loc = re.replaceFirst(u, template: rule.snap.target ?? "") else { return .go("redirect template") }
                var lh = GoHeader()
                lh.set("Location", loc)
                log.headers = lh.sortedPairs
                return NativeRewriteEngine.logged(NativeRewriteEngine.commitLocal(status: action == "307" ? 307 : 302, header: lh, first: nil), log, Data())
            case "header":
                guard rule.snap.targetOK == true, let re = rule.re,
                      let nu = re.replaceFirst(u, template: rule.snap.target ?? "") else { return .go("rewrite template") }
                guard let p = NativeRewriteEngine.parseAbsolute(nu) else { return .go("rewritten url") }
                u = nu
                log.url = u
                r.scheme = p.scheme; r.host = p.host; r.path = p.path; r.query = p.query
            default:
                return .go("url action \(action)")
            }
            break
        }

        // ---- 2. Map Local: first match wins ----
        for rule in active where rule.kind == "maplocal" {
            switch matches(rule, u) {
            case .unknown(let why): return .go(why)
            case .no: continue
            case .yes: break
            }
            guard let l = rule.snap.local else { return .go("map local file") }
            log.rules.append(rule.snap.i)
            log.url = u
            // ent.Local(st, h, body, …): the rule's header map, before writeLocal touched the writer's copy
            log.headers = GoHeader(pairs: l.headers ?? []).sortedPairs
            return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: l.status, header: GoHeader(pairs: l.headers ?? []), body: l.body ?? Data()),
                                              log, l.body ?? Data())
        }

        // ---- 3. request phase rules in order ----
        var reqBodyRules: [NativeBodyRule] = []
        for rule in active where rule.phase != "response" {
            switch rule.kind {
            case "header":
                switch matches(rule, u) {
                case .unknown(let why): return .go(why)
                case .no: continue
                case .yes: break
                }
                guard rule.snap.opsOK == true else { return .go("header ops") }
                log.rules.append(rule.snap.i)
                if r.header.get("Host").isEmpty { r.header.set("Host", r.host) }
                guard NativeRewriteEngine.apply(rule.snap.headers ?? [], to: &r.header) else { return .go("header op input") }
                let nh = r.header.get("Host")
                if !nh.isEmpty { r.host = nh }
                r.header.del("Host")
            case "body", "jq", "json", "script":
                switch matches(rule, u) {
                case .unknown(let why): return .go(why)
                case .no: continue
                case .yes: break
                }
                guard bodies, rule.kind != "script", let br = bodyRule(rule) else { return .go(rule.kind) }
                reqBodyRules.append(br)
                log.rules.append(rule.snap.i)
            default:
                continue
            }
        }

        // the request body rules (Go: loadBody once, setBody after each rule that succeeded)
        var reqPlan: NativeRequestBodyPlan?
        if !reqBodyRules.isEmpty {
            if r.contentLength < 0 || r.contentLength > Int64(NativeBodyRuntime.maxBody) { return .go("request body length") }
            if r.contentLength == 0 {
                // no body (http.NoBody): a regex leaves it empty, a json / jq rule fails on it (Go skips the rule)
                if reqBodyRules.contains(where: { $0.kind != "body" }) { return .go("empty request body") }
            } else {
                reqPlan = NativeRequestBodyPlan(rules: reqBodyRules, length: r.contentLength)
            }
            r.header.set("Content-Length", String(r.contentLength)) // setBody; the final length is patched in later
        }

        // ---- 4. response rules against the final URL ----
        var plan = RewriteDecision.ResponsePlan()
        for rule in active where rule.phase == "response" && rule.kind != "url" && rule.kind != "maplocal" {
            switch matches(rule, u) {
            case .unknown(let why): return .go(why)
            case .no: continue
            case .yes: break
            }
            if bodies, rule.kind == "body" || rule.kind == "jq" || rule.kind == "json", let br = bodyRule(rule) {
                plan.steps.append(.body(br))
                plan.hasBody = true
                continue
            }
            guard rule.kind == "header", rule.snap.opsOK == true else { return .go("response \(rule.kind)") }
            let ops = rule.snap.headers ?? []
            // replace-regex reads the upstream's value, unknown until the response: a value Swift will not run a
            // regex on could only be refused then, when Go can no longer take over. Such rules stay with Go.
            if ops.contains(where: { $0.op == "replace-regex" }) { return .go("response replace-regex") }
            plan.ops.append(ops)
            plan.rules.append(rule.snap.i)
            plan.steps.append(.header(ops, rule.snap.i))
        }

        // ---- 5. the outbound request (flowOutbound + forward) ----
        guard r.host.isEmpty || NativeRewriteEngine.plainHost(r.host) else { return .go("host after rules") }
        log.url = u
        log.headers = r.header.sortedPairs   // ent.ReqHeaders(r.Method, r.Header)
        var out = r.header
        let upType = out.containsToken("Connection", "Upgrade") ? out.get("Upgrade") : ""
        let teTrailers = r.header.containsToken("Te", "trailers")
        out.removeHopByHop()
        if teTrailers { out.set("Te", "trailers") }
        if !upType.isEmpty { out.set("Connection", "Upgrade"); out.set("Upgrade", upType) }
        for k in ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"] { out.del(k) }
        out.del("Content-Length")
        // requestPhase: a response body rule makes Go ask only for encodings it can decode (after ent.ReqHeaders)
        if plan.hasBody { out.set("Accept-Encoding", "gzip, deflate, br") }
        if let qy = r.query, qy.contains(";") || !NativeRewriteEngine.validEscapes(qy) { return .go("query") }
        var (mode, length): (FlowBodyMode, Int64) = r.contentLength == 0 ? (.none, 0) : (.client, r.contentLength)
        if reqPlan != nil { mode = .read }
        return .forward(.init(method: method, url: u, host: r.host, headers: out.sortedPairs, bodyMode: mode, length: length,
                              response: plan, log: log, requestBody: reqPlan))
    }

    // MARK: - Response phase (natively forwarded requests)

    /// runResponse + modifyResponse for header-only rules: status / headers / length of the upstream's head.
    func respond(_ plan: RewriteDecision.ResponsePlan, status: Int, headers: [[String]], length: Int64, method: String) -> RewriteResponse? {
        var h = GoHeader(pairs: headers)
        var contentLength = length
        if !h.values("Transfer-Encoding").isEmpty {
            h.del("Transfer-Encoding")
            contentLength = -1
        } else {
            let cl = h.get("Content-Length")
            if !cl.isEmpty, let n = Int64(RWAscii.trimSpace(cl)), n >= 0 { contentLength = n }
        }
        let noBody = method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status)
        if status == 101 {
            return RewriteResponse(action: .upgrade, status: 101, headers: h.sortedPairs, bodyMode: .upstream, length: -1, note: nil,
                                   logHeaders: h.sortedPairs)
        }
        h.removeHopByHop()
        for ops in plan.ops {
            guard NativeRewriteEngine.apply(ops, to: &h) else { return nil }
        }
        var outLen: Int64 = -1
        let cl = h.get("Content-Length")
        if !cl.isEmpty {
            if let n = Int64(RWAscii.trimSpace(cl)), n >= 0 { outLen = n }
        } else if contentLength >= 0 {
            outLen = contentLength
        }
        let logHeaders = h.sortedPairs // ent.Response(resp.StatusCode, resp.Header) at the end of modifyResponse
        if !noBody { h.del("Content-Length") }
        h.del("Transfer-Encoding")
        let ct = h.get("Content-Type")
        let media = RWAscii.lower(RWAscii.trimSpace(String(ct.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")))
        // flow.go runResponse: an empty (Content-Length 0) body is http.NoBody, not the upstream's reader → "read"
        // (Go hands back an empty body; the native driver serves it the same way).
        let mode: FlowBodyMode = noBody ? .none : (contentLength == 0 ? .read : .upstream)
        return RewriteResponse(action: .respond, status: status, headers: h.sortedPairs, bodyMode: mode,
                               length: outLen, note: media == "text/event-stream" ? "flush" : nil, logHeaders: logHeaders)
    }

    // MARK: - Pieces

    private enum M { case yes, no, unknown(String) }

    private func matches(_ rule: Rule, _ u: String) -> M {
        guard let re = rule.re else { return .no } // no pattern: Go's match is false
        switch re.match(u) {
        case .no: return .no
        case .unknown: return .unknown("pattern")
        case .yes: return rule.snap.hgate == true ? .unknown("url-and-header") : .yes
        }
    }

    /// handler.go applyHeaderOps for the ops Go marked portable. false: an input Swift will not run a regex on.
    static func apply(_ ops: [RWSnapHeaderOp], to h: inout GoHeader) -> Bool {
        for op in ops {
            let name = op.name ?? "", value = op.value ?? ""
            switch op.op {
            case "add": h.add(name, value)
            case "del": h.del(name)
            case "replace": if !h.get(name).isEmpty { h.set(name, value) }
            case "replace-regex":
                let v = h.get(name)
                if v.isEmpty { continue }
                guard let src = op.re, RWAscii.isPrintable(v), v.utf8.count <= 8192 else { return false }
                guard let nv = RWRegexCache.shared.regex(src).replaceAll(v, template: value) else { return false }
                h.set(name, nv)
            default:
                return false
            }
        }
        return true
    }

    /// Attaches the request-log view to a local decision (a deferral passes through).
    static func logged(_ d: RewriteDecision, _ log: RewriteLog, _ body: Data) -> RewriteDecision {
        guard case .local(var l) = d else { return d }
        l.log = log
        l.logBody = body
        return .local(l)
    }

    /// handler.go writeLocal followed by flowWriter.commit.
    static func writeLocal(status: Int, header: GoHeader, body: Data) -> RewriteDecision {
        var h = header
        h.del("Content-Encoding")
        h.del("Transfer-Encoding")
        h.set("Content-Length", String(body.count))
        return commitLocal(status: status, header: h, first: body.isEmpty ? nil : body)
    }

    /// flow_request.go flowWriter.commit on the header snapshot taken at WriteHeader.
    static func commitLocal(status: Int, header: GoHeader, first: Data?) -> RewriteDecision {
        var h = header
        let bodyOK = status >= 200 && status != 204 && status != 304
        if !h.has("Content-Type") && h.get("Content-Encoding").isEmpty && bodyOK && first != nil {
            return .go("content sniffing") // http.DetectContentType: not reproduced (Go always sets a type here)
        }
        var length: Int64 = -1
        let cl = h.get("Content-Length")
        if !cl.isEmpty {
            if let n = Int64(cl), n >= 0 { length = n }
        } else if first == nil {
            length = 0
        }
        var mode = FlowBodyMode.read
        if length == 0 || !bodyOK { mode = .none; length = max(length, 0) }
        if bodyOK { h.del("Content-Length") }
        h.del("Transfer-Encoding")
        let body = mode == .read ? (first ?? Data()) : Data()
        return .local(.init(status: status, headers: h.sortedPairs, body: body, bodyMode: mode, length: length))
    }

    // MARK: - Input proofs (Swift decides only where Go provably reads the same)

    /// A request-target Go's url.ParseRequestURI + RequestURI hand back unchanged: "/" path of unreserved / sub-delim
    /// characters and valid %XX escapes, optional "?" + visible-ASCII query without "#".
    static func splitTarget(_ t: String) -> (String, String?)? {
        let b = Array(t.utf8)
        guard b.first == UInt8(ascii: "/"), !(b.count > 1 && b[1] == UInt8(ascii: "/")) else { return nil }
        var i = 0
        while i < b.count && b[i] != UInt8(ascii: "?") {
            let c = b[i]
            if c == UInt8(ascii: "%") {
                guard i + 2 < b.count, RWAscii.isHex(b[i + 1]), RWAscii.isHex(b[i + 2]) else { return nil }
                i += 3
                continue
            }
            guard pathByte(c) else { return nil }
            i += 1
        }
        let path = String(decoding: b[0..<i], as: UTF8.self)
        if i == b.count { return (path, nil) }
        let q = b[(i + 1)...]
        guard q.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E && $0 != UInt8(ascii: "#") }) else { return nil }
        return (path, String(decoding: q, as: UTF8.self))
    }

    private static func pathByte(_ c: UInt8) -> Bool {
        switch c {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"): return true
        case UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"), UInt8(ascii: "!"), UInt8(ascii: "$"),
             UInt8(ascii: "&"), UInt8(ascii: "'"), UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"), UInt8(ascii: "+"),
             UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "="), UInt8(ascii: ":"), UInt8(ascii: "@"), UInt8(ascii: "["),
             UInt8(ascii: "]"), UInt8(ascii: "/"): return true
        default: return false
        }
    }

    /// A host[:port] Go keeps verbatim everywhere it is used: letters, digits, "-", ".", optional ":digits".
    static func plainHost(_ h: String) -> Bool {
        let parts = h.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count <= 2, let name = parts.first, !name.isEmpty else { return false }
        for c in name.utf8 {
            let ok = (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || RWAscii.isDigit(c) || c == UInt8(ascii: "-") || c == UInt8(ascii: ".")
            if !ok { return false }
        }
        if parts.count == 2 { return !parts[1].isEmpty && parts[1].utf8.allSatisfy(RWAscii.isDigit) }
        return true
    }

    static func validEscapes(_ s: String) -> Bool {
        let b = Array(s.utf8)
        var i = 0
        while i < b.count {
            if b[i] == UInt8(ascii: "%") {
                guard i + 2 < b.count, RWAscii.isHex(b[i + 1]), RWAscii.isHex(b[i + 2]) else { return false }
                i += 3
            } else { i += 1 }
        }
        return true
    }

    /// An absolute URL Go's url.Parse takes apart and URL.String puts back unchanged (lowercase http/https, plain
    /// host, path / query as in splitTarget).
    static func parseAbsolute(_ s: String) -> (scheme: String, host: String, path: String, query: String?)? {
        let scheme: String
        let rest: Substring
        if s.hasPrefix("https://") { scheme = "https"; rest = s.dropFirst(8) }
        else if s.hasPrefix("http://") { scheme = "http"; rest = s.dropFirst(7) }
        else { return nil }
        let end = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) ?? rest.endIndex
        let host = String(rest[..<end])
        guard plainHost(host) else { return nil }
        let tail = String(rest[end...])
        if tail.isEmpty { return (scheme, host, "", nil) }
        if tail.hasPrefix("?") {
            let q = String(tail.dropFirst())
            guard q.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E && $0 != UInt8(ascii: "#") }) else { return nil }
            return (scheme, host, "", q)
        }
        guard let split = splitTarget(tail) else { return nil }
        return (scheme, host, split.0, split.1)
    }

    static let tinyGIF = Data([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
                               0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                               0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b])
}

/// Compiled header-op regexes, shared across requests (bounded).
final class RWRegexCache {
    static let shared = RWRegexCache()
    private let lock = NSLock()
    private var map: [String: RWRegex] = [:]

    func regex(_ src: RWSnapRegex) -> RWRegex {
        lock.lock(); defer { lock.unlock() }
        if let r = map[src.p] { return r }
        if map.count >= 256 { map.removeAll() }
        let r = RWRegex(src)
        map[src.p] = r
        return r
    }
}
