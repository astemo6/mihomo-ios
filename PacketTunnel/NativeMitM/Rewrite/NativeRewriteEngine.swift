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
    // native request scripts (native-final): the drop reason of a script's abort (「脚本中止：<name>」), the
    // request-log notes of the request scripts (skipped / failed, in order) and the method after them when changed
    var why = ""
    var notes: [String] = []
    var reqMethod = ""
}

/// The outcome of one http-request script the native dispatcher ran (NativeRequestScripts.swift), applied by the
/// engine where Go's requestPhase applies it (handler.go: Match, abort, local answer, URL / method / headers / body).
struct RequestScriptOutcome {
    enum Kind { case skipped, failed, ran }
    struct Mock {
        var status: Int              // as the script returned it (validScriptStatus applied by the engine)
        var headers: [[String]]?
        var body: Data
    }
    var kind: Kind
    var abort = false
    var abortWhy = ""
    var url: String?
    var method: String?
    var headers: [[String]]?
    var bodySet = false
    var body = Data()
    var mock: Mock?
}

/// What the engine needs from the request-script dispatcher: the outcomes so far (by Ruleset index) and whether the
/// client's request body is in Swift's hands (Go: loadBody read it).
struct RequestScriptState {
    var outcomes: [Int: RequestScriptOutcome] = [:]
    var bodyLoaded = false
}

/// The engine stopped at a request script without an outcome: the request as the script sees it ($request).
struct RequestScriptPause {
    var rule: Int
    var requiresBody: Bool
    var url: String
    var method: String
    var header: CanonicalHeader          // r.Header (Host taken out)
    var host: String              // r.Host
    var contentLength: Int64      // r.ContentLength (-1 chunked)
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
        /// Entry.Bytes when it is not logBody.count (a streamed Map Local file), and whether the body is never
        /// captured (Go's serveLargeMapLocal logs no body).
        var logLen: Int64?
        var logNoCapture = false
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
        /// native-final: the body a request script set ($done({body})) — sent instead of the client's; nil none.
        var scriptBody: Data?
    }
    /// Header operations of the response-phase header rules that matched, in order (applied to the upstream head),
    /// and those rules' indices (logged at the response).
    struct ResponsePlan {
        var ops: [[RWSnapHeaderOp]] = []
        var rules: [Int] = []
        /// stage 3b: header and body rules in Go's order; hasBody → NativeBodyExec.response, not respond().
        var steps: [ResponseStep] = []
        var hasBody = false
        /// Lane s3-script: the response rules in order (header and script) when http-response scripts matched —
        /// the native script dispatcher runs them (NativeScriptDispatcher.swift); nil: header rules only.
        var scripts: [ScriptPlanStep]?
        /// The outbound request as the response scripts see it ($request): out.Header before Content-Length is
        /// taken out of the decision, Accept-Encoding as sent.
        var requestHeader = CanonicalHeader()
        var requestHost = ""
        var url = ""
        var method = ""
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
    // Gap C5 (astemo6/Muse NativeCore): in the Go-free tunnel nothing stands behind a `.go(why)` — a deferred
    // request used to pass through with NONE of its rules applied. There, a rule the native engine cannot run is
    // skipped on its own (counted in skipStats, noted in the request log) and every other rule still applies;
    // regexes run on non-ASCII input (RWRegex.lenient), header ops apply best effort, and when scripts and body
    // rules meet on one flow the scripts run and the body rules are skipped. The Go-backed app build keeps deferring.
    static let goFree = true
    private static let skipLock = NSLock()
    private static var skips: [String: Int] = [:]
    static func noteSkip(_ why: String) {
        skipLock.lock(); skips[why, default: 0] += 1; skipLock.unlock()
    }
    /// Rule-level skips since the tunnel started (诊断: NativeRewriteDriver.stats has the request-level defers).
    static func skipStats() -> [String: Int] { skipLock.lock(); defer { skipLock.unlock() }; return skips }

    private static var _shared: NativeRewriteEngine?
    private static let _sharedLock = NSLock()

    static var shared: NativeRewriteEngine {
        get {
            _sharedLock.lock()
            defer { _sharedLock.unlock() }
            if let s = _shared { return s }
            let empty = NativeRewriteEngine(snapshot: RWSnapshot(version: 1, gen: 0, on: false, capture: false))
            _shared = empty
            return empty
        }
        set {
            _sharedLock.lock()
            _shared = newValue
            _sharedLock.unlock()
        }
    }

    static func load(_ snapshot: RWSnapshot) {
        shared = NativeRewriteEngine(snapshot: snapshot)
    }

    private struct Rule {
        let snap: RWSnapRule
        let re: RWRegex?
        let kind: String
        let phase: String
    }

    let generation: Int64
    let on: Bool
    /// Go applies the response header rules when Swift cannot (respond()); nil in tests without Go.
    var headerOpsFallback: ((_ gen: Int64, _ rules: [Int], _ status: Int, _ headers: [[String]]) -> [[String]]?)?
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
        var header: CanonicalHeader
        var host: String          // r.Host
        var contentLength: Int64
        var path: String          // r.URL.EscapedPath()
        var query: String         // r.URL.RawQuery
        var forceQuery: Bool      // r.URL.ForceQuery
        var scheme: String

        /// URL.RequestURI for the URLs Swift builds (no opaque part).
        var requestURI: String {
            (path.isEmpty ? "/" : path) + (forceQuery || !query.isEmpty ? "?" + query : "")
        }
    }

    /// Request-line + Host + headers as matchReq builds them for a QX url-and-header condition, with the header
    /// map walked in `order` (Go walks its map in random order; Swift tries two orders and defers when they differ).
    private static func headerBlock(_ r: Req, reversed: Bool) -> String {
        var s = r.method + " " + r.requestURI + " HTTP/1.1\r\n"
        if !r.host.isEmpty { s += "Host: " + r.host + "\r\n" }
        var keys = r.header.map.keys.sorted(by: RWAscii.less)
        if reversed { keys.reverse() }
        for k in keys { for v in r.header.values(k) { s += k + ": " + v + "\r\n" } }
        return s
    }

    /// bodies: stage 3b body rules may be run natively (NativeBodyRuntime.enabled); false = stage 3a behaviour.
    /// scripts: lane s3-script — response-phase http-response scripts are planned for the native script dispatcher
    /// instead of deferring the request (request-phase scripts: see requestScripts, final integration).
    /// A request that would need both a native body flow and a native script flow is handed to Go.
    func decide(_ q: RewriteRequest, bodies: Bool = false, scripts: Bool = false) -> RewriteDecision {
        var pause: RequestScriptPause?
        return decideCore(q, bodies: bodies, scripts: scripts, requestScripts: nil, pause: &pause)
    }

    /// native-final: decide with http-request scripts run by the native dispatcher. A request script without an
    /// outcome in `state` stops the engine: the answer is then .go and `pause` says which script and the request it
    /// sees; the dispatcher runs it, adds its outcome and calls this again (the request phase up to the script is
    /// deterministic, so re-running it reaches the same point — exactly how Go's FlowHead.Scripted hand-over works).
    func decide(_ q: RewriteRequest, bodies: Bool, scripts: Bool, requestScripts state: RequestScriptState,
                pause: inout RequestScriptPause?) -> RewriteDecision {
        pause = nil
        return decideCore(q, bodies: bodies, scripts: scripts, requestScripts: capture ? nil : state, pause: &pause)
    }

    private func decideCore(_ q: RewriteRequest, bodies: Bool, scripts: Bool, requestScripts: RequestScriptState?,
                            pause: inout RequestScriptPause?) -> RewriteDecision {
        let bodies = bodies && !capture
        // ---- FlowHead.request + requestURL, reproducing Go's parsing (or deferring where Swift cannot) ----
        let method = q.method.isEmpty ? "GET" : q.method
        if !method.utf8.allSatisfy(RWAscii.isTokenByte) { return .go("method") }
        let target = q.target.isEmpty ? "/" : q.target
        guard let t = NetURL.parseRequestURI(target) else { return .go("target") }
        for kv in q.headers where kv.count == 2 {
            if !RWAscii.isPrintable(kv[0]) || kv[1].utf8.contains(where: { $0 == 0x0D || $0 == 0x0A || $0 == 0 }) { return .go("header bytes") }
        }
        var h = CanonicalHeader(pairs: q.headers)
        var host = q.host
        let hv = h.get("Host")
        if !hv.isEmpty { host = hv }
        h.del("Host")
        if host.isEmpty, let th = t.host { host = th }
        if host.isEmpty {
            host = q.connHost
            if q.connPort != 0 && q.connPort != 443 && q.connPort != 80 { host += ":\(q.connPort)" }
        }
        if host.isEmpty || !RWAscii.isVisible(host) { return .go("host") }
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
        var r = Req(method: method, header: h, host: host, contentLength: cl, path: t.path, query: t.query, forceQuery: t.forceQuery,
                    scheme: scheme)
        var log = RewriteLog(rules: [], url: "", host: host, method: method, tls: q.tls, headers: [])
        /// gap C5: a rule skipped in the Go-free tunnel (see goFree)
        func skipRule(_ why: String, _ rule: Rule) {
            NativeRewriteEngine.noteSkip(why)
            if log.notes.count < 8 { log.notes.append("跳过规则（原生引擎不支持：\(why)）：\(rule.snap.kind) #\(rule.snap.i)") }
        }
        var urlHost = host
        if let (hh, port) = NetURL.splitHostPort(host), (scheme == "https" && port == "443") || (scheme == "http" && port == "80") { urlHost = hh }
        var u = scheme + "://" + urlHost + r.requestURI
        if u.utf8.count > 8192 || !RWAscii.isVisible(u) { return .go("url") }
        let clientBody = cl != 0     // the client sends a body (Go: r.Body is not http.NoBody)

        let active = on ? rules : []

        // ---- 1. URL rewrite: first match wins ----
        for rule in active where rule.kind == "url" {
            switch matches(rule, u, r) {
            case .unknown(let why): if Self.goFree { skipRule(why, rule); continue }; return .go(why)
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
                var lh = CanonicalHeader()
                lh.set("Content-Type", ctype)
                // ent.Local(status, w.Header(), …): the writer's header after writeLocal
                var wh = lh
                wh.del("Content-Encoding"); wh.del("Transfer-Encoding"); wh.set("Content-Length", String(body.count))
                log.headers = wh.sortedPairs
                return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: status, header: lh, body: body), log, body)
            case "302", "307":
                guard rule.snap.targetOK == true, let re = rule.re else {
                    if Self.goFree { log.rules.removeLast(); skipRule("redirect template", rule); continue }
                    return .go("redirect template")
                }
                var loc = rule.snap.target ?? ""
                if rule.snap.tperr != true {
                    guard let tp = rule.snap.tp, let l = re.replaceFirst(u, tp) else {
                        if Self.goFree { log.rules.removeLast(); skipRule("redirect template", rule); continue }
                        return .go("redirect template")
                    }
                    loc = l
                }
                var lh = CanonicalHeader()
                lh.set("Location", loc)
                log.headers = lh.sortedPairs
                return NativeRewriteEngine.logged(NativeRewriteEngine.commitLocal(status: action == "307" ? 307 : 302, header: lh, first: nil), log, Data())
            case "header":
                guard rule.snap.targetOK == true, let re = rule.re else {
                    if Self.goFree { log.rules.removeLast(); skipRule("rewrite template", rule); continue }
                    return .go("rewrite template")
                }
                if rule.snap.tperr == true { break } // Replace fails: Go keeps the URL
                guard let tp = rule.snap.tp, let nu = re.replaceFirst(u, tp) else {
                    if Self.goFree { log.rules.removeLast(); skipRule("rewrite template", rule); continue }
                    return .go("rewrite template")
                }
                guard let p = NetURL.parseAbsolute(nu) else {
                    if Self.goFree { log.rules.removeLast(); skipRule("rewritten url", rule); continue }
                    return .go("rewritten url")
                }
                u = nu
                log.url = u
                r.host = p.host; r.path = p.path; r.query = p.query; r.forceQuery = p.forceQuery
            default:
                if Self.goFree { log.rules.removeLast(); skipRule("url action \(action)", rule); continue }
                return .go("url action \(action)")
            }
            break
        }
        if u.utf8.count > 8192 || !RWAscii.isVisible(u) { return .go("url") }

        // ---- 2. Map Local: first match wins ----
        for rule in active where rule.kind == "maplocal" {
            switch matches(rule, u, r) {
            case .unknown(let why): if Self.goFree { skipRule(why, rule); continue }; return .go(why)
            case .no: continue
            case .yes: break
            }
            guard let l = rule.snap.local else {
                if Self.goFree { skipRule("map local", rule); continue }
                return .go("map local")
            }
            log.rules.append(rule.snap.i)
            log.url = u
            if let f = l.file { return mapLocalFile(l, f, log) }
            // ent.Local(st, h, body, …): the rule's header map, before writeLocal touched the writer's copy
            log.headers = CanonicalHeader(pairs: l.headers ?? []).sortedPairs
            return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: l.status, header: CanonicalHeader(pairs: l.headers ?? []), body: l.body ?? Data()),
                                              log, l.body ?? Data())
        }

        // ---- 3. request phase rules in order ----
        var reqBodyRules: [NativeBodyRule] = []
        var scriptsRan = false
        var scriptBody: Data?
        for rule in active where rule.phase != "response" {
            switch rule.kind {
            case "header":
                switch matches(rule, u, r) {
                case .unknown(let why): if Self.goFree { skipRule(why, rule); continue }; return .go(why)
                case .no: continue
                case .yes: break
                }
                if rule.snap.opsOK != true {
                    // Go-free: the portable ops apply, the others are skipped (apply's best-effort mode)
                    if !Self.goFree { return .go("header ops") }
                    skipRule("header ops", rule)
                }
                log.rules.append(rule.snap.i)
                if r.header.get("Host").isEmpty { r.header.set("Host", r.host) }
                let firstLine = r.method + " " + r.requestURI + " HTTP/1.1"
                if !NativeRewriteEngine.apply(rule.snap.headers ?? [], to: &r.header, firstLine: firstLine) {
                    if !Self.goFree { return .go("header op input") }
                    skipRule("header op input", rule)
                }
                let nh = r.header.get("Host")
                if !nh.isEmpty { r.host = nh }
                r.header.del("Host")
            case "body", "jq", "json", "script":
                switch matches(rule, u, r) {
                case .unknown(let why): if Self.goFree { skipRule(why, rule); continue }; return .go(why)
                case .no: continue
                case .yes: break
                }
                if rule.kind == "script", let rs = requestScripts {
                    // native-final: an http-request script — its outcome where Go's requestPhase applies it
                    guard let sc = rule.snap.script else { return .go("request script") }
                    guard let o = rs.outcomes[rule.snap.i] else {
                        pause = RequestScriptPause(rule: rule.snap.i, requiresBody: sc.requiresBody == true, url: u, method: r.method,
                                                   header: r.header, host: r.host, contentLength: r.contentLength)
                        return .go("request script")
                    }
                    scriptsRan = true
                    switch o.kind {
                    case .skipped: continue
                    case .failed: log.rules.append(rule.snap.i); continue   // ent.Match, then the error note
                    case .ran: log.rules.append(rule.snap.i)
                    }
                    if o.abort {
                        log.url = u
                        log.why = o.abortWhy
                        return .drop(log)
                    }
                    if let m = o.mock {
                        guard NativeRewriteEngine.scriptHeadersOK(m.headers ?? []) else { return .go("script response headers") }
                        let status = (200...999).contains(m.status) ? m.status : 200
                        let h = CanonicalHeader(pairs: m.headers ?? [])
                        log.url = u
                        log.headers = h.sortedPairs // ent.Local(code, h, …): the script's map, not the writer's
                        return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: status, header: h, body: m.body), log, m.body)
                    }
                    if let nu = o.url, !nu.isEmpty, nu != u {
                        // url.Parse(res.URL) with a host: Swift takes only what it parses exactly like Go
                        guard let p = NetURL.parseAbsolute(nu) else { return .go("script url") }
                        u = nu
                        log.url = u
                        r.host = p.host; r.path = p.path; r.query = p.query; r.forceQuery = p.forceQuery; r.scheme = p.scheme
                    }
                    if let m = o.method, !m.isEmpty {
                        guard m.utf8.allSatisfy({ $0 < 0x80 }) else { return .go("script method") }
                        let up = m.uppercased() // strings.ToUpper on ASCII
                        guard up.utf8.allSatisfy(RWAscii.isTokenByte) else { return .go("script method") }
                        r.method = up
                    }
                    if let hs = o.headers {
                        guard NativeRewriteEngine.scriptHeadersOK(hs) else { return .go("script headers") }
                        var nh = CanonicalHeader(pairs: hs)
                        let hv = nh.get("Host")
                        if !hv.isEmpty { r.host = hv }
                        nh.del("Host")
                        r.header = nh
                    }
                    if o.bodySet {
                        // a body set over a client body nobody read: Go leaves the client's bytes unread (hand it over)
                        if clientBody && !rs.bodyLoaded { return .go("script body over an unread client body") }
                        r.header.set("Content-Length", String(o.body.count)) // setBody
                        r.contentLength = Int64(o.body.count)
                        scriptBody = o.body
                    }
                    continue
                }
                guard bodies, rule.kind != "script", let br = bodyRule(rule) else {
                    if Self.goFree { skipRule(rule.kind, rule); continue }
                    return .go(rule.kind)
                }
                reqBodyRules.append(br)
                log.rules.append(rule.snap.i)
            default:
                continue
            }
        }

        if scriptsRan {
            if u.utf8.count > 8192 || !RWAscii.isVisible(u) { return .go("url") }
            // request scripts next to request body rules: one body owner (Go) — hand the request over
            if !reqBodyRules.isEmpty {
                if !Self.goFree { return .go("request script with body rules") }
                for _ in reqBodyRules { NativeRewriteEngine.noteSkip("request body rule next to a request script") }
                log.notes.append("跳过请求体规则（与请求脚本同时命中，原生引擎先运行脚本）")
                reqBodyRules.removeAll()
            }
        }
        // the request body rules (Go: loadBody once, setBody after each rule that succeeded)
        var reqPlan: NativeRequestBodyPlan?
        if !reqBodyRules.isEmpty {
            if r.contentLength < 0 || r.contentLength > Int64(NativeBodyRuntime.maxBody) {
                if !Self.goFree { return .go("request body length") }
                NativeRewriteEngine.noteSkip("request body length")
                log.notes.append(r.contentLength < 0 ? "跳过请求体规则（分块请求体）" : "跳过请求体规则（请求体 \(r.contentLength >> 10) KB 超过上限）")
                reqBodyRules.removeAll()
            } else if r.contentLength == 0 {
                // no body (http.NoBody): a regex leaves it empty, a json / jq rule fails on it (Go skips the rule) —
                // Go-free: the json / jq rules are skipped the same way, the regex rules leave it empty
                if reqBodyRules.contains(where: { $0.kind != "body" }) && !Self.goFree { return .go("empty request body") }
                // Go's json / jq rule errors on the empty body before ent.Match, so the request log does not list it
                let failed = Set(reqBodyRules.filter { $0.kind != "body" }.map(\.index))
                if !failed.isEmpty {
                    log.rules.removeAll { failed.contains($0) }
                    reqBodyRules.removeAll { failed.contains($0.index) }
                }
            } else {
                reqPlan = NativeRequestBodyPlan(rules: reqBodyRules, length: r.contentLength)
            }
            if !reqBodyRules.isEmpty { r.header.set("Content-Length", String(r.contentLength)) } // setBody; the final length is patched in later
        }

        // ---- 4. response rules against the final URL ----
        var plan = RewriteDecision.ResponsePlan()
        var steps: [ScriptPlanStep] = []
        var hasScript = false, needRespBody = false
        for rule in active where rule.phase == "response" && rule.kind != "url" && rule.kind != "maplocal" {
            switch matches(rule, u, r) {
            case .unknown(let why): if Self.goFree { skipRule(why, rule); continue }; return .go(why)
            case .no: continue
            case .yes: break
            }
            if rule.kind == "script" && scripts {
                guard let sc = rule.snap.script else {
                    if Self.goFree { skipRule("response script", rule); continue }
                    return .go("response script")
                }
                // Go records the script's body; the native side does not (Go-free: the request log keeps the head)
                if capture && !Self.goFree { return .go("capture") }
                hasScript = true
                if sc.requiresBody == true { needRespBody = true }
                steps.append(ScriptPlanStep(rule: rule.snap.i, kind: .script(requiresBody: sc.requiresBody == true)))
                continue
            }
            if bodies, rule.kind == "body" || rule.kind == "jq" || rule.kind == "json", let br = bodyRule(rule) {
                plan.steps.append(.body(br))
                plan.hasBody = true
                continue
            }
            guard rule.kind == "header" else {
                if Self.goFree { skipRule("response \(rule.kind)", rule); continue }
                return .go("response \(rule.kind)")
            }
            if rule.snap.opsOK != true {
                if !Self.goFree { return .go("response \(rule.kind)") }
                skipRule("response header ops", rule)
            }
            var ops = rule.snap.headers ?? []
            // regex ops read the upstream's values, unknown until the response: the patterns must compile now
            // (an input Swift cannot run them on is then handled by Go's header-op helper, see respond()).
            // Go-free: an op whose pattern ICU cannot compile is dropped, the rule's other ops stay.
            let compiles: (RWSnapHeaderOp) -> Bool = { op in
                guard op.op == "replace-regex" || op.op == "raw" else { return true }
                guard let src = op.re else { return false }
                return RWRegexCache.shared.regex(src).compiles || op.tperr == true
            }
            if !ops.allSatisfy(compiles) {
                if !Self.goFree { return .go("response regex") }
                skipRule("response regex", rule)
                ops = ops.filter(compiles)
            }
            plan.ops.append(ops)
            plan.rules.append(rule.snap.i)
            plan.steps.append(.header(ops, rule.snap.i))
            steps.append(ScriptPlanStep(rule: rule.snap.i, kind: .header(ops)))
        }
        // native-final: request scripts that ran and a response body flow → Go takes the request (one body owner)
        // Go-free: scripts and body rules on one flow — the scripts run, the body rules are skipped (one body owner)
        func dropBodySteps(_ why: String) {
            let n = plan.steps.filter { if case .body = $0 { return true }; return false }.count
            for _ in 0..<max(n, reqPlan == nil ? 0 : 1) { NativeRewriteEngine.noteSkip(why) }
            plan.steps.removeAll { if case .body = $0 { return true }; return false }
            plan.hasBody = false
            reqPlan = nil
            log.notes.append("跳过响应体 / 请求体规则（与脚本同时命中，原生引擎先运行脚本）")
        }
        if scriptsRan && plan.hasBody {
            if !Self.goFree { return .go("request script with body rules") }
            dropBodySteps("body rule next to a request script")
        }
        if hasScript {
            // the native script dispatcher applies header ops without a Go fallback, and a script flow is not a body
            // flow: a regex header op, a body rule or a request body rule next to a script → Go
            if plan.hasBody || reqPlan != nil {
                if !Self.goFree { return .go("script with body rules") }
                dropBodySteps("body rule next to a response script")
            }
            // Go-free: the dispatcher's native header ops are all there is (lenient regex) — no hand-over
            if !Self.goFree, plan.ops.contains(where: { $0.contains(where: { $0.op == "replace-regex" || $0.op == "raw" }) }) { return .go("script with regex header op") }
            plan.scripts = steps
        }

        // ---- 5. the outbound request (flowOutbound + forward) ----
        guard r.host.isEmpty || NativeRewriteEngine.plainHost(r.host) else { return .go("host after rules") }
        guard let target = NetURL.parseAbsolute(u) else { return .go("target url") } // url.Parse(f.url)
        log.url = u
        log.headers = r.header.sortedPairs   // ent.ReqHeaders(r.Method, r.Header)
        if r.method != method { log.reqMethod = r.method }
        // requestPhase: a response body rule / body script asks only for encodings Go can decode
        if needRespBody { r.header.set("Accept-Encoding", "gzip, deflate, br") }
        var out = r.header
        let upType = out.containsToken("Connection", "Upgrade") ? out.get("Upgrade") : ""
        let teTrailers = r.header.containsToken("Te", "trailers")
        out.removeHopByHop()
        if teTrailers { out.set("Te", "trailers") }
        if !upType.isEmpty { out.set("Connection", "Upgrade"); out.set("Upgrade", upType) }
        for k in ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"] { out.del(k) }
        // requestPhase: a response body rule makes Go ask only for encodings it can decode (after ent.ReqHeaders)
        if plan.hasBody { out.set("Accept-Encoding", "gzip, deflate, br") }
        guard let cleaned = NetURL.cleanQuery(r.query) else { return .go("query") }
        // out.URL.String(): r.URL with the target's scheme and host, the cleaned query
        var outURL = target.scheme + "://" + target.host
        if !r.path.isEmpty && !r.path.hasPrefix("/") { outURL += "/" }
        outURL += r.path
        if r.forceQuery || !cleaned.isEmpty { outURL += "?" + cleaned }
        if hasScript {
            plan.requestHeader = out
            plan.requestHost = r.host
            plan.url = outURL
            plan.method = r.method
        }
        out.del("Content-Length")
        var (mode, length): (FlowBodyMode, Int64) = r.contentLength == 0 ? (.none, 0) : (.client, r.contentLength)
        if reqPlan != nil { mode = .read }
        if let b = scriptBody { (mode, length) = b.isEmpty ? (.none, 0) : (.read, Int64(b.count)) }
        return .forward(.init(method: r.method, url: outURL, host: r.host, headers: out.sortedPairs, bodyMode: mode, length: length,
                              response: plan, log: log, requestBody: reqPlan, scriptBody: scriptBody))
    }

    // MARK: - Map Local from a file

    /// Go's file / URL Map Local (handler.go serveLargeMapLocal, then mapLocalData), read here from the same path.
    private func mapLocalFile(_ l: RWSnapLocal, _ f: RWSnapFile, _ logIn: RewriteLog) -> RewriteDecision {
        var log = logIn
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: f.path, isDirectory: &isDir)
        var attrs: [FileAttributeKey: Any]? = nil
        if exists { attrs = try? fm.attributesOfItem(atPath: f.path) }
        let regular = exists && !isDir.boolValue && (attrs?[.type] as? FileAttributeType) == .typeRegular
        if f.remote == true {
            // Go downloads a missing resource and refreshes a stale one: both stay with Go
            guard regular, let mtime = attrs?[.modificationDate] as? Date else { return .go("map local download") }
            if let maxAge = f.maxAge, maxAge > 0, Date().timeIntervalSince(mtime) > TimeInterval(maxAge) { return .go("map local stale") }
        }
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        let status = l.status
        var h = CanonicalHeader(pairs: l.headers ?? [])
        if regular && size >= Int64(f.large) {
            // serveLargeMapLocal: streamed from disk, Content-Length = size, no body captured in the log
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: f.path), options: .alwaysMapped), Int64(data.count) == size else {
                return .go("map local read")
            }
            if h.get("Content-Type").isEmpty { h.set("Content-Type", f.ctype ?? NetSniff.detect(data.prefix(512))) }
            h.del("Content-Encoding"); h.del("Transfer-Encoding"); h.set("Content-Length", String(size))
            log.headers = h.sortedPairs
            guard case .local(var dl) = NativeRewriteEngine.commitLocal(status: status, header: h, first: data.isEmpty ? nil : data) else {
                return .go("map local commit")
            }
            dl.log = log
            dl.logBody = Data()
            dl.logLen = size
            dl.logNoCapture = true
            return .local(dl)
        }
        // mapLocalData: the whole file (a read error serves an empty body, like Go)
        var body = Data()
        if regular {
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: f.path)) else { return .go("map local read") }
            body = d
        } else if f.remote == true {
            return .go("map local download")
        }
        if h.get("Content-Type").isEmpty { h.set("Content-Type", f.ctype ?? NetSniff.detect(body.prefix(512))) }
        log.headers = h.sortedPairs
        return NativeRewriteEngine.logged(NativeRewriteEngine.writeLocal(status: status, header: h, body: body), log, body)
    }

    // MARK: - Response phase (natively forwarded requests)

    /// runResponse + modifyResponse for header-only rules: status / headers / length of the upstream's head.
    func respond(_ plan: RewriteDecision.ResponsePlan, status: Int, headers: [[String]], length: Int64, method: String) -> RewriteResponse? {
        var h = CanonicalHeader(pairs: headers)
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
        let before = h
        let firstLine = "HTTP/1.1 " + NetStatus.status(status)
        for ops in plan.ops {
            if NativeRewriteEngine.apply(ops, to: &h, firstLine: firstLine) { continue }
            // an upstream value Swift cannot run the regex on (non-ASCII, a QX raw rewrite whose result would
            // depend on Go's map order…): Go applies the rules' ops (no flow — bridge MitmRewriteHeaderOps)
            guard let fb = headerOpsFallback, let pairs = fb(generation, plan.rules, status, before.sortedPairs) else { return nil }
            h = CanonicalHeader(raw: pairs)
            break
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

    private func matches(_ rule: Rule, _ u: String, _ r: Req) -> M {
        guard let re = rule.re else { return .no } // no pattern: Go's match is false
        switch re.match(u) {
        case .no: return .no
        case .unknown: return .unknown("pattern")
        case .yes:
            guard rule.snap.hgate == true else { return .yes }
            // QX url-and-header: the condition regex on the request line, Host and headers (matchReq). Go walks
            // its header map in random order: decide only when two orders agree (then the order does not matter
            // for this request).
            guard let hs = rule.snap.hre else { return .unknown("url-and-header") }
            let hre = RWRegexCache.shared.regex(hs)
            let a = hre.match(NativeRewriteEngine.headerBlock(r, reversed: false))
            if a == .unknown { return .unknown("url-and-header") }
            if r.header.map.count > 1, hre.match(NativeRewriteEngine.headerBlock(r, reversed: true)) != a { return .unknown("url-and-header order") }
            return a == .yes ? .yes : .no
        }
    }

    /// handler.go applyHeaderOps for the ops Go marked portable. false: an input Swift will not run a regex on.
    static func apply(_ ops: [RWSnapHeaderOp], to h: inout CanonicalHeader, firstLine: String) -> Bool {
        for op in ops {
            let name = op.name ?? "", value = op.value ?? ""
            switch op.op {
            case "add": h.add(name, value)
            case "del": h.del(name)
            case "replace": if !h.get(name).isEmpty { h.set(name, value) }
            case "replace-regex":
                let v = h.get(name)
                if v.isEmpty { continue }
                guard let src = op.re else { continue }      // Go: no compiled regex → skipped
                if op.tperr == true { continue }             // Go: Replace fails → unchanged
                guard let tp = op.tp, RWRegex.inputOK(v), v.utf8.count <= 65536 else { if goFree { continue }; return false }
                guard let nv = RWRegexCache.shared.regex(src).replaceAll(v, tp) else { if goFree { continue }; return false }
                h.set(name, nv)
            case "raw":
                guard let src = op.re else { continue }
                if op.tperr == true { continue }
                guard let tp = op.tp else { if goFree { continue }; return false }
                let re = RWRegexCache.shared.regex(src)
                guard let a = raw(h, re, tp, firstLine, reversed: false) else { if goFree { continue }; return false }
                // Go walks its header map in random order; Go-free takes the sorted order when the two disagree
                if h.map.count > 1 && !goFree {
                    guard let b = raw(h, re, tp, firstLine, reversed: true), a == b else { return false }
                }
                h = a
            default:
                if goFree { continue }
                return false
            }
        }
        return true
    }

    /// The QX raw header-block rewrite (applyHeaderOps "raw"): first line, headers in map order (sorted or
    /// reversed here), blank line; every match replaced; headers rebuilt from the lines after the first.
    static func raw(_ h: CanonicalHeader, _ re: RWRegex, _ tp: RWSnapTemplate, _ firstLine: String, reversed: Bool) -> CanonicalHeader? {
        var s = firstLine + "\r\n"
        var keys = h.map.keys.sorted(by: RWAscii.less)
        if reversed { keys.reverse() }
        for k in keys { for v in h.values(k) { s += k + ": " + v + "\r\n" } }
        s += "\r\n"
        guard RWRegex.inputOK(s), s.utf8.count <= 65536, let out = re.replaceAll(s, tp) else { return nil }
        var nh = CanonicalHeader()
        let b = Array(out.utf8)
        var lines: [ArraySlice<UInt8>] = []
        var start = 0, i = 0
        while i + 1 < b.count {
            if b[i] == 0x0D && b[i + 1] == 0x0A { lines.append(b[start..<i]); i += 2; start = i } else { i += 1 }
        }
        lines.append(b[start...])
        for l in lines.dropFirst() {
            guard let c = l.firstIndex(of: UInt8(ascii: ":")) else { continue }
            let k = RWAscii.trimSpace(String(decoding: l[l.startIndex..<c], as: UTF8.self))
            let v = RWAscii.trimSpace(String(decoding: l[(c + 1)...], as: UTF8.self))
            if !k.isEmpty { nh.add(k, v) }
        }
        return nh
    }

    /// Attaches the request-log view to a local decision (a deferral passes through).
    static func logged(_ d: RewriteDecision, _ log: RewriteLog, _ body: Data) -> RewriteDecision {
        guard case .local(var l) = d else { return d }
        l.log = log
        l.logBody = body
        return .local(l)
    }

    /// handler.go writeLocal followed by flowWriter.commit.
    static func writeLocal(status: Int, header: CanonicalHeader, body: Data) -> RewriteDecision {
        var h = header
        h.del("Content-Encoding")
        h.del("Transfer-Encoding")
        h.set("Content-Length", String(body.count))
        return commitLocal(status: status, header: h, first: body.isEmpty ? nil : body)
    }

    /// flow_request.go flowWriter.commit on the header snapshot taken at WriteHeader.
    static func commitLocal(status: Int, header: CanonicalHeader, first: Data?) -> RewriteDecision {
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

    /// A host[:port] Go keeps verbatim everywhere it is used: letters, digits, "-", ".", optional ":digits".
    /// Header pairs from a script that Swift sends exactly as Go would (pairsHeader + the transport's checks):
    /// token names, values without CR / LF / NUL. Anything else → Go.
    static func scriptHeadersOK(_ hs: [[String]]) -> Bool {
        for kv in hs {
            guard kv.count == 2, !kv[0].isEmpty, kv[0].utf8.allSatisfy(RWAscii.isTokenByte) else { return false }
            if kv[1].utf8.contains(where: { $0 == 0x0D || $0 == 0x0A || $0 == 0 }) { return false }
        }
        return true
    }

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
        let key = src.p + "\u{0}" + (src.icu ?? "")
        if let r = map[key] { return r }
        if map.count >= 256 { map.removeAll() }
        let r = RWRegex(src)
        map[key] = r
        return r
    }
}
