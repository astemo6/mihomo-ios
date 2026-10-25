// Go-zero (nc-integrate): one build of this file — the NativeCore tunnel; the app target compiles the same code
// for its unit tests (tunnel-engine calls behind TERN_TUNNEL). The Go-backed variant is gone with bridge/.
// Native MitM stage 3a — plugs the native rewrite engine into NativeMitmSession.
//
// NativeRewriteDriver is a MitmFlowDriving in front of the Go driver. For each request it asks the native engine
// first (only when the switch `nativeMitmRewrite` is on — default OFF — and a snapshot for the running engine's
// current generation is loaded); a native decision gets a negative flow id and every later call for that id
// (response head, local body reads, end / cancel) is answered here without Go. A deferral (.go), the switch off, no
// snapshot, an unknown snapshot version or any inconsistency → the Go flow exactly as before. The session is not
// changed: it cannot tell a native decision from a Go one.
//
// Request log: every native decision is reported to Go's request log through NativeRequestRecorder (batched, off
// the request path), so the 请求 list / capture shows it like a Go-handled request (bridge/mitm/nativerecord.go).
//
// Body rewrites (stage 3b, switch `nativeMitmBody`, default OFF): a forward whose request or response has body
// rules Swift can run becomes a BodyFlow. The request body is taken (need-body) and rewritten here; the response
// body is taken whole (≤ 256 KB, known length) and decoded, rewritten and served here (NativeBodyExec). Whenever
// that is not certain to match Go — at the response head (chunked, large, no body) or once the body is in (not
// UTF-8 / not JSON / an encoding not decoded exactly like Go / a jq error / a slow regex) — the exchange is
// "adopted" by Go: MitmFlowBegin runs again with the original head (Go's request phase for a request Swift
// forwarded is deterministic: no scripts, no body Go needs except the request body pushed back to it), then
// MitmFlowResponse with the upstream head and the buffered body; every later call for the id is relayed to that
// Go flow. A body flow's request-log entry is written only once Swift has answered it natively (an adopted one is
// Go's own entry).
//
// Scripts (lane s3-script, switch `nativeMitmScript`, default OFF): a forward whose response runs http-response
// scripts becomes a ScriptFlow run by NativeScriptResponse (Script/NativeScriptDispatcher.swift); anything it cannot
// reproduce exactly is handed back to the Go flow before a script ran.
//
// Request scripts (native-final, switch `nativeMitmScript`): the engine stops at an http-request script, the
// script runs here (Script/NativeRequestScripts.swift; a requires-body script takes the request body from the
// session first: need-body .request), the engine goes on with its outcome. A request Swift cannot finish after a
// script ran is handed to Go with FlowHead.Scripted (the outcomes so far): Go's requestPhase applies them instead of
// running the scripts again. A response-script flow that hands its response back does the same.
//
// Snapshot freshness: MitmRewriteGeneration() is checked on every request (an int from Go); the JSON is fetched and
// decoded only when it moved (engine reload). A request racing a reload may use the previous rule set — the same
// window the Go path has between reading its state pointer and the reload storing a new one.

import Foundation

// MARK: - Switch

enum NativeRewriteRuntime {
    /// App-group key; default OFF (integration is decided by measurement).
    static let defaultsKey = "nativeMitmRewrite"

    /// Tests force it; nil = read the app-group default (cached for a second).
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

// MARK: - Snapshot source

protocol RewriteSnapshotSource: AnyObject {
    /// Current snapshot generation (0: engine not running).
    func generation() -> Int64
    /// The snapshot JSON ("" none).
    func snapshotJSON() -> String
    /// Go applies the given response header rules of snapshot `gen` (Swift could not: see NativeRewriteEngine
    /// respond). nil: unavailable.
    func headerOps(gen: Int64, rules: [Int], status: Int, headers: [[String]]) -> [[String]]?
    /// The decoded snapshot (nil none). Default: decodes snapshotJSON().
    func currentSnapshot() -> RWSnapshot?
}

extension RewriteSnapshotSource {
    func headerOps(gen: Int64, rules: [Int], status: Int, headers: [[String]]) -> [[String]]? { nil }
    func currentSnapshot() -> RWSnapshot? { RWSnapshot.decode(snapshotJSON()) }
}

final class NativeRewriteSnapshotSource: RewriteSnapshotSource {
    static let shared = NativeRewriteSnapshotSource()
    private let lock = NSLock()
    private var gen: Int64 = 1
    private var snapshot: RWSnapshot?
    /// The JSON the snapshot was read from (nativecore-rewrite.json); "" when it was built from a .conf profile.
    private var json = ""

    /// RWSnapshot is Decodable only: keep the decoded value (with this source's generation) plus the source text.
    func setSnapshot(_ s: RWSnapshot, json: String = "") {
        lock.lock()
        defer { lock.unlock() }
        gen += 1
        var copy = s
        copy.gen = gen
        snapshot = copy
        self.json = json
    }

    func currentSnapshot() -> RWSnapshot? {
        lock.lock(); defer { lock.unlock() }
        return snapshot
    }

    func generation() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return gen
    }

    func snapshotJSON() -> String {
        lock.lock(); defer { lock.unlock() }
        return snapshot == nil ? "" : json
    }
}

/// Holds the engine for the current generation.
final class NativeRewriteProvider {
    private let source: RewriteSnapshotSource
    private let lock = NSLock()
    private var engine: NativeRewriteEngine?
    private var failedGen: Int64 = 0
    private(set) var loads = 0

    init(source: RewriteSnapshotSource) { self.source = source }

    func current() -> NativeRewriteEngine? {
        let gen = source.generation()
        if gen == 0 { return nil }
        lock.lock(); defer { lock.unlock() }
        if let e = engine, e.generation == gen { return e }
        if failedGen == gen { return nil }
        guard let s = source.currentSnapshot(), (s.gen ?? 0) == gen else {
            failedGen = gen
            engine = nil
            return nil
        }
        let e = NativeRewriteEngine(snapshot: s)
        e.headerOpsFallback = { [weak source = self.source] gen, rules, status, headers in
            source?.headerOps(gen: gen, rules: rules, status: status, headers: headers)
        }
        engine = e
        loads += 1
        return e
    }
}

// MARK: - Driver

/// A Go flow driver that can start a request whose request scripts Swift already ran (FlowHead.Gen / Scripted).
protocol MitmScriptedFlowStarting: AnyObject {
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]]) -> FlowDecision
}

final class NativeRewriteDriver: MitmFlowDriving {
    private enum NativeFlow {
        case local(body: Data, offset: Int)
        case forward(plan: RewriteDecision.ResponsePlan, method: String, engine: NativeRewriteEngine)
        case responded(body: Data, offset: Int)
        case body(BodyFlow)
        /// Lane s3-script: a forward whose response runs http-response scripts natively.
        case script(ScriptFlow)
        /// native-final: a request script waits for the request body (need-body .request).
        case reqScript(ReqScriptFlow)
        /// native-final: handed to Go after request scripts ran natively — every call goes to this Go flow.
        case relay(Int64)
        case done
    }

    /// The request of a native request-script run (native-final).
    final class ReqScriptFlow {
        let q: RewriteRequest
        let engine: NativeRewriteEngine
        let head: HTTPRequestHead
        let conn: MitmConnInfo
        let rewrite: Bool, scripts: Bool, bodies: Bool
        let wall: Double
        let t0: UInt64
        let rs: NativeRequestScripts
        init(q: RewriteRequest, engine: NativeRewriteEngine, head: HTTPRequestHead, conn: MitmConnInfo, rewrite: Bool, scripts: Bool,
             bodies: Bool, wall: Double, t0: UInt64, rs: NativeRequestScripts) {
            self.q = q; self.engine = engine; self.head = head; self.conn = conn; self.rewrite = rewrite; self.scripts = scripts
            self.bodies = bodies; self.wall = wall; self.t0 = t0; self.rs = rs
        }
    }

    /// A native script flow (lane s3-script). Its request-log "forward" is written only when the response is
    /// handled natively; a response handed back to Go gets a Go flow (goID) and Go writes the whole entry.
    final class ScriptFlow {
        let plan: RewriteDecision.ResponsePlan
        let engine: NativeRewriteEngine
        let head: HTTPRequestHead
        let conn: MitmConnInfo
        let log: RewriteLog
        let wall: Double
        let t0: UInt64
        var response: NativeScriptResponse?
        var goID: Int64 = 0
        /// native-final: request scripts that ran natively (FlowHead.Scripted for a hand-back) and the client body
        /// Swift read for them (pushed to Go if its request phase loads it again).
        var scripted: [[String: Any]] = []
        var clientBody: Data?
        var out = Data()
        var offset = 0
        var closedWithError = false
        init(plan: RewriteDecision.ResponsePlan, engine: NativeRewriteEngine, head: HTTPRequestHead, conn: MitmConnInfo,
             log: RewriteLog, wall: Double, t0: UInt64) {
            self.plan = plan; self.engine = engine; self.head = head; self.conn = conn; self.log = log; self.wall = wall; self.t0 = t0
        }
    }

    /// A forward with body rules (stage 3b).
    private final class BodyFlow {
        enum Stage { case requestBody, forwarded, responseBody, responded, adopted, failed }
        let head: HTTPRequestHead
        let conn: MitmConnInfo
        let engine: NativeRewriteEngine
        var fwd: RewriteDecision.Forward
        var stage: Stage
        var reqIn = Data()                 // the client's request body as pushed
        var reqOut = Data(), reqOff = 0    // the rewritten request body (read .request)
        var respHead: HTTPResponseHead?
        var respLength: Int64 = -1
        var respIn = Data()                // the upstream's response body as pushed
        var respOut = Data(), respOff = 0  // the rewritten response body (read .response)
        var goID: Int64 = 0                // adopted: the Go flow
        var pending: [Data] = []           // adopted: body pieces Go has not taken yet ("more")
        var pendingWhich = FlowBodyWhich.response
        var pendingClose = false
        var rawServe: Data?                // adopted: Go said "upstream" after Swift had read the body itself
        var rawOff = 0
        var firstEvent: NativeRequestEvent? // the deferred "forward" log event
        let t0: UInt64
        init(head: HTTPRequestHead, conn: MitmConnInfo, engine: NativeRewriteEngine, fwd: RewriteDecision.Forward, t0: UInt64) {
            self.head = head; self.conn = conn; self.engine = engine; self.fwd = fwd; self.t0 = t0
            stage = fwd.requestBody != nil ? .requestBody : .forwarded
        }
    }

    struct Stats: Equatable {
        var local = 0, forward = 0, drop = 0, deferred = 0, off = 0
        var reasons: [String: Int] = [:]
        /// stage 3b: body flows answered in Swift / handed to Go mid-way (with why).
        var bodyNative = 0, bodyAdopted = 0
        var adoptReasons: [String: Int] = [:]
        /// Lane s3-script: script responses handled natively / handed back to Go (reasons in handBackReasons).
        var script = 0, scriptHandedBack = 0
        var handBackReasons: [String: Int] = [:]
        /// native-final: requests whose request scripts ran natively and that Swift finished / handed to Go.
        var reqScript = 0, reqScriptHandedOver = 0
        var handOverReasons: [String: Int] = [:]
    }

    /// A natively forwarded request's request-log state (until end / cancel / upstream failure).
    private struct LogCtx {
        let key: Int64
        let start: UInt64          // uptime ns at the request phase
        var responded = false      // a "respond" decision exists (Go: nf.respBody != nil)
        var upstreamMode = false   // the body is relayed from the upstream (Go counts the bytes the native side sent)
    }

    let inner: MitmFlowDriving
    let provider: NativeRewriteProvider
    let recorder: NativeRequestRecorder?
    /// Lane s3-script: what the native script dispatcher uses (production: Go bridge, JavaScriptCore, NativeBodyStore).
    var scriptGo: ScriptGoHost = GoScriptHost.shared
    var scriptJS: () -> NativeJSEngine? = {
        JSCScriptEngine.nativeBlobs != nil && JSCScriptEngine.shared.canInterrupt ? JSCScriptEngine.shared : nil
    }
    var scriptStore: () -> ScriptBodyStore? = { JSCScriptEngine.nativeBlobs as? ScriptBodyStore }
    var nativeBlobBase: Int64 = NativeBodyStore.defaultBlobBase
    private let lock = NSLock()
    private var flows: [Int64: NativeFlow] = [:]
    private var logs: [Int64: LogCtx] = [:]
    /// native-final: request bodies Swift serves for a forward (read .request): a request script's body or the
    /// client body it read.
    private var reqBodies: [Int64: (body: Data, off: Int)] = [:]
    private var nextID: Int64 = 0
    private var counters = Stats()

    init(inner: MitmFlowDriving, provider: NativeRewriteProvider = NativeRewriteProvider(source: NativeRewriteSnapshotSource.shared),
         recorder: NativeRequestRecorder? = NativeRequestRecorder.shared) {
        self.inner = inner
        self.provider = provider
        self.recorder = recorder
    }

    var stats: Stats { lock.lock(); defer { lock.unlock() }; return counters }
    var liveNativeFlows: Int { lock.lock(); defer { lock.unlock() }; return flows.count }
    /// Native forwards whose request-log entry is still open (tests).
    var openLogEntries: Int { lock.lock(); defer { lock.unlock() }; return logs.count }

    private func newID(_ f: NativeFlow) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        nextID -= 1
        flows[nextID] = f
        return nextID
    }

    private func count(_ k: WritableKeyPath<Stats, Int>, reason: String? = nil) {
        lock.lock()
        counters[keyPath: k] += 1
        if let reason { counters.reasons[reason, default: 0] += 1 }
        lock.unlock()
    }

    static func request(_ head: HTTPRequestHead, _ conn: MitmConnInfo) -> RewriteRequest {
        // the same head GoMitmFlowDriver.requestPhase sends to MitmFlowBegin
        let length: Int64 = head.isChunked ? -1 : (head.contentLength ?? 0)
        return RewriteRequest(method: head.method, target: head.target, host: head.host ?? "", headers: headerPairs(head.headers),
                              length: length, connHost: conn.host, connPort: conn.port, tls: conn.tls)
    }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        let rewrite = NativeRewriteRuntime.enabled
        let scripts = NativeScriptRuntime.enabled
        guard rewrite || scripts else { count(\.off); return inner.requestPhase(head: head, conn: conn) }
        guard let engine = provider.current() else { count(\.deferred, reason: "no snapshot"); return inner.requestPhase(head: head, conn: conn) }
        if let d = native(Self.request(head, conn), engine: engine, rewrite: rewrite, scripts: scripts, head: head, conn: conn,
                          bodies: rewrite && NativeBodyRuntime.enabled) { return d }
        return inner.requestPhase(head: head, conn: conn)
    }

    /// The native decision for q (nil: deferred to Go, counted). Records the request-log event of the decision.
    /// rewrite: native rewrite decisions are on (nativeMitmRewrite); scripts: lane s3-script (nativeMitmScript) — a
    /// forward whose response runs http-response scripts is taken natively; bodies: stage 3b body flows.
    /// head / conn: the session's request (needed for body and script flows, which Go may have to adopt / take
    /// back); without them body rules and scripts are left to Go.
    func native(_ q: RewriteRequest, engine: NativeRewriteEngine, rewrite: Bool = true, scripts: Bool = false,
                head: HTTPRequestHead? = nil, conn: MitmConnInfo? = nil, bodies: Bool = false) -> FlowDecision? {
        let wall = Date().timeIntervalSince1970
        let t0 = DispatchTime.now().uptimeNanoseconds
        let withHead = head != nil && conn != nil
        var plain: RewriteDecision?
        if scripts, let head, let conn, inner is MitmScriptedFlowStarting, let js = scriptJS(), scriptGo.ready() {
            // native-final: http-request scripts run here
            var pause: RequestScriptPause?
            let state = RequestScriptState()
            let d0 = engine.decide(q, bodies: bodies, scripts: true, requestScripts: state, pause: &pause)
            if pause != nil {
                let rs = NativeRequestScripts(gen: engine.generation, go: scriptGo, js: js, store: scriptStore(), nativeBase: nativeBlobBase)
                let rf = ReqScriptFlow(q: q, engine: engine, head: head, conn: conn, rewrite: rewrite, scripts: scripts, bodies: bodies,
                                       wall: wall, t0: t0, rs: rs)
                return runRequestScripts(rf, flowID: nil)
            }
            plain = d0 // no request script matched: the usual decision (same rules, same answer)
        }
        let decision = plain ?? engine.decide(q, bodies: bodies && withHead, scripts: scripts && withHead)
        if case .forward(let f) = decision, f.response.scripts != nil, let head, let conn {
            let sf = ScriptFlow(plan: f.response, engine: engine, head: head, conn: conn, log: f.log, wall: wall, t0: t0)
            let id = newID(.script(sf))
            return forwardDecision(id, f, bodyMode: f.bodyMode, length: f.length)
        }
        if !rewrite {
            if case .go(let why) = decision { count(\.deferred, reason: why) } else { count(\.off) }
            return nil
        }
        switch decision {
        case .go(let why):
            count(\.deferred, reason: why)
            return nil
        case .drop(let log):
            count(\.drop)
            let id = newID(.done)
            emitFirst("drop", log, engine: engine, wall: wall, t0: t0)
            return FlowDecision(id: id, action: .drop)
        case .local(let l):
            count(\.local)
            var d = FlowDecision(id: newID(.local(body: l.body, offset: 0)), action: .local)
            d.status = l.status; d.headers = l.headers; d.body = l.bodyMode; d.length = l.length
            emitFirst("local", l.log, engine: engine, wall: wall, t0: t0) { e in
                e.status = l.status
                e.len = l.logLen ?? Int64(l.logBody.count)
                if engine.capture && !l.logNoCapture && !l.logBody.isEmpty { e.body = l.logBody }
            }
            return d
        case .forward(let f) where f.requestBody != nil || f.response.hasBody:
            guard let head, let conn else { count(\.deferred, reason: "body without head"); return nil }
            count(\.forward)
            let bf = BodyFlow(head: head, conn: conn, engine: engine, fwd: f, t0: t0)
            bf.firstEvent = makeFirst("forward", f.log, engine: engine, wall: wall, t0: t0)
            let id = newID(.body(bf))
            if f.requestBody != nil {
                var d = FlowDecision(id: id, action: .needBody)
                d.which = FlowBodyWhich.request.rawValue
                return d
            }
            return forwardDecision(id, f, bodyMode: f.bodyMode, length: f.length)
        case .forward(let f):
            count(\.forward)
            let id = newID(.forward(plan: f.response, method: f.method, engine: engine))
            var d = FlowDecision(id: id, action: .forward)
            d.method = f.method; d.url = f.url; d.host = f.host; d.headers = f.headers; d.body = f.bodyMode; d.length = f.length
            if let key = emitFirst("forward", f.log, engine: engine, wall: wall, t0: t0) {
                lock.lock(); logs[id] = LogCtx(key: key, start: t0); lock.unlock()
            }
            return d
        }
    }

    // MARK: request log

    private static func ms(since t0: UInt64) -> Double {
        let now = DispatchTime.now().uptimeNanoseconds
        return now > t0 ? Double(now - t0) / 1e6 : 0
    }

    private func forwardDecision(_ id: Int64, _ f: RewriteDecision.Forward, bodyMode: FlowBodyMode, length: Int64) -> FlowDecision {
        var d = FlowDecision(id: id, action: .forward)
        d.method = f.method; d.url = f.url; d.host = f.host; d.headers = f.headers; d.body = bodyMode; d.length = length
        return d
    }

    /// A first event built now (its ms measured now) but recorded later (body flows: only once answered natively).
    private func makeFirst(_ ev: String, _ log: RewriteLog, engine: NativeRewriteEngine, wall: Double, t0: UInt64) -> NativeRequestEvent? {
        guard let recorder = recorder else { return nil }
        var e = NativeRequestEvent(k: recorder.newKey(), ev: ev, t: wall, ms: Self.ms(since: t0), gen: engine.generation,
                                   rules: log.rules.isEmpty ? nil : log.rules, method: log.method, url: log.url, host: log.host,
                                   tls: log.tls, headers: log.headers.isEmpty ? nil : log.headers)
        Self.scriptFields(&e, log)
        return e
    }

    /// Records a body flow's deferred forward event (once) and opens its log state.
    private func commitFirst(_ id: Int64, _ bf: BodyFlow) {
        guard let recorder = recorder, let e = bf.firstEvent else { return }
        bf.firstEvent = nil
        recorder.add(e)
        lock.lock(); logs[id] = LogCtx(key: e.k, start: bf.t0); lock.unlock()
    }

    /// The first event of a native request (drop / local / forward); returns its key (nil: no recorder).
    @discardableResult
    private func emitFirst(_ ev: String, _ log: RewriteLog, engine: NativeRewriteEngine, wall: Double, t0: UInt64,
                           _ fill: ((inout NativeRequestEvent) -> Void)? = nil) -> Int64? {
        guard let recorder = recorder else { return nil }
        let key = recorder.newKey()
        var e = NativeRequestEvent(k: key, ev: ev, t: wall, ms: Self.ms(since: t0), gen: engine.generation,
                                   rules: log.rules.isEmpty ? nil : log.rules, method: log.method, url: log.url, host: log.host,
                                   tls: log.tls, headers: log.headers.isEmpty ? nil : log.headers)
        Self.scriptFields(&e, log)
        fill?(&e)
        recorder.add(e)
        return key
    }

    /// native-final: the request scripts' part of a first event (notes, an abort's reason, the changed method).
    private static func scriptFields(_ e: inout NativeRequestEvent, _ log: RewriteLog) {
        if !log.notes.isEmpty { e.notes = log.notes }
        if !log.why.isEmpty { e.why = log.why }
        if !log.reqMethod.isEmpty { e.rmethod = log.reqMethod }
    }

    /// A later event of a natively forwarded request; `last` drops its log state.
    private func emit(_ id: Int64, last: Bool, _ make: (LogCtx) -> NativeRequestEvent?) {
        guard let recorder = recorder else { return }
        lock.lock()
        guard let ctx = logs[id] else { lock.unlock(); return }
        if last { logs.removeValue(forKey: id) }
        lock.unlock()
        if let e = make(ctx) { recorder.add(e) }
    }

    private func updateLog(_ id: Int64, _ f: (inout LogCtx) -> Void) {
        lock.lock()
        if var c = logs[id] { f(&c); logs[id] = c }
        lock.unlock()
    }

    func await(_ id: Int64) -> FlowDecision {
        if id >= 0 { return inner.await(id) }
        if let g = relayID(id) { return relabel(inner.await(g), id) }
        if let rf = reqScriptFlow(id) {
            if rf.rs.pushFailed {
                lock.lock(); flows[id] = .done; lock.unlock()
                rf.rs.end()
                return FlowDecision(id: id, action: .error, note: "request body truncated")
            }
            switch rf.rs.bodyArrived() {
            case .next: return runRequestScripts(rf, flowID: id)
            case .needBody: return FlowDecision(id: id, action: .error, note: "native request script wants a second body")
            case .handOver(let why): return handOver(rf, why: why, flowID: id)
            }
        }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return relabel(inner.await(sf.goID), id) }
            guard let r = sf.response else { return FlowDecision(id: id, action: .error, note: "native script flow has no response") }
            if sf.closedWithError {
                r.end()
                return FlowDecision(id: id, action: .error, note: "upstream body truncated")
            }
            switch r.awaitAfterBody() {
            case .done(let out): return scriptDecision(id, sf, out)
            case .needBody: return FlowDecision(id: id, action: .error, note: "native script flow wants a second body")
            case .handBack(let why):
                r.end()
                return FlowDecision(id: id, action: .error, note: "native script flow cannot hand back after the body: \(why)")
            }
        }
        guard let bf = bodyFlow(id) else { return FlowDecision(id: id, action: .error, note: "native flow has no pending decision") }
        switch bf.stage {
        case .adopted:
            return mapped(id, inner.await(bf.goID))
        case .requestBody:
            guard let plan = bf.fwd.requestBody else { return FlowDecision(id: id, action: .error, note: "no request body plan") }
            switch NativeBodyExec.request(plan, body: bf.reqIn) {
            case .body(let b):
                bf.reqOut = b
                bf.stage = .forwarded
                // setBody: r.Header Content-Length is the final length in Go's ent.ReqHeaders
                if var e = bf.firstEvent, var hs = e.headers {
                    for k in hs.indices where hs[k].count == 2 && hs[k][0] == "Content-Length" { hs[k][1] = String(b.count) }
                    e.headers = hs
                    bf.firstEvent = e
                }
                if !bf.fwd.response.hasBody { commitFirst(id, bf); count(\.bodyNative) }
                return forwardDecision(id, bf.fwd, bodyMode: b.isEmpty ? .none : .read, length: Int64(b.count))
            case .handBack(let why):
                return adoptRequest(id, bf, why: why)
            }
        case .responseBody:
            guard let h = bf.respHead else { return FlowDecision(id: id, action: .error, note: "no response head") }
            switch NativeBodyExec.response(bf.fwd.response.steps, status: h.status, headers: headerPairs(h.headers), length: bf.respLength, raw: bf.respIn) {
            case .native(let r):
                bf.respOut = r.body
                bf.stage = .responded
                count(\.bodyNative)
                commitFirst(id, bf)
                updateLog(id) { c in c.responded = true; c.upstreamMode = true } // Go counts the bytes the client reads
                emit(id, last: false) { c in
                    NativeRequestEvent(k: c.key, ev: "response", ms: Self.ms(since: c.start), gen: bf.engine.generation,
                                       rules: r.rules.isEmpty ? nil : r.rules, status: r.status, headers: r.logHeaders.isEmpty ? nil : r.logHeaders)
                }
                var d = FlowDecision(id: id, action: .respond)
                d.status = r.status; d.headers = r.headers; d.body = .read; d.length = r.length; d.note = r.note
                return d
            case .handBack(let why):
                return adoptResponse(id, bf, buffered: true, why: why)
            }
        default:
            return FlowDecision(id: id, action: .error, note: "native flow has no pending decision")
        }
    }

    // MARK: body flows

    private func bodyFlow(_ id: Int64) -> BodyFlow? {
        lock.lock(); defer { lock.unlock() }
        if case .body(let bf)? = flows[id] { return bf }
        return nil
    }

    private func adopted(_ why: String) {
        lock.lock()
        counters.bodyAdopted += 1
        counters.adoptReasons[why, default: 0] += 1
        lock.unlock()
    }

    /// A Go decision handed to the session under the native id.
    private func mapped(_ id: Int64, _ d: FlowDecision) -> FlowDecision {
        var d = d
        d.id = id
        return d
    }

    /// FlowWrite of a whole buffered body: pieces Go did not take ("full" after its decision) wait in pending for
    /// a "more"; "stop" drops the rest. false: the flow is gone.
    private func push(_ bf: BodyFlow, _ which: FlowBodyWhich, _ data: Data, close: Bool) -> Bool {
        var off = 0
        let chunk = 32 << 10
        while off < data.count {
            let piece = data.subdata(in: off..<min(off + chunk, data.count))
            switch inner.write(bf.goID, which, piece) {
            case .taken:
                off += piece.count
            case .stop:
                return true
            case .full:
                var rest: [Data] = []
                var o = off
                while o < data.count { rest.append(data.subdata(in: o..<min(o + chunk, data.count))); o += chunk }
                bf.pending = rest
                bf.pendingWhich = which
                bf.pendingClose = close
                return true
            case .gone:
                return false
            }
        }
        if close { inner.closeBody(bf.goID, which, error: "") }
        return true
    }

    /// Go takes the request before anything went upstream: MitmFlowBegin + the buffered request body.
    private func adoptRequest(_ id: Int64, _ bf: BodyFlow, why: String) -> FlowDecision {
        adopted(why)
        var d = inner.requestPhase(head: bf.head, conn: bf.conn)
        bf.goID = d.id
        bf.stage = .adopted
        bf.firstEvent = nil
        if d.action == .needBody {
            guard push(bf, .request, bf.reqIn, close: true) else { return FlowDecision(id: id, action: .error, note: "go flow gone") }
            d = inner.await(bf.goID)
        }
        return mapped(id, d)
    }

    /// Go takes the exchange after Swift forwarded the request: MitmFlowBegin again (same rules, same request →
    /// the same forward), then MitmFlowResponse; buffered: the response body Swift already read is pushed to Go.
    private func adoptResponse(_ id: Int64, _ bf: BodyFlow, buffered: Bool, why: String) -> FlowDecision {
        adopted(why)
        bf.firstEvent = nil
        bf.stage = .adopted
        var d = inner.requestPhase(head: bf.head, conn: bf.conn)
        bf.goID = d.id
        if d.action == .needBody {
            guard push(bf, .request, bf.reqIn, close: true) else { return FlowDecision(id: id, action: .error, note: "go flow gone") }
            d = inner.await(bf.goID)
            // whatever Go would send upstream was already sent by Swift: drop its request body
            if d.action == .forward && d.body == .read {
                for _ in 0..<10000 {
                    if inner.read(bf.goID, .request, max: 128 << 10).isEmpty {
                        if inner.readState(bf.goID, .request) != .again { break }
                    }
                }
            }
        }
        guard d.action == .forward, let h = bf.respHead else {
            inner.cancel(bf.goID, why: "native adopt: request phase changed")
            bf.stage = .failed
            return FlowDecision(id: id, action: .error, note: "adopt: Go answered \(d.action.rawValue)")
        }
        var r = inner.responsePhase(bf.goID, head: h, length: bf.respLength)
        if !buffered { return mapped(id, r) }
        if r.action == .needBody {
            guard push(bf, .response, bf.respIn, close: true) else { return FlowDecision(id: id, action: .error, note: "go flow gone") }
            r = inner.await(bf.goID)
        }
        if r.action == .respond && r.body == .upstream {
            // Go would relay the upstream's body untouched — Swift already read it: serve those bytes
            bf.rawServe = bf.respIn
            r.body = .read
            r.length = Int64(bf.respIn.count)
        }
        return mapped(id, r)
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        if id >= 0 { return inner.responsePhase(id, head: head, length: length) }
        if let g = relayID(id) { return relabel(inner.responsePhase(g, head: head, length: length), id) }
        if let bf = bodyFlow(id) { return bodyResponse(id, bf, head: head, length: length) }
        lock.lock()
        let f = flows[id]
        lock.unlock()
        if case .script(let sf)? = f { return scriptResponse(id, sf, head: head, length: length) }
        return headerResponse(id, f, head: head, length: length)
    }

    private func bodyResponse(_ id: Int64, _ bf: BodyFlow, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        switch bf.stage {
        case .adopted:
            return mapped(id, inner.responsePhase(bf.goID, head: head, length: length))
        case .forwarded:
            break
        default:
            return FlowDecision(id: id, action: .error, note: "native flow is not waiting for a response")
        }
        bf.respHead = head
        bf.respLength = length
        if !bf.fwd.response.hasBody {
            // request body rules only: the response is the header-only path (its log state is open already)
            return headerResponse(id, .forward(plan: bf.fwd.response, method: bf.fwd.method, engine: bf.engine), head: head, length: length)
        }
        if let why = NativeBodyExec.responseHeadOK(status: head.status, headers: headerPairs(head.headers), length: length, method: bf.fwd.method) {
            return adoptResponse(id, bf, buffered: false, why: why)
        }
        bf.stage = .responseBody
        var d = FlowDecision(id: id, action: .needBody)
        d.which = FlowBodyWhich.response.rawValue
        return d
    }

    private func headerResponse(_ id: Int64, _ f: NativeFlow?, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        guard case .forward(let plan, let method, let engine)? = f,
              let r = engine.respond(plan, status: head.status, headers: headerPairs(head.headers), length: length, method: method) else {
            emit(id, last: true) { c in NativeRequestEvent(k: c.key, ev: "error", ms: Self.ms(since: c.start)) }
            return FlowDecision(id: id, action: .error, note: "native flow is not waiting for a response")
        }
        lock.lock()
        flows[id] = .responded(body: Data(), offset: 0)
        lock.unlock()
        updateLog(id) { c in
            c.responded = r.action == .respond
            c.upstreamMode = r.bodyMode == .upstream
        }
        emit(id, last: false) { c in
            NativeRequestEvent(k: c.key, ev: "response", ms: Self.ms(since: c.start), gen: engine.generation,
                               rules: plan.rules.isEmpty ? nil : plan.rules, status: r.status,
                               headers: r.logHeaders.isEmpty ? nil : r.logHeaders)
        }
        var d = FlowDecision(id: id, action: r.action)
        d.status = r.status; d.headers = r.headers; d.body = r.bodyMode; d.length = r.length; d.note = r.note
        return d
    }

    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        if id >= 0 { return inner.write(id, which, data) }
        if let g = relayID(id) { return inner.write(g, which, data) }
        if let rf = reqScriptFlow(id) { return which == .request ? rf.rs.write(data) : .stop }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return inner.write(sf.goID, which, data) }
            guard which == .response, let r = sf.response else { return .stop }
            return r.write(data)
        }
        guard let bf = bodyFlow(id) else { return .stop }
        switch (bf.stage, which) {
        case (.adopted, _): return inner.write(bf.goID, which, data)
        case (.requestBody, .request):
            if bf.reqIn.count + data.count > NativeBodyRuntime.maxBody + 1 { return .stop }
            bf.reqIn.append(data)
            return .taken
        case (.responseBody, .response):
            if bf.respIn.count + data.count > NativeBodyRuntime.maxBody + 1 { return .stop }
            bf.respIn.append(data)
            return .taken
        default: return .stop
        }
    }

    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {
        if id >= 0 { inner.closeBody(id, which, error: error); return }
        if let g = relayID(id) { inner.closeBody(g, which, error: error); return }
        if let rf = reqScriptFlow(id) { if !error.isEmpty { rf.rs.pushError() }; return }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { inner.closeBody(sf.goID, which, error: error); return }
            if !error.isEmpty { sf.closedWithError = true }
            return
        }
        guard let bf = bodyFlow(id) else { return }
        if bf.stage == .adopted { inner.closeBody(bf.goID, which, error: error); return }
        if !error.isEmpty && (bf.stage == .requestBody || bf.stage == .responseBody) { bf.stage = .failed }
    }

    /// An adopted flow's read: Go asking for more of a body Swift holds is fed from pending.
    private func adoptedRead(_ bf: BodyFlow, _ which: FlowBodyWhich, max: Int) -> Data {
        if which == .response, let raw = bf.rawServe {
            let n = Swift.min(Swift.max(max, 1), raw.count - bf.rawOff)
            if n <= 0 { return Data() }
            defer { bf.rawOff += n }
            return raw.subdata(in: bf.rawOff..<(bf.rawOff + n))
        }
        for _ in 0..<64 {
            let d = inner.read(bf.goID, which, max: max)
            if !d.isEmpty { return d }
            guard inner.readState(bf.goID, which) == .more, feedPending(bf, which) else { return d }
        }
        return Data()
    }

    /// Pushes the next pending piece (or the close) after a "more". false: nothing left to give.
    private func feedPending(_ bf: BodyFlow, _ which: FlowBodyWhich) -> Bool {
        guard bf.pendingWhich == which else { return false }
        if let next = bf.pending.first {
            switch inner.write(bf.goID, which, next) {
            case .taken: bf.pending.removeFirst()
            case .full: break
            case .stop, .gone: bf.pending.removeAll(); bf.pendingClose = false; return false
            }
            return true
        }
        if bf.pendingClose {
            bf.pendingClose = false
            inner.closeBody(bf.goID, which, error: "")
            return true
        }
        return false
    }

    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        if id >= 0 { return inner.read(id, which, max: max) }
        if which == .request, let b = servedRequestBody(id, max: max) { return b }
        if let g = relayID(id) { return inner.read(g, which, max: max) }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return inner.read(sf.goID, which, max: max) }
            guard which == .response else { return Data() }
            lock.lock(); defer { lock.unlock() }
            let n = Swift.min(Swift.max(max, 1), sf.out.count - sf.offset)
            if n <= 0 { return Data() }
            let start = sf.out.startIndex + sf.offset
            sf.offset += n
            return sf.out.subdata(in: start..<(start + n))
        }
        if let bf = bodyFlow(id) {
            switch bf.stage {
            case .adopted: return adoptedRead(bf, which, max: max)
            case .forwarded, .responseBody, .responded:
                if which == .request {
                    let n = Swift.min(Swift.max(max, 1), bf.reqOut.count - bf.reqOff)
                    if n <= 0 { return Data() }
                    defer { bf.reqOff += n }
                    return bf.reqOut.subdata(in: bf.reqOff..<(bf.reqOff + n))
                }
                guard bf.stage == .responded else { return Data() }
                let n = Swift.min(Swift.max(max, 1), bf.respOut.count - bf.respOff)
                if n <= 0 { return Data() }
                defer { bf.respOff += n }
                return bf.respOut.subdata(in: bf.respOff..<(bf.respOff + n))
            default: return Data()
            }
        }
        guard which == .response else { return Data() }
        lock.lock(); defer { lock.unlock() }
        switch flows[id] {
        case .local(let body, let off)?:
            let n = Swift.min(Swift.max(max, 1), body.count - off)
            if n <= 0 { return Data() }
            flows[id] = .local(body: body, offset: off + n)
            return body.subdata(in: off..<(off + n))
        case .responded(let body, let off)?:
            let n = Swift.min(Swift.max(max, 1), body.count - off)
            if n <= 0 { return Data() }
            flows[id] = .responded(body: body, offset: off + n)
            return body.subdata(in: off..<(off + n))
        default:
            return Data()
        }
    }

    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState {
        if id >= 0 { return inner.readState(id, which) }
        if which == .request, hasServedRequestBody(id) { return .eof }
        if let g = relayID(id) { return inner.readState(g, which) }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return inner.readState(sf.goID, which) }
            return which == .response ? .eof : .failed("err: no body to read")
        }
        if let bf = bodyFlow(id) {
            switch bf.stage {
            case .adopted:
                if which == .response, bf.rawServe != nil { return .eof }
                let st = inner.readState(bf.goID, which)
                if st == .more && feedPending(bf, which) { return .again }
                return st
            case .forwarded, .responseBody, .responded: return .eof
            default: return .failed("err: native body flow failed")
            }
        }
        guard which == .response else { return .failed("err: no body to read") }
        lock.lock(); defer { lock.unlock() }
        switch flows[id] {
        case .local?, .responded?: return .eof // read() returned empty: the (in-memory) body is complete
        default: return .failed("err: unknown flow")
        }
    }

    func upstreamFailed(_ id: Int64, why: String) {
        if id >= 0 { return inner.upstreamFailed(id, why: why) }
        if let g = relayID(id) { return inner.upstreamFailed(g, why: why) }
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return inner.upstreamFailed(sf.goID, why: why) }
            lock.lock(); flows.removeValue(forKey: id); lock.unlock()
            sf.response?.end()
            // the deferred forward record first (Go wrote it at FlowBegin), then the failure
            if let key = emitFirst("forward", sf.log, engine: sf.engine, wall: sf.wall, t0: sf.t0) {
                recorder?.add(NativeRequestEvent(k: key, ev: "upstream", ms: Self.ms(since: sf.t0), why: why))
            }
            return
        }
        if let bf = bodyFlow(id) {
            if bf.stage == .adopted { return inner.upstreamFailed(bf.goID, why: why) }
            commitFirst(id, bf) // Swift forwarded it: the entry is native
        }
        emit(id, last: true) { c in NativeRequestEvent(k: c.key, ev: "upstream", ms: Self.ms(since: c.start), why: why) }
    }

    func end(_ id: Int64, sent: Int64, error: String) {
        if id >= 0 { return inner.end(id, sent: sent, error: error) }
        dropServedRequestBody(id)
        if let g = relayID(id) { lock.lock(); flows.removeValue(forKey: id); lock.unlock(); return inner.end(g, sent: sent, error: error) }
        if let rf = reqScriptFlow(id) { lock.lock(); flows.removeValue(forKey: id); lock.unlock(); rf.rs.end(); return }
        if let sf = scriptFlow(id) {
            lock.lock(); flows.removeValue(forKey: id); lock.unlock()
            sf.response?.end()
            if sf.goID != 0 { return inner.end(sf.goID, sent: sent, error: error) }
            if !hasLog(id) {
                // ended before its native response was recorded: the forward record, then the end
                if let key = emitFirst("forward", sf.log, engine: sf.engine, wall: sf.wall, t0: sf.t0) {
                    recorder?.add(NativeRequestEvent(k: key, ev: "end", ms: Self.ms(since: sf.t0), why: error.isEmpty ? nil : error))
                }
                return
            }
        }
        if let bf = bodyFlow(id) {
            lock.lock(); flows.removeValue(forKey: id); lock.unlock()
            if bf.stage == .adopted || bf.stage == .failed && bf.goID != 0 { return inner.end(bf.goID, sent: sent, error: error) }
            commitFirst(id, bf)
        }
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
        emit(id, last: true) { c in
            NativeRequestEvent(k: c.key, ev: "end", ms: Self.ms(since: c.start), sent: c.upstreamMode && sent > 0 ? sent : nil,
                               resp: c.responded ? true : nil, why: error.isEmpty ? nil : error)
        }
    }

    func cancel(_ id: Int64, why: String) {
        if id >= 0 { return inner.cancel(id, why: why) }
        dropServedRequestBody(id)
        if let g = relayID(id) { lock.lock(); flows.removeValue(forKey: id); lock.unlock(); return inner.cancel(g, why: why) }
        if let rf = reqScriptFlow(id) { lock.lock(); flows.removeValue(forKey: id); lock.unlock(); rf.rs.end(); return }
        if let sf = scriptFlow(id) {
            lock.lock(); flows.removeValue(forKey: id); lock.unlock()
            sf.response?.end()
            if sf.goID != 0 { return inner.cancel(sf.goID, why: why) }
            if !hasLog(id) {
                // cancelled before its native response was recorded: the forward record, then the cancel
                if let key = emitFirst("forward", sf.log, engine: sf.engine, wall: sf.wall, t0: sf.t0) {
                    recorder?.add(NativeRequestEvent(k: key, ev: "cancel", ms: Self.ms(since: sf.t0), why: why.isEmpty ? nil : why))
                }
                return
            }
        }
        if let bf = bodyFlow(id) {
            lock.lock(); flows.removeValue(forKey: id); lock.unlock()
            if bf.stage == .adopted || bf.stage == .failed && bf.goID != 0 { return inner.cancel(bf.goID, why: why) }
            commitFirst(id, bf)
        }
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
        emit(id, last: true) { c in
            NativeRequestEvent(k: c.key, ev: "cancel", ms: Self.ms(since: c.start), resp: c.responded ? true : nil, why: why.isEmpty ? nil : why)
        }
    }

    // MARK: - lane s3-script

    private func hasLog(_ id: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return logs[id] != nil
    }

    private func scriptFlow(_ id: Int64) -> ScriptFlow? {
        lock.lock(); defer { lock.unlock() }
        if case .script(let sf)? = flows[id] { return sf }
        return nil
    }

    private func relabel(_ d: FlowDecision, _ id: Int64) -> FlowDecision {
        var d = d
        d.id = id
        return d
    }

    private func countScript(handedBack why: String?) {
        lock.lock()
        if let why {
            counters.scriptHandedBack += 1
            counters.handBackReasons[why, default: 0] += 1
        } else {
            counters.script += 1
        }
        lock.unlock()
    }

    /// The response phase of a native script flow: natively (NativeScriptResponse), or handed back to the Go flow.
    private func scriptResponse(_ id: Int64, _ sf: ScriptFlow, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        guard let steps = sf.plan.scripts, let js = scriptJS(), let store = scriptStore(), scriptGo.ready() else {
            return handBack(id, sf, head: head, length: length, why: "engine")
        }
        let view = ScriptRequestView(url: sf.plan.url, method: sf.plan.method, header: sf.plan.requestHeader, host: sf.plan.requestHost)
        let r = NativeScriptResponse(gen: sf.engine.generation, steps: steps, request: view, go: scriptGo, js: js, store: store,
                                     nativeBase: nativeBlobBase)
        sf.response = r
        switch r.head(status: head.status, headers: headerPairs(head.headers), length: length) {
        case .handBack(let why):
            r.end()
            sf.response = nil
            return handBack(id, sf, head: head, length: length, why: why)
        case .needBody:
            var d = FlowDecision(id: id, action: .needBody)
            d.which = FlowBodyWhich.response.rawValue
            return d
        case .done(let out):
            return scriptDecision(id, sf, out)
        }
    }

    /// Go takes the response over: its request phase runs again (no script ran yet, so nothing is repeated; it
    /// decides the same forward), then FlowResponse with the upstream's head. Every later call for id goes to it.
    private func handBack(_ id: Int64, _ sf: ScriptFlow, head: HTTPResponseHead, length: Int64, why: String) -> FlowDecision {
        countScript(handedBack: why)
        let d = goBegin(sf.head, sf.conn, gen: sf.engine.generation, scripted: sf.scripted, clientBody: sf.clientBody, alreadySent: true)
        guard d.action == .forward, d.id > 0 else {
            if d.id > 0 { inner.cancel(d.id, why: "native hand-back") }
            return FlowDecision(id: id, action: .error, note: "hand-back: Go answered \(d.action) (\(d.note ?? ""))")
        }
        sf.goID = d.id
        return relabel(inner.responsePhase(d.id, head: head, length: length), id)
    }

    /// The native response decision: the deferred forward record, the response record, the session's decision.
    private func scriptDecision(_ id: Int64, _ sf: ScriptFlow, _ out: ScriptResponseOutput) -> FlowDecision {
        countScript(handedBack: nil)
        let key = emitFirst("forward", sf.log, engine: sf.engine, wall: sf.wall, t0: sf.t0)
        if let key {
            lock.lock()
            logs[id] = LogCtx(key: key, start: sf.t0, responded: out.action == .respond, upstreamMode: out.bodyMode != .none)
            lock.unlock()
        }
        let gen = sf.engine.generation
        if out.action == .error {
            lock.lock(); flows[id] = .done; lock.unlock()
            if out.abortWhy != nil {
                emit(id, last: true) { c in
                    NativeRequestEvent(k: c.key, ev: "abort", ms: Self.ms(since: c.start), gen: gen, rules: out.rules.isEmpty ? nil : out.rules,
                                       why: out.abortWhy, notes: out.notes.isEmpty ? nil : out.notes)
                }
            } else {
                emit(id, last: true) { c in NativeRequestEvent(k: c.key, ev: "error", ms: Self.ms(since: c.start)) }
            }
            return FlowDecision(id: id, action: .error, note: out.note)
        }
        lock.lock()
        sf.out = out.body
        sf.offset = 0
        lock.unlock()
        emit(id, last: false) { c in
            NativeRequestEvent(k: c.key, ev: "response", ms: Self.ms(since: c.start), gen: gen,
                               rules: out.rules.isEmpty || out.status == 101 ? nil : out.rules, status: out.status,
                               headers: out.logHeaders.isEmpty ? nil : out.logHeaders, notes: out.notes.isEmpty ? nil : out.notes)
        }
        var d = FlowDecision(id: id, action: out.action)
        d.status = out.status; d.headers = out.headers; d.body = out.bodyMode; d.length = out.length; d.lane = out.lane; d.note = out.note
        return d
    }
    // MARK: - native-final: request scripts

    private func relayID(_ id: Int64) -> Int64? {
        lock.lock(); defer { lock.unlock() }
        if case .relay(let g)? = flows[id] { return g }
        return nil
    }

    private func reqScriptFlow(_ id: Int64) -> ReqScriptFlow? {
        lock.lock(); defer { lock.unlock() }
        if case .reqScript(let rf)? = flows[id] { return rf }
        return nil
    }

    private func servedRequestBody(_ id: Int64, max: Int) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard let (body, off) = reqBodies[id] else { return nil }
        let n = Swift.min(Swift.max(max, 1), body.count - off)
        if n <= 0 { return Data() }
        reqBodies[id] = (body, off + n)
        let start = body.startIndex + off
        return body.subdata(in: start..<(start + n))
    }

    private func hasServedRequestBody(_ id: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return reqBodies[id] != nil
    }

    private func dropServedRequestBody(_ id: Int64) {
        lock.lock(); reqBodies.removeValue(forKey: id); lock.unlock()
    }

    private func countReqScript(handedOver why: String?) {
        lock.lock()
        if let why {
            counters.reqScriptHandedOver += 1
            counters.handOverReasons[why, default: 0] += 1
        } else {
            counters.reqScript += 1
        }
        lock.unlock()
    }

    /// Decide → run the script the engine stopped at → decide again, until a decision (or a body wait / hand-over).
    /// flowID: the native id the session already holds (after a body wait), nil: none yet.
    private func runRequestScripts(_ rf: ReqScriptFlow, flowID: Int64?) -> FlowDecision {
        for _ in 0..<4096 {
            var pause: RequestScriptPause?
            let d = rf.engine.decide(rf.q, bodies: rf.bodies, scripts: true, requestScripts: rf.rs.state, pause: &pause)
            guard let p = pause else { return finishRequestScripts(rf, d, flowID: flowID) }
            switch rf.rs.step(p) {
            case .next:
                continue
            case .handOver(let why):
                return handOver(rf, why: why, flowID: flowID)
            case .needBody:
                let id: Int64
                if let flowID {
                    lock.lock(); flows[flowID] = .reqScript(rf); lock.unlock()
                    id = flowID
                } else {
                    id = newID(.reqScript(rf))
                }
                var nd = FlowDecision(id: id, action: .needBody)
                nd.which = FlowBodyWhich.request.rawValue
                return nd
            }
        }
        return handOver(rf, why: "request scripts loop", flowID: flowID)
    }

    /// The engine's decision after the request scripts.
    private func finishRequestScripts(_ rf: ReqScriptFlow, _ decision: RewriteDecision, flowID: Int64?) -> FlowDecision {
        let rs = rf.rs
        if case .go(let why) = decision { return handOver(rf, why: why, flowID: flowID) }
        if case .forward(let f) = decision, f.requestBody != nil || f.response.hasBody {
            return handOver(rf, why: "request script with body rules", flowID: flowID) // (the engine hands these over already)
        }
        let engine = rf.engine
        let wall = rf.wall, t0 = rf.t0
        func place(_ f: NativeFlow) -> Int64 {
            if let flowID { lock.lock(); flows[flowID] = f; lock.unlock(); return flowID }
            return newID(f)
        }
        countReqScript(handedOver: nil)
        switch decision {
        case .go:
            return FlowDecision(id: flowID ?? 0, action: .error, note: "unreachable")
        case .drop(var log):
            log.notes = rs.notes
            rs.end()
            count(\.drop)
            let id = place(.done)
            emitFirst("drop", log, engine: engine, wall: wall, t0: t0)
            return FlowDecision(id: id, action: .drop)
        case .local(var l):
            l.log.notes = rs.notes
            if let w = rs.mockWarn {
                _ = scriptGo.host(gen: engine.generation, rule: w.rule, op: "log", arg: "warn\n脚本返回的状态码 \(w.status) 无效，按 200 处理")
            }
            rs.end()
            count(\.local)
            var d = FlowDecision(id: place(.local(body: l.body, offset: 0)), action: .local)
            d.status = l.status; d.headers = l.headers; d.body = l.bodyMode; d.length = l.length
            emitFirst("local", l.log, engine: engine, wall: wall, t0: t0) { e in
                e.status = l.status
                e.len = l.logLen ?? Int64(l.logBody.count)
                if engine.capture && !l.logNoCapture && !l.logBody.isEmpty { e.body = l.logBody }
            }
            return d
        case .forward(var f):
            f.log.notes = rs.notes
            // the body Go would send: a script's body, else the client body Swift read for a script
            let served: Data? = f.scriptBody ?? (rs.state.bodyLoaded ? rs.clientBytes : nil)
            var mode = f.bodyMode, length = f.length
            if let b = served { (mode, length) = b.isEmpty ? (.none, 0) : (.read, Int64(b.count)) }
            let scripted = rs.scriptedForGo
            let clientBody = rs.clientBytes
            rs.end()
            count(\.forward)
            let id: Int64
            if f.response.scripts != nil {
                let sf = ScriptFlow(plan: f.response, engine: engine, head: rf.head, conn: rf.conn, log: f.log, wall: wall, t0: t0)
                sf.scripted = scripted
                sf.clientBody = clientBody
                id = place(.script(sf))
            } else {
                id = place(.forward(plan: f.response, method: f.method, engine: engine))
                if let key = emitFirst("forward", f.log, engine: engine, wall: wall, t0: t0) {
                    lock.lock(); logs[id] = LogCtx(key: key, start: t0); lock.unlock()
                }
            }
            if let b = served, !b.isEmpty { lock.lock(); reqBodies[id] = (b, 0); lock.unlock() }
            return forwardDecision(id, f, bodyMode: mode, length: length)
        }
    }

    /// Go takes the request with the request-script outcomes so far.
    private func handOver(_ rf: ReqScriptFlow, why: String, flowID: Int64?) -> FlowDecision {
        countReqScript(handedOver: why)
        let rs = rf.rs
        let held = rs.clientBytes
        let scripted = rs.scriptedForGo
        rs.end()
        var d = goBegin(rf.head, rf.conn, gen: rf.engine.generation, scripted: scripted, clientBody: held, alreadySent: false)
        // Go forwards the client body untouched but Swift holds it: serve those bytes
        var serve: Data?
        if d.action == .forward, d.body == .client, let b = held {
            d.body = b.isEmpty ? FlowBodyMode.none : .read
            d.length = Int64(b.count)
            serve = b
        }
        guard d.id > 0 else { return flowID.map { relabel(d, $0) } ?? d }
        if flowID == nil && serve == nil { return d } // nothing of the request is in Swift: the Go flow as it is
        let id: Int64
        if let flowID {
            lock.lock(); flows[flowID] = .relay(d.id); lock.unlock()
            id = flowID
        } else {
            id = newID(.relay(d.id))
        }
        if let b = serve, !b.isEmpty { lock.lock(); reqBodies[id] = (b, 0); lock.unlock() }
        return relabel(d, id)
    }

    /// MitmFlowBegin with FlowHead.Scripted; a request phase that loads the body again gets the bytes Swift holds.
    /// alreadySent: Swift already sent the request upstream (a response hand-back) — whatever request body Go would
    /// send is drained.
    private func goBegin(_ head: HTTPRequestHead, _ conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]], clientBody: Data?,
                         alreadySent: Bool) -> FlowDecision {
        guard !scripted.isEmpty, let starter = inner as? MitmScriptedFlowStarting else { return inner.requestPhase(head: head, conn: conn) }
        var d = starter.requestPhase(head: head, conn: conn, gen: gen, scripted: scripted)
        if d.action == .needBody, d.id > 0, let body = clientBody {
            var off = 0
            var tries = 0
            pushing: while off < body.count {
                let end = Swift.min(off + (32 << 10), body.count)
                switch inner.write(d.id, .request, body.subdata(in: (body.startIndex + off)..<(body.startIndex + end))) {
                case .taken: off = end
                case .full:
                    tries += 1
                    if tries > 5000 { break pushing }
                    usleep(1000)
                case .stop, .gone: break pushing
                }
            }
            inner.closeBody(d.id, .request, error: "")
            d = inner.await(d.id)
            if alreadySent && d.action == .forward && d.body == .read {
                for _ in 0..<10000 {
                    if inner.read(d.id, .request, max: 128 << 10).isEmpty {
                        if inner.readState(d.id, .request) != .again { break }
                    }
                }
            }
        }
        return d
    }
}
