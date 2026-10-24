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
// Snapshot freshness: MitmRewriteGeneration() is checked on every request (an int from Go); the JSON is fetched and
// decoded only when it moved (engine reload). A request racing a reload may use the previous rule set — the same
// window the Go path has between reading its state pointer and the reload storing a new one.

import Foundation
import Libmihomo

// MARK: - Switch

enum NativeRewriteRuntime {
    /// App-group key; default OFF (integration is decided by measurement).
    static let defaultsKey = "nativeMitmRewrite"

    /// Tests force it; nil = read the app-group default (cached for a second).
    static var override: Bool?

    private static let lock = NSLock()
    private static var cached = false
    private static var readAt: TimeInterval = 0

    static var enabled: Bool {
        if let o = override { return o }
        lock.lock(); defer { lock.unlock() }
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = UserDefaults(suiteName: NativeMitmRuntime.appGroup)?.bool(forKey: defaultsKey) ?? false
        }
        return cached
    }
}

// MARK: - Snapshot source

protocol RewriteSnapshotSource: AnyObject {
    /// Current snapshot generation (0: engine not running).
    func generation() -> Int64
    /// The snapshot JSON ("" none).
    func snapshotJSON() -> String
}

final class GoRewriteSnapshotSource: RewriteSnapshotSource {
    func generation() -> Int64 { LibmihomoMitmRewriteGeneration() }
    func snapshotJSON() -> String { LibmihomoMitmRewriteSnapshot() }
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
        guard let s = RWSnapshot.decode(source.snapshotJSON()), (s.gen ?? 0) == gen else {
            failedGen = gen
            engine = nil
            return nil
        }
        let e = NativeRewriteEngine(snapshot: s)
        engine = e
        loads += 1
        return e
    }
}

// MARK: - Driver

final class NativeRewriteDriver: MitmFlowDriving {
    private enum NativeFlow {
        case local(body: Data, offset: Int)
        case forward(plan: RewriteDecision.ResponsePlan, method: String, engine: NativeRewriteEngine)
        case responded(body: Data, offset: Int)
        /// Lane s3-script: a forward whose response runs http-response scripts natively.
        case script(ScriptFlow)
        case done
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
        var out = Data()
        var offset = 0
        var closedWithError = false
        init(plan: RewriteDecision.ResponsePlan, engine: NativeRewriteEngine, head: HTTPRequestHead, conn: MitmConnInfo,
             log: RewriteLog, wall: Double, t0: UInt64) {
            self.plan = plan; self.engine = engine; self.head = head; self.conn = conn; self.log = log; self.wall = wall; self.t0 = t0
        }
    }

    struct Stats: Equatable {
        var local = 0, forward = 0, drop = 0, deferred = 0, off = 0
        var reasons: [String: Int] = [:]
        /// Lane s3-script: script responses handled natively / handed back to Go (reasons in handBackReasons).
        var script = 0, scriptHandedBack = 0
        var handBackReasons: [String: Int] = [:]
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
    var nativeBlobBase: Int64 = LibmihomoNativeBlobBase()
    private let lock = NSLock()
    private var flows: [Int64: NativeFlow] = [:]
    private var logs: [Int64: LogCtx] = [:]
    private var nextID: Int64 = 0
    private var counters = Stats()

    init(inner: MitmFlowDriving, provider: NativeRewriteProvider = NativeRewriteProvider(source: GoRewriteSnapshotSource()),
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
        if let d = native(Self.request(head, conn), engine: engine, rewrite: rewrite, scripts: scripts, head: head, conn: conn) { return d }
        return inner.requestPhase(head: head, conn: conn)
    }

    /// The native decision for q (nil: deferred to Go, counted). Records the request-log event of the decision.
    /// rewrite: native rewrite decisions are on (nativeMitmRewrite); scripts: lane s3-script (nativeMitmScript) — a
    /// forward whose response runs http-response scripts is taken natively (head / conn: the request as the session
    /// parsed it, for a hand-back to the Go flow at the response).
    func native(_ q: RewriteRequest, engine: NativeRewriteEngine, rewrite: Bool = true, scripts: Bool = false,
                head: HTTPRequestHead? = nil, conn: MitmConnInfo? = nil) -> FlowDecision? {
        let wall = Date().timeIntervalSince1970
        let t0 = DispatchTime.now().uptimeNanoseconds
        let decision = engine.decide(q, scripts: scripts && head != nil)
        if case .forward(let f) = decision, f.response.scripts != nil, let head, let conn {
            let sf = ScriptFlow(plan: f.response, engine: engine, head: head, conn: conn, log: f.log, wall: wall, t0: t0)
            let id = newID(.script(sf))
            var d = FlowDecision(id: id, action: .forward)
            d.method = f.method; d.url = f.url; d.host = f.host; d.headers = f.headers; d.body = f.bodyMode; d.length = f.length
            return d
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
                e.len = Int64(l.logBody.count)
                if engine.capture && !l.logBody.isEmpty { e.body = l.logBody }
            }
            return d
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

    /// The first event of a native request (drop / local / forward); returns its key (nil: no recorder).
    @discardableResult
    private func emitFirst(_ ev: String, _ log: RewriteLog, engine: NativeRewriteEngine, wall: Double, t0: UInt64,
                           _ fill: ((inout NativeRequestEvent) -> Void)? = nil) -> Int64? {
        guard let recorder = recorder else { return nil }
        let key = recorder.newKey()
        var e = NativeRequestEvent(k: key, ev: ev, t: wall, ms: Self.ms(since: t0), gen: engine.generation,
                                   rules: log.rules.isEmpty ? nil : log.rules, method: log.method, url: log.url, host: log.host,
                                   tls: log.tls, headers: log.headers.isEmpty ? nil : log.headers)
        fill?(&e)
        recorder.add(e)
        return key
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
        return FlowDecision(id: id, action: .error, note: "native flow has no pending decision")
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        if id >= 0 { return inner.responsePhase(id, head: head, length: length) }
        lock.lock()
        let f = flows[id]
        lock.unlock()
        if case .script(let sf)? = f { return scriptResponse(id, sf, head: head, length: length) }
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
        guard let sf = scriptFlow(id) else { return .stop }
        if sf.goID != 0 { return inner.write(sf.goID, which, data) }
        guard which == .response, let r = sf.response else { return .stop }
        return r.write(data)
    }

    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {
        if id >= 0 { inner.closeBody(id, which, error: error); return }
        guard let sf = scriptFlow(id) else { return }
        if sf.goID != 0 { inner.closeBody(sf.goID, which, error: error); return }
        if !error.isEmpty { sf.closedWithError = true }
    }

    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        if id >= 0 { return inner.read(id, which, max: max) }
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
        if let sf = scriptFlow(id) {
            if sf.goID != 0 { return inner.readState(sf.goID, which) }
            return which == .response ? .eof : .failed("err: no body to read")
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
        emit(id, last: true) { c in NativeRequestEvent(k: c.key, ev: "upstream", ms: Self.ms(since: c.start), why: why) }
    }

    func end(_ id: Int64, sent: Int64, error: String) {
        if id >= 0 { return inner.end(id, sent: sent, error: error) }
        lock.lock(); let f = flows.removeValue(forKey: id); lock.unlock()
        if case .script(let sf)? = f {
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
        emit(id, last: true) { c in
            NativeRequestEvent(k: c.key, ev: "end", ms: Self.ms(since: c.start), sent: c.upstreamMode && sent > 0 ? sent : nil,
                               resp: c.responded ? true : nil, why: error.isEmpty ? nil : error)
        }
    }

    func cancel(_ id: Int64, why: String) {
        if id >= 0 { return inner.cancel(id, why: why) }
        lock.lock(); let f = flows.removeValue(forKey: id); lock.unlock()
        if case .script(let sf)? = f {
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
        let d = inner.requestPhase(head: sf.head, conn: sf.conn)
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
}
