// Native MitM final integration — http-request scripts in Swift (switch `nativeMitmScript`, default OFF).
//
// The rewrite engine stops at a request-phase script it has no outcome for (NativeRewriteEngine.decide with a
// RequestScriptState → RequestScriptPause). This runs that script the way the old core's requestPhase does (handler.go):
//
//   1. the script slot (NativeScriptReserve: the same slots / large-bundle lock / queue; a refusal is a skip with
//      reserveFailed's note and log line);
//   2. requires-body: loadBody(scriptBodyLimit) — cached once loaded; admission (memory gates, reqCap, the body
//      budget) by the old core (MitmScriptReqBodyAdmit) and the body pushed by the session into Swift (need-body .request);
//      a refused body is the 「跳过脚本：」 skip with the old core's own words (MitmScriptReqBodySkip);
//   3. Match, prepare (the program in JavaScriptCore), the run (NativeScriptRun, $done parsed with
//      requestPhase = true: abort / local answer / url / method / headers / body);
//   4. the outcome for the engine (applied where the old core applies it) and the same outcome for the old core (FlowScripted): if
//      the request has to go to the old core after all (a later rule only the old core handles, a chunked body, a response the native
//      flow hands back), MitmFlowBegin gets every outcome so far and requestPhase applies them instead of running
//      the scripts again.
//
// Every log line and request-log note is written by the old core's code; the body never enters the old core.

import Foundation

final class NativeRequestScripts {
    enum Step {
        case next              // an outcome was recorded: decide again
        case needBody          // the session must push the request body (the slot is held)
        case handOver(String)  // the old core takes the request with the outcomes so far
    }

    let gen: Int64
    private let hostAPI: ScriptHostAPI
    private let js: NativeJSEngine
    private let store: JSCNativeBlobProvider?
    private let nativeBase: Int64

    private(set) var state = RequestScriptState()
    /// FlowScripted objects for the old core (FlowHead.Scripted), in run order.
    private(set) var scripted: [[String: Any]] = []
    /// Request-log notes in order (skipped / failed scripts).
    private(set) var notes: [String] = []
    /// A local answer's invalid status to warn about once the answer is native (rule, status).
    private(set) var mockWarn: (rule: Int, status: Int)?

    private var token: Int64 = 0
    // loadBody's state (requestPhase)
    private var bodyLoaded = false
    private var bodyOK = false
    private(set) var body: Data?        // the loaded body (bodyOK, bytes in Swift)
    private var reqSkip = ""
    private var ticket: Int64 = 0
    // a load waiting for the session's push
    private var pending: (pause: RequestScriptPause, slot: Int64, limit: Int64)?
    private var bodyIn = Data()
    private var bodyCap: Int64 = 0
    private(set) var pushFailed = false
    private var finished = false

    init(gen: Int64, hostAPI: ScriptHostAPI, js: NativeJSEngine, store: JSCNativeBlobProvider?, nativeBase: Int64) {
        self.gen = gen
        self.hostAPI = hostAPI
        self.js = js
        self.store = store
        self.nativeBase = nativeBase
    }

    var isEmpty: Bool { scripted.isEmpty }
    /// The client's request body as the session pushed it to Swift (nil: still with the session).
    private(set) var clientBytes: Data?

    // MARK: one script

    func step(_ p: RequestScriptPause) -> Step {
        if token == 0 { token = hostAPI.token() }
        let ans = hostAPI.reserve(gen: gen, rule: p.rule, token: token)
        guard let slot = ans.slot, slot > 0 else {
            if ans.gone == true { return .handOver("script rule gone") }
            record(p.rule, load: false, skip: ans.note ?? "", engine: RequestScriptOutcome(kind: .skipped))
            return .next
        }
        if p.requiresBody {
            let limit = hostAPI.reqLimit(gen: gen, rule: p.rule)
            if limit < 0 { hostAPI.release(slot: slot, ran: false); return .handOver("script rule gone") }
            if bodyLoaded {
                if bodyOK && Int64(body?.count ?? 0) <= limit { return run(p, slot: slot) }
                return skipBody(p, slot: slot, limit: limit)
            }
            if p.contentLength < 0 {
                hostAPI.release(slot: slot, ran: false)
                return .handOver("chunked request body")
            }
            let a = hostAPI.reqBodyAdmit(gen: gen, rule: p.rule, url: p.url, contentLength: p.contentLength, token: token)
            if a.gone == true { hostAPI.release(slot: slot, ran: false); return .handOver("script rule gone") }
            bodyLoaded = true
            guard a.ok == true else {
                if a.retry == true { bodyLoaded = false } // a later script with a larger limit may read it
                reqSkip = a.skip ?? ""
                return skipBody(p, slot: slot, limit: limit)
            }
            ticket = a.ticket ?? 0
            if p.contentLength == 0 {
                bodyOK = true // http.NoBody
                body = Data()
                state.bodyLoaded = true
                return run(p, slot: slot)
            }
            bodyCap = a.cap ?? p.contentLength
            pending = (p, slot, limit)
            bodyIn = Data()
            return .needBody
        }
        return run(p, slot: slot)
    }

    /// The session's push of the request body (need-body).
    func write(_ data: Data) -> FlowWriteResult {
        guard pending != nil, !finished else { return .stop }
        if Int64(bodyIn.count + data.count) > bodyCap + 1 { return .stop }
        bodyIn.append(data)
        return .taken
    }

    /// The push ended with an error (client gone / truncated).
    func pushError() { pushFailed = true }

    /// After the push (FlowAwait): readCapped, then the script.
    func bodyArrived() -> Step {
        guard let pd = pending else { return .handOver("no pending load") }
        pending = nil
        let p = pd.pause
        clientBytes = bodyIn
        state.bodyLoaded = true
        if pushFailed || Int64(bodyIn.count) > bodyCap {
            // readCapped failed: the old core would forward what it has plus the rest — let the old core take it with the bytes
            hostAPI.release(slot: pd.slot, ran: false)
            bodyLoaded = false
            return .handOver("request body read failed")
        }
        body = bodyIn
        bodyOK = true
        if Int64(bodyIn.count) > pd.limit {
            reqSkip = "请求体 \(bodyIn.count >> 10) KB 超过上限 \(pd.limit >> 10) KB"
            return skipBody(p, slot: pd.slot, limit: pd.limit)
        }
        return run(p, slot: pd.slot)
    }

    private func skipBody(_ p: RequestScriptPause, slot: Int64, limit: Int64) -> Step {
        hostAPI.release(slot: slot, ran: false)
        let blen: Int64 = bodyLoaded && bodyOK ? Int64(body?.count ?? 0) : -1
        let note = hostAPI.reqBodySkip(gen: gen, rule: p.rule, why: reqSkip, blen: blen)
        record(p.rule, load: true, skip: note, engine: RequestScriptOutcome(kind: .skipped))
        return .next
    }

    /// Match, prepare, run, parse $done (slot held).
    private func run(_ p: RequestScriptPause, slot: Int64) -> Step {
        let pr = hostAPI.prepare(gen: gen, rule: p.rule, slot: slot, reload: false)
        guard pr.ok, let key = pr.key else {
            hostAPI.release(slot: slot, ran: true)
            let f = hostAPI.fail(gen: gen, rule: p.rule, mode: "msg", detail: pr.err ?? "脚本运行时内部错误", stop: 0, timeoutMs: 0, afterDone: false)
            record(p.rule, load: p.requiresBody, fail: f.note ?? "", engine: RequestScriptOutcome(kind: .failed))
            return .next
        }
        let run = NativeScriptRun(gen: gen, rule: p.rule, hostAPI: hostAPI, js: js, lane: store, nativeBase: nativeBase, laneOK: false)
        run.requestPhase = true
        let setup = setupJSON(base: pr.setupJSON, run: run, p: p)
        let outcome = run.run(key: key, setup: setup, timeoutMs: pr.timeoutMs ?? 10_000) { [hostAPI, gen] in
            let p2 = hostAPI.prepare(gen: gen, rule: p.rule, slot: slot, reload: true)
            return p2.ok ? p2.key : nil
        }
        hostAPI.release(slot: slot, ran: true)
        run.releaseNatives(keep: 0)
        switch outcome {
        case .failed(let note):
            record(p.rule, load: p.requiresBody, fail: note, engine: RequestScriptOutcome(kind: .failed))
        case .ok(let res):
            var o = RequestScriptOutcome(kind: .ran)
            var js: [String: Any] = ["rule": p.rule]
            if p.requiresBody { js["load"] = true }
            if res.abort {
                o.abort = true
                o.abortWhy = "脚本中止：" + (pr.name ?? "")
                js["abort"] = true
            } else if let m = res.mock {
                o.mock = m
                var mj: [String: Any] = ["status": m.status]
                if let h = m.headers { mj["headers"] = h }
                if !m.body.isEmpty { mj["body"] = m.body.base64EncodedString() }
                js["mock"] = mj
                if m.status != 0 && !(200...999).contains(m.status) { mockWarn = (p.rule, m.status) } else { mockWarn = nil }
            } else {
                if let u = res.url { o.url = u; js["url"] = u }
                if let m = res.method { o.method = m; js["method"] = m }
                if let h = res.headerPairs { o.headers = h; js["headers"] = h }
                if res.bodySet {
                    o.bodySet = true
                    o.body = res.body ?? Data()
                    js["bodySet"] = true
                    if !o.body.isEmpty { js["body"] = o.body.base64EncodedString() }
                    // setBody: the body is now these bytes (loadBody answers from them)
                    bodyLoaded = true
                    bodyOK = true
                    body = o.body
                }
            }
            state.outcomes[p.rule] = o
            scripted.append(js)
        }
        return .next
    }

    private func record(_ rule: Int, load: Bool, skip: String = "", fail: String = "", engine o: RequestScriptOutcome) {
        var js: [String: Any] = ["rule": rule]
        if load { js["load"] = true }
        if !skip.isEmpty { js["skip"] = skip }
        if !fail.isEmpty { js["fail"] = fail }
        let note = skip.isEmpty ? fail : skip
        if !note.isEmpty { notes.append(note) }
        state.outcomes[rule] = o
        scripted.append(js)
    }

    /// setupJSON(req, nil): the old core's base + phase "request" + $request (Host added to the headers, the body blob).
    private func setupJSON(base: String, run: NativeScriptRun, p: RequestScriptPause) -> String {
        var obj = ((try? JSONSerialization.jsonObject(with: Data(base.utf8))) as? [String: Any]) ?? [:]
        obj["phase"] = "request"
        var rh = p.header
        if !p.host.isEmpty && rh.get("Host").isEmpty { rh.set("Host", p.host) }
        let id = String(UInt64(max(0, Date().timeIntervalSince1970 * 1e9)), radix: 36)
        var req: [String: Any] = ["url": p.url, "method": p.method, "id": id, "headers": NativeScriptResponse.headerPairs(rh), "body": -1]
        if p.requiresBody { req["body"] = run.addBody(body ?? Data(), native: 0) }
        obj["req"] = req
        guard let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) else { return base }
        return s
    }

    /// the old core's request phase ended (native decision or hand-over): the body share and the token go.
    func end() {
        if finished { return }
        finished = true
        if let pd = pending {
            pending = nil
            hostAPI.release(slot: pd.slot, ran: false)
        }
        if ticket > 0 { hostAPI.bodyRelease(ticket: ticket); ticket = 0 }
        if token != 0 { hostAPI.cancel(token); token = 0 }
    }

    /// FlowHead.Scripted as JSON-ready objects.
    var scriptedForGo: [[String: Any]] { scripted }
}
