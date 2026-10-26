// Native MitM stage 3, lane s3-script — the response phase of a natively forwarded request whose response rules
// include http-response scripts, in Swift.
//
// It reproduces what the Go flow API answers for the same request (flow_request.go runResponse around handler.go
// modifyResponse with the native body lane): header rules and scripts in rule order; the body loaded once, at the
// first script that needs it, through the same admission (Go: slots, budgets, locks, memory gates) into
// NativeBodyStore (decoded there, Go's lane rules); every skip / error path with Go's own messages; $done applied
// exactly as modifyResponse applies it (status validity, header replacement, Set-Cookie, body from the store or
// bytes, Content-Length / Content-Encoding / Transfer-Encoding); the final decision shaped like runResponse's
// (respond: none / upstream / read / lane, upgrade, error for an abort).
//
// The body never enters Go: the session pushes it here (need-body), it is decoded into the store, JavaScriptCore
// reads it from there, a large result stays there, and the session streams the answer from there (lane mode).
//
// Hand-back: before anything ran, a response this does not support goes to the Go flow (NativeRewriteDriver re-runs
// the request phase in Go, then FlowResponse) — so every unsupported shape answers exactly as before:
//   - the store, JavaScriptCore (with its execution time limit) or the Go engine is not available;
//   - a script needs the body and the upstream body is chunked / close-delimited (its size is unknown: Go streams
//     an oversized one through, which needs the Go pipe), or its Content-Encoding is not one the store decodes;
//   - a non-body script precedes a body script, or a header rule touching Content-Encoding precedes one (Go reads
//     the encoding when it loads the body);
//   - the store refuses to open the body (memory floor).

import Foundation

/// What the response phase needs from NativeBodyStore (a protocol for the unit tests).
protocol ScriptBodyStore: JSCNativeBlobProvider {
    func open(_ enc: String?, limit: Int64, hint: Int64) -> Int64
    /// NativeCore: open with a streaming charge (every appended raw / decoded byte is charged; nil = none).
    func open(_ enc: String?, limit: Int64, hint: Int64, charge: NativeBodyCharge?) -> Int64
    func write(_ h: Int64, b data: Data?) -> String
    func finish(_ h: Int64) -> Int64
    func err(_ h: Int64) -> String
    func len(_ h: Int64, raw: Bool) -> Int64
    func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data?
}

extension NativeBodyStore: ScriptBodyStore {}

/// One response-phase rule of a native script flow (Go's f.rules entry).
struct ScriptPlanStep {
    enum Kind {
        case header([RWSnapHeaderOp])
        case script(requiresBody: Bool)
    }
    var rule: Int
    var kind: Kind
}

/// The request as the response scripts see it ($request: Go's resp.Request = the outbound request).
struct ScriptRequestView {
    var url: String          // f.url
    var method: String
    var header: CanonicalHeader     // out.Header (Content-Length kept, Accept-Encoding as sent)
    var host: String         // out.Host
}

/// The answer to the session (FlowDecision fields) plus what the request log needs.
struct ScriptResponseOutput {
    var action: FlowDecision.Action
    var status: Int = 502
    var headers: [[String]] = []
    var bodyMode: FlowBodyMode = .none
    var length: Int64 = 0
    var lane: FlowDecision.Lane?
    var note: String?
    /// Bytes to serve in read mode.
    var body = Data()
    // request log
    var rules: [Int] = []
    var notes: [String] = []
    var logHeaders: [[String]] = []
    /// abort / lost result: the 「上游错误：」 reason (shortErr(err) is applied by Go).
    var abortWhy: String?
}

final class NativeScriptResponse {
    enum HeadOutcome {
        case handBack(String)
        case needBody
        case done(ScriptResponseOutput)
    }

    let gen: Int64
    private let steps: [ScriptPlanStep]
    private let req: ScriptRequestView
    private let hostAPI: ScriptHostAPI
    private let js: NativeJSEngine
    private let store: ScriptBodyStore
    private let nativeBase: Int64

    // modifyResponse's state
    private var status = 0
    private var header = CanonicalHeader()
    private var contentLength: Int64 = -1   // resp.ContentLength
    private var upstreamLength: Int64 = -1  // the head's length (framing)
    private var mrNoBody = false            // HEAD / 204 / 304
    private var loaded = false
    private var tooBig = false
    private var respSkip = ""
    private var nativeH: Int64 = 0          // the store handle holding the current body
    private var nativeLen: Int64 = 0
    private var goBody: Data?               // `body` when it is bytes (a set body)
    private var bodySet = false             // resp.Body replaced by bytes (setBody ran with a body)
    private var rawPass = false             // resp.Body is the raw bytes as received (a skipped load)
    private var rawTail = Data()            // received bytes the store did not take (after its failure)
    private var loadH: Int64 = 0            // the load's handle (raw bytes for a pass-through)
    private var owned: Set<Int64> = []      // store handles to free at the end
    private var rules: [Int] = []
    private var notes: [String] = []
    private var sideEffects = false         // a script ran (no hand-back from here on)

    // the load in progress (need-body)
    private var pos = 0                     // next step to run
    private var pendingSlot: Int64 = 0
    private var pendingLimit: Int64 = 0
    private var ticket: Int64 = 0
    private var cap: Int64 = 0
    private var rawCount: Int64 = 0
    private var loadFailure: (kind: String, detail: String)?
    private var token: Int64 = 0
    private var finished = false
    private var loadPending = false         // .needBody answered, the push / await not done yet (slot held)

    init(gen: Int64, steps: [ScriptPlanStep], request: ScriptRequestView, hostAPI: ScriptHostAPI, js: NativeJSEngine,
         store: ScriptBodyStore, nativeBase: Int64) {
        self.gen = gen
        self.steps = steps
        self.req = request
        self.hostAPI = hostAPI
        self.js = js
        self.store = store
        self.nativeBase = nativeBase
    }

    /// laneEncodingOK.
    static func encodingOK(_ enc: String) -> Bool {
        switch RWAscii.lower(enc.trimmingCharacters(in: .whitespaces)) {
        case "", "identity", "gzip", "x-gzip", "deflate", "br": return true
        default: return false
        }
    }

    /// Static checks on the plan (see the file comment); nil = supported.
    static func unsupported(_ steps: [ScriptPlanStep]) -> String? { unsupported(steps, nativeOnly: false) }

    /// nativeOnly: there is no other engine to hand back to (a hand-back relays the response with NO script run), so the
    /// "non-body script before a body script" shape runs natively: walk() already runs the steps in rule order,
    /// a plain script's $done headers / body feed the later load exactly like modifyResponse (setBody → loaded,
    /// Content-Encoding read at load time), and after a script ran a refused / over-limit load takes the
    /// skip path instead of a hand-back.
    static func unsupported(_ steps: [ScriptPlanStep], nativeOnly: Bool) -> String? {
        var lastBody = -1
        var firstPlain = Int.max
        for (i, s) in steps.enumerated() {
            if case .script(let rb) = s.kind {
                if rb { lastBody = i } else { firstPlain = min(firstPlain, i) }
            }
        }
        if !nativeOnly && lastBody >= 0 && firstPlain < lastBody { return "script before body script" }
        for (i, s) in steps.enumerated() where i < lastBody {
            if case .header(let ops) = s.kind, ops.contains(where: { RWAscii.equalFold($0.name ?? "", "Content-Encoding") || $0.op == "raw" }) {
                return "content-encoding rule"
            }
        }
        return nil
    }

    private var needsBody: Bool {
        steps.contains { if case .script(true) = $0.kind { return true }; return false }
    }

    // MARK: head

    /// FlowResponse for the upstream's head: runs the rules up to the first body load (then .needBody), or to the end.
    func head(status st: Int, headers: [[String]], length: Int64) -> HeadOutcome {
        var h = CanonicalHeader(pairs: headers)
        var cl = length
        if !h.values("Transfer-Encoding").isEmpty {
            h.del("Transfer-Encoding")
            cl = -1
        } else {
            let v = h.get("Content-Length")
            if !v.isEmpty, let n = Int64(RWAscii.trimSpace(v)), n >= 0 { cl = n }
        }
        status = st
        contentLength = cl
        upstreamLength = cl
        mrNoBody = req.method == "HEAD" || st == 204 || st == 304
        let flowNoBody = mrNoBody || (100..<200).contains(st)
        if st == 101 {
            // modifyResponse returns at once: no rule runs
            return .done(ScriptResponseOutput(action: .upgrade, status: 101, headers: h.sortedPairs, bodyMode: .upstream, length: -1,
                                              logHeaders: h.sortedPairs))
        }
        h.removeHopByHop()
        header = h
        if let why = Self.unsupported(steps, nativeOnly: true) { return .handBack(why) }
        if needsBody {
            if !(flowNoBody || cl == 0) && cl < 0 { return .handBack("body length unknown") }
            if !Self.encodingOK(header.get("Content-Encoding")) { return .handBack("content-encoding") }
        }
        token = hostAPI.token()
        return walk()
    }

    /// Runs steps from `pos` until a body is needed (→ .needBody) or the end (→ .done). Head time and after a load.
    private func walk() -> HeadOutcome {
        while pos < steps.count {
            let step = steps[pos]
            switch step.kind {
            case .header(let ops):
                rules.append(step.rule)
                _ = NativeRewriteEngine.apply(ops, to: &header, firstLine: "HTTP/1.1 " + NetStatus.status(status)) // add / del / replace only (regex ops → Go at decide)
                pos += 1
            case .script(let requiresBody):
                let ans = hostAPI.reserve(gen: gen, rule: step.rule, token: token)
                guard let slot = ans.slot, slot > 0 else {
                    if let n = ans.note, !n.isEmpty { notes.append(n) }
                    pos += 1
                    continue
                }
                if requiresBody {
                    switch loadBody(step.rule, slot: slot) {
                    case .ready(let limit):
                        if let o = runBodyScript(step.rule, slot: slot, limit: limit) { return .done(o) }
                    case .skipped:
                        break
                    case .needBody:
                        return .needBody
                    case .handBack(let why):
                        hostAPI.release(slot: slot, ran: false)
                        return .handBack(why)
                    }
                } else {
                    if let o = runScript(step.rule, slot: slot, body: false) { return .done(o) }
                }
                pos += 1
            }
        }
        return .done(finish())
    }

    private enum Load { case ready(Int64), skipped, needBody, handBack(String) }

    private var blen: Int64 { nativeH > 0 ? nativeLen : Int64(goBody?.count ?? 0) }

    /// modifyResponse's `loadBody(limit)` for the script at rule, holding slot. .ready: run it; .skipped: logged,
    /// slot released; .needBody: wait for the session's push.
    private func loadBody(_ rule: Int, slot: Int64) -> Load {
        if loaded {
            if tooBig {
                hostAPI.release(slot: slot, ran: false)
                notes.append(hostAPI.skip(gen: gen, rule: rule, why: respSkip))
                return .skipped
            }
            let check = hostAPI.bodyCheck(gen: gen, rule: rule, blen: blen, limit: -1)
            if (check.note ?? "").isEmpty { return .ready(check.limit) }
            hostAPI.release(slot: slot, ran: false)
            notes.append(check.note ?? "")
            return .skipped
        }
        let enc = header.get("Content-Encoding")
        let a = hostAPI.bodyAdmit(gen: gen, rule: rule, respRules: steps.map { $0.rule }, url: req.url, contentLength: contentLength, enc: enc, token: token)
        if a.ok != true {
            loaded = a.retry != true
            tooBig = true
            respSkip = a.skip ?? ""
            hostAPI.release(slot: slot, ran: false)
            notes.append(hostAPI.skip(gen: gen, rule: rule, why: respSkip))
            return .skipped
        }
        let t = a.ticket ?? 0
        let h = store.open(enc, limit: a.cap ?? 0, hint: contentLength, charge: hostAPI.bodyCharge(ticket: t))
        if h <= 0 {
            hostAPI.bodyRelease(ticket: t)
            if !sideEffects { return .handBack("store refused") }
            // after a script ran Go can no longer take over: Go's lane failure path (counted)
            loaded = true
            tooBig = true
            respSkip = hostAPI.bodyFailed(ticket: 0, url: req.url, kind: "lane", raw: 0, detail: "open refused")
            hostAPI.release(slot: slot, ran: false)
            notes.append(hostAPI.skip(gen: gen, rule: rule, why: respSkip))
            return .skipped
        }
        owned.insert(h)
        loadH = h
        ticket = t
        cap = a.cap ?? 0
        pendingSlot = slot
        pendingLimit = a.limit ?? 0
        rawCount = 0
        loadFailure = nil
        let flowNoBody = mrNoBody || (100..<200).contains(status)
        if flowNoBody || contentLength == 0 {
            return completeLoad(rule) // http.NoBody: nothing to push
        }
        loadPending = true
        return .needBody
    }

    // MARK: body push (session → store)

    func write(_ data: Data) -> FlowWriteResult {
        guard loadH > 0, !finished else { return .stop }
        if loadFailure != nil {
            rawTail.append(data)
            return .taken
        }
        rawCount += Int64(data.count)
        if rawCount > cap {
            // laneLoad: the received bytes themselves are capped at limit
            loadFailure = ("too-big", "")
            rawTail.append(data)
            return .taken
        }
        let msg = store.write(loadH, b: data)
        if !msg.isEmpty {
            rawTail.append(data)
            if msg == "too-big" {
                loadFailure = ("too-big", "")
            } else if msg.hasPrefix("decode:") {
                // loadBodyLane: strings.TrimPrefix(err, "decode: ")
                loadFailure = ("decode", msg.hasPrefix("decode: ") ? String(msg.dropFirst(8)) : msg)
            } else {
                loadFailure = ("lane", "write: " + msg)
            }
        }
        return .taken
    }

    /// After the push (FlowAwait): finish the load, then run the rest.
    func awaitAfterBody() -> HeadOutcome {
        guard loadPending, loadH > 0, pos < steps.count else { return .done(errorOutput("native script flow has no load")) }
        loadPending = false
        let rule = steps[pos].rule
        switch completeLoad(rule) {
        case .ready(let limit):
            if let o = runBodyScript(rule, slot: pendingSlot, limit: limit) { return .done(o) }
        case .skipped, .needBody:
            break
        case .handBack(let why):
            return .handBack(why)
        }
        pos += 1
        return walk()
    }

    /// The end of loadBodyLane + loadBody for the body now in the store.
    private func completeLoad(_ rule: Int) -> Load {
        let slot = pendingSlot
        let limit = pendingLimit
        loaded = true
        tooBig = true
        var failure = loadFailure
        var decoded: Int64 = 0
        if failure == nil {
            decoded = store.finish(loadH)
            switch decoded {
            case ..<(-2): failure = ("lane", "finish: " + store.err(loadH))
            case -2: failure = ("too-big", "")
            case -1: failure = ("decode", store.err(loadH))
            default: break
            }
        }
        if let f = failure {
            respSkip = hostAPI.bodyFailed(ticket: ticket, url: req.url, kind: f.kind, raw: rawCount, detail: f.detail)
            rawPass = true
        } else {
            let skip = hostAPI.bodyLoaded(ticket: ticket, url: req.url, decoded: decoded)
            if !skip.isEmpty {
                respSkip = skip
                rawPass = true
            } else {
                nativeH = loadH
                nativeLen = decoded
                tooBig = false
                header.del("Content-Encoding")
            }
        }
        if tooBig {
            hostAPI.release(slot: slot, ran: false)
            notes.append(hostAPI.skip(gen: gen, rule: rule, why: respSkip))
            return .skipped
        }
        if nativeLen > limit {
            hostAPI.release(slot: slot, ran: false)
            let check = hostAPI.bodyCheck(gen: gen, rule: rule, blen: nativeLen, limit: limit)
            if let n = check.note, !n.isEmpty { notes.append(n) }
            return .skipped
        }
        return .ready(limit)
    }

    // MARK: scripts

    private func runBodyScript(_ rule: Int, slot: Int64, limit: Int64) -> ScriptResponseOutput? {
        runScript(rule, slot: slot, body: true)
    }

    /// One script, slot held: Match, run, apply $done (modifyResponse's script case). Non-nil: the response ends
    /// here (an abort / a lost result).
    private func runScript(_ rule: Int, slot: Int64, body: Bool) -> ScriptResponseOutput? {
        let p = hostAPI.prepare(gen: gen, rule: rule, slot: slot, reload: false)
        rules.append(rule) // ent.Match before RunReserved
        guard p.ok, let key = p.key else {
            hostAPI.release(slot: slot, ran: true)
            let f = hostAPI.fail(gen: gen, rule: rule, mode: "msg", detail: p.err ?? "脚本运行时内部错误", stop: 0, timeoutMs: 0, afterDone: false)
            if let n = f.note, !n.isEmpty { notes.append(n) }
            return nil
        }
        sideEffects = true
        let laneOK = body && nativeH > 0
        let run = NativeScriptRun(gen: gen, rule: rule, hostAPI: hostAPI, js: js, lane: store, nativeBase: nativeBase, laneOK: laneOK)
        let setup = setupJSON(base: p.setupJSON, run: run, body: body)
        let outcome = run.run(key: key, setup: setup, timeoutMs: p.timeoutMs ?? 10_000) { [hostAPI, gen] in
            let p2 = hostAPI.prepare(gen: gen, rule: rule, slot: slot, reload: true)
            return p2.ok ? p2.key : nil
        }
        hostAPI.release(slot: slot, ran: true)
        switch outcome {
        case .failed(let note):
            run.releaseNatives(keep: 0)
            if !note.isEmpty { notes.append(note) }
            return nil
        case .ok(let res):
            run.releaseNatives(keep: res.nativeBody)
            return apply(res, rule: rule, prepared: p)
        }
    }

    /// setupJSON for the response phase: Go's base + phase, $request (the outbound request, Host added), $response.
    private func setupJSON(base: String, run: NativeScriptRun, body: Bool) -> String {
        var obj = ((try? JSONSerialization.jsonObject(with: Data(base.utf8))) as? [String: Any]) ?? [:]
        obj["phase"] = "response"
        var rh = req.header
        if !req.host.isEmpty && rh.get("Host").isEmpty { rh.set("Host", req.host) }
        let id = String(UInt64(max(0, Date().timeIntervalSince1970 * 1e9)), radix: 36)
        obj["req"] = ["url": req.url, "method": req.method, "id": id, "headers": Self.headerPairs(rh), "body": -1] as [String: Any]
        let sc = header.values("Set-Cookie")
        if sc.count > 1 { run.origSetCookie = sc }
        var resp: [String: Any] = ["headers": Self.headerPairs(header), "body": -1]
        if status != 0 { resp["status"] = status }
        if body {
            resp["body"] = nativeH > 0 ? run.addBody(nil, native: nativeH) : run.addBody(goBody ?? Data(), native: 0)
        }
        obj["resp"] = resp
        guard let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) else { return base }
        return s
    }

    /// headerPairs: names sorted, several values joined with ", ".
    static func headerPairs(_ h: CanonicalHeader) -> [[String]] {
        h.map.keys.sorted(by: RWAscii.less).map { [$0, (h.map[$0] ?? []).joined(separator: ", ")] }
    }

    /// modifyResponse after RunReserved returned res.
    private func apply(_ res: NativeScriptResult, rule: Int, prepared p: ScriptPrepared) -> ScriptResponseOutput? {
        let name = p.name ?? ""
        if res.abort {
            if res.nativeBody > 0 { store.free(res.nativeBody) }
            notes.append("脚本中止：" + name)
            return abortOutput("脚本 \(name) 中止了响应")
        }
        if res.status > 0 && !(res.status >= 200 && res.status <= 999) {
            _ = hostAPI.host(gen: gen, rule: rule, op: "log", arg: "warn\n脚本返回的状态码 \(res.status) 无效，已忽略")
        } else if res.status > 0 {
            status = res.status
        }
        if let h = res.headers {
            header = h
            if !mrNoBody { header.del("Content-Length") }
            if loaded && !tooBig { header.del("Content-Encoding") }
        }
        if res.bodySet && res.nativeBody > 0 {
            owned.insert(res.nativeBody)
            if nativeH > 0 && nativeH != res.nativeBody { freeOwned(nativeH) }
            nativeH = res.nativeBody
            goBody = nil
            nativeLen = store.len(res.nativeBody, raw: false)
            loaded = true
            tooBig = false
            if nativeLen < 0 {
                return abortOutput("脚本 \(name) 的结果丢失")
            }
        } else if res.bodySet {
            if nativeH > 0 { freeOwned(nativeH); nativeH = 0; nativeLen = 0 }
            setBody(res.body ?? Data())
        } else if loaded && !tooBig && nativeH == 0 {
            setBody(goBody ?? Data())
        }
        return nil
    }

    /// modifyResponse's setBody.
    private func setBody(_ b: Data) {
        goBody = b
        loaded = true
        if mrNoBody { return }
        bodySet = true
        rawPass = false
        contentLength = Int64(b.count)
        header.set("Content-Length", String(b.count))
        header.del("Content-Encoding")
        header.del("Transfer-Encoding")
    }

    private func freeOwned(_ h: Int64) {
        if owned.remove(h) != nil { store.free(h) }
    }

    // MARK: the decision

    /// The end of modifyResponse + runResponse's decision.
    private func finish() -> ScriptResponseOutput {
        releaseTicket()
        let flowNoBody = mrNoBody || (100..<200).contains(status)
        var out = ScriptResponseOutput(action: .respond, status: status)
        var h = header
        var mode = FlowBodyMode.read
        var laneOut: FlowDecision.Lane?
        var serve = Data()
        var laneLen: Int64 = -1
        if nativeH > 0 {
            if !mrNoBody {
                contentLength = nativeLen
                h.set("Content-Length", String(nativeLen))
                h.del("Content-Encoding")
                h.del("Transfer-Encoding")
                laneOut = FlowDecision.Lane(handle: nativeH, raw: false)
                laneLen = nativeLen
                mode = .lane
            } else {
                freeOwned(nativeH)
                nativeH = 0
            }
        } else {
            if loaded && !tooBig {
                setBody(goBody ?? Data())
                h = header
            }
            if bodySet {
                serve = goBody ?? Data()
            } else if rawPass && loadH > 0 {
                // the raw bytes as received: the store's raw part, then what it did not take
                let rawLen = store.len(loadH, raw: true)
                if rawTail.isEmpty && rawLen >= 0 {
                    laneOut = FlowDecision.Lane(handle: loadH, raw: true)
                    laneLen = rawLen
                    mode = .lane
                } else {
                    serve = (rawLen > 0 ? store.read(loadH, raw: true, off: 0, n: rawLen) ?? Data() : Data()) + rawTail
                }
            } else if !(flowNoBody || upstreamLength == 0) && !loadedSomething {
                mode = .upstream
            }
        }
        out.logHeaders = h.sortedPairs // ent.Response(resp.StatusCode, resp.Header)
        var length: Int64 = -1
        let clv = h.get("Content-Length")
        if !clv.isEmpty {
            if let n = Int64(RWAscii.trimSpace(clv)), n >= 0 { length = n }
        } else if contentLength >= 0 {
            length = contentLength
        }
        if flowNoBody {
            mode = .none
            laneOut = nil
        } else {
            h.del("Content-Length")
        }
        h.del("Transfer-Encoding")
        if mode == .lane { length = laneLen }
        out.length = length
        out.bodyMode = mode
        out.lane = laneOut
        out.body = mode == .read ? serve : Data()
        out.headers = h.sortedPairs
        let ct = h.get("Content-Type")
        let media = RWAscii.lower(RWAscii.trimSpace(String(ct.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")))
        if media == "text/event-stream" { out.note = "flush" }
        out.rules = rules
        out.notes = notes
        if mode != .lane { keepOnly(nil) } else { keepOnly(laneOut?.handle) }
        return out
    }

    /// Whether the session pushed the body (the upstream reader is no longer untouched).
    private var loadedSomething: Bool { loadH > 0 }

    private func abortOutput(_ why: String) -> ScriptResponseOutput {
        releaseTicket()
        keepOnly(nil)
        var o = ScriptResponseOutput(action: .error, status: 502)
        o.note = why
        o.rules = rules
        o.notes = notes
        o.abortWhy = why
        return o
    }

    private func errorOutput(_ why: String) -> ScriptResponseOutput {
        releaseTicket()
        keepOnly(nil)
        var o = ScriptResponseOutput(action: .error, status: 502)
        o.note = why
        return o
    }

    private func releaseTicket() {
        if ticket > 0 { hostAPI.bodyRelease(ticket: ticket); ticket = 0 }
    }

    /// Frees every owned handle except keep (the one the session streams; freed by end()).
    private func keepOnly(_ keep: Int64?) {
        for h in owned where h != keep { store.free(h) }
        owned = []
        if let k = keep { owned.insert(k) }
        if !owned.contains(loadH) { loadH = 0 }
    }

    /// The flow is over (end / cancel / hand-back): free what is still held.
    func end() {
        if finished { return }
        finished = true
        releaseTicket()
        if loadPending {
            // a load that never completed (client gone mid-push): its slot is still held
            loadPending = false
            hostAPI.release(slot: pendingSlot, ran: false)
        }
        for h in owned { store.free(h) }
        owned = []
        if token != 0 { hostAPI.cancel(token); token = 0 }
    }
}
