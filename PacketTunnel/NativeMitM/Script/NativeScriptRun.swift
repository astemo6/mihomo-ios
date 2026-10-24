// Native MitM stage 3, lane s3-script — one script run driven by Swift.
//
// The Go path's runCtx + execute (bridge/mitm/script.go) ported to Swift for runs the native dispatcher makes:
// the prelude's host side (blobs, timers, $done, the "nblob" hand-over of large results), the event loop (timers,
// $httpClient / $httpAPI answers delivered through __tern_fire / __tern_deliver), the run's timeout, cancellation
// and memory guard (JavaScriptCore's execution time limit asks shouldStop every 100 ms), and $done → result. The
// JavaScript itself runs in the same JSCScriptEngine context Go would use (Go's program cache index loads it:
// ScriptGoHost.prepare), so the script sees the identical prelude and API.
//
// What still goes to Go (ScriptGoHost): $persistentStore, notifications, $httpAPI, geo, btoa / atob, console lines
// (the Go log ring), $httpClient (egress through mihomo routing), ungzip / compress, error / finish log lines.
// Bodies never do: the response body is a NativeBodyStore handle (blob id NativeBlobBase + handle) that
// JSCScriptEngine reads directly, large results stay in the store.
//
// Threading: begin / every job runs on the caller's thread (the session's flow queue, which the Go flow API blocks
// the same way); timers and fetches only post jobs. Host calls come in on that thread too (inside JavaScriptCore).

import Foundation
#if !TERN_NO_GO
import Libmihomo
#endif

/// The JavaScript engine as a run uses it (JSCScriptEngine; a protocol for the unit tests).
protocol NativeJSEngine: AnyObject {
    func begin(run: JSCRun, key: String, setup: String) -> String
    func call(_ runID: Int64, fn: String?, arg: String?) -> String
    func end(_ runID: Int64)
}

extension JSCScriptEngine: NativeJSEngine {}

/// What `$done` asked for in the response phase (Go's ScriptResult; parseDone).
struct NativeScriptResult {
    var status = 0
    var headers: GoHeader?
    var body: Data?
    var bodySet = false
    /// With bodySet: the new body is this store handle (body nil); ownership passes to the caller.
    var nativeBody: Int64 = 0
    var abort = false
    // request phase (native-final): parseDone(requestPhase=true) — a local answer, the URL, the method, and the
    // header pairs as the script returned them (pairsHeader order)
    var mock: RequestScriptOutcome.Mock?
    var url: String?
    var method: String?
    var headerPairs: [[String]]?
}

final class NativeScriptRun: JSCRun {
    /// Native run ids are negative (Go's runCtx ids are positive; both share JSCScriptEngine's table).
    private static let idLock = NSLock()
    private static var idSeq: Int64 = 0
    private static func nextID() -> Int64 {
        idLock.lock(); defer { idLock.unlock() }
        idSeq -= 1
        return idSeq
    }

    enum Stop: Int { case none = 0, timeout = 1, memory = 2, cancelled = 3 }

    private enum Blob {
        case bytes(Data, temp: Bool)
        case native(Int64, temp: Bool)
    }

    let runID: Int64
    let gen: Int64
    let rule: Int
    private let go: ScriptGoHost
    private let js: NativeJSEngine
    private let lane: JSCNativeBlobProvider?
    private let nativeBase: Int64
    /// The run may hand large results back through the store ("nblob"): the response body is a store body.
    let laneOK: Bool
    /// native-final: an http-request script ($done parsed with requestPhase = true).
    var requestPhase = false

    // host state (hmu)
    private let hmu = NSLock()
    private var dead = false
    private var blobs: [Int64: Blob] = [:]
    private var blobSeq: Int64 = 0
    private var nativeOwned: [Int64] = []
    private var done = false
    private var doneRaw = ""
    /// The response's Set-Cookie lines when there were several (fixSetCookie).
    var origSetCookie: [String] = []

    // event loop (loop thread only, except `queue` / `stopReason`)
    private let cond = NSCondition()
    private var queue: [() -> String] = []
    private var pending = 0
    private var timers: [Int64: DispatchSourceTimer] = [:]
    private var fetches: [ObjectIdentifier: ScriptFetch] = [:]
    private let stopLock = NSLock()
    private var stopReason = Stop.none
    private var token: Int64 = 0
    private let timerQueue = DispatchQueue(label: "tern.native-script.timers", qos: .userInitiated)

    init(gen: Int64, rule: Int, go: ScriptGoHost, js: NativeJSEngine, lane: JSCNativeBlobProvider?, nativeBase: Int64, laneOK: Bool) {
        runID = Self.nextID()
        self.gen = gen
        self.rule = rule
        self.go = go
        self.js = js
        self.lane = lane
        self.nativeBase = nativeBase
        self.laneOK = laneOK && lane != nil
    }

    // MARK: blobs (callers hold hmu)

    private func addBlob(_ d: Data, temp: Bool) -> Int64 {
        blobSeq += 1
        blobs[blobSeq] = .bytes(d, temp: temp)
        return blobSeq
    }

    /// Go's useBlob: a temp Go blob goes away when read.
    private func useBlob(_ id: Int64) -> Data? {
        guard let b = blobs[id] else { return nil }
        switch b {
        case .bytes(let d, let temp):
            if temp { blobs.removeValue(forKey: id) }
            return d
        case .native(let h, _):
            return nativeBytes(h)
        }
    }

    private func nativeBytes(_ h: Int64) -> Data? {
        guard let lane else { return nil }
        var out: Data?
        _ = lane.withDecoded(h) { buf in out = Data(buf) }
        return out
    }

    /// The phase body as a blob: a store handle (laneOK) or bytes.
    func addBody(_ data: Data?, native h: Int64) -> Int64 {
        hmu.lock(); defer { hmu.unlock() }
        if h > 0 {
            let id = nativeBase + h
            blobs[id] = .native(h, temp: false)
            return id
        }
        return addBlob(data ?? Data(), temp: false)
    }

    // MARK: JSCRun

    func put(_ data: Data) -> Int64 {
        hmu.lock(); defer { hmu.unlock() }
        if dead { return -1 }
        return addBlob(data, temp: true)
    }

    func take(_ id: Int64) -> Data? {
        hmu.lock(); defer { hmu.unlock() }
        return useBlob(id)
    }

    func shouldStop() -> Bool {
        stopLock.lock(); defer { stopLock.unlock() }
        return stopReason != .none
    }

    private var stop: Stop {
        stopLock.lock(); defer { stopLock.unlock() }
        return stopReason
    }

    /// Ends the run's JavaScript as soon as the engine can (first reason wins).
    func requestStop(_ r: Stop) {
        stopLock.lock()
        if stopReason == .none { stopReason = r }
        stopLock.unlock()
        cond.lock(); cond.signal(); cond.unlock()
    }

    func host(_ op: String, _ arg: String) -> String {
        hmu.lock()
        if dead { hmu.unlock(); return "" }
        defer { hmu.unlock() }
        switch op {
        case "done":
            if !done { done = true; doneRaw = arg }
            return ""
        case "nblob":
            guard let h = Int64(arg), h > 0, laneOK else { return "" }
            let id = nativeBase + h
            blobs[id] = .native(h, temp: true)
            nativeOwned.append(h)
            return String(id)
        case "timer":
            let f = arg.split(separator: ",", omittingEmptySubsequences: false)
            if f.count == 3, let id = Int64(f[0]) {
                addTimer(id, ms: Int64(f[1]) ?? 0, repeating: f[2] == "1")
            }
            return ""
        case "clear":
            if let id = Int64(arg), let t = timers.removeValue(forKey: id) {
                t.cancel()
                pending -= 1
            }
            return ""
        case "utf8":
            return String(addBlob(Data(arg.utf8), temp: true))
        case "text":
            guard let id = Int64(arg), let d = useBlob(id) else { return "" }
            return d.withUnsafeBytes { JSCScriptEngine.goText($0) }
        case "http":
            startFetch(arg)
            return ""
        case "api":
            let out = go.api(gen: gen, rule: rule, arg: arg)
            if !out.isEmpty {
                pending += 1
                post { [weak self] in
                    guard let self else { return "" }
                    hmu.lock(); pending -= 1; hmu.unlock()
                    return js.call(runID, fn: "__tern_deliver", arg: out)
                }
            }
            return ""
        case "ungzip":
            guard let id = Int64(arg), let input = useBlob(id), let out = go.bytes(op: "ungzip", arg: "", input: input) else { return "-1" }
            return String(addBlob(out, temp: true))
        case "compress":
            let parts = arg.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2, let id = Int64(parts[1]), let input = useBlob(id),
                  let out = go.bytes(op: "compress", arg: String(parts[0]), input: input) else { return "-1" }
            return String(addBlob(out, temp: true))
        case "log", "sread", "swrite", "sclear", "notify", "geo", "btoa", "atob":
            return go.host(gen: gen, rule: rule, op: op, arg: arg)
        default:
            return ""
        }
    }

    // MARK: event loop

    private func post(_ job: @escaping () -> String) {
        cond.lock()
        queue.append(job)
        cond.signal()
        cond.unlock()
    }

    /// Go's addTimer (hmu held): one pending count per timer; a repeating timer is re-armed when its job runs
    /// (time.AfterFunc again), so at most one firing of a timer is queued at a time.
    private func addTimer(_ id: Int64, ms: Int64, repeating: Bool) {
        pending += 1
        arm(id, ms: max(ms, 0), repeating: repeating)
    }

    /// Schedules timer id's next firing (hmu held).
    private func arm(_ id: Int64, ms: Int64, repeating: Bool) {
        timers.removeValue(forKey: id)?.cancel()
        let t = DispatchSource.makeTimerSource(queue: timerQueue)
        t.schedule(deadline: .now() + .milliseconds(Int(ms)))
        t.setEventHandler { [weak self] in
            self?.post { [weak self] in
                guard let self else { return "" }
                hmu.lock()
                guard timers[id] != nil else { hmu.unlock(); return "" }
                if repeating {
                    arm(id, ms: ms, repeating: true)
                } else {
                    timers.removeValue(forKey: id)?.cancel()
                    pending -= 1
                }
                hmu.unlock()
                return js.call(runID, fn: "__tern_fire", arg: String(id))
            }
        }
        timers[id] = t
        t.resume()
    }

    private struct FetchArg: Decodable { var id: Int64; var body: Int64? }

    /// Go's startFetch: the download runs in Go (mihomo routing, the script's policy) off this thread; its answer
    /// is delivered to __tern_deliver with the body as a blob (hmu held).
    private func startFetch(_ arg: String) {
        guard let j = try? JSONDecoder().decode(FetchArg.self, from: Data(arg.utf8)) else { return }
        var body = Data()
        if let bid = j.body, bid >= 0, let b = blobs[bid] {
            switch b {
            case .bytes(let d, _):
                body = d
                blobs.removeValue(forKey: bid)
            case .native(let h, _):
                body = nativeBytes(h) ?? Data()
            }
        }
        pending += 1
        let tok = token
        let (g, r, go, reqBody) = (gen, rule, self.go, body)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = go.fetch(gen: g, rule: r, token: tok, arg: arg, body: reqBody)
            guard let self else { res.done(); return }
            self.hmu.lock()
            if self.dead { self.hmu.unlock(); res.done(); return }
            self.fetches[ObjectIdentifier(res)] = res
            self.hmu.unlock()
            self.post { [weak self] in
                guard let self else { res.done(); return "" }
                hmu.lock()
                pending -= 1
                fetches.removeValue(forKey: ObjectIdentifier(res))
                var out = res.meta
                var bid: Int64 = -1
                if var obj = (try? JSONSerialization.jsonObject(with: Data(res.meta.utf8))) as? [String: Any], obj["err"] == nil {
                    bid = addBlob(res.body, temp: false)
                    obj["body"] = bid
                    if let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) { out = s }
                }
                hmu.unlock()
                let err = js.call(runID, fn: "__tern_deliver", arg: out)
                if bid >= 0 {
                    hmu.lock(); blobs.removeValue(forKey: bid); hmu.unlock()
                }
                res.done()
                return err
            }
        }
    }

    // MARK: running

    /// The outcome of run(): the result, or the request-log note of a failure (already logged by Go).
    enum Outcome {
        case ok(NativeScriptResult)
        case failed(note: String)
    }

    /// execute + run + parseDone for the response phase. `setup` is the full __tern_begin JSON; key the program's
    /// context; timeoutMs the run's timeout. Blocks until $done, nothing pending, the timeout or a stop.
    func run(key: String, setup: String, timeoutMs: Int64, reload: () -> String?) -> Outcome {
        currentTimeout = timeoutMs
        token = go.token()
        let start = DispatchTime.now().uptimeNanoseconds
        let deadline = DispatchTime.now() + .milliseconds(Int(timeoutMs))
        // the timeout and the memory guard set the stop reason while JavaScript runs on this thread
        let guardTimer = DispatchSource.makeTimerSource(queue: timerQueue)
        guardTimer.schedule(deadline: .now() + .milliseconds(50), repeating: .milliseconds(50))
        let go = self.go
        guardTimer.setEventHandler { [weak self] in
            guard let self else { return }
            if DispatchTime.now() >= deadline { self.requestStop(.timeout); return }
            if go.memLow() { self.requestStop(.memory) }
        }
        guardTimer.resume()
        defer {
            guardTimer.cancel()
            finishRun()
        }

        var r = js.begin(run: self, key: key, setup: setup)
        if r == "missing", let k2 = reload() {
            r = js.begin(run: self, key: k2, setup: setup)
        }
        if r == "missing" {
            return .failed(note: fail("js", "missing")) // parseNativeErr: 「脚本引擎错误：missing」
        }
        if !r.isEmpty, !afterDone(r) {
            return .failed(note: fail("js", r))
        }
        while !isDone {
            cond.lock()
            if queue.isEmpty {
                if pendingNow <= 0 { cond.unlock(); break } // nothing left to wait for and $done never called
                if stop == .cancelled { cond.unlock(); return .failed(note: fail("cancel", "")) }
                if DispatchTime.now() >= deadline || stop == .timeout { cond.unlock(); return .failed(note: fail("timeout", "")) }
                _ = cond.wait(until: Date().addingTimeInterval(min(0.05, max(0.001, Double(deadline.uptimeNanoseconds &- DispatchTime.now().uptimeNanoseconds) / 1e9))))
                cond.unlock()
                continue
            }
            let job = queue.removeFirst()
            cond.unlock()
            let e = job()
            if !e.isEmpty, !afterDone(e) {
                return .failed(note: fail("js", e))
            }
        }
        var res = NativeScriptResult()
        if isDone {
            guard let d = readDone() else { return .failed(note: lastFailNote) }
            res = parseDone(d)
        }
        let ms = (DispatchTime.now().uptimeNanoseconds &- start) / 1_000_000
        _ = go.host(gen: gen, rule: rule, op: "x-finished", arg: String(ms))
        return .ok(res)
    }

    private var isDone: Bool { hmu.lock(); defer { hmu.unlock() }; return done }
    private var pendingNow: Int { hmu.lock(); defer { hmu.unlock() }; return pending }

    private var lastFailNote = ""

    /// Go's jsFail / the loop's errors, logged by Go; returns the note.
    private func fail(_ mode: String, _ detail: String) -> String {
        let f = go.fail(gen: gen, rule: rule, mode: mode, detail: detail, stop: stop.rawValue, timeoutMs: currentTimeout, afterDone: false)
        lastFailNote = f.note ?? ""
        return lastFailNote
    }

    private var currentTimeout: Int64 = 10_000

    /// afterDone: an exception after $done is only logged (the answer stands); interruptions still fail.
    private func afterDone(_ err: String) -> Bool {
        guard isDone else { return false }
        let f = go.fail(gen: gen, rule: rule, mode: "js", detail: err, stop: stop.rawValue, timeoutMs: currentTimeout, afterDone: true)
        return f.ignored == true
    }

    private func finishRun() {
        hmu.lock()
        dead = true
        let ts = timers
        timers = [:]
        let fs = Array(fetches.values)
        fetches = [:]
        hmu.unlock()
        for t in ts.values { t.cancel() }
        js.end(runID)
        go.cancel(token)
        for f in fs { f.done() }
        cond.lock()
        let leftover = queue
        queue = []
        cond.unlock()
        _ = leftover // jobs never run: their fetch results were released above
    }

    /// Frees the store handles the engine registered with this run, except keep (the result's body).
    func releaseNatives(keep: Int64) {
        hmu.lock()
        let owned = nativeOwned
        nativeOwned = []
        hmu.unlock()
        for h in owned where h != keep { lane?.free(h) }
    }

    // MARK: $done

    private struct DoneMock: Decodable {
        var status: StatusValue?
        var statusCode: StatusValue?
        var headers: [[String]]?
        var body: Int64?
    }

    private struct DoneDesc: Decodable {
        var kind: String?
        var err: String?
        var abort: Bool?
        var mock: DoneMock?
        var url: String?
        var method: String?
        var status: StatusValue?
        var statusCode: StatusValue?
        var headers: [[String]]?
        var body: Int64?
    }

    /// The prelude's statusOf: a number, a string ("200" / "HTTP/1.1 200 OK"), null or absent.
    enum StatusValue: Decodable {
        case number(Double), string(String), null
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if c.decodeNil() { self = .null; return }
            if let d = try? c.decode(Double.self) { self = .number(d); return }
            if let s = try? c.decode(String.self) { self = .string(s); return }
            self = .null
        }
    }

    /// Go's parseStatus.
    static func parseStatus(_ v: StatusValue?) -> Int {
        switch v {
        case .number(let d)?:
            guard d.isFinite, abs(d) < 9.2e18 else { return 0 }
            return Int(d)
        case .string(let raw)?:
            var s = RWAscii.trimSpace(raw)
            if s.hasPrefix("HTTP/") {
                let f = s.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" || $0 == "\u{0B}" || $0 == "\u{0C}" })
                if f.count >= 2 { s = String(f[1]) }
            }
            return goAtoi(s) ?? 0
        default:
            return 0
        }
    }

    /// strconv.Atoi (optional sign, decimal digits, no spaces).
    static func goAtoi(_ s: String) -> Int? {
        var b = Substring(s)
        var neg = false
        if let f = b.first, f == "+" || f == "-" { neg = f == "-"; b = b.dropFirst() }
        guard !b.isEmpty, b.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let n = Int(b) else { return nil }
        return neg ? -n : n
    }

    private func readDone() -> DoneDesc? {
        hmu.lock()
        let raw = doneRaw
        hmu.unlock()
        guard let d = try? JSONDecoder().decode(DoneDesc.self, from: Data(raw.utf8)) else {
            lastFailNote = fail("done", "invalid descriptor")
            return nil
        }
        if let e = d.err, !e.isEmpty { _ = go.host(gen: gen, rule: rule, op: "x-doneerr", arg: e) }
        return d
    }

    /// Go's parseDone for the response phase.
    private func parseDone(_ d: DoneDesc) -> NativeScriptResult {
        var res = NativeScriptResult()
        guard d.kind == "obj" else { return res }
        if d.abort == true { res.abort = true; return res }
        if requestPhase {
            if let m = d.mock {
                var st = Self.parseStatus(m.status)
                if st == 0 { st = Self.parseStatus(m.statusCode) }
                var body = Data()
                if let id = m.body, id >= 0 { body = blobBytes(id) ?? Data() }
                res.mock = RequestScriptOutcome.Mock(status: st, headers: m.headers.map { $0.filter { $0.count == 2 } }, body: body)
                return res
            }
            res.url = d.url
            res.method = d.method
            if let hs = d.headers {
                let pairs = hs.filter { $0.count == 2 }
                var h = GoHeader()
                for kv in pairs { h.add(kv[0], kv[1]) }
                res.headers = h
                res.headerPairs = pairs
            }
            if let id = d.body, id >= 0 {
                res.body = blobBytes(id) ?? Data()
                res.bodySet = true
            }
            return res
        }
        res.status = Self.parseStatus(d.status)
        if res.status == 0 { res.status = Self.parseStatus(d.statusCode) }
        if let hs = d.headers {
            var h = GoHeader()
            for kv in hs where kv.count == 2 { h.add(kv[0], kv[1]) } // pairsHeader: Add, no trimming
            Self.fixSetCookie(&h, origSetCookie)
            res.headers = h
        }
        if let id = d.body, id >= 0 {
            hmu.lock()
            let b = blobs[id]
            hmu.unlock()
            if case .native(let h, _)? = b, laneOK {
                res.nativeBody = h
                res.bodySet = true
                hmu.lock()
                if let i = nativeOwned.firstIndex(of: h) { nativeOwned.remove(at: i) }
                hmu.unlock()
                return res
            }
            hmu.lock()
            var data: Data?
            switch b {
            case .bytes(let x, _)?: data = x
            case .native(let h, _)?: data = nativeBytes(h)
            case nil: data = nil
            }
            hmu.unlock()
            res.body = data ?? Data()
            res.bodySet = true
        }
        return res
    }

    /// rc.blobBytes: a blob's bytes (request phase: always bytes, never a lane handle).
    private func blobBytes(_ id: Int64) -> Data? {
        hmu.lock()
        defer { hmu.unlock() }
        switch blobs[id] {
        case .bytes(let x, _)?: return x
        case .native(let h, _)?: return nativeBytes(h)
        case nil: return nil
        }
    }

    /// fixSetCookie: an unchanged joined value gets the original lines back, a changed one is split before each
    /// "name=" that starts a new cookie.
    static func fixSetCookie(_ h: inout GoHeader, _ orig: [String]) {
        let vs = h.values("Set-Cookie")
        guard vs.count == 1 else { return }
        if orig.count > 1 && vs[0] == orig.joined(separator: ", ") {
            h.setValues("Set-Cookie", orig)
            return
        }
        let parts = splitSetCookie(vs[0])
        if parts.count > 1 { h.setValues("Set-Cookie", parts) }
    }

    /// splitSetCookie (byte-wise, like Go).
    static func splitSetCookie(_ v: String) -> [String] {
        let b = Array(v.utf8)
        var out: [String] = []
        var start = 0
        var i = 0
        func isStop(_ c: UInt8) -> Bool { c == UInt8(ascii: "=") || c == UInt8(ascii: ";") || c == UInt8(ascii: ",") || c == 0x20 || c == 0x09 }
        while i < b.count {
            if b[i] != UInt8(ascii: ",") { i += 1; continue }
            var j = i + 1
            while j < b.count && (b[j] == 0x20 || b[j] == 0x09) { j += 1 }
            var k = j
            while k < b.count && !isStop(b[k]) { k += 1 }
            if k > j && k < b.count && b[k] == UInt8(ascii: "=") {
                out.append(goTrimSpace(b[start..<i]))
                start = j
            }
            i += 1
        }
        out.append(goTrimSpace(b[start..<b.count]))
        return out
    }

    /// strings.TrimSpace on bytes (ASCII white space; the values here are header values).
    static func goTrimSpace(_ s: ArraySlice<UInt8>) -> String {
        var lo = s.startIndex, hi = s.endIndex
        func ws(_ c: UInt8) -> Bool { c == 0x20 || (c >= 0x09 && c <= 0x0D) }
        while lo < hi && ws(s[lo]) { lo += 1 }
        while hi > lo && ws(s[hi - 1]) { hi -= 1 }
        return String(decoding: s[lo..<hi], as: UTF8.self)
    }
}

extension GoHeader {
    /// h[key] = values (canonical key).
    mutating func setValues(_ k: String, _ vs: [String]) {
        del(k)
        for v in vs { add(k, v) }
    }
}
