import Foundation

/// B6 (nc-dego-rest): 脚本调试 (script workbench) without Go — bridge/workbench.go ScriptDebugRun +
/// bridge/mitm/debugrun.go DebugRun in Swift. One script runs in the app process on the same JavaScriptCore
/// engine and prelude (TernPrelude.js) the tunnel uses, driven by NativeScriptRun (the tunnel's Swift run loop:
/// timers, $done parsing, timeout), with a host that captures console lines and notifications instead of
/// logging / posting them. $persistentStore is the real store (NCPersistentStore, engine/store.json).
///
/// Differences from the Go workbench: $httpClient uses URLSession from the app (Go dialed directly from the app
/// too; redirects are always followed here, `policy` / `insecure` are ignored); $httpAPI gets no answer (no
/// tunnel controller in the app process); the Egern ctx adapter (Go's egernadapter.go) is not applied.
enum NCScriptDebug {

    struct HTTP {
        var url: String?
        var method: String?
        var status: Int?
        var headers: [String: String]?
        var body: String?
        var bodyBase64: Bool?

        /// DebugHTTP.bytes: base64 when marked so, else the text.
        var bytes: Data {
            let b = body ?? ""
            if bodyBase64 == true {
                let t = b.trimmingCharacters(in: .whitespacesAndNewlines)
                if let d = Data(base64Encoded: t) { return d }
                var r = t.trimmingCharacters(in: CharacterSet(charactersIn: "="))
                while r.count % 4 != 0 { r += "=" }
                if let d = Data(base64Encoded: r) { return d }
            }
            return Data(b.utf8)
        }
    }

    struct Input {
        var code = ""
        var path: String?
        var name = ""
        var type = ""
        var argument: String?
        var timeout = 0
        var binary = false
        var request: HTTP?
        var response: HTTP?
    }

    static let maxLogs = 400

    // MARK: prelude (once per process)

    private static let preludeLock = NSLock()
    private static var preludeState: String?

    /// Loads TernPrelude.js (App bundle resource) into the shared engine; "" when ready, else the error.
    static func ensurePrelude() -> String {
        preludeLock.lock(); defer { preludeLock.unlock() }
        if let s = preludeState { return s }
        let state: String
        if let url = Bundle.main.url(forResource: "TernPrelude", withExtension: "js"),
           let p = try? String(contentsOf: url, encoding: .utf8) {
            state = JSCScriptEngine.shared.prepare(p)
        } else {
            state = "TernPrelude.js missing from the app bundle"
        }
        preludeState = state
        return state
    }

    // MARK: helpers (debugrun.go)

    static func normType(_ t: String) -> String {
        switch t.trimmingCharacters(in: .whitespaces).lowercased() {
        case "request", "http-request": return "http-request"
        case "response", "http-response": return "http-response"
        case let x: return x
        }
    }

    static func clip(_ s: String, _ n: Int) -> String {
        s.count <= n ? s : String(s.prefix(n)) + "…"
    }

    static func header(from m: [String: String]?) -> CanonicalHeader {
        var h = CanonicalHeader()
        for (k, v) in m ?? [:] { h.set(k, v) }
        return h
    }

    static func headerMap(_ h: CanonicalHeader?) -> [String: String]? {
        guard let h, !h.map.isEmpty else { return nil }
        var m: [String: String] = [:]
        for (k, v) in h.map { m[k] = v.joined(separator: ", ") }
        return m
    }

    static func bodyOut(_ d: Data) -> (String, Bool?) {
        if let s = String(data: d, encoding: .utf8) { return (s, nil) }
        return (d.base64EncodedString(), true)
    }

    // MARK: run

    /// mitm DebugRun. home: the core home (scripts / cache / store live under it).
    static func run(home: String, input inp: Input) -> DebugOutput {
        let start = Date()
        var out = DebugOutput(ok: false, error: nil, durationMs: 0, done: false, doneJSON: nil, summary: [],
                              result: nil, mock: nil, logs: [], notifications: [])
        func finish() -> DebugOutput {
            out.durationMs = Int64(Date().timeIntervalSince(start) * 1000)
            return out
        }
        var typ = normType(inp.type)
        if typ.isEmpty { typ = "http-response" }
        if inp.code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (inp.path ?? "").isEmpty {
            out.error = "没有脚本内容"
            return finish()
        }
        let name = inp.name.isEmpty ? "调试" : inp.name
        let timeout = min(max(inp.timeout <= 0 ? 10 : inp.timeout, 1), 60)

        // source: inline code, else the local / cached remote script
        var source = inp.code
        if source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            switch NCScriptSource.source(home: home, path: inp.path ?? "") {
            case .success(let s): source = s
            case .failure(let e):
                out.error = "加载脚本失败：" + e.message
                return finish()
            }
        }
        if source.hasPrefix("\u{FEFF}") { source.removeFirst() }

        let pState = ensurePrelude()
        if !pState.isEmpty {
            out.error = "脚本引擎不可用：" + pState
            return finish()
        }
        let js = JSCScriptEngine.shared
        let key = "debug:" + UUID().uuidString
        let loadErr = js.load(key, name: name, source: source)
        if !loadErr.isEmpty {
            out.error = loadErr.hasPrefix("prelude:") ? "脚本引擎不可用：" + loadErr : "脚本语法错误：" + clip(loadErr, 400)
            return finish()
        }
        defer { js.drop(key) }

        let host = DebugScriptHost(start: start, timeoutMs: Int64(timeout) * 1000, maxLogs: maxLogs)
        let run = NativeScriptRun(gen: 0, rule: 0, hostAPI: host, js: js, lane: nil, nativeBase: Int64(1) << 52, laneOK: false)
        let isHTTP = typ == "http-request" || typ == "http-response"
        run.requestPhase = typ == "http-request"

        // setup (mitm jsSetup)
        let language = NCEngineConfig.load(home: home).scriptLanguage
        var setup: [String: Any] = [
            "name": name, "type": typ, "path": inp.path ?? "", "phase": "task", "echo": false, "binary": inp.binary,
            "export": true,
            "arg": ["has": inp.argument != nil, "obj": false, "s": inp.argument ?? ""] as [String: Any],
            "env": ["surge-version": "5.20.0", "surge-build": "3000", "language": language, "system": "iOS",
                    "mihomo-ios": true] as [String: Any],
            "egernEnv": [String: String](), "egernCron": "", "hasParams": false,
        ]
        var reqURL = "", reqMethod = "GET"
        var reqHeader = CanonicalHeader()
        var reqBody = Data()
        var respStatus = 200
        var respHeader = CanonicalHeader()
        var respBody = Data()
        if isHTTP {
            let r = inp.request ?? HTTP()
            reqURL = (r.url ?? "").isEmpty ? "https://example.com/" : r.url!
            reqMethod = ((r.method ?? "").isEmpty ? "GET" : r.method!).uppercased()
            reqHeader = header(from: r.headers)
            reqBody = r.bytes
            let id = String(UInt64(max(0, Date().timeIntervalSince1970 * 1e9)), radix: 36)
            var req: [String: Any] = ["url": reqURL, "method": reqMethod, "id": id,
                                      "headers": NativeScriptResponse.headerPairs(reqHeader), "body": -1]
            if typ == "http-request" {
                setup["phase"] = "request"
                req["body"] = run.addBody(reqBody, native: 0)
            } else {
                setup["phase"] = "response"
                let rs = inp.response ?? HTTP(status: 200)
                respStatus = (rs.status ?? 0) == 0 ? 200 : rs.status!
                respHeader = header(from: rs.headers)
                respBody = rs.bytes
                setup["resp"] = ["status": respStatus, "headers": NativeScriptResponse.headerPairs(respHeader),
                                 "body": run.addBody(respBody, native: 0)] as [String: Any]
            }
            setup["req"] = req
        } else {
            setup["globals"] = ["$network": ["v4": [String: Any](), "wifi": [String: Any]()]]
        }
        guard let sd = try? JSONSerialization.data(withJSONObject: setup), let setupJSON = String(data: sd, encoding: .utf8) else {
            out.error = "脚本参数错误"
            return finish()
        }

        let outcome = run.run(key: key, setup: setupJSON, timeoutMs: Int64(timeout) * 1000) { nil }
        out.logs = host.logs.map { DebugOutput.Log(t: $0.t, level: $0.level, msg: $0.msg) }
        out.notifications = host.notifications
        let res: NativeScriptResult
        switch outcome {
        case .failed(let note):
            out.error = note.isEmpty ? "脚本错误" : note
            return finish()
        case .ok(let r):
            res = r
        }
        out.ok = true
        let raw = run.doneJSON
        if raw.isEmpty {
            out.summary.append("脚本结束但没有调用 $done()：线上会在超时后按原样放行")
            return finish()
        }
        out.done = true
        out.doneJSON = renderDone(raw)
        if !isHTTP {
            out.summary.append("$done() 已调用")
            return finish()
        }
        if res.abort {
            out.summary.append("脚本中止了请求（ctx.abort）")
            return finish()
        }
        if typ == "http-request" {
            if let m = res.mock {
                var mh = CanonicalHeader()
                for kv in m.headers ?? [] where kv.count == 2 { mh.add(kv[0], kv[1]) }
                let (b, b64) = bodyOut(m.body)
                let st = m.status == 0 ? 200 : m.status
                out.mock = DebugHTTPPayload(url: nil, method: nil, status: st, headers: headerMap(mh), body: b, bodyBase64: b64)
                out.summary.append("本地应答：HTTP \(st)，\(m.body.count) 字节（不会请求服务器）")
                return finish()
            }
            var r = DebugHTTPPayload(url: reqURL, method: reqMethod, status: nil, headers: headerMap(reqHeader), body: nil, bodyBase64: nil)
            if let u = res.url, !u.isEmpty, u != reqURL {
                r.url = u
                out.summary.append("URL 改为 " + clip(u, 200))
            }
            if let me = res.method, !me.isEmpty, me.lowercased() != reqMethod.lowercased() {
                r.method = me.uppercased()
                out.summary.append("方法改为 " + me.uppercased())
            }
            if let h = res.headers {
                r.headers = headerMap(h)
                out.summary.append("请求头已替换（\(h.map.count) 个）")
            }
            var b = reqBody
            if res.bodySet {
                b = res.body ?? Data()
                out.summary.append("请求体已修改（\(reqBody.count) → \(b.count) 字节）")
            }
            (r.body, r.bodyBase64) = bodyOut(b)
            out.result = r
        } else {
            var r = DebugHTTPPayload(url: nil, method: nil, status: respStatus, headers: headerMap(respHeader), body: nil, bodyBase64: nil)
            if res.status != 0 && res.status != respStatus {
                r.status = res.status
                out.summary.append("状态码改为 \(res.status)")
            }
            if let h = res.headers {
                r.headers = headerMap(h)
                out.summary.append("响应头已替换（\(h.map.count) 个）")
            }
            var b = respBody
            if res.bodySet {
                b = res.body ?? Data()
                out.summary.append("响应体已修改（\(respBody.count) → \(b.count) 字节）")
            }
            (r.body, r.bodyBase64) = bodyOut(b)
            out.result = r
        }
        if out.summary.isEmpty { out.summary.append("$done() 未做修改：原样放行") }
        return finish()
    }

    /// mitm doneJSON: the $done argument for display (long strings clipped, binary as a size, pretty JSON).
    static func renderDone(_ raw: String) -> String {
        guard let d = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any] else { return "undefined" }
        if d["undef"] as? Bool == true { return "undefined" }
        if d["isNull"] as? Bool == true { return "null" }
        guard let v = d["value"], !(v is NSNull) else { return "undefined" }
        func walk(_ x: Any, _ depth: Int) -> Any {
            if depth > 8 { return "…" }
            if let s = x as? String { return clip(s, 2000) }
            if let m = x as? [String: Any] {
                if m.count == 1, let n = m["__ternBinary"] as? NSNumber { return "<\(n.int64Value) 字节二进制>" }
                return m.mapValues { walk($0, depth + 1) }
            }
            if let a = x as? [Any] { return a.prefix(200).map { walk($0, depth + 1) } }
            return x
        }
        let w = walk(v, 0)
        guard let data = try? JSONSerialization.data(withJSONObject: w, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed]),
              let s = String(data: data, encoding: .utf8) else { return "undefined" }
        return s
    }
}

/// The run's host for 脚本调试: captures console lines / notifications, the real persistent store, URLSession
/// for $httpClient; admission / bodies are not involved (the sample bodies are handed over whole).
final class DebugScriptHost: ScriptHostAPI {
    struct Line { var t: Int64; var level: String; var msg: String }

    private let lock = NSLock()
    private let start: Date
    private let timeoutMs: Int64
    private let maxLogs: Int
    private var tokenSeq: Int64 = 0
    private var _logs: [Line] = []
    private var _notes: [[String: String]] = []

    init(start: Date, timeoutMs: Int64, maxLogs: Int) {
        self.start = start
        self.timeoutMs = timeoutMs
        self.maxLogs = maxLogs
    }

    var logs: [Line] { lock.lock(); defer { lock.unlock() }; return _logs }
    var notifications: [[String: String]] { lock.lock(); defer { lock.unlock() }; return _notes }

    private func addLog(_ level: String, _ msg: String) {
        lock.lock(); defer { lock.unlock() }
        let t = Int64(Date().timeIntervalSince(start) * 1000)
        if _logs.count >= maxLogs {
            if _logs.count == maxLogs { _logs.append(Line(t: t, level: "warn", msg: "（日志过多，后续输出已省略）")) }
            return
        }
        _logs.append(Line(t: t, level: level, msg: NCScriptDebug.clip(msg, 4000)))
    }

    func ready() -> Bool { true }
    func token() -> Int64 { lock.lock(); defer { lock.unlock() }; tokenSeq += 1; return tokenSeq }
    func cancel(_ token: Int64) {}
    func reserve(gen: Int64, rule: Int, token: Int64) -> ScriptReserveAnswer { ScriptReserveAnswer(slot: 1) }
    func release(slot: Int64, ran: Bool) {}
    func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared { ScriptPrepared(ok: false, err: "debug") }
    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
        ScriptAdmit(ok: true)
    }
    func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String { "" }
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String { "" }
    func bodyRelease(ticket: Int64) {}
    func bodyCharge(ticket: Int64) -> NativeBodyCharge? { nil }
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck { ScriptBodyCheck(limit: Int64.max) }
    func skip(gen: Int64, rule: Int, why: String) -> String { why }

    /// The run's failure as the workbench reports it (mitm jsErr wording).
    func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail {
        let why: String
        switch stop {
        case 1: why = "脚本执行超时（\(max(timeoutMs, self.timeoutMs) / 1000)s）"
        case 2: why = "脚本内存占用过高，已终止"
        case 3: why = "脚本已取消"
        default:
            switch mode {
            case "timeout": why = "脚本执行超时（\(max(timeoutMs, self.timeoutMs) / 1000)s）"
            case "cancel": why = "脚本已取消"
            case "done": why = "脚本运行时内部错误：$done " + detail
            default: why = Self.engineError(detail)
            }
        }
        var f = ScriptFail()
        if afterDone && stop == 0 {
            f.ignored = true
            f.msg = why
            addLog("warn", "$done 之后：" + why)
        } else {
            f.note = why
        }
        return f
    }

    /// mitm parseNativeErr + jsErr: the engine's {kind, message} as the workbench's error line.
    static func engineError(_ s: String) -> String {
        struct Desc: Decodable { var kind: String?; var message: String? }
        guard let d = try? JSONDecoder().decode(Desc.self, from: Data(s.utf8)), (d.kind ?? "") != "" || (d.message ?? "") != "" else {
            return "脚本引擎错误：" + NCScriptDebug.clip(s, 300)
        }
        let msg = d.message ?? ""
        switch d.kind ?? "" {
        case "terminated": return "脚本执行超时"
        case "exception":
            if msg.contains("Maximum call stack size exceeded") { return "脚本调用栈溢出（递归过深）" }
            return "脚本异常：" + NCScriptDebug.clip(msg, 400)
        case "syntax": return "脚本语法错误：" + NCScriptDebug.clip(msg, 400)
        case "memory": return msg
        default: return "脚本引擎错误：" + msg
        }
    }

    func host(gen: Int64, rule: Int, op: String, arg: String) -> String {
        switch op {
        case "log":
            let nl = arg.firstIndex(of: "\n")
            let level = nl.map { String(arg[..<$0]) } ?? "log"
            let msg = nl.map { String(arg[arg.index(after: $0)...]) } ?? arg
            addLog(level, msg)
            return ""
        case "notify":
            if let arr = (try? JSONSerialization.jsonObject(with: Data(arg.utf8))) as? [String], arr.count >= 3 {
                lock.lock()
                _notes.append(["title": arr[0], "subtitle": arr[1], "body": arr[2], "url": arr.count > 3 ? arr[3] : ""])
                lock.unlock()
                return "true"
            }
            return "false"
        case "sread":
            if let v = NCPersistentStore.shared.read(key: arg) { return "1" + v }
            return "0"
        case "swrite":
            // "w<keyLen UTF-16>:<key><value>" / "d<keyLen>:<key>" (the tunnel host's format)
            guard arg.count >= 3 else { return "false" }
            let del = arg.first == "d"
            let rest = String(arg.dropFirst())
            guard let colon = rest.firstIndex(of: ":"), let kl = Int(rest[..<colon]) else { return "false" }
            let after = String(rest[rest.index(after: colon)...])
            guard kl >= 0, after.utf16.count >= kl else { return "false" }
            let keyEnd = String.Index(utf16Offset: kl, in: after)
            let k = String(after[..<keyEnd]), v = String(after[keyEnd...])
            if del { return NCPersistentStore.shared.delete(key: k) ? "true" : "false" }
            return NCPersistentStore.shared.write(key: k, value: v) ? "true" : "false"
        case "sclear":
            return NCPersistentStore.shared.clear() ? "true" : "false"
        case "btoa":
            return Data(arg.utf8).base64EncodedString()
        case "atob":
            return Data(base64Encoded: arg).flatMap { String(data: $0, encoding: .utf8) } ?? ""
        case "x-doneerr":
            addLog("warn", "$done 的参数无法读取：" + NCScriptDebug.clip(arg, 300))
            return ""
        default:
            return "" // geo, apisync, x-finished: nothing in the app process
        }
    }

    func bytes(op: String, arg: String, input: Data) -> Data? {
        if op == "ungzip", case .decoded(let d) = NativeBodyDecode.gunzip([UInt8](input), limit: 16 << 20) { return d }
        return nil
    }

    func api(gen: Int64, rule: Int, arg: String) -> String { "" }

    /// $httpClient: URLSession from the app. Meta {"id","status","headers":[[k,v]…]} or {"id","err"}.
    func fetch(gen: Int64, rule: Int, token: Int64, arg: String, body: Data) -> ScriptFetch {
        struct Req: Decodable { var id: Int64; var url: String; var method: String?; var headers: [[String]]?; var timeout: Double? }
        func meta(_ o: [String: Any]) -> String {
            (try? JSONSerialization.data(withJSONObject: o)).flatMap { String(data: $0, encoding: .utf8) } ?? #"{"id":0,"err":"meta"}"#
        }
        guard let r = try? JSONDecoder().decode(Req.self, from: Data(arg.utf8)) else {
            return DebugScriptFetch(meta: #"{"id":0,"err":"invalid fetch request"}"#, body: Data())
        }
        guard let url = URL(string: r.url) else { return DebugScriptFetch(meta: meta(["id": r.id, "err": "invalid url"]), body: Data()) }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData,
                             timeoutInterval: (r.timeout ?? 0) > 0 ? r.timeout! / 1000 : 15)
        req.httpMethod = (r.method ?? "").isEmpty ? "GET" : r.method!
        for kv in r.headers ?? [] where kv.count == 2 { req.addValue(kv[1], forHTTPHeaderField: kv[0]) }
        if !body.isEmpty { req.httpBody = body }
        let sem = DispatchSemaphore(value: 0)
        var result = DebugScriptFetch(meta: meta(["id": r.id, "err": "request failed"]), body: Data())
        let method = req.httpMethod ?? "GET"
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, err in
            defer { sem.signal() }
            if let err {
                result = DebugScriptFetch(meta: meta(["id": r.id, "err": err.localizedDescription]), body: Data())
                self?.addLog("warn", "$httpClient \(method) \(NCScriptDebug.clip(r.url, 100)) failed: \(err.localizedDescription)")
                return
            }
            guard let h = resp as? HTTPURLResponse else { return }
            var pairs: [[String]] = []
            for (k, v) in h.allHeaderFields {
                pairs.append(["\(k)", "\(v)"])
            }
            pairs.sort { $0[0] < $1[0] }
            result = DebugScriptFetch(meta: meta(["id": r.id, "status": h.statusCode, "headers": pairs]), body: data ?? Data())
        }.resume()
        sem.wait()
        return result
    }

    func memLow() -> Bool { false }
    func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit { ScriptAdmit(ok: true) }
    func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String { why }
    func reqLimit(gen: Int64, rule: Int) -> Int64 { Int64.max }
    func held() -> Int64 { 0 }
}

/// A finished $httpClient download of a debug run (no budget to release).
final class DebugScriptFetch: ScriptFetch {
    let meta: String
    let body: Data
    init(meta: String, body: Data) { self.meta = meta; self.body = body }
    func done() {}
}
