import XCTest
import Libmihomo
@testable import Mihomo

/// Lane s3-script (native script dispatch): every case of the corpus below runs twice on one Go engine
/// (LibmihomoMitmScriptTestStart), both times with JavaScriptCore and the native body lane registered —
///   1. Go dispatch: the Go flow API (GoMitmFlowDriver; Go's runCtx runs the script, the body goes through Go);
///   2. native dispatch: NativeRewriteDriver with nativeMitmScript on (NativeScriptResponse; the body goes from the
///      "session" straight into NativeBodyStore and JavaScriptCore, Go only admits / logs / serves host APIs) —
/// and the two must agree on everything a client or the user can see: the decision (action, status, headers), the
/// body bytes, the script log lines and the request-log entry (status, matched rules, notes, bytes), and the
/// $persistentStore / $httpClient effects (their results are in the bodies). Cases the native side does not support
/// are handed back to Go and must still agree. The test reports handled vs handed back and fails on any mismatch.
final class NativeMitmScriptTests: XCTestCase {
    private static let host = "api.test.com"

    // MARK: corpus

    private static let conf = """
    vip = type=http-response,pattern=^https://api\\.test\\.com/vip,requires-body=1,max-size=-1,script-path=vip.js
    qx = type=http-response,pattern=^https://api\\.test\\.com/qx,requires-body=1,script-path=qx.js
    loon = type=http-response,pattern=^https://api\\.test\\.com/loon,requires-body=1,script-path=loon.js
    egern = type=http-response,pattern=^https://api\\.test\\.com/egern,requires-body=1,script-path=egern.js
    status = type=http-response,pattern=^https://api\\.test\\.com/status,requires-body=1,script-path=status.js
    badstatus = type=http-response,pattern=^https://api\\.test\\.com/badstatus,requires-body=1,script-path=badstatus.js
    hdr = type=http-response,pattern=^https://api\\.test\\.com/hdr,script-path=hdr.js
    bin = type=http-response,pattern=^https://api\\.test\\.com/bin,requires-body=1,binary-body-mode=1,script-path=bin.js
    none = type=http-response,pattern=^https://api\\.test\\.com/none,requires-body=1,script-path=none.js
    err = type=http-response,pattern=^https://api\\.test\\.com/err,requires-body=1,script-path=err.js
    abort = type=http-response,pattern=^https://api\\.test\\.com/abort,requires-body=1,script-path=abort.js
    spin = type=http-response,pattern=^https://api\\.test\\.com/spin,requires-body=1,timeout=1,script-path=spin.js
    delay = type=http-response,pattern=^https://api\\.test\\.com/delay,requires-body=1,script-path=delay.js
    fetch = type=http-response,pattern=^https://api\\.test\\.com/fetch,requires-body=1,script-path=fetch.js
    fetchgz = type=http-response,pattern=^https://api\\.test\\.com/fetchgz,requires-body=1,script-path=fetchgz.js
    after = type=http-response,pattern=^https://api\\.test\\.com/after,requires-body=1,script-path=after.js
    nodone = type=http-response,pattern=^https://api\\.test\\.com/nodone,requires-body=1,script-path=nodone.js
    big = type=http-response,pattern=^https://api\\.test\\.com/big,requires-body=1,max-size=-1,script-path=big.js
    arg = type=http-response,pattern=^https://api\\.test\\.com/arg,requires-body=1,argument=hello world,script-path=arg.js
    small = type=http-response,pattern=^https://api\\.test\\.com/small,requires-body=1,max-size=16,script-path=vip.js
    cookie = type=http-response,pattern=^https://api\\.test\\.com/cookie,script-path=cookie.js
    same = type=http-response,pattern=^https://api\\.test\\.com/same,requires-body=1,script-path=same.js
    text = type=http-response,pattern=^https://api\\.test\\.com/text,requires-body=1,script-path=text.js
    two1 = type=http-response,pattern=^https://api\\.test\\.com/two,requires-body=1,script-path=vip.js
    two2 = type=http-response,pattern=^https://api\\.test\\.com/two,requires-body=1,script-path=qx.js
    two3 = type=http-response,pattern=^https://api\\.test\\.com/two,script-path=hdr.js
    plainfirst1 = type=http-response,pattern=^https://api\\.test\\.com/plainfirst,script-path=hdr.js
    plainfirst2 = type=http-response,pattern=^https://api\\.test\\.com/plainfirst,requires-body=1,script-path=vip.js
    reqscript = type=http-request,pattern=^https://api\\.test\\.com/reqscript,script-path=req.js
    rule: http-response ^https://api\\.test\\.com/hrule header-add X-Rule yes
    hrule = type=http-response,pattern=^https://api\\.test\\.com/hrule,requires-body=1,script-path=vip.js
    rqhdr = type=http-request,pattern=^https://api\\.test\\.com/rqhdr,script-path=req.js
    rqurl = type=http-request,pattern=^https://api\\.test\\.com/rqurl,script-path=rqurl.js
    rqmethod = type=http-request,pattern=^https://api\\.test\\.com/rqmethod,script-path=rqmethod.js
    rqbody = type=http-request,pattern=^https://api\\.test\\.com/rqbody,requires-body=1,script-path=rqbody.js
    rqjson = type=http-request,pattern=^https://api\\.test\\.com/rqjson,requires-body=1,script-path=rqjson.js
    rqkeep = type=http-request,pattern=^https://api\\.test\\.com/rqkeep,requires-body=1,script-path=none.js
    rqmock = type=http-request,pattern=^https://api\\.test\\.com/rqmock,script-path=rqmock.js
    rqqx = type=http-request,pattern=^https://api\\.test\\.com/rqqx,script-path=rqqx.js
    rqbad = type=http-request,pattern=^https://api\\.test\\.com/rqbad,script-path=rqbad.js
    rqabort = type=http-request,pattern=^https://api\\.test\\.com/rqabort,script-path=abort.js
    rqerr = type=http-request,pattern=^https://api\\.test\\.com/rqerr,script-path=err.js
    rqstore = type=http-request,pattern=^https://api\\.test\\.com/rqstore,script-path=rqstore.js
    rqsmall = type=http-request,pattern=^https://api\\.test\\.com/rqsmall,requires-body=1,max-size=16,script-path=rqbody.js
    rqtwo1 = type=http-request,pattern=^https://api\\.test\\.com/rqtwo,script-path=req.js
    rqtwo2 = type=http-request,pattern=^https://api\\.test\\.com/rqtwo,requires-body=1,script-path=rqbody.js
    rqresp1 = type=http-request,pattern=^https://api\\.test\\.com/rqresp,script-path=rqurl.js
    rqresp2 = type=http-response,pattern=^https://api\\.test\\.com/rqresp2,script-path=hdr.js
    rqhb1 = type=http-request,pattern=^https://api\\.test\\.com/rqhb,script-path=req.js
    rqhb2 = type=http-response,pattern=^https://api\\.test\\.com/rqhb,requires-body=1,script-path=vip.js
    rqmix1 = type=http-request,pattern=^https://api\\.test\\.com/rqmix,script-path=req.js
    rqmix2 = type=http-request,pattern=^https://api\\.test\\.com/rqmix,requires-body=1,script-path=rqbody.js
    rule: http-request ^https://api\\.test\\.com/rqrule header-add X-Rule-Req yes
    rqrule = type=http-request,pattern=^https://api\\.test\\.com/rqrule,script-path=req.js
    """

    private static let scripts: [String: String] = [
        "vip.js": #"var o = JSON.parse($response.body); o.vip = true; o.url = $request.url; $done({body: JSON.stringify(o)});"#,
        "qx.js": #"$prefs.setValueForKey("v1-" + $request.url.length, "qxk"); var o = JSON.parse($response.body); o.qx = $prefs.valueForKey("qxk") || "none"; $done({body: JSON.stringify(o)});"#,
        "loon.js": #"$persistentStore.write("lv", "lk"); var o = JSON.parse($response.body); o.loon = $persistentStore.read("lk"); $notification.post("t", "s", "b"); var h = $response.headers; h["X-Loon"] = "1"; $done({body: JSON.stringify(o), headers: h});"#,
        "egern.js": #"export default async function(ctx) { const d = await ctx.response.json(); d.eg = ctx.env.MODE || "unset"; d.m = ctx.request.method; return { body: d }; }"#,
        "status.js": #"$done({status: 201, headers: Object.assign({}, $response.headers, {"X-S": "s"}), body: "changed"});"#,
        "badstatus.js": #"$done({status: 99, body: "kept status"});"#,
        "hdr.js": #"var h = $response.headers; h["X-Resp"] = "ok"; h["X-Req-UA"] = $request.headers["User-Agent"] || ""; $done({headers: h});"#,
        "bin.js": #"var b = new Uint8Array($response.bodyBytes); b[0] = 9; $done({bodyBytes: b.buffer});"#,
        "none.js": #"$done({});"#,
        "err.js": #"throw new Error("boom");"#,
        "abort.js": #"export default async function(ctx) { ctx.abort(); }"#,
        "spin.js": #"while (true) {}"#,
        "delay.js": #"setTimeout(function () { $done({body: $response.body + "!"}); }, 30);"#,
        "fetch.js": #"$httpClient.get({url: "http://fetch.test/echo", headers: {"User-Agent": "T/1"}}, function (e, r, d) { var o = JSON.parse($response.body); var f = JSON.parse(d); o.f = f.ua + "|" + f.path + "|" + r.status; $done({body: JSON.stringify(o)}); });"#,
        "fetchgz.js": #"$httpClient.post({url: "http://fetch.test/gz", body: "pb"}, function (e, r, d) { $done({body: d}); });"#,
        "after.js": #"$done({body: "answered"}); throw new Error("after");"#,
        "nodone.js": #"var x = JSON.parse($response.body); console.log("no done " + Object.keys(x).length);"#,
        "big.js": #"var s = "a".repeat(200000); $done({body: s});"#,
        "arg.js": #"var o = JSON.parse($response.body); o.arg = typeof $argument === "string" ? $argument : JSON.stringify($argument); $done({body: JSON.stringify(o)});"#,
        "cookie.js": #"var h = $response.headers; $done({headers: h});"#,
        "same.js": #"$done({body: $response.body});"#,
        "text.js": #"$done({body: "[" + $response.body + "]"});"#,
        "req.js": #"var h = $request.headers; h["X-Req"] = "1"; $done({headers: h});"#,
        "rqurl.js": #"$done({url: $request.url.replace("/rqurl", "/rqurl2").replace("/rqresp", "/rqresp2") + "&added=1"});"#,
        "rqmethod.js": #"$done({method: "post", headers: Object.assign({}, $request.headers, {"X-M": $request.method})});"#,
        "rqbody.js": #"$done({body: "[" + ($request.body || "") + "]"});"#,
        "rqjson.js": #"var o = JSON.parse($request.body); o.injected = true; $done({body: JSON.stringify(o)});"#,
        "rqmock.js": #"$done({response: {status: 201, headers: {"Content-Type": "text/plain", "X-Mock": "1"}, body: "mocked " + $request.method}});"#,
        "rqqx.js": #"$done({status: "HTTP/1.1 403 Forbidden", headers: {"X-QX": "1"}, body: "qx"});"#,
        "rqbad.js": #"$done({response: {status: 99, body: "bad status"}});"#,
        "rqstore.js": #"$persistentStore.write("rv-" + $request.url.length, "rqk"); var h = $request.headers; h["X-Store"] = $persistentStore.read("rqk"); $done({headers: h});"#,
    ]

    private struct Case {
        var name: String
        var path: String
        var status = 200
        var method = "GET"
        var headers: [(String, String)] = [("Content-Type", "application/json")]
        var body = Data(#"{"a":1}"#.utf8)
        var encoding: String? = nil
        var chunked = false
        var reqHeaders: [(String, String)] = [("User-Agent", "Client/2"), ("Accept", "*/*")]
    }

    private static var cases: [Case] {
        var c: [Case] = []
        for p in ["vip", "qx", "loon", "egern", "status", "badstatus", "hdr", "none", "err", "abort", "spin", "delay", "fetch",
                  "fetchgz", "after", "nodone", "big", "arg", "same", "two", "hrule"] {
            c.append(Case(name: p, path: "/\(p)?q=1"))
        }
        c.append(Case(name: "qx again (store read)", path: "/qx?q=2"))
        c.append(Case(name: "small (skipped)", path: "/small", body: Data(("{\"k\":\"" + String(repeating: "y", count: 2000) + "\"}").utf8)))
        c.append(Case(name: "bin", path: "/bin", headers: [("Content-Type", "application/octet-stream")], body: Data([1, 2, 3, 0xFF, 0])))
        c.append(Case(name: "text invalid utf8", path: "/text", headers: [("Content-Type", "text/plain")], body: Data([0x61, 0xFF, 0xFE, 0x62])))
        c.append(Case(name: "text bom", path: "/text", headers: [("Content-Type", "text/plain")], body: Data([0xEF, 0xBB, 0xBF, 0x78])))
        c.append(Case(name: "cookie", path: "/cookie", headers: [("Content-Type", "application/json"), ("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Expires=Wed, 21 Oct 2027 07:28:00 GMT")]))
        for enc in ["gzip", "deflate", "br"] {
            c.append(Case(name: "vip \(enc)", path: "/vip?enc=\(enc)", encoding: enc))
        }
        c.append(Case(name: "vip large gzip", path: "/vip?large", body: Data(("{\"k\":\"" + String(repeating: "x", count: 900_000) + "\"}").utf8), encoding: "gzip"))
        c.append(Case(name: "vip broken gzip", path: "/vip?broken", headers: [("Content-Type", "application/json"), ("Content-Encoding", "gzip")], body: Data([0x1F, 0x8B, 8, 0, 1, 2, 3])))
        c.append(Case(name: "vip empty", path: "/vip?empty", body: Data()))
        c.append(Case(name: "vip HEAD", path: "/vip?head", method: "HEAD", headers: [("Content-Type", "application/json"), ("Content-Length", "7")], body: Data()))
        c.append(Case(name: "vip 204", path: "/vip?nc", status: 204, headers: [], body: Data()))
        c.append(Case(name: "vip 304", path: "/vip?nm", status: 304, headers: [("ETag", "\"x\"")], body: Data()))
        // handed back to Go (unsupported natively), must still agree
        c.append(Case(name: "chunked (hand-back)", path: "/vip?chunked", chunked: true))
        c.append(Case(name: "zstd (hand-back)", path: "/vip?zstd", headers: [("Content-Type", "application/json"), ("Content-Encoding", "zstd")]))
        c.append(Case(name: "plain script first (hand-back)", path: "/plainfirst"))
        c.append(Case(name: "request script (Go)", path: "/reqscript"))
        c.append(Case(name: "no rule (Go)", path: "/norule"))
        return c
    }

    // MARK: driving a MitmFlowDriving like the session does

    private struct Outcome: Equatable {
        var action = ""
        var status = 0
        var headers: [String] = []
        var body = Data()
        var length: Int64 = 0
        var note = ""
    }

    private func encode(_ c: Case) -> (Data, [(String, String)]) {
        var headers = c.headers
        var body = c.body
        if let enc = c.encoding {
            body = LibmihomoMitmScriptTestEncode(enc, c.body) ?? Data()
            headers.append(("Content-Encoding", enc))
        }
        if c.chunked {
            headers.append(("Transfer-Encoding", "chunked"))
        } else if !headers.contains(where: { $0.0.lowercased() == "content-length" }) && c.status != 204 && c.status != 304 {
            headers.append(("Content-Length", String(body.count)))
        }
        return (body, headers)
    }

    private func drive(_ d: MitmFlowDriving, _ c: Case, store: NativeBodyStore) -> Outcome {
        var reqHeaders = c.reqHeaders
        reqHeaders.insert(("Host", Self.host), at: 0)
        let head = HTTPRequestHead(method: c.method, target: c.path, headers: reqHeaders)
        let conn = MitmConnInfo(host: Self.host, port: 443, tls: true, connID: 1)
        let first = d.requestPhase(head: head, conn: conn)
        var out = Outcome()
        guard first.action == .forward else {
            out.action = "\(first.action)"
            out.status = first.status ?? 0
            d.end(first.id, sent: 0, error: "")
            return out
        }
        let id = first.id
        let (body, headers) = encode(c)
        let rh = HTTPResponseHead(status: c.status, reason: "R", headers: headers)
        let noBody = c.method == "HEAD" || c.status == 204 || c.status == 304
        let length: Int64 = noBody ? 0 : (c.chunked ? -1 : Int64(body.count))
        var r = d.responsePhase(id, head: rh, length: length)
        var pushed = false
        while r.action == .needBody {
            var off = 0
            var tries = 0
            pushLoop: while off < body.count {
                let end = min(off + 32 << 10, body.count)
                switch d.write(id, .response, body.subdata(in: off..<end)) {
                case .full:
                    tries += 1
                    if tries > 5000 { break pushLoop }
                    usleep(1000)
                    continue
                case .stop, .gone:
                    break pushLoop
                case .taken:
                    off = end
                }
            }
            d.closeBody(id, .response, error: "")
            pushed = true
            r = d.await(id)
        }
        out.action = "\(r.action)"
        out.status = r.status ?? 0
        out.headers = (r.headers ?? []).map { $0.joined(separator: ": ") }.sorted()
        out.note = r.action == .error ? (r.note ?? "") : ""
        out.length = r.length
        var sent: Int64 = 0
        if r.action == .respond {
            switch r.body ?? .none {
            case .read:
                var tries = 0
                while tries < 20000 {
                    let b = d.read(id, .response, max: 64 << 10)
                    if !b.isEmpty { out.body.append(b); continue }
                    if d.readState(id, .response) != .again { break }
                    tries += 1
                    usleep(500)
                }
            case .lane:
                if let l = r.lane {
                    let n = store.len(l.handle, raw: l.raw)
                    if n > 0 { out.body = store.read(l.handle, raw: l.raw, off: 0, n: n) ?? Data() }
                }
            case .upstream:
                out.body = pushed ? Data("<upstream after push>".utf8) : body
            case .none, .client:
                break
            }
            sent = Int64(out.body.count)
            if r.body == .lane || r.body == .upstream || r.body == .read { out.length = sent }
        }
        d.end(id, sent: sent, error: "")
        return out
    }

    // MARK: the side effects Go recorded

    private struct Side: Equatable {
        var logs: [String] = []
        var requests: [String] = []
    }

    private static let durationRe = try! NSRegularExpression(pattern: "用时 \\d+ ms")

    private func take(expectRequests: Int) -> Side {
        var side = Side()
        let deadline = Date().addingTimeInterval(5)
        repeat {
            let js = LibmihomoMitmScriptTestTake()
            if let obj = (try? JSONSerialization.jsonObject(with: Data(js.utf8))) as? [String: Any] {
                for l in (obj["logs"] as? [[String: Any]]) ?? [] {
                    var msg = l["msg"] as? String ?? ""
                    msg = Self.durationRe.stringByReplacingMatches(in: msg, range: NSRange(msg.startIndex..., in: msg), withTemplate: "用时 N ms")
                    side.logs.append("\(l["script"] ?? "") \(l["level"] ?? "") \(msg)")
                }
                for r in (obj["requests"] as? [[String: Any]]) ?? [] {
                    let matched = (r["matched"] as? [String] ?? []).joined(separator: " | ")
                    let notes = (r["notes"] as? [String] ?? []).joined(separator: " | ")
                    side.requests.append("\(r["url"] ?? "") status=\(r["status"] ?? "") bytes=\(r["bytes"] ?? "") matched=[\(matched)] notes=[\(notes)]")
                }
            }
            if side.requests.count >= expectRequests { break }
            usleep(20_000)
        } while Date() < deadline
        return side
    }

    // MARK: the test

    func testNativeScriptDispatchMatchesGo() throws {
        XCTAssertEqual(JSCScriptEngine.register(), "")
        let store = NativeBodyStore.shared
        JSCScriptEngine.setLaneForTests(store)
        defer {
            LibmihomoMitmScriptTestStop()
            JSCScriptEngine.setLaneForTests(nil)
            NativeScriptRuntime.override = nil
            NativeRewriteRuntime.override = nil
        }
        let home = NSTemporaryDirectory() + "native-script-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let sj = String(data: try JSONSerialization.data(withJSONObject: Self.scripts), encoding: .utf8) ?? "{}"
        let started = LibmihomoMitmScriptTestStart(home, Self.conf, sj, Self.host)
        XCTAssertEqual(started, "", "test engine")
        guard started.isEmpty else { return }
        XCTAssertTrue(LibmihomoMitmScriptReady(), "JavaScriptCore + lane registered")
        XCTAssertTrue(JSCScriptEngine.shared.canInterrupt, "JavaScriptCore time limit")
        _ = take(expectRequests: 0)

        NativeRewriteRuntime.override = false
        NativeScriptRuntime.override = true
        let recorder = NativeRequestRecorder(sink: GoNativeRequestLogSink(), watchMemory: false)
        let native = NativeRewriteDriver(inner: GoMitmFlowDriver(), provider: NativeRewriteProvider(source: GoRewriteSnapshotSource()),
                                         recorder: recorder)
        let goDriver = GoMitmFlowDriver()
        var same = 0, mismatches: [String] = []
        var report: [String] = []
        for c in Self.cases {
            let before = native.stats
            let g = drive(goDriver, c, store: store)
            let gs = take(expectRequests: 1)
            let n = drive(native, c, store: store)
            recorder.flushNow()
            recorder.waitIdle()
            let ns = take(expectRequests: 1)
            let after = native.stats
            let how = after.script > before.script ? "native" : (after.scriptHandedBack > before.scriptHandedBack ? "handed back" : "go")
            var diffs: [String] = []
            if g != n { diffs.append("decision/body:\n  go     \(describe(g))\n  native \(describe(n))") }
            if gs.logs != ns.logs { diffs.append("logs:\n  go     \(gs.logs)\n  native \(ns.logs)") }
            if gs.requests != ns.requests { diffs.append("request log:\n  go     \(gs.requests)\n  native \(ns.requests)") }
            report.append("\(c.name): \(how) — \(diffs.isEmpty ? "same" : "DIFFERENT")")
            if diffs.isEmpty { same += 1 } else { mismatches.append("\(c.name) (\(how)):\n" + diffs.joined(separator: "\n")) }
            XCTAssertEqual(LibmihomoMitmScriptHeld(), 0, "\(c.name): Go handles left")
        }
        let st = native.stats
        let summary = "native script conformance: \(Self.cases.count) cases, same \(same), mismatches \(mismatches.count); handled natively \(st.script), handed back \(st.scriptHandedBack) \(st.handBackReasons), deferred at the request \(st.deferred) \(st.reasons)"
        print("[native-script] " + summary)
        for l in report { print("[native-script] " + l) }
        for m in mismatches { print("[native-script] MISMATCH " + m) }
        XCTAssertTrue(mismatches.isEmpty, summary + "\n" + mismatches.joined(separator: "\n\n"))
        XCTAssertGreaterThanOrEqual(st.script, 36, "most cases are handled natively")
        XCTAssertEqual(native.liveNativeFlows, 0, "native flows left")
        XCTAssertEqual(JSCScriptEngine.laneLive(), 0, "Go lane handles left")
    }

    // MARK: request scripts (native-final)

    private struct ReqCase {
        var name: String
        var path: String
        var method = "GET"
        var body = Data()
        var chunked = false
        var respChunked = false
    }

    private static var reqCases: [ReqCase] {
        let json = Data(#"{"a":1}"#.utf8)
        return [
            ReqCase(name: "rq headers", path: "/rqhdr?q=1"),
            ReqCase(name: "rq headers POST body untouched", path: "/rqhdr?p", method: "POST", body: json),
            ReqCase(name: "rq url", path: "/rqurl?q=1"),
            ReqCase(name: "rq method", path: "/rqmethod?q=1"),
            ReqCase(name: "rq body", path: "/rqbody?q=1", method: "POST", body: Data("hello".utf8)),
            ReqCase(name: "rq body GET (no body)", path: "/rqbody?g"),
            ReqCase(name: "rq json", path: "/rqjson", method: "PUT", body: json),
            ReqCase(name: "rq keep body", path: "/rqkeep", method: "POST", body: Data("keep me".utf8)),
            ReqCase(name: "rq mock", path: "/rqmock?q=1"),
            ReqCase(name: "rq qx mock", path: "/rqqx"),
            ReqCase(name: "rq bad status mock", path: "/rqbad"),
            ReqCase(name: "rq abort", path: "/rqabort"),
            ReqCase(name: "rq error", path: "/rqerr"),
            ReqCase(name: "rq store", path: "/rqstore?a=1"),
            ReqCase(name: "rq store again", path: "/rqstore?a=22"),
            ReqCase(name: "rq small (skipped)", path: "/rqsmall", method: "POST", body: Data(String(repeating: "z", count: 100).utf8)),
            ReqCase(name: "rq two scripts", path: "/rqtwo", method: "POST", body: Data("two".utf8)),
            ReqCase(name: "rq url then response script", path: "/rqresp?x=1"),
            ReqCase(name: "rq header rule + script", path: "/rqrule"),
            ReqCase(name: "rq then response hand-back (chunked response)", path: "/rqhb", respChunked: true),
            ReqCase(name: "rq then chunked request (hand-over)", path: "/rqmix", method: "POST", body: Data("chunk".utf8), chunked: true),
            ReqCase(name: "rq mix fixed length", path: "/rqmix", method: "POST", body: Data("fixed".utf8)),
        ]
    }

    private struct ReqOutcome: Equatable {
        var first = ""
        var forward = ""
        var reqBody = Data()
        var resp = Outcome()
    }

    private func pushAll(_ d: MitmFlowDriving, _ id: Int64, _ which: FlowBodyWhich, _ body: Data) {
        var off = 0, tries = 0
        while off < body.count {
            let end = min(off + 32 << 10, body.count)
            switch d.write(id, which, body.subdata(in: off..<end)) {
            case .full:
                tries += 1
                if tries > 5000 { off = body.count } else { usleep(1000) }
            case .stop, .gone: off = body.count
            case .taken: off = end
            }
        }
        d.closeBody(id, which, error: "")
    }

    private func readAll(_ d: MitmFlowDriving, _ id: Int64, _ which: FlowBodyWhich) -> Data {
        var out = Data(), tries = 0
        while tries < 20000 {
            let b = d.read(id, which, max: 64 << 10)
            if !b.isEmpty { out.append(b); continue }
            if d.readState(id, which) != .again { break }
            tries += 1
            usleep(500)
        }
        return out
    }

    private func driveReq(_ d: MitmFlowDriving, _ c: ReqCase) -> ReqOutcome {
        var hs: [(String, String)] = [("Host", Self.host), ("User-Agent", "Client/2"), ("Accept", "*/*")]
        if c.chunked { hs.append(("Transfer-Encoding", "chunked")) } else if !c.body.isEmpty { hs.append(("Content-Length", String(c.body.count))) }
        if !c.body.isEmpty { hs.append(("Content-Type", "application/json")) }
        let head = HTTPRequestHead(method: c.method, target: c.path, headers: hs)
        let conn = MitmConnInfo(host: Self.host, port: 443, tls: true, connID: 1)
        var out = ReqOutcome()
        var r = d.requestPhase(head: head, conn: conn)
        var clientBodyTaken = false
        if r.action == .needBody {
            pushAll(d, r.id, .request, c.body)
            clientBodyTaken = true
            r = d.await(r.id)
        }
        let id = r.id
        out.first = "\(r.action) \(r.status ?? 0)"
        guard r.action == .forward else {
            if r.action == .local {
                out.first += " " + (r.headers ?? []).map { $0.joined(separator: ": ") }.sorted().joined(separator: "; ")
                out.reqBody = readAll(d, id, .response) // the local body (kept in reqBody for the comparison)
            }
            d.end(id, sent: Int64(out.reqBody.count), error: "")
            return out
        }
        out.forward = "\(r.method ?? "") \(r.url ?? "") host=\(r.host ?? "") body=\(r.body?.rawValue ?? "") len=\(r.length) " +
            (r.headers ?? []).map { $0.joined(separator: ": ") }.sorted().joined(separator: "; ")
        switch r.body ?? .none {
        case .read: out.reqBody = readAll(d, id, .request)
        case .client: out.reqBody = clientBodyTaken ? Data("<client body taken>".utf8) : c.body
        default: break
        }
        let rbody = Data(#"{"r":1}"#.utf8)
        var rh: [(String, String)] = [("Content-Type", "application/json")]
        if c.respChunked { rh.append(("Transfer-Encoding", "chunked")) } else { rh.append(("Content-Length", String(rbody.count))) }
        var resp = d.responsePhase(id, head: HTTPResponseHead(status: 200, reason: "OK", headers: rh), length: c.respChunked ? -1 : Int64(rbody.count))
        var pushed = false
        while resp.action == .needBody {
            pushAll(d, id, .response, rbody)
            pushed = true
            resp = d.await(id)
        }
        out.resp.action = "\(resp.action)"
        out.resp.status = resp.status ?? 0
        out.resp.headers = (resp.headers ?? []).map { $0.joined(separator: ": ") }.sorted()
        out.resp.note = resp.action == .error ? (resp.note ?? "") : ""
        if resp.action == .respond {
            switch resp.body ?? .none {
            case .read: out.resp.body = readAll(d, id, .response)
            case .upstream: out.resp.body = pushed ? Data("<upstream after push>".utf8) : rbody
            case .lane:
                if let l = resp.lane {
                    let n = NativeBodyStore.shared.len(l.handle, raw: l.raw)
                    if n > 0 { out.resp.body = NativeBodyStore.shared.read(l.handle, raw: l.raw, off: 0, n: n) ?? Data() }
                }
            default: break
            }
        }
        d.end(id, sent: Int64(out.resp.body.count), error: "")
        return out
    }

    /// native-final: http-request scripts run natively (engine stops at the script, Swift runs it, applies $done)
    /// vs the Go flow — the forwarded request (method, URL, headers, body), local answers, drops, the response, the
    /// script log and the request-log entry must be identical. Requests Swift cannot finish are handed to Go with the
    /// outcomes so far (FlowHead.Scripted) and must still agree (no script runs twice: the logs would differ).
    func testNativeRequestScriptsMatchGo() throws {
        XCTAssertEqual(JSCScriptEngine.register(), "")
        let store = NativeBodyStore.shared
        JSCScriptEngine.setLaneForTests(store)
        defer {
            LibmihomoMitmScriptTestStop()
            JSCScriptEngine.setLaneForTests(nil)
            NativeScriptRuntime.override = nil
            NativeRewriteRuntime.override = nil
        }
        let home = NSTemporaryDirectory() + "native-reqscript-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let sj = String(data: try JSONSerialization.data(withJSONObject: Self.scripts), encoding: .utf8) ?? "{}"
        let started = LibmihomoMitmScriptTestStart(home, Self.conf, sj, Self.host)
        XCTAssertEqual(started, "", "test engine")
        guard started.isEmpty else { return }
        XCTAssertTrue(LibmihomoMitmScriptReady(), "JavaScriptCore + lane registered")
        _ = take(expectRequests: 0)

        NativeRewriteRuntime.override = true
        NativeScriptRuntime.override = true
        let recorder = NativeRequestRecorder(sink: GoNativeRequestLogSink(), watchMemory: false)
        let native = NativeRewriteDriver(inner: GoMitmFlowDriver(), provider: NativeRewriteProvider(source: GoRewriteSnapshotSource()),
                                         recorder: recorder)
        let goDriver = GoMitmFlowDriver()
        var same = 0, mismatches: [String] = [], report: [String] = []
        for c in Self.reqCases {
            let before = native.stats
            let g = driveReq(goDriver, c)
            let gs = take(expectRequests: 1)
            let n = driveReq(native, c)
            recorder.flushNow()
            recorder.waitIdle()
            let ns = take(expectRequests: 1)
            let after = native.stats
            let how = after.reqScript > before.reqScript ? "native" : (after.reqScriptHandedOver > before.reqScriptHandedOver ? "handed over" : "go")
            var diffs: [String] = []
            if g != n { diffs.append("decision:\n  go     \(g)\n  native \(n)") }
            if gs.logs != ns.logs { diffs.append("logs:\n  go     \(gs.logs)\n  native \(ns.logs)") }
            if gs.requests != ns.requests { diffs.append("request log:\n  go     \(gs.requests)\n  native \(ns.requests)") }
            report.append("\(c.name): \(how) — \(diffs.isEmpty ? "same" : "DIFFERENT")")
            if diffs.isEmpty { same += 1 } else { mismatches.append("\(c.name) (\(how)):\n" + diffs.joined(separator: "\n")) }
            XCTAssertEqual(LibmihomoMitmScriptHeld(), 0, "\(c.name): Go handles left")
        }
        let st = native.stats
        let summary = "native request-script conformance: \(Self.reqCases.count) cases, same \(same), mismatches \(mismatches.count); finished natively \(st.reqScript), handed over \(st.reqScriptHandedOver) \(st.handOverReasons); response hand-backs \(st.scriptHandedBack) \(st.handBackReasons)"
        print("[native-reqscript] " + summary)
        for l in report { print("[native-reqscript] " + l) }
        for m in mismatches { print("[native-reqscript] MISMATCH " + m) }
        XCTAssertTrue(mismatches.isEmpty, summary + "\n" + mismatches.joined(separator: "\n\n"))
        XCTAssertGreaterThanOrEqual(st.reqScript, 15, "most request-script cases are finished natively")
        XCTAssertEqual(native.liveNativeFlows, 0, "native flows left")
    }

    private func describe(_ o: Outcome) -> String {
        let text = String(data: o.body.prefix(160), encoding: .utf8) ?? o.body.prefix(32).map { String(format: "%02x", $0) }.joined()
        return "\(o.action) \(o.status) len=\(o.length) note=\(o.note) headers=\(o.headers) body(\(o.body.count))=\(text)"
    }

    /// The pieces ported from Go, checked on their own.
    func testPortedHelpers() {
        XCTAssertEqual(NativeScriptRun.splitSetCookie("a=1, b=2; Expires=Wed, 21 Oct 2027 07:28:00 GMT"), ["a=1", "b=2; Expires=Wed, 21 Oct 2027 07:28:00 GMT"])
        XCTAssertEqual(NativeScriptRun.parseStatus(.string("HTTP/1.1 201 Created")), 201)
        XCTAssertEqual(NativeScriptRun.parseStatus(.number(404)), 404)
        XCTAssertEqual(NativeScriptRun.parseStatus(.string(" 302 ")), 302)
        XCTAssertEqual(NativeScriptRun.parseStatus(.string("x")), 0)
        XCTAssertEqual(NativeScriptRun.parseStatus(.null), 0)
        var h = GoHeader()
        h.add("set-cookie", "a=1, b=2")
        NativeScriptRun.fixSetCookie(&h, [])
        XCTAssertEqual(h.values("Set-Cookie"), ["a=1", "b=2"])
        var h2 = GoHeader()
        h2.add("Set-Cookie", "a=1, x=2")
        NativeScriptRun.fixSetCookie(&h2, ["a=1", "x=2"])
        XCTAssertEqual(h2.values("Set-Cookie"), ["a=1", "x=2"])
        XCTAssertNil(NativeScriptResponse.unsupported([ScriptPlanStep(rule: 1, kind: .script(requiresBody: true)),
                                                       ScriptPlanStep(rule: 2, kind: .script(requiresBody: false))]))
        XCTAssertNotNil(NativeScriptResponse.unsupported([ScriptPlanStep(rule: 1, kind: .script(requiresBody: false)),
                                                          ScriptPlanStep(rule: 2, kind: .script(requiresBody: true))]))
        XCTAssertTrue(NativeScriptResponse.encodingOK("GZIP"))
        XCTAssertFalse(NativeScriptResponse.encodingOK("zstd"))
    }
}
