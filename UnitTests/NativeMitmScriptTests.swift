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
