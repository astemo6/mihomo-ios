// BEGIN XCTEST
import XCTest
@testable import Tern
// END XCTEST
import Foundation

/// Native MitM stage 3b: body rewrites in Swift must produce exactly the bytes the old core's flow API sends.
/// NativeMitmBodyFixtures.json is written by the old core: per suite the
/// rewrite snapshot (with the body rules the old core exported) and, per exchange, the request (and its body), the upstream's
/// response head and raw body, and what the old core really sent — the outbound request and body, the response decision and
/// body, the request-log entry. Suites: a body edge module (every regex / json / jq form, header rules around
/// body rules, things the old core must keep), the Surge / Loon / QX / Egern compat matrix, AppClean, and the user's QX corpus.
/// Handing back to the old core is always allowed; a native result must match byte for byte.
enum NativeBodyConformance {
    struct Decision: Decodable {
        var action: String
        var status: Int?
        var headers: [[String]]?
        var body: String?
        var length: Int64
        var method: String?
        var url: String?
        var host: String?
        var data: String?
        var note: String?
    }
    struct Resp: Decodable {
        var status: Int
        var headers: [[String]]?
        var length: Int64
        var body: Data?
        var expect: Decision
        var data: Data?
        var elided: Bool?
    }
    struct LogEntry: Decodable {
        var status: Int
        var matched: [String]?
    }
    struct Case: Decodable {
        var name: String
        var method: String
        var target: String
        var headers: [[String]]?
        var length: Int64
        var connHost: String
        var connPort: Int
        var reqBody: Data?
        var expect: Decision
        var reqData: Data?
        var resp: Resp?
        var log: LogEntry?
    }
    struct Suite: Decodable {
        var name: String
        var snapshot: RWSnapshot
        var labels: [String]?
        var cases: [Case]?
    }
    struct Fixtures: Decodable { var version: Int; var suites: [Suite] }

    struct Report {
        var total = 0, native = 0, handedBack = 0, mismatch = 0, nativeSkipped = 0
        var reasons: [String: Int] = [:]
        var skipReasons: [String: Int] = [:]
        var failures: [String] = []
        var perSuite: [String] = []
        var summary: String {
            let top = reasons.sorted { $0.value > $1.value }.prefix(12).map { "\($0.key) \($0.value)" }.joined(separator: ", ")
            let skips = skipReasons.sorted { $0.value > $1.value }.prefix(8).map { "\($0.key) \($0.value)" }.joined(separator: ", ")
            return "body exchanges \(total): native & identical \(native), handed back \(handedBack), mismatches \(mismatch), native rule skips \(nativeSkipped) (\(skips)); hand-back reasons: \(top)"
        }
    }

    static func request(_ c: Case) -> RewriteRequest {
        RewriteRequest(method: c.method, target: c.target, host: "", headers: c.headers ?? [], length: c.length,
                       connHost: c.connHost, connPort: c.connPort, tls: true)
    }

    enum Outcome { case native, handBack(String), mismatch(String), nativeSkip(String) }

    /// The skip note of a decision that skipped a rule the native engine cannot run (NativeRewriteEngine.skipRule).
    static func skipNote(_ d: RewriteDecision) -> String? {
        let notes: [String]
        switch d {
        case .deferred: return nil
        case .drop(let l): notes = l.notes
        case .local(let l): notes = l.log.notes
        case .forward(let f): notes = f.log.notes
        }
        return notes.first { $0.hasPrefix("跳过") }
    }

    static func check(_ c: Case, _ engine: NativeRewriteEngine, labels: [String]) -> Outcome {
        let d = engine.decide(request(c), bodies: true)
        let out = check(d, c, engine, labels: labels)
        // native-only (nc-integrate): nothing stands behind .deferred any more — a rule the native
        // engine cannot run (a regexp2-only body pattern, a response script next to body rules…) is skipped on its
        // own and noted in the request log (gap C5). the old core's answer in the fixture includes that rule's effect, so a
        // difference is expected exactly when such a skip happened; any other difference stays a mismatch.
        if case .mismatch(let why) = out, let note = skipNote(d) { return .nativeSkip("\(note): \(why)") }
        return out
    }

    static func check(_ decision: RewriteDecision, _ c: Case, _ engine: NativeRewriteEngine, labels: [String]) -> Outcome {
        let e = c.expect
        switch decision {
        case .deferred(let why):
            return .handBack("request: \(why)")
        case .drop:
            return e.action == "drop" ? .native : .mismatch("native drop, expected \(e.action)")
        case .local(let l):
            guard e.action == "local", l.status == e.status, l.headers == (e.headers ?? []), l.length == e.length else {
                return .mismatch("native local \(l.status), expected \(e.action) \(e.status ?? 0)")
            }
            return .native
        case .forward(let f):
            guard e.action == "forward" else { return .mismatch("native forward, expected \(e.action) \(e.note ?? "")") }
            if f.method != e.method { return .mismatch("method \(f.method) vs \(e.method ?? "")") }
            if f.url != e.url { return .mismatch("url \(f.url) vs \(e.url ?? "")") }
            if f.host != e.host { return .mismatch("host \(f.host) vs \(e.host ?? "")") }
            if f.headers != (e.headers ?? []) { return .mismatch("forward headers \(f.headers) vs \(e.headers ?? [])") }
            var reqRules = f.log.rules
            if let plan = f.requestBody {
                switch NativeBodyExec.request(plan, body: c.reqBody ?? Data()) {
                case .handBack(let why): return .handBack("request body: \(why)")
                case .body(let b):
                    let mode = b.isEmpty ? "none" : "read"
                    if mode != (e.body ?? "none") { return .mismatch("request body mode \(mode) vs \(e.body ?? "")") }
                    if Int64(b.count) != e.length { return .mismatch("request length \(b.count) vs \(e.length)") }
                    if b != (c.reqData ?? Data()) {
                        return .mismatch("request body bytes differ: \(String(decoding: b.prefix(200), as: UTF8.self)) vs \(String(decoding: (c.reqData ?? Data()).prefix(200), as: UTF8.self))")
                    }
                }
            } else {
                if f.bodyMode.rawValue != (e.body ?? "none") { return .mismatch("body mode \(f.bodyMode) vs \(e.body ?? "")") }
                if f.length != e.length { return .mismatch("length \(f.length) vs \(e.length)") }
            }
            guard let r = c.resp else { return .native }
            let x = r.expect
            if !f.response.hasBody {
                guard let got = engine.respond(f.response, status: r.status, headers: r.headers ?? [], length: r.length, method: f.method) else {
                    return .mismatch("header-only response failed")
                }
                if got.status != (x.status ?? 0) || got.headers != (x.headers ?? []) || got.bodyMode.rawValue != (x.body ?? "none") || got.length != x.length {
                    return .mismatch("header-only response \(got.status) \(got.headers) \(got.bodyMode) \(got.length) vs \(x.status ?? 0) \(x.headers ?? []) \(x.body ?? "") \(x.length)")
                }
                reqRules += f.response.rules
                return checkLog(c, reqRules, labels)
            }
            if let why = NativeBodyExec.responseHeadOK(status: r.status, headers: r.headers ?? [], length: r.length, method: f.method) {
                return .handBack("response head: \(why)")
            }
            if r.elided == true { return .mismatch("a body over 256 KB was taken natively") }
            switch NativeBodyExec.response(f.response.steps, status: r.status, headers: r.headers ?? [], length: r.length, raw: r.body ?? Data()) {
            case .handBack(let why):
                return .handBack("response body: \(why)")
            case .native(let got):
                guard x.action == "respond" else { return .mismatch("native respond, expected \(x.action) \(x.note ?? "")") }
                if got.status != (x.status ?? 0) { return .mismatch("response status \(got.status) vs \(x.status ?? 0)") }
                if got.headers != (x.headers ?? []) { return .mismatch("response headers \(got.headers) vs \(x.headers ?? [])") }
                if "read" != (x.body ?? "none") { return .mismatch("response body mode read vs \(x.body ?? "")") }
                if got.length != x.length { return .mismatch("response length \(got.length) vs \(x.length)") }
                if got.note != x.note { return .mismatch("response note \(got.note ?? "nil") vs \(x.note ?? "nil")") }
                let want = r.data ?? Data()
                if got.body != want {
                    return .mismatch("response body bytes differ (\(got.body.count) vs \(want.count)): \(String(decoding: got.body.prefix(300), as: UTF8.self)) ||| \(String(decoding: want.prefix(300), as: UTF8.self))")
                }
                reqRules += got.rules
                return checkLog(c, reqRules, labels)
            }
        }
    }

    /// The rules the request log shows (Entry.Matched, by label) must be the old core's.
    static func checkLog(_ c: Case, _ rules: [Int], _ labels: [String]) -> Outcome {
        guard let log = c.log else { return .native }
        let got = rules.map { $0 < labels.count ? labels[$0] : "?" }
        let want = log.matched ?? []
        return got == want ? .native : .mismatch("log matched \(got) vs \(want)")
    }

    static func run(_ fx: Fixtures) -> Report {
        var rep = Report()
        for s in fx.suites {
            let engine = NativeRewriteEngine(snapshot: s.snapshot)
            var n = 0, h = 0, m = 0, k = 0
            for c in s.cases ?? [] {
                rep.total += 1
                switch check(c, engine, labels: s.labels ?? []) {
                case .native:
                    rep.native += 1; n += 1
                case .handBack(let why):
                    rep.handedBack += 1; h += 1
                    let key = why.split(separator: ":").prefix(2).joined(separator: ":")
                    rep.reasons[key, default: 0] += 1
                case .nativeSkip(let why):
                    rep.nativeSkipped += 1; k += 1
                    rep.skipReasons[String(why.split(separator: ":").first ?? "").prefix(60).description, default: 0] += 1
                case .mismatch(let why):
                    rep.mismatch += 1; m += 1
                    if rep.failures.count < 40 { rep.failures.append("\(s.name) / \(c.name): \(why)") }
                }
            }
            rep.perSuite.append("\(s.name): \(n) native, \(h) handed back, \(m) mismatches, \(k) native skips")
        }
        return rep
    }
}


/// NativeRewriteDriver with body flows against a fake old flow API: native request / response bodies, and the three
/// ways the old core adopts an exchange (response head, response body, request body).
enum NativeBodyDriverChecks {
    static let snap = #"""
    {"version":1,"gen":7,"on":true,"capture":false,"inc":[{"pat":"a.com"}],"exc":[],"total":2,"portable":2,"rules":[
     {"i":0,"kind":"body","phase":"response","re":{"p":"^https://a\\.com/b","ok":true,"lit":"https://a.com/b","groups":0},
      "body":[{"icu":"\\x{61}\\x{64}","parts":[{"l":"AD","g":-1}]}],"bodyOK":true},
     {"i":1,"kind":"body","phase":"request","re":{"p":"^https://a\\.com/q","ok":true,"lit":"https://a.com/q","groups":0},
      "body":[{"icu":"\\x{61}\\x{61}\\x{61}","parts":[{"l":"ccc","g":-1}]}],"bodyOK":true}]}
    """#

    final class InnerDriverFake: MitmFlowDriving {
        var calls: [String] = []
        var bodies: [Int: Data] = [0: Data(), 1: Data()]
        var out = Data(), off = 0
        var stage = ""
        func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
            calls.append("begin \(head.target)")
            if head.method == "POST" { stage = "req"; var d = FlowDecision(id: 9, action: .needBody); d.which = 0; return d }
            var d = FlowDecision(id: 9, action: .forward); d.body = FlowBodyMode.none; d.length = 0; return d
        }
        func await(_ id: Int64) -> FlowDecision {
            calls.append("await")
            if stage == "req" {
                stage = ""
                out = Data("GO:".utf8) + bodies[0]!; off = 0
                var d = FlowDecision(id: id, action: .forward); d.body = .read; d.length = Int64(out.count); return d
            }
            out = Data("GO:".utf8) + bodies[1]!; off = 0
            var d = FlowDecision(id: id, action: .respond); d.status = 200; d.body = .read; d.length = Int64(out.count); return d
        }
        func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
            calls.append("response \(head.status)")
            var d = FlowDecision(id: id, action: .needBody); d.which = 1; return d
        }
        func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
            calls.append("write \(which.rawValue) \(data.count)"); bodies[which.rawValue]!.append(data); return .taken
        }
        func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) { calls.append("close \(which.rawValue)") }
        func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
            let n = min(max, out.count - off); if n <= 0 { return Data() }
            defer { off += n }; return out.subdata(in: off..<(off + n))
        }
        func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { .eof }
        func upstreamFailed(_ id: Int64, why: String) { calls.append("upstream") }
        func end(_ id: Int64, sent: Int64, error: String) { calls.append("end") }
        func cancel(_ id: Int64, why: String) { calls.append("cancel") }
    }

    static func readAll(_ d: NativeRewriteDriver, _ id: Int64, _ which: FlowBodyWhich) -> Data {
        var out = Data()
        for _ in 0..<100 { let b = d.read(id, which, max: 4); if b.isEmpty { break }; out += b }
        return out
    }

    static func run() -> [String] {
        var fails: [String] = []
        func expect(_ ok: Bool, _ what: String) { if !ok { fails.append(what) } }
        guard let s = RWSnapshot.decode(snap) else { return ["snapshot did not decode"] }
        let engine = NativeRewriteEngine(snapshot: s)
        let conn = MitmConnInfo(host: "a.com", port: 443, tls: true, connID: 1)
        func head(_ method: String, _ target: String, _ extra: HTTPHeaderList = []) -> HTTPRequestHead {
            HTTPRequestHead(method: method, target: target, headers: [("Host", "a.com"), ("User-Agent", "t")] + extra)
        }
        func q(_ h: HTTPRequestHead) -> RewriteRequest { NativeRewriteDriver.request(h, conn) }
        let body = Data("x ad y ad".utf8)
        let up = HTTPResponseHead(status: 200, reason: "OK", headers: [("Content-Length", String(body.count)), ("Content-Type", "text/plain")])

        // 1. response body rewritten natively
        do {
            let inner = InnerDriverFake(), d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: InnerRewriteSnapshotSourceStub()), recorder: nil)
            let h = head("GET", "/b")
            guard let f = d.native(q(h), engine: engine, head: h, conn: conn, bodies: true) else { return ["1: not native"] }
            expect(f.action == .forward && f.id < 0, "1: forward \(f.action)")
            expect((f.headers ?? []).contains(["Accept-Encoding", "gzip, deflate, br"]), "1: Accept-Encoding \(f.headers ?? [])")
            let r = d.responsePhase(f.id, head: up, length: Int64(body.count))
            expect(r.action == .needBody && r.which == 1, "1: need-body \(r.action)")
            expect(d.write(f.id, .response, body) == .taken, "1: write")
            d.closeBody(f.id, .response, error: "")
            let a = d.await(f.id)
            expect(a.action == .respond && a.body == .read && a.length == 9, "1: respond \(a.action) \(String(describing: a.body)) \(a.length)")
            expect(readAll(d, f.id, .response) == Data("x AD y AD".utf8), "1: body")
            expect(d.readState(f.id, .response) == .eof, "1: eof")
            d.end(f.id, sent: 9, error: "")
            expect(inner.calls.isEmpty, "1: inner driver was called \(inner.calls)")
            expect(d.stats.bodyNative == 1 && d.liveNativeFlows == 0, "1: stats \(d.stats)")
        }
        // 2. chunked response: the old core adopts at the head
        do {
            let inner = InnerDriverFake(), d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: InnerRewriteSnapshotSourceStub()), recorder: nil)
            let h = head("GET", "/b")
            guard let f = d.native(q(h), engine: engine, head: h, conn: conn, bodies: true) else { return fails + ["2: not native"] }
            let ch = HTTPResponseHead(status: 200, reason: "OK", headers: [("Transfer-Encoding", "chunked")])
            let r = d.responsePhase(f.id, head: ch, length: -1)
            expect(r.action == .needBody && r.id == f.id, "2: mapped need-body \(r.action) \(r.id)")
            _ = d.write(f.id, .response, body)
            d.closeBody(f.id, .response, error: "")
            let a = d.await(f.id)
            expect(a.action == .respond && a.id == f.id, "2: respond")
            expect(readAll(d, f.id, .response) == Data("GO:".utf8) + body, "2: inner driver's body")
            d.end(f.id, sent: 0, error: "")
            expect(inner.calls == ["begin /b", "response 200", "write 1 9", "close 1", "await", "end"], "2: calls \(inner.calls)")
            expect(d.stats.bodyAdopted == 1 && d.stats.adoptReasons["chunked"] == 1, "2: stats \(d.stats)")
        }
        // 3. body not UTF-8: the old core adopts after Swift read it (the buffered body is pushed to the old core)
        do {
            let inner = InnerDriverFake(), d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: InnerRewriteSnapshotSourceStub()), recorder: nil)
            let h = head("GET", "/b")
            guard let f = d.native(q(h), engine: engine, head: h, conn: conn, bodies: true) else { return fails + ["3: not native"] }
            let bad = Data([0xFF, 0x61, 0x64])
            let up3 = HTTPResponseHead(status: 200, reason: "OK", headers: [("Content-Length", "3")])
            _ = d.responsePhase(f.id, head: up3, length: 3)
            _ = d.write(f.id, .response, bad)
            d.closeBody(f.id, .response, error: "")
            let a = d.await(f.id)
            expect(a.action == .respond && a.id == f.id, "3: respond \(a.action)")
            expect(readAll(d, f.id, .response) == Data("GO:".utf8) + bad, "3: inner driver's body")
            d.end(f.id, sent: 0, error: "")
            expect(inner.calls == ["begin /b", "response 200", "write 1 3", "close 1", "await", "end"], "3: calls \(inner.calls)")
        }
        // 4. request body rewritten natively
        do {
            let inner = InnerDriverFake(), d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: InnerRewriteSnapshotSourceStub()), recorder: nil)
            let h = head("POST", "/q", [("Content-Length", "5")])
            guard let f = d.native(q(h), engine: engine, head: h, conn: conn, bodies: true) else { return fails + ["4: not native"] }
            expect(f.action == .needBody && f.which == 0, "4: need-body \(f.action)")
            _ = d.write(f.id, .request, Data("aaa!!".utf8))
            d.closeBody(f.id, .request, error: "")
            let a = d.await(f.id)
            expect(a.action == .forward && a.body == .read && a.length == 5, "4: forward \(a.action) \(String(describing: a.body)) \(a.length)")
            expect(readAll(d, f.id, .request) == Data("ccc!!".utf8), "4: request body")
            let r = d.responsePhase(f.id, head: up, length: Int64(body.count))
            expect(r.action == .respond && r.body == .upstream, "4: header-only response \(r.action)")
            d.end(f.id, sent: 9, error: "")
            expect(inner.calls.isEmpty, "4: inner driver was called \(inner.calls)")
        }
        // 5. request body not UTF-8: the old core adopts the request (nothing went upstream yet)
        do {
            let inner = InnerDriverFake(), d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: InnerRewriteSnapshotSourceStub()), recorder: nil)
            let h = head("POST", "/q", [("Content-Length", "4")])
            guard let f = d.native(q(h), engine: engine, head: h, conn: conn, bodies: true) else { return fails + ["5: not native"] }
            _ = d.write(f.id, .request, Data([0xFF, 0x61, 0x61, 0x61]))
            d.closeBody(f.id, .request, error: "")
            let a = d.await(f.id)
            expect(a.action == .forward && a.id == f.id && a.body == .read, "5: forward \(a.action)")
            expect(readAll(d, f.id, .request) == Data("GO:".utf8) + Data([0xFF, 0x61, 0x61, 0x61]), "5: inner driver's request body")
            d.end(f.id, sent: 0, error: "")
            expect(inner.calls == ["begin /q", "write 0 4", "close 0", "await", "end"], "5: calls \(inner.calls)")
        }
        return fails
    }
}

/// A snapshot source nobody asks (the checks call native() with an engine).
final class InnerRewriteSnapshotSourceStub: RewriteSnapshotSource {
    func generation() -> Int64 { 0 }
    func snapshotJSON() -> String { "" }
}

// BEGIN XCTEST
final class NativeMitmBodyTests: XCTestCase {
    func testDriverBodyFlowsAndAdoption() {
        let fails = NativeBodyDriverChecks.run()
        XCTAssertEqual(fails, [], fails.joined(separator: "\n"))
    }

    private func fixtures() throws -> NativeBodyConformance.Fixtures {
        let bundle = Bundle(for: NativeMitmBodyTests.self)
        guard let url = bundle.url(forResource: "NativeMitmBodyFixtures", withExtension: "json") else {
            XCTFail("NativeMitmBodyFixtures.json missing from the test bundle")
            return NativeBodyConformance.Fixtures(version: 0, suites: [])
        }
        return try JSONDecoder().decode(NativeBodyConformance.Fixtures.self, from: Data(contentsOf: url))
    }

    /// Every body exchange Swift answers matches the old core byte for byte; the rest is handed back.
    func testBodyConformanceWithGo() throws {
        let fx = try fixtures()
        XCTAssertEqual(fx.version, RWSnapshot.supportedVersion)
        let rep = NativeBodyConformance.run(fx)
        // "passed" keeps these lines in the CI job log (ui-tests.yml filters the xcodebuild output)
        print("NativeMitmBodyTests summary (passed filter): " + rep.summary)
        for line in rep.perSuite { print("NativeMitmBodyTests suite (passed filter): " + line) }
        for f in rep.failures { print("NativeMitmBodyTests MISMATCH (passed filter): " + f) }
        XCTAssertEqual(rep.mismatch, 0, rep.failures.prefix(5).joined(separator: "\n"))
        XCTAssertGreaterThan(rep.native, 0)
        // lane regexp2: body ops on regexp2's path (look-around, \b, $) and the old core's RE2 nested repeats run natively —
        // 297 skipped exchanges before, 166 after (run 40196702919): what remains is jq forms outside the native
        // subset (3 rules × 53) and chunked request bodies (7), no regex rule
        XCTAssertLessThanOrEqual(rep.nativeSkipped, 166)
    }

    /// the old core's JSON encoder output for the corner cases the corpus may not hold.
    func testJSONEncodingMatchesGo() {
        let cases: [(String, String)] = [
            (#"{"b":1,"a":[true,false,null],"c":{}}"#, #"{"a":[true,false,null],"b":1,"c":{}}"#),
            (#"{"s":"<&>\u2028\u2029\u0001\b\f\n\r\t\"\\\/é"}"#, #"{"s":"<&>\u2028\u2029\u0001\b\f\n\r\t\"\\/é"}"#),
            (#"[1.0,-0,1e5,12345678901234567890]"#, #"[1.0,-0,1e5,12345678901234567890]"#),
            (#"{"a":1,"a":2}"#, #"{"a":2}"#),
            (#"{"é":1,"e\u0301":2}"#, "{\"e\u{301}\":2,\"é\":1}"),
            (" [ ] ", "[]"),
        ]
        for (input, want) in cases {
            guard let v = BodyJSON.parse(input), let out = v.encoded() else { XCTFail("parse \(input)"); continue }
            XCTAssertEqual(String(decoding: out, as: UTF8.self), want, input)
        }
        for bad in [#"{"a":"\ud800"}"#, "{} x", "\u{feff}{}", "[01]", "{'a':1}", #"{"a":"\#u{1}"}"#] {
            XCTAssertNil(BodyJSON.parse(bad), bad)
        }
    }

    /// jq set / del follow jq 1.7.1 (setpath creates, delpaths ignores missing paths, wrong types throw).
    func testJQSubset() throws {
        let doc = BodyJSON.parse(#"{"data":{"list":[1,2,3],"n":5}}"#)!
        let set = try BodyJQ.setpath(doc, [.key(Array("data".utf8)), .key(Array("new".utf8)), .index(2)], .bool(true))
        XCTAssertEqual(String(decoding: set.encoded()!, as: UTF8.self), #"{"data":{"list":[1,2,3],"n":5,"new":[null,null,true]}}"#)
        let del = try BodyJQ.delpaths(doc, [[.key(Array("data".utf8)), .key(Array("list".utf8)), .index(0)], [.key(Array("data".utf8)), .key(Array("missing".utf8))]])
        XCTAssertEqual(String(decoding: del.encoded()!, as: UTF8.self), #"{"data":{"list":[2,3],"n":5}}"#)
        XCTAssertThrowsError(try BodyJQ.setpath(doc, [.key(Array("data".utf8)), .key(Array("n".utf8)), .key(Array("x".utf8))], .null))
    }
}
// END XCTEST
