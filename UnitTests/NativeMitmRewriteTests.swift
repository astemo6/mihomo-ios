import XCTest
@testable import Mihomo

/// Native MitM stage 3a: the Swift rewrite engine must decide every request it claims exactly like Go's flow API.
/// NativeMitmRewriteFixtures.json is written by Go (bridge/mitm/rewritesnap_test.go TestGenRewriteFixtures): per
/// suite the snapshot Go exports and, per request, what FlowBegin / FlowResponse really answered (or that Go would
/// run a script / body rule — then Swift must defer). Suites: edge cases, the Surge/Loon/QX/Egern compat matrix,
/// AppClean and YouTube modules in every dialect, and the user's QX corpus (work/qx-rewrite-remote.txt resources +
/// the 30-module corpus). Deferring is always allowed; a native decision must match field for field.
final class NativeMitmRewriteTests: XCTestCase {

    // MARK: fixture

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
        var expect: Decision
    }
    struct Case: Decodable {
        var name: String
        var method: String
        var target: String
        var host: String?
        var headers: [[String]]?
        var length: Int64
        var connHost: String
        var connPort: Int
        var needsGo: Bool?
        var expect: Decision
        var resp: Resp?
        var log: LogEntry?
    }
    /// The request-log entry Go's flow API left (bridge/mitm/nativerecord.go: what the native records must reproduce).
    struct LogEntry: Decodable, Equatable {
        var method: String
        var url: String
        var host: String
        var mitm: Bool
        var status: Int
        var matched: [String]?
        var notes: [String]?
        var local: Bool?
        var done: Bool
        var bytes: Int64
        var reqHeaders: [String: String]?
        var respHeaders: [String: String]?
    }
    struct HostCase: Decodable { var host: String; var port: Int; var match: Bool }
    struct Suite: Decodable {
        var name: String
        var snapshot: RWSnapshot
        var cases: [Case]?
        var hosts: [HostCase]?
        var labels: [String]?
    }
    struct Fixtures: Decodable { var version: Int; var suites: [Suite] }

    private func fixtures() throws -> Fixtures {
        let bundle = Bundle(for: NativeMitmRewriteTests.self)
        guard let url = bundle.url(forResource: "NativeMitmRewriteFixtures", withExtension: "json") else {
            XCTFail("NativeMitmRewriteFixtures.json missing from the test bundle")
            return Fixtures(version: 0, suites: [])
        }
        return try JSONDecoder().decode(Fixtures.self, from: Data(contentsOf: url))
    }

    private static func request(_ c: Case) -> RewriteRequest {
        RewriteRequest(method: c.method, target: c.target, host: c.host ?? "", headers: c.headers ?? [], length: c.length,
                       connHost: c.connHost, connPort: c.connPort, tls: true)
    }

    /// nil = same; else what differs.
    private static func compare(_ d: RewriteDecision, _ c: Case, _ engine: NativeRewriteEngine) -> String? {
        let e = c.expect
        switch d {
        case .go:
            return nil
        case .drop:
            return e.action == "drop" ? nil : "native drop, Go \(e.action)"
        case .local(let l):
            guard e.action == "local" else { return "native local \(l.status), Go \(e.action) \(e.note ?? "")" }
            if l.status != e.status { return "status \(l.status) vs \(e.status ?? 0)" }
            if l.headers != (e.headers ?? []) { return "headers \(l.headers) vs \(e.headers ?? [])" }
            if l.bodyMode.rawValue != (e.body ?? "none") { return "body mode \(l.bodyMode) vs \(e.body ?? "")" }
            if l.length != e.length { return "length \(l.length) vs \(e.length)" }
            let want = e.data.flatMap { Data(base64Encoded: $0) } ?? Data()
            if l.bodyMode == .read && l.body != want { return "local body \(l.body.count) B vs \(want.count) B" }
            return nil
        case .forward(let f):
            guard e.action == "forward" else { return "native forward \(f.url), Go \(e.action) \(e.note ?? "")" }
            if f.method != e.method { return "method \(f.method) vs \(e.method ?? "")" }
            if f.url != e.url { return "url \(f.url) vs \(e.url ?? "")" }
            if f.host != e.host { return "host \(f.host) vs \(e.host ?? "")" }
            if f.headers != (e.headers ?? []) { return "headers \(f.headers) vs \(e.headers ?? [])" }
            if f.bodyMode.rawValue != (e.body ?? "none") { return "body mode \(f.bodyMode) vs \(e.body ?? "")" }
            if f.length != e.length { return "length \(f.length) vs \(e.length)" }
            guard let r = c.resp else { return nil }
            guard let got = engine.respond(f.response, status: r.status, headers: r.headers ?? [], length: r.length, method: f.method) else {
                return "response: native engine failed"
            }
            let x = r.expect
            if got.action.rawValueString != x.action { return "response action \(got.action) vs \(x.action)" }
            if got.status != (x.status ?? 0) { return "response status \(got.status) vs \(x.status ?? 0)" }
            if got.headers != (x.headers ?? []) { return "response headers \(got.headers) vs \(x.headers ?? [])" }
            if got.bodyMode.rawValue != (x.body ?? "none") { return "response body \(got.bodyMode) vs \(x.body ?? "")" }
            if got.length != x.length { return "response length \(got.length) vs \(x.length)" }
            if got.note != x.note { return "response note \(got.note ?? "nil") vs \(x.note ?? "nil")" }
            return nil
        }
    }

    // MARK: conformance

    func testConformanceWithGoDecisions() throws {
        let fx = try fixtures()
        XCTAssertEqual(fx.version, RWSnapshot.supportedVersion)
        XCTAssertGreaterThanOrEqual(fx.suites.count, 4)
        var total = 0, native = 0, deferred = 0, mismatch = 0, mustDefer = 0, goNative = 0, hostsOK = 0
        var reasons: [String: Int] = [:]
        var perSuite: [String] = []
        for s in fx.suites {
            let engine = NativeRewriteEngine(snapshot: s.snapshot)
            var sn = 0, sd = 0
            for c in s.cases ?? [] {
                total += 1
                let expectNative = c.expect.action == "local" || c.expect.action == "drop" || c.expect.action == "forward"
                if expectNative { goNative += 1 }
                let d = engine.decide(Self.request(c))
                if case .go(let why) = d {
                    deferred += 1; sd += 1
                    reasons[why, default: 0] += 1
                    continue
                }
                if c.needsGo == true || !expectNative {
                    mustDefer += 1
                    XCTFail("[\(s.name)] \(c.name): Go \(c.expect.action)\(c.needsGo == true ? " (script/body)" : "") but native decided \(d)")
                    continue
                }
                if let why = Self.compare(d, c, engine) {
                    mismatch += 1
                    XCTFail("[\(s.name)] \(c.name) \(c.method) \(c.target): \(why)")
                    continue
                }
                native += 1; sn += 1
            }
            for h in s.hosts ?? [] {
                if engine.intercepts(host: h.host, port: h.port) == h.match { hostsOK += 1 } else {
                    XCTFail("[\(s.name)] host \(h.host):\(h.port) expected \(h.match)")
                }
            }
            perSuite.append("\(s.name) \(sn)/\(sn + sd)")
        }
        let top = reasons.sorted { $0.value > $1.value }.prefix(8).map { "\($0.key) \($0.value)" }.joined(separator: ", ")
        print("NativeMitmRewrite conformance: \(fx.suites.count) suites, \(total) cases; native == Go \(native), deferred \(deferred) (\(top)), mismatches \(mismatch), must-defer violations \(mustDefer); Go-native cases \(goNative); hosts ok \(hostsOK)")
        print("NativeMitmRewrite per suite (native/total): " + perSuite.joined(separator: "; "))
        XCTAssertEqual(mismatch, 0)
        XCTAssertEqual(mustDefer, 0)
        // guard against an engine that defers everything (always "correct", never useful)
        XCTAssertGreaterThan(native, goNative / 2, "native engine decided only \(native) of \(goNative) Go-native cases")
    }

    // MARK: replacement templates (regexp2 non-ECMAScript rules)

    private func rx(_ p: String, groups: Int) -> RWRegex {
        RWRegex(RWSnapRegex(p: p, ok: true, lit: nil, fold: nil, groups: groups, named: nil, empty: false))
    }

    func testTemplateExpansion() {
        let r = rx("^https://a\\.com/(\\w+)/(\\d+)", groups: 2)
        let u = "https://a.com/abc/123?q"
        XCTAssertEqual(r.replaceFirst(u, template: "https://b.com/$2/$1"), "https://b.com/123/abc?q")
        XCTAssertEqual(r.replaceFirst(u, template: "$$1-$&"), "$1-https://a.com/abc/123?q")
        XCTAssertEqual(r.replaceFirst(u, template: "x$3y"), "x$3y?q")          // no group 3: literal
        XCTAssertEqual(r.replaceFirst(u, template: "${2}0"), "1230?q")
        XCTAssertEqual(r.replaceFirst(u, template: "$20"), "$20?q")            // greedy digits, no group 20
        XCTAssertEqual(r.replaceFirst(u, template: "${-}/$"), "${-}/$?q")       // ${ + non-word char: literal; trailing $ literal
        XCTAssertNil(r.replaceFirst(u, template: "${x}"))                     // ${name}: left to Go
        XCTAssertNil(r.replaceFirst(u, template: "$`"))
        XCTAssertNil(r.replaceFirst(u, template: "${name}"))
        let all = rx("(\\w+)/(\\d+)", groups: 2)
        XCTAssertEqual(all.replaceAll("Mozilla/5 Tern/12", template: "$2-$1"), "5-Mozilla 12-Tern")
        XCTAssertNil(RWRegex(RWSnapRegex(p: "x*", ok: true, lit: nil, fold: nil, groups: 0, named: nil, empty: true)).replaceAll("abc", template: "y"))
    }

    func testLiteralPrefilterSkipsRegex() {
        // not portable, but the literal proves it cannot match: decided without Go
        let r = RWRegex(RWSnapRegex(p: "^https://a\\.com/\\p{L}+", ok: false, lit: "https://a.com/", fold: nil, groups: 0, named: nil, empty: false))
        if case .no = r.match("https://b.com/x") {} else { XCTFail("literal should rule it out") }
        if case .unknown = r.match("https://a.com/x") {} else { XCTFail("non-portable pattern must be unknown") }
        let f = RWRegex(RWSnapRegex(p: "(?i)^https://A\\.com/X", ok: true, lit: "https://a.com/x", fold: true, groups: 0, named: nil, empty: false))
        if case .yes = f.match("https://A.COM/x") {} else { XCTFail("fold literal") }
    }

    func testHeaderCanonicalAndHop() {
        XCTAssertEqual(GoHeader.canonical("x-foo-BAR"), "X-Foo-Bar")
        XCTAssertEqual(GoHeader.canonical("x foo"), "x foo")
        var h = GoHeader(pairs: [["connection", "keep-alive, X-Hop"], ["x-hop", "1"], ["Te", "trailers"], ["A", "1"], ["a", "2"]])
        XCTAssertTrue(h.containsToken("Te", "TRAILERS"))
        h.removeHopByHop()
        XCTAssertEqual(h.sortedPairs, [["A", "1"], ["A", "2"]])
    }

    // MARK: driver

    final class FakeSource: RewriteSnapshotSource {
        var gen: Int64 = 1
        var json: String
        var fetches = 0
        init(_ json: String) { self.json = json }
        func generation() -> Int64 { gen }
        func snapshotJSON() -> String { fetches += 1; return json.replacingOccurrences(of: "\"gen\":0", with: "\"gen\":\(gen)") }
    }

    final class Inner: MitmFlowDriving {
        var calls: [String] = []
        func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
            calls.append("begin \(head.target)")
            return FlowDecision.decode(#"{"id":9,"action":"forward","method":"GET","url":"https://go/","body":"none","length":0}"#)
        }
        func await(_ id: Int64) -> FlowDecision { calls.append("await"); return FlowDecision(id: id, action: .error) }
        func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision { calls.append("response \(id)"); return FlowDecision(id: id, action: .error) }
        func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult { calls.append("write"); return .taken }
        func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) { calls.append("close") }
        func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data { calls.append("read"); return Data() }
        func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { .eof }
        func upstreamFailed(_ id: Int64, why: String) { calls.append("upfail") }
        func end(_ id: Int64, sent: Int64, error: String) { calls.append("end \(id)") }
        func cancel(_ id: Int64, why: String) { calls.append("cancel \(id)") }
    }

    private static let snapJSON = """
    {"version":1,"gen":0,"on":true,"capture":false,"inc":[{"pat":"a.com"}],"exc":[],"rules":[
     {"i":0,"kind":"url","phase":"request","re":{"p":"^https://a\\\\.com/ad","ok":true,"lit":"https://a.com/ad","groups":0},"action":"reject-dict","target":"-"},
     {"i":1,"kind":"maplocal","phase":"request","re":{"p":"^https://a\\\\.com/ml","ok":true,"lit":"https://a.com/ml","groups":0},"local":{"status":200,"headers":[["Content-Type","text/plain; charset=utf-8"]],"body":"aGVsbG8="}},
     {"i":2,"kind":"header","phase":"response","re":{"p":"^https://a\\\\.com/h","ok":true,"lit":"https://a.com/h","groups":0},"headers":[{"op":"add","name":"X-R","value":"1"}],"opsOK":true},
     {"i":3,"kind":"script","phase":"response","re":{"p":"^https://a\\\\.com/s","ok":true,"lit":"https://a.com/s","groups":0},"script":{"name":"s","type":"http-response","requiresBody":true}}
    ],"total":4,"portable":4}
    """

    private func head(_ target: String) -> HTTPRequestHead {
        HTTPRequestHead(method: "GET", target: target, headers: [("Host", "a.com"), ("User-Agent", "t")])
    }
    private let conn = MitmConnInfo(host: "a.com", port: 443, tls: true, connID: 1)

    override func tearDown() { NativeRewriteRuntime.override = nil }

    // MARK: request log

    final class Sink: NativeRequestLogSink {
        var batches: [String] = []
        func record(_ json: String) -> Int { batches.append(json); return 1 }
    }

    struct Ev: Decodable {
        var k: Int64
        var ev: String
        var t: Double?
        var ms: Double
        var gen: Int64?
        var rules: [Int]?
        var method: String?
        var url: String?
        var host: String?
        var tls: Bool?
        var status: Int?
        var headers: [[String]]?
        var len: Int64?
        var body: Data?
        var sent: Int64?
        var resp: Bool?
        var why: String?
    }

    private static func events(_ batches: [String]) -> [Ev] {
        batches.flatMap { (try? JSONDecoder().decode([Ev].self, from: Data($0.utf8))) ?? [] }
    }

    private static func recorder(_ sink: Sink) -> NativeRequestRecorder {
        NativeRequestRecorder(sink: sink, maxQueued: 1 << 20, flushAt: 1 << 20, delay: 3600, watchMemory: false)
    }

    /// What bridge/mitm/nativerecord.go makes of a request's events (the same Entry calls in the same order).
    private static func entry(_ evs: [Ev], labels: [String]) -> LogEntry? {
        guard let first = evs.first else { return nil }
        func flat(_ h: [[String]]?) -> [String: String]? {
            let m = GoHeader(pairs: h ?? []).map.mapValues { $0.joined(separator: ", ") }
            return m.isEmpty ? nil : m
        }
        func names(_ r: [Int]?) -> [String] { (r ?? []).compactMap { $0 >= 0 && $0 < labels.count ? labels[$0] : nil } }
        var host = first.host ?? ""
        if let i = host.lastIndex(of: ":"), i != host.startIndex, !host[i...].contains("]") { host = String(host[..<i]) }
        var e = LogEntry(method: (first.method ?? "").isEmpty ? "GET" : first.method!, url: first.url ?? "", host: host, mitm: first.tls ?? false,
                         status: 0, matched: nil, notes: nil, local: nil, done: false, bytes: 0, reqHeaders: nil, respHeaders: nil)
        func match(_ r: [Int]?) { let n = names(r); if !n.isEmpty { e.matched = (e.matched ?? []) + n } }
        func note(_ s: String) { e.notes = (e.notes ?? []) + [s] }
        func finish(_ status: Int, _ n: String) {
            if e.done { return }
            e.done = true
            if status >= 0 { e.status = status }
            if !n.isEmpty { note(n) }
        }
        for v in evs {
            switch v.ev {
            case "drop": match(v.rules); finish(0, "拒绝（断开）")
            case "local":
                match(v.rules); e.url = v.url ?? ""; e.local = true; e.status = v.status ?? 0
                e.respHeaders = flat(v.headers); e.bytes = v.len ?? 0; finish(-1, "")
            case "forward": match(v.rules); e.url = v.url ?? ""; e.reqHeaders = flat(v.headers)
            case "response":
                if v.status != 101 { match(v.rules) }
                e.status = v.status ?? 0; e.respHeaders = flat(v.headers)
                if v.status == 101 { finish(101, "WebSocket / Upgrade") }
            case "end":
                e.bytes += v.sent ?? 0
                if let w = v.why, !w.isEmpty, v.resp == true { note(w) }
                finish(-1, "")
            case "cancel":
                let w = (v.why ?? "").isEmpty ? "客户端取消" : v.why!
                if v.resp == true { note(w); finish(-1, "") } else { finish(0, w) }
            case "upstream": finish(502, "上游错误：" + (v.why ?? ""))
            case "error": finish(502, "内部错误")
            default: return nil
            }
        }
        return e
    }

    private static func normalized(_ l: LogEntry) -> LogEntry {
        var x = l
        if x.matched?.isEmpty == true { x.matched = nil }
        if x.notes?.isEmpty == true { x.notes = nil }
        if x.local == false { x.local = nil }
        if x.reqHeaders?.isEmpty == true { x.reqHeaders = nil }
        if x.respHeaders?.isEmpty == true { x.respHeaders = nil }
        return x
    }

    /// Every request the native driver answers produces, through its request-log events, exactly the entry Go's
    /// flow API wrote for it (matched labels, URL, host, status, headers, notes, bytes) — across all fixture suites.
    func testRequestLogMatchesGo() throws {
        let fx = try fixtures()
        var checked = 0, failed = 0
        for s in fx.suites {
            let labels = s.labels ?? []
            let engine = NativeRewriteEngine(snapshot: s.snapshot)
            let sink = Sink()
            let rec = Self.recorder(sink)
            let d = NativeRewriteDriver(inner: Inner(), provider: NativeRewriteProvider(source: FakeSource(Self.snapJSON)), recorder: rec)
            for c in s.cases ?? [] {
                guard let want = c.log else { continue }
                guard let dec = d.native(Self.request(c), engine: engine) else { continue }
                if dec.action == .forward, let r = c.resp {
                    _ = d.responsePhase(dec.id, head: HTTPResponseHead(status: r.status, reason: "", headers: headerList(r.headers ?? [])), length: r.length)
                }
                d.end(dec.id, sent: 0, error: "")
                sink.batches.removeAll()
                rec.flushNow()
                let evs = Self.events(sink.batches)
                guard let got = Self.entry(evs, labels: labels) else {
                    failed += 1
                    XCTFail("[\(s.name)] \(c.name): no request-log events (\(sink.batches))")
                    continue
                }
                if Self.normalized(got) != Self.normalized(want) {
                    failed += 1
                    if failed <= 20 { XCTFail("[\(s.name)] \(c.name):\n native \(got)\n go     \(want)") }
                    continue
                }
                checked += 1
            }
            XCTAssertEqual(d.openLogEntries, 0, s.name)
            XCTAssertEqual(rec.stats.dropped, 0, s.name)
        }
        print("NativeMitmRewrite request log: \(checked) native entries identical to Go's, \(failed) different")
        XCTAssertEqual(failed, 0)
        XCTAssertGreaterThan(checked, 1000)
    }

    func testRecorderBoundsBatchesAndSheds() throws {
        let sink = Sink()
        let r = NativeRequestRecorder(sink: sink, maxQueued: 4, flushAt: 4, delay: 3600, watchMemory: false)
        for i in 0..<6 { r.add(NativeRequestEvent(k: Int64(i), ev: "drop", ms: 0)) }
        r.flushNow()
        XCTAssertEqual(sink.batches.count, 1)
        XCTAssertEqual(Self.events(sink.batches).map(\.k), [0, 1, 2, 3])
        XCTAssertEqual(r.stats.dropped, 2)
        XCTAssertEqual(r.stats.sent, 4)

        // reaching flushAt sends without waiting for the delay; the JSON is what Go decodes (base64 body, no nulls)
        let s2 = Sink()
        let r2 = NativeRequestRecorder(sink: s2, maxQueued: 8, flushAt: 2, delay: 3600, watchMemory: false)
        r2.add(NativeRequestEvent(k: 1, ev: "local", t: 1.5, ms: 0.25, rules: [3], status: 200, headers: [["Content-Type", "x"]], len: 2, body: Data("{}".utf8)))
        r2.add(NativeRequestEvent(k: 2, ev: "end", ms: 1, sent: 7, resp: true))
        r2.waitIdle()   // no flushNow: reaching flushAt alone sent the batch
        XCTAssertEqual(s2.batches.count, 1)
        let obj = try JSONSerialization.jsonObject(with: Data(s2.batches[0].utf8)) as? [[String: Any]]
        XCTAssertEqual(obj?.count, 2)
        XCTAssertEqual(obj?[0]["body"] as? String, "e30=")
        XCTAssertEqual(obj?[0]["rules"] as? [Int], [3])
        XCTAssertNil(obj?[1]["url"])
        XCTAssertEqual(obj?[1]["sent"] as? Int, 7)

        // memory pressure: the queue is dropped and recording pauses
        r2.add(NativeRequestEvent(k: 3, ev: "drop", ms: 0))
        r2.shed(pause: 60)
        r2.add(NativeRequestEvent(k: 4, ev: "drop", ms: 0))
        XCTAssertEqual(r2.stats.queued, 0)
        XCTAssertEqual(r2.stats.shed, 1)
        XCTAssertEqual(r2.stats.dropped, 2)
        r2.shed(pause: 0)
        r2.add(NativeRequestEvent(k: 5, ev: "drop", ms: 0))
        XCTAssertEqual(r2.stats.queued, 1)
        XCTAssertNotEqual(r2.newKey(), r2.newKey())
    }

    func testDriverOffPassesThrough() {
        NativeRewriteRuntime.override = false
        let inner = Inner(), src = FakeSource(Self.snapJSON)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: src), recorder: nil)
        XCTAssertEqual(d.requestPhase(head: head("/ad"), conn: conn).id, 9)
        XCTAssertEqual(inner.calls, ["begin /ad"])
        XCTAssertEqual(src.fetches, 0)
    }

    func testDriverNativeLocalForwardAndDefer() {
        NativeRewriteRuntime.override = true
        let inner = Inner(), src = FakeSource(Self.snapJSON)
        let sink = Sink()
        let rec = Self.recorder(sink)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: src), recorder: rec)

        let rej = d.requestPhase(head: head("/ad"), conn: conn)
        XCTAssertEqual(rej.action, .local); XCTAssertLessThan(rej.id, 0)
        XCTAssertEqual(rej.status, 200); XCTAssertEqual(rej.body, .read); XCTAssertEqual(rej.length, 2)
        XCTAssertEqual(d.read(rej.id, .response, max: 1), Data("{".utf8))
        XCTAssertEqual(d.read(rej.id, .response, max: 64), Data("}".utf8))
        XCTAssertEqual(d.read(rej.id, .response, max: 64), Data())
        XCTAssertEqual(d.readState(rej.id, .response), .eof)
        d.end(rej.id, sent: 0, error: "")

        let ml = d.requestPhase(head: head("/ml"), conn: conn)
        XCTAssertEqual(ml.action, .local); XCTAssertEqual(d.read(ml.id, .response, max: 64), Data("hello".utf8))
        d.end(ml.id, sent: 0, error: "")

        let fw = d.requestPhase(head: head("/h/x"), conn: conn)
        XCTAssertEqual(fw.action, .forward); XCTAssertEqual(fw.url, "https://a.com/h/x"); XCTAssertEqual(fw.host, "a.com")
        XCTAssertEqual(fw.body, FlowBodyMode.none)
        let up = HTTPResponseHead(status: 200, reason: "OK", headers: [("Content-Length", "3"), ("Connection", "keep-alive")])
        let r = d.responsePhase(fw.id, head: up, length: 3)
        XCTAssertEqual(r.action, .respond); XCTAssertEqual(r.body, .upstream); XCTAssertEqual(r.length, 3)
        XCTAssertEqual(r.headers ?? [], [["X-R", "1"]])
        d.end(fw.id, sent: 3, error: "")

        let sc = d.requestPhase(head: head("/s"), conn: conn)   // response script → Go
        XCTAssertEqual(sc.id, 9)
        d.end(sc.id, sent: 0, error: "")

        XCTAssertEqual(inner.calls, ["begin /s", "end 9"])
        XCTAssertEqual(d.liveNativeFlows, 0)
        XCTAssertEqual(d.stats.local, 2); XCTAssertEqual(d.stats.forward, 1); XCTAssertEqual(d.stats.deferred, 1)
        XCTAssertEqual(src.fetches, 1)

        // request log: one event per native decision, the forward's response and end; nothing for the Go request
        rec.flushNow()
        let evs = Self.events(sink.batches)
        XCTAssertEqual(evs.map(\.ev), ["local", "local", "forward", "response", "end"])
        XCTAssertEqual(evs[0].rules, [0]); XCTAssertEqual(evs[0].url, "https://a.com/ad"); XCTAssertEqual(evs[0].status, 200)
        XCTAssertEqual(evs[0].len, 2); XCTAssertNil(evs[0].body) // capture off
        XCTAssertEqual(evs[0].headers ?? [], [["Content-Length", "2"], ["Content-Type", "application/json"]])
        XCTAssertEqual(evs[1].rules, [1]); XCTAssertEqual(evs[1].headers ?? [], [["Content-Type", "text/plain; charset=utf-8"]]); XCTAssertEqual(evs[1].len, 5)
        XCTAssertNil(evs[2].rules); XCTAssertEqual(evs[2].host, "a.com"); XCTAssertEqual(evs[2].method, "GET"); XCTAssertEqual(evs[2].tls, true)
        XCTAssertEqual(evs[2].headers ?? [], [["User-Agent", "t"]])
        XCTAssertEqual(evs[3].rules, [2]); XCTAssertEqual(evs[3].status, 200)
        XCTAssertEqual(evs[3].headers ?? [], [["Content-Length", "3"], ["X-R", "1"]])
        XCTAssertEqual(evs[4].sent, 3); XCTAssertEqual(evs[4].resp, true); XCTAssertNil(evs[4].why)
        XCTAssertEqual(Set(evs[2...].map(\.k)).count, 1)
        XCTAssertEqual(Set(evs.map(\.k)).count, 3)
        XCTAssertTrue(evs.allSatisfy { $0.ms >= 0 })
        XCTAssertNotNil(evs[0].t); XCTAssertNil(evs[3].t)
        XCTAssertEqual(d.openLogEntries, 0)

        // cancel / upstream failure of native forwards
        sink.batches.removeAll()
        let c1 = d.requestPhase(head: head("/h/1"), conn: conn)
        d.cancel(c1.id, why: "")
        let c2 = d.requestPhase(head: head("/h/2"), conn: conn)
        d.upstreamFailed(c2.id, why: "dial: refused")
        d.end(c2.id, sent: 0, error: "")
        rec.flushNow()
        XCTAssertEqual(Self.events(sink.batches).map(\.ev), ["forward", "cancel", "forward", "upstream"])
        XCTAssertEqual(Self.events(sink.batches)[3].why, "dial: refused")
        XCTAssertEqual(d.openLogEntries, 0)

        // a reload (new generation) fetches the new snapshot once; a bad one defers everything to Go
        src.gen = 2
        src.json = "{\"version\":99}"
        XCTAssertEqual(d.requestPhase(head: head("/ad"), conn: conn).id, 9)
        XCTAssertEqual(d.requestPhase(head: head("/ad"), conn: conn).id, 9)
        XCTAssertEqual(src.fetches, 2)
    }

    func testSessionAnswersRejectWithoutGo() {
        NativeRewriteRuntime.override = true
        let inner = Inner()
        let sink = Sink()
        let rec = Self.recorder(sink)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: FakeSource(Self.snapJSON)), recorder: rec)
        let client = NativeMitmSessionTests.MemStream()
        let up = NativeMitmSessionTests.Upstream(response: Data())
        let s = NativeMitmSession(conn: MitmAcceptedConnection(stream: client, host: "a.com", port: 443, alpn: "http/1.1", connID: 3),
                                  codec: HTTPLaneCodec(), upstream: up, driver: d, bodies: NativeMitmSessionTests.Bodies())
        let done = expectation(description: "finished")
        s?.onFinish = { _ in done.fulfill() }
        s?.start()
        client.feed(Data("GET /ad HTTP/1.1\r\nHost: a.com\r\nConnection: close\r\n\r\n".utf8), eof: true)
        wait(for: [done], timeout: 5)
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 200 OK\r\n"), client.text)
        XCTAssertTrue(client.text.contains("Content-Type: application/json"), client.text)
        XCTAssertTrue(client.text.hasSuffix("\r\n\r\n{}"), client.text)
        XCTAssertTrue(up.opened.isEmpty)
        XCTAssertTrue(inner.calls.isEmpty, "\(inner.calls)")
        XCTAssertEqual(d.liveNativeFlows, 0)
        rec.flushNow()
        XCTAssertEqual(Self.events(sink.batches).map(\.ev), ["local"])
    }
}

private extension FlowDecision.Action {
    var rawValueString: String { rawValue }
}
