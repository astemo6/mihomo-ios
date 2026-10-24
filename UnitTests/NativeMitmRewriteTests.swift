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
    }
    struct HostCase: Decodable { var host: String; var port: Int; var match: Bool }
    struct Suite: Decodable {
        var name: String
        var snapshot: RWSnapshot
        var cases: [Case]?
        var hosts: [HostCase]?
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

    func testDriverOffPassesThrough() {
        NativeRewriteRuntime.override = false
        let inner = Inner(), src = FakeSource(Self.snapJSON)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: src))
        XCTAssertEqual(d.requestPhase(head: head("/ad"), conn: conn).id, 9)
        XCTAssertEqual(inner.calls, ["begin /ad"])
        XCTAssertEqual(src.fetches, 0)
    }

    func testDriverNativeLocalForwardAndDefer() {
        NativeRewriteRuntime.override = true
        let inner = Inner(), src = FakeSource(Self.snapJSON)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: src))

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
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: FakeSource(Self.snapJSON)))
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
    }
}

private extension FlowDecision.Action {
    var rawValueString: String { rawValue }
}
