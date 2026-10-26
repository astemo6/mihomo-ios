import XCTest
@testable import Tern

/// Native MitM stage 3a: the Swift rewrite engine must decide every request it claims exactly like the old core's flow API.
/// NativeMitmRewriteFixtures.json is written by the old core: per
/// suite the snapshot the old core exports and, per request, what FlowBegin / FlowResponse really answered (or that the old core would
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
    /// The request-log entry the old core's flow API left.
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
        case .deferred:
            return nil
        case .drop:
            return e.action == "drop" ? nil : "native drop, expected \(e.action)"
        case .local(let l):
            guard e.action == "local" else { return "native local \(l.status), expected \(e.action) \(e.note ?? "")" }
            if l.status != e.status { return "status \(l.status) vs \(e.status ?? 0)" }
            if l.headers != (e.headers ?? []) { return "headers \(l.headers) vs \(e.headers ?? [])" }
            if l.bodyMode.rawValue != (e.body ?? "none") { return "body mode \(l.bodyMode) vs \(e.body ?? "")" }
            if l.length != e.length { return "length \(l.length) vs \(e.length)" }
            let want = e.data.flatMap { Data(base64Encoded: $0) } ?? Data()
            if l.bodyMode == .read && l.body != want { return "local body \(l.body.count) B vs \(want.count) B" }
            return nil
        case .forward(let f):
            guard e.action == "forward" else { return "native forward \(f.url), expected \(e.action) \(e.note ?? "")" }
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

    /// The decision skipped a rule the native engine cannot run (native-only tunnel: NativeRewriteEngine.skipRule).
    private static func skipNoted(_ d: RewriteDecision) -> Bool {
        let notes: [String]
        switch d {
        case .deferred: return false
        case .drop(let l): notes = l.notes
        case .local(let l): notes = l.log.notes
        case .forward(let f): notes = f.log.notes
        }
        return notes.contains { $0.hasPrefix("跳过") }
    }

    func testConformanceWithGoDecisions() throws {
        let fx = try fixtures()
        XCTAssertEqual(fx.version, RWSnapshot.supportedVersion)
        XCTAssertGreaterThanOrEqual(fx.suites.count, 4)
        var total = 0, native = 0, deferred = 0, mismatch = 0, mustDefer = 0, goNative = 0, hostsOK = 0, nativeSkipped = 0
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
                if case .deferred(let why) = d {
                    deferred += 1; sd += 1
                    reasons[why, default: 0] += 1
                    continue
                }
                if c.needsGo == true || !expectNative {
                    // native-only (nc-integrate): nothing stands behind .deferred any more. A rule the old core
                    // ran as a script / body rule that the stage-3a engine cannot run is skipped on its own and noted
                    // in the request log (gap C5); the fixture's the old core answer includes that rule's effect, so the decision
                    // is not compared. A native decision without such a skip note is still a violation.
                    if Self.skipNoted(d) { nativeSkipped += 1; continue }
                    mustDefer += 1
                    XCTFail("[\(s.name)] \(c.name): expected \(c.expect.action)\(c.needsGo == true ? " (script/body)" : "") but native decided \(d)")
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
        print("NativeMitmRewrite conformance: \(fx.suites.count) suites, \(total) cases; native == fixture \(native), deferred \(deferred) (\(top)), mismatches \(mismatch), must-defer violations \(mustDefer), native rule skips \(nativeSkipped); fixture-native cases \(goNative); hosts ok \(hostsOK)")
        print("NativeMitmRewrite per suite (native/total): " + perSuite.joined(separator: "; "))
        XCTAssertEqual(mismatch, 0)
        XCTAssertEqual(mustDefer, 0)
        // guard against an engine that defers everything (always "correct", never useful)
        XCTAssertGreaterThan(native, goNative / 2, "native engine decided only \(native) of \(goNative) fixture-native cases")
    }

    // MARK: regexp2 → ICU translation (lane s3-full)

    struct RxIn: Decodable { var s: String; var m: Bool; var f: String?; var a: String? }
    struct RxCase: Decodable { var re: RWSnapRegex; var re2: Bool?; var repl: Bool?; var t: String?; var tp: RWSnapTemplate?; var `in`: [RxIn] }
    struct RxTarget: Decodable { var t: String; var err: Bool?; var host: String?; var path: String?; var query: String?; var force: Bool? }
    struct RxHost: Decodable { var hp: String; var err: Bool?; var host: String?; var port: String? }
    struct RxNet: Decodable {
        var targets: [RxTarget]
        var queries: [[String]]
        var hosts: [RxHost]
        var status: [String: String]
        var sniff: [[String]]
    }
    struct RxFixtures: Decodable { var version: Int; var cases: [RxCase]; var pathEsc: [Int]; var queryEsc: [Int]; var net: RxNet }

    private func regexFixtures() throws -> RxFixtures? {
        let bundle = Bundle(for: NativeMitmRewriteTests.self)
        guard let url = bundle.url(forResource: "NativeMitmRegexFixtures", withExtension: "json") else {
            XCTFail("NativeMitmRegexFixtures.json missing from the test bundle")
            return nil
        }
        return try JSONDecoder().decode(RxFixtures.self, from: Data(contentsOf: url))
    }

    /// the old core's ICU translations of 1500 generated regexp2 patterns and every CI-suite
    /// rule pattern, replayed on NSRegularExpression: match / first replacement / replace-all must equal what
    /// regexp2 (or RE2, where the old core matches URLs with it) produced. A pattern ICU refuses (an unbounded look-behind)
    /// is fine — the engine then hands the request to the old core.
    func testRegexTranslationMatchesRegexp2() throws {
        guard let fx = try regexFixtures() else { return }
        var ok = 0, refused = 0, bad = 0, checks = 0
        for c in fx.cases {
            let r = RWRegex(c.re)
            guard r.compiles else { refused += 1; continue }
            var caseBad = false
            for i in c.in {
                checks += 1
                let m = r.match(i.s)
                if m == .unknown || (m == .yes) != i.m {
                    caseBad = true
                    if bad < 20 { XCTFail("match \(c.re.p) → \(c.re.icu ?? "") on \(i.s.debugDescription): regexp2 \(i.m), ICU \(m)") }
                }
                if c.repl == true, let tp = c.tp {
                    let f = r.replaceFirst(i.s, tp), a = r.replaceAll(i.s, tp)
                    if f != i.f || a != i.a {
                        caseBad = true
                        if bad < 20 { XCTFail("replace \(c.re.p) / \(c.t ?? "") on \(i.s.debugDescription): regexp2 \(i.f.debugDescription) \(i.a.debugDescription), ICU \(f.debugDescription) \(a.debugDescription)") }
                    }
                }
            }
            if caseBad { bad += 1 } else { ok += 1 }
        }
        print("NativeMitmRegex translation: \(fx.cases.count) patterns, \(checks) inputs; identical \(ok), ICU refused \(refused), different \(bad)")
        XCTAssertEqual(bad, 0)
        XCTAssertGreaterThan(ok, fx.cases.count * 9 / 10)
    }

    /// lane regexp2 (native-only): RX2ICU translates the same 1600 regexp2 / RE2 patterns from their source text alone
    /// (Unicode-faithful pieces instead of the old core's ASCII sets) — match, first replacement, replace-all and the parsed
    /// replacement program must equal what regexp2 (RE2 for URL matchers) produced.
    func testRX2ICUMatchesRegexp2Fixtures() throws {
        guard let fx = try regexFixtures() else { return }
        var ok = 0, refused = 0, icuRefused = 0, bad = 0, checks = 0, tpSame = 0
        var why: [String: Int] = [:]
        for c in fx.cases {
            var dialect = RX2ICU.Dialect.regexp2
            var tr = RX2ICU.translate(c.re.p)
            if c.re2 == true, let t = RX2ICU.translate(c.re.p, dialect: .re2).0 { tr = (t, ""); dialect = .re2 }
            guard let t = tr.0 else { refused += 1; why[tr.1, default: 0] += 1; continue }
            let r = RWRegex(RWSnapRegex(p: c.re.p, ok: true, icu: t.icu, slots: t.identity ? nil : t.slots, lit: nil, fold: nil,
                                        groups: t.groups, named: nil, empty: nil))
            guard r.compiles else { icuRefused += 1; continue }
            var tp: RWSnapTemplate?
            if dialect == .regexp2, c.repl == true, let text = c.t {
                let (mine, tperr) = RX2ICU.template(text, t)
                if let g = c.tp, let m = mine, !tperr {
                    if m.r == g.r && (m.s ?? []) == (g.s ?? []) { tpSame += 1 } else if bad < 20 {
                        XCTFail("template \(c.re.p) / \(text): regexp2 \(g.r) \(g.s ?? []), RX2ICU \(m.r) \(m.s ?? [])")
                    }
                }
                tp = tperr ? nil : mine
            }
            var caseBad = false
            for i in c.in {
                checks += 1
                let m = r.match(i.s)
                if m == .unknown || (m == .yes) != i.m {
                    caseBad = true
                    if bad < 20 { XCTFail("match \(c.re.p) → \(t.icu) on \(i.s.debugDescription): expected \(i.m), RX2ICU \(m)") }
                }
                if let tp = tp {
                    let f = r.replaceFirst(i.s, tp), a = r.replaceAll(i.s, tp)
                    if f != i.f || a != i.a {
                        caseBad = true
                        if bad < 20 { XCTFail("replace \(c.re.p) → \(t.icu) / \(c.t ?? "") on \(i.s.debugDescription): regexp2 \(i.f.debugDescription) \(i.a.debugDescription), RX2ICU \(f.debugDescription) \(a.debugDescription)") }
                    }
                }
            }
            if caseBad { bad += 1 } else { ok += 1 }
        }
        let top = why.sorted { $0.value > $1.value }.prefix(8).map { "\($0.key) \($0.value)" }.joined(separator: ", ")
        print("NativeMitmRegex RX2ICU (passed filter): \(fx.cases.count) patterns, \(checks) inputs; identical \(ok), refused \(refused) (\(top)), ICU refused \(icuRefused), different \(bad), templates identical \(tpSame)")
        XCTAssertEqual(bad, 0)
        XCTAssertGreaterThan(ok, fx.cases.count * 9 / 10)
    }

    /// regexp2 forms the ASCII-set translation refused, run natively by RX2ICU with regexp2's meaning.
    func testRX2ICUFeatures() {
        func rx(_ p: String) -> RWRegex? {
            guard let s = RX2ICU.snapRegex(p) else { return nil }
            let r = RWRegex(s)
            return r.compiles ? r : nil
        }
        func all(_ p: String, _ repl: String, _ s: String) -> String? {
            guard let t = RX2ICU.translate(p).0, let r = rx(p), let tp = RX2ICU.template(repl, t).0 else { return nil }
            return r.replaceAll(s, tp)
        }
        // named groups: regexp2 numbers unnamed groups first, then named ones
        XCTAssertEqual(all(#"(?<y>\d{4})-(\d\d)"#, "$1|${y}|$2", "2026-10"), "10|2026|2026")
        XCTAssertEqual(RX2ICU.translate(#"(?<y>\d{4})-(\d\d)"#).0?.slots, [0, 2, 1])
        // \k<name> and multi-digit back-references
        XCTAssertEqual(rx(#"(?<q>["'])x\k<q>"#)?.match("'x'"), .yes)
        XCTAssertEqual(rx(#"(?<q>["'])x\k<q>"#)?.match("'x\""), .no)
        XCTAssertEqual(rx(#"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\10"#)?.match("abcdefghijj"), .yes)
        // x mode, comments
        XCTAssertEqual(rx("(?x) a  b # comment\n c (?#more)")?.match("abc"), .yes)
        // Unicode classes: \w and \b see CJK as word characters, . matches any non-\n scalar
        XCTAssertEqual(all(#"\w+"#, "X", "中文abc-1"), "X-X")
        XCTAssertEqual(rx(#"\bad\b"#)?.match("中ad"), .no)
        XCTAssertEqual(rx(#"\bad\b"#)?.match("中 ad"), .yes)
        XCTAssertEqual(rx("a.b")?.match("a中b"), .yes)
        XCTAssertEqual(rx("a.b")?.match("a\nb"), .no)
        XCTAssertEqual(rx("(?s)a.b")?.match("a\nb"), .yes)
        XCTAssertEqual(all(#"[\p{L}\d]+"#, "X", "中1-"), "X-")
        // $ is the end or before a final \n; (?m) every line end
        XCTAssertEqual(all("ad$", "X", "ad\nad\n"), "ad\nX\n")
        XCTAssertEqual(all("(?m)^ad$", "X", "ad\nad\n"), "X\nX\n")
        // look-behind, look-ahead, atomic group, lazy
        XCTAssertEqual(all(#"(?<=\$)\d+"#, "N", "$12 34"), "$N 34")
        XCTAssertEqual(all("foo(?=bar)", "X", "foobar foobaz"), "Xbar foobaz")
        XCTAssertEqual(rx("(?>a+)ab")?.match("aaab"), .no)
        XCTAssertEqual(all("<.+?>", "T", "<a><b>"), "TT")
        // case-insensitive ASCII sets
        XCTAssertEqual(all("(?i)abc", "x", "ABC aBc"), "x x")
        XCTAssertEqual(all("(?i)[a-c]+", "x", "ABCd"), "xd")
        // class subtraction (.NET)
        XCTAssertEqual(all("[a-z-[aeiou]]+", "_", "hello"), "_e_o")
        // replacement forms: $0, ${1}0, $10 without group 10 is literal, $$, $&
        XCTAssertEqual(all("(a)", "[$0|${1}0|$10|$$|$&]", "a"), "[a|a0|$10|$|a]")
        // empty matches are walked like regexp2
        XCTAssertEqual(all("x*", "-", "ab"), "-a-b-")
        // \_ is a literal _ (the old core compiled such patterns with the escape dropped)
        XCTAssertEqual(rx(#"a\_b"#)?.match("a_b"), .yes)
        // what stays refused
        for p in ["(?(x)y|z)", #"\G"#, "(?<a-b>x)", "(?<n>a)(?<n>b)", "(?<1>a)", "[[:alpha:]]", #"\p{IsGreek}"#, "(?<=(a))b", "(a*)*b"] {
            XCTAssertNil(RX2ICU.translate(p).0, p)
        }
        // an untranslatable-by-snapshot pattern (ok false) now runs through RX2ICU in the tunnel
        let fb = RWRegex(RWSnapRegex(p: "(?x) ^https://a\\.com/ (\\d+)", ok: false, lit: nil, fold: nil, groups: 0, named: nil, empty: nil))
        XCTAssertEqual(fb.match("https://a.com/12"), .yes)
        XCTAssertEqual(fb.match("https://a.com/x"), .no)
        // and the app's snapshot exports it portable, with a template in RX2ICU's numbering
        let sr = NCRewriteICU.snapRegex(pattern: "(?x) ^https://a\\.com/ (?<id>\\d+) / (\\w+)", re2: false, replace: true)
        XCTAssertTrue(sr.ok)
        let (tp, tperr) = NCRewriteICU.snapTemplate(pattern: "(?x) ^https://a\\.com/ (?<id>\\d+) / (\\w+)", repl: "https://b.com/${id}/$1")
        XCTAssertFalse(tperr)
        XCTAssertEqual(tp?.r, [0, -7, 1, -6])
    }

    /// lane regexp2: body ops on regexp2's path / the old core's RE2 path exported as source run natively.
    func testBodySourceOps() {
        func rule(_ ops: String) -> NativeBodyRule? {
            let json = #"{"i":0,"kind":"body","phase":"response","re":{"p":"x","ok":true,"icu":"x","groups":0},"body":["# + ops + #"],"bodyOK":true}"#
            guard let r = try? JSONDecoder().decode(RWSnapRule.self, from: Data(json.utf8)) else { return nil }
            return NativeBodyRule(r)
        }
        func run(_ r: NativeBodyRule?, _ s: String) -> String? {
            guard let r = r, case .body(let d) = r.apply(Data(s.utf8)) else { return nil }
            return String(decoding: d, as: UTF8.self)
        }
        XCTAssertEqual(run(rule(#"{"p":"(?<=id=)\\d+","repl":"0"}"#), "id=12&x=3 中文"), "id=0&x=3 中文")
        XCTAssertEqual(run(rule(#"{"p":"\\bad\\b","repl":"X"}"#), "中ad ad,"), "中ad X,")
        XCTAssertEqual(run(rule(#"{"p":"x*","repl":"-"}"#), "ab"), "-a-b-")
        XCTAssertEqual(run(rule(#"{"p":"(?<k>\\w+)=(\\d)","repl":"$1:${k}"}"#), "a=1"), "1:a")
        XCTAssertEqual(run(rule(#"{"p":"(a+)+b","re2":true,"parts":[{"l":"X","g":-1}]}"#), "aaab ab"), "X X")
        XCTAssertNil(rule(#"{"p":"(?(x)y)","repl":"X"}"#), "untranslatable: the rule stays skipped")
    }

    /// net/url, net, net/http pieces (NetSemantics.swift) against the old core's own answers.
    func testNetSemantics() throws {
        guard let fx = try regexFixtures() else { return }
        XCTAssertEqual(NetURL.pathEsc.map { Int($0) }, fx.pathEsc.map { Int(UInt32(truncatingIfNeeded: $0)) })
        XCTAssertEqual(NetURL.queryEsc.map { Int($0) }, fx.queryEsc.map { Int(UInt32(truncatingIfNeeded: $0)) })
        for t in fx.net.targets {
            let got = NetURL.parseRequestURI(t.t)
            if t.err == true {
                XCTAssertNil(got, "target \(t.t.debugDescription): the fixture errors")
                continue
            }
            guard let g = got else { continue } // refused: the old core decided (allowed)
            XCTAssertEqual(g.path, t.path ?? "", t.t)
            XCTAssertEqual(g.query, t.query ?? "", t.t)
            XCTAssertEqual(g.forceQuery, t.force ?? false, t.t)
            XCTAssertEqual(g.host ?? "", t.host ?? "", t.t)
        }
        for q in fx.net.queries { XCTAssertEqual(NetURL.cleanQuery(q[0]), q[1], q[0]) }
        for h in fx.net.hosts {
            let got = NetURL.splitHostPort(h.hp)
            if h.err == true { XCTAssertNil(got, h.hp); continue }
            XCTAssertEqual(got?.0, h.host ?? "", h.hp)
            XCTAssertEqual(got?.1, h.port ?? "", h.hp)
        }
        for code in 0..<1000 { XCTAssertEqual(NetStatus.text[code], fx.net.status[String(code)], "status \(code)") }
        for s in fx.net.sniff {
            let d = Data(base64Encoded: s[0]) ?? Data()
            XCTAssertEqual(NetSniff.detect(d), s[1], s[0])
        }
    }

    private func rx(_ p: String, icu: String, groups: Int, slots: [Int]? = nil) -> RWRegex {
        RWRegex(RWSnapRegex(p: p, ok: true, icu: icu, slots: slots, lit: nil, fold: nil, groups: groups, named: nil, empty: false))
    }

    func testTemplateProgram() {
        // (a)(?<n>b)(c): regexp2 numbers the named group last — slots [0,1,3,2] map slot → ICU group
        let r = rx("(a)(?<n>b)(c)", icu: "(a)(b)(c)", groups: 3, slots: [0, 1, 3, 2])
        // "[$1|$2|${n}|$+|$`|$'|$$]": literals, slot 1, slot 2 (= ICU 3), slot 3 (= ICU 2), last group, before, after
        let tp = RWSnapTemplate(s: ["[", "|", "|", "|", "|", "|", "|$]"], r: [0, -6, 1, -7, 2, -8, 3, -2, 4, -4, 5, -3, 6])
        XCTAssertEqual(r.replaceFirst("xabcy", tp), "x[a|c|b|b|x|y|$]y")
        XCTAssertEqual(r.replaceAll("abcabc", RWSnapTemplate(s: ["-"], r: [0])), "--")
        // non-ASCII input: the ICU translation runs on it (RWRegex.lenient, gap C5)
        XCTAssertEqual(r.replaceFirst("é abc", tp), "é [a|c|b|b|é ||$]", "non-ASCII input: native")
        // empty matches are walked like regexp2 does
        let e = rx("x*", icu: "x*", groups: 0)
        XCTAssertEqual(e.replaceAll("axb", RWSnapTemplate(s: ["-"], r: [0])), "-a--b-")
    }

    func testLiteralPrefilterSkipsRegex() {
        // not translatable, but the literal proves it cannot match: decided without the old core
        let r = RWRegex(RWSnapRegex(p: "^https://a\\.com/(?(x)y)", ok: false, lit: "https://a.com/", fold: nil, groups: 0, named: nil, empty: false))
        if case .no = r.match("https://b.com/x") {} else { XCTFail("literal should rule it out") }
        if case .unknown = r.match("https://a.com/x") {} else { XCTFail("untranslatable pattern must be unknown") }
        let f = rx("(?i)^https://A\\.com/X", icu: "\\Ahttps\\x3a\\x2f\\x2f[Aa]\\x2e[Cc][Oo][Mm]\\x2f[Xx]", groups: 0)
        if case .yes = f.match("https://A.COM/x") {} else { XCTFail("explicit case sets") }
    }

    /// Map Local from a file: read where the old core reads it, Content-Type from the extension or sniffed, a missing local
    /// file serves an empty body (the old core's read error), a missing / stale remote one goes to the old core, a large one is served
    /// whole with Content-Length and no captured body.
    func testMapLocalFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rwfile-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let small = dir.appendingPathComponent("a.json"), sniff = dir.appendingPathComponent("blob"), big = dir.appendingPathComponent("big.bin")
        try Data("{\"a\":1}".utf8).write(to: small)
        try Data("<html>x".utf8).write(to: sniff)
        try Data(repeating: 0x41, count: 600 << 10).write(to: big)
        func snap(_ rules: String) -> NativeRewriteEngine {
            NativeRewriteEngine(json: #"{"version":1,"gen":3,"on":true,"capture":true,"inc":[],"exc":[],"rules":["# + rules + "]}")!
        }
        func rule(_ i: Int, _ name: String, file: String) -> String {
            #"{"i":\#(i),"kind":"maplocal","phase":"request","re":{"p":"^https://f\\.com/\#(name)$","ok":true,"icu":"\\Ahttps\\x3a\\x2f\\x2ff\\x2ecom\\x2f\#(name)(?=\\x0a?\\z)","groups":0},"local":{"status":200,"headers":[],"body":null,"file":\#(file)}}"#
        }
        let e = snap([
            rule(0, "s", file: #"{"path":"\#(small.path)","ctype":"application/json","large":524288}"#),
            rule(1, "n", file: #"{"path":"\#(sniff.path)","large":524288}"#),
            rule(2, "m", file: #"{"path":"\#(dir.path)/missing.txt","ctype":"text/plain; charset=utf-8","large":524288}"#),
            rule(3, "r", file: #"{"path":"\#(dir.path)/missing-remote","remote":true,"maxAge":86400,"large":524288}"#),
            rule(4, "b", file: #"{"path":"\#(big.path)","large":524288}"#),
        ].joined(separator: ","))
        func q(_ t: String) -> RewriteRequest {
            RewriteRequest(method: "GET", target: t, host: "f.com", headers: [], length: 0, connHost: "f.com", connPort: 443)
        }
        guard case .local(let s) = e.decide(q("/s")) else { return XCTFail("small file") }
        XCTAssertEqual(s.headers, [["Content-Type", "application/json"]])
        XCTAssertEqual(s.body, Data("{\"a\":1}".utf8))
        XCTAssertEqual(s.length, 7)
        guard case .local(let n) = e.decide(q("/n")) else { return XCTFail("sniffed file") }
        XCTAssertEqual(n.headers, [["Content-Type", "text/html; charset=utf-8"]])
        guard case .local(let m) = e.decide(q("/m")) else { return XCTFail("missing local file") }
        XCTAssertEqual(m.status, 200)
        XCTAssertEqual(m.length, 0)
        XCTAssertEqual(m.bodyMode, .none)
        if case .deferred = e.decide(q("/r")) {} else { XCTFail("missing remote file: deferred") }
        guard case .local(let b) = e.decide(q("/b")) else { return XCTFail("large file") }
        XCTAssertEqual(b.length, Int64(600 << 10))
        XCTAssertEqual(b.body.count, 600 << 10)
        XCTAssertEqual(b.headers, [["Content-Type", "text/plain; charset=utf-8"]])
        XCTAssertEqual(b.logLen, Int64(600 << 10))
        XCTAssertTrue(b.logNoCapture)
        XCTAssertEqual(b.log.headers, [["Content-Length", "614400"], ["Content-Type", "text/plain; charset=utf-8"]])
    }

    /// A response replace-regex on a value Swift does not run regexes on (non-ASCII) goes to the old core's header-op
    /// helper; without it the native response fails (the session then answers an error).
    func testResponseRegexFallsBackToGo() {
        let json = #"{"version":1,"gen":5,"on":true,"capture":false,"inc":[],"exc":[],"rules":[{"i":0,"kind":"header","phase":"response","re":{"p":"^https://f\\.com/","ok":true,"icu":"\\Ahttps\\x3a\\x2f\\x2ff\\x2ecom\\x2f","groups":0},"opsOK":true,"headers":[{"op":"replace-regex","name":"X-A","value":"y","re":{"p":"x","ok":true,"icu":"x","groups":0},"tp":{"s":["y"],"r":[0]}}]}]}"#
        let e = NativeRewriteEngine(json: json)!
        guard case .forward(let f) = e.decide(RewriteRequest(method: "GET", target: "/", host: "f.com", headers: [], length: 0, connHost: "f.com", connPort: 443)) else {
            return XCTFail("forward")
        }
        let ascii = e.respond(f.response, status: 200, headers: [["X-A", "axa"], ["Content-Length", "0"]], length: 0, method: "GET")
        XCTAssertEqual(ascii?.headers, [["X-A", "aya"]])
        if RWRegex.lenient {
            // native-only: the regex runs natively on the non-ASCII value; the old core's header-op helper is never consulted
            var asked = false
            e.headerOpsFallback = { _, _, _, _ in asked = true; return nil }
            let native = e.respond(f.response, status: 200, headers: [["X-A", "éx"]], length: 0, method: "GET")
            XCTAssertEqual(native?.headers, [["X-A", "éy"]])
            XCTAssertFalse(asked)
            return
        }
        XCTAssertNil(e.respond(f.response, status: 200, headers: [["X-A", "éx"]], length: 0, method: "GET"))
        var asked: (Int64, [Int], Int, [[String]])?
        e.headerOpsFallback = { gen, rules, status, headers in asked = (gen, rules, status, headers); return [["X-A", "éy"]] }
        let viaGo = e.respond(f.response, status: 200, headers: [["X-A", "éx"]], length: 0, method: "GET")
        XCTAssertEqual(viaGo?.headers, [["X-A", "éy"]])
        XCTAssertEqual(asked?.0, 5)
        XCTAssertEqual(asked?.1, [0])
        XCTAssertEqual(asked?.3, [["X-A", "éx"]])
    }

    func testHeaderCanonicalAndHop() {
        XCTAssertEqual(CanonicalHeader.canonical("x-foo-BAR"), "X-Foo-Bar")
        XCTAssertEqual(CanonicalHeader.canonical("x foo"), "x foo")
        var h = CanonicalHeader(pairs: [["connection", "keep-alive, X-Hop"], ["x-hop", "1"], ["Te", "trailers"], ["A", "1"], ["a", "2"]])
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

    override func tearDown() { NativeRewriteRuntime.override = nil; NativeScriptRuntime.override = nil }

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

    /// What the retired bridge of a request's events (the same Entry calls in the same order).
    private static func entry(_ evs: [Ev], labels: [String]) -> LogEntry? {
        guard let first = evs.first else { return nil }
        func flat(_ h: [[String]]?) -> [String: String]? {
            let m = CanonicalHeader(pairs: h ?? []).map.mapValues { $0.joined(separator: ", ") }
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

    /// Every request the native driver answers produces, through its request-log events, exactly the entry the old core's
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
        print("NativeMitmRewrite request log: \(checked) native entries identical to the fixture's, \(failed) different")
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

        // reaching flushAt sends without waiting for the delay; the JSON is what the old core decodes (base64 body, no nulls)
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
        // native-only: NativeScriptRuntime is on by default (engineSwitch) and would fetch the snapshot for scripts alone;
        // "off" here means both native switches off
        NativeRewriteRuntime.override = false
        NativeScriptRuntime.override = false
        let inner = Inner(), src = FakeSource(Self.snapJSON)
        let d = NativeRewriteDriver(inner: inner, provider: NativeRewriteProvider(source: src), recorder: nil)
        XCTAssertEqual(d.requestPhase(head: head("/ad"), conn: conn).id, 9)
        XCTAssertEqual(inner.calls, ["begin /ad"])
        XCTAssertEqual(src.fetches, 0)
    }

    func testDriverNativeLocalForwardAndDefer() {
        NativeRewriteRuntime.override = true
        NativeScriptRuntime.override = true   // native-only default (engineSwitch): response scripts run natively
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

        // native-only: a response script is no longer handed to the old core — the native script dispatcher takes the flow
        let sc = d.requestPhase(head: head("/s"), conn: conn)
        XCTAssertEqual(sc.action, .forward); XCTAssertLessThan(sc.id, 0)
        XCTAssertEqual(sc.url, "https://a.com/s")
        d.end(sc.id, sent: 0, error: "")

        XCTAssertEqual(inner.calls, [])
        XCTAssertEqual(d.liveNativeFlows, 0)
        XCTAssertEqual(d.stats.local, 2); XCTAssertEqual(d.stats.forward, 1); XCTAssertEqual(d.stats.deferred, 0)
        XCTAssertEqual(src.fetches, 1)

        // request log: one event per native decision, the forward's response and end; the script flow's forward / end
        rec.flushNow()
        let evs = Self.events(sink.batches)
        XCTAssertEqual(evs.map(\.ev), ["local", "local", "forward", "response", "end", "forward", "end"])
        XCTAssertEqual(evs[0].rules, [0]); XCTAssertEqual(evs[0].url, "https://a.com/ad"); XCTAssertEqual(evs[0].status, 200)
        XCTAssertEqual(evs[0].len, 2); XCTAssertNil(evs[0].body) // capture off
        XCTAssertEqual(evs[0].headers ?? [], [["Content-Length", "2"], ["Content-Type", "application/json"]])
        XCTAssertEqual(evs[1].rules, [1]); XCTAssertEqual(evs[1].headers ?? [], [["Content-Type", "text/plain; charset=utf-8"]]); XCTAssertEqual(evs[1].len, 5)
        XCTAssertNil(evs[2].rules); XCTAssertEqual(evs[2].host, "a.com"); XCTAssertEqual(evs[2].method, "GET"); XCTAssertEqual(evs[2].tls, true)
        XCTAssertEqual(evs[2].headers ?? [], [["User-Agent", "t"]])
        XCTAssertEqual(evs[3].rules, [2]); XCTAssertEqual(evs[3].status, 200)
        XCTAssertEqual(evs[3].headers ?? [], [["Content-Length", "3"], ["X-R", "1"]])
        XCTAssertEqual(evs[4].sent, 3); XCTAssertEqual(evs[4].resp, true); XCTAssertNil(evs[4].why)
        XCTAssertEqual(Set(evs[2...4].map(\.k)).count, 1)
        XCTAssertEqual(Set(evs[5...].map(\.k)).count, 1)
        XCTAssertEqual(Set(evs.map(\.k)).count, 4)
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

        // a reload (new generation) fetches the new snapshot once; a bad one defers everything to the old core
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
