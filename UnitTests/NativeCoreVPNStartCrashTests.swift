import XCTest
@testable import Mihomo

// fix/nc-vpn-start-crash (build #374): tapping 连接 with a QX / Surge / Loon module trapped in
// rx2TranslateUncached (`for s in 1...0` on a capture-free regex) while preparing the runtime, and the
// on-demand tunnel then ran on stale files ("connected, no network"). These tests pin:
//  - real-world rewrite regexes and malformed ones never trap (a failure is ok=false with a why);
//  - replacement templates keep UTF-8;
//  - the prepare markers / quarantine fingerprint / transactional runtime used to recover from a crashed prepare;
//  - modules are decoded UTF-8 first (#139 regression).

final class NCRewriteICUCrashTests: XCTestCase {

    /// Typical module patterns: every one must come back (no trap) and the common shapes must be portable.
    private let realWorld: [String] = [
        #"^https?:\/\/(www\.)?(g|google)\.cn"#,
        #"^https?://api\.m\.jd\.com/client\.action\?functionId=(start|queryMaterial)"#,
        #"^https?://ad\.example\.com/"#,                       // no capture group: the #374 crash
        #"^https?:\/\/[^/]+\/api\/v\d{1,}\/ads"#,
        #"^https?://([^/]+)/(.*)$"#,
        #"(?i)^https?://m\.Example\.com/splash"#,
        #"^https?://(?<host>[a-z0-9.]+)/x"#,
        #"\d{1,}"#,
        #"[^/]+"#,
        #"^https?://a\.com/\x41\u0042"#,
        #"^https?://a\.com/(a||b)"#,
        #"^https?://例子\.中国/广告"#,
        #"^https?://a\.com/😀/x"#,
        #"^https?://a\.com/\p{Han}+"#,
        #"(a)\1"#,
        #"(?<n>a)\k<n>"#,
        #"^https?://a\.com/(?:x|y)?z$"#,
        #"^http:\/\/www\.google\.cn"#,
    ]

    /// Malformed / unusual input: must not trap; most are simply not portable.
    private let malformed: [String] = [
        #"abc\"#,                     // trailing backslash
        #"(abc"#,                     // unbalanced (
        #"abc)"#,                     // unbalanced )
        #"[abc"#,                     // unbalanced [
        #"a{"#, #"a{1"#, #"a{,3}"#, #"{2}"#,
        #"a{99999999999999999999}"#,  // Int overflow in requiredLiteral
        #"\x"#, #"\x4"#, #"\u12"#, #"\uZZZZ"#, #"\c"#, #"\k"#, #"\k<"#, #"\p"#, #"\p{"#,
        #"a||b"#, #"|"#, #"()"#, #"(?"#, #"(?<"#, #"(?<>a)"#, #"(?<1a>a)"#, #"(?P<n>a)"#, #"(?#"#,
        #"(?i"#, #"(?z)"#, #"*a"#, #"a**"#, #"[]"#, #"[^]"#, #"[]a]"#, #"[a-[b]]"#, #"[[:alpha:]]"#,
        #"(?<n>a)(?<n>b)"#, #"\9"#, #"(a)\12"#, #"\G"#, #"$"#, #"^"#,
        "中文", "😀", "🇨🇳+", "e\u{301}", "\u{0}",
        String(repeating: "(", count: 500) + "a" + String(repeating: ")", count: 500),
        String(repeating: "a", count: 40_000),
    ]

    func testCaptureFreePatternDoesNotTrap() {
        let sr = NCRewriteICU.snapRegex(pattern: #"^https?://ad\.example\.com/"#, re2: true, replace: false)
        XCTAssertTrue(sr.ok)
        XCTAssertEqual(sr.groups, 0)
        XCTAssertNil(sr.slots)
        XCTAssertNotNil(sr.icu)
        let sr2 = NCRewriteICU.snapRegex(pattern: #"^https?://ad\.example\.com/"#, re2: false, replace: true)
        XCTAssertTrue(sr2.ok)
        XCTAssertEqual(sr2.groups, 0)
        // 302 template on a capture-free pattern (snapTemplate path of the crash stack)
        let (tp, tperr) = NCRewriteICU.snapTemplate(pattern: #"^https?://ad\.example\.com/"#, repl: "https://example.org/")
        XCTAssertFalse(tperr)
        XCTAssertEqual(tp?.s, ["https://example.org/"])
    }

    func testRealWorldPatternsNeverTrap() {
        for p in realWorld {
            for (re2, replace) in [(true, false), (false, true), (false, false)] {
                let sr = NCRewriteICU.snapRegex(pattern: p, re2: re2, replace: replace)
                XCTAssertGreaterThanOrEqual(sr.groups, 0, p)
                if sr.ok, let icu = sr.icu {
                    XCTAssertNoThrow(try NSRegularExpression(pattern: icu), "ICU text must compile: \(p) -> \(icu)")
                }
            }
            _ = NCRewriteICU.snapTemplate(pattern: p, repl: "https://b.com/$1/${2}/$$")
            _ = NCRewriteICU.snapRegex(p)
            _ = NCRewriteICU.portableRegex(p)
            _ = NCRewriteICU.requiredLiteral(p)
        }
        XCTAssertTrue(NCRewriteICU.snapRegex(#"^https?:\/\/(www\.)?(g|google)\.cn"#).ok)
        XCTAssertEqual(NCRewriteICU.snapRegex(#"^https?:\/\/(www\.)?(g|google)\.cn"#).groups, 2)
        XCTAssertTrue(NCRewriteICU.snapRegex(#"^https?://api\.m\.jd\.com/client\.action\?functionId=(start|queryMaterial)"#).ok)
        let named = NCRewriteICU.snapRegex(pattern: #"(a)(?<host>[a-z]+)(b)"#, re2: false, replace: true)
        XCTAssertTrue(named.ok)
        XCTAssertEqual(named.groups, 3)
        XCTAssertEqual(named.named, true)
        // regexp2 numbering: unnamed 1..u first, then named -> slot 3 is the named group (ICU group 2)
        XCTAssertEqual(named.slots, [0, 1, 3, 2])
        let br = NCRewriteICU.snapRegex(pattern: #"(a)\1"#, re2: false, replace: false)
        XCTAssertTrue(br.ok)
        XCTAssertTrue(br.icu?.contains(#"\1"#) == true)
    }

    func testMalformedPatternsFailInsteadOfTrapping() {
        for p in malformed {
            for (re2, replace) in [(true, false), (false, true), (false, false)] {
                let sr = NCRewriteICU.snapRegex(pattern: p, re2: re2, replace: replace)
                XCTAssertGreaterThanOrEqual(sr.groups, 0)
            }
            _ = NCRewriteICU.snapTemplate(pattern: p, repl: "$1")
            _ = NCRewriteICU.snapRegex(p)
            _ = NCRewriteICU.portableRegex(p)
            _ = NCRewriteICU.requiredLiteral(p)
        }
        for p in [#"abc\"#, #"(abc"#, #"[abc"#, #"(?<n>a)(?<n>b)"#, #"\G"#] {
            XCTAssertFalse(NCRewriteICU.snapRegex(pattern: p, re2: false, replace: true).ok, p)
        }
        let deep = String(repeating: "(", count: 500) + "a" + String(repeating: ")", count: 500)
        XCTAssertFalse(NCRewriteICU.snapRegex(pattern: deep, re2: false, replace: true).ok)
    }

    func testReplacementTemplateKeepsUTF8() {
        let (tp, tperr) = NCRewriteICU.snapTemplate(pattern: #"^https?://a\.com/(.*)"#, repl: "https://b.com/中文/😀/$1?x=é")
        XCTAssertFalse(tperr)
        XCTAssertEqual(tp?.s, ["https://b.com/中文/😀/", "?x=é"])
        XCTAssertEqual(tp?.r, [0, -6, 1])
        // "$" handling unchanged: $$ literal, unknown $ literal, trailing $ literal
        let (tp2, _) = NCRewriteICU.snapTemplate(pattern: "(a)", repl: "价$$格$x$")
        XCTAssertEqual(tp2?.s, ["价$格$x$"])
    }
}

final class NCPrepRecoveryTests: XCTestCase {
    private var home: String!

    override func setUp() {
        super.setUp()
        home = (NSTemporaryDirectory() as NSString).appendingPathComponent("nc-prep-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: home)
        super.tearDown()
    }

    func testInflightAndQuarantineMarkersRoundTrip() {
        XCTAssertNil(NCPrepMarkers.readInflight(home: home))
        let m = NCPrepMarkers.Inflight(stage: "rewrite", at: 1, build: "0.20.0 (374)", fp: "abc")
        NCPrepMarkers.writeInflight(home: home, m)
        XCTAssertEqual(NCPrepMarkers.readInflight(home: home), m)
        NCPrepMarkers.clearInflight(home: home)
        XCTAssertNil(NCPrepMarkers.readInflight(home: home))
        // a corrupt marker still reports "a prepare died"
        try? Data("{".utf8).write(to: URL(fileURLWithPath: home).appendingPathComponent(NCPrepMarkers.inflightFile))
        XCTAssertEqual(NCPrepMarkers.readInflight(home: home)?.stage, "?")

        let q = NCPrepMarkers.Quarantine(fp: "abc", build: "0.20.0 (374)", at: 2)
        NCPrepMarkers.writeQuarantine(home: home, q)
        XCTAssertEqual(NCPrepMarkers.readQuarantine(home: home), q)
        NCPrepMarkers.clearQuarantine(home: home)
        XCTAssertNil(NCPrepMarkers.readQuarantine(home: home))
    }

    func testFingerprintIsStableAndSensitive() {
        // FNV-1a 64 is process-independent (Swift's Hasher is not): fixed vector.
        XCTAssertEqual(NCPrepMarkers.fingerprint([]), "cbf29ce484222325")
        XCTAssertEqual(NCPrepMarkers.fingerprint(["a"]), NCPrepMarkers.fingerprint(["a"]))
        XCTAssertNotEqual(NCPrepMarkers.fingerprint(["ab", "c"]), NCPrepMarkers.fingerprint(["a", "bc"]))

        let cfg = NCEngineConfig()
        let rs = NCEngineRuleset()
        var r = NCEngineRule()
        r.kind = "url"
        r.pattern = #"^https?://ad\.example\.com/"#
        r.action = "reject"
        rs.rules = [r]
        let a = NativeRuntimePrep.rewriteFingerprint(cfg: cfg, rs: rs, build: "0.20.0 (374)")
        XCTAssertEqual(a, NativeRuntimePrep.rewriteFingerprint(cfg: cfg, rs: rs, build: "0.20.0 (374)"))
        // a new app build or an edited rule lifts the quarantine
        XCTAssertNotEqual(a, NativeRuntimePrep.rewriteFingerprint(cfg: cfg, rs: rs, build: "0.20.0 (375)"))
        rs.rules[0].pattern = #"^https?://ad\.example\.org/"#
        XCTAssertNotEqual(a, NativeRuntimePrep.rewriteFingerprint(cfg: cfg, rs: rs, build: "0.20.0 (374)"))
    }

    /// A prepare that dies before commit (the #374 crash) leaves the previous generation intact and its staging
    /// directory is removed by the next prepare: the tunnel never sees a partial runtime and nothing blocks.
    func testCrashedPrepareLeavesLastGoodRuntime() throws {
        let live = URL(fileURLWithPath: home)
        try Data("old-runtime".utf8).write(to: live.appendingPathComponent("nativecore-runtime.json"))
        try Data("old-rewrite".utf8).write(to: live.appendingPathComponent("nativecore-rewrite.json"))

        // "crashed" prepare: staged, never committed nor discarded
        let crashed = PrepTransaction(home: home)
        try crashed.put(Data("new-runtime".utf8), "nativecore-runtime.json")
        crashed.remove("nativecore-rewrite.json")
        XCTAssertEqual(try String(contentsOf: live.appendingPathComponent("nativecore-runtime.json"), encoding: .utf8), "old-runtime")
        XCTAssertEqual(try String(contentsOf: live.appendingPathComponent("nativecore-rewrite.json"), encoding: .utf8), "old-rewrite")
        XCTAssertTrue(FileManager.default.fileExists(atPath: crashed.stage))

        // next prepare: stale stage removed, a fresh transaction commits normally
        PrepTransaction.removeStale(home: home)
        XCTAssertFalse(FileManager.default.fileExists(atPath: crashed.stage))
        let next = PrepTransaction(home: home)
        try next.put(Data("new-runtime-2".utf8), "nativecore-runtime.json")
        next.remove("nativecore-rewrite.json")
        try next.commit()
        next.discard()
        XCTAssertEqual(try String(contentsOf: live.appendingPathComponent("nativecore-runtime.json"), encoding: .utf8), "new-runtime-2")
        XCTAssertFalse(FileManager.default.fileExists(atPath: live.appendingPathComponent("nativecore-rewrite.json").path))
        // no lock file is ever created for the prepare lock (in-process NCPathLock key only)
        XCTAssertFalse(FileManager.default.fileExists(atPath: live.appendingPathComponent(".nativecore-prepare.lock").path))
    }

    func testPrepareLockKeyIsReentrantAfterAbandonedHolder() {
        // The prepare lock is an in-process NSLock keyed by path: nothing on disk can keep a later prepare out.
        let key = (home as NSString).appendingPathComponent(".nativecore-prepare.lock")
        let first: Int = NCPathLock.shared.withLock(for: key) { 1 }
        let second: Int = NCPathLock.shared.withLock(for: key) { 2 }
        XCTAssertEqual(first + second, 3)
    }
}

final class NCModuleTextDecodingTests: XCTestCase {
    func testUTF8ModuleIsNotMojibaked() {
        let text = """
        #!name=去广告 🚫
        #!desc=中文模块
        [URL Rewrite]
        ^https?://a\\.com/x https://b.com/中文 302
        [MITM]
        hostname = %APPEND% a.com
        """
        let decoded = NCMitmBuild.moduleText(Data(text.utf8))
        XCTAssertEqual(decoded, text)
        let rs = NCEngineRuleset()
        rs.parseText(decoded, source: "去广告 🚫", args: [:])
        XCTAssertEqual(rs.name, "去广告 🚫")
        XCTAssertFalse(rs.rules.contains { $0.target.contains("ä¸") || $0.source.contains("ä¸") })
        if let r = rs.rules.first {
            XCTAssertTrue(r.target.contains("中文"), r.target)
        }
    }

    func testNonUTF8ModuleFallsBackToLatin1() {
        let data = Data([0x23, 0x21, 0x6E, 0x61, 0x6D, 0x65, 0x3D, 0xE9]) // "#!name=" + 0xE9 (invalid UTF-8)
        XCTAssertEqual(NCMitmBuild.moduleText(data), "#!name=é")
    }
}
