import XCTest
@testable import Mihomo

/// feat/nc-selfcheck-2: the pure logic behind 一键自检 — startup-log parsing (the exact line formats the extension
/// writes), the config-integrity comparison (E2E: 1/1/3 vs 9/29/85 must FAIL with the numbers), node sampling,
/// rewrite probe URLs, error descriptions, memory verdict, report layout (FAILs first) and redaction of the report.
final class SelfCheckLogicTests: XCTestCase {

    // MARK: startup log

    func testCurrentSessionAndStamp() {
        let log = "=== start\n12:52:00.001 [ext] native core up (gen 1): x\n--- 上一次 ---\n12:00:00.000 [ext] old"
        XCTAssertFalse(SelfCheckLogic.currentSession(log).contains("old"))
        XCTAssertEqual(SelfCheckLogic.lastLine(log, containing: "native core up"), "native core up (gen 1): x")
        XCTAssertEqual(SelfCheckLogic.stripStamp("12:52:02.778 [warning] [delay] a: 1 ms"), "[delay] a: 1 ms")
        XCTAssertEqual(SelfCheckLogic.stripStamp("no stamp here"), "no stamp here")
    }

    func testParseCoreStats() {
        let l = "native core up (gen 2): native core (runtime): 9 proxies + 33 from 1 provider(s), 31 groups, 91 rules (2 ignored), unsupported 0, fake-ip 12 entries"
        XCTAssertEqual(SelfCheckLogic.parseCoreStats(l), .init(proxies: 9, providerNodes: 33, providers: 1, groups: 31, rules: 91, ignoredRules: 2))
        XCTAssertNil(SelfCheckLogic.parseCoreStats("native core: not loaded"))
    }

    func testParseMitmScriptTaskLines() {
        let rw = SelfCheckLogic.parseRewriteSnapshot("native rewrite snapshot: 288 rules, 312 MitM hosts, on true")
        XCTAssertEqual(rw?.rules, 288); XCTAssertEqual(rw?.hosts, 312); XCTAssertEqual(rw?.on, true)
        let sc = SelfCheckLogic.parseScripts("native scripts: 125 script rule(s), 3 unloadable; prelude ok; JSC interruptible")
        XCTAssertEqual(sc?.scripts, 125); XCTAssertEqual(sc?.unloadable, 3)
        XCTAssertEqual(SelfCheckLogic.parseTasks("native tasks: 11 task(s), 2 panel(s)"), 11)
    }

    func testParsePlaneCounters() {
        let l = "diagnostics: native: packets in 109, tcp accepted 0, sessions 0, dns queries 4, dns replies 4, dns no-upstream 0, dns failed 0, udp dropped 0, relay ok 0, direct 0, relay failed 0, rejected 0, udp opened 2, mitm decrypted 0, mitm passthrough 0, mitm fallback 0 (front DOWN), fake-ip unmapped reset 1; controller: accepted 90, routed 90"
        let c = SelfCheckLogic.parsePlaneCounters(l)
        XCTAssertEqual(c["packets in"], 109)
        XCTAssertEqual(c["tcp accepted"], 0)
        XCTAssertEqual(c["dns replies"], 4)
        XCTAssertEqual(c["dns no-upstream"], 0)
        XCTAssertEqual(c["udp opened"], 2)
        XCTAssertEqual(c["mitm fallback"], 0)
        XCTAssertEqual(c["fake-ip unmapped reset"], 1)
        XCTAssertNil(c["accepted"], "controller counters are not data-plane counters")
    }

    func testRuleSetFailures() {
        let log = """
        12:00:00.000 [ext] rule set: fetch failed raw.example.com/…/ads.list — HTTP 404
        12:00:01.000 [ext] rule set: fetch failed cdn.example.net/…/cn.yaml — A server with the specified hostname could not be found.
        12:00:02.000 [ext] rule set: fetch failed raw.example.com/…/ads.list — The request timed out.
        """
        let f = SelfCheckLogic.ruleSetFailures(log)
        XCTAssertEqual(f.map(\.name), ["raw.example.com/…/ads.list", "cdn.example.net/…/cn.yaml"])
        XCTAssertEqual(f[0].reason, "The request timed out.")
    }

    // MARK: integrity

    func testCompareFlagsTheE2ELoss() {
        let m: [SelfCheckLogic.Metric] = [
            .init(name: "节点", layers: [("配置", 9), ("运行时", 1), ("内核", 1)]),
            .init(name: "策略组", layers: [("配置", 29), ("运行时", 1), ("内核", 1)]),
            .init(name: "规则", layers: [("配置", 85), ("运行时", 3), ("内核", 3)]),
        ]
        let c = SelfCheckLogic.compare(m)
        XCTAssertEqual(c.lost.count, 3)
        XCTAssertEqual(c.lost[0], "节点：配置 9 → 运行时 1 → 内核 1")
        XCTAssertTrue(c.lost[2].contains("85") && c.lost[2].contains("3"))
    }

    func testCompareAllowsExtrasMissingLayersReferencesAndTolerance() {
        let m: [SelfCheckLogic.Metric] = [
            .init(name: "规则", layers: [("配置", 85), ("App", 85), ("运行时", 88), ("内核", nil)]),
            .init(name: "重写", layers: [("模块", 300), ("运行时", 288), ("内核", 288)], strictFrom: 1),
            .init(name: "订阅节点", layers: [("App", 33), ("内核", 30)], tolerance: 0.5),
        ]
        let c = SelfCheckLogic.compare(m)
        XCTAssertTrue(c.lost.isEmpty, "\(c.lost)")
        XCTAssertEqual(c.table.first, "规则：配置 85 → App 85 → 运行时 88")
        // a reference layer still catches "had some, now none"
        XCTAssertEqual(SelfCheckLogic.compare([.init(name: "重写", layers: [("模块", 300), ("运行时", 0)], strictFrom: 1)]).lost.count, 1)
        // strict part after the reference catches any drop
        XCTAssertEqual(SelfCheckLogic.compare([.init(name: "重写", layers: [("模块", 300), ("运行时", 288), ("内核", 200)], strictFrom: 1)]).lost.count, 1)
        XCTAssertEqual(SelfCheckLogic.compare([.init(name: "订阅节点", layers: [("App", 33), ("内核", 10)], tolerance: 0.5)]).lost.count, 1)
    }

    // MARK: delay

    func testSamplePrefersTrickyNames() {
        let names = ["HK 01", "plain", "东京 ORA JP01 [CF V6]", "🇭🇰 Alice HK CF CDN", "a/b", "x", "y"]
        let s = SelfCheckLogic.sample(names, max: 4)
        XCTAssertEqual(s.count, 4)
        XCTAssertEqual(s[0], "a/b")
        XCTAssertEqual(s[1], "🇭🇰 Alice HK CF CDN")
        XCTAssertEqual(s[2], "东京 ORA JP01 [CF V6]")
        XCTAssertEqual(SelfCheckLogic.sample(["p", "q"], max: 5), ["p", "q"])
        XCTAssertTrue(SelfCheckLogic.isTricky("A&B"))
        XCTAssertFalse(SelfCheckLogic.isTricky("HK01"))
    }

    func testDelayLineAndStage() {
        let p = ["[delay] other: 12 ms", "[delay] 东京 ORA JP01 [CF V6]: timeout at stage ws after 5000 ms | dns 0 ms · tcp 310 ms",
                 "[delay] 东京 ORA JP01 [CF V6]: failed at stage tls (handshake)"]
        let t = SelfCheckLogic.delayLine(for: "东京 ORA JP01 [CF V6]", in: p)
        XCTAssertEqual(t, "failed at stage tls (handshake)")
        XCTAssertEqual(SelfCheckLogic.delayStage(t!), "tls")
        XCTAssertEqual(SelfCheckLogic.delayStage("timeout at stage ws after 5000 ms"), "ws")
        XCTAssertNil(SelfCheckLogic.delayStage("245 ms (unified) | dns 1 ms"))
        XCTAssertNil(SelfCheckLogic.delayLine(for: "missing", in: p))
    }

    // MARK: rewrite

    func testProbeURL() {
        XCTAssertEqual(SelfCheckLogic.probeURL(fromPattern: #"^https?:\/\/api\.example\.com\/ad\/v1"#)?.absoluteString, "https://api.example.com/ad/v1")
        XCTAssertEqual(SelfCheckLogic.probeURL(fromPattern: #"^https://ads\.example\.com/x.+"#)?.absoluteString, "https://ads.example.com/x")
        XCTAssertEqual(SelfCheckLogic.probeURL(fromPattern: #"^https?://ads.example.com"#)?.absoluteString, "https://ads.example.com/")
        XCTAssertNil(SelfCheckLogic.probeURL(fromPattern: #"^https?://(www|m)\.example\.com/"#), "host with a group")
        XCTAssertNil(SelfCheckLogic.probeURL(fromPattern: #"^https?://.+\.example\.com/"#))
        XCTAssertNil(SelfCheckLogic.probeURL(fromPattern: #"^http://ads\.example\.com/"#), "plain http is not probed")
        XCTAssertNil(SelfCheckLogic.probeURL(fromPattern: #"^https?://1\.2\.3\.4/x"#), "bare IP")
        XCTAssertTrue(SelfCheckLogic.isPlainHTTPOnly(#"^http://ads\.example\.com/"#))
        XCTAssertFalse(SelfCheckLogic.isPlainHTTPOnly(#"^https?://ads\.example\.com/"#))
    }

    func testHostMatches() {
        XCTAssertTrue(SelfCheckLogic.hostMatches("*.example.com", "api.example.com"))
        XCTAssertTrue(SelfCheckLogic.hostMatches("api.example.com", "API.example.com"))
        XCTAssertTrue(SelfCheckLogic.hostMatches("api.example.com:443", "api.example.com"))
        XCTAssertFalse(SelfCheckLogic.hostMatches("-api.example.com", "api.example.com"))
        XCTAssertFalse(SelfCheckLogic.hostMatches("*.example.com", "example.org"))
    }

    // MARK: errors / urls

    func testShortURLHidesQueryAndUser() {
        XCTAssertEqual(SelfCheckLogic.shortURL("https://user:pw@raw.example.com/a/b/rules.list?token=SECRET"), "raw.example.com/…/rules.list")
        XCTAssertEqual(SelfCheckLogic.shortURL("https://example.com"), "example.com")
    }

    func testDescribeNetworkErrors() {
        let dns = NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotFindHost)
        XCTAssertTrue(SelfCheckLogic.describe(dns).contains("NSURLErrorDomain -1003"))
        XCTAssertTrue(SelfCheckLogic.describe(dns).contains("DNS"))
        let tls = NSError(domain: NSURLErrorDomain, code: NSURLErrorSecureConnectionFailed)
        XCTAssertTrue(SelfCheckLogic.describe(tls).contains("TLS"))
        let to = NSError(domain: NSURLErrorDomain, code: NSURLErrorTimedOut)
        XCTAssertTrue(SelfCheckLogic.describe(to).contains("-1001"))
    }

    // MARK: memory

    func testMemoryVerdict() {
        let mb = 1_048_576.0
        let ok = SelfCheckLogic.memorySample(try! JSONSerialization.data(withJSONObject: ["footprint": 20 * mb, "peak": 24 * mb, "available": 30 * mb]), label: "启动后")
        XCTAssertEqual(ok?.footprint, 20)
        let v = SelfCheckLogic.memoryVerdict([ok!])
        XCTAssertTrue(v.ok, v.detail)
        XCTAssertTrue(v.detail.contains("50.0"), v.detail)
        let tight = SelfCheckLogic.MemorySample(label: "访问", footprint: 47, peak: 47, available: 3)
        XCTAssertFalse(SelfCheckLogic.memoryVerdict([ok!, tight]).ok)
        XCTAssertNil(SelfCheckLogic.memorySample(nil, label: "x"))
    }

    // MARK: report + redaction

    func testReportListsFailsFirstThenKnown() {
        let r = SelfCheckLogic.report(header: "Tern 一键自检", summary: "通过 1 · 失败 1 · 已知 1 · 跳过 0", steps: [
            .init(mark: "PASS", title: "A", detail: "fine"),
            .init(mark: "KNOWN", title: "HTTP", detail: "已知缺口：明文\nmore"),
            .init(mark: "FAIL", title: "完整性", detail: "数量对不上：节点：配置 9 → 运行时 1\nsecond line"),
        ])
        let lines = r.components(separatedBy: "\n")
        let failIdx = lines.firstIndex { $0.hasPrefix("FAIL 完整性：数量对不上：节点：配置 9 → 运行时 1") }
        let knownIdx = lines.firstIndex { $0.hasPrefix("KNOWN HTTP：已知缺口：明文") }
        let detailIdx = lines.firstIndex { $0 == "[PASS] A" }
        XCTAssertNotNil(failIdx); XCTAssertNotNil(knownIdx); XCTAssertNotNil(detailIdx)
        XCTAssertLessThan(failIdx!, knownIdx!)
        XCTAssertLessThan(knownIdx!, detailIdx!)
        XCTAssertFalse(lines[failIdx!].contains("second line"), "one-line cause")
        XCTAssertTrue(r.contains("    second line"), "full detail kept below")
    }

    func testReportIsRedacted() {
        let r = DiagnosticRedactor()
        r.remember("my-secret-server.example.net")
        let text = r.text("[delay] HK: timeout at stage tls | dns 3 ms (→ 104.21.33.7) via my-secret-server.example.net, sub https://sub.example.com/link?token=abcdef123456")
        XCTAssertFalse(text.contains("my-secret-server"))
        XCTAssertFalse(text.contains("104.21.33.7"))
        XCTAssertTrue(text.contains("104.21.x.x"))
        XCTAssertFalse(text.contains("abcdef123456"))
    }
}
