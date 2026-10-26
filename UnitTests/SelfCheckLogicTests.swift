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
        XCTAssertEqual(SelfCheckLogic.parseCoreStats(l), SelfCheckLogic.CoreCounts(proxies: 9, providerNodes: 33, providers: 1, groups: 31, rules: 91, ignoredRules: 2))
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

    // MARK: CA signature (after fix/nc-rsa-ca)

    /// openssl req -x509 (P-256 / RSA 2048) self-signed test certificates — no private key in the repo.
    static let ecCert = "MIIBjTCCATOgAwIBAgIUbK3RlrbGppVTQXB9X+Bce9TzvE8wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRU2VsZkNoZWNrIFRlc3QgRUMwHhcNMjYxMDI2MDYzNzA0WhcNMzYxMDIzMDYzNzA0WjAcMRowGAYDVQQDDBFTZWxmQ2hlY2sgVGVzdCBFQzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJSuBUXZY0ydjDcDcuJ5D0Ud44XLYer1OsY2ECbirwQRfhNcnRXcrDll5r6BJb6k+QV5bHr6RrHmOYAs7+9KPcCjUzBRMB0GA1UdDgQWBBQ3M/g7L5lsOqJp1dggwoiA/PFHvTAfBgNVHSMEGDAWgBQ3M/g7L5lsOqJp1dggwoiA/PFHvTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCICiYgQa0Ou7gAvBc/+qkP0/Jy6eY7ULVV1dudwsNbdoHAiEArN9Jw4fEZbz33O5jcDHqODOduYyWOBNGPiAo6M1E/6k="
    static let rsaCert = "MIIDGzCCAgOgAwIBAgIURYzLyn+GnCVoOlnV2Oc8/dwpFC8wDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAwwSU2VsZkNoZWNrIFRlc3QgUlNBMB4XDTI2MTAyNjA2MzcwNFoXDTM2MTAyMzA2MzcwNFowHTEbMBkGA1UEAwwSU2VsZkNoZWNrIFRlc3QgUlNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApujKauTfKWv778Mg2D7+egXq8oUAwQYYH/hX3ihvRrpZKQjriD+WIU2F01vT/UJBo9FY4vln596FVo0noQpK0p/a0A6MxM4/jbg5k2q8LtUju05YDhcsMeFHMD2qa5Uob6hKzMvUTtnEiAXSEGBkHrlHEXpz15sWkLgXJhb+t7Yteq27T2bgUQI89WaXX/Nf3w99S2E2NzD9yUIymCVHyCe4KJyA/jkgr9KNVZx9pL1V/Iyj69DHMlPv3GefX+154YyCJnc4ny0OK3by6/eHSjBK6RtiYZdHi3u2KYN0rHmfiHqzFex/iRcM2OheSNqEpAXfbCmLGnAdxaxZpH4/WQIDAQABo1MwUTAdBgNVHQ4EFgQUzo0WN25MAatB1JKrfmI5K7HBTr8wHwYDVR0jBBgwFoAUzo0WN25MAatB1JKrfmI5K7HBTr8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHgKXnPHhPaL3yWvCToWVQ1I7Wvbd+5ycpgAGKqqi5QMxeVraMjq6Mpoz6pXJoT2QO9X3uU7PutBNnDwZidQRW93Dsn/fdu8GiHyPTyWGUqbdP9VUzDE/PtsKTeZ2jDt699AI87/A3RLfLLuIJ2GlzqY72Qqys6DswyCe9f+qwqjFihrbMPY6CfzCz3I2uUzZrwdaihXhzSrFCV0qMCldyhHHO0B4kxoAXr1kU9oYZTTN4RtpPLtD8ip5iJEGYsOBfcPwKK2tQkTyHb7Gol+Ud/Fqth81rprNqJR07G0WtisWUSGjyy4kCuiiobehrVojAuJu+Fh+Q/Z2ob3FioVq3A=="

    func testSelfSignatureVerifies() {
        for (name, b64) in [("EC", Self.ecCert), ("RSA", Self.rsaCert)] {
            let der = Data(base64Encoded: b64)!
            let r = SelfCheckLogic.verifySelfSignature(der)
            XCTAssertEqual(r.ok, true, "\(name): \(r.why)")
        }
        XCTAssertEqual(SelfCheckLogic.certSignatureParts(Data(base64Encoded: Self.ecCert)!)?.algorithmName, "ecdsa-with-SHA256")
        XCTAssertEqual(SelfCheckLogic.certSignatureParts(Data(base64Encoded: Self.rsaCert)!)?.algorithmName, "sha256WithRSA")
    }

    func testBadSelfSignatureIsCaught() {
        for b64 in [Self.ecCert, Self.rsaCert] {
            var der = [UInt8](Data(base64Encoded: b64)!)
            der[der.count - 2] ^= 0x5a // inside the signature value
            XCTAssertNotEqual(SelfCheckLogic.verifySelfSignature(Data(der)).ok, true)
        }
        XCTAssertNil(SelfCheckLogic.verifySelfSignature(Data([0x30, 0x03, 0x02, 0x01, 0x00])).ok)
    }

    // MARK: build 419 feedback

    func testDelayFailuresGroupReasonsByNodeCount() {
        let p = [
            "[delay] 🇨🇳 SZ CN: failed at stage tls (-9808: 错误的证书格式) | dial 391 ms · connect 391 ms",
            "[delay] 🇯🇵 东京ORA JP02 CFT [ORA V6]: failed at stage tls (-9824: 握手失败) | dial 537 ms · connect 537 ms",
            "[delay] 🇯🇵 东京ORA JP01 CFT [CF V6]: failed at stage tls (-9824: 握手失败) | dial 556 ms · connect 556 ms",
            "[delay] 土耳其V6落地: failed at stage ws (handshake failed: ws upgrade refused) | dial 763 ms · dns 1 ms (expired cache, 13 addr → [2606:4700::1]) · tcp 145 ms",
            "[delay] 印度V6落地: failed at stage ws (handshake failed: ws upgrade refused) | dial 765 ms · tls 167 ms (rtt 164 ms)",
            "[delay] 印度V6落地: failed at stage ws (handshake failed: ws upgrade refused) | dial 700 ms",
            "[delay] 美国V6落地: failed at stage ws (handshake failed: ws upgrade refused) | dial 765 ms",
            "[delay] HK CF CDN: timeout at stage request after 2000 ms | dial 1909 ms · dns 10 ms (cache, 3 addr)",
            "[delay] a/b: not in the running config (404), not tested",
            "[delay] Proxy: 137 ms (unified) | dial 756 ms",
            "[TCP] www.gstatic.com:443 rule MATCH → Proxy",
        ]
        let f = SelfCheckLogic.delayFailures(p)
        XCTAssertEqual(f.first?.stage, "ws")
        XCTAssertEqual(f.first?.reason, "handshake failed: ws upgrade refused")
        XCTAssertEqual(f.first?.nodes.count, 3, "distinct nodes")
        XCTAssertEqual(f[1].stage, "tls"); XCTAssertEqual(f[1].reason, "-9824: 握手失败"); XCTAssertEqual(f[1].nodes.count, 2)
        // "超时" is localized (the unit-test runner may use en): check the reason is the localized timeout word.
        XCTAssertTrue(f.contains { $0.stage == "request" && $0.reason == String(localized: "超时") }, "\(f)")
        XCTAssertTrue(f.contains { $0.stage == "route" && $0.nodes == ["a/b"] })
        XCTAssertFalse(f.contains { $0.nodes.contains("Proxy") }, "successes are not failures")
        let lines = SelfCheckLogic.delayFailureLines(f, top: 2)
        XCTAssertTrue(lines[0].hasPrefix("ws · handshake failed: ws upgrade refused"), lines[0])
        XCTAssertTrue(lines[0].contains("3"))
        XCTAssertEqual(lines.count, 3, "top 2 + 「另有」")
    }

    func testFetchDiagnosisNamesTcpAccepted0() {
        let b = SelfCheckLogic.parsePlaneCounters("diagnostics: native: packets in 75, tcp accepted 0, sessions 0, dns queries 5, dns replies 5, dns failed 0, relay ok 0, direct 0, relay failed 0, rejected 0")
        let a = SelfCheckLogic.parsePlaneCounters("diagnostics: native: packets in 90, tcp accepted 0, sessions 0, dns queries 7, dns replies 7, dns failed 0, relay ok 0, direct 0, relay failed 0, rejected 0")
        let d = SelfCheckLogic.fetchDiagnosis(before: b, after: a, tun: true)
        XCTAssertNotNil(d)
        XCTAssertTrue(d!.hasPrefix("隧道未收到 TCP 连接（tcp accepted 0"), d!)
        XCTAssertTrue(d!.contains("packets in +15"))
        XCTAssertNil(SelfCheckLogic.fetchDiagnosis(before: b, after: a, tun: false).flatMap { $0.contains("TCP 连接") ? $0 : nil })
        var ok = a; ok["tcp accepted"] = 3; ok["relay ok"] = 3
        XCTAssertNil(SelfCheckLogic.fetchDiagnosis(before: b, after: ok, tun: true))
        var relayFail = a; relayFail["tcp accepted"] = 3; relayFail["relay failed"] = 3
        XCTAssertTrue(SelfCheckLogic.fetchDiagnosis(before: b, after: relayFail, tun: true)!.contains("没有一个转发成功"))
    }

    func testMitmHostsReadFromPatField() throws {
        // nativecore-rewrite.json "inc" entries are {"pat": …} (RWSnapHost), not "host".
        let json = #"{"version":1,"on":true,"capture":false,"inc":[{"pat":"*.example.com"},{"pat":"api.example.net","port":443}],"rules":[]}"#
        let snap = try XCTUnwrap(RWSnapshot.decode(json))
        XCTAssertEqual(snap.inc?.map(\.pat), ["*.example.com", "api.example.net"])
    }
}
