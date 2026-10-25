import XCTest
@testable import Mihomo

/// nc-script-runtime-verify: end-to-end verification of the script wiring
/// that #120 (registration) and #124 (tunnel execution) landed but nothing
/// had ever driven on a real chain:
///
///   config text (Surge / Loon / QX / Egern)
///     → NCEngineConfig.load + NCMitmBuild.build        (the app prep path)
///     → NCScriptManifest.export                        (real manifest)
///     → NCRewriteSnapshotBuilder.exportData            (real snapshot)
///     → NativeScriptHost.load(home:)                   (the tunnel host)
///     → NCScriptHookRunner (type=dns / type=rule) and
///       NativeRewriteDriver (MitM http-request / http-response)
///
/// No network, no DNS upstream: hook inputs are hand-built wire messages
/// and MitM flows are driven at the flow-driver layer with the real
/// pass-through inner driver. Every test installs its own temp home and
/// tearDown resets the shared host to an empty manifest, so the suites
/// around this one see the same host state as before (an empty table).
final class NativeCoreScriptRuntimeVerifyTests: XCTestCase {

    private var homes: [String] = []

    override func setUp() {
        super.setUp()
        NativeBodyStore.register()
        NativeRewriteRuntime.override = true
        NativeScriptRuntime.override = true
        resetScriptHost()
    }

    override func tearDown() {
        resetScriptHost()
        for h in homes { try? FileManager.default.removeItem(atPath: h) }
        homes = []
        NativeRewriteRuntime.override = nil
        NativeScriptRuntime.override = nil
        super.tearDown()
    }

    private func resetScriptHost() {
        let dir = NSTemporaryDirectory() + "nc-sverify-empty-" + UUID().uuidString
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        _ = NativeScriptHost.shared.load(home: dir)
        try? FileManager.default.removeItem(atPath: dir)
    }

    // MARK: - harness (production builders only)

    /// Writes a temp engine home: engine/engine.json (modules + script
    /// items + hostnames), engine/modules/<id>.txt, engine/scripts/*.
    private func makeHome(modules: [(id: String, text: String)] = [],
                          engineScripts: [String] = [],
                          hostnames: [String] = [],
                          files: [String: String]) throws -> String {
        let dir = NSTemporaryDirectory() + "nc-sverify-" + UUID().uuidString
        homes.append(dir)
        let fm = FileManager.default
        try fm.createDirectory(atPath: dir + "/engine/modules", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: dir + "/engine/scripts", withIntermediateDirectories: true)
        for (name, code) in files {
            try code.write(toFile: dir + "/engine/scripts/" + name, atomically: true, encoding: .utf8)
        }
        var engine: [String: Any] = ["enabled": true, "mitm": true]
        if !hostnames.isEmpty { engine["hostnames"] = hostnames }
        if !engineScripts.isEmpty {
            engine["scripts"] = engineScripts.map { ["id": UUID().uuidString, "enabled": true, "line": $0] }
        }
        if !modules.isEmpty {
            engine["modules"] = modules.map { ["id": $0.id, "name": $0.id, "enabled": true] }
            for m in modules {
                try m.text.write(toFile: NCEngineConfig.modulePath(home: dir, id: m.id),
                                 atomically: true, encoding: .utf8)
            }
        }
        let data = try JSONSerialization.data(withJSONObject: engine)
        try data.write(to: URL(fileURLWithPath: dir + "/engine/engine.json"))
        return dir
    }

    /// The production prep chain for a home, then the tunnel host load.
    private func buildAndLoad(_ dir: String) throws -> (cfg: NCEngineConfig, rs: NCEngineRuleset) {
        let cfg = NCEngineConfig.load(home: dir)
        let rs = NCMitmBuild.build(home: dir, cfg: cfg)
        let out = try NCScriptManifest.export(home: dir, cfg: cfg, rs: rs)
        XCTAssertEqual(out.bad, 0, "manifest export left scripts unloadable")
        XCTAssertGreaterThan(out.scripts, 0, "manifest export produced no script entries")
        let msg = NativeScriptHost.shared.load(home: dir)
        XCTAssertTrue(msg.contains(" 0 unloadable"), msg)
        XCTAssertTrue(msg.contains("prelude ok"), msg)
        XCTAssertTrue(msg.contains("JSC interruptible"), msg)
        return (cfg, rs)
    }

    /// The `type` of every entry in the written manifest, in order.
    private func manifestTypes(_ dir: String) throws -> [String] {
        let data = try Data(contentsOf: URL(fileURLWithPath: dir + "/nativecore-scripts.json"))
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let list = obj["scripts"] as? [[String: Any]] ?? []
        return list.map { $0["type"] as? String ?? "?" }
    }

    // MARK: - DNS / rule hook helpers

    private func dnsQuery(name: String, type: UInt16 = NCDNSMessage.typeA) -> Data {
        var q = NCDNSMessage()
        q.id = 0x4242
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        return q.serialized()
    }

    private func dnsReply(name: String, ips: [String], type: UInt16 = NCDNSMessage.typeA) -> Data {
        var m = NCDNSMessage()
        m.id = 0x4242
        m.isResponse = true
        m.recursionDesired = true
        m.recursionAvailable = true
        m.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        m.answers = ips.map { ip in
            NCDNSRecord(name: name, type: type, klass: NCDNSMessage.classIN,
                        ttl: 300, rdata: Data(NCIP(ip)!.bytes))
        }
        return m.serialized()
    }

    private func runDNS(query: Data, reply: Data, timeout: TimeInterval = 15) -> Data {
        let exp = expectation(description: "dns hook completion")
        var out: Data?
        let cb = DispatchQueue(label: "nc.sverify.dns-cb")
        NCScriptHookRunner.shared.applyDNS(query: query, reply: reply, on: cb) { r in
            out = r
            exp.fulfill()
        }
        wait(for: [exp], timeout: timeout)
        return out ?? Data()
    }

    private func ruleContext(domain: String?) -> NCMatchContext {
        var ctx = NCMatchContext()
        ctx.domain = domain
        ctx.network = "tcp"
        ctx.dstPort = 443
        return ctx
    }

    // MARK: - ① Surge type=dns: answer rewrite

    func testSurgeDNSScriptRewritesAnswers() throws {
        let dir = try makeHome(modules: [(id: "surge-dns", text: """
        [Script]
        dns-fix = type=dns, script-path=dns-fix.js
        """)], files: ["dns-fix.js": #"$done(["203.0.113.7"]);"#])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["dns"])
        XCTAssertTrue(NCScriptHookRunner.shared.hasDNSScripts)

        let out = runDNS(query: dnsQuery(name: "example.com"),
                         reply: dnsReply(name: "example.com", ips: ["192.0.2.1"]))
        let msg = try XCTUnwrap(NCDNSMessage.parse(out))
        XCTAssertEqual(msg.addressAnswers.map { $0.0.string }, ["203.0.113.7"])
        XCTAssertEqual(msg.rcode, 0)
    }

    func testSurgeDNSScriptRewritesRcode() throws {
        let dir = try makeHome(modules: [(id: "surge-dns-rcode", text: """
        [Script]
        dns-nx = type=dns, script-path=dns-nx.js
        """)], files: ["dns-nx.js": #"$done({ rcode: 3 });"#])
        _ = try buildAndLoad(dir)

        let out = runDNS(query: dnsQuery(name: "gone.example.com"),
                         reply: dnsReply(name: "gone.example.com", ips: ["192.0.2.1"]))
        let msg = try XCTUnwrap(NCDNSMessage.parse(out))
        XCTAssertEqual(msg.rcode, 3)
        XCTAssertTrue(msg.answers.isEmpty, "an error rcode without addresses is authoritative-empty")
    }

    func testSurgeDNSPatternFilter() throws {
        let dir = try makeHome(modules: [(id: "surge-dns-pat", text: """
        [Script]
        dns-org = type=dns, script-path=dns-org.js, pattern=example\\.org$
        """)], files: ["dns-org.js": #"$done(["203.0.113.8"]);"#])
        _ = try buildAndLoad(dir)

        // Non-matching name: the script must not run, reply passes through.
        let miss = runDNS(query: dnsQuery(name: "example.com"),
                          reply: dnsReply(name: "example.com", ips: ["192.0.2.1"]))
        XCTAssertEqual(try XCTUnwrap(NCDNSMessage.parse(miss)).addressAnswers.map { $0.0.string },
                       ["192.0.2.1"])
        // Matching name: rewritten.
        let hit = runDNS(query: dnsQuery(name: "sub.example.org"),
                         reply: dnsReply(name: "sub.example.org", ips: ["192.0.2.1"]))
        XCTAssertEqual(try XCTUnwrap(NCDNSMessage.parse(hit)).addressAnswers.map { $0.0.string },
                       ["203.0.113.8"])
    }

    // MARK: - ② Surge type=rule: verdict + pass-through

    func testSurgeRuleScriptVerdictAndPatternOrder() throws {
        let dir = try makeHome(modules: [(id: "surge-rule", text: """
        [Script]
        rule-miss = type=rule, script-path=rule-miss.js, pattern=nomatch\\.example$
        rule-hit = type=rule, script-path=rule-hit.js
        """)], files: [
            "rule-miss.js": #"$done("WrongPolicy");"#,
            "rule-hit.js": #"$done("ProxyB");"#,
        ])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["rule", "rule"])
        XCTAssertTrue(NCScriptHookRunner.shared.hasRuleScripts)

        // The pattern-filtered script is declared first but must be
        // skipped for this domain; the second script decides.
        let verdict = NCScriptHookRunner.shared.ruleVerdict(ctx: ruleContext(domain: "www.example.com"))
        XCTAssertEqual(verdict?.policy, "ProxyB")
        XCTAssertEqual(verdict?.script, "rule-hit")
    }

    func testSurgeRuleScriptPassThrough() throws {
        let dir = try makeHome(modules: [(id: "surge-rule-pass", text: """
        [Script]
        rule-none = type=rule, script-path=rule-none.js
        """)], files: ["rule-none.js": "$done();"])
        _ = try buildAndLoad(dir)

        XCTAssertNil(NCScriptHookRunner.shared.ruleVerdict(ctx: ruleContext(domain: "www.example.com")))

        let exp = expectation(description: "rule hook completion")
        var gotPolicy: String? = "unset"
        var gotScript: String? = "unset"
        let cb = DispatchQueue(label: "nc.sverify.rule-cb")
        NCScriptHookRunner.shared.applyRule(ctx: ruleContext(domain: "www.example.com"), on: cb) { policy, script in
            gotPolicy = policy
            gotScript = script
            exp.fulfill()
        }
        wait(for: [exp], timeout: 15)
        XCTAssertNil(gotPolicy)
        XCTAssertNil(gotScript)
    }

    // MARK: - ③ Egern ctx: dns phase (ctx.env / ctx.request / ctx.respond)

    func testEgernCtxDNSScript() throws {
        let dir = try makeHome(modules: [(id: "egern-dns", text: """
        name: EgernVerify
        scriptings:
          - name: egern-dns
            url: egern-dns.js
            timeout: 5
            env:
              answer: 203.0.113.99
            dns: true
        """)], files: ["egern-dns.js": """
        export default async function (ctx) {
          if (ctx.request.domain === "example.com") {
            return ctx.respond({ addresses: [ctx.env.answer] });
          }
          return ctx.respond({ addresses: ["198.51.100.1"] });
        }
        """])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["dns"])

        let out = runDNS(query: dnsQuery(name: "example.com"),
                         reply: dnsReply(name: "example.com", ips: ["192.0.2.1"]))
        let msg = try XCTUnwrap(NCDNSMessage.parse(out))
        XCTAssertEqual(msg.addressAnswers.map { $0.0.string }, ["203.0.113.99"],
                       "ctx.env must reach the script and ctx.respond must be honored")
    }

    // MARK: - hook failure modes: exception + timeout are fail-open

    func testHookScriptsExceptionFailsOpen() throws {
        let dir = try makeHome(modules: [(id: "surge-boom", text: """
        [Script]
        dns-boom = type=dns, script-path=dns-boom.js
        rule-boom = type=rule, script-path=rule-boom.js
        """)], files: [
            "dns-boom.js": #"throw new Error("boom");"#,
            "rule-boom.js": #"throw new Error("boom");"#,
        ])
        _ = try buildAndLoad(dir)

        let reply = dnsReply(name: "example.com", ips: ["192.0.2.1"])
        let out = runDNS(query: dnsQuery(name: "example.com"), reply: reply)
        XCTAssertEqual(out, reply, "a throwing dns script must pass the reply through untouched")
        XCTAssertNil(NCScriptHookRunner.shared.ruleVerdict(ctx: ruleContext(domain: "www.example.com")),
                     "a throwing rule script must be no-match")
    }

    func testDNSScriptTimeoutFailsOpen() throws {
        let dir = try makeHome(modules: [(id: "surge-slow", text: """
        [Script]
        dns-slow = type=dns, script-path=dns-slow.js, timeout=1
        """)], files: ["dns-slow.js": "while (true) {}"])
        _ = try buildAndLoad(dir)

        let reply = dnsReply(name: "example.com", ips: ["192.0.2.1"])
        let start = Date()
        let out = runDNS(query: dnsQuery(name: "example.com"), reply: reply, timeout: 30)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(out, reply, "a timed-out dns script must pass the reply through untouched")
        XCTAssertLessThan(elapsed, 20, "the 1 s manifest timeout must bound the run (took \(elapsed)s)")
    }

    // MARK: - MitM driver harness

    private final class SnapSource: RewriteSnapshotSource {
        var json: String
        init(_ json: String) { self.json = json }
        func generation() -> Int64 { 1 }
        func snapshotJSON() -> String { json }
    }

    /// A rewrite driver over the production snapshot for the home's
    /// ruleset, with the real pass-through inner driver; its scriptGo
    /// stays the default (NativeScriptHost.shared, loaded by
    /// buildAndLoad) — nothing about the script path is faked.
    private func makeDriver(_ dir: String) throws -> NativeRewriteDriver {
        let cfg = NCEngineConfig.load(home: dir)
        let rs = NCMitmBuild.build(home: dir, cfg: cfg)
        let snap = try NCRewriteSnapshotBuilder.exportData(home: dir, cfg: cfg, rs: rs)
        XCTAssertGreaterThan(snap.hostCount, 0, "snapshot carries no MitM hosts")
        let json = try XCTUnwrap(String(data: snap.data, encoding: .utf8))
        return NativeRewriteDriver(inner: NativeMitmFlowDriver(),
                                   provider: NativeRewriteProvider(source: SnapSource(json)),
                                   recorder: nil)
    }

    private func apiConn() -> MitmConnInfo {
        MitmConnInfo(host: "api.example.com", port: 443, tls: true, connID: 1)
    }

    private func apiHead() -> HTTPRequestHead {
        HTTPRequestHead(method: "GET", target: "/x",
                        headers: [("Host", "api.example.com"), ("User-Agent", "sverify")])
    }

    private func headerValue(_ headers: [[String]]?, _ name: String) -> String? {
        headers?.first { $0.count == 2 && $0[0].lowercased() == name.lowercased() }?[1]
    }

    private func readAll(_ d: NativeRewriteDriver, _ id: Int64, _ which: FlowBodyWhich) -> Data {
        var out = Data()
        for _ in 0..<1000 {
            let b = d.read(id, which, max: 4096)
            if b.isEmpty { break }
            out += b
        }
        return out
    }

    private static let requestHeaderScript = """
    var h = $request.headers;
    h["X-Added"] = "yes";
    $done({ headers: h });
    """

    // MARK: - ④ MitM http-request / http-response (Surge format)

    func testSurgeRequestScriptRewritesHeader() throws {
        let dir = try makeHome(modules: [(id: "surge-mitm-req", text: """
        [Script]
        req-hdr = type=http-request, pattern=^https://api\\.example\\.com/, script-path=req-hdr.js
        [MITM]
        hostname = api.example.com
        """)], files: ["req-hdr.js": Self.requestHeaderScript])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["http-request"])

        let d = try makeDriver(dir)
        let dec = d.requestPhase(head: apiHead(), conn: apiConn())
        XCTAssertEqual(dec.action, .forward)
        XCTAssertEqual(headerValue(dec.headers, "X-Added"), "yes",
                       "the http-request script's header change must reach the forward decision")
        XCTAssertEqual(headerValue(dec.headers, "User-Agent"), "sverify")
        d.end(dec.id, sent: 0, error: "")
    }

    func testSurgeResponseScriptRewritesBody() throws {
        let dir = try makeHome(modules: [(id: "surge-mitm-resp", text: """
        [Script]
        resp-body = type=http-response, pattern=^https://api\\.example\\.com/, script-path=resp-body.js, requires-body=true
        [MITM]
        hostname = api.example.com
        """)], files: ["resp-body.js": #"$done({ body: $response.body.replace("hello", "HELLO") });"#])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["http-response"])

        let d = try makeDriver(dir)
        let dec = d.requestPhase(head: apiHead(), conn: apiConn())
        XCTAssertEqual(dec.action, .forward)
        let head = HTTPResponseHead(status: 200, reason: "OK",
                                    headers: [("Content-Type", "text/plain"), ("Content-Length", "11")])
        let rdec = d.responsePhase(dec.id, head: head, length: 11)
        XCTAssertEqual(rdec.action, .needBody)
        XCTAssertEqual(rdec.which, FlowBodyWhich.response.rawValue)
        XCTAssertEqual(d.write(dec.id, .response, Data("hello world".utf8)), .taken)
        d.closeBody(dec.id, .response, error: "")
        let fin = d.await(dec.id)
        XCTAssertEqual(fin.action, .respond)
        XCTAssertEqual(fin.body, .read)
        XCTAssertEqual(readAll(d, dec.id, .response), Data("HELLO world".utf8),
                       "the http-response script's body rewrite must be what the client is served")
        d.end(dec.id, sent: 11, error: "")
    }

    // MARK: - ⑤ Loon / QX formats enter the same manifest and execute

    func testLoonRequestScriptRewritesHeader() throws {
        let dir = try makeHome(modules: [(id: "loon-mitm", text: """
        [Script]
        http-request ^https://api\\.example\\.com/ script-path=loon-req.js, tag=loon-req
        [MITM]
        hostname = api.example.com
        """)], files: ["loon-req.js": Self.requestHeaderScript])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["http-request"])

        let d = try makeDriver(dir)
        let dec = d.requestPhase(head: apiHead(), conn: apiConn())
        XCTAssertEqual(dec.action, .forward)
        XCTAssertEqual(headerValue(dec.headers, "X-Added"), "yes")
        d.end(dec.id, sent: 0, error: "")
    }

    func testQXRequestScriptRewritesHeader() throws {
        let dir = try makeHome(modules: [(id: "qx-mitm", text: """
        [rewrite_local]
        ^https://api\\.example\\.com/ url script-request-header qx-req.js
        [mitm]
        hostname = api.example.com
        """)], files: ["qx-req.js": Self.requestHeaderScript])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["http-request"])

        let d = try makeDriver(dir)
        let dec = d.requestPhase(head: apiHead(), conn: apiConn())
        XCTAssertEqual(dec.action, .forward)
        XCTAssertEqual(headerValue(dec.headers, "X-Added"), "yes")
        d.end(dec.id, sent: 0, error: "")
    }

    // MARK: - MitM failure mode: over-limit response body skips the body script

    func testMitmResponseBodyScriptSkippedOverLimit() throws {
        let dir = try makeHome(modules: [(id: "surge-mitm-big", text: """
        [Script]
        resp-hdr = type=http-response, pattern=^https://api\\.example\\.com/, script-path=resp-hdr.js
        resp-big = type=http-response, pattern=^https://api\\.example\\.com/, script-path=resp-big.js, requires-body=true
        [MITM]
        hostname = api.example.com
        """)], files: [
            "resp-hdr.js": """
            var h = $response.headers;
            h["X-A"] = "ran";
            $done({ headers: h });
            """,
            "resp-big.js": #"$done({ body: "REWRITTEN" });"#,
        ])
        _ = try buildAndLoad(dir)
        XCTAssertEqual(try manifestTypes(dir), ["http-response", "http-response"])

        // One byte over the host's 8 MB body cap: admission must refuse
        // the body script at head time (existing semantics: skip the
        // script, relay the response untouched) while the header-phase
        // script on the same response still runs.
        let bigLen: Int64 = (8 << 20) + 1
        let d = try makeDriver(dir)
        let dec = d.requestPhase(head: apiHead(), conn: apiConn())
        XCTAssertEqual(dec.action, .forward)
        let head = HTTPResponseHead(status: 200, reason: "OK",
                                    headers: [("Content-Type", "text/plain"),
                                              ("Content-Length", String(bigLen))])
        let fin = d.responsePhase(dec.id, head: head, length: bigLen)
        XCTAssertEqual(fin.action, .respond)
        XCTAssertEqual(fin.body, .upstream, "an over-limit body must stream past, not be buffered for the script")
        XCTAssertEqual(fin.length, bigLen)
        XCTAssertEqual(headerValue(fin.headers, "X-A"), "ran",
                       "the header-phase script must still run when the body script is skipped")
        d.end(dec.id, sent: 0, error: "")
    }
}
