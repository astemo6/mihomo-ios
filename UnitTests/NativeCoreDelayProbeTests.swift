import Network
import XCTest
@testable import Mihomo

/// fix/nc-delay-test (build 404 device report: group 测延迟 showed 超时 for almost every node, the two that answered
/// took ~1 s where the Go core showed 100–300 ms): the delay probe's HTTP exchange (cold vs mihomo unified-delay),
/// per-probe timeout accounting and group concurrency against a real loopback HTTP server, stage tracing, and the
/// readable failure text.
final class NativeCoreDelayProbeTests: XCTestCase {

    // MARK: Response head parsing

    func testParseHead() {
        typealias T = NCTunnelDelayTester
        XCTAssertEqual(T.parseHead(Data("HTTP/1.1 204 No Content\r\nDate: x\r\n".utf8)), .incomplete)
        XCTAssertEqual(T.parseHead(Data("HTTP/1.1 204 No Content\r\n\r\n".utf8)), .complete(reusable: true))
        XCTAssertEqual(T.parseHead(Data("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".utf8)), .complete(reusable: false))
        XCTAssertEqual(T.parseHead(Data("HTTP/1.0 200 OK\r\n\r\n".utf8)), .complete(reusable: false))
        XCTAssertEqual(T.parseHead(Data("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n".utf8)), .complete(reusable: true))
        XCTAssertEqual(T.parseHead(Data("SSH-2.0-x\r\n\r\n".utf8)), .invalid)
    }

    func testRequestShape() {
        let t = (host: "www.gstatic.com", port: 443, tls: true, path: "/generate_204")
        let keep = String(decoding: NCTunnelDelayTester.request(t, keepAlive: true), as: UTF8.self)
        XCTAssertTrue(keep.hasPrefix("HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n"))
        XCTAssertTrue(keep.contains("Connection: keep-alive\r\n"))
        let other = String(decoding: NCTunnelDelayTester.request((host: "h", port: 8080, tls: false, path: "/"), keepAlive: false), as: UTF8.self)
        XCTAssertTrue(other.contains("Host: h:8080\r\n"))
        XCTAssertTrue(other.contains("Connection: close\r\n"))
    }

    // MARK: HTTP exchange over a scripted relay

    /// Answers each request with `responses[i]` after `delays[i]` ms; nil response = EOF.
    private final class ScriptedRelay: NCRelayStream {
        let q = DispatchQueue(label: "test.relay")
        var responses: [Data?]
        var delays: [Int]
        var sent: [String] = []
        private var pending: ((Data?, Error?) -> Void)?
        private var ready: [Data?] = []

        init(responses: [Data?], delays: [Int]) { self.responses = responses; self.delays = delays }

        func send(_ data: Data, completion: @escaping () -> Void) {
            q.async {
                let i = self.sent.count
                self.sent.append(String(decoding: data, as: UTF8.self))
                completion()
                guard i < self.responses.count else { return }
                let r = self.responses[i]
                self.q.asyncAfter(deadline: .now() + .milliseconds(self.delays[i])) { self.deliver(r) }
            }
        }

        private func deliver(_ d: Data?) {
            if let h = pending { pending = nil; h(d, nil) } else { ready.append(d) }
        }

        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            q.async {
                if !self.ready.isEmpty { let d = self.ready.removeFirst(); handler(d, nil) } else { self.pending = handler }
            }
        }

        func cancel() {}
    }

    private let target = (host: "www.gstatic.com", port: 80, tls: false, path: "/generate_204")
    private let ok204 = Data("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8)

    private func run(_ relay: ScriptedRelay, unified: Bool) -> (ms: Int?, err: String?, trace: NCDialTrace) {
        let trace = NCDialTrace()
        let e = expectation(description: "exchange")
        var out: (Int?, String?) = (nil, nil)
        NCTunnelDelayTester.HTTPExchange(relay: relay, target: target, unified: unified, trace: trace, start: trace.start) { ms, err in
            out = (ms, err)
            e.fulfill()
        }.run()
        wait(for: [e], timeout: 5)
        return (out.0, out.1, trace)
    }

    func testUnifiedTimesTheSecondRequestOnly() {
        let relay = ScriptedRelay(responses: [ok204, ok204], delays: [400, 20])
        let r = run(relay, unified: true)
        XCTAssertEqual(relay.sent.count, 2)
        XCTAssertTrue(relay.sent[0].contains("Connection: keep-alive"))
        XCTAssertTrue(relay.sent[1].contains("Connection: close"))
        let ms = try? XCTUnwrap(r.ms)
        XCTAssertNotNil(ms)
        XCTAssertLessThan(ms ?? 9999, 300, "unified delay must exclude the cold first exchange")
        XCTAssertTrue(r.trace.summary.contains("request2"))
    }

    func testColdModeTimesFromProbeStart() {
        let relay = ScriptedRelay(responses: [ok204], delays: [300])
        let r = run(relay, unified: false)
        XCTAssertEqual(relay.sent.count, 1)
        XCTAssertGreaterThanOrEqual(r.ms ?? 0, 290)
    }

    func testUnifiedFallsBackToColdWhenNotReusable() {
        let close = Data("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".utf8)
        let relay = ScriptedRelay(responses: [close], delays: [300])
        let r = run(relay, unified: true)
        XCTAssertEqual(relay.sent.count, 1)
        XCTAssertGreaterThanOrEqual(r.ms ?? 0, 290)
    }

    func testUnifiedSecondFailureKeepsColdTime() {
        let relay = ScriptedRelay(responses: [ok204, nil], delays: [300, 10])
        let r = run(relay, unified: true)
        XCTAssertEqual(relay.sent.count, 2)
        XCTAssertGreaterThanOrEqual(r.ms ?? 0, 290)
        XCTAssertNil(r.err)
    }

    func testEOFBeforeResponseIsAReadableFailure() {
        let relay = ScriptedRelay(responses: [nil], delays: [10])
        let r = run(relay, unified: true)
        XCTAssertNil(r.ms)
        XCTAssertEqual(r.err, "request: connection closed before any response")
        XCTAssertEqual(r.trace.openStage, "request")
    }

    // MARK: Trace / text

    func testTraceOpenStageAndSummary() {
        let t = NCDialTrace()
        XCTAssertEqual(t.openStage, "dial")
        t.begin("dial")
        t.begin("connect")
        XCTAssertEqual(t.openStage, "connect (dns/tcp/tls)")
        t.end("connect")
        XCTAssertEqual(t.openStage, "handshake")
        t.begin("ws")
        XCTAssertEqual(t.openStage, "ws")
        t.end("ws", error: NCConnector.Failure.handshake("websocket upgrade got HTTP 403"))
        t.end("dial", error: NCConnector.Failure.handshake("websocket upgrade got HTTP 403"))
        XCTAssertEqual(t.openStage, "ws")
        XCTAssertTrue(t.summary.contains("ws "), t.summary)
        XCTAssertTrue(t.lastError?.contains("HTTP 403") ?? false)
    }

    func testConnectFailureNamesTheStage() {
        let t = NCDialTrace()
        t.begin("connect")
        t.end("connect", error: NWError.dns(-65554))
        t.connectFailed(NWError.dns(-65554))
        XCTAssertEqual(t.openStage, "dns")
        let t2 = NCDialTrace()
        t2.begin("connect")
        t2.end("connect", error: NWError.posix(.ECONNREFUSED))
        t2.connectFailed(NWError.posix(.ECONNREFUSED))
        XCTAssertEqual(t2.openStage, "tcp")
    }

    func testConnectorFailureIsReadable() {
        let e: Error = NCConnector.Failure.handshake("vmess missing uuid")
        XCTAssertEqual(e.localizedDescription, "handshake failed: vmess missing uuid")
        XCTAssertFalse((e as NSError).localizedDescription.contains("Failure"))
        XCTAssertTrue(NCConnector.Failure.unsupported("x").localizedDescription.hasPrefix("unsupported"))
        XCTAssertEqual(NCDialTrace.describe(NCConnector.Failure.rejected), "rejected by policy (REJECT)")
        XCTAssertEqual((NCTLSClientStream.TLSError.closed as Error).localizedDescription, "TLS connection closed by the peer")
    }

    func testOutcomeMessageAndLogLine() {
        var o = NCTunnelDelayTester.Outcome(ms: nil, failure: "timeout", stage: "ws", error: nil,
                                            stages: "dns 30 ms · tcp 180 ms · tls 200 ms · ws open", unified: true)
        XCTAssertEqual(o.message, "Timeout at stage ws")
        XCTAssertEqual(NCTunnelDelayTester.logLine(name: "HK-01", outcome: o, timeoutMs: 5000),
                       "[delay] HK-01: timeout at stage ws after 5000 ms | dns 30 ms · tcp 180 ms · tls 200 ms · ws open")
        o.failure = "error"; o.stage = "tcp"; o.error = "POSIXErrorCode: Connection refused"
        XCTAssertEqual(o.message, "An error occurred in the delay test at stage tcp (POSIXErrorCode: Connection refused)")
        o = NCTunnelDelayTester.Outcome(ms: 245, failure: nil, stage: nil, error: nil, stages: "request 300 ms · request2 245 ms", unified: true)
        XCTAssertEqual(NCTunnelDelayTester.logLine(name: "JP", outcome: o, timeoutMs: 5000),
                       "[delay] JP: 245 ms (unified) | request 300 ms · request2 245 ms")
    }

    func testManualRoundFitsTheAppRequestWindow() {
        // App: GET /group/{name}/delay with a URLSession timeout of timeout + 10 s.
        for (t, n) in [(5000, 20), (5000, 200), (10_000, 3), (30_000, 50)] {
            let r = NCTunnelDelayTester.manualRoundTimeoutMs(timeoutMs: t, members: n, concurrency: 10)
            XCTAssertLessThan(r, t + 10_000)
            XCTAssertGreaterThanOrEqual(r, t)
        }
        XCTAssertEqual(NCTunnelDelayTester.manualRoundTimeoutMs(timeoutMs: Int.max, members: 5, concurrency: 10), Int.max)
    }

    func testLineLimiter() {
        let l = NCLineLimiter(perWindow: 2, window: 10)
        let t0 = Date()
        XCTAssertTrue(l.admit(now: t0).0)
        XCTAssertTrue(l.admit(now: t0).0)
        XCTAssertFalse(l.admit(now: t0).0)
        XCTAssertFalse(l.admit(now: t0).0)
        let next = l.admit(now: t0.addingTimeInterval(11))
        XCTAssertTrue(next.0)
        XCTAssertEqual(next.1, 2)
    }

    // MARK: Real sockets: concurrency + per-probe timeout (DIRECT through NCStream to a loopback HTTP server)

    private final class SlowHTTPServer {
        let queue = DispatchQueue(label: "test.slowhttp")
        let listener: NCLoopbackListener
        var firstDelayMs: Int
        var silent = false
        private(set) var active = 0
        private(set) var maxActive = 0
        private(set) var accepted = 0
        private var conns: [ObjectIdentifier: NCLoopbackConn] = [:]
        /// Connections counted as active (fix/nc-delay-2: a probe is over once its last response is out — the
        /// client's close reaches this server's read only later, so counting until EOF overstated the overlap:
        /// run 40265638851 saw maxActive 20 with the real cap at 10).
        private var live: Set<ObjectIdentifier> = []
        /// Responses after which a connection's probe is done (unified-delay: 2).
        var responsesPerProbe = 2

        init(firstDelayMs: Int) {
            self.firstDelayMs = firstDelayMs
            listener = NCLoopbackListener(queue: queue)
            listener.onAccept = { [unowned self] c in self.serve(c) }
        }

        func start() -> UInt16? { listener.start(port: 0) == nil ? listener.port : nil }

        func stop() {
            queue.sync {
                listener.stop()
                for c in conns.values { c.onClose = nil; c.cancel() }
                conns.removeAll()
            }
        }

        private func serve(_ c: NCLoopbackConn) {
            let id = ObjectIdentifier(c)
            conns[id] = c
            live.insert(id)
            accepted += 1
            active += 1
            maxActive = max(maxActive, active)
            c.onClose = { [unowned self] in self.closed(id) }
            read(c, Data(), served: 0)
        }

        /// The probe closed its side (EOF) or the socket went away: no longer active (once per connection).
        private func closed(_ id: ObjectIdentifier) { closed(id: id) }
        private func closed(id: ObjectIdentifier) {
            conns.removeValue(forKey: id)
            guard live.remove(id) != nil else { return }
            active -= 1
        }

        private func read(_ c: NCLoopbackConn, _ buf: Data, served: Int) {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [unowned self] data, _, done, err in
                var buf = buf
                if let data { buf.append(data) }
                if buf.range(of: Data("\r\n\r\n".utf8)) != nil {
                    guard !self.silent else { return }
                    let delay = served == 0 ? self.firstDelayMs : 0
                    self.queue.asyncAfter(deadline: .now() + .milliseconds(delay)) {
                        c.send(content: Data("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8), completion: .idempotent)
                        if served + 1 >= self.responsesPerProbe, self.live.remove(ObjectIdentifier(c)) != nil { self.active -= 1 }
                        self.read(c, Data(), served: served + 1)
                    }
                    return
                }
                if err != nil || done { self.closed(id: ObjectIdentifier(c)); c.cancel(); return }
                self.read(c, buf, served: served)
            }
        }

        var stats: (accepted: Int, maxActive: Int) { queue.sync { (accepted, maxActive) } }
    }

    private func directEngine() -> NCGroupEngine { NCGroupEngine(config: NCConfig.decode(root: [:])) }

    func testGroupProbesRunConcurrentlyEachWithItsOwnTimeout() throws {
        let server = SlowHTTPServer(firstDelayMs: 400)
        let port = try XCTUnwrap(server.start())
        defer { server.stop() }
        let members = Array(repeating: "DIRECT", count: 20)
        let e = expectation(description: "group")
        let t0 = Date()
        var results: [String: Int?] = [:]
        // 20 probes × 400 ms cold: serialized this would take 8 s and blow the 1.5 s per-probe timeout.
        NCTunnelDelayTester.measureGroup(groupEngine: directEngine(), members: members,
                                         url: "http://127.0.0.1:\(port)/generate_204", timeoutMs: 1500,
                                         maxConcurrency: 10, unified: true) { r in
            results = r
            e.fulfill()
        }
        wait(for: [e], timeout: 10)
        let elapsed = Date().timeIntervalSince(t0)
        XCTAssertLessThan(elapsed, 3.0, "probes must overlap (two rounds of 10)")
        let ms = try XCTUnwrap(results["DIRECT"] ?? nil)
        XCTAssertLessThan(ms, 300, "unified: the second request on the warm connection is what counts")
        let s = server.stats
        XCTAssertEqual(s.accepted, 20)
        XCTAssertLessThanOrEqual(s.maxActive, 10)
        XCTAssertGreaterThanOrEqual(s.maxActive, 5)
    }

    func testProbeTimeoutNamesTheRequestStage() throws {
        let server = SlowHTTPServer(firstDelayMs: 0)
        server.silent = true
        let port = try XCTUnwrap(server.start())
        defer { server.stop() }
        let e = expectation(description: "probe")
        var outcome: NCTunnelDelayTester.Outcome?
        let t0 = Date()
        // unified: false — with unified-delay the cold phase gets max(timeout, 5000) (fix/nc-delay-2).
        NCTunnelDelayTester.measure(groupEngine: directEngine(), name: "DIRECT", url: "http://127.0.0.1:\(port)/",
                                    timeoutMs: 600, unified: false) { o in
            outcome = o
            e.fulfill()
        }
        wait(for: [e], timeout: 5)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0, "the timeout runs from the probe's own start")
        let o = try XCTUnwrap(outcome)
        XCTAssertNil(o.ms)
        XCTAssertEqual(o.failure, "timeout")
        XCTAssertEqual(o.stage, "request")
        XCTAssertTrue(o.message.hasPrefix("Timeout at stage request"), o.message)
    }

    func testRefusedConnectFailsFastWithTheReason() throws {
        // A port nobody listens on: bind one, then close it.
        let server = SlowHTTPServer(firstDelayMs: 0)
        let port = try XCTUnwrap(server.start())
        server.stop()
        let e = expectation(description: "probe")
        var outcome: NCTunnelDelayTester.Outcome?
        let t0 = Date()
        NCTunnelDelayTester.measure(groupEngine: directEngine(), name: "DIRECT", url: "http://127.0.0.1:\(port)/",
                                    timeoutMs: 4000, unified: false) { o in
            outcome = o
            e.fulfill()
        }
        wait(for: [e], timeout: 6)
        let o = try XCTUnwrap(outcome)
        XCTAssertNil(o.ms)
        XCTAssertEqual(o.failure, "error", "a refused connect is an error, not a timeout (NWConnection .waiting fails fast)")
        XCTAssertLessThan(Date().timeIntervalSince(t0), 3.0)
        XCTAssertEqual(o.stage, "tcp")
        XCTAssertFalse((o.error ?? "").isEmpty)
    }

    // MARK: fix/nc-delay-2

    /// build 409: "timeout at stage request after 2000 ms | dial 1909 ms" — the cold dial ate the whole timeout.
    /// With unified-delay the cold phase has max(timeout, 5000); the warm request is what `timeout` bounds.
    func testColdPhaseHasItsOwnBudgetInUnifiedMode() throws {
        let server = SlowHTTPServer(firstDelayMs: 700)
        let port = try XCTUnwrap(server.start())
        defer { server.stop() }
        let e = expectation(description: "probe")
        var outcome: NCTunnelDelayTester.Outcome?
        NCTunnelDelayTester.measure(groupEngine: directEngine(), name: "DIRECT", url: "http://127.0.0.1:\(port)/generate_204",
                                    timeoutMs: 300, unified: true) { o in
            outcome = o
            e.fulfill()
        }
        wait(for: [e], timeout: 8)
        let o = try XCTUnwrap(outcome)
        let ms = try XCTUnwrap(o.ms, "a 700 ms cold phase must not time out a 300 ms unified test: \(o.message) | \(o.stages)")
        XCTAssertLessThan(ms, 300)
    }

    func testBudgets() {
        typealias T = NCTunnelDelayTester
        XCTAssertEqual(T.coldBudgetMs(timeoutMs: 2000, unified: true), 5000)
        XCTAssertEqual(T.coldBudgetMs(timeoutMs: 8000, unified: true), 8000)
        XCTAssertEqual(T.coldBudgetMs(timeoutMs: 2000, unified: false), 2000)
        XCTAssertEqual(T.probeWindowMs(timeoutMs: 2000, unified: true), 7000)
        XCTAssertEqual(T.probeWindowMs(timeoutMs: 2000, unified: false), 2000)
        XCTAssertEqual(T.probeWindowMs(timeoutMs: Int.max, unified: true), Int.max)
        // The App's per-node request window covers the core's longest probe.
        for t in [1000, 2000, 5000, 10_000, 30_000] {
            XCTAssertGreaterThan(ControllerClient.delayWindow(t) * 1000, Double(T.probeWindowMs(timeoutMs: t, unified: true)) - 1)
            let round = T.manualRoundTimeoutMs(timeoutMs: T.probeWindowMs(timeoutMs: t, unified: true), members: 40, concurrency: 10)
            XCTAssertLessThan(Double(round), (ControllerClient.delayWindow(t) + 10) * 1000, "group round inside the App's group window")
        }
    }

    /// Node names from the build 409 report through the App's real URL building and the controller's real target
    /// parsing: the provider-node route must land on the exact name.
    func testControllerRouteDecodesAppEncodedNames() {
        let names = ["东京 ORA JP01 [CF V6]", "🇭🇰 Alice HK CF CDN", "HK CF CDN", "春川 ORA KR01 [全 WARP]",
                     "a/b %20 +&=?#", "新加坡 ORA SG02 CF CDN  [ORA V6]"]
        let provider = "SelfBuild 订阅 #1"
        let url = "https://www.gstatic.com/generate_204?x=1&y=a b"
        for n in names {
            let path = "/providers/proxies/\(ControllerClient.enc(provider))/\(ControllerClient.enc(n))/healthcheck"
            let q = ControllerClient.query([("url", url), ("timeout", "2000")])
            let r = NCControllerRoute.split(target: path + "?" + q)
            XCTAssertEqual(r.comps, ["providers", "proxies", provider, n, "healthcheck"], n)
            XCTAssertEqual(r.query["url"], url)
            XCTAssertEqual(r.query["timeout"], "2000")
            let d = NCControllerRoute.split(target: "/proxies/\(ControllerClient.enc(n))/delay?" + q)
            XCTAssertEqual(d.comps, ["proxies", n, "delay"], n)
        }
        XCTAssertEqual(NCControllerRoute.split(target: "/version").comps, ["version"])
        XCTAssertEqual(NCControllerRoute.split(target: "/logs?token=abc").query["token"], "abc")
    }
}
