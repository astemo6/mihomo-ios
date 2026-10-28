import XCTest
@testable import Tern

/// fix/nc-0.20.3-diag (device diag 0917, build 527): MitM upstream connection reuse, per-node dial pacing, the route in
/// failures, REJECT not tripping the MitM failure breaker, the app's TCP destination kept for a fronted Host header,
/// and the one retry of a request whose reused connection died before the response head.
final class NativeCoreMitmUpstreamReuseTests: XCTestCase {

    final class Obj { let id: Int; init(_ i: Int) { id = i } }

    // MARK: NCIdlePool

    func testIdlePoolLIFOTTLAndCaps() {
        var t: TimeInterval = 1000
        var discarded: [Int] = []
        let pool = NCIdlePool<Obj>(ttl: 15, maxPerKey: 2, maxTotal: 3, now: { t }, discard: { discarded.append($0.id) })
        XCTAssertNil(pool.take("a"))
        XCTAssertTrue(pool.put(Obj(1), key: "a"))
        t += 1; pool.put(Obj(2), key: "a")
        t += 1; pool.put(Obj(3), key: "a")           // over maxPerKey 2 → oldest of "a" (1) goes
        XCTAssertEqual(discarded, [1])
        XCTAssertEqual(pool.take("a")?.id, 3, "warmest first")
        t += 1; pool.put(Obj(4), key: "b")
        t += 1; pool.put(Obj(5), key: "c")
        t += 1; pool.put(Obj(6), key: "c")           // total 4 > 3 → oldest overall (2) goes
        XCTAssertEqual(discarded, [1, 2])
        XCTAssertNil(pool.take("a"))
        t += 20                                       // everything expires
        XCTAssertNil(pool.take("b"))
        XCTAssertEqual(Set(discarded), Set([1, 2, 4]), "stale entry of the taken key discarded on access")
        pool.removeAll()
        XCTAssertEqual(Set(discarded), Set([1, 2, 4, 5, 6]))
        XCTAssertEqual(pool.count, 0)
        XCTAssertEqual(pool.reuses, 1)
    }

    func testIdlePoolDisabledKeepsNothing() {
        let pool = NCIdlePool<Obj>(ttl: 15, maxPerKey: 0, maxTotal: 0, discard: { _ in })
        XCTAssertFalse(pool.put(Obj(1), key: "a"))
        XCTAssertEqual(pool.count, 0)
    }

    // MARK: NCDialGate

    func testDialGateQueuesBeyondLimitFIFO() {
        let gate = NCDialGate(limit: 2)
        var started: [Int] = []
        for i in 1...5 { gate.acquire("node") { started.append(i) } }
        XCTAssertEqual(started, [1, 2])
        XCTAssertEqual(gate.inFlight("node"), 2)
        XCTAssertEqual(gate.waiting("node"), 3)
        gate.acquire("other") { started.append(99) }   // another node is not held up
        XCTAssertEqual(started, [1, 2, 99])
        gate.release("node")
        XCTAssertEqual(started, [1, 2, 99, 3])
        XCTAssertEqual(gate.inFlight("node"), 2, "the slot passed to the waiter")
        gate.release("node"); gate.release("node")
        XCTAssertEqual(started, [1, 2, 99, 3, 4, 5])
        gate.release("node"); gate.release("node")
        XCTAssertEqual(gate.inFlight("node"), 0)
        XCTAssertEqual(gate.queuedTotal, 3)
    }

    // MARK: connector helpers

    func testRouteTextPoolKeyGateKeyAndRetryClass() {
        let node = NCProxy(name: "🇯🇵 东京Green CDN", type: "vmess", fields: ["server": .string("cdn.example"), "port": .number(443)])
        XCTAssertEqual(NCUpstreamConnector.routeText(policy: "终极清单", rule: "MATCH,终极清单", resolution: .proxy(node)),
                       "rule MATCH,终极清单 → 终极清单 (🇯🇵 东京Green CDN)")
        XCTAssertEqual(NCUpstreamConnector.routeText(policy: "DIRECT", rule: "GEOIP,cn,DIRECT", resolution: .direct),
                       "rule GEOIP,cn,DIRECT → DIRECT")
        XCTAssertEqual(NCUpstreamConnector.gateKey(.proxy(node)), "🇯🇵 东京Green CDN|cdn.example|443")
        XCTAssertNil(NCUpstreamConnector.gateKey(.direct))
        let k1 = NCUpstreamConnector.poolKey(host: "API.ex.com", port: 443, tls: true, insecure: false, alpn: ["http/1.1"], via: "x")
        let k2 = NCUpstreamConnector.poolKey(host: "api.ex.com", port: 443, tls: true, insecure: false, alpn: ["h2", "http/1.1"], via: "x")
        XCTAssertNotEqual(k1, k2, "ALPN offer is part of the key")
        XCTAssertTrue(k1.hasPrefix("api.ex.com:443|tls|"))
        XCTAssertTrue(NCUpstreamConnector.isTransientUpstream(UpstreamError.connectFailed("handshake failed: ws upgrade refused: HTTP/1.1 403 Forbidden")))
        XCTAssertTrue(NCUpstreamConnector.isTransientUpstream(UpstreamError.timeout))
        XCTAssertFalse(NCUpstreamConnector.isTransientUpstream(UpstreamError.connectFailed("upstream TLS: bad cert")))
        XCTAssertFalse(NCUpstreamConnector.isTransientUpstream(UpstreamError.connectFailed("unknown policy: X")))
        XCTAssertFalse(NCUpstreamConnector.isTransientUpstream(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule")))
        XCTAssertTrue(NCUpstreamRetry.isTransient(NCConnector.Failure.handshake("ws upgrade refused")))
        XCTAssertFalse(NCUpstreamRetry.isTransient(NCConnector.Failure.rejected))
    }

    // MARK: session helpers

    func testDialHostKeepsTheAppsDestinationForAFrontedHost() {
        // 喜马拉雅: TCP/TLS to mermaid.c.ximalaya.com, `Host: mermaid.ximalaya.com`
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "mermaid.ximalaya.com", urlPort: nil, scheme: "https",
                                                  requestHost: "mermaid.ximalaya.com", connHost: "mermaid.c.ximalaya.com",
                                                  connPort: 443, connTLS: true), "mermaid.c.ximalaya.com")
        // same host: unchanged
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "www.youtube.com", urlPort: nil, scheme: "https",
                                                  requestHost: "www.youtube.com", connHost: "www.youtube.com",
                                                  connPort: 443, connTLS: true), "www.youtube.com")
        // re-targeted by a rewrite / script (URL host ≠ Host header): the new host
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "other.example", urlPort: nil, scheme: "https",
                                                  requestHost: "a.example", connHost: "a.c.example",
                                                  connPort: 443, connTLS: true), "other.example")
        // IP connection host (no SNI): the Host header
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "a.example", urlPort: nil, scheme: "https",
                                                  requestHost: "a.example", connHost: "1.2.3.4",
                                                  connPort: 443, connTLS: true), "a.example")
        // another port / scheme in the URL: the URL host
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "a.example", urlPort: 8443, scheme: "https",
                                                  requestHost: "a.example:8443", connHost: "a.c.example",
                                                  connPort: 443, connTLS: true), "a.example")
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "a.example", urlPort: nil, scheme: "http",
                                                  requestHost: "a.example", connHost: "a.c.example",
                                                  connPort: 443, connTLS: true), "a.example")
        // Host header with the default port still counts as the same authority
        XCTAssertEqual(NativeMitmSession.dialHost(urlHost: "a.example", urlPort: 443, scheme: "https",
                                                  requestHost: "a.example:443", connHost: "a.c.example",
                                                  connPort: 443, connTLS: true), "a.c.example")
        XCTAssertEqual(NativeMitmSession.hostOnly("[::1]:443"), "::1")
        XCTAssertEqual(NativeMitmSession.hostOnly("ex.com:80"), "ex.com")
        XCTAssertEqual(NativeMitmSession.hostOnly("ex.com"), "ex.com")
        XCTAssertTrue(NativeMitmSession.isRejection(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule")))
        XCTAssertTrue(NativeMitmSession.isRejection(UpstreamError.proxyRefused(status: 403, reason: "rejected by policy REJECT")))
        XCTAssertFalse(NativeMitmSession.isRejection(UpstreamError.connectFailed("handshake failed: ws upgrade refused: HTTP/1.1 403 Forbidden")))
    }

    // MARK: session behaviour (fakes from NativeMitmSessionTests)

    final class ReusedLease: MitmUpstreamLease {
        let mem = NativeMitmSessionTests.MemStream()
        var stream: ByteStream { mem }
        let reused: Bool
        var released: Bool?
        init(reused: Bool) { self.reused = reused }
        var wasReused: Bool { reused }
        func release(reusable: Bool) { if released == nil { released = reusable } }
    }

    /// Scripted upstream: each open takes the next step — a lease (fed `response`, then EOF when `eof`) or an error.
    final class ScriptedUpstream: MitmUpstreamConnecting {
        enum Step { case lease(reused: Bool, response: Data, eof: Bool), fail(Error) }
        var steps: [Step]
        var opened: [String] = []
        var leases: [ReusedLease] = []
        let lock = NSLock()
        init(_ steps: [Step]) { self.steps = steps }
        func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
            lock.lock()
            opened.append(host)
            let step = steps.isEmpty ? Step.fail(UpstreamError.closed) : steps.removeFirst()
            lock.unlock()
            switch step {
            case .lease(let reused, let response, let eof):
                let l = ReusedLease(reused: reused)
                lock.lock(); leases.append(l); lock.unlock()
                l.mem.feed(response, eof: eof)
                completion(.success(l))
            case .fail(let e):
                completion(.failure(e))
            }
        }
    }

    private func runSession(_ up: ScriptedUpstream, client: NativeMitmSessionTests.MemStream,
                            driver: NativeMitmSessionTests.Driver, connHost: String, request: String) {
        NativeMitmSession.timeouts = .init()
        NativeMitmRuntime.maxSessions = 48
        let s = NativeMitmSession(conn: MitmAcceptedConnection(stream: client, host: connHost, port: 443, alpn: "http/1.1", connID: 9),
                                  codec: HTTPLaneCodec(), upstream: up, driver: driver, bodies: NativeMitmSessionTests.Bodies())
        let done = expectation(description: "finished")
        s?.onFinish = { _ in done.fulfill() }
        s?.start()
        client.feed(Data(request.utf8), eof: true)
        wait(for: [done], timeout: 5)
    }

    func testReusedConnectionDeadBeforeHeadIsRetriedOnceOnAFreshOne() {
        let ok = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".utf8)
        let up = ScriptedUpstream([.lease(reused: true, response: Data(), eof: true), .lease(reused: false, response: ok, eof: false)])
        let client = NativeMitmSessionTests.MemStream()
        let driver = NativeMitmSessionTests.Driver()
        runSession(up, client: client, driver: driver, connHost: "ex.com",
                   request: "GET /a HTTP/1.1\r\nHost: ex.com\r\nConnection: close\r\n\r\n")
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 200 OK\r\n"), client.text)
        XCTAssertTrue(client.text.hasSuffix("ok"), client.text)
        XCTAssertEqual(up.opened.count, 2, "one retry on a fresh connection")
        XCTAssertEqual(up.leases.first?.released, false, "the dead pooled connection is dropped")
        XCTAssertTrue(up.leases[1].mem.text.hasPrefix("GET /a HTTP/1.1\r\n"), up.leases[1].mem.text)
    }

    func testFreshConnectionDeadBeforeHeadIsNotRetried() {
        let up = ScriptedUpstream([.lease(reused: false, response: Data(), eof: true),
                                   .lease(reused: false, response: Data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8), eof: false)])
        let client = NativeMitmSessionTests.MemStream()
        runSession(up, client: client, driver: NativeMitmSessionTests.Driver(), connHost: "ex.com",
                   request: "GET /a HTTP/1.1\r\nHost: ex.com\r\nConnection: close\r\n\r\n")
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 502 Bad Gateway\r\n"), client.text)
        XCTAssertEqual(up.opened.count, 1)
    }

    func testRejectedUpstreamAnswers403AndDoesNotTripTheBreaker() {
        let host = "rej-\(UUID().uuidString.prefix(8)).example".lowercased()
        NativeMitmUpstreamHealth.reset()
        for _ in 0..<4 {
            let up = ScriptedUpstream([.fail(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule"))])
            let client = NativeMitmSessionTests.MemStream()
            let driver = NativeMitmSessionTests.Driver()
            driver.begin = { _ in FlowDecision.decode(#"{"id":1,"action":"forward","method":"GET","url":"https://\#(host)/a","body":"none","length":0}"#) }
            runSession(up, client: client, driver: driver, connHost: host,
                       request: "GET /a HTTP/1.1\r\nHost: \(host)\r\n\r\n")
            XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 403 Forbidden\r\n"), client.text)
        }
        XCTAssertFalse(NCPinningMemory.shared.isPinned(host), "REJECT is a verdict, not an upstream failure")
    }

    func testUpstreamFailuresStillTripTheBreaker() {
        let host = "fail-\(UUID().uuidString.prefix(8)).example".lowercased()
        NativeMitmUpstreamHealth.reset()
        for _ in 0..<3 {
            let up = ScriptedUpstream([.fail(UpstreamError.connectFailed("via x: handshake failed: ws upgrade refused: HTTP/1.1 403 Forbidden"))])
            let client = NativeMitmSessionTests.MemStream()
            let driver = NativeMitmSessionTests.Driver()
            driver.begin = { _ in FlowDecision.decode(#"{"id":1,"action":"forward","method":"GET","url":"https://\#(host)/a","body":"none","length":0}"#) }
            runSession(up, client: client, driver: driver, connHost: host,
                       request: "GET /a HTTP/1.1\r\nHost: \(host)\r\n\r\n")
            XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 502 Bad Gateway\r\n"), client.text)
        }
        XCTAssertTrue(NCPinningMemory.shared.isPinned(host))
        NativeMitmUpstreamHealth.reset()
    }

    func testFrontedHostIsDialedAtTheConnectionsDestination() {
        let ok = Data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)
        let up = ScriptedUpstream([.lease(reused: false, response: ok, eof: false)])
        let client = NativeMitmSessionTests.MemStream()
        let driver = NativeMitmSessionTests.Driver()
        driver.begin = { _ in FlowDecision.decode(#"{"id":1,"action":"forward","method":"GET","url":"https://mermaid.ximalaya.com/config","body":"none","length":0}"#) }
        runSession(up, client: client, driver: driver, connHost: "mermaid.c.ximalaya.com",
                   request: "GET /config HTTP/1.1\r\nHost: mermaid.ximalaya.com\r\nConnection: close\r\n\r\n")
        XCTAssertEqual(up.opened, ["mermaid.c.ximalaya.com"])
        XCTAssertTrue(up.leases[0].mem.text.contains("Host: mermaid.ximalaya.com\r\n"), "Host header unchanged: \(up.leases[0].mem.text)")
    }
}
