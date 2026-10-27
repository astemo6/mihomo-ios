import XCTest
@testable import Tern

/// fix/nc-tails: (1) connections through the local listeners (mixed port / probe listener) in /app/stats;
/// (2) the build433 DNS SERVFAIL burst — upstream exchanges the race gave up on held the coordinator's slots for the
/// transport's full timeout, so a reload-time burst with a black-holed first nameserver starved the healthy one.
final class NativeCoreTailsTests: XCTestCase {

    // MARK: - (1) listener flows in /app/stats

    private func stats(_ r: NCStatsRecorder) -> [String: Any] {
        r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
    }

    private func row(_ list: Any?, _ name: String) -> [String: Any]? {
        (list as? [[String: Any]])?.first { $0["name"] as? String == name }
    }

    func testMixedProxyFlowRecordsHostPolicyRuleBytesAndClosed() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        var f = NCListenerFlowStats()
        f.open(rule: "DOMAIN-SUFFIX,ipinfo.io,Proxy", policy: "Proxy", chain: "HK 01", host: "ipinfo.io", recorder: r)
        f.count(up: 517)
        f.count(down: 4096)
        // stats tick: growth since the last report
        let p = try XCTUnwrap(f.takePending())
        XCTAssertEqual(p.policy, "Proxy")
        XCTAssertEqual(p.host, "ipinfo.io")
        XCTAssertEqual(p.up, 517)
        XCTAssertEqual(p.down, 4096)
        r.bytesBatch([p])
        XCTAssertNil(f.takePending(), "nothing new since the tick")
        f.count(up: 3, down: 900)
        f.close(id: "lp7", type: "HTTPS", srcIP: "127.0.0.1", srcPort: 50123, dstIP: "", dstPort: 443,
                remote: "ipinfo.io", start: Date(timeIntervalSince1970: 1_700_000_001),
                end: Date(timeIntervalSince1970: 1_700_000_003), recorder: r)
        f.close(id: "lp7", type: "HTTPS", srcIP: "127.0.0.1", srcPort: 50123, dstIP: "", dstPort: 443,
                remote: "ipinfo.io", start: Date(), recorder: r) // idempotent

        let s = stats(r)
        XCTAssertEqual(s["totalConnections"] as? Int, 1)
        let host = try XCTUnwrap(row(s["hosts"], "ipinfo.io"))
        XCTAssertEqual(host["up"] as? Int64, 520)
        XCTAssertEqual(host["down"] as? Int64, 4996)
        let pol = try XCTUnwrap(row(s["policies"], "Proxy"))
        XCTAssertEqual(pol["down"] as? Int64, 4996)
        let rules = try XCTUnwrap(s["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules[0]["rule"] as? String, "DOMAIN-SUFFIX,ipinfo.io,Proxy")
        XCTAssertEqual(rules[0]["policy"] as? String, "Proxy")
        XCTAssertEqual(rules[0]["hits"] as? Int, 1)
        let closed = try XCTUnwrap(s["closed"] as? [[String: Any]])
        XCTAssertEqual(closed.count, 1)
        let c = closed[0]
        XCTAssertEqual(c["id"] as? String, "lp7")
        XCTAssertEqual(c["upload"] as? Int64, 520)
        XCTAssertEqual(c["download"] as? Int64, 4996)
        XCTAssertEqual(c["chains"] as? [String], ["HK 01", "Proxy"])
        XCTAssertEqual(c["rule"] as? String, "DOMAIN-SUFFIX,ipinfo.io,Proxy")
        let md = try XCTUnwrap(c["metadata"] as? [String: Any])
        XCTAssertEqual(md["type"] as? String, "HTTPS")
        XCTAssertEqual(md["sourceIP"] as? String, "127.0.0.1")
        XCTAssertEqual(md["sourcePort"] as? String, "50123")
        XCTAssertEqual(md["host"] as? String, "ipinfo.io")
        XCTAssertEqual(md["destinationPort"] as? String, "443")
    }

    func testProbeListenerFlowUsesListenerPolicy() throws {
        // TERN-PROBE on 127.0.0.1:7899: fixed policy, no rule; the dialed node is the chain head.
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        var f = NCListenerFlowStats()
        f.open(rule: "", policy: "TERN-PROBE", chain: "JP 02", host: "ip-api.com", recorder: r)
        f.count(up: 120, down: 300)
        f.close(id: "probe1", type: "HTTP", srcIP: "127.0.0.1", srcPort: 0, dstIP: "", dstPort: 80,
                remote: "ip-api.com", start: Date(), recorder: r)
        let s = stats(r)
        XCTAssertNotNil(row(s["hosts"], "ip-api.com"))
        XCTAssertNotNil(row(s["policies"], "TERN-PROBE"))
        let rules = try XCTUnwrap(s["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first?["rule"] as? String, "—")
        XCTAssertEqual(rules.first?["policy"] as? String, "TERN-PROBE")
        let c = try XCTUnwrap((s["closed"] as? [[String: Any]])?.first)
        XCTAssertEqual(c["chains"] as? [String], ["JP 02", "TERN-PROBE"])
        XCTAssertEqual((c["metadata"] as? [String: Any])?["sourcePort"] as? String, "")
    }

    func testDirectFlowAndReRouteCountOneConnection() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        var f = NCListenerFlowStats()
        // MitM front first, then the front declined → routed normally: one connection, two rule hits
        f.open(rule: "MITM", policy: NCStatsRecorder.engineOutbound, chain: "MITM", host: "a.test", recorder: r)
        f.open(rule: "GEOIP,CN,DIRECT", policy: "DIRECT", chain: "DIRECT", host: "a.test", recorder: r)
        f.count(down: 10)
        f.close(id: "lp1", type: "Socks5", srcIP: "127.0.0.1", srcPort: 1, dstIP: "", dstPort: 443,
                remote: "a.test", start: Date(), recorder: r)
        let s = stats(r)
        XCTAssertEqual(s["totalConnections"] as? Int, 1)
        XCTAssertEqual((s["rules"] as? [[String: Any]])?.count, 2)
        let c = try XCTUnwrap((s["closed"] as? [[String: Any]])?.first)
        XCTAssertEqual(c["chains"] as? [String], ["DIRECT"], "policy == chain → one entry")
        XCTAssertFalse(NCListenerFlowStats.isProxied("DIRECT"))
        XCTAssertFalse(NCListenerFlowStats.isProxied("REJECT"))
        XCTAssertTrue(NCListenerFlowStats.isProxied("HK 01"))
    }

    func testUnroutedFlowRecordsNothing() {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        var f = NCListenerFlowStats()
        f.count(up: 50) // head bytes before routing
        XCTAssertNil(f.takePending())
        f.close(id: "lp9", type: "HTTP", srcIP: "127.0.0.1", srcPort: 1, dstIP: "", dstPort: 80, remote: "x",
                start: Date(), recorder: r)
        let s = stats(r)
        XCTAssertEqual(s["totalConnections"] as? Int, 0)
        XCTAssertEqual((s["closed"] as? [Any])?.count, 0)
        XCTAssertEqual(s["hostCount"] as? Int, 0)
    }

    func testTUNClosedRecordKeepsDefaults() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        r.closed(NCStatsRecorder.Closed(seq: 0, id: "12", network: "tcp", srcPort: 5000, dstIP: "1.2.3.4", dstPort: 443,
                                        host: "h", remote: "h", chains: ["DIRECT"], rule: "MATCH", up: 1, down: 2,
                                        start: 0, closedAt: 0))
        let md = try XCTUnwrap((stats(r)["closed"] as? [[String: Any]])?.first?["metadata"] as? [String: Any])
        XCTAssertEqual(md["type"] as? String, "Native")
        XCTAssertEqual(md["sourceIP"] as? String, "198.18.0.1")
    }

    func testSideBytesReachSpeedSeries() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        r.sample(now: Date(timeIntervalSince1970: 1_700_000_010), up: 0, down: 0, proxyUp: 0, proxyDown: 0)
        r.sideBytes(up: 1000, down: 5000, proxied: true)
        r.sample(now: Date(timeIntervalSince1970: 1_700_000_011), up: 0, down: 0, proxyUp: 0, proxyDown: 0)
        let secs = try XCTUnwrap(r.speedJSON(lastSeconds: 0, buckets: false)["seconds"] as? [[Int64]])
        XCTAssertEqual(secs.last, [1_700_000_011, 1000, 5000, 1000, 5000])
        r.sideBytes(up: 10, down: 0, proxied: false)
        r.sample(now: Date(timeIntervalSince1970: 1_700_000_012), up: 0, down: 0, proxyUp: 0, proxyDown: 0)
        let secs2 = try XCTUnwrap(r.speedJSON(lastSeconds: 0, buckets: false)["seconds"] as? [[Int64]])
        XCTAssertEqual(secs2.last, [1_700_000_012, 10, 0, 0, 0])
    }

    func testListenerFlowsMemoryBounded() {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        for i in 0..<2000 {
            var f = NCListenerFlowStats()
            f.open(rule: "DOMAIN,h\(i).test,P\(i % 400)", policy: "P\(i % 400)", chain: "N", host: "h\(i).test", recorder: r)
            f.count(up: 1, down: 1)
            f.close(id: "lp\(i)", type: "HTTP", srcIP: "127.0.0.1", srcPort: i, dstIP: "", dstPort: 80,
                    remote: "h\(i).test", start: Date(), recorder: r)
        }
        let s = stats(r)
        XCTAssertEqual(s["totalConnections"] as? Int, 2000)
        XCTAssertLessThanOrEqual(s["hostCount"] as? Int ?? .max, NCStatsRecorder.hostCap)
        XCTAssertLessThanOrEqual(s["ruleCount"] as? Int ?? .max, NCStatsRecorder.ruleCap)
        XCTAssertLessThanOrEqual((s["policies"] as? [Any])?.count ?? .max, NCStatsRecorder.policyCap)
        XCTAssertLessThanOrEqual((s["closed"] as? [Any])?.count ?? .max, NCStatsRecorder.closedCap)
    }

    // MARK: - (2) DNS: abandoned upstream exchanges free their slot

    private let callerQueue = DispatchQueue(label: "nc.test.tails.caller")

    private func eventually(timeout: TimeInterval = 3, file: StaticString = #filePath, line: UInt = #line,
                            _ predicate: @escaping () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTFail("condition not met within \(timeout)s", file: file, line: line)
    }

    private static func drained(_ c: NCDNSUpstreamCoordinator) -> Bool {
        let n = c.inFlightCounts()
        return n.entries == 0 && n.active == 0 && n.pending == 0
    }

    private final class Counter {
        private let lock = NSLock()
        private var n = 0
        func bump() { lock.lock(); n += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    func testAbandonCancelsRunningExchangeAndStartsNext() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 1)
        let cancelled = Counter()
        let started = Counter()
        let t1 = coord.submitCancellable(key: "a", id: 1, callerQueue: callerQueue, execute: { _ in
            started.bump()
            return { cancelled.bump() } // never answers on its own
        }, completion: { _ in XCTFail("abandoned waiter must not be called") })
        let exp = expectation(description: "second query answered")
        coord.submitCancellable(key: "b", id: 2, callerQueue: callerQueue, execute: { done in
            started.bump()
            done(Data([0, 2, 0x81, 0x80]))
            return nil
        }, completion: { r in XCTAssertNotNil(r); exp.fulfill() })
        eventually { started.value == 1 }
        XCTAssertEqual(coord.inFlightCounts().pending, 1, "b waits for a's slot")
        coord.abandon(t1)
        wait(for: [exp], timeout: 2)
        XCTAssertEqual(cancelled.value, 1)
        eventually { Self.drained(coord) }
    }

    func testAbandonDropsQueuedEntry() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 1)
        let ran = Counter()
        var finishA: ((Data?) -> Void)?
        coord.submitCancellable(key: "a", id: 1, callerQueue: callerQueue, execute: { done in
            finishA = done
            return nil
        }, completion: { _ in })
        let t2 = coord.submitCancellable(key: "b", id: 2, callerQueue: callerQueue, execute: { _ in
            ran.bump()
            return nil
        }, completion: { _ in XCTFail("abandoned") })
        eventually { coord.inFlightCounts().pending == 1 }
        coord.abandon(t2)
        eventually { coord.inFlightCounts().pending == 0 }
        finishA?(Data([0, 1, 0x81, 0x80]))
        eventually { Self.drained(coord) }
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(ran.value, 0, "a dropped queued entry never runs")
    }

    func testAbandonKeepsCoalescedEntryForOtherWaiters() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 4)
        let cancelled = Counter()
        var finish: ((Data?) -> Void)?
        let t1 = coord.submitCancellable(key: "k", id: 0x1111, callerQueue: callerQueue, execute: { done in
            finish = done
            return { cancelled.bump() }
        }, completion: { _ in XCTFail("abandoned") })
        let exp = expectation(description: "second waiter")
        coord.submitCancellable(key: "k", id: 0x2222, callerQueue: callerQueue, execute: { _ in
            XCTFail("coalesced: never executed"); return nil
        }, completion: { r in
            XCTAssertEqual(r?.prefix(2), Data([0x22, 0x22]))
            exp.fulfill()
        })
        eventually { finish != nil && coord.inFlightCounts().entries == 1 }
        coord.abandon(t1)
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(cancelled.value, 0, "another waiter still wants the answer")
        finish?(Data([0x99, 0x99, 0x81, 0x80]))
        wait(for: [exp], timeout: 2)
    }

    // Fake nameservers for the coordinated race: index 0 black-holed (answers nothing; the real UDP transport gives
    // up after 5 s), index 1 healthy (20 ms).
    private final class FakeServers {
        let lock = NSLock()
        var started = [0, 0]
        var cancelled = [0, 0]
        let servers: [NCDNSUpstream]
        let blackholeTimeout: TimeInterval
        init(_ servers: [NCDNSUpstream], blackholeTimeout: TimeInterval = 5) {
            self.servers = servers
            self.blackholeTimeout = blackholeTimeout
        }
        func execute(_ u: NCDNSUpstream, query: Data, _ done: @escaping (Data?) -> Void) -> (() -> Void)? {
            let i = servers.firstIndex(of: u)!
            lock.lock(); started[i] += 1; lock.unlock()
            let q = DispatchQueue.global()
            let gate = NSLock()
            var over = false
            func end(_ d: Data?) {
                gate.lock(); let first = !over; over = true; gate.unlock()
                if first { done(d) }
            }
            if i == 1 {
                var resp = query
                if resp.count >= 4 { resp[2] = 0x81; resp[3] = 0x80 }
                q.asyncAfter(deadline: .now() + 0.02) { end(resp) }
            } else {
                q.asyncAfter(deadline: .now() + blackholeTimeout) { end(nil) } // transport timeout
            }
            return { [weak self] in
                self?.lock.lock(); self?.cancelled[i] += 1; self?.lock.unlock()
                end(nil) // NCDNSForwarder's cancel: socket closed, answers nil
            }
        }
        var counts: (started: [Int], cancelled: [Int]) { lock.lock(); defer { lock.unlock() }; return (started, cancelled) }
    }

    private static func query(_ n: Int) -> Data {
        var m = NCDNSMessage()
        m.id = UInt16(truncatingIfNeeded: 0x100 + n)
        m.recursionDesired = true
        m.questions = [NCDNSQuestion(name: "host\(n).example.com", type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        return m.serialized()
    }

    /// build433: a full reload landed while queries were in flight; the reload does not touch upstream sockets
    /// (in-flight queries keep running), but it clears the rule resolver's cache and restarts health checks, so a
    /// burst of distinct queries follows at once. With the first nameserver black-holed, every query's first attempt
    /// sat on a coordinator slot for the transport's full 5 s although the race had moved on after 2.5 s, and the
    /// healthy second server's attempts queued behind them until the 5 s race cap → SERVFAIL for the whole burst.
    /// Scaled down: 8 slots and 8 + 24 queries (production: 32 slots, a few dozen queries per page load).
    func testReloadMidQueryBurstWithBlackholedFirstServerAllAnswered() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 8)
        let list: [NCDNSUpstream] = [.udp(host: "13.78.100.57", port: 53), .udp(host: "119.29.29.29", port: 53)]
        let fake = FakeServers(list)
        let q = DispatchQueue(label: "nc.test.tails.race")
        let lock = NSLock()
        var answered = 0, failed = 0
        let all = expectation(description: "every query settled")
        all.expectedFulfillmentCount = 32
        func ask(_ n: Int, start: Int) {
            let query = Self.query(n)
            NCDNSRace.runCoordinated(query: query, list: list, start: start, coordinator: coord, queue: q,
                                     execute: { u, done in fake.execute(u, query: query, done) },
                                     completion: { resp, _ in
                lock.lock()
                if let resp, NCDNSRace.isUsable(resp), resp.prefix(2) == query.prefix(2) { answered += 1 } else { failed += 1 }
                lock.unlock()
                all.fulfill()
            })
        }
        let t0 = Date()
        // in flight when the reload lands
        for n in 0..<8 { ask(n, start: 0) }
        Thread.sleep(forTimeInterval: 0.1)
        // reload: same nameservers (the group's last-good order survives a reload; worst case = first server first
        // because no query has won yet), then the post-reload burst
        for n in 8..<32 { ask(n, start: 0) }
        wait(for: [all], timeout: 8)
        let dt = Date().timeIntervalSince(t0)
        lock.lock(); let ok = answered, bad = failed; lock.unlock()
        XCTAssertEqual(ok, 32, "no SERVFAIL burst (failed \(bad))")
        XCTAssertLessThan(dt, 4.5, "answered after the 2.5 s failover, inside the 5 s race cap")
        let c = fake.counts
        XCTAssertGreaterThan(c.cancelled[0], 0, "given-up attempts on the black-holed server were torn down")
        eventually { Self.drained(coord) }
    }

    func testRaceWinnerCancelsLoserAndFreesSlot() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 4)
        let list: [NCDNSUpstream] = [.udp(host: "13.78.100.57", port: 53), .udp(host: "119.29.29.29", port: 53)]
        let fake = FakeServers(list)
        let q = DispatchQueue(label: "nc.test.tails.race2")
        let exp = expectation(description: "answered")
        let query = Self.query(1)
        let t0 = Date()
        NCDNSRace.runCoordinated(query: query, list: list, start: 0, coordinator: coord, queue: q,
                                 execute: { u, done in fake.execute(u, query: query, done) },
                                 completion: { resp, winner in
            XCTAssertNotNil(resp)
            XCTAssertEqual(winner, 1)
            exp.fulfill()
        })
        wait(for: [exp], timeout: 3)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 1.0)
        // the black-holed attempt does not keep its slot for 5 s
        eventually(timeout: 1) { Self.drained(coord) }
        XCTAssertEqual(fake.counts.cancelled[0], 1)
        XCTAssertEqual(fake.counts.cancelled[1], 0)
    }

    func testAttemptTimeoutCancelsAttempt() {
        let list: [NCDNSUpstream] = [.udp(host: "10.0.0.1", port: 53)]
        let q = DispatchQueue(label: "nc.test.tails.race3")
        let cancelled = Counter()
        let exp = expectation(description: "gave up")
        NCDNSRace.run(list: list, start: 0, queue: q, attemptTimeout: 0.2, overallTimeout: 1,
                      cancellableExchange: { _, _ in return { cancelled.bump() } },
                      completion: { resp, _ in XCTAssertNil(resp); exp.fulfill() })
        wait(for: [exp], timeout: 2)
        XCTAssertEqual(cancelled.value, 1)
    }
}
