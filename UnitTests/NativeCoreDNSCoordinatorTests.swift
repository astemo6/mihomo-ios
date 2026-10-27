import XCTest
@testable import Tern

// Coverage for the #117 upstream-DNS machinery itself — the coalescing
// coordinator and the DoT/DoH connection pools. #126 could only pin the
// Shared wire-format contract because these classes lived in the tunnel
// target; they have since moved to Shared/NativeCore/NCDNSUpstreamPools.swift
// (with two test seams: coordinator limits are init parameters, pools take a
// stream factory), so this file exercises the real classes against fake
// execute closures / fake transports. No real network anywhere.
final class NativeCoreDNSCoordinatorTests: XCTestCase {

    private let callerQueue = DispatchQueue(label: "nc.test.dns.caller")

    /// Poll `predicate` (5 ms) until it holds or `timeout` elapses.
    private func eventually(timeout: TimeInterval = 3, file: StaticString = #filePath, line: UInt = #line,
                            _ predicate: @escaping () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTFail("condition not met within \(timeout)s", file: file, line: line)
    }

    private func framed(_ d: Data) -> Data {
        var f = Data()
        f.appendBE16(UInt16(d.count))
        f.append(d)
        return f
    }

    // MARK: - Coordinator: coalescing

    func testCoalescesIdenticalQueriesAndRewritesEachWaitersID() {
        let coord = NCDNSUpstreamCoordinator()
        let rec = ExecuteRecorder()
        let expA = expectation(description: "waiter A")
        let expB = expectation(description: "waiter B")
        var respA: Data?
        var respB: Data?
        coord.submit(key: "k", id: 0x1111, callerQueue: callerQueue, execute: rec.execute(tag: "k1")) { r in
            respA = r
            expA.fulfill()
        }
        coord.submit(key: "k", id: 0x2222, callerQueue: callerQueue, execute: rec.execute(tag: "k2")) { r in
            respB = r
            expB.fulfill()
        }
        // Sentinel: the coordinator queue is FIFO, so once this third submit's
        // execute fires, the second submit above has definitely been processed
        // — if it had not merged, its own execute ("k2") would precede "other".
        coord.submit(key: "other", id: 0x3333, callerQueue: callerQueue, execute: rec.execute(tag: "other")) { _ in }
        eventually { rec.tags == ["k1", "other"] }

        rec.complete(tag: "k1", with: Data([0x99, 0x99, 0x81, 0x80, 0xAA]))
        wait(for: [expA, expB], timeout: 3)
        // One upstream answer, fanned out with each waiter's own ID restored;
        // every byte past the ID is the shared upstream response.
        XCTAssertEqual(respA, Data([0x11, 0x11, 0x81, 0x80, 0xAA]))
        XCTAssertEqual(respB, Data([0x22, 0x22, 0x81, 0x80, 0xAA]))
        rec.complete(tag: "other", with: nil)
    }

    func testDistinctKeysDoNotCoalesce() {
        let coord = NCDNSUpstreamCoordinator()
        let rec = ExecuteRecorder()
        let expA = expectation(description: "a")
        let expB = expectation(description: "b")
        var respA: Data?
        var respB: Data?
        coord.submit(key: "a", id: 0x0001, callerQueue: callerQueue, execute: rec.execute(tag: "a")) { r in
            respA = r
            expA.fulfill()
        }
        coord.submit(key: "b", id: 0x0002, callerQueue: callerQueue, execute: rec.execute(tag: "b")) { r in
            respB = r
            expB.fulfill()
        }
        eventually { rec.tags == ["a", "b"] }
        rec.complete(tag: "a", with: Data([0x00, 0x01, 0x0A]))
        rec.complete(tag: "b", with: Data([0x00, 0x02, 0x0B]))
        wait(for: [expA, expB], timeout: 3)
        XCTAssertEqual(respA, Data([0x00, 0x01, 0x0A]))
        XCTAssertEqual(respB, Data([0x00, 0x02, 0x0B]))
    }

    // MARK: - Coordinator: in-flight cap + queue timeout

    func testInFlightCapQueuesNewQueriesUntilASlotFrees() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 2, maxQueueWait: 30, maxPendingEntries: 512)
        let rec = ExecuteRecorder()
        coord.submit(key: "a", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "a")) { _ in }
        coord.submit(key: "b", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "b")) { _ in }
        let expC = expectation(description: "queued c eventually runs")
        var respC: Data?
        coord.submit(key: "c", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "c")) { r in
            respC = r
            expC.fulfill()
        }
        eventually { rec.tags == ["a", "b"] }
        // Both slots busy: c must still be queued after the coordinator had
        // ample time to (wrongly) start it.
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(rec.tags, ["a", "b"])
        // Freeing a slot starts the queued entry, FIFO.
        rec.complete(tag: "a", with: Data([0x00, 0x00, 0x01]))
        eventually { rec.tags == ["a", "b", "c"] }
        rec.complete(tag: "c", with: Data([0x00, 0x00, 0x03]))
        wait(for: [expC], timeout: 3)
        XCTAssertEqual(respC, Data([0x00, 0x00, 0x03]))
        rec.complete(tag: "b", with: nil)
    }

    func testQueuedQueryFailsNilAfterQueueWaitAndIsEvicted() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 1, maxQueueWait: 0.2, maxPendingEntries: 512)
        let rec = ExecuteRecorder()
        coord.submit(key: "a", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "a")) { _ in }
        let expB = expectation(description: "queued b times out to nil")
        var respB: Data?
        var respBSet = false
        coord.submit(key: "b", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "b")) { r in
            respB = r
            respBSet = true
            expB.fulfill()
        }
        wait(for: [expB], timeout: 3)
        XCTAssertTrue(respBSet)
        XCTAssertNil(respB)
        // Free the single in-flight slot, then resubmit: the timed-out entry
        // was evicted, so the same key starts a fresh upstream exchange
        // instead of joining a dead entry.
        rec.complete(tag: "a", with: nil)
        let expB2 = expectation(description: "resubmitted b completes")
        var respB2: Data?
        coord.submit(key: "b", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "b2")) { r in
            respB2 = r
            expB2.fulfill()
        }
        eventually { rec.tags.contains("b2") }
        rec.complete(tag: "b2", with: Data([0x00, 0x00, 0x07]))
        wait(for: [expB2], timeout: 3)
        XCTAssertEqual(respB2, Data([0x00, 0x00, 0x07]))
    }

    // MARK: - DoT pool

    func testDoTPoolReusesOneStreamAndDiscardsItOnError() {
        let maker = FakeStreamMaker()
        let pool = NCDNSDoTPool(streamFactory: maker.factory)
        let q1 = Data([0x01, 0x01, 0x01, 0x00])
        let q2 = Data([0x02, 0x02, 0x01, 0x00])
        let q3 = Data([0x03, 0x03, 0x01, 0x00])
        let q4 = Data([0x04, 0x04, 0x01, 0x00])
        let r1 = Data([0x01, 0x01, 0x81, 0x80])
        let r2 = Data([0x02, 0x02, 0x81, 0x80])
        let r4 = Data([0x04, 0x04, 0x81, 0x80])

        let exp1 = expectation(description: "q1 answered")
        var resp1: Data?
        pool.forward(q1, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp1 = r
            exp1.fulfill()
        }
        eventually { maker.count == 1 }
        let s0 = maker.streams[0]
        eventually { s0.sent == [self.framed(q1)] }
        s0.deliver(framed(r1))
        wait(for: [exp1], timeout: 3)
        XCTAssertEqual(resp1, r1)

        // Second query rides the same stream: no new transport is created.
        let exp2 = expectation(description: "q2 answered")
        var resp2: Data?
        pool.forward(q2, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp2 = r
            exp2.fulfill()
        }
        eventually { s0.sent.count == 2 }
        XCTAssertEqual(maker.count, 1)
        s0.deliver(framed(r2))
        wait(for: [exp2], timeout: 3)
        XCTAssertEqual(resp2, r2)

        // A dead stream fails the in-flight query with nil and is discarded.
        let exp3 = expectation(description: "q3 fails nil")
        var resp3: Data?
        var resp3Set = false
        pool.forward(q3, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp3 = r
            resp3Set = true
            exp3.fulfill()
        }
        eventually { s0.sent.count == 3 }
        s0.deliver(nil)
        wait(for: [exp3], timeout: 3)
        XCTAssertTrue(resp3Set)
        XCTAssertNil(resp3)
        XCTAssertTrue(s0.cancelled)

        // The next query opens a fresh stream.
        let exp4 = expectation(description: "q4 answered on a new stream")
        var resp4: Data?
        pool.forward(q4, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp4 = r
            exp4.fulfill()
        }
        eventually { maker.count == 2 }
        let s1 = maker.streams[1]
        eventually { s1.sent == [self.framed(q4)] }
        s1.deliver(framed(r4))
        wait(for: [exp4], timeout: 3)
        XCTAssertEqual(resp4, r4)
    }

    func testDoTPoolConnectFailureFailsHeadQueryAndNextQueryRetries() {
        let maker = FakeStreamMaker()
        maker.startError = NSError(domain: "nc.test", code: 1)
        let pool = NCDNSDoTPool(streamFactory: maker.factory)
        let exp1 = expectation(description: "q1 fails nil on connect error")
        var resp1Set = false
        pool.forward(Data([0x01]), host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            XCTAssertNil(r)
            resp1Set = true
            exp1.fulfill()
        }
        wait(for: [exp1], timeout: 3)
        XCTAssertTrue(resp1Set)

        maker.startError = nil
        let exp2 = expectation(description: "q2 answered after retry")
        var resp2: Data?
        pool.forward(Data([0x02]), host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp2 = r
            exp2.fulfill()
        }
        eventually { maker.count == 2 }
        let s = maker.streams[1]
        eventually { s.sent.count == 1 }
        s.deliver(framed(Data([0x02, 0x81])))
        wait(for: [exp2], timeout: 3)
        XCTAssertEqual(resp2, Data([0x02, 0x81]))
    }

    // MARK: - DoH pool

    func testDoHPoolKeepAliveReuseAndConnectionCloseDiscards() {
        let maker = FakeStreamMaker()
        let pool = NCDNSDoHPool(streamFactory: maker.factory)
        let url = "https://doh.test/dns-query"
        let q1 = Data([0x01, 0x01, 0x01, 0x00])
        let q2 = Data([0x02, 0x02, 0x01, 0x00])
        let q3 = Data([0x03, 0x03, 0x01, 0x00])
        let r1 = Data([0x01, 0x01, 0x81, 0x80])
        let r2 = Data([0x02, 0x02, 0x81, 0x80])
        let r3 = Data([0x03, 0x03, 0x81, 0x80])

        func httpResponse(_ body: Data, close: Bool) -> Data {
            var head = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(body.count)\r\n"
            if close { head += "Connection: close\r\n" }
            head += "\r\n"
            var d = Data(head.utf8)
            d.append(body)
            return d
        }

        let exp1 = expectation(description: "q1 answered")
        var resp1: Data?
        pool.forward(q1, urlString: url, host: "doh.test", port: 443, path: "/dns-query", callerQueue: callerQueue) { r in
            resp1 = r
            exp1.fulfill()
        }
        eventually { maker.count == 1 }
        let s0 = maker.streams[0]
        eventually { s0.sent.count == 1 }
        // The request body is the raw query, appended after the HTTP head.
        XCTAssertEqual(s0.sent[0].suffix(q1.count), q1)
        s0.deliver(httpResponse(r1, close: false))
        wait(for: [exp1], timeout: 3)
        XCTAssertEqual(resp1, r1)

        // keep-alive: the second query reuses the same connection.
        let exp2 = expectation(description: "q2 answered")
        var resp2: Data?
        pool.forward(q2, urlString: url, host: "doh.test", port: 443, path: "/dns-query", callerQueue: callerQueue) { r in
            resp2 = r
            exp2.fulfill()
        }
        eventually { s0.sent.count == 2 }
        XCTAssertEqual(maker.count, 1)
        // A `Connection: close` response is still delivered, but the stream
        // is discarded afterwards.
        s0.deliver(httpResponse(r2, close: true))
        wait(for: [exp2], timeout: 3)
        XCTAssertEqual(resp2, r2)
        XCTAssertTrue(s0.cancelled)

        let exp3 = expectation(description: "q3 answered on a new connection")
        var resp3: Data?
        pool.forward(q3, urlString: url, host: "doh.test", port: 443, path: "/dns-query", callerQueue: callerQueue) { r in
            resp3 = r
            exp3.fulfill()
        }
        eventually { maker.count == 2 }
        let s1 = maker.streams[1]
        eventually { s1.sent.count == 1 }
        s1.deliver(httpResponse(r3, close: false))
        wait(for: [exp3], timeout: 3)
        XCTAssertEqual(resp3, r3)
    }

    // MARK: - Lifecycle teardown (nc-lifecycle)

    func testCoordinatorCancelAllFailsEveryWaiterAndStaysUsable() {
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 1, maxQueueWait: 30, maxPendingEntries: 512)
        let rec = ExecuteRecorder()
        let expA = expectation(description: "in-flight a fails nil")
        let expB = expectation(description: "coalesced waiter fails nil")
        let expC = expectation(description: "queued c fails nil")
        let nilLock = NSLock()
        var nilCount = 0
        func nilCompletion(_ exp: XCTestExpectation) -> (Data?) -> Void {
            { r in
                XCTAssertNil(r)
                nilLock.lock()
                nilCount += 1
                nilLock.unlock()
                exp.fulfill()
            }
        }
        coord.submit(key: "a", id: 0x0001, callerQueue: callerQueue, execute: rec.execute(tag: "a"), completion: nilCompletion(expA))
        // Same key while a is in flight: coalesces onto a's entry.
        coord.submit(key: "a", id: 0x0002, callerQueue: callerQueue, execute: rec.execute(tag: "a2"), completion: nilCompletion(expB))
        // Different key with the single slot busy: stays queued.
        coord.submit(key: "c", id: 0x0003, callerQueue: callerQueue, execute: rec.execute(tag: "c"), completion: nilCompletion(expC))
        eventually { rec.tags == ["a"] }
        eventually {
            let c = coord.inFlightCounts()
            return c.entries == 2 && c.active == 1 && c.pending == 1
        }
        coord.cancelAll()
        wait(for: [expA, expB, expC], timeout: 3)
        XCTAssertEqual(nilCount, 3)
        let after = coord.inFlightCounts()
        XCTAssertEqual(after.entries, 0)
        XCTAssertEqual(after.active, 0)
        XCTAssertEqual(after.pending, 0)
        // The cancelled entry's late upstream answer is dropped (the entry
        // is gone), and the coordinator immediately serves a fresh query.
        rec.complete(tag: "a", with: Data([0x00, 0x01, 0xFF]))
        let expD = expectation(description: "fresh query completes after cancelAll")
        var respD: Data?
        coord.submit(key: "d", id: 0x0004, callerQueue: callerQueue, execute: rec.execute(tag: "d")) { r in
            respD = r
            expD.fulfill()
        }
        eventually { rec.tags.contains("d") }
        rec.complete(tag: "d", with: Data([0x00, 0x04, 0x2A]))
        wait(for: [expD], timeout: 3)
        XCTAssertEqual(respD, Data([0x00, 0x04, 0x2A]))
    }

    func testDoTPoolResetFailsInFlightAndPendingThenPoolReusable() {
        let maker = FakeStreamMaker()
        let pool = NCDNSDoTPool(streamFactory: maker.factory)
        let q1 = Data([0x01, 0x01, 0x01, 0x00])
        let q2 = Data([0x02, 0x02, 0x01, 0x00])
        let q3 = Data([0x03, 0x03, 0x01, 0x00])
        let r3 = Data([0x03, 0x03, 0x81, 0x80])
        let exp1 = expectation(description: "q1 fails nil on reset")
        let exp2 = expectation(description: "q2 fails nil on reset")
        pool.forward(q1, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            XCTAssertNil(r)
            exp1.fulfill()
        }
        eventually { maker.count == 1 }
        let s0 = maker.streams[0]
        eventually { s0.sent == [self.framed(q1)] }
        // q2 queues behind the in-flight q1 on the same stream. The
        // pooledConnectionCount() round-trip is enqueued after q2's forward
        // on the pool queue, so q2 is definitely pending before reset().
        pool.forward(q2, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            XCTAssertNil(r)
            exp2.fulfill()
        }
        XCTAssertEqual(pool.pooledConnectionCount(), 1)
        pool.reset()
        wait(for: [exp1, exp2], timeout: 3)
        eventually { s0.cancelled }
        eventually { pool.pooledConnectionCount() == 0 }
        // Reusable: the next query opens a fresh stream and completes.
        let exp3 = expectation(description: "q3 answered on a new stream")
        var resp3: Data?
        pool.forward(q3, host: "dot.test", port: 853, callerQueue: callerQueue) { r in
            resp3 = r
            exp3.fulfill()
        }
        eventually { maker.count == 2 }
        let s1 = maker.streams[1]
        eventually { s1.sent == [self.framed(q3)] }
        s1.deliver(framed(r3))
        wait(for: [exp3], timeout: 3)
        XCTAssertEqual(resp3, r3)
    }

    func testDoHPoolResetDropsPooledConnectionAndPoolReusable() {
        let maker = FakeStreamMaker()
        let pool = NCDNSDoHPool(streamFactory: maker.factory)
        let url = "https://doh.test/dns-query"
        let q1 = Data([0x01, 0x01, 0x01, 0x00])
        let q2 = Data([0x02, 0x02, 0x01, 0x00])
        let r1 = Data([0x01, 0x01, 0x81, 0x80])
        let r2 = Data([0x02, 0x02, 0x81, 0x80])
        func httpResponse(_ body: Data) -> Data {
            var d = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(body.count)\r\n\r\n".utf8)
            d.append(body)
            return d
        }
        let exp1 = expectation(description: "q1 answered")
        var resp1: Data?
        pool.forward(q1, urlString: url, host: "doh.test", port: 443, path: "/dns-query", callerQueue: callerQueue) { r in
            resp1 = r
            exp1.fulfill()
        }
        eventually { maker.count == 1 }
        let s0 = maker.streams[0]
        eventually { s0.sent.count == 1 }
        s0.deliver(httpResponse(r1))
        wait(for: [exp1], timeout: 3)
        XCTAssertEqual(resp1, r1)
        XCTAssertEqual(pool.pooledConnectionCount(), 1)
        pool.reset()
        eventually { pool.pooledConnectionCount() == 0 }
        XCTAssertTrue(s0.cancelled)
        let exp2 = expectation(description: "q2 answered on a new connection")
        var resp2: Data?
        pool.forward(q2, urlString: url, host: "doh.test", port: 443, path: "/dns-query", callerQueue: callerQueue) { r in
            resp2 = r
            exp2.fulfill()
        }
        eventually { maker.count == 2 }
        let s1 = maker.streams[1]
        eventually { s1.sent.count == 1 }
        s1.deliver(httpResponse(r2))
        wait(for: [exp2], timeout: 3)
        XCTAssertEqual(resp2, r2)
    }

    // MARK: - Coordinator: pending-entry cap (nc-memory, fix/nc-followup-a)

    func testPendingCapFailsNewDistinctQueryAtOnceButNotCoalescedWaiters() {
        // Small limits through the init seam: 1 slot, 2 pending entries, and a
        // 30 s queue wait so a nil inside the test window can only come from
        // the pending cap, never from the queue timeout.
        let coord = NCDNSUpstreamCoordinator(maxInFlight: 1, maxQueueWait: 30, maxPendingEntries: 2)
        let rec = ExecuteRecorder()
        coord.submit(key: "a", id: 0x0A01, callerQueue: callerQueue, execute: rec.execute(tag: "a")) { _ in }
        let expB1 = expectation(description: "first b waiter")
        let expB2 = expectation(description: "coalesced b waiter past the cap")
        var respB1: Data?
        var respB2: Data?
        coord.submit(key: "b", id: 0x0B01, callerQueue: callerQueue, execute: rec.execute(tag: "b")) { r in
            respB1 = r
            expB1.fulfill()
        }
        coord.submit(key: "c", id: 0x0C01, callerQueue: callerQueue, execute: rec.execute(tag: "c")) { _ in }
        eventually {
            let c = coord.inFlightCounts()
            return c.entries == 3 && c.active == 1 && c.pending == 2
        }

        // Cap reached: a new distinct key fails nil at once, never runs upstream
        // and never becomes an entry.
        let expD = expectation(description: "over-cap d fails nil immediately")
        var respD: Data? = Data([0xEE])
        coord.submit(key: "d", id: 0x0D01, callerQueue: callerQueue, execute: rec.execute(tag: "d")) { r in
            respD = r
            expD.fulfill()
        }
        wait(for: [expD], timeout: 3)
        XCTAssertNil(respD)
        XCTAssertFalse(rec.tags.contains("d"))

        // A waiter joining an existing pending entry is not capped.
        coord.submit(key: "b", id: 0x0B02, callerQueue: callerQueue, execute: rec.execute(tag: "b2")) { r in
            respB2 = r
            expB2.fulfill()
        }
        let mid = coord.inFlightCounts() // queue.sync: the b2 submit has been processed
        XCTAssertEqual(mid.entries, 3)
        XCTAssertEqual(mid.pending, 2)

        // Freeing the slot starts b (FIFO); its one upstream answer fans out to
        // both waiters, each with its own transaction ID.
        rec.complete(tag: "a", with: nil)
        eventually { rec.tags == ["a", "b"] }
        rec.complete(tag: "b", with: Data([0xFF, 0xFF, 0x81, 0x80, 0x01]))
        wait(for: [expB1, expB2], timeout: 3)
        XCTAssertEqual(respB1, Data([0x0B, 0x01, 0x81, 0x80, 0x01]))
        XCTAssertEqual(respB2, Data([0x0B, 0x02, 0x81, 0x80, 0x01]))
        XCTAssertFalse(rec.tags.contains("b2"))
        coord.cancelAll()
    }

    func testProductionDefaultsCapPendingEntriesAt512() {
        XCTAssertEqual(NCDNSUpstreamCoordinator.maxPendingEntries, 512)
        XCTAssertEqual(NCDNSUpstreamCoordinator.maxInFlight, 32)
        // Default init = the shared instance's limits (32 in flight, 512
        // pending, 6 s wait). Fill every slot and the whole pending queue.
        let coord = NCDNSUpstreamCoordinator()
        let rec = ExecuteRecorder()
        let total = NCDNSUpstreamCoordinator.maxInFlight + NCDNSUpstreamCoordinator.maxPendingEntries
        for i in 0..<total {
            coord.submit(key: "q\(i)", id: UInt16(i), callerQueue: callerQueue, execute: rec.execute(tag: "q\(i)")) { _ in }
        }
        let full = coord.inFlightCounts()
        XCTAssertEqual(full.active, 32)
        XCTAssertEqual(full.pending, 512)
        XCTAssertEqual(full.entries, 544)
        XCTAssertEqual(rec.tags.count, 32)

        // The 513th pending query fails nil well inside the 6 s queue wait.
        let started = Date()
        let expOver = expectation(description: "query past the 512 cap fails nil")
        var respOver: Data? = Data([0xEE])
        coord.submit(key: "over", id: 0xFFFF, callerQueue: callerQueue, execute: rec.execute(tag: "over")) { r in
            respOver = r
            expOver.fulfill()
        }
        wait(for: [expOver], timeout: 3)
        XCTAssertNil(respOver)
        XCTAssertLessThan(Date().timeIntervalSince(started), NCDNSUpstreamCoordinator.maxQueueWait)
        XCTAssertFalse(rec.tags.contains("over"))
        XCTAssertEqual(coord.inFlightCounts().pending, 512)

        // A duplicate of a queued key still coalesces at the cap.
        let expDup = expectation(description: "coalesced waiter at the cap")
        var respDup: Data? = Data([0xEE])
        coord.submit(key: "q100", id: 0x4242, callerQueue: callerQueue, execute: rec.execute(tag: "dup")) { r in
            respDup = r
            expDup.fulfill()
        }
        XCTAssertEqual(coord.inFlightCounts().entries, 544)
        coord.cancelAll() // fails every waiter (incl. the duplicate) with nil
        wait(for: [expDup], timeout: 3)
        XCTAssertNil(respDup)
        XCTAssertFalse(rec.tags.contains("dup"))
    }

    // MARK: - Coordinator: fan-out ID rewrite edges

    func testFanOutRewriteSkipsNilIDWaitersAndShortOrNilResponses() {
        let coord = NCDNSUpstreamCoordinator()
        let rec = ExecuteRecorder()
        let expNoID = expectation(description: "waiter without an ID")
        let expID = expectation(description: "waiter with an ID")
        var respNoID: Data?
        var respID: Data?
        coord.submit(key: "k", id: nil, callerQueue: callerQueue, execute: rec.execute(tag: "k")) { r in
            respNoID = r
            expNoID.fulfill()
        }
        coord.submit(key: "k", id: 0x1234, callerQueue: callerQueue, execute: rec.execute(tag: "k2")) { r in
            respID = r
            expID.fulfill()
        }
        _ = coord.inFlightCounts() // both submits processed: the second coalesced
        XCTAssertEqual(rec.tags, ["k"])
        rec.complete(tag: "k", with: Data([0xAB, 0xCD, 0x01]))
        wait(for: [expNoID, expID], timeout: 3)
        XCTAssertEqual(respNoID, Data([0xAB, 0xCD, 0x01])) // untouched
        XCTAssertEqual(respID, Data([0x12, 0x34, 0x01]))

        // A response too short to carry an ID is passed through unchanged.
        let expShort = expectation(description: "short response")
        var respShort: Data?
        coord.submit(key: "s", id: 0x5555, callerQueue: callerQueue, execute: rec.execute(tag: "s")) { r in
            respShort = r
            expShort.fulfill()
        }
        eventually { rec.tags.contains("s") }
        rec.complete(tag: "s", with: Data([0x07]))
        wait(for: [expShort], timeout: 3)
        XCTAssertEqual(respShort, Data([0x07]))

        // Upstream failure: every coalesced waiter gets nil, no rewrite.
        let expN1 = expectation(description: "nil 1")
        let expN2 = expectation(description: "nil 2")
        var n1: Data? = Data([0xEE])
        var n2: Data? = Data([0xEE])
        coord.submit(key: "n", id: 0x0001, callerQueue: callerQueue, execute: rec.execute(tag: "n")) { r in
            n1 = r
            expN1.fulfill()
        }
        coord.submit(key: "n", id: 0x0002, callerQueue: callerQueue, execute: rec.execute(tag: "n2")) { r in
            n2 = r
            expN2.fulfill()
        }
        _ = coord.inFlightCounts()
        rec.complete(tag: "n", with: nil)
        wait(for: [expN1, expN2], timeout: 3)
        XCTAssertNil(n1)
        XCTAssertNil(n2)
    }

    func testForwarderMergeKeyAndIDHelpersDriveCoalescedFanOut() {
        // The production key/ID helpers NCDNSForwarder feeds the coordinator:
        // queries differing only in transaction ID share a key; each waiter
        // gets the shared answer under its own ID.
        // flags RD, QDCOUNT 1, then example.com IN A (split for the type checker).
        var body: [UInt8] = [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        body.append(0x07)
        body.append(contentsOf: Array("example".utf8))
        body.append(0x03)
        body.append(contentsOf: Array("com".utf8))
        body.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01] as [UInt8])
        let q1 = Data([UInt8(0x12), 0x34] + body)
        let q2 = Data([UInt8(0xAB), 0xCD] + body)
        var otherBody = body
        otherBody[otherBody.count - 3] = 0x1C // QTYPE A → AAAA
        let q3 = Data([UInt8(0x12), 0x34] + otherBody)
        XCTAssertEqual(NCDNSForwarder.transactionID(q1), 0x1234)
        XCTAssertEqual(NCDNSForwarder.transactionID(q2), 0xABCD)
        XCTAssertNil(NCDNSForwarder.transactionID(Data([0x01])))
        XCTAssertEqual(NCDNSForwarder.mergeKeySuffix(q1), NCDNSForwarder.mergeKeySuffix(q2))
        XCTAssertNotEqual(NCDNSForwarder.mergeKeySuffix(q1), NCDNSForwarder.mergeKeySuffix(q3))

        let coord = NCDNSUpstreamCoordinator()
        let rec = ExecuteRecorder()
        let exp1 = expectation(description: "q1")
        let exp2 = expectation(description: "q2")
        var r1: Data?
        var r2: Data?
        for (q, tag) in [(q1, "q1"), (q2, "q2")] {
            coord.submit(key: "udp://1.1.1.1:53|" + NCDNSForwarder.mergeKeySuffix(q),
                         id: NCDNSForwarder.transactionID(q), callerQueue: callerQueue,
                         execute: rec.execute(tag: tag)) { r in
                if tag == "q1" { r1 = r; exp1.fulfill() } else { r2 = r; exp2.fulfill() }
            }
        }
        _ = coord.inFlightCounts()
        XCTAssertEqual(rec.tags, ["q1"])
        var answer = q1
        answer[2] = 0x81
        answer[3] = 0x80
        rec.complete(tag: "q1", with: answer)
        wait(for: [exp1, exp2], timeout: 3)
        XCTAssertEqual(r1, answer)
        var expected2 = answer
        expected2[0] = 0xAB
        expected2[1] = 0xCD
        XCTAssertEqual(r2, expected2)
    }
}

// MARK: - Test doubles

/// Records the coordinator's upstream exchanges instead of performing them:
/// each execute call is captured under a tag so the test decides when (and
/// with what) it finishes. Thread-safe; calls happen on the coordinator queue.
private final class ExecuteRecorder {
    private let lock = NSLock()
    private var entries: [(tag: String, done: (Data?) -> Void)] = []

    func execute(tag: String) -> (@escaping (Data?) -> Void) -> Void {
        { [weak self] done in
            guard let self else { return }
            self.lock.lock()
            self.entries.append((tag, done))
            self.lock.unlock()
        }
    }

    var tags: [String] {
        lock.lock()
        defer { lock.unlock() }
        return entries.map { $0.tag }
    }

    func complete(tag: String, with data: Data?) {
        lock.lock()
        let done = entries.first { $0.tag == tag }?.done
        lock.unlock()
        done?(data)
    }
}

/// A fake pool transport: records sends, lets the test deliver receive
/// results. Callbacks are dispatched on the queue handed to the factory —
/// the pool's queue — exactly like NCStream's.
private final class FakePoolStream: NCDNSPoolStream {
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var sentChunks: [Data] = []
    private var receiveHandler: ((Data?, Error?) -> Void)?
    private var didCancel = false
    private var parked: [Data?] = []
    var startError: Error?

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    var sent: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return sentChunks
    }

    var cancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didCancel
    }

    func start(ready: @escaping (Error?) -> Void) {
        let err = startError
        queue.async { ready(err) }
    }

    func send(_ data: Data) {
        lock.lock()
        sentChunks.append(data)
        lock.unlock()
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !parked.isEmpty {
            let data = parked.removeFirst()
            lock.unlock()
            queue.async { handler(data, nil) }
            return
        }
        receiveHandler = handler
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        didCancel = true
        lock.unlock()
    }

    /// Deliver one receive result (nil = EOF/error), on the stream queue.
    func deliver(_ data: Data?) {
        lock.lock()
        let handler = receiveHandler
        receiveHandler = nil
        lock.unlock()
        guard let handler else {
            // The pool registers receive() just after send(); a test can see `sent` before
            // that. Park the delivery until receive() is called instead of dropping it.
            lock.lock()
            parked.append(data)
            lock.unlock()
            return
        }
        queue.async { handler(data, nil) }
    }
}

/// Builds FakePoolStreams for a pool and remembers them in creation order.
private final class FakeStreamMaker {
    private let lock = NSLock()
    private var made: [FakePoolStream] = []
    var startError: Error?

    var factory: NCDNSStreamFactory {
        { [weak self] _, _, queue in
            let stream = FakePoolStream(queue: queue)
            stream.startError = self?.startError
            self?.record(stream)
            return stream
        }
    }

    private func record(_ stream: FakePoolStream) {
        lock.lock()
        made.append(stream)
        lock.unlock()
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return made.count
    }

    var streams: [FakePoolStream] {
        lock.lock()
        defer { lock.unlock() }
        return made
    }
}
