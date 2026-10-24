import XCTest
@testable import Mihomo

/// Native MitM stage 2 (lane wire, B9): NativeMitmSession against fakes of the other lanes and of Go's flow API.
/// Uses the integrated http lane (HTTPLaneCodec); what is under test is the wiring: which Go call happens when,
/// keep-alive, body modes, cleanup on every exit.
final class NativeMitmSessionTests: XCTestCase {

    // MARK: fakes

    /// In-memory stream; the test plays the peer.
    final class MemStream: ByteStream {
        private let lock = NSLock()
        private var inbox = Data()
        private var eof = false
        private var waiting: ((Data?, Bool, Error?) -> Void)?
        private(set) var written = Data()
        private(set) var closed = false
        private(set) var halfClosed = false

        func feed(_ d: Data, eof e: Bool = false) {
            lock.lock(); inbox.append(d); if e { eof = true }; let w = waiting; waiting = nil; lock.unlock()
            if let w { deliver(w) }
        }
        private func deliver(_ cb: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if closed { lock.unlock(); return cb(Data(), true, S2Error.cancelled) }
            if inbox.isEmpty && !eof { waiting = cb; lock.unlock(); return }
            let d = inbox; inbox = Data(); let e = eof
            lock.unlock()
            DispatchQueue.global().async { cb(d, e, nil) }
        }
        func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) { deliver(completion) }
        func write(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); let c = closed; if !c { written.append(data) }; lock.unlock()
            DispatchQueue.global().async { completion(c ? S2Error.cancelled : nil) }
        }
        func closeWrite() { lock.lock(); halfClosed = true; lock.unlock() }
        func close() {
            lock.lock(); closed = true; let w = waiting; waiting = nil; lock.unlock()
            w?(Data(), true, S2Error.cancelled)
        }
        var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: written, as: UTF8.self) }
    }

    final class Lease: MitmUpstreamLease {
        let mem = MemStream()
        var stream: ByteStream { mem }
        var released: Bool?
        func release(reusable: Bool) { if released == nil { released = reusable } }
    }

    final class Upstream: MitmUpstreamConnecting {
        var leases: [Lease] = []
        var response: Data
        var opened: [(String, Int, Bool)] = []
        init(response: Data) { self.response = response }
        func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
            let l = Lease(); leases.append(l); opened.append((host, port, tls))
            l.mem.feed(response)
            completion(.success(l))
        }
    }

    final class Driver: MitmFlowDriving {
        var begin: (HTTPRequestHead) -> FlowDecision = { _ in FlowDecision.decode(#"{"id":1,"action":"forward","method":"GET","url":"https://ex.com/a","body":"none","length":0}"#) }
        var resp: (HTTPResponseHead) -> FlowDecision = { _ in FlowDecision.decode(#"{"id":1,"action":"respond","status":200,"headers":[["X-A","1"]],"body":"upstream","length":-1}"#) }
        var awaitD: () -> FlowDecision = { FlowDecision(id: 1, action: .error) }
        var pushed: [FlowBodyWhich: Data] = [:]
        var produce: [FlowBodyWhich: [Data]] = [:]
        var calls: [String] = []
        var ended: [(Int64, Int64, String)] = []
        var cancelled: [Int64] = []
        let lock = NSLock()
        func log(_ s: String) { lock.lock(); calls.append(s); lock.unlock() }

        func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision { log("begin \(head.method) \(head.target)"); return begin(head) }
        func await(_ id: Int64) -> FlowDecision { log("await"); return awaitD() }
        func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision { log("response \(head.status) \(length)"); return resp(head) }
        func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult { pushed[which, default: Data()].append(data); return .taken }
        func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) { log("close \(which.rawValue) \(error)") }
        func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
            guard var q = produce[which], !q.isEmpty else { return Data() }
            let d = q.removeFirst(); produce[which] = q; return d
        }
        func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { (produce[which] ?? []).isEmpty ? .eof : .again }
        func upstreamFailed(_ id: Int64, why: String) { log("upstreamFailed") }
        func end(_ id: Int64, sent: Int64, error: String) { lock.lock(); ended.append((id, sent, error)); lock.unlock() }
        func cancel(_ id: Int64, why: String) { lock.lock(); cancelled.append(id); lock.unlock() }
    }

    final class Bodies: NativeBodyReading {
        var store: [Int64: Data] = [:]
        func len(_ h: Int64, raw: Bool) -> Int64 { store[h].map { Int64($0.count) } ?? -1 }
        func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data? {
            guard let d = store[h] else { return nil }
            let s = Int(off), e = min(d.count, s + Int(n))
            return d.subdata(in: s..<e)
        }
    }

    // MARK: harness

    private var client: MemStream!
    private var driver: Driver!
    private var bodies: Bodies!

    override func setUp() {
        client = MemStream(); driver = Driver(); bodies = Bodies()
        NativeMitmSession.timeouts = .init()
        NativeMitmRuntime.maxSessions = 48
    }

    @discardableResult
    private func run(_ upstream: Upstream, request: String, eof: Bool = true, block: Bool = true) -> NativeMitmSession? {
        let s = NativeMitmSession(conn: MitmAcceptedConnection(stream: client, host: "ex.com", port: 443, alpn: "http/1.1", connID: 7),
                                  codec: HTTPLaneCodec(), upstream: upstream, driver: driver, bodies: bodies)
        let done = block ? expectation(description: "finished") : nil
        if let done { s?.onFinish = { _ in done.fulfill() } }
        s?.start()
        client.feed(Data(request.utf8), eof: eof)
        if let done { wait(for: [done], timeout: 5) }
        return s
    }

    // MARK: tests

    func testForwardStreamsUpstreamBodyAndEndsFlow() {
        let up = Upstream(response: Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-O: o\r\n\r\nhello".utf8))
        run(up, request: "GET /a HTTP/1.1\r\nHost: ex.com\r\nConnection: close\r\n\r\n")
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 200 OK\r\n"), client.text)
        XCTAssertTrue(client.text.hasSuffix("\r\n\r\nhello"), client.text)
        XCTAssertTrue(client.text.contains("Content-Length: 5"))
        XCTAssertTrue(client.text.contains("X-A: 1"))   // Go's headers, not the origin's
        XCTAssertEqual(up.opened.first?.0, "ex.com"); XCTAssertEqual(up.opened.first?.1, 443); XCTAssertEqual(up.opened.first?.2, true)
        XCTAssertTrue(up.leases[0].mem.text.hasPrefix("GET /a HTTP/1.1\r\nHost: ex.com\r\n"), up.leases[0].mem.text)
        XCTAssertEqual(driver.ended.count, 1); XCTAssertEqual(driver.ended.first?.1, 5); XCTAssertEqual(driver.ended.first?.2, "")
        XCTAssertEqual(up.leases[0].released, false) // Connection: close → not reused
        XCTAssertEqual(NativeMitmRuntime.liveSessions, 0)
    }

    func testLocalAnswerNeverOpensUpstream() {
        driver.begin = { _ in FlowDecision.decode(#"{"id":2,"action":"local","status":302,"headers":[["Location","https://x/"]],"body":"none","length":0}"#) }
        let up = Upstream(response: Data())
        run(up, request: "GET /ad HTTP/1.1\r\nHost: ex.com\r\n\r\n")
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 302 Found\r\n"), client.text)
        XCTAssertTrue(client.text.contains("Location: https://x/"))
        XCTAssertTrue(up.opened.isEmpty)
        XCTAssertEqual(driver.ended.map(\.0), [2])
    }

    func testKeepAlivePipelinedRequests() {
        let up = Upstream(response: Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".utf8))
        run(up, request: "GET /1 HTTP/1.1\r\nHost: ex.com\r\n\r\nGET /2 HTTP/1.1\r\nHost: ex.com\r\n\r\n")
        XCTAssertEqual(driver.calls.filter { $0.hasPrefix("begin") }, ["begin GET /1", "begin GET /2"])
        XCTAssertEqual(client.text.components(separatedBy: "HTTP/1.1 200").count - 1, 2)
        XCTAssertEqual(driver.ended.count, 2)
    }

    func testRequestBodyPushedToGoThenRewrittenBodyForwarded() {
        driver.begin = { _ in FlowDecision.decode(#"{"id":3,"action":"need-body","which":0,"length":0}"#) }
        driver.awaitD = { FlowDecision.decode(#"{"id":3,"action":"forward","method":"POST","url":"https://ex.com/p","body":"read","length":-1}"#) }
        driver.produce[.request] = [Data("HELLO".utf8)]
        let up = Upstream(response: Data("HTTP/1.1 204 No Content\r\n\r\n".utf8))
        driver.resp = { _ in FlowDecision.decode(#"{"id":3,"action":"respond","status":204,"body":"none","length":0}"#) }
        run(up, request: "POST /p HTTP/1.1\r\nHost: ex.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        XCTAssertEqual(driver.pushed[.request], Data("hello".utf8))
        XCTAssertTrue(driver.calls.contains("close 0 "))
        XCTAssertTrue(up.leases[0].mem.text.contains("Transfer-Encoding: chunked"))
        XCTAssertTrue(up.leases[0].mem.text.hasSuffix("5\r\nHELLO\r\n0\r\n\r\n"), up.leases[0].mem.text)
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 204"), client.text)
    }

    func testLaneBodyReadFromNativeBodyStore() {
        bodies.store[42] = Data(repeating: 0x61, count: 150_000)
        driver.resp = { _ in FlowDecision.decode(#"{"id":1,"action":"respond","status":200,"body":"lane","length":150000,"lane":{"handle":42,"raw":false}}"#) }
        let up = Upstream(response: Data("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".utf8))
        driver.begin = { _ in FlowDecision.decode(#"{"id":1,"action":"forward","method":"GET","url":"https://ex.com/a","body":"none","length":0}"#) }
        // Go asked for the upstream body first (need-body 1), then answered from the lane.
        var first = true
        let laneResp = driver.resp
        driver.resp = { h in if first { first = false; return FlowDecision.decode(#"{"id":1,"action":"need-body","which":1,"length":0}"#) }; return laneResp(h) }
        driver.awaitD = { laneResp(HTTPResponseHead(status: 200, reason: "OK", headers: [])) }
        run(up, request: "GET /a HTTP/1.1\r\nHost: ex.com\r\nConnection: close\r\n\r\n")
        XCTAssertEqual(driver.pushed[.response], Data("abc".utf8))
        XCTAssertTrue(client.text.contains("Content-Length: 150000"))
        XCTAssertEqual(client.written.count - (client.written.range(of: Data("\r\n\r\n".utf8))!.upperBound), 150_000)
        XCTAssertEqual(driver.ended.first?.1, 150_000)
        XCTAssertNotNil(bodies.store[42]) // handle left to Go (freed at MitmFlowEnd), never freed natively
    }

    func testClientGoneMidFlowCancelsFlowAndFreesSlot() {
        // Upstream never answers; the client disconnects.
        let up = Upstream(response: Data())
        let s = run(up, request: "GET /slow HTTP/1.1\r\nHost: ex.com\r\n\r\n", eof: false, block: false)
        XCTAssertNotNil(s)
        let gone = expectation(description: "gone")
        s?.onFinish = { _ in gone.fulfill() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { s?.cancel("client gone") }
        wait(for: [gone], timeout: 5)
        XCTAssertEqual(driver.cancelled, [1])
        XCTAssertEqual(up.leases.first?.released, false)
        XCTAssertEqual(NativeMitmRuntime.liveSessions, 0)
    }

    func testUpstreamHeadTimeoutAnswers504() {
        NativeMitmSession.timeouts.upstreamHead = 0.3
        let up = Upstream(response: Data())
        run(up, request: "GET /t HTTP/1.1\r\nHost: ex.com\r\n\r\n", eof: false)
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 504"), client.text)
        XCTAssertEqual(driver.ended.count, 1)
        XCTAssertTrue(client.closed)
    }

    func testIdleClientTimesOutWithoutFlow() {
        NativeMitmSession.timeouts.firstHead = 0.2
        run(Upstream(response: Data()), request: "", eof: false)
        XCTAssertTrue(driver.calls.isEmpty)
        XCTAssertTrue(client.closed)
    }

    func testSessionCapRefusesAndClosesStream() {
        NativeMitmRuntime.maxSessions = 0
        let s = NativeMitmSession(conn: MitmAcceptedConnection(stream: client, host: "ex.com", port: 443, alpn: nil, connID: 1),
                                  codec: HTTPLaneCodec(), upstream: Upstream(response: Data()), driver: driver, bodies: bodies)
        XCTAssertNil(s)
        XCTAssertTrue(client.closed)
        XCTAssertFalse(NativeMitmRuntime.canAccept)
    }

    /// listen() reserves a slot for the hand-over it answers, so a burst cannot get past listen() beyond the cap and
    /// then be refused after the handshake; the session claims it; unclaimed reservations expire.
    func testListenReservationsHoldTheCap() {
        NativeMitmRuntime.maxSessions = 2
        let ttl = NativeMitmRuntime.reservationTTL
        defer { NativeMitmRuntime.reservationTTL = ttl }
        XCTAssertTrue(NativeMitmRuntime.reserve())
        XCTAssertTrue(NativeMitmRuntime.reserve())
        XCTAssertFalse(NativeMitmRuntime.reserve())
        XCTAssertFalse(NativeMitmRuntime.canAccept)
        XCTAssertTrue(NativeMitmRuntime.acquire()) // claims a reservation although live + reserved == cap
        XCTAssertFalse(NativeMitmRuntime.reserve())
        NativeMitmRuntime.release()
        NativeMitmRuntime.unreserve()
        XCTAssertTrue(NativeMitmRuntime.canAccept)
        NativeMitmRuntime.reservationTTL = 0
        Thread.sleep(forTimeInterval: 0.01)
        XCTAssertTrue(NativeMitmRuntime.reserve()) // expired ones no longer count
        NativeMitmRuntime.reservationTTL = 0
        Thread.sleep(forTimeInterval: 0.01)
        XCTAssertTrue(NativeMitmRuntime.canAccept)
    }

    func testBusyAnswers503AndDecisionDecoding() {
        driver.begin = { _ in FlowDecision.decode(#"{"id":0,"action":"busy","length":0}"#) }
        run(Upstream(response: Data()), request: "GET / HTTP/1.1\r\nHost: ex.com\r\n\r\n")
        XCTAssertTrue(client.text.hasPrefix("HTTP/1.1 503"), client.text)
        XCTAssertEqual(FlowDecision.decode("not json").action, .error)
        XCTAssertEqual(FlowDecision.decode(#"{"id":5,"action":"weird","length":3}"#).action, .unknown)
    }

    /// Key absent → NativeMitmRuntime.defaultOn; the app-group key is an override either way.
    func testRuntimeSwitchDefaultAndOverride() {
        let name = "NativeMitmSessionTests.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: name)!
        defer { d.removePersistentDomain(forName: name) }
        XCTAssertEqual(NativeMitmRuntime.enabled(in: d), NativeMitmRuntime.defaultOn)
        XCTAssertEqual(NativeMitmRuntime.enabled(in: nil), NativeMitmRuntime.defaultOn)
        d.set(false, forKey: NativeMitmRuntime.defaultsKey)
        XCTAssertFalse(NativeMitmRuntime.enabled(in: d))
        d.set(true, forKey: NativeMitmRuntime.defaultsKey)
        XCTAssertTrue(NativeMitmRuntime.enabled(in: d))
    }

    // MARK: body de-framer (S2Integration.swift)

    func testBodyDecoderChunkedAtEverySplit() throws {
        let wire = Data("5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\nNEXT".utf8)
        for split in 0...wire.count {
            let d = HTTPBodyDecoder(.chunked)
            var buf = Data(), out = Data(), done = false
            let parts = [wire.prefix(split), wire.suffix(from: split)]
            for (k, part) in parts.enumerated() {
                buf.append(contentsOf: part)
                if done { continue } // the body ended in an earlier part: the rest only accumulates
                let c = try d.feed(buf)
                buf.removeFirst(c.consumed); out.append(c.payload); done = c.done
                _ = k
            }
            XCTAssertTrue(done, "split \(split)")
            XCTAssertEqual(String(decoding: out, as: UTF8.self), "hello world", "split \(split)")
            XCTAssertEqual(String(decoding: buf, as: UTF8.self), "NEXT", "split \(split)")
        }
    }

    func testBodyDecoderLengthAndCloseAndErrors() throws {
        let d = HTTPBodyDecoder(.contentLength(3))
        let c = try d.feed(Data("abcdef".utf8))
        XCTAssertEqual(c.payload, Data("abc".utf8)); XCTAssertEqual(c.consumed, 3); XCTAssertTrue(c.done)
        XCTAssertThrowsError(try HTTPBodyDecoder(.contentLength(3)).finishAtEOF())
        let u = HTTPBodyDecoder(.untilClose)
        XCTAssertEqual(try u.feed(Data("xy".utf8)).payload, Data("xy".utf8))
        XCTAssertNoThrow(try u.finishAtEOF())
        XCTAssertThrowsError(try HTTPBodyDecoder(.chunked).feed(Data("zz\r\n".utf8)))
    }

    func testLaneCodecHeadParsingKeepsBytesAndPipelinedRest() throws {
        var buf = Data("\r\nGET /a HTTP/1.1\r\nhOsT: ex.com\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\nGET /b".utf8)
        let h = try XCTUnwrap(HTTPLaneCodec().parseRequestHead(&buf))
        XCTAssertEqual(h.method, "GET"); XCTAssertEqual(h.target, "/a"); XCTAssertEqual(h.host, "ex.com")
        XCTAssertEqual(h.headers.map(\.name), ["hOsT", "X-Dup", "X-Dup"])
        XCTAssertEqual(String(decoding: buf, as: UTF8.self), "GET /b")
        var partial = Data("GET /b HTTP/1.1\r\nHost".utf8)
        XCTAssertNil(try HTTPLaneCodec().parseRequestHead(&partial))
        XCTAssertEqual(partial.count, 21)
    }
}
