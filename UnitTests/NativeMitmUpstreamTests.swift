import Network
import XCTest
@testable import Mihomo

/// Native MitM stage 2, lane `upstream` (B8b): UpstreamConnection / UpstreamPool against a fake CONNECT relay on
/// loopback that behaves like bridge/mitm/relay.go (CONNECT only, "200 Connection established", 502 +
/// X-Tern-Error on dial failure), then echoes bytes.
final class NativeMitmUpstreamTests: XCTestCase {

    // MARK: fake relay

    final class FakeRelay {
        enum Mode { case echo, refuse, leftover, stall, tlsGarbage }
        let mode: Mode
        let queue = DispatchQueue(label: "test.fake-relay")
        private let listener: NWListener
        private var heads: [String] = []
        private var accepted = 0
        private var conns: [NWConnection] = []

        init(_ mode: Mode) throws {
            self.mode = mode
            let params = NWParameters.tcp
            params.requiredInterfaceType = .loopback
            params.allowLocalEndpointReuse = true
            listener = try NWListener(using: params, on: .any)
        }

        func start() throws -> Int {
            let ready = DispatchSemaphore(value: 0)
            var failure: Error?
            listener.stateUpdateHandler = { st in
                switch st {
                case .ready: ready.signal()
                case .failed(let e): failure = e; ready.signal()
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] c in self?.handle(c) }
            listener.start(queue: queue)
            if ready.wait(timeout: .now() + 5) == .timedOut { throw UpstreamError.timeout }
            if let failure { throw failure }
            return Int(listener.port?.rawValue ?? 0)
        }

        func stop() {
            queue.sync {
                listener.cancel()
                conns.forEach { $0.cancel() }
                conns.removeAll()
            }
        }

        var recordedHeads: [String] { queue.sync { heads } }
        var acceptedCount: Int { queue.sync { accepted } }

        private func handle(_ c: NWConnection) {
            accepted += 1
            conns.append(c)
            c.start(queue: queue)
            readHead(c, Data())
        }

        private func readHead(_ c: NWConnection, _ acc: Data) {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
                guard let self else { return }
                var acc = acc
                if let data { acc.append(data) }
                if let r = acc.range(of: Data("\r\n\r\n".utf8)) {
                    self.heads.append(String(decoding: acc.subdata(in: acc.startIndex..<r.upperBound), as: UTF8.self))
                    self.respond(c, rest: acc.subdata(in: r.upperBound..<acc.endIndex))
                } else if done || err != nil {
                    c.cancel()
                } else {
                    self.readHead(c, acc)
                }
            }
        }

        private func respond(_ c: NWConnection, rest: Data) {
            let ok = Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8)
            switch mode {
            case .echo:
                c.send(content: ok, completion: .idempotent)
                if !rest.isEmpty { c.send(content: rest, completion: .idempotent) }
                echo(c)
            case .leftover:
                c.send(content: ok + Data("EARLY".utf8), completion: .idempotent)
                echo(c)
            case .refuse:
                let r = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nX-Tern-Error: dial tcp: connection refused\r\n\r\n"
                c.send(content: Data(r.utf8), contentContext: .finalMessage, isComplete: true, completion: .idempotent)
            case .stall:
                break
            case .tlsGarbage:
                c.send(content: ok, completion: .idempotent)
                c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { _, _, _, _ in
                    c.send(content: Data("HTTP/1.1 400 not tls\r\n\r\n".utf8), contentContext: .finalMessage,
                           isComplete: true, completion: .idempotent)
                }
            }
        }

        /// Echo; "QUIT" → FIN; client FIN → "BYE" + FIN.
        private func echo(_ c: NWConnection) {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
                if let data, !data.isEmpty {
                    if String(decoding: data, as: UTF8.self) == "QUIT" {
                        c.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                        return
                    }
                    c.send(content: data, completion: .idempotent)
                }
                if done {
                    c.send(content: Data("BYE".utf8), contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                    return
                }
                if err != nil { return }
                self?.echo(c)
            }
        }
    }

    private var relays: [FakeRelay] = []

    override func tearDown() {
        relays.forEach { $0.stop() }
        relays.removeAll()
        super.tearDown()
    }

    private func relay(_ mode: FakeRelay.Mode) throws -> (FakeRelay, Int) {
        let r = try FakeRelay(mode)
        relays.append(r)
        return (r, try r.start())
    }

    private func pool(port: Int, _ cfg: UpstreamPool.Config = UpstreamPool.Config()) -> UpstreamPool {
        UpstreamPool(config: cfg, relayPort: { port })
    }

    // MARK: helpers

    private func acquire(_ p: UpstreamPool, _ t: UpstreamTarget, timeout: TimeInterval = 5) -> Result<UpstreamConnection, UpstreamError> {
        let e = expectation(description: "acquire \(t)")
        var out: Result<UpstreamConnection, UpstreamError> = .failure(.timeout)
        p.acquire(t) { r in out = r; e.fulfill() }
        wait(for: [e], timeout: timeout)
        return out
    }

    private func write(_ c: UpstreamConnection, _ d: Data) {
        let e = expectation(description: "write")
        c.write(d) { err in XCTAssertNil(err); e.fulfill() }
        wait(for: [e], timeout: 5)
    }

    /// Reads until `count` bytes or EOF; returns (bytes, sawEOF, error).
    private func read(_ c: UpstreamConnection, count: Int = .max, timeout: TimeInterval = 5) -> (Data, Bool, Error?) {
        var acc = Data()
        var eof = false
        var error: Error?
        while acc.count < count, !eof, error == nil {
            let e = expectation(description: "read")
            var timedOut = true
            c.read(min: 1, max: 65536) { d, done, err in
                if let d { acc.append(d) }
                eof = done
                error = err
                timedOut = false
                e.fulfill()
            }
            wait(for: [e], timeout: timeout)
            if timedOut { break }
        }
        return (acc, eof, error)
    }

    private func settle(_ seconds: TimeInterval = 0.3) {
        let e = expectation(description: "settle")
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { e.fulfill() }
        wait(for: [e], timeout: seconds + 5)
    }

    // MARK: tests

    func testConnectHeadPolicyAndRawEcho() throws {
        let (r, port) = try relay(.echo)
        let p = pool(port: port)
        let c = try acquire(p, UpstreamTarget(host: "origin.test", port: 80, tls: false, policy: "DIRECT")).get()
        XCTAssertFalse(c.reused)
        // Every byte value, unchanged (raw stream, no transformation).
        let blob = Data((0..<4096).map { UInt8($0 % 256) })
        write(c, blob)
        let (got, eof, err) = read(c, count: blob.count)
        XCTAssertNil(err)
        XCTAssertFalse(eof)
        XCTAssertEqual(got, blob)
        let head = try XCTUnwrap(r.recordedHeads.first)
        XCTAssertTrue(head.hasPrefix("CONNECT origin.test:80 HTTP/1.1\r\n"), head)
        XCTAssertTrue(head.contains("\r\nHost: origin.test:80\r\n"), head)
        XCTAssertTrue(head.contains("\r\nX-Tern-Policy: DIRECT\r\n"), head)
        c.close()
    }

    func testIPv6AuthorityIsBracketed() throws {
        let (r, port) = try relay(.echo)
        let c = try acquire(pool(port: port), UpstreamTarget(host: "[2001:db8::1]", port: 8080, tls: false)).get()
        XCTAssertTrue(r.recordedHeads.first?.hasPrefix("CONNECT [2001:db8::1]:8080 HTTP/1.1\r\n") == true, r.recordedHeads.first ?? "")
        XCTAssertFalse(r.recordedHeads.first?.contains("X-Tern-Policy") == true)
        c.close()
    }

    func testRelayRefusalSurfacesStatusAndReason() throws {
        let (_, port) = try relay(.refuse)
        let p = pool(port: port)
        let res = acquire(p, UpstreamTarget(host: "down.test", port: 443, tls: false))
        XCTAssertEqual(res.failureValue, .proxyRefused(status: 502, reason: "dial tcp: connection refused"))
        XCTAssertEqual(p.statsNow().dialFailures, 1)
    }

    func testBytesAfterReplyAreDeliveredFirst() throws {
        let (_, port) = try relay(.leftover)
        let c = try acquire(pool(port: port), UpstreamTarget(host: "o.test", port: 80, tls: false)).get()
        XCTAssertEqual(String(decoding: read(c, count: 5).0, as: UTF8.self), "EARLY")
        write(c, Data("ping".utf8))
        XCTAssertEqual(String(decoding: read(c, count: 4).0, as: UTF8.self), "ping")
        c.close()
    }

    func testPoolReusesIdleConnection() throws {
        let (r, port) = try relay(.echo)
        let p = pool(port: port)
        let t = UpstreamTarget(host: "keep.test", port: 80, tls: false)
        let c1 = try acquire(p, t).get()
        write(c1, Data("a".utf8))
        XCTAssertEqual(read(c1, count: 1).0, Data("a".utf8))
        p.release(c1, reusable: true)
        settle(0.2)
        XCTAssertEqual(p.statsNow().idle, 1)
        let c2 = try acquire(p, t).get()
        XCTAssertTrue(c2 === c1)
        XCTAssertTrue(c2.reused)
        write(c2, Data("b".utf8))
        XCTAssertEqual(read(c2, count: 1).0, Data("b".utf8))
        // A different policy is a different pool key.
        let c3 = try acquire(p, UpstreamTarget(host: "keep.test", port: 80, tls: false, policy: "Proxy")).get()
        XCTAssertFalse(c3 === c1)
        let s = p.statsNow()
        XCTAssertEqual(s.dials, 2)
        XCTAssertEqual(s.reuses, 1)
        XCTAssertEqual(r.acceptedCount, 2)
        c2.close()
        c3.close()
    }

    func testNotReusableIsClosed() throws {
        let (_, port) = try relay(.echo)
        let p = pool(port: port)
        let t = UpstreamTarget(host: "x.test", port: 80, tls: false)
        let c1 = try acquire(p, t).get()
        p.release(c1, reusable: false)
        settle(0.2)
        XCTAssertEqual(p.statsNow().idle, 0)
        let c2 = try acquire(p, t).get()
        XCTAssertFalse(c2 === c1)
        // Unread bytes also make a connection unpoolable.
        write(c2, Data("left".utf8))
        settle(0.3)
        let peek = expectation(description: "peek")
        c2.read(min: 1, max: 1) { _, _, _ in peek.fulfill() } // pulls the echo into the buffer, consumes 1 byte
        wait(for: [peek], timeout: 5)
        p.release(c2, reusable: true)
        settle(0.2)
        XCTAssertEqual(p.statsNow().idle, 0)
    }

    func testIdleTimeoutAndCaps() throws {
        let (_, port) = try relay(.echo)
        var cfg = UpstreamPool.Config()
        cfg.idleTimeout = 0.3
        cfg.maxIdlePerHost = 1
        cfg.maxIdleTotal = 2
        let p = pool(port: port, cfg)
        let a = UpstreamTarget(host: "a.test", port: 80, tls: false)
        let b = UpstreamTarget(host: "b.test", port: 80, tls: false)
        let c = UpstreamTarget(host: "c.test", port: 80, tls: false)
        let a1 = try acquire(p, a).get(), a2 = try acquire(p, a).get()
        p.release(a1, reusable: true)
        p.release(a2, reusable: true)
        settle(0.1)
        XCTAssertEqual(p.statsNow().idle, 1, "per-host cap")
        let b1 = try acquire(p, b).get(), c1 = try acquire(p, c).get()
        p.release(b1, reusable: true)
        p.release(c1, reusable: true)
        settle(0.1)
        var s = p.statsNow()
        XCTAssertEqual(s.idle, 2, "global cap")
        XCTAssertEqual(s.idleEvicted, 2)
        settle(0.6)
        s = p.statsNow()
        XCTAssertEqual(s.idle, 0, "idle timeout")
        XCTAssertEqual(s.idleExpired, 2)
    }

    func testServerCloseWhileIdleEvicts() throws {
        let (_, port) = try relay(.echo)
        let p = pool(port: port)
        let t = UpstreamTarget(host: "bye.test", port: 80, tls: false)
        let c1 = try acquire(p, t).get()
        write(c1, Data("QUIT".utf8)) // server FINs shortly after
        p.release(c1, reusable: true)
        settle(0.5)
        let s = p.statsNow()
        XCTAssertEqual(s.idle, 0)
        XCTAssertEqual(s.idleEvicted, 1)
        let c2 = try acquire(p, t).get()
        XCTAssertFalse(c2 === c1)
        XCTAssertFalse(c2.reused)
        c2.close()
    }

    func testHalfClose() throws {
        let (_, port) = try relay(.echo)
        let p = pool(port: port)
        let c = try acquire(p, UpstreamTarget(host: "half.test", port: 80, tls: false)).get()
        write(c, Data("abc".utf8))
        let e = expectation(description: "shutdown")
        c.shutdownWrite { err in XCTAssertNil(err); e.fulfill() }
        wait(for: [e], timeout: 5)
        let (got, eof, err) = read(c)
        XCTAssertNil(err)
        XCTAssertTrue(eof)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "abcBYE")
        let w = expectation(description: "write after shutdown")
        c.write(Data("x".utf8)) { err in XCTAssertNotNil(err); w.fulfill() }
        wait(for: [w], timeout: 5)
        p.release(c, reusable: true)
        settle(0.2)
        XCTAssertEqual(p.statsNow().idle, 0)
    }

    func testCloseFailsPendingRead() throws {
        let (_, port) = try relay(.echo)
        let c = try acquire(pool(port: port), UpstreamTarget(host: "r.test", port: 80, tls: false)).get()
        let e = expectation(description: "pending read")
        c.read(min: 1, max: 10) { d, done, err in
            XCTAssertNil(d)
            XCTAssertFalse(done)
            XCTAssertEqual(err as? UpstreamError, .closed)
            e.fulfill()
        }
        c.close()
        wait(for: [e], timeout: 5)
    }

    func testCancelWhileDialingAndTimeout() throws {
        let (_, port) = try relay(.stall)
        let p = pool(port: port)
        let t = UpstreamTarget(host: "slow.test", port: 80, tls: false)
        let e = expectation(description: "cancelled")
        let a = p.acquire(t) { r in
            XCTAssertEqual(r.failureValue, .cancelled)
            e.fulfill()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { a.cancel() }
        wait(for: [e], timeout: 5)

        var cfg = UpstreamPool.Config()
        cfg.connectTimeout = 0.3
        XCTAssertEqual(acquire(pool(port: port, cfg), t).failureValue, .timeout)
    }

    func testRelayDownAndInvalidTargets() throws {
        XCTAssertEqual(acquire(pool(port: 0), UpstreamTarget(host: "a.test", port: 80, tls: false)).failureValue, .relayUnavailable)
        let p = pool(port: 1)
        XCTAssertEqual(acquire(p, UpstreamTarget(host: "a.test\r\nX-Evil: 1", port: 80, tls: false)).failureValue, .invalidTarget("host"))
        XCTAssertEqual(acquire(p, UpstreamTarget(host: "a.test", port: 0, tls: false)).failureValue, .invalidTarget("port"))
        XCTAssertEqual(acquire(p, UpstreamTarget(host: "a.test", port: 80, tls: false, policy: "P\r\nX: y")).failureValue, .invalidTarget("policy"))
    }

    func testReplyParsing() {
        func parse(_ s: String) -> Result<Void, UpstreamError> { UpstreamConnection.parseReply(Data(s.utf8)) }
        XCTAssertNil(parse("HTTP/1.1 200 Connection established\r\n\r\n").failureValue)
        XCTAssertNil(parse("HTTP/1.0 200 OK\r\nProxy-Agent: x\r\n\r\n").failureValue)
        XCTAssertEqual(parse("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n").failureValue,
                       .proxyRefused(status: 405, reason: "Method Not Allowed"))
        XCTAssertEqual(parse("SSH-2.0-OpenSSH\r\n\r\n").failureValue, .malformedProxyReply)
    }

    /// tls mode: Network.framework's CONNECT must reach our relay (ProxyConfiguration on loopback, iOS 17+), and a
    /// non-TLS answer after the 200 must fail the open instead of hanging or yielding a stream.
    func testTLSModeGoesThroughRelay() throws {
        let (r, port) = try relay(.tlsGarbage)
        let res = acquire(pool(port: port), UpstreamTarget(host: "origin.test", port: 443, tls: true), timeout: 15)
        if #available(iOS 17.0, *) {
            XCTAssertNotNil(res.failureValue, "TLS against a plain-text server must fail")
            if case .connectFailed = res.failureValue {} else if case .timeout = res.failureValue {} else {
                XCTFail("unexpected \(String(describing: res.failureValue))")
            }
            let head = r.recordedHeads.first ?? ""
            XCTAssertTrue(head.hasPrefix("CONNECT origin.test:443 "), "relay saw: \(head.debugDescription)")
        } else {
            if case .unsupported = res.failureValue {} else { XCTFail("iOS 16 must report unsupported") }
        }
    }
}

private extension Result {
    var failureValue: Failure? {
        if case .failure(let e) = self { return e }
        return nil
    }
}
