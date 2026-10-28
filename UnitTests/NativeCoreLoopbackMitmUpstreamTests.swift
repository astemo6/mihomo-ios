import XCTest
import Network
@testable import Tern

/// fix/nc-0.20.3-diag (device diag 0917, build 527): the MitM upstream path — NCUpstreamConnector: rule match → select
/// group → vmess + ws + TLS node (CDN shape: servername + ws Host header + path) → origin — against the loopback
/// fleet's `vmess-ws-tls-in` (sing-box, :18064). On device every MitM-forwarded request dialed a new ws connection and
/// a burst of them was refused `HTTP/1.1 403 Forbidden` by the CDN edge; these tests pin the connection pattern the
/// fix restores: keep-alive reuse, at most NCUpstreamConnector.dialGate.limit dials in flight per node, the route
/// named in a failure.
///
/// An extension of NativeCoreLoopbackTests so proto-loopback.yml's `-only-testing:TernUnitTests/NativeCoreLoopbackTests`
/// runs it (and its setUp skips it when the fleet is down outside CI).
extension NativeCoreLoopbackTests {

    private static let mitmEcho = NCTarget(host: "127.0.0.1", port: 18080)

    private static let mitmYAML = """
    mode: rule
    proxies:
      - name: loop-vmess-ws-cdn
        type: vmess
        server: 127.0.0.1
        port: 18064
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
        cipher: aes-128-gcm
        network: ws
        tls: true
        servername: localhost
        skip-cert-verify: true
        udp: true
        ws-opts:
          path: /vws
          headers:
            Host: cdn.loop.test
    proxy-groups:
      - {name: 终极清单, type: select, proxies: [loop-vmess-ws-cdn]}
    rules:
      - MATCH,终极清单
    """

    /// Loads the one-node config into a fresh engine and makes it the active one (what the tunnel does at start).
    private func startMitmEngine() throws -> (NativeCoreEngine, URL) {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-mitm-up-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(Self.mitmYAML.utf8).write(to: home.appendingPathComponent("runtime.yaml"))
        let engine = NativeCoreEngine()
        if let err = engine.load(home: home.path) { throw NSError(domain: "mitm", code: 1, userInfo: [NSLocalizedDescriptionKey: err]) }
        NativeCoreEngine.active = engine
        NCUpstreamConnector.idlePool.removeAll()
        return (engine, home)
    }

    private func stopMitmEngine(_ engine: NativeCoreEngine, _ home: URL) {
        NCUpstreamConnector.idlePool.removeAll()
        NativeCoreEngine.active = nil
        engine.stop()
        try? FileManager.default.removeItem(at: home)
    }

    private func mitmOpen(_ target: NCTarget, timeout: TimeInterval = 30) throws -> MitmUpstreamLease {
        let exp = expectation(description: "open \(target.host):\(target.port)")
        let lock = NSLock()
        var out: Result<MitmUpstreamLease, Error>?
        NCUpstreamConnector.shared.open(host: target.host, port: target.port, tls: false) { r in
            lock.lock(); out = r; lock.unlock()
            exp.fulfill()
        }
        wait(for: [exp], timeout: timeout)
        lock.lock(); defer { lock.unlock() }
        switch out {
        case .success(let l)?: return l
        case .failure(let e)?: throw e
        case nil: throw NSError(domain: "mitm", code: 2, userInfo: [NSLocalizedDescriptionKey: "open timed out"])
        }
    }

    /// Writes `payload` on the lease's ByteStream and reads until the same number of bytes came back.
    private func mitmEchoRoundTrip(_ lease: MitmUpstreamLease, _ payload: Data, timeout: TimeInterval = 20,
                                   file: StaticString = #filePath, line: UInt = #line) {
        let exp = expectation(description: "echo")
        let lock = NSLock()
        var got = Data()
        var failure: Error?
        func pump() {
            lease.stream.read(min: 1, max: 65536) { data, eof, err in
                lock.lock()
                if let data { got.append(data) }
                if let err { failure = err }
                let done = got.count >= payload.count || eof || err != nil
                lock.unlock()
                if done { exp.fulfill() } else { pump() }
            }
        }
        lease.stream.write(payload) { err in
            if let err { lock.lock(); failure = err; lock.unlock() }
        }
        pump()
        wait(for: [exp], timeout: timeout)
        lock.lock(); defer { lock.unlock() }
        XCTAssertNil(failure, "echo error", file: file, line: line)
        XCTAssertEqual(got, payload, "echoed bytes differ (\(got.count)/\(payload.count))", file: file, line: line)
    }

    /// One MitM upstream lease through the CDN-shaped vmess+ws+tls node carries bytes both ways; a released keep-alive
    /// lease is reused for the next open of the same origin (no second ws upgrade) and still carries bytes.
    func testMitmUpstreamThroughVMessWSTLSReusesKeepAlive() throws {
        let (engine, home) = try startMitmEngine()
        defer { stopMitmEngine(engine, home) }
        let before = NCUpstreamConnector.stats
        let payload = Data((0..<4096).map { UInt8(($0 * 13 + 5) & 0xff) })

        let first = try mitmOpen(Self.mitmEcho)
        XCTAssertFalse(first.wasReused)
        mitmEchoRoundTrip(first, payload)
        first.release(reusable: true)
        XCTAssertEqual(NCUpstreamConnector.idlePool.count, 1, "keep-alive lease parked")

        let second = try mitmOpen(Self.mitmEcho)
        XCTAssertTrue(second.wasReused, "the parked connection is reused")
        XCTAssertTrue(second === first, "same lease object back from the pool")
        mitmEchoRoundTrip(second, Data(payload.reversed()))
        second.release(reusable: false)
        XCTAssertEqual(NCUpstreamConnector.idlePool.count, 0)

        let after = NCUpstreamConnector.stats
        XCTAssertEqual(after.dials - before.dials, 1, "one proxy dial for two requests")
        XCTAssertEqual(after.reuses - before.reuses, 1)
    }

    /// A launch burst: 12 opens at once through one node all succeed, never more than `limit` dials in flight.
    func testMitmUpstreamBurstIsPacedPerNode() throws {
        let (engine, home) = try startMitmEngine()
        defer { stopMitmEngine(engine, home) }
        let gate = NCUpstreamConnector.dialGate
        let queuedBefore = gate.queuedTotal
        let n = 12
        let exp = expectation(description: "burst")
        exp.expectedFulfillmentCount = n
        let lock = NSLock()
        var leases: [MitmUpstreamLease] = []
        var errors: [String] = []
        var maxInFlight = 0
        let key = "loop-vmess-ws-cdn|127.0.0.1|18064"
        for _ in 0..<n {
            NCUpstreamConnector.shared.open(host: Self.mitmEcho.host, port: Self.mitmEcho.port, tls: false) { r in
                lock.lock()
                maxInFlight = max(maxInFlight, gate.inFlight(key))
                switch r {
                case .success(let l): leases.append(l)
                case .failure(let e): errors.append("\(e)")
                }
                lock.unlock()
                exp.fulfill()
            }
        }
        wait(for: [exp], timeout: 60)
        lock.lock(); let ls = leases, es = errors, peak = maxInFlight; lock.unlock()
        XCTAssertEqual(es, [], "every burst open succeeds")
        XCTAssertEqual(ls.count, n)
        XCTAssertLessThanOrEqual(peak, gate.limit, "dials in flight per node stay within the gate")
        XCTAssertGreaterThan(gate.queuedTotal - queuedBefore, 0, "the burst queued behind the gate")
        let payload = Data("tern-burst".utf8)
        for l in ls.prefix(3) { mitmEchoRoundTrip(l, payload) }
        ls.forEach { $0.release(reusable: false) }
    }

    /// A dial that cannot succeed names its route in the error (the device 502 line then says which policy / node).
    func testMitmUpstreamFailureNamesRoute() throws {
        // :18060 is the trojan-ws inbound (TLS, ws path /tj): TLS succeeds, the upgrade to /vws is refused — the device's
        // failure shape ("ws upgrade refused: HTTP/1.1 403 Forbidden" there, a 404 from sing-box here)
        let yaml = Self.mitmYAML.replacingOccurrences(of: "port: 18064", with: "port: 18060")
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-mitm-up-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(yaml.utf8).write(to: home.appendingPathComponent("runtime.yaml"))
        let engine = NativeCoreEngine()
        XCTAssertNil(engine.load(home: home.path))
        NativeCoreEngine.active = engine
        let savedDelay = NCUpstreamConnector.retryDelay
        NCUpstreamConnector.retryDelay = 0.05
        defer {
            NCUpstreamConnector.retryDelay = savedDelay
            stopMitmEngine(engine, home)
        }
        let before = NCUpstreamConnector.stats
        XCTAssertThrowsError(try mitmOpen(Self.mitmEcho, timeout: 60)) { e in
            let text = "\(e)"
            XCTAssertTrue(text.contains("via rule MATCH,终极清单 → 终极清单 (loop-vmess-ws-cdn)"), text)
            XCTAssertTrue(text.contains("ws upgrade refused"), text)
        }
        XCTAssertEqual(NCUpstreamConnector.stats.retries - before.retries, 1, "one retry of a transient dial failure")
    }
}
