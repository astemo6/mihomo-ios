import XCTest

/// fix/nc-openconnect-dp: the OpenConnect data plane against a REAL ocserv (tools/loopback/ocserv: Alpine + ocserv
/// 1.6 under QEMU on the macOS runner, TCP 443 forwarded to 127.0.0.1:18443). Everything after the TLS handshake
/// is the production path: auth (XML init + form POST), CONNECT /CSCOSSLC/tunnel, the lwIP netif on X-CSTP-Address
/// with X-CSTP-MTU, IP packets in CSTP DATA frames, X-CSTP-DNS over the tunnel, DPD, and reconnect with the cookie.
///
/// Lives in TernE2ETunnelTests because the netif (NCOpenConnectNetif.swift + lwip/nc_wg.c) is PacketTunnel code.
/// Runs in proto-loopback.yml job `openconnect` with TEST_RUNNER_NC_OC_LOOPBACK=1 — there it FAILS (never skips)
/// when the server is unreachable; elsewhere (e2e-replay only runs its own class) it skips.
///
/// Server-side constants (tools/loopback/ocserv/user-data): user tern / tern-pass, pool 10.77.0.0/24, server end
/// 10.77.0.1 with TCP echo :9000, UDP echo :9001, DNS :53 answering *.oc.test → 10.77.0.1.
final class NCOpenConnectLoopbackTests: XCTestCase {
    private let port = Int(ProcessInfo.processInfo.environment["NC_OC_PORT"] ?? "") ?? 18443
    private let echoIP = "10.77.0.1"
    private let q = DispatchQueue(label: "oc.loopback.test")

    private func node(password: String = "tern-pass", name: String = "oc-loop") -> NCProxy {
        NCProxy(name: name, type: "openconnect", fields: [
            "server": .string("127.0.0.1"), "port": .number(Double(port)),
            "username": .string("tern"), "password": .string(password),
            "skip-cert-verify": .bool(true), "sni": .string("ocserv.test"),
        ])
    }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["NC_OC_LOOPBACK"] == "1" else {
            throw XCTSkip("OpenConnect loopback: set TEST_RUNNER_NC_OC_LOOPBACK=1 with the ocserv VM up (proto-loopback.yml)")
        }
        NCConnector.installOpenConnectDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCOCStack.shared.teardownAll() }
        super.tearDown()
    }

    // MARK: helpers

    private func dial(_ p: NCProxy, _ host: String, _ port: Int, timeout: TimeInterval = 60,
                      file: StaticString = #filePath, line: UInt = #line) -> (NCRelayStream?, Error?) {
        let exp = expectation(description: "dial \(host):\(port)")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        NCConnector.connect(target: NCTarget(host: host, port: port), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: timeout)
        return out
    }

    private func pattern(_ n: Int, seed: UInt8) -> Data {
        var d = Data(count: n)
        d.withUnsafeMutableBytes { raw in
            let b = raw.bindMemory(to: UInt8.self)
            for i in 0..<n { b[i] = UInt8(truncatingIfNeeded: i &* 31 &+ Int(seed)) }
        }
        return d
    }

    /// Writes `payload` (16 KB chunks, each waiting for its send completion) and reads until as many bytes came
    /// back; returns what was read.
    private func echo(_ s: NCRelayStream, _ payload: Data, timeout: TimeInterval = 90) -> Data {
        let done = expectation(description: "echo \(payload.count)")
        var got = Data()
        var finished = false
        func finish() { if !finished { finished = true; done.fulfill() } }
        func read() {
            s.receive { d, _ in
                guard let d, !d.isEmpty else { finish(); return }
                got.append(d)
                if got.count >= payload.count { finish() } else { read() }
            }
        }
        q.async { read() }
        func write(_ off: Int) {
            guard off < payload.count else { return }
            let end = min(off + 16384, payload.count)
            s.send(payload.subdata(in: off..<end)) { self.q.async { write(end) } }
        }
        q.async { write(0) }
        wait(for: [done], timeout: timeout)
        return q.sync { got }
    }

    private func device(_ p: NCProxy) -> NCOCDevice? {
        NCLwIP.queue.sync { NCOCStack.shared.device(for: p).0 }
    }

    private func waitUntil(_ what: String, timeout: TimeInterval, _ cond: @escaping () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if NCLwIP.queue.sync(execute: cond) { return }
            Thread.sleep(forTimeInterval: 0.2)
        }
        XCTFail("timed out waiting for \(what)")
    }

    // MARK: tests

    /// Auth + CSTP + netif parameters, then a byte-exact 1 MiB TCP echo to the server end of the tunnel.
    func testTCPEchoThroughTunnel() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        NCLwIP.queue.sync {
            XCTAssertTrue(dev.ready)
            XCTAssertTrue(dev.has4)
            XCTAssertEqual(dev.params?.assignedIPv4?.hasPrefix("10.77.0."), true, "\(String(describing: dev.params))")
            XCTAssertEqual(dev.params?.dnsServers, ["10.77.0.1"])
            XCTAssertGreaterThan(dev.params?.mtu ?? 0, 1000)
            XCTAssertLessThanOrEqual(dev.params?.mtu ?? 0, 1400)
        }
        let small = pattern(1000, seed: 1)
        XCTAssertEqual(echo(stream, small), small)
        let big = pattern(1 << 20, seed: 7)
        let t0 = Date()
        let back = echo(stream, big)
        XCTAssertEqual(back.count, big.count)
        XCTAssertTrue(back == big, "1 MiB echo differs")
        NSLog("[oc-loopback] 1 MiB echo in %.2f s; frames out %d in %d, tx dropped %d",
              Date().timeIntervalSince(t0), NCLwIP.queue.sync { dev.framesOut }, NCLwIP.queue.sync { dev.framesIn },
              NCLwIP.queue.sync { dev.txDropped })
    }

    /// A domain target resolves through X-CSTP-DNS (dnsmasq behind ocserv), not the system resolver.
    func testDomainResolvesThroughTunnelDNS() throws {
        let p = node()
        let (s, err) = dial(p, "echo.oc.test", 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let msg = Data("hello through tunnel dns".utf8)
        XCTAssertEqual(echo(stream, msg), msg)
    }

    /// UDP from the netif (NCUDPWireGuardSession with the OpenConnect device) to the UDP echo.
    func testUDPEchoThroughTunnel() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCOCStack.shared.acquire($0) })
        defer { session.cancel() }
        let got = expectation(description: "udp reply")
        var reply: Data?
        session.onReply = { d in
            if reply == nil { reply = d; got.fulfill() }
        }
        let msg = Data("udp over cstp".utf8)
        // The first send waits for the tunnel inside resolve(); resend until an answer comes (UDP may be lost).
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { session.send(msg, to: NCTarget(host: self.echoIP, port: 9001)) }
        timer.resume()
        wait(for: [got], timeout: 60)
        timer.cancel()
        XCTAssertEqual(q.sync { reply }, msg)
    }

    /// DPD request → DPD response from ocserv.
    func testDeadPeerDetection() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        let before = NCLwIP.queue.sync { dev.dpdResponsesReceived }
        NCLwIP.queue.sync { dev.debugSendDPD() }
        waitUntil("DPD-RESP", timeout: 15) { dev.dpdResponsesReceived > before }
    }

    /// The TLS channel drops; the device reconnects with the session cookie, gets the same address
    /// (predictable-ips) and the SAME lwIP TCP flow keeps working.
    func testReconnectKeepsFlows() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        let first = pattern(4000, seed: 3)
        XCTAssertEqual(echo(stream, first), first)
        let addr = NCLwIP.queue.sync { dev.params?.assignedIPv4 }
        NCLwIP.queue.sync { dev.debugDropChannel() }
        waitUntil("reconnect", timeout: 45) { dev.ready && dev.reconnects >= 1 }
        XCTAssertEqual(NCLwIP.queue.sync { dev.params?.assignedIPv4 }, addr)
        let second = pattern(200_000, seed: 9)
        XCTAssertEqual(echo(stream, second), second, "flow did not survive the reconnect")
        // and a new flow works too
        let (s2, err2) = dial(p, echoIP, 9000)
        let stream2 = try XCTUnwrap(s2, "dial after reconnect failed: \(String(describing: err2))")
        defer { stream2.cancel() }
        let third = Data("after reconnect".utf8)
        XCTAssertEqual(echo(stream2, third), third)
    }

    /// Wrong password: the connector fails with the server's auth error (no hang, no netif).
    func testWrongPasswordFails() throws {
        let p = node(password: "wrong", name: "oc-bad")
        let (s, err) = dial(p, echoIP, 9000)
        XCTAssertNil(s)
        let text = "\(String(describing: err))"
        XCTAssertTrue(text.contains("openconnect"), text)
        XCTAssertNil(NCLwIP.queue.sync { NCOCStack.shared.debugExisting(p) }, "a failed node must not keep a device")
    }
}
