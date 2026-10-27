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
/// 10.77.0.1 with TCP echo :9000, UDP echo :9001, DNS :53 answering *.oc.test → 10.77.0.1, HTTP :8080 (busybox
/// httpd: /hello.txt, /big.txt = "tern-oc-0123456789\n" repeated to 304000 bytes).
final class NCOpenConnectLoopbackTests: XCTestCase {
    private let port = Int(ProcessInfo.processInfo.environment["NC_OC_PORT"] ?? "") ?? 18443
    private let echoIP = "10.77.0.1"
    private let q = DispatchQueue(label: "oc.loopback.test")

    /// DTLS on by default: UDP 443 of the VM is forwarded to the same host port as TCP, so `dtls-port` points there.
    private func node(password: String = "tern-pass", name: String = "oc-loop", dtls: Bool = true) -> NCProxy {
        NCProxy(name: name, type: "openconnect", fields: [
            "server": .string("127.0.0.1"), "port": .number(Double(port)),
            "username": .string("tern"), "password": .string(password),
            "skip-cert-verify": .bool(true), "sni": .string("ocserv.test"),
            "dtls": .bool(dtls), "dtls-port": .number(Double(port)),
        ])
    }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["NC_OC_LOOPBACK"] == "1" else {
            throw XCTSkip("OpenConnect loopback: set TEST_RUNNER_NC_OC_LOOPBACK=1 with the ocserv VM up (proto-loopback.yml)")
        }
        NCConnector.installOpenConnectDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync {
            NCOCStack.shared.teardownAll()
            NCOCDevice.debugDTLSPortOverride = nil
        }
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
        let secs = Date().timeIntervalSince(t0)
        NSLog("[oc-loopback] 1 MiB echo in %.2f s; frames out %d in %d, tx dropped %d, max in flight %d",
              secs, NCLwIP.queue.sync { dev.framesOut }, NCLwIP.queue.sync { dev.framesIn },
              NCLwIP.queue.sync { dev.txDropped }, NCLwIP.queue.sync { dev.maxInFlightSeen })
        NSLog("[oc-loopback] DTLS %@ out %d in %d", NCLwIP.queue.sync { dev.dtlsState },
              NCLwIP.queue.sync { dev.dtlsPacketsOut }, NCLwIP.queue.sync { dev.dtlsPacketsIn })
        XCTAssertLessThan(secs, 30)
    }

    /// fix/nc-oc-dtls: CSTP-only throughput with several frames in flight (each its own TLS record — ocserv rejects
    /// coalesced frames, so a byte-exact echo also proves no record carried two frames). 1da28ca (one frame per
    /// write) took 2.68 s for this echo (mirror run 40454139517).
    func testCSTPPipelinedThroughput() throws {
        let p = node(name: "oc-cstp", dtls: false)
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        let big = pattern(1 << 20, seed: 11)
        let t0 = Date()
        let back = echo(stream, big)
        let secs = Date().timeIntervalSince(t0)
        XCTAssertTrue(back == big, "1 MiB echo differs")
        NSLog("[oc-loopback] CSTP-only 1 MiB echo in %.2f s; max in flight %d, frames out %d, tx dropped %d",
              secs, NCLwIP.queue.sync { dev.maxInFlightSeen }, NCLwIP.queue.sync { dev.framesOut },
              NCLwIP.queue.sync { dev.txDropped })
        XCTAssertEqual(NCLwIP.queue.sync { dev.dtlsPacketsOut }, 0)
        XCTAssertGreaterThan(NCLwIP.queue.sync { dev.maxInFlightSeen }, 1, "uplink never pipelined")
        XCTAssertLessThan(secs, 30)
    }

    /// fix/nc-oc-dtls: the DTLS data channel (ocserv PSK-NEGOTIATE): handshake with the exporter PSK and the App-ID
    /// session id, then IP packets both ways over DTLS, DTLS DPD answered.
    func testDTLSDataChannel() throws {
        let p = node(name: "oc-dtls")
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        NCLwIP.queue.sync {
            NSLog("[oc-loopback] DTLS params port %@ suite %@ app-id %@ mtu %@", "\(dev.params?.dtlsPort ?? -1)",
                  dev.params?.dtlsCipherSuite ?? "-", dev.params?.dtlsAppID ?? "-", "\(dev.params?.dtlsMTU ?? -1)")
        }
        waitUntil("DTLS up", timeout: 20) { dev.dtlsState == "up" }
        NSLog("[oc-loopback] DTLS state %@", NCLwIP.queue.sync { dev.dtlsState })
        let big = pattern(1 << 20, seed: 5)
        let t0 = Date()
        let back = echo(stream, big)
        XCTAssertTrue(back == big, "1 MiB echo over DTLS differs")
        NSLog("[oc-loopback] DTLS 1 MiB echo in %.2f s; dtls out %d in %d, cstp frames out %d",
              Date().timeIntervalSince(t0), NCLwIP.queue.sync { dev.dtlsPacketsOut },
              NCLwIP.queue.sync { dev.dtlsPacketsIn }, NCLwIP.queue.sync { dev.framesOut })
        XCTAssertGreaterThan(NCLwIP.queue.sync { dev.dtlsPacketsOut }, 100)
        XCTAssertGreaterThan(NCLwIP.queue.sync { dev.dtlsPacketsIn }, 100)
        let before = NCLwIP.queue.sync { dev.debugDTLSDPDResponses }
        NCLwIP.queue.sync { dev.debugDTLSDPD() }
        waitUntil("DTLS DPD-RESP", timeout: 10) { dev.debugDTLSDPDResponses > before }
        // DTLS dies mid-flow → the same lwIP flow continues over CSTP.
        NCLwIP.queue.sync { dev.debugKillDTLS() }
        XCTAssertTrue(NCLwIP.queue.sync { dev.dtlsState.hasPrefix("fallback") })
        let after = pattern(100_000, seed: 6)
        XCTAssertEqual(echo(stream, after), after, "flow did not continue over CSTP after DTLS died")
    }

    /// fix/nc-oc-dtls: UDP blocked (DTLS sent to a closed port) → handshake fails, CSTP carries everything.
    func testDTLSBlockedFallsBackToCSTP() throws {
        NCLwIP.queue.sync { NCOCDevice.debugDTLSPortOverride = 9 } // discard port, nothing listens
        let p = node(name: "oc-dtls-blocked")
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        let first = pattern(50_000, seed: 2)
        XCTAssertEqual(echo(stream, first), first, "CSTP must carry traffic while DTLS is attempted")
        waitUntil("DTLS fallback", timeout: 20) { dev.dtlsState.hasPrefix("fallback") }
        NSLog("[oc-loopback] blocked DTLS → %@", NCLwIP.queue.sync { dev.dtlsState })
        XCTAssertEqual(NCLwIP.queue.sync { dev.dtlsUps }, 0)
        let second = pattern(200_000, seed: 4)
        XCTAssertEqual(echo(stream, second), second)
        XCTAssertEqual(NCLwIP.queue.sync { dev.dtlsPacketsOut }, 0)
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

    /// Reads an HTTP/1.0 response to EOF (the server closes) and returns (status line, body).
    private func httpGet(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 90) -> (String, Data) {
        let done = expectation(description: "GET \(path)")
        var raw = Data()
        var finished = false
        func finish() { if !finished { finished = true; done.fulfill() } }
        func read() {
            s.receive { d, _ in
                guard let d, !d.isEmpty else { finish(); return }
                raw.append(d)
                read()
            }
        }
        q.async {
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-oc-loopback\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else { return (String(decoding: all.prefix(200), as: UTF8.self), Data()) }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        return (head.components(separatedBy: "\r\n").first ?? "", Data(all[r.upperBound...]))
    }

    /// A real HTTP fetch through the tunnel by name: X-CSTP-DNS resolves web.oc.test, lwIP TCP over CSTP carries the
    /// request and a 304000-byte body that must arrive byte-exact.
    func testHTTPFetchThroughTunnel() throws {
        let p = node()
        let (s1, e1) = dial(p, "web.oc.test", 8080)
        let small = try XCTUnwrap(s1, "dial failed: \(String(describing: e1))")
        let (status, body) = httpGet(small, host: "web.oc.test:8080", path: "/hello.txt")
        small.cancel()
        XCTAssertTrue(status.contains(" 200"), status)
        XCTAssertEqual(String(decoding: body, as: UTF8.self), "tern-openconnect-ok\n")

        let (s2, e2) = dial(p, "web.oc.test", 8080)
        let big = try XCTUnwrap(s2, "dial failed: \(String(describing: e2))")
        defer { big.cancel() }
        let t0 = Date()
        let (status2, body2) = httpGet(big, host: "web.oc.test:8080", path: "/big.txt")
        XCTAssertTrue(status2.contains(" 200"), status2)
        var want = Data()
        let line = Data("tern-oc-0123456789\n".utf8)
        while want.count < 304_000 { want.append(line) }
        want = want.prefix(304_000)
        XCTAssertEqual(body2.count, want.count)
        XCTAssertTrue(body2 == want, "HTTP body differs")
        NSLog("[oc-loopback] HTTP 304000 B in %.2f s", Date().timeIntervalSince(t0))
    }

    /// A DNS query as plain UDP through the netif to the VPN's resolver (X-CSTP-DNS), answer parsed.
    func testUDPDNSThroughTunnel() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCOCStack.shared.acquire($0) })
        defer { session.cancel() }
        let qid: UInt16 = 0x7a31
        var query: [UInt8] = [UInt8(qid >> 8), UInt8(qid & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["echo", "oc", "test"] { query.append(UInt8(label.utf8.count)); query += Array(label.utf8) }
        query += [0, 0, 1, 0, 1]
        let got = expectation(description: "dns answer")
        var answer: [NCIP]?
        session.onReply = { d in
            guard answer == nil, let r = NCWGDevice.parseDNS([UInt8](d), id: qid, qtype: 1) else { return }
            answer = r
            got.fulfill()
        }
        let dns = echoIP // = the X-CSTP-DNS ocserv announces (asserted in testTCPEchoThroughTunnel)
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { session.send(Data(query), to: NCTarget(host: dns, port: 53)) }
        timer.resume()
        wait(for: [got], timeout: 60)
        timer.cancel()
        XCTAssertEqual(q.sync { answer?.map { $0.string } }, ["10.77.0.1"])
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

    /// fix/nc-oc-dtls: the server's split-tunnel routes decide which destinations use the node. ocserv announces
    /// include 10.77.0.0/24 and exclude 10.77.0.192/26; 127.0.0.1 is outside, so a flow to the host's forwarded
    /// ocserv port goes DIRECT (through the tunnel 127.0.0.1 would be the VM's own loopback with nothing listening).
    func testSplitRoutes() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        NCLwIP.queue.sync {
            NSLog("[oc-loopback] split include %@ exclude %@", "\(dev.params?.splitIncludes ?? [])",
                  "\(dev.params?.splitExcludes ?? [])")
            XCTAssertFalse(dev.params?.splitIncludes.isEmpty ?? true, "no X-CSTP-Split-Include")
            XCTAssertFalse(dev.params?.splitExcludes.isEmpty ?? true, "no X-CSTP-Split-Exclude")
            XCTAssertTrue(dev.routesThroughTunnel(NCIP("10.77.0.1")!))
            XCTAssertTrue(dev.routesThroughTunnel(NCIP("10.77.0.100")!))
            XCTAssertFalse(dev.routesThroughTunnel(NCIP("10.77.0.200")!))
            XCTAssertFalse(dev.routesThroughTunnel(NCIP("127.0.0.1")!))
            XCTAssertFalse(dev.routesThroughTunnel(NCIP("1.1.1.1")!))
        }
        let before = NCLwIP.queue.sync { dev.splitDirect }
        let framesBefore = NCLwIP.queue.sync { dev.framesOut }
        let (d, derr) = dial(p, "127.0.0.1", port)
        let direct = try XCTUnwrap(d, "split-excluded dial failed: \(String(describing: derr))")
        direct.cancel()
        XCTAssertEqual(NCLwIP.queue.sync { dev.splitDirect }, before + 1)
        // A direct dial sends no CSTP DATA (keepalive/DPD may add a frame or two at most).
        XCTAssertLessThanOrEqual(NCLwIP.queue.sync { dev.framesOut } - framesBefore, 2)
        // Inside the include the same node still tunnels.
        let msg = Data("still tunnelled".utf8)
        XCTAssertEqual(echo(stream, msg), msg)
    }

    /// fix/nc-oc-dtls: flow errors on the OpenConnect netif say "openconnect:", not "wireguard:".
    func testFlowErrorsNameOpenConnect() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9) // nothing listens on 10.77.0.1:9 → RST through the tunnel
        XCTAssertNil(s)
        let text = "\(String(describing: err))"
        XCTAssertTrue(text.contains("openconnect"), text)
        XCTAssertFalse(text.contains("wireguard"), text)
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
