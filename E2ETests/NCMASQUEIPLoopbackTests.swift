import XCTest

/// fix/nc-masque-ip: the MASQUE CONNECT-IP (RFC 9484) data plane against a REAL CONNECT-IP proxy
/// (tools/loopback/connectip: the upstream connect-ip-go integration proxy in an Alpine VM under QEMU on the macOS
/// runner, QUIC UDP 4433 forwarded to 127.0.0.1:18446). Everything after the QUIC handshake is the production path:
/// HTTP/3 SETTINGS, Extended CONNECT `:protocol = connect-ip` on https://proxy:4433/vpn, ADDRESS_ASSIGN /
/// ROUTE_ADVERTISEMENT capsules, the lwIP netif on the assigned address, IP packets as HTTP Datagrams, DNS over the
/// tunnel.
///
/// Lives in TernE2ETunnelTests because the netif (NCMASQUEIPNetif.swift + lwip/nc_wg.c) is PacketTunnel code.
/// Runs in proto-loopback.yml job `masque-ip` with TEST_RUNNER_NC_MQIP_LOOPBACK=1 — there it FAILS (never skips)
/// when the proxy is unreachable; elsewhere it skips.
///
/// Server-side constants (tools/loopback/connectip/user-data): client address 10.89.0.2/32, route 10.89.1.0/24,
/// 10.89.1.1 with TCP echo :9000, UDP echo :9001, DNS :53 answering *.mq.test → 10.89.1.1, HTTP :8080
/// (/hello.txt, /big.txt = "tern-mq-0123456789\n" repeated to 304000 bytes).
final class NCMASQUEIPLoopbackTests: XCTestCase {
    private let port = Int(ProcessInfo.processInfo.environment["NC_MQIP_PORT"] ?? "") ?? 18446
    private let echoIP = "10.89.1.1"
    private let q = DispatchQueue(label: "mqip.loopback.test")

    private func node(uri: String = "https://proxy:4433/vpn", name: String = "mq-ip-loop") -> NCProxy {
        NCProxy(name: name, type: "masque", fields: [
            "server": .string("127.0.0.1"), "port": .number(Double(port)),
            "mode": .string("connect-ip"), "uri": .string(uri),
            "sni": .string("proxy"), "skip-cert-verify": .bool(true),
            "mtu": .number(1200), "dns": .array([.string("10.89.1.1")]),
        ])
    }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["NC_MQIP_LOOPBACK"] == "1" else {
            throw XCTSkip("MASQUE CONNECT-IP loopback: set TEST_RUNNER_NC_MQIP_LOOPBACK=1 with the proxy VM up (proto-loopback.yml)")
        }
        NCConnector.installMASQUEIPDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
        // The upstream proxy assigns the same address to every session; let the old one wind down.
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    // MARK: helpers

    private func dial(_ p: NCProxy, _ host: String, _ port: Int, timeout: TimeInterval = 60) -> (NCRelayStream?, Error?) {
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

    private func echo(_ s: NCRelayStream, _ payload: Data, timeout: TimeInterval = 120) -> Data {
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

    private func device(_ p: NCProxy) -> NCMQIPDevice? {
        NCLwIP.queue.sync { NCMQIPStack.shared.debugExisting(p) }
    }

    private func httpGet(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 120) -> (String, Data) {
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
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-mqip-loopback\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else { return (String(decoding: all.prefix(200), as: UTF8.self), Data()) }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        return (head.components(separatedBy: "\r\n").first ?? "", Data(all[r.upperBound...]))
    }

    // MARK: tests

    /// Extended CONNECT + capsules + netif parameters, then a byte-exact 1 MiB TCP echo through CONNECT-IP.
    func testTCPEchoThroughConnectIP() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        NCLwIP.queue.sync {
            XCTAssertTrue(dev.ready)
            XCTAssertTrue(dev.has4)
            XCTAssertEqual(dev.params?.ipv4, "10.89.0.2", "\(String(describing: dev.params))")
            XCTAssertEqual(Int(dev.mtu), NCMASQUE.connectIPMaxPacket) // node mtu 1200, capped by the datagram room
        }
        let small = pattern(1000, seed: 1)
        XCTAssertEqual(echo(stream, small), small)
        let big = pattern(1 << 20, seed: 7)
        let t0 = Date()
        let back = echo(stream, big)
        XCTAssertEqual(back.count, big.count)
        XCTAssertTrue(back == big, "1 MiB echo differs")
        NSLog("[mqip-loopback] 1 MiB echo in %.2f s; packets out %d in %d, tx dropped %d, routes %d",
              Date().timeIntervalSince(t0), NCLwIP.queue.sync { dev.packetsOut }, NCLwIP.queue.sync { dev.packetsIn },
              NCLwIP.queue.sync { dev.txDropped }, NCLwIP.queue.sync { dev.params?.routes.count ?? -1 })
    }

    /// ROUTE_ADVERTISEMENT: the proxy's 10.89.1.0/24 (all protocols) arrives as a capsule.
    func testRouteAdvertisement() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, NCLwIP.queue.sync(execute: { dev.params?.routes.isEmpty ?? true }) {
            Thread.sleep(forTimeInterval: 0.2)
        }
        let routes = NCLwIP.queue.sync { dev.params?.routes ?? [] }
        XCTAssertEqual(routes.first?.ipVersion, 4)
        XCTAssertEqual(routes.first.map { [UInt8]($0.startIP) }, [10, 89, 1, 0])
        XCTAssertEqual(routes.first.map { [UInt8]($0.endIP) }, [10, 89, 1, 255])
        XCTAssertEqual(routes.first?.ipProtocol, 0)
    }

    /// A domain target resolves through the node's `dns` (dnsmasq behind the proxy) over the tunnel.
    func testDomainResolvesThroughTunnelDNS() throws {
        let p = node()
        let (s, err) = dial(p, "echo.mq.test", 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let msg = Data("hello through connect-ip dns".utf8)
        XCTAssertEqual(echo(stream, msg), msg)
    }

    /// UDP from the netif (NCUDPWireGuardSession with the CONNECT-IP device) to the UDP echo.
    func testUDPEchoThroughConnectIP() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCMQIPStack.shared.acquire($0) })
        defer { session.cancel() }
        let got = expectation(description: "udp reply")
        var reply: Data?
        session.onReply = { d in
            if reply == nil { reply = d; got.fulfill() }
        }
        let msg = Data("udp over connect-ip".utf8)
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { session.send(msg, to: NCTarget(host: self.echoIP, port: 9001)) }
        timer.resume()
        wait(for: [got], timeout: 60)
        timer.cancel()
        XCTAssertEqual(q.sync { reply }, msg)
    }

    /// A DNS query as plain UDP through the netif to the resolver behind the proxy, answer parsed.
    func testUDPDNSThroughConnectIP() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCMQIPStack.shared.acquire($0) })
        defer { session.cancel() }
        let qid: UInt16 = 0x6d71
        var query: [UInt8] = [UInt8(qid >> 8), UInt8(qid & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["web", "mq", "test"] { query.append(UInt8(label.utf8.count)); query += Array(label.utf8) }
        query += [0, 0, 1, 0, 1]
        let got = expectation(description: "dns answer")
        var answer: [NCIP]?
        session.onReply = { d in
            guard answer == nil, let r = NCWGDevice.parseDNS([UInt8](d), id: qid, qtype: 1) else { return }
            answer = r
            got.fulfill()
        }
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { session.send(Data(query), to: NCTarget(host: self.echoIP, port: 53)) }
        timer.resume()
        wait(for: [got], timeout: 60)
        timer.cancel()
        XCTAssertEqual(q.sync { answer?.map { $0.string } }, ["10.89.1.1"])
    }

    /// A real HTTP fetch by name: tunnel DNS resolves web.mq.test, lwIP TCP over HTTP Datagrams carries a
    /// 304000-byte body that must arrive byte-exact.
    func testHTTPFetchThroughConnectIP() throws {
        let p = node()
        let (s1, e1) = dial(p, "web.mq.test", 8080)
        let small = try XCTUnwrap(s1, "dial failed: \(String(describing: e1))")
        let (status, body) = httpGet(small, host: "web.mq.test:8080", path: "/hello.txt")
        small.cancel()
        XCTAssertTrue(status.contains(" 200"), status)
        XCTAssertEqual(String(decoding: body, as: UTF8.self), "tern-masque-ip-ok\n")

        let (s2, e2) = dial(p, "web.mq.test", 8080)
        let big = try XCTUnwrap(s2, "dial failed: \(String(describing: e2))")
        defer { big.cancel() }
        let (status2, body2) = httpGet(big, host: "web.mq.test:8080", path: "/big.txt")
        XCTAssertTrue(status2.contains(" 200"), status2)
        var want = Data()
        let line = Data("tern-mq-0123456789\n".utf8)
        while want.count < 304_000 { want.append(line) }
        want = want.prefix(304_000)
        XCTAssertEqual(body2.count, want.count)
        XCTAssertTrue(body2 == want, "HTTP body differs")
    }

    /// The tunnel goes away (device torn down): the next flow dials a fresh CONNECT-IP session and works.
    func testRedialAfterTunnelLoss() throws {
        let p = node()
        let (s, err) = dial(p, echoIP, 9000)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        let first = Data("before".utf8)
        XCTAssertEqual(echo(stream, first), first)
        NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
        stream.cancel()
        Thread.sleep(forTimeInterval: 1)
        let (s2, err2) = dial(p, echoIP, 9000)
        let stream2 = try XCTUnwrap(s2, "redial failed: \(String(describing: err2))")
        defer { stream2.cancel() }
        let second = pattern(64_000, seed: 5)
        XCTAssertEqual(echo(stream2, second), second)
    }

    /// A template path the proxy does not serve: Extended CONNECT is refused (HTTP 404), no netif is left behind.
    func testWrongPathFails() throws {
        let p = node(uri: "https://proxy:4433/nope", name: "mq-ip-bad")
        let (s, err) = dial(p, echoIP, 9000)
        XCTAssertNil(s)
        let text = "\(String(describing: err))"
        XCTAssertTrue(text.contains("masque"), text)
        XCTAssertNil(device(p), "a failed node must not keep a device")
    }
}
