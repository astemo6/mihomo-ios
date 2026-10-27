import XCTest

/// feat/nc-masque-warp: Cloudflare WARP MASQUE (cf-connect-ip + mTLS client identity + server-key pinning) against the
/// REAL Cloudflare endpoint. proto-loopback.yml job `masque-warp` registers a throwaway free WARP device on the runner
/// (tools/loopback/warp/register.py: POST /reg, then PATCH /reg/{id} enrolling a fresh P-256 key with key_type
/// secp256r1 / tunnel_type masque), passes the profile in TEST_RUNNER_NC_WARP_* and deletes the device afterwards.
/// No key is ever committed and no repository secret is needed.
///
/// Everything is the production path: NCMASQUEConnection (QUIC h3, SNI consumer-masque.cloudflareclient.com, client
/// identity from the WARP key, verify block pinning the endpoint key), NCMASQUEIPTunnel (`:protocol = cf-connect-ip`,
/// node `ip` / `ipv6` binding), the lwIP netif (NCMASQUEIPNetif.swift), TCP / UDP / DNS through it.
///
/// With TEST_RUNNER_NC_WARP_INTEROP=1 the tests FAIL (never skip) when the endpoint is unreachable; elsewhere they skip.
final class NCMASQUEWarpInteropTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "warp.interop.test")

    private func node(name: String = "warp-interop", privateKey: String? = nil, publicKey: String? = nil) -> NCProxy {
        var f: [String: NCJSONValue] = [
            "server": .string(env["NC_WARP_SERVER"] ?? ""), "port": .number(Double(env["NC_WARP_PORT"] ?? "") ?? 443),
            "private-key": .string(privateKey ?? env["NC_WARP_PRIV"] ?? ""),
            "public-key": .string(publicKey ?? env["NC_WARP_PUB"] ?? ""),
            "ip": .string(env["NC_WARP_IP4"] ?? ""),
            "mtu": .number(1280), "dns": .array([.string("1.1.1.1")]),
        ]
        if let v6 = env["NC_WARP_IP6"], !v6.isEmpty { f["ipv6"] = .string(v6) }
        return NCProxy(name: name, type: "masque", fields: f)
    }

    override func setUpWithError() throws {
        guard env["NC_WARP_INTEROP"] == "1" else {
            throw XCTSkip("WARP interop: set TEST_RUNNER_NC_WARP_INTEROP=1 with a registered device (proto-loopback.yml masque-warp)")
        }
        for k in ["NC_WARP_SERVER", "NC_WARP_PRIV", "NC_WARP_PUB", "NC_WARP_IP4"] {
            XCTAssertFalse((env[k] ?? "").isEmpty, "\(k) missing")
        }
        NCConnector.installMASQUEIPDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    // MARK: helpers

    private func dial(_ p: NCProxy, _ host: String, _ port: Int, timeout: TimeInterval = 60) -> (NCRelayStream?, Error?) {
        let exp = expectation(description: "dial \(host):\(port)")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: host, port: port), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: timeout)
        NSLog("[warp-interop] dial %@ %@:%d in %.2f s -> %@", p.name, host, port, Date().timeIntervalSince(t0),
              out.0 != nil ? "ok" : "\(String(describing: out.1))")
        return out
    }

    private func tls(_ raw: NCRelayStream, host: String) throws -> NCRelayStream {
        let s = NCTLSClientStream(raw: raw, config: .init(serverName: host, alpn: ["http/1.1"]), queue: q)
        let exp = expectation(description: "tls \(host)")
        var err: Error?
        q.async { s.startHandshake { e in err = e; exp.fulfill() } }
        wait(for: [exp], timeout: 60)
        if let err { throw err }
        return s
    }

    /// HTTP/1.0 GET over `s` until the server closes; returns (status line, lower-cased headers, de-chunked body).
    private func get(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 180) -> (String, String, Data) {
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
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-warp-interop\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else { return (String(decoding: all.prefix(200), as: UTF8.self), "", Data()) }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        var body = Data(all[r.upperBound...])
        let headers = head.lowercased()
        if headers.contains("transfer-encoding: chunked") { body = dechunk(body) }
        return (head.components(separatedBy: "\r\n").first ?? "", headers, body)
    }

    private func dechunk(_ d: Data) -> Data {
        var out = Data()
        var i = d.startIndex
        while let crlf = d[i...].range(of: Data([13, 10])) {
            let sizeLine = String(decoding: d[i..<crlf.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let n = Int(sizeLine.trimmingCharacters(in: .whitespaces), radix: 16), n > 0 else { break }
            let start = crlf.upperBound
            guard start + n <= d.endIndex else { out.append(d[start...]); break }
            out.append(d[start..<(start + n)])
            i = min(start + n + 2, d.endIndex)
        }
        return out
    }

    private func trace(_ p: NCProxy) throws -> String {
        let (s, err) = dial(p, "www.cloudflare.com", 443)
        let raw = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { raw.cancel() }
        let t = try tls(raw, host: "www.cloudflare.com")
        let (status, _, body) = get(t, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        XCTAssertTrue(status.contains(" 200"), status)
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[warp-interop] trace: %@", text.split(separator: "\n").filter { $0.hasPrefix("warp=") || $0.hasPrefix("colo=") || $0.hasPrefix("http=") || $0.hasPrefix("tls=") }.joined(separator: " "))
        return text
    }

    private func device(_ p: NCProxy) -> NCMQIPDevice? {
        NCLwIP.queue.sync { NCMQIPStack.shared.debugExisting(p) }
    }

    // MARK: tests

    /// HTTPS GET through TCP over cf-connect-ip: www.cloudflare.com/cdn-cgi/trace, certificate verified by the system
    /// roots, must report `warp=on` (the request left through WARP). Also checks the bound node address and MTU.
    func testHTTPSGetThroughWARP() throws {
        let p = node()
        let text = try trace(p)
        XCTAssertTrue(text.contains("warp=on") || text.contains("warp=plus"), text)
        let dev = try XCTUnwrap(device(p))
        NCLwIP.queue.sync {
            XCTAssertTrue(dev.ready)
            XCTAssertEqual(dev.params?.ipv4, env["NC_WARP_IP4"])
            NSLog("[warp-interop] device v4=%@ v6=%@ mtu=%d routes=%d", dev.params?.ipv4 ?? "-", dev.params?.ipv6 ?? "-",
                  Int(dev.mtu), dev.params?.routes.count ?? -1)
        }
    }

    /// A DNS query as plain UDP through the netif to 1.1.1.1:53, answer parsed.
    func testUDPDNSThroughWARP() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCMQIPStack.shared.acquire($0) })
        defer { session.cancel() }
        let qid: UInt16 = 0x7761
        var query: [UInt8] = [UInt8(qid >> 8), UInt8(qid & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["one", "one", "one", "one"] { query.append(UInt8(label.utf8.count)); query += Array(label.utf8) }
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
        timer.setEventHandler { session.send(Data(query), to: NCTarget(host: "1.1.1.1", port: 53)) }
        timer.resume()
        wait(for: [got], timeout: 60)
        timer.cancel()
        let ips = Set(q.sync { answer?.map { $0.string } ?? [] })
        NSLog("[warp-interop] one.one.one.one A = %@", ips.sorted().joined(separator: ","))
        XCTAssertFalse(ips.isDisjoint(with: ["1.1.1.1", "1.0.0.1"]), "\(ips)")
    }

    /// 1 MiB HTTPS download (speed.cloudflare.com) byte-count exact.
    func testOneMiBDownloadThroughWARP() throws {
        let p = node()
        let (s, err) = dial(p, "speed.cloudflare.com", 443)
        let raw = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { raw.cancel() }
        let t = try tls(raw, host: "speed.cloudflare.com")
        let t0 = Date()
        let (status, _, body) = get(t, host: "speed.cloudflare.com", path: "/__down?bytes=1048576")
        let dt = Date().timeIntervalSince(t0)
        XCTAssertTrue(status.contains(" 200"), status)
        XCTAssertEqual(body.count, 1_048_576)
        let dev = device(p)
        NSLog("[warp-interop] 1 MiB in %.2f s (%.1f Mbit/s); packets out %d in %d, tx dropped %d", dt,
              Double(body.count) * 8 / max(dt, 0.001) / 1e6,
              dev.map { d in NCLwIP.queue.sync { d.packetsOut } } ?? -1,
              dev.map { d in NCLwIP.queue.sync { d.packetsIn } } ?? -1,
              dev.map { d in NCLwIP.queue.sync { d.txDropped } } ?? -1)
    }

    /// The tunnel goes away (device torn down): the next flow dials a fresh cf-connect-ip session and works.
    func testReconnectAfterTunnelLoss() throws {
        let p = node()
        XCTAssertTrue(try trace(p).contains("warp="))
        NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
        Thread.sleep(forTimeInterval: 1)
        XCTAssertNil(device(p))
        let again = try trace(p)
        XCTAssertTrue(again.contains("warp=on") || again.contains("warp=plus"), again)
    }

    /// A P-256 key that was never enrolled: Cloudflare refuses the client; no stream, no device left behind.
    func testWrongPrivateKeyRejected() throws {
        let wrong = try XCTUnwrap(env["NC_WARP_WRONG_PRIV"], "NC_WARP_WRONG_PRIV missing")
        let p = node(name: "warp-wrong-priv", privateKey: wrong)
        let (s, err) = dial(p, "www.cloudflare.com", 443, timeout: 90)
        s?.cancel()
        XCTAssertNil(s, "an unenrolled key must not get a tunnel")
        let text = "\(String(describing: err))"
        NSLog("[warp-interop] wrong private key -> %@", text)
        XCTAssertTrue(text.contains(NCMASQUEWarp.warpRejected) || text.contains("被拒绝"), text)
        XCTAssertNil(device(p), "a refused node must not keep a device")
    }

    /// A pinned endpoint key that is not Cloudflare's: our verify block refuses the server — pin-mismatch error.
    func testWrongPublicKeyRejected() throws {
        let wrong = try XCTUnwrap(env["NC_WARP_WRONG_PUB"], "NC_WARP_WRONG_PUB missing")
        let p = node(name: "warp-wrong-pub", publicKey: wrong)
        let t0 = Date()
        let (s, err) = dial(p, "www.cloudflare.com", 443, timeout: 90)
        s?.cancel()
        XCTAssertNil(s, "a server whose key does not match public-key must be refused")
        XCTAssertLessThan(Date().timeIntervalSince(t0), 10, "pin mismatch must fail fast, not at the 15 s timeout")
        let text = "\(String(describing: err))"
        NSLog("[warp-interop] wrong public key -> %@", text)
        XCTAssertTrue(text.contains(NCMASQUEWarp.warpPinMismatch), text)
        XCTAssertNil(device(p))
    }
}
