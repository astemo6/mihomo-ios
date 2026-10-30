import XCTest

/// verify/kit-amneziawg PROBE (throwaway scaffolding, not for merge): the production WireGuard
/// outbound with AmneziaWG obfuscation (NCWireGuard.swift lwIP netif, dialer installed exactly
/// like PacketTunnelProvider does) against the REAL kit server on zhiheng — amneziawg-go
/// userspace, UDP 24035, peer 10.67.0.2/32, Jc 4 / Jmin 40 / Jmax 70 / S1 29 / S2 56 /
/// H1 610898151 / H2 1285981084 / H3 1767517731 / H4 1995304650.
/// The kit's group delay test reported this node as “超时”; this probe measures the path
/// directly: handshake + proxied HTTP fetch + UDP DNS through the AWG tunnel.
///
/// Runs in proto-loopback.yml job `amneziawg-zh` (verify branch only) with TEST_RUNNER_NC_AWG_ZH=1
/// and TEST_RUNNER_NC_AWG_{SERVER,PORT,PRIV,PUB} in the environment; there it FAILS (never skips)
/// when the server is unreachable; elsewhere it skips.
final class NCAmneziaWGZhihengInteropTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "awg.zh.interop.test")

    private func node() -> NCProxy {
        NCProxy(name: "Tern-AmneziaWG", type: "wireguard", fields: [
            "server": .string(env["NC_AWG_SERVER"] ?? ""),
            "port": .number(Double(env["NC_AWG_PORT"] ?? "") ?? 24035),
            "ip": .string("10.67.0.2"),
            "private-key": .string(env["NC_AWG_PRIV"] ?? ""),
            "public-key": .string(env["NC_AWG_PUB"] ?? ""),
            "mtu": .number(1280),
            "dns": .array([.string("1.1.1.1")]),
            "remote-dns-resolve": .bool(true),
            "udp": .bool(true),
            "amnezia-wg-option": .object([
                "jc": .number(4), "jmin": .number(40), "jmax": .number(70),
                "s1": .number(29), "s2": .number(56),
                "h1": .number(610898151), "h2": .number(1285981084),
                "h3": .number(1767517731), "h4": .number(1995304650),
            ]),
        ])
    }

    override func setUpWithError() throws {
        guard env["NC_AWG_ZH"] == "1" else {
            throw XCTSkip("AmneziaWG zhiheng interop: set TEST_RUNNER_NC_AWG_ZH=1 with the kit node env (proto-loopback.yml amneziawg-zh)")
        }
        for k in ["NC_AWG_SERVER", "NC_AWG_PRIV", "NC_AWG_PUB"] {
            XCTAssertFalse((env[k] ?? "").isEmpty, "\(k) missing")
        }
        NCConnector.installWireGuardDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCWGStack.shared.teardownAll() }
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
        NSLog("[awg-zh] dial %@:%d in %.2f s -> %@", host, port, Date().timeIntervalSince(t0),
              out.0 != nil ? "ok" : "\(String(describing: out.1))")
        return out
    }

    /// HTTP/1.0 GET over `s` until the server closes; returns (status line, body).
    private func get(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 120) -> (String, Data) {
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
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-awg-zh-probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else {
            return (String(decoding: all.prefix(200), as: UTF8.self), Data())
        }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        var body = Data(all[r.upperBound...])
        if head.lowercased().contains("transfer-encoding: chunked") { body = dechunk(body) }
        return (head.components(separatedBy: "\r\n").first ?? "", body)
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

    /// Peers with a completed handshake (session keys derived), read on the lwIP queue.
    private func activeSessions(_ p: NCProxy) -> Int {
        NCLwIP.queue.sync { (NCWGStack.shared.device(for: p).0 as? NCWGDevice)?.activeRelayCount ?? -1 }
    }

    // MARK: tests

    /// TCP through the AWG netif: remote-dns-resolve (DNS over the tunnel to 1.1.1.1), then a plain
    /// HTTP fetch of cloudflare's trace page — the reported egress IP must be the zhiheng server's
    /// own address (45.92.159.155), proving the traffic really left through the tunnel + NAT.
    func testHTTPFetchThroughAmneziaWG() throws {
        let p = node()
        let (s, err) = dial(p, "www.cloudflare.com", 80)
        let raw = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { raw.cancel() }
        XCTAssertEqual(activeSessions(p), 1, "no AmneziaWG session (handshake) after a successful dial")
        let (status, body) = get(raw, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[awg-zh] GET /cdn-cgi/trace -> %@", status)
        XCTAssertTrue(status.contains(" 200"), status)
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[awg-zh] trace: %@", text.split(separator: "\n").filter { $0.hasPrefix("ip=") || $0.hasPrefix("colo=") }.joined(separator: " "))
        XCTAssertTrue(text.contains("ip=45.92.159.155"), "egress is not the zhiheng server: \(text)")
    }

    /// A DNS query as plain UDP through the AWG netif to 1.1.1.1:53, answer parsed.
    func testUDPDNSThroughAmneziaWG() throws {
        let p = node()
        let session = NCUDPWireGuardSession(proxy: p, queue: q)
        defer { session.cancel() }
        let qid: UInt16 = 0x7767
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
        NSLog("[awg-zh] one.one.one.one A = %@", ips.sorted().joined(separator: ","))
        XCTAssertFalse(ips.isDisjoint(with: ["1.1.1.1", "1.0.0.1"]), "\(ips)")
        XCTAssertEqual(activeSessions(p), 1, "no AmneziaWG session (handshake) after UDP DNS")
    }
}
