import XCTest

/// fix/kit-juicity DIAGNOSIS (scaffolding): the production Juicity outbound (NCJuicityConnection,
/// NWConnectionGroup QUIC + TLS-exporter auth) against the REAL kit server on zhiheng — the
/// official juicity-server, UDP 24033, user 6ceb5215-… (server health already proven with the
/// official juicity-client from an external host: egress = the server's own IP).
///
/// The kit probe and the in-process sweep both report Juicity dead at "stage handshake" while
/// TUIC — same NWConnectionGroup mechanics, same exporter auth code — works. This probe splits
/// the dial into stages with timings so the failing stage names itself:
///   stage 1: NCJuicityConnection.start() (QUIC group + auth stream + auth send)
///   stage 2: first TCP stream + plain HTTP fetch through it (egress must be 45.92.159.155)
///   stage 3: the production registry path (NCConnector.connect), as the delay tester drives it.
///
/// Runs in proto-loopback.yml job `juicity-zh` with TEST_RUNNER_NC_JUICITY_ZH=1 and
/// TEST_RUNNER_NC_JUICITY_{SERVER,PORT,UUID,PASSWORD} in the environment; there it FAILS
/// (never skips) when the server is unreachable; elsewhere it skips.
final class NCJuicityZhihengInteropTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "juicity.zh.interop.test")

    private func node() -> NCProxy {
        NCProxy(name: "Tern-Juicity", type: "juicity", fields: [
            "server": .string(env["NC_JUICITY_SERVER"] ?? ""),
            "port": .number(Double(env["NC_JUICITY_PORT"] ?? "") ?? 24033),
            "uuid": .string(env["NC_JUICITY_UUID"] ?? ""),
            "password": .string(env["NC_JUICITY_PASSWORD"] ?? ""),
            "sni": .string("tern.test"),
            "congestion-controller": .string("bbr"),
            "skip-cert-verify": .bool(true),
            "udp": .bool(true),
        ])
    }

    override func setUpWithError() throws {
        guard env["NC_JUICITY_ZH"] == "1" else {
            throw XCTSkip("Juicity zhiheng interop: set TEST_RUNNER_NC_JUICITY_ZH=1 with the kit node env (proto-loopback.yml juicity-zh)")
        }
        for k in ["NC_JUICITY_SERVER", "NC_JUICITY_UUID", "NC_JUICITY_PASSWORD"] {
            XCTAssertFalse((env[k] ?? "").isEmpty, "\(k) missing")
        }
    }

    override func tearDown() {
        _ = NCConnector.closeAllJuicitySessions()
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    // MARK: helpers

    /// HTTP/1.0 GET over `s` until the server closes; returns (status line, body).
    private func get(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 60) -> (String, Data) {
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
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-juicity-zh-probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
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

    private func assertTraceEgress(_ s: NCRelayStream, _ label: String) {
        let (status, body) = get(s, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[juicity-zh] %@ GET /cdn-cgi/trace -> %@", label, status)
        XCTAssertTrue(status.contains(" 200"), "\(label): \(status)")
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[juicity-zh] %@ trace: %@", label, text.split(separator: "\n").filter { $0.hasPrefix("ip=") || $0.hasPrefix("colo=") }.joined(separator: " "))
        XCTAssertTrue(text.contains("ip=45.92.159.155"), "\(label): egress is not the zhiheng server: \(text)")
    }

    // MARK: tests

    /// Stage-split direct dial: NCJuicityConnection.start() outcome first (QUIC + auth),
    /// then a TCP stream through the same connection.
    func testDirectConnectionStages() throws {
        let p = node()
        let conn = try XCTUnwrap(NCJuicityConnection(proxy: p, queue: q), "NCJuicityConnection init failed (uuid parse?)")
        defer { conn.close() }
        let started = expectation(description: "juicity start")
        var startErr: Error?
        let t0 = Date()
        conn.start { e in
            startErr = e
            started.fulfill()
        }
        wait(for: [started], timeout: 30)
        let dt = Date().timeIntervalSince(t0)
        NSLog("[juicity-zh] stage1 start -> %@ in %.2f s (state=%@)",
              startErr == nil ? "ready" : "error \(String(describing: startErr))", dt, "\(conn.state)")
        XCTAssertNil(startErr, "stage1 start failed: \(String(describing: startErr))")
        guard startErr == nil else { return }
        XCTAssertTrue(conn.isAlive)
        let s = try XCTUnwrap(conn.openTCP(target: NCTarget(host: "www.cloudflare.com", port: 80), callerQueue: q),
                              "stage2 openTCP returned nil on a ready connection")
        defer { s.cancel() }
        assertTraceEgress(s, "stage2")
    }

    /// CONTROL, same harness/process: NCTUICConnection (identical NWConnectionGroup
    /// mechanics, identical exporter-auth code) against the kit TUIC node on the same
    /// server (sing-box, UDP 24015, same uuid/password/cert/SNI). If TUIC's start()
    /// completes here while Juicity's times out, the harness and the shared QUIC
    /// machinery are exonerated and the fault is Juicity-specific interop.
    func testTUICControlSameHarness() throws {
        let p = NCProxy(name: "Tern-TUIC", type: "tuic", fields: [
            "server": .string(env["NC_TUIC_SERVER"] ?? "45.92.159.155"),
            "port": .number(Double(env["NC_TUIC_PORT"] ?? "") ?? 24015),
            "uuid": .string(env["NC_JUICITY_UUID"] ?? ""),
            "password": .string(env["NC_JUICITY_PASSWORD"] ?? ""),
            "sni": .string("tern.test"),
            "congestion-controller": .string("bbr"),
            "skip-cert-verify": .bool(true),
            "udp": .bool(true),
        ])
        let conn = try XCTUnwrap(NCTUICConnection(proxy: p, queue: q), "NCTUICConnection init failed")
        defer { conn.close() }
        let started = expectation(description: "tuic start")
        var startErr: Error?
        let t0 = Date()
        conn.start { e in
            startErr = e
            started.fulfill()
        }
        wait(for: [started], timeout: 30)
        NSLog("[juicity-zh] tuic-control start -> %@ in %.2f s",
              startErr == nil ? "ready" : "error \(String(describing: startErr))", Date().timeIntervalSince(t0))
        XCTAssertNil(startErr, "TUIC control failed too — harness/shared-machinery suspect: \(String(describing: startErr))")
    }

    /// The production path: NCConnector.connect via the shared-connection registry,
    /// exactly what the delay tester / data plane drive.
    func testProductionPathViaConnector() throws {
        let p = node()
        let exp = expectation(description: "connector dial")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: "www.cloudflare.com", port: 80), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 30)
        NSLog("[juicity-zh] stage3 connect -> %@ in %.2f s",
              out.0 != nil ? "ok" : "error \(String(describing: out.1))", Date().timeIntervalSince(t0))
        let s = try XCTUnwrap(out.0, "stage3 connect failed: \(String(describing: out.1))")
        defer { s.cancel() }
        assertTraceEgress(s, "stage3")
    }
}
