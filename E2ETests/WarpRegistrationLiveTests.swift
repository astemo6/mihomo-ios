import XCTest

/// feat/nc-warp-register: the in-app WARP registration end to end against the REAL Cloudflare API and endpoint.
/// WarpRegistration.register() (App/Core/WarpRegistration.swift, compiled into this bundle by project-uitests.yml)
/// registers a throwaway free device with a CryptoKit P-256 key; its node dictionary is then dialled through NativeCore
/// MASQUE (cf-connect-ip, NCConnector, the lwIP netif) and https://www.cloudflare.com/cdn-cgi/trace must say warp=on.
/// The device is deleted again (WarpRegistration.unregister) in tearDown. Nothing is stored or committed.
///
/// Opt-in: proto-loopback.yml job `warp-register` (dispatch with jobs containing "warp-register") sets
/// TEST_RUNNER_NC_WARP_REGISTER_LIVE=1; then the test FAILS (never skips) on any error. Elsewhere it skips.
final class WarpRegistrationLiveTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "warp.register.live")
    private var registered: WarpRegistration.Account?

    override func setUpWithError() throws {
        guard env["NC_WARP_REGISTER_LIVE"] == "1" else {
            throw XCTSkip("WARP registration live test: set TEST_RUNNER_NC_WARP_REGISTER_LIVE=1 (proto-loopback.yml warp-register)")
        }
        NCConnector.installMASQUEIPDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
        if let acct = registered {
            let done = expectation(description: "unregister")
            Task {
                do {
                    try await WarpRegistration.unregister(acct)
                    NSLog("[warp-register] DELETE /reg/<id> ok")
                } catch {
                    NSLog("[warp-register] DELETE /reg/<id> failed: %@", "\(error)")
                }
                done.fulfill()
            }
            wait(for: [done], timeout: 60)
        }
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    /// Registration with a short retry (the API rate-limits per address; CI shares addresses).
    private func registerNode() throws -> WarpRegistration.Node {
        var last: Error?
        for attempt in 1...3 {
            let got = expectation(description: "register \(attempt)")
            var result: Result<WarpRegistration.Node, Error>?
            let t0 = Date()
            Task {
                do { result = .success(try await WarpRegistration.register(name: "tern-ci-register")) } catch { result = .failure(error) }
                got.fulfill()
            }
            wait(for: [got], timeout: 120)
            switch result {
            case .success(let n)?:
                NSLog("[warp-register] registered in %.2f s: server=%@ server6=%@ port=%d ip=%@ ipv6 set=%d mtu=%d key=SEC1(%d b64) pin=SPKI(%d b64) account=%@",
                      Date().timeIntervalSince(t0), n.server, n.server6, n.port, n.ipv4, n.ipv6.isEmpty ? 0 : 1, n.mtu,
                      n.privateKey.count, n.publicKey.count, n.account.accountType)
                return n
            case .failure(let e)?:
                last = e
                NSLog("[warp-register] attempt %d failed: %@", attempt, "\(e)")
            case nil:
                last = WarpRegistration.Failure.transport("timeout")
            }
            Thread.sleep(forTimeInterval: 10)
        }
        throw last ?? WarpRegistration.Failure.transport("unknown")
    }

    private func dial(_ p: NCProxy, _ host: String, _ port: Int) -> (NCRelayStream?, Error?) {
        let exp = expectation(description: "dial \(host)")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: host, port: port), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 60)
        NSLog("[warp-register] dial %@:%d in %.2f s -> %@", host, port, Date().timeIntervalSince(t0),
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

    /// HTTP/1.0 GET until close; (status line, body). /cdn-cgi/trace is small and never chunked under HTTP/1.0.
    private func get(_ s: NCRelayStream, host: String, path: String) -> (String, String) {
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
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-warp-register\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: 120)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else { return (String(decoding: all.prefix(200), as: UTF8.self), "") }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        return (head.components(separatedBy: "\r\n").first ?? "", String(decoding: all[r.upperBound...], as: UTF8.self))
    }

    func testRegisterThenTraceThroughWARP() throws {
        let node = try registerNode()
        registered = node.account
        XCTAssertFalse(node.account.id.isEmpty)
        XCTAssertFalse(node.account.token.isEmpty)
        XCTAssertEqual(node.port, 443)
        XCTAssertFalse(node.ipv4.isEmpty)
        XCTAssertNil(NCMASQUEWarp.validate(privateKey: node.privateKey, publicKey: node.publicKey))

        // Exactly the dictionary the app saves as a manual node.
        let p = NCProxy(name: node.name, type: "masque", fields: node.proxyFields.mapValues(NCJSONValue.init))
        XCTAssertNil(NCSupport.unsupportedReason(p), "a freshly registered node must be available")
        XCTAssertEqual(NCMASQUE.Config(proxy: p)?.isWarp, true)

        // The enrollment takes a moment to propagate at the edge; give the first dial one retry.
        var (s, err) = dial(p, "www.cloudflare.com", 443)
        if s == nil {
            NCLwIP.queue.sync { NCMQIPStack.shared.teardownAll() }
            Thread.sleep(forTimeInterval: 5)
            (s, err) = dial(p, "www.cloudflare.com", 443)
        }
        let raw = try XCTUnwrap(s, "dial through the registered node failed: \(String(describing: err))")
        defer { raw.cancel() }
        let t = try tls(raw, host: "www.cloudflare.com")
        let (status, text) = get(t, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[warp-register] trace: %@ | %@", status,
              text.split(separator: "\n").filter { $0.hasPrefix("warp=") || $0.hasPrefix("colo=") || $0.hasPrefix("http=") }.joined(separator: " "))
        XCTAssertTrue(status.contains(" 200"), status)
        XCTAssertTrue(text.contains("warp=on") || text.contains("warp=plus"), text)
    }
}
