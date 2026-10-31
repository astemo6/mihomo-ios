import XCTest

/// fix/kit-wireguard: the WireGuard data plane against a local sing-box WireGuard endpoint
/// (tools/loopback/wg-sing-box-config.json, UDP :18071, started by start-servers.sh as its own
/// sing-box instance — the fleet's main config already carries a WG endpoint on :18008, but its
/// client keypair is not recorded anywhere, so this test stands up an isolated one with a test
/// keypair, the same pattern as the Reality inbound on :18070).
///
/// The node parameters mirror the zhiheng kit's WireGuard node in shape: tunnel address
/// 10.66.0.2 (server 10.66.0.1), client MTU 1280, no pre-shared key, no persistent-keepalive,
/// dns 1.1.1.1 with remote-dns-resolve. Everything after the dial is the production path:
/// NCConnector's WireGuard dialer (installed below, as PacketTunnelProvider does), the lwIP
/// netif (nc_wg.c), the Noise_IKpsk2 handshake in NCWireGuard.swift and the TCP relay.
///
/// Lives in TernE2ETunnelTests because the dialer + netif are PacketTunnel code — the
/// app-hosted TernUnitTests bundle cannot link them (the reason NativeCoreLoopbackTests has
/// no WireGuard case). Runs in proto-loopback.yml job `wireguard` with
/// TEST_RUNNER_NC_WG_LOOPBACK=1 — there it FAILS (never skips) when the server is unreachable;
/// elsewhere it skips.
final class NCWireGuardLoopbackTests: XCTestCase {
    private let port = 18071
    private let echoHost = "127.0.0.1"
    private let echoPort = 18080 // tools/loopback/echo_server.py TCP echo
    private let q = DispatchQueue(label: "wg.loopback.test")

    // Test keypair (loopback only; the matching server half is wg-sing-box-config.json).
    private static let clientPrivateKey = "oPfUvsxNDsNtRNje79EP1r7fCzeVoe7hZI/OSsfL/XA="
    private static let serverPublicKey = "FJc3btcSEhLvvouEyjpeyrFXFOJPgL4zpB1WMNzpBSQ="

    private func node() -> NCProxy {
        NCProxy(name: "wg-loop", type: "wireguard", fields: [
            "server": .string("127.0.0.1"), "port": .number(Double(port)),
            "ip": .string("10.66.0.2"), "udp": .bool(true),
            "private-key": .string(Self.clientPrivateKey),
            "public-key": .string(Self.serverPublicKey),
            "mtu": .number(1280),
            "dns": .array([.string("1.1.1.1")]),
            "remote-dns-resolve": .bool(true),
        ])
    }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["NC_WG_LOOPBACK"] == "1" else {
            throw XCTSkip("WireGuard loopback: set TEST_RUNNER_NC_WG_LOOPBACK=1 with the loopback fleet up (proto-loopback.yml)")
        }
        NCConnector.installWireGuardDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync { NCWGStack.shared.teardownAll() }
        super.tearDown()
    }

    // MARK: helpers (same shapes as NCOpenConnectLoopbackTests)

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

    /// Writes `payload` (16 KB chunks, each waiting for its send completion) and reads until as
    /// many bytes came back; returns what was read.
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

    private func device(_ p: NCProxy) -> NCWGDevice? {
        NCLwIP.queue.sync { NCWGStack.shared.device(for: p).0 }
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

    /// Handshake against the reference endpoint, then a byte-exact TCP echo through the tunnel
    /// (the echo server is reached by sing-box's direct outbound from inside the WG endpoint).
    func testWireGuardTCPEcho() throws {
        let p = node()
        let (s, err) = dial(p, echoHost, echoPort)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let dev = try XCTUnwrap(device(p))
        waitUntil("WireGuard session", timeout: 10) { dev.peers.contains { $0.hasSession } }
        NSLog("[wg-loopback] session up; echoing through 127.0.0.1:%d", echoPort)
        let small = pattern(1000, seed: 3)
        XCTAssertEqual(echo(stream, small), small)
        let big = pattern(256 * 1024, seed: 9)
        let back = echo(stream, big)
        XCTAssertTrue(back == big, "256 KiB echo differs (\(back.count) bytes back)")
    }
}
