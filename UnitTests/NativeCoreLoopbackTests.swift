import XCTest
import Network
@testable import Mihomo

/// Protocol loopback tests (fix/nc-proto-loopback): drive the real NativeCore
/// outbound stacks (NCConnector) against a local sing-box server and check
/// byte-exact echo, send-completion back-pressure (#116 semantics on a real
/// socket) and UDP relay — the wire interop the pure unit tests cannot cover.
///
/// Servers: tools/loopback/start-servers.sh (sing-box, one inbound per
/// protocol on 127.0.0.1, plus python echo/blackhole backends). The constants
/// below mirror tools/loopback/sing-box-config.json — keep them in sync.
///
/// Guard: these tests only run when NC_LOOPBACK=1 is in the environment
/// (TEST_RUNNER_NC_LOOPBACK=1 under xcodebuild, set by proto-loopback.yml)
/// or when the SS port already answers (local manual run). Otherwise every
/// test skips, so the normal UnitTests run is unaffected.
final class NativeCoreLoopbackTests: XCTestCase {

    // MARK: - Topology (mirror of tools/loopback/sing-box-config.json)

    private static let host = "127.0.0.1"
    private static let ssPort = 18001
    private static let ss2022Port = 18002
    private static let vmessPort = 18003
    private static let vlessPort = 18004
    private static let trojanPort = 18005
    private static let hy2Port = 18006
    private static let tuicPort = 18007
    private static let vlessEchPort = 18014
    private static let trojanEchPort = 18015
    private static let tcpEchoPort = 18080
    private static let udpEchoPort = 18081
    private static let blackholePort = 18082
    private static let controlPort = 18083

    private static let ssPassword = "nc-loop-ss-pw"
    private static let ssCipher = "aes-256-gcm"
    private static let ss2022Password = "bmMtbG9vcC0yMDIyLXB3MA==" // base64 of the 16-byte PSK "nc-loop-2022-pw0"
    private static let ss2022Method = "2022-blake3-aes-128-gcm"
    private static let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    private static let trojanPassword = "nc-loop-trojan-pw"
    private static let hy2Password = "nc-loop-hy2-pw"
    private static let tuicPassword = "nc-loop-tuic-pw"

    private static let echInnerSni = "localhost"
    /// Base64 of ECHConfigList matching tools/loopback/ech_config.pem
    /// Generated via: sing-box generate ech-keypair outer.localhost
    private static let echConfigBase64 = "AEr+DQBGAAAgACCb7RpDhFlwk1UfROZmEKsx55OeBngAV46wCg57TCInAQAMAAEAAQABAAIAAQADAA9vdXRlci5sb2NhbGhvc3QAAA=="
    /// Base64 of mismatched ECHConfigList matching tools/loopback/ech_config_stale.pem
    /// Generated via: sing-box generate ech-keypair stale.outer.localhost
    private static let staleEchConfigBase64 = "AFD+DQBMAAAgACBJO61PMZnuwwy2kKPiDFuetw4JyJqPZifWvUGvRed0ewAMAAEAAQABAAIAAQADABVzdGFsZS5vdXRlci5sb2NhbGhvc3QAAA=="

    /// Same generator as the validation probe: byte i = (i * 7 + 3) % 256.
    private static let payload = Data((0..<8192).map { UInt8(($0 * 7 + 3) & 0xff) })

    /// A minimal DNS query for example.com/A — the UDP tests just need a
    /// DNS-shaped datagram; the UDP echo backend returns it verbatim.
    private static let dnsQuery: Data = {
        var q = Data()
        q.append(contentsOf: [0x4e, 0x43])             // transaction ID "NC"
        q.append(contentsOf: [0x01, 0x00])             // RD set
        q.append(contentsOf: [0x00, 0x01])             // QDCOUNT 1
        q.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in ["example", "com"] {
            q.append(UInt8(label.count))
            q.append(contentsOf: label.utf8)
        }
        q.append(0x00)
        q.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // QTYPE A, QCLASS IN
        return q
    }()

    // MARK: - Guard

    override func setUpWithError() throws {
        let env = ProcessInfo.processInfo.environment["NC_LOOPBACK"] == "1"
        if !env && !Self.serversReachable() {
            throw XCTSkip("loopback servers not running (start tools/loopback/start-servers.sh or set NC_LOOPBACK=1)")
        }
    }

    private static func serversReachable() -> Bool {
        let conn = NWConnection(host: NWEndpoint.Host(Self.host),
                                port: NWEndpoint.Port(rawValue: UInt16(Self.ssPort))!,
                                using: .tcp)
        let sem = DispatchSemaphore(value: 0)
        let box = LockedBox(false)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                box.set(true)
                sem.signal()
            case .failed, .cancelled:
                sem.signal()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "nc.loopback.probe"))
        _ = sem.wait(timeout: .now() + 1.0)
        conn.cancel()
        return box.get()
    }

    // MARK: - Proxy builders

    private static func proxy(name: String, type: String, port: Int,
                              extra: [String: NCJSONValue]) -> NCProxy {
        var fields: [String: NCJSONValue] = [
            "server": .string(Self.host),
            "port": .number(Double(port)),
        ]
        for (k, v) in extra { fields[k] = v }
        return NCProxy(name: name, type: type, fields: fields)
    }

    private static var ssProxy: NCProxy {
        Self.proxy(name: "loop-ss", type: "ss", port: Self.ssPort, extra: [
            "cipher": .string(Self.ssCipher), "password": .string(Self.ssPassword), "udp": .bool(true),
        ])
    }

    private static var ss2022Proxy: NCProxy {
        Self.proxy(name: "loop-ss2022", type: "ss", port: Self.ss2022Port, extra: [
            "cipher": .string(Self.ss2022Method), "password": .string(Self.ss2022Password), "udp": .bool(true),
        ])
    }

    private static var vmessProxy: NCProxy {
        Self.proxy(name: "loop-vmess", type: "vmess", port: Self.vmessPort, extra: [
            "uuid": .string(Self.uuid), "cipher": .string("aes-128-gcm"),
            "alterId": .number(0), "network": .string("tcp"),
        ])
    }

    private static var vlessProxy: NCProxy {
        Self.proxy(name: "loop-vless", type: "vless", port: Self.vlessPort, extra: [
            "uuid": .string(Self.uuid), "network": .string("tcp"),
        ])
    }

    private static var trojanProxy: NCProxy {
        Self.proxy(name: "loop-trojan", type: "trojan", port: Self.trojanPort, extra: [
            "password": .string(Self.trojanPassword), "sni": .string("localhost"),
            "skip-cert-verify": .bool(true),
        ])
    }

    private static var hy2Proxy: NCProxy {
        Self.proxy(name: "loop-hy2", type: "hysteria2", port: Self.hy2Port, extra: [
            "password": .string(Self.hy2Password), "sni": .string("localhost"),
            "skip-cert-verify": .bool(true),
        ])
    }

    private static var tuicProxy: NCProxy {
        Self.proxy(name: "loop-tuic", type: "tuic", port: Self.tuicPort, extra: [
            "uuid": .string(Self.uuid), "password": .string(Self.tuicPassword),
            "sni": .string("localhost"), "skip-cert-verify": .bool(true),
        ])
    }

    private static var trojanECHProxy: NCProxy {
        Self.proxy(name: "loop-trojan-ech", type: "trojan", port: Self.trojanEchPort, extra: [
            "password": .string(Self.trojanPassword),
            "sni": .string(Self.echInnerSni),
            "skip-cert-verify": .bool(true),
            "ech-opts": .object([
                "enable": .bool(true),
                "config": .string(Self.echConfigBase64),
            ]),
        ])
    }

    private static var trojanECHStaleProxy: NCProxy {
        Self.proxy(name: "loop-trojan-ech-stale", type: "trojan", port: Self.trojanEchPort, extra: [
            "password": .string(Self.trojanPassword),
            "sni": .string(Self.echInnerSni),
            "skip-cert-verify": .bool(true),
            "ech-opts": .object([
                "enable": .bool(true),
                "config": .string(Self.staleEchConfigBase64),
            ]),
        ])
    }

    private static var vlessECHProxy: NCProxy {
        Self.proxy(name: "loop-vless-ech", type: "vless", port: Self.vlessEchPort, extra: [
            "uuid": .string(Self.uuid),
            "network": .string("tcp"),
            "tls": .bool(true),
            "sni": .string(Self.echInnerSni),
            "skip-cert-verify": .bool(true),
            "ech-opts": .object([
                "enable": .bool(true),
                "config": .string(Self.echConfigBase64),
            ]),
        ])
    }

    private static var echoTarget: NCTarget { NCTarget(host: Self.host, port: Self.tcpEchoPort) }
    private static var blackholeTarget: NCTarget { NCTarget(host: Self.host, port: Self.blackholePort) }

    // MARK: - Helpers

    private func connect(proxy: NCProxy, target: NCTarget, timeout: TimeInterval = 30) throws -> NCRelayStream {
        let exp = self.expectation(description: "connect \(proxy.name)")
        let box = LockedBox<(NCRelayStream?, Error?)>((nil, nil))
        let queue = DispatchQueue(label: "nc.loopback.\(proxy.name)")
        NCConnector.connect(target: target, proxy: proxy, queue: queue) { stream, err in
            box.set((stream, err))
            exp.fulfill()
        }
        self.wait(for: [exp], timeout: timeout)
        let (stream, err) = box.get()
        if let err { throw err }
        return try XCTUnwrap(stream, "\(proxy.name): connect returned neither stream nor error")
    }

    /// Send `payload`, collect receives until the same byte count has come
    /// back, and require a byte-exact match.
    private func assertEcho(_ stream: NCRelayStream, payload: Data,
                            timeout: TimeInterval = 20,
                            file: StaticString = #filePath, line: UInt = #line) throws {
        let exp = self.expectation(description: "echo round trip")
        let state = EchoState(want: payload.count) { exp.fulfill() }
        stream.send(payload)
        state.pump(stream)
        self.wait(for: [exp], timeout: timeout)
        let (data, err) = state.result()
        if let err { throw err }
        XCTAssertEqual(data, payload, "echoed bytes differ", file: file, line: line)
    }

    /// One-shot UDP round trip over an already-started connection.
    private func udpRoundTrip(_ conn: NWConnection, packet: Data, timeout: TimeInterval = 15) throws -> Data {
        let exp = self.expectation(description: "udp round trip")
        let box = LockedBox<(Data?, Error?)>((nil, nil))
        conn.receiveMessage { data, _, _, err in
            box.set((data, err))
            exp.fulfill()
        }
        conn.send(content: packet, completion: .contentProcessed { _ in })
        self.wait(for: [exp], timeout: timeout)
        let (data, err) = box.get()
        if let err { throw err }
        return try XCTUnwrap(data, "empty UDP reply")
    }

    private func udpConnection(to port: Int) throws -> NWConnection {
        let conn = NWConnection(host: NWEndpoint.Host(Self.host),
                                port: NWEndpoint.Port(rawValue: UInt16(port))!,
                                using: .udp)
        let exp = self.expectation(description: "udp ready \(port)")
        let box = LockedBox<Error?>(nil)
        let once = NCCallOnce { exp.fulfill() }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                once.call()
            case .failed(let e):
                box.set(e)
                once.call()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "nc.loopback.udp"))
        self.wait(for: [exp], timeout: 10)
        if let err = box.get() { conn.cancel(); throw err }
        return conn
    }

    /// Fire-and-forget control datagram to the echo server ("pause" / "go"
    /// flip the blackhole between hold-unread and read-and-discard).
    private func sendControl(_ word: String) {
        let conn = NWConnection(host: NWEndpoint.Host(Self.host),
                                port: NWEndpoint.Port(rawValue: UInt16(Self.controlPort))!,
                                using: .udp)
        conn.stateUpdateHandler = { state in
            if case .ready = state {
                conn.send(content: Data(word.utf8), completion: .contentProcessed { _ in
                    conn.stateUpdateHandler = nil
                    conn.cancel()
                })
            }
        }
        conn.start(queue: DispatchQueue(label: "nc.loopback.control"))
    }

    /// SOCKS-style target-header strip, mirroring
    /// NCUDPSSSession.stripTargetHeader (PacketTunnel target — not visible
    /// from this bundle, so the 15 lines live here too).
    private static func stripTargetHeader(_ data: Data) -> Data? {
        guard let first = data.first else { return nil }
        var offset: Int
        switch first {
        case 0x01: offset = 1 + 4 + 2
        case 0x04: offset = 1 + 16 + 2
        case 0x03:
            guard data.count >= 2 else { return nil }
            offset = 1 + 1 + Int(data[data.startIndex + 1]) + 2
        default: return nil
        }
        guard data.count > offset else { return nil }
        return Data(data.dropFirst(offset))
    }

    // MARK: - Server sanity

    func testServerPortsReachable() {
        for port in [Self.ssPort, Self.ss2022Port, Self.vmessPort, Self.vlessPort,
                     Self.trojanPort, Self.vlessEchPort, Self.trojanEchPort,
                     Self.tcpEchoPort, Self.blackholePort] {
            let conn = NWConnection(host: NWEndpoint.Host(Self.host),
                                    port: NWEndpoint.Port(rawValue: UInt16(port))!,
                                    using: .tcp)
            let exp = self.expectation(description: "port \(port)")
            let box = LockedBox(false)
            // Exactly-once is load-bearing here (this helper is what tripped
            // "NCCallOnce fired twice" in run 40171239186): a probe connection that
            // reaches .ready fulfills, and the cancel() below then delivers .cancelled
            // to the same handler, which used to call the once a second time and crash
            // the test host. The `fired` flag (handler invocations are serialized on
            // the connection's serial queue) plus clearing the handler before cancel
            // close both paths. (udpConnection below never had the bug: its switch
            // ignores .cancelled.)
            let fired = LockedBox(false)
            let once = NCCallOnce { exp.fulfill() }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.set(true)
                    if !fired.get() { fired.set(true); once.call() }
                case .failed, .cancelled:
                    if !fired.get() { fired.set(true); once.call() }
                default:
                    break
                }
            }
            conn.start(queue: DispatchQueue(label: "nc.loopback.ports"))
            self.wait(for: [exp], timeout: 5)
            conn.stateUpdateHandler = nil
            conn.cancel()
            XCTAssertTrue(box.get(), "127.0.0.1:\(port) not accepting (servers up?)")
        }
    }

    // MARK: - TCP echo (one per protocol)

    func testShadowsocksTCPEcho() throws {
        let stream = try self.connect(proxy: Self.ssProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testShadowsocks2022TCPEcho() throws {
        let stream = try self.connect(proxy: Self.ss2022Proxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testVMessTCPEcho() throws {
        let stream = try self.connect(proxy: Self.vmessProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testVLESSTCPEcho() throws {
        let stream = try self.connect(proxy: Self.vlessProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testTrojanTCPEcho() throws {
        let stream = try self.connect(proxy: Self.trojanProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testHysteria2TCPEcho() throws {
        let stream = try self.connect(proxy: Self.hy2Proxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testTUICTCPEcho() throws {
        let stream = try self.connect(proxy: Self.tuicProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    // MARK: - ECH (Encrypted Client Hello) loopback

    /// ECH client-side TLS 1.3 handshake and retry_configs handling (E4 #152 + E5 #153, fix/nc-ech-rest).
    /// The sing-box reference inbounds (:18014 and :18015) and test keypair materials are live.
    private static var isClientECHImplemented: Bool {
        true
    }

    /// Trojan + TLS ECH accept: client connects with valid ECH config matching the server's
    /// private key. Server decrypts ClientHelloInner (SNI localhost), completes handshake,
    /// and echo traffic round-trips byte-for-byte.
    func testTrojanECHAccept() throws {
        guard Self.isClientECHImplemented else {
            throw XCTSkip("client-side ECH handshake pending E4 (feat/nc-ech-tls)")
        }
        let stream = try self.connect(proxy: Self.trojanECHProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    /// VLESS + TLS ECH accept: client connects with valid ECH config to the VLESS ECH inbound.
    func testVLESSECHAccept() throws {
        guard Self.isClientECHImplemented else {
            throw XCTSkip("client-side ECH handshake pending E4 (feat/nc-ech-tls)")
        }
        let stream = try self.connect(proxy: Self.vlessECHProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    /// Trojan + TLS ECH with a stale config: the server cannot decrypt the inner hello and finishes the outer
    /// handshake for public_name. sing-box 1.12.24 never sets the old core's EncryptedClientHelloKey.SendAsRetry, so no
    /// retry_configs come back: the client must verify the outer certificate and fail with echRejected (never
    /// fall through to a connection under the outer name). The retry-once path itself is covered offline by
    /// NativeCoreECHTLSTests.testEncryptedExtensionsRetryConfigsParsing.
    func testTrojanECHRejectedWithoutRetryConfigs() throws {
        guard Self.isClientECHImplemented else {
            throw XCTSkip("client-side ECH pending")
        }
        XCTAssertThrowsError(try self.connect(proxy: Self.trojanECHStaleProxy, target: Self.echoTarget)) { err in
            guard let tlsErr = err as? NCTLSClientStream.TLSError, case .echRejected = tlsErr else {
                return XCTFail("expected echRejected, got \(err)")
            }
        }
    }

    /// Dynamic ECH (ech-rest): `ech-opts: {enable: true}` without `config` — the ECHConfigList comes from the
    /// DNS lookup hook (NativeCoreEngine installs NCECHResolver there in the tunnel; injected here), queried
    /// for the TLS server name, then the handshake is accepted by the sing-box ECH inbound.
    func testTrojanECHDynamicConfig() throws {
        let list = try XCTUnwrap(Data(base64Encoded: Self.echConfigBase64))
        let asked = NSMutableArray()
        NCConnector.echConfigLookup = { name, done in
            asked.add(name)
            done(list, nil)
        }
        defer { NCConnector.echConfigLookup = nil }
        let p = Self.proxy(name: "loop-trojan-ech-dns", type: "trojan", port: Self.trojanEchPort, extra: [
            "password": .string(Self.trojanPassword),
            "sni": .string(Self.echInnerSni),
            "skip-cert-verify": .bool(true),
            "ech-opts": .object(["enable": .bool(true)]),
        ])
        let stream = try self.connect(proxy: p, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        XCTAssertEqual(asked.compactMap { $0 as? String }, [Self.echInnerSni])
    }

    /// Dynamic ECH with no record: the dial fails — never a silent plaintext-SNI handshake.
    func testTrojanECHDynamicNoRecordFails() throws {
        NCConnector.echConfigLookup = { _, done in done(nil, nil) }
        defer { NCConnector.echConfigLookup = nil }
        let p = Self.proxy(name: "loop-trojan-ech-none", type: "trojan", port: Self.trojanEchPort, extra: [
            "password": .string(Self.trojanPassword),
            "sni": .string(Self.echInnerSni),
            "skip-cert-verify": .bool(true),
            "ech-opts": .object(["enable": .bool(true)]),
        ])
        XCTAssertThrowsError(try self.connect(proxy: p, target: Self.echoTarget))
    }

    // MARK: - Native TLS parity (E5 #153): client-fingerprint moves trojan / vless+TLS to the native TLS stack

    func testTrojanFingerprintNativeTLS() throws {
        let p = Self.proxy(name: "loop-trojan-fp", type: "trojan", port: Self.trojanPort, extra: [
            "password": .string(Self.trojanPassword), "sni": .string("localhost"),
            "skip-cert-verify": .bool(true), "client-fingerprint": .string("chrome"),
        ])
        XCTAssertTrue(NCConnector.needsNativeTLS(p))
        let stream = try self.connect(proxy: p, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    /// VLESS + TLS (tcp) with a fingerprint and no ECH against the ECH-capable inbound (which also serves plain
    /// TLS 1.3): native stack, no ALPN offered (Clash.Meta default for vless tcp).
    func testVLESSTLSFingerprintNativeTLS() throws {
        let p = Self.proxy(name: "loop-vless-tls-fp", type: "vless", port: Self.vlessEchPort, extra: [
            "uuid": .string(Self.uuid), "network": .string("tcp"), "tls": .bool(true),
            "sni": .string(Self.echInnerSni), "skip-cert-verify": .bool(true),
            "client-fingerprint": .string("safari"),
        ])
        XCTAssertTrue(NCConnector.needsNativeTLS(p))
        XCTAssertEqual(NCConnector.defaultALPN(for: p), [])
        let stream = try self.connect(proxy: p, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    // WireGuard and Mieru are intentionally absent:
    // - WireGuard: NCConnector refuses outside the tunnel (its dialer runs on
    //   the PacketTunnel-only userspace lwIP stack, NCWireGuard.swift), so the
    //   app-hosted test bundle cannot open a WG stream at all. The sing-box
    //   WireGuard endpoint still stands up in the server config.
    // - Mieru: sing-box has no mieru inbound; there is no reference server.

    // MARK: - Back-pressure on a real socket (#116 send(_:completion:))
    //
    // The fake-based half of this contract (completion held by a fake raw
    // stream) is NativeCoreFlowControlTests. Here the peer is real: the
    // target is the blackhole backend, which accepts and reads nothing, so
    // once the kernels' and sing-box's buffers fill, send completions must
    // stop firing; after the "go" control datagram makes the blackhole
    // discard, every outstanding completion must fire, in send order,
    // exactly once. If this environment's buffers absorb everything sent,
    // the lag never appears and the test skips instead of failing — the
    // property is then simply not observable here.

    func testShadowsocksBackpressure() throws {
        try self.assertBackpressure(proxy: Self.ssProxy)
    }

    func testVMessBackpressure() throws {
        try self.assertBackpressure(proxy: Self.vmessProxy)
    }

    private func assertBackpressure(proxy: NCProxy,
                                    file: StaticString = #filePath, line: UInt = #line) throws {
        self.sendControl("pause")
        Thread.sleep(forTimeInterval: 0.2)
        let stream = try self.connect(proxy: proxy, target: Self.blackholeTarget)
        defer { stream.cancel() }

        let tracker = CompletionTracker()
        let chunk = Data(repeating: 0x5a, count: 64 * 1024)
        let maxChunks = 512 // 32 MiB worst case — beyond any default loopback buffering
        var sent = 0
        while sent < maxChunks {
            let index = sent
            stream.send(chunk) { tracker.record(index) }
            sent += 1
            if sent - tracker.count >= 16 { break } // lag is already observable; stop piling on
            if sent % 64 == 0 { Thread.sleep(forTimeInterval: 0.01) }
        }

        // Let completions settle: wait until the count stops moving.
        var last = -1
        var stableRounds = 0
        let settleDeadline = Date().addingTimeInterval(10)
        while stableRounds < 4 && Date() < settleDeadline {
            Thread.sleep(forTimeInterval: 0.25)
            let c = tracker.count
            if c == last { stableRounds += 1 } else { stableRounds = 0; last = c }
        }

        let firedBeforeGo = tracker.order
        if firedBeforeGo.count >= sent {
            throw XCTSkip("buffers absorbed all \(sent) chunks; back-pressure not observable in this environment")
        }
        XCTAssertEqual(firedBeforeGo, Array(0..<firedBeforeGo.count),
                       "completions fired out of order or twice before release", file: file, line: line)

        self.sendControl("go")
        let deadline = Date().addingTimeInterval(30)
        while tracker.count < sent && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertEqual(tracker.count, sent,
                       "only \(tracker.count)/\(sent) completions fired after the peer resumed", file: file, line: line)
        XCTAssertEqual(tracker.order, Array(0..<sent),
                       "completions must fire in send order, exactly once each", file: file, line: line)
    }

    // MARK: - UDP relay
    //
    // The UDP session classes (NCUDPSSSession & friends) live in the
    // PacketTunnel target, which this bundle cannot link. These tests drive
    // the same Shared wire primitives those sessions are built from —
    // NCShadowsocks.udpPacketEncode / udpPacketDecode (SIP022 packet format:
    // salt ‖ single zero-nonce seal; NOT the TCP stream codec) and
    // NCSS2022UDPCrypto — over a real NWConnection UDP socket to the
    // sing-box SS inbound, targeting the UDP echo backend.

    func testShadowsocksUDPEcho() throws {
        let conn = try self.udpConnection(to: Self.ssPort)
        defer { conn.cancel() }
        let target = NCTarget(host: Self.host, port: Self.udpEchoPort)
        var plain = target.atypEncoded
        plain.append(Self.dnsQuery)
        let packet = try XCTUnwrap(NCShadowsocks.udpPacketEncode(cipher: Self.ssCipher,
                                                                 password: Self.ssPassword, plain: plain))
        let reply = try self.udpRoundTrip(conn, packet: packet)
        let plainReply = try XCTUnwrap(NCShadowsocks.udpPacketDecode(cipher: Self.ssCipher,
                                                                     password: Self.ssPassword, packet: reply),
                                       "SS UDP reply did not decrypt")
        let payload = try XCTUnwrap(Self.stripTargetHeader(plainReply), "SS UDP reply has no target header")
        XCTAssertEqual(payload, Self.dnsQuery)
    }

    func testShadowsocks2022UDPEcho() throws {
        let conn = try self.udpConnection(to: Self.ss2022Port)
        defer { conn.cancel() }
        let target = NCTarget(host: Self.host, port: Self.udpEchoPort)
        let crypto = try XCTUnwrap(NCSS2022UDPCrypto(method: Self.ss2022Method, password: Self.ss2022Password))
        let packet = try XCTUnwrap(crypto.encodePacket(target: target, payload: Self.dnsQuery,
                                                       timestamp: UInt64(Date().timeIntervalSince1970)))
        let reply = try self.udpRoundTrip(conn, packet: packet)
        let decoded = try XCTUnwrap(crypto.decodePacket(reply), "SS2022 UDP reply did not decode")
        XCTAssertEqual(decoded.1, Self.dnsQuery)
        XCTAssertEqual(decoded.0.port, Self.udpEchoPort)
    }

    /// Hysteria2 UDP over real QUIC datagrams (feat/nc-hy2-datagram): the shared NCHysteria2Connection
    /// (Shared — the tunnel's NCUDPHysteria2Session is a thin wrapper over exactly these calls) opens its
    /// RFC 9221 datagram flow, sends spec UDPMessages to the sing-box hy2 inbound, which relays to the UDP
    /// echo backend. A DNS-sized packet checks the plain path; a 3000-byte packet checks fragmentation
    /// both ways (client → server fragments at 1197, sing-box re-fragments the echo at its udpMTU and
    /// NCHy2UDP.Reassembler puts it back together).
    func testHysteria2UDPEcho() throws {
        let queue = DispatchQueue(label: "nc.loopback.hy2udp")
        let exp = self.expectation(description: "hy2 connect")
        let box = LockedBox<(NCHysteria2Connection?, Error?)>((nil, nil))
        NCConnector.sharedHysteria2(proxy: Self.hy2Proxy, server: Self.host, port: Self.hy2Port, queue: queue) { c, e in
            box.set((c, e))
            exp.fulfill()
        }
        self.wait(for: [exp], timeout: 30)
        let (connOpt, connErr) = box.get()
        if let connErr { throw connErr }
        let conn = try XCTUnwrap(connOpt)
        XCTAssertTrue(conn.udpEnabled, "sing-box hy2 inbound must answer Hysteria-UDP: true")

        let replies = UDPReplies()
        let sessionID = try XCTUnwrap(conn.registerUDP { raw in replies.feed(raw) }, "registerUDP refused")
        replies.sessionID = sessionID
        defer { conn.unregisterUDP(sessionID) }
        let target = NCTarget(host: Self.host, port: Self.udpEchoPort)

        // The datagram flow comes up asynchronously; resend until the first echo lands.
        var first: Data?
        let deadline = Date().addingTimeInterval(15)
        while first == nil && Date() < deadline {
            conn.sendUDP(sessionID: sessionID, target: target, payload: Self.dnsQuery)
            first = replies.wait(timeout: 1.0)
        }
        XCTAssertEqual(first, Self.dnsQuery, "no hysteria2 UDP echo over QUIC datagrams (\(conn.udpDiagnostics))")

        // hy2-frag ladder, printed as one "HY2LADDER" line whatever the outcome (diagnostics):
        //  A = the shipped defaults on the shared connection (no H3_DATAGRAM in SETTINGS, windowed send
        //      queue, batched pumps, budget = min(1197, flow maximumDatagramSize));
        //  B = control group: a private connection that announces H3_DATAGRAM like the first cut did —
        //      the server's http3 layer then steals QUIC datagrams (hy2-frag root cause), so B is lossy.
        // Rungs: "u<W>" one unfragmented datagram of W wire bytes; "b<n>x<W>[g<ms>]" n separate packets
        // back to back (or <ms> apart); "f<budget><mode>" a 3000-byte packet fragmented at <budget>.
        let probeA = Hy2UDPProbe(conn: conn, sessionID: sessionID, replies: replies, target: target)
        var ladder: [String] = ["A[" + conn.udpDiagnostics + "]"]
        ladder.append(contentsOf: probeA.sizeRungs([1197, 1300, 1400]))
        ladder.append(probeA.burst(3, wire: 1000, gapMs: 0))
        ladder.append(probeA.burst(6, wire: 300, gapMs: 0))
        let b8 = probeA.burst(8, wire: 1000, gapMs: 0)
        ladder.append(b8)
        // The acceptance check: five fragmented 3000-byte packets in a row, each must come back on its
        // first and only send (no retry masks a loss any more).
        var fragOK = 0
        for i in 0..<5 {
            if probeA.once(Hy2UDPProbe.pattern(3000, seed: 101 + i)) { fragOK += 1 }
        }
        ladder.append("fDEFAULT(\(conn.udpDatagramLimit))x5:\(fragOK)/5")
        let burstOK = b8.hasPrefix("b8x1000:8/8")

        // B: control connection without the payload cap.
        var bLine = "B[unavailable]"
        if let b = Self.startPrivateHy2(advertiseH3Datagram: true) {
            let bReplies = UDPReplies()
            if let bID = b.registerUDP({ raw in bReplies.feed(raw) }) {
                bReplies.sessionID = bID
                let probeB = Hy2UDPProbe(conn: b, sessionID: bID, replies: bReplies, target: target)
                if probeB.warmUp(Self.dnsQuery) {
                    var r: [String] = []
                    r.append(contentsOf: probeB.sizeRungs([1197, 1300]))
                    r.append(probeB.burst(8, wire: 1000, gapMs: 0))
                    r.append(probeB.fragRung(budget: 1197, label: "", seed: 300))
                    bLine = "B[" + b.udpDiagnostics + "] " + r.joined(separator: " ")
                } else {
                    bLine = "B[no warm-up echo " + b.udpDiagnostics + "]"
                }
                b.unregisterUDP(bID)
            }
            b.close()
        }
        ladder.append(bLine)
        ladder.append("A-end[" + conn.udpDiagnostics + "]")
        let line = "HY2LADDER " + ladder.joined(separator: " ")
        print(line)
        XCTContext.runActivity(named: line) { _ in }
        XCTAssertEqual(fragOK, 5, "fragmented 3000-byte UDP packets lost at the default settings [\(line)]")
        XCTAssertTrue(burstOK, "back-to-back UDP packets lost at the default settings [\(line)]")
    }

    /// A private (non-registry) hysteria2 connection to the loopback inbound, for control-group rungs.
    private static func startPrivateHy2(advertiseH3Datagram: Bool) -> NCHysteria2Connection? {
        let queue = DispatchQueue(label: "nc.loopback.hy2udp.b")
        guard let conn = NCHysteria2Connection(proxy: Self.hy2Proxy, queue: queue) else { return nil }
        conn.advertiseH3DatagramForTesting = advertiseH3Datagram
        let done = DispatchSemaphore(value: 0)
        let box = LockedBox<Error?>(nil)
        conn.start { err in
            box.set(err)
            done.signal()
        }
        guard done.wait(timeout: .now() + 30) == .success, box.get() == nil else {
            conn.close()
            return nil
        }
        return conn
    }
    // MARK: - NaïveProxy (feat/nc-naive-h2h3): sing-box naive inbound, h2 on 18040 (TCP), h3 on 18041 (UDP)

    private static let naiveH2Port = 18040
    private static let naiveH3Port = 18041
    private static let naiveUser = "nc-loop"
    private static let naivePassword = "nc-loop-naive-pw"

    private static func naiveProxy(name: String, quic: Bool, password: String = NativeCoreLoopbackTests.naivePassword) -> NCProxy {
        Self.proxy(name: name, type: "naive", port: quic ? Self.naiveH3Port : Self.naiveH2Port, extra: [
            "username": .string(Self.naiveUser), "password": .string(password),
            "sni": .string("localhost"), "skip-cert-verify": .bool(true), "quic": .bool(quic),
            "udp-over-tcp": .bool(true),
        ])
    }

    /// Many small writes: the first eight cross the wire padded, the rest raw — both directions.
    private func assertChunkedEcho(_ stream: NCRelayStream, chunks: Int = 20, size: Int = 700) throws {
        var all = Data()
        for i in 0..<chunks { all.append(Data((0..<size).map { UInt8(($0 + i * 31) & 0xff) })) }
        let exp = self.expectation(description: "chunked echo")
        let state = EchoState(want: all.count) { exp.fulfill() }
        for i in 0..<chunks { stream.send(all.subdata(in: (i * size)..<((i + 1) * size))) }
        state.pump(stream)
        self.wait(for: [exp], timeout: 20)
        let (data, err) = state.result()
        if let err { throw err }
        XCTAssertEqual(data, all)
    }

    func testNaiveH2TCPEcho() throws {
        let proxy = Self.naiveProxy(name: "loop-naive-h2", quic: false)
        let stream = try self.connect(proxy: proxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        try self.assertChunkedEcho(stream)
    }

    func testNaiveH2ConcurrentStreamsShareOneSession() throws {
        let proxy = Self.naiveProxy(name: "loop-naive-h2-multi", quic: false)
        let streams = try (0..<3).map { _ in try self.connect(proxy: proxy, target: Self.echoTarget) }
        defer { streams.forEach { $0.cancel() } }
        XCTAssertEqual(Set(streams.compactMap { ($0 as? NCH2ProxyStream).map { ObjectIdentifier($0) } }).count, 3)
        for s in streams { try self.assertEcho(s, payload: Self.payload) }
        XCTAssertGreaterThanOrEqual(NCConnector.sharedSessionCounts()["naive"] ?? 0, 1)
    }

    func testNaiveH3TCPEcho() throws {
        let proxy = Self.naiveProxy(name: "loop-naive-h3", quic: true)
        let stream = try self.connect(proxy: proxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        try self.assertChunkedEcho(stream)
    }

    func testNaiveWrongPasswordRejected() {
        let proxy = Self.naiveProxy(name: "loop-naive-badpw", quic: false, password: "wrong")
        XCTAssertThrowsError(try self.connect(proxy: proxy, target: Self.echoTarget)) { err in
            XCTAssertTrue((err as NSError).localizedDescription.contains("407"), "\(err)")
        }
    }

    /// UDP-over-TCP v2 through the naive CONNECT tunnel (NCUDPUoTSession's wire, driven directly).
    func testNaiveUoTUDPEcho() throws {
        for quic in [false, true] {
            let proxy = Self.naiveProxy(name: "loop-naive-uot-\(quic)", quic: quic)
            let stream = try self.connect(proxy: proxy, target: NCUoT.magicTarget)
            defer { stream.cancel() }
            let target = NCTarget(host: Self.host, port: Self.udpEchoPort)
            stream.send(NCUoT.request(destination: target))
            stream.send(NCUoT.packet(target: target, payload: Self.dnsQuery))
            let exp = self.expectation(description: "uot reply \(quic)")
            let box = LockedBox<Data>(Data())
            func pump() {
                stream.receive { d, _ in
                    guard let d else { exp.fulfill(); return }
                    var b = box.get(); b.append(d); box.set(b)
                    if NCUoT.parsePacket(b) != nil { exp.fulfill() } else { pump() }
                }
            }
            pump()
            self.wait(for: [exp], timeout: 15)
            let (from, payload, _) = try XCTUnwrap(NCUoT.parsePacket(box.get()), "no UoT reply (quic \(quic))")
            XCTAssertEqual(payload, Self.dnsQuery)
            XCTAssertEqual(from.port, Self.udpEchoPort)
        }
    }
}

/// hy2-frag ladder rungs over one registered hysteria2 UDP session (see testHysteria2UDPEcho).
private final class Hy2UDPProbe {
    let conn: NCHysteria2Connection
    let sessionID: UInt32
    let replies: UDPReplies
    let target: NCTarget
    let addrHeader: Int

    init(conn: NCHysteria2Connection, sessionID: UInt32, replies: UDPReplies, target: NCTarget) {
        self.conn = conn
        self.sessionID = sessionID
        self.replies = replies
        self.target = target
        self.addrHeader = NCHy2UDP.headerSize(address: NCHysteria2Connection.udpAddress(target))
    }

    static func pattern(_ n: Int, seed: Int) -> Data {
        var d = Data(count: n)
        for j in 0..<n {
            let v: Int = j &* 13 &+ seed &* 7
            d[j] = UInt8(truncatingIfNeeded: v)
        }
        return d
    }

    /// Resends `payload` until it echoes (the datagram flow comes up asynchronously).
    func warmUp(_ payload: Data) -> Bool {
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            conn.sendUDP(sessionID: sessionID, target: target, payload: payload)
            if let got = replies.wait(timeout: 1.0), got == payload { return true }
        }
        return false
    }

    /// One send, wait for its exact echo.
    func once(_ payload: Data, timeout: TimeInterval = 2.0) -> Bool {
        replies.drain()
        conn.sendUDP(sessionID: sessionID, target: target, payload: payload)
        let until = Date().addingTimeInterval(timeout)
        while Date() < until {
            guard let got = replies.wait(timeout: until.timeIntervalSinceNow) else { break }
            if got == payload { return true }
        }
        return false
    }

    /// Unfragmented single datagrams of each wire size (budget pinned above them).
    func sizeRungs(_ wires: [Int]) -> [String] {
        conn.setUDPDatagramLimitForTesting(9000)
        var out: [String] = []
        for wire in wires {
            let p = Self.pattern(wire - addrHeader, seed: wire)
            let before = replies.rawCount
            let ok = once(p, timeout: 1.5)
            out.append("u\(wire):\(ok ? "ok" : "LOST")(rx=\(replies.rawCount - before))")
        }
        conn.setUDPDatagramLimitForTesting(0)
        return out
    }

    /// `n` separate unfragmented packets of `wire` bytes, back to back or `gapMs` apart.
    func burst(_ n: Int, wire: Int, gapMs: Int) -> String {
        replies.drain()
        let before = replies.rawCount
        var want = Set<Data>()
        for i in 0..<n {
            let p = Self.pattern(wire - addrHeader, seed: 1000 + i * 31 + wire + gapMs)
            want.insert(p)
            conn.sendUDP(sessionID: sessionID, target: target, payload: p)
            if gapMs > 0 { Thread.sleep(forTimeInterval: Double(gapMs) / 1000) }
        }
        var got = 0
        let until = Date().addingTimeInterval(1.5)
        while got < n, Date() < until {
            guard let r = replies.wait(timeout: until.timeIntervalSinceNow) else { break }
            if want.remove(r) != nil { got += 1 }
        }
        let tag = gapMs > 0 ? "g\(gapMs)" : ""
        return "b\(n)x\(wire)\(tag):\(got)/\(n)(rx=\(replies.rawCount - before))"
    }

    /// Two 3000-byte packets fragmented at `budget`, one send each.
    func fragRung(budget: Int, label: String, seed: Int) -> String {
        conn.setUDPDatagramLimitForTesting(budget)
        let before = replies.rawCount
        var ok = 0
        for i in 0..<2 where once(Self.pattern(3000, seed: seed + i), timeout: 1.5) { ok += 1 }
        conn.setUDPDatagramLimitForTesting(0)
        return "f\(budget)\(label):\(ok)/2(rx=\(replies.rawCount - before))"
    }
}

// MARK: - Small thread-safe helpers

private final class LockedBox<T> {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func set(_ newValue: T) { self.lock.lock(); self.value = newValue; self.lock.unlock() }
    func get() -> T { self.lock.lock(); defer { self.lock.unlock() }; return self.value }
}

/// Accumulates relay receives until `want` bytes arrived, then fires `done`
/// exactly once. EOF before that is an error.
private final class EchoState {
    private let lock = NSLock()
    private var data = Data()
    private var err: Error?
    private var finished = false
    private let want: Int
    private let done: () -> Void

    init(want: Int, done: @escaping () -> Void) {
        self.want = want
        self.done = done
    }

    func pump(_ stream: NCRelayStream) {
        stream.receive { [weak self] chunk, error in
            guard let self else { return }
            self.lock.lock()
            if self.finished { self.lock.unlock(); return }
            if let chunk {
                self.data.append(chunk)
            }
            if let error {
                self.err = error
                self.finished = true
            } else if chunk == nil {
                self.err = NSError(domain: "NativeCoreLoopback", code: 1,
                                   userInfo: [NSLocalizedDescriptionKey: "EOF after \(self.data.count)/\(self.want) bytes"])
                self.finished = true
            } else if self.data.count >= self.want {
                self.finished = true
            }
            let isDone = self.finished
            self.lock.unlock()
            if isDone {
                self.done()
            } else {
                self.pump(stream)
            }
        }
    }

    func result() -> (Data, Error?) {
        self.lock.lock()
        defer { self.lock.unlock() }
        return (self.data, self.err)
    }
}

/// Records send-completion indices in firing order.
private final class CompletionTracker {
    private let lock = NSLock()
    private var indices: [Int] = []

    func record(_ index: Int) {
        self.lock.lock()
        self.indices.append(index)
        self.lock.unlock()
    }

    var count: Int {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.indices.count
    }

    var order: [Int] {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.indices
    }
}

/// Collects reassembled hysteria2 UDP replies for one session (sink runs on the connection queue).
private final class UDPReplies {
    private let cond = NSCondition()
    private var reassembler = NCHy2UDP.Reassembler()
    private var ready: [Data] = []
    var sessionID: UInt32 = 0

    private var rawSeen = 0
    /// Raw datagrams delivered to this session so far (any fragment, matched or not).
    var rawCount: Int {
        cond.lock(); defer { cond.unlock() }
        return rawSeen
    }

    func feed(_ raw: Data) {
        cond.lock(); defer { cond.unlock() }
        rawSeen += 1
        guard let frame = NCHy2UDP.decodeFrame(raw), frame.sessionID == sessionID,
              let payload = reassembler.feed(frame) else { return }
        ready.append(payload)
        cond.signal()
    }

    /// Forget echoes of earlier rungs that arrived late.
    func drain() {
        cond.lock(); defer { cond.unlock() }
        ready.removeAll()
    }

    func wait(timeout: TimeInterval) -> Data? {
        cond.lock(); defer { cond.unlock() }
        let until = Date().addingTimeInterval(max(0, timeout))
        while ready.isEmpty {
            if !cond.wait(until: until) { break }
        }
        return ready.isEmpty ? nil : ready.removeFirst()
    }
}

// MARK: - fix/nc-silent-fail: stream transports (tools/loopback/sing-box-config.json 18060–18063)

extension NativeCoreLoopbackTests {
    private static func silentFailProxy(_ name: String, _ type: String, _ port: Int,
                                        _ extra: [String: NCJSONValue]) -> NCProxy {
        var fields: [String: NCJSONValue] = ["server": .string("127.0.0.1"), "port": .number(Double(port))]
        for (k, v) in extra { fields[k] = v }
        return NCProxy(name: name, type: type, fields: fields)
    }

    private static let sfUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
    private static var sfEcho: NCTarget { NCTarget(host: "127.0.0.1", port: 18080) }
    private static let sfPayload = Data((0..<8192).map { UInt8(($0 * 7 + 3) & 0xff) })

    func testTrojanWebSocketEcho() throws {
        let p = Self.silentFailProxy("loop-trojan-ws", "trojan", 18060, [
            "password": .string("nc-loop-trojan-pw"), "sni": .string("localhost"), "skip-cert-verify": .bool(true),
            "network": .string("ws"), "ws-opts": .object(["path": .string("/tj")]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sfPayload)
    }

    func testTrojanGRPCEcho() throws {
        let p = Self.silentFailProxy("loop-trojan-grpc", "trojan", 18063, [
            "password": .string("nc-loop-trojan-pw"), "sni": .string("localhost"), "skip-cert-verify": .bool(true),
            "network": .string("grpc"), "grpc-opts": .object(["grpc-service-name": .string("TunSvc")]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sfPayload)
    }

    func testVLESSHTTPUpgradeEcho() throws {
        let p = Self.silentFailProxy("loop-vless-hu", "vless", 18061, [
            "uuid": .string(Self.sfUUID), "network": .string("ws"),
            "ws-opts": .object(["path": .string("/up"), "v2ray-http-upgrade": .bool(true)]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sfPayload)
    }

    /// Fast-open against sing-box 1.12.24 is EXPECTED TO FAIL — a server limitation, not a client
    /// bug (fix/nc-silent-fail iteration notes): sing-box's v2ray-httpupgrade inbound drops the
    /// bytes that arrive together with the upgrade request (its request read consumes past the
    /// header end and the remainder is discarded), so the vless layer starts mid-stream — server
    /// log: `inbound/vless[vless-httpupgrade-in]: unknown version: 3` (3 = first payload byte of
    /// the echo pattern). Reproduced with a plain-socket reference client: waiting for the 101
    /// echoes fine (testVLESSHTTPUpgradeEcho), while fast-open in one write or in split writes
    /// gets the same "unknown version" error and a reset. Clash.Meta fast-open semantics (send before
    /// the 101) are the feature under test and are covered client-side by the unit test
    /// testHTTPUpgradeFastOpenSendsBefore101. If a future sing-box preserves early data this test
    /// goes red at the XCTFail below — flip it back to a plain assertEcho then.
    func testVLESSHTTPUpgradeFastOpenEcho() throws {
        let p = Self.silentFailProxy("loop-vless-hu-fo", "vless", 18061, [
            "uuid": .string(Self.sfUUID), "network": .string("ws"),
            "ws-opts": .object(["path": .string("/up"), "v2ray-http-upgrade": .bool(true),
                                "v2ray-http-upgrade-fast-open": .bool(true)]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        do {
            try self.assertEcho(stream, payload: Self.sfPayload)
            XCTFail("fast-open echo unexpectedly succeeded — sing-box now preserves early data; "
                    + "restore the plain echo assertion in this test")
        } catch {
            // Expected: the server closes the connection after eating the early bytes
            // (EOF after 0 echoed bytes). The connect itself must have succeeded above.
        }
    }

    func testVLESSWebSocketEarlyDataEcho() throws {
        let p = Self.silentFailProxy("loop-vless-ws-ed", "vless", 18062, [
            "uuid": .string(Self.sfUUID), "network": .string("ws"),
            "ws-opts": .object(["path": .string("/ed"), "max-early-data": .number(2048),
                                "early-data-header-name": .string("Sec-WebSocket-Protocol")]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sfPayload)
    }

    func testVLESSWebSocketEDQueryEcho() throws {
        let p = Self.silentFailProxy("loop-vless-ws-edq", "vless", 18062, [
            "uuid": .string(Self.sfUUID), "network": .string("ws"),
            "ws-opts": .object(["path": .string("/ed?ed=2048")]),
        ])
        let stream = try self.connect(proxy: p, target: Self.sfEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sfPayload)
    }
}
