import XCTest
import Network
@testable import Tern

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
    private static let hy1Port = 18010
    private static let socks5TlsPort = 18019
    private static let socks5Port = 18020
    private static let socks5User = "nc-loop-socks-user"
    private static let socks5Password = "nc-loop-socks-pw"
    private static let trustTunnelPort = 18013
    private static let trustTunnelUser = "nc-loop-tt-user"
    private static let trustTunnelPassword = "nc-loop-tt-pw"
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
    private static let hy1Auth = "nc-loop-hy1-auth"
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

    private static var hy1Proxy: NCProxy {
        Self.proxy(name: "loop-hy1", type: "hysteria", port: Self.hy1Port, extra: [
            "auth-str": .string(Self.hy1Auth), "up": .string("50 Mbps"), "down": .string("100 Mbps"),
            "alpn": .array([.string("hysteria")]), "protocol": .string("udp"),
            "sni": .string("localhost"), "skip-cert-verify": .bool(true),
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

    func testHysteria1TCPEcho() throws {
        let stream = try self.connect(proxy: Self.hy1Proxy, target: Self.echoTarget)
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

    // MARK: - SOCKS5 / SOCKS5 over TLS (feat/nc-socks5-tls, #168)
    // Servers: the minimal SOCKS5 servers in tools/loopback/echo_server.py —
    // plain on :18020, TLS-wrapped on :18019 (self-signed cert, SAN localhost).

    private static var socks5PlainProxy: NCProxy {
        Self.proxy(name: "loop-socks5", type: "socks5", port: Self.socks5Port, extra: [:])
    }

    private static var socks5TLSProxy: NCProxy {
        Self.proxy(name: "loop-socks5-tls", type: "socks5", port: Self.socks5TlsPort, extra: [
            "tls": .bool(true), "sni": .string("localhost"), "skip-cert-verify": .bool(true),
        ])
    }

    private static var socks5TLSAuthProxy: NCProxy {
        Self.proxy(name: "loop-socks5-tls-auth", type: "socks5", port: Self.socks5TlsPort, extra: [
            "tls": .bool(true), "sni": .string("localhost"), "skip-cert-verify": .bool(true),
            "username": .string(Self.socks5User), "password": .string(Self.socks5Password),
        ])
    }

    func testSocks5PlainEcho() throws {
        let stream = try self.connect(proxy: Self.socks5PlainProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testSocks5TLSEcho() throws {
        let stream = try self.connect(proxy: Self.socks5TLSProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        let stream2 = try self.connect(proxy: Self.socks5TLSProxy, target: Self.echoTarget)
        defer { stream2.cancel() }
        try self.assertEcho(stream2, payload: Data((0..<(1 << 20)).map { UInt8(($0 * 31 + 7) & 0xff) }), timeout: 60)
    }

    func testSocks5TLSWithAuth() throws {
        let stream = try self.connect(proxy: Self.socks5TLSAuthProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testSocks5TLSWrongSNIRejected() throws {
        // Without skip-cert-verify the self-signed loopback cert must not
        // verify for a wrong SNI; with it, the same node connects.
        let strict = Self.proxy(name: "loop-socks5-tls-wrong-sni", type: "socks5", port: Self.socks5TlsPort, extra: [
            "tls": .bool(true), "sni": .string("wrong.example.com"),
        ])
        XCTAssertThrowsError(try self.connect(proxy: strict, target: Self.echoTarget))
        let skipping = Self.proxy(name: "loop-socks5-tls-wrong-sni-skip", type: "socks5", port: Self.socks5TlsPort, extra: [
            "tls": .bool(true), "sni": .string("wrong.example.com"), "skip-cert-verify": .bool(true),
        ])
        let stream = try self.connect(proxy: skipping, target: Self.echoTarget)
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
        var plain = try XCTUnwrap(target.atypEncoded)
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
            stream.send(try XCTUnwrap(NCUoT.request(destination: target)))
            stream.send(try XCTUnwrap(NCUoT.packet(target: target, payload: Self.dnsQuery)))
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

    // MARK: - Lua custom backend (feat/nc-lua S2)

    private static let luaPort = 18016

    /// The peer (tools/loopback/lua-mock-server.py) answers the script's
    /// "HE" greeting with "HO" and echoes every chunk XORed with 0x5A; the
    /// script's on_read applies the same XOR, so assertEcho verifies the
    /// whole flags -> handshake -> write/read transform path over real TCP.
    private static let luaXORScript = """
    local KEY = 0x5A
    local function xorBytes(s)
      return (s:gsub(".", function(c) return string.char(string.byte(c) ~ KEY) end))
    end
    function wa_lua_on_flags_cb(ctx)
      backend.write(ctx, "HE")
      return 0
    end
    function wa_lua_on_handshake_cb(ctx) return _G.hs_done == true end
    function wa_lua_on_read_cb(ctx, buf)
      if _G.hs_done ~= true then
        if buf == "HO" then
          _G.hs_done = true
          return backend.RESULT.HANDSHAKE, nil
        end
        return backend.RESULT.ERROR, nil
      end
      return backend.RESULT.SUCCESS, xorBytes(buf)
    end
    function wa_lua_on_write_cb(ctx, buf) return backend.RESULT.SUCCESS, xorBytes(buf) end
    function wa_lua_on_close_cb(ctx) return 0 end
    """

    private static var luaProxy: NCProxy {
        Self.proxy(name: "loop-lua", type: "lua", port: Self.luaPort, extra: [
            "script": .string(Self.luaXORScript),
        ])
    }

    func testLuaCustomBackendEcho() throws {
        // Diagnostic probes (added after run 40422207536 hung in connect with
        // no completion at all): prove the mock is reachable from this
        // process and speaks HE/HO before involving NCConnector.
        let probe = NWConnection(host: NWEndpoint.Host(Self.host),
                                 port: NWEndpoint.Port(rawValue: UInt16(Self.luaPort))!,
                                 using: .tcp)
        let readyExp = expectation(description: "lua mock ready")
        let readyBox = LockedBox(false)
        probe.stateUpdateHandler = { state in
            if case .ready = state { readyBox.set(true); readyExp.fulfill() }
            if case .failed = state { readyExp.fulfill() }
        }
        probe.start(queue: DispatchQueue(label: "nc.loopback.lua.probe"))
        wait(for: [readyExp], timeout: 5)
        XCTAssertTrue(readyBox.get(), "lua mock :\(Self.luaPort) not reachable from the test process")
        let hoExp = expectation(description: "lua mock HO")
        let hoBox = LockedBox<Data?>(nil)
        probe.send(content: Data("HE".utf8), completion: .idempotent)
        probe.receive(minimumIncompleteLength: 1, maximumLength: 64) { data, _, _, _ in
            hoBox.set(data)
            hoExp.fulfill()
        }
        wait(for: [hoExp], timeout: 5)
        XCTAssertEqual(hoBox.get(), Data("HO".utf8), "lua mock did not answer HE with HO")
        probe.cancel()

        let stream = try self.connect(proxy: Self.luaProxy, target: Self.echoTarget, timeout: 20)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    /// Shadowrocket/lua-backend http-backend.lua (MIT, github.com/Shadowrocket/lua-backend), verbatim — the
    /// shape every real Shadowrocket Lua backend has (`require 'backend'`, on_flags = DIRECT_WRITE,
    /// RESULT.DIRECT, handshake keyed by ctx uuid) — against sing-box's plain HTTP CONNECT inbound on 18018.
    private static let shadowrocketHTTPBackend = #"""
    -- file: lua/backend-http.lua

    local http = require 'http'
    local backend = require 'backend'

    local char = string.char
    local byte = string.byte
    local find = string.find
    local sub = string.sub

    local ADDRESS = backend.ADDRESS
    local PROXY = backend.PROXY
    local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE

    local SUCCESS = backend.RESULT.SUCCESS
    local HANDSHAKE = backend.RESULT.HANDSHAKE
    local DIRECT = backend.RESULT.DIRECT

    local ctx_uuid = backend.get_uuid
    local ctx_proxy_type = backend.get_proxy_type
    local ctx_address_type = backend.get_address_type
    local ctx_address_host = backend.get_address_host
    local ctx_address_bytes = backend.get_address_bytes
    local ctx_address_port = backend.get_address_port
    local ctx_write = backend.write
    local ctx_free = backend.free
    local ctx_debug = backend.debug

    local flags = {}
    local kHttpHeaderSent = 1
    local kHttpHeaderRecived = 2

    function wa_lua_on_flags_cb(ctx)
        return DIRECT_WRITE
    end

    function wa_lua_on_handshake_cb(ctx)
        local uuid = ctx_uuid(ctx)

        if flags[uuid] == kHttpHeaderRecived then
            return true
        end

        if flags[uuid] ~= kHttpHeaderSent then
            local host = ctx_address_host(ctx)
            local port = ctx_address_port(ctx)
            local res = 'CONNECT ' .. host .. ':' .. port .. ' HTTP/1.1\r\n' ..
                        'Host: ' .. host .. ':' .. port .. '\r\n' ..
                        'Proxy-Connection: Keep-Alive\r\n\r\n'
            ctx_write(ctx, res)
            flags[uuid] = kHttpHeaderSent
        end

        return false
    end

    function wa_lua_on_read_cb(ctx, buf)
        ctx_debug('wa_lua_on_read_cb')
        local uuid = ctx_uuid(ctx)
        if flags[uuid] == kHttpHeaderSent then
            flags[uuid] = kHttpHeaderRecived
            return HANDSHAKE, nil
        end
        return DIRECT, buf
    end

    function wa_lua_on_write_cb(ctx, buf)
        ctx_debug('wa_lua_on_write_cb')
        return DIRECT, buf
    end

    function wa_lua_on_close_cb(ctx)
        ctx_debug('wa_lua_on_close_cb')
        local uuid = ctx_uuid(ctx)
        flags[uuid] = nil
        ctx_free(ctx)
        return SUCCESS
    end
    """#

    func testLuaShadowrocketHTTPBackendEcho() throws {
        let proxy = Self.proxy(name: "loop-lua-http", type: "lua", port: 18018, extra: [
            "script": .string(Self.shadowrocketHTTPBackend),
        ])
        let stream = try self.connect(proxy: proxy, target: Self.echoTarget, timeout: 20)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    // MARK: - TrustTunnel (#161, official trusttunnel_endpoint on 18013, HTTP/2 track)

    private static func trustTunnelProxy(name: String, password: String, quic: Bool = false) -> NCProxy {
        Self.proxy(name: name, type: "trusttunnel", port: Self.trustTunnelPort, extra: [
            "username": .string(Self.trustTunnelUser), "password": .string(password),
            "sni": .string("localhost"), "skip-cert-verify": .bool(true), "quic": .bool(quic),
            // H3 cases must prove HTTP/3 itself: no silent fallback to the H2 listener on the same port.
            "h2-fallback": .bool(false),
        ])
    }

    /// One `_udp2` stream (spec §6) to the UDP echo; DNS-sized and 1200-byte datagrams must come back byte-exact.
    private func assertTrustTunnelUDPEcho(quic: Bool) throws {
        let proxy = Self.trustTunnelProxy(name: quic ? "loop-trusttunnel-h3-udp" : "loop-trusttunnel-h2-udp",
                                          password: Self.trustTunnelPassword, quic: quic)
        let exp = self.expectation(description: "tt udp open")
        let box = LockedBox<(NCRelayStream?, Error?)>((nil, nil))
        NCTrustTunnelSessionManager.udpStream(proxy: proxy, target: NCTarget(host: Self.host, port: Self.udpEchoPort),
                                              queue: DispatchQueue(label: "nc.loopback.tt.udp.\(quic)")) { s, e in
            box.set((s, e)); exp.fulfill()
        }
        self.wait(for: [exp], timeout: 20)
        let (s, e) = box.get()
        if let e { throw e }
        let stream = try XCTUnwrap(s, "tt udp: neither stream nor error")
        defer { stream.cancel() }
        for payload in [Self.dnsQuery, Data((0..<1200).map { UInt8(($0 * 7 + 3) & 0xff) })] {
            let got = self.expectation(description: "tt udp echo")
            let reply = LockedBox<Data?>(nil)
            stream.receive { d, _ in reply.set(d); got.fulfill() }
            stream.send(payload)
            self.wait(for: [got], timeout: 10)
            XCTAssertEqual(reply.get(), payload)
        }
    }

    // MARK: - TrustTunnel HTTP/3 (fix/nc-trusttunnel-h3) against the official endpoint's QUIC listener

    /// 8 KiB, then 1 MiB byte-exact through one H3 CONNECT stream, then a second stream on the same QUIC connection.
    func testTrustTunnelH3TCPEcho() throws {
        let proxy = Self.trustTunnelProxy(name: "loop-trusttunnel-h3", password: Self.trustTunnelPassword, quic: true)
        let stream = try self.connect(proxy: proxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        try self.assertEcho(stream, payload: Data((0..<(1 << 20)).map { UInt8(($0 * 31 + 7) & 0xff) }), timeout: 60)
        let second = try self.connect(proxy: proxy, target: Self.echoTarget)
        defer { second.cancel() }
        try self.assertEcho(second, payload: Self.payload)
    }

    func testTrustTunnelH3WrongPasswordRejected() {
        let proxy = Self.trustTunnelProxy(name: "loop-trusttunnel-h3-badpw", password: "wrong-password", quic: true)
        XCTAssertThrowsError(try self.connect(proxy: proxy, target: Self.echoTarget)) { err in
            XCTAssertTrue("\(err)".contains("407"), "\(err)")
        }
    }

    func testTrustTunnelH3UDPEcho() throws { try assertTrustTunnelUDPEcho(quic: true) }

    func testTrustTunnelH2UDPEcho() throws { try assertTrustTunnelUDPEcho(quic: false) }

    /// 8 KiB echo plus a chunked echo: the endpoint announces MAX_CONCURRENT_STREAMS 1000 and a 128 KiB stream
    /// window — the #161 run stalled at exactly 1000 bytes because the old NCH2MuxCore read SETTINGS id 0x3 as
    /// INITIAL_WINDOW_SIZE (fixed on integrate by fix/nc-h2-cidr).
    func testTrustTunnelH2TCPEcho() throws {
        let stream = try self.connect(proxy: Self.trustTunnelProxy(name: "loop-trusttunnel-h2", password: Self.trustTunnelPassword),
                                      target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
        try self.assertEcho(stream, payload: Data((0..<200_000).map { UInt8(($0 * 13 + 5) & 0xff) }))
    }

    func testTrustTunnelWrongPasswordRejected() {
        let proxy = Self.trustTunnelProxy(name: "loop-trusttunnel-badpw", password: "wrong-password")
        XCTAssertThrowsError(try self.connect(proxy: proxy, target: Self.echoTarget)) { err in
            XCTAssertTrue("\(err)".contains("407"), "\(err)")
        }
    }

    // MARK: - MASQUE CONNECT-UDP (#160, RFC 9298) against masque-go's proxy on 18012

    private static var masqueProxy: NCProxy {
        Self.proxy(name: "loop-masque", type: "masque", port: 18012, extra: [
            "mode": .string("connect-udp"),
            "username": .string("loop"), "password": .string("loop"),
            "uri": .string("https://\(Self.host):18012/.well-known/masque/udp/{target_host}/{target_port}/"),
            "sni": .string("localhost"),
            "skip-cert-verify": .bool(true),
        ])
    }

    /// The tunnel's NCUDPMASQUESession is a thin wrapper over exactly this call: Extended CONNECT
    /// (:protocol connect-udp, the template path with its trailing slash — #160 got a 307 without it), then
    /// HTTP Datagrams to the UDP echo; two concurrent flows on the shared connection must not cross.
    func testMASQUEUDPEcho() throws {
        func open(_ label: String) throws -> NCRelayStream {
            let exp = self.expectation(description: "masque \(label)")
            let box = LockedBox<(NCRelayStream?, Error?)>((nil, nil))
            NCMASQUERegistry.masqueStream(proxy: Self.masqueProxy, target: NCTarget(host: Self.host, port: Self.udpEchoPort),
                                          queue: DispatchQueue(label: "nc.loopback.masque.\(label)")) { s, e in
                box.set((s, e)); exp.fulfill()
            }
            self.wait(for: [exp], timeout: 20)
            let (s, e) = box.get()
            if let e { throw e }
            return try XCTUnwrap(s, "masque \(label): neither stream nor error")
        }
        let a = try open("a")
        defer { a.cancel() }
        let b = try open("b")
        defer { b.cancel() }
        for (stream, payload) in [(a, Self.dnsQuery), (b, Data((0..<1000).map { UInt8(($0 * 3 + 1) & 0xff) }))] {
            let exp = self.expectation(description: "masque echo")
            let box = LockedBox<Data?>(nil)
            stream.receive { d, _ in box.set(d); exp.fulfill() }
            stream.send(payload)
            self.wait(for: [exp], timeout: 10)
            XCTAssertEqual(box.get(), payload)
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

// MARK: - fix/nc-sudoku-interop: the official Sudoku server (tools/loopback/sudoku/*.json, :18090–:18094)

extension NativeCoreLoopbackTests {
    /// Split ("available") private key of the loopback master key pair; the servers hold the master public key
    /// 3388f6b5…451d, so this also exercises the client's key normalisation (Ed25519 r·B + k·B).
    private static let sudokuKey = "e2eac3d4c0036ceb028048417bf2bf7c213681e145603c38ec8bffadb2e40c014130de746760b7dc9b515545f47e29df255687fe3ee972c2c517264f6a37b60b"
    private static var sudokuEcho: NCTarget { NCTarget(host: "127.0.0.1", port: 18080) }
    /// Plain HTTP origin (python http.server) started next to the Sudoku servers.
    private static var sudokuHTTPOrigin: NCTarget { NCTarget(host: "127.0.0.1", port: 18095) }
    /// Large enough to span many records and TCP reads (server-side padding lands between clue bytes).
    private static let sudokuPayload: Data = {
        var bytes = [UInt8](repeating: 0, count: 96_000)
        for i in 0..<bytes.count { bytes[i] = UInt8(truncatingIfNeeded: i &* 31 &+ 7) }
        return Data(bytes)
    }()
    /// tools/loopback/start-servers.sh writes the same 48 KiB page.
    private static let sudokuPage: Data = {
        var bytes = Array("tern-sudoku-loopback-ok\n".utf8)
        let marker = bytes.count
        bytes.reserveCapacity(48 * 1024)
        for i in 0..<(48 * 1024 - marker) {
            let v: Int = 0x21 + (i * 7) % 94
            bytes.append(UInt8(v))
        }
        return Data(bytes)
    }()

    private static func sudokuProxy(_ name: String, _ port: Int, _ extra: [String: NCJSONValue]) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string("127.0.0.1"), "port": .number(Double(port)),
                                        "key": .string(Self.sudokuKey)]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: name, type: "sudoku", fields: f)
    }

    /// The public path: the node is available and NCConnector dials it (TCP + NCSudokuSession).
    private func sudokuDial(_ proxy: NCProxy, target: NCTarget, timeout: TimeInterval = 30) throws -> NCRelayStream {
        XCTAssertNil(NCSupport.unsupportedReason(proxy), "\(proxy.name): node must be available")
        return try self.connect(proxy: proxy, target: target, timeout: timeout)
    }

    /// Receives until EOF, or until the HTTP body reaches its Content-Length.
    private func readHTTPResponse(_ stream: NCRelayStream, timeout: TimeInterval = 20) throws -> (head: String, body: Data) {
        let exp = self.expectation(description: "http response")
        let acc = LockedBox(Data())
        let failure = LockedBox<Error?>(nil)
        let once = NCCallOnce { exp.fulfill() }
        let sep = Data("\r\n\r\n".utf8)
        func complete(_ d: Data) -> Bool {
            guard let r = d.range(of: sep) else { return false }
            let head = String(decoding: d[..<r.lowerBound], as: UTF8.self).lowercased()
            guard let line = head.split(separator: "\r\n").first(where: { $0.hasPrefix("content-length:") }),
                  let n = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) else {
                return false
            }
            return d.count - r.upperBound >= n
        }
        func pump() {
            stream.receive { chunk, err in
                if let err { failure.set(err); once.call(); return }
                guard let chunk else { once.call(); return }
                var d = acc.get()
                d.append(chunk)
                acc.set(d)
                if complete(d) { once.call() } else { pump() }
            }
        }
        pump()
        self.wait(for: [exp], timeout: timeout)
        if let err = failure.get() { throw err }
        let d = acc.get()
        guard let r = d.range(of: sep) else {
            throw NSError(domain: "NativeCoreLoopback", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "no HTTP head in \(d.count) bytes"])
        }
        return (String(decoding: d[..<r.lowerBound], as: UTF8.self), Data(d[r.upperBound...]))
    }

    func testSudokuServerPortsReachable() {
        for port in 18090...18095 {
            let ok = LockedBox(false)
            let exp = self.expectation(description: "sudoku port \(port)")
            let once = NCCallOnce { exp.fulfill() }
            let conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(port))!, using: .tcp)
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    ok.set(true)
                    once.call()
                case .failed, .cancelled:
                    once.call()
                default: break
                }
            }
            conn.start(queue: DispatchQueue(label: "nc.loopback.sudoku.ports"))
            self.wait(for: [exp], timeout: 5)
            conn.stateUpdateHandler = nil
            conn.cancel()
            XCTAssertTrue(ok.get(), "official sudoku server / http origin 127.0.0.1:\(port) not accepting")
        }
    }

    /// prefer_entropy, chacha20-poly1305, legacy HTTP mask, pure downlink, server pads 10–30 %.
    func testSudokuTCPEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku", 18090, ["aead-method": .string("chacha20-poly1305"),
                                                        "table-type": .string("prefer_entropy")])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sudokuPayload)
        try self.assertEcho(stream, payload: Data("second round".utf8))
    }

    /// 1 MiB, byte-exact, streamed in 64 KiB chunks with back-pressure (many records, TCP reads, server padding).
    private func sudokuBigEcho(_ stream: NCRelayStream, bytes: Int, timeout: TimeInterval) throws {
        var raw = [UInt8](repeating: 0, count: bytes)
        for i in 0..<bytes { raw[i] = UInt8(truncatingIfNeeded: (i &* 131) ^ (i >> 9)) }
        let payload = Data(raw)
        let exp = self.expectation(description: "sudoku big echo")
        let state = EchoState(want: payload.count) { exp.fulfill() }
        state.pump(stream)
        let chunk = 64 * 1024
        func sendFrom(_ off: Int) {
            guard off < payload.count else { return }
            let end = min(off + chunk, payload.count)
            stream.send(payload.subdata(in: off..<end)) { sendFrom(end) }
        }
        sendFrom(0)
        self.wait(for: [exp], timeout: timeout)
        let (data, err) = state.result()
        if let err { throw err }
        XCTAssertEqual(data.count, payload.count, "echoed length")
        XCTAssertTrue(data == payload, "big echo bytes differ")
    }

    func testSudokuTCPEcho1MiB() throws {
        let p = Self.sudokuProxy("loop-sudoku-1m", 18090, ["aead-method": .string("chacha20-poly1305")])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.sudokuBigEcho(stream, bytes: 1 << 20, timeout: 90)
    }

    /// Rekey path: the client rotates its send epoch every 128 KiB (official KeyUpdateAfterBytes semantics, lowered
    /// for the test), so the official server must derive each new epoch key and keep decrypting — 8 key updates.
    func testSudokuClientEpochRekeyEcho() throws {
        let saved = NCSudokuRecordLayer.keyUpdateAfterBytes
        NCSudokuRecordLayer.keyUpdateAfterBytes = 128 * 1024
        defer { NCSudokuRecordLayer.keyUpdateAfterBytes = saved }
        let p = Self.sudokuProxy("loop-sudoku-rekey", 18091, [
            "aead-method": .string("aes-128-gcm"), "table-type": .string("prefer_ascii"),
            "enable-pure-downlink": .bool(false), "http-mask": .bool(false),
        ])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.sudokuBigEcho(stream, bytes: 1 << 20, timeout: 90)
    }

    /// Rekey path with the official constants on both ends: 33 MiB each way crosses KeyUpdateAfterBytes (32 MiB), so
    /// the client rotates its send epoch and the official server rotates its own — the client must follow the
    /// server's new epoch key mid-stream, byte-exact.
    func testSudokuBidirectionalEpochRekey33MiB() throws {
        XCTAssertEqual(NCSudokuRecordLayer.keyUpdateAfterBytes, 32 << 20, "official KeyUpdateAfterBytes")
        let p = Self.sudokuProxy("loop-sudoku-rekey33", 18090, ["aead-method": .string("chacha20-poly1305")])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.sudokuBigEcho(stream, bytes: 33 << 20, timeout: 300)
    }

    /// A real HTTP/1 fetch through the official server: GET a 48 KiB page from the :18095 origin.
    func testSudokuHTTPFetch() throws {
        let p = Self.sudokuProxy("loop-sudoku-http", 18090, [:])
        let stream = try self.sudokuDial(p, target: Self.sudokuHTTPOrigin)
        defer { stream.cancel() }
        stream.send(Data("GET /sudoku-fetch.txt HTTP/1.1\r\nHost: 127.0.0.1:18095\r\nUser-Agent: tern-loopback\r\nAccept: */*\r\nConnection: close\r\n\r\n".utf8))
        let (head, body) = try self.readHTTPResponse(stream)
        XCTAssertTrue(head.hasPrefix("HTTP/1.0 200") || head.hasPrefix("HTTP/1.1 200"), head)
        XCTAssertEqual(body.count, Self.sudokuPage.count)
        XCTAssertEqual(body, Self.sudokuPage, "page bytes differ")
    }

    /// prefer_ascii, aes-128-gcm, no HTTP mask, packed (bandwidth-optimised) downlink.
    func testSudokuASCIIPackedDownlinkEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku-ascii", 18091, [
            "aead-method": .string("aes-128-gcm"), "table-type": .string("prefer_ascii"),
            "enable-pure-downlink": .bool(false), "http-mask": .bool(false),
        ])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sudokuPayload)
    }

    /// up_ascii_down_entropy with a custom x/p/v layout, aead none (raw passthrough), official nested httpmask block.
    func testSudokuDirectionalCustomNoneEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku-dir", 18092, [
            "aead-method": .string("none"), "table-type": .string("up_ascii_down_entropy"),
            "custom-table": .string("xpxvvpvv"), "httpmask": .object(["disable": .bool(true)]),
        ])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.sudokuPayload)
    }

    /// custom-tables rotation: each dial picks one table and announces it with the ClientHello table hint.
    func testSudokuCustomTablesRotationEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku-rot", 18093, [
            "custom-tables": .array([.string("xpxvvpvv"), .string("vxpvxvvp")]), "enable-pure-downlink": .bool(false),
        ])
        for _ in 0..<4 {
            let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
            try self.assertEcho(stream, payload: Data(Self.sudokuPayload.prefix(8192)))
            stream.cancel()
        }
    }

    /// A key the server does not hold is rejected by the server itself: it cannot open the ClientHello, logs
    /// "Suspicious connection" after its 5 s handshake window and hands the socket to the fallback — the echo
    /// backend reflects our own records (they fail authentication), the closed fallback drops the socket.
    /// Either way the client reports that verdict well inside its own 10 s deadline, never a timeout.
    func testSudokuWrongKeyRejected() throws {
        var bad = Self.sudokuKey
        bad.removeLast(2)
        bad += "0c" // still a canonical split key, different master public key
        for (port, expected) in [(18090, "无法认证"), (18094, "关闭了连接")] {
            let p = Self.sudokuProxy("loop-sudoku-badkey-\(port)", port, ["key": .string(bad)])
            let t0 = Date()
            XCTAssertThrowsError(try self.sudokuDial(p, target: Self.sudokuEcho, timeout: 15)) { err in
                let msg = err.localizedDescription
                XCTAssertTrue(msg.contains(expected), "port \(port): \(msg)")
                XCTAssertFalse(msg.lowercased().contains("timeout") || msg.contains("超时"), "port \(port): \(msg)")
            }
            XCTAssertLessThan(Date().timeIntervalSince(t0), 9.5, "port \(port): rejection should come from the server")
        }
    }

    /// The master public key itself as the client key (no private key to normalise) also interoperates.
    func testSudokuPublicKeyAsClientKeyEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku-pub", 18090, [
            "key": .string("3388f6b59b225f4e41cd14f445b73b6568711ce536832217b15649253612451d"),
        ])
        let stream = try self.sudokuDial(p, target: Self.sudokuEcho)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Data(Self.sudokuPayload.prefix(4096)))
    }

    // MARK: Sudoku UDP (feat/nc-sudoku-udp): UoT inside the tunnel, KIP StartUoT, against the official server

    /// tools/loopback/echo_server.py's DNS responder: answers every A query with 192.0.2.53.
    private static let loopDNSPort = 18084

    /// The data plane's Sudoku UDP session (NCSudokuUDPSession, created by NCDataPlane.openUDP) against the official
    /// server; datagrams are sent in order and the replies collected with the peer the server reported.
    /// `afterFirstReply` datagrams are sent once the first reply arrived (the tunnel is up).
    private func sudokuUDP(_ proxy: NCProxy, _ datagrams: [(NCTarget, Data)], afterFirstReply: [(NCTarget, Data)] = [],
                           expect: Int, timeout: TimeInterval = 20) throws -> [(peer: NCTarget?, payload: Data)] {
        XCTAssertNil(NCSupport.unsupportedReason(proxy), "\(proxy.name): node must be available")
        let queue = DispatchQueue(label: "nc.loopback.sudoku-udp.\(proxy.name)")
        let replies = LockedBox<[(peer: NCTarget?, payload: Data)]>([])
        let closed = LockedBox<String?>(nil)
        let exp = self.expectation(description: "sudoku udp \(proxy.name)")
        exp.expectedFulfillmentCount = max(1, expect)
        exp.assertForOverFulfill = false
        let session: NCSudokuUDPSession = queue.sync {
            let s = NCSudokuUDPSession(proxy: proxy, queue: queue)
            s.onDatagram = { [weak s] peer, payload in
                var r = replies.get(); r.append((peer, payload)); replies.set(r)
                if r.count == 1, let s { for (t, d) in afterFirstReply { s.send(d, to: t) } }
                exp.fulfill()
            }
            s.onClose = { err in
                closed.set(err?.localizedDescription ?? "EOF")
                for _ in 0..<max(1, expect) { exp.fulfill() }
            }
            return s
        }
        defer { queue.sync { session.cancel() } }
        // Sent while the tunnel is still opening: exercises the bounded pre-open queue too.
        queue.async { for (t, d) in datagrams { session.send(d, to: t) } }
        // XCTWaiter: a short count is reported by the callers' assertions, not as a bare timeout.
        _ = XCTWaiter().wait(for: [exp], timeout: timeout)
        if let why = closed.get(), replies.get().count < expect {
            XCTFail("\(proxy.name): UoT tunnel closed early: \(why)")
        }
        return replies.get()
    }

    /// DNS-sized + 1400-byte datagrams to the UDP echo backend by IP, and one to a domain (resolved by the server).
    func testSudokuUDPEcho() throws {
        let p = Self.sudokuProxy("loop-sudoku-udp", 18090, ["aead-method": .string("chacha20-poly1305")])
        let big = Data((0..<1400).map { UInt8(($0 * 13 + 5) & 0xff) })
        let echo = NCTarget(host: "127.0.0.1", port: Self.udpEchoPort)
        let r = try self.sudokuUDP(p, [(echo, Self.dnsQuery), (echo, big),
                                       (NCTarget(host: "localhost", port: Self.udpEchoPort), Data("by-domain".utf8))],
                                   expect: 3)
        XCTAssertEqual(r.count, 3, "replies: \(r.map { $0.payload.count })")
        let payloads = r.map { $0.payload }
        XCTAssertTrue(payloads.contains(Self.dnsQuery), "DNS-sized datagram not echoed")
        XCTAssertTrue(payloads.contains(big), "1400-byte datagram not echoed byte-exact")
        XCTAssertTrue(payloads.contains(Data("by-domain".utf8)), "domain-addressed datagram not echoed")
        for x in r {
            XCTAssertEqual(x.peer?.host, "127.0.0.1")
            XCTAssertEqual(x.peer?.port, Self.udpEchoPort)
        }
    }

    /// DNS over UDP through the tunnel: a real query answered by a real (loopback) DNS server.
    func testSudokuUDPDNSQuery() throws {
        let p = Self.sudokuProxy("loop-sudoku-dns", 18090, [:])
        var q = Data([0x5a, 0x17, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in ["tern-sudoku", "test"] {
            q.append(UInt8(label.utf8.count))
            q.append(contentsOf: label.utf8)
        }
        q.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        let r = try self.sudokuUDP(p, [(NCTarget(host: "127.0.0.1", port: Self.loopDNSPort), q)], expect: 1)
        let answer = try XCTUnwrap(r.first?.payload, "no DNS answer through the Sudoku UoT tunnel")
        XCTAssertGreaterThanOrEqual(answer.count, q.count + 16)
        let a = [UInt8](answer)
        XCTAssertEqual(Array(a[0..<2]), [0x5a, 0x17], "transaction id")
        XCTAssertEqual(a[2] & 0x80, 0x80, "QR bit")
        XCTAssertEqual(Int(a[6]) << 8 | Int(a[7]), 1, "ANCOUNT")
        XCTAssertEqual(Array(a.suffix(4)), [192, 0, 2, 53], "A record")
    }

    /// The other wire variants carry UoT too: prefer_ascii + aes-128-gcm + packed downlink, and
    /// up_ascii_down_entropy + custom table + aead none.
    func testSudokuUDPEchoAcrossWireVariants() throws {
        let echo = NCTarget(host: "127.0.0.1", port: Self.udpEchoPort)
        let big = Data((0..<1400).map { UInt8(($0 * 31 + 1) & 0xff) })
        let variants: [NCProxy] = [
            Self.sudokuProxy("loop-sudoku-udp-ascii", 18091, [
                "aead-method": .string("aes-128-gcm"), "table-type": .string("prefer_ascii"),
                "enable-pure-downlink": .bool(false), "http-mask": .bool(false),
            ]),
            Self.sudokuProxy("loop-sudoku-udp-dir", 18092, [
                "aead-method": .string("none"), "table-type": .string("up_ascii_down_entropy"),
                "custom-table": .string("xpxvvpvv"), "httpmask": .object(["disable": .bool(true)]),
            ]),
        ]
        for p in variants {
            let r = try self.sudokuUDP(p, [(echo, Self.dnsQuery), (echo, big)], expect: 2)
            XCTAssertEqual(Set(r.map { $0.payload }), Set([Self.dnsQuery, big]), p.name)
        }
    }

    /// A burst of 64 × 1400 B datagrams on one open association (frames coalesce into records / TCP reads both
    /// ways), after 16 queued while the tunnel was opening (the pre-open cap).
    func testSudokuUDPBurst() throws {
        let p = Self.sudokuProxy("loop-sudoku-udp-burst", 18090, [:])
        let echo = NCTarget(host: "127.0.0.1", port: Self.udpEchoPort)
        func gram(_ i: Int) -> (NCTarget, Data) {
            var d = Data(repeating: UInt8(i & 0xff), count: 1400)
            d[0] = 0xb5
            return (echo, d)
        }
        let r = try self.sudokuUDP(p, (0..<16).map(gram), afterFirstReply: (16..<80).map(gram), expect: 80,
                                   timeout: 30)
        // Loopback UDP between the official server and the echo backend may still drop a datagram under a burst.
        XCTAssertGreaterThanOrEqual(r.count, 76, "burst: \(r.count)/80 echoed")
        XCTAssertTrue(r.allSatisfy { $0.payload.count == 1400 && $0.payload.first == 0xb5 }, "a burst datagram was corrupted")
        let firstSixteen = Set(r.map { Int($0.payload[1]) }).intersection(Set(0..<16))
        XCTAssertGreaterThanOrEqual(firstSixteen.count, 15, "pre-open queue: \(firstSixteen.count)/16 echoed")
    }

    /// feat/nc-sudoku-udp-wire: with `udp: false` the node's UDP must not ride Sudoku at all.
    /// NCDataPlane.openUDP's sudoku case is gated on `proxy.effectiveUDP`, so this flow lands
    /// in the default drop path like any UDP-incapable policy (the data plane itself has no
    /// in-process harness — this pins the gate predicate on an otherwise fully valid node,
    /// against the same server parameters the echo tests above dial).
    func testSudokuUDPDisabledByNodeFlag() throws {
        let off = Self.sudokuProxy("loop-sudoku-udp-off", 18090, ["udp": .bool(false)])
        XCTAssertNil(NCSupport.unsupportedReason(off), "node itself is valid")
        XCTAssertFalse(off.effectiveUDP, "udp: false must close the data plane's Sudoku UDP case")
        let on = Self.sudokuProxy("loop-sudoku-udp-on", 18090, [:])
        XCTAssertTrue(on.effectiveUDP, "no flag: Sudoku UDP defaults on")
    }
}
