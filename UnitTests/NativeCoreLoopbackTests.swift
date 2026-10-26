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
    private static let openConnectPort = 18011
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
    private static let openConnectUser = "nc-loop-oc-user"
    private static let openConnectPassword = "nc-loop-oc-pw"

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
        isPortReachable(Self.ssPort)
    }

    private static func isPortReachable(_ port: Int) -> Bool {
        let conn = NWConnection(host: NWEndpoint.Host(Self.host),
                                port: NWEndpoint.Port(rawValue: UInt16(port))!,
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

    private static var openConnectProxy: NCProxy {
        Self.proxy(name: "loop-openconnect", type: "openconnect", port: Self.openConnectPort, extra: [
            "username": .string(Self.openConnectUser),
            "password": .string(Self.openConnectPassword),
            "sni": .string("localhost"),
            "skip-cert-verify": .bool(true),
            "dtls": .bool(false),
        ])
    }

    private static var openConnectDTLSProxy: NCProxy {
        Self.proxy(name: "loop-openconnect-dtls", type: "openconnect", port: Self.openConnectPort, extra: [
            "username": .string(Self.openConnectUser),
            "password": .string(Self.openConnectPassword),
            "sni": .string("localhost"),
            "skip-cert-verify": .bool(true),
            "dtls": .bool(true),
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
        var ports = [Self.ssPort, Self.ss2022Port, Self.vmessPort, Self.vlessPort,
                     Self.trojanPort, Self.tcpEchoPort, Self.blackholePort]
        if Self.isPortReachable(Self.openConnectPort) {
            ports.append(Self.openConnectPort)
        }
        for port in ports {
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

    func testOpenConnectTCPEcho() throws {
        guard Self.isPortReachable(Self.openConnectPort) else {
            throw XCTSkip("ocserv not running on port \(Self.openConnectPort)")
        }
        let stream = try self.connect(proxy: Self.openConnectProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testOpenConnectDTLSFallback() throws {
        guard Self.isPortReachable(Self.openConnectPort) else {
            throw XCTSkip("ocserv not running on port \(Self.openConnectPort)")
        }
        let stream = try self.connect(proxy: Self.openConnectDTLSProxy, target: Self.echoTarget)
        defer { stream.cancel() }
        try self.assertEcho(stream, payload: Self.payload)
    }

    func testOpenConnectDTLSSkip() throws {
        // DTLS 1.2 PSK requires setting ClientHello.legacy_session_id to X-DTLS-App-ID.
        // Network.framework does not expose custom SessionID setting via public sec_protocol_options API.
        // Per S1/S2 design and dispatcher instructions, skip explicitly rather than faking.
        throw XCTSkip("OpenConnect DTLS 1.2 PSK requires setting ClientHello.legacy_session_id to X-DTLS-App-ID, which Network.framework does not expose via public API; DTLS fast channel skipped per S1/S2 design note")
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
