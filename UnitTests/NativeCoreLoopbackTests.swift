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
                     Self.trojanPort, Self.tcpEchoPort, Self.blackholePort] {
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

        // Size ladder (diagnostics, always printed as one "HY2LADDER" line — proto-loopback.yml greps it):
        //  - "u<N>": one unfragmented datagram of N wire bytes (budget raised to 1197 so it is not split);
        //  - "f<B>": the 3000-byte packet fragmented at a B-byte budget.
        // Each rung records the pieces we sent, the raw datagrams / fragments / packets that came back and
        // the largest raw datagram received, so a lost rung tells the direction: rx=0 ⇒ our datagrams never
        // reached sing-box (or its reply never left); rx>0 with pk=0 ⇒ reply fragments lost / not reassembled.
        let addrHeader = NCHy2UDP.headerSize(address: NCHysteria2Connection.udpAddress(target))
        func roundTrip(_ payload: Data, budget: Int, tries: Int = 2) -> String {
            conn.setUDPDatagramLimitForTesting(budget)
            let pieces = NCHy2UDP.fragment(sessionID: sessionID, packetID: 0, address: NCHysteria2Connection.udpAddress(target),
                                           payload: payload, maxDatagramSize: budget > 0 ? budget : conn.udpDatagramLimit)
            let before = replies.counters()
            var ok = false
            for _ in 0..<tries where !ok {
                conn.sendUDP(sessionID: sessionID, target: target, payload: payload)
                let until = Date().addingTimeInterval(1.5)
                while Date() < until, let got = replies.wait(timeout: until.timeIntervalSinceNow) {
                    if got == payload { ok = true; break }
                }
            }
            let after = replies.counters()
            return "\(ok ? "ok" : "LOST")(tx=\(pieces.count)x\(pieces.map(\.count).max() ?? 0) rx=\(after.raw - before.raw) frag=\(after.frags - before.frags) pk=\(after.packets - before.packets) rxMax=\(after.maxRaw))"
        }
        // Burst of n separate, unfragmented packets (n sendUDP calls in a row, optionally `gapMs` apart):
        // separates "Network.framework drops back-to-back datagrams" from "fragments are not reassembled".
        func burst(_ n: Int, wire: Int, gapMs: Int) -> String {
            conn.setUDPDatagramLimitForTesting(1197)
            let before = replies.counters()
            var want = Set<Data>()
            for i in 0..<n {
                let p = Data((0..<(wire - addrHeader)).map { UInt8(($0 * 7 + i * 31 + wire + gapMs) & 0xff) })
                want.insert(p)
                conn.sendUDP(sessionID: sessionID, target: target, payload: p)
                if gapMs > 0 { Thread.sleep(forTimeInterval: Double(gapMs) / 1000) }
            }
            var got = 0
            let until = Date().addingTimeInterval(1.5)
            while Date() < until, got < n, let r = replies.wait(timeout: until.timeIntervalSinceNow) {
                if want.remove(r) != nil { got += 1 }
            }
            let after = replies.counters()
            return "\(got)/\(n)(rx=\(after.raw - before.raw))"
        }
        var ladder: [String] = []
        for wire in [600, 1197] {
            let n = wire - addrHeader
            let p = Data((0..<n).map { UInt8(($0 * 11 + wire) & 0xff) })
            ladder.append("u\(wire):" + roundTrip(p, budget: 1197))
        }
        ladder.append("b3x1000:" + burst(3, wire: 1000, gapMs: 0))
        ladder.append("b6x600:" + burst(6, wire: 600, gapMs: 0))
        ladder.append("b3x1000gap5:" + burst(3, wire: 1000, gapMs: 5))
        // Distinct bytes per rung, so a late echo of a lost rung can never pass a later one.
        func big(_ seed: Int) -> Data { Data((0..<3000).map { UInt8(($0 * 13 + seed) & 0xff) }) }
        for mode in [0, 1, 2] {
            conn.setUDPFragmentPacingForTesting(mode)
            for budget in [1197, 1100, 600] {
                ladder.append("f\(budget)p\(mode):" + roundTrip(big(budget + mode), budget: budget))
            }
        }
        // The shipped default (budget 0 = no test override: the connection's own limit and pacing).
        conn.setUDPFragmentPacingForTesting(2)
        let r = roundTrip(big(7), budget: 0)
        let defaultOK = r.hasPrefix("ok")
        ladder.append("fDEFAULT(\(conn.udpDatagramLimit)):" + r)
        let line = "HY2LADDER " + ladder.joined(separator: " ") + " | " + conn.udpDiagnostics
        print(line)
        XCTContext.runActivity(named: line) { _ in }
        XCTAssertTrue(defaultOK, "fragmented 3000-byte UDP packet did not round-trip at the default budget [\(line)]")
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

    private var raw = 0, frags = 0, packets = 0, maxRaw = 0

    func feed(_ data: Data) {
        cond.lock(); defer { cond.unlock() }
        raw += 1
        maxRaw = max(maxRaw, data.count)
        guard let frame = NCHy2UDP.decodeFrame(data), frame.sessionID == sessionID else { return }
        if frame.fragCount > 1 { frags += 1 }
        guard let payload = reassembler.feed(frame) else { return }
        packets += 1
        ready.append(payload)
        cond.signal()
    }

    func counters() -> (raw: Int, frags: Int, packets: Int, maxRaw: Int) {
        cond.lock(); defer { cond.unlock() }
        return (raw, frags, packets, maxRaw)
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
