import XCTest
import Network
@testable import Tern

/// feat/nc-gost-relay: GOST v3 relay outbound (Clash.Meta `gost-relay`, NCGostRelay.swift).
/// Request vectors were produced by running Clash.Meta v1.19.33's own transport/gost writeRelayRequest
/// (copied verbatim into an old-core harness) — byte-for-byte parity, not a re-derivation.
/// No public gost server / sing-box support exists for loopback CI, so the socket tests below use an
/// in-process fake relay server (NWListener on loopback) that speaks the server side of the protocol.
final class NativeCoreGostRelayTests: XCTestCase {

    private static func hex(_ s: String) -> Data {
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    private static func node(_ extra: [String: NCJSONValue] = [:], server: String = "relay.example.com",
                             port: Int = 8443) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string(server), "port": .number(Double(port))]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "G", type: "gost-relay", fields: f)
    }

    // MARK: Request encoding (Clash.Meta vectors)

    func testRequestDomainTCPNoAuth() {
        XCTAssertEqual(NCGostRelay.request(target: NCTarget(host: "example.com", port: 443), udp: false,
                                           username: nil, password: nil),
                       Self.hex("0101001702000f030b6578616d706c652e636f6d01bb0400020000"))
    }

    func testRequestIPv4WithAuth() {
        XCTAssertEqual(NCGostRelay.request(target: NCTarget(host: "1.2.3.4", port: 80), udp: false,
                                           username: "user", password: "pass"),
                       Self.hex("0101001c01000a04757365720470617373020007010102030400500400020000"))
    }

    func testRequestIPv6UDP() {
        XCTAssertEqual(NCGostRelay.request(target: NCTarget(host: "2001:db8::1", port: 53), udp: true,
                                           username: "", password: ""),
                       Self.hex("0181001b0200130420010db800000000000000000000000100350400020001"))
    }

    func testRequestForwardModeUserOnly() {
        // forward: true → no addr feature; user without password still sends the auth feature.
        XCTAssertEqual(NCGostRelay.request(target: nil, udp: false, username: "u", password: nil),
                       Self.hex("0101000b0100030175000400020000"))
    }

    func testRequestPasswordOnlyUDP() {
        XCTAssertEqual(NCGostRelay.request(target: NCTarget(host: "8.8.8.8", port: 53), udp: true,
                                           username: nil, password: "pw"),
                       Self.hex("0181001601000400027077020007010808080800350400020001"))
    }

    func testRequestRejectsOversizedCredentials() {
        let long = String(repeating: "x", count: 256)
        XCTAssertNil(NCGostRelay.request(target: NCTarget(host: "a.b", port: 1), udp: false, username: long, password: nil))
        XCTAssertNil(NCGostRelay.request(target: NCTarget(host: String(repeating: "d", count: 300), port: 1),
                                         udp: false, username: nil, password: nil))
    }

    // MARK: Response

    func testParseResponse() {
        XCTAssertEqual(NCGostRelay.parseResponse(Data([1, 0, 0])), .needMore)
        XCTAssertEqual(NCGostRelay.parseResponse(Data([1, 0, 0, 0])), .ok(consumed: 4))
        XCTAssertEqual(NCGostRelay.parseResponse(Data([1, 0, 0, 3, 9, 9])), .needMore)
        XCTAssertEqual(NCGostRelay.parseResponse(Data([1, 0, 0, 3, 9, 9, 9, 0x41])), .ok(consumed: 7))
        XCTAssertEqual(NCGostRelay.parseResponse(Data([1, 2, 0, 0])), .failed(status: 2))
        XCTAssertEqual(NCGostRelay.parseResponse(Data([5, 0, 0, 0])), .badVersion(5))
        // slice-safe
        let d = Data([0xff, 1, 0, 0, 0, 0x42])
        XCTAssertEqual(NCGostRelay.parseResponse(d.dropFirst()), .ok(consumed: 4))
        XCTAssertEqual(NCGostRelay.statusText(2), "unauthorized")
        XCTAssertEqual(NCGostRelay.statusText(0x08), "internal server error")
    }

    private final class NullRaw: NCRelayStream {
        var sent: [Data] = []
        var cancelled = false
        func send(_ data: Data) { sent.append(data) }
        func send(_ data: Data, completion: @escaping () -> Void) { sent.append(data); completion() }
        func receive(_ handler: @escaping (Data?, Error?) -> Void) {}
        func cancel() { cancelled = true }
    }

    func testRelayStreamStripsFragmentedResponse() throws {
        let s = NCGostRelayStream(raw: NullRaw())
        try s.feedExternal(Data([1, 0]))
        try s.feedExternal(Data([0, 2, 0xAA]))
        try s.feedExternal(Data([0xBB]) + Data("hel".utf8))
        try s.feedExternal(Data("lo".utf8))
        var got = Data()
        for _ in 0..<2 { s.receive { d, _ in if let d { got.append(d) } } }
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "hello")
    }

    func testRelayStreamFailsOnStatus() {
        let s = NCGostRelayStream(raw: NullRaw())
        XCTAssertThrowsError(try s.feedExternal(Data([1, 3, 0, 0]))) { err in
            XCTAssertTrue("\(err.localizedDescription)".contains("0x03"))
        }
        let v = NCGostRelayStream(raw: NullRaw())
        XCTAssertThrowsError(try v.feedExternal(Data([2, 0, 0, 0])))
    }

    // MARK: UDP framing

    func testUDPFrames() {
        XCTAssertEqual(NCGostRelay.udpFrame(Data([1, 2, 3])), Data([0, 3, 1, 2, 3]))
        XCTAssertNil(NCGostRelay.udpFrame(Data(count: 65536)))
        let buf = Data([0, 2, 0xA, 0xB, 0, 1, 0xC, 0, 5, 1])
        let first = NCGostRelay.nextUDPFrame(buf, at: 0)
        XCTAssertEqual(first?.0, Data([0xA, 0xB]))
        XCTAssertEqual(first?.1, 4)
        let second = NCGostRelay.nextUDPFrame(buf, at: 4)
        XCTAssertEqual(second?.0, Data([0xC]))
        XCTAssertNil(NCGostRelay.nextUDPFrame(buf, at: 7)) // incomplete
        XCTAssertNil(NCGostRelay.nextUDPFrame(buf.dropFirst(3), at: 4)) // slice-relative offset, incomplete
    }

    // MARK: Support gate / type naming

    func testTypeDoesNotCollideWithRelayGroup() {
        XCTAssertTrue(NCSupport.types.contains("gost-relay"))
        XCTAssertFalse(NCSupport.types.contains("relay"))
        XCTAssertTrue(NCSupport.groupTypes.contains("relay"))
        XCTAssertFalse(NCSupport.groupTypes.contains("gost-relay"))
    }

    func testSupportGate() {
        XCTAssertNil(NCSupport.unsupportedReason(Self.node()))
        XCTAssertNil(NCSupport.unsupportedReason(Self.node(["tls": .bool(true), "mux": .bool(true),
                                                            "network": .string("ws"), "udp": .bool(true)])))
        XCTAssertNotNil(NCSupport.unsupportedReason(Self.node(["network": .string("grpc")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(Self.node(["certificate": .string("-----BEGIN")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(Self.node(["fingerprint": .string("chrome")])))
        XCTAssertNil(NCSupport.unsupportedReason(Self.node(["fingerprint": .string(String(repeating: "ab", count: 32))])))
        XCTAssertNotNil(NCSupport.unsupportedReason(NCProxy(name: "x", type: "gost-relay", fields: [:])))
    }

    func testOptionsServerName() {
        let (o1, _) = NCGostRelay.options(Self.node(["tls": .bool(true)]))
        XCTAssertEqual(o1?.serverName, "relay.example.com")
        let (o2, _) = NCGostRelay.options(Self.node(["sni": .string("sni.example")]))
        XCTAssertEqual(o2?.serverName, "sni.example")
        let (o3, _) = NCGostRelay.options(Self.node(["network": .string("ws"),
                                                     "ws-opts": .object(["path": .string("/r"),
                                                                         "headers": .object(["Host": .string("cdn.example")])])]))
        XCTAssertEqual(o3?.serverName, "cdn.example")
        XCTAssertEqual(o3?.ws?.path, "/r")
        XCTAssertEqual(o3?.needsCustomTLS, false)
        let (o4, _) = NCGostRelay.options(Self.node(["client-fingerprint": .string("safari")]))
        XCTAssertEqual(o4?.needsCustomTLS, true)
    }

    // MARK: Import / export

    func testShareLinkPlainGostStyle() throws {
        let p = try XCTUnwrap(NCSubscriptionParser.parseURI("relay+mwss://alice:s%40cret@1.2.3.4:443?path=/ws&host=cdn.example#R1"))
        XCTAssertEqual(p.type, "gost-relay")
        XCTAssertEqual(p.name, "R1")
        XCTAssertEqual(p.server, "1.2.3.4")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.fields["username"]?.string, "alice")
        XCTAssertEqual(p.password, "s@cret")
        XCTAssertEqual(p.fields["tls"]?.bool, true)
        XCTAssertEqual(p.fields["mux"]?.bool, true)
        XCTAssertEqual(p.fields["network"]?.string, "ws")
        XCTAssertEqual(p.fields["ws-opts"]?.object?["path"]?.string, "/ws")
        XCTAssertEqual(p.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string, "cdn.example")
        XCTAssertNil(NCSupport.unsupportedReason(p))
    }

    func testShareLinkShadowrocketBase64() throws {
        let blob = Data("bob:pw@relay.example.com:8443".utf8).base64EncodedString()
        let uri = "relay://\(blob)?remarks=SR%20Relay&tls=1&peer=sni.example&allowInsecure=1&obfs=websocket&obfsParam=h.example&path=%2Fp&udp=1"
        let p = try XCTUnwrap(NCSubscriptionParser.parseURI(uri))
        XCTAssertEqual(p.name, "SR Relay")
        XCTAssertEqual(p.server, "relay.example.com")
        XCTAssertEqual(p.port, 8443)
        XCTAssertEqual(p.fields["username"]?.string, "bob")
        XCTAssertEqual(p.password, "pw")
        XCTAssertEqual(p.fields["tls"]?.bool, true)
        XCTAssertEqual(p.fields["sni"]?.string, "sni.example")
        XCTAssertEqual(p.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(p.fields["network"]?.string, "ws")
        XCTAssertEqual(p.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string, "h.example")
        XCTAssertEqual(p.fields["ws-opts"]?.object?["path"]?.string, "/p")
        XCTAssertEqual(p.fields["udp"]?.bool, true)
    }

    func testShareLinkUnknownTransportRejected() {
        XCTAssertNil(NCSubscriptionParser.parseURI("relay+kcp://1.2.3.4:443"))
        XCTAssertNotNil(NCSubscriptionParser.parseURI("gost-relay://1.2.3.4:443"))
    }

    func testShareLinkExportRoundTrip() throws {
        let n = NCProxy(name: "Exp", type: "gost-relay", fields: [
            "server": .string("r.example"), "port": .number(443), "username": .string("u"), "password": .string("p"),
            "tls": .bool(true), "sni": .string("s.example"), "mux": .bool(true), "udp": .bool(true),
            "network": .string("ws"),
            "ws-opts": .object(["path": .string("/x"), "headers": .object(["Host": .string("c.example")])]),
        ])
        let link = try NCShareLink.encode(n)
        XCTAssertTrue(link.hasPrefix("relay://u:p@r.example:443?"), link)
        let back = try XCTUnwrap(NCSubscriptionParser.parseURI(link))
        XCTAssertEqual(back.type, "gost-relay")
        XCTAssertEqual(back.name, "Exp")
        for k in ["server", "username", "password", "sni"] { XCTAssertEqual(back.fields[k]?.string, n.fields[k]?.string, k) }
        XCTAssertEqual(back.port, 443)
        for k in ["tls", "mux", "udp"] { XCTAssertEqual(back.fields[k]?.bool, true, k) }
        XCTAssertEqual(back.fields["network"]?.string, "ws")
        XCTAssertEqual(back.fields["ws-opts"]?.object?["path"]?.string, "/x")
        XCTAssertEqual(back.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string, "c.example")
    }

    func testConfLineShadowrocketRelay() throws {
        let line = "SR = relay, 1.2.3.4, 8080, user, pass, tls=true, peer=s.example, obfs=websocket, obfsParam=c.example, path=/ws, mux=1"
        let parsed = try XCTUnwrap(NCConfImport.parseNamedNodeLine(line))
        var report = NCImportReport()
        let p = try XCTUnwrap(NCConfImport.buildSurgeLikeNode(name: parsed.name, positional: parsed.positional,
                                                              kv: parsed.kv, order: parsed.order, report: &report))
        XCTAssertEqual(p.type, "gost-relay")
        XCTAssertEqual(p.server, "1.2.3.4")
        XCTAssertEqual(p.port, 8080)
        XCTAssertEqual(p.fields["username"]?.string, "user")
        XCTAssertEqual(p.password, "pass")
        XCTAssertEqual(p.fields["tls"]?.bool, true)
        XCTAssertEqual(p.fields["sni"]?.string, "s.example")
        XCTAssertEqual(p.fields["mux"]?.bool, true)
        XCTAssertEqual(p.fields["network"]?.string, "ws")
        XCTAssertEqual(p.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string, "c.example")
        XCTAssertNil(p.fields["obfs"])
        XCTAssertNil(p.fields["obfsparam"])
        XCTAssertNil(NCSupport.unsupportedReason(p))
    }

    // MARK: In-process fake relay server (loopback sockets)

    /// Server side of the relay protocol: reads one request (header + features), records it, answers with
    /// `status`, then echoes the rest of the stream byte for byte (UDP frames are echoed as-is too).
    private final class FakeGostServer {
        let status: UInt8
        let queue = DispatchQueue(label: "test.fake-gost")
        private let listener: NWListener
        private var conns: [NWConnection] = []
        private var heads: [Data] = []

        init(status: UInt8 = 0) throws {
            self.status = status
            let params = NWParameters.tcp
            params.requiredInterfaceType = .loopback
            params.allowLocalEndpointReuse = true
            listener = try NWListener(using: params, on: .any)
        }

        func start() throws -> Int {
            let ready = DispatchSemaphore(value: 0)
            var failure: Error?
            listener.stateUpdateHandler = { st in
                switch st {
                case .ready: ready.signal()
                case .failed(let e): failure = e; ready.signal()
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] c in self?.handle(c) }
            listener.start(queue: queue)
            if ready.wait(timeout: .now() + 5) == .timedOut { throw NSError(domain: "fake-gost", code: 1) }
            if let failure { throw failure }
            return Int(listener.port?.rawValue ?? 0)
        }

        func stop() {
            queue.sync {
                listener.cancel()
                conns.forEach { $0.cancel() }
                conns.removeAll()
            }
        }

        var recordedHeads: [Data] { queue.sync { heads } }

        private func handle(_ c: NWConnection) {
            conns.append(c)
            c.start(queue: queue)
            readHead(c, Data())
        }

        private func readHead(_ c: NWConnection, _ acc: Data) {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
                guard let self else { return }
                var acc = acc
                if let data { acc.append(data) }
                if acc.count >= 4 {
                    let need = 4 + (Int(acc[acc.startIndex + 2]) << 8 | Int(acc[acc.startIndex + 3]))
                    if acc.count >= need {
                        self.heads.append(Data(acc.prefix(need)))
                        let rest = Data(acc.dropFirst(need))
                        if self.status != 0 {
                            c.send(content: Data([1, self.status, 0, 0]), contentContext: .finalMessage,
                                   isComplete: true, completion: .idempotent)
                            return
                        }
                        // OK with a 3-byte feature block the client must skip.
                        c.send(content: Data([1, 0, 0, 3, 0x7f, 0, 0]) + rest, completion: .idempotent)
                        self.echo(c)
                        return
                    }
                }
                if done || err != nil { c.cancel(); return }
                self.readHead(c, acc)
            }
        }

        private func echo(_ c: NWConnection) {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
                if let data, !data.isEmpty { c.send(content: data, completion: .idempotent) }
                if done || err != nil { return }
                self?.echo(c)
            }
        }
    }

    private var servers: [FakeGostServer] = []

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers.removeAll()
        super.tearDown()
    }

    private func server(status: UInt8 = 0) throws -> (FakeGostServer, Int) {
        let s = try FakeGostServer(status: status)
        servers.append(s)
        return (s, try s.start())
    }

    /// Read until `count` bytes arrived (or an error / EOF).
    private func read(_ s: NCRelayStream, count: Int, timeout: TimeInterval = 5) -> (Data, Error?) {
        let done = expectation(description: "read")
        var got = Data()
        var failure: Error?
        func pump() {
            s.receive { d, e in
                if let d { got.append(d) }
                if d == nil || e != nil { failure = e ?? NSError(domain: "eof", code: 0); done.fulfill(); return }
                if got.count >= count { done.fulfill(); return }
                pump()
            }
        }
        pump()
        wait(for: [done], timeout: timeout)
        return (got, failure)
    }

    private func dial(_ proxy: NCProxy, target: NCTarget, udp: Bool = false) throws -> NCRelayStream {
        let q = DispatchQueue(label: "test.gost.client")
        let opened = expectation(description: "open")
        var stream: NCRelayStream?
        var failure: Error?
        if udp {
            NCConnector.gostRelayStream(proxy: proxy, target: target, udp: true, queue: q, transport: nil) { s, e in
                stream = s; failure = e; opened.fulfill()
            }
        } else {
            NCConnector.connect(target: target, proxy: proxy, queue: q) { s, e in
                stream = s; failure = e; opened.fulfill()
            }
        }
        wait(for: [opened], timeout: 5)
        if let failure { throw failure }
        return try XCTUnwrap(stream)
    }

    func testLoopbackTCPConnectEcho() throws {
        let (srv, port) = try server()
        let proxy = Self.node(["username": .string("user"), "password": .string("pass")], server: "127.0.0.1", port: port)
        let s = try dial(proxy, target: NCTarget(host: "example.com", port: 443))
        s.send(Data("ping-gost".utf8))
        let (got, err) = read(s, count: 9)
        XCTAssertNil(err)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "ping-gost")
        XCTAssertEqual(srv.recordedHeads.first,
                       NCGostRelay.request(target: NCTarget(host: "example.com", port: 443), udp: false,
                                           username: "user", password: "pass"))
        s.cancel()
    }

    func testLoopbackForwardModeOmitsAddress() throws {
        let (srv, port) = try server()
        let proxy = Self.node(["forward": .bool(true)], server: "127.0.0.1", port: port)
        let s = try dial(proxy, target: NCTarget(host: "ignored.example", port: 80))
        s.send(Data("x".utf8))
        _ = read(s, count: 1)
        XCTAssertEqual(srv.recordedHeads.first, Self.hex("010100050400020000"))
        s.cancel()
    }

    func testLoopbackUnauthorizedSurfacesStatus() throws {
        let (_, port) = try server(status: 0x02)
        let proxy = Self.node(["password": .string("bad")], server: "127.0.0.1", port: port)
        let s = try dial(proxy, target: NCTarget(host: "example.com", port: 443))
        s.send(Data("hi".utf8))
        let (got, err) = read(s, count: 1)
        XCTAssertTrue(got.isEmpty)
        let msg = err.map { "\($0.localizedDescription)" } ?? ""
        XCTAssertTrue(msg.contains("unauthorized"), msg)
        s.cancel()
    }

    func testLoopbackUDPAssociationFrames() throws {
        let (srv, port) = try server()
        let proxy = Self.node(["udp": .bool(true)], server: "127.0.0.1", port: port)
        let target = NCTarget(host: "8.8.8.8", port: 53)
        let s = try dial(proxy, target: target, udp: true)
        let f1 = try XCTUnwrap(NCGostRelay.udpFrame(Data([0xde, 0xad])))
        let f2 = try XCTUnwrap(NCGostRelay.udpFrame(Data("dns?".utf8)))
        s.send(f1 + f2)
        let (got, err) = read(s, count: f1.count + f2.count)
        XCTAssertNil(err)
        let a = try XCTUnwrap(NCGostRelay.nextUDPFrame(got, at: 0))
        XCTAssertEqual(a.0, Data([0xde, 0xad]))
        let b = try XCTUnwrap(NCGostRelay.nextUDPFrame(got, at: a.1))
        XCTAssertEqual(String(decoding: b.0, as: UTF8.self), "dns?")
        XCTAssertEqual(srv.recordedHeads.first, NCGostRelay.request(target: target, udp: true, username: nil, password: nil))
        s.cancel()
    }
}
