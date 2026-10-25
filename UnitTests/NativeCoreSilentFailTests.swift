import XCTest
@testable import Mihomo

/// fix/nc-silent-fail: nodes that used to look usable but connected wrongly — Trojan ws/grpc/h2, ws early data,
/// v2ray-http-upgrade, http-opts (HTTP/1.1 obfs), Snell obfs-opts, smux/yamux, VMess alterId > 0, ECH, and the
/// Vision / REALITY fingerprint fields. Wire shapes follow mihomo v1.19.33 (transport/vmess/websocket.go, http.go).
final class NativeCoreSilentFailTests: XCTestCase {

    // MARK: - Fake transport (callbacks on the test's serial queue, like a real stream on its connection queue)

    private final class FakeRaw: NCRelayStream {
        let q: DispatchQueue
        private(set) var sent = Data()
        private var inbox: [Data] = []
        private var waiting: ((Data?, Error?) -> Void)?
        private(set) var cancelled = false

        init(queue: DispatchQueue) { q = queue }

        func send(_ data: Data, completion: @escaping () -> Void) {
            sent.append(data)
            q.async(execute: completion)
        }

        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            if !inbox.isEmpty {
                let d = inbox.removeFirst()
                q.async { handler(d, nil) }
                return
            }
            waiting = handler
        }

        /// Call on `q`.
        func inject(_ d: Data) {
            if let h = waiting {
                waiting = nil
                q.async { h(d, nil) }
            } else {
                inbox.append(d)
            }
        }

        func takeSent() -> Data { let s = sent; sent = Data(); return s }

        func cancel() { cancelled = true }
    }

    private let q = DispatchQueue(label: "nc.silentfail.test")

    private func onQ<T>(_ body: () -> T) -> T { q.sync(execute: body) }

    /// Let queued callbacks on `q` run.
    private func settle() {
        let e = expectation(description: "settle")
        q.async { self.q.async { self.q.async { e.fulfill() } } }
        wait(for: [e], timeout: 3)
    }

    private func node(_ type: String, _ fields: [String: NCJSONValue]) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string("srv.example.com"), "port": .number(443)]
        for (k, v) in fields { f[k] = v }
        return NCProxy(name: "n", type: type, fields: f)
    }

    private func text(_ d: Data) -> String { String(decoding: d, as: UTF8.self) }

    private static let upgrade101 = Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".utf8)

    // MARK: - NCSupport gates

    func testECHEnabledIsUnsupported() {
        let p = node("trojan", ["password": .string("x"), "ech-opts": .object(["enable": .bool(true)])])
        XCTAssertNotNil(NCSupport.unsupportedReason(p))
        XCTAssertTrue(NCSupport.unsupportedReason(p)!.contains("ECH"))
        let off = node("trojan", ["password": .string("x"), "ech-opts": .object(["enable": .bool(false)])])
        XCTAssertNil(NCSupport.unsupportedReason(off))
    }

    func testVMessAlterIdGate() {
        let legacy = node("vmess", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "alterId": .number(64)])
        XCTAssertNotNil(NCSupport.unsupportedReason(legacy))
        let legacyStr = node("vmess", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "alterId": .string("2")])
        XCTAssertNotNil(NCSupport.unsupportedReason(legacyStr))
        let aead = node("vmess", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "alterId": .number(0)])
        XCTAssertNil(NCSupport.unsupportedReason(aead))
    }

    func testSnellObfsGate() {
        for mode in ["http", "tls", ""] {
            let p = node("snell", ["psk": .string("k"), "obfs-opts": .object(["mode": .string(mode)])])
            XCTAssertNil(NCSupport.unsupportedReason(p), mode)
        }
        let st = node("snell", ["psk": .string("k"), "obfs-opts": .object(["mode": .string("shadow-tls")])])
        XCTAssertNotNil(NCSupport.unsupportedReason(st))
    }

    func testTransportsStillSupported() {
        for net in ["ws", "grpc", "h2", "http", "tcp"] {
            XCTAssertNil(NCSupport.unsupportedReason(node("vless", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"),
                                                                     "network": .string(net)])), net)
            XCTAssertNil(NCSupport.unsupportedReason(node("trojan", ["password": .string("p"), "network": .string(net)])), net)
        }
    }

    // MARK: - smux

    func testSmuxUsableOnlyForH2Mux() {
        func p(_ proto: String?) -> NCProxy {
            var smux: [String: NCJSONValue] = ["enabled": .bool(true)]
            if let proto { smux["protocol"] = .string(proto) }
            return node("vless", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "smux": .object(smux)])
        }
        XCTAssertTrue(NCConnector.smuxUsable(p(nil)))
        XCTAssertTrue(NCConnector.smuxUsable(p("h2mux")))
        XCTAssertFalse(NCConnector.smuxUsable(p("smux")))
        XCTAssertFalse(NCConnector.smuxUsable(p("yamux")))
        XCTAssertNil(NCSupport.unsupportedReason(p("yamux")))
        XCTAssertFalse(NCConnector.smuxUsable(node("vless", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811")])))
    }

    // MARK: - Trojan transports

    func testTrojanUsesTransport() {
        for (net, want) in [("ws", true), ("grpc", true), ("h2", true), ("tcp", false), ("http", false)] {
            XCTAssertEqual(NCConnector.trojanUsesTransport(node("trojan", ["network": .string(net)])), want, net)
        }
        XCTAssertFalse(NCConnector.trojanUsesTransport(node("trojan", [:])))
    }

    func testTrojanWSUsesSNIAsHostAndCarriesHead() {
        let p = node("trojan", ["password": .string("pw"), "sni": .string("front.example.com"),
                                "network": .string("ws"), "ws-opts": .object(["path": .string("/tj")])])
        let raw = FakeRaw(queue: q)
        let done = expectation(description: "transport")
        var stream: NCRelayStream?
        q.async {
            NCConnector.transportStream(raw: raw, proxy: p, server: "srv.example.com", queue: self.q) { s, err in
                XCTAssertNil(err)
                stream = s
                done.fulfill()
            }
            let req = self.text(raw.takeSent())
            XCTAssertTrue(req.hasPrefix("GET /tj HTTP/1.1\r\n"), req)
            XCTAssertTrue(req.contains("Host: front.example.com\r\n"), req)
            XCTAssertTrue(req.contains("Sec-WebSocket-Key: "), req)
            raw.inject(Self.upgrade101)
        }
        wait(for: [done], timeout: 3)
        let head = NCTrojan.requestHead(password: "pw", target: NCTarget(host: "example.org", port: 80))
        onQ { stream?.send(head) }
        settle()
        let frame = onQ { raw.takeSent() }
        // Masked binary frame carrying the Trojan head (FIN|binary, MASK bit set).
        XCTAssertEqual(frame.first, 0x82)
        XCTAssertEqual(frame.count, head.count + 2 + (head.count >= 126 ? 2 : 0) + 4)
    }

    // MARK: - ws-opts parsing

    func testEDQueryExtraction() {
        XCTAssertNil(NCWSTransportOptions.extractED("/ws"))
        XCTAssertNil(NCWSTransportOptions.extractED("/ws?x=1"))
        XCTAssertNil(NCWSTransportOptions.extractED("/ws?ed=abc"))
        let a = NCWSTransportOptions.extractED("/ws?ed=2048")
        XCTAssertEqual(a?.0, "/ws"); XCTAssertEqual(a?.1, 2048)
        let b = NCWSTransportOptions.extractED("/ws?a=1&ed=1024&b=2")
        XCTAssertEqual(b?.0, "/ws?a=1&b=2"); XCTAssertEqual(b?.1, 1024)
    }

    func testWSOptionsParse() {
        let p = node("vless", ["network": .string("ws"), "ws-opts": .object([
            "path": .string("/v?ed=2560"),
            "headers": .object(["host": .string("cdn.example.com"), "X-A": .string("1")]),
            "max-early-data": .number(100), "early-data-header-name": .string("X-Ignored"),
        ])])
        let o = NCWSTransportOptions.parse(p, defaultHost: "srv.example.com")
        XCTAssertEqual(o.path, "/v")
        XCTAssertEqual(o.maxEarlyData, 2560)                         // ?ed= wins (mihomo)
        XCTAssertEqual(o.earlyDataHeaderName, "Sec-WebSocket-Protocol")
        XCTAssertEqual(o.hostHeader, "cdn.example.com")              // case-insensitive Host
        XCTAssertEqual(o.headers, ["X-A": "1"])                      // Host not duplicated
        XCTAssertFalse(o.httpUpgrade)

        let q2 = node("vmess", ["network": .string("ws"), "ws-opts": .object([
            "max-early-data": .number(2048), "v2ray-http-upgrade": .bool(true),
            "v2ray-http-upgrade-fast-open": .bool(true)])])
        let o2 = NCWSTransportOptions.parse(q2, defaultHost: "srv.example.com")
        XCTAssertEqual(o2.path, "/")
        XCTAssertEqual(o2.hostHeader, "srv.example.com")
        XCTAssertEqual(o2.maxEarlyData, 2048)
        XCTAssertEqual(o2.earlyDataHeaderName, "")
        XCTAssertTrue(o2.httpUpgrade)
        XCTAssertTrue(o2.httpUpgradeFastOpen)
    }

    func testEarlyDataRequestPlacement() {
        var o = NCWSTransportOptions(path: "/p?x=1", hostHeader: "h", headers: [:], maxEarlyData: 10,
                                     earlyDataHeaderName: "", httpUpgrade: false, httpUpgradeFastOpen: false)
        XCTAssertEqual(o.request(earlyData: "QUJD").path, "/pQUJD?x=1")
        o.earlyDataHeaderName = "Sec-WebSocket-Protocol"
        let r = o.request(earlyData: "QUJD")
        XCTAssertEqual(r.path, "/p?x=1")
        XCTAssertEqual(r.headers["Sec-WebSocket-Protocol"], "QUJD")
        XCTAssertEqual(NCWSTransportOptions.base64URLRaw(Data([0xfb, 0xff, 0xfe])), "-__-")
        XCTAssertEqual(NCWSTransportOptions.base64URLRaw(Data("a".utf8)), "YQ")
    }

    // MARK: - ws stream modes

    func testHTTPUpgradeSendsNoWebSocketFraming() {
        let o = NCWSTransportOptions(path: "/up", hostHeader: "h.example", headers: [:], maxEarlyData: 0,
                                     earlyDataHeaderName: "", httpUpgrade: true, httpUpgradeFastOpen: false)
        let raw = FakeRaw(queue: q)
        let s = NCV2RayWSStream(raw: raw, options: o)
        let started = expectation(description: "started")
        q.async {
            s.start { err in XCTAssertNil(err); started.fulfill() }
            let req = self.text(raw.takeSent())
            XCTAssertTrue(req.hasPrefix("GET /up HTTP/1.1\r\n"), req)
            XCTAssertTrue(req.contains("Upgrade: websocket"), req)
            XCTAssertFalse(req.contains("Sec-WebSocket-Key"), req)
            raw.inject(Self.upgrade101 + Data("srv".utf8))
        }
        wait(for: [started], timeout: 3)
        onQ { s.send(Data("hello".utf8)) }
        settle()
        XCTAssertEqual(onQ { raw.takeSent() }, Data("hello".utf8)) // raw bytes, no frame header
        let got = expectation(description: "recv")
        q.async { s.receive { d, _ in XCTAssertEqual(d, Data("srv".utf8)); got.fulfill() } }
        wait(for: [got], timeout: 3)
    }

    func testHTTPUpgradeFastOpenSendsBefore101() {
        let o = NCWSTransportOptions(path: "/", hostHeader: "h", headers: [:], maxEarlyData: 0,
                                     earlyDataHeaderName: "", httpUpgrade: true, httpUpgradeFastOpen: true)
        let raw = FakeRaw(queue: q)
        let s = NCV2RayWSStream(raw: raw, options: o)
        let started = expectation(description: "started")
        q.async { s.start { err in XCTAssertNil(err); started.fulfill() } }
        wait(for: [started], timeout: 3)
        onQ { _ = raw.takeSent(); s.send(Data("x".utf8)) }
        settle()
        XCTAssertEqual(onQ { raw.takeSent() }, Data("x".utf8))
    }

    func testWSEarlyDataInHeaderThenRestAsFrame() {
        let o = NCWSTransportOptions(path: "/ed", hostHeader: "h", headers: [:], maxEarlyData: 16,
                                     earlyDataHeaderName: "Sec-WebSocket-Protocol", httpUpgrade: false,
                                     httpUpgradeFastOpen: false)
        let raw = FakeRaw(queue: q)
        let s = NCV2RayWSStream(raw: raw, options: o)
        let started = expectation(description: "started")
        q.async { s.start { err in XCTAssertNil(err); started.fulfill() } }
        wait(for: [started], timeout: 3)
        XCTAssertEqual(onQ { raw.sent.count }, 0, "upgrade deferred to the first write")

        // A read before the dial waits for it.
        let got = expectation(description: "recv")
        q.async { s.receive { d, e in XCTAssertNil(e); XCTAssertEqual(d, Data("ok".utf8)); got.fulfill() } }

        let payload = Data((0..<40).map { UInt8($0) })
        let sentDone = expectation(description: "send completion")
        q.async { s.send(payload) { sentDone.fulfill() } }
        settle()
        let req = text(onQ { raw.takeSent() })
        let early = NCWSTransportOptions.base64URLRaw(payload.prefix(16))
        XCTAssertTrue(req.hasPrefix("GET /ed HTTP/1.1\r\n"), req)
        XCTAssertTrue(req.contains("Sec-WebSocket-Protocol: \(early)\r\n"), req)
        XCTAssertTrue(req.contains("Sec-WebSocket-Key: "), req)
        // Server 101 + one unmasked binary frame "ok".
        onQ { raw.inject(Self.upgrade101 + Data([0x82, 0x02]) + Data("ok".utf8)) }
        wait(for: [sentDone, got], timeout: 3)
        let frame = onQ { raw.takeSent() }
        XCTAssertEqual(frame.first, 0x82)
        XCTAssertEqual(Int(frame[1] & 0x7f), 24, "the 24 bytes past max-early-data follow as one frame")
        // Unmask and compare.
        let key = Array(frame[2..<6])
        let body = frame[6...].enumerated().map { $0.element ^ key[$0.offset % 4] }
        XCTAssertEqual(Data(body), payload.dropFirst(16))
    }

    func testWSEarlyDataInPathWhenNoHeaderName() {
        let o = NCWSTransportOptions(path: "/p", hostHeader: "h", headers: [:], maxEarlyData: 64,
                                     earlyDataHeaderName: "", httpUpgrade: true, httpUpgradeFastOpen: false)
        let raw = FakeRaw(queue: q)
        let s = NCV2RayWSStream(raw: raw, options: o)
        let started = expectation(description: "started")
        q.async { s.start { _ in started.fulfill() } }
        wait(for: [started], timeout: 3)
        let done = expectation(description: "sent")
        q.async { s.send(Data("abc".utf8)) { done.fulfill() } }
        settle()
        let req = text(onQ { raw.takeSent() })
        XCTAssertTrue(req.hasPrefix("GET /pYWJj HTTP/1.1\r\n"), req)
        onQ { raw.inject(Self.upgrade101) }
        wait(for: [done], timeout: 3)
        XCTAssertEqual(onQ { raw.takeSent() }.count, 0, "everything fit in the early data")
    }

    func testWSEarlyDataRefusedFailsSendsAndReads() {
        let o = NCWSTransportOptions(path: "/", hostHeader: "h", headers: [:], maxEarlyData: 8,
                                     earlyDataHeaderName: "Sec-WebSocket-Protocol", httpUpgrade: false,
                                     httpUpgradeFastOpen: false)
        let raw = FakeRaw(queue: q)
        let s = NCV2RayWSStream(raw: raw, options: o)
        q.async { s.start { _ in } }
        let got = expectation(description: "recv fails")
        q.async { s.receive { d, e in XCTAssertNil(d); XCTAssertNotNil(e); got.fulfill() } }
        let done = expectation(description: "send completes")
        q.async { s.send(Data("abcdefghijk".utf8)) { done.fulfill() } }
        settle()
        onQ { raw.inject(Data("HTTP/1.1 403 Forbidden\r\n\r\n".utf8)) }
        wait(for: [got, done], timeout: 3)
    }

    // MARK: - http-opts

    func testHTTPObfsRequestShape() {
        let p = node("vmess", ["network": .string("http"), "http-opts": .object([
            "method": .string("get"),
            "path": .array([.string("/a"), .string("/b")]),
            "headers": .object(["Host": .array([.string("x.example"), .string("y.example")]),
                                "connection": .array([.string("keep-alive")]),
                                "Accept-Encoding": .string("gzip")]),
        ])])
        let o = NCHTTPObfsOptions.parse(p, server: "srv.example.com")
        XCTAssertEqual(o.method, "GET")
        XCTAssertEqual(o.paths, ["/a", "/b"])
        let head = o.requestHead(payload: Data("BODY".utf8), pick: { $0 - 1 })
        XCTAssertEqual(text(head),
                       "GET /b HTTP/1.1\r\nHost: y.example\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 4\r\n"
                       + "Accept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\nBODY")
        let d = NCHTTPObfsOptions.parse(node("vless", ["network": .string("http")]), server: "srv.example.com")
        XCTAssertEqual(text(d.requestHead(payload: Data("x".utf8))),
                       "GET / HTTP/1.1\r\nHost: srv.example.com\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 1\r\n\r\nx")
    }

    func testHTTPNetworkIsObfsNotH2() {
        let p = node("vless", ["uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "network": .string("http"),
                               "http-opts": .object(["path": .array([.string("/obfs")])])])
        let raw = FakeRaw(queue: q)
        let done = expectation(description: "transport")
        var stream: NCRelayStream?
        q.async {
            NCConnector.transportStream(raw: raw, proxy: p, server: "srv.example.com", queue: self.q) { s, err in
                XCTAssertNil(err); stream = s; done.fulfill()
            }
        }
        wait(for: [done], timeout: 3)
        XCTAssertTrue(stream is NCHTTPObfsStream)
        XCTAssertEqual(onQ { raw.sent.count }, 0, "no h2 preface")
        onQ { stream?.send(Data("first".utf8)); stream?.send(Data("second".utf8)) }
        settle()
        let wire = text(onQ { raw.takeSent() })
        XCTAssertTrue(wire.hasPrefix("GET /obfs HTTP/1.1\r\n"), wire)
        XCTAssertTrue(wire.hasSuffix("\r\n\r\nfirstsecond"), wire)

        let got = expectation(description: "recv")
        q.async {
            stream?.receive { d, e in XCTAssertNil(e); XCTAssertEqual(d, Data("data".utf8)); got.fulfill() }
            raw.inject(Data("HTTP/1.1 200 OK\r\nContent-Type: text/html\r".utf8))
            raw.inject(Data("\n\r\ndata".utf8))
        }
        wait(for: [got], timeout: 3)
    }

    func testHTTPObfsHeadStripAcrossChunks() {
        var head = Data()
        let r1 = NCHTTPObfsStream.stripResponseHead(&head, appending: Data("HTTP/1.1 200 OK\r\n".utf8))
        XCTAssertEqual(r1, .needMore)
        let r2 = NCHTTPObfsStream.stripResponseHead(&head, appending: Data("\r\nrest".utf8))
        XCTAssertEqual(r2, .done(Data("rest".utf8)))
        XCTAssertTrue(head.isEmpty)
    }

    // MARK: - Snell obfs

    func testSnellObfsOptionsAndWire() throws {
        XCTAssertNil(NCConnector.snellObfsOptions(node("snell", [:])))
        let http = try XCTUnwrap(NCConnector.snellObfsOptions(node("snell", ["obfs-opts": .object(["mode": .string("http")])])))
        XCTAssertEqual(http.mode, "http")
        XCTAssertEqual(http.host, "bing.com") // mihomo default
        let tls = try XCTUnwrap(NCConnector.snellObfsOptions(node("snell", ["obfs-opts": .object([
            "mode": .string("tls"), "host": .string("cdn.example")])])))
        XCTAssertEqual(tls.mode, "tls")
        XCTAssertEqual(tls.host, "cdn.example")

        let raw = FakeRaw(queue: q)
        let s = NCSSPluginStream(raw: raw, options: http, serverPort: "443")
        onQ { s.send(Data("snell".utf8)) }
        settle()
        let wire = text(onQ { raw.takeSent() })
        XCTAssertTrue(wire.hasPrefix("GET / HTTP/1.1\r\n"), wire)
        XCTAssertTrue(wire.contains("Host: bing.com"), wire)
        XCTAssertTrue(wire.hasSuffix("snell"), wire)
    }

    // MARK: - fingerprint vs client-fingerprint

    private func sameProfile(_ a: NCClientHelloProfile, _ b: NCClientHelloProfile) -> Bool {
        a.cipherSuites == b.cipherSuites && a.groups == b.groups && a.sigAlgs == b.sigAlgs
            && a.sct == b.sct && a.sessionTicket == b.sessionTicket && a.paddingTo512 == b.paddingTo512
    }

    func testClientFingerprintDrivesUTLSAndFingerprintPins() {
        let hex = String(repeating: "ab", count: 32)
        let p = node("vless", ["client-fingerprint": .string("firefox"), "fingerprint": .string(hex)])
        XCTAssertTrue(sameProfile(NCConnector.utlsProfile(p), .firefox))
        XCTAssertEqual(NCConnector.certPin(p), .pin(Data(repeating: 0xab, count: 32)))

        let colons = node("vless", ["fingerprint": .string(Array(repeating: "AB", count: 32).joined(separator: ":"))])
        XCTAssertEqual(NCConnector.certPin(colons), .pin(Data(repeating: 0xab, count: 32)))
        XCTAssertTrue(sameProfile(NCConnector.utlsProfile(colons), .chrome), "a pin is never a ClientHello name")

        // Legacy: a browser name in `fingerprint` still picks the hello when client-fingerprint is absent; no pin.
        let legacy = node("vless", ["fingerprint": .string("safari")])
        XCTAssertTrue(sameProfile(NCConnector.utlsProfile(legacy), .safari))
        XCTAssertEqual(NCConnector.certPin(legacy), .absent)
        // client-fingerprint wins over a legacy name.
        let both = node("vless", ["fingerprint": .string("safari"), "client-fingerprint": .string("ios")])
        XCTAssertTrue(sameProfile(NCConnector.utlsProfile(both), .ios))

        XCTAssertEqual(NCConnector.certPin(node("vless", ["fingerprint": .string("abcd")])), .invalid)
        XCTAssertEqual(NCConnector.certPin(node("vless", ["fingerprint": .string(String(repeating: "zz", count: 32))])), .invalid)
        XCTAssertEqual(NCConnector.certPin(node("vless", [:])), .absent)
    }
}
