import XCTest
@testable import Tern

/// feat/nc-naive-h2h3: NaïveProxy padding codec, CONNECT request building (HPACK / QPACK), the HTTP/3 frame
/// reader, option parsing / support gating, share-link import / export, and the multiplexed HTTP/2 CONNECT
/// session driven against a scripted server over a fake base stream. The wire interop with a real server
/// is NativeCoreLoopbackTests (sing-box naive inbound).
final class NativeCoreNaiveH2H3Tests: XCTestCase {

    // MARK: - Padding codec

    func testPaddingEncodeFramesFirstEightWritesOnly() {
        var p = NCNaivePadding()
        var wire: [Data] = []
        for i in 0..<10 {
            wire.append(p.encode(Data([UInt8(i), UInt8(i)]), paddingLength: { 3 }))
        }
        for i in 0..<8 {
            XCTAssertEqual(wire[i], Data([0x00, 0x02, 0x03, UInt8(i), UInt8(i), 0, 0, 0]), "frame \(i)")
        }
        XCTAssertEqual(wire[8], Data([8, 8]))
        XCTAssertEqual(wire[9], Data([9, 9]))
        XCTAssertEqual(p.writesPadded, 8)
    }

    func testPaddingEncodeSplitsLargeWritesIntoSeveralFrames() {
        var p = NCNaivePadding()
        let big = Data((0..<(65535 + 10)).map { UInt8($0 & 0xff) })
        let wire = p.encode(big, paddingLength: { 0 })
        XCTAssertEqual(p.writesPadded, 2)
        XCTAssertEqual(wire.count, big.count + 6)
        XCTAssertEqual(Array(wire.prefix(3)), [0xff, 0xff, 0x00])
        XCTAssertEqual(Array(wire[(3 + 65535)..<(6 + 65535)]), [0x00, 0x0a, 0x00])
        var d = NCNaivePadding()
        XCTAssertEqual(d.decode(wire), big)
    }

    func testPaddingRoundTripAtEveryByteSplit() {
        var enc = NCNaivePadding()
        var wire = Data()
        var plain = Data()
        var seed: UInt8 = 7
        for i in 0..<12 {
            let chunk = Data((0..<(i * 13 + 1)).map { UInt8(($0 + i) & 0xff) })
            plain.append(chunk)
            wire.append(enc.encode(chunk, paddingLength: { seed &+= 37; return Int(seed) }))
        }
        for split in [1, 2, 3, 5, 7, 64, 1000] {
            var dec = NCNaivePadding()
            var out = Data()
            var i = 0
            while i < wire.count {
                let end = min(wire.count, i + split)
                out.append(dec.decode(wire.subdata(in: i..<end)))
                i = end
            }
            XCTAssertEqual(out, plain, "split \(split)")
            XCTAssertEqual(dec.readsPadded, 8)
        }
    }

    func testPaddingDecodeSingBoxServerFrames() {
        // sing-box paddingConn.writeWithPadding: [len u16][pad u8][payload][pad bytes].
        var wire = Data([0x00, 0x05, 0x02]) + Data("hello".utf8) + Data([0xaa, 0xbb])
        wire += Data([0x00, 0x00, 0x04, 1, 2, 3, 4]) // empty payload frame, 4 padding bytes
        var p = NCNaivePadding()
        XCTAssertEqual(p.decode(wire), Data("hello".utf8))
        XCTAssertEqual(p.readsPadded, 2)
    }

    func testPaddingHeaderValueShape() {
        for _ in 0..<50 {
            let v = NCNaivePadding.headerValue()
            XCTAssertTrue((16...32).contains(v.count))
            let head = v.prefix(16)
            XCTAssertTrue(head.allSatisfy { "!#$()+<>?@[]^`{}".contains($0) })
            XCTAssertTrue(v.dropFirst(16).allSatisfy { $0 == "~" })
        }
    }

    func testPaddingNegotiation() {
        XCTAssertTrue(NCNaivePadding.negotiated(responseHeaders: [(":status", "200"), ("padding", "~~~~")]))
        XCTAssertTrue(NCNaivePadding.negotiated(responseHeaders: [(":status", "200"), ("padding-type-reply", "1")]))
        XCTAssertFalse(NCNaivePadding.negotiated(responseHeaders: [(":status", "200"), ("padding-type-reply", "0"),
                                                                   ("padding", "x")]))
        XCTAssertFalse(NCNaivePadding.negotiated(responseHeaders: [(":status", "200")]))
    }

    // MARK: - Options / request headers

    private func proxy(_ type: String, _ extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string("proxy.example.com"), "port": .number(443)]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "n", type: type, fields: f)
    }

    func testOptionsCarrierMapping() throws {
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive"))).carrier, .h2)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive", ["quic": .bool(true)]))).carrier, .h3)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("http2"))).carrier, .h2)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("H2"))).carrier, .h2)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("http3"))).carrier, .h3)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("h3"))).carrier, .h3)
        XCTAssertTrue(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive"))).naive)
        XCTAssertFalse(try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("http2"))).naive)
        XCTAssertNil(NCH2H3ProxyOptions(proxy: proxy("http")))
        XCTAssertNil(NCH2H3ProxyOptions(proxy: NCProxy(name: "x", type: "naive", fields: ["port": .number(443)])))
    }

    func testOptionsFields() throws {
        let o = try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive", [
            "username": .string("u"), "password": .string("p"), "sni": .string("front.example"),
            "skip-cert-verify": .bool(true), "insecure-concurrency": .number(50),
            "extra-headers": .object(["X-Real": .string("1"), "Host": .string("evil")]),
            "udp-over-tcp": .bool(true),
        ])))
        XCTAssertEqual(o.username, "u")
        XCTAssertEqual(o.password, "p")
        XCTAssertEqual(o.serverName, "front.example")
        XCTAssertTrue(o.allowInsecure)
        XCTAssertEqual(o.concurrency, 8) // clamped
        XCTAssertTrue(o.udpOverTCP)
        XCTAssertEqual(o.extraHeaders.map { $0.0 }, ["X-Real"]) // Host is reserved
        let d = try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("http2")))
        XCTAssertEqual(d.serverName, "proxy.example.com")
        XCTAssertNil(d.username)
        XCTAssertEqual(d.concurrency, 1)
    }

    func testHeaderParsingForms() {
        XCTAssertEqual(NCH2H3ProxyOptions.parseHeaders(.string("A: 1\r\nB:2")).map { "\($0.0)=\($0.1)" }, ["A=1", "B=2"])
        XCTAssertEqual(NCH2H3ProxyOptions.parseHeaders(.array([.string("C: 3")])).map { "\($0.0)=\($0.1)" }, ["C=3"])
        XCTAssertEqual(NCH2H3ProxyOptions.parseHeaders(.object([":path": .string("/"), "padding": .string("x")])).count, 0)
    }

    func testConnectRequestHeaders() throws {
        let o = try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive", ["username": .string("user"),
                                                                        "password": .string("pass")])))
        let h = NCHTTPConnect.requestHeaders(target: NCTarget(host: "example.com", port: 443), options: o,
                                             paddingHeader: "!!!!!!!!!!!!!!!!~~")
        XCTAssertEqual(h[0].0, ":method"); XCTAssertEqual(h[0].1, "CONNECT")
        XCTAssertEqual(h[1].0, ":authority"); XCTAssertEqual(h[1].1, "example.com:443")
        XCTAssertTrue(h.contains { $0.0 == "proxy-authorization" && $0.1 == "Basic dXNlcjpwYXNz" })
        XCTAssertTrue(h.contains { $0.0 == "padding" && $0.1 == "!!!!!!!!!!!!!!!!~~" })
        XCTAssertTrue(h.contains { $0.0 == "padding-type-request" && $0.1 == "1, 0" })
        XCTAssertFalse(h.contains { $0.0 == ":path" || $0.0 == ":scheme" })

        let plain = try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("http2")))
        let h2 = NCHTTPConnect.requestHeaders(target: NCTarget(host: "::1", port: 8080), options: plain, paddingHeader: nil)
        XCTAssertEqual(h2.map { $0.0 }, [":method", ":authority"])
        XCTAssertEqual(h2[1].1, "[::1]:8080")
    }

    func testHPACKRequestDecodes() throws {
        let o = try XCTUnwrap(NCH2H3ProxyOptions(proxy: proxy("naive", ["password": .string("pw")])))
        let h = NCHTTPConnect.requestHeaders(target: NCTarget(host: "a.b", port: 80), options: o, paddingHeader: "{{{{{{{{{{{{{{{{")
        let decoded = try XCTUnwrap(NCHPACKDecoder().decode(NCHPACK.encodeHeaders(h)))
        XCTAssertEqual(decoded.map { "\($0.0)=\($0.1)" }, h.map { "\($0.0)=\($0.1)" })
    }

    func testQPACKRequestRoundTrip() throws {
        let headers: [(String, String)] = [(":method", "CONNECT"), (":authority", "example.com:443"),
                                           ("proxy-authorization", "Basic eDp5"), ("padding", "~~~~"),
                                           ("user-agent", "x")]
        let block = NCHTTPConnect.qpackEncode(headers)
        // :method CONNECT is static index 15: indexed field line 0xC0 | 15.
        XCTAssertEqual(Array(block.prefix(3)), [0x00, 0x00, 0xCF])
        let fields = try XCTUnwrap(NCHy2.qpackDecodeFieldSection(block))
        XCTAssertEqual(fields.map { "\($0.name)=\($0.value)" }, headers.map { "\($0.0)=\($0.1)" })
    }

    // MARK: - HTTP/3 frame reader

    func testH3FrameReaderAtEveryByteSplit() {
        let headersBlock = NCHTTPConnect.qpackEncode([(":status", "200")])
        var wire = NCHy2.http3HeadersFrame(fieldSection: headersBlock)
        wire.append(NCHy2.http3Frame(type: 0x21, payload: Data([1, 2, 3])))  // reserved type: skipped
        wire.append(NCH3FrameReader.dataFrame(Data("hello".utf8)))
        wire.append(NCH3FrameReader.dataFrame(Data()))
        wire.append(NCH3FrameReader.dataFrame(Data(repeating: 0x5a, count: 300)))
        let expected = Data("hello".utf8) + Data(repeating: 0x5a, count: 300)
        for split in [1, 2, 3, 4, 7, 100, wire.count] {
            var r = NCH3FrameReader()
            var headers: [Data] = []
            var data = Data()
            var i = 0
            while i < wire.count {
                let end = min(wire.count, i + split)
                for e in r.feed(wire.subdata(in: i..<end)) {
                    switch e {
                    case .headers(let h): headers.append(h)
                    case .data(let d): data.append(d)
                    case .malformed(let m): XCTFail("malformed \(m) at split \(split)")
                    }
                }
                i = end
            }
            XCTAssertEqual(headers, [headersBlock], "split \(split)")
            XCTAssertEqual(data, expected, "split \(split)")
            XCTAssertEqual(r.buffered, 0)
        }
    }

    func testH3FrameReaderRejectsHugeHeaders() {
        var r = NCH3FrameReader()
        var wire = NCHy2.varintEncode(0x01)
        wire.append(NCHy2.varintEncode(UInt64(NCH3FrameReader.maxHeadersFrame + 1)))
        XCTAssertEqual(r.feed(wire), [.malformed("HEADERS frame too large")])
    }

    // MARK: - Support gate, share links

    func testSupportGate() {
        for t in ["naive", "http2", "h2", "http3", "h3"] {
            XCTAssertNil(NCSupport.unsupportedReason(proxy(t)), t)
        }
        XCTAssertNotNil(NCSupport.unsupportedReason(NCProxy(name: "x", type: "naive", fields: [:])))
    }

    func testNaiveShareLinkImport() throws {
        let p = try XCTUnwrap(NCSubscriptionParser.parseURI(
            "naive+https://user:pa%40ss@example.com:8443/?padding=true&extra-headers=X-A%3A%201%0D%0AX-B%3A%202#My%20Node"))
        XCTAssertEqual(p.type, "naive")
        XCTAssertEqual(p.name, "My Node")
        XCTAssertEqual(p.server, "example.com")
        XCTAssertEqual(p.port, 8443)
        XCTAssertEqual(p.fields["username"]?.string, "user")
        XCTAssertEqual(p.password, "pa@ss")
        XCTAssertNil(p.fields["quic"])
        let o = try XCTUnwrap(NCH2H3ProxyOptions(proxy: p))
        XCTAssertEqual(o.extraHeaders.map { "\($0.0)=\($0.1)" }, ["X-A=1", "X-B=2"])

        let q = try XCTUnwrap(NCSubscriptionParser.parseURI("naive+quic://secret@[2001:db8::1]#q"))
        XCTAssertEqual(q.fields["quic"]?.bool, true)
        XCTAssertEqual(q.port, 443)
        XCTAssertEqual(q.server, "2001:db8::1")
        XCTAssertEqual(q.password, "secret")
        XCTAssertNil(q.fields["username"])
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: q)).carrier, .h3)
    }

    func testHTTP2HTTP3ShareLinkImport() throws {
        let b64 = Data("alice:s3cret".utf8).base64EncodedString()
        let p = try XCTUnwrap(NCSubscriptionParser.parseURI("http2://\(b64)@h2.example.com:443?sni=front.example#H2"))
        XCTAssertEqual(p.type, "http2")
        XCTAssertEqual(p.fields["username"]?.string, "alice")
        XCTAssertEqual(p.password, "s3cret")
        XCTAssertEqual(p.fields["sni"]?.string, "front.example")
        let q = try XCTUnwrap(NCSubscriptionParser.parseURI("http3://bob:pw@h3.example.com:8443#H3"))
        XCTAssertEqual(q.type, "http3")
        XCTAssertEqual(q.port, 8443)
    }

    func testShareLinkExportRoundTrip() throws {
        let src = NCProxy(name: "N 1", type: "naive", fields: [
            "server": .string("example.com"), "port": .number(443),
            "username": .string("u"), "password": .string("p:w"), "quic": .bool(true),
            "extra-headers": .object(["X-A": .string("1")]),
        ])
        let link = try NCShareLink.encode(src)
        XCTAssertTrue(link.hasPrefix("naive+quic://"), link)
        let back = try XCTUnwrap(NCSubscriptionParser.parseURI(link))
        XCTAssertEqual(back.type, "naive")
        XCTAssertEqual(back.name, "N 1")
        XCTAssertEqual(back.fields["username"]?.string, "u")
        XCTAssertEqual(back.password, "p:w")
        XCTAssertEqual(back.fields["quic"]?.bool, true)
        XCTAssertEqual(try XCTUnwrap(NCH2H3ProxyOptions(proxy: back)).extraHeaders.map { $0.0 }, ["X-A"])

        let h3 = try NCShareLink.encode(NCProxy(name: "x", type: "http3", fields: [
            "server": .string("h.example"), "port": .number(443), "username": .string("a"), "password": .string("b")]))
        XCTAssertTrue(h3.hasPrefix("http3://a:b@h.example:443"), h3)
    }

    func testSingBoxNaiveOutboundImport() throws {
        let json = """
        {"outbounds":[{"type":"naive","tag":"nv","server":"n.example","server_port":443,"username":"u",
        "password":"p","quic":true,"insecure_concurrency":2,"extra_headers":{"X-A":"1"},
        "udp_over_tcp":{"enabled":true},"tls":{"enabled":true,"server_name":"sni.example"}}]}
        """
        let nodes = NCSubscriptionParser.parse(json)
        let p = try XCTUnwrap(nodes.first)
        XCTAssertEqual(p.type, "naive")
        XCTAssertEqual(p.name, "nv")
        XCTAssertEqual(p.fields["quic"]?.bool, true)
        XCTAssertEqual(p.fields["sni"]?.string, "sni.example")
        XCTAssertEqual(p.fields["udp-over-tcp"]?.bool, true)
        let o = try XCTUnwrap(NCH2H3ProxyOptions(proxy: p))
        XCTAssertEqual(o.concurrency, 2)
        XCTAssertEqual(o.carrier, .h3)
    }

    // MARK: - HTTP/2 CONNECT session against a scripted server

    private static func frames(_ data: Data) -> [(type: UInt8, flags: UInt8, stream: Int, payload: Data)] {
        var out: [(UInt8, UInt8, Int, Data)] = []
        var i = 0
        let b = [UInt8](data)
        while i + 9 <= b.count {
            let len = Int(b[i]) << 16 | Int(b[i + 1]) << 8 | Int(b[i + 2])
            guard i + 9 + len <= b.count else { break }
            let sid = Int(b[i + 5] & 0x7f) << 24 | Int(b[i + 6]) << 16 | Int(b[i + 7]) << 8 | Int(b[i + 8])
            out.append((b[i + 3], b[i + 4], sid, Data(b[(i + 9)..<(i + 9 + len)])))
            i += 9 + len
        }
        return out
    }

    private func waitUntil(_ timeout: TimeInterval = 3, _ cond: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if cond() { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        return cond()
    }

    func testH2SessionNaiveConnectPaddedExchange() throws {
        let base = NaiveFakeBase()
        let session = NCH2ProxySession(key: "test-naive")
        session.attach(base: base)
        XCTAssertTrue(waitUntil { base.sentData.starts(with: NCH2ClientCore.preface) })

        let q = DispatchQueue(label: "nc.test.naive")
        let readyExp = expectation(description: "ready")
        let readyErr = NaiveLocked<Error?>(nil)
        let headers: [(String, String)] = [(":method", "CONNECT"), (":authority", "example.com:443"),
                                           ("padding", "~~~~~~~~~~~~~~~~")]
        let stream = session.openStream(headers: headers, naive: true, callerQueue: q) { err in
            readyErr.set(err)
            readyExp.fulfill()
        }
        // The HEADERS frame on stream 1 carries the request.
        var hdr: Data?
        XCTAssertTrue(waitUntil {
            hdr = Self.frames(Data(base.sentData.dropFirst(NCH2ClientCore.preface.count)))
                .first(where: { $0.type == 0x1 && $0.stream == 1 })?.payload
            return hdr != nil
        })
        let req = try XCTUnwrap(NCHPACKDecoder().decode(try XCTUnwrap(hdr)))
        XCTAssertEqual(req.map { "\($0.0)=\($0.1)" }, headers.map { "\($0.0)=\($0.1)" })

        // Data sent before the response is held.
        stream.send(Data("hi".utf8))
        let before = base.sentData.count

        // Server: SETTINGS, then :status 200 with a padding header.
        var server = NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0, payload: Data())
        server.append(NCH2ClientCore.frame(type: 0x1, flags: 0x4, streamID: 1,
                                           payload: NCHPACK.encodeHeaders([(":status", "200"), ("padding", "~~~~")])))
        base.push(server)
        wait(for: [readyExp], timeout: 3)
        XCTAssertNil(readyErr.get())

        // The held "hi" went out as the first padded frame.
        var dataFrame: Data?
        XCTAssertTrue(waitUntil {
            dataFrame = Self.frames(Data(base.sentData.dropFirst(before)))
                .first(where: { $0.type == 0x0 && $0.stream == 1 })?.payload
            return dataFrame != nil
        })
        let df = try XCTUnwrap(dataFrame)
        XCTAssertEqual(Array(df.prefix(2)), [0x00, 0x02])
        XCTAssertEqual(df.count, 3 + 2 + Int(df[2]))
        XCTAssertEqual(df.subdata(in: 3..<5), Data("hi".utf8))

        // Server DATA, padded (sing-box style) → plain bytes to the reader.
        let recvExp = expectation(description: "recv")
        let got = NaiveLocked<Data?>(nil)
        stream.receive { d, _ in got.set(d); recvExp.fulfill() }
        let padded = Data([0x00, 0x05, 0x03]) + Data("world".utf8) + Data([0, 0, 0])
        base.push(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: 1, payload: padded))
        wait(for: [recvExp], timeout: 3)
        XCTAssertEqual(got.get(), Data("world".utf8))

        // END_STREAM → clean EOF.
        let eofExp = expectation(description: "eof")
        let eof = NaiveLocked<(Data?, Bool)>((Data([1]), false))
        stream.receive { d, e in eof.set((d, e == nil)); eofExp.fulfill() }
        base.push(NCH2ClientCore.frame(type: 0x0, flags: 0x1, streamID: 1, payload: Data()))
        wait(for: [eofExp], timeout: 3)
        XCTAssertNil(eof.get().0)
        XCTAssertTrue(eof.get().1)
        stream.cancel()
        session.close()
    }

    func testH2SessionConnectRejected() {
        let base = NaiveFakeBase()
        let session = NCH2ProxySession(key: "test-407")
        session.attach(base: base)
        let q = DispatchQueue(label: "nc.test.407")
        let exp = expectation(description: "ready")
        let err = NaiveLocked<Error?>(nil)
        _ = session.openStream(headers: [(":method", "CONNECT"), (":authority", "a:1")], naive: false,
                               callerQueue: q) { e in err.set(e); exp.fulfill() }
        XCTAssertTrue(waitUntil { Self.frames(Data(base.sentData.dropFirst(NCH2ClientCore.preface.count))).contains { $0.type == 0x1 } })
        base.push(NCH2ClientCore.frame(type: 0x1, flags: 0x5, streamID: 1,
                                       payload: NCHPACK.encodeHeaders([(":status", "407")])))
        wait(for: [exp], timeout: 3)
        XCTAssertNotNil(err.get())
        XCTAssertTrue("\(err.get()!)".contains("407") || (err.get()! as NSError).localizedDescription.contains("407"))
        // The rejected stream left the table; the session itself stays usable.
        XCTAssertTrue(waitUntil { session.activeStreamCount == 0 })
        XCTAssertTrue(session.isAlive)
        session.close()
    }

    func testH2SessionStartBytesRaiseWindows() {
        let bytes = NCH2ProxySession.startBytes()
        let fr = Self.frames(Data(bytes.dropFirst(NCH2ClientCore.preface.count)))
        XCTAssertEqual(fr.map { $0.type }, [0x4, 0x8])
        XCTAssertEqual(fr[0].payload, Data([0x00, 0x02, 0, 0, 0, 0, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00]))
        XCTAssertEqual(fr[1].stream, 0)
    }
}

/// Fake base stream: records what the session writes, lets the test push server bytes.
private final class NaiveFakeBase: NCRelayStream {
    private let lock = NSLock()
    private var sent = Data()
    private var handler: ((Data?, Error?) -> Void)?
    private var inbox: [Data] = []

    var sentData: Data { lock.lock(); defer { lock.unlock() }; return sent }

    func send(_ data: Data, completion: @escaping () -> Void) {
        lock.lock(); sent.append(data); lock.unlock()
        completion()
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !inbox.isEmpty {
            let d = inbox.removeFirst()
            lock.unlock()
            handler(d, nil)
            return
        }
        self.handler = handler
        lock.unlock()
    }

    func push(_ data: Data) {
        lock.lock()
        if let h = handler {
            handler = nil
            lock.unlock()
            h(data, nil)
        } else {
            inbox.append(data)
            lock.unlock()
        }
    }

    func cancel() {}
}

private final class NaiveLocked<T> {
    private let lock = NSLock()
    private var value: T
    init(_ v: T) { value = v }
    func set(_ v: T) { lock.lock(); value = v; lock.unlock() }
    func get() -> T { lock.lock(); defer { lock.unlock() }; return value }
}

/// The hand-rolled ClientHello (NCTLSClientStream, naive h2's TLS) must parse under the old core's strict rules:
/// supported_versions is a u8-length list of u16 versions with nothing left over.
final class NativeCoreClientHelloSupportedVersionsTests: XCTestCase {
    func testSupportedVersionsExtensionIsWellFormed() throws {
        for profile in [NCClientHelloProfile.chrome, .firefox, .safari, .ios] {
            let hello = [UInt8](NCTLS13.buildClientHello(random: Data(count: 32), sessionID: Data(count: 32),
                                                         serverName: "localhost", alpn: ["h2", "http/1.1"],
                                                         keyShare: Data(count: 32), profile: profile))
            // handshake header 4, version 2, random 32, session id 1+32, suites 2+n, compression 2, ext len 2.
            var i = 4 + 2 + 32
            i += 1 + Int(hello[i])
            i += 2 + (Int(hello[i]) << 8 | Int(hello[i + 1]))
            i += 1 + Int(hello[i])
            let extEnd = i + 2 + (Int(hello[i]) << 8 | Int(hello[i + 1]))
            i += 2
            var found: [UInt8]?
            while i + 4 <= extEnd {
                let type = Int(hello[i]) << 8 | Int(hello[i + 1])
                let len = Int(hello[i + 2]) << 8 | Int(hello[i + 3])
                if type == 43 { found = Array(hello[(i + 4)..<(i + 4 + len)]) }
                i += 4 + len
            }
            XCTAssertEqual(i, extEnd)
            let sv = try XCTUnwrap(found)
            XCTAssertEqual(Int(sv[0]), sv.count - 1)
            XCTAssertEqual(sv.count % 2, 1)
            XCTAssertEqual(Array(sv.dropFirst()), [0x03, 0x04, 0x03, 0x03])
        }
    }
}
