import XCTest
@testable import Tern

/// feat/nc-xhttp: XHTTP (splithttp) transport — config parsing (Clash.Meta xhttp-opts), request construction
/// (paths, placements, padding, browser headers), the multi-stream HTTP/2 core, the relay stream's three
/// modes against a scripted in-memory server, share-link import / export, and the NCSupport gate.
/// (sing-box has no XHTTP inbound, so there is no loopback case.)
final class NativeCoreXHTTPTests: XCTestCase {

    // MARK: helpers

    private func proxy(_ type: String = "vless", opts: [String: NCJSONValue] = [:],
                       extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = [
            "server": .string("203.0.113.9"), "port": .number(443),
            "uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"), "password": .string("pw"),
            "network": .string("xhttp"), "tls": .bool(true), "xhttp-opts": .object(opts),
        ]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "x", type: type, fields: f)
    }

    private func header(_ h: [(String, String)], _ name: String) -> String? {
        h.first(where: { $0.0 == name })?.1
    }

    // MARK: Range

    func testRangeParse() {
        XCTAssertEqual(NCXHTTPRange.parse("100-1000", fallback: "1"), NCXHTTPRange(100, 1000))
        XCTAssertEqual(NCXHTTPRange.parse(" 30 ", fallback: "1"), NCXHTTPRange(30, 30))
        XCTAssertEqual(NCXHTTPRange.parse("", fallback: "16-32"), NCXHTTPRange(16, 32))
        XCTAssertEqual(NCXHTTPRange.parse(nil, fallback: "30"), NCXHTTPRange(30, 30))
        XCTAssertEqual(NCXHTTPRange.parse("10 - 20", fallback: "1"), NCXHTTPRange(10, 20))
        XCTAssertNil(NCXHTTPRange.parse("20-10", fallback: "1"))
        XCTAssertNil(NCXHTTPRange.parse("a-b", fallback: "1"))
        XCTAssertNil(NCXHTTPRange.parse("1-2-3", fallback: "1"))
        XCTAssertNil(NCXHTTPRange.parse("-5", fallback: "1"))
        let r = NCXHTTPRange(5, 9)
        for _ in 0..<50 { XCTAssertTrue((5...9).contains(r.rand())) }
    }

    // MARK: config

    func testHostFallbacksAndModes() throws {
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy(opts: ["host": .string("h.example")])).host, "h.example")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy(extra: ["servername": .string("sni.example")])).host, "sni.example")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy()).host, "203.0.113.9")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy(extra: ["server": .string("2001:db8::1")])).host, "[2001:db8::1]")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy("trojan", extra: ["sni": .string("t.example")])).host, "t.example")

        let auto = try NCXHTTPConfig.parse(proxy())
        XCTAssertEqual(auto.mode, "auto")
        XCTAssertEqual(auto.effectiveMode(hasReality: false), "packet-up")
        XCTAssertEqual(auto.effectiveMode(hasReality: true), "stream-one")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy(opts: ["mode": .string("stream-up")])).effectiveMode(hasReality: true), "stream-up")
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["mode": .string("bogus")])))
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["mode": .string("stream-one"),
                                                                  "download-settings": .object(["server": .string("d")])])))
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["sc-max-each-post-bytes": .number(0)])))
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["sc-min-posts-interval-ms": .string("x")])))
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["x-padding-bytes": .string("9-1")])))
        // numbers (YAML ints) read like Clash.Meta's weakly typed decode
        let n = try NCXHTTPConfig.parse(proxy(opts: ["sc-max-each-post-bytes": .number(4096), "sc-min-posts-interval-ms": .number(5)]))
        XCTAssertEqual(n.scMaxEachPostBytes, NCXHTTPRange(4096, 4096))
        XCTAssertEqual(n.scMinPostsIntervalMs, NCXHTTPRange(5, 5))
    }

    func testNormalizedPath() throws {
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy()).normalizedPath, "/")
        XCTAssertEqual(try NCXHTTPConfig.parse(proxy(opts: ["path": .string("xp")])).normalizedPath, "/xp/")
        let q = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/xp"), "session-placement": .string("query"),
                                                     "seq-placement": .string("header")]))
        XCTAssertEqual(q.normalizedPath, "/xp")
        XCTAssertEqual(q.sessionKey, "x_session")
        XCTAssertEqual(q.seqKey, "X-Seq")
    }

    func testSessionIDs() throws {
        let def = try NCXHTTPConfig.parse(proxy()).generateSessionID()
        XCTAssertEqual(def.count, 32)
        XCTAssertTrue(def.allSatisfy { "0123456789abcdef".contains($0) })
        let uuid = try NCXHTTPConfig.parse(proxy(opts: ["session-table": .string("uuid")])).generateSessionID()
        XCTAssertNotNil(UUID(uuidString: uuid))
        XCTAssertEqual(uuid, uuid.lowercased())
        let tab = try NCXHTTPConfig.parse(proxy(opts: ["session-table": .string("number"), "session-length": .string("12-14")]))
        for _ in 0..<20 {
            let id = tab.generateSessionID()
            XCTAssertTrue((12...14).contains(id.count))
            XCTAssertTrue(id.allSatisfy { $0.isNumber })
        }
        // 10^1..10^3 < 2^31: rejected like Clash.Meta
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["session-table": .string("number"), "session-length": .string("1-3")])))
        XCTAssertThrowsError(try NCXHTTPConfig.parse(proxy(opts: ["session-table": .string("ab€"), "session-length": .string("40")])))
    }

    // MARK: requests

    func testPacketRequestDefaults() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/xp"), "x-padding-bytes": .string("10-20")],
                                                extra: ["servername": .string("cdn.example.com")]))
        let r = cfg.packetRequest(sessionID: "abc", seq: 7, data: Data([1, 2, 3]))
        XCTAssertEqual(r.method, "POST")
        XCTAssertEqual(r.requestURI, "/xp/abc/7")
        XCTAssertEqual(r.body, Data([1, 2, 3]))
        let h = r.h2Headers()
        XCTAssertEqual(h.prefix(4).map { $0.0 }, [":method", ":scheme", ":authority", ":path"])
        XCTAssertEqual(header(h, ":authority"), "cdn.example.com")
        XCTAssertEqual(header(h, ":path"), "/xp/abc/7")
        XCTAssertEqual(header(h, "content-length"), "3")
        XCTAssertNil(header(h, "content-type"))
        let referer = try XCTUnwrap(header(h, "referer"))
        let prefix = "https://cdn.example.com/xp/?x_padding="
        XCTAssertTrue(referer.hasPrefix(prefix), referer)
        let pad = referer.dropFirst(prefix.count)
        XCTAssertTrue((10...20).contains(pad.count))
        XCTAssertTrue(pad.allSatisfy { $0 == "X" })
        // default Chrome masquerade for a fetch()
        XCTAssertTrue(header(h, "user-agent")?.contains("Chrome/") ?? false)
        XCTAssertEqual(header(h, "sec-fetch-mode"), "cors")
        XCTAssertEqual(header(h, "sec-fetch-site"), "same-origin")
        XCTAssertEqual(header(h, "priority"), "u=1, i")
        XCTAssertEqual(header(h, "accept"), "*/*")
        XCTAssertNotNil(header(h, "sec-ch-ua"))
        XCTAssertTrue(h.allSatisfy { $0.0 == $0.0.lowercased() })
    }

    func testStreamRequests() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/s")]))
        let one = cfg.streamRequest(method: "POST", sessionID: "", hasBody: true)
        XCTAssertEqual(one.requestURI, "/s/")
        let h1 = one.h2Headers()
        XCTAssertEqual(header(h1, "content-type"), "application/grpc")
        XCTAssertNil(header(h1, "content-length")) // streaming body
        let dl = cfg.downloadRequest(sessionID: "sess")
        XCTAssertEqual(dl.method, "GET")
        XCTAssertEqual(dl.requestURI, "/s/sess")
        XCTAssertNil(header(dl.h2Headers(), "content-type"))
        XCTAssertNil(header(dl.h2Headers(), "content-length"))
        let noGRPC = try NCXHTTPConfig.parse(proxy(opts: ["no-grpc-header": .bool(true)]))
        XCTAssertNil(header(noGRPC.streamRequest(method: "POST", sessionID: "", hasBody: true).h2Headers(), "content-type"))
    }

    func testPlacementsAndObfsPadding() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: [
            "path": .string("/p"), "session-placement": .string("query"), "seq-placement": .string("cookie"),
            "x-padding-obfs-mode": .bool(true), "x-padding-placement": .string("header"),
            "x-padding-header": .string("X-Pad"), "x-padding-bytes": .string("8"),
            "headers": .object(["Host": .string("ignored.example"), "X-Custom": .string("v")]),
        ]))
        let r = cfg.packetRequest(sessionID: "S1", seq: 3, data: Data("hi".utf8))
        XCTAssertEqual(r.requestURI, "/p?x_session=S1")
        let h = r.h2Headers()
        XCTAssertEqual(header(h, "cookie"), "x_seq=3")
        XCTAssertEqual(header(h, "x-pad"), "XXXXXXXX")
        XCTAssertNil(header(h, "referer"))
        XCTAssertNil(header(h, "host"))
        XCTAssertEqual(header(h, "x-custom"), "v")

        let q = try NCXHTTPConfig.parse(proxy(opts: [
            "session-placement": .string("header"), "seq-placement": .string("query"), "seq-key": .string("n"),
            "x-padding-obfs-mode": .bool(true), "x-padding-placement": .string("query"), "x-padding-key": .string("pad"),
            "x-padding-bytes": .string("4"),
        ]))
        let r2 = q.packetRequest(sessionID: "S2", seq: 0, data: Data([9]))
        XCTAssertEqual(r2.requestURI, "/?n=0&pad=XXXX") // url.Values.Encode: sorted keys
        XCTAssertEqual(header(r2.h2Headers(), "x-session"), "S2")

        let ck = try NCXHTTPConfig.parse(proxy(opts: [
            "session-placement": .string("cookie"), "seq-placement": .string("cookie"),
            "x-padding-obfs-mode": .bool(true), "x-padding-placement": .string("cookie"), "x-padding-key": .string("p"),
            "x-padding-bytes": .string("2"),
        ]))
        XCTAssertEqual(header(ck.packetRequest(sessionID: "a", seq: 1, data: Data([1])).h2Headers(), "cookie"),
                       "p=XX; x_session=a; x_seq=1")
    }

    func testHeaderAndCookieDataPlacement() throws {
        let payload = Data((0..<3000).map { UInt8($0 & 0xff) })
        let expected = payload.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["uplink-data-placement": .string("header"),
                                                       "uplink-data-key": .string("X-Data"),
                                                       "uplink-chunk-size": .string("100-200")]))
        let r = cfg.packetRequest(sessionID: "s", seq: 0, data: payload)
        XCTAssertNil(r.body)
        let h = r.h2Headers()
        XCTAssertEqual(header(h, "content-length"), "0") // POST without body, like the old core's transport
        var joined = ""
        var i = 0
        while let part = header(h, "x-data-\(i)") {
            XCTAssertTrue(part.count <= 200)
            if header(h, "x-data-\(i + 1)") != nil { XCTAssertTrue(part.count >= 100) }
            joined += part
            i += 1
        }
        XCTAssertEqual(joined, expected)

        let ck = try NCXHTTPConfig.parse(proxy(opts: ["uplink-data-placement": .string("cookie"),
                                                      "uplink-data-key": .string("d")]))
        XCTAssertEqual(ck.uplinkChunkSize, NCXHTTPRange(2048, 3072))
        let cookie = try XCTUnwrap(header(ck.packetRequest(sessionID: "s", seq: 0, data: payload).h2Headers(), "cookie"))
        let parts = cookie.components(separatedBy: "; ")
        XCTAssertEqual(parts.map { String($0.split(separator: "=", maxSplits: 1)[1]) }.joined(), expected)
        XCTAssertTrue(parts.first?.hasPrefix("d_0=") ?? false)
        // chunk size floor of 64
        let small = try NCXHTTPConfig.parse(proxy(opts: ["uplink-data-placement": .string("header"), "uplink-chunk-size": .number(10)]))
        XCTAssertEqual(small.uplinkChunkSize, NCXHTTPRange(64, 64))
    }

    func testPaddingMethods() {
        XCTAssertEqual(NCXHTTPPadding.generate(method: "", length: 5), "XXXXX")
        XCTAssertEqual(NCXHTTPPadding.generate(method: "repeat-x", length: 0), "")
        XCTAssertEqual(NCXHTTPPadding.huffmanLength("XXXX"), 4) // 'X' is an 8-bit code
        for target in [16, 100, 600] {
            let t = NCXHTTPPadding.generate(method: "tokenish", length: target)
            XCTAssertTrue(abs(NCXHTTPPadding.huffmanLength(t) - target) <= 2, "\(target): \(t.count)")
            XCTAssertTrue(t.utf8.allSatisfy { NCXHTTPPadding.base62.contains($0) })
        }
    }

    func testBrowserMasquerade() throws {
        let custom = try NCXHTTPConfig.parse(proxy(opts: ["headers": .object(["User-Agent": .string("MyUA/1")])]))
        let h = custom.baseHeaders()
        XCTAssertEqual(h.get("user-agent"), "MyUA/1")
        XCTAssertNil(h.get("sec-fetch-mode")) // custom UA: left alone entirely
        let ff = try NCXHTTPConfig.parse(proxy(opts: ["headers": .object(["User-Agent": .string("firefox")])])).baseHeaders()
        XCTAssertTrue(ff.get("user-agent")?.contains("Firefox/") ?? false)
        XCTAssertEqual(ff.get("priority"), "u=4")
        let golangUA = try NCXHTTPConfig.parse(proxy(opts: ["headers": .object(["User-Agent": .string("golang")])]))
        XCTAssertEqual(header(golangUA.downloadRequest(sessionID: "s").h2Headers(), "user-agent"), "Go-http-client/2.0")
        let ch = NCXHTTPBrowser.greasedChUa(140, fork: "chrome")
        XCTAssertTrue(ch.contains("\"Chromium\";v=\"140\"") && ch.contains("\"Google Chrome\";v=\"140\""))
        XCTAssertEqual(ch.components(separatedBy: ", ").count, 3)
    }

    // MARK: HTTP/2 core

    private struct Frame {
        var type: UInt8
        var flags: UInt8
        var sid: UInt32
        var payload: Data
    }

    private func frames(_ d: Data, skipPreface: Bool = false) -> [Frame] {
        var data = d
        if skipPreface, data.starts(with: NCXHTTPH2Core.preface) { data = data.dropFirst(NCXHTTPH2Core.preface.count) }
        var out: [Frame] = []
        var b = data.startIndex
        while data.endIndex - b >= 9 {
            let len = Int(data[b]) << 16 | Int(data[b + 1]) << 8 | Int(data[b + 2])
            guard data.endIndex - b >= 9 + len else { break }
            let sid = UInt32(data[b + 5] & 0x7f) << 24 | UInt32(data[b + 6]) << 16 | UInt32(data[b + 7]) << 8 | UInt32(data[b + 8])
            out.append(Frame(type: data[b + 3], flags: data[b + 4], sid: sid, payload: Data(data[(b + 9)..<(b + 9 + len)])))
            b += 9 + len
        }
        return out
    }

    private func srvFrame(_ type: UInt8, _ flags: UInt8, _ sid: UInt32, _ payload: Data = Data()) -> Data {
        NCXHTTPH2Core.frame(type: type, flags: flags, streamID: sid, payload: payload)
    }

    private func statusBlock(_ status: Int) -> Data {
        NCHPACK.encodeHeaders([(":status", String(status))])
    }

    func testCoreStartAndHeaders() {
        let core = NCXHTTPH2Core(localWindow: 512 * 1024)
        let start = core.start()
        XCTAssertTrue(start.starts(with: NCXHTTPH2Core.preface))
        let fs = frames(start, skipPreface: true)
        XCTAssertEqual(fs.map { $0.type }, [0x4, 0x8])
        XCTAssertEqual(fs[0].payload, Data([0, 2, 0, 0, 0, 0, 0, 4, 0, 8, 0, 0]))  // ENABLE_PUSH 0, INITIAL_WINDOW 512K
        XCTAssertEqual(NCXHTTPH2Core.u32(fs[1].payload, 0), UInt32(2 * 512 * 1024 - 65535))

        let a = core.openStream(headers: [(":method", "GET"), (":path", "/")], endStream: true)!
        let b = core.openStream(headers: [(":method", "POST"), ("x-big", String(repeating: "Y", count: 40_000))], endStream: false)!
        XCTAssertEqual(a.id, 1)
        XCTAssertEqual(b.id, 3)
        let fa = frames(a.frames)
        XCTAssertEqual(fa.count, 1)
        XCTAssertEqual(fa[0].flags, 0x5) // END_STREAM | END_HEADERS
        let fb = frames(b.frames)
        XCTAssertEqual(fb.map { $0.type }, [0x1, 0x9, 0x9])
        XCTAssertEqual(fb.map { $0.flags }, [0x0, 0x0, 0x4])
        XCTAssertTrue(fb.allSatisfy { $0.payload.count <= 16384 && $0.sid == 3 })
        let block = fb.reduce(Data()) { $0 + $1.payload }
        let decoded = NCHPACKDecoder().decode(block)
        XCTAssertEqual(decoded?.last?.1.count, 40_000)
    }

    func testCoreFlowControlAndEvents() {
        let core = NCXHTTPH2Core(localWindow: 65535)
        _ = core.start()
        let s = core.openStream(headers: [(":method", "POST")], endStream: false)!
        // send window: 65535 initially, peer raises it to 100000 by SETTINGS, frames ≤ 16384
        let big = Data(repeating: 7, count: 70_000)
        var r = core.makeData(stream: s.id, big)
        XCTAssertEqual(r.consumed, 65535)
        XCTAssertTrue(frames(r.frames).allSatisfy { $0.payload.count <= 16384 && $0.flags == 0 })
        var settings = Data([0, 4]); settings.append(NCXHTTPH2Core.be32(100_000))
        var fr = core.feed(srvFrame(0x4, 0, 0, settings))
        XCTAssertEqual(frames(fr.outbound).first?.type, 0x4) // ACK
        XCTAssertEqual(frames(fr.outbound).first?.flags, 0x1)
        XCTAssertEqual(fr.events, [.windowIncreased])
        // connection window is still exhausted until a connection WINDOW_UPDATE
        r = core.makeData(stream: s.id, Data(big.suffix(4465)), endStream: true)
        XCTAssertEqual(r.consumed, 0)
        fr = core.feed(srvFrame(0x8, 0, 0, NCXHTTPH2Core.be32(10_000)))
        XCTAssertEqual(fr.events, [.windowIncreased])
        r = core.makeData(stream: s.id, Data(big.suffix(4465)), endStream: true)
        XCTAssertEqual(r.consumed, 4465)
        XCTAssertEqual(frames(r.frames).last?.flags, 0x1) // END_STREAM on the last byte

        // response + data + end, with receive credit handed back on consume
        var inbound = srvFrame(0x1, 0x4, s.id, statusBlock(200))
        inbound.append(srvFrame(0x0, 0, s.id, Data(repeating: 1, count: 16384)))
        inbound.append(srvFrame(0x0, 0, s.id, Data(repeating: 2, count: 16384)))
        // split across feeds to exercise buffering
        fr = core.feed(inbound.prefix(5))
        XCTAssertTrue(fr.events.isEmpty)
        fr = core.feed(inbound.dropFirst(5))
        XCTAssertEqual(fr.events.count, 3)
        XCTAssertEqual(fr.events.first, .response(stream: s.id, status: 200))
        XCTAssertTrue(fr.outbound.isEmpty) // no automatic window return
        XCTAssertTrue(core.consume(stream: s.id, 16384).isEmpty) // below threshold (32 KiB)
        let wu = frames(core.consume(stream: s.id, 16384))
        XCTAssertEqual(wu.map { $0.type }, [0x8, 0x8])
        XCTAssertEqual(wu.map { $0.sid }, [0, s.id])
        XCTAssertEqual(NCXHTTPH2Core.u32(wu[1].payload, 0), 32768)
        fr = core.feed(srvFrame(0x0, 0x1, s.id, Data()))
        XCTAssertEqual(fr.events, [.end(stream: s.id)])
        XCTAssertFalse(core.isOpen(s.id)) // both sides closed

        // informational responses are skipped; RST and GOAWAY surface
        let t = core.openStream(headers: [(":method", "GET")], endStream: true)!
        fr = core.feed(srvFrame(0x1, 0x4, t.id, statusBlock(103)))
        XCTAssertTrue(fr.events.isEmpty)
        fr = core.feed(srvFrame(0x3, 0, t.id, NCXHTTPH2Core.be32(2)))
        XCTAssertEqual(fr.events, [.reset(stream: t.id, code: 2)])
        // DATA for a forgotten stream still returns connection credit
        fr = core.feed(srvFrame(0x0, 0, t.id, Data(repeating: 0, count: 40_000 / 3)))
        fr = core.feed(srvFrame(0x0, 0, t.id, Data(repeating: 0, count: 16384)) + srvFrame(0x0, 0, t.id, Data(repeating: 0, count: 16384)))
        XCTAssertTrue(frames(fr.outbound).contains { $0.type == 0x8 && $0.sid == 0 })
        var ga = NCXHTTPH2Core.be32(5); ga.append(NCXHTTPH2Core.be32(0))
        fr = core.feed(srvFrame(0x7, 0, 0, ga))
        XCTAssertEqual(fr.events, [.goaway(lastStreamID: 5, code: 0)])
        XCTAssertNil(core.openStream(headers: [(":method", "GET")], endStream: true))
        // PING is answered
        fr = core.feed(srvFrame(0x6, 0, 0, Data(repeating: 9, count: 8)))
        XCTAssertEqual(frames(fr.outbound).first?.flags, 0x1)
    }

    func testCoreProtocolErrors() {
        let c1 = NCXHTTPH2Core()
        _ = c1.openStream(headers: [(":method", "GET")], endStream: true)
        var big = Data([0x00, 0x80, 0x00, 0x0, 0x0, 0, 0, 0, 1]); big.append(Data(count: 10))
        XCTAssertTrue(isConnError(c1.feed(big).events.first), "oversized frame must fail")
        XCTAssertTrue(c1.failed)
        let c2 = NCXHTTPH2Core()
        let s = c2.openStream(headers: [(":method", "GET")], endStream: true)!
        // HEADERS without END_HEADERS followed by DATA: interrupted header block
        var bad = srvFrame(0x1, 0, s.id, statusBlock(200))
        bad.append(srvFrame(0x0, 0, s.id, Data([1])))
        XCTAssertTrue(isConnError(c2.feed(bad).events.last), "interrupted header block must fail")
        let c3 = NCXHTTPH2Core()
        XCTAssertTrue(isConnError(c3.feed(srvFrame(0x5, 0x4, 1, Data(count: 4))).events.first), "push must fail")
    }

    private func isConnError(_ e: NCXHTTPH2Core.Event?) -> Bool {
        if case .connectionError(_)? = e { return true }
        return false
    }

    // MARK: relay stream against a scripted server

    private final class FakeRaw: NCRelayStream {
        private let lock = NSLock()
        private var sentData = Data()
        private var inbox: [Data] = []
        private var waiting: ((Data?, Error?) -> Void)?
        private var cancelledFlag = false
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelledFlag }
        let q = DispatchQueue(label: "xhttp.fake.raw")

        var sent: Data { lock.lock(); defer { lock.unlock() }; return sentData }

        func send(_ data: Data, completion: @escaping () -> Void) {
            lock.lock(); sentData.append(data); lock.unlock()
            q.async(execute: completion)
        }

        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            lock.lock()
            if !inbox.isEmpty {
                let d = inbox.removeFirst()
                lock.unlock()
                q.async { handler(d, nil) }
                return
            }
            waiting = handler
            lock.unlock()
        }

        func inject(_ d: Data) {
            lock.lock()
            if let h = waiting {
                waiting = nil
                lock.unlock()
                q.async { h(d, nil) }
            } else {
                inbox.append(d)
                lock.unlock()
            }
        }

        func cancel() { lock.lock(); cancelledFlag = true; lock.unlock() }
    }

    /// Server view of what the client wrote: requests (decoded headers) and DATA per stream.
    private struct ServerView {
        var requests: [UInt32: [(String, String)]] = [:]
        var order: [UInt32] = []
        var data: [UInt32: Data] = [:]
        var ended: Set<UInt32> = []
    }

    private func serverView(_ sent: Data) -> ServerView {
        var v = ServerView()
        let dec = NCHPACKDecoder()
        var block = Data()
        var blockSid: UInt32 = 0
        var blockEnd = false
        for f in frames(sent, skipPreface: true) {
            switch f.type {
            case 0x1, 0x9:
                if f.type == 0x1 { block = Data(); blockSid = f.sid; blockEnd = f.flags & 0x1 != 0 }
                block.append(f.payload)
                if f.flags & 0x4 != 0 {
                    v.requests[blockSid] = dec.decode(block) ?? []
                    v.order.append(blockSid)
                    if blockEnd { v.ended.insert(blockSid) }
                }
            case 0x0:
                v.data[f.sid, default: Data()].append(f.payload)
                if f.flags & 0x1 != 0 { v.ended.insert(f.sid) }
            default:
                break
            }
        }
        return v
    }

    private func waitUntil(_ timeout: TimeInterval = 3, _ cond: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if cond() { return true }
            Thread.sleep(forTimeInterval: 0.005)
        }
        return cond()
    }

    private func receiveOne(_ s: NCRelayStream) -> (Data?, Error?) {
        let done = expectation(description: "receive")
        var out: (Data?, Error?) = (nil, nil)
        s.receive { d, e in out = (d, e); done.fulfill() }
        wait(for: [done], timeout: 3)
        return out
    }

    private let caller = DispatchQueue(label: "xhttp.test.caller")

    func testStreamOneRoundTrip() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/one"), "mode": .string("stream-one")]))
        let raw = FakeRaw()
        let s = NCXHTTPStream(raw: raw, config: cfg, mode: .streamOne, callerQueue: caller)
        s.start { XCTAssertNil($0) }
        let sentDone = expectation(description: "send completion")
        s.send(Data("hello".utf8)) { sentDone.fulfill() }
        wait(for: [sentDone], timeout: 3)
        var v = serverView(raw.sent)
        XCTAssertEqual(v.order, [1])
        XCTAssertEqual(header(v.requests[1] ?? [], ":method"), "POST")
        XCTAssertEqual(header(v.requests[1] ?? [], ":path"), "/one/") // NormalizedPath: session placement is path
        XCTAssertEqual(header(v.requests[1] ?? [], "content-type"), "application/grpc")
        XCTAssertEqual(v.data[1], Data("hello".utf8))
        XCTAssertFalse(v.ended.contains(1))

        var resp = srvFrame(0x4, 0, 0)
        resp.append(srvFrame(0x1, 0x4, 1, statusBlock(200)))
        resp.append(srvFrame(0x0, 0, 1, Data("world".utf8)))
        raw.inject(resp)
        let got = receiveOne(s)
        XCTAssertEqual(got.0, Data("world".utf8))
        raw.inject(srvFrame(0x0, 0x1, 1))
        let eof = receiveOne(s)
        XCTAssertNil(eof.0)
        XCTAssertNil(eof.1)
        v = serverView(raw.sent)
        XCTAssertEqual(v.order, [1])
        s.cancel()
        XCTAssertTrue(waitUntil { raw.cancelled })
    }

    func testStreamUpOpensDownloadThenUpload() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/up"), "mode": .string("stream-up")]))
        let raw = FakeRaw()
        let s = NCXHTTPStream(raw: raw, config: cfg, mode: .streamUp, callerQueue: caller)
        s.start { XCTAssertNil($0) }
        let sentDone = expectation(description: "send completion")
        s.send(Data([1, 2, 3])) { sentDone.fulfill() }
        wait(for: [sentDone], timeout: 3)
        let v = serverView(raw.sent)
        XCTAssertEqual(v.order, [1, 3])
        XCTAssertEqual(header(v.requests[1] ?? [], ":method"), "GET")
        XCTAssertEqual(header(v.requests[1] ?? [], ":path"), "/up/\(s.sessionID)")
        XCTAssertTrue(v.ended.contains(1))
        XCTAssertEqual(header(v.requests[3] ?? [], ":method"), "POST")
        XCTAssertEqual(header(v.requests[3] ?? [], ":path"), "/up/\(s.sessionID)")
        XCTAssertEqual(v.data[3], Data([1, 2, 3]))
        XCTAssertEqual(s.sessionID.count, 32)
        // a non-200 download fails the stream
        raw.inject(srvFrame(0x1, 0x4, 1, statusBlock(404)))
        let r = receiveOne(s)
        XCTAssertNil(r.0)
        XCTAssertNotNil(r.1)
        XCTAssertTrue(waitUntil { raw.cancelled })
    }

    func testPacketUpSegmentsAndSequencesPosts() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["path": .string("/pk"), "mode": .string("packet-up"),
                                                       "sc-max-each-post-bytes": .number(1000),
                                                       "sc-min-posts-interval-ms": .number(5)]))
        let raw = FakeRaw()
        let s = NCXHTTPStream(raw: raw, config: cfg, mode: .packetUp, callerQueue: caller)
        XCTAssertEqual(s.postLimit, 1000)
        s.start { XCTAssertNil($0) }
        let payload = Data((0..<2500).map { UInt8($0 % 251) })
        let sentDone = expectation(description: "send completion")
        s.send(payload) { sentDone.fulfill() } // fills a whole post: completion waits for the first post
        // download GET first
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).order.count >= 2 })
        var v = serverView(raw.sent)
        XCTAssertEqual(header(v.requests[1] ?? [], ":method"), "GET")
        XCTAssertEqual(header(v.requests[1] ?? [], ":path"), "/pk/\(s.sessionID)")
        XCTAssertEqual(header(v.requests[3] ?? [], ":path"), "/pk/\(s.sessionID)/0")
        XCTAssertEqual(header(v.requests[3] ?? [], "content-length"), "1000")
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).ended.contains(3) })
        // only one POST in flight until the server answers it
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(serverView(raw.sent).order, [1, 3])
        raw.inject(srvFrame(0x1, 0x5, 3, statusBlock(200)))
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).ended.contains(5) })
        // the write completes once less than a whole post is left buffered
        wait(for: [sentDone], timeout: 3)
        raw.inject(srvFrame(0x1, 0x5, 5, statusBlock(200)))
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).ended.contains(7) })
        v = serverView(raw.sent)
        XCTAssertEqual(v.order, [1, 3, 5, 7])
        XCTAssertEqual(header(v.requests[5] ?? [], ":path"), "/pk/\(s.sessionID)/1")
        XCTAssertEqual(header(v.requests[7] ?? [], ":path"), "/pk/\(s.sessionID)/2")
        XCTAssertEqual(v.data[3]?.count, 1000)
        XCTAssertEqual(v.data[5]?.count, 1000)
        XCTAssertEqual(v.data[7]?.count, 500)
        XCTAssertEqual((v.data[3] ?? Data()) + (v.data[5] ?? Data()) + (v.data[7] ?? Data()), payload)
        XCTAssertEqual(s.seq, 3)

        // download bytes flow back; a failed POST status kills the stream
        raw.inject(srvFrame(0x1, 0x4, 1, statusBlock(200)) + srvFrame(0x0, 0, 1, Data("down".utf8)))
        XCTAssertEqual(receiveOne(s).0, Data("down".utf8))
        raw.inject(srvFrame(0x1, 0x5, 7, statusBlock(500)))
        let r = receiveOne(s)
        XCTAssertNil(r.0)
        XCTAssertNotNil(r.1)
        XCTAssertTrue(waitUntil { raw.cancelled })
    }

    func testPacketUpBatchesSmallWritesAndFlushesOnCancel() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["mode": .string("packet-up"),
                                                       "sc-min-posts-interval-ms": .number(20)]))
        let raw = FakeRaw()
        let s = NCXHTTPStream(raw: raw, config: cfg, mode: .packetUp, callerQueue: caller)
        s.start { XCTAssertNil($0) }
        for i in 0..<5 { s.send(Data([UInt8(i)])) }
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).ended.contains(3) })
        XCTAssertEqual(serverView(raw.sent).data[3], Data([0, 1, 2, 3, 4])) // one batched post
        s.send(Data([9, 9]))
        s.cancel() // the pending batch still goes out once the in-flight post is answered
        raw.inject(srvFrame(0x1, 0x5, 3, statusBlock(200)))
        XCTAssertTrue(waitUntil { self.serverView(raw.sent).data[5] == Data([9, 9]) })
        raw.inject(srvFrame(0x1, 0x5, 5, statusBlock(200)))
        XCTAssertTrue(waitUntil { raw.cancelled })
    }

    func testDownloadFlowControlBoundsBuffering() throws {
        let cfg = try NCXHTTPConfig.parse(proxy(opts: ["mode": .string("stream-one")]))
        let raw = FakeRaw()
        let s = NCXHTTPStream(raw: raw, config: cfg, mode: .streamOne, callerQueue: caller, localWindow: 65535)
        s.start { XCTAssertNil($0) }
        var resp = srvFrame(0x1, 0x4, 1, statusBlock(200))
        for _ in 0..<4 { resp.append(srvFrame(0x0, 0, 1, Data(repeating: 5, count: 16000))) }
        raw.inject(resp)
        Thread.sleep(forTimeInterval: 0.1)
        // nothing read yet: no WINDOW_UPDATE went out
        XCTAssertFalse(frames(raw.sent, skipPreface: true).contains { $0.type == 0x8 && $0.sid == 1 })
        for _ in 0..<4 { XCTAssertEqual(receiveOne(s).0?.count, 16000) }
        XCTAssertTrue(waitUntil { self.frames(raw.sent, skipPreface: true).contains { $0.type == 0x8 && $0.sid == 1 } })
        s.cancel()
    }

    // MARK: share links

    func testShareLinkImport() throws {
        let extra = #"{"headers":{"X-A":"1"},"xPaddingBytes":"50-60","noGRPCHeader":true,"scMaxEachPostBytes":50000,"scMinPostsIntervalMs":10,"sessionIDPlacement":"query","xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":30},"downloadSettings":{"address":"dl.example","port":8443,"security":"tls","tlsSettings":{"serverName":"dl.sni"},"xhttpSettings":{"path":"/dl"}}}"#
        let enc = extra.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@x.example:443?encryption=none&security=tls&sni=x.example&type=xhttp&path=%2Fxp&host=cdn.example&mode=packet-up&extra=\(enc)#XH"
        let p = try XCTUnwrap(NCSubscriptionParser.parseURI(link))
        XCTAssertEqual(p.fields["network"]?.string, "xhttp")
        let o = try XCTUnwrap(p.fields["xhttp-opts"]?.object)
        XCTAssertEqual(o["path"]?.string, "/xp")
        XCTAssertEqual(o["host"]?.string, "cdn.example")
        XCTAssertEqual(o["mode"]?.string, "packet-up")
        XCTAssertEqual(o["headers"]?.object?["X-A"]?.string, "1")
        XCTAssertEqual(o["x-padding-bytes"]?.string, "50-60")
        XCTAssertEqual(o["no-grpc-header"]?.bool, true)
        XCTAssertEqual(o["sc-max-each-post-bytes"]?.int, 50000)
        XCTAssertEqual(o["sc-min-posts-interval-ms"]?.int, 10)
        XCTAssertEqual(o["session-placement"]?.string, "query")
        XCTAssertEqual(o["reuse-settings"]?.object?["max-concurrency"]?.string, "16-32")
        XCTAssertEqual(o["reuse-settings"]?.object?["h-keep-alive-period"]?.int, 30)
        let ds = try XCTUnwrap(o["download-settings"]?.object)
        XCTAssertEqual(ds["server"]?.string, "dl.example")
        XCTAssertEqual(ds["port"]?.int, 8443)
        XCTAssertEqual(ds["tls"]?.bool, true)
        XCTAssertEqual(ds["servername"]?.string, "dl.sni")
        XCTAssertEqual(ds["path"]?.string, "/dl")

        // Xray's old name, and Trojan
        let sp = try XCTUnwrap(NCSubscriptionParser.parseURI("vless://b831381d-6324-4d53-ad4f-8cda48b30811@x.example:443?type=splithttp&path=%2Fs#S"))
        XCTAssertEqual(sp.fields["network"]?.string, "xhttp")
        XCTAssertEqual(sp.fields["xhttp-opts"]?.object?["path"]?.string, "/s")
        let tj = try XCTUnwrap(NCSubscriptionParser.parseURI("trojan://pw@t.example:443?sni=t.example&type=xhttp&path=%2Ft&mode=stream-up#T"))
        XCTAssertEqual(tj.fields["network"]?.string, "xhttp")
        XCTAssertEqual(tj.fields["xhttp-opts"]?.object?["mode"]?.string, "stream-up")

        // vmess JSON: mode rides in "type"
        let vm = #"{"v":"2","ps":"VX","add":"v.example","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"xhttp","type":"stream-one","host":"h.example","path":"/v","tls":"tls"}"#
        let vp = try XCTUnwrap(NCSubscriptionParser.parseURI("vmess://" + Data(vm.utf8).base64EncodedString()))
        XCTAssertEqual(vp.fields["network"]?.string, "xhttp")
        XCTAssertEqual(vp.fields["xhttp-opts"]?.object?["mode"]?.string, "stream-one")
        XCTAssertEqual(vp.fields["xhttp-opts"]?.object?["host"]?.string, "h.example")
    }

    func testShareLinkExportImportRoundTrip() throws {
        for type in ["vless", "trojan", "vmess"] {
            let node = proxy(type, opts: ["path": .string("/rt"), "host": .string("cdn.rt"), "mode": .string("stream-up")],
                             extra: ["servername": .string("rt.example"), "sni": .string("rt.example")])
            let link = try NCShareLink.encode(node)
            let back = try XCTUnwrap(NCSubscriptionParser.parseURI(link), link)
            XCTAssertEqual(back.fields["network"]?.string, "xhttp", type)
            let o = back.fields["xhttp-opts"]?.object
            XCTAssertEqual(o?["path"]?.string, "/rt", type)
            XCTAssertEqual(o?["host"]?.string, "cdn.rt", type)
            XCTAssertEqual(o?["mode"]?.string, "stream-up", type)
        }
    }

    // MARK: support gate

    func testSupportGate() {
        XCTAssertTrue(NCSupport.transports.contains("xhttp"))
        XCTAssertNil(NCSupport.unsupportedReason(proxy()))
        XCTAssertNil(NCSupport.unsupportedReason(proxy("vmess", extra: ["cipher": .string("auto"), "alterId": .number(0)])))
        XCTAssertNil(NCSupport.unsupportedReason(proxy("trojan")))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy(opts: ["download-settings": .object(["server": .string("d")])])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy(extra: ["alpn": .array([.string("h3")])])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy(extra: ["alpn": .array([.string("http/1.1")])])))
        XCTAssertNil(NCSupport.unsupportedReason(proxy(extra: ["alpn": .array([.string("h2"), .string("http/1.1")])])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy(opts: ["mode": .string("stream-two")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(proxy(extra: ["network": .string("splithttp")])))
    }
}
