import XCTest
@testable import Mihomo

/// Native MitM stage 2 lane `http` (B8a): PacketTunnel/NativeMitM/HTTP. Every stream is also fed split at every byte
/// position, one byte at a time, and in seeded random chunks — the normalized event list must not change.
final class NativeMitmHTTPTests: XCTestCase {

    // MARK: - Harness

    private func d(_ s: String) -> Data { Data(s.utf8) }

    /// Normalized view: body pieces merged, upgrade + passthrough merged into one raw tail.
    private enum N: Equatable {
        case req(String, [String], Data, HTTPBodyFraming)
        case resp(String, [String], Data, HTTPBodyFraming)
        case interim(String)
        case body(Data)
        case trailers([String])
        case end(Bool)
        case upgradeRequested
        case raw(Data)
    }

    private func fields(_ h: HTTPHeaderList) -> [String] { h.map { "\($0.name)=\($0.value)" } }

    private func normalize(_ evs: [HTTPParserEvent]) -> [N] {
        var out: [N] = []
        for e in evs {
            let n: N
            switch e {
            case let .request(h, f): n = .req(h.rawStartLine, fields(h.headers), h.rawBytes, f)
            case let .response(h, f): n = .resp(h.rawStartLine, fields(h.headers), h.rawBytes, f)
            case let .interim(h): n = .interim(h.rawStartLine)
            case let .body(b): n = .body(b)
            case let .trailers(t, _): n = .trailers(fields(t))
            case let .end(k): n = .end(k)
            case .upgradeRequested: n = .upgradeRequested
            case let .upgrade(b), let .passthrough(b): n = .raw(b)
            }
            switch (out.last, n) {
            case let (.body(a)?, .body(b)): out[out.count - 1] = .body(a + b)
            case let (.raw(a)?, .raw(b)): out[out.count - 1] = .raw(a + b)
            default: out.append(n)
            }
        }
        return out
    }

    private struct Run: Equatable {
        var events: [N]
        var error: HTTPParseError?
    }

    private func run(_ role: HTTPParser.Role, _ chunks: [Data], methods: [String] = [], mode: HTTPParser.BodyMode = .decoded,
                     limits: HTTPParserLimits = HTTPParserLimits(), eof: Bool = true) -> Run {
        let p = HTTPParser(role: role, limits: limits, bodyMode: mode)
        methods.forEach { p.expectResponse(toMethod: $0) }
        var evs: [HTTPParserEvent] = []
        do {
            for c in chunks { evs += try p.feed(c) }
            if eof { evs += try p.finish() }
        } catch let e as HTTPParseError {
            return Run(events: [], error: e)
        } catch {
            XCTFail("unexpected \(error)")
        }
        return Run(events: normalize(evs), error: nil)
    }

    private struct LCG {
        var s: UInt64
        mutating func next() -> UInt64 { s = s &* 6364136223846793005 &+ 1442695040888963407; return s >> 33 }
        mutating func below(_ n: Int) -> Int { Int(next() % UInt64(max(n, 1))) }
    }

    /// Same result for whole / every 2-way split / bytewise / random chunking.
    @discardableResult
    private func assertSplitInvariant(_ role: HTTPParser.Role, _ stream: Data, methods: [String] = [],
                                      mode: HTTPParser.BodyMode = .decoded, file: StaticString = #filePath,
                                      line: UInt = #line) -> Run {
        let whole = run(role, [stream], methods: methods, mode: mode)
        for cut in 0...stream.count {
            let r = run(role, [stream.prefix(cut), stream.dropFirst(cut)].map { Data($0) }, methods: methods, mode: mode)
            XCTAssertEqual(r, whole, "split at \(cut)", file: file, line: line)
            if r != whole { break }
        }
        let bytes = stream.map { Data([$0]) }
        XCTAssertEqual(run(role, bytes, methods: methods, mode: mode), whole, "bytewise", file: file, line: line)
        var rng = LCG(s: UInt64(stream.count) &+ 7)
        for _ in 0..<20 {
            var chunks: [Data] = []
            var i = 0
            while i < stream.count {
                let n = 1 + rng.below(64)
                chunks.append(stream.subdata(in: i..<min(stream.count, i + n)))
                i += n
            }
            XCTAssertEqual(run(role, chunks, methods: methods, mode: mode), whole, "random chunks", file: file, line: line)
        }
        return whole
    }

    // MARK: - Requests

    private let pipelined =
        "GET /a?x=1 HTTP/1.1\r\nHost: api.example.com\r\nx-Lower: v\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n" +
        "POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 11\r\n\r\nhello world" +
        "PUT /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n" +
        "5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: abc\r\n\r\n" +
        "GET /last HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"

    func testPipelinedRequestsPreserveBytesAndOrder() throws {
        let r = assertSplitInvariant(.request, d(pipelined))
        XCTAssertNil(r.error)
        let starts = r.events.compactMap { e -> String? in if case let .req(s, _, _, _) = e { return s }; return nil }
        XCTAssertEqual(starts, ["GET /a?x=1 HTTP/1.1", "POST /upload HTTP/1.1", "PUT /c HTTP/1.1", "GET /last HTTP/1.1"])
        guard case let .req(_, f, raw, framing) = r.events[0] else { return XCTFail() }
        XCTAssertEqual(f, ["Host=api.example.com", "x-Lower=v", "X-Dup=1", "X-Dup=2"])
        XCTAssertEqual(raw, d("GET /a?x=1 HTTP/1.1\r\nHost: api.example.com\r\nx-Lower: v\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\n"))
        XCTAssertEqual(framing, HTTPBodyFraming.none)
        XCTAssertTrue(r.events.contains(.body(d("hello world"))))
        XCTAssertTrue(r.events.contains(.trailers(["X-Checksum=abc"])))
        XCTAssertEqual(r.events.filter { $0 == .end(true) }.count, 3)
        XCTAssertEqual(r.events.last, .end(false))
    }

    func testRawModeReproducesStreamExactly() throws {
        let p = HTTPParser(role: .request, bodyMode: .raw)
        var out = Data()
        for b in d(pipelined) {
            for e in try p.feed(Data([b])) {
                switch e {
                case let .request(h, _): out += try h.serialized()
                case let .body(b): out += b
                default: break
                }
            }
        }
        XCTAssertEqual(out, d(pipelined))
        assertSplitInvariant(.request, d(pipelined), mode: .raw)
    }

    func testPristineHeadSerializesOriginalBytesAndModifiedRebuilds() throws {
        let raw = "GET  /x HTTP/1.1\r\nHost:h\r\n\r\n"   // double space: target " /x" is rejected
        XCTAssertNotNil(run(.request, [d(raw)]).error)
        let src = "GET /x HTTP/1.1\r\nhost:   h  \r\nAccept:*/*\r\n\r\n"
        let p = HTTPParser(role: .request)
        guard case let .request(head, _)? = try p.feed(d(src)).first else { return XCTFail() }
        XCTAssertFalse(head.isModified)
        XCTAssertEqual(try head.serialized(), d(src))            // odd whitespace survives untouched
        XCTAssertEqual(head.value(for: "HOST"), "h")
        var m = head
        m.setHeader("Accept", "text/html")
        m.addHeader("X-Tern", "1")
        m.setStartLine(target: "/y")
        XCTAssertTrue(m.isModified)
        XCTAssertEqual(try m.serialized(), d("GET /y HTTP/1.1\r\nhost: h\r\nAccept: text/html\r\nX-Tern: 1\r\n\r\n"))
        m.removeHeader("ACCEPT")
        XCTAssertEqual(m.headers.map { $0.name }, ["host", "X-Tern"])
        m.setHeader("X-Bad", "a\r\nInjected: 1")
        XCTAssertThrowsError(try m.serialized())
    }

    func testObsTextValueRoundTripsByteForByte() throws {
        var src = d("GET / HTTP/1.1\r\nHost: h\r\nContent-Disposition: attachment; filename=\"")
        src += Data([0xE9, 0xFF, 0x80, 0xC3, 0xA9])
        src += d("\"\r\n\r\n")
        let p = HTTPParser(role: .request)
        guard case let .request(head, _)? = try p.feed(src).first else { return XCTFail() }
        XCTAssertEqual(try head.serialized(), src)
        var m = head
        m.addHeader("X", "y")
        let out = try m.serialized()
        XCTAssertNotNil(out.range(of: Data([0xE9, 0xFF, 0x80, 0xC3, 0xA9])))
    }

    func testLeadingEmptyLinesBeforeRequestAreIgnored() throws {
        let r = assertSplitInvariant(.request, d("\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"))
        guard case let .req(_, _, raw, _)? = r.events.first else { return XCTFail() }
        XCTAssertEqual(raw, d("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
    }

    func testBareLFLinesAccepted() {
        let r = assertSplitInvariant(.request, d("GET / HTTP/1.1\nHost: h\n\n"))
        XCTAssertNil(r.error)
        XCTAssertEqual(r.events.last, .end(true))
    }

    func testKeepAliveRules() {
        func ka(_ s: String) -> Bool? {
            if case .end(let k)? = run(.request, [d(s)]).events.last { return k }; return nil
        }
        XCTAssertEqual(ka("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), true)
        XCTAssertEqual(ka("GET / HTTP/1.1\r\nConnection: Keep-Alive, CLOSE\r\n\r\n"), false)
        XCTAssertEqual(ka("GET / HTTP/1.0\r\n\r\n"), false)
        XCTAssertEqual(ka("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"), true)
        let resp = run(.response, [d("HTTP/1.1 200 OK\r\n\r\nstream until close")])
        XCTAssertEqual(resp.events.suffix(2), [.body(d("stream until close")), .end(false)])
    }

    func testExpectContinue() throws {
        let p = HTTPParser(role: .request)
        let evs = try p.feed(d("POST /u HTTP/1.1\r\nHost: h\r\nExpect: 100-Continue\r\nContent-Length: 3\r\n\r\n"))
        guard case let .request(head, framing)? = evs.first else { return XCTFail() }
        XCTAssertTrue(head.expectsContinue)
        XCTAssertEqual(framing, .contentLength(3))
        XCTAssertEqual(evs.count, 1)                       // body not here yet: caller may send 100 Continue
        XCTAssertEqual(try p.feed(d("abc")), [.body(d("abc")), .end(keepAlive: true)])
        XCTAssertEqual(HTTPResponseHead.continueBytes, d("HTTP/1.1 100 Continue\r\n\r\n"))
    }

    // MARK: - Responses

    func testResponseFramingByMethodAndStatus() {
        let stream =
            "HTTP/1.1 100 Continue\r\n\r\n" +
            "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody" +
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" +                    // HEAD: no body
            "HTTP/1.1 204 No Content\r\n\r\n" +
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 3\r\n\r\n" +
            "3\r\nabc\r\n0\r\n\r\n" +
            "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n" +
            "HTTP/1.0 200 OK\r\n\r\ntail"
        let methods = ["POST", "HEAD", "GET", "GET", "GET", "GET", "GET"]
        let r = assertSplitInvariant(.response, d(stream), methods: methods)
        XCTAssertNil(r.error)
        let framings = r.events.compactMap { e -> HTTPBodyFraming? in if case let .resp(_, _, _, f) = e { return f }; return nil }
        XCTAssertEqual(framings, [.contentLength(4), .none, .none, .none, .chunked, .contentLength(0), .untilClose])
        XCTAssertEqual(r.events.prefix(2), [.interim("HTTP/1.1 100 Continue"), .interim("HTTP/1.1 103 Early Hints")])
        XCTAssertTrue(r.events.contains(.body(d("abc"))))
        XCTAssertEqual(r.events.suffix(2), [.body(d("tail")), .end(false)])
    }

    func testResponseHeadAccessors() throws {
        let p = HTTPParser(role: .response)
        guard case let .response(h, _)? = try p.feed(d("HTTP/1.1 404 Not Found Here\r\nContent-Length: 0\r\n\r\n")).first
        else { return XCTFail() }
        XCTAssertEqual(h.status, 404)
        XCTAssertEqual(h.reason, "Not Found Here")
        XCTAssertEqual(h.version, "HTTP/1.1")
        var m = HTTPResponseHead(status: 200, reason: "OK", headers: [("Content-Length", "2")])
        m.addHeader("Set-Cookie", "a=1")
        m.addHeader("Set-Cookie", "b=2")
        XCTAssertEqual(try m.serialized(), d("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"))
    }

    // MARK: - Upgrade / CONNECT

    func testWebSocketUpgradeAcceptedAndRejected() throws {
        let req = "GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        let p = HTTPParser(role: .request)
        let evs = try p.feed(d(req + "\u{81}\u{05}frame"))
        XCTAssertEqual(Array(evs.dropFirst()), [.end(keepAlive: true), .upgradeRequested])
        XCTAssertEqual(try p.feed(d("more")), [])
        XCTAssertEqual(p.acceptUpgrade(), d("\u{81}\u{05}framemore"))
        XCTAssertTrue(p.isPassthrough)
        XCTAssertEqual(try p.feed(d("x")), [.passthrough(d("x"))])

        let q = HTTPParser(role: .request)
        _ = try q.feed(d(req + "GET /next HTTP/1.1\r\nHost: h\r\n\r\n"))
        let resumed = try q.rejectUpgrade()
        guard case let .request(h, _)? = resumed.first else { return XCTFail() }
        XCTAssertEqual(h.target, "/next")
        XCTAssertEqual(resumed.last, .end(keepAlive: true))
    }

    func testConnectRequestAndResponses() throws {
        let p = HTTPParser(role: .request)
        let evs = try p.feed(d("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\u{16}\u{03}"))
        guard case let .request(h, f)? = evs.first else { return XCTFail() }
        XCTAssertTrue(h.isConnect && h.requestsUpgrade)
        XCTAssertEqual(f, HTTPBodyFraming.none)
        XCTAssertEqual(p.acceptUpgrade(), d("\u{16}\u{03}"))

        let r = assertSplitInvariant(.response, d("HTTP/1.1 200 Connection Established\r\n\r\nTLSBYTES"), methods: ["CONNECT"])
        XCTAssertEqual(r.events.last, .raw(d("TLSBYTES")))
        let ws = assertSplitInvariant(.response, d("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nWS"))
        XCTAssertEqual(ws.events.last, .raw(d("WS")))
        // CONNECT refused: normal framed response.
        let no = run(.response, [d("HTTP/1.1 407 Auth\r\nContent-Length: 2\r\n\r\nno")], methods: ["CONNECT"])
        XCTAssertEqual(no.events.suffix(2), [.body(d("no")), .end(true)])
    }

    // MARK: - Errors & limits

    func testMalformedInputsFailClosed() {
        let cases: [(String, HTTPParser.Role, HTTPParseError)] = [
            ("GET / HTTP/1.1\r\n Host: h\r\n\r\n", .request, .obsFold),
            ("GET / HTTP/1.1\r\nHost : h\r\n\r\n", .request, .malformedHeaderLine),
            ("GET / HTTP/1.1\r\n: h\r\n\r\n", .request, .malformedHeaderLine),
            ("GET / HTTP/1.1\r\nNoColon\r\n\r\n", .request, .malformedHeaderLine),
            ("GET / HTTP/1.1\r\nX: a\u{01}b\r\n\r\n", .request, .invalidHeaderValue),
            ("GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", .request, .bareCR),
            ("GET / HTTP/2.0\r\n\r\n", .request, .unsupportedVersion),
            ("GET / HTTX/1.1\r\n\r\n", .request, .malformedStartLine),
            ("GET /\r\n\r\n", .request, .malformedStartLine),
            ("G(T / HTTP/1.1\r\n\r\n", .request, .malformedStartLine),
            ("POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n", .request, .badContentLength),
            ("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", .request, .badContentLength),
            ("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", .request, .badContentLength),
            ("POST / HTTP/1.1\r\nContent-Length: 3, 4\r\n\r\n", .request, .badContentLength),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", .request, .conflictingFraming),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", .request, .unsupportedTransferEncoding),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", .request, .unsupportedTransferEncoding),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", .request, .badChunkSize),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\r\n", .request, .badChunkSize),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1000000000000000\r\n", .request, .badChunkSize),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n", .request, .badChunkTerminator),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 x\r\n", .request, .badChunkSize),
            ("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort", .request, .unexpectedEOF),
            ("GET / HTTP/1.1\r\nHost: h\r\n", .request, .unexpectedEOF),
            ("HTTP/1.1 2000 OK\r\n\r\n", .response, .malformedStartLine),
            ("HTTP/1.1 099 x\r\n\r\n", .response, .malformedStartLine),
            ("HTTP/1.1 200OK\r\n\r\n", .response, .malformedStartLine),
            ("\r\nHTTP/1.1 200 OK\r\n\r\n", .response, .malformedStartLine),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", .response, .unexpectedEOF),
        ]
        for (s, role, want) in cases {
            for chunking in [[d(s)], d(s).map { Data([$0]) }] {
                XCTAssertEqual(run(role, chunking).error, want, s.debugDescription)
            }
        }
    }

    func testErrorsAreSticky() {
        let p = HTTPParser(role: .request)
        XCTAssertThrowsError(try p.feed(d("BAD\r\n\r\n")))
        XCTAssertThrowsError(try p.feed(d("GET / HTTP/1.1\r\n\r\n"))) { XCTAssertEqual($0 as? HTTPParseError, .malformedStartLine) }
        XCTAssertThrowsError(try p.finish())
    }

    func testHeadAndLineLimits() {
        let big = String(repeating: "a", count: 17 << 10)
        XCTAssertEqual(run(.request, [d("GET / HTTP/1.1\r\nX: \(big)\r\n\r\n")]).error, .lineTooLong(limit: 16 << 10))
        XCTAssertEqual(run(.request, [d("GET / HTTP/1.1\r\nX: \(big)")], eof: false).error, .lineTooLong(limit: 16 << 10))
        let many = (0..<9).map { "X-\($0): \(String(repeating: "b", count: 8000))\r\n" }.joined()
        XCTAssertEqual(run(.request, [d("GET / HTTP/1.1\r\n\(many)\r\n")]).error, .headTooLarge(limit: 64 << 10))
        XCTAssertEqual(run(.request, [d("GET / HTTP/1.1\r\n\(many)")], eof: false).error, .headTooLarge(limit: 64 << 10))
        var lim = HTTPParserLimits()
        lim.maxHeaderCount = 3
        XCTAssertEqual(run(.request, [d("GET / HTTP/1.1\r\na: 1\r\nb: 1\r\nc: 1\r\nd: 1\r\n\r\n")], limits: lim).error,
                       .tooManyHeaders(limit: 3))
        XCTAssertNil(run(.request, [d("GET / HTTP/1.1\r\na: 1\r\nb: 1\r\nc: 1\r\n\r\n")], limits: lim).error)
        lim = HTTPParserLimits()
        lim.maxTrailerBytes = 16
        XCTAssertEqual(run(.request, [d("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Long-Trailer: 123456\r\n\r\n")],
                           limits: lim).error, .trailersTooLarge(limit: 16))
        // Exactly at the limit is fine.
        lim = HTTPParserLimits()
        let head = "GET / HTTP/1.1\r\nX: "
        let pad = String(repeating: "c", count: (64 << 10) - head.utf8.count - 4)
        let exact = head + pad + "\r\n\r\n"
        XCTAssertEqual(exact.utf8.count, 64 << 10)
        lim.maxLineBytes = 64 << 10
        XCTAssertNil(run(.request, [d(exact)], limits: lim).error)
    }

    // MARK: - Zero copy, slices, big bodies

    func testBodyIsCallersDataWhenWholeReadIsBody() throws {
        let p = HTTPParser(role: .response)
        _ = try p.feed(d("HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\n"))
        let chunk = Data(repeating: 0x5A, count: 100_000)
        let evs = try p.feed(chunk)
        guard case let .body(b)? = evs.first else { return XCTFail() }
        XCTAssertEqual(b.count, 100_000)
        chunk.withUnsafeBytes { a in b.withUnsafeBytes { c in XCTAssertEqual(a.baseAddress, c.baseAddress) } }
        // A slice with non-zero startIndex is accepted and indexed correctly.
        let backing = d("zzzz") + Data(repeating: 0x41, count: 200_000) + d("HTTP/1.1 204 No Content\r\n\r\n")
        let slice = backing[4...]
        let evs2 = try p.feed(slice)
        XCTAssertEqual(evs2.first, .body(Data(repeating: 0x41, count: 200_000)))
        XCTAssertEqual(evs2.dropFirst().first, .end(keepAlive: true))
        guard case let .response(h, f)? = evs2.dropFirst(2).first else { return XCTFail() }
        XCTAssertEqual(h.status, 204)
        XCTAssertEqual(f, HTTPBodyFraming.none)
        XCTAssertEqual(p.bufferedByteCount, 0)
    }

    func testLargeChunkedBodyInRandomChunks() {
        var rng = LCG(s: 42)
        var payload = Data()
        var wire = d("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        for _ in 0..<50 {
            let n = 1 + rng.below(5000)
            let piece = Data((0..<n).map { _ in UInt8(rng.below(256)) })
            payload += piece
            wire += HTTPChunkedEncoder.chunk(piece)
        }
        wire += (try? HTTPChunkedEncoder.lastChunk(trailers: [("Server-Timing", "x;dur=1")])) ?? Data()
        var chunks: [Data] = []
        var i = 0
        while i < wire.count { let n = 1 + rng.below(9000); chunks.append(wire.subdata(in: i..<min(wire.count, i + n))); i += n }
        let r = run(.response, chunks)
        XCTAssertNil(r.error)
        XCTAssertTrue(r.events.contains(.body(payload)))
        XCTAssertTrue(r.events.contains(.trailers(["Server-Timing=x;dur=1"])))
        XCTAssertEqual(r.events.last, .end(true))
    }

    func testChunkedEncoderEdgeCases() throws {
        XCTAssertEqual(HTTPChunkedEncoder.chunk(Data()), Data())
        XCTAssertEqual(HTTPChunkedEncoder.chunk(d("0123456789abcdefX")), d("11\r\n0123456789abcdefX\r\n"))
        XCTAssertEqual(try HTTPChunkedEncoder.lastChunk(), d("0\r\n\r\n"))
        XCTAssertThrowsError(try HTTPChunkedEncoder.lastChunk(trailers: [("Bad Name", "v")]))
    }

    // MARK: - Fuzz-ish

    /// Byte mutations / truncations of valid streams: never crash, and whole vs bytewise feeding agree exactly.
    func testMutationFuzzSplitAgreement() {
        let seeds: [(HTTPParser.Role, String, [String])] = [
            (.request, pipelined, []),
            (.response, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\nT: 1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", ["POST", "GET"]),
            (.response, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\nraw", []),
        ]
        var rng = LCG(s: 0xC0FFEE)
        let interesting: [UInt8] = Array("\r\n :;0aZ\t\u{7f}".utf8) + [0x00, 0xFF]
        for (role, s, methods) in seeds {
            let base = d(s)
            for _ in 0..<300 {
                var m = [UInt8](base)
                for _ in 0..<(1 + rng.below(3)) {
                    switch rng.below(3) {
                    case 0: m[rng.below(m.count)] = interesting[rng.below(interesting.count)]
                    case 1: m.remove(at: rng.below(m.count))
                    default: m.insert(interesting[rng.below(interesting.count)], at: rng.below(m.count))
                    }
                }
                if rng.below(5) == 0 { m = Array(m.prefix(rng.below(m.count))) }
                let data = Data(m)
                let whole = run(role, [data], methods: methods)
                let bytewise = run(role, data.map { Data([$0]) }, methods: methods)
                XCTAssertEqual(whole, bytewise, "mutated: \(String(decoding: data, as: UTF8.self).debugDescription)")
            }
        }
    }

    // MARK: - Header rewrite (port of astemo6's draft HeaderRewrite, fixed)

    func testHeaderRewriteRejectsCRLFPair() {
        var h = HTTPRequestHead(method: "GET", target: "/", headers: [("Host", "h")])
        // "\r\n" is one Character: the draft's String.contains("\r") let this through.
        XCTAssertThrowsError(try HTTPHeaderRewrite.apply([.set(name: "X", value: "a\r\nInjected: 1")], to: &h))
        XCTAssertThrowsError(try HTTPHeaderRewrite.apply([.add(name: "X", value: "a\u{0}")], to: &h))
        XCTAssertThrowsError(try HTTPHeaderRewrite.apply([.remove(name: "Bad Name")], to: &h))
        XCTAssertNoThrow(try HTTPHeaderRewrite.apply([.set(name: "host", value: "x"), .add(name: "A", value: "1\t2"),
                                                     .remove(name: "nope")], to: &h))
        XCTAssertEqual(fields(h.headers), ["host=x", "A=1\t2"])
    }

    func testStripHopByHop() throws {
        let src = "GET /ws HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, X-Secret\r\nConnection: Upgrade\r\n" +
            "X-Secret: 1\r\nKeep-Alive: 5\r\nTE: trailers, gzip\r\nProxy-Authenticate: x\r\nUpgrade: websocket\r\nA: b\r\n\r\n"
        guard case var .request(h, _)? = try HTTPParser(role: .request).feed(d(src)).first else { return XCTFail() }
        var u = h
        HTTPHeaderRewrite.stripHopByHop(&h)
        XCTAssertEqual(fields(h.headers), ["Host=h", "A=b", "Te=trailers"])
        HTTPHeaderRewrite.stripHopByHop(&u, keepUpgrade: true)
        XCTAssertEqual(fields(u.headers), ["Host=h", "A=b", "Te=trailers", "Connection=Upgrade", "Upgrade=websocket"])
        // Nothing to strip: head stays pristine (original bytes).
        guard case var .request(p, _)? = try HTTPParser(role: .request).feed(d("GET / HTTP/1.1\r\nHost: h\r\n\r\n")).first
        else { return XCTFail() }
        HTTPHeaderRewrite.stripHopByHop(&p)
        XCTAssertFalse(p.isModified)
    }
}
