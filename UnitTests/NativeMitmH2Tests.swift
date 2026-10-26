import Foundation
import XCTest
@testable import Mihomo

/// Native MitM stage 3 lane s3-h2: HPACK (RFC 7541 Appendix C + the old core hpack fixtures), the frame codec (the old core Framer
/// fixtures), H2Connection (flow control, back-pressure, limits, protocol errors) over in-memory streams, and
/// NativeH2Session end to end with a scripted flow driver and in-memory h2 / HTTP/1.1 origins.
/// Pure Foundation: also runs on Linux (work/s3h2/build.sh). The the old core loopback comparison is
/// NativeMitmH2LoopbackTests.
final class NativeMitmH2Tests: XCTestCase {

    // MARK: helpers

    static func hex(_ s: String) -> [UInt8] {
        let c = Array(s.replacingOccurrences(of: " ", with: "").utf8)
        var out: [UInt8] = []
        var i = 0
        while i + 1 < c.count {
            out.append(UInt8(String(decoding: c[i...i + 1], as: UTF8.self), radix: 16)!)
            i += 2
        }
        return out
    }
    static func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    static func same(_ a: HTTPHeaderList, _ b: [(String, String)], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(a.map { "\($0.name): \($0.value)" }, b.map { "\($0.0): \($0.1)" }, file: file, line: line)
    }

    private func fixtures() throws -> [String: Any] {
        var url = Bundle(for: NativeMitmH2Tests.self).url(forResource: "NativeMitmH2Fixtures", withExtension: "json")
        if url == nil, let p = ProcessInfo.processInfo.environment["H2_FIXTURES"] { url = URL(fileURLWithPath: p) }
        let u = try XCTUnwrap(url, "NativeMitmH2Fixtures.json missing")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: u)) as? [String: Any])
    }

    // MARK: - HPACK primitives (RFC 7541 C.1, C.4.1)

    func testIntegerRepresentationRFC() throws {
        var out: [UInt8] = []
        HPACKPrimitive.encodeInt(10, prefix: 5, flags: 0, into: &out)
        XCTAssertEqual(out, [0x0a])
        out = []
        HPACKPrimitive.encodeInt(1337, prefix: 5, flags: 0, into: &out)
        XCTAssertEqual(out, [0x1f, 0x9a, 0x0a])
        out = []
        HPACKPrimitive.encodeInt(42, prefix: 8, flags: 0, into: &out)
        XCTAssertEqual(out, [0x2a])
        var i = 0
        XCTAssertEqual(try HPACKPrimitive.decodeInt([0x1f, 0x9a, 0x0a], &i, prefix: 5), 1337)
        XCTAssertEqual(i, 3)
        i = 0
        XCTAssertThrowsError(try HPACKPrimitive.decodeInt([0x1f, 0x9a], &i, prefix: 5))
        i = 0
        XCTAssertThrowsError(try HPACKPrimitive.decodeInt([0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], &i, prefix: 5))
    }

    func testHuffmanRFCAndRoundTrip() throws {
        var out: [UInt8] = []
        HPACKHuffman.encode(Array("www.example.com".utf8), into: &out)
        XCTAssertEqual(Self.hexString(out), "f1e3c2e5f23a6ba0ab90f4ff")
        XCTAssertEqual(try HPACKHuffman.decode(out), Array("www.example.com".utf8))
        out = []
        HPACKHuffman.encode(Array("no-cache".utf8), into: &out)
        XCTAssertEqual(Self.hexString(out), "a8eb10649cbf")
        // every byte value, several lengths (padding at every bit position)
        for n in 0..<24 {
            let s = (0..<(n * 11 + 1)).map { UInt8(($0 * 37 + n) % 256) }
            var e: [UInt8] = []
            HPACKHuffman.encode(s, into: &e)
            XCTAssertEqual(e.count, HPACKHuffman.encodedLength(s))
            XCTAssertEqual(try HPACKHuffman.decode(e), s)
        }
        XCTAssertThrowsError(try HPACKHuffman.decode([0xff, 0xff, 0xff, 0xff])) // EOS / > 7 bits of padding
        XCTAssertThrowsError(try HPACKHuffman.decode([0x00]))                   // padding not all ones ('0' = 00000, then 000)
    }

    // MARK: - HPACK RFC 7541 Appendix C

    /// Decodes each block with one decoder, encodes the same fields with one encoder (Huffman as the RFC example
    /// does), and checks both against the RFC bytes and table sizes.
    private func rfcSequence(_ blocks: [(hex: String, fields: [(String, String)], size: Int)], tableSize: Int, huffman: Bool,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let dec = HPACKDecoder(maxTableSize: tableSize)
        let enc = HPACKEncoder(maxTableSize: tableSize)
        enc.huffman = huffman ? .always : .never
        enc.neverIndex = []
        for (i, b) in blocks.enumerated() {
            let got = try dec.decode(Self.hex(b.hex))
            Self.same(got, b.fields, file: file, line: line)
            XCTAssertEqual(dec.table.size, b.size, "decoder table after block \(i)", file: file, line: line)
            let bytes = enc.encode(b.fields.map { (name: $0.0, value: $0.1) })
            XCTAssertEqual(Self.hexString(bytes), b.hex.replacingOccurrences(of: " ", with: ""), "encoder block \(i)", file: file, line: line)
            XCTAssertEqual(enc.table.size, b.size, "encoder table after block \(i)", file: file, line: line)
        }
    }

    func testRFC7541C2LiteralForms() throws {
        let d = HPACKDecoder()
        Self.same(try d.decode(Self.hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572")), [("custom-key", "custom-header")])
        XCTAssertEqual(d.table.size, 55)
        let d2 = HPACKDecoder()
        Self.same(try d2.decode(Self.hex("040c 2f73 616d 706c 652f 7061 7468")), [(":path", "/sample/path")])
        XCTAssertEqual(d2.table.size, 0)
        Self.same(try d2.decode(Self.hex("1008 7061 7373 776f 7264 0673 6563 7265 74")), [("password", "secret")])
        XCTAssertEqual(d2.table.size, 0)
        Self.same(try d2.decode([0x82]), [(":method", "GET")])
        // never-indexed output for credentials
        let e = HPACKEncoder()
        e.huffman = .never
        XCTAssertEqual(Self.hexString(e.encode([("authorization", "x")])), "1f080178") // 0x10 | 15 → name index 23
        XCTAssertEqual(e.table.size, 0)
    }

    func testRFC7541C3RequestsWithoutHuffman() throws {
        try rfcSequence([
            ("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
             [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")], 57),
            ("8286 84be 5808 6e6f 2d63 6163 6865",
             [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")], 110),
            ("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
             [(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "www.example.com"), ("custom-key", "custom-value")], 164),
        ], tableSize: 4096, huffman: false)
    }

    func testRFC7541C4RequestsWithHuffman() throws {
        try rfcSequence([
            ("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
             [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")], 57),
            ("8286 84be 5886 a8eb 1064 9cbf",
             [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")], 110),
            ("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
             [(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "www.example.com"), ("custom-key", "custom-value")], 164),
        ], tableSize: 4096, huffman: true)
    }

    private static let c5Fields: [[(String, String)]] = [
        [(":status", "302"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")],
        [(":status", "307"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")],
        [(":status", "200"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT"), ("location", "https://www.example.com"),
         ("content-encoding", "gzip"), ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")],
    ]

    func testRFC7541C5ResponsesWithoutHuffmanEviction() throws {
        try rfcSequence([
            ("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
             Self.c5Fields[0], 222),
            ("4803 3330 37c1 c0bf", Self.c5Fields[1], 222),
            ("88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
             Self.c5Fields[2], 215),
        ], tableSize: 256, huffman: false)
    }

    func testRFC7541C6ResponsesWithHuffmanEviction() throws {
        try rfcSequence([
            ("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
             Self.c5Fields[0], 222),
            ("4883 640e ffc1 c0bf", Self.c5Fields[1], 222),
            ("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
             Self.c5Fields[2], 215),
        ], tableSize: 256, huffman: true)
    }

    func testHPACKGoEncoderFixtures() throws {
        let fx = try fixtures()
        let seqs = try XCTUnwrap(fx["hpack"] as? [[String: Any]])
        XCTAssertEqual(seqs.count, 2)
        for seq in seqs {
            let dec = HPACKDecoder(maxTableSize: seq["tableSize"] as? Int ?? 4096)
            for b in try XCTUnwrap(seq["blocks"] as? [[String: Any]]) {
                let want = try XCTUnwrap(b["fields"] as? [[String]]).map { ($0[0], $0[1]) }
                let got = try dec.decode(Self.hex(try XCTUnwrap(b["hex"] as? String)))
                Self.same(got, want)
                // our encoder's output decodes to the same list in a fresh decoder pair
                let enc = HPACKEncoder(), d2 = HPACKDecoder()
                Self.same(try d2.decode(enc.encode(got)), want)
            }
        }
    }

    func testHPACKErrorsAndLimits() throws {
        XCTAssertThrowsError(try HPACKDecoder().decode([0x80])) { XCTAssertEqual($0 as? HPACKError, .badIndex(0)) }
        XCTAssertThrowsError(try HPACKDecoder().decode([0xbe])) { XCTAssertEqual($0 as? HPACKError, .badIndex(62)) } // empty dynamic table
        XCTAssertThrowsError(try HPACKDecoder().decode([0x40, 0x05, 0x61])) { XCTAssertEqual($0 as? HPACKError, .truncated) }
        XCTAssertThrowsError(try HPACKDecoder().decode([0x3f, 0xe2, 0x1f])) { XCTAssertEqual($0 as? HPACKError, .tableSizeUpdate) } // 4097 > 4096
        XCTAssertThrowsError(try HPACKDecoder().decode([0x82, 0x20])) { XCTAssertEqual($0 as? HPACKError, .tableSizeUpdate) }      // after a field
        XCTAssertThrowsError(try HPACKDecoder().decode([0x00, 0x81, 0xff, 0x00])) { XCTAssertEqual($0 as? HPACKError, .huffman) }
        // header list too large: reported, but the dynamic table still got the entry (stays in sync)
        let d = HPACKDecoder(maxTableSize: 4096, maxHeaderListSize: 64)
        let e = HPACKEncoder()
        let block = e.encode([("x-big", String(repeating: "a", count: 100))])
        XCTAssertThrowsError(try d.decode(block)) { XCTAssertEqual($0 as? HPACKError, .headerListTooLarge) }
        XCTAssertEqual(d.table.entries.count, 1)
        d.maxHeaderListSize = 1 << 20
        Self.same(try d.decode(e.encode([("x-big", String(repeating: "a", count: 100))])), [("x-big", String(repeating: "a", count: 100))])
        // size update 0 → table emptied; then dynamic references fail
        let d3 = HPACKDecoder()
        _ = try d3.decode(HPACKEncoder().encode([("a", "b")]))
        XCTAssertEqual(d3.table.entries.count, 1)
        _ = try d3.decode([0x20])
        XCTAssertEqual(d3.table.size, 0)
    }

    func testEncoderSignalsPeerTableSize() throws {
        let e = HPACKEncoder()
        let d = HPACKDecoder()
        _ = try d.decode(e.encode([("x-a", "1"), ("x-b", "2")]))
        e.setPeerMaxTableSize(0)
        e.setPeerMaxTableSize(100)
        let b = e.encode([("x-c", "3")])
        XCTAssertEqual(Array(b.prefix(1)), [0x20])            // min (0) first …
        XCTAssertEqual(Array(b[1...2]), [0x3f, 0x45])          // … then the final 100
        Self.same(try d.decode(b), [("x-c", "3")])
        XCTAssertEqual(d.table.maxSize, 100)
        XCTAssertEqual(e.table.maxSize, 100)
        e.setPeerMaxTableSize(1 << 20)                          // capped at our own 4096
        _ = try d.decode(e.encode([]))
        XCTAssertEqual(e.table.maxSize, 4096)
        // obs-text survives (ISO-8859-1 mapping like the HTTP/1.1 lane)
        let v = HTTPWire.latin1(Data([0x63, 0x61, 0x66, 0xe9, 0x20, 0xff]))
        Self.same(try d.decode(e.encode([("x-bin", v)])), [("x-bin", v)])
        XCTAssertEqual(H2Text.bytes(v), [0x63, 0x61, 0x66, 0xe9, 0x20, 0xff])
    }

    // MARK: - Frames

    func testFrameCodecGoFramerFixtures() throws {
        let fx = try fixtures()
        let frames = try XCTUnwrap(fx["frames"] as? [[String: Any]])
        XCTAssertGreaterThan(frames.count, 20)
        for f in frames {
            let name = f["name"] as? String ?? "?"
            let exp = try XCTUnwrap(f["expect"] as? [String: Any])
            var q = H2ByteQueue()
            q.append(Self.hex(try XCTUnwrap(f["hex"] as? String)))
            var dec = H2FrameDecoder()
            if let code = exp["error"] as? Int {
                XCTAssertThrowsError(try dec.next(&q), name) { e in
                    let h = e as? H2Error
                    XCTAssertEqual(h?.code.rawValue, UInt32(code), name)
                    XCTAssertEqual(h?.stream, UInt32(exp["stream"] as? Int ?? 0), name)
                }
                continue
            }
            let frame = try XCTUnwrap(try dec.next(&q), name)
            XCTAssertEqual(q.count, 0, name)
            let ty = exp["type"] as? String
            switch frame {
            case .data(let s, let p, let end, let flow):
                XCTAssertEqual(ty, "data", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Self.hexString(p), exp["payload"] as? String, name)
                XCTAssertEqual(end, exp["endStream"] as? Bool, name)
                XCTAssertEqual(flow, exp["flowSize"] as? Int, name)
            case .headers(let s, let b, let end, let eh):
                XCTAssertEqual(ty, "headers", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Self.hexString(b), exp["block"] as? String, name)
                XCTAssertEqual(end, exp["endStream"] as? Bool, name)
                XCTAssertEqual(eh, exp["endHeaders"] as? Bool, name)
            case .continuation(let s, let b, let eh):
                XCTAssertEqual(ty, "continuation", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Self.hexString(b), exp["block"] as? String, name)
                XCTAssertEqual(eh, exp["endHeaders"] as? Bool, name)
            case .settings(let ack, let vs):
                XCTAssertEqual(ty, "settings", name)
                XCTAssertEqual(ack, exp["ack"] as? Bool, name)
                let want = (exp["values"] as? [[Int]] ?? []).map { "\($0[0])=\($0[1])" }
                XCTAssertEqual(vs.map { "\($0.id)=\($0.value)" }, want, name)
            case .ping(let ack, let p):
                XCTAssertEqual(ty, "ping", name)
                XCTAssertEqual(ack, exp["ack"] as? Bool, name)
                XCTAssertEqual(Self.hexString(p), exp["payload"] as? String, name)
            case .goaway(let last, let code, let debug):
                XCTAssertEqual(ty, "goaway", name)
                XCTAssertEqual(Int(last), exp["lastStream"] as? Int, name)
                XCTAssertEqual(Int(code), exp["code"] as? Int, name)
                XCTAssertEqual(Self.hexString(debug), exp["debug"] as? String, name)
            case .windowUpdate(let s, let inc):
                XCTAssertEqual(ty, "windowUpdate", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Int(inc), exp["increment"] as? Int, name)
            case .rstStream(let s, let code):
                XCTAssertEqual(ty, "rstStream", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Int(code), exp["code"] as? Int, name)
            case .priority(let s):
                XCTAssertEqual(ty, "priority", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
            case .pushPromise(let s, let promised, let b, let eh):
                XCTAssertEqual(ty, "pushPromise", name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
                XCTAssertEqual(Int(promised), exp["promised"] as? Int, name)
                XCTAssertEqual(Self.hexString(b), exp["block"] as? String, name)
                XCTAssertEqual(eh, exp["endHeaders"] as? Bool, name)
            case .unknown(let t, let s):
                XCTAssertEqual(ty, "unknown", name)
                XCTAssertEqual(Int(t), exp["rawType"] as? Int, name)
                XCTAssertEqual(Int(s), exp["stream"] as? Int, name)
            }
        }
    }

    func testFrameEncoderRoundTripAndSplitting() throws {
        var out: [UInt8] = []
        H2FrameEncoder.data(stream: 3, Array("abc".utf8), endStream: true, into: &out)
        H2FrameEncoder.settings([H2SettingValue(.maxConcurrentStreams, 7)], into: &out)
        H2FrameEncoder.settingsAck(into: &out)
        H2FrameEncoder.ping(ack: true, [1, 2, 3, 4, 5, 6, 7, 8], into: &out)
        H2FrameEncoder.goaway(lastStream: 9, code: .enhanceYourCalm, debug: "x", into: &out)
        H2FrameEncoder.windowUpdate(stream: 5, increment: 1000, into: &out)
        H2FrameEncoder.rstStream(stream: 5, code: .cancel, into: &out)
        let block = (0..<40).map { UInt8($0) }
        H2FrameEncoder.headers(stream: 7, block: block, endStream: true, maxFrame: 16, into: &out)
        var q = H2ByteQueue()
        var dec = H2FrameDecoder()
        var got: [H2Frame] = []
        for b in out { // one byte at a time: frames only complete when all bytes are in
            q.append([b])
            while let f = try dec.next(&q) { got.append(f) }
        }
        XCTAssertEqual(got.count, 10)
        XCTAssertEqual(got[0], .data(stream: 3, payload: Array("abc".utf8), endStream: true, flowSize: 3))
        XCTAssertEqual(got[1], .settings(ack: false, values: [H2SettingValue(3, 7)]))
        XCTAssertEqual(got[2], .settings(ack: true, values: []))
        XCTAssertEqual(got[3], .ping(ack: true, payload: [1, 2, 3, 4, 5, 6, 7, 8]))
        XCTAssertEqual(got[4], .goaway(lastStream: 9, code: 0xb, debug: Array("x".utf8)))
        XCTAssertEqual(got[5], .windowUpdate(stream: 5, increment: 1000))
        XCTAssertEqual(got[6], .rstStream(stream: 5, code: 8))
        XCTAssertEqual(got[7], .headers(stream: 7, block: Array(block[0..<16]), endStream: true, endHeaders: false))
        XCTAssertEqual(got[8], .continuation(stream: 7, block: Array(block[16..<32]), endHeaders: false))
        XCTAssertEqual(got[9], .continuation(stream: 7, block: Array(block[32..<40]), endHeaders: true))
        // frame larger than our SETTINGS_MAX_FRAME_SIZE
        var big: [UInt8] = []
        H2FrameEncoder.data(stream: 1, [UInt8](repeating: 0, count: 16_385), endStream: false, into: &big)
        var q2 = H2ByteQueue()
        q2.append(big)
        XCTAssertThrowsError(try dec.next(&q2)) { XCTAssertEqual(($0 as? H2Error)?.code, .frameSizeError) }
    }

    // MARK: - H2Connection over memory streams

    func testConnectionRequestResponseAndPing() throws {
        let pair = H2Pair()
        let sid = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/x")], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[sid] != nil })
        XCTAssertEqual(pair.server.requests[sid]?.first { $0.name == ":path" }?.value, "/x")
        pair.q.sync {
            pair.serverConn.sendHeaders(sid, [(":status", "200"), ("content-type", "text/plain")], endStream: false)
            pair.serverConn.sendData(sid, Data("hello".utf8))
            pair.serverConn.endStream(sid, trailers: [("x-trailer", "t")])
        }
        XCTAssertTrue(pair.wait { pair.client.ended.contains(sid) })
        XCTAssertEqual(pair.client.bodies[sid], Data("hello".utf8))
        Self.same(pair.client.trailers[sid] ?? [], [("x-trailer", "t")])
        XCTAssertTrue(pair.wait { pair.serverConn.activeStreams == 0 && pair.clientConn.activeStreams == 0 })
        pair.q.sync { pair.clientConn.ping([9, 9, 9, 9, 9, 9, 9, 9]) } // answered; nothing breaks
        let sid2 = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/y")], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[sid2] != nil })
        XCTAssertEqual(sid2, sid + 2)
        pair.close()
    }

    func testConnectionFlowControlAndBackPressure() throws {
        let pair = H2Pair(clientAutoConsume: false)
        let sid = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/big")], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[sid] != nil })
        let total = 300_000
        pair.q.sync {
            pair.serverConn.sendHeaders(sid, [(":status", "200")], endStream: false)
            pair.serverConn.sendData(sid, Data(repeating: 7, count: total))
            pair.serverConn.endStream(sid)
        }
        // The client grants nothing back: the server stops at the initial stream window (65 535).
        XCTAssertTrue(pair.wait { (pair.client.bodies[sid]?.count ?? 0) == 65_535 })
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertEqual(pair.client.bodies[sid]?.count, 65_535)
        XCTAssertEqual(pair.q.sync { pair.serverConn.outbound(sid) }, total - 65_535)
        // consuming opens the window again; everything arrives
        pair.client.autoConsume = true
        pair.q.sync { pair.clientConn.consumed(sid, 65_535) }
        XCTAssertTrue(pair.wait { pair.client.ended.contains(sid) })
        XCTAssertEqual(pair.client.bodies[sid]?.count, total)
        pair.close()
    }

    func testConnectionWindowSharedAcrossStreams() throws {
        var lim = H2Limits()
        lim.connectionWindow = 65_535           // no connection-level WINDOW_UPDATE at start
        let pair = H2Pair(clientAutoConsume: false, clientLimits: lim)
        var sids: [UInt32] = []
        for i in 0..<3 {
            sids.append(try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/\(i)")], end: true)))
        }
        XCTAssertTrue(pair.wait { sids.allSatisfy { pair.server.requests[$0] != nil } })
        pair.q.sync {
            for s in sids {
                pair.serverConn.sendHeaders(s, [(":status", "200")], endStream: false)
                pair.serverConn.sendData(s, Data(repeating: 1, count: 40_000))
            }
        }
        XCTAssertTrue(pair.wait { sids.reduce(0) { $0 + (pair.client.bodies[$1]?.count ?? 0) } == 65_535 })
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertEqual(sids.reduce(0) { $0 + (pair.client.bodies[$1]?.count ?? 0) }, 65_535)
        pair.close()
    }

    func testConcurrencyLimitRefusesExtraStreams() throws {
        var sl = H2Limits()
        sl.maxConcurrentStreams = 2
        var cl = H2Limits()
        cl.maxConcurrentStreams = 10
        // all three opened in the same turn of the queue as start(), before the server's SETTINGS (limit 2) arrive
        let pair = H2Pair(serverLimits: sl, clientLimits: cl,
                          openAtStart: (0..<3).map { [(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/\($0)")] })
        let sids = pair.preOpened
        XCTAssertEqual(sids.count, 3)
        guard sids.count == 3 else { return }
        XCTAssertTrue(pair.wait { pair.client.resets[sids[2]] == .refusedStream })
        XCTAssertNotNil(pair.server.requests[sids[0]])
        XCTAssertNotNil(pair.server.requests[sids[1]])
        XCTAssertNil(pair.server.requests[sids[2]])
        XCTAssertEqual(pair.server.refused, [sids[2]])
        pair.close()
    }

    func testLargeHeadersUseContinuationAndListLimitIsPerStream() throws {
        let pair = H2Pair()                       // server list limit 64 KB
        let big = String(repeating: "v", count: 30_000) // > one 16 KB frame even Huffman-coded: CONTINUATION
        let s1 = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/1"),
                                                ("x-a", big)], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[s1] != nil })
        XCTAssertEqual(pair.server.requests[s1]?.first { $0.name == "x-a" }?.value, big)
        // > 64 KB list: refused on that stream only; the connection keeps working
        let s2 = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/2"),
                                                ("x-a", big), ("x-b", big), ("x-c", big)], end: true))
        XCTAssertTrue(pair.wait { pair.server.refused.contains(s2) })
        let s3 = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/3")], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[s3] != nil })
        XCTAssertFalse(pair.q.sync { pair.serverConn.closed })
        pair.close()
    }

    func testResetAndGoAway() throws {
        let pair = H2Pair()
        let sid = try XCTUnwrap(pair.clientOpen([(":method", "POST"), (":scheme", "https"), (":authority", "a.test"), (":path", "/up")], end: false))
        XCTAssertTrue(pair.wait { pair.server.requests[sid] != nil })
        pair.q.sync { pair.clientConn.resetStream(sid, .cancel) }
        XCTAssertTrue(pair.wait { pair.server.resets[sid] == .cancel })
        let s2 = try XCTUnwrap(pair.clientOpen([(":method", "GET"), (":scheme", "https"), (":authority", "a.test"), (":path", "/x")], end: true))
        XCTAssertTrue(pair.wait { pair.server.requests[s2] != nil })
        pair.q.sync { pair.serverConn.goAway(.noError) }
        XCTAssertTrue(pair.wait { pair.client.goaway == s2 })
        XCTAssertFalse(pair.q.sync { pair.clientConn.canOpenStream })
        pair.q.sync { pair.serverConn.sendHeaders(s2, [(":status", "204")], endStream: true) }   // open stream still finishes
        XCTAssertTrue(pair.wait { pair.client.ended.contains(s2) })
        XCTAssertTrue(pair.wait { pair.server.closed })
        pair.close()
    }

    /// Raw byte sequences against a server connection: each must end in the right GOAWAY / close.
    func testServerProtocolErrors() throws {
        func run(_ bytes: [UInt8], expect code: H2ErrorCode?, _ what: String) {
            let raw = RawPeer()
            raw.send(bytes)
            XCTAssertTrue(raw.wait { raw.server.closed }, what)
            if let code { XCTAssertEqual(raw.goawayCode(), code, what) }
            raw.close()
        }
        let preface = H2Wire.preface
        var settings: [UInt8] = []
        H2FrameEncoder.settings([], into: &settings)
        run(Array("GET / HTTP/1.1\r\n\r\n".utf8) + [UInt8](repeating: 0, count: 8), expect: nil, "not a preface")
        var ping: [UInt8] = []
        H2FrameEncoder.ping(ack: false, [0, 0, 0, 0, 0, 0, 0, 0], into: &ping)
        run(preface + ping, expect: .protocolError, "first frame not SETTINGS")
        var data: [UInt8] = []
        H2FrameEncoder.data(stream: 1, [1], endStream: false, into: &data)
        run(preface + settings + data, expect: .protocolError, "DATA on idle stream")
        var wu: [UInt8] = []
        H2FrameEncoder.windowUpdate(stream: 0, increment: 0x7fff_ffff, into: &wu)
        run(preface + settings + wu, expect: .flowControlError, "connection window overflow")
        var pp: [UInt8] = []
        H2FrameEncoder.raw(type: 5, flags: 4, stream: 1, payload: [0, 0, 0, 2, 0x82], into: &pp)
        run(preface + settings + pp, expect: .protocolError, "PUSH_PROMISE from a client")
        var even: [UInt8] = []
        H2FrameEncoder.headers(stream: 2, block: [0x82], endStream: true, maxFrame: 16_384, into: &even)
        run(preface + settings + even, expect: .protocolError, "even stream id")
        var badHpack: [UInt8] = []
        H2FrameEncoder.headers(stream: 1, block: [0xff, 0xff], endStream: true, maxFrame: 16_384, into: &badHpack)
        run(preface + settings + badHpack, expect: .compressionError, "bad HPACK")
        var interleave: [UInt8] = []
        H2FrameEncoder.raw(type: 1, flags: 0, stream: 1, payload: [0x82], into: &interleave) // HEADERS without END_HEADERS
        interleave += ping
        run(preface + settings + interleave, expect: .protocolError, "frame between HEADERS and CONTINUATION")
        var badSetting: [UInt8] = []
        H2FrameEncoder.settings([H2SettingValue(.maxFrameSize, 100)], into: &badSetting)
        run(preface + badSetting, expect: .protocolError, "MAX_FRAME_SIZE out of range")
    }

    // MARK: - request parsing

    func testRequestParse() throws {
        let p = try H2Request.parse([(":method", "POST"), (":scheme", "https"), (":authority", "api.test:8443"), (":path", "/a?b=1"),
                                     ("cookie", "a=1"), ("user-agent", "t"), ("cookie", "b=2"), ("content-length", "3")], endStream: false).get()
        XCTAssertEqual(p.head.method, "POST")
        XCTAssertEqual(p.head.target, "/a?b=1")
        XCTAssertEqual(p.length, 3)
        Self.same(p.head.headers, [("Host", "api.test:8443"), ("cookie", "a=1; b=2"), ("user-agent", "t"), ("content-length", "3")])
        let q = try H2Request.parse([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "h.test")], endStream: false).get()
        XCTAssertEqual(q.length, -1)
        Self.same(q.head.headers, [("Host", "h.test"), ("Transfer-Encoding", "chunked")])
        XCTAssertEqual(try H2Request.parse([(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "x")], endStream: true).get().length, 0)
        func rejected(_ f: [(String, String)]) -> H2RequestReject? {
            if case .failure(let r) = H2Request.parse(f.map { (name: $0.0, value: $0.1) }, endStream: true) { return r }
            return nil
        }
        XCTAssertEqual(rejected([(":method", "CONNECT"), (":authority", "x:443")]), .connect)
        XCTAssertEqual(rejected([(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/"), (":authority", "x")]), .extendedConnect)
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("Upper", "x")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("connection", "keep-alive")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("te", "gzip")]))
        XCTAssertNil(rejected([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("te", "trailers")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https"), ("x", "1"), (":path", "/")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":method", "GET"), (":scheme", "https"), (":path", "/")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https")]))
        XCTAssertNotNil(rejected([(":method", "GET"), (":scheme", "https"), (":path", "/"), ("content-length", "x")]))
        Self.same(H2Request.h2Fields([("Content-Type", "a"), ("Connection", "close"), ("Content-Length", "3"), ("X-A", "b")], dropContentLength: true),
                  [("content-type", "a"), ("x-a", "b")])
    }

    // MARK: - NativeH2Session end to end (scripted driver, in-memory origins)

    func testSessionForwardsToH2OriginMultiplexed() throws {
        let env = SessionEnv(originH2: true)
        var sids: [UInt32] = []
        for i in 0..<10 {
            sids.append(try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/echo?i=\(i)"),
                                                       ("user-agent", "ut")], end: true)))
        }
        XCTAssertTrue(env.wait { sids.allSatisfy { env.client.ended.contains($0) } })
        for (i, s) in sids.enumerated() {
            XCTAssertEqual(env.client.status(s), "200")
            XCTAssertEqual(env.client.text(s), "h2 GET /echo?i=\(i) ua=ut body=0")
        }
        XCTAssertEqual(env.opener.opens, 1)              // one multiplexed origin connection
        XCTAssertEqual(env.driver.ends.count, 10)
        XCTAssertTrue(env.driver.ends.allSatisfy { $0.err == "" })
        XCTAssertTrue(env.driver.cancels.isEmpty)
        env.close()
    }

    func testSessionForwardsToHTTP1Origin() throws {
        let env = SessionEnv(originH2: false)
        let s = try XCTUnwrap(env.client.open([(":method", "POST"), (":scheme", "https"), (":authority", "h1.test"), (":path", "/echo"),
                                               ("content-length", "5")], end: false))
        env.client.send(s, Data("hello".utf8), end: true)
        XCTAssertTrue(env.wait { env.client.ended.contains(s) })
        XCTAssertEqual(env.client.status(s), "200")
        XCTAssertEqual(env.client.text(s), "h1 POST /echo body=5:hello")
        XCTAssertEqual(env.driver.ends.first?.sent, Int64("h1 POST /echo body=5:hello".utf8.count))
        let s2 = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h1.test"), (":path", "/echo")], end: true))
        XCTAssertTrue(env.wait { env.client.ended.contains(s2) })
        XCTAssertEqual(env.client.text(s2), "h1 GET /echo body=0:")
        env.close()
    }

    func testSessionLocalAnswerAndResponseRewriteViaGoRead() throws {
        let env = SessionEnv(originH2: true)
        env.driver.local["/local"] = (201, [("Content-Type", "text/plain"), ("X-Local", "1")], Data("from go".utf8))
        env.driver.rewriteResponse["/echo?rw"] = { Data($0.uppercased().utf8) }
        let a = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/local")], end: true))
        let b = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/echo?rw")], end: true))
        XCTAssertTrue(env.wait { env.client.ended.contains(a) && env.client.ended.contains(b) })
        XCTAssertEqual(env.client.status(a), "201")
        XCTAssertEqual(env.client.header(a, "x-local"), "1")
        XCTAssertEqual(env.client.header(a, "content-length"), "7")
        XCTAssertEqual(env.client.text(a), "from go")
        XCTAssertEqual(env.client.text(b), "H2 GET /ECHO?RW UA= BODY=0")
        XCTAssertEqual(env.originRequests(), 1)           // the local answer never reached the origin
        env.close()
    }

    func testSessionRequestBodyPushedToGo() throws {
        let env = SessionEnv(originH2: true)
        env.driver.rewriteRequest["/echo?up"] = { Data(("<" + $0 + ">").utf8) }
        let s = try XCTUnwrap(env.client.open([(":method", "PUT"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/echo?up")], end: false))
        let chunk = String(repeating: "x", count: 10_000)
        for _ in 0..<20 { env.client.send(s, Data(chunk.utf8), end: false) }
        env.client.send(s, Data(), end: true)
        XCTAssertTrue(env.wait(10) { env.client.ended.contains(s) })
        XCTAssertEqual(env.client.text(s), "h2 PUT /echo?up ua= body=200002")
        env.close()
    }

    func testSessionStreamingGoReadPullsMoreFromUpstream() throws {
        let env = SessionEnv(originH2: true)
        env.driver.streamUpper.insert("/big?n=300000")
        let s = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/big?n=300000")], end: true))
        XCTAssertTrue(env.wait(15) { env.client.ended.contains(s) })
        let want = Data(String(decoding: Data((0..<300_000).map { UInt8($0 % 251) }), as: UTF8.self).uppercased().utf8)
        XCTAssertEqual(env.client.bodies[s]?.count, want.count)
        XCTAssertEqual(env.client.bodies[s], want)
        XCTAssertNil(env.client.header(s, "content-length"))
        env.close()
    }

    func testSessionLargeResponseBackPressure() throws {
        let env = SessionEnv(originH2: true)
        let s = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/big?n=1000000")], end: true))
        XCTAssertTrue(env.wait(15) { env.client.ended.contains(s) })
        XCTAssertEqual(env.client.bodies[s]?.count, 1_000_000)
        XCTAssertEqual(env.client.bodies[s], Data((0..<1_000_000).map { UInt8($0 % 251) }))
        XCTAssertEqual(env.driver.ends.first?.sent, 1_000_000)
        env.close()
    }

    func testSessionTrailersPassThrough() throws {
        let env = SessionEnv(originH2: true)
        let s = try XCTUnwrap(env.client.open([(":method", "POST"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/grpc"),
                                               ("content-type", "application/grpc"), ("te", "trailers")], end: false))
        env.client.send(s, Data([0, 0, 0, 0, 1, 7]), end: true)
        XCTAssertTrue(env.wait { env.client.ended.contains(s) })
        XCTAssertEqual(env.client.status(s), "200")
        Self.same(env.client.trailers[s] ?? [], [("grpc-status", "0"), ("grpc-message", "ok")])
        env.close()
    }

    func testSessionUnsupportedAndMalformedStreams() throws {
        let env = SessionEnv(originH2: true)
        let c = try XCTUnwrap(env.client.open([(":method", "CONNECT"), (":authority", "x.test:443")], end: false))
        let w = try XCTUnwrap(env.client.open([(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/ws"),
                                               (":authority", "h2.test")], end: false))
        let m = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/"),
                                               ("connection", "close")], end: true))
        XCTAssertTrue(env.wait { env.client.status(c) == "501" && env.client.resets[w] != nil && env.client.resets[m] != nil })
        XCTAssertEqual(env.client.resets[w], .protocolError)
        XCTAssertEqual(env.client.resets[m], .protocolError)
        // still serving
        let ok = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/echo")], end: true))
        XCTAssertTrue(env.wait { env.client.ended.contains(ok) })
        XCTAssertEqual(env.client.status(ok), "200")
        XCTAssertEqual(env.driver.begins.count, 1)        // none of the refused streams reached the driver
        env.close()
    }

    func testSessionDropBusyAndUpstreamFailure() throws {
        let env = SessionEnv(originH2: true)
        env.driver.drop.insert("/drop")
        env.driver.busy.insert("/busy")
        env.opener.failHosts.insert("down.test")
        let d = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/drop")], end: true))
        let b = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/busy")], end: true))
        let f = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "down.test"), (":path", "/x")], end: true))
        XCTAssertTrue(env.wait { env.client.resets[d] != nil && env.client.ended.contains(b) && env.client.ended.contains(f) })
        XCTAssertEqual(env.client.resets[d], .internalError)
        XCTAssertEqual(env.client.status(b), "503")
        XCTAssertEqual(env.client.status(f), "502")
        XCTAssertTrue(env.wait { env.driver.upstreamFailures.count == 1 })
        XCTAssertTrue(env.wait { env.driver.ends.count == 3 })
        env.close()
    }

    func testSessionClientResetCancelsFlowAndOrigin() throws {
        let env = SessionEnv(originH2: true)
        let s = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/hang")], end: true))
        XCTAssertTrue(env.wait { env.originRequests() == 1 })
        env.client.reset(s)
        XCTAssertTrue(env.wait { env.driver.cancels.count == 1 })
        XCTAssertTrue(env.wait { env.originResets() == 1 })
        XCTAssertTrue(env.wait { env.session.openExchanges == 0 })
        env.close()
        XCTAssertTrue(env.wait { env.finished })
    }

    func testSessionAdmissionHookRefuses() throws {
        let env = SessionEnv(originH2: true)
        NativeH2Runtime.admitStream = { false }
        defer { NativeH2Runtime.admitStream = nil }
        let s = try XCTUnwrap(env.client.open([(":method", "GET"), (":scheme", "https"), (":authority", "h2.test"), (":path", "/echo")], end: true))
        XCTAssertTrue(env.wait { env.client.resets[s] == .refusedStream })
        XCTAssertTrue(env.driver.begins.isEmpty)
        env.close()
    }
}

// MARK: - test doubles

/// In-memory ByteStream pair.
final class H2MemStream: ByteStream {
    private let lock = NSLock()
    weak var peer: H2MemStream?
    private var buf = Data()
    private var eof = false
    private var closed = false
    private var waiter: (Int, (Data?, Bool, Error?) -> Void)?

    static func pair() -> (H2MemStream, H2MemStream) {
        let a = H2MemStream(), b = H2MemStream()
        a.peer = b; b.peer = a
        return (a, b)
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if !buf.isEmpty {
            let d = buf.prefix(max)
            buf = Data(buf.dropFirst(d.count))
            lock.unlock()
            DispatchQueue.global().async { completion(Data(d), false, nil) }
            return
        }
        if closed { lock.unlock(); DispatchQueue.global().async { completion(nil, false, S2Error.closed) }; return }
        if eof { lock.unlock(); DispatchQueue.global().async { completion(nil, true, nil) }; return }
        waiter = (max, completion)
        lock.unlock()
    }

    fileprivate func deliver(_ d: Data?) {
        lock.lock()
        if let d { buf.append(d) } else { eof = true }
        guard let w = waiter else { lock.unlock(); return }
        waiter = nil
        if !buf.isEmpty {
            let out = buf.prefix(w.0)
            buf = Data(buf.dropFirst(out.count))
            lock.unlock()
            DispatchQueue.global().async { w.1(Data(out), false, nil) }
        } else {
            lock.unlock()
            DispatchQueue.global().async { w.1(nil, true, nil) }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock(); let dead = closed; lock.unlock()
        if dead { return DispatchQueue.global().async { completion(S2Error.closed) } }
        peer?.deliver(data)
        DispatchQueue.global().async { completion(nil) }
    }

    func closeWrite() { peer?.deliver(nil) }

    func close() {
        lock.lock()
        let first = !closed
        closed = true
        let w = waiter
        waiter = nil
        lock.unlock()
        if let w { DispatchQueue.global().async { w.1(nil, false, S2Error.closed) } }
        if first { peer?.deliver(nil) }
    }
}

/// Collects one H2Connection's events (on its queue).
final class H2Recorder: H2ConnectionOwner {
    var requests: [UInt32: HTTPHeaderList] = [:]
    var responses: [UInt32: HTTPHeaderList] = [:]
    var bodies: [UInt32: Data] = [:]
    var trailers: [UInt32: HTTPHeaderList] = [:]
    var ended: Set<UInt32> = []
    var resets: [UInt32: H2ErrorCode] = [:]
    var refused: [UInt32] = []
    var goaway: UInt32?
    var closed = false
    var autoConsume = true
    var onHeaders: ((H2Connection, UInt32, HTTPHeaderList, Bool) -> Void)?
    var onData: ((H2Connection, UInt32, Data, Bool) -> Void)?

    func h2Event(_ c: H2Connection, _ event: H2Event) {
        switch event {
        case .headers(let s, let f, let end, let tr):
            if tr { trailers[s] = f } else if c.role == .server { requests[s] = f } else { responses[s] = f }
            if end { ended.insert(s) }
            onHeaders?(c, s, f, end)
        case .refused(let s, _, _):
            refused.append(s)
        case .data(let s, let d, let end):
            bodies[s, default: Data()].append(d)
            if autoConsume { c.consumed(s, d.count) }
            if end { ended.insert(s) }
            onData?(c, s, d, end)
        case .reset(let s, let code, _):
            resets[s] = code
        case .writable:
            break
        case .goaway(let last, _):
            goaway = last
        case .closed:
            closed = true
        }
    }
}

/// A client and a server H2Connection wired together on one queue.
final class H2Pair {
    let q = DispatchQueue(label: "h2pair")
    let server = H2Recorder()
    let client = H2Recorder()
    let serverConn: H2Connection
    let clientConn: H2Connection
    private(set) var preOpened: [UInt32] = []

    init(clientAutoConsume: Bool = true, serverLimits: H2Limits = H2Limits(), clientLimits: H2Limits = H2Limits(),
         openAtStart: [[(String, String)]] = []) {
        let (a, b) = H2MemStream.pair()
        serverConn = H2Connection(role: .server, io: a, queue: q, limits: serverLimits)
        clientConn = H2Connection(role: .client, io: b, queue: q, limits: clientLimits)
        serverConn.owner = server
        clientConn.owner = client
        client.autoConsume = clientAutoConsume
        q.sync {
            serverConn.start(); clientConn.start()
            for f in openAtStart {
                guard let s = clientConn.openStream() else { continue }
                clientConn.sendHeaders(s, f.map { (name: $0.0, value: $0.1) }, endStream: true)
                preOpened.append(s)
            }
        }
        // let SETTINGS cross
        if openAtStart.isEmpty { Thread.sleep(forTimeInterval: 0.05) }
    }

    func clientOpen(_ f: [(String, String)], end: Bool) -> UInt32? {
        q.sync {
            guard let s = clientConn.openStream() else { return nil }
            clientConn.sendHeaders(s, f.map { (name: $0.0, value: $0.1) }, endStream: end)
            return s
        }
    }

    func wait(_ seconds: TimeInterval = 5, _ cond: @escaping () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if q.sync(execute: cond) { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return q.sync(execute: cond)
    }

    func close() { q.sync { clientConn.close(); serverConn.close() } }
}

/// Raw bytes against a server H2Connection; collects what the server writes back.
final class RawPeer {
    let q = DispatchQueue(label: "rawpeer")
    let server = H2Recorder()
    let conn: H2Connection
    private let mine: H2MemStream
    private var got = Data()

    init() {
        let (a, b) = H2MemStream.pair()
        mine = b
        conn = H2Connection(role: .server, io: a, queue: q)
        conn.owner = server
        q.sync { conn.start() }
        pump()
    }

    private func pump() {
        mine.read(min: 1, max: 65_536) { [weak self] d, eof, err in
            guard let self else { return }
            self.q.async {
                if let d { self.got.append(d) }
                if !eof && err == nil { self.pump() }
            }
        }
    }

    func send(_ b: [UInt8]) { mine.write(Data(b)) { _ in } }

    func wait(_ cond: @escaping () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if q.sync(execute: cond) { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }

    /// The error code of the last GOAWAY the server sent.
    func goawayCode() -> H2ErrorCode? {
        Thread.sleep(forTimeInterval: 0.05)
        var q2 = H2ByteQueue()
        q2.append(q.sync { got })
        var dec = H2FrameDecoder()
        dec.maxFrameSize = 1 << 24 - 1
        var code: H2ErrorCode?
        while let f = try? dec.next(&q2) {
            if case .goaway(_, let c, _) = f { code = H2ErrorCode(code: c) }
        }
        return code
    }

    func close() { q.sync { conn.close() }; mine.close() }
}

/// Scripted flow driver: forwards everything to the request's own authority unless told otherwise; supports
/// local answers, request / response body rewrites (need-body → read), drop, busy. Thread-safe.
final class ScriptedH2Driver: MitmFlowDriving {
    struct End { let id: Int64; let sent: Int64; let err: String }
    private let lock = NSLock()
    private var nextID: Int64 = 0
    var local: [String: (Int, HTTPHeaderList, Data)] = [:]
    var rewriteResponse: [String: (String) -> Data] = [:]
    var rewriteRequest: [String: (String) -> Data] = [:]
    var drop: Set<String> = []
    var busy: Set<String> = []
    /// Streaming response rewrite: "respond / read" right away, FlowRead answers "more" until the next piece of
    /// the upstream body is pushed (the old core's streaming mode after its phase, design §12.2).
    var streamUpper: Set<String> = []
    private var _begins: [String] = []
    private var _ends: [End] = []
    private var _cancels: [Int64] = []
    private var _upstreamFailures: [Int64] = []
    var begins: [String] { sync { _begins } }
    var ends: [End] { sync { _ends } }
    var cancels: [Int64] { sync { _cancels } }
    var upstreamFailures: [Int64] { sync { _upstreamFailures } }
    private var flows: [Int64: Flow] = [:]

    private final class Flow {
        let head: HTTPRequestHead
        var reqIn = Data(), reqClosed = false
        var respIn = Data(), respClosed = false
        var out: [Int: Data] = [:]       // which → body the old core produces
        var stage = 0                    // 1 = request need-body, 2 = response need-body
        init(head: HTTPRequestHead) { self.head = head }
    }

    private func sync<T>(_ f: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return f() }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        sync {
            nextID += 1
            let id = nextID
            _begins.append(head.target)
            let f = Flow(head: head)
            flows[id] = f
            if drop.contains(head.target) { return FlowDecision(id: id, action: .drop) }
            if busy.contains(head.target) { return FlowDecision(id: id, action: .busy) }
            if let l = local[head.target] {
                f.out[1] = l.2
                var d = FlowDecision(id: id, action: .local)
                d.status = l.0
                d.headers = headerPairs(l.1)
                d.body = .read
                d.length = Int64(l.2.count)
                return d
            }
            if rewriteRequest[head.target] != nil {
                f.stage = 1
                var d = FlowDecision(id: id, action: .needBody)
                d.which = 0
                return d
            }
            return forward(id, f, bodyMode: head.value(for: "Content-Length") == "0" ? .none : (head.isChunked || head.contentLength ?? 0 > 0 ? .client : .none),
                           length: head.isChunked ? -1 : (head.contentLength ?? 0))
        }
    }

    private func forward(_ id: Int64, _ f: Flow, bodyMode: FlowBodyMode, length: Int64) -> FlowDecision {
        var d = FlowDecision(id: id, action: .forward)
        d.method = f.head.method
        d.url = "https://\(f.head.host ?? "x")\(f.head.target)"
        d.headers = headerPairs(f.head.headers.filter { !["host", "transfer-encoding", "content-length"].contains($0.name.lowercased()) })
        d.body = bodyMode
        d.length = length
        return d
    }

    func await(_ id: Int64) -> FlowDecision {
        // wait for the pushed body to close (the old core would block in its phase thread)
        for _ in 0..<2000 {
            let r: FlowDecision? = sync {
                guard let f = flows[id] else { return FlowDecision(id: id, action: .error, note: "gone") }
                if f.stage == 1 && f.reqClosed, let rw = rewriteRequest[f.head.target] {
                    let body = rw(String(decoding: f.reqIn, as: UTF8.self))
                    f.out[0] = body
                    f.stage = 0
                    return forward(id, f, bodyMode: .read, length: Int64(body.count))
                }
                if f.stage == 2 && f.respClosed, let rw = rewriteResponse[f.head.target] {
                    let body = rw(String(decoding: f.respIn, as: UTF8.self))
                    f.out[1] = body
                    f.stage = 0
                    var d = FlowDecision(id: id, action: .respond)
                    d.status = 200
                    d.headers = [["Content-Type", "text/plain"]]
                    d.body = .read
                    d.length = Int64(body.count)
                    return d
                }
                return nil
            }
            if let r { return r }
            usleep(1000)
        }
        return FlowDecision(id: id, action: .error, note: "await timeout")
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        sync {
            guard let f = flows[id] else { return FlowDecision(id: id, action: .error, note: "gone") }
            if streamUpper.contains(f.head.target) {
                f.stage = 3
                f.out[1] = Data()
                var d = FlowDecision(id: id, action: .respond)
                d.status = head.status
                d.headers = [["Content-Type", "text/plain"]]
                d.body = .read
                d.length = -1
                return d
            }
            if rewriteResponse[f.head.target] != nil {
                f.stage = 2
                var d = FlowDecision(id: id, action: .needBody)
                d.which = 1
                return d
            }
            var d = FlowDecision(id: id, action: .respond)
            d.status = head.status
            d.headers = headerPairs(head.headers.filter { $0.name.lowercased() != "content-length" })
            d.body = .upstream
            d.length = length
            return d
        }
    }

    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        sync {
            guard let f = flows[id] else { return .gone }
            if f.stage == 3 && which == .response {
                if (f.out[1]?.count ?? 0) > 0 { return .full }   // drain first
                f.out[1] = Data(String(decoding: data, as: UTF8.self).uppercased().utf8)
                return .taken
            }
            if which == .request { f.reqIn.append(data) } else { f.respIn.append(data) }
            return .taken
        }
    }

    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {
        sync {
            guard let f = flows[id] else { return }
            if which == .request { f.reqClosed = true } else { f.respClosed = true }
        }
    }

    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        sync {
            guard let f = flows[id], let b = f.out[which.rawValue], !b.isEmpty else { return Data() }
            let d = b.prefix(max)
            f.out[which.rawValue] = Data(b.dropFirst(d.count))
            return Data(d)
        }
    }

    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState {
        sync {
            guard let f = flows[id] else { return .failed("gone") }
            if f.stage == 3 && which == .response { return f.respClosed ? .eof : .more }
            return f.out[which.rawValue] != nil ? .eof : .failed("no body")
        }
    }

    func upstreamFailed(_ id: Int64, why: String) { sync { _upstreamFailures.append(id) } }
    func end(_ id: Int64, sent: Int64, error: String) { sync { _ends.append(End(id: id, sent: sent, err: error)); flows[id] = nil } }
    func cancel(_ id: Int64, why: String) { sync { _cancels.append(id); flows[id] = nil } }
}

/// In-memory origins: "h2.test" speaks h2 (when originH2), anything else HTTP/1.1. Paths: /echo, /big?n=, /grpc
/// (trailers), /hang (never answers).
final class MemOriginOpener: H2UpstreamOpening {
    let originH2: Bool
    let q = DispatchQueue(label: "origins")
    private let lock = NSLock()
    private(set) var opens = 0
    var failHosts: Set<String> = []
    private(set) var requests = 0
    private(set) var resets = 0
    private var keep: [AnyObject] = []

    init(originH2: Bool) { self.originH2 = originH2 }

    func open(host: String, port: Int, tls: Bool, offerH2: Bool, completion: @escaping (Result<H2UpstreamTransport, Error>) -> Void) {
        lock.lock(); opens += 1; lock.unlock()
        if failHosts.contains(host) { return completion(.failure(UpstreamError.invalidTarget("down"))) }
        let (mine, theirs) = H2MemStream.pair()
        let h2 = originH2 && offerH2 && host == "h2.test"
        if h2 { startH2(mine) } else { startH1(mine) }
        completion(.success(H2UpstreamTransport(stream: theirs, alpn: h2 ? "h2" : nil) { _ in theirs.close() }))
    }

    private func count(_ f: (MemOriginOpener) -> Void) { lock.lock(); f(self); lock.unlock() }

    static func reply(_ proto: String, _ method: String, _ path: String, _ ua: String, _ body: Data) -> Data {
        if path.hasPrefix("/big") {
            let n = Int(path.split(separator: "=").last ?? "0") ?? 0
            return Data((0..<n).map { UInt8($0 % 251) })
        }
        return Data("\(proto) \(method) \(path) ua=\(ua) body=\(body.count)".utf8)
    }

    private func startH2(_ s: H2MemStream) {
        let c = H2Connection(role: .server, io: s, queue: q)
        let rec = H2Recorder()
        rec.onHeaders = { [weak self] c, sid, f, end in
            guard let self else { return }
            if end { self.answerH2(c, sid, rec) }
        }
        rec.onData = { [weak self] c, sid, _, end in if end { self?.answerH2(c, sid, rec) } }
        let owner = OriginOwner(rec: rec, onRequest: { [weak self] in self?.count { $0.requests += 1 } },
                                onReset: { [weak self] in self?.count { $0.resets += 1 } })
        c.owner = owner   // weak: kept alive below
        keep.append(c); keep.append(owner)
        q.async { c.start() }
    }

    private func answerH2(_ c: H2Connection, _ sid: UInt32, _ rec: H2Recorder) {
        let f = rec.requests[sid] ?? []
        func v(_ n: String) -> String { f.first { $0.name == n }?.value ?? "" }
        let path = v(":path")
        if path == "/hang" { return }
        if path == "/grpc" {
            c.sendHeaders(sid, [(":status", "200"), ("content-type", "application/grpc")], endStream: false)
            c.sendData(sid, Data([0, 0, 0, 0, 0]))
            c.endStream(sid, trailers: [("grpc-status", "0"), ("grpc-message", "ok")])
            return
        }
        let body = Self.reply("h2", v(":method"), path, v("user-agent"), rec.bodies[sid] ?? Data())
        c.sendHeaders(sid, [(":status", "200"), ("content-type", "text/plain"), ("content-length", String(body.count))], endStream: false)
        // big bodies in pieces, as a real server would
        var off = 0
        while off < body.count {
            let n = min(64 << 10, body.count - off)
            c.sendData(sid, body.subdata(in: off..<(off + n)))
            off += n
        }
        c.endStream(sid)
    }

    private func startH1(_ s: H2MemStream) {
        let st = H1OriginState()
        func serve() {
            while true {
                if st.head == nil {
                    guard let h = try? st.codec.parseRequestHead(&st.buf) else { return }
                    st.head = h
                }
                guard let head = st.head else { return }
                var n = 0
                if case .contentLength(let k) = st.codec.requestFraming(head) { n = Int(k) }
                guard st.buf.count >= n else { return } // the body is still on its way
                let body = st.buf.prefix(n)
                st.buf = Data(st.buf.dropFirst(n))
                st.head = nil
                count { $0.requests += 1 }
                let text = "h1 \(head.method) \(head.target) body=\(body.count):" + String(decoding: body, as: UTF8.self)
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \(text.utf8.count)\r\n\r\n" + text
                s.write(Data(resp.utf8)) { _ in }
            }
        }
        func loop() {
            s.read(min: 1, max: 65_536) { [weak self] d, eof, err in
                guard let self else { return }
                self.q.async {
                    if let d { st.buf.append(d) }
                    serve()
                    if !eof && err == nil { loop() }
                }
            }
        }
        loop()
    }
}

private final class H1OriginState {
    let codec = HTTPLaneCodec()
    var buf = Data()
    var head: HTTPRequestHead?
}

private final class OriginOwner: H2ConnectionOwner {
    let rec: H2Recorder
    let onRequest: () -> Void
    let onReset: () -> Void
    init(rec: H2Recorder, onRequest: @escaping () -> Void, onReset: @escaping () -> Void) {
        self.rec = rec; self.onRequest = onRequest; self.onReset = onReset
    }
    func h2Event(_ c: H2Connection, _ event: H2Event) {
        if case .reset = event { onReset() }
        if case .headers(_, _, _, false) = event { onRequest() }
        rec.h2Event(c, event)
    }
}

/// A client H2Connection talking to a NativeH2Session over memory streams.
final class SessionEnv {
    let driver = ScriptedH2Driver()
    let opener: MemOriginOpener
    let session: NativeH2Session
    let client: H2TestClient
    private let lock = NSLock()
    private var _finished = false
    var finished: Bool { lock.lock(); defer { lock.unlock() }; return _finished }

    init(originH2: Bool) {
        opener = MemOriginOpener(originH2: originH2)
        let (a, b) = H2MemStream.pair()
        let conn = MitmAcceptedConnection(stream: a, host: "h2.test", port: 443, alpn: "h2", connID: 1)
        session = NativeH2Session(conn: conn, codec: HTTPLaneCodec(), opener: opener, driver: driver, bodies: NoBodies())!
        client = H2TestClient(io: b)
        session.onFinish = { [weak self] _ in
            guard let self else { return }
            self.lock.lock(); self._finished = true; self.lock.unlock()
        }
        session.start()
        Thread.sleep(forTimeInterval: 0.05)
    }

    func wait(_ seconds: TimeInterval = 5, _ cond: @escaping () -> Bool) -> Bool { client.wait(seconds, cond) }
    func originRequests() -> Int { opener.q.sync { opener.requests } }
    func originResets() -> Int { opener.q.sync { opener.resets } }
    func close() { client.close(); session.cancel("test over") }
}

final class NoBodies: NativeBodyReading {
    func len(_ h: Int64, raw: Bool) -> Int64 { -1 }
    func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data? { nil }
}

final class H2TestClient {
    let q = DispatchQueue(label: "h2client")
    let rec = H2Recorder()
    let conn: H2Connection
    var ended: Set<UInt32> { q.sync { rec.ended } }
    var bodies: [UInt32: Data] { q.sync { rec.bodies } }
    var trailers: [UInt32: HTTPHeaderList] { q.sync { rec.trailers } }
    var resets: [UInt32: H2ErrorCode] { q.sync { rec.resets } }

    init(io: ByteStream) {
        conn = H2Connection(role: .client, io: io, queue: q)
        conn.owner = rec
        q.sync { conn.start() }
    }

    func open(_ f: [(String, String)], end: Bool) -> UInt32? {
        q.sync {
            guard let s = conn.openStream() else { return nil }
            conn.sendHeaders(s, f.map { (name: $0.0, value: $0.1) }, endStream: end)
            return s
        }
    }
    func send(_ s: UInt32, _ d: Data, end: Bool) {
        q.sync {
            if !d.isEmpty { conn.sendData(s, d) }
            if end { conn.endStream(s) }
        }
    }
    func reset(_ s: UInt32) { q.sync { conn.resetStream(s, .cancel) } }
    func status(_ s: UInt32) -> String? { q.sync { rec.responses[s]?.first { $0.name == ":status" }?.value } }
    func header(_ s: UInt32, _ n: String) -> String? { q.sync { rec.responses[s]?.first { $0.name == n }?.value } }
    func text(_ s: UInt32) -> String { String(decoding: bodies[s] ?? Data(), as: UTF8.self) }
    func wait(_ seconds: TimeInterval, _ cond: @escaping () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if cond() { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return cond()
    }
    func close() { q.sync { conn.close() } }
}
