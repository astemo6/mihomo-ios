import XCTest
@testable import Mihomo

/// sing-mux h2mux: preamble/stream-request bytes and the multi-stream
/// HTTP/2 core exercised with fixtures.
final class NativeCoreMuxTests: XCTestCase {
    func testPreambleAndStreamRequest() {
        XCTAssertEqual([UInt8](NCMux.preamble()), [0x00, 0x02]) // v0, protocol h2mux
        let req = NCMux.streamRequestTCP(target: NCTarget(host: "example.com", port: 443))
        XCTAssertEqual([UInt8](req.prefix(2)), [0x00, 0x00]) // flags: TCP
        XCTAssertEqual(Data(req.dropFirst(2)), NCTarget(host: "example.com", port: 443).atypEncoded)
        XCTAssertEqual(NCMux.destination.host, "sp.mux.sing-box.arpa")
        XCTAssertEqual(NCMux.destination.port, 444)
    }

    func testStreamResponseParsing() {
        XCTAssertEqual(NCMux.parseStreamResponse(Data([0x00, 0xff]))?.ok, true)
        XCTAssertEqual(NCMux.parseStreamResponse(Data([0x00, 0xff]))?.consumed, 1)
        XCTAssertNil(NCMux.parseStreamResponse(Data()))
        XCTAssertNil(NCMux.parseStreamResponse(Data([0x01, 0x00]))) // incomplete message
        let err = NCMux.parseStreamResponse(Data([0x01, 0x00, 0x03]) + Data("bad".utf8))
        XCTAssertEqual(err?.ok, false)
        XCTAssertEqual(err?.message, "bad")
        XCTAssertEqual(err?.consumed, 6)
    }

    func testUDPPacketFrames() {
        let frame = NCMux.udpPacketFrame(target: NCTarget(host: "8.8.8.8", port: 53),
                                         payload: Data("query".utf8))
        let parsed = NCMux.parseUDPPacketFrame(frame + Data([0x00]))
        XCTAssertEqual(parsed?.0, NCTarget(host: "8.8.8.8", port: 53))
        XCTAssertEqual(parsed?.1, Data("query".utf8))
        XCTAssertEqual(parsed?.2, frame.count)
    }

    func testMuxCoreStreamLifecycle() {
        let core = NCH2MuxCore()
        let start = core.start()
        XCTAssertTrue([UInt8](start).starts(with: [UInt8](NCH2ClientCore.preface)))
        let (id, headers) = core.openStream()
        XCTAssertEqual(id, 1)
        XCTAssertEqual(headers[3], 0x1) // HEADERS
        // App data within the initial window.
        let (frames, consumed) = core.makeData(streamID: id, data: Data("hello".utf8))
        XCTAssertEqual(consumed, 5)
        XCTAssertFalse(frames.isEmpty)
        // Server responds: HEADERS (:status 200) + DATA "world" + WU.
        var inbound = NCH2ClientCore.frame(type: 0x1, flags: 0x4, streamID: id,
                                           payload: NCHPACK.encodeHeaders([(":status", "200")]))
        inbound.append(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: id, payload: Data("world".utf8)))
        let result = core.feed(inbound)
        XCTAssertTrue(result.events.contains {
            if case .responseHeaders(let sid, _) = $0 { return sid == id }
            return false
        })
        XCTAssertTrue(result.events.contains {
            if case .payload(let sid, let d) = $0 { return sid == id && d == Data("world".utf8) }
            return false
        })
        // Second stream gets id 3.
        XCTAssertEqual(core.openStream().0, 3)
        // RST surfaces.
        let rst = core.feed(NCH2ClientCore.frame(type: 0x3, flags: 0, streamID: id, payload: Data(count: 4)))
        XCTAssertTrue(rst.events.contains {
            if case .reset(let sid) = $0 { return sid == id }
            return false
        })
    }
}
