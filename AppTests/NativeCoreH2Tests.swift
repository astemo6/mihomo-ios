import XCTest
@testable import Mihomo

/// HTTP/2 client core driven purely with byte fixtures.
final class NativeCoreH2Tests: XCTestCase {
    func testStartEmitsPrefaceSettingsHeaders() {
        let core = NCH2ClientCore()
        let out = core.start(headers: [(":method", "POST"), (":path", "/GunService/Tun"),
                                       (":scheme", "https"), (":authority", "example.com")])
        XCTAssertTrue([UInt8](out).starts(with: [UInt8](NCH2ClientCore.preface)))
        var rest = Data(out.dropFirst(NCH2ClientCore.preface.count))
        // SETTINGS frame: length 0, type 4, stream 0.
        XCTAssertEqual(rest[2], 0)
        XCTAssertEqual(rest[3], 0x4)
        rest = Data(rest.dropFirst(9))
        // HEADERS frame on stream 1 with END_HEADERS.
        XCTAssertEqual(rest[3], 0x1)
        XCTAssertEqual(rest[4] & 0x4, 0x4)
        XCTAssertEqual(rest[8], 1)
    }

    func testServerSettingsAckedAndDataReturnedWithWindowUpdates() {
        let core = NCH2ClientCore()
        _ = core.start(headers: [(":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", "h")])
        // Server SETTINGS with INITIAL_WINDOW_SIZE 100000.
        var settings = Data()
        settings.append(contentsOf: [0x00, 0x04, 0x00, 0x01, 0x86, 0xa0]) // id 0x4 (fix/nc-h2-cidr: was 0x3)
        var inbound = NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0, payload: settings)
        inbound.append(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: 1, payload: Data("hello".utf8)))
        let result = core.feed(inbound)
        XCTAssertEqual(result.payloads, [Data("hello".utf8)])
        // Outbound must contain: SETTINGS ACK + 2 WINDOW_UPDATE frames.
        XCTAssertTrue(containsFrame(result.outbound, type: 0x4, flags: 0x1))
        XCTAssertEqual(countFrames(result.outbound, type: 0x8), 2)
        XCTAssertEqual(core.streamSendWindow, 65535 + (100000 - 65535))
    }

    func testPingAckedVerbatim() {
        let core = NCH2ClientCore()
        let payload = Data([1, 2, 3, 4, 5, 6, 7, 8])
        let result = core.feed(NCH2ClientCore.frame(type: 0x6, flags: 0, streamID: 0, payload: payload))
        XCTAssertEqual(result.outbound, NCH2ClientCore.frame(type: 0x6, flags: 0x1, streamID: 0, payload: payload))
    }

    func testDataFramesHonorWindow() {
        let core = NCH2ClientCore()
        let big = Data(repeating: 0x61, count: 70000)
        let (frames, consumed) = core.makeData(big)
        XCTAssertEqual(consumed, 65535) // both windows start at 65535
        XCTAssertFalse(frames.isEmpty)
        // After a WINDOW_UPDATE of 100000 on the stream AND connection, rest flows.
        let wu = NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: 0, payload: Data([0x00, 0x01, 0x86, 0xa0]))
        _ = core.feed(wu)
        let wu2 = NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: 1, payload: Data([0x00, 0x01, 0x86, 0xa0]))
        _ = core.feed(wu2)
        let (_, consumed2) = core.makeData(Data(big.dropFirst(consumed)))
        XCTAssertEqual(consumed + consumed2, 70000)
    }

    func testResponseHeadersDecoded() {
        let core = NCH2ClientCore()
        _ = core.start(headers: [(":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", "h")])
        let block = NCHPACK.encodeHeaders([(":status", "200"), ("content-type", "application/grpc")])
        let result = core.feed(NCH2ClientCore.frame(type: 0x1, flags: 0x4, streamID: 1, payload: block))
        XCTAssertEqual(result.events.count, 1)
        if case .headers(let headers) = result.events[0] {
            XCTAssertTrue(headers.contains { $0.0 == ":status" && $0.1 == "200" })
        } else { XCTFail("expected headers event") }
    }

    private func containsFrame(_ data: Data, type: UInt8, flags: UInt8) -> Bool {
        countFrames(data, type: type, flags: flags) > 0
    }

    private func countFrames(_ data: Data, type: UInt8, flags: UInt8? = nil) -> Int {
        var count = 0
        var rest = data
        while rest.count >= 9 {
            let len = Int(rest[0]) << 16 | Int(rest[1]) << 8 | Int(rest[2])
            if rest[3] == type && (flags == nil || rest[4] == flags) { count += 1 }
            rest = Data(rest.dropFirst(9 + len))
        }
        return count
    }
}
