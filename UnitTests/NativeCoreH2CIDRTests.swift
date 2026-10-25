import XCTest
@testable import Mihomo

/// fix/nc-h2-cidr:
/// - NCH2ClientCore / NCH2MuxCore read SETTINGS_INITIAL_WINDOW_SIZE from id 0x3 (MAX_CONCURRENT_STREAMS), so a
///   server advertising e.g. 100 concurrent streams shrank the send window to 100 bytes and stalled gRPC / h2
///   uploads. Peer SETTINGS are now validated per RFC 9113 §6.5.2 and window changes follow §6.9.2.
/// - HPACK dynamic table size updates are enforced (≤ 4096, applied at once).
/// - fake-ip-range6 (and NCCIDR) v6 prefixes not a multiple of 8 trapped in UInt8(0xff << n).
final class NativeCoreH2CIDRTests: XCTestCase {

    // MARK: helpers

    private func settings(_ pairs: [(Int, Int)]) -> Data {
        var p = Data()
        for (id, v) in pairs {
            p.append(contentsOf: [UInt8(id >> 8), UInt8(id & 0xff),
                                  UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff),
                                  UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
        }
        return NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0, payload: p)
    }

    private func windowUpdate(stream: Int, _ inc: Int) -> Data {
        NCH2ClientCore.frame(type: 0x8, flags: 0, streamID: stream,
                             payload: Data([UInt8((inc >> 24) & 0x7f), UInt8((inc >> 16) & 0xff),
                                            UInt8((inc >> 8) & 0xff), UInt8(inc & 0xff)]))
    }

    /// (type, flags, stream, payload) of every frame in `data`.
    private func frames(_ data: Data) -> [(UInt8, UInt8, Int, Data)] {
        var out: [(UInt8, UInt8, Int, Data)] = []
        let b = [UInt8](data)
        var i = 0
        while i + 9 <= b.count {
            let len = Int(b[i]) << 16 | Int(b[i + 1]) << 8 | Int(b[i + 2])
            let sid = Int(b[i + 5] & 0x7f) << 24 | Int(b[i + 6]) << 16 | Int(b[i + 7]) << 8 | Int(b[i + 8])
            guard i + 9 + len <= b.count else { break }
            out.append((b[i + 3], b[i + 4], sid, Data(b[(i + 9)..<(i + 9 + len)])))
            i += 9 + len
        }
        return out
    }

    /// Error code of the GOAWAY in `data`, nil when there is none.
    private func goawayCode(_ data: Data) -> Int? {
        guard let f = frames(data).first(where: { $0.0 == 0x7 }), f.3.count >= 8 else { return nil }
        let p = [UInt8](f.3)
        return Int(p[4]) << 24 | Int(p[5]) << 16 | Int(p[6]) << 8 | Int(p[7])
    }

    private func hasReset(_ r: NCH2ClientCore.FeedResult) -> Bool {
        r.events.contains { if case .reset = $0 { return true }; return false }
    }

    private func startedCore() -> NCH2ClientCore {
        let core = NCH2ClientCore()
        _ = core.start(headers: [(":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", "h")])
        return core
    }

    // MARK: NCH2ClientCore SETTINGS

    func testMaxConcurrentStreamsLeavesSendWindowAlone() {
        let core = startedCore()
        let r = core.feed(settings([(0x3, 100)])) // the setting that used to become a 100-byte window
        XCTAssertTrue(frames(r.outbound).contains { $0.0 == 0x4 && $0.1 == 0x1 }) // ACK
        XCTAssertNil(goawayCode(r.outbound))
        XCTAssertEqual(core.streamSendWindow, 65535)
        let (_, consumed) = core.makeData(Data(repeating: 0x61, count: 70000))
        XCTAssertEqual(consumed, 65535)
    }

    func testInitialWindowSizeIsId4() {
        let core = startedCore()
        _ = core.feed(settings([(0x3, 100), (0x4, 100_000)]))
        XCTAssertEqual(core.streamSendWindow, 100_000)
        XCTAssertEqual(core.connSendWindow, 65535) // §6.9.2: never the connection window
    }

    func testInitialWindowDeltaAppliesToOpenStreamAndMayGoNegative() {
        let core = startedCore()
        let (_, sent) = core.makeData(Data(repeating: 0x61, count: 60000))
        XCTAssertEqual(sent, 60000)
        XCTAssertEqual(core.streamSendWindow, 5535)
        _ = core.feed(settings([(0x4, 1000)]))
        XCTAssertEqual(core.streamSendWindow, 5535 + (1000 - 65535))
        XCTAssertLessThan(core.streamSendWindow, 0)
        XCTAssertEqual(core.makeData(Data(repeating: 0x61, count: 10)).consumed, 0)
        _ = core.feed(settings([(0x4, 200_000)]))
        XCTAssertEqual(core.streamSendWindow, 5535 + (200_000 - 65535))
        // Settings in one frame are applied in order.
        _ = core.feed(settings([(0x4, 1), (0x4, 65535)]))
        XCTAssertEqual(core.streamSendWindow, 5535)
    }

    func testInitialWindowAboveMaxIsFlowControlError() {
        let core = startedCore()
        let r = core.feed(settings([(0x4, 0x8000_0000)]))
        XCTAssertEqual(goawayCode(r.outbound), 0x3)
        XCTAssertTrue(hasReset(r))
        XCTAssertTrue(core.connectionFailed)
        XCTAssertFalse(frames(r.outbound).contains { $0.0 == 0x4 && $0.1 == 0x1 }) // no ACK
        // Everything after a connection error is dropped.
        let after = core.feed(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: 1, payload: Data("x".utf8)))
        XCTAssertTrue(after.outbound.isEmpty)
        XCTAssertTrue(after.payloads.isEmpty)
    }

    func testInitialWindowDeltaOverflowIsFlowControlError() {
        let core = startedCore()
        _ = core.feed(windowUpdate(stream: 1, 0x7fff_ffff - 65535))
        XCTAssertEqual(core.streamSendWindow, 0x7fff_ffff)
        let r = core.feed(settings([(0x4, 65536)])) // +1 → 2^31
        XCTAssertEqual(goawayCode(r.outbound), 0x3)
        XCTAssertTrue(core.connectionFailed)
    }

    func testMaxFrameSizeRange() {
        for bad in [0, 16383, 16_777_216] {
            let core = startedCore()
            let r = core.feed(settings([(0x5, bad)]))
            XCTAssertEqual(goawayCode(r.outbound), 0x1, "MAX_FRAME_SIZE \(bad)")
        }
        let core = startedCore()
        _ = core.feed(settings([(0x5, 32768), (0x4, 1_000_000)]))
        _ = core.feed(windowUpdate(stream: 0, 1_000_000))
        let (out, consumed) = core.makeData(Data(repeating: 0x61, count: 40000))
        XCTAssertEqual(consumed, 40000)
        XCTAssertEqual(frames(out).map { $0.3.count }, [32768, 40000 - 32768])
    }

    func testOtherSettingIds() {
        // HEADER_TABLE_SIZE (our encoder never indexes), ENABLE_PUSH 0/1, MAX_HEADER_LIST_SIZE, unknown: accepted.
        let core = startedCore()
        let r = core.feed(settings([(0x1, 0), (0x2, 0), (0x2, 1), (0x6, 8192), (0x99, 7)]))
        XCTAssertNil(goawayCode(r.outbound))
        XCTAssertEqual(core.streamSendWindow, 65535)
        XCTAssertFalse(core.connectionFailed)
        // ENABLE_PUSH other than 0/1 is a PROTOCOL_ERROR.
        let core2 = startedCore()
        XCTAssertEqual(goawayCode(core2.feed(settings([(0x2, 2)])).outbound), 0x1)
    }

    func testSettingsFrameShape() {
        let a = startedCore() // payload not a multiple of 6 → FRAME_SIZE_ERROR
        XCTAssertEqual(goawayCode(a.feed(NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 0,
                                                              payload: Data([0, 4, 0, 0, 1]))).outbound), 0x6)
        let b = startedCore() // SETTINGS on a stream → PROTOCOL_ERROR
        XCTAssertEqual(goawayCode(b.feed(NCH2ClientCore.frame(type: 0x4, flags: 0, streamID: 1,
                                                              payload: Data())).outbound), 0x1)
        let c = startedCore() // ACK with a payload → FRAME_SIZE_ERROR
        XCTAssertEqual(goawayCode(c.feed(NCH2ClientCore.frame(type: 0x4, flags: 0x1, streamID: 0,
                                                              payload: Data(count: 6))).outbound), 0x6)
        let d = startedCore() // plain ACK: nothing sent
        XCTAssertTrue(d.feed(NCH2ClientCore.frame(type: 0x4, flags: 0x1, streamID: 0, payload: Data())).outbound.isEmpty)
    }

    func testWindowUpdateOverflow() {
        let conn = startedCore()
        XCTAssertEqual(goawayCode(conn.feed(windowUpdate(stream: 0, 0x7fff_ffff)).outbound), 0x3)
        let stream = startedCore()
        let r = stream.feed(windowUpdate(stream: 1, 0x7fff_ffff))
        XCTAssertNil(goawayCode(r.outbound))
        XCTAssertTrue(frames(r.outbound).contains { $0.0 == 0x3 && $0.2 == 1 && $0.3 == Data([0, 0, 0, 3]) })
        XCTAssertTrue(hasReset(r))
    }

    // MARK: NCH2MuxCore SETTINGS

    func testMuxInitialWindowAppliesToEveryOpenStream() {
        let core = NCH2MuxCore()
        _ = core.start()
        let (a, _) = core.openStream()
        let (b, _) = core.openStream()
        _ = core.makeData(streamID: a, data: Data(repeating: 0x61, count: 1000))
        _ = core.feed(settings([(0x3, 100)]))
        XCTAssertEqual(core.streamWindow(a), 64535)
        XCTAssertEqual(core.streamWindow(b), 65535)
        let r = core.feed(settings([(0x4, 100_000)]))
        XCTAssertTrue(frames(r.outbound).contains { $0.0 == 0x4 && $0.1 == 0x1 })
        XCTAssertEqual(core.streamWindow(a), 99000)
        XCTAssertEqual(core.streamWindow(b), 100_000)
        let (c, _) = core.openStream()
        XCTAssertEqual(core.streamWindow(c), 100_000)
        XCTAssertEqual(core.connSendWindow, 65535 - 1000)
    }

    func testMuxConnectionErrors() {
        let core = NCH2MuxCore()
        _ = core.start()
        _ = core.openStream()
        let r = core.feed(settings([(0x4, 0x8000_0000)]))
        XCTAssertEqual(goawayCode(r.outbound), 0x3)
        XCTAssertTrue(r.events.contains { if case .goaway = $0 { return true }; return false })
        XCTAssertTrue(core.connectionFailed)
        XCTAssertTrue(core.feed(settings([(0x3, 1)])).outbound.isEmpty)

        let core2 = NCH2MuxCore()
        _ = core2.start()
        XCTAssertEqual(goawayCode(core2.feed(settings([(0x5, 100)])).outbound), 0x1)
    }

    // MARK: HPACK dynamic table size update

    func testHPACKTableSizeUpdate() {
        let dec = NCHPACKDecoder()
        // Literal with incremental indexing, new name "x-a": "1" → dynamic index 62.
        let insert = Data([0x40, 0x03]) + Data("x-a".utf8) + Data([0x01]) + Data("1".utf8)
        XCTAssertEqual(dec.decode(insert)?.first?.0, "x-a")
        XCTAssertEqual(dec.decode(Data([0xbe]))?.first?.1, "1")
        // Size update to 4096 (== our SETTINGS default) is fine; above it is a decoding error.
        XCTAssertNotNil(dec.decode(Data([0x3f, 0xe1, 0x1f])))
        XCTAssertNil(dec.decode(Data([0x3f, 0xe2, 0x1f])))
        // Size update to 0 evicts everything: index 62 is gone.
        let dec2 = NCHPACKDecoder()
        _ = dec2.decode(insert)
        XCTAssertNil(dec2.decode(Data([0x20, 0xbe])))
    }

    // MARK: fake-ip-range6 / NCCIDR odd v6 prefixes

    func testFakeIPRange6PrefixNotMultipleOf8() {
        let p60 = NCFakeIPPool(range: "198.18.0.1/16", range6: "fdfe:dcba:9876::/60")
        let a = p60.address6(for: "a.example")
        XCTAssertNotNil(a)
        if let a { XCTAssertTrue(p60.isFakeAddress(a)) }
        XCTAssertTrue(p60.isFakeAddress(NCIP("fdfe:dcba:9876:f::1")!))
        XCTAssertFalse(p60.isFakeAddress(NCIP("fdfe:dcba:9876:10::1")!))
        XCTAssertFalse(p60.isFakeAddress(NCIP("fdfe:dcba:9877::1")!))
        XCTAssertFalse(p60.isFakeAddress(NCIP("198.19.0.1")!))

        let p7 = NCFakeIPPool(range: "198.18.0.1/16", range6: "fc00::/7")
        XCTAssertTrue(p7.isFakeAddress(NCIP("fd12::1")!))
        XCTAssertTrue(p7.isFakeAddress(NCIP("fc00::1")!))
        XCTAssertFalse(p7.isFakeAddress(NCIP("fe00::1")!))
        if case .v6(let b)? = p7.address6(for: "b.example") { XCTAssertEqual(b[0] & 0xfe, 0xfc) }
        else { XCTFail("no v6 fake address for /7") }

        let p10 = NCFakeIPPool(range: "198.18.0.1/16", range6: "fe80::/10")
        XCTAssertTrue(p10.isFakeAddress(NCIP("febf::1")!))
        XCTAssertFalse(p10.isFakeAddress(NCIP("fec0::1")!))
        XCTAssertNotNil(p10.address6(for: "c.example"))

        // Host bits in the configured range are masked off the base (UInt8 shift path).
        let dirty = NCFakeIPPool(range: "198.18.0.1/16", range6: "fdfe:dcba:9876:5::/60")
        XCTAssertTrue(dirty.isFakeAddress(NCIP("fdfe:dcba:9876::1")!))
        if case .v6(let b)? = dirty.address6(for: "d.example") { XCTAssertEqual(b[7], 0) } // host nibble 0x5 cleared
        else { XCTFail("no v6 fake address for dirty /60") }
    }

    func testCIDRV6OddPrefix() {
        XCTAssertTrue(NCCIDR("fe80::/10")!.contains(NCIP("fe80::2")!))
        XCTAssertTrue(NCCIDR("fe80::/10")!.contains(NCIP("febf::1")!))
        XCTAssertFalse(NCCIDR("fe80::/10")!.contains(NCIP("fec0::1")!))
        XCTAssertTrue(NCCIDR("fc00::/7")!.contains(NCIP("fd12::1")!))
        XCTAssertFalse(NCCIDR("fc00::/7")!.contains(NCIP("fe00::1")!))
        XCTAssertTrue(NCCIDR("fdfe:dcba:9876::/60")!.contains(NCIP("fdfe:dcba:9876:f::1")!))
        XCTAssertFalse(NCCIDR("fdfe:dcba:9876::/60")!.contains(NCIP("fdfe:dcba:9876:10::1")!))
    }
}
