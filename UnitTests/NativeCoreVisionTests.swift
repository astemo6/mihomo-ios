import XCTest
@testable import Tern

/// Deterministic tests for the xtls-rprx-vision padding state machines
/// (NCVision.swift), ported from Clash.Meta's transport/vless/vision. Randomness
/// is pinned through NCVisionWriter.randomBelow so frame layouts are exact.
final class NativeCoreVisionTests: XCTestCase {
    private let uuid: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

    private func u16be(_ b: [UInt8], _ off: Int) -> Int {
        (Int(b[off]) << 8) | Int(b[off + 1])
    }

    /// Minimal TLS ServerHello record: 105 bytes total, record length 100
    /// (so remainingServerHello = 105 >= 79), session-id length 0 at [43],
    /// cipher 0x1301 at [44]. Optionally carries the TLS 1.3
    /// supported_versions pattern inside the record span.
    private func serverHello(tls13: Bool) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: 105)
        b[0] = 0x16; b[1] = 0x03; b[2] = 0x03 // record header
        b[3] = 0x00; b[4] = 100               // record length
        b[5] = 0x02                           // handshake type: ServerHello
        b[9] = 0x03; b[10] = 0x03             // legacy version
        b[43] = 0                             // session id length
        b[44] = 0x13; b[45] = 0x01            // TLS_AES_128_GCM_SHA256
        if tls13 {
            let sv: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
            for (i, v) in sv.enumerated() { b[60 + i] = v }
        }
        return b
    }

    private func appDataChunk() -> [UInt8] {
        [0x17, 0x03, 0x03, 0x00, 0x20] + [UInt8](repeating: 0x77, count: 32)
    }

    // MARK: Frame layout

    func testFirstFrameLayoutLongPadding() {
        // 100-byte ClientHello-shaped chunk → filter sees TLS → long padding.
        var chunk = [UInt8](repeating: 0xaa, count: 100)
        chunk[0] = 0x16; chunk[1] = 0x03; chunk[2] = 0x01
        chunk[3] = 0x00; chunk[4] = 95
        chunk[5] = 0x01 // ClientHello handshake type

        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 250 }
        let frames = writer.process(chunk)
        XCTAssertEqual(frames.count, 1)
        let f = frames[0]
        // paddingLen = 250 + 900 - 100 = 1050; total = 21 + 100 + 1050.
        XCTAssertEqual(f.count, 1171)
        XCTAssertEqual(Array(f[0..<16]), uuid)
        XCTAssertEqual(f[16], NCVision.commandContinue)
        XCTAssertEqual(u16be(f, 17), 100)
        XCTAssertEqual(u16be(f, 19), 1050)
        XCTAssertEqual(Array(f[21..<121]), chunk)
        XCTAssertTrue(f[121...].allSatisfy { $0 == 0 })
    }

    func testEmptyFirstWriteGetsLongPadding() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        let frames = writer.process([])
        XCTAssertEqual(frames.count, 1)
        let f = frames[0]
        XCTAssertEqual(f.count, 21 + 900)
        XCTAssertEqual(Array(f[0..<16]), uuid)
        XCTAssertEqual(f[16], NCVision.commandContinue)
        XCTAssertEqual(u16be(f, 17), 0)
        XCTAssertEqual(u16be(f, 19), 900)
    }

    func testContentAtLeast900HasNoPadding() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 123 } // must not influence the result
        let frames = writer.process([UInt8](repeating: 0x55, count: 900))
        XCTAssertEqual(frames.count, 1)
        let f = frames[0]
        XCTAssertEqual(f.count, 21 + 900)
        XCTAssertEqual(u16be(f, 17), 900)
        XCTAssertEqual(u16be(f, 19), 0)
    }

    func testSecondFrameHasNoUUID() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        _ = writer.process([UInt8](repeating: 0x61, count: 10))
        let frames = writer.process([UInt8](repeating: 0x62, count: 40))
        XCTAssertEqual(frames.count, 1)
        let f = frames[0]
        XCTAssertEqual(f[0], NCVision.commandContinue) // command comes first
        XCTAssertEqual(u16be(f, 1), 40)
        let pad = u16be(f, 3)
        XCTAssertEqual(f.count, 5 + 40 + pad)
    }

    // MARK: Round trip

    func testWriterReaderRoundTrip() throws {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { n in n / 2 }
        let chunks: [[UInt8]] = [
            [UInt8](repeating: 0x61, count: 200),
            [UInt8](repeating: 0x62, count: 50),
            (0..<2000).map { UInt8(0x61 + ($0 % 26)) },
        ]
        var wire: [UInt8] = []
        for c in chunks { for f in writer.process(c) { wire += f } }

        var reader = NCVisionReader(userUUID: uuid)
        var received: [UInt8] = []
        var i = 0
        while i < wire.count {
            let n = min(7, wire.count - i) // awkward splits across every boundary
            for piece in try reader.feed(Array(wire[i..<(i + n)])) { received += piece }
            i += n
        }
        XCTAssertEqual(received, chunks.flatMap { $0 })
        XCTAssertFalse(reader.passthrough)
        XCTAssertFalse(reader.directRequested)
    }

    // MARK: Reader errors and filter

    func testReaderRejectsWrongUUID() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        let wire = writer.process([UInt8](repeating: 0x61, count: 10))[0]

        var other = uuid
        other[0] = 0xff
        var reader = NCVisionReader(userUUID: other)
        XCTAssertThrowsError(try reader.feed(wire)) { error in
            XCTAssertEqual(error as? NCVisionError, .unknownServerUUID)
        }
    }

    func testFilterDetectsTLS13() {
        let filter = NCVisionFilter()
        filter.filter(serverHello(tls13: true))
        XCTAssertTrue(filter.isTLS)
        XCTAssertTrue(filter.isTLS12orAbove)
        XCTAssertTrue(filter.enableXTLS)
        XCTAssertEqual(filter.cipher, 0x1301)
        XCTAssertEqual(filter.packetsToFilter, 0)
    }

    func testFilterDetectsTLS12() {
        let filter = NCVisionFilter()
        filter.filter(serverHello(tls13: false))
        XCTAssertTrue(filter.isTLS)
        XCTAssertTrue(filter.isTLS12orAbove)
        XCTAssertFalse(filter.enableXTLS)
        XCTAssertEqual(filter.packetsToFilter, 0)
    }

    // MARK: Writer end / direct switching

    func testWriterEndsAfterTLS12ServerHello() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        _ = writer.process(serverHello(tls13: false))
        let frames = writer.process(appDataChunk())
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0][0], NCVision.commandEnd) // 2nd frame: no UUID
        XCTAssertFalse(writer.isDirect)
        XCTAssertFalse(writer.isFiltering)
        // From now on, chunks pass through raw.
        XCTAssertEqual(writer.process([1, 2, 3]), [[1, 2, 3]])
    }

    func testWriterGoesDirectAfterTLS13ServerHello() {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        _ = writer.process(serverHello(tls13: true))
        let frames = writer.process(appDataChunk())
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0][0], NCVision.commandDirect)
        XCTAssertTrue(writer.isDirect)
        XCTAssertFalse(writer.isFiltering)
    }

    func testReaderEndsPassthroughOnEndCommand() throws {
        // Drive a real end: writer sees TLS 1.2 ServerHello + app data.
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        var wire: [UInt8] = []
        for f in writer.process(serverHello(tls13: false)) { wire += f }
        for f in writer.process(appDataChunk()) { wire += f }
        let tail: [UInt8] = [9, 8, 7, 6]
        for f in writer.process(tail) { wire += f } // writer already raw

        var reader = NCVisionReader(userUUID: uuid)
        var received: [UInt8] = []
        for piece in try reader.feed(wire) { received += piece }
        XCTAssertEqual(received, serverHello(tls13: false) + appDataChunk() + tail)
        XCTAssertTrue(reader.passthrough)
        XCTAssertFalse(reader.directRequested)
    }
}
