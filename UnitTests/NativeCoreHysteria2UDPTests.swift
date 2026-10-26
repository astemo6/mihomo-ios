import XCTest
@testable import Mihomo

/// Hysteria2 UDPMessage codec (Shared/NativeCore/NCHysteria2UDPCodec.swift): the spec wire layout
/// (apernet/hysteria PROTOCOL.md — uint32 session ID, uint16 packet ID, u8 frag ID / count, varint
/// address length, address, payload; byte-identical to sing-quic hysteria2 udpMessage.pack),
/// fragmentation at the datagram limit and reassembly (order, duplicates, count mismatch, caps).
/// Also the thread-safe HPACK Huffman table the QPACK auth response decode relies on.
final class NativeCoreHysteria2UDPTests: XCTestCase {

    private static func hex(_ s: String) -> Data {
        var out = Data()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }

    private static func pattern(_ n: Int) -> Data { Data((0..<n).map { UInt8(($0 * 7 + 3) & 0xff) }) }

    // MARK: Wire layout

    func testEncodeMatchesSpecLayout() {
        let frame = NCHy2UDP.encodeFrame(sessionID: 0x0102_0304, packetID: 0x0506, fragID: 0, fragCount: 1,
                                         address: "1.2.3.4:53", payload: Data("hi".utf8))
        // 01020304 | 0506 | 00 | 01 | 0a | "1.2.3.4:53" | "hi"
        XCTAssertEqual(frame, Self.hex("01020304" + "0506" + "00" + "01" + "0a" + "312e322e332e343a3533" + "6869"))
        XCTAssertEqual(NCHy2UDP.headerSize(address: "1.2.3.4:53"), 8 + 1 + 10)
    }

    func testSessionIDIsFixedWidthNotVarint() {
        // A small session ID is still 4 bytes, packet ID 2 (the old codec wrote varints here).
        let frame = NCHy2UDP.encodeFrame(sessionID: 1, packetID: 1, fragID: 0, fragCount: 1,
                                         address: "a:1", payload: Data())
        XCTAssertEqual(Array(frame.prefix(8)), [0, 0, 0, 1, 0, 1, 0, 1])
        XCTAssertEqual(NCHy2UDP.peekSessionID(frame), 1)
    }

    func testDecodeRoundTripAndLongAddressVarint() throws {
        let host = String(repeating: "h", count: 70) + ".example"   // > 63 → 2-byte varint length
        let address = host + ":443"
        let payload = Self.pattern(300)
        let wire = NCHy2UDP.encodeFrame(sessionID: 0xdead_beef, packetID: 0xfffe, fragID: 2, fragCount: 3,
                                        address: address, payload: payload)
        XCTAssertEqual(wire[8] & 0xc0, 0x40, "address length must be a 2-byte QUIC varint")
        let frame = try XCTUnwrap(NCHy2UDP.decodeFrame(wire))
        XCTAssertEqual(frame, NCHy2UDP.Frame(sessionID: 0xdead_beef, packetID: 0xfffe, fragID: 2, fragCount: 3,
                                             address: address, payload: payload))
        // Decoding a non-zero-based slice works too.
        var padded = Data([0xaa, 0xbb])
        padded.append(wire)
        XCTAssertEqual(NCHy2UDP.decodeFrame(padded.dropFirst(2)), frame)
    }

    func testDecodeRejectsMalformed() {
        XCTAssertNil(NCHy2UDP.decodeFrame(Data([0, 0, 0, 1, 0, 0, 0])))                     // short header
        XCTAssertNil(NCHy2UDP.decodeFrame(Data([0, 0, 0, 1, 0, 0, 0, 0, 0])))               // frag count 0
        XCTAssertNil(NCHy2UDP.decodeFrame(Data([0, 0, 0, 1, 0, 0, 2, 2, 0])))               // frag ID ≥ count
        XCTAssertNil(NCHy2UDP.decodeFrame(Data([0, 0, 0, 1, 0, 0, 0, 1, 9, 0x61])))         // address truncated
    }

    func testIPv6AddressIsBracketed() {
        XCTAssertEqual(NCHysteria2Connection.udpAddress(NCTarget(host: "2001:db8::1", port: 53)), "[2001:db8::1]:53")
        XCTAssertEqual(NCHysteria2Connection.udpAddress(NCTarget(host: "1.1.1.1", port: 53)), "1.1.1.1:53")
        XCTAssertEqual(NCHysteria2Connection.udpAddress(NCTarget(host: "dns.google", port: 853)), "dns.google:853")
    }

    // MARK: Fragmentation

    func testSmallPacketIsOneFrame() throws {
        let frames = NCHy2UDP.fragment(sessionID: 7, packetID: 9, address: "1.1.1.1:53", payload: Self.pattern(100))
        XCTAssertEqual(frames.count, 1)
        let f = try XCTUnwrap(NCHy2UDP.decodeFrame(frames[0]))
        XCTAssertEqual(f.fragCount, 1)
        XCTAssertEqual(f.fragID, 0)
    }

    func testFragmentSizesAndHeaders() throws {
        let address = "127.0.0.1:18081"
        let header = NCHy2UDP.headerSize(address: address)
        let room = NCHy2UDP.maxDatagramSize - header
        let payload = Self.pattern(room * 2 + 17)
        let frames = NCHy2UDP.fragment(sessionID: 42, packetID: 300, address: address, payload: payload)
        XCTAssertEqual(frames.count, 3)
        XCTAssertEqual(frames.map(\.count), [NCHy2UDP.maxDatagramSize, NCHy2UDP.maxDatagramSize, header + 17])
        var joined = Data()
        for (i, wire) in frames.enumerated() {
            let f = try XCTUnwrap(NCHy2UDP.decodeFrame(wire))
            XCTAssertEqual(f.sessionID, 42)
            XCTAssertEqual(f.packetID, 300)
            XCTAssertEqual(f.fragID, UInt8(i))
            XCTAssertEqual(f.fragCount, 3)
            XCTAssertEqual(f.address, address, "every fragment repeats the address (hysteria requires it)")
            joined.append(f.payload)
        }
        XCTAssertEqual(joined, payload)
    }

    func testExactRoomIsNotFragmented() {
        let address = "1.1.1.1:53"
        let room = NCHy2UDP.maxDatagramSize - NCHy2UDP.headerSize(address: address)
        XCTAssertEqual(NCHy2UDP.fragment(sessionID: 1, packetID: 1, address: address, payload: Self.pattern(room)).count, 1)
        XCTAssertEqual(NCHy2UDP.fragment(sessionID: 1, packetID: 1, address: address, payload: Self.pattern(room + 1)).count, 2)
    }

    func testCustomLimitAndUncarriablePackets() {
        let address = "1.1.1.1:53"
        // Lowered limit (EMSGSIZE / path metadata) fragments finer.
        let frames = NCHy2UDP.fragment(sessionID: 1, packetID: 1, address: address,
                                       payload: Self.pattern(1000), maxDatagramSize: 519)
        XCTAssertEqual(frames.count, 2)
        XCTAssertTrue(frames.allSatisfy { $0.count <= 519 })
        // Header alone does not fit, or > 255 fragments: dropped, never truncated.
        XCTAssertTrue(NCHy2UDP.fragment(sessionID: 1, packetID: 1, address: address,
                                        payload: Self.pattern(10), maxDatagramSize: 10).isEmpty)
        XCTAssertTrue(NCHy2UDP.fragment(sessionID: 1, packetID: 1, address: address,
                                        payload: Self.pattern(256 * 64), maxDatagramSize: 19 + 64).isEmpty)
    }

    // MARK: Reassembly

    private func frames(_ payload: Data, packetID: UInt16 = 1, limit: Int = 200) -> [NCHy2UDP.Frame] {
        NCHy2UDP.fragment(sessionID: 5, packetID: packetID, address: "1.1.1.1:53", payload: payload,
                          maxDatagramSize: limit).compactMap(NCHy2UDP.decodeFrame)
    }

    func testReassembleInOrderAndOutOfOrder() {
        let payload = Self.pattern(1000)
        var r = NCHy2UDP.Reassembler()
        let fs = frames(payload)
        XCTAssertGreaterThan(fs.count, 3)
        for f in fs.dropLast() { XCTAssertNil(r.feed(f)) }
        XCTAssertEqual(r.feed(fs.last!), payload)
        XCTAssertEqual(r.openPackets, 0)

        var r2 = NCHy2UDP.Reassembler()
        let shuffled = Array(fs.reversed())
        var out: Data?
        for f in shuffled { if let d = r2.feed(f) { XCTAssertNil(out); out = d } }
        XCTAssertEqual(out, payload)
    }

    func testDuplicateFragmentIgnoredAndDeliveredOnce() {
        let payload = Self.pattern(500)
        let fs = frames(payload)
        var r = NCHy2UDP.Reassembler()
        XCTAssertNil(r.feed(fs[0]))
        XCTAssertNil(r.feed(fs[0]))
        var delivered = 0
        for f in fs.dropFirst() { if r.feed(f) == payload { delivered += 1 } }
        XCTAssertEqual(delivered, 1)
        XCTAssertNil(r.feed(fs.last!), "a late duplicate after completion starts a new partial, never re-delivers")
    }

    func testInterleavedPackets() {
        let a = Self.pattern(600), b = Data(Self.pattern(700).reversed())
        let fa = frames(a, packetID: 10), fb = frames(b, packetID: 11)
        var r = NCHy2UDP.Reassembler()
        var got: [Data] = []
        for i in 0..<max(fa.count, fb.count) {
            if i < fa.count, let d = r.feed(fa[i]) { got.append(d) }
            if i < fb.count, let d = r.feed(fb[i]) { got.append(d) }
        }
        XCTAssertEqual(Set(got), Set([a, b]))
    }

    func testFragCountMismatchRestartsPacket() {
        var r = NCHy2UDP.Reassembler()
        let old = frames(Self.pattern(500), packetID: 3)            // e.g. 3 fragments
        XCTAssertNil(r.feed(old[0]))
        let fresh = frames(Self.pattern(900), packetID: 3)          // same ID, different count
        XCTAssertNotEqual(old.count, fresh.count)
        var out: Data?
        for f in fresh { if let d = r.feed(f) { out = d } }
        XCTAssertEqual(out, Self.pattern(900))
    }

    func testOpenPacketCapEvictsOldest() {
        var r = NCHy2UDP.Reassembler()
        let n = NCHy2UDP.Reassembler.maxOpenPackets
        var firsts: [[NCHy2UDP.Frame]] = []
        for id in 0...UInt16(n) {
            let fs = frames(Self.pattern(500), packetID: id)
            firsts.append(fs)
            XCTAssertNil(r.feed(fs[0]))
        }
        XCTAssertEqual(r.openPackets, n)
        // Packet 0 was evicted: its remaining fragments alone cannot complete it.
        var out0: Data?
        for f in firsts[0].dropFirst() { if let d = r.feed(f) { out0 = d } }
        XCTAssertNil(out0)
        // The newest one still completes.
        var outN: Data?
        for f in firsts[n].dropFirst() { if let d = r.feed(f) { outN = d } }
        XCTAssertEqual(outN, Self.pattern(500))
    }

    func testPerPacketByteCap() {
        var r = NCHy2UDP.Reassembler()
        // 255 fragments × 300 B = 76.5 KB > 64 KB cap.
        let big = frames(Self.pattern(255 * (300 - 19)), packetID: 1, limit: 300)
        XCTAssertEqual(big.count, 255)
        var out: Data?
        for f in big { if let d = r.feed(f) { out = d } }
        XCTAssertNil(out)
        XCTAssertLessThanOrEqual(r.openPackets, 1)
    }

    func testSingleFragmentPassesThrough() {
        var r = NCHy2UDP.Reassembler()
        let f = NCHy2UDP.Frame(sessionID: 1, packetID: 9, fragID: 0, fragCount: 1, address: "a:1", payload: Data([1, 2]))
        XCTAssertEqual(r.feed(f), Data([1, 2]))
        XCTAssertEqual(r.openPackets, 0)
    }

    // MARK: HPACK Huffman table (static let, thread-safe lazy init)

    func testHuffmanDecodeConcurrentFirstUse() {
        // RFC 7541 C.4.1: "www.example.com".
        let encoded = Self.hex("f1e3c2e5f23a6ba0ab90f4ff")
        let lock = NSLock()
        var ok = 0
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            let good = NCHPACK.huffmanDecode(encoded) == Data("www.example.com".utf8)
            lock.lock(); if good { ok += 1 }; lock.unlock()
        }
        XCTAssertEqual(ok, 64)
        XCTAssertEqual(NCHPACK.huffmanLookup.count, 256)
    }
}
