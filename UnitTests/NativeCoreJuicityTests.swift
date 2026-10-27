import XCTest
@testable import Tern

/// Juicity wire codecs (Shared/NativeCore/NCJuicity.swift) against daeuniverse/outbound protocol/juicity +
/// protocol/trojanc (the code the juicity server runs): trojanc ATYP 1/3/4, network byte 1 = TCP / 3 = UDP,
/// UDP frames [addr][len u16 BE][payload], auth [ver 0][cmd 0][uuid 16][token 32].
final class NativeCoreJuicityTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testUUIDBytes() {
        let u = NCJuicityWire.uuidBytes("00112233-4455-6677-8899-aabbccddeeff")
        XCTAssertEqual(u.map(hex), "00112233445566778899aabbccddeeff")
        XCTAssertEqual(NCJuicityWire.uuidBytes("00112233445566778899AABBCCDDEEFF").map(hex),
                       "00112233445566778899aabbccddeeff")
        XCTAssertNil(NCJuicityWire.uuidBytes("not-a-uuid"))
        XCTAssertNil(NCJuicityWire.uuidBytes("00112233-4455-6677-8899-aabbccddeezz"))
    }

    func testRequestHeaders() {
        let v4 = NCTarget(host: "1.2.3.4", port: 443)
        XCTAssertEqual(hex(NCJuicityWire.tcpRequestHeader(target: v4)), "010101020304" + "01bb")
        XCTAssertEqual(hex(NCJuicityWire.udpRequestHeader(target: v4)), "030101020304" + "01bb")
        let dom = NCTarget(host: "a.io", port: 53)
        XCTAssertEqual(hex(NCJuicityWire.tcpRequestHeader(target: dom)), "0103" + "04" + "612e696f" + "0035")
        let v6 = NCTarget(host: "::1", port: 80)
        XCTAssertEqual(hex(NCJuicityWire.udpRequestHeader(target: v6)),
                       "0304" + "00000000000000000000000000000001" + "0050")
    }

    func testUDPFrameRoundTripAndPartial() {
        let t = NCTarget(host: "8.8.8.8", port: 53)
        let payload = Data([0xde, 0xad, 0xbe, 0xef])
        let frame = NCJuicityWire.sealUDPPacket(target: t, payload: payload)
        XCTAssertEqual(hex(frame), "01080808080035" + "0004" + "deadbeef")
        // Two frames back to back, second one cut short: the first parses, the second waits for more bytes.
        var buf = frame
        buf.append(NCJuicityWire.sealUDPPacket(target: NCTarget(host: "x.y", port: 1), payload: Data([1, 2, 3])))
        let first = NCJuicityWire.unsealUDPPacket(buf)
        XCTAssertEqual(first?.payload, payload)
        XCTAssertEqual(first?.consumed, frame.count)
        let second = NCJuicityWire.unsealUDPPacket(buf, at: frame.count)
        XCTAssertEqual(second?.payload, Data([1, 2, 3]))
        for cut in 1..<(buf.count - frame.count) {
            XCTAssertNil(NCJuicityWire.unsealUDPPacket(buf.prefix(frame.count + cut), at: frame.count), "cut \(cut)")
        }
        // Unknown ATYP is rejected, not read as a length.
        XCTAssertNil(NCJuicityWire.unsealUDPPacket(Data([0x02, 0, 0, 0, 0, 0, 0, 0, 0])))
    }

    func testAuthMessage() {
        let uuid = Data(repeating: 0xab, count: 16)
        let token = Data(repeating: 0xcd, count: 32)
        let m = NCJuicityWire.authMessage(uuid: uuid, token: token)
        XCTAssertEqual(m.count, 50)
        XCTAssertEqual(m.prefix(2), Data([0x00, 0x00]))
        XCTAssertEqual(m.subdata(in: 2..<18), uuid)
        XCTAssertEqual(m.suffix(32), token)
    }

    func testCertChainHash() {
        // juicity common.GenerateCertChainHash: h = sha256(c0); h = sha256(h || sha256(ci)).
        let leaf = Data("cert-leaf".utf8), mid = Data("cert-intermediate".utf8)
        XCTAssertEqual(NCJuicityWire.generateCertChainHash(rawCerts: [leaf]).map(hex),
                       "a6c2dea4828947009fa7e4e9069ad7dcd7869872b9f837639ef08811004d480c")
        XCTAssertEqual(NCJuicityWire.generateCertChainHash(rawCerts: [leaf, mid]).map(hex),
                       "22ff500621d26abc01305388b326c9f51c70698bcddf83c2a68babd7e720b4e0")
        XCTAssertNil(NCJuicityWire.generateCertChainHash(rawCerts: []))
    }

    func testParseHash() {
        let raw = Data((0..<32).map { UInt8($0) })
        XCTAssertEqual(NCJuicityWire.parseHash(raw.base64EncodedString()), raw)
        let hexStr = raw.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(NCJuicityWire.parseHash(hexStr), raw)
        XCTAssertNil(NCJuicityWire.parseHash("  "))
    }

    func testStreamCapMatchesSpec() {
        // Spec: without a stream-availability API the client must open a new connection after 30 streams.
        XCTAssertEqual(NCJuicityConnection.maxStreamsPerConnection, 30)
    }
}
