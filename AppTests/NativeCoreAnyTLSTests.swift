import XCTest
import CryptoKit
@testable import Mihomo

/// AnyTLS framing/auth + UoT packet codec.
final class NativeCoreAnyTLSTests: XCTestCase {
    func testAuthBlock() {
        let block = NCAnyTLS.authBlock(password: "secret", paddingLen: 10)
        XCTAssertEqual(block.count, 32 + 2 + 10)
        XCTAssertEqual(Data(block.prefix(32)), Data(SHA256.hash(data: Data("secret".utf8))))
        XCTAssertEqual(Int(block[32]) << 8 | Int(block[33]), 10)
        XCTAssertTrue(block.suffix(10).allSatisfy { $0 == 0 })
    }

    func testSettingsFrame() {
        let frame = NCAnyTLS.settingsFrame(clientMetadata: "")
        var parser = NCAnyTLS.FrameParser()
        let frames = parser.feed(frame)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0].cmd, NCAnyTLS.cmdSettings)
        XCTAssertEqual(frames[0].streamID, 0)
        let text = String(decoding: frames[0].data, as: UTF8.self)
        XCTAssertTrue(text.contains("padding-md5=75cff2ad89aadf5e257059ee571ebe11"), text)
        XCTAssertTrue(text.contains("v=2"), text)
    }

    func testFrameParserFragmentation() {
        var wire = NCAnyTLS.frame(cmd: NCAnyTLS.cmdSYN, streamID: 7)
        wire.append(NCAnyTLS.frame(cmd: NCAnyTLS.cmdPSH, streamID: 7, data: Data("hello".utf8)))
        var parser = NCAnyTLS.FrameParser()
        var frames: [NCAnyTLS.Frame] = []
        for byte in wire { frames.append(contentsOf: parser.feed(Data([byte]))) }
        XCTAssertEqual(frames.count, 2)
        XCTAssertEqual(frames[1].data, Data("hello".utf8))
    }

    func testUoTPackets() {
        let req = NCUoT.request(destination: NCTarget(host: "dns.example", port: 53))
        XCTAssertEqual(req[0], 0)
        XCTAssertEqual(Data(req.dropFirst(1)), NCTarget(host: "dns.example", port: 53).atypEncoded)
        XCTAssertEqual(NCUoT.magicTarget.host, "sp.v2.udp-over-tcp.arpa")

        let packet = NCUoT.packet(target: NCTarget(host: "8.8.8.8", port: 53), payload: Data("q".utf8))
        XCTAssertEqual(packet[0], 0x00) // uot family byte: v4
        let parsed = NCUoT.parsePacket(packet + Data([0xff]))
        XCTAssertEqual(parsed?.0, NCTarget(host: "8.8.8.8", port: 53))
        XCTAssertEqual(parsed?.1, Data("q".utf8))
        XCTAssertEqual(parsed?.2, packet.count)

        let domainPacket = NCUoT.packet(target: NCTarget(host: "example.com", port: 443), payload: Data())
        XCTAssertEqual(domainPacket[0], 0x02) // uot family byte: fqdn
        XCTAssertEqual(NCUoT.parsePacket(domainPacket)?.0.host, "example.com")
    }
}
