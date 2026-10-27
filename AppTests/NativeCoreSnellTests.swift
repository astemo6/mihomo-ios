import XCTest
@testable import Tern

/// Snell: KDF is the old-core-verified Argon2id output truncated; framing is
/// validated by round-trips anchored on that key.
final class NativeCoreSnellTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testSessionKeyMatchesArgon2() {
        let salt = Data((0..<16).map { UInt8($0) })
        // Full 32-byte Argon2id for "my-snell-psk" (the old core vector); the AES
        // session key is its first 16 bytes.
        let key = NCSnell.sessionKey(psk: Data("my-snell-psk".utf8), salt: salt, keySize: 16)
        XCTAssertEqual(hex(key), "8eb893d1afc12e85718ec026071d1043771ed164")
        let key32 = NCSnell.sessionKey(psk: Data("my-snell-psk".utf8), salt: salt, keySize: 32)
        XCTAssertEqual(hex(key32), "8eb893d1afc12e85718ec026071d1043771ed164c8720d2a0b9fb9165b4d150a")
    }

    func testConnectHeader() {
        let h = NCSnell.connectHeader(host: "example.com", port: 443, version: 1)
        XCTAssertEqual([UInt8](h), [0x01, 0x01, 0x00, 11] + [UInt8]("example.com".utf8) + [0x01, 0xbb])
        let h2 = NCSnell.connectHeader(host: "a.b", port: 80, version: 2)
        XCTAssertEqual(h2[1], 0x05) // connect-v2 command
    }

    func testReplyParsing() {
        XCTAssertEqual(NCSnell.parseReply(Data([0x00, 0x99])).consumedOrNil, 1)
        let err = NCSnell.parseReply(Data([0x02, 0x03, 0x03]) + Data("bad".utf8))
        if case .error(let msg) = err {
            XCTAssertTrue(msg.contains("code 3"), msg)
            XCTAssertTrue(msg.contains("bad"), msg)
        } else { XCTFail("expected error, got \(err)") }
        if case .pending = NCSnell.parseReply(Data([0x02, 0x03])) {} else {
            XCTFail("short error frame must be pending")
        }
    }

    func testV123StreamRoundTrip() {
        let psk = Data("secret".utf8)
        let salt = Data((0..<16).map { UInt8(0x30 + $0) })
        for version in [1, 2, 3] {
            let enc = NCSnellStreamEncoder(psk: psk, version: version, salt: salt)
            let dec = NCSnellStreamDecoder(psk: psk, version: version)
            let head = NCSnell.connectHeader(host: "example.com", port: 443, version: version)
            let body = Data("payload-\(version)".utf8)
            var wire = enc.encode(head)!
            wire.append(enc.encode(body)!)
            XCTAssertEqual([UInt8](wire.prefix(16)), [UInt8](salt))
            var got: [Data] = []
            for slice in [wire.prefix(7), wire.dropFirst(7)] {
                got.append(contentsOf: dec.feed(Data(slice))!)
            }
            XCTAssertEqual(got, [head, body], "version \(version)")
        }
    }

    func testUDPFrames() {
        let domain = NCSnell.udpFrame(target: NCTarget(host: "dns.example", port: 53), payload: Data([0xaa]))
        XCTAssertEqual([UInt8](domain), [0x01, 11] + [UInt8]("dns.example".utf8) + [0x00, 0x35, 0xaa])
        let v4 = NCSnell.udpFrame(target: NCTarget(host: "8.8.4.4", port: 53), payload: Data([0xbb]))
        XCTAssertEqual([UInt8](v4), [0x01, 0x00, 0x04, 8, 8, 4, 4, 0x00, 0x35, 0xbb])
        let resp = Data([0x04, 1, 2, 3, 4, 0x01, 0xbb]) + Data("data".utf8)
        let parsed = NCSnell.parseUDPResponse(resp)
        XCTAssertEqual(parsed?.0, NCTarget(host: "1.2.3.4", port: 443))
        XCTAssertEqual(parsed?.1, Data("data".utf8))
    }

    func testV4FrameRoundTrip() {
        let psk = Data("v4secret".utf8)
        let salt = Data((0..<16).map { UInt8(0x50 + $0) })
        let writer = NCSnellV4Writer(psk: psk, salt: salt, firstPaddingLen: 300)
        let reader = NCSnellV4Reader(psk: psk)
        let payload = Data("hello snell v4".utf8)
        var wire = writer.frame(payload)!
        XCTAssertEqual(Data(wire.prefix(16)), salt)
        wire.append(writer.frame(Data("second".utf8))!)
        wire.append(writer.frame(Data())!) // zero frame
        var pieces: [NCSnellV4Reader.Piece] = []
        for slice in [wire.prefix(20), wire.dropFirst(20).prefix(50), wire.dropFirst(70)] {
            pieces.append(contentsOf: reader.feed(Data(slice))!)
        }
        XCTAssertEqual(pieces.count, 3)
        if case .data(let d) = pieces[0] { XCTAssertEqual(d, payload) } else { XCTFail() }
        if case .data(let d) = pieces[1] { XCTAssertEqual(d, Data("second".utf8)) } else { XCTFail() }
        if case .end = pieces[2] {} else { XCTFail("zero frame must read as .end") }
    }

    func testV4SwapIsInvolution() {
        var p = Data([1, 2, 3, 4, 5])
        var c = Data([9, 8, 7, 6, 5, 4, 3])
        let p0 = p, c0 = c
        NCSnellV4Writer.swap(&p, &c)
        XCTAssertNotEqual(p, p0)
        NCSnellV4Writer.swap(&p, &c)
        XCTAssertEqual(p, p0)
        XCTAssertEqual(c, c0)
    }
}

private extension NCSnell.ReplyParse {
    var consumedOrNil: Int? {
        if case .ok(let c) = self { return c }
        return nil
    }
}
