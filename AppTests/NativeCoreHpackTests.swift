import XCTest
@testable import Tern

/// HPACK checks against RFC 7541 worked examples.
final class NativeCoreHpackTests: XCTestCase {
    private func data(_ hex: String) -> Data {
        var out = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    func testIntegerCoding() {
        XCTAssertEqual([UInt8](NCHPACK.encodeInteger(10, prefixBits: 5, firstByte: 0)), [0x0a])
        XCTAssertEqual([UInt8](NCHPACK.encodeInteger(1337, prefixBits: 5, firstByte: 0)), [0x1f, 0x9a, 0x0a])
        XCTAssertEqual([UInt8](NCHPACK.encodeInteger(42, prefixBits: 8, firstByte: 0)), [42])
    }

    func testHuffmanDecode() {
        // RFC 7541 C.4.1: "www.example.com" Huffman-coded.
        let decoded = NCHPACK.huffmanDecode(data("f1e3c2e5f23a6ba0ab90f4ff"))
        XCTAssertEqual(decoded.map { String(decoding: $0, as: UTF8.self) }, "www.example.com")
    }

    func testLiteralWithIncrementalIndexing() {
        // RFC 7541 C.2.1.
        let dec = NCHPACKDecoder()
        let out = dec.decode(data("400a637573746f6d2d6b65790d637573746f6d2d686561646572"))
        XCTAssertEqual(out?.map { [$0.0, $0.1] }, [["custom-key", "custom-header"]])
        XCTAssertEqual(dec.entry(62)?.0, "custom-key")
        // C.2.2 on the same connection state.
        let out2 = dec.decode(data("040c2f73616d706c652f70617468"))
        XCTAssertEqual(out2?.map { [$0.0, $0.1] }, [[":path", "/sample/path"]])
    }

    func testHuffmanResponseBlock() {
        // RFC 7541 C.4.1 response (Huffman + incremental indexing).
        let dec = NCHPACKDecoder()
        let block = data("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff")
        let out = dec.decode(block)
        XCTAssertEqual(out?.first?.0, ":status")
        XCTAssertEqual(out?.first?.1, "302")
        XCTAssertTrue(out?.contains { $0.0 == "location" && $0.1 == "https://www.example.com" } ?? false)
        XCTAssertTrue(out?.contains { $0.0 == "cache-control" && $0.1 == "private" } ?? false)
    }

    func testEncoderRoundTrip() {
        let headers: [(String, String)] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/GunService/Tun"),
            (":authority", "example.com"),
            ("content-type", "application/grpc"),
            ("user-agent", "grpc-go/1.0"),
            ("te", "trailers"),
        ]
        let dec = NCHPACKDecoder()
        let out = dec.decode(NCHPACK.encodeHeaders(headers))
        XCTAssertEqual(out?.map { [$0.0, $0.1] }, headers.map { [$0.0, $0.1] })
    }
}

/// ClientHello fingerprint profiles keep the REALITY layout invariant.
final class NativeCoreFingerprintTests: XCTestCase {
    func testProfilesVaryAndKeepLayout() {
        let random = Data((0..<32).map { UInt8($0) })
        let share = Data((0..<32).map { UInt8(0xa0 + $0) })
        for profile in [NCClientHelloProfile.chrome, .firefox, .safari, .ios] {
            let hello = NCTLS13.buildClientHello(random: random, sessionID: Data(count: 32),
                                                 serverName: "example.com", alpn: ["h2"],
                                                 keyShare: share, profile: profile)
            // Handshake header 4B, then legacy version (2) + random (32)
            // puts the session-id length at offset 39.
            XCTAssertEqual(hello[4 + 2 + 32], 32)
            XCTAssertEqual(Data(hello[6..<38]), random)
        }
        let chrome = NCTLS13.buildClientHello(random: random, sessionID: Data(count: 32),
                                              serverName: "example.com", alpn: ["h2"],
                                              keyShare: share, profile: .chrome)
        let firefox = NCTLS13.buildClientHello(random: random, sessionID: Data(count: 32),
                                               serverName: "example.com", alpn: ["h2"],
                                               keyShare: share, profile: .firefox)
        XCTAssertNotEqual(chrome, firefox)
        XCTAssertGreaterThanOrEqual(chrome.count, 512) // chrome pads
    }
}
