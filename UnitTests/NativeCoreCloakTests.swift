import XCTest
@testable import Mihomo

/// Cloak SS plugin options + the Salsa20 core it (and kcptun's salsa20 crypt) relies on.
final class NativeCoreCloakTests: XCTestCase {
    private let uid = Data((0..<16).map { UInt8($0) }).base64EncodedString()
    private let pub = Data((0..<32).map { UInt8($0 + 1) }).base64EncodedString()

    func testSalsa20ECRYPTVector() {
        // ECRYPT Salsa20/20 256-bit set 1 vector 0: key = 0x80 00 .. 00, IV = 0.
        var buf = [UInt8](repeating: 0, count: 32)
        NCSalsa20.xorKeyStream(data: &buf, key: Data([0x80] + [UInt8](repeating: 0, count: 31)), nonce: Data(count: 8))
        XCTAssertEqual(buf.map { String(format: "%02x", $0) }.joined(),
                       "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844")
    }

    func testParseShadowrocketAndMihomoKeys() {
        let a = NCCloakPluginOptions.parse(["UID": .string(uid), "PublicKey": .string(pub),
                                            "ServerName": .string("www.bing.com"), "EncryptionMethod": .string("aes-gcm")])
        XCTAssertNil(a.1)
        XCTAssertEqual(a.0?.uid.count, 16)
        XCTAssertEqual(a.0?.encryptionMethodByte, 1)
        let b = NCCloakPluginOptions.parse(["uid": .string(uid), "public-key": .string(pub),
                                            "encryption-method": .string("chacha20-poly1305")], fallbackHost: "h.example")
        XCTAssertEqual(b.0?.serverName, "h.example")
        XCTAssertEqual(b.0?.encryptionMethodByte, 2)
        XCTAssertNotNil(NCCloakPluginOptions.parse(["uid": .string("short"), "public-key": .string(pub)]).1)
    }

    func testCDNTransportIsReportedUnsupported() {
        let r = NCCloakPluginOptions.parse(["UID": .string(uid), "PublicKey": .string(pub), "Transport": .string("CDN")])
        XCTAssertNil(r.0)
        XCTAssertNotNil(r.1)
    }
}
