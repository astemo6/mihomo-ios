import XCTest
@testable import Tern

/// BLAKE2b and Argon2id vectors generated offline with an independent reference implementation
/// (the exact library Clash.Meta's Snell KDF uses).
final class NativeCoreArgon2Tests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testBlake2bVectors() {
        XCTAssertEqual(hex(NCBlake2b.hash(Data(), outputLength: 64)),
                       "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
                       "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
        XCTAssertEqual(hex(NCBlake2b.hash(Data("abc".utf8), outputLength: 64)),
                       "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                       "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        XCTAssertEqual(hex(NCBlake2b.hash(Data("abc".utf8), outputLength: 32)),
                       "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
        let big = Data((0..<300).map { UInt8($0 & 0xff) })
        XCTAssertEqual(hex(NCBlake2b.hash(big, outputLength: 64)),
                       "d9cf5983dc6b34c0fa1f0226926855ad3eccd2bcdcd8f8053b9a80664d33b5af" +
                       "cc32fd21c70ea14f4ef50ca97c3203c4d1803159f0e01bb6cb1d1c83db52b63c")
    }

    func testArgon2idSnellParams() {
        // Snell's exact parameters: argon2id(psk, salt, 3, 8 KiB, 1, 32).
        let salt = Data((0..<16).map { UInt8($0) })
        let key = NCArgon2.idKey(password: Data("my-snell-psk".utf8), salt: salt,
                                 iterations: 3, memoryKB: 8, lanes: 1, keyLength: 32)
        XCTAssertEqual(hex(key), "8eb893d1afc12e85718ec026071d1043771ed164c8720d2a0b9fb9165b4d150a")
    }

    func testArgon2idVariants() {
        let key = NCArgon2.idKey(password: Data("password".utf8), salt: Data("0123456789abcdef".utf8),
                                 iterations: 3, memoryKB: 8, lanes: 1, keyLength: 32)
        XCTAssertEqual(hex(key), "914e76b036c057f676ab350e0e248d6ebb86b284c966695bdba365f92f2bb1e8")
        let tiny = NCArgon2.idKey(password: Data("p".utf8), salt: Data("s".utf8),
                                  iterations: 3, memoryKB: 8, lanes: 1, keyLength: 32)
        XCTAssertEqual(hex(tiny), "d30b48d0d4dc1f751333fa00caae80d4c7f09ccf94eb7b0de592795e16557cff")
        // Larger memory exercises the segment/index math harder.
        let mem64 = NCArgon2.idKey(password: Data("password".utf8), salt: Data("0123456789abcdef".utf8),
                                   iterations: 3, memoryKB: 64, lanes: 1, keyLength: 32)
        XCTAssertEqual(hex(mem64), "4b5dc7fd03bc8449b6becb981762b597e860b2322fc34685d1fd2dc21aaf07cb")
        let time1 = NCArgon2.idKey(password: Data("password".utf8), salt: Data("0123456789abcdef".utf8),
                                   iterations: 1, memoryKB: 32, lanes: 1, keyLength: 32)
        XCTAssertEqual(hex(time1), "a119788868b4fbf8b3aa69cdbe7968d2b518e0149a86ee367fa3d403c7e7726c")
        let key16 = NCArgon2.idKey(password: Data("password".utf8), salt: Data("0123456789abcdef".utf8),
                                   iterations: 3, memoryKB: 8, lanes: 1, keyLength: 16)
        XCTAssertEqual(hex(key16), "0fb7d83c1ba5d8574a295cbb89664cbd")
    }
}
