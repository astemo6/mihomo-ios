import XCTest
@testable import Mihomo

/// Vectors generated with github.com/metacubex/blake3 (the library mihomo
/// itself uses), over the standard i % 251 input pattern.
final class NativeCoreBlake3Tests: XCTestCase {
    private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func pattern(_ n: Int) -> [UInt8] { (0..<n).map { UInt8($0 % 251) } }

    func testHash() {
        XCTAssertEqual(hex(NCBlake3.hash([])),
                       "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        XCTAssertEqual(hex(NCBlake3.hash([UInt8]("abc".utf8))),
                       "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        XCTAssertEqual(hex(NCBlake3.hash(pattern(1024))),
                       "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7")
        XCTAssertEqual(hex(NCBlake3.hash(pattern(2048))),
                       "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a")
        XCTAssertEqual(hex(NCBlake3.hash(pattern(3073))),
                       "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3")
    }

    func testKeyedAndDerive() {
        let key = [UInt8]("whats the Elvish word for friend".utf8)
        XCTAssertEqual(key.count, 32)
        XCTAssertEqual(hex(NCBlake3.keyedHash(key: key, [UInt8]("abc".utf8))),
                       "157f8b4b104070014ab0b3b7aff364f794e010e92b1c976318e892f380b53406")
        XCTAssertEqual(hex(NCBlake3.deriveKey(context: "BLAKE3 2019-02-27 16:44:10 +0200 +0200",
                                              material: [UInt8]("abc".utf8))),
                       "76798799584e8535b3ed9515ef8495f74e61d951ae24a9036b7062101236700c")
        XCTAssertEqual(hex(NCBlake3.deriveKey(context: "shadowsocks 2022 session subkey",
                                              material: [UInt8]("abc".utf8))),
                       "3f3cbef3eeb4a0db8e8db1ac4ead790f80059817888c8c9e1a628f6d336162d4")
    }

    func testTuicV4Token() {
        // TUIC v4 GenTKN: BLAKE3-256 of the token string's UTF-8 bytes.
        XCTAssertEqual(hex(NCBlake3.hash([UInt8]("my-secret-token".utf8))),
                       "47668d320c722f585eaef30aa1f6a6c0f911026ecf1efb0622bbc0e251b1ee4d")
    }
}
