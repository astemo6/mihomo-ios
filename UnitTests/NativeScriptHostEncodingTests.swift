import XCTest
@testable import Tern

/// fix/nc-script-atob-binary: the host's atob/btoa must follow web semantics — byte strings
/// (Latin-1), not UTF-8 text. The pre-Swift-port behaviour is pinned by the (previously
/// unexecuted) conformance case "text-encoding-base64" in ScriptEngineConformance.json:
/// btoa('hi\u{FF}') == "aGn/" and atob('aGn/') == "hi\u{FF}". The UTF-8 implementation
/// returned "" for atob of any binary payload, which is what killed script-side AES
/// decryption of base64 ciphertext on device (build 546).
final class NativeScriptHostEncodingTests: XCTestCase {
    private func host(_ op: String, _ arg: String) -> String {
        NativeScriptHost.shared.host(gen: 0, rule: -1, op: op, arg: arg)
    }

    func testAtobBinaryString() {
        XCTAssertEqual(host("atob", "aGn/"), "hi\u{FF}")
    }

    func testAtobUnpadded() {
        XCTAssertEqual(host("atob", "aGk"), "hi")
    }

    func testAtobArbitraryBytesSurvive() {
        let bytes: [UInt8] = [0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x61]
        let b64 = Data(bytes).base64EncodedString()
        let out = host("atob", b64)
        XCTAssertEqual([UInt8](out.unicodeScalars.map { UInt8($0.value) }), bytes)
    }

    func testBtoaBinaryString() {
        XCTAssertEqual(host("btoa", "hi\u{FF}"), "aGn/")
    }

    func testBtoaPlainText() {
        XCTAssertEqual(host("btoa", "hello"), "aGVsbG8=")
    }

    func testRoundTrip() {
        let original = "pay\u{00}load\u{FF}\u{80}~"
        XCTAssertEqual(host("atob", host("btoa", original)), original)
    }
}
