import XCTest
@testable import Tern

// CRLF / CR profiles (Windows-edited or exported by some subscription
// converters): NCYAML must read them exactly like LF, and group reorder on a
// CRLF file must work and keep CRLF line endings.
final class NativeCoreYAMLCRLFTests: XCTestCase {
    private let lf = """
    mixed-port: 7890
    mode: rule
    proxy-groups:
      - {name: Proxy, type: select, proxies: [DIRECT, Auto]}
      - name: Auto
        type: url-test
        proxies: [DIRECT]
    literal: |
      line one
      line two
    """

    private func check(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        guard case .object(let root)? = NCYAML.parse(text) else {
            return XCTFail("root not object", file: file, line: line)
        }
        XCTAssertEqual(root["mixed-port"]?.int, 7890, file: file, line: line)
        XCTAssertEqual(root["mode"]?.string, "rule", file: file, line: line)
        let groups = root["proxy-groups"]?.array
        XCTAssertEqual(groups?.count, 2, file: file, line: line)
        XCTAssertEqual(groups?[1].object?["name"]?.string, "Auto", file: file, line: line)
        XCTAssertEqual(groups?[1].object?["type"]?.string, "url-test", file: file, line: line)
        XCTAssertEqual(root["literal"]?.string?.contains("\r"), false, file: file, line: line)
    }

    func testLFParses() { check(lf) }

    func testCRLFParsesLikeLF() {
        check(lf.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n")
    }

    func testCRParsesLikeLF() {
        check(lf.replacingOccurrences(of: "\n", with: "\r"))
    }

    func testGroupReorderOnCRLFProfile() {
        let crlf = lf.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n"
        let r = NCGroupOrder.reorderGroupsText(crlf, want: ["Auto", "Proxy"])
        XCTAssertNil(r.error)
        XCTAssertTrue(r.changed)
        XCTAssertEqual(r.order, ["Auto", "Proxy"])
        XCTAssertTrue(r.text.contains("\r\n"))
    }
}
