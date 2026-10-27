import XCTest
@testable import Tern

/// v0.20.0 build 372 launch crash: qxRawPair sliced `line` / `rest` with indices from lowercased copies
/// (String.Index range trap). Quantumult X `url request-header REGEX request-header REPL` lines hit it.
final class NativeCoreQXRawPairTests: XCTestCase {
    func testRequestHeaderPair() {
        let line = #"^https?://example\.com/api url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Foo$2"#
        let pair = NCEngineRuleset.qxRawPair(line: line, act: "request-header")
        XCTAssertEqual(pair?.0, #"(\r\n)User-Agent:.+(\r\n)"#)
        XCTAssertEqual(pair?.1, "$1User-Agent: Foo$2")
    }

    func testMixedCaseAndNonASCII() {
        let line = "^https://例子.com/ÄÖ URL Response-Body 广告İ Response-Body 空"
        let pair = NCEngineRuleset.qxRawPair(line: line, act: "response-body")
        XCTAssertEqual(pair?.0, "广告İ")
        XCTAssertEqual(pair?.1, "空")
    }
}
