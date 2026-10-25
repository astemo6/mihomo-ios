import XCTest
@testable import Mihomo

/// Lane s3-script helpers. Go-zero (nc-integrate): the Go-vs-native differential runs over the Go script engine
/// (LibmihomoMitmScriptTestStart / MitmFlowDriverAdapter, testNativeScriptDispatchMatchesGo /
/// testNativeRequestScriptsMatchGo) are removed with bridge/; the native dispatch is covered by the device runs and
/// NativeCorePersistentStoreTests. What stays are the ported helpers.
final class NativeMitmScriptTests: XCTestCase {
    /// The pieces ported from Go, checked on their own.
    func testPortedHelpers() {
        XCTAssertEqual(NativeScriptRun.splitSetCookie("a=1, b=2; Expires=Wed, 21 Oct 2027 07:28:00 GMT"), ["a=1", "b=2; Expires=Wed, 21 Oct 2027 07:28:00 GMT"])
        XCTAssertEqual(NativeScriptRun.parseStatus(.string("HTTP/1.1 201 Created")), 201)
        XCTAssertEqual(NativeScriptRun.parseStatus(.number(404)), 404)
        XCTAssertEqual(NativeScriptRun.parseStatus(.string(" 302 ")), 302)
        XCTAssertEqual(NativeScriptRun.parseStatus(.string("x")), 0)
        XCTAssertEqual(NativeScriptRun.parseStatus(.null), 0)
        var h = CanonicalHeader()
        h.add("set-cookie", "a=1, b=2")
        NativeScriptRun.fixSetCookie(&h, [])
        XCTAssertEqual(h.values("Set-Cookie"), ["a=1", "b=2"])
        var h2 = CanonicalHeader()
        h2.add("Set-Cookie", "a=1, x=2")
        NativeScriptRun.fixSetCookie(&h2, ["a=1", "x=2"])
        XCTAssertEqual(h2.values("Set-Cookie"), ["a=1", "x=2"])
        XCTAssertNil(NativeScriptResponse.unsupported([ScriptPlanStep(rule: 1, kind: .script(requiresBody: true)),
                                                       ScriptPlanStep(rule: 2, kind: .script(requiresBody: false))]))
        XCTAssertNotNil(NativeScriptResponse.unsupported([ScriptPlanStep(rule: 1, kind: .script(requiresBody: false)),
                                                          ScriptPlanStep(rule: 2, kind: .script(requiresBody: true))]))
        XCTAssertTrue(NativeScriptResponse.encodingOK("GZIP"))
        XCTAssertFalse(NativeScriptResponse.encodingOK("zstd"))
    }
}
