import XCTest
@testable import Mihomo

/// feat/jsc-engine: the shared engine-conformance corpus (ScriptEngineConformance.json, also run by Go's
/// TestEngineConformance) must give the same result on goja and on JavaScriptCore (JSCScriptEngine) — the same
/// prelude, the same host, only the JavaScript engine differs. Cases with "repeat" run several times on the same
/// JSContext (the per-script context is reused; globals a run created must not leak into the next).
final class ScriptEngineConformanceTests: XCTestCase {
    private func corpus() throws -> [[String: Any]] {
        let bundle = Bundle(for: ScriptEngineConformanceTests.self)
        guard let url = bundle.url(forResource: "ScriptEngineConformance", withExtension: "json") else {
            XCTFail("ScriptEngineConformance.json missing from the test bundle")
            return []
        }
        let data = try Data(contentsOf: url)
        return (try JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
    }

    func testJavaScriptCoreMatchesGoja() throws {
        XCTAssertEqual(JSCScriptEngine.register(), "", "JavaScriptCore engine not taken")
        let status = JSCScriptEngine.status()
        XCTAssertTrue(status.contains("\"engine\":\"native\""), status)
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("jsc-conformance-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let cases = try corpus()
        XCTAssertGreaterThan(cases.count, 30)
        var gojaMs: Int64 = 0, jscMs: Int64 = 0
        for c in cases {
            let name = c["name"] as? String ?? "?"
            let caseJSON = String(data: try JSONSerialization.data(withJSONObject: c), encoding: .utf8) ?? "{}"
            let out = JSCScriptEngine.conformance(home: home.path, caseJSON: caseJSON)
            guard let r = try JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any] else {
                XCTFail("\(name): bad result \(out)")
                continue
            }
            gojaMs += (r["gojaMs"] as? NSNumber)?.int64Value ?? 0
            jscMs += (r["nativeMs"] as? NSNumber)?.int64Value ?? 0
            XCTAssertEqual(r["ok"] as? Bool, true, "\(name): \(out)")
        }
        // Simulator numbers (the app process may JIT; the tunnel extension on a device runs the interpreter).
        print("[jsc-conformance] \(cases.count) cases: goja \(gojaMs) ms, JavaScriptCore \(jscMs) ms; \(JSCScriptEngine.status())")
    }
}
