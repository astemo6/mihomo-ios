import XCTest
@testable import Mihomo

/// feat/jsc-engine: the shared engine-conformance corpus (ScriptEngineConformance.json, also run by Go's
/// TestEngineConformance) must give the same result on goja and on JavaScriptCore (JSCScriptEngine) — the same
/// prelude, the same host, only the JavaScript engine differs. Cases with "repeat" run several times on the same
/// JSContext (the per-script context is reused; globals a run created must not leak into the next).
///
/// The test can never hang CI: every engine call runs on its own thread with a hard deadline (caseTimeout per
/// case, totalTimeout for the whole corpus). On a missed deadline the case is logged, every goroutine's stack is
/// written next to the screenshots (UI_SHOT_DIR/jsc-conformance) and the process aborts, so the crash report
/// (Self-test "Crash logs") carries the native thread stacks too — a stuck call would hold JavaScriptCore's VM
/// lock and wedge everything after it anyway.
final class ScriptEngineConformanceTests: XCTestCase {
    private static let caseTimeout: TimeInterval = 30
    private static let totalTimeout: TimeInterval = 240

    private final class Box: @unchecked Sendable {
        var value = ""
    }

    private func corpus() throws -> [[String: Any]] {
        let bundle = Bundle(for: ScriptEngineConformanceTests.self)
        guard let url = bundle.url(forResource: "ScriptEngineConformance", withExtension: "json") else {
            XCTFail("ScriptEngineConformance.json missing from the test bundle")
            return []
        }
        let data = try Data(contentsOf: url)
        return (try JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
    }

    private static func log(_ s: String) {
        // stderr is unbuffered: the line is in the xcodebuild log even if the process dies right after.
        fputs("[jsc-conformance] " + s + "\n", stderr)
        appendDiag("progress.txt", s + "\n")
    }

    private static var diagDir: URL? {
        guard let d = ProcessInfo.processInfo.environment["UI_SHOT_DIR"], !d.isEmpty else { return nil }
        let u = URL(fileURLWithPath: d).appendingPathComponent("jsc-conformance")
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    private static func appendDiag(_ file: String, _ s: String) {
        guard let dir = diagDir else { return }
        let u = dir.appendingPathComponent(file)
        if let h = try? FileHandle(forWritingTo: u) {
            h.seekToEndOfFile()
            h.write(Data(s.utf8))
            try? h.close()
        } else {
            try? Data(s.utf8).write(to: u)
        }
    }

    /// Runs body on a fresh thread (8 MB stack); nil when it did not return within timeout.
    private static func timed(_ timeout: TimeInterval, _ body: @escaping () -> String) -> String? {
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            box.value = body()
            sem.signal()
        }
        t.stackSize = 8 << 20
        t.start()
        // The main run loop keeps turning while we wait: nothing the engine schedules on the main thread
        // (JavaScriptCore's VM timers belong to the run loop it was created on) can deadlock against the test.
        let deadline = Date().addingTimeInterval(timeout)
        while sem.wait(timeout: .now() + .milliseconds(20)) == .timedOut {
            if Date() >= deadline { return nil }
            if Thread.isMainThread { RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02)) }
        }
        return box.value
    }

    /// A call missed its deadline: log what is known, dump the goroutines and abort (see the class comment).
    private static func hung(_ what: String) -> Never {
        log("HUNG: \(what) did not return within its deadline; dumping goroutines and aborting")
        let dump = timed(10) { JSCScriptEngine.goroutineDump() } ?? "(goroutine dump did not return)"
        appendDiag("goroutines.txt", dump)
        fputs(String(dump.prefix(60_000)) + "\n", stderr)
        fflush(stderr)
        abort()
    }

    func testJavaScriptCoreMatchesGoja() throws {
        let started = Date()
        // Device parity: the tunnel extension (and any iOS app) gets no JIT, so JavaScriptCore runs its
        // interpreter there; the simulator would JIT. Options are read from JSC_* when the first VM is created
        // (the Self-test also passes TEST_RUNNER_JSC_useJIT=false so it is set before launch).
        setenv("JSC_useJIT", "false", 0)
        Self.log("JSC_useJIT=\(ProcessInfo.processInfo.environment["JSC_useJIT"] ?? "(unset)")")
        guard let reg = Self.timed(Self.caseTimeout, { JSCScriptEngine.register() }) else { Self.hung("register") }
        XCTAssertEqual(reg, "", "JavaScriptCore engine not taken")
        let status = JSCScriptEngine.status()
        Self.log("registered: \(status)")
        XCTAssertTrue(status.contains("\"engine\":\"native\""), status)
        XCTAssertTrue(status.contains("time limit on"), "JSContextGroupSetExecutionTimeLimit not found: \(status)")
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("jsc-conformance-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let cases = try corpus()
        XCTAssertGreaterThan(cases.count, 30)
        var gojaMs: Int64 = 0, jscMs: Int64 = 0, passed = 0
        for (i, c) in cases.enumerated() {
            let name = c["name"] as? String ?? "?"
            if Date().timeIntervalSince(started) > Self.totalTimeout { Self.hung("corpus (total \(Int(Self.totalTimeout)) s) before \(name)") }
            let caseJSON = String(data: try JSONSerialization.data(withJSONObject: c), encoding: .utf8) ?? "{}"
            let path = home.path
            Self.log("\(i + 1)/\(cases.count) \(name) …")
            let t0 = Date()
            guard let out = Self.timed(Self.caseTimeout, { JSCScriptEngine.conformance(home: path, caseJSON: caseJSON) }) else {
                Self.hung("case \(name)")
            }
            let wall = Int(Date().timeIntervalSince(t0) * 1000)
            guard let r = try JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any] else {
                XCTFail("\(name): bad result \(out)")
                continue
            }
            let g = (r["gojaMs"] as? NSNumber)?.int64Value ?? 0
            let n = (r["nativeMs"] as? NSNumber)?.int64Value ?? 0
            gojaMs += g
            jscMs += n
            let ok = r["ok"] as? Bool == true
            if ok { passed += 1 }
            Self.log("\(i + 1)/\(cases.count) \(name) \(ok ? "ok" : "FAIL") goja \(g) ms, jsc \(n) ms, wall \(wall) ms")
            if !ok { Self.appendDiag("failures.txt", "\(name): \(out)\n") }
            if !ok || name.hasPrefix("timeout") { Self.log("status: \(JSCScriptEngine.status())") }
            XCTAssertTrue(ok, "\(name): \(out)")
        }
        // Simulator numbers (the app process may JIT; the tunnel extension on a device runs the interpreter).
        Self.log("\(passed)/\(cases.count) cases passed: goja \(gojaMs) ms, JavaScriptCore \(jscMs) ms; \(JSCScriptEngine.status())")
    }
}
