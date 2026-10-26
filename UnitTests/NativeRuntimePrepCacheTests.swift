import XCTest
@testable import Mihomo

// fix/app-toggle-hitch (build 404, iPhone17,1: the Home switch hitched ~1.5 s while the connect regenerated the
// runtime every time). Pins the generation cache: identical bytes rewritten still hit, any input change misses,
// tunnel-only / log / output files are ignored, a changed output or a leftover prepare marker misses.
final class NativeRuntimePrepCacheTests: XCTestCase {
    private var root: URL!
    private var home: String { root.appendingPathComponent("mihomo").path }
    private var profiles: String { root.appendingPathComponent("profiles").path }
    private var profile: String { (profiles as NSString).appendingPathComponent("p1.yaml") }

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("prepcache-" + UUID().uuidString)
        try FileManager.default.createDirectory(atPath: home + "/engine/modules", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: profiles, withIntermediateDirectories: true)
        try put("overrides.json", "{\"mode\":\"rule\"}")
        try put("engine/engine.json", "{}")
        try put("engine/modules/m1.txt", "[Rewrite]\n^https://a/ reject")
        try Data("proxies: []\n".utf8).write(to: URL(fileURLWithPath: profile))
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private func put(_ rel: String, _ text: String) throws {
        let p = (home as NSString).appendingPathComponent(rel)
        try FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Data(text.utf8).write(to: URL(fileURLWithPath: p))
    }

    private func fp(build: String = "0.20.0 (1)") -> String {
        NativeRuntimePrepCache.inputsFingerprint(home: home, profilesDir: profiles, extraFiles: [], profilePath: profile, build: build)
    }

    func testStableAndIdenticalRewriteStillMatches() throws {
        let a = fp()
        XCTAssertEqual(a, fp(), "same tree, same fingerprint")
        usleep(20_000)
        try put("overrides.json", "{\"mode\":\"rule\"}") // saved on every connect with the same content
        XCTAssertEqual(a, fp(), "rewriting identical bytes (new mtime) is not a change")
    }

    func testInputChangesMiss() throws {
        let a = fp()
        try put("engine/modules/m1.txt", "[Rewrite]\n^https://b/ reject")
        let b = fp()
        XCTAssertNotEqual(a, b, "module edit")
        try Data("proxies: [x]\n".utf8).write(to: URL(fileURLWithPath: profile))
        let c = fp()
        XCTAssertNotEqual(b, c, "profile edit")
        try put("engine/modules/m2.txt", "x")
        XCTAssertNotEqual(c, fp(), "new module file")
        XCTAssertNotEqual(fp(), fp(build: "0.20.0 (2)"), "app build")
    }

    func testTunnelLogAndOutputFilesIgnored() throws {
        let a = fp()
        for rel in ["runtime.yaml", "nativecore-runtime.json", "nativecore-rewrite.json", "nativecore-prep.json",
                    "nativecore-fakeip.json", "nativecore-selections.json", "tunnel-alive.txt", "core-log.txt",
                    "traffic-history.json", "engine/store.json", "nativecore-rulesets/abc.list",
                    "nativecore-geosite/cn.list", ".nativecore-stage-1234/runtime.yaml", "x.json.tmp-1",
                    NativeRuntimePrepCache.recordFile, NCPrepMarkers.inflightFile] {
            try put(rel, UUID().uuidString)
        }
        XCTAssertEqual(a, fp(), "outputs / tunnel state / logs are not inputs")
        XCTAssertFalse(NativeRuntimePrepCache.isExcluded(relative: "engine/modules/m1.txt"), "module .txt files are inputs")
        XCTAssertFalse(NativeRuntimePrepCache.isExcluded(relative: NCPrepMarkers.quarantineFile), "quarantine changes the output")
    }

    func testHitRequiresSameInputsOutputsAndNoMarker() throws {
        try put("runtime.yaml", "a")
        try put("nativecore-runtime.json", "{}")
        let inputs = fp()
        NativeRuntimePrepCache.write(home: home, .init(inputs: inputs, outputs: NativeRuntimePrepCache.outputsFingerprint(home: home)))
        XCTAssertTrue(NativeRuntimePrepCache.hit(home: home, inputs: inputs))
        XCTAssertFalse(NativeRuntimePrepCache.hit(home: home, inputs: inputs + "x"), "other inputs")

        try put(NCPrepMarkers.inflightFile, "{}")
        XCTAssertFalse(NativeRuntimePrepCache.hit(home: home, inputs: inputs), "a prepare died mid-way")
        try FileManager.default.removeItem(atPath: (home as NSString).appendingPathComponent(NCPrepMarkers.inflightFile))
        XCTAssertTrue(NativeRuntimePrepCache.hit(home: home, inputs: inputs))

        usleep(20_000)
        try put("runtime.yaml", "b") // someone else replaced an output
        XCTAssertFalse(NativeRuntimePrepCache.hit(home: home, inputs: inputs), "outputs changed since the record")

        NativeRuntimePrepCache.invalidate(home: home)
        XCTAssertNil(NativeRuntimePrepCache.read(home: home))
    }
}
