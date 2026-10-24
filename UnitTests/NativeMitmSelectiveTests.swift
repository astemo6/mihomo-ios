import Network
import XCTest
import Libmihomo
@testable import Mihomo

/// feat/selective-native: is the native MitM path worth it for heavy work only? Whole-process footprint (peak during
/// the burst and 1 s after) and Go heap (peak during the burst, no GC; and after a GC) for bursts through the bench
/// engine (bridge/s2bench.go, MitmBenchStartConf + MitmBenchHeavyConf: heavy.bench.test has a response jq rule on
/// /jq and a requires-body response script on /script, both on N KB of JSON; api.bench.test has no rules).
///
/// Workloads (one request per connection, then idle keep-alive):
///   heavy: 16 concurrent connections to heavy.bench.test — jq on 200 KB (the native body engine's limit is 256 KB)
///          and 960 KB (Go's JSON rewrite limit is 1 MB; natively handed back to Go), script on 2 MB and 3.5 MB
///          (Go's script body limit is 4 MB);
///   mixed: 90 plain connections to api.bench.test + 10 heavy (script on 2 MB);
///   plain: 100 plain connections.
/// Modes:
///   go         all Go (production default: JavaScriptCore registered, no native body store);
///   go+lane    all Go with the stage-1 native body store registered (scripts read the body from native memory) —
///              measured in the decision run (78837e9, Self-test 40102633460), no longer in the default workloads;
///   selective  native front installed in selective mode (production cap 48): Go hands over only hosts with a heavy
///              rule, the native rewrite / body / script engines on (selective default), body store registered;
///   allnative  native front for every connection (no cap) + native engines (the v0.19.23 "all native" reference).
/// 1 uncounted warm-up per mode, then 4 counted rounds alternating forward / reversed; medians.
final class NativeMitmSelectiveTests: XCTestCase {
    enum Mode: String { case go, goLane = "go+lane", selective, allnative }

    struct Workload {
        var name: String
        var plain: Int
        var heavy: Int
        var heavyPath: String
        var modes: [Mode]
    }

    static let heavyWorkloads: [Workload] = [
        Workload(name: "jq-200k", plain: 0, heavy: 16, heavyPath: "/jq?kb=200", modes: [.go, .selective]),
        Workload(name: "jq-960k", plain: 0, heavy: 16, heavyPath: "/jq?kb=960", modes: [.go, .selective]),
        Workload(name: "script-2m", plain: 0, heavy: 16, heavyPath: "/script?kb=2048", modes: [.go, .selective]),
        Workload(name: "script-3.5m", plain: 0, heavy: 16, heavyPath: "/script?kb=3584", modes: [.go, .selective]),
    ]
    static let mixed = Workload(name: "mixed-90+10", plain: 90, heavy: 10, heavyPath: "/script?kb=2048", modes: [.go, .selective, .allnative])
    static let plain = Workload(name: "plain-100", plain: 100, heavy: 0, heavyPath: "", modes: [.go, .selective])

    struct GoMem: Decodable { var heapInuse: Int64; var sys: Int64; var stack: Int64; var goroutines: Int; var handed: Int64; var fellBack: Int64 }
    struct GoPeek: Decodable { var heapObjects: Int64; var mapped: Int64 }
    struct SelStats: Decodable { var handed: Int64; var skipped: Int64; var learned: Int64 }

    struct Run {
        var workload: String
        var mode: Mode
        var ok = 0
        /// answers that carried the rule's mark (Go skips body rules under its burst gates and passes the body on)
        var applied = 0
        var failures: [String] = []
        var fpBefore: UInt64 = 0, fpAfter: UInt64 = 0, fpPeak: UInt64 = 0
        var heapBefore: Int64 = 0, heapPeak: Int64 = 0, mappedBefore: Int64 = 0, mappedPeak: Int64 = 0
        var goBefore: GoMem?, goAfter: GoMem?
        var mallocBefore = 0, mallocAfter = 0
        var handed: Int64 = 0, selHanded: Int64 = 0, selSkipped: Int64 = 0
        var seconds: Double = 0
        var nativeErrors: [String] = []
        var goLog: [String] = []
    }

    static func mb(_ v: Double) -> String { String(format: "%+.2f", v) }

    override class func setUp() {
        super.setUp()
        _ = JSCScriptEngine.register()
    }

    override func tearDown() {
        JSCScriptEngine.setLaneForTests(nil)
        super.tearDown()
    }

    // MARK: tests

    /// nativeMitmStage2 wins both ways; absent → nativeMitmSelective (absent → NativeMitmSelective.defaultOn).
    func testModeSwitches() {
        let suite = "test.selective.\(UUID().uuidString)"
        guard let d = UserDefaults(suiteName: suite) else { return XCTFail("defaults") }
        defer { d.removePersistentDomain(forName: suite) }
        let absent: NativeMitmRuntime.Mode = NativeMitmRuntime.defaultOn ? .all : (NativeMitmSelective.defaultOn ? .selective : .off)
        XCTAssertEqual(NativeMitmRuntime.mode(in: d), absent)
        XCTAssertEqual(NativeMitmRuntime.mode(in: nil), absent)
        d.set(true, forKey: NativeMitmSelective.defaultsKey)
        XCTAssertEqual(NativeMitmRuntime.mode(in: d), NativeMitmRuntime.defaultOn ? .all : .selective)
        d.set(false, forKey: NativeMitmSelective.defaultsKey)
        XCTAssertEqual(NativeMitmRuntime.mode(in: d), NativeMitmRuntime.defaultOn ? .all : .off)
        d.set(true, forKey: NativeMitmRuntime.defaultsKey)
        XCTAssertEqual(NativeMitmRuntime.mode(in: d), .all)
        d.set(false, forKey: NativeMitmRuntime.defaultsKey)
        d.set(true, forKey: NativeMitmSelective.defaultsKey)
        XCTAssertEqual(NativeMitmRuntime.mode(in: d), .off, "explicit nativeMitmStage2 = false turns selective off too")
        // engines: explicit value wins, else follow the installed selective mode (not installed here → off)
        XCTAssertFalse(NativeMitmRuntime.selectiveEngines)
        XCTAssertFalse(NativeMitmRuntime.engineSwitch(explicit: nil))
        XCTAssertTrue(NativeMitmRuntime.engineSwitch(explicit: true))
    }

    func testHeavyBodiesGoVersusSelective() throws {
        guard #available(iOS 17.0, *) else { throw XCTSkip("native front needs iOS 17") }
        XCTAssertEqual(JSCScriptEngine.register(), "", "JavaScriptCore")
        var lines: [String] = []
        for w in Self.heavyWorkloads {
            let runs = try rounds(w)
            lines += report(runs, w)
        }
        for l in lines { print(l); NSLog("%@", l) }
    }

    func testMixedGoVersusSelective() throws {
        guard #available(iOS 17.0, *) else { throw XCTSkip("native front needs iOS 17") }
        XCTAssertEqual(JSCScriptEngine.register(), "", "JavaScriptCore")
        let runs = try rounds(Self.mixed)
        for l in report(runs, Self.mixed) { print(l); NSLog("%@", l) }
    }

    func testPlainGoVersusSelective() throws {
        guard #available(iOS 17.0, *) else { throw XCTSkip("native front needs iOS 17") }
        XCTAssertEqual(JSCScriptEngine.register(), "", "JavaScriptCore")
        let runs = try rounds(Self.plain)
        for l in report(runs, Self.plain) { print(l); NSLog("%@", l) }
    }

    // MARK: rounds / report

    @available(iOS 17.0, *)
    private func rounds(_ w: Workload) throws -> [Run] {
        for m in w.modes { _ = try burst(w, m) } // warm-up
        var runs: [Run] = []
        for round in 0..<4 {
            for m in (round % 2 == 0 ? w.modes : w.modes.reversed()) { runs.append(try burst(w, m)) }
        }
        let total = w.plain + w.heavy
        for r in runs {
            XCTAssertEqual(r.ok, total, "\(w.name) \(r.mode.rawValue): \(r.ok)/\(total) answered; \(r.failures.prefix(2)); native \(r.nativeErrors.suffix(2)); engine \(r.goLog.suffix(3))")
            switch r.mode {
            case .selective:
                // the native engines apply every heavy rule (the Go path may skip some under its gates: reported)
                XCTAssertEqual(r.applied, total, "\(w.name) selective: rule applied \(r.applied)/\(total); engine \(r.goLog.suffix(3))")
                XCTAssertEqual(r.handed, Int64(min(w.heavy, NativeMitmRuntime.maxSessions)), "\(w.name) selective: native front took \(r.handed), want the heavy connections only")
                XCTAssertGreaterThanOrEqual(r.selSkipped, Int64(w.plain), "\(w.name) selective: plain connections not kept on Go")
            case .allnative:
                XCTAssertGreaterThanOrEqual(r.handed, Int64(total), "\(w.name) allnative: native front took \(r.handed)")
            case .go, .goLane:
                XCTAssertEqual(r.handed, 0, "\(w.name) \(r.mode.rawValue): front must be off")
            }
        }
        return runs
    }

    private func median(_ runs: [Run], _ m: Mode, _ f: (Run) -> Double) -> Double {
        let v = runs.filter { $0.mode == m }.map(f).sorted()
        guard !v.isEmpty else { return .nan }
        return v.count % 2 == 1 ? v[v.count / 2] : (v[v.count / 2 - 1] + v[v.count / 2]) / 2
    }

    private func report(_ runs: [Run], _ w: Workload) -> [String] {
        let M = 1_048_576.0
        var out: [String] = []
        for (i, r) in runs.enumerated() {
            out.append(String(format: "[selective] run passed %@ #%d %@: ok %d/%d (rule applied %d), footprint peak %@ after %@ MB, Go heap peak %@ mapped peak %@ MB, malloc %@ MB, handed %lld (selective %lld/%lld), %.0f ms",
                              w.name as NSString, i + 1, r.mode.rawValue as NSString, r.ok, w.plain + w.heavy, r.applied,
                              Self.mb(Double(Int64(r.fpPeak) - Int64(r.fpBefore)) / M) as NSString, Self.mb(Double(Int64(r.fpAfter) - Int64(r.fpBefore)) / M) as NSString,
                              Self.mb(Double(r.heapPeak - r.heapBefore) / M) as NSString, Self.mb(Double(r.mappedPeak - r.mappedBefore) / M) as NSString,
                              Self.mb(Double(r.mallocAfter - r.mallocBefore) / M) as NSString, r.handed, r.selHanded, r.selSkipped, r.seconds * 1000))
        }
        let peak: (Run) -> Double = { Double(Int64($0.fpPeak) - Int64($0.fpBefore)) / M }
        let after: (Run) -> Double = { Double(Int64($0.fpAfter) - Int64($0.fpBefore)) / M }
        let heapPk: (Run) -> Double = { Double($0.heapPeak - $0.heapBefore) / M }
        let mapPk: (Run) -> Double = { Double($0.mappedPeak - $0.mappedBefore) / M }
        let heapGC: (Run) -> Double = { r in Double((r.goAfter?.heapInuse ?? 0) - (r.goBefore?.heapInuse ?? 0)) / M }
        let mal: (Run) -> Double = { Double($0.mallocAfter - $0.mallocBefore) / M }
        let ms: (Run) -> Double = { $0.seconds * 1000 }
        let okc: (Run) -> Double = { Double($0.ok) }
        let appc: (Run) -> Double = { Double($0.applied) }
        for m in w.modes {
            out.append(String(format: "[selective] MEDIAN passed %@ %@: footprint peak %@ MB, after 1 s %@ MB | Go heap peak %@ MB, Go mapped peak %@ MB, Go heap after GC %@ MB | malloc %@ MB | burst %.0f ms | ok %.0f/%d, rule applied %.0f",
                              w.name as NSString, (m.rawValue as NSString).padding(toLength: 9, withPad: " ", startingAt: 0) as NSString,
                              Self.mb(median(runs, m, peak)) as NSString, Self.mb(median(runs, m, after)) as NSString,
                              Self.mb(median(runs, m, heapPk)) as NSString, Self.mb(median(runs, m, mapPk)) as NSString, Self.mb(median(runs, m, heapGC)) as NSString,
                              Self.mb(median(runs, m, mal)) as NSString, median(runs, m, ms), median(runs, m, okc), w.plain + w.heavy, median(runs, m, appc)))
        }
        if w.modes.contains(.selective) {
            let d = median(runs, .selective, peak) - median(runs, .go, peak)
            let a = median(runs, .selective, after) - median(runs, .go, after)
            let h = median(runs, .selective, heapPk) - median(runs, .go, heapPk)
            out.append(String(format: "[selective] SUMMARY passed %@: selective − go: footprint peak %@ MB, after 1 s %@ MB, Go heap peak %@ MB",
                              w.name as NSString, Self.mb(d) as NSString, Self.mb(a) as NSString, Self.mb(h) as NSString))
        }
        return out
    }

    // MARK: one burst

    private func goMem() -> GoMem? { try? JSONDecoder().decode(GoMem.self, from: Data(LibmihomoMitmBenchMem().utf8)) }
    private func goPeek() -> GoPeek? { try? JSONDecoder().decode(GoPeek.self, from: Data(LibmihomoMitmBenchMemPeek().utf8)) }
    private func selStats() -> SelStats? { try? JSONDecoder().decode(SelStats.self, from: Data(LibmihomoMitmBenchSelective().utf8)) }

    @available(iOS 17.0, *)
    private func burst(_ w: Workload, _ mode: Mode) throws -> Run {
        var run = Run(workload: w.name, mode: mode)
        let native = mode == .selective || mode == .allnative
        let lane = mode != .go
        JSCScriptEngine.setLaneForTests(lane ? NativeBodyStore.shared : nil)
        let cap = NativeMitmRuntime.maxSessions
        if mode == .allnative { NativeMitmRuntime.maxSessions = w.plain + w.heavy + 8 }
        if mode == .allnative {
            NativeRewriteRuntime.override = true
            NativeBodyRuntime.override = true
            NativeScriptRuntime.override = true
        }
        defer {
            NativeMitmRuntime.maxSessions = cap
            NativeRewriteRuntime.override = nil
            NativeBodyRuntime.override = nil
            NativeScriptRuntime.override = nil
        }
        struct Start: Decodable { var enginePort: Int?; var error: String? }
        let st = try JSONDecoder().decode(Start.self, from: Data(LibmihomoMitmBenchStartConf(LibmihomoMitmBenchHeavyConf()).utf8))
        guard let port = st.enginePort, st.error == nil else { throw XCTSkip("bench engine: \(st.error ?? "?")") }
        defer { NativeMitmBench.stop() }
        var front: MitmTLSFront?
        if native {
            UpstreamConnection.trustAnyOriginForTesting = true
            let f = MitmTLSFront(identities: LeafIdentityCache(), queue: DispatchQueue(label: "test.selective.front"))
            let pool = UpstreamPool(relayPort: { NativeMitmBench.relayPort() })
            XCTAssertTrue(NativeMitmRuntime.install(front: f, upstream: UpstreamPoolConnector(pool: pool), codec: HTTPLaneCodec(),
                                                    force: true, selective: mode == .selective))
            if mode == .selective {
                XCTAssertEqual(LibmihomoMitmNativeSelective(), NativeMitmSelective.kinds)
                XCTAssertTrue(NativeRewriteRuntime.enabled && NativeBodyRuntime.enabled && NativeScriptRuntime.enabled, "selective mode turns the engines on")
            }
            front = f
        }
        defer {
            if native {
                NativeMitmRuntime.uninstall()
                front?.reset()
                UpstreamConnection.trustAnyOriginForTesting = false
            }
        }
        NativeMitmRuntime.clearErrors()
        _ = NativeMitmBench.goLog()
        let plainNeedle = "\"keep\":1", heavyNeedle = "\"combo\":true"
        // warm-up: listeners, leaves, relay, pools, script compile (heavy host on a small body)
        let warmPlain = BenchClient(enginePort: port, needle: plainNeedle)
        XCTAssertTrue(warmPlain.run(timeout: 15), "\(w.name) \(mode.rawValue) plain warm-up: \(warmPlain.failure ?? "timeout")")
        warmPlain.cancel()
        if w.heavy > 0 {
            let p = w.heavyPath.replacingOccurrences(of: #"kb=\d+"#, with: "kb=8", options: .regularExpression)
            let warmHeavy = BenchClient(enginePort: port, needle: heavyNeedle, host: "heavy.bench.test", path: p)
            XCTAssertTrue(warmHeavy.run(timeout: 30), "\(w.name) \(mode.rawValue) heavy warm-up: \(warmHeavy.failure ?? "timeout"); native: \(NativeMitmRuntime.recentErrors.last ?? "-"); engine: \(NativeMitmBench.goLog().split(separator: "\n").suffix(3).joined(separator: " | "))")
            warmHeavy.cancel()
        }
        Thread.sleep(forTimeInterval: 0.5)
        FootprintProbe.relieve()
        NativeMitmBench.freeGoMemory()
        Thread.sleep(forTimeInterval: 0.2)
        run.goBefore = goMem()
        let sel0 = selStats()
        let pk0 = goPeek()
        run.heapBefore = pk0?.heapObjects ?? 0
        run.mappedBefore = pk0?.mapped ?? 0
        run.heapPeak = run.heapBefore
        run.mappedPeak = run.mappedBefore
        run.mallocBefore = FootprintProbe.mallocInUse()
        run.fpBefore = ProcessMemory.footprintBytes()
        run.fpPeak = run.fpBefore

        // heavy connections spread evenly among the plain ones
        let total = w.plain + w.heavy
        let heavyAt = Set((0..<w.heavy).map { k in Int((Double(k) + 0.5) * Double(total) / Double(w.heavy)) })
        let clients: [BenchClient] = (0..<total).map { i in
            heavyAt.contains(i)
                ? BenchClient(enginePort: port, needle: heavyNeedle, host: "heavy.bench.test", path: w.heavyPath, completeWithoutNeedle: true)
                : BenchClient(enginePort: port, needle: plainNeedle, completeWithoutNeedle: true)
        }
        let group = DispatchGroup()
        let lock = NSLock()
        var ok = 0
        var failures: [String] = []
        let start = Date()
        for c in clients {
            group.enter()
            c.start { [c] success in
                lock.lock()
                if success { ok += 1 } else if failures.count < 5 { failures.append(c.failure ?? "timeout") }
                lock.unlock()
                group.leave()
            }
        }
        var timedOut = true
        let deadline = Date().addingTimeInterval(90)
        while Date() < deadline {
            if group.wait(timeout: .now() + 0.02) == .success { timedOut = false; break }
            run.fpPeak = max(run.fpPeak, ProcessMemory.footprintBytes())
            if let p = goPeek() {
                run.heapPeak = max(run.heapPeak, p.heapObjects)
                run.mappedPeak = max(run.mappedPeak, p.mapped)
            }
        }
        run.seconds = Date().timeIntervalSince(start)
        if timedOut { lock.lock(); failures.append("burst timed out after 90 s"); lock.unlock() }
        Thread.sleep(forTimeInterval: 1.0) // idle keep-alive
        lock.lock(); run.ok = ok; run.failures = failures; lock.unlock()
        run.applied = clients.filter(\.applied).count
        run.fpAfter = ProcessMemory.footprintBytes()
        run.fpPeak = max(run.fpPeak, run.fpAfter)
        run.mallocAfter = FootprintProbe.mallocInUse()
        run.goAfter = goMem()
        run.handed = (run.goAfter?.handed ?? 0) - (run.goBefore?.handed ?? 0)
        if let a = selStats(), let b = sel0 {
            run.selHanded = a.handed - b.handed
            run.selSkipped = a.skipped - b.skipped
        }
        run.nativeErrors = NativeMitmRuntime.recentErrors
        run.goLog = NativeMitmBench.goLog().split(separator: "\n").map(String.init).filter { !$0.hasPrefix("info ") }
        for c in clients { c.cancel() }
        let end = Date().addingTimeInterval(10)
        while Date() < end, NativeMitmRuntime.runningSessions > 0 || NativeMitmRuntime.liveSessions > 0 {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertEqual(NativeMitmRuntime.runningSessions, 0, "\(w.name) \(mode.rawValue): sessions still running")
        XCTAssertEqual(NativeMitmRuntime.liveSessions, 0, "\(w.name) \(mode.rawValue): session slots leaked")
        Thread.sleep(forTimeInterval: 0.3)
        FootprintProbe.relieve()
        return run
    }
}
