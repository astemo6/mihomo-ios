import Network
import XCTest
@testable import Mihomo

/// Native MitM stage 2 memory check (user 2026-10-24 13:31: 「先试试新代码能不能降低内存占用」): a 喜马拉雅-like burst of
/// 100 concurrent MitM connections (one small JSON request each, then idle keep-alive) through the Go path and
/// through the native front, measuring the whole process's phys_footprint (what jetsam reads) and the Go runtime.
/// Everything runs in this process: the Go bench engine + origin (bridge/s2bench.go), the native front / sessions /
/// upstream pool (native runs), and the Network.framework clients — the clients and origin cost the same in both
/// modes, so the difference is the MitM path. Every mode runs once uncounted (warm-up), then 4 rounds in order
/// alternating forward / reversed; medians are reported (allocator reuse favours later runs).
final class NativeMitmMemoryTests: XCTestCase {
    static let conns = 100

    struct GoMem: Decodable { var heapInuse: Int64; var sys: Int64; var stack: Int64; var goroutines: Int; var handed: Int64; var fellBack: Int64 }

    struct Run {
        var mode: String
        var ok = 0
        var failures: [String] = []
        var nativeErrors: [String] = []
        var goLog: [String] = []
        var fpBefore: UInt64 = 0, fpAfter: UInt64 = 0
        var goBefore: GoMem?, goAfter: GoMem?
        /// feat/native-slim attribution: malloc bytes in use (all zones), thread count, footprint after teardown.
        var mallocBefore = 0, mallocAfter = 0
        var threadsBefore = 0, threadsAfter = 0, threadsPeak = 0
        var fpResidual: UInt64 = 0
        /// Peak footprint while the burst ran (sampled every 20 ms); footprint with the sessions still open after
        /// malloc pressure relief + Go GC/scavenge (what the live sessions really retain).
        var fpPeak: UInt64 = 0, fpRelieved: UInt64 = 0, mallocRelieved = 0
    }

    /// Modes: "go" (Go path), "native" (production cap 48, slim on), "native-nocap" (every connection native, slim
    /// on), then no-cap ablations (feat/native-slim) — one Slim knob back to the 13f6c41 behaviour each, and all of
    /// them ("nocap-legacy") — so the medians say what each knob saves.
    static let modes: [(name: String, cap: Bool, slim: NativeMitmRuntime.Slim?)] = {
        // 90a7b2f measured the other knobs one by one: shared PrivacyContext / 16 KB io / idle buffer release are
        // within this bench's run-to-run noise (±3 MB); own queues cost +3.9 MB (thread peak +48).
        // a84818d: relief knob −3.9 MB at 1 s; with relief + Go scavenge every mode retains ~+2.5–2.7 MB (go too) —
        // the native excess is the burst's transient (peak), so this round limits concurrent upstream dials.
        var d8 = NativeMitmRuntime.Slim(); d8.maxConcurrentDials = 8
        var d24 = NativeMitmRuntime.Slim(); d24.maxConcurrentDials = 24
        return [("go", true, nil), ("native", true, NativeMitmRuntime.Slim()), ("native-nocap", false, NativeMitmRuntime.Slim()),
                ("nocap-dial8", false, d8), ("nocap-dial24", false, d24), ("nocap-legacy", false, .legacy)]
    }()

    static func mb(_ b: Int64) -> String { String(format: "%+.2f", Double(b) / 1_048_576) }
    static func mbAbs(_ b: UInt64) -> String { String(format: "%.2f", Double(b) / 1_048_576) }

    func testBurstFootprintGoPathVersusNativeFront() throws {
        guard #available(iOS 17.0, *) else { throw XCTSkip("native front needs iOS 17") }
        // "native" = production session cap (NativeMitmRuntime.maxSessions, 48: the rest of the burst stays on the
        // Go path); "native-nocap" = every connection native.
        let modes = Self.modes.map(\.name)
        // uncounted warm-up of every mode: grows the allocator and the pools once so no counted run pays for it
        for m in modes { _ = try burst(mode: m) }
        // 4 rounds, order alternating forward / reversed (run-order drift lands on every mode alike); medians reported
        var runs: [Run] = []
        for round in 0..<4 {
            for m in (round % 2 == 0 ? modes : modes.reversed()) { runs.append(try burst(mode: m)) }
        }
        for (i, r) in runs.enumerated() {
            guard let gb = r.goBefore, let ga = r.goAfter else { continue }
            let line = "[s2-memory] run \(i + 1) \(r.mode): \(r.ok)/\(Self.conns) requests passed; footprint \(Self.mbAbs(r.fpBefore)) → \(Self.mbAbs(r.fpAfter)) MB (\(Self.mb(Int64(r.fpAfter) - Int64(r.fpBefore))) MB), peak \(Self.mb(Int64(r.fpPeak) - Int64(r.fpBefore))) MB, relieved \(Self.mb(Int64(r.fpRelieved) - Int64(r.fpBefore))) MB, after teardown \(Self.mb(Int64(r.fpResidual) - Int64(r.fpBefore))) MB; malloc \(Self.mb(Int64(r.mallocAfter - r.mallocBefore))) MB; threads \(r.threadsBefore) → \(r.threadsAfter) (peak \(r.threadsPeak)); Go heap \(Self.mb(ga.heapInuse - gb.heapInuse)) MB, Go sys \(Self.mb(ga.sys - gb.sys)) MB, stacks \(Self.mb(ga.stack - gb.stack)) MB, goroutines \(ga.goroutines - gb.goroutines >= 0 ? "+" : "")\(ga.goroutines - gb.goroutines); handed \(ga.handed - gb.handed), fell back \(ga.fellBack - gb.fellBack)"
            print(line)
            NSLog("%@", line)
            if !r.failures.isEmpty { print("[s2-memory] run \(i + 1) failures: \(r.failures.prefix(3).joined(separator: " | "))") }
            if !r.nativeErrors.isEmpty { print("[s2-memory] run \(i + 1) native errors: \(r.nativeErrors.suffix(4).joined(separator: " | "))") }
            if !r.goLog.isEmpty { print("[s2-memory] run \(i + 1) engine log: \(r.goLog.suffix(6).joined(separator: " | "))") }
        }
        func median(_ m: String, _ f: (Run) -> Int64?) -> Double {
            let v = runs.filter { $0.mode == m }.compactMap(f).map { Double($0) / 1_048_576 }.sorted()
            guard !v.isEmpty else { return .nan }
            return v.count % 2 == 1 ? v[v.count / 2] : (v[v.count / 2 - 1] + v[v.count / 2]) / 2
        }
        let fp: (Run) -> Int64? = { Int64($0.fpAfter) - Int64($0.fpBefore) }
        let heap: (Run) -> Int64? = { r in r.goAfter.flatMap { a in r.goBefore.map { a.heapInuse - $0.heapInuse } } }
        let sys: (Run) -> Int64? = { r in r.goAfter.flatMap { a in r.goBefore.map { a.sys - $0.sys } } }
        let stk: (Run) -> Int64? = { r in r.goAfter.flatMap { a in r.goBefore.map { a.stack - $0.stack } } }
        let mal: (Run) -> Int64? = { Int64($0.mallocAfter - $0.mallocBefore) }
        let res: (Run) -> Int64? = { Int64($0.fpResidual) - Int64($0.fpBefore) }
        let thr: (Run) -> Int64? = { Int64($0.threadsAfter - $0.threadsBefore) * 1_048_576 } // median() divides by 1 MiB
        let pk: (Run) -> Int64? = { Int64($0.threadsPeak - $0.threadsBefore) * 1_048_576 }
        let gor: (Run) -> Int64? = { r in r.goAfter.flatMap { a in r.goBefore.map { Int64(a.goroutines - $0.goroutines) * 1_048_576 } } }
        let okc: (Run) -> Int64? = { Int64($0.ok) * 1_048_576 }
        let peak: (Run) -> Int64? = { Int64($0.fpPeak) - Int64($0.fpBefore) }
        let rel: (Run) -> Int64? = { Int64($0.fpRelieved) - Int64($0.fpBefore) }
        let malRel: (Run) -> Int64? = { Int64($0.mallocRelieved - $0.mallocBefore) }
        print("[s2-memory] MEDIANS (\(Self.conns) conns, 4 counted runs per mode; footprint/malloc/Go in MB; per-conn = footprint ÷ \(Self.conns))")
        for m in modes {
            let name: NSString = m.padding(toLength: 16, withPad: " ", startingAt: 0) as NSString
            let f: Double = median(m, fp)
            var args: [CVarArg] = [name, f, f * 1024 / Double(Self.conns), median(m, res), median(m, mal)]
            args += [median(m, thr), median(m, pk), median(m, heap), median(m, sys), median(m, stk)]
            args += [median(m, gor), median(m, okc), Self.conns]
            let line = String(format: "[s2-memory] median %@ footprint %+6.2f MB (%+4.0f KB/conn) | after teardown %+6.2f | malloc %+6.2f | threads %+4.0f (peak %+4.0f) | Go heap %+5.2f sys %+5.2f stacks %+5.2f goroutines %+4.0f | ok %3.0f/%d", arguments: args)
            print(line)
            NSLog("%@", line)
            var a2: [CVarArg] = [name, median(m, peak), median(m, rel), median(m, rel) * 1024 / Double(Self.conns), median(m, malRel)]
            a2 += [median(m, malRel) * 1024 / Double(Self.conns)]
            let line2 = String(format: "[s2-memory] median %@ peak during burst %+6.2f MB | sessions open, after malloc relief + Go scavenge: footprint %+6.2f MB (%+4.0f KB/conn), malloc %+6.2f MB (%+4.0f KB/conn)", arguments: a2)
            print(line2)
            NSLog("%@", line2)
        }
        let summary = String(format: "[s2-memory] summary passed: median footprint Δ per burst go-path %.2f MB, native (cap %d) %.2f MB, native no cap %.2f MB (native − go %+.2f / %+.2f MB)", median("go", fp), NativeMitmRuntime.maxSessions, median("native", fp), median("native-nocap", fp), median("native", fp) - median("go", fp), median("native-nocap", fp) - median("go", fp))
        print(summary)
        NSLog("%@", summary)
        for r in runs { XCTAssertEqual(r.ok, Self.conns, "\(r.mode): \(r.ok)/\(Self.conns) requests answered") }
        for r in runs where r.mode != "go" {
            if let a = r.goAfter, let b = r.goBefore {
                let capped = Self.modes.first(where: { $0.name == r.mode })?.cap ?? true
                let want = capped ? min(Self.conns, NativeMitmRuntime.maxSessions) : Self.conns
                XCTAssertGreaterThanOrEqual(a.handed - b.handed, Int64(want),
                                            "\(r.mode): native front took too few connections")
            }
        }
    }

    @available(iOS 17.0, *)
    private func burst(mode: String) throws -> Run {
        let spec = Self.modes.first { $0.name == mode }!
        let native = spec.slim != nil
        var run = Run(mode: mode)
        let cap = NativeMitmRuntime.maxSessions
        let slim = NativeMitmRuntime.slim
        if !spec.cap { NativeMitmRuntime.maxSessions = Self.conns + 8 }
        if let s = spec.slim { NativeMitmRuntime.slim = s }
        defer { NativeMitmRuntime.maxSessions = cap; NativeMitmRuntime.slim = slim }
        struct Start: Decodable { var enginePort: Int?; var error: String? }
        let st = try JSONDecoder().decode(Start.self, from: Data(NativeMitmBench.start().utf8))
        guard let port = st.enginePort, st.error == nil else { throw XCTSkip("bench engine: \(st.error ?? "?")") }
        defer { NativeMitmBench.stop() }
        var front: MitmTLSFront?
        if native {
            UpstreamConnection.trustAnyOriginForTesting = true
            let f = MitmTLSFront(identities: LeafIdentityCache(), queue: DispatchQueue(label: "test.s2mem.front"))
            let pool = UpstreamPool(relayPort: { NativeMitmBench.relayPort() })
            XCTAssertTrue(NativeMitmRuntime.install(front: f, upstream: UpstreamPoolConnector(pool: pool), codec: HTTPLaneCodec(), force: true))
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
        // warm-up: listener, leaf, relay, pools
        let warm = BenchClient(enginePort: port)
        XCTAssertTrue(warm.run(timeout: 15), "\(mode) warm-up request failed: \(warm.failure ?? "timeout"); native: \(NativeMitmRuntime.recentErrors.last ?? "-"); engine: \(NativeMitmBench.goLog().split(separator: "\n").suffix(3).joined(separator: " | "))")
        warm.cancel()
        Thread.sleep(forTimeInterval: 0.5)
        run.goBefore = goMem()
        run.mallocBefore = FootprintProbe.mallocInUse()
        run.threadsBefore = FootprintProbe.threadCount()
        run.threadsPeak = run.threadsBefore
        run.fpBefore = ProcessMemory.footprintBytes()
        run.fpPeak = run.fpBefore

        let clients = (0..<Self.conns).map { _ in BenchClient(enginePort: port) }
        let group = DispatchGroup()
        let lock = NSLock()
        var ok = 0
        var failures: [String] = []
        for c in clients {
            group.enter()
            c.start { [c] success in
                lock.lock()
                if success { ok += 1 } else if failures.count < 5 { failures.append(c.failure ?? "timeout") }
                lock.unlock()
                group.leave()
            }
        }
        // thread peak while the burst runs (sampled every 20 ms)
        var timedOut = true
        let deadline60 = Date().addingTimeInterval(60)
        while Date() < deadline60 {
            if group.wait(timeout: .now() + 0.02) == .success { timedOut = false; break }
            run.threadsPeak = max(run.threadsPeak, FootprintProbe.threadCount())
            run.fpPeak = max(run.fpPeak, ProcessMemory.footprintBytes())
        }
        if timedOut { lock.lock(); failures.append("burst timed out after 60 s"); lock.unlock() }
        Thread.sleep(forTimeInterval: 1.0) // idle keep-alive
        lock.lock(); run.ok = ok; run.failures = failures; lock.unlock()
        run.nativeErrors = NativeMitmRuntime.recentErrors
        run.goLog = NativeMitmBench.goLog().split(separator: "\n").map(String.init).filter { !$0.hasPrefix("info ") }
        run.fpAfter = ProcessMemory.footprintBytes()
        run.mallocAfter = FootprintProbe.mallocInUse()
        run.threadsAfter = FootprintProbe.threadCount()
        run.threadsPeak = max(run.threadsPeak, run.threadsAfter)
        run.goAfter = goMem()
        run.fpPeak = max(run.fpPeak, run.fpAfter)
        FootprintProbe.relieve()
        NativeMitmBench.freeGoMemory()
        Thread.sleep(forTimeInterval: 0.2)
        run.fpRelieved = ProcessMemory.footprintBytes()
        run.mallocRelieved = FootprintProbe.mallocInUse()
        for c in clients { c.cancel() }
        // sessions end when their clients go; nothing may leak into the next run (or the next test class)
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, NativeMitmRuntime.runningSessions > 0 || NativeMitmRuntime.liveSessions > 0 {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertEqual(NativeMitmRuntime.runningSessions, 0, "\(mode): sessions still running after the clients left")
        XCTAssertEqual(NativeMitmRuntime.liveSessions, 0, "\(mode): session slots leaked")
        // what stays after everything closed (allocator retention / leaks), after a malloc pressure relief
        Thread.sleep(forTimeInterval: 0.5)
        FootprintProbe.relieve()
        run.fpResidual = ProcessMemory.footprintBytes()
        return run
    }

    private func goMem() -> GoMem? { try? JSONDecoder().decode(GoMem.self, from: Data(NativeMitmBench.goMemory().utf8)) }
}

/// One MitM client: TLS (bench CA not checked) to api.bench.test:443 through the engine as an HTTP CONNECT proxy,
/// one GET, then left open (keep-alive).
@available(iOS 17.0, *)
final class BenchClient {
    private static let queue = DispatchQueue(label: "test.s2mem.clients")
    private let conn: NWConnection
    private var buf = Data()
    private var done: ((Bool) -> Void)?
    private(set) var failure: String?

    init(enginePort: Int) {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, "api.bench.test")
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, Self.queue)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let ctx = NWParameters.PrivacyContext(description: "test.s2mem")
        ctx.proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(enginePort))!), tlsOptions: nil)]
        params.setPrivacyContext(ctx)
        conn = NWConnection(host: "api.bench.test", port: 443, using: params)
    }

    func start(_ completion: @escaping (Bool) -> Void) {
        done = completion
        conn.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                let req = "GET /json HTTP/1.1\r\nHost: api.bench.test\r\nUser-Agent: s2mem\r\nAccept: */*\r\n\r\n"
                self.conn.send(content: Data(req.utf8), completion: .contentProcessed { [weak self] e in
                    if let e { self?.finish(false, "send: \(e)") } else { self?.receive() }
                })
            case .failed(let e): self.finish(false, "failed: \(e)")
            case .waiting(let e): self.finish(false, "waiting: \(e)")
            default: break
            }
        }
        conn.start(queue: Self.queue)
    }

    private func receive() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 << 10) { [weak self] data, _, eof, err in
            guard let self else { return }
            if let data { self.buf.append(data) }
            if let s = String(data: self.buf, encoding: .utf8), s.contains("\"keep\":1") {
                self.finish(s.hasPrefix("HTTP/1.1 200"), s.hasPrefix("HTTP/1.1 200") ? nil : String(s.prefix(200)))
                return
            }
            if eof || err != nil {
                let got = String(decoding: self.buf.prefix(240), as: UTF8.self).replacingOccurrences(of: "\r\n", with: "⏎")
                self.finish(false, "eof/err \(String(describing: err)) after \(self.buf.count) bytes: \(got)")
                return
            }
            self.receive()
        }
    }

    private func finish(_ ok: Bool, _ why: String?) {
        guard let d = done else { return }
        done = nil
        failure = why
        d(ok)
    }

    /// Synchronous variant for the warm-up.
    func run(timeout: TimeInterval) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        var ok = false
        start { ok = $0; sem.signal() }
        return sem.wait(timeout: .now() + timeout) == .success && ok
    }

    func cancel() { conn.cancel() }
}
