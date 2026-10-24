import Network
import XCTest
@testable import Mihomo

/// Native MitM stage 2 memory check (user 2026-10-24 13:31: 「先试试新代码能不能降低内存占用」): a 喜马拉雅-like burst of
/// 100 concurrent MitM connections (one small JSON request each, then idle keep-alive) through the Go path and
/// through the native front, measuring the whole process's phys_footprint (what jetsam reads) and the Go runtime.
/// Everything runs in this process: the Go bench engine + origin (bridge/s2bench.go), the native front / sessions /
/// upstream pool (native runs), and the Network.framework clients — the clients and origin cost the same in both
/// modes, so the difference is the MitM path. Runs alternate go, native, go, native (allocator reuse favours later
/// runs, so each mode gets an early and a late slot).
final class NativeMitmMemoryTests: XCTestCase {
    static let conns = 100

    struct GoMem: Decodable { var heapInuse: Int64; var sys: Int64; var stack: Int64; var goroutines: Int; var handed: Int64; var fellBack: Int64 }

    struct Run {
        var mode: String
        var ok = 0
        var fpBefore: UInt64 = 0, fpAfter: UInt64 = 0
        var goBefore: GoMem?, goAfter: GoMem?
    }

    static func mb(_ b: Int64) -> String { String(format: "%+.2f", Double(b) / 1_048_576) }
    static func mbAbs(_ b: UInt64) -> String { String(format: "%.2f", Double(b) / 1_048_576) }

    func testBurstFootprintGoPathVersusNativeFront() throws {
        guard #available(iOS 17.0, *) else { throw XCTSkip("native front needs iOS 17") }
        var runs: [Run] = []
        // "native" = production session cap (NativeMitmRuntime.maxSessions, 48: the rest of the burst stays on the
        // Go path); "native-nocap" = every connection native.
        for mode in ["go", "native", "native-nocap", "go", "native", "native-nocap"] {
            runs.append(try burst(mode: mode))
        }
        for (i, r) in runs.enumerated() {
            guard let gb = r.goBefore, let ga = r.goAfter else { continue }
            let line = "[s2-memory] run \(i + 1) \(r.mode): \(r.ok)/\(Self.conns) requests passed; footprint \(Self.mbAbs(r.fpBefore)) → \(Self.mbAbs(r.fpAfter)) MB (\(Self.mb(Int64(r.fpAfter) - Int64(r.fpBefore))) MB); Go heap \(Self.mb(ga.heapInuse - gb.heapInuse)) MB, Go sys \(Self.mb(ga.sys - gb.sys)) MB, stacks \(Self.mb(ga.stack - gb.stack)) MB, goroutines \(ga.goroutines - gb.goroutines >= 0 ? "+" : "")\(ga.goroutines - gb.goroutines); handed \(ga.handed - gb.handed), fell back \(ga.fellBack - gb.fellBack)"
            print(line)
            NSLog("%@", line)
        }
        func avg(_ m: String) -> Double {
            let rs = runs.filter { $0.mode == m }
            return rs.map { Double(Int64($0.fpAfter) - Int64($0.fpBefore)) }.reduce(0, +) / Double(max(rs.count, 1)) / 1_048_576
        }
        let summary = String(format: "[s2-memory] summary passed: footprint Δ per burst go-path %.2f MB, native (cap %d) %.2f MB, native no cap %.2f MB (native − go %+.2f / %+.2f MB)", avg("go"), NativeMitmRuntime.maxSessions, avg("native"), avg("native-nocap"), avg("native") - avg("go"), avg("native-nocap") - avg("go"))
        print(summary)
        NSLog("%@", summary)
        for r in runs { XCTAssertEqual(r.ok, Self.conns, "\(r.mode): \(r.ok)/\(Self.conns) requests answered") }
        for r in runs where r.mode != "go" {
            if let a = r.goAfter, let b = r.goBefore {
                XCTAssertGreaterThanOrEqual(a.handed - b.handed, Int64(r.mode == "native" ? min(Self.conns, NativeMitmRuntime.maxSessions) : Self.conns),
                                            "\(r.mode): native front took too few connections")
            }
        }
    }

    @available(iOS 17.0, *)
    private func burst(mode: String) throws -> Run {
        let native = mode != "go"
        var run = Run(mode: mode)
        let cap = NativeMitmRuntime.maxSessions
        if mode == "native-nocap" { NativeMitmRuntime.maxSessions = Self.conns + 8 }
        defer { NativeMitmRuntime.maxSessions = cap }
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
        // warm-up: listener, leaf, relay, pools
        let warm = BenchClient(enginePort: port)
        XCTAssertTrue(warm.run(timeout: 15), "warm-up request failed: \(warm.failure ?? "")")
        warm.cancel()
        Thread.sleep(forTimeInterval: 0.5)
        run.goBefore = goMem()
        run.fpBefore = ProcessMemory.footprintBytes()

        let clients = (0..<Self.conns).map { _ in BenchClient(enginePort: port) }
        let group = DispatchGroup()
        let lock = NSLock()
        var ok = 0
        for c in clients {
            group.enter()
            c.start { success in
                if success { lock.lock(); ok += 1; lock.unlock() }
                group.leave()
            }
        }
        _ = group.wait(timeout: .now() + 60)
        Thread.sleep(forTimeInterval: 1.0) // idle keep-alive
        run.ok = ok
        run.fpAfter = ProcessMemory.footprintBytes()
        run.goAfter = goMem()
        for c in clients { c.cancel() }
        Thread.sleep(forTimeInterval: 0.5)
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
            if eof || err != nil { self.finish(false, "eof/err \(String(describing: err)) after \(self.buf.count) bytes"); return }
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
