import XCTest
@testable import Mihomo

// nc-lifecycle REWORK — the 20-reload evidence PR #135 was missing.
//
// #135 shipped the in-tunnel carrier (NativeTunnelCore.runLifecycleSelfTest,
// provider message "lifecycleTest") with the right assertions but no actual
// run output: the tunnel core needs a live NEPacketTunnelFlow and could not
// be driven from any test bundle. This class closes that gap at the deepest
// layer that CAN be driven in-process: the real NativeCoreEngine, compiled
// into the app target for these tests (see project.yml). It performs the
// same protocol as the tunnel carrier — initial load, 20 reloads with full
// config swaps at rounds 7 and 14, a footprint sample per round via the
// same NCMemorySampler, then the stop-level drains and the same pass
// criteria (registries/coordinator/pools all zero; last footprint within
// +3 MB of the first).
//
// What this evidence does NOT cover (still device-only, via the tunnel
// carrier): NCDataPlane / lwIP and NativeTunnelCore itself — they need a
// packet flow. Everything they own is drained through the same primitives
// asserted here (NCConnector.closeAllSharedSessions, coordinator
// cancelAll, pool resets), which is why those primitives are the ones
// pinned below.
//
// The per-round [nc-mem] lines the sampler logs, plus the [nc-evidence]
// table printed at the end, are the checkable output: they land in the
// test log verbatim.
final class NativeCoreReloadEvidenceTests: XCTestCase {

    private var homeA: URL!
    private var homeB: URL!

    // Two minimal but real configs. A: one node. B: two nodes and an extra
    // rule, so a swap is observable through engine.config — a reload that
    // silently kept the old config would fail the round 7/14 assertions.
    // The select group is deliberate: url-test/fallback groups would make
    // the health-check scheduler probe the network, which a unit test must
    // never do; with no rule-providers and no subscriptions, load() stays
    // entirely on disk + CPU.
    private let yamlA = """
    mode: rule
    dns:
      enable: true
      enhanced-mode: fake-ip
    proxies:
      - {name: A1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
    proxy-groups:
      - {name: G, type: select, proxies: [A1, DIRECT]}
    rules:
      - DOMAIN-SUFFIX,example.com,A1
      - MATCH,G
    """

    private let yamlB = """
    mode: rule
    dns:
      enable: true
      enhanced-mode: fake-ip
    proxies:
      - {name: A1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
      - {name: A2, type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: pw}
    proxy-groups:
      - {name: G, type: select, proxies: [A1, A2, DIRECT]}
    rules:
      - DOMAIN-SUFFIX,example.com,A1
      - DOMAIN-SUFFIX,example.org,A2
      - MATCH,G
    """

    override func setUpWithError() throws {
        homeA = try Self.makeHome(yamlA)
        homeB = try Self.makeHome(yamlB)
    }

    override func tearDownWithError() throws {
        if let homeA { try? FileManager.default.removeItem(at: homeA) }
        if let homeB { try? FileManager.default.removeItem(at: homeB) }
        homeA = nil
        homeB = nil
    }

    private static func makeHome(_ yaml: String) throws -> URL {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-evidence-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(yaml.utf8).write(to: home.appendingPathComponent("runtime.yaml"))
        return home
    }

    func testTwentyReloadsFootprintAndDrainEvidence() {
        let engine = NativeCoreEngine()

        // Baseline: initial load of config A (mirrors the tunnel carrier's
        // round 0, sampled with the engine already up). Load #1 also absorbs
        // the one-time warm-up (parsers, pool, group engine, scheduler) that
        // must not be charged against the reload rounds.
        XCTAssertNil(engine.load(home: homeA.path), "initial load failed")
        XCTAssertTrue(engine.isRunning)
        XCTAssertEqual(engine.config?.proxies.count, 1)
        var samples: [(round: Int, mb: Double)] = []
        let baseline = NCMemorySampler.sample("evidence-baseline")
        samples.append((0, baseline.footprintMB))

        // 20 reloads of the same home; rounds 7 and 14 load config B instead
        // (the tunnel carrier's full-reload stand-ins for a config swap).
        for r in 1...20 {
            let swap = (r == 7 || r == 14)
            let err = engine.load(home: swap ? homeB.path : homeA.path)
            XCTAssertNil(err, "reload round \(r) failed: \(err ?? "")")
            if swap {
                XCTAssertEqual(engine.config?.proxies.count, 2,
                               "round \(r): config B not in effect after swap reload")
            } else if r == 8 || r == 15 {
                XCTAssertEqual(engine.config?.proxies.count, 1,
                               "round \(r): config A not restored after swap round")
            }
            let s = NCMemorySampler.sample("evidence-r\(r)")
            samples.append((r, s.footprintMB))
        }

        // Stop-level teardown: the engine's own stop, then the exact drain
        // primitives NativeTunnelCore.stopLocked runs, in the same order.
        engine.stop()
        XCTAssertFalse(engine.isRunning)
        NCConnector.closeAllSharedSessions()
        NCDNSUpstreamCoordinator.shared.cancelAll()
        NCDNSDoTPool.shared.reset()
        NCDNSDoHPool.shared.reset()
        Thread.sleep(forTimeInterval: 0.3)

        for (kind, n) in NCConnector.sharedSessionCounts() {
            XCTAssertEqual(n, 0, "session registry \(kind) not empty after drains")
        }
        let dc = NCDNSUpstreamCoordinator.shared.inFlightCounts()
        XCTAssertEqual(dc.entries, 0, "DNS coordinator entries not drained")
        XCTAssertEqual(dc.active, 0, "DNS coordinator active queries not drained")
        XCTAssertEqual(dc.pending, 0, "DNS coordinator pending queries not drained")
        XCTAssertEqual(NCDNSDoTPool.shared.pooledConnectionCount(), 0, "DoT pool not drained")
        XCTAssertEqual(NCDNSDoHPool.shared.pooledConnectionCount(), 0, "DoH pool not drained")

        // Footprint verdict, same allowance and rationale as the tunnel
        // carrier: +3 MB over the first sample. What legitimately persists
        // across reloads is process-wide by design (allocator arenas; on a
        // device also the mmap'd geo databases and the JSC prelude context —
        // neither is loaded by this config). Growth beyond that, round over
        // round, is a leak, and 3 MB sits far inside the 50 MB budget.
        let first = samples[0].mb
        let last = samples[samples.count - 1].mb
        let growth = last - first
        let table = samples
            .map { "round \($0.round): \(String(format: "%.1f", $0.mb))MB" }
            .joined(separator: "\n")
        NSLog("[nc-evidence] 20-reload footprint table:\n%@", table)
        NSLog("[nc-evidence] footprint growth first→last: %@MB (allowance 3.0MB)",
              String(format: "%+.1f", growth))
        XCTAssertLessThanOrEqual(growth, 3.0,
            "footprint grew \(String(format: "%.1f", growth))MB over 20 reloads "
            + "(first \(String(format: "%.1f", first))MB, last \(String(format: "%.1f", last))MB)")
    }
}
