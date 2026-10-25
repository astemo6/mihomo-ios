import XCTest
@testable import Mihomo

// nc-lifecycle: the process-wide teardown primitives the tunnel core's
// stop path uses (NCConnector.closeAllSharedSessions, the DNS singleton
// drains). The engine / core / data plane live in the tunnel target and
// cannot be driven from this bundle — the in-tunnel carrier for those is
// NativeTunnelCore.runLifecycleSelfTest (provider app message
// "lifecycleTest", 20 reloads + the same drains + footprint assertions).
// What this file pins: the Shared-level drains leave every registry empty
// and are safe, idempotent no-ops when nothing is live.
final class NativeCoreLifecycleTests: XCTestCase {

    func testCloseAllSharedSessionsLeavesEveryRegistryEmpty() {
        NCConnector.closeAllSharedSessions()
        let counts = NCConnector.sharedSessionCounts()
        XCTAssertEqual(Set(counts.keys), ["mux", "anytls", "hy2", "hy1", "tuic", "ssh"])
        for (kind, n) in counts {
            XCTAssertEqual(n, 0, "registry \(kind) not empty after closeAllSharedSessions")
        }
        // Idempotent: a second drain closes nothing and stays empty.
        let closedAgain = NCConnector.closeAllSharedSessions()
        XCTAssertEqual(closedAgain.values.reduce(0, +), 0)
        for (kind, n) in NCConnector.sharedSessionCounts() {
            XCTAssertEqual(n, 0, "registry \(kind) not empty after second drain")
        }
    }

    func testSharedDNSDrainsOnEmptySingletonsAreNoOps() {
        NCDNSUpstreamCoordinator.shared.cancelAll()
        NCDNSDoTPool.shared.reset()
        NCDNSDoHPool.shared.reset()
        let dc = NCDNSUpstreamCoordinator.shared.inFlightCounts()
        XCTAssertEqual(dc.entries, 0)
        XCTAssertEqual(dc.active, 0)
        XCTAssertEqual(dc.pending, 0)
        XCTAssertEqual(NCDNSDoTPool.shared.pooledConnectionCount(), 0)
        XCTAssertEqual(NCDNSDoHPool.shared.pooledConnectionCount(), 0)
    }
}
