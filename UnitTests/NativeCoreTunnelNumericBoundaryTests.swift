import XCTest
@testable import Mihomo

/// fix/nc-followup-c: numeric-boundary sweep of PacketTunnel/**. Only the group delay round's timeout is in the
/// app (unit-test) target; the other fixes of the sweep (controller Content-Length, script $httpClient chunk size,
/// Tailscale control HTTP framing, script "nblob" handle, cron step) live in tunnel-only files.
final class NativeCoreTunnelNumericBoundaryTests: XCTestCase {

    func testRoundTimeoutKeepsTheUsualSum() {
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: 5000, rounds: 1), 10_000)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: 5000, rounds: 3), 20_000)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: 0, rounds: 4), 5000)
    }

    /// `timeout: 9223372036854775807` (config) or `?timeout=` (controller) overflowed timeoutMs * rounds + 5000.
    func testRoundTimeoutSaturatesInsteadOfTrapping() {
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: Int.max, rounds: 3), Int.max)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: Int.max, rounds: 1), Int.max)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: Int.max - 10, rounds: 1), Int.max)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: Int.min, rounds: 2), 0)
        XCTAssertEqual(NCTunnelDelayTester.roundTimeoutMs(timeoutMs: -1000, rounds: 2), 3000)
    }

    /// The whole round with a huge per-member timeout: completes (no engine → every member fails at once).
    func testMeasureGroupWithHugeTimeoutCompletes() {
        let done = expectation(description: "round delivered")
        NCTunnelDelayTester.measureGroup(groupEngine: nil, members: ["a", "b", "c"], url: "http://example.com/",
                                         timeoutMs: Int.max, maxConcurrency: 1) { results in
            XCTAssertEqual(Set(results.keys), ["a", "b", "c"])
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
    }
}
