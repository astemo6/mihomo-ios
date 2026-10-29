import XCTest
@testable import Tern

/// fix/tools-node-sub-count (user 2026-10-29): the 工具 → 节点与订阅 card read 节点订阅 0
/// while 节点 read 42 — the count only knew NodeSubStore, but a profile's own
/// subscriptions (QX [server_remote] / Clash proxy-providers) surface as inspector
/// proxy providers. The card now counts providers + not-yet-materialized subs.
final class ToolStatsTests: XCTestCase {
    private func provider(_ name: String, path: String?) -> InspectProvider {
        InspectProvider(name: name, kind: "proxy", vehicle: "HTTP", behavior: nil, format: nil,
                        url: nil, path: path, interval: nil, cached: true, cachedAt: nil,
                        size: nil, count: 0, proxies: nil, preview: nil, cachePath: nil)
    }

    private func stats(providers: [InspectProvider], subIDs: [String]) -> ToolStats {
        var r = InspectResult()
        r.proxyProviders = providers
        return ToolStats.compute(profiles: [], nodeSubIDs: subIDs, result: r, delays: [:],
                                 customRules: [], cfg: EngineConfig(), moduleInfo: [:],
                                 caExists: false, caTrusted: nil)
    }

    func testInProfileProvidersCountAsNodeSubs() {
        // The reported case: a local .conf whose nodes come from its own subscriptions —
        // no remote profiles, no standalone node subs. The old count read 0.
        let s = stats(providers: [provider("机场 A", path: "providers/a.yaml"),
                                  provider("机场 B", path: "providers/b.yaml")], subIDs: [])
        XCTAssertEqual(s.nodeSubs, 2)
    }

    func testMaterializedSubIsNotDoubleCounted() {
        // "abc" already downloaded into its provider; "def" added but not fetched yet.
        let s = stats(providers: [provider("Sub X", path: "nodesubs/abc.yaml")], subIDs: ["abc", "def"])
        XCTAssertEqual(s.nodeSubs, 2)
    }

    func testZeroWhenNothingFeedsNodes() {
        XCTAssertEqual(stats(providers: [], subIDs: []).nodeSubs, 0)
    }
}
