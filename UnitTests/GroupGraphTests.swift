import XCTest
@testable import Tern

/// hotfix/group-test-offline: a select group made only of other groups is tested through the real nodes behind it,
/// and each member group shows the delay of the node it resolves to.
final class GroupGraphTests: XCTestCase {
    private typealias G = GroupGraph.Group

    private func graph(_ groups: [String: G], nodes: Set<String>) -> GroupGraph {
        GroupGraph(groups: groups, isTestable: { nodes.contains($0) })
    }

    // 节点选择 → 自动选择 (url-test) / 日本 (select) / proxy (select, nested 自动选择 again) / 直连组 / 故障转移.
    private var sample: GroupGraph {
        graph([
            "节点选择": G(type: "select", members: ["自动选择", "日本", "proxy", "直连组", "故障转移"], now: "自动选择"),
            "自动选择": G(type: "url-test", members: ["JP1", "HK1", "SG1"], now: "JP1"),
            "日本": G(type: "select", members: ["JP1", "JP2"], now: "JP2"),
            "proxy": G(type: "select", members: ["自动选择", "US1", "DIRECT"], now: "US1"),
            "直连组": G(type: "select", members: ["DIRECT"], now: "DIRECT"),
            "故障转移": G(type: "fallback", members: ["SG1", "HK1"], now: "SG1"),
        ], nodes: ["JP1", "JP2", "HK1", "SG1", "US1"])
    }

    func testLeavesExpandNestedGroupsOnceInOrder() {
        XCTAssertEqual(sample.leaves(of: "节点选择"), ["JP1", "HK1", "SG1", "JP2", "US1"])
        XCTAssertEqual(sample.leaves(of: "直连组"), [], "DIRECT is not testable")
        XCTAssertEqual(sample.leaves(of: "JP1"), ["JP1"], "a node is its own leaf")
        XCTAssertEqual(sample.leaves(of: ["日本", "故障转移"]), ["JP1", "JP2", "SG1", "HK1"])
    }

    func testCycleIsCut() {
        let g = graph([
            "A": G(type: "select", members: ["B", "N1"], now: "B"),
            "B": G(type: "select", members: ["A", "N2"], now: "A"),
        ], nodes: ["N1", "N2"])
        XCTAssertEqual(g.leaves(of: "A"), ["N2", "N1"])
        XCTAssertNil(g.resolve("A", delays: ["N1": 10, "N2": 20]), "A → B → A resolves nowhere")
        XCTAssertNil(g.follow("A"))
    }

    func testResolveBeforeAnyMeasurement() {
        let r = sample.resolve("节点选择", delays: [:])
        XCTAssertEqual(r?.node, "JP1", "url-test falls back to its listed current member")
        XCTAssertNil(r?.delay)
    }

    func testSelectFollowsSelection() {
        let d = ["JP1": 80, "JP2": 120, "HK1": 40, "SG1": 0, "US1": 200]
        XCTAssertEqual(sample.resolve("日本", delays: d), .init(node: "JP2", delay: 120, how: .selected))
        XCTAssertEqual(sample.resolve("proxy", delays: d), .init(node: "US1", delay: 200, how: .selected))
        XCTAssertEqual(sample.resolve("直连组", delays: d), .init(node: "DIRECT", delay: nil, how: .selected), "DIRECT is never measured")
    }

    func testURLTestPicksFastestMeasured() {
        let d = ["JP1": 80, "JP2": 120, "HK1": 40, "SG1": 0, "US1": 200]
        XCTAssertEqual(sample.resolve("自动选择", delays: d), .init(node: "HK1", delay: 40, how: .fastest))
        // A select group whose selection is the url-test group carries the url-test's pick (and says how).
        XCTAssertEqual(sample.resolve("节点选择", delays: d), .init(node: "HK1", delay: 40, how: .fastest))
    }

    func testFallbackPicksFirstAnswering() {
        let d = ["SG1": 0, "HK1": 300]
        XCTAssertEqual(sample.resolve("故障转移", delays: d), .init(node: "HK1", delay: 300, how: .firstAvailable))
        let d2 = ["SG1": 90, "HK1": 30]
        XCTAssertEqual(sample.resolve("故障转移", delays: d2), .init(node: "SG1", delay: 90, how: .firstAvailable), "order, not speed")
    }

    func testAllTimeoutsShowTimeoutNotFastest() {
        let d = ["JP1": 0, "HK1": 0, "SG1": 0]
        XCTAssertEqual(sample.resolve("自动选择", delays: d), .init(node: "JP1", delay: 0, how: .selected))
        // Partly measured (SG1 missing), nothing answered yet: the listed member with its own timeout, never 「最快」.
        XCTAssertEqual(sample.resolve("自动选择", delays: ["JP1": 0, "HK1": 0]), .init(node: "JP1", delay: 0, how: .selected))
    }

    func testRelayHasNoSingleNodeDelay() {
        let g = graph(["R": G(type: "relay", members: ["N1", "N2"], now: nil)], nodes: ["N1", "N2"])
        XCTAssertEqual(g.leaves(of: "R"), ["N1", "N2"])
        XCTAssertNil(g.resolve("R", delays: ["N1": 10, "N2": 20]))
    }

    func testFollowLiveNow() {
        XCTAssertEqual(sample.follow("节点选择"), "JP1")
        XCTAssertEqual(sample.follow("proxy"), "US1")
        XCTAssertNil(sample.follow("JP1"), "not a group")
    }

    /// The offline inspector's GLOBAL (synthesized: DIRECT, REJECT, every node, every group) expands the same way.
    func testGlobalLikeGroup() {
        var gs = sample.groups
        gs["GLOBAL"] = G(type: "select", members: ["DIRECT", "REJECT", "JP1", "US1", "节点选择", "日本"], now: "节点选择")
        let g = graph(gs, nodes: ["JP1", "JP2", "HK1", "SG1", "US1"])
        XCTAssertEqual(g.leaves(of: "GLOBAL"), ["JP1", "US1", "HK1", "SG1", "JP2"])
        XCTAssertEqual(g.resolve("GLOBAL", delays: ["JP1": 50, "HK1": 70, "SG1": 0])?.node, "JP1")
    }
}
