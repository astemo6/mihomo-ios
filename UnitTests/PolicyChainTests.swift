import XCTest
@testable import Tern

/// feat/policy-chain: the 策略 card subtitle is the whole path down to the final node (Egern 策略).
@MainActor
final class PolicyChainTests: XCTestCase {
    private typealias G = GroupGraph.Group

    private func graph(_ groups: [String: G], nodes: Set<String>) -> GroupGraph {
        GroupGraph(groups: groups, isTestable: { nodes.contains($0) })
    }

    private var sample: GroupGraph {
        graph([
            "流媒体": G(type: "select", members: ["节点选择", "DIRECT"], now: "节点选择"),
            "节点选择": G(type: "select", members: ["日本节点", "自动选择", "DIRECT"], now: "日本节点"),
            "日本节点": G(type: "select", members: ["东京 AZ JP01", "大阪 JP02"], now: "东京 AZ JP01"),
            "自动选择": G(type: "url-test", members: ["香港 HK01", "新加坡 SG01"], now: "香港 HK01"),
            "直连": G(type: "select", members: ["DIRECT"], now: "DIRECT"),
            "拦截": G(type: "select", members: ["REJECT"], now: "REJECT"),
            "链式": G(type: "relay", members: ["香港 HK01", "东京 AZ JP01"], now: nil),
            "用链式": G(type: "select", members: ["链式"], now: "链式"),
        ], nodes: ["东京 AZ JP01", "大阪 JP02", "香港 HK01", "新加坡 SG01"])
    }

    func testLiveChainFollowsEveryHop() {
        XCTAssertEqual(sample.chain(from: "节点选择").hops, ["日本节点", "东京 AZ JP01"])
        XCTAssertEqual(sample.chain(from: "流媒体").hops, ["节点选择", "日本节点", "东京 AZ JP01"])
        XCTAssertEqual(sample.chain(from: "日本节点").hops, ["东京 AZ JP01"])
        XCTAssertEqual(sample.chain(from: "东京 AZ JP01"), .init(), "a node has no chain")
        XCTAssertEqual(PolicyChainText.text(sample.chain(from: "节点选择")), "日本节点 › 🇯🇵 东京 AZ JP01")
        XCTAssertEqual(PolicyChainText.text(sample.chain(from: "流媒体")), "节点选择 › 日本节点 › 🇯🇵 东京 AZ JP01")
    }

    func testBuiltinsPlain() {
        XCTAssertEqual(PolicyChainText.text(sample.chain(from: "直连")), "DIRECT")
        XCTAssertEqual(PolicyChainText.text(sample.chain(from: "拦截")), "REJECT")
    }

    func testRelayEndsTheChain() {
        XCTAssertEqual(sample.chain(from: "用链式").hops, ["链式"])
        XCTAssertEqual(sample.chain(from: "链式").hops, [], "relay has no pick")
        XCTAssertEqual(PolicyChainText.text(sample.chain(from: "链式")), "—")
    }

    func testCycleStops() {
        let g = graph([
            "A": G(type: "select", members: ["B"], now: "B"),
            "B": G(type: "select", members: ["C"], now: "C"),
            "C": G(type: "select", members: ["A"], now: "A"),
        ], nodes: [])
        let c = g.chain(from: "A")
        XCTAssertEqual(c.hops, ["B", "C"])
        XCTAssertTrue(c.looped)
        XCTAssertEqual(PolicyChainText.text(c), "B › … › C")
        XCTAssertEqual(PolicyChainText.parts(c).last, "C", "r7: the last hop stays last (ChainLine keeps it visible)")
    }

    func testDepthCap() {
        var gs: [String: G] = [:]
        for i in 0..<8 { gs["G\(i)"] = G(type: "select", members: ["G\(i + 1)"], now: "G\(i + 1)") }
        gs["G8"] = G(type: "select", members: ["N"], now: "N")
        let c = graph(gs, nodes: ["N"]).chain(from: "G0")
        XCTAssertEqual(c.hops.count, GroupGraph.chainMaxDepth)
        XCTAssertTrue(c.truncated)
        let parts = PolicyChainText.parts(c)
        XCTAssertEqual(parts.last, c.hops.last, "r7: truncation must not push the last hop out of the final slot")
        XCTAssertEqual(parts[parts.count - 2], "…")
    }

    func testMissingNowStops() {
        let g = graph(["X": G(type: "select", members: ["N"], now: nil)], nodes: ["N"])
        XCTAssertEqual(g.chain(from: "X").hops, [], "live: no now, nothing invented")
    }

    func testOfflineAutomaticFollowsMeasuredPick() {
        let d = ["香港 HK01": 0, "新加坡 SG01": 60]
        var gs = sample.groups
        gs["节点选择"]?.now = "自动选择"
        let g = graph(gs, nodes: ["东京 AZ JP01", "大阪 JP02", "香港 HK01", "新加坡 SG01"])
        let c = g.chain(from: "节点选择", delays: d)
        XCTAssertEqual(c.hops, ["自动选择", "新加坡 SG01"], "the measured pick, the node whose delay the card shows")
        XCTAssertEqual(c.how, .fastest)
        XCTAssertEqual(PolicyChainText.text(c), "自动选择 › " + String(localized: "最快 \("🇸🇬 新加坡 SG01")"))
        // Nothing measured: the listed current member.
        XCTAssertEqual(g.chain(from: "节点选择", delays: [:]).hops, ["自动选择", "香港 HK01"])
        XCTAssertEqual(g.chain(from: "节点选择", delays: [:]).how, .selected)
    }

    func testNodeFlag() {
        XCTAssertEqual(NodeFlag.decorate("东京 AZ JP01"), "🇯🇵 东京 AZ JP01")
        XCTAssertEqual(NodeFlag.decorate("HK-01 IPLC"), "🇭🇰 HK-01 IPLC")
        XCTAssertEqual(NodeFlag.decorate("🇺🇸 洛杉矶 US01"), "🇺🇸 洛杉矶 US01", "already flagged")
        XCTAssertEqual(NodeFlag.decorate("DIRECT"), "DIRECT")
        XCTAssertEqual(NodeFlag.decorate("REJECT"), "REJECT")
        XCTAssertEqual(NodeFlag.decorate("my-server"), "my-server", "no region, no guessed flag")
        XCTAssertEqual(NodeFlag.decorate("台北 TW01"), "🇨🇳 台北 TW01", "TW drawn as CN, like the Home header")
    }
}
