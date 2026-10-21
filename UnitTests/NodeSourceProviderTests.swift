import XCTest
@testable import Mihomo

/// Review 7 R7A-4: node detail lookups (credentials, 添加到本地节点, offline / live delay, share link) go to the
/// node's own source: "" for the profile's proxies, else the runtime provider name.
final class NodeSourceProviderTests: XCTestCase {
    func testRuntimeProvider() {
        XCTAssertEqual(NodeSource(kind: .profile, name: "我的配置").runtimeProvider, "")
        XCTAssertEqual(NodeSource(kind: .manual, name: "手动节点").runtimeProvider, "")
        XCTAssertEqual(NodeSource(kind: .provider, name: "机场A").runtimeProvider, "机场A")
        // A node subscription's merged provider can be renamed on a clash ("B" → "B 2"): the runtime name wins.
        XCTAssertEqual(NodeSource(kind: .subscription, name: "B", subID: "s1", provider: "B 2").runtimeProvider, "B 2")
        XCTAssertEqual(NodeSource(kind: .subscription, name: "B", subID: "s1").runtimeProvider, "B")
    }

    func testSameNameDifferentSourcesStayApart() {
        let a = ManagedNode(name: "🇭🇰 香港 01", type: "ss", server: "1.1.1.1", port: 1, udp: false,
                            source: NodeSource(kind: .subscription, name: "A", subID: "a", provider: "A"), inRuntime: true)
        let b = ManagedNode(name: "🇭🇰 香港 01", type: "ss", server: "2.2.2.2", port: 1, udp: false,
                            source: NodeSource(kind: .subscription, name: "B", subID: "b", provider: "B"), inRuntime: true)
        XCTAssertNotEqual(a.id, b.id)
        XCTAssertNotEqual(a.source.runtimeProvider, b.source.runtimeProvider)
    }
}
