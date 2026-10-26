import XCTest
@testable import Mihomo

/// hotfix/sub-disabled-nodes: a 停用 节点集 / node subscription must not reach 全部节点 / 筛选节点 from a core that still
/// serves it (reload pending or failed).
final class ExcludedProvidersTests: XCTestCase {
    func testDisabledAndDeletedProvidersAreExcluded() {
        let ov: [String: ProviderOverride] = [
            "eds": ProviderOverride(disabled: true),
            "old": ProviderOverride(deleted: true),
            "SelfBuild": ProviderOverride(icon: "sf:star"),
        ]
        let out = NodeManagerModel.excludedProviders(runtime: ["SelfBuild", "薯条"], overrides: ov, subs: [])
        XCTAssertEqual(out, ["eds", "old"])
    }

    func testDisabledNodeSubscriptionIsExcluded() {
        let subs = [NodeSubscription(name: "Sub A", url: "https://a.example.invalid", enabled: false),
                    NodeSubscription(name: "Sub B", url: "https://b.example.invalid", enabled: true)]
        let out = NodeManagerModel.excludedProviders(runtime: ["Sub B"], overrides: [:], subs: subs)
        XCTAssertEqual(out, ["Sub A"])
    }

    func testRuntimeProviderOfTheSameNameStays() {
        // Re-enabled (runtime has it again) or a profile provider that shares the name: listed as usual.
        let out = NodeManagerModel.excludedProviders(runtime: ["eds"], overrides: ["eds": ProviderOverride(disabled: true)],
                                                     subs: [NodeSubscription(name: "eds", url: "https://e.example.invalid", enabled: false)])
        XCTAssertTrue(out.isEmpty)
    }

    /// r7: `runtime` is the provider set of the BUILT config (ProfileInspector → the old core buildRuntime, which already drops
    /// 停用/删除 节点集 and disabled node subscriptions) — the set a finished reload serves. An unnamed subscription is
    /// built as "订阅" (the old core mergeNodeSubs), so that is the name to exclude.
    func testUnnamedDisabledSubscriptionUsesGoDefaultName() {
        let subs = [NodeSubscription(name: "  ", url: "https://u.example.invalid", enabled: false)]
        XCTAssertEqual(NodeManagerModel.excludedProviders(runtime: [], overrides: [:], subs: subs), ["订阅"])
    }

    func testEnabledEverythingExcludesNothing() {
        let out = NodeManagerModel.excludedProviders(runtime: ["A"], overrides: [:],
                                                     subs: [NodeSubscription(name: "A", url: "https://a.example.invalid")])
        XCTAssertTrue(out.isEmpty)
    }
}
