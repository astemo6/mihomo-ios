import XCTest
@testable import Mihomo

/// Relay groups and dialer-proxy expansion in the group engine.
final class NativeCoreChainTests: XCTestCase {
    private func config(proxies: [NCProxy], groups: [NCProxyGroup]) -> NCConfig {
        NCConfig(mode: "rule", logLevel: "info", ipv6: false, proxies: proxies,
                 groups: groups, rules: [], dns: NCDNSConfig(fields: [:]), raw: [:])
    }

    private func proxy(_ name: String, fields: [String: NCJSONValue] = [:]) -> NCProxy {
        var f = fields
        f["server"] = .string("127.0.0.1")
        f["port"] = .number(1080)
        return NCProxy(name: name, type: "ss", fields: f)
    }

    func testRelayGroupBuildsChain() {
        let a = proxy("a"), b = proxy("b")
        let relay = NCProxyGroup(name: "R", type: "relay", proxies: ["a", "b"], fields: [:])
        let engine = NCGroupEngine(config: config(proxies: [a, b], groups: [relay]))
        XCTAssertEqual(engine.resolve("R"), .chain([a, b]))
    }

    func testRelaySingleMemberDegrades() {
        let a = proxy("a")
        let relay = NCProxyGroup(name: "R", type: "relay", proxies: ["a"], fields: [:])
        let engine = NCGroupEngine(config: config(proxies: [a], groups: [relay]))
        XCTAssertEqual(engine.resolve("R"), .proxy(a))
    }

    func testDialerProxyExpansion() {
        let front = proxy("front")
        let back = proxy("back", fields: ["dialer-proxy": .string("front")])
        let engine = NCGroupEngine(config: config(proxies: [front, back], groups: []))
        XCTAssertEqual(engine.resolve("back"), .chain([front, back]))
        XCTAssertEqual(engine.resolve("front"), .proxy(front))
    }

    func testDialerThroughGroupAndLoopGuard() {
        let front = proxy("front")
        let g = NCProxyGroup(name: "G", type: "select", proxies: ["front"], fields: [:])
        let back = proxy("back", fields: ["dialer-proxy": .string("G")])
        let loopy = proxy("loopy", fields: ["dialer-proxy": .string("loopy")])
        let engine = NCGroupEngine(config: config(proxies: [front, back, loopy], groups: [g]))
        XCTAssertEqual(engine.resolve("back"), .chain([front, back]))
        XCTAssertEqual(engine.resolve("loopy"), .unknown("loopy"))
    }
}
