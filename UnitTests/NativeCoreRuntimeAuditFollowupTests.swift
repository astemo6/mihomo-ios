import XCTest
@testable import Tern

/// fix/nc-c-followup task 2: regression tests for the bugs found auditing
/// NCRuntimeFiles / NCRuntimeSubRules / NCRuntimeSteps / GroupEditing.

final class NativeCoreRuntimeAuditFollowupTests: XCTestCase {

    /// 节点处理 dedupe keyed a node's port with String(Int64(n)), which
    /// traps for a YAML number outside Int64 range (`port: 1e30`) or inf;
    /// fixReferences did the same for numeric group members. Both now go
    /// through NCValueCoercion.sprint (the old core fmt.Sprint shape).
    func testSubRulesDedupeAndRefsSurviveHugeNumbers() {
        func node(_ n: String, _ port: Double) -> NCJSONValue {
            .object(["name": .string(n), "type": .string("ss"), "server": .string("1.1.1.1"), "port": .number(port)])
        }
        var raw: [String: NCJSONValue] = [
            "proxies": .array([node("A", 1e30), node("B", 1e30), node("C", .infinity), node("D", 443), node("E", 443)]),
            "proxy-groups": .array([.object([
                "name": .string("G"), "type": .string("select"),
                "proxies": .array([.string("A"), .string("B"), .number(1e30), .string("D"), .string("E")]),
            ])]),
        ]
        var r = NCSubRules()
        r.enabled = true
        r.dedupe = true
        let warnings = NCRuntimeSteps.applySubRules(&raw, r)
        XCTAssertEqual(warnings, [])
        let names = raw.list("proxies").compactMap { v -> String? in
            if case .object(let m) = v { return m.str("name") }
            return nil
        }
        XCTAssertEqual(names, ["A", "C", "D"]) // B dup of A, E dup of D
        guard case .object(let g)? = raw.list("proxy-groups").first else { return XCTFail("group missing") }
        XCTAssertEqual(g.strList("proxies"), ["A", "1e+30", "D"])
    }

    /// GroupSpecs (the group editor's view of the profile) merges node
    /// subscriptions with the runtime's own mergeNodeSubs: a second
    /// subscription with the same name is "<name>-2" there, as at runtime
    /// (bridge uniqueProviderName). The old private merge named it
    /// "<name> 2", so a `use:` saved from the editor never matched.
    func testGroupSpecsNodeSubNamesMatchRuntime() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("cfollow-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home.appendingPathComponent("nodesubs"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let subs = [NodeSubscription(id: "s1", name: "机场", url: "https://a.example/sub"),
                    NodeSubscription(id: "s2", name: "机场", url: "https://b.example/sub")]
        try JSONEncoder().encode(subs).write(to: home.appendingPathComponent("node-subscriptions.json"))
        let nodeYAML = """
        proxies:
          - name: b1
            type: ss
            server: 1.1.1.1
            port: 1
            cipher: aes-128-gcm
            password: x
        """
        for id in ["s1", "s2"] {
            try Data(nodeYAML.utf8).write(to: home.appendingPathComponent("nodesubs/\(id).yaml"))
        }
        let profile = home.appendingPathComponent("p.yaml")
        try Data("""
        proxies:
          - name: n1
            type: ss
            server: 2.2.2.2
            port: 2
            cipher: aes-128-gcm
            password: y
        proxy-groups:
          - name: PROXY
            type: select
            proxies:
              - n1
        """.utf8).write(to: profile)

        let res = NCGroupEditing.specs(home: home, profilePath: profile.path)
        XCTAssertEqual(res.providers, ["机场", "机场-2"])
        XCTAssertEqual(res.groups.first { $0.name == "PROXY" }?.use, ["机场", "机场-2"])

        let pool = NCGroupEditing.buildMemberPool(home: home, path: profile.path)
        XCTAssertEqual(pool.providers.keys.sorted(), ["机场", "机场-2"])

        // No proxy-groups at all: bridge mergeNodeSubs still adds the
        // providers (the private copy returned early).
        try Data("""
        proxies:
          - name: n1
            type: ss
            server: 2.2.2.2
            port: 2
            cipher: aes-128-gcm
            password: y
        """.utf8).write(to: profile)
        XCTAssertEqual(NCGroupEditing.specs(home: home, profilePath: profile.path).providers, ["机场", "机场-2"])
    }
}
