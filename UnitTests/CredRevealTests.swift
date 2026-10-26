import XCTest
@testable import Tern

/// hotfix/node-cred-reveal: credential lookup by summary key and the 添加到本地节点 name.
final class CredRevealTests: XCTestCase {
    func testCredentialValuePaths() {
        let node: [String: Any] = [
            "name": "n", "uuid": "u-1", "port": NSNumber(value: 443), "password": "",
            "reality-opts": ["public-key": "PK", "short-id": "ab12"],
            "peers": [["public-key": "P0"], ["public-key": "P1", "pre-shared-key": "S1"]],
        ]
        XCTAssertEqual(NodeManagerModel.credentialValue(node, path: "uuid"), "u-1")
        XCTAssertEqual(NodeManagerModel.credentialValue(node, path: "port"), "443")
        XCTAssertNil(NodeManagerModel.credentialValue(node, path: "password"), "empty is not a value")
        XCTAssertEqual(NodeManagerModel.credentialValue(node, path: "reality-opts.public-key"), "PK")
        XCTAssertEqual(NodeManagerModel.credentialValue(node, path: "reality-opts.short-id"), "ab12")
        XCTAssertEqual(NodeManagerModel.credentialValue(node, path: "peers.1.pre-shared-key"), "S1")
        XCTAssertNil(NodeManagerModel.credentialValue(node, path: "peers.5.public-key"))
        XCTAssertNil(NodeManagerModel.credentialValue(node, path: "missing"))
    }

    func testLocalCopyName() {
        XCTAssertEqual(NodeManagerModel.localCopyName("A", taken: []), "A")
        let c1 = NodeManagerModel.localCopyName("A", taken: ["A"])
        XCTAssertNotEqual(c1, "A")
        XCTAssertTrue(c1.hasPrefix("A "))
        let c2 = NodeManagerModel.localCopyName("A", taken: ["A", c1])
        XCTAssertNotEqual(c2, c1)
        XCTAssertTrue(c2.hasSuffix("2"))
    }
}
