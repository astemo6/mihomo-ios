import XCTest
@testable import Tern

/// merge-440 (UI test10_ProfileNodeEdit, baseline failure since the Swift port): renaming / deleting a profile node
/// must follow it into one-line flow-mapping groups (`- {name: Auto, type: url-test, proxies: [...]}`) and flow-mapping
/// proxies' `dialer-proxy`. The block-style renamer skipped those lines, so the edited profile kept the old member and
/// the validator refused the save ("proxy group[0]: Auto: '🇯🇵 Tokyo 02' not found").
final class NativeCoreFlowGroupRenameTests: XCTestCase {

    private let doc = """
    proxies:
      - {name: "🇯🇵 Tokyo 01", type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: p}
      - {name: "🇯🇵 Tokyo 02", type: ss, server: 192.0.2.2, port: 443, cipher: aes-128-gcm, password: p}
      - {name: Relay, type: ss, server: 192.0.2.3, port: 443, cipher: aes-128-gcm, password: p, dialer-proxy: "🇯🇵 Tokyo 02"}
    proxy-groups:
      - {name: Proxy, type: select, proxies: [Auto, "🇯🇵 Tokyo 01", "🇯🇵 Tokyo 02", DIRECT]}
      - {name: Auto, type: url-test, proxies: ["🇯🇵 Tokyo 01", "🇯🇵 Tokyo 02"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - name: Block
        type: select
        proxies:
          - "🇯🇵 Tokyo 02"
          - DIRECT
    rules:
      - MATCH,Proxy
    """

    func testRenameFollowsFlowMappingGroups() {
        let d = NCProfileYAML(text: doc)
        let st = d.renameRefs(oldName: "🇯🇵 Tokyo 02", newName: "Tokyo 02 Edited")
        XCTAssertEqual(Set(st.groups), ["Proxy", "Auto", "Block"])
        XCTAssertEqual(st.dialers, ["Relay"])
        let text = d.text()
        XCTAssertTrue(text.contains("- {name: Proxy, type: select, proxies: [Auto, \"🇯🇵 Tokyo 01\", Tokyo 02 Edited, DIRECT]}"), text)
        XCTAssertTrue(text.contains("- {name: Auto, type: url-test, proxies: [\"🇯🇵 Tokyo 01\", Tokyo 02 Edited], url: \"http://www.gstatic.com/generate_204\", interval: 600}"), text)
        XCTAssertTrue(text.contains("dialer-proxy: Tokyo 02 Edited}"), text)
        XCTAssertTrue(text.contains("- Tokyo 02 Edited"), text)
        // Only the node's own entry (renamed by upsertProxy, not renameRefs) still carries the old name.
        XCTAssertEqual(text.components(separatedBy: "\"🇯🇵 Tokyo 02\"").count, 2, text)
        XCTAssertNotNil(NCYAML.parse(text), "still valid YAML")
    }

    func testDeleteDropsFlowMappingMemberAndDialer() {
        let d = NCProfileYAML(text: doc)
        let st = d.renameRefs(oldName: "🇯🇵 Tokyo 02", newName: "")
        XCTAssertEqual(Set(st.groups), ["Proxy", "Auto", "Block"])
        let text = d.text()
        XCTAssertTrue(text.contains("proxies: [Auto, \"🇯🇵 Tokyo 01\", DIRECT]}"), text)
        XCTAssertTrue(text.contains("proxies: [\"🇯🇵 Tokyo 01\"], url:"), text)
        XCTAssertFalse(text.contains("dialer-proxy"), text)
        XCTAssertNotNil(NCYAML.parse(text))
    }

    func testUnrelatedFlowLinesKeptVerbatim() {
        let d = NCProfileYAML(text: doc)
        _ = d.renameRefs(oldName: "Nope", newName: "X")
        XCTAssertEqual(d.text(), NCProfileYAML(text: doc).text())
        XCTAssertNil(NCProfileYAML.renameInFlowMapping("  - {name: A, proxies: [B, C]}  # c", oldName: "Z", newName: "Y"))
        XCTAssertEqual(NCProfileYAML.renameInFlowMapping("  - {name: A, proxies: [B, C]}  # c", oldName: "B", newName: "Node Y")?.line,
                       "  - {name: A, proxies: [Node Y, C]}  # c")
        // A name that YAML 1.1 reads as a bool (y / Y / on …) is quoted, as the reference YAML library writes it.
        XCTAssertEqual(NCProfileYAML.renameInFlowMapping("  - {name: A, proxies: [B, C]}", oldName: "B", newName: "Y")?.line,
                       "  - {name: A, proxies: [\"Y\", C]}")
    }
}
