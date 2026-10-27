import XCTest
@testable import Tern

// Coverage for PR #119 (fix/nc-app-ui), items 3+4: NCYAML.parseWithError
// reports the 1-based line of the problems the lenient parser can localize
// (unclosed flow collections, unterminated quotes), and NCProfileYAML's
// group member handling became quote/depth-aware so flow-style member
// names containing commas survive parsing and renames.
final class NativeCoreYAMLErrorTests: XCTestCase {

    func testUnclosedFlowSequenceReportsItsLine() {
        let text = """
        mixed-port: 7890
        proxies: [A, B
        rules:
          - MATCH,DIRECT
        """
        let (value, error) = NCYAML.parseWithError(text)
        XCTAssertNotNil(value) // lenient: a value still comes back
        XCTAssertEqual(error?.line, 2)
        XCTAssertEqual(error?.message, "流式序列未闭合")
    }

    func testUnclosedFlowMappingReportsItsLine() {
        let text = """
        proxies:
          - {name: A, type: ss, server: 1.2.3.4
          - {name: B, type: ss, server: 5.6.7.8}
        """
        let (_, error) = NCYAML.parseWithError(text)
        XCTAssertEqual(error?.line, 2)
        XCTAssertEqual(error?.message, "流式映射未闭合")
    }

    func testUnterminatedQuoteInFlowReportsItsLine() {
        let text = """
        mixed-port: 7890
        proxy-groups: [{name: "G}]
        """
        let (_, error) = NCYAML.parseWithError(text)
        XCTAssertEqual(error?.line, 2)
        XCTAssertEqual(error?.message, "引号未闭合")
    }

    func testWellFormedDocumentHasNoError() {
        let text = """
        mixed-port: 7890
        proxies:
          - {name: A, type: ss, server: 1.2.3.4, port: 8388}
        proxy-groups:
          - name: G
            type: select
            proxies: [A, DIRECT]
        rules:
          - MATCH,G
        """
        let (value, error) = NCYAML.parseWithError(text)
        XCTAssertNil(error)
        XCTAssertNotNil(value)
        // parse() and parseWithError agree on the value.
        XCTAssertEqual(NCYAML.parse(text), value)
    }

    /// Only the FIRST localizable problem is reported.
    func testFirstErrorWins() {
        let text = """
        a: [1, 2
        b: {x: 1
        """
        let (_, error) = NCYAML.parseWithError(text)
        XCTAssertEqual(error?.line, 1)
    }
}

final class NativeCoreProfileCommaGroupTests: XCTestCase {
    private let doc = """
    proxies:
      - name: A,B
        type: ss
        server: 1.2.3.4
        port: 8388
      - name: C
        type: ss
        server: 5.6.7.8
        port: 8388
    proxy-groups:
      - name: G
        type: select
        proxies: ["A,B", C, 'D,E']
    rules:
      - MATCH,G
    """

    /// Flow members whose names contain commas (quoted) parse as single
    /// members — the old naive comma split produced five broken names here.
    func testFlowMembersWithCommasParseIntact() {
        let groups = NCProfileYAML(text: doc).listGroups()
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups.first?.name, "G")
        XCTAssertEqual(groups.first?.proxies, ["A,B", "C", "D,E"])
        XCTAssertEqual(groups.first?.isProxiesFlowStyle, true)
    }

    /// Renaming a comma-named member writes it back quoted, leaves the
    /// other members' raw text (including their quote style) untouched,
    /// and the result re-parses to exactly the renamed member list.
    /// formatYAMLString mirrors yaml.v3: "X,Y" is printable and resolves
    /// to !!str, plain is not allowed in flow (comma), so it is emitted
    /// single-quoted ('X,Y'), not double-quoted.
    func testRenameCommaMemberRoundTrips() {
        let doc = NCProfileYAML(text: self.doc)
        let stats = doc.renameRefs(oldName: "A,B", newName: "X,Y")
        XCTAssertEqual(stats.groups, ["G"])
        let text = doc.text()
        XCTAssertTrue(text.contains("proxies: ['X,Y', C, 'D,E']"), text)
        XCTAssertTrue(text.contains("'D,E'"), text) // untouched member kept verbatim
        let reparsed = NCProfileYAML(text: text).listGroups()
        XCTAssertEqual(reparsed.first?.proxies, ["X,Y", "C", "D,E"])
    }

    /// Renaming a plain member must not disturb the comma-named ones.
    func testRenamePlainMemberKeepsCommaMembers() {
        let doc = NCProfileYAML(text: self.doc)
        _ = doc.renameRefs(oldName: "C", newName: "Z")
        let reparsed = NCProfileYAML(text: doc.text()).listGroups()
        XCTAssertEqual(reparsed.first?.proxies, ["A,B", "Z", "D,E"])
    }

    /// A group whose own name carries a comma (block style, quoted) is
    /// read back whole.
    func testGroupNameWithComma() {
        let text = """
        proxy-groups:
          - name: "G,1"
            type: select
            proxies: [DIRECT]
        """
        let groups = NCProfileYAML(text: text).listGroups()
        XCTAssertEqual(groups.first?.name, "G,1")
        XCTAssertEqual(groups.first?.proxies, ["DIRECT"])
    }
}
