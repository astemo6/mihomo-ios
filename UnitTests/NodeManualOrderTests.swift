import XCTest
@testable import Tern

/// feat/long-press-reorder (user 2026-10-29): the node list's manual order — a drag inside one source
/// section splices that section's new order into the full id list at the slots the section holds, and
/// ManualOrder.apply (the slot rule every manual order in the app uses) re-applies it after a
/// subscription refresh rebuilds the nodes in source order.
final class NodeManualOrderTests: XCTestCase {
    func testSplicedKeepsOtherSectionsInTheirSlots() {
        let all = ["a1", "a2", "b1", "b2", "c1"]
        XCTAssertEqual(NodeManualOrder.spliced(all: all, sectionNew: ["b2", "b1"]),
                       ["a1", "a2", "b2", "b1", "c1"])
        XCTAssertEqual(NodeManualOrder.spliced(all: all, sectionNew: ["a2", "a1"]),
                       ["a2", "a1", "b1", "b2", "c1"])
        // A section shown in its current order changes nothing.
        XCTAssertEqual(NodeManualOrder.spliced(all: all, sectionNew: ["b1", "b2"]), all)
    }

    func testApplyAfterRefreshKeepsOrderAndNewNodeSlots() {
        // A refresh rebuilds the source's nodes in source order; one node is new since the order was saved.
        let rebuilt = ["n1", "new", "n2", "n3"]
        let applied = ManualOrder.apply(rebuilt, order: ["n3", "n1", "n2"]) { $0 }
        XCTAssertEqual(applied, ["n3", "new", "n1", "n2"])
        // A deleted node's id in the saved order is simply ignored.
        let afterDelete = ManualOrder.apply(["n1", "n2"], order: ["n3", "n2", "n1"]) { $0 }
        XCTAssertEqual(afterDelete, ["n2", "n1"])
    }

    func testSpliceThenApplyRoundTrips() {
        // Drag section B, persist the spliced ids, rebuild in source order, re-apply: the drag survives.
        let display = ["a1", "a2", "b1", "b2"]
        let saved = NodeManualOrder.spliced(all: display, sectionNew: ["b2", "b1"])
        let rebuilt = ["a1", "a2", "b1", "b2"]
        XCTAssertEqual(ManualOrder.apply(rebuilt, order: saved) { $0 }, ["a1", "a2", "b2", "b1"])
    }
}
