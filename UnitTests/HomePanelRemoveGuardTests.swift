import XCTest
@testable import Tern

/// fix/home-panel-remove-guard (device 2026-10-29, screen recording): long-press a Home panel →
/// 从首页移除 did nothing, repeatedly. The menu's remove was gated on "no drag session, and no drag
/// activity for 1 s" — but the context menu's own long press starts a drag session (onDrag →
/// beginDrag), and every session transition stamped drag activity, so a natural-speed tap always
/// landed inside the poisoned window and was silently swallowed (not even the confirmation came up).
/// The guard now keys on MOVEMENT: only a drag that actually travelled blocks the remove.
@MainActor
final class HomePanelRemoveGuardTests: XCTestCase {
    private func allowed(dragging: Bool, moved: Bool, since: TimeInterval) -> Bool {
        HomePanelStore.removeAllowed(dragging: dragging, dragMoved: moved, secondsSinceDragActivity: since)
    }

    func testStationaryLongPressNeverBlocks() {
        // The device case: a drag session is "in flight" (armed by the long press) but never moved,
        // and the tap comes immediately.
        XCTAssertTrue(allowed(dragging: true, moved: false, since: 0.0))
        XCTAssertTrue(allowed(dragging: true, moved: false, since: 0.1))
        XCTAssertTrue(allowed(dragging: false, moved: false, since: 5.0))
    }

    func testMovedDragBlocksInFlightAndBrieflyAfter() {
        XCTAssertFalse(allowed(dragging: true, moved: true, since: 0.1), "moved drag in flight")
        XCTAssertFalse(allowed(dragging: false, moved: true, since: 0.5), "just ended over the menu")
        XCTAssertFalse(allowed(dragging: false, moved: false, since: 0.5),
                       "right after a moved drag committed (its stamp still guards)")
        XCTAssertTrue(allowed(dragging: false, moved: true, since: 1.5), "window over")
    }
}
