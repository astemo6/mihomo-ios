import XCTest
import Combine
@testable import Mihomo

/// fix/home-pull-jank (v0.19.21 「首页下拉卡顿的问题在这个版本中又出现了」): the pinned 首页 header's scroll state must
/// not publish on every scroll frame. Ordinary scrolling publishes nothing but the one `scrolled` flip; only a
/// pull past the rest position moves the overscroll value, and a header height change does not feed back.
final class PinnedHeaderScrollTests: XCTestCase {
    private var bag = Set<AnyCancellable>()

    private func counting(_ t: PinnedHeaderScrollTracker) -> (flag: () -> Int, offset: () -> Int) {
        var f = 0, o = 0
        t.scrolled.objectWillChange.sink { f += 1 }.store(in: &bag)
        t.overscroll.objectWillChange.sink { o += 1 }.store(in: &bag)
        return ({ f }, { o })
    }

    func testOrdinaryScrollPublishesOnlyTheScrolledFlip() {
        let t = PinnedHeaderScrollTracker(pixel: 1)
        t.headerMoved(to: 150)
        t.probeMoved(to: 150) // at rest
        let n = counting(t)
        // Scroll up through 600 points, one frame per point, and back down to rest.
        for y in stride(from: 150.0, through: -450.0, by: -1) { t.probeMoved(to: CGFloat(y)) }
        for y in stride(from: -450.0, through: 150.0, by: 1) { t.probeMoved(to: CGFloat(y)) }
        XCTAssertEqual(n.flag(), 2, "scrolled flips once going up and once coming back")
        XCTAssertEqual(n.offset(), 0, "no overscroll publish during an ordinary scroll")
        XCTAssertFalse(t.scrolled.value)
        XCTAssertEqual(t.overscroll.value, 0)
    }

    func testPullRidesDownAndSettles() {
        let t = PinnedHeaderScrollTracker(pixel: 1)
        t.headerMoved(to: 150)
        t.probeMoved(to: 150)
        let n = counting(t)
        for y in stride(from: 150.0, through: 230.0, by: 0.25) { t.probeMoved(to: CGFloat(y)) } // sub-pixel frames
        XCTAssertEqual(t.overscroll.value, 80)
        XCTAssertLessThanOrEqual(n.offset(), 81, "at most one publish per whole pixel of pull")
        XCTAssertEqual(n.flag(), 0)
        for y in stride(from: 230.0, through: 150.0, by: -1) { t.probeMoved(to: CGFloat(y)) }
        XCTAssertEqual(t.overscroll.value, 0)
    }

    func testHeaderMeasurementDoesNotFeedBack() {
        let t = PinnedHeaderScrollTracker(pixel: 1)
        t.headerMoved(to: 150)
        t.probeMoved(to: 190)
        XCTAssertEqual(t.overscroll.value, 40)
        let n = counting(t)
        // The same layout bottom reported again (sub-point jitter) changes nothing.
        t.headerMoved(to: 150.2)
        t.headerMoved(to: 149.8)
        XCTAssertEqual(n.offset(), 0)
        XCTAssertEqual(t.headerBottom, 150)
        // A real height change (exit IP line, Dynamic Type) moves the rest position once.
        t.headerMoved(to: 170)
        XCTAssertEqual(t.overscroll.value, 20)
        XCTAssertEqual(n.offset(), 1)
    }

    func testUnknownGeometryShowsRest() {
        let t = PinnedHeaderScrollTracker(pixel: 1)
        t.probeMoved(to: 300)
        XCTAssertEqual(t.overscroll.value, 0)
        XCTAssertFalse(t.scrolled.value)
    }
}
