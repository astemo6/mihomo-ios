import XCTest
@testable import Mihomo

// fix/bg-chart + feat/traffic-scope: Home speed series and the scoped traffic numbers.
final class SpeedSeriesTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    func testAppendsOncePerSecondAndKeepsCapacity() {
        var s = SpeedSeries()
        for i in 0..<100 {
            let at = t0.addingTimeInterval(Double(i))
            XCTAssertEqual(s.append(up: Int64(i), down: Int64(i * 2), requestedAt: at.addingTimeInterval(-0.05), receivedAt: at), .appended)
        }
        XCTAssertEqual(s.up.count, SpeedSeries.capacity)
        XCTAssertEqual(s.up.last, 99)
        XCTAssertEqual(s.down.last, 198)
        XCTAssertEqual(s.up.first, 40)
    }

    func testGapAfterBackgroundRestartsInsteadOfReplaying() {
        var s = SpeedSeries()
        for i in 0..<10 {
            let at = t0.addingTimeInterval(Double(i))
            s.append(up: 1_000, down: 5_000, requestedAt: at, receivedAt: at)
        }
        // 40 s in the background, then the first answer after returning.
        let back = t0.addingTimeInterval(50)
        XCTAssertEqual(s.append(up: 7, down: 9, requestedAt: back, receivedAt: back), .restarted)
        XCTAssertEqual(s.up.count, SpeedSeries.capacity)
        XCTAssertEqual(s.up.dropLast().filter { $0 != 0 }.count, 0, "old samples are not kept after a gap")
        XCTAssertEqual(s.up.last, 7)
        XCTAssertEqual(s.down.last, 9)
        // Normal 1 s cadence afterwards.
        XCTAssertEqual(s.append(up: 8, down: 10, requestedAt: back.addingTimeInterval(1), receivedAt: back.addingTimeInterval(1)), .appended)
    }

    func testLateAndOutOfOrderSamplesAreDropped() {
        var s = SpeedSeries()
        s.append(up: 1, down: 1, requestedAt: t0, receivedAt: t0)
        let before = s
        // Asked before suspension, answered 20 s later: stale.
        XCTAssertEqual(s.append(up: 99, down: 99, requestedAt: t0.addingTimeInterval(1), receivedAt: t0.addingTimeInterval(21)), .dropped)
        XCTAssertEqual(s.up, before.up)
        XCTAssertEqual(s.lastAt, before.lastAt)
        // r7 R7A-8: the stale answer only marks a heartbeat at its request time; 20 s later is still a gap.
        var bg = s
        XCTAssertEqual(bg.append(up: 3, down: 3, requestedAt: t0.addingTimeInterval(22), receivedAt: t0.addingTimeInterval(22.1)), .restarted)
        // Older than the newest sample.
        XCTAssertEqual(s.append(up: 50, down: 50, requestedAt: t0.addingTimeInterval(-1), receivedAt: t0.addingTimeInterval(-0.5)), .dropped)
        XCTAssertEqual(s.up, before.up)
        XCTAssertEqual(s.lastAt, before.lastAt)
    }

    /// r7 R7A-8: slow answers (3 s each) in a row keep the chart instead of wiping it every time.
    func testSlowAnswersDoNotRestart() {
        var s = SpeedSeries()
        for i in 0..<10 {
            let at = t0.addingTimeInterval(Double(i))
            s.append(up: 1_000, down: 1_000, requestedAt: at, receivedAt: at)
        }
        var t = t0.addingTimeInterval(9)
        for _ in 0..<3 { // ask 1 s after the last answer, answered 3 s later → dropped
            let ask = t.addingTimeInterval(1)
            XCTAssertEqual(s.append(up: 5, down: 5, requestedAt: ask, receivedAt: ask.addingTimeInterval(3)), .dropped)
            t = ask.addingTimeInterval(3)
        }
        let ask = t.addingTimeInterval(1)
        XCTAssertEqual(s.append(up: 2_000, down: 2_000, requestedAt: ask, receivedAt: ask.addingTimeInterval(0.1)), .appended)
        XCTAssertEqual(s.up.filter { $0 == 1_000 }.count, 10, "the earlier samples are kept")
    }

    func testScopedNumbers() {
        let t = AppTraffic(up: 100, down: 200, upTotal: 1_000, downTotal: 2_000, proxyUp: 10, proxyDown: 20, proxyUpTotal: 300, proxyDownTotal: 600)
        XCTAssertEqual(t.speed(.all).down, 200)
        XCTAssertEqual(t.speed(.proxy).down, 20)
        XCTAssertEqual(t.totals(.all).up, 1_000)
        XCTAssertEqual(t.totals(.proxy).up, 300)
    }

    func testLiveStatsParsesOldAndNewFormats() {
        let old = LiveStats(status: "1\t2\t3\t4\tNode A")
        XCTAssertEqual(old.node, "Node A")
        XCTAssertNil(old.proxyUp)
        XCTAssertEqual(old.speed(.all).up, 1)
        XCTAssertEqual(old.speed(.proxy).up, 0, "no proxy numbers from an older tunnel: show 0, never the all-traffic value")
        let new = LiveStats(status: "1\t2\t3\t4\tNode A\t5\t6\t7\t8")
        XCTAssertEqual(new.node, "Node A")
        XCTAssertEqual(new.speed(.proxy).up, 5)
        XCTAssertEqual(new.speed(.proxy).down, 6)
        XCTAssertEqual(new.proxyTotalDown, 8)
        // A sample stored by an older build (no proxy keys) still decodes.
        let data = Data(#"{"up":1,"down":2,"totalUp":3,"totalDown":4,"node":"n","time":0}"#.utf8)
        XCTAssertNoThrow(try JSONDecoder().decode(LiveStats.self, from: data))
    }
}
