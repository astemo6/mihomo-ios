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

    // P0-2: the last minute the tunnel recorded becomes the chart on return; the normal cadence continues from it.
    func testSeedFromTunnelThenAppend() {
        var s = SpeedSeries()
        let last = t0.addingTimeInterval(9)
        s.seed(up: (1...10).map { Int64($0) }, down: Array(repeating: 5, count: 10), lastAt: last)
        XCTAssertEqual(s.up.count, SpeedSeries.capacity)
        XCTAssertEqual(s.up.suffix(10), ArraySlice((1...10).map { Int64($0) }))
        XCTAssertEqual(s.up.dropLast(10).filter { $0 != 0 }.count, 0, "padded with the empty baseline")
        XCTAssertEqual(s.lastAt, last)
        let next = last.addingTimeInterval(1)
        XCTAssertEqual(s.append(up: 11, down: 5, requestedAt: next, receivedAt: next), .appended)
        XCTAssertEqual(s.up.last, 11)
    }

    // P0-2: GET /app/stats as the tunnel writes it.
    func testTunnelStatsDecodes() throws {
        let json = #"""
        {"session":1700000000000,"since":1700000000000,"version":7,"totalConnections":3,"ruleCount":2,"hostCount":2,"closedSeq":1,"full":true,
        "policies":[{"name":"Proxy","up":500,"down":5000}],
        "rules":[{"rule":"DomainSuffix(example.com)","policy":"Proxy","hits":1}],
        "hosts":[{"name":"a.example.com","up":500,"down":5000}],
        "closed":[{"seq":1,"id":"6f1c","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"",
        "sourcePort":"51000","destinationPort":"443","host":"a.example.com","sniffHost":"","process":"","remoteDestination":""},
        "upload":500,"download":5000,"start":"2023-11-14T22:13:20Z","chains":["HK 01","Proxy"],"rule":"DomainSuffix",
        "rulePayload":"example.com","closedAt":1700000002000}]}
        """#
        let s = try JSONDecoder().decode(TunnelStats.self, from: Data(json.utf8))
        XCTAssertEqual(s.totalConnections, 3)
        XCTAssertEqual(s.closed.count, 1)
        let c = s.closed[0].item
        XCTAssertEqual(c.id, "6f1c")
        XCTAssertEqual(c.chains?.last, "Proxy")
        XCTAssertEqual(c.ruleText, "DomainSuffix(example.com)")
        XCTAssertEqual(c.closedAt, Date(timeIntervalSince1970: 1_700_000_002))
        XCTAssertNotNil(c.startDate)
        let speed = #"{"at":1700000002,"seconds":[[1700000001,1,2,3,4],[1700000002,5,6,7,8]],"minutes":[[1699999980,6,8,10,12,2]],"hours":[]}"#
        let h = try JSONDecoder().decode(TunnelSpeedHistory.self, from: Data(speed.utf8))
        XCTAssertEqual(h.seconds.count, 2)
        XCTAssertEqual(h.minutes.first?.last, 2)
    }
}
