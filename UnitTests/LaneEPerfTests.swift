import XCTest
import Darwin
@testable import Mihomo

/// E 线 (tunnel performance): utun framing with sendmsg (#2) and the off-main load of the 连接分析
/// history (#3).
final class LaneEPerfTests: XCTestCase {
    // MARK: - #2 PacketFraming

    private func socketPair() throws -> (Int32, Int32) {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        for fd in fds { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) }
        return (fds[0], fds[1])
    }

    private func receive(_ fd: Int32) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: 70_000)
        let n = buf.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        return n < 0 ? nil : Array(buf[0..<n])
    }

    func testFramedSendIsOneDatagramWithBigEndianFamily() throws {
        let (a, b) = try socketPair()
        defer { close(a); close(b) }
        let v4 = Data([0x45, 0x00, 0x00, 0x14] + [UInt8](repeating: 7, count: 16))
        let v6 = Data([0x60] + (1...1399).map { UInt8($0 & 0xff) })
        XCTAssertEqual(PacketFraming.send(fd: a, family: AF_INET, packet: v4), 4 + v4.count)
        XCTAssertEqual(PacketFraming.send(fd: a, family: AF_INET6, packet: v6), 4 + v6.count)
        // A slice (non-zero start index) is sent from its own bytes.
        let slice = v6[100..<300]
        XCTAssertEqual(PacketFraming.send(fd: a, family: AF_INET6, packet: slice), 4 + slice.count)

        let f4 = UInt32(bitPattern: AF_INET).bigEndian, f6 = UInt32(bitPattern: AF_INET6).bigEndian
        let h4 = withUnsafeBytes(of: f4) { Array($0) }, h6 = withUnsafeBytes(of: f6) { Array($0) }
        XCTAssertEqual(receive(b), h4 + [UInt8](v4))
        XCTAssertEqual(receive(b), h6 + [UInt8](v6))
        XCTAssertEqual(receive(b), h6 + [UInt8](slice))
        XCTAssertNil(receive(b), "exactly one datagram per send")
        XCTAssertEqual(PacketFraming.framedSize(v4), 4 + v4.count)
    }

    func testFramedSendEmptyPacketAndFamilyGuess() throws {
        let (a, b) = try socketPair()
        defer { close(a); close(b) }
        XCTAssertEqual(PacketFraming.send(fd: a, family: AF_INET, packet: Data()), 4)
        XCTAssertEqual(receive(b)?.count, 4)
        XCTAssertEqual(PacketFraming.family(of: Data([0x45])), AF_INET)
        XCTAssertEqual(PacketFraming.family(of: Data([0x60])), AF_INET6)
        XCTAssertEqual(PacketFraming.family(of: Data()), AF_INET)
    }

    func testFramedSendReportsBackPressure() throws {
        let (a, b) = try socketPair()
        defer { close(a); close(b) }
        let packet = Data(repeating: 1, count: 1400)
        var sent = 0
        var last = 0
        while sent < 100_000 {
            last = PacketFraming.send(fd: a, family: AF_INET, packet: packet)
            if last < 0 { break }
            XCTAssertEqual(last, 1404)
            sent += 1
        }
        let e = errno
        XCTAssertEqual(last, -1, "a full socket buffer must fail the send instead of blocking")
        XCTAssertTrue([EAGAIN, EWOULDBLOCK, ENOBUFS].contains(e), "errno \(e)")
        XCTAssertGreaterThan(sent, 0)
    }

    // MARK: - #3 AnalyticsHistory loads off the main thread

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("analytics-\(UUID().uuidString).json")
    }

    @MainActor
    private func waitLoaded(_ h: AnalyticsHistory) async throws {
        let deadline = Date().addingTimeInterval(5)
        while !h.isLoaded {
            if Date() > deadline { XCTFail("history never loaded"); return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    @MainActor
    func testHistoryLoadsOffMainAndKeepsEarlyDeltas() async throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let today = TrafficHistory.dayFormatter.string(from: Date())
        var stored = AnalyticsHistory.Day(day: today)
        stored.direct = .init(up: 10, down: 20)
        stored.policies["DIRECT"] = .init(up: 10, down: 20)
        stored.hosts["a.com"] = .init(up: 1, down: 2)
        let old = AnalyticsHistory.Day(day: "2000-01-01", proxy: .init(up: 5, down: 5))
        try JSONEncoder().encode([old, stored]).write(to: url)

        let h = AnalyticsHistory(fileURL: url)
        // init returned without reading the file on this (main) thread: the load lands on a later turn.
        XCTAssertFalse(h.isLoaded)
        XCTAssertTrue(h.days.isEmpty)
        // A delta counted before the load finishes is kept and added to the stored day.
        h.add(policies: ["DIRECT": .init(up: 1, down: 1)], hosts: ["a.com": .init(up: 1, down: 1), "b.com": .init(up: 3, down: 3)])
        try await waitLoaded(h)
        XCTAssertEqual(h.days.map(\.day), ["2000-01-01", today])
        let d = try XCTUnwrap(h.days.last)
        XCTAssertEqual(d.direct, .init(up: 11, down: 21))
        XCTAssertEqual(d.policies["DIRECT"], .init(up: 11, down: 21))
        XCTAssertEqual(d.hosts["a.com"], .init(up: 2, down: 3))
        XCTAssertEqual(d.hosts["b.com"], .init(up: 3, down: 3))
        h.save(force: true)
        let back = try XCTUnwrap(AnalyticsHistory.read(url))
        XCTAssertEqual(back.map(\.day), ["2000-01-01", today])
        XCTAssertEqual(back.last?.direct, .init(up: 11, down: 21))
    }

    @MainActor
    func testClearBeforeLoadWins() async throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try JSONEncoder().encode([AnalyticsHistory.Day(day: "2000-01-01", proxy: .init(up: 5, down: 5))]).write(to: url)
        let h = AnalyticsHistory(fileURL: url)
        h.clear()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertTrue(h.days.isEmpty, "a load still in flight brought the cleared history back")
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    @MainActor
    func testMissingFileLoadsEmpty() async throws {
        let h = AnalyticsHistory(fileURL: tempURL())
        try await waitLoaded(h)
        XCTAssertTrue(h.days.isEmpty)
    }

    func testMergeKeepsNewestDays() {
        let stored = (1...5).map { AnalyticsHistory.Day(day: String(format: "2026-01-%02d", $0)) }
        let live = [AnalyticsHistory.Day(day: "2026-01-06")]
        let m = AnalyticsHistory.merge(stored: stored, live: live, keep: 3)
        XCTAssertEqual(m.map(\.day), ["2026-01-04", "2026-01-05", "2026-01-06"])
        XCTAssertEqual(AnalyticsHistory.merge(stored: stored, live: [], keep: 3).count, 5, "nothing to merge: stored as is")
    }
}
