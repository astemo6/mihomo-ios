import XCTest
@testable import Tern

/// fix/update-end-notice: an App update that replaces the extension binary can end the
/// tunnel without stopTunnel; the alive marker's build stamp tells that end apart from a
/// genuinely abnormal one (crash / jetsam / power off), so the restart is not announced
/// or recorded as 异常退出.
final class TunnelStopReasonUpdateTests: XCTestCase {
    private let iso = ISO8601DateFormatter()

    func testParseStampedMarker() {
        let s = "\(iso.string(from: Date(timeIntervalSince1970: 1_700_000_000)))\t551"
        let p = TunnelStopReason.parseAlive(s)
        XCTAssertEqual(p?.build, "551")
        XCTAssertEqual(p?.date.timeIntervalSince1970 ?? 0, 1_700_000_000, accuracy: 1)
    }

    func testParseLegacyMarkerHasNoBuild() {
        let s = iso.string(from: Date(timeIntervalSince1970: 1_700_000_000))
        let p = TunnelStopReason.parseAlive(s)
        XCTAssertNotNil(p?.date)
        XCTAssertNil(p?.build)
    }

    func testParseGarbage() {
        XCTAssertNil(TunnelStopReason.parseAlive("not a marker"))
        XCTAssertNil(TunnelStopReason.parseAlive(""))
    }

    func testUpdateEndClassification() {
        XCTAssertTrue(TunnelStopReason.isUpdateEnd(markerBuild: "550", currentBuild: "551"))
        XCTAssertFalse(TunnelStopReason.isUpdateEnd(markerBuild: "551", currentBuild: "551"))
        XCTAssertFalse(TunnelStopReason.isUpdateEnd(markerBuild: nil, currentBuild: "551")) // legacy marker
        XCTAssertFalse(TunnelStopReason.isUpdateEnd(markerBuild: "?", currentBuild: "551"))
        XCTAssertFalse(TunnelStopReason.isUpdateEnd(markerBuild: "", currentBuild: "551"))
    }

    func testAppUpdateReasonWording() {
        XCTAssertEqual(TunnelStopReason.appUpdate, 16) // NEProviderStopReason.appUpdate
        XCTAssertTrue(TunnelStopReason.describe(TunnelStopReason.appUpdate).contains("更新"))
    }
}
