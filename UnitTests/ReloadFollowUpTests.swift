import XCTest
@testable import Mihomo

/// fix/xmly-memory-2 (device 2026-10-24 22:14: 「重载失败：重新加载超时」 while 喜马拉雅 kept the extension memory-critical):
/// after a reload reply times out the app asks the core for its reload state.
final class ReloadFollowUpTests: XCTestCase {
    private func st(_ json: String) -> VPNManager.ReloadStatus? { VPNManager.reloadStatus(Data(json.utf8)) }

    func testDecodesCoreJSON() {
        let s = st(#"{"running":false,"seq":3,"done":3,"kind":"full","lastError":"","lastMs":51234,"lastDoneAgoMs":120,"runningMs":0}"#)
        XCTAssertEqual(s, VPNManager.ReloadStatus(running: false, seq: 3, done: 3, lastError: ""))
        XCTAssertNil(VPNManager.reloadStatus(nil))
        XCTAssertNil(VPNManager.reloadStatus(Data("not json".utf8)))
    }

    func testFinishedLateIsSuccess() {
        // the reload took 51 s: finished after the 45 s reply timeout, applied fine
        let s = st(#"{"running":false,"seq":3,"done":3,"lastError":""}"#)
        XCTAssertEqual(VPNManager.reloadFollowUp(s, baselineDone: 2), .finished(nil))
        XCTAssertNil(VPNManager.reloadFollowUp(s, baselineDone: 2).message)
    }

    func testFinishedLateWithError() {
        let s = st(#"{"running":false,"seq":3,"done":3,"lastError":"yaml: line 3"}"#)
        XCTAssertEqual(VPNManager.reloadFollowUp(s, baselineDone: 2), .finished("yaml: line 3"))
    }

    func testStillRunningKeepsWaiting() {
        let s = st(#"{"running":true,"seq":3,"done":2,"lastError":""}"#)
        XCTAssertEqual(VPNManager.reloadFollowUp(s, baselineDone: 2), .running)
    }

    func testLostReloadIsUnknown() {
        // nothing finished since the baseline and nothing running: the request never reached the core
        let s = st(#"{"running":false,"seq":2,"done":2,"lastError":""}"#)
        XCTAssertEqual(VPNManager.reloadFollowUp(s, baselineDone: 2), .unknown)
        XCTAssertEqual(VPNManager.reloadFollowUp(nil, baselineDone: 2), .unknown)
    }

    func testNoBaselineCountsIdleAsFinished() {
        let s = st(#"{"running":false,"seq":5,"done":5,"lastError":""}"#)
        XCTAssertEqual(VPNManager.reloadFollowUp(s, baselineDone: nil), .finished(nil))
    }

    func testTimeoutMessageUnchanged() {
        XCTAssertEqual(VPNManager.reloadResult(nil, stillConnected: true), VPNManager.reloadTimeoutMessage)
    }
}
