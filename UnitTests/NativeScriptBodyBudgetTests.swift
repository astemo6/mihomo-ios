import XCTest
@testable import Mihomo

/// NativeCore script body admission (NativeScriptBodyBudget): bodies start on their raw length and are charged by the
/// bytes the decoder actually produces. Injected availability that falls as bytes are charged (a decoded buffer is
/// malloc'd memory: it shows up in os_proc_available_memory at once). Written 2026-10-25; not run yet (the user asked
/// for no test runs until NativeCore reaches feature parity).
final class NativeScriptBodyBudgetTests: XCTestCase {
    static let KB: Int64 = 1 << 10
    static let MB: Int64 = 1 << 20

    /// availability = base − what the budget charged (− extra, e.g. another allocation)
    final class FakeAvail {
        var base: Int64
        var extra: Int64 = 0
        weak var budget: NativeScriptBodyBudget?
        init(_ base: Int64) { self.base = base }
        func read() -> Int64? { base - extra - (budget?.chargedBytes ?? 0) }
    }

    private func make(availMB: Double) -> (NativeScriptBodyBudget, FakeAvail) {
        let a = FakeAvail(Int64(availMB * 1_048_576))
        let b = NativeScriptBodyBudget(available: { a.read() })
        a.budget = b
        return (b, a)
    }

    /// Streams a body through a charge the way NativeBodyStore does: the raw bytes as they arrive (16 KB reads), the
    /// decoded bytes as the decoder emits them (64 KB scratch). Returns the decoded bytes accepted.
    private func stream(_ c: NativeBodyCharge, raw: Int64, decoded: Int64) -> (ok: Bool, decoded: Int64) {
        var r: Int64 = 0
        var d: Int64 = 0
        let ratio = Double(decoded) / Double(max(raw, 1))
        while r < raw {
            let n = min(16 * Self.KB, raw - r)
            guard c.grow(Int(n)) else { return (false, d) }
            r += n
            // the decoder catches up with the input
            let target = min(decoded, Int64(Double(r) * ratio))
            while d < target {
                let m = min(64 * Self.KB, target - d)
                guard c.grow(Int(m)) else { return (false, d) }
                d += m
            }
        }
        while d < decoded {
            let m = min(64 * Self.KB, decoded - d)
            guard c.grow(Int(m)) else { return (false, d) }
            d += m
        }
        return (true, d)
    }

    /// Device report 2026-10-25 07:32 (v0.19.26, old core): youtube.response skipped at 3.0 / 4.1 MB available with a
    /// 147 KB br body (estimated ×8 ≈ 1.2 MB → 256 KB tight budget → refused). NativeCore must run it.
    func testYouTube147KBBrotliRunsAt3To4MBAvailable() {
        let raw = 147 * Self.KB
        // YouTube's player / browse JSON compresses ~7–8× with br
        for decoded in [Int64(1_100) * Self.KB, Int64(1_180) * Self.KB] {
            for availMB in [3.0, 3.5, 4.0, 4.1] {
                let (b, _) = make(availMB: availMB)
                guard let c = b.admit(rawLength: raw, limit: b.config.hardMax) else {
                    return XCTFail("not admitted at \(availMB) MB")
                }
                let r = stream(c, raw: raw, decoded: decoded)
                XCTAssertTrue(r.ok, "stopped at \(r.decoded >> 10) KB of \(decoded >> 10) KB with \(availMB) MB: \(c.stopNote(rawReceived: raw))")
                XCTAssertNil(c.stop)
                XCTAssertEqual(c.chargedBytes, raw + decoded)
                c.release()
                XCTAssertEqual(b.chargedBytes, 0)
                XCTAssertEqual(b.openCharges, 0)
            }
        }
    }

    /// No ratio guess at admission: a br body is admitted on its raw length alone (the old core estimate refused it).
    func testAdmissionUsesRawLengthOnly() {
        let (b, _) = make(availMB: 3.0)
        XCTAssertTrue(b.roomToStart(rawLength: 147 * Self.KB))
        XCTAssertNotNil(b.admit(rawLength: 147 * Self.KB, limit: b.config.hardMax))
        // raw + slack does not fit above the reserve
        let (b2, _) = make(availMB: 1.8)
        XCTAssertNil(b2.admit(rawLength: 147 * Self.KB, limit: b2.config.hardMax))
        // raw longer than the script's max-size
        let (b3, _) = make(availMB: 20)
        XCTAssertNil(b3.admit(rawLength: 600 * Self.KB, limit: 512 * Self.KB))
    }

    /// The load stops only when the bytes really produced would cross the reserve.
    func testStopsAtReserveByActualBytes() {
        let (b, _) = make(availMB: 3.0)
        let c = b.admit(rawLength: 147 * Self.KB, limit: b.config.hardMax)!
        let r = stream(c, raw: 147 * Self.KB, decoded: 2 * Self.MB)
        XCTAssertFalse(r.ok)
        guard case .memory(let avail)? = c.stop else { return XCTFail("stop \(String(describing: c.stop))") }
        XCTAssertGreaterThanOrEqual(avail, b.config.reserve)
        // everything charged stayed above the reserve
        XCTAssertGreaterThanOrEqual(3 * Self.MB - c.chargedBytes, b.config.reserve)
        XCTAssertFalse(c.grow(1), "a stopped charge stays stopped")
        XCTAssertTrue(c.stopNote(rawReceived: 147 * Self.KB).contains("内存不足"))
        c.release()
        XCTAssertEqual(b.chargedBytes, 0)
    }

    /// The script's max-size caps the decoded bytes.
    func testMaxSizeLimit() {
        let (b, _) = make(availMB: 30)
        let c = b.admit(rawLength: 100 * Self.KB, limit: 512 * Self.KB)!
        let r = stream(c, raw: 100 * Self.KB, decoded: 800 * Self.KB)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(c.stop, .limit)
        XCTAssertLessThanOrEqual(c.chargedBytes, 512 * Self.KB)
    }

    /// Concurrent bodies share hardMax.
    func testSharedBudgetAcrossBodies() {
        var cfg = NativeScriptBodyBudget.Config()
        cfg.hardMax = 2 * Self.MB
        let b = NativeScriptBodyBudget(config: cfg, available: { nil })
        let c1 = b.admit(rawLength: 100 * Self.KB, limit: cfg.hardMax)!
        let c2 = b.admit(rawLength: 100 * Self.KB, limit: cfg.hardMax)!
        XCTAssertTrue(stream(c1, raw: 100 * Self.KB, decoded: 1_200 * Self.KB).ok)
        let r2 = stream(c2, raw: 100 * Self.KB, decoded: 1_200 * Self.KB)
        XCTAssertFalse(r2.ok)
        XCTAssertEqual(c2.stop, .shared)
        XCTAssertLessThanOrEqual(b.chargedBytes, cfg.hardMax)
        c1.release()
        c2.release()
        XCTAssertEqual(b.chargedBytes, 0)
        // released budget is usable again
        let c3 = b.admit(rawLength: 100 * Self.KB, limit: cfg.hardMax)!
        XCTAssertTrue(stream(c3, raw: 100 * Self.KB, decoded: 1_200 * Self.KB).ok)
    }

    /// A charge dropped without release (no store body took it) gives its bytes back.
    func testDeinitReleases() {
        let (b, _) = make(availMB: 30)
        do {
            let c = b.admit(rawLength: 10 * Self.KB, limit: b.config.hardMax)!
            XCTAssertTrue(c.grow(Int(500 * Self.KB)))
            XCTAssertEqual(b.chargedBytes, 500 * Self.KB)
        }
        XCTAssertEqual(b.chargedBytes, 0)
        XCTAssertEqual(b.openCharges, 0)
    }

    /// NativeCore's numbers (c): 1.5 MB reserve (the old core: 3 MB), 8 MB shared cap.
    func testNativeCoreDefaults() {
        let c = NativeScriptBodyBudget.Config()
        XCTAssertEqual(c.reserve, 1_536 * Self.KB)
        XCTAssertEqual(c.hardMax, 8 * Self.MB)
        XCTAssertEqual(c.admitSlack, 256 * Self.KB)
    }
}
