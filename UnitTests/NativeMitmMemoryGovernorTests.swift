import XCTest
@testable import Mihomo

/// feat/s3-mem: NativeMemoryGovernor driven with injected memory readings and a fake old side (deterministic: no
/// real os_proc_available_memory, no old runtime, a manual clock).
final class NativeMitmMemoryGovernorTests: XCTestCase {
    static let MB = 1 << 20

    final class FakeMemory: NativeMemorySampling {
        var footprint: UInt64 = 30 << 20
        var available = 20 << 20
        func sample() -> NativeMemorySample { NativeMemorySample(footprint: footprint, available: available) }
        func set(availMB: Double, fpMB: Double = 30) {
            available = Int(availMB * 1_048_576)
            footprint = UInt64(fpMB * 1_048_576)
        }
    }

    final class FakeControl: RuntimeMemoryControlling {
        var active = false
        var configured: Int64 = 26 << 20
        var nonGarbage: Int64 = 12 << 20
        var limit: Int64 = 26 << 20
        var loan = false
        var limitCalls: [Int64] = []
        var freeOS = 0
        var sheds: [(level: Int, flags: MemoryShedFlags, reason: String)] = []
        var connShed: [Int] = []
        /// what a FreeOSMemory gives back (applied to `memory`)
        var freeOSGives = 0
        weak var memory: FakeMemory?

        func setActive(_ on: Bool) { active = on }
        func info() -> RuntimeMemoryInfo? {
            RuntimeMemoryInfo(heap: 10 << 20, nonGarbage: nonGarbage, floor: max(16 << 20, nonGarbage + 2 << 20), limit: limit,
                         configured: configured, numGC: 1, tasks: 100, loan: loan)
        }
        func setLimit(_ bytes: Int64) -> Int64 {
            limitCalls.append(bytes)
            // = the retired bridge
            var want = bytes <= 0 ? configured : min(bytes, configured)
            let floor = max(16 << 20, nonGarbage + 2 << 20)
            if want < floor { want = min(floor, configured + 16 << 20) }
            limit = want
            return want
        }
        func freeOSMemory() -> Bool {
            freeOS += 1
            memory?.available += freeOSGives
            return true
        }
        func shed(level: Int, flags: MemoryShedFlags, reason: String) -> String {
            sheds.append((level, flags, reason))
            return "shed L\(level)"
        }
        func shedConnections(percent: Int) -> Int { connShed.append(percent); return 7 }
    }

    var mem: FakeMemory!
    var control: FakeControl!
    var clock: TimeInterval = 1000
    var logs: [String] = []

    override func setUp() {
        super.setUp()
        mem = FakeMemory()
        control = FakeControl()
        control.memory = mem
        clock = 1000
        logs = []
    }

    override func tearDown() {
        NativeMemoryGovernor.setActive(nil)
        super.tearDown()
    }

    func make(_ reclaimers: [NativeReclaimer] = []) -> NativeMemoryGovernor {
        NativeMemoryGovernor(memory: mem, control: control, reclaimers: reclaimers, now: { [unowned self] in self.clock },
                             log: { [unowned self] in self.logs.append($0) })
    }

    // MARK: levels

    func testLevelsWithHysteresis() {
        let g = make()
        let steps: [(Double, MemoryLevel)] = [
            (20, .normal), (13.9, .elevated), (15.5, .elevated), (16, .normal),
            (8.9, .high), (10.5, .high), (11, .elevated), (13, .elevated),
            (4.9, .critical), (6.2, .critical), (7, .high), (10.9, .high), (16.5, .normal),
        ]
        for (i, (a, want)) in steps.enumerated() {
            mem.set(availMB: a)
            clock += 1
            g.tick()
            XCTAssertEqual(g.level, want, "step \(i): \(a) MB available")
        }
    }

    func testUnknownAvailableUsesFootprintAndNeverRefuses() {
        let g = make()
        mem.available = 0 // the app / simulator
        mem.footprint = 45 << 20
        g.tick()
        XCTAssertEqual(g.level, .high)
        XCTAssertTrue(g.admit(.body, bytes: -1), "unknown available: never refuse")
        mem.footprint = 43 << 20 // within 2 MB of the 44 MB backstop: stays
        clock += 1; g.tick()
        XCTAssertEqual(g.level, .high)
        mem.footprint = 41 << 20
        clock += 1; g.tick()
        XCTAssertEqual(g.level, .elevated)
    }

    // MARK: calm critical

    /// iOS "critical" while the extension still has room (the 喜马拉雅 burst: event at ~10 MB available): at most
    /// `elevated`, a light shed, no DNS clear, no script-queue kick (engine critical), no stop.
    func testCriticalEventIsCalm() {
        let g = make()
        mem.set(availMB: 20)
        g.onPressureEvent(critical: true)
        XCTAssertEqual(g.level, .elevated)
        XCTAssertEqual(control.sheds.count, 1)
        XCTAssertEqual(control.sheds[0].level, 1)
        XCTAssertEqual(control.sheds[0].flags, [], "calm: caches only")
        XCTAssertEqual(control.freeOS, 0)
        // 8.5 MB available (a few seconds into the burst): high → one stop (freeOS flag), idle conns, no DNS
        mem.set(availMB: 8.5)
        clock += 1
        g.onPressureEvent(critical: true)
        XCTAssertEqual(g.level, .high)
        let last = control.sheds.last!
        XCTAssertEqual(last.level, 1)
        XCTAssertTrue(last.flags.contains(.freeOS))
        XCTAssertTrue(last.flags.contains(.idleConns))
        XCTAssertFalse(last.flags.contains(.dns))
        XCTAssertFalse(last.flags.contains(.engineCritical))
        XCTAssertEqual(control.freeOS, 0, "the shed's own FreeOSMemory is the only stop")
        // the event hold ends: back to the reading's level
        mem.set(availMB: 20)
        clock += 11
        g.tick()
        XCTAssertEqual(g.level, .normal)
    }

    /// Critical as a reading: engine critical + idle conns; DNS only from the timer once critical lasted 30 s, at
    /// most every 2 min, never on an event (a burst).
    func testCriticalDNSOnlyAfterSustainedCriticalOnTimer() {
        let g = make()
        mem.set(availMB: 4.5)
        g.tick()
        XCTAssertEqual(g.level, .critical)
        var s = control.sheds.last!
        XCTAssertEqual(s.level, 2)
        XCTAssertTrue(s.flags.contains(.engineCritical))
        XCTAssertFalse(s.flags.contains(.dns), "fresh critical (burst): no DNS clear")
        clock += 31
        g.onPressureEvent(critical: true)
        XCTAssertFalse(control.sheds.last!.flags.contains(.dns), "event: never DNS")
        clock += 5
        g.tick()
        s = control.sheds.last!
        XCTAssertTrue(s.flags.contains(.dns), "sustained critical on the timer")
        clock += 30
        g.tick()
        XCTAssertFalse(control.sheds.last!.flags.contains(.dns), "rate limit 2 min")
        clock += 121
        g.tick()
        XCTAssertTrue(control.sheds.last!.flags.contains(.dns))
        XCTAssertEqual(g.counters.dnsClears, 2)
    }

    func testShedBackoffWhenNothingFreed() {
        let g = make()
        mem.set(availMB: 12) // elevated
        g.tick()
        XCTAssertEqual(control.sheds.count, 1)
        clock += 3; g.tick() // gap 3 s + backoff 5 s
        XCTAssertEqual(control.sheds.count, 1)
        clock += 5; g.tick()
        XCTAssertEqual(control.sheds.count, 2)
        clock += 8; g.tick() // backoff now 10 s
        XCTAssertEqual(control.sheds.count, 2)
        mem.set(availMB: 8) // level rose: at once
        clock += 1; g.tick()
        XCTAssertEqual(control.sheds.count, 3)
    }

    // MARK: heap limit

    func testLimitFollowsLevelWithAntiThrashFloor() {
        let g = make()
        mem.set(availMB: 20)
        g.tick()
        XCTAssertEqual(control.limitCalls, [0])
        mem.set(availMB: 8)
        clock += 1; g.tick()
        XCTAssertEqual(control.limitCalls.last, 22 << 20)
        XCTAssertEqual(control.limit, 22 << 20)
        clock += 1; g.tick()
        XCTAssertEqual(control.limitCalls.count, 2, "unchanged ask is not repeated")
        // critical with 30 MB of non-garbage the old core memory: the ask (18 MB) is clamped up to 32 MB (no GC thrash)
        control.nonGarbage = 30 << 20
        mem.set(availMB: 4)
        clock += 1; g.tick()
        XCTAssertEqual(control.limitCalls.last, 18 << 20)
        XCTAssertEqual(control.limit, 32 << 20)
        XCTAssertEqual(g.limitInEffect, 32 << 20)
        // a heap-limit loan: hands off
        control.loan = true
        mem.set(availMB: 20)
        clock += 20; g.tick()
        XCTAssertEqual(control.limitCalls.count, 3)
        control.loan = false
        clock += 1; g.tick()
        XCTAssertEqual(control.limitCalls.last, 0)
    }

    // MARK: admission

    /// The 喜马拉雅 numbers: baseInfo / homePage JSON at 5.2 MB available (refused by the old 6 MB floor) pass; a
    /// 256 KB body needs 5.25 MB; big / unknown work is refused at critical.
    func testSmallWorkAllowedDownToFloorBigGated() {
        let g = make()
        mem.set(availMB: 5.2)
        XCTAssertTrue(g.admit(.body, bytes: 40 << 10))
        XCTAssertTrue(g.admit(.script, bytes: 20 << 10))
        XCTAssertTrue(g.admit(.session, bytes: NativeMemoryGovernor.sessionCost))
        XCTAssertFalse(g.admit(.body, bytes: 256 << 10))
        XCTAssertFalse(g.admit(.body, bytes: -1))
        XCTAssertFalse(g.admit(.body, bytes: 2 << 20))
        mem.set(availMB: 4.4)
        XCTAssertFalse(g.admit(.session, bytes: NativeMemoryGovernor.sessionCost), "below 4.5 MB: even small work waits")
        XCTAssertEqual(g.counters.refusedBy["body"], 3)
        XCTAssertEqual(g.counters.refusedBy["session"], 1)
        // normal: big work with 9 MB + 2× size
        mem.set(availMB: 20)
        clock += 1
        XCTAssertTrue(g.admit(.body, bytes: 3 << 20))
        mem.set(availMB: 14.5)
        XCTAssertFalse(g.admit(.body, bytes: 3 << 20))
    }

    /// Reclaim before refusing: native reclaimers (by level) + one the old core FreeOSMemory, re-read, decide again; at most
    /// once a second.
    func testReclaimBeforeRefuse() {
        var ran: [String] = []
        let g = make([
            NativeReclaimer(name: "bodies", from: .elevated) { _ in ran.append("bodies"); return 300 << 10 },
            NativeReclaimer(name: "jsc", from: .elevated) { [unowned self] _ in ran.append("jsc"); self.mem.available += 2 << 20; return -1 },
            NativeReclaimer(name: "tls", from: .high) { _ in ran.append("tls"); return 10 << 10 },
            NativeReclaimer(name: "pool", from: .critical) { _ in ran.append("pool"); return 0 },
        ])
        control.freeOSGives = 1 << 20
        // high (8.5 MB): a 512 KB body is big → refused at first; reclaim gives 2 (jsc) + 1 (FreeOSMemory) MB →
        // 11.5 MB = elevated again → 9 + 2 × 0.5 MB needed → admitted
        mem.set(availMB: 8.5)
        XCTAssertTrue(g.admit(.body, bytes: 512 << 10))
        XCTAssertEqual(ran, ["bodies", "jsc", "tls"], "reclaimers up to high, cheapest first (pool only at critical)")
        XCTAssertEqual(control.freeOS, 1)
        XCTAssertEqual(g.counters.reclaims, 1)
        XCTAssertEqual(g.counters.refused, 0)
        // a second refusal within 1 s does not reclaim again
        ran.removeAll()
        mem.set(availMB: 8.5)
        XCTAssertFalse(g.admit(.body, bytes: 2 << 20))
        XCTAssertEqual(ran, [])
        XCTAssertEqual(control.freeOS, 1)
        // after the window: 6 MB → reclaim → 9 MB, still high (exit at 11 MB): big work needs 11 + 2 × size → refused
        clock += 1.5
        mem.set(availMB: 6)
        XCTAssertFalse(g.admit(.body, bytes: 300 << 10))
        XCTAssertEqual(ran, ["bodies", "jsc", "tls"])
        XCTAssertEqual(g.counters.reclaims, 2)
        XCTAssertEqual(g.counters.refusedBy["body"], 2)
        XCTAssertTrue(logs.contains { $0.contains("memory reclaim (before refusing body (512 KB))") }, logs.joined(separator: "\n"))
    }

    func testRuntimeSessionAdmissionUsesActiveGovernor() {
        let g = make()
        mem.set(availMB: 4)
        XCTAssertTrue(NativeMitmRuntime.canAccept, "no governor: only the session cap")
        NativeMemoryGovernor.setActive(g)
        XCTAssertFalse(NativeMitmRuntime.canAccept, "governor: 4 MB available, session declined (pass-through)")
        mem.set(availMB: 20)
        clock += 2
        XCTAssertTrue(NativeMitmRuntime.canAccept)
        NativeMemoryGovernor.setActive(nil)
    }

    // MARK: emergency

    func testEmergencyClosesOldestOnceUntilRearmed() {
        let g = make()
        mem.set(availMB: 2.5, fpMB: 46)
        g.tick()
        XCTAssertEqual(control.connShed, [25])
        clock += 3
        g.tick()
        XCTAssertEqual(control.connShed, [25], "not again before re-arm (30 s or footprint < 42 MB)")
        mem.set(availMB: 1.5, fpMB: 46)
        clock += 31
        g.tick()
        XCTAssertEqual(control.connShed, [25, 50])
        XCTAssertEqual(g.counters.emergencies, 2)
    }

    // MARK: diagnostics

    func testDiagnosticsLineAndSnapshot() throws {
        let g = make()
        mem.set(availMB: 8)
        g.tick()
        _ = g.admit(.body, bytes: -1)
        let line = g.diagnosticsLine()
        XCTAssertTrue(line.hasPrefix("native governor high"), line)
        XCTAssertTrue(line.contains("heap limit 22.0 MB"), line)
        XCTAssertTrue(line.contains("refused 1 (body 1)"), line)
        let f = g.snapshotFields()
        XCTAssertEqual(f["level"] as? String, "high")
        XCTAssertEqual(f["refused"] as? Int, 1)
        // the app decodes it in 隧道内存
        let obj: [String: Any] = ["footprint": 30 << 20, "peak": 31 << 20, "available": 8 << 20, "at": 1, "governor": f]
        let json = try JSONSerialization.data(withJSONObject: obj)
        let snap = try JSONDecoder().decode(TunnelMemorySnapshot.self, from: json)
        XCTAssertEqual(snap.governor?.level, "high")
        XCTAssertEqual(snap.governor?.refused, 1)
        XCTAssertFalse(snap.governor?.text.isEmpty ?? true)
    }

    // MARK: native reclaimers

    func testBodyStoreTrimKeepsBytes() {
        let store = NativeBodyStore.shared
        let h = store.open("identity", limit: 4 << 20, hint: 1 << 20) // Content-Length said 1 MB
        XCTAssertGreaterThan(h, 0)
        let payload = Data((0..<(40 << 10)).map { UInt8($0 & 0xff) })
        XCTAssertEqual(store.write(h, b: payload), "")
        XCTAssertEqual(store.finish(h), Int64(payload.count))
        let freed = store.trimForMemory()
        XCTAssertGreaterThanOrEqual(freed, (1 << 20) - payload.count)
        XCTAssertEqual(store.read(h, raw: false, off: 0, n: Int64(payload.count)), payload)
        XCTAssertEqual(store.read(h, raw: true, off: 0, n: Int64(payload.count)), payload)
        XCTAssertEqual(store.trimForMemory(), 0, "each body at most once")
        store.free(h)
    }

    func testBoundedLRUTrim() {
        let lru = BoundedLRU<Int>(maxCount: 64, maxBytes: 1 << 20)
        for i in 0..<20 { lru.set("h\(i).example", i, cost: 1000) }
        _ = lru.get("h0.example") // most recent now
        XCTAssertEqual(lru.trim(keep: 4), 16 * 1000)
        XCTAssertEqual(lru.count, 4)
        XCTAssertNotNil(lru.get("h0.example"))
        XCTAssertNotNil(lru.get("h19.example"))
        XCTAssertNil(lru.get("h1.example"))
    }

    func testSwitchDefaultsOff() {
        let d = UserDefaults(suiteName: NativeMitmRuntime.appGroup)
        let had = d?.object(forKey: NativeMemoryGovernor.defaultsKey)
        d?.removeObject(forKey: NativeMemoryGovernor.defaultsKey)
        XCTAssertFalse(NativeMemoryGovernor.enabled)
        XCTAssertNil(NativeMemoryGovernor.active)
        if let had { d?.set(had, forKey: NativeMemoryGovernor.defaultsKey) }
    }
}
