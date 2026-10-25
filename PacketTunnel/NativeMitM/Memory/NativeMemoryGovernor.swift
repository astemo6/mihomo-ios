// Native MitM stage 3b (feat/s3-mem): the extension's memory governor in Swift.
//
// One coordinator instead of two competing ones. Today MemoryGuard (PacketTunnelProvider.swift) samples the
// footprint and asks Go to shed, while Go runs its own GOMEMLIMIT governor (bridge/memshed.go governLimit) and its
// own gates. With the app-group switch `nativeMemGovernor` on (default OFF; off = all of that unchanged), this
// class replaces MemoryGuard: it reads os_proc_available_memory + phys_footprint + the DispatchSource memory-pressure
// events, keeps one level with hysteresis, admits native work by size, reclaims native memory before refusing,
// and drives Go through the bridge (LibmihomoNativeGovernLimit / NativeShed / NativeFreeOSMemory, bridge/nativegov.go;
// Go's governor stands down while LibmihomoSetNativeMemoryGovernor(true)).
//
// Numbers from the 喜马拉雅 device log (work/xmly-memory-2026-10-24.md, fix/xmly-memory 897fffd):
//   - iOS sends "critical" at ~10 MB available while an app opens ~100 connections; a critical *event* is not a
//     reason to clear DNS caches or kick the script queue then (the old shed made the footprint 39.8 → 42.1 MB in
//     62 ms). Critical here is a *reading* (< 5 MB available), and DNS clears only from the timer once critical
//     lasted ≥ 30 s, at most every 2 min.
//   - Small work (bodies / scripts / sessions ≤ 256 KB) stays allowed down to 4.5 MB + 3× its size; big or
//     unknown-size work is gated from the `high` level on. Every refusal first reclaims (rate-limited 1/s).
//   - GOMEMLIMIT never goes below Go's non-garbage memory + 2 MB (Go clamps it; gc ran ~100×/s below it).
//   - One stop per shed: no runtime.GC() + FreeOSMemory pair, FreeOSMemory itself rate-limited in Go.
//
// Everything that reads memory or touches the world is injected (NativeMemorySampling / GoMemoryControlling /
// NativeReclaimer), so UnitTests/NativeMitmMemoryGovernorTests.swift drives it with fixed readings.

import Foundation

// MARK: - inputs

struct NativeMemorySample: Equatable {
    /// phys_footprint, bytes.
    var footprint: UInt64
    /// os_proc_available_memory, bytes; 0 = not a memory-limited process (app, simulator): treated as unknown.
    var available: Int
}

protocol NativeMemorySampling {
    func sample() -> NativeMemorySample
}

/// Go's numbers (LibmihomoNativeGoMemory JSON, bytes).
struct GoMemoryInfo: Decodable, Equatable {
    var heap: Int64 = 0
    var nonGarbage: Int64 = 0
    var floor: Int64 = 0
    var limit: Int64 = 0
    var configured: Int64 = 0
    var numGC: Int64 = 0
    var goroutines: Int = 0
    var loan: Bool = false
}

/// The bridge calls the governor drives (production: LibmihomoGoMemoryControl).
protocol GoMemoryControlling: AnyObject {
    func setActive(_ on: Bool)
    func info() -> GoMemoryInfo?
    /// GOMEMLIMIT; 0 = the configured limit. Returns the limit in effect (Go clamps to its anti-thrash floor).
    func setLimit(_ bytes: Int64) -> Int64
    func freeOSMemory() -> Bool
    func shed(level: Int, flags: GoShedFlags, reason: String) -> String
    /// Oldest connections, percent (emergency only).
    func shedConnections(percent: Int) -> Int
}

/// = bridge/nativegov.go NativeShed* flags.
struct GoShedFlags: OptionSet, Equatable {
    let rawValue: Int
    static let engineCritical = GoShedFlags(rawValue: 1 << 0)
    static let dns = GoShedFlags(rawValue: 1 << 1)
    static let idleConns = GoShedFlags(rawValue: 1 << 2)
    static let freeOS = GoShedFlags(rawValue: 1 << 3)
}

/// Something native that can give memory back (JSC garbage, failed native bodies, idle upstream connections, TLS
/// identities). `reclaim` returns the bytes it estimates it freed (-1 unknown) and must be safe from any thread.
struct NativeReclaimer {
    var name: String
    /// Lowest level at which it runs (a reclaim before a refusal runs everything up to the current level).
    var from: MemoryLevel
    var reclaim: (MemoryLevel) -> Int
}

enum MemoryLevel: Int, Comparable, CustomStringConvertible {
    case normal = 0, elevated, high, critical
    static func < (a: MemoryLevel, b: MemoryLevel) -> Bool { a.rawValue < b.rawValue }
    var description: String { ["normal", "elevated", "high", "critical"][rawValue] }
}

enum NativeWork: String {
    case session, body, script
}

// MARK: - governor

final class NativeMemoryGovernor {
    /// App-group switch; default OFF (MemoryGuard + Go's governor unchanged).
    static let defaultsKey = "nativeMemGovernor"
    static var enabled: Bool {
        UserDefaults(suiteName: NativeMitmRuntime.appGroup)?.bool(forKey: defaultsKey) ?? false
    }

    /// The running governor (nil = off): NativeBodyStore / NativeMitmRuntime / JSCScriptEngine ask it.
    private static let activeLock = NSLock()
    private static var _active: NativeMemoryGovernor?
    static var active: NativeMemoryGovernor? {
        activeLock.lock(); defer { activeLock.unlock() }
        return _active
    }
    static func setActive(_ g: NativeMemoryGovernor?) {
        activeLock.lock(); _active = g; activeLock.unlock()
    }

    struct Config {
        // levels by available memory: enter below, leave at or above (hysteresis)
        var elevatedEnter = 14 << 20, elevatedExit = 16 << 20
        var highEnter = 9 << 20, highExit = 11 << 20
        var criticalEnter = 5 << 20, criticalExit = 6 << 20 + 512 << 10
        /// footprint backstops (when available is unknown or lags): at least elevated / high / critical
        var fpElevated: UInt64 = 40 << 20, fpHigh: UInt64 = 44 << 20, fpCritical: UInt64 = 47 << 20
        /// a pressure event holds at least `elevated` this long (never more by itself: calm critical)
        var eventHold: TimeInterval = 10
        // admission
        var smallMax = 256 << 10
        var smallFloor = 4 << 20 + 512 << 10, smallFactor = 3
        var bigFloor = 9 << 20, bigFactor = 2
        /// after a reclaim, big work at high is let through with this much (+ factor × size)
        var bigFloorAfterReclaim = 11 << 20
        var reclaimEvery: TimeInterval = 1
        // shedding
        var shedMinGap: TimeInterval = 3, shedMaxBackoff: TimeInterval = 120
        /// critical must last this long before the timer clears DNS caches (not in a burst), at most every dnsEvery
        var dnsAfterCritical: TimeInterval = 30, dnsEvery: TimeInterval = 120
        /// idle tunnel connections are closed below this much available (Go: memPressureAvail)
        var idleConnsBelow = 12 << 20
        /// GOMEMLIMIT below the configured value at high / critical (Go clamps to non-garbage + 2 MB)
        var limitCutHigh: Int64 = 4 << 20, limitCutCritical: Int64 = 8 << 20
        // emergency (= MemoryGuard): oldest connections closed
        var emergencyAvail = 3 << 20, emergencyFP: UInt64 = 47 << 20, emergencyRearmFP: UInt64 = 42 << 20
        var emergencyGap: TimeInterval = 30
        // sampling
        var calmInterval = 10, busyInterval = 2
    }

    struct Counters: Equatable {
        var admitted = 0, refused = 0, reclaims = 0, sheds = 0, emergencies = 0, dnsClears = 0
        var reclaimedBytes = 0
        var refusedBy: [String: Int] = [:]
    }

    let config: Config
    private let memory: NativeMemorySampling
    private let go: GoMemoryControlling
    private let reclaimers: [NativeReclaimer]
    private let now: () -> TimeInterval
    private let log: (String) -> Void

    private let lock = NSLock()
    private(set) var level: MemoryLevel = .normal
    /// rv2-life: `level` read under the lock, for callers on other queues (the data plane's buffer budget).
    var currentLevel: MemoryLevel { lock.lock(); defer { lock.unlock() }; return level }
    private var levelSince: TimeInterval
    private var criticalSince: TimeInterval?
    private var lastEvent: TimeInterval = -.infinity
    private var lastReclaim: TimeInterval = -.infinity
    private var reclaiming = false
    private var lastShed: TimeInterval = -.infinity
    private var shedBackoff: TimeInterval = 0
    private var lastShedLevel: MemoryLevel = .normal
    private var lastDNS: TimeInterval = -.infinity
    private var lastEmergency: TimeInterval = -.infinity
    private var emergencyArmed = true
    private var limitAsked: Int64 = -1
    private(set) var limitInEffect: Int64 = 0
    private(set) var lastSample = NativeMemorySample(footprint: 0, available: 0)
    private(set) var lastGo: GoMemoryInfo?
    private(set) var counters = Counters()

    init(config: Config = Config(), memory: NativeMemorySampling, go: GoMemoryControlling, reclaimers: [NativeReclaimer] = [],
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         log: @escaping (String) -> Void = { _ in }) {
        self.config = config
        self.memory = memory
        self.go = go
        self.reclaimers = reclaimers
        self.now = now
        self.log = log
        levelSince = now()
    }

    // MARK: levels

    /// Available bytes; nil when unknown (os_proc_available_memory returns 0 outside a memory-limited process — the
    /// app, the simulator): then admission never refuses (like NativeBodyStore's floor) and only the footprint
    /// backstops set the level.
    func effectiveAvailable(_ s: NativeMemorySample) -> Int? { s.available > 0 ? s.available : nil }

    private func enterLevel(_ a: Int) -> MemoryLevel {
        let c = config
        if a < c.criticalEnter { return .critical }
        if a < c.highEnter { return .high }
        if a < c.elevatedEnter { return .elevated }
        return .normal
    }

    private func exitThreshold(_ l: MemoryLevel) -> Int {
        switch l {
        case .critical: return config.criticalExit
        case .high: return config.highExit
        case .elevated: return config.elevatedExit
        case .normal: return 0
        }
    }

    /// The level for a reading, from `current` (hysteresis): rising uses the enter thresholds, falling steps down
    /// only while the reading is at or above the exit threshold of the level it leaves. Footprint backstops and a
    /// recent pressure event only raise it (an event never above `elevated`).
    func levelFor(_ s: NativeMemorySample, from current: MemoryLevel, at t: TimeInterval) -> MemoryLevel {
        var l: MemoryLevel = .normal
        if let a = effectiveAvailable(s) {
            let enter = enterLevel(a)
            l = max(enter, current)
            while l > enter, a >= exitThreshold(l) { l = MemoryLevel(rawValue: l.rawValue - 1)! }
        }
        var fpLevel: MemoryLevel = .normal
        if s.footprint >= config.fpCritical { fpLevel = .critical }
        else if s.footprint >= config.fpHigh { fpLevel = .high }
        else if s.footprint >= config.fpElevated { fpLevel = .elevated }
        if effectiveAvailable(s) == nil, fpLevel < current, s.footprint + 2 << 20 > fpThreshold(current) {
            fpLevel = current // footprint-only hysteresis: 2 MB below the backstop before falling
        }
        l = max(l, fpLevel)
        if t - lastEvent < config.eventHold { l = max(l, .elevated) }
        return l
    }

    private func fpThreshold(_ l: MemoryLevel) -> UInt64 {
        switch l {
        case .critical: return config.fpCritical
        case .high: return config.fpHigh
        case .elevated: return config.fpElevated
        case .normal: return 0
        }
    }

    @discardableResult
    private func updateLevelLocked(_ s: NativeMemorySample, _ t: TimeInterval) -> (old: MemoryLevel, new: MemoryLevel) {
        lastSample = s
        let old = level
        let new = levelFor(s, from: old, at: t)
        if new != old {
            level = new
            levelSince = t
        }
        if new == .critical { if criticalSince == nil { criticalSince = t } } else { criticalSince = nil }
        return (old, new)
    }

    // MARK: admission

    /// Whether `work` of `bytes` (-1 = unknown size) may start now. Small work (≤ 256 KB) needs 4.5 MB + 3× its size;
    /// big / unknown work needs 9 MB + 2× its size and is refused from `high` on. Before refusing: one reclaim
    /// (native caches + Go FreeOSMemory, at most once a second), a fresh reading, and the same test again
    /// (big work at `high` then passes with 11 MB + 2× its size).
    func admit(_ work: NativeWork, bytes: Int) -> Bool {
        let s = memory.sample()
        let t = now()
        lock.lock()
        updateLevelLocked(s, t)
        let ok = decide(bytes: bytes, sample: s, level: level, afterReclaim: false)
        if ok { counters.admitted += 1; lock.unlock(); return true }
        let canReclaim = !reclaiming && t - lastReclaim >= config.reclaimEvery
        if canReclaim { reclaiming = true; lastReclaim = t }
        let lvl = level
        lock.unlock()

        if canReclaim {
            let freed = runReclaim(upTo: max(lvl, .high), why: "before refusing \(work.rawValue) (\(bytes < 0 ? "unknown size" : Self.kb(bytes)))")
            lock.lock()
            reclaiming = false
            counters.reclaims += 1
            counters.reclaimedBytes += max(0, freed)
            lock.unlock()
        }
        let s2 = memory.sample()
        lock.lock()
        updateLevelLocked(s2, now())
        let ok2 = decide(bytes: bytes, sample: s2, level: level, afterReclaim: canReclaim)
        if ok2 { counters.admitted += 1 } else {
            counters.refused += 1
            counters.refusedBy[work.rawValue, default: 0] += 1
        }
        lock.unlock()
        return ok2
    }

    private func decide(bytes: Int, sample s: NativeMemorySample, level: MemoryLevel, afterReclaim: Bool) -> Bool {
        guard let avail = effectiveAvailable(s) else { return true }
        let c = config
        if bytes >= 0 && bytes <= c.smallMax {
            return avail >= c.smallFloor + c.smallFactor * bytes
        }
        let size = max(bytes, c.smallMax) // unknown counts as at least a big body
        switch level {
        case .normal, .elevated:
            return avail >= c.bigFloor + c.bigFactor * size
        case .high:
            return afterReclaim && avail >= c.bigFloorAfterReclaim + c.bigFactor * size
        case .critical:
            return false
        }
    }

    // MARK: reclaim

    /// Runs the native reclaimers that apply up to `level`, then one Go FreeOSMemory. Returns the bytes freed
    /// (estimate; footprint difference when the reclaimers do not know).
    @discardableResult
    func runReclaim(upTo level: MemoryLevel, why: String) -> Int {
        let before = memory.sample()
        var parts: [String] = []
        var est = 0
        for r in reclaimers where r.from <= level {
            let n = r.reclaim(level)
            if n > 0 { est += n; parts.append("\(r.name) \(Self.kb(n))") } else if n < 0 { parts.append(r.name) }
        }
        let freedOS = go.freeOSMemory()
        let after = memory.sample()
        let fpDelta = Int(clamping: Int64(before.footprint) - Int64(after.footprint))
        log("memory reclaim (\(why)): \(parts.isEmpty ? "nothing native" : parts.joined(separator: ", "))\(freedOS ? ", go FreeOSMemory" : ""); footprint \(Self.mb(before.footprint)) → \(Self.mb(after.footprint)), available \(Self.mb(before.available)) → \(Self.mb(after.available))")
        return max(est, fpDelta)
    }

    // MARK: events and ticks

    /// DispatchSource memory-pressure event. Calm: an event alone never raises the level past `elevated`, never
    /// clears DNS caches, never kicks queues — the reading decides.
    func onPressureEvent(critical: Bool) {
        let t = now()
        lock.lock()
        lastEvent = t
        lock.unlock()
        tick(trigger: critical ? .criticalEvent : .warningEvent)
    }

    enum Trigger: String { case timer, warningEvent = "pressure warning", criticalEvent = "pressure critical", reload }

    /// One governor step: level, GOMEMLIMIT, shed, emergency. Returns what it did (tests / logs).
    @discardableResult
    func tick(trigger: Trigger = .timer) -> [String] {
        let s = memory.sample()
        let t = now()
        let goInfo = go.info()
        var did: [String] = []
        lock.lock()
        lastGo = goInfo
        let (old, lvl) = updateLevelLocked(s, t)
        if old != lvl { did.append("level \(old) → \(lvl)") }

        // GOMEMLIMIT
        let want: Int64
        switch lvl {
        case .normal, .elevated: want = 0
        case .high: want = max(0, (goInfo?.configured ?? 0) - config.limitCutHigh)
        case .critical: want = max(0, (goInfo?.configured ?? 0) - config.limitCutCritical)
        }
        let askLimit = goInfo != nil && !(goInfo?.loan ?? false) && want != limitAsked
        if askLimit { limitAsked = want }

        // shed: on rising level at once, else rate-limited with backoff while sheds free nothing
        var shedLevel: Int?
        var flags: GoShedFlags = []
        let rose = lvl > lastShedLevel
        // DNS caches: not in a burst — only from the timer once critical lasted dnsAfterCritical (or before a
        // reload), at most every dnsEvery; a due clear is a new lever, so it sheds through the backoff
        let lasted = criticalSince.map { t - $0 >= config.dnsAfterCritical } ?? false
        let dnsDue = lvl == .critical && (trigger == .timer && lasted || trigger == .reload) && t - lastDNS >= config.dnsEvery
        if lvl >= .elevated, rose || dnsDue || t - lastShed >= config.shedMinGap + shedBackoff {
            shedLevel = lvl >= .critical ? 2 : 1
            if lvl >= .high { flags.insert(.freeOS) }
            let avail = effectiveAvailable(s) ?? Int.max
            if lvl >= .high && avail < config.idleConnsBelow { flags.insert(.idleConns) }
            if lvl == .critical { flags.insert(.engineCritical) } // < 5 MB available (or a footprint ≥ 47 MB)
            if dnsDue {
                flags.insert(.dns)
                lastDNS = t
                counters.dnsClears += 1
            }
            lastShed = t
            lastShedLevel = lvl
        }
        if lvl == .normal { lastShedLevel = .normal; shedBackoff = 0 }

        // emergency
        let avail = effectiveAvailable(s)
        let lowAvail = avail.map { $0 < config.emergencyAvail } ?? false
        if s.footprint < config.emergencyRearmFP || t - lastEmergency > config.emergencyGap { emergencyArmed = true }
        let emergency = (s.footprint >= config.emergencyFP || lowAvail) && emergencyArmed
        lock.unlock()

        if askLimit {
            let v = go.setLimit(want)
            lock.lock(); limitInEffect = v; lock.unlock()
            did.append("GOMEMLIMIT \(Self.mb(v))")
        }
        if let sl = shedLevel {
            // native first (no stop), then Go's shed — whose single FreeOSMemory (from `high`) is the only stop
            let freedNative = runNativeOnly(upTo: lvl)
            let line = go.shed(level: sl, flags: flags, reason: "\(trigger.rawValue), level \(lvl)")
            let after = memory.sample()
            let freed = Int64(s.footprint) - Int64(after.footprint)
            lock.lock()
            counters.sheds += 1
            if freed < 1 << 20 && freedNative < 1 << 20 {
                shedBackoff = shedBackoff == 0 ? 5 : min(shedBackoff * 2, config.shedMaxBackoff)
            } else {
                shedBackoff = 0
            }
            lock.unlock()
            did.append("shed L\(sl) \(Self.flagText(flags))")
            if !line.isEmpty { log(line) }
        }
        if emergency {
            // a shed above already returned memory: re-read before closing connections (often that is enough)
            let s2 = memory.sample()
            let a2 = effectiveAvailable(s2)
            let low2 = a2.map { $0 < config.emergencyAvail } ?? false
            if s2.footprint >= config.emergencyFP || low2 {
                let percent = (a2.map { $0 < 2 << 20 } ?? false) ? 50 : 25
                let n = go.shedConnections(percent: percent)
                lock.lock()
                emergencyArmed = false
                lastEmergency = now()
                counters.emergencies += 1
                lock.unlock()
                did.append("closed \(n) oldest connections (\(percent) %)")
                log("memory governor emergency: closed \(n) oldest connections (\(percent) %) at footprint \(Self.mb(s2.footprint)), available \(Self.mb(s2.available))")
            }
        }
        return did
    }

    /// The native reclaimers only (no Go FreeOSMemory: the shed that follows carries it).
    private func runNativeOnly(upTo level: MemoryLevel) -> Int {
        var est = 0
        for r in reclaimers where r.from <= level { est += max(0, r.reclaim(level)) }
        return est
    }

    /// Sampling interval for the timer: faster from `high` on.
    var interval: Int { lock.lock(); defer { lock.unlock() }; return level >= .high ? config.busyInterval : config.calmInterval }

    // MARK: diagnostics

    /// One line for the memory log / 隧道内存.
    func diagnosticsLine() -> String {
        lock.lock(); defer { lock.unlock() }
        let c = counters
        let refusedBy = c.refusedBy.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ")
        var s = "native governor \(level): available \(Self.mb(lastSample.available)), footprint \(Self.mb(lastSample.footprint))"
        if let g = lastGo {
            s += ", GOMEMLIMIT \(Self.mb(limitInEffect > 0 ? limitInEffect : g.limit)) (floor \(Self.mb(g.floor)), go non-garbage \(Self.mb(g.nonGarbage)))"
        }
        s += "; admitted \(c.admitted), refused \(c.refused)\(refusedBy.isEmpty ? "" : " (\(refusedBy))"), reclaims \(c.reclaims) (\(Self.mb(c.reclaimedBytes))), sheds \(c.sheds), dns clears \(c.dnsClears), emergencies \(c.emergencies)"
        return s
    }

    /// Fields merged into the 隧道内存 snapshot JSON ("governor").
    func snapshotFields() -> [String: Any] {
        let line = diagnosticsLine()
        lock.lock(); defer { lock.unlock() }
        return ["level": level.description, "admitted": counters.admitted, "refused": counters.refused,
                "reclaims": counters.reclaims, "sheds": counters.sheds, "limit": limitInEffect, "line": line]
    }

    static func mb<T: BinaryInteger>(_ v: T) -> String { String(format: "%.1f MB", Double(v) / 1_048_576) }
    static func kb(_ v: Int) -> String { v >= 1 << 20 ? mb(v) : "\(v >> 10) KB" }
    static func flagText(_ f: GoShedFlags) -> String {
        var p: [String] = []
        if f.contains(.engineCritical) { p.append("engine critical") }
        if f.contains(.dns) { p.append("dns") }
        if f.contains(.idleConns) { p.append("idle conns") }
        if f.contains(.freeOS) { p.append("freeOS") }
        return p.isEmpty ? "(caches)" : "(" + p.joined(separator: ", ") + ")"
    }
}
