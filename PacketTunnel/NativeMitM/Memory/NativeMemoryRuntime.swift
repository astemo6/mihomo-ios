// Native MitM stage 3b (feat/s3-mem): production wiring of NativeMemoryGovernor — the process readings, the Go
// bridge (bridge/nativegov.go), the native reclaimers, and the sampler that replaces MemoryGuard while the
// `nativeMemGovernor` switch is on.

import Foundation

/// phys_footprint + os_proc_available_memory (Shared/Startup.swift ProcessMemory).
struct ProcessMemorySampler: NativeMemorySampling {
    func sample() -> NativeMemorySample {
        NativeMemorySample(footprint: ProcessMemory.footprintBytes(), available: max(0, ProcessMemory.availableBytes()))
    }
}

/// Pure Swift memory control (no-op stand-in when Go is not running).
final class NativeNoopMemoryControl: GoMemoryControlling {
    func setActive(_ on: Bool) {}
    func info() -> GoMemoryInfo? { GoMemoryInfo() }
    func setLimit(_ bytes: Int64) -> Int64 { bytes }
    func freeOSMemory() -> Bool { true }
    func shed(level: Int, flags: GoShedFlags, reason: String) -> String { "" }
    func shedConnections(percent: Int) -> Int { 0 }
}

extension NativeMemoryGovernor {
    /// The native memory the governor can take back, cheapest first. The stage-2 pieces (upstream pool, TLS
    /// identities) are only touched when the native front is on (their `shared` instances are lazy).
    static func standardReclaimers(nativeFront: Bool = NativeMitmRuntime.enabled) -> [NativeReclaimer] {
        var r: [NativeReclaimer] = [
            NativeReclaimer(name: "native bodies", from: .elevated) { level in
                NativeBodyStore.shared.trimForMemory(maxCopy: level >= .critical ? 256 << 10 : 1 << 20)
            },
            NativeReclaimer(name: "jsc gc", from: .elevated) { _ in
                NativeMemoryGovernor.collectJSCAsync()
                return -1
            },
        ]
        if nativeFront {
            r.append(NativeReclaimer(name: "tls identities", from: .high) { level in
                LeafIdentityCache.shared.cache.trim(keep: level >= .critical ? 4 : 16)
            })
            r.append(NativeReclaimer(name: "upstream idle", from: .high) { _ in
                // async on the pool's queue (never statsNow here: admission may run on any thread)
                UpstreamPool.shared.closeIdle()
                return -1
            })
        }
        return r
    }

    /// JSC collection off the caller's thread: JSGarbageCollect takes the VM lock, which a script run holds for up to
    /// ~1 s — admission (a Go goroutine opening a body) must not wait for it. Coalesced: one pending at a time.
    private static let jscQueue = DispatchQueue(label: "mihomo.nativememgovernor.jsc", qos: .utility)
    private static let jscLock = NSLock()
    private static var jscPending = false
    static func collectJSCAsync() {
        Self.jscLock.lock()
        if Self.jscPending { Self.jscLock.unlock(); return }
        Self.jscPending = true
        Self.jscLock.unlock()
        Self.jscQueue.async {
            NativeMemoryGovernor.jscLock.lock()
            NativeMemoryGovernor.jscPending = false
            NativeMemoryGovernor.jscLock.unlock()
            JSCScriptEngine.shared.collect()
        }
    }

    /// Small-work cost of one native session (buffers it may hold soon after accept): admission size.
    static let sessionCost = 64 << 10
}

extension BoundedLRU {
    /// Drops the least recently used entries until at most `keep` remain; returns the bytes released.
    @discardableResult
    func trim(keep: Int) -> Int {
        let before = bytes
        let ks = keys
        for k in ks.prefix(max(0, ks.count - keep)) { remove(k) }
        return max(0, before - bytes)
    }
}

/// Replaces MemoryGuard while `nativeMemGovernor` is on: timer (10 s, 2 s from `high`), memory-pressure source,
/// Go's memory sample (connection activity + periodic memory line; Go's own governor stands down), the 隧道内存
/// snapshot. All on one serial queue.
final class NativeMemoryGovernorSampler {
    let governor: NativeMemoryGovernor
    private let go: GoMemoryControlling
    private let queue = DispatchQueue(label: "mihomo.nativememgovernor", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var pressure: DispatchSourceMemoryPressure?
    private var interval = 0
    private var stopped = false
    private var lastPressureLog = Date.distantPast
    private var lastLine = Date.distantPast
    /// Called on every tick with footprint / available (the tunnel writes the 隧道内存 snapshot here).
    private let onSample: (UInt64, Int) -> Void

    init(governor: NativeMemoryGovernor, go: GoMemoryControlling, onSample: @escaping (UInt64, Int) -> Void = { _, _ in }) {
        self.governor = governor
        self.go = go
        self.onSample = onSample
    }

    /// Production: process readings, Go bridge, standard reclaimers, logs to the startup log.
    static func makeDefault(onSample: @escaping (UInt64, Int) -> Void) -> NativeMemoryGovernorSampler {
        let go = NativeNoopMemoryControl()
        let g = NativeMemoryGovernor(memory: ProcessMemorySampler(), go: go, reclaimers: NativeMemoryGovernor.standardReclaimers(),
                                     log: { StartupLog.write($0) })
        return NativeMemoryGovernorSampler(governor: g, go: go, onSample: onSample)
    }

    func start() {
        queue.async { [self] in
            guard !stopped else { return }
            go.setActive(true)
            NativeMemoryGovernor.setActive(governor)
            let p = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
            p.setEventHandler { [weak self] in
                guard let self, !self.stopped, let ev = self.pressure?.data else { return }
                let critical = ev.contains(.critical)
                if Date().timeIntervalSince(self.lastPressureLog) > 60 {
                    self.lastPressureLog = Date()
                    StartupLog.write("memory pressure \(critical ? "critical" : "warning") (native governor; logged at most once a minute): \(ProcessMemory.summary())")
                }
                self.governor.onPressureEvent(critical: critical)
                self.reschedule()
            }
            p.resume()
            pressure = p
            StartupLog.write("memory governor: native (Swift) — \(governor.diagnosticsLine())")
            schedule(governor.interval)
        }
    }

    func stop() {
        queue.sync {
            stopped = true
            timer?.cancel()
            timer = nil
            pressure?.cancel()
            pressure = nil
            NativeMemoryGovernor.setActive(nil)
            go.setActive(false)
        }
    }

    private func schedule(_ seconds: Int) {
        guard !stopped else { return }
        interval = seconds
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(seconds), repeating: .seconds(seconds), leeway: .seconds(max(1, seconds / 4)))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func reschedule() {
        let want = governor.interval
        if want != interval { schedule(want) }
    }

    private func tick() {
        guard !stopped else { return }
        let fp = ProcessMemory.footprintBytes()
        let avail = ProcessMemory.availableBytes()
        governor.tick()
        onSample(fp, avail)
        // the governor's own line next to Go's periodic memory line: every 5 min from `elevated`, else 30 min
        let every: TimeInterval = governor.level >= .elevated ? 300 : 1800
        if Date().timeIntervalSince(lastLine) >= every {
            lastLine = Date()
            StartupLog.write(governor.diagnosticsLine())
        }
        reschedule()
    }
}
