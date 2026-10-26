import Foundation

/// fix/nc-mem-4: transient-memory locator (DEBUG builds only — the E2E replay builds Debug; Release is a no-op).
///
/// The E2E replay measured a kernel lifetime peak (ledger_phys_footprint_peak) ~+66 MB over the pre-start baseline
/// while the settled footprint was only +18 MB. The 100 ms sampler in the test process mostly misses such a short
/// transient, so this keeps:
///   * a tiny ring of the latest core events (controller requests in / out, health-check rounds, probes),
///   * live counters (controller requests in flight, delay probes in flight, NCStreams alive),
///   * a watcher (20 ms) that logs one `[nc-mem] scene=peak-step` line whenever the kernel peak grew by ≥ 1 MB since
///     the last line, with the counters and the event ring — so the stage-2 log says what was running when the
///     high-water mark moved.
/// `line(_:_:)` prints `[nc-mem] scene=<scene> <detail> footprint=…MB peak=…MB` at explicit checkpoints.
enum NCMemTrace {
    #if DEBUG
    static var enabled = true
    #else
    static var enabled = false
    #endif

    private static let lock = NSLock()
    private static var ring: [String] = []
    private static var ringStart = DispatchTime.now()
    private static var ctrlInFlight = 0
    private static var probesInFlight = 0
    private static var probesMax = 0
    private static var streamsAlive = 0
    private static var streamsMax = 0
    private static var watcher: DispatchSourceTimer?
    private static var lastPeak: UInt64 = 0

    private static func mb(_ v: UInt64) -> String { String(format: "%.1f", Double(v) / 1_048_576) }

    /// One checkpoint line with the current footprint and the kernel peak.
    static func line(_ scene: String, _ detail: String = "") {
        guard enabled else { return }
        let fp = ProcessMemory.footprintBytes(), pk = ProcessMemory.peakBytes()
        NSLog("[nc-mem] scene=%@ %@ footprint=%@MB peak=%@MB %@", scene, detail, mb(fp), mb(pk), counters())
    }

    /// Records a core event in the ring (kept short: the last 8).
    static func event(_ s: String) {
        guard enabled else { return }
        let t = Double(DispatchTime.now().uptimeNanoseconds &- ringStart.uptimeNanoseconds) / 1e9
        lock.lock()
        ring.append(String(format: "%.2f ", t) + s)
        if ring.count > 8 { ring.removeFirst(ring.count - 8) }
        lock.unlock()
    }

    static func ctrl(_ delta: Int) { guard enabled else { return }; lock.lock(); ctrlInFlight += delta; lock.unlock() }

    static func probe(_ delta: Int) {
        guard enabled else { return }
        lock.lock(); probesInFlight += delta; probesMax = max(probesMax, probesInFlight); lock.unlock()
    }

    static func stream(_ delta: Int) {
        guard enabled else { return }
        lock.lock(); streamsAlive += delta; streamsMax = max(streamsMax, streamsAlive); lock.unlock()
    }

    static func counters() -> String {
        lock.lock(); defer { lock.unlock() }
        return "ctrl=\(ctrlInFlight) probes=\(probesInFlight)/max\(probesMax) streams=\(streamsAlive)/max\(streamsMax)"
    }

    /// Starts the peak watcher (idempotent).
    static func startWatcher() {
        guard enabled else { return }
        lock.lock(); defer { lock.unlock() }
        guard watcher == nil else { return }
        ringStart = DispatchTime.now()
        lastPeak = ProcessMemory.peakBytes()
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "nc.memtrace", qos: .utility))
        t.schedule(deadline: .now() + 0.02, repeating: 0.02)
        t.setEventHandler { NCMemTrace.tick() }
        t.resume()
        watcher = t
    }

    static func stopWatcher() {
        lock.lock(); let t = watcher; watcher = nil; lock.unlock()
        t?.cancel()
    }

    private static func tick() {
        let pk = ProcessMemory.peakBytes()
        lock.lock()
        guard pk >= lastPeak &+ (1 << 20) else { lock.unlock(); return }
        lastPeak = pk
        let events = ring.joined(separator: " | ")
        lock.unlock()
        let fp = ProcessMemory.footprintBytes()
        NSLog("[nc-mem] scene=peak-step footprint=%@MB peak=%@MB %@ recent: %@", mb(fp), mb(pk), counters(), events)
    }
}
