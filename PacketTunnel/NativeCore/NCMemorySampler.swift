import Foundation

/// nc-lifecycle: lightweight process-memory sampler for lifecycle events.
///
/// One NSLog line per sample under the unified `[nc-mem]` prefix with a
/// scene tag — greppable in the tunnel log / Console:
///   [nc-mem] scene=start footprint=18.4MB peak=21.0MB avail=31.2MB
///
/// `footprint` is task_vm_info's phys_footprint (the number jetsam counts
/// against the extension budget) via the existing ProcessMemory helpers.
/// When that read fails (returns 0) the footprint falls back to an estimate
/// derived from os_proc_available_memory against the 50 MB budget and the
/// line is marked ` est`.
///
/// Call ONLY at lifecycle points (start / reload / stop / the lifecycle
/// self-test) and on the data plane's low-frequency stats cadence — never
/// per packet. Logging only; sampling never changes behavior.
enum NCMemorySampler {
    /// The tunnel extension's jetsam budget the fallback estimate uses.
    static let budgetBytes: UInt64 = 50 << 20

    struct Sample {
        let footprint: UInt64
        let peak: UInt64
        let available: Int
        let estimated: Bool
        /// The exact line sample() logged.
        let text: String

        var footprintMB: Double { Double(footprint) / 1_048_576 }
    }

    @discardableResult
    static func sample(_ scene: String) -> Sample {
        var fp = ProcessMemory.footprintBytes()
        let peak = ProcessMemory.peakBytes()
        let avail = ProcessMemory.availableBytes()
        var estimated = false
        if fp == 0, avail >= 0, UInt64(avail) < budgetBytes {
            fp = budgetBytes - UInt64(avail)
            estimated = true
        }
        func mb(_ v: UInt64) -> String { String(format: "%.1f", Double(v) / 1_048_576) }
        let availText = avail >= 0 ? mb(UInt64(avail)) : "-"
        let text = "[nc-mem] scene=\(scene) footprint=\(mb(fp))MB peak=\(mb(peak))MB avail=\(availText)MB\(estimated ? " est" : "")"
        NSLog("%@", text)
        return Sample(footprint: fp, peak: peak, available: avail, estimated: estimated, text: text)
    }
}
