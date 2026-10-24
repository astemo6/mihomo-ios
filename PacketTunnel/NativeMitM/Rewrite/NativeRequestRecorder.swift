// Two builds of this file (feat/native-core-eval): TERN_NO_GO = the Go-free tunnel on NativeCore (no Libmihomo);
// otherwise the app target, which still links Go and drives the Go-backed MitM benches/tests.
#if TERN_NO_GO
// Native MitM stage 3a — request-log records for requests NativeRewriteDriver answered in Swift.
//
// Such a request never reaches Go, so the request log (HTTP capture) is recorded here. The
// driver hands small events to this recorder; it batches them off the request path in-memory,
// so a native entry reads in the list and the detail view.
//
// Cost on the request path: one struct append under a lock. Bounded: at most `maxQueued` events wait (further
// events are dropped and counted); a batch goes out after `delay` or as soon as `flushAt` events wait. Under memory
// pressure the queue is emptied and recording pauses for a few seconds (the log is diagnostics; the tunnel is not).

import Foundation

/// Where batches go (in-memory in the tunnel; tests capture them).
protocol NativeRequestLogSink: AnyObject {
    /// Applies a JSON array of events; returns how many were applied (-1 bad JSON).
    func record(_ json: String) -> Int
}

final class InMemoryNativeRequestLogSink: NativeRequestLogSink {
    static let shared = InMemoryNativeRequestLogSink()
    private let lock = NSLock()
    private(set) var recordedBatches: [String] = []

    func record(_ json: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        recordedBatches.append(json)
        if recordedBatches.count > 100 { recordedBatches.removeFirst(recordedBatches.count - 100) }
        return 1
    }
}

/// One event (bridge/mitm/nativerecord.go NativeRecord; field names are the JSON keys).
struct NativeRequestEvent: Encodable, Equatable {
    var k: Int64
    var ev: String           // drop / local / forward / response / end / cancel / upstream / error / abort
    var t: Double? = nil     // request start, unix seconds (first event of a request)
    var ms: Double           // start → this event, milliseconds
    var gen: Int64? = nil
    var rules: [Int]? = nil
    var method: String? = nil
    var url: String? = nil
    var host: String? = nil
    var tls: Bool? = nil
    var status: Int? = nil
    var headers: [[String]]? = nil
    var len: Int64? = nil
    var body: Data? = nil    // local answer body, only while capture is on (JSON: base64, like Go's []byte)
    var sent: Int64? = nil
    var resp: Bool? = nil
    var why: String? = nil
    /// Request-log notes (lane s3-script: skipped scripts, script errors, an abort), in order.
    var notes: [String]? = nil
    /// native-final: forward — the method after the request scripts when one changed it.
    var rmethod: String? = nil
}

final class NativeRequestRecorder {
    static let shared = NativeRequestRecorder(sink: InMemoryNativeRequestLogSink.shared)

    struct Stats: Equatable { var queued = 0, sent = 0, dropped = 0, batches = 0, shed = 0 }

    let maxQueued: Int
    let flushAt: Int
    let delay: TimeInterval
    private let sink: NativeRequestLogSink
    private let queue = DispatchQueue(label: "tern.native-rewrite.requestlog", qos: .utility)
    private let lock = NSLock()
    private var buf: [NativeRequestEvent] = []
    private var scheduled = false
    private var pausedUntil: UInt64 = 0
    private var counters = Stats()
    private var keySeq: Int64
    private var pressure: DispatchSourceMemoryPressure?

    /// `watchMemory`: shed on the system's memory-pressure events (the tunnel's recorder; tests leave it off).
    init(sink: NativeRequestLogSink, maxQueued: Int = 256, flushAt: Int = 64, delay: TimeInterval = 0.25, watchMemory: Bool = true) {
        self.sink = sink
        self.maxQueued = maxQueued
        self.flushAt = min(flushAt, maxQueued)
        self.delay = delay
        // keys only need to be unique per tunnel run on the Go side; a random base keeps a recreated recorder apart
        keySeq = Int64(UInt32.random(in: 1...UInt32.max)) << 20
        if watchMemory {
            let p = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
            p.setEventHandler { [weak self] in self?.shed() }
            p.resume()
            pressure = p
        }
    }

    deinit { pressure?.cancel() }

    var stats: Stats { lock.lock(); defer { lock.unlock() }; var s = counters; s.queued = buf.count; return s }

    func newKey() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        keySeq += 1
        return keySeq
    }

    /// Queues one event (the request path: no encoding, no Go call here).
    func add(_ e: NativeRequestEvent) {
        lock.lock()
        if pausedUntil != 0 {
            if DispatchTime.now().uptimeNanoseconds < pausedUntil {
                counters.dropped += 1
                lock.unlock()
                return
            }
            pausedUntil = 0
        }
        guard buf.count < maxQueued else {
            counters.dropped += 1
            lock.unlock()
            return
        }
        buf.append(e)
        let now = buf.count >= flushAt
        let schedule = !scheduled
        if schedule { scheduled = true }
        lock.unlock()
        if now {
            queue.async { [weak self] in self?.flush() }
        } else if schedule {
            queue.asyncAfter(deadline: .now() + delay) { [weak self] in self?.flush() }
        }
    }

    /// Sends what is queued. Runs on the recorder's serial queue only, so batches reach Go in order.
    private func flush() {
        lock.lock()
        let batch = buf
        buf = []
        scheduled = false
        lock.unlock()
        guard !batch.isEmpty else { return }
        guard let data = try? JSONEncoder().encode(batch), let json = String(data: data, encoding: .utf8) else {
            lock.lock(); counters.dropped += batch.count; lock.unlock()
            return
        }
        _ = sink.record(json)
        lock.lock()
        counters.sent += batch.count
        counters.batches += 1
        lock.unlock()
    }

    /// Flushes now on the recorder's queue (batches stay in order; tests).
    func flushNow() {
        queue.sync { flush() }
    }

    /// Waits until the recorder's queue has run what is already queued (tests).
    func waitIdle() {
        queue.sync {}
    }

    /// Memory pressure: drop the queue and pause recording for `seconds`.
    func shed(pause seconds: Double = 5) {
        lock.lock()
        counters.dropped += buf.count
        counters.shed += 1
        buf = []
        pausedUntil = DispatchTime.now().uptimeNanoseconds + UInt64(max(seconds, 0) * 1e9)
        lock.unlock()
    }
}
#else
// Native MitM stage 3a — request-log records for requests NativeRewriteDriver answered in Swift.
//
// Such a request never reaches Go's flow API, so Go's request log (请求 → HTTP, capture) would not show it. The
// driver hands small events to this recorder instead; it batches them off the request path and gives them to Go
// in one call (LibmihomoMitmRecordNative, JSON array → bridge/mitm/nativerecord.go), which writes the Entry with
// the same calls the Go path makes, so a native entry reads exactly like a Go one in the list and the detail view.
//
// Cost on the request path: one struct append under a lock. Bounded: at most `maxQueued` events wait (further
// events are dropped and counted); a batch goes out after `delay` or as soon as `flushAt` events wait. Under memory
// pressure the queue is emptied and recording pauses for a few seconds (the log is diagnostics; the tunnel is not).

import Foundation
import Libmihomo

/// Where batches go (Go in the tunnel; tests capture them).
protocol NativeRequestLogSink: AnyObject {
    /// Applies a JSON array of events; returns how many were applied (-1 bad JSON).
    func record(_ json: String) -> Int
}

final class GoNativeRequestLogSink: NativeRequestLogSink {
    func record(_ json: String) -> Int { Int(LibmihomoMitmRecordNative(json)) }
}

/// One event (bridge/mitm/nativerecord.go NativeRecord; field names are the JSON keys).
struct NativeRequestEvent: Encodable, Equatable {
    var k: Int64
    var ev: String           // drop / local / forward / response / end / cancel / upstream / error / abort
    var t: Double? = nil     // request start, unix seconds (first event of a request)
    var ms: Double           // start → this event, milliseconds
    var gen: Int64? = nil
    var rules: [Int]? = nil
    var method: String? = nil
    var url: String? = nil
    var host: String? = nil
    var tls: Bool? = nil
    var status: Int? = nil
    var headers: [[String]]? = nil
    var len: Int64? = nil
    var body: Data? = nil    // local answer body, only while capture is on (JSON: base64, like Go's []byte)
    var sent: Int64? = nil
    var resp: Bool? = nil
    var why: String? = nil
    /// Request-log notes (lane s3-script: skipped scripts, script errors, an abort), in order.
    var notes: [String]? = nil
    /// native-final: forward — the method after the request scripts when one changed it.
    var rmethod: String? = nil
}

final class NativeRequestRecorder {
    static let shared = NativeRequestRecorder(sink: GoNativeRequestLogSink())

    struct Stats: Equatable { var queued = 0, sent = 0, dropped = 0, batches = 0, shed = 0 }

    let maxQueued: Int
    let flushAt: Int
    let delay: TimeInterval
    private let sink: NativeRequestLogSink
    private let queue = DispatchQueue(label: "tern.native-rewrite.requestlog", qos: .utility)
    private let lock = NSLock()
    private var buf: [NativeRequestEvent] = []
    private var scheduled = false
    private var pausedUntil: UInt64 = 0
    private var counters = Stats()
    private var keySeq: Int64
    private var pressure: DispatchSourceMemoryPressure?

    /// `watchMemory`: shed on the system's memory-pressure events (the tunnel's recorder; tests leave it off).
    init(sink: NativeRequestLogSink, maxQueued: Int = 256, flushAt: Int = 64, delay: TimeInterval = 0.25, watchMemory: Bool = true) {
        self.sink = sink
        self.maxQueued = maxQueued
        self.flushAt = min(flushAt, maxQueued)
        self.delay = delay
        // keys only need to be unique per tunnel run on the Go side; a random base keeps a recreated recorder apart
        keySeq = Int64(UInt32.random(in: 1...UInt32.max)) << 20
        if watchMemory {
            let p = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
            p.setEventHandler { [weak self] in self?.shed() }
            p.resume()
            pressure = p
        }
    }

    deinit { pressure?.cancel() }

    var stats: Stats { lock.lock(); defer { lock.unlock() }; var s = counters; s.queued = buf.count; return s }

    func newKey() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        keySeq += 1
        return keySeq
    }

    /// Queues one event (the request path: no encoding, no Go call here).
    func add(_ e: NativeRequestEvent) {
        lock.lock()
        if pausedUntil != 0 {
            if DispatchTime.now().uptimeNanoseconds < pausedUntil {
                counters.dropped += 1
                lock.unlock()
                return
            }
            pausedUntil = 0
        }
        guard buf.count < maxQueued else {
            counters.dropped += 1
            lock.unlock()
            return
        }
        buf.append(e)
        let now = buf.count >= flushAt
        let schedule = !scheduled
        if schedule { scheduled = true }
        lock.unlock()
        if now {
            queue.async { [weak self] in self?.flush() }
        } else if schedule {
            queue.asyncAfter(deadline: .now() + delay) { [weak self] in self?.flush() }
        }
    }

    /// Sends what is queued. Runs on the recorder's serial queue only, so batches reach Go in order.
    private func flush() {
        lock.lock()
        let batch = buf
        buf = []
        scheduled = false
        lock.unlock()
        guard !batch.isEmpty else { return }
        guard let data = try? JSONEncoder().encode(batch), let json = String(data: data, encoding: .utf8) else {
            lock.lock(); counters.dropped += batch.count; lock.unlock()
            return
        }
        _ = sink.record(json)
        lock.lock()
        counters.sent += batch.count
        counters.batches += 1
        lock.unlock()
    }

    /// Flushes now on the recorder's queue (batches stay in order; tests).
    func flushNow() {
        queue.sync { flush() }
    }

    /// Waits until the recorder's queue has run what is already queued (tests).
    func waitIdle() {
        queue.sync {}
    }

    /// Memory pressure: drop the queue and pause recording for `seconds`.
    func shed(pause seconds: Double = 5) {
        lock.lock()
        counters.dropped += buf.count
        counters.shed += 1
        buf = []
        pausedUntil = DispatchTime.now().uptimeNanoseconds + UInt64(max(seconds, 0) * 1e9)
        lock.unlock()
    }
}
#endif
