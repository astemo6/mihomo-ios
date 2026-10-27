import Foundation
import Network

/// fix/nc-delay-test: per-dial stage timings, so a 诊断包 shows where a delay probe (or a slow real dial) spends its
/// time: node DNS, TCP, node TLS, the transport upgrade (ws / grpc / h2), the inner TLS of an https test URL, and the
/// proxied request itself.
///
/// A delay probe runs on its own serial queue and attaches a trace to it (`DispatchQueue.setSpecific`); the dial code
/// below it (NCStream.start, NCConnector.transportStream) looks the trace up on the queue it was handed, so no
/// connector signature changes and real flows (whose queues carry no trace) pay one `getSpecific` per dial.
/// NWConnection does DNS + TCP + TLS as one step; its establishment report (requested after `.ready`) splits it.
final class NCDialTrace {
    static let key = DispatchSpecificKey<NCDialTrace>()

    /// The trace attached to `queue`, if any.
    static func on(_ queue: DispatchQueue) -> NCDialTrace? { queue.getSpecific(key: key) }

    /// Where log lines go (installed by the tunnel: NativeLogRing → App 日志 + core-log.txt). nil in the App / tests.
    /// Set once at tunnel start, read-only afterwards. `warning` = the line reports a failure.
    static var logSink: ((_ line: String, _ warning: Bool) -> Void)?

    struct Stage { var name: String; var startMs: Int; var endMs: Int?; var detail: String? }

    let start: DispatchTime
    private let lock = NSLock()
    private var stages: [Stage] = []
    private var notes: [String] = []
    private(set) var lastError: String?
    /// dns / tcp / tls, from the NWError of a connect that failed.
    private var connectFailureStage: String?
    /// The first non-"dial" stage that ended with an error ("dial" only when nothing inside it failed).
    private var failedStage: String?

    func connectFailed(_ error: Error) {
        let stage: String
        if let e = error as? NWError {
            switch e {
            case .dns: stage = "dns"
            case .tls: stage = "tls"
            default: stage = "tcp"
            }
        } else { stage = "tcp" }
        lock.lock(); connectFailureStage = stage; lock.unlock()
    }

    init(start: DispatchTime = .now()) { self.start = start }

    var elapsedMs: Int { Self.ms(from: start, to: .now()) }

    static func ms(from a: DispatchTime, to b: DispatchTime) -> Int {
        b.uptimeNanoseconds >= a.uptimeNanoseconds ? Int((b.uptimeNanoseconds - a.uptimeNanoseconds) / 1_000_000) : 0
    }

    func begin(_ name: String) {
        let t = elapsedMs
        lock.lock(); stages.append(Stage(name: name, startMs: t)); lock.unlock()
    }

    /// Ends the latest open stage called `name`; an error is kept as the trace's last error.
    func end(_ name: String, error: Error? = nil, detail: String? = nil) {
        let t = elapsedMs
        lock.lock()
        if let i = stages.lastIndex(where: { $0.name == name && $0.endMs == nil }) {
            stages[i].endMs = t
            if let detail { stages[i].detail = detail }
        }
        if let error {
            lastError = "\(name): \(Self.describe(error))"
            if failedStage == nil || name != "dial" { failedStage = name }
        }
        lock.unlock()
    }

    /// A stage that is known only after the fact (from the establishment report): `startMs`…`startMs + durationMs`.
    func record(_ name: String, startMs: Int, durationMs: Int, detail: String? = nil) {
        lock.lock()
        stages.append(Stage(name: name, startMs: startMs, endMs: startMs + max(0, durationMs), detail: detail))
        lock.unlock()
    }

    func note(_ s: String) { lock.lock(); if notes.count < 4 { notes.append(s) }; lock.unlock() }

    func fail(_ s: String) { lock.lock(); lastError = s; lock.unlock() }

    /// The stage a probe was in when it gave up: the newest stage still open, else "request" once dialing is over
    /// (or "dial" when nothing was traced at all, e.g. a shared-session protocol dialing on its own queue).
    var openStage: String {
        lock.lock(); defer { lock.unlock() }
        if let open = stages.last(where: { $0.endMs == nil }) {
            // NWConnection does DNS + TCP + TLS in one step and reports the split only once ready.
            if open.name == "connect" { return "connect (dns/tcp/tls)" }
            // Only the connector's outer stage open: the proxy protocol handshake (or a shared session's own dial).
            return open.name == "dial" ? "handshake" : open.name
        }
        // A connect that failed: its NWError says which part (see NCStream.start).
        if failedStage == "connect" { return connectFailureStage ?? "connect" }
        // The connector failed after the socket was up: the proxy protocol / transport handshake.
        if failedStage == "dial" { return "handshake" }
        if let f = failedStage { return f }
        return stages.isEmpty ? "dial" : "request"
    }

    /// "dns 120 ms (query) · tcp 180 ms · tls 190 ms · ws 210 ms · request 260 ms" (stage durations, in order).
    var summary: String {
        lock.lock(); defer { lock.unlock() }
        // The raw "connect" stage is shown only when the report did not split it (no dns/tcp/tls entries).
        let split = stages.contains { ["dns", "tcp", "tls"].contains($0.name) }
        var parts: [String] = []
        for s in stages.sorted(by: { $0.startMs < $1.startMs }) where !(split && s.name == "connect" && s.endMs != nil) {
            let d = s.endMs.map { "\($0 - s.startMs) ms" } ?? "open"
            parts.append(s.detail.map { "\(s.name) \(d) (\($0))" } ?? "\(s.name) \(d)")
        }
        parts.append(contentsOf: notes)
        return parts.joined(separator: " · ")
    }

    /// Reads NWConnection's establishment report into dns / tcp / tls stages (relative to `connectStartMs`).
    func absorb(_ report: NWConnection.EstablishmentReport, connectStartMs: Int) {
        var cursor = connectStartMs + Int(report.attemptStartedAfterInterval * 1000)
        for r in report.resolutions {
            let src: String
            switch r.source {
            case .cache: src = "cache"
            case .expiredCache: src = "expired cache"
            default: src = "query"
            }
            let d = Int(r.duration * 1000)
            record("dns", startMs: cursor, durationMs: d, detail: "\(src), \(r.endpointCount) addr → \(Self.short(r.successfulEndpoint))")
            cursor += d
        }
        for h in report.handshakes {
            let d = Int(h.handshakeDuration * 1000)
            let name = h.definition.name.lowercased()
            let label = name.contains("tls") ? "tls" : (name.contains("tcp") ? "tcp" : name)
            record(label, startMs: cursor, durationMs: d, detail: "rtt \(Int(h.handshakeRTT * 1000)) ms")
            cursor += d
        }
        if report.previousAttemptCount > 0 { note("\(report.previousAttemptCount + 1) attempts") }
        if report.usedProxy { note("via system proxy") }
    }

    static func short(_ e: NWEndpoint) -> String {
        if case .hostPort(let host, _) = e {
            switch host {
            case .ipv4(let a): return "\(a)"
            case .ipv6(let a): return "[\(a)]"
            case .name(let n, _): return n
            @unknown default: return "\(host)"
            }
        }
        return "\(e)"
    }

    /// One readable line for any error: LocalizedError text, NWError's own description, else domain + code.
    static func describe(_ error: Error) -> String {
        if let e = error as? NWError { return e.debugDescription }
        if let e = error as? LocalizedError, let d = e.errorDescription { return d }
        let ns = error as NSError
        if let d = ns.userInfo[NSLocalizedDescriptionKey] as? String { return d }
        return "\(ns.domain) \(ns.code)"
    }
}

/// Rate limiter for diagnostic lines: at most `perWindow` lines per `window` seconds; the rest are counted and
/// reported as one "suppressed" line at the start of the next window.
final class NCLineLimiter {
    private let lock = NSLock()
    private let perWindow: Int
    private let window: TimeInterval
    private var windowStart = Date.distantPast
    private var used = 0
    private var suppressed = 0

    init(perWindow: Int, window: TimeInterval) {
        self.perWindow = perWindow
        self.window = window
    }

    /// Returns (allowed, suppressedToReport): when allowed and > 0, emit a "N line(s) suppressed" line first.
    func admit(now: Date = Date()) -> (Bool, Int) {
        lock.lock(); defer { lock.unlock() }
        var report = 0
        if now.timeIntervalSince(windowStart) >= window {
            windowStart = now
            used = 0
            report = suppressed
            suppressed = 0
        }
        guard used < perWindow else { suppressed += 1; return (false, 0) }
        used += 1
        return (true, report)
    }
}
