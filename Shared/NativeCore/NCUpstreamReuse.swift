import Foundation

// fix/nc-0.20.3-diag (device diag 0917, build 527): every MitM-forwarded request dialed a brand-new proxy connection —
// TCP + TLS + WebSocket upgrade + VMess header — and closed it after the response, keep-alive or not
// (NCRelayUpstreamLease.release ignored `reusable`). A decrypted app that sends a few dozen small requests (喜马拉雅 at
// launch, the YouTube app) therefore produced a few dozen ws upgrade requests per second against the same CDN host,
// where its plain TUN flows (one proxy connection per app connection, reused by the app) produce a handful. CDN edges
// with request-rate / CC protection answer such a burst with `HTTP/1.1 403 Forbidden` to the upgrade — on device every
// MitM'd 喜马拉雅 / YouTube request failed `ws upgrade refused: HTTP/1.1 403 Forbidden` while plain flows through the
// same vmess+ws+tls node worked. The two pieces here bring the MitM path back to the plain path's connection pattern:
//   * NCIdlePool — a small keep-alive pool for finished upstream connections (per route + origin), short TTL;
//   * NCDialGate — at most `limit` dials in flight per proxy node; the rest wait their turn instead of bursting.
// Both are pure bookkeeping (no I/O, injected clock) so the unit tests drive them directly.

/// Bounded keep-alive pool of idle objects keyed by a string. Entries older than `ttl` are dropped on access; at most
/// `maxPerKey` per key and `maxTotal` overall (the oldest goes first). Thread-safe. Evicted objects are handed to
/// `discard` outside the lock (they close their connection there).
final class NCIdlePool<T: AnyObject> {
    var ttl: TimeInterval
    var maxPerKey: Int
    var maxTotal: Int
    private let discard: (T) -> Void
    private let now: () -> TimeInterval
    private let lock = NSLock()
    private var idle: [String: [(item: T, at: TimeInterval)]] = [:]
    private(set) var reuses = 0

    init(ttl: TimeInterval, maxPerKey: Int, maxTotal: Int,
         now: @escaping () -> TimeInterval = { Date().timeIntervalSince1970 },
         discard: @escaping (T) -> Void) {
        self.ttl = ttl; self.maxPerKey = maxPerKey; self.maxTotal = maxTotal
        self.now = now; self.discard = discard
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return idle.values.reduce(0) { $0 + $1.count } }

    /// The most recently parked live entry for `key` (LIFO: the warmest connection), or nil.
    func take(_ key: String) -> T? {
        let t = now()
        lock.lock()
        var stale: [T] = []
        var list = idle[key] ?? []
        let fresh = list.filter { t - $0.at < ttl }
        if fresh.count != list.count { stale = list.filter { t - $0.at >= ttl }.map { $0.item } }
        list = fresh
        let got = list.popLast()?.item
        if list.isEmpty { idle.removeValue(forKey: key) } else { idle[key] = list }
        if got != nil { reuses += 1 }
        lock.unlock()
        stale.forEach(discard)
        return got
    }

    /// Parks `item`; false (and nothing kept) when the pool is disabled (maxPerKey/maxTotal 0).
    @discardableResult
    func put(_ item: T, key: String) -> Bool {
        guard maxPerKey > 0, maxTotal > 0, ttl > 0 else { return false }
        let t = now()
        lock.lock()
        var evicted: [T] = []
        // expire everything stale first
        for (k, list) in idle {
            let keep = list.filter { t - $0.at < ttl }
            if keep.count != list.count {
                evicted += list.filter { t - $0.at >= ttl }.map { $0.item }
                if keep.isEmpty { idle.removeValue(forKey: k) } else { idle[k] = keep }
            }
        }
        var list = idle[key] ?? []
        list.append((item, t))
        while list.count > maxPerKey { evicted.append(list.removeFirst().item) }
        idle[key] = list
        var total = idle.values.reduce(0) { $0 + $1.count }
        while total > maxTotal {
            // drop the oldest entry overall (each key's list is in parking order, so its first is its oldest)
            var oldestKey: String?
            var oldestAt = TimeInterval.greatestFiniteMagnitude
            for (k, l) in idle {
                if let first = l.first, first.at < oldestAt { oldestAt = first.at; oldestKey = k }
            }
            guard let k = oldestKey, var l = idle[k], !l.isEmpty else { break }
            evicted.append(l.removeFirst().item)
            if l.isEmpty { idle.removeValue(forKey: k) } else { idle[k] = l }
            total -= 1
        }
        lock.unlock()
        evicted.forEach(discard)
        return true
    }

    func removeAll() {
        lock.lock()
        let all = idle.values.flatMap { $0.map { $0.item } }
        idle.removeAll()
        lock.unlock()
        all.forEach(discard)
    }
}

/// At most `limit` concurrent dials per key (a proxy node). `acquire` runs `start` at once when a slot is free, else
/// queues it (FIFO); `release` frees the slot and starts the next waiter. `start` runs outside the lock, on the caller's
/// thread (acquire) or the releasing thread (release) — callers hop to their own queue inside it.
final class NCDialGate {
    var limit: Int
    private let lock = NSLock()
    private var inFlight: [String: Int] = [:]
    private var waiters: [String: [() -> Void]] = [:]
    private(set) var queuedTotal = 0

    init(limit: Int) { self.limit = limit }

    /// The one per-node dial budget shared by every dial path (MitM upstream, plain TUN flows,
    /// probes, health checks): they all contend for the same proxy edge, so separate gates would
    /// each allow `limit` concurrent upgrades and the burst protection would not hold (device
    /// diag 2026-10-28: plain flows still died with ws-upgrade 403s while only the MitM path
    /// was gated).
    static let sharedNodeGate = NCDialGate(limit: 4)

    func inFlight(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return inFlight[key] ?? 0 }
    func waiting(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return waiters[key]?.count ?? 0 }

    func acquire(_ key: String, _ start: @escaping () -> Void) {
        lock.lock()
        let n = inFlight[key] ?? 0
        if limit <= 0 || n < limit {
            inFlight[key] = n + 1
            lock.unlock()
            start()
            return
        }
        waiters[key, default: []].append(start)
        queuedTotal += 1
        lock.unlock()
    }

    func release(_ key: String) {
        lock.lock()
        if var w = waiters[key], !w.isEmpty {
            let next = w.removeFirst()
            if w.isEmpty { waiters.removeValue(forKey: key) } else { waiters[key] = w }
            lock.unlock()
            next() // the slot passes straight to the waiter
            return
        }
        let n = (inFlight[key] ?? 1) - 1
        if n <= 0 { inFlight.removeValue(forKey: key) } else { inFlight[key] = n }
        lock.unlock()
    }
}

/// Whether a proxied dial failure is worth one more try after a short pause: the transport / handshake towards the
/// proxy failed (a CDN edge refusing a burst of upgrades, a reset during TLS), not a policy decision (REJECT, unknown
/// policy, unsupported node) that would fail the same way again.
enum NCUpstreamRetry {
    static func isTransient(_ error: Error?) -> Bool {
        guard let error else { return true }
        if let f = error as? NCConnector.Failure {
            switch f {
            case .handshake: return true
            case .rejected, .unknownPolicy, .unsupported: return false
            }
        }
        return true // NWError / POSIX (reset, timeout, refused)
    }
}
