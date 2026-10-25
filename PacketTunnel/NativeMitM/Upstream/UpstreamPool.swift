// Native MitM stage 2, lane `upstream` (B8b): bounded keep-alive pool of UpstreamConnections, keyed by
// UpstreamTarget (host, port, tls, policy). Mirrors the Go path's http.Transport defaults where they matter:
// MaxIdleConnsPerHost 2, a global idle cap, an idle timeout, LIFO reuse. A connection is only pooled when the
// HTTP lane says the exchange ended cleanly (`release(_:reusable: true)`) and the stream is still fully open
// with nothing unread; while idle one receive stays outstanding, so a server close evicts it right away.
//
// The relay port is read per dial (LibmihomoMitmRelayPort() starts the relay lazily and returns 0 when the engine
// is not running); `closeIdle()` should be called on engine reload / network change / tunnel stop.

import Foundation

final class UpstreamPool {
    struct Config {
        var maxIdlePerHost = 2
        var maxIdleTotal = 16
        var idleTimeout: TimeInterval = 60
        var connectTimeout: TimeInterval = 20
        /// feat/native-slim: most dials (TCP + CONNECT + TLS handshake) in flight at once; nil = no limit. Further
        /// acquires wait FIFO (a connection released meanwhile serves them first). Read per acquire, so
        /// NativeMitmRuntime.slim can change it.
        var maxDialing: () -> Int? = { NativeMitmRuntime.slim.maxConcurrentDials }
    }

    struct Stats: Equatable {
        var dials = 0          // opens started
        var dialFailures = 0
        var reuses = 0         // acquires served from the idle list
        var idle = 0           // currently pooled
        var dialing = 0
        var idleExpired = 0    // closed by the idle timeout
        var idleEvicted = 0    // closed by a cap or a server-side close while idle
    }

    /// One acquire in flight. `cancel()` aborts a dial still running (completion: `.cancelled`); after the
    /// completion ran it does nothing.
    final class Acquisition {
        fileprivate var completion: ((Result<UpstreamConnection, UpstreamError>) -> Void)?
        fileprivate var dialing: UpstreamConnection?
        fileprivate weak var pool: UpstreamPool?

        func cancel() {
            guard let pool else { return }
            pool.queue.async {
                if let c = self.dialing {
                    self.dialing = nil
                    c.closeOnQueue() // the open completion reports .cancelled
                } else {
                    self.fire(.failure(.cancelled))
                }
            }
        }

        fileprivate func fire(_ r: Result<UpstreamConnection, UpstreamError>) {
            guard let cb = completion else {
                if case .success(let c) = r { c.closeOnQueue() } // cancelled after the open won the race
                return
            }
            completion = nil
            cb(r)
        }
    }

    private struct IdleEntry {
        let conn: UpstreamConnection
        let since: DispatchTime
        let timer: DispatchWorkItem
    }

    static let shared = UpstreamPool(relayPort: { 0 })

    let queue: DispatchQueue
    let config: Config
    let relayPort: () -> Int
    private var idle: [UpstreamTarget: [IdleEntry]] = [:]
    private var idleCount = 0
    private var waiting: [(target: UpstreamTarget, acq: Acquisition)] = []
    private var nextID: UInt64 = 0
    private var stats = Stats()

    init(config: Config = Config(), queue: DispatchQueue = DispatchQueue(label: "tern.nativemitm.upstream"),
         relayPort: @escaping () -> Int) {
        self.config = config
        self.queue = queue
        self.relayPort = relayPort
    }

    /// A pooled connection to `target` (reused == true) or a freshly opened one. Completion runs on `queue`.
    @discardableResult
    func acquire(_ target: UpstreamTarget,
                 completion: @escaping (Result<UpstreamConnection, UpstreamError>) -> Void) -> Acquisition {
        let a = Acquisition()
        a.completion = completion
        a.pool = self
        queue.async { self.acquireOnQueue(target, a) }
        return a
    }

    private func acquireOnQueue(_ target: UpstreamTarget, _ a: Acquisition) {
        guard a.completion != nil else { return } // cancelled before we got here
        if let c = popIdle(target) {
            c.reused = true
            stats.reuses += 1
            a.fire(.success(c))
            return
        }
        if let cap = config.maxDialing(), stats.dialing >= max(1, cap) {
            waiting.append((target, a))
            return
        }
        nextID += 1
        stats.dials += 1
        stats.dialing += 1
        let port = relayPort()
        var counted = true
        let c = UpstreamConnection.open(target: target, relayPort: port, queue: queue, id: nextID,
                                        connectTimeout: config.connectTimeout) { [weak self] r in
            // `a` is held strongly until the open finishes (callers may drop the Acquisition).
            if counted, let self = self { counted = false; self.stats.dialing -= 1; if case .failure = r { self.stats.dialFailures += 1 } }
            a.dialing = nil
            a.fire(r)
            self?.drainWaiting()
        }
        if a.completion != nil { a.dialing = c }
    }

    /// Starts waiting acquires while dial slots are free (and serves them from the idle list first).
    private func drainWaiting() {
        while !waiting.isEmpty {
            if let cap = config.maxDialing(), stats.dialing >= max(1, cap) {
                // a waiter whose target has an idle connection need not wait for a dial slot
                guard let i = waiting.firstIndex(where: { idle[$0.target] != nil && $0.acq.completion != nil }) else { return }
                let w = waiting.remove(at: i)
                acquireOnQueue(w.target, w.acq)
                continue
            }
            let w = waiting.removeFirst()
            acquireOnQueue(w.target, w.acq)
        }
    }

    private func popIdle(_ target: UpstreamTarget) -> UpstreamConnection? {
        while var list = idle[target], let e = list.popLast() {
            idle[target] = list.isEmpty ? nil : list
            idleCount -= 1
            stats.idle = idleCount
            e.timer.cancel()
            e.conn.isIdle = false
            e.conn.onIdleEvent = nil
            if e.conn.isReusable { return e.conn }
            stats.idleEvicted += 1
            e.conn.closeOnQueue()
        }
        return nil
    }

    /// Hands a connection back after an exchange. `reusable: false` (or a stream that is no longer clean) closes
    /// it; otherwise it is pooled, evicting the oldest idle connection when a cap is exceeded.
    func release(_ conn: UpstreamConnection, reusable: Bool) {
        queue.async { self.releaseOnQueue(conn, reusable: reusable) }
    }

    private func releaseOnQueue(_ conn: UpstreamConnection, reusable: Bool) {
        conn.requestsServed += 1
        guard reusable, conn.isReusable, config.maxIdlePerHost > 0, config.maxIdleTotal > 0 else {
            conn.closeOnQueue()
            return
        }
        let target = conn.target
        let timer = DispatchWorkItem { [weak self, weak conn] in
            guard let self, let conn else { return }
            if self.remove(conn) { self.stats.idleExpired += 1; conn.closeOnQueue() }
        }
        conn.isIdle = true
        conn.onIdleEvent = { [weak self] c in
            guard let self else { return }
            if self.remove(c) { self.stats.idleEvicted += 1 }
            c.closeOnQueue()
        }
        idle[target, default: []].append(IdleEntry(conn: conn, since: .now(), timer: timer))
        idleCount += 1
        queue.asyncAfter(deadline: .now() + config.idleTimeout, execute: timer)
        // Caps: per host, then global (oldest first).
        while let list = idle[target], list.count > config.maxIdlePerHost { evict(target, list[0].conn) }
        while idleCount > config.maxIdleTotal, let oldest = oldestIdle() { evict(oldest.conn.target, oldest.conn) }
        stats.idle = idleCount
        if conn.isIdle { conn.startIdleProbe() }
        if !waiting.isEmpty { drainWaiting() }
    }

    private func oldestIdle() -> IdleEntry? {
        idle.values.compactMap { $0.first }.min { $0.since < $1.since }
    }

    private func evict(_ target: UpstreamTarget, _ conn: UpstreamConnection) {
        if remove(conn) { stats.idleEvicted += 1 }
        conn.closeOnQueue()
    }

    /// Removes `conn` from the idle lists (false when it was not pooled).
    @discardableResult
    private func remove(_ conn: UpstreamConnection) -> Bool {
        guard var list = idle[conn.target], let i = list.firstIndex(where: { $0.conn === conn }) else { return false }
        list[i].timer.cancel()
        list.remove(at: i)
        idle[conn.target] = list.isEmpty ? nil : list
        idleCount -= 1
        stats.idle = idleCount
        conn.isIdle = false
        conn.onIdleEvent = nil
        return true
    }

    /// Closes every idle connection (all hosts, or only `host`). In-use connections are untouched.
    func closeIdle(host: String? = nil) {
        queue.async {
            for (t, list) in self.idle where host == nil || t.host == host {
                for e in list where self.remove(e.conn) { e.conn.closeOnQueue() }
            }
        }
    }

    /// Stats snapshot, delivered on `queue`.
    func stats(_ completion: @escaping (Stats) -> Void) {
        queue.async { completion(self.stats) }
    }

    /// Synchronous snapshot for tests / diagnostics; must not be called on `queue`.
    func statsNow() -> Stats {
        dispatchPrecondition(condition: .notOnQueue(queue))
        return queue.sync { stats }
    }
}
