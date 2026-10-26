import Foundation

// fix/nc-open-6-10 #7: upstream DNS race across a nameserver group.
//
// build433 device diag: one burst of 18 SERVFAIL right after a core reload — every nameserver "failed" for the
// queries in flight. The group was tried strictly sequentially with a 2.5 s per-server timeout and the first
// server (13.78.100.57, far away) was slow, so one slow server cost every query 2.5 s before the second server
// was even asked. mihomo (dns/util.go batchExchange) asks every nameserver of a group at once and takes the first
// usable answer; Surge sends to several servers and uses the fastest. Here: at most two exchanges in flight, the
// second one staggered by 300 ms (most answers arrive well inside that, so the common case still costs one
// upstream packet), a failed / timed-out exchange immediately starts the next server, and the first answer whose
// rcode is not SERVFAIL / REFUSED wins (such an answer is kept as a last resort, like mihomo).
//
// Pure scheduling logic in Shared (the exchange is injected) so the unit tests drive it with fake servers.

/// What happened to each upstream a query tried — for the per-query failure log line. Bounded (≤ 6 parts).
final class NCDNSAttemptTrace {
    private(set) var parts: [String] = []
    /// The core reloaded while this query was in flight and the query was re-sent on the new config.
    var retriedAfterReload = false
    func add(_ s: String) {
        if parts.count < 6 { parts.append(s) } else if parts.count == 6 { parts.append("…") }
    }
    var summary: String { parts.isEmpty ? "no upstream tried" : parts.joined(separator: "; ") }
}

enum NCDNSRace {
    static let stagger: TimeInterval = 0.3
    static let attemptTimeout: TimeInterval = 2.5
    static let overallTimeout: TimeInterval = 5.0
    static let maxParallel = 2

    /// DNS header rcode (low 4 bits of byte 3); 0 for a too-short message.
    static func rcode(_ d: Data) -> UInt8 {
        d.count >= 4 ? d[d.startIndex + 3] & 0x0F : 0
    }

    /// An answer worth delivering at once: anything but SERVFAIL (2) / REFUSED (5). NXDOMAIN is a real answer.
    static func isUsable(_ d: Data) -> Bool {
        let rc = rcode(d)
        return d.count >= 12 && rc != 2 && rc != 5
    }

    private final class State {
        var next = 0
        var active = 0
        var done = false
        var lastResort: Data?
        /// fix/nc-tails: cancel handles of attempts still unsettled (keyed by launch serial).
        var cancels: [Int: () -> Void] = [:]
    }

    /// Race `list` starting at index `start` (the last server that answered goes first). `exchange` performs one
    /// upstream query and may call back on any queue; all bookkeeping runs on `queue`. `completion` fires exactly
    /// once on `queue` with the winning answer (or the last-resort SERVFAIL/REFUSED answer, or nil) and the index
    /// of the server that produced a usable answer.
    static func run(list: [NCDNSUpstream], start: Int, queue: DispatchQueue, trace: NCDNSAttemptTrace? = nil,
                    stagger: TimeInterval = NCDNSRace.stagger,
                    attemptTimeout: TimeInterval = NCDNSRace.attemptTimeout,
                    overallTimeout: TimeInterval = NCDNSRace.overallTimeout,
                    maxParallel: Int = NCDNSRace.maxParallel,
                    exchange: @escaping (NCDNSUpstream, @escaping (Data?) -> Void) -> Void,
                    completion: @escaping (Data?, Int?) -> Void) {
        run(list: list, start: start, queue: queue, trace: trace, stagger: stagger, attemptTimeout: attemptTimeout,
            overallTimeout: overallTimeout, maxParallel: maxParallel,
            cancellableExchange: { u, done in exchange(u, done); return nil }, completion: completion)
    }

    /// Same race; `cancellableExchange` may return a cancel handle (fix/nc-tails). An attempt that timed out, and
    /// every attempt still running when the race is decided, is cancelled at once — its coordinator slot and socket
    /// are freed instead of being held for the transport's full timeout (see NCDNSUpstreamCoordinator.abandon).
    static func run(list: [NCDNSUpstream], start: Int, queue: DispatchQueue, trace: NCDNSAttemptTrace? = nil,
                    stagger: TimeInterval = NCDNSRace.stagger,
                    attemptTimeout: TimeInterval = NCDNSRace.attemptTimeout,
                    overallTimeout: TimeInterval = NCDNSRace.overallTimeout,
                    maxParallel: Int = NCDNSRace.maxParallel,
                    cancellableExchange exchange: @escaping (NCDNSUpstream, @escaping (Data?) -> Void) -> (() -> Void)?,
                    completion: @escaping (Data?, Int?) -> Void) {
        let count = list.count
        guard count > 0 else { queue.async { completion(nil, nil) }; return }
        let st = State()
        let t0 = DispatchTime.now()
        func ms() -> Int { Int((DispatchTime.now().uptimeNanoseconds &- t0.uptimeNanoseconds) / 1_000_000) }
        func finish(_ resp: Data?, _ idx: Int?) {
            guard !st.done else { return }
            st.done = true
            let losers = st.cancels.values
            st.cancels.removeAll()
            for c in losers { c() }
            completion(resp, idx)
        }
        func launchNextOrFinish() {
            guard !st.done else { return }
            if st.next < count { launch() } else if st.active == 0 { finish(st.lastResort, nil) }
        }
        func launch() {
            guard !st.done, st.next < count else { return }
            let idx = (start + st.next) % count
            st.next += 1
            st.active += 1
            let server = list[idx]
            let began = ms()
            let serial = st.next
            var settled = false
            let cancel = exchange(server) { resp in
                queue.async {
                    guard !settled else { return }
                    settled = true
                    st.cancels.removeValue(forKey: serial)
                    st.active -= 1
                    guard !st.done else { return }
                    if let resp, isUsable(resp) { finish(resp, idx); return }
                    if let resp {
                        trace?.add("\(server.label) rcode \(rcode(resp) == 2 ? "SERVFAIL" : rcode(resp) == 5 ? "REFUSED" : "\(rcode(resp))") \(ms() - began) ms")
                        if st.lastResort == nil { st.lastResort = resp }
                    } else {
                        trace?.add("\(server.label) no answer \(ms() - began) ms")
                    }
                    launchNextOrFinish()
                }
            }
            if !settled, let cancel { st.cancels[serial] = cancel }
            queue.asyncAfter(deadline: .now() + attemptTimeout) {
                guard !settled else { return }
                settled = true
                st.active -= 1
                st.cancels.removeValue(forKey: serial)?()
                guard !st.done else { return }
                trace?.add("\(server.label) timeout \(Int(attemptTimeout * 1000)) ms")
                launchNextOrFinish()
            }
        }
        queue.async {
            launch()
            if count > 1, maxParallel > 1 {
                queue.asyncAfter(deadline: .now() + stagger) {
                    if !st.done, st.active < maxParallel, st.next < count { launch() }
                }
            }
            queue.asyncAfter(deadline: .now() + overallTimeout) {
                guard !st.done else { return }
                trace?.add("gave up after \(Int(overallTimeout * 1000)) ms")
                finish(st.lastResort, nil)
            }
        }
    }
}

extension NCDNSRace {
    /// fix/nc-tails: the group race where every attempt is one coordinated upstream exchange (coalescing + global
    /// cap, NCDNSUpstreamCoordinator) and every attempt the race gives up on is abandoned there — its socket closed
    /// and its slot freed at once. `execute` performs one real exchange with `u` and may return a cancel handle.
    /// NCDNSForwarder.forwardGroup (tunnel) runs on this; the unit tests drive it with fake servers.
    static func runCoordinated(query: Data, list: [NCDNSUpstream], start: Int,
                               coordinator: NCDNSUpstreamCoordinator = .shared,
                               queue: DispatchQueue, trace: NCDNSAttemptTrace? = nil,
                               stagger: TimeInterval = NCDNSRace.stagger,
                               attemptTimeout: TimeInterval = NCDNSRace.attemptTimeout,
                               overallTimeout: TimeInterval = NCDNSRace.overallTimeout,
                               execute: @escaping (NCDNSUpstream, @escaping (Data?) -> Void) -> (() -> Void)?,
                               completion: @escaping (Data?, Int?) -> Void) {
        let suffix = NCDNSForwarder.mergeKeySuffix(query)
        let id = NCDNSForwarder.transactionID(query)
        run(list: list, start: start, queue: queue, trace: trace, stagger: stagger, attemptTimeout: attemptTimeout,
            overallTimeout: overallTimeout,
            cancellableExchange: { u, done in
                let ticket = coordinator.submitCancellable(
                    key: "\(u)|" + suffix, id: id, callerQueue: queue,
                    execute: { finished in execute(u, finished) }, completion: done)
                return { coordinator.abandon(ticket) }
            }, completion: completion)
    }
}

extension NCDNSUpstream {
    /// Short human label for logs: "13.78.100.57", "tls://dns.google", "https://doh.pub/dns-query".
    var label: String {
        switch self {
        case .udp(let h, let p): return p == 53 ? h : "\(h):\(p)"
        case .tcp(let h, let p): return "tcp://\(h)" + (p == 53 ? "" : ":\(p)")
        case .dot(let h, let p): return "tls://\(h)" + (p == 853 ? "" : ":\(p)")
        case .doq(let h, let p): return "quic://\(h)" + (p == 853 ? "" : ":\(p)")
        case .doh(let u): return u.count > 64 ? String(u.prefix(64)) + "…" : u
        case .group(let l): return l.map { $0.label }.joined(separator: ",")
        }
    }
}
