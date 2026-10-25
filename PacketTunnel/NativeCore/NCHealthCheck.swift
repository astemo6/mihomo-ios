import Foundation

/// Reusable HTTP/HTTPS probe and latency measurement core, used by both
/// `NCController` (manual /delay and /group/{name}/delay) and `NCHealthCheckScheduler`
/// (background periodic and lazy health checks).
enum NCTunnelDelayTester {
    static func httpTarget(_ urlString: String) -> (host: String, port: Int, tls: Bool, path: String)? {
        guard let url = URL(string: urlString), let host = url.host else { return nil }
        let tls = url.scheme == "https"
        let port = url.port ?? (tls ? 443 : 80)
        let path = url.path.isEmpty ? "/" : url.path
        return (host, port, tls, path)
    }

    static func httpProbe(stream: NCStream, target: (host: String, port: Int, tls: Bool, path: String),
                          start: Date, finish: @escaping (Int?) -> Void) {
        stream.send(Data("GET \(target.path) HTTP/1.1\r\nHost: \(target.host)\r\nConnection: close\r\n\r\n".utf8))
        stream.receive { data, _ in
            if data != nil {
                finish(Int(Date().timeIntervalSince(start) * 1000))
            } else {
                finish(nil)
            }
            stream.cancel()
        }
    }

    static func httpProbe(relay: NCRelayStream, target: (host: String, port: Int, tls: Bool, path: String),
                          start: Date, finish: @escaping (Int?) -> Void) {
        relay.send(Data("GET \(target.path) HTTP/1.1\r\nHost: \(target.host)\r\nConnection: close\r\n\r\n".utf8))
        relay.receive { data, _ in
            if data != nil {
                finish(Int(Date().timeIntervalSince(start) * 1000))
            } else {
                finish(nil)
            }
            relay.cancel()
        }
    }

    /// End-to-end delay through the named node (or resolution):
    /// open a relay to the test URL and time until the first response byte.
    static func measureDelay(
        groupEngine: NCGroupEngine?,
        name: String,
        url: String,
        timeoutMs: Int,
        completion: @escaping (Int?) -> Void
    ) {
        guard let groups = groupEngine else {
            completion(nil)
            return
        }
        let resolution = groups.resolve(name)
        guard let target = httpTarget(url) else {
            completion(nil)
            return
        }
        let start = Date()
        var done = false
        let lock = NSLock()
        var streamToCancel: NCStream?
        var relayToCancel: NCRelayStream?

        let finish: (Int?) -> Void = { ms in
            lock.lock()
            guard !done else {
                lock.unlock()
                return
            }
            done = true
            let s = streamToCancel
            let r = relayToCancel
            streamToCancel = nil
            relayToCancel = nil
            lock.unlock()

            s?.cancel()
            r?.cancel()
            completion(ms)
        }

        let workQueue = DispatchQueue(label: "nc.delay", qos: .userInitiated)
        workQueue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { finish(nil) }

        if case .direct = resolution {
            let stream = target.tls
                ? NCStream(to: target.host, port: target.port, tlsServerName: target.host, allowInsecure: false, queue: workQueue)
                : NCStream(to: target.host, port: target.port, queue: workQueue)
            lock.lock()
            if done {
                lock.unlock()
                return
            }
            streamToCancel = stream
            lock.unlock()

            stream.start { err in
                if err != nil { finish(nil); return }
                httpProbe(stream: stream, target: target, start: start, finish: finish)
            }
            return
        }

        NCConnector.connect(target: NCTarget(host: target.host, port: target.port), resolution: resolution, queue: workQueue) { relay, _ in
            guard let relay else { finish(nil); return }
            lock.lock()
            if done {
                lock.unlock()
                relay.cancel()
                return
            }
            relayToCancel = relay
            lock.unlock()

            if target.tls {
                let tlsStream = NCTLSClientStream(raw: relay,
                                                  config: .init(serverName: target.host, alpn: ["http/1.1"]),
                                                  queue: workQueue)
                lock.lock()
                if done {
                    lock.unlock()
                    relay.cancel()
                    return
                }
                relayToCancel = tlsStream
                lock.unlock()

                tlsStream.startHandshake { err in
                    if err != nil { finish(nil); return }
                    httpProbe(relay: tlsStream, target: target, start: start, finish: finish)
                }
            } else {
                httpProbe(relay: relay, target: target, start: start, finish: finish)
            }
        }
    }

    /// Measures multiple group members concurrently (bounded concurrency), reporting
    /// successes (ms) and failures (nil). A per-member timeout plus an overall round
    /// timeout (scaled to the member count) keep hung probes from stalling the caller;
    /// members that miss the round are absent from the result, not marked dead.
    ///
    /// rv2-life: fully asynchronous — at most `maxConcurrency` probes are in flight and each finished probe starts
    /// the next one. It used to park one global-queue thread per member on a semaphore (a 200-node group = ~64
    /// blocked GCD worker threads, 512 KB stack reservation each, starving every other global-queue user).
    /// 6 in flight: the leanest of the reference clients' group tests, and each probe costs a socket + TLS state.
    static let defaultGroupConcurrency = 6

    static func measureGroup(
        groupEngine: NCGroupEngine?,
        members: [String],
        url: String,
        timeoutMs: Int,
        overallTimeoutMs: Int? = nil,
        maxConcurrency: Int = defaultGroupConcurrency,
        queue: DispatchQueue = .global(qos: .userInitiated),
        isCancelled: @escaping () -> Bool = { false },
        completion: @escaping ([String: Int?]) -> Void
    ) {
        guard !members.isEmpty else {
            queue.async { completion([:]) }
            return
        }
        let run = GroupRun(groupEngine: groupEngine, members: members, url: url, timeoutMs: timeoutMs,
                           queue: queue, isCancelled: isCancelled, completion: completion)
        let limit = max(1, min(maxConcurrency, members.count))
        // Bound the round so hung members can never stall the caller: every member
        // gets its own timeout, plus slack for queueing behind the concurrency cap.
        let rounds = (members.count + limit - 1) / limit
        let roundTimeout = overallTimeoutMs ?? roundTimeoutMs(timeoutMs: timeoutMs, rounds: rounds)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(roundTimeout)) { run.finish() }
        for _ in 0..<limit { run.launchNext() }
    }

    /// timeoutMs × rounds + 5 s slack, saturating: the per-member timeout comes from config (`timeout:`) or the
    /// controller's `?timeout=` query, and a huge value overflowed Int and trapped the tunnel.
    static func roundTimeoutMs(timeoutMs: Int, rounds: Int) -> Int {
        let (scaled, o1) = timeoutMs.multipliedReportingOverflow(by: rounds)
        if o1 { return (timeoutMs < 0) != (rounds < 0) ? 0 : Int.max } // a negative product: fire at once
        let (sum, o2) = scaled.addingReportingOverflow(5000)
        return o2 ? Int.max : sum
    }

    /// One group round: a cursor over the members, a running count, the results (all under `lock`).
    private final class GroupRun {
        let groupEngine: NCGroupEngine?
        let members: [String]
        let url: String
        let timeoutMs: Int
        let queue: DispatchQueue
        let isCancelled: () -> Bool
        var completion: (([String: Int?]) -> Void)?
        let lock = NSLock()
        var next = 0
        var running = 0
        var results: [String: Int?] = [:]

        init(groupEngine: NCGroupEngine?, members: [String], url: String, timeoutMs: Int, queue: DispatchQueue,
             isCancelled: @escaping () -> Bool, completion: @escaping ([String: Int?]) -> Void) {
            self.groupEngine = groupEngine
            self.members = members
            self.url = url
            self.timeoutMs = timeoutMs
            self.queue = queue
            self.isCancelled = isCancelled
            self.completion = completion
        }

        func launchNext() {
            let cancelled = isCancelled() // outside our lock: it takes the scheduler's
            lock.lock()
            guard completion != nil, !cancelled, next < members.count else {
                let idle = running == 0
                lock.unlock()
                if idle { finish() }
                return
            }
            let member = members[next]
            next += 1
            running += 1
            lock.unlock()
            NCTunnelDelayTester.measureDelay(groupEngine: groupEngine, name: member, url: url, timeoutMs: timeoutMs) { ms in
                self.lock.lock()
                if self.completion != nil { self.results[member] = ms }
                self.running -= 1
                self.lock.unlock()
                self.launchNext()
            }
        }

        /// Delivers the results so far, once (round timeout, all done, or cancelled with nothing running).
        func finish() {
            lock.lock()
            guard let done = completion else { lock.unlock(); return }
            completion = nil
            let res = results
            lock.unlock()
            queue.async { done(res) }
        }
    }
}

/// Single background scheduler for native core health checks (url-test and fallback groups),
/// aligning with mihomo health-check semantics.
final class NCHealthCheckScheduler {
    private weak var engine: NativeCoreEngine?
    private let queue = DispatchQueue(label: "nc.healthcheck", qos: .utility)
    private var timer: DispatchSourceTimer?

    private let stateLock = NSLock()
    private var _isRunning: Bool = false
    var isRunning: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _isRunning
        }
        set {
            stateLock.lock()
            _isRunning = newValue
            stateLock.unlock()
        }
    }

    private var activeProbingGroups: Set<String> = []
    private var lastCheckTime: [String: Date] = [:]
    private var nextCheckTime: [String: Date] = [:]

    init(engine: NativeCoreEngine) {
        self.engine = engine
    }

    func start() {
        isRunning = true
        queue.async { [weak self] in
            self?.scheduleNext()
        }
    }

    func stop() {
        isRunning = false
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
            self?.activeProbingGroups.removeAll()
        }
    }

    func updateConfig() {
        queue.async { [weak self] in
            guard let self = self, self.isRunning else { return }
            self.scheduleNext()
        }
    }

    /// Called when real traffic resolves through a proxy group. Lazy groups only
    /// probe on use, so a touch is their wake-up call; non-lazy groups ignore it.
    func notifyTouch(group groupName: String) {
        queue.async { [weak self] in
            guard let self = self, self.isRunning, let engine = self.engine, let cfg = engine.effectiveConfig else { return }
            guard let g = cfg.groupMap[groupName], g.type == "url-test" || g.type == "fallback", g.lazy else { return }
            guard !self.activeProbingGroups.contains(g.name) else { return }
            // Never probed or overdue → probe now; otherwise the armed timer
            // already covers the next round.
            let now = Date()
            let interval = TimeInterval(max(g.interval, 5))
            if let lastCheck = self.lastCheckTime[g.name], now.timeIntervalSince(lastCheck) < interval {
                self.scheduleNext()
                return
            }
            self.probeGroup(g)
        }
    }

    private func scheduleNext() {
        guard isRunning, let engine = engine, let cfg = engine.effectiveConfig else { return }
        let now = Date()
        let eligible = cfg.groups.filter { $0.type == "url-test" || $0.type == "fallback" }
        guard !eligible.isEmpty else {
            armTimer(for: nil)
            return
        }
        let eligibleNames = Set(eligible.map(\.name))
        // Forget bookkeeping for groups the (reloaded) config no longer knows.
        nextCheckTime = nextCheckTime.filter { eligibleNames.contains($0.key) }
        lastCheckTime = lastCheckTime.filter { eligibleNames.contains($0.key) }
        activeProbingGroups = activeProbingGroups.filter(eligibleNames.contains)

        var nextDeadline: Date?

        for g in eligible {
            let interval = TimeInterval(max(g.interval, 5))
            if g.lazy {
                // Lazy (mihomo semantics): only probe groups the tunnel actually
                // used recently; unused groups sleep until touched.
                guard let lastTouch = engine.groupEngine?.lastTouch(for: g.name),
                      now.timeIntervalSince(lastTouch) <= interval * 2 else { continue }
                let due = nextCheckTime[g.name] ?? now
                if now >= due {
                    probeGroup(g)
                } else if nextDeadline == nil || due < nextDeadline! {
                    nextDeadline = due
                }
            } else {
                // Non-lazy: probe continuously on schedule
                let due = nextCheckTime[g.name] ?? now
                if now >= due {
                    probeGroup(g)
                } else if nextDeadline == nil || due < nextDeadline! {
                    nextDeadline = due
                }
            }
        }

        armTimer(for: nextDeadline)
    }

    private func probeGroup(_ g: NCProxyGroup) {
        guard isRunning, !activeProbingGroups.contains(g.name) else { return }
        guard !g.proxies.isEmpty else { return }

        let groupEngine = engine?.groupEngine
        // Nodes the connector cannot dial are already avoided by selection;
        // probing them would only burn a timeout.
        let members = g.proxies.filter { !(groupEngine?.unsupported.contains($0) ?? false) }
        guard !members.isEmpty else { return }

        let now = Date()
        let interval = TimeInterval(max(g.interval, 5))
        nextCheckTime[g.name] = now.addingTimeInterval(interval)
        activeProbingGroups.insert(g.name)

        let testURL = g.url ?? "http://www.gstatic.com/generate_204"
        let timeoutMs = g.fields["timeout"]?.int ?? 5000

        NCTunnelDelayTester.measureGroup(
            groupEngine: groupEngine,
            members: members,
            url: testURL,
            timeoutMs: timeoutMs,
            queue: queue,
            isCancelled: { [weak self] in self?.isRunning != true }
        ) { [weak self] results in
            guard let self = self, self.isRunning else { return }
            self.activeProbingGroups.remove(g.name)
            self.lastCheckTime[g.name] = Date()

            if let engine = self.engine {
                for (member, ms) in results {
                    if let ms = ms {
                        engine.recordDelay(name: member, ms: ms)
                    } else {
                        engine.recordFailure(name: member)
                    }
                }
            }

            self.scheduleNext()
        }
    }

    /// Arms the single timer for the earliest pending deadline. nil means
    /// nothing is due (e.g. only lazy groups the tunnel has not used yet): no
    /// timer is armed, since touches (notifyTouch) and config reloads
    /// (updateConfig) wake the scheduler on demand.
    private func armTimer(for deadline: Date?) {
        timer?.cancel()
        timer = nil
        guard isRunning, let deadline else { return }

        let delaySeconds = max(0.5, deadline.timeIntervalSince(Date()))
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + delaySeconds)
        t.setEventHandler { [weak self] in
            self?.scheduleNext()
        }
        t.resume()
        timer = t
    }
}
