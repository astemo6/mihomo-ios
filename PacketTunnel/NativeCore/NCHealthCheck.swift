import Foundation

/// Reusable HTTP/HTTPS probe and latency measurement core, used by both
/// `NCController` (manual /delay and /group/{name}/delay) and `NCHealthCheckScheduler`
/// (background periodic and lazy health checks).
enum NCDelayTester {
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

    /// Measures multiple group members concurrently (bounded concurrency), reporting both
    /// successes (ms) and failures (nil) for every member. Enforces an overall timeout
    /// so slow or hanging probes never block the engine.
    static func measureGroup(
        groupEngine: NCGroupEngine?,
        members: [String],
        url: String,
        timeoutMs: Int,
        overallTimeoutMs: Int? = nil,
        maxConcurrency: Int = 10,
        queue: DispatchQueue = .global(qos: .userInitiated),
        isCancelled: @escaping () -> Bool = { false },
        completion: @escaping ([String: Int?]) -> Void
    ) {
        guard !members.isEmpty else {
            queue.async { completion([:]) }
            return
        }
        let group = DispatchGroup()
        let lock = NSLock()
        var results: [String: Int?] = [:]
        var finished = false
        let semaphore = DispatchSemaphore(value: max(1, maxConcurrency))

        let finishOnce: ([String: Int?]) -> Void = { res in
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            queue.async { completion(res) }
        }

        let roundTimeout = overallTimeoutMs ?? (timeoutMs + 2000)
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + .milliseconds(roundTimeout)) {
            lock.lock()
            let current = results
            lock.unlock()
            var filled = current
            for m in members where filled[m] == nil {
                filled[m] = nil
            }
            finishOnce(filled)
        }

        for member in members {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                if isCancelled() {
                    lock.lock()
                    if results[member] == nil { results[member] = nil }
                    lock.unlock()
                    group.leave()
                    return
                }
                semaphore.wait()
                if isCancelled() {
                    semaphore.signal()
                    lock.lock()
                    if results[member] == nil { results[member] = nil }
                    lock.unlock()
                    group.leave()
                    return
                }
                measureDelay(groupEngine: groupEngine, name: member, url: url, timeoutMs: timeoutMs) { ms in
                    lock.lock()
                    results[member] = ms
                    lock.unlock()
                    semaphore.signal()
                    group.leave()
                }
            }
        }

        group.notify(queue: DispatchQueue.global(qos: .userInitiated)) {
            lock.lock()
            let res = results
            lock.unlock()
            var filled = res
            for m in members where filled[m] == nil {
                filled[m] = nil
            }
            finishOnce(filled)
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

    /// Called when real traffic resolves through a proxy group.
    func notifyTouch(group groupName: String) {
        queue.async { [weak self] in
            guard let self = self, self.isRunning, let engine = self.engine, let cfg = engine.effectiveConfig else { return }
            guard let g = cfg.groupMap[groupName], g.type == "url-test" || g.type == "fallback" else { return }
            guard g.lazy, !self.activeProbingGroups.contains(g.name) else { return }

            let now = Date()
            let interval = TimeInterval(max(g.interval, 5))
            let lastCheck = self.lastCheckTime[g.name]
            // If never probed or overdue, probe immediately; otherwise schedule
            if lastCheck == nil || now.timeIntervalSince(lastCheck!) >= interval {
                self.probeGroup(g)
            } else {
                self.scheduleNext()
            }
        }
    }

    private func scheduleNext() {
        guard isRunning, let engine = engine, let cfg = engine.effectiveConfig else { return }
        let now = Date()
        let eligible = cfg.groups.filter { $0.type == "url-test" || $0.type == "fallback" }
        guard !eligible.isEmpty else { return }

        var nextDeadline: Date?

        for g in eligible {
            let interval = TimeInterval(max(g.interval, 5))
            if g.lazy {
                let lastTouch = engine.groupEngine?.lastTouch(for: g.name)
                // Lazy: only probe if the group has been used recently (within interval * 2)
                if let lastTouch = lastTouch, now.timeIntervalSince(lastTouch) <= interval * 2 {
                    let due = nextCheckTime[g.name] ?? now
                    if now >= due {
                        probeGroup(g)
                    } else if nextDeadline == nil || due < nextDeadline! {
                        nextDeadline = due
                    }
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

        let now = Date()
        let interval = TimeInterval(max(g.interval, 5))
        nextCheckTime[g.name] = now.addingTimeInterval(interval)
        activeProbingGroups.insert(g.name)

        let testURL = g.url ?? "http://www.gstatic.com/generate_204"
        let timeoutMs = g.fields["timeout"]?.int ?? 5000
        let groupEngine = engine?.groupEngine

        NCDelayTester.measureGroup(
            groupEngine: groupEngine,
            members: g.proxies,
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

    private func armTimer(for deadline: Date?) {
        timer?.cancel()
        timer = nil
        guard isRunning else { return }

        let now = Date()
        let delaySeconds: Double
        if let deadline = deadline {
            delaySeconds = max(0.5, deadline.timeIntervalSince(now))
        } else {
            // Heartbeat check for lazy groups or newly added groups
            delaySeconds = 60.0
        }

        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + delaySeconds)
        t.setEventHandler { [weak self] in
            self?.scheduleNext()
        }
        t.resume()
        timer = t
    }
}
