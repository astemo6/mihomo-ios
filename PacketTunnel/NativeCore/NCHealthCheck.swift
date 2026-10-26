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

    /// fix/nc-delay-test: what one probe found — the delay, or why and where it gave up, plus the stage split.
    struct Outcome {
        var ms: Int?
        /// "timeout" or "error".
        var failure: String?
        /// The stage the probe was in when it failed (dns / tcp / tls / connect / ws / grpc / h2 / inner-tls /
        /// request / dial), nil on success.
        var stage: String?
        /// The underlying error text, when there was one.
        var error: String?
        /// Stage durations ("dns 40 ms (cache, …) · tcp 180 ms · tls 190 ms · ws 210 ms · request 260 ms").
        var stages: String
        var unified: Bool

        /// The message the controller's delay API returns on failure.
        var message: String {
            guard ms == nil else { return "ok" }
            let at = stage.map { " at stage \($0)" } ?? ""
            let why = error.map { " (\($0))" } ?? ""
            return failure == "timeout" ? "Timeout\(at)\(why)" : "An error occurred in the delay test\(at)\(why)"
        }
    }

    /// Lines per 10 s for probe diagnostics (a 20-node group test fits; background health checks only log failures).
    private static let probeLimiter = NCLineLimiter(perWindow: 40, window: 10)

    /// One core-log line per probe: "[delay] <node>: 245 ms (unified) | dns … · tcp … · request …" or
    /// "[delay] <node>: timeout at stage ws after 5000 ms (error) | …".
    static func logLine(name: String, outcome o: Outcome, timeoutMs: Int) -> String {
        let head: String
        if let ms = o.ms {
            head = "[delay] \(name): \(ms) ms\(o.unified ? " (unified)" : "")"
        } else if o.failure == "timeout" {
            head = "[delay] \(name): timeout at stage \(o.stage ?? "dial") after \(timeoutMs) ms" + (o.error.map { " (\($0))" } ?? "")
        } else {
            head = "[delay] \(name): failed at stage \(o.stage ?? "dial")" + (o.error.map { " (\($0))" } ?? "")
        }
        return o.stages.isEmpty ? head : "\(head) | \(o.stages)"
    }

    private static func emit(name: String, outcome: Outcome, timeoutMs: Int, logSuccess: Bool) {
        guard let sink = NCDialTrace.logSink, logSuccess || outcome.ms == nil else { return }
        let (ok, dropped) = probeLimiter.admit()
        guard ok else { return }
        if dropped > 0 { sink("[delay] \(dropped) probe line(s) suppressed", false) }
        sink(logLine(name: name, outcome: outcome, timeoutMs: timeoutMs), outcome.ms == nil)
    }

    /// The test request: HEAD like mihomo's URLTest; keep-alive when a second (unified) request follows.
    static func request(_ target: (host: String, port: Int, tls: Bool, path: String), keepAlive: Bool) -> Data {
        let hostHeader = (target.port == (target.tls ? 443 : 80)) ? target.host : "\(target.host):\(target.port)"
        return Data("HEAD \(target.path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: \(keepAlive ? "keep-alive" : "close")\r\n\r\n".utf8)
    }

    enum ResponseHead: Equatable { case incomplete, complete(reusable: Bool), invalid }

    /// Whether `buf` holds a complete HTTP/1.x response head, and whether the connection may carry another request
    /// (no "Connection: close", HTTP/1.1 or explicit keep-alive). HEAD responses have no body.
    static func parseHead(_ buf: Data) -> ResponseHead {
        if buf.count >= 5, !buf.starts(with: Data("HTTP/".utf8)) { return .invalid }
        guard let end = buf.range(of: Data("\r\n\r\n".utf8)) else { return buf.count > 16_384 ? .invalid : .incomplete }
        let head = String(decoding: buf[buf.startIndex..<end.lowerBound], as: UTF8.self).lowercased()
        let lines = head.split(separator: "\r\n")
        guard let status = lines.first, status.hasPrefix("http/1.") else { return .invalid }
        let conn = lines.dropFirst().first { $0.hasPrefix("connection:") }?.dropFirst("connection:".count)
            .trimmingCharacters(in: .whitespaces)
        if conn == "close" { return .complete(reusable: false) }
        if status.hasPrefix("http/1.0") { return .complete(reusable: conn == "keep-alive") }
        return .complete(reusable: true)
    }

    /// Request/response over an established stream (plain or the inner TLS of an https test URL).
    /// Cold: time from the probe start (dial included) to the first response byte — mihomo with unified-delay off.
    /// Unified (mihomo `unified-delay: true`, which the App's runtime config always sets): after the first response
    /// head, a second HEAD on the same connection is timed alone; if the server will not reuse the connection or the
    /// second request fails, the cold time stands (mihomo URLTest does the same).
    final class HTTPExchange {
        let relay: NCRelayStream
        let target: (host: String, port: Int, tls: Bool, path: String)
        let unified: Bool
        let trace: NCDialTrace?
        let start: DispatchTime
        let finish: (Int?, String?) -> Void
        private var buf = Data()
        private var second = false
        private var firstMs: Int?
        private var t2 = DispatchTime.now()

        init(relay: NCRelayStream, target: (host: String, port: Int, tls: Bool, path: String), unified: Bool,
             trace: NCDialTrace?, start: DispatchTime, finish: @escaping (Int?, String?) -> Void) {
            self.relay = relay
            self.target = target
            self.unified = unified
            self.trace = trace
            self.start = start
            self.finish = finish
        }

        func run() {
            trace?.begin("request")
            relay.send(NCTunnelDelayTester.request(target, keepAlive: unified))
            next()
        }

        private func next() {
            relay.receive { [self] data, err in
                guard let data, !data.isEmpty else {
                    if second, let firstMs {
                        trace?.end("request2", error: err)
                        trace?.note("unified: 2nd request failed, cold time kept")
                        finish(firstMs, nil)
                    } else {
                        let why = err.map(NCDialTrace.describe) ?? "connection closed before any response"
                        trace?.end("request", error: err)
                        trace?.fail("request: \(why)")
                        finish(nil, "request: \(why)")
                    }
                    return
                }
                if second {
                    trace?.end("request2")
                    finish(NCDialTrace.ms(from: t2, to: .now()), nil)
                    return
                }
                if firstMs == nil {
                    firstMs = NCDialTrace.ms(from: start, to: .now())
                    trace?.end("request")
                }
                guard unified else { finish(firstMs, nil); return }
                buf.append(data)
                switch NCTunnelDelayTester.parseHead(buf) {
                case .incomplete:
                    next()
                case .invalid, .complete(reusable: false):
                    trace?.note("unified: connection not reusable, cold time")
                    finish(firstMs, nil)
                case .complete(reusable: true):
                    second = true
                    buf = Data()
                    t2 = .now()
                    trace?.begin("request2")
                    relay.send(NCTunnelDelayTester.request(target, keepAlive: false))
                    next()
                }
            }
        }
    }

    /// Back-compat entry (background health checks): delay or nil.
    static func measureDelay(
        groupEngine: NCGroupEngine?,
        name: String,
        url: String,
        timeoutMs: Int,
        unified: Bool = false,
        logSuccess: Bool = false,
        completion: @escaping (Int?) -> Void
    ) {
        measure(groupEngine: groupEngine, name: name, url: url, timeoutMs: timeoutMs, unified: unified,
                logSuccess: logSuccess) { completion($0.ms) }
    }

    /// End-to-end delay through the named node (or group's resolution): dial the test URL through it and time the
    /// response (see HTTPExchange for cold vs unified). The timeout runs from this probe's own start, on its own
    /// serial queue, so a probe never waits on another. Every probe leaves one `[delay]` line (successes only when
    /// `logSuccess`) with the stage split.
    static func measure(
        groupEngine: NCGroupEngine?,
        name: String,
        url: String,
        timeoutMs: Int,
        unified: Bool,
        logSuccess: Bool = true,
        completion: @escaping (Outcome) -> Void
    ) {
        let timeoutMs = max(1, timeoutMs)
        guard let groups = groupEngine else {
            completion(Outcome(ms: nil, failure: "error", stage: nil, error: "core not running", stages: "", unified: unified))
            return
        }
        guard let target = httpTarget(url) else {
            completion(Outcome(ms: nil, failure: "error", stage: nil, error: "bad test URL \(url.prefix(80))", stages: "", unified: unified))
            return
        }
        let resolution = groups.resolve(name)
        let trace = NCDialTrace()
        let start = trace.start
        var done = false
        let lock = NSLock()
        var toCancel: [NCRelayStream] = []

        let workQueue = DispatchQueue(label: "nc.delay", qos: .userInitiated)
        workQueue.setSpecific(key: NCDialTrace.key, value: trace)

        let finish: (Int?, String?, Bool) -> Void = { ms, err, timedOut in
            lock.lock()
            guard !done else { lock.unlock(); return }
            done = true
            let cancel = toCancel
            toCancel = []
            lock.unlock()
            cancel.forEach { $0.cancel() }
            var o = Outcome(ms: ms, failure: nil, stage: nil, error: nil, stages: "", unified: unified)
            if ms == nil {
                o.failure = timedOut ? "timeout" : "error"
                o.stage = trace.openStage
                o.error = err ?? trace.lastError
            }
            // The establishment report is delivered on the work queue right after .ready; read the split after it.
            let pre = o
            workQueue.async {
                var o = pre
                o.stages = trace.summary
                emit(name: name, outcome: o, timeoutMs: timeoutMs, logSuccess: logSuccess)
                completion(o)
            }
        }
        let keep: (NCRelayStream) -> Bool = { s in
            lock.lock(); defer { lock.unlock() }
            if done { return false }
            toCancel.append(s)
            return true
        }

        workQueue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { finish(nil, nil, true) }

        let exchange: (NCRelayStream) -> Void = { relay in
            HTTPExchange(relay: relay, target: target, unified: unified, trace: trace, start: start) { ms, err in
                finish(ms, err, false)
            }.run()
        }

        if case .direct = resolution {
            let stream = target.tls
                ? NCStream(to: target.host, port: target.port, tlsServerName: target.host, allowInsecure: false, queue: workQueue)
                : NCStream(to: target.host, port: target.port, queue: workQueue)
            guard keep(stream) else { return }
            stream.start { err in
                if let err { finish(nil, "connect: \(NCDialTrace.describe(err))", false); return }
                exchange(stream)
            }
            return
        }
        if case .unknown(let n) = resolution {
            workQueue.async { finish(nil, NCConnector.Failure.unknownPolicy(n).description, false) }
            return
        }

        trace.begin("dial")
        NCConnector.connect(target: NCTarget(host: target.host, port: target.port), resolution: resolution, queue: workQueue) { relay, err in
            trace.end("dial", error: err)
            guard let relay else {
                finish(nil, err.map(NCDialTrace.describe) ?? "dial failed", false)
                return
            }
            guard keep(relay) else { relay.cancel(); return }
            guard target.tls else { exchange(relay); return }
            let tlsStream = NCTLSClientStream(raw: relay, config: .init(serverName: target.host, alpn: ["http/1.1"]), queue: workQueue)
            guard keep(tlsStream) else { return }
            trace.begin("inner-tls")
            tlsStream.startHandshake { herr in
                trace.end("inner-tls", error: herr)
                if let herr { finish(nil, "inner-tls: \(NCDialTrace.describe(herr))", false); return }
                exchange(tlsStream)
            }
        }
    }

    /// 测速设置 → TCP 握手延迟 (Go bridge /tern/node-tcp-delay): TCP connect time to the node's server for nodes that
    /// dial their server over TCP directly; nil `proxy` / UDP-based / dialer-proxy nodes → nil (caller URL-tests).
    static func tcpCapable(_ p: NCProxy) -> Bool {
        let udpTypes: Set<String> = ["hysteria", "hysteria2", "hy2", "tuic", "wireguard", "tailscale", "juicity", "masque"]
        if udpTypes.contains(p.type) { return false }
        if let d = p.fields["dialer-proxy"]?.string, !d.isEmpty { return false }
        return p.server != nil && p.port != nil
    }

    static func tcpHandshake(host: String, port: Int, timeoutMs: Int, completion: @escaping (Int?, String?) -> Void) {
        let q = DispatchQueue(label: "nc.tcpdelay", qos: .userInitiated)
        let s = NCStream(to: host, port: port, queue: q)
        var fired = false
        let start = DispatchTime.now()
        let done: (Int?, String?) -> Void = { ms, e in
            guard !fired else { return }
            fired = true
            s.cancel()
            completion(ms, e)
        }
        q.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs))) { done(nil, "timeout") }
        s.start { err in
            q.async {
                if let err { done(nil, NCDialTrace.describe(err)); return }
                let total = NCDialTrace.ms(from: start, to: .now())
                // The TCP handshake alone (DNS excluded), like the Go route; the whole connect if no report.
                s.conn.requestEstablishmentReport(queue: q) { r in
                    let tcp = r?.handshakes.first { $0.definition.name.lowercased().contains("tcp") }
                    done(max(1, tcp.map { Int($0.handshakeDuration * 1000) } ?? total), nil)
                }
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
        unified: Bool = false,
        logSuccess: Bool = false,
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
        run.unified = unified
        run.logSuccess = logSuccess
        let limit = max(1, min(maxConcurrency, members.count))
        // Bound the round so hung members can never stall the caller: every member
        // gets its own timeout, plus slack for queueing behind the concurrency cap.
        let rounds = (members.count + limit - 1) / limit
        let roundTimeout = overallTimeoutMs ?? roundTimeoutMs(timeoutMs: timeoutMs, rounds: rounds)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(roundTimeout)) { run.finish() }
        for _ in 0..<limit { run.launchNext() }
    }

    /// fix/nc-delay-test: the manual group test (GET /group/{name}/delay) answers within the App's request timeout
    /// (timeout + 10 s): the round is capped at timeout + 9 s; members still running then are left out (= timeout).
    static func manualRoundTimeoutMs(timeoutMs: Int, members: Int, concurrency: Int) -> Int {
        let limit = max(1, min(concurrency, members))
        let rounds = (max(members, 1) + limit - 1) / limit
        let (cap, o) = max(timeoutMs, 0).addingReportingOverflow(9000)
        return min(roundTimeoutMs(timeoutMs: timeoutMs, rounds: rounds), o ? Int.max : cap)
    }

    /// Concurrency of a manual group test: the App's own per-member test window is 10 as well.
    static let manualGroupConcurrency = 10

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
        var unified = false
        var logSuccess = false
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
            NCTunnelDelayTester.measureDelay(groupEngine: groupEngine, name: member, url: url, timeoutMs: timeoutMs,
                                             unified: unified, logSuccess: logSuccess) { ms in
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
            unified: engine?.unifiedDelay ?? false,
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

extension NativeCoreEngine {
    /// fix/nc-delay-test: mihomo `unified-delay` (top-level). The App's runtime config always sets it to true
    /// (NCRuntimeBuilder), which is what the Go core measured with; the native core used to ignore it and report
    /// cold-connection times (node DNS + TCP + TLS + ws upgrade + inner TLS + request ≈ 1 s on a CDN node).
    var unifiedDelay: Bool {
        guard let v = effectiveConfig?.raw["unified-delay"] else { return false }
        return v.bool ?? (v.string?.lowercased() == "true")
    }
}
