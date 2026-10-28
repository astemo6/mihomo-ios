import Foundation
import Network
import os

/// Pure Swift upstream connector using NCConnector and NCStream.
/// Replaces the old core HTTP CONNECT loopback relay.
final class NCUpstreamConnector: MitmUpstreamConnecting {
    /// nc-perf: one shared dial queue for every open (was a fresh DispatchQueue per open).
    /// Serial and on the shared session target — the #116 session-queue pattern: the leases'
    /// ByteStreams confine their hand-offs to it exactly like they did to a per-open queue,
    /// and dialling no longer creates a queue (and its thread bookkeeping) per connection.
    private static let dialQueue = DispatchQueue(label: "nc.upstream.dial", qos: .userInitiated,
                                                 target: NCSessionQueues.target)

    static let shared: NCUpstreamConnector = {
        let c = NCUpstreamConnector()
        UpstreamPoolConnector.nativeConnector = c
        return c
    }()

    func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        // The MitM entry (NativeMitmRuntime installs the shared connector as its upstream): its route is logged.
        open(host: host, port: port, tls: tls, policy: nil, insecure: false, alpn: ["http/1.1"], route: nil,
             logRoute: true, completion: completion)
    }

    /// policy: an explicit proxy / group / DIRECT / REJECT name instead of the rule match ($httpClient `policy`);
    /// unknown names fail. insecure: skip origin certificate verification ($httpClient `insecure`).
    /// (astemo6/Muse NativeCore, 2026-10-25)
    func open(host: String, port: Int, tls: Bool, policy: String?, insecure: Bool,
              completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        open(host: host, port: port, tls: tls, policy: policy, insecure: insecure, alpn: ["http/1.1"], completion: completion)
    }

    /// alpn: offered to the origin on the proxied TLS path (the h2 MitM upstream offers "h2", "http/1.1"); the
    /// lease's `negotiatedALPN` says what the origin picked (feat/nc-proto2, based on astemo6/Muse NativeCore).
    func open(host: String, port: Int, tls: Bool, policy: String?, insecure: Bool, alpn: [String],
              completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        open(host: host, port: port, tls: tls, policy: policy, insecure: insecure, alpn: alpn, route: nil, completion: completion)
    }

    // MARK: fix/nc-0.20.3-diag — connection reuse, dial pacing, route log

    /// Finished keep-alive upstream connections (route + origin key). 15 s: well inside common origin / CDN idle
    /// timeouts, so a parked connection is rarely dead when taken; NativeMitmSession retries a request whose reused
    /// connection fails before the response head. ≤ 2 per origin, ≤ 12 overall (memory first: each holds its relay).
    static let idlePool = NCIdlePool<NCRelayUpstreamLease>(ttl: 15, maxPerKey: 2, maxTotal: 12,
                                                       discard: { $0.closeNow() })
    /// At most 4 dials in flight per proxy node; the rest queue (a decrypted app's launch burst no longer turns into
    /// dozens of simultaneous TLS + ws upgrades against one CDN host).
    static let dialGate = NCDialGate.sharedNodeGate
    /// One more try for a transient proxied dial failure, after this pause (+ up to the same again, jittered).
    static var retryDelay: TimeInterval = 0.4
    /// Counters for 诊断 / the tests.
    private static let statsLock = NSLock()
    private static var _dials = 0, _reuses = 0, _retries = 0
    static var stats: (dials: Int, reuses: Int, retries: Int) {
        statsLock.lock(); defer { statsLock.unlock() }; return (_dials, _reuses, _retries)
    }
    private static func count(dial: Int = 0, reuse: Int = 0, retry: Int = 0) {
        statsLock.lock(); _dials += dial; _reuses += reuse; _retries += retry; statsLock.unlock()
    }
    /// Route log: one line per host per minute ("[MITM] upstream host:port → rule … → policy (node)").
    private static let routeLogLock = NSLock()
    private static var routeLogged: [String: TimeInterval] = [:]
    static func logRouteOnce(_ key: String, _ line: String, now: TimeInterval = Date().timeIntervalSince1970) {
        routeLogLock.lock()
        let last = routeLogged[key]
        let fire = last == nil || now - last! >= 60
        if fire {
            if routeLogged.count > 256 { routeLogged.removeAll() }
            routeLogged[key] = now
        }
        routeLogLock.unlock()
        if fire { NCDiagLimiter.shared.line(line) }
    }

    /// "rule → policy (node chain)" for logs and error texts.
    static func routeText(policy: String, rule: String, resolution: NCGroupEngine.Resolution) -> String {
        let chain: String = switch resolution {
        case .direct: "DIRECT"
        case .reject: "REJECT"
        case .proxy(let p): p.name
        case .chain(let ps): ps.map { $0.name }.joined(separator: " -> ")
        case .unknown(let n): n
        }
        let r = rule.isEmpty ? "" : "rule \(rule) → "
        return policy == chain || policy.isEmpty ? r + chain : r + "\(policy) (\(chain))"
    }

    /// The node a resolution dials first (the dial gate's key); nil for DIRECT / REJECT.
    static func gateKey(_ resolution: NCGroupEngine.Resolution) -> String? {
        switch resolution {
        case .proxy(let p): return "\(p.name)|\(p.server ?? "")|\(p.port ?? 0)"
        case .chain(let ps): return ps.first.map { "\($0.name)|\($0.server ?? "")|\($0.port ?? 0)" }
        default: return nil
        }
    }

    /// fix/nc-open-6-10 #9: `route` (when given) receives the rule / policy / chain this open used, for
    /// /app/stats (script requests). The routing itself is unchanged.
    /// logRoute: the MitM paths — the chosen route goes to the core log (once per host per minute) and every dial
    /// failure names the policy / node it went through.
    func open(host: String, port: Int, tls: Bool, policy: String?, insecure: Bool, alpn: [String], route: NCUpstreamRoute?,
              logRoute: Bool = false, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        let queue = Self.dialQueue
        let target = NCTarget(host: host, port: port)

        let explicit = policy?.trimmingCharacters(in: .whitespaces) ?? ""
        if !explicit.isEmpty {
            let up = explicit.uppercased()
            if up == "REJECT" || up == "REJECT-DROP" || up == "REJECT-TINYGIF" || up == "REJECT-NO-DROP" {
                completion(.failure(UpstreamError.proxyRefused(status: 403, reason: "rejected by policy \(explicit)")))
                return
            }
        }
        // fix/nc-diag-439 (A4): the rule match for an upstream (MitM forward, script $httpClient) used to be a
        // domain-only, never-resolving match — every IP rule (RULE-SET over IP-ASN / IP-CIDR, GEOIP) was skipped, so a
        // MitM-decrypted China host went MATCH → proxy while its own TUN flow went DIRECT. Now the same
        // resolve-then-continue matcher as the data plane (routeAsync: one A lookup through the kernel DNS when an IP
        // rule without no-resolve is reached), so both sides agree.
        let decide: (@escaping (NCGroupEngine.Resolution?, String, String) -> Void) -> Void = { next in
            if !explicit.isEmpty {
                if explicit.uppercased() == "DIRECT" { return next(.direct, explicit, "policy=\(explicit)") }
                return next(NativeCoreEngine.active?.resolve(policyName: explicit), explicit, "policy=\(explicit)")
            }
            guard let engine = NativeCoreEngine.active else { return next(.direct, "DIRECT", "") }
            let ctx = engine.matchContext(domain: NCIP(host) == nil ? host : nil, ip: NCIP(host), dstPort: port, network: "tcp")
            engine.routeAsync(ctx, queue: queue) { policy, rule, res in next(res, policy, rule ?? "") }
        }
        decide { resolution, policyName, ruleText in
            guard let resolution else {
                completion(.failure(UpstreamError.connectFailed("unknown policy: \(explicit)")))
                return
            }
            let via = Self.routeText(policy: policyName, rule: ruleText, resolution: resolution)
            if let route {
                route.policy = policyName
                route.rule = ruleText
                route.chain = switch resolution {
                case .direct: "DIRECT"
                case .reject: "REJECT"
                case .proxy(let p): p.name
                case .chain(let ps): ps.map { $0.name }.joined(separator: " -> ")
                case .unknown(let n): n
                }
            }
            if logRoute {
                Self.logRouteOnce("\(host.lowercased()):\(port)", "[MITM] upstream \(host):\(port) → \(via)")
            }
            if case .reject = resolution {
                completion(.failure(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule")))
                return
            }
            // Reuse a parked keep-alive connection of the same route to the same origin (same TLS / ALPN offer).
            let key = Self.poolKey(host: host, port: port, tls: tls, insecure: insecure, alpn: alpn, via: via)
            if let lease = Self.idlePool.take(key) {
                lease.markReused()
                Self.count(reuse: 1)
                return completion(.success(lease))
            }
            let finish: (Result<MitmUpstreamLease, Error>) -> Void = { r in
                if case .success(let l) = r, let rl = l as? NCRelayUpstreamLease { rl.poolKey = key }
                if logRoute, case .failure(let e) = r {
                    // the 502 line names the route: "connect failed: via 终极清单 (🇯🇵 node): handshake failed: …"
                    if case UpstreamError.connectFailed(let s)? = e as? UpstreamError, !s.hasPrefix("via ") {
                        return completion(.failure(UpstreamError.connectFailed("via \(via): \(s)")))
                    }
                }
                completion(r)
            }
            guard let gate = Self.gateKey(resolution) else {
                Self.count(dial: 1)
                return Self.dial(host: host, port: port, tls: tls, insecure: insecure, alpn: alpn, target: target,
                                 resolution: resolution, queue: queue, completion: finish)
            }
            Self.gatedDial(gate: gate, host: host, port: port, tls: tls, insecure: insecure, alpn: alpn, target: target,
                           resolution: resolution, queue: queue, retry: true, completion: finish)
        }
    }

    static func poolKey(host: String, port: Int, tls: Bool, insecure: Bool, alpn: [String], via: String) -> String {
        "\(host.lowercased()):\(port)|\(tls ? "tls" : "tcp")|\(insecure ? "k" : "v")|\(alpn.joined(separator: ","))|\(via)"
    }

    /// A proxied dial through the node's gate; a transient failure (handshake / transport) is retried once after a
    /// short jittered pause, outside the gate slot.
    private static func gatedDial(gate: String, host: String, port: Int, tls: Bool, insecure: Bool, alpn: [String],
                                  target: NCTarget, resolution: NCGroupEngine.Resolution, queue: DispatchQueue, retry: Bool,
                                  completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        Self.dialGate.acquire(gate) {
            queue.async {
                Self.count(dial: 1)
                Self.dial(host: host, port: port, tls: tls, insecure: insecure, alpn: alpn, target: target,
                          resolution: resolution, queue: queue) { r in
                    Self.dialGate.release(gate)
                    if retry, case .failure(let e) = r, Self.isTransientUpstream(e) {
                        Self.count(retry: 1)
                        let pause = Self.retryDelay + Double.random(in: 0...max(0, Self.retryDelay))
                        queue.asyncAfter(deadline: .now() + pause) {
                            Self.gatedDial(gate: gate, host: host, port: port, tls: tls, insecure: insecure, alpn: alpn,
                                           target: target, resolution: resolution, queue: queue, retry: false,
                                           completion: completion)
                        }
                        return
                    }
                    completion(r)
                }
            }
        }
    }

    /// Transport / handshake failures towards the proxy are worth one retry; a refusal by policy, an unknown policy
    /// or an origin TLS failure (the origin, not the path, said no) is not.
    static func isTransientUpstream(_ e: Error) -> Bool {
        guard let u = e as? UpstreamError else { return true }
        switch u {
        case .connectFailed(let s):
            if s.hasPrefix("upstream TLS:") || s.hasPrefix("unknown policy") { return false }
            if s.hasPrefix("unsupported:") || s.contains("rejected by policy") { return false }
            return true
        case .timeout: return true
        default: return false
        }
    }

    private static func dial(host: String, port: Int, tls: Bool, insecure: Bool, alpn: [String], target: NCTarget,
                             resolution: NCGroupEngine.Resolution, queue: DispatchQueue,
                             completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        if case .reject = resolution {
            completion(.failure(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule")))
            return
        }

        // Direct connection path:
        if case .direct = resolution {
            let stream = tls
                ? NCStream(to: host, port: port, tlsServerName: host, allowInsecure: insecure, queue: queue)
                : NCStream(to: host, port: port, queue: queue)
            stream.start { err in
                if let err {
                    completion(.failure(UpstreamError.connectFailed(err.localizedDescription)))
                } else {
                    let lease = NCRelayUpstreamLease(stream: stream, queue: queue)
                    completion(.success(lease))
                }
            }
            return
        }

        // Proxy connection path via NCConnector (unpaced entry: this dial is already gated and
        // retried by gatedDial above — gating again here would nest acquires on the same key).
        NCConnector.connectUnpaced(target: target, resolution: resolution, queue: queue) { relayStream, err in
            guard let relayStream else {
                let text: String
                if let f = err as? NCConnector.Failure { text = f.description } else { text = err?.localizedDescription ?? "connector failed" }
                completion(.failure(UpstreamError.connectFailed(text)))
                return
            }
            guard tls else {
                completion(.success(NCRelayUpstreamLease(relay: relayStream, queue: queue)))
                return
            }
            // The proxy relays raw bytes: the origin TLS session runs on top of it
            // (the direct path gets TLS from NCStream/Network.framework).
            let tlsStream = NCTLSClientStream(raw: relayStream,
                                              config: .init(serverName: host, alpn: alpn, allowInsecure: insecure),
                                              queue: queue)
            tlsStream.startHandshake { err in
                if let err {
                    tlsStream.cancel()
                    completion(.failure(UpstreamError.connectFailed("upstream TLS: \(err)")))
                } else {
                    let lease = NCRelayUpstreamLease(relay: tlsStream, queue: queue)
                    lease.negotiatedALPN = tlsStream.negotiatedALPN
                    completion(.success(lease))
                }
            }
        }
    }
}

/// fix/nc-open-6-10 #9: what NCUpstreamConnector.open routed a request by (filled before the dial).
final class NCUpstreamRoute {
    var policy = ""
    var rule = ""
    var chain = ""
}

final class NCRelayUpstreamLease: MitmUpstreamLease {
    let stream: ByteStream
    /// Origin ALPN on the proxied TLS path (nil: plain, direct, or the origin sent none).
    var negotiatedALPN: String?
    /// fix/nc-0.20.3-diag: the idle-pool key (route + origin) set by NCUpstreamConnector; nil = never pooled.
    var poolKey: String?
    private let lock = NSLock()
    private var released = false
    private var _reused = false
    /// True when this lease was taken from the idle pool (it served a request before).
    var wasReused: Bool { lock.lock(); defer { lock.unlock() }; return _reused }

    init(stream: NCStream, queue: DispatchQueue) {
        self.stream = NCStreamByteStream(stream: stream, queue: queue)
    }

    init(relay: NCRelayStream, queue: DispatchQueue) {
        self.stream = NCRelayByteStream(relay: relay, queue: queue)
    }

    func markReused() { lock.lock(); _reused = true; released = false; lock.unlock() }

    /// fix/nc-0.20.3-diag: a keep-alive connection (complete response, nothing pending) goes back to the idle pool
    /// (was: always closed, so every MitM request dialed the proxy again). h2 connections are owned by their
    /// H2Connection and never pooled here. Released twice → the second call is ignored.
    func release(reusable: Bool) {
        lock.lock()
        let first = !released
        released = true
        lock.unlock()
        guard first else { return }
        if reusable, negotiatedALPN != "h2", let key = poolKey, NCUpstreamConnector.idlePool.put(self, key: key) { return }
        stream.close()
    }

    /// Pool eviction / shutdown.
    func closeNow() { stream.close() }
}

final class NCStreamByteStream: ByteStream {
    private let stream: NCStream
    private let queue: DispatchQueue
    /// nc-perf: `closed` / `buffer` are touched from three places — read() on the dial queue,
    /// the stream's receive callback (the connection's queue), and close() from the lease
    /// owner's thread, which never hopped queues. Both fields live behind this lock now
    /// (was: unsynchronized cross-thread writes in close() and the EOF path).
    private let stateLock = OSAllocatedUnfairLock(initialState: (closed: false, buffer: Data()))

    init(stream: NCStream, queue: DispatchQueue) {
        self.stream = stream
        self.queue = queue
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            enum Step { case chunk(Data), eof, wait }
            let step: Step = self.stateLock.withLock { st in
                if !st.buffer.isEmpty {
                    let n = Swift.min(st.buffer.count, max)
                    let chunk = Data(st.buffer.prefix(n))
                    st.buffer.removeFirst(n)
                    return .chunk(chunk)
                }
                return st.closed ? .eof : .wait
            }
            switch step {
            case .chunk(let d):
                completion(d, false, nil)
            case .eof:
                completion(nil, true, nil)
            case .wait:
                self.stream.receive { [weak self] data, error in
                    guard let self else { completion(nil, true, nil); return }
                    if let error {
                        completion(nil, false, error)
                    } else if let data, !data.isEmpty {
                        if data.count > max {
                            self.stateLock.withLock { $0.buffer.append(data.dropFirst(max)) }
                            completion(Data(data.prefix(max)), false, nil)
                        } else {
                            completion(data, false, nil)
                        }
                    } else {
                        self.stateLock.withLock { $0.closed = true }
                        completion(nil, true, nil)
                    }
                }
            }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        // The completion form (Shared since build fix #366): write completion now means the
        // socket took the bytes — the same back-pressure the relay variant below gets.
        stream.send(data) { self.queue.async { completion(nil) } }
    }

    func closeWrite() {}

    func close() {
        stateLock.withLock { $0.closed = true }
        stream.cancel()
    }
}

final class NCRelayByteStream: ByteStream {
    private let relay: NCRelayStream
    private let queue: DispatchQueue
    /// nc-perf: same three-thread access as NCStreamByteStream (read on the dial queue, the
    /// relay's receive callback on the relay's own queue, close() from the lease owner) —
    /// `closed` / `buffer` live behind this lock.
    private let stateLock = OSAllocatedUnfairLock(initialState: (closed: false, buffer: Data()))

    init(relay: NCRelayStream, queue: DispatchQueue) {
        self.relay = relay
        self.queue = queue
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            enum Step { case chunk(Data), eof, wait }
            let step: Step = self.stateLock.withLock { st in
                if !st.buffer.isEmpty {
                    let n = Swift.min(st.buffer.count, max)
                    let chunk = Data(st.buffer.prefix(n))
                    st.buffer.removeFirst(n)
                    return .chunk(chunk)
                }
                return st.closed ? .eof : .wait
            }
            switch step {
            case .chunk(let d):
                completion(d, false, nil)
            case .eof:
                completion(nil, true, nil)
            case .wait:
                self.relay.receive { [weak self] data, error in
                    guard let self else { completion(nil, true, nil); return }
                    if let error {
                        completion(nil, false, error)
                    } else if let data, !data.isEmpty {
                        if data.count > max {
                            self.stateLock.withLock { $0.buffer.append(data.dropFirst(max)) }
                            completion(Data(data.prefix(max)), false, nil)
                        } else {
                            completion(data, false, nil)
                        }
                    } else {
                        self.stateLock.withLock { $0.closed = true }
                        completion(nil, true, nil)
                    }
                }
            }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        relay.send(data, completion: { self.queue.async { completion(nil) } })
    }

    func closeWrite() {}

    func close() {
        stateLock.withLock { $0.closed = true }
        relay.cancel()
    }
}
