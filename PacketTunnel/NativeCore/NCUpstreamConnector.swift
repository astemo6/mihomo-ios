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
        open(host: host, port: port, tls: tls, policy: nil, insecure: false, completion: completion)
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

    /// fix/nc-open-6-10 #9: `route` (when given) receives the rule / policy / chain this open used, for
    /// /app/stats (script requests). The routing itself is unchanged.
    func open(host: String, port: Int, tls: Bool, policy: String?, insecure: Bool, alpn: [String], route: NCUpstreamRoute?,
              completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
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
            Self.dial(host: host, port: port, tls: tls, insecure: insecure, alpn: alpn, target: target,
                      resolution: resolution, queue: queue, completion: completion)
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

        // Proxy connection path via NCConnector:
        NCConnector.connect(target: target, resolution: resolution, queue: queue) { relayStream, err in
            guard let relayStream else {
                completion(.failure(UpstreamError.connectFailed(err?.localizedDescription ?? "connector failed")))
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

    init(stream: NCStream, queue: DispatchQueue) {
        self.stream = NCStreamByteStream(stream: stream, queue: queue)
    }

    init(relay: NCRelayStream, queue: DispatchQueue) {
        self.stream = NCRelayByteStream(relay: relay, queue: queue)
    }

    /// There is no native pool behind this lease: a "reusable" connection was never reused and stayed open until
    /// the origin closed it. Close it either way (memory first).
    func release(reusable: Bool) {
        stream.close()
    }
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
