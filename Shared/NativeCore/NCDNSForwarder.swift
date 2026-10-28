import Foundation
import Network

// nc-lifecycle (evidence rework): NCDNSForwarder moved verbatim from
// PacketTunnel/NativeCore/NCUDPSessions.swift to Shared — the #131 pattern.
// NativeCoreEngine owns a forwarder instance for rule resolution, and the
// engine is compiled into the app target for unit tests (see project.yml),
// which requires every engine dependency to live in Shared. The class only
// ever depended on Shared types (NCDNSUpstreamCoordinator, NCOutboundBinding,
// Data helpers) plus Network.framework. Behavior unchanged; the data plane
// and the engine see the exact same type through the same name/signatures.

/// One-shot upstream DNS forwarding over UDP, with TCP retry on truncation.
/// Used for queries the fake-IP responder declines (filter hosts, non-A types).
final class NCDNSForwarder {
    let queue: DispatchQueue

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func forward(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        // nc-dns: identical in-flight queries coalesce and the global upstream cap applies
        // (see NCDNSUpstreamCoordinator); the one-shot UDP exchange is forwardUDPOnce.
        NCDNSUpstreamCoordinator.shared.submit(
            key: "udp://\(server):\(port)|" + Self.mergeKeySuffix(query),
            id: Self.transactionID(query), callerQueue: queue,
            execute: { [weak self] done in
                guard let self else { done(nil); return }
                self.forwardUDPOnce(query, server: server, port: port, completion: done)
            }, completion: completion)
    }

    static func transactionID(_ query: Data) -> UInt16? {
        guard query.count >= 2 else { return nil }
        return UInt16(query[0]) << 8 | UInt16(query[1])
    }

    /// Coalescing key material: the whole wire query minus its transaction ID — two queries
    /// merge only when flags, question and additional (EDNS) bytes are all identical.
    static func mergeKeySuffix(_ query: Data) -> String {
        Data(query.dropFirst(min(2, query.count))).base64EncodedString()
    }

    /// Returns a cancel handle (fix/nc-tails): tears the socket down and answers nil, for an exchange its caller gave
    /// up on (the coordinator then frees the slot at once instead of after the 5 s timeout).
    @discardableResult
    func forwardUDPOnce(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) -> () -> Void {
        let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any
        let conn = NWConnection(host: NWEndpoint.Host(server), port: nwPort, using: NCOutboundBinding.params(.udp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: query, completion: .contentProcessed { _ in
                    conn.receiveMessage { data, _, _, _ in
                        guard let data else {
                            finish(nil)
                            return
                        }
                        // Truncated bit (TC) set: retry over TCP like resolvers do.
                        if data.count > 2, data[2] & 0x02 != 0 {
                            Self.forwardTCP(query, server: server, port: port, queue: self.queue) { finish($0 ?? data) }
                        } else {
                            finish(data)
                        }
                    }
                })
            case .failed:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
        return { [queue = self.queue] in queue.async { finish(nil) } }
    }

    @discardableResult
    static func forwardTCP(_ query: Data, server: String, port: Int = 53, queue: DispatchQueue, completion: @escaping (Data?) -> Void) -> () -> Void {
        let conn = NWConnection(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any, using: NCOutboundBinding.params(.tcp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            if case .ready = state {
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
                            finish(data)
                        }
                    }
                })
            } else if case .failed = state {
                finish(nil)
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
        return { queue.async { finish(nil) } }
    }

    /// Forward via any upstream kind. nc-dns: single upstreams go through the shared
    /// coordinator (identical in-flight queries coalesce, the global in-flight cap
    /// applies — DoQ included, it just does not reuse connections yet). Groups race
    /// their members (fix/nc-open-6-10, NCDNSRace); each attempt is a separate coordinated query.
    func forward(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) {
        forward(query, upstream: upstream, trace: nil, completion: completion)
    }

    /// Same, recording what each tried server did into `trace` (per-query failure log, fix/nc-open-6-10 #7).
    func forward(_ query: Data, upstream: NCDNSUpstream, trace: NCDNSAttemptTrace?,
                 completion: @escaping (Data?) -> Void) {
        if case .group(let list) = upstream {
            forwardGroup(query, list: list, trace: trace, completion: completion)
            return
        }
        let t0 = DispatchTime.now()
        NCDNSUpstreamCoordinator.shared.submit(
            key: "\(upstream)|" + Self.mergeKeySuffix(query),
            id: Self.transactionID(query), callerQueue: queue,
            execute: { [weak self] done in
                guard let self else { done(nil); return }
                self.dispatchOnce(query, upstream: upstream, completion: done)
            }, completion: { resp in
                if let trace {
                    let ms = Int((DispatchTime.now().uptimeNanoseconds &- t0.uptimeNanoseconds) / 1_000_000)
                    if resp == nil { trace.add("\(upstream.label) no answer \(ms) ms") }
                    else if let r = resp, !NCDNSRace.isUsable(r) { trace.add("\(upstream.label) rcode \(NCDNSRace.rcode(r)) \(ms) ms") }
                    else { trace.winner = upstream.label }
                }
                completion(resp)
            })
    }

    /// One real upstream exchange (the coordinator's execute step; no coalescing here). Returns a cancel handle for
    /// the transports that own their socket (UDP / TCP; fix/nc-tails) — pooled DoT / DoH streams are shared and
    /// keep their own timeout, DoQ its 5 s one.
    @discardableResult
    private func dispatchOnce(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) -> (() -> Void)? {
        switch upstream {
        case .udp(let host, let port):
            return forwardUDPOnce(query, server: host, port: port, completion: completion)
        case .tcp(let host, let port):
            return Self.forwardTCP(query, server: host, port: port, queue: queue, completion: completion)
        case .dot(let host, let port):
            Self.forwardDoT(query, host: host, port: port, queue: queue, completion: completion)
        case .doh(let url):
            Self.forwardDoH(query, urlString: url, queue: queue, completion: completion)
        case .doq(let host, let port):
            Self.forwardDoQ(query, host: host, port: port, queue: queue, completion: completion)
        case .group:
            completion(nil) // unreachable: groups are handled in forward()
        }
        return nil
    }

    private static let groupLock = NSLock()
    private static var groupLastGood: [String: Int] = [:]

    /// Every configured nameserver, raced (fix/nc-open-6-10 #7; was rv2-rules' strictly sequential failover with a
    /// 2.5 s per-server timeout): at most two exchanges in flight, the second 300 ms after the first, a failed or
    /// timed-out server starts the next one at once, first usable answer wins (NCDNSRace). The server that answered
    /// last time goes first. A late answer from a server already given up on is ignored.
    private func forwardGroup(_ query: Data, list: [NCDNSUpstream], trace: NCDNSAttemptTrace?,
                              completion: @escaping (Data?) -> Void) {
        guard !list.isEmpty else { completion(nil); return }
        let key = "\(list)"
        Self.groupLock.lock()
        let start = (Self.groupLastGood[key] ?? 0) % list.count
        Self.groupLock.unlock()
        // fix/nc-tails: each member attempt is a coordinated exchange the race can abandon (slot + socket freed when
        // it times out or loses), see NCDNSRace.runCoordinated. Members are single upstreams (NCDNSUpstream.of
        // flattens groups); per-member trace lines come from the race itself.
        NCDNSRace.runCoordinated(query: query, list: list, start: start, queue: queue, trace: trace, execute: { [weak self] u, done in
            guard let self else { done(nil); return nil }
            return self.dispatchOnce(query, upstream: u, completion: done)
        }, completion: { resp, winner in
            if let winner, resp != nil { trace?.winner = list[winner].label }
            if let winner, winner != start {
                Self.groupLock.lock()
                if Self.groupLastGood.count > 64 { Self.groupLastGood.removeAll() }
                Self.groupLastGood[key] = winner
                Self.groupLock.unlock()
            }
            completion(resp)
        })
    }

    /// DoQ (RFC 9250): one bidirectional QUIC stream per query inside a
    /// throwaway connection group; the message is length-prefixed exactly
    /// like DNS-over-TCP, and the send side is closed after the query.
    private static func forwardDoQ(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        // QUIC is TLS 1.3-only by construction; no min-version pinning needed.
        let quicOptions = NWProtocolQUIC.Options(alpn: ["doq"])
        let params = NWParameters(quic: quicOptions)
        NCOutboundBinding.apply(params, host: host)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            group.cancel()
            completion(data)
        }
        group.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let conn = group.extract(connectionTo: nil, using: nil) else {
                    finish(nil)
                    return
                }
                conn.stateUpdateHandler = { cstate in
                    if case .failed = cstate { finish(nil) }
                }
                conn.start(queue: queue)
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, contentContext: .defaultMessage, isComplete: true,
                          completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
                            finish(data)
                        }
                    }
                })
            case .failed:
                finish(nil)
            default:
                break
            }
        }
        group.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    /// DoT (RFC 7858): length-framed queries over the pooled per-upstream TLS stream
    /// (NCDNSDoTPool: connection reuse, strict sequencing, discard on error/timeout).
    private static func forwardDoT(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        NCDNSDoTPool.shared.forward(query, host: host, port: port, callerQueue: queue, completion: completion)
    }

    /// DoH (RFC 8484): POST the wire query over the pooled per-endpoint HTTPS connection
    /// (NCDNSDoHPool: keep-alive reuse, one query at a time, exact response framing).
    private static func forwardDoH(_ query: Data, urlString: String, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: urlString), let host = url.host else {
            completion(nil)
            return
        }
        let port = url.port ?? 443
        let path = url.path.isEmpty ? "/dns-query" : url.path
        NCDNSDoHPool.shared.forward(query, urlString: urlString, host: host, port: port, path: path,
                                    callerQueue: queue, completion: completion)
    }
}
