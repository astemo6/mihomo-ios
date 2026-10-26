import Foundation

/// feat/nc-naive-h2h3: dialing HTTP/2 / HTTP/3 CONNECT proxies and NaïveProxy (see NCNaive.swift).
///
///  - h2: one shared NCH2ProxySession per node (up to `insecure-concurrency` sessions, streams go to the
///    least-loaded one), TLS by the hand-rolled client (NCTLSClientStream: ALPN h2, ClientHello profile
///    from client-fingerprint, chrome by default — the naive point of looking like Chrome), so it also
///    works over a chain transport (then with a private session that closes with its one stream).
///  - h3: one shared NCH3ProxyConnection per node (QUIC multiplexes; no concurrency knob needed).
///  - UDP: sing-box naive `udp-over-tcp` — UoT v2 through a CONNECT tunnel to sp.v2.udp-over-tcp.arpa:0
///    (NCUoT); the PacketTunnel side is NCUDPUoTSession.
extension NCConnector {
    private static var h2ProxyRegistry: [String: [NCH2ProxySession]] = [:]
    private static var h3ProxyRegistry: [String: NCH3ProxyConnection] = [:]
    private static let h2h3Lock = NSLock()

    static func registryKey(_ proxy: NCProxy, _ o: NCH2H3ProxyOptions) -> String {
        "\(proxy.name)|\(proxy.type.lowercased())|\(o.server)|\(o.port)|\(o.carrier == .h3 ? "h3" : "h2")"
    }

    /// Entry point from connectViaProxy.
    static func naiveH2H3Stream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                transport: NCRelayStream?,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let o = NCH2H3ProxyOptions(proxy: proxy) else {
            queue.async { completion(nil, Failure.handshake("\(proxy.type) missing server/port")) }
            return
        }
        let padding = o.naive ? NCNaivePadding.headerValue() : nil
        let headers = NCHTTPConnect.requestHeaders(target: target, options: o, paddingHeader: padding)
        switch o.carrier {
        case .h3:
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("\(proxy.type) (HTTP/3) over a chain transport")) }
                return
            }
            sharedH3Proxy(proxy: proxy, options: o, queue: queue) { conn, err in
                guard let conn else { completion(nil, err); return }
                openH3(conn, headers: headers, naive: o.naive, queue: queue, completion: completion)
            }
        case .h2:
            if let transport {
                let session = NCH2ProxySession(key: registryKey(proxy, o) + "|chain", closeWhenIdle: true)
                dialH2Session(session, options: o, transport: transport)
                session.whenReady(callerQueue: queue) { err in
                    if let err { completion(nil, err); return }
                    openH2(session, headers: headers, naive: o.naive, queue: queue, completion: completion)
                }
                return
            }
            sharedH2Proxy(proxy: proxy, options: o, queue: queue) { session, err in
                guard let session else { completion(nil, err); return }
                openH2(session, headers: headers, naive: o.naive, queue: queue, completion: completion)
            }
        }
    }

    private static func openH2(_ session: NCH2ProxySession, headers: [(String, String)], naive: Bool,
                               queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let box = NCStreamBox()
        let stream = session.openStream(headers: headers, naive: naive, callerQueue: queue) { err in
            completion(err == nil ? box.get() : nil, err)
        }
        box.set(stream)
    }

    private static func openH3(_ conn: NCH3ProxyConnection, headers: [(String, String)], naive: Bool,
                               queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let box = NCStreamBox()
        let stream = conn.openStream(headers: headers, naive: naive, callerQueue: queue) { err in
            completion(err == nil ? box.get() : nil, err)
        }
        guard let stream else {
            queue.async { completion(nil, Failure.handshake("h3 proxy: cannot open request stream")) }
            return
        }
        box.set(stream)
    }

    // MARK: h2 sessions

    /// TCP (or the chain transport) → TLS with ALPN h2 → session.attach. Runs on the session queue.
    private static func dialH2Session(_ session: NCH2ProxySession, options o: NCH2H3ProxyOptions,
                                      transport: NCRelayStream?) {
        let q = session.queue
        func tls(over raw: NCRelayStream) {
            var cfg = NCTLSClientStream.Config(serverName: o.serverName)
            cfg.alpn = ["h2", "http/1.1"]
            cfg.allowInsecure = o.allowInsecure
            cfg.profile = NCClientHelloProfile.named(o.fingerprint)
            let tls = NCTLSClientStream(raw: raw, config: cfg, queue: q)
            tls.startHandshake { err in
                if let err { tls.cancel(); session.attachFailed(err); return }
                if let alpn = tls.negotiatedALPN, alpn != "h2" {
                    tls.cancel()
                    session.attachFailed(Failure.handshake("\(o.naive ? "naive" : "h2 proxy"): server chose ALPN \(alpn), not h2"))
                    return
                }
                session.attach(base: tls)
            }
        }
        if let transport {
            q.async { tls(over: transport) }
            return
        }
        let raw = NCStream(to: o.server, port: o.port, queue: q)
        raw.start { err in
            if let err { raw.cancel(); session.attachFailed(err); return }
            tls(over: raw)
        }
    }

    private static func sharedH2Proxy(proxy: NCProxy, options o: NCH2H3ProxyOptions, queue: DispatchQueue,
                                      completion: @escaping (NCH2ProxySession?, Error?) -> Void) {
        let key = registryKey(proxy, o)
        h2h3Lock.lock()
        var list = (h2ProxyRegistry[key] ?? []).filter { $0.state == .connecting || $0.isAlive }
        // Least-loaded usable session; a new one while below the concurrency budget and all are busy.
        let best = list.filter { $0.isAlive && $0.hasCapacity }.min(by: { $0.load < $1.load })
        let connecting = list.first(where: { $0.state == .connecting })
        let session: NCH2ProxySession
        var dial = false
        if let best, best.load == 0 || list.count >= o.concurrency {
            session = best
        } else if list.count < o.concurrency {
            session = NCH2ProxySession(key: key + "#\(list.count)")
            list.append(session)
            dial = true
        } else if let connecting {
            session = connecting
        } else if let best {
            session = best
        } else {
            session = NCH2ProxySession(key: key + "#\(list.count)")
            list.append(session)
            dial = true
        }
        h2ProxyRegistry[key] = list
        h2h3Lock.unlock()
        if dial {
            session.onClosed = { [weak session] in
                h2h3Lock.lock()
                if let session { h2ProxyRegistry[key]?.removeAll { $0 === session } }
                if h2ProxyRegistry[key]?.isEmpty == true { h2ProxyRegistry[key] = nil }
                h2h3Lock.unlock()
            }
            dialH2Session(session, options: o, transport: nil)
        }
        session.whenReady(callerQueue: queue) { err in
            completion(err == nil ? session : nil, err)
        }
    }

    // MARK: h3 connections

    private static func sharedH3Proxy(proxy: NCProxy, options o: NCH2H3ProxyOptions, queue: DispatchQueue,
                                      completion: @escaping (NCH3ProxyConnection?, Error?) -> Void) {
        let key = registryKey(proxy, o)
        h2h3Lock.lock()
        let conn: NCH3ProxyConnection
        var dial = false
        if let existing = h3ProxyRegistry[key], existing.state == .ready || existing.state == .connecting
            || existing.state == .idle {
            conn = existing
        } else {
            conn = NCH3ProxyConnection(key: key, options: o)
            h3ProxyRegistry[key] = conn
            dial = true
        }
        h2h3Lock.unlock()
        if dial {
            conn.onClosed = { [weak conn] in
                h2h3Lock.lock()
                if let conn, h3ProxyRegistry[key] === conn { h3ProxyRegistry[key] = nil }
                h2h3Lock.unlock()
            }
            conn.start()
        }
        conn.whenReady(callerQueue: queue) { err in
            completion(err == nil ? conn : nil, err)
        }
    }

    // MARK: lifecycle (closeAllSharedSessions / sharedSessionCounts)

    static var naiveH2H3SessionCount: Int {
        h2h3Lock.lock()
        defer { h2h3Lock.unlock() }
        return h2ProxyRegistry.values.reduce(0) { $0 + $1.count } + h3ProxyRegistry.count
    }

    @discardableResult
    static func closeAllNaiveH2H3Sessions() -> Int {
        h2h3Lock.lock()
        let h2 = h2ProxyRegistry.values.flatMap { $0 }
        let h3 = Array(h3ProxyRegistry.values)
        h2ProxyRegistry.removeAll()
        h3ProxyRegistry.removeAll()
        h2h3Lock.unlock()
        for s in h2 { s.close() }
        for c in h3 { c.close() }
        return h2.count + h3.count
    }
}

/// Hands a stream created synchronously to its own (asynchronous) ready callback.
private final class NCStreamBox {
    private let lock = NSLock()
    private var stream: NCRelayStream?
    func set(_ s: NCRelayStream) { lock.lock(); stream = s; lock.unlock() }
    func get() -> NCRelayStream? { lock.lock(); defer { lock.unlock() }; return stream }
}
