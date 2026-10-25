import Foundation
import Network
import Security
import os

/// TUIC v5 / v4 client, TCP relay (feat/nc-proto A1, based on astemo6/Muse NativeCore), protocol from mihomo
/// v1.19.33 transport/tuic. Built on Network.framework QUIC like NCHysteria2Connection:
///  - authentication rides a client-initiated unidirectional stream (NWProtocolQUIC.Options.direction = .unidirectional);
///  - the v5 token is the TLS 1.3 keying-material exporter (label = UUID bytes, context = password, 32 bytes) via
///    sec_protocol_metadata_create_secret_with_context on the QUIC stream's security metadata;
///  - v4 authenticates with BLAKE3(token).
/// UDP relay (feat/nc-proto2): `udp-relay-mode: native` (default) sends Packet commands as QUIC DATAGRAM frames on a
/// datagram flow (NWProtocolQUIC.Options.isDatagram, the group advertises max_datagram_frame_size); `quic` sends each
/// packet on its own unidirectional stream and reads the server's uni streams (NCTUICUDP.swift).
/// Not yet: heartbeat datagrams (the QUIC idle timeout closes an idle session and the next flow reconnects), custom
/// congestion control (system QUIC CC is used).
enum NCTUICWire {
    static func address(_ t: NCTarget) -> Data {
        var d = Data()
        if let v4 = IPv4Address(t.host) {
            d.append(1); d.append(v4.rawValue)
        } else if let v6 = IPv6Address(t.host) {
            d.append(2); d.append(v6.rawValue)
        } else {
            let h = Data(t.host.utf8.prefix(255))
            d.append(0); d.append(UInt8(h.count)); d.append(h)
        }
        d.appendBE16(UInt16(clamping: t.port))
        return d
    }

    static func uuidBytes(_ s: String) -> Data? {
        let hex = s.replacingOccurrences(of: "-", with: "")
        guard hex.count == 32 else { return nil }
        var out = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}

final class NCTUICConnection {
    enum State { case idle, connecting, ready, failed, closed }

    private let server: String, port: Int
    private let version: Int
    private let uuid: Data, password: Data, token: Data
    private let sni: String?, alpn: [String], allowInsecure: Bool
    /// nc-races: the connection's own session queue (the #116 pattern, as in NCMuxSession): the NW group,
    /// the auth flow, the UDP association registry (NCTUICUDP.swift) and every TCP stream's state are
    /// touched only here. Callers hop in via `queue.async` (the UDP session already does) or the
    /// ncOnSessionQueue entry points below. The queue passed to init is kept as `callbackQueue`: the start
    /// completion is delivered on it, exactly where callers used to get it when the group ran there.
    let queue: DispatchQueue
    private let callbackQueue: DispatchQueue

    /// Lock-protected snapshot for cross-thread readers (the connector registry, the UDP session): the
    /// state and the readiness waiters. Waiters are drained under the lock and fired outside it, each on
    /// its own caller queue — no polling.
    private struct Snapshot {
        var state: State = .idle
        var waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready } }
    private func setState(_ state: State) { snapshot.withLock { $0.state = state } }

    /// Registers interest in readiness (the connector registry): ready → nil at once on `callerQueue`,
    /// failed/closed → the failure, connecting → queued until start resolves either way. Replaces the
    /// registry's old 0.25 s × 60 poll of `state` (nc-races, mirroring NCMuxSession.whenReady).
    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        enum Action { case now(Error?), wait }
        let action: Action = snapshot.withLock { snap in
            switch snap.state {
            case .ready:
                return .now(nil)
            case .failed, .closed:
                return .now(NCConnector.Failure.handshake("tuic connection failed"))
            case .idle, .connecting:
                snap.waiters.append((callerQueue, completion))
                return .wait
            }
        }
        if case .now(let error) = action {
            callerQueue.async { completion(error) }
        }
    }

    /// Fires every queued readiness waiter exactly once, each on its own caller queue.
    private func notifyWaiters(_ error: Error?) {
        let waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = snapshot.withLock { snap in
            let drained = snap.waiters
            snap.waiters = []
            return drained
        }
        for waiter in waiters {
            waiter.queue.async { waiter.completion(error) }
        }
    }
    private(set) var group: NWConnectionGroup?
    /// Session queue only: the auth stream is extracted exactly once, when the group first
    /// reports .ready. Extracting from a just-started group logs
    /// `nw_connection_group_create_connection_for_endpoint_and_parameters … failed to
    /// create connection` and returns nil (proto-loopback run 40171239186, iOS 18.5
    /// simulator — this failed there with "cannot open auth stream" before any packet
    /// was sent; same failure shape as NCHysteria2Connection, fixed the same way).
    private var authOpened = false
    /// UDP relay state (NCTUICUDP.swift).
    var udpNative = true
    var udpMaxPacket = 1252
    var udpHandlers: [UInt16: (Data) -> Void] = [:]
    var datagramFlow: NWConnection?
    var tuicVersion: Int { version }
    private var authStream: NWConnection?
    private var startCompletion: ((Error?) -> Void)?

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let server = proxy.server, let port = proxy.port else { return nil }
        self.server = server
        self.port = port
        if let t = proxy.fields["token"]?.string, !t.isEmpty {
            version = 4
            token = Data(NCBlake3.hash([UInt8](t.utf8)))
            uuid = Data(); password = Data()
        } else {
            guard let u = proxy.fields["uuid"]?.string, let ub = NCTUICWire.uuidBytes(u) else { return nil }
            version = 5
            uuid = ub
            password = Data((proxy.fields["password"]?.string ?? "").utf8)
            token = Data()
        }
        let disableSNI = proxy.fields["disable-sni"]?.bool ?? false
        sni = disableSNI ? nil : (proxy.fields["sni"]?.string ?? server)
        alpn = proxy.fields["alpn"]?.array?.compactMap { $0.string } ?? ["h3"]
        allowInsecure = proxy.fields["skip-cert-verify"]?.bool ?? false
        self.callbackQueue = queue
        self.queue = NCSessionQueues.make("nc.tuic.\(server):\(port)")
        udpNative = (proxy.fields["udp-relay-mode"]?.string ?? "native").lowercased() != "quic"
        let overhead = version == 4 ? NCTUICUDP.overheadV4 : NCTUICUDP.overheadV5
        var frame = proxy.fields["max-datagram-frame-size"]?.int ?? 0
        if frame == 0 { frame = (proxy.fields["max-udp-relay-packet-size"]?.int ?? 1252) + overhead }
        udpMaxPacket = min(frame, 1400) - overhead
    }

    func start(completion: @escaping (Error?) -> Void) {
        // Check-and-set under the snapshot lock: two concurrent starts must not both pass and
        // overwrite each other's completion.
        let first: Bool = snapshot.withLock { snap in
            guard snap.state == .idle else { return false }
            snap.state = .connecting
            return true
        }
        guard first else {
            callbackQueue.async { completion(NCConnector.Failure.handshake("tuic already started")) }
            return
        }
        startCompletion = completion
        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    /// QUIC options for the group parameters AND for every stream extracted from
    /// the group: the two must agree on ALPN and TLS settings. The auth stream used
    /// to be extracted with a bare `NWProtocolQUIC.Options()` — direction only, no
    /// ALPN, no SNI, default TLS — and the server refused the negotiation, so the
    /// auth stream never opened ("cannot open auth stream"; review rework). Fresh
    /// instance per call: the options object is a mutable class, and sharing one
    /// instance between the group parameters and the extracted streams invites
    /// drift (e.g. setting .direction on the group's own copy).
    func quicStreamOptions() -> NWProtocolQUIC.Options {
        let options = NWProtocolQUIC.Options(alpn: alpn)
        let tls = options.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        if let sni, !sni.isEmpty { sec_protocol_options_set_tls_server_name(tls, sni) }
        if allowInsecure { sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, queue) }
        options.idleTimeout = 30_000
        // RFC 9221: advertise DATAGRAM support so native-mode UDP (and server heartbeats) can flow.
        options.maxDatagramFrameSize = 1400
        return options
    }

    /// Session queue only: build the QUIC group; the auth stream opens when the group
    /// reports .ready (openAuthStream), not before.
    private func startOnQueue() {
        let params = NWParameters(quic: quicStreamOptions())
        NCOutboundBinding.apply(params, host: server)
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        self.group = group
        group.stateUpdateHandler = { [weak self] (st: NWConnectionGroup.State) in
            guard let self else { return }
            switch st {
            case .ready:
                self.openAuthStream()
            case .failed(let e):
                if self.state == .connecting { self.finish(e) } else if self.state == .ready {
                    self.setState(.failed)
                    self.close(keepState: true)
                }
            default:
                break
            }
        }
        // Server-opened flows: uni streams carrying quic-mode UDP packets, or the datagram flow.
        group.newConnectionHandler = { [weak self] incoming in
            guard let self else { incoming.cancel(); return }
            self.acceptIncoming(incoming)
        }
        group.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.finish(NCConnector.Failure.handshake("tuic handshake timeout"))
        }
    }

    /// Session queue only, one-shot: open the unidirectional auth stream once the group
    /// is .ready (extracting earlier returns nil — see `authOpened`).
    private func openAuthStream() {
        guard !authOpened, state == .connecting, let group else { return }
        authOpened = true
        // Same ALPN/TLS as the group parameters (quicStreamOptions) — a bare
        // options object here negotiates without ALPN and sing-box refuses it.
        let uniOptions = quicStreamOptions()
        uniOptions.direction = .unidirectional
        guard let auth = group.extract(connectionTo: nil, using: uniOptions) else {
            finish(NCConnector.Failure.handshake("tuic: cannot open auth stream"))
            return
        }
        authStream = auth
        var fired = false
        auth.stateUpdateHandler = { [weak self] st in
            guard let self, !fired else { return }
            switch st {
            case .ready:
                fired = true
                self.sendAuth(on: auth)
            case .failed(let e):
                fired = true
                self.finish(e)
            case .cancelled:
                fired = true
                self.finish(NCConnector.Failure.handshake("tuic auth stream cancelled"))
            default:
                break
            }
        }
        auth.start(queue: queue)
    }

    private func sendAuth(on conn: NWConnection) {
        var cmd = Data()
        if version == 4 {
            cmd.append(4); cmd.append(0); cmd.append(token)
        } else {
            guard let tk = exportToken(conn) else {
                finish(NCConnector.Failure.handshake("tuic: TLS exporter unavailable"))
                return
            }
            cmd.append(5); cmd.append(0); cmd.append(uuid); cmd.append(tk)
        }
        conn.send(content: cmd, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] err in
            guard let self else { return }
            if let err { self.finish(err); return }
            // Streams opened from here on queue behind the authentication on the server (as mihomo does).
            self.setState(.ready)
            self.finish(nil)
        })
    }

    /// TLS 1.3 exporter, label = UUID bytes, context = password, 32 bytes (GenToken).
    private func exportToken(_ conn: NWConnection) -> Data? {
        guard let md = conn.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata else { return nil }
        let sec = md.securityProtocolMetadata
        let label = [CChar](uuid.map { CChar(bitPattern: $0) })
        let ctx = [UInt8](password)
        let secret = label.withUnsafeBufferPointer { lp in
            ctx.withUnsafeBufferPointer { cp in
                sec_protocol_metadata_create_secret_with_context(sec, lp.count, lp.baseAddress!, cp.count,
                                                                 cp.baseAddress ?? UnsafePointer<UInt8>(bitPattern: 1)!, 32)
            }
        }
        guard let secret else { return nil }
        // dispatch_data_t is NSData-bridged on Darwin.
        let out = Data(referencing: (secret as AnyObject) as! NSData)
        return out.count == 32 ? out : nil
    }

    private func finish(_ error: Error?) {
        if error != nil, state != .ready { setState(.failed) }
        let c = startCompletion
        startCompletion = nil
        if let c {
            callbackQueue.async { c(error) }
        }
        notifyWaiters(error)
        if error != nil { close(keepState: true) }
    }

    func close(keepState: Bool = false) {
        if !keepState { setState(.closed) }
        notifyWaiters(NCConnector.Failure.handshake("tuic connection closed"))
        ncOnSessionQueue(queue) {
            self.datagramFlow?.cancel(); self.datagramFlow = nil
            self.udpHandlers.removeAll()
            self.authStream?.cancel(); self.authStream = nil
            self.group?.cancel(); self.group = nil
        }
    }

    /// Open a proxied TCP flow; nil unless authenticated. `callerQueue` is where the stream delivers
    /// receive handlers (recorded at open, as in NCMuxStream). Synchronous return via the session
    /// queue, like NCMuxSession.openStream.
    func openTCP(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        if NCSessionQueues.isCurrent(queue) { return openTCPOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openTCPOnQueue(target: target, callerQueue: callerQueue) }
    }

    private func openTCPOnQueue(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        var head = Data([UInt8(version), 1])
        head.append(NCTUICWire.address(target))
        let s = NCTUICTCPStream(channel: NCHy2StreamChannel(conn: conn), head: head, expectResponse: version == 4,
                                queue: queue, callerQueue: callerQueue)
        s.begin()
        return s
    }
}

/// One TUIC TCP flow: Connect command, then raw bytes (v4 waits for its Response [4][0xff][rep]).
final class NCTUICTCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let head: Data
    /// The owning connection's session queue: all stream state lives here (nc-races, the #116 pattern).
    private let queue: DispatchQueue
    /// Where the registered receive handler is delivered (recorded at openTCP, as in NCMuxStream).
    private let callerQueue: DispatchQueue
    private var waitingResponse: Bool
    private var open = false, closed = false
    private var failure: Error?
    private var outbox = Data()
    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var respBuf = Data()
    private var pending: ((Data?, Error?) -> Void)?
    /// Completions of sends buffered in `outbox` until the channel is up; fired on flush/fail/cancel.
    private var outboxWaiters: [NCCallOnce] = []

    /// nc-memory: pre-open outbox / reader-ahead inbox caps (see NCHysteria2TCPStream.maxQueuedBytes).
    static let maxQueuedBytes = 256 * 1024

    init(channel: NCHy2StreamChannel, head: Data, expectResponse: Bool, queue: DispatchQueue,
         callerQueue: DispatchQueue) {
        self.channel = channel
        self.head = head
        self.waitingResponse = expectResponse
        self.queue = queue
        self.callerQueue = callerQueue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.fail(err); return }
            self.open = true
            let waiters = self.outboxWaiters; self.outboxWaiters = []
            self.channel.send(self.head + self.outbox) { waiters.forEach { $0.call() } }
            self.outbox = Data()
            self.loop()
        }
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard !self.closed, self.failure == nil else { once.call(); return }
            if self.open {
                self.channel.send(data, completion: once.call)
            } else if self.outbox.count + data.count <= Self.maxQueuedBytes {
                self.outbox.append(data); self.outboxWaiters.append(once)
            } else {
                once.call()
                self.fail(NCConnector.Failure.handshake("tuic tcp send buffer overflow"))
            }
        }
    }

    private func drainOutboxWaiters() {
        let w = outboxWaiters; outboxWaiters = []
        w.forEach { $0.call() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.inbox.isEmpty {
                let data = self.inbox.removeFirst()
                self.inboxBytes -= data.count
                self.callerQueue.async { handler(data, nil) }
                return
            }
            if let failure = self.failure {
                self.callerQueue.async { handler(nil, failure) }
                return
            }
            if self.closed {
                self.callerQueue.async { handler(nil, nil) }
                return
            }
            self.pending = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            self.closed = true
            self.drainOutboxWaiters()
            self.channel.cancel()
        }
    }

    private func loop() {
        channel.receive { [weak self] data, error in
            guard let self, !self.closed || self.pending != nil else { return }
            guard var data else {
                self.closed = true
                // EOF before begin() flushed the outbox must still release the buffered
                // sends: their completions fire on every path per the NCRelayStream
                // contract (previously they hung forever — the pump stalled).
                self.drainOutboxWaiters()
                if let h = self.pending {
                    self.pending = nil
                    self.callerQueue.async { h(nil, error) }
                }
                return
            }
            if self.waitingResponse {
                self.respBuf.append(data)
                guard self.respBuf.count >= 3 else { self.loop(); return }
                let s = self.respBuf.startIndex
                guard self.respBuf[s] == 4, self.respBuf[s + 1] == 0xff, self.respBuf[s + 2] == 0 else {
                    self.fail(NCConnector.Failure.handshake("tuic v4 connect rejected"))
                    return
                }
                data = Data(self.respBuf.dropFirst(3))
                self.respBuf = Data()
                self.waitingResponse = false
                if data.isEmpty { self.loop(); return }
            }
            if let h = self.pending {
                self.pending = nil
                self.callerQueue.async { h(data, nil) }
            } else if self.inboxBytes + data.count <= Self.maxQueuedBytes {
                self.inboxBytes += data.count
                self.inbox.append(data)
            } else {
                self.fail(NCConnector.Failure.handshake("tuic tcp receive buffer overflow"))
                return
            }
            self.loop()
        }
    }

    private func fail(_ e: Error) {
        failure = e
        closed = true
        drainOutboxWaiters()
        channel.cancel()
        if let h = pending {
            pending = nil
            callerQueue.async { h(nil, e) }
        }
    }
}

extension NCConnector {
    private static var tuicRegistry: [String: NCTUICConnection] = [:]
    private static let tuicLock = NSLock()

    static func tuicStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                           completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        tuicLock.lock()
        if let c = tuicRegistry[key] {
            tuicLock.unlock()
            if c.isAlive {
                openTUICStream(c, target: target, queue: queue, completion: completion)
            } else if c.state == .connecting {
                // nc-races: readiness is a one-shot waiter on the connection (no 0.25 s polling, the
                // shape #116 set for mux/anytls); the registry cleanup on failure stays here.
                c.whenReady(callerQueue: queue) { err in
                    if let err {
                        tuicLock.lock()
                        if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                        tuicLock.unlock()
                        completion(nil, err)
                    } else {
                        openTUICStream(c, target: target, queue: queue, completion: completion)
                    }
                }
            } else {
                tuicLock.lock()
                if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                tuicLock.unlock()
                tuicStream(proxy: proxy, target: target, queue: queue, completion: completion)
            }
            return
        }
        guard let c = NCTUICConnection(proxy: proxy, queue: queue) else {
            tuicLock.unlock()
            queue.async { completion(nil, Failure.handshake("tuic bad config (uuid / token)")) }
            return
        }
        tuicRegistry[key] = c
        tuicLock.unlock()
        c.start { err in
            if let err {
                tuicLock.lock()
                if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                tuicLock.unlock()
                completion(nil, err)
                return
            }
            openTUICStream(c, target: target, queue: queue, completion: completion)
        }
    }

    private static func openTUICStream(_ c: NCTUICConnection, target: NCTarget, queue: DispatchQueue,
                                       completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let s = c.openTCP(target: target, callerQueue: queue) { completion(s, nil) }
        else { completion(nil, Failure.handshake("tuic open stream failed")) }
    }

    /// The shared, authenticated TUIC connection for a proxy (UDP sessions; feat/nc-proto2). nil on failure.
    static func tuicShared(proxy: NCProxy, queue: DispatchQueue, completion: @escaping (NCTUICConnection?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        tuicLock.lock()
        if let c = tuicRegistry[key] {
            tuicLock.unlock()
            if c.isAlive {
                completion(c)
            } else if c.state == .connecting {
                c.whenReady(callerQueue: queue) { err in
                    if err != nil {
                        tuicLock.lock()
                        if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                        tuicLock.unlock()
                        completion(nil)
                    } else {
                        completion(c)
                    }
                }
            } else {
                tuicLock.lock()
                if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                tuicLock.unlock()
                tuicShared(proxy: proxy, queue: queue, completion: completion)
            }
            return
        }
        guard let c = NCTUICConnection(proxy: proxy, queue: queue) else {
            tuicLock.unlock()
            queue.async { completion(nil) }
            return
        }
        tuicRegistry[key] = c
        tuicLock.unlock()
        c.start { err in
            if err != nil {
                tuicLock.lock()
                if tuicRegistry[key] === c { tuicRegistry.removeValue(forKey: key) }
                tuicLock.unlock()
                completion(nil)
                return
            }
            completion(c)
        }
    }
}
