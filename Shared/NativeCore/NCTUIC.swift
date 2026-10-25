import Foundation
import Network
import Security

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
    let queue: DispatchQueue
    private(set) var state: State = .idle
    private(set) var group: NWConnectionGroup?
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
        self.queue = queue
        udpNative = (proxy.fields["udp-relay-mode"]?.string ?? "native").lowercased() != "quic"
        let overhead = version == 4 ? NCTUICUDP.overheadV4 : NCTUICUDP.overheadV5
        var frame = proxy.fields["max-datagram-frame-size"]?.int ?? 0
        if frame == 0 { frame = (proxy.fields["max-udp-relay-packet-size"]?.int ?? 1252) + overhead }
        udpMaxPacket = min(frame, 1400) - overhead
    }

    func start(completion: @escaping (Error?) -> Void) {
        guard state == .idle else {
            queue.async { completion(NCConnector.Failure.handshake("tuic already started")) }
            return
        }
        state = .connecting
        startCompletion = completion
        let quic = NWProtocolQUIC.Options(alpn: alpn)
        let tls = quic.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        if let sni, !sni.isEmpty { sec_protocol_options_set_tls_server_name(tls, sni) }
        if allowInsecure { sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, queue) }
        quic.idleTimeout = 30_000
        // RFC 9221: advertise DATAGRAM support so native-mode UDP (and server heartbeats) can flow.
        quic.maxDatagramFrameSize = 1400
        let params = NWParameters(quic: quic)
        NCOutboundBinding.apply(params, host: server)
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        self.group = group
        group.stateUpdateHandler = { [weak self] (st: NWConnectionGroup.State) in
            guard let self else { return }
            if case .failed(let e) = st {
                if self.state == .connecting { self.finish(e) } else if self.state == .ready {
                    self.state = .failed
                    self.close(keepState: true)
                }
            }
        }
        // Server-opened flows: uni streams carrying quic-mode UDP packets, or the datagram flow.
        group.newConnectionHandler = { [weak self] incoming in
            guard let self else { incoming.cancel(); return }
            self.acceptIncoming(incoming)
        }
        group.start(queue: queue)

        let uniOptions = NWProtocolQUIC.Options()
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
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.finish(NCConnector.Failure.handshake("tuic handshake timeout"))
        }
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
            self.state = .ready
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
        if error != nil, state != .ready { state = .failed }
        let c = startCompletion
        startCompletion = nil
        c?(error)
        if error != nil { close(keepState: true) }
    }

    func close(keepState: Bool = false) {
        if !keepState { state = .closed }
        datagramFlow?.cancel(); datagramFlow = nil
        udpHandlers.removeAll()
        authStream?.cancel(); authStream = nil
        group?.cancel(); group = nil
    }

    func openTCP(target: NCTarget) -> NCRelayStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        var head = Data([UInt8(version), 1])
        head.append(NCTUICWire.address(target))
        let s = NCTUICTCPStream(channel: NCHy2StreamChannel(conn: conn), head: head, expectResponse: version == 4,
                                queue: queue)
        s.begin()
        return s
    }
}

/// One TUIC TCP flow: Connect command, then raw bytes (v4 waits for its Response [4][0xff][rep]).
final class NCTUICTCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let head: Data
    private let queue: DispatchQueue
    private var waitingResponse: Bool
    private var open = false, closed = false
    private var failure: Error?
    private var outbox = Data()
    private var inbox: [Data] = []
    private var respBuf = Data()
    private var pending: ((Data?, Error?) -> Void)?
    /// Completions of sends buffered in `outbox` until the channel is up; fired on flush/fail/cancel.
    private var outboxWaiters: [NCCallOnce] = []

    init(channel: NCHy2StreamChannel, head: Data, expectResponse: Bool, queue: DispatchQueue) {
        self.channel = channel
        self.head = head
        self.waitingResponse = expectResponse
        self.queue = queue
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
        guard !closed, failure == nil else { once.call(); return }
        if open { channel.send(data, completion: once.call) } else { outbox.append(data); outboxWaiters.append(once) }
    }

    private func drainOutboxWaiters() {
        let w = outboxWaiters; outboxWaiters = []
        w.forEach { $0.call() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !inbox.isEmpty { handler(inbox.removeFirst(), nil); return }
        if let failure { handler(nil, failure); return }
        if closed { handler(nil, nil); return }
        pending = handler
    }

    func cancel() {
        closed = true
        drainOutboxWaiters()
        channel.cancel()
    }

    private func loop() {
        channel.receive { [weak self] data, error in
            guard let self, !self.closed || self.pending != nil else { return }
            guard var data else {
                self.closed = true
                if let h = self.pending { self.pending = nil; h(nil, error) }
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
            if let h = self.pending { self.pending = nil; h(data, nil) } else { self.inbox.append(data) }
            self.loop()
        }
    }

    private func fail(_ e: Error) {
        failure = e
        closed = true
        drainOutboxWaiters()
        channel.cancel()
        if let h = pending { pending = nil; h(nil, e) }
    }
}

extension NCConnector {
    private static var tuicRegistry: [String: NCTUICConnection] = [:]
    private static let tuicLock = NSLock()

    static func tuicStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                           completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        tuicLock.lock()
        if let c = tuicRegistry[key], c.state == .ready || c.state == .connecting {
            tuicLock.unlock()
            waitTUIC(c, target: target, queue: queue, attempts: 60, completion: completion)
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
            if let s = c.openTCP(target: target) { completion(s, nil) }
            else { completion(nil, Failure.handshake("tuic open stream failed")) }
        }
    }

    /// The shared, authenticated TUIC connection for a proxy (UDP sessions; feat/nc-proto2). nil on failure.
    static func tuicShared(proxy: NCProxy, queue: DispatchQueue, completion: @escaping (NCTUICConnection?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        tuicLock.lock()
        if let c = tuicRegistry[key], c.state == .ready || c.state == .connecting {
            tuicLock.unlock()
            waitTUICReady(c, queue: queue, attempts: 60, completion: completion)
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

    private static func waitTUICReady(_ c: NCTUICConnection, queue: DispatchQueue, attempts: Int,
                                      completion: @escaping (NCTUICConnection?) -> Void) {
        switch c.state {
        case .ready: completion(c)
        case .connecting where attempts > 0:
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitTUICReady(c, queue: queue, attempts: attempts - 1, completion: completion)
            }
        default: completion(nil)
        }
    }

    private static func waitTUIC(_ c: NCTUICConnection, target: NCTarget, queue: DispatchQueue, attempts: Int,
                                 completion: @escaping (NCRelayStream?, Error?) -> Void) {
        switch c.state {
        case .ready:
            if let s = c.openTCP(target: target) { completion(s, nil) }
            else { completion(nil, Failure.handshake("tuic open stream failed")) }
        case .connecting where attempts > 0:
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitTUIC(c, target: target, queue: queue, attempts: attempts - 1, completion: completion)
            }
        default:
            completion(nil, Failure.handshake("tuic connection failed"))
        }
    }
}
