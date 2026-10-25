import Foundation
import Network

/// Hysteria v1 client (protocol version 3, mihomo v1.19.33 transport/hysteria/core) over Network.framework QUIC
/// (feat/nc-proto A3, based on astemo6/Muse NativeCore). Same QUIC group model as NCHysteria2Connection.
/// Scope: TCP over QUIC streams; UDP relay over QUIC datagrams; obfs (XPlus), protocol wechat-video and port hopping
/// (`ports`, `hop-interval`) through the loopback packet shim (NCHysteria1UDP.swift, feat/nc-proto2). Not available:
/// protocol faketcp (raw sockets) and Brutal congestion control (the system QUIC congestion controller is used).
enum NCHy1 {
    /// utils.StringToBps: "100" = 100 Mbps; "<n> [KMGT]?[Bb]ps".
    /// rv2-proto: multiplications are overflow-checked (a huge config value used to trap); overflow → 0 (= invalid,
    /// same as an unparsable value).
    static func bps(_ s: String?) -> UInt64 {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return 0 }
        if let v = UInt64(s) {
            let (m, o) = v.multipliedReportingOverflow(by: 1_000_000)
            return o ? 0 : m / 8
        }
        var digits = ""
        var rest = Substring(s)
        while let c = rest.first, c.isASCII, c.isNumber { digits.append(c); rest = rest.dropFirst() }
        rest = rest.drop(while: { $0 == " " })
        guard let v = UInt64(digits) else { return 0 }
        var n: UInt64 = 1
        if let c = rest.first, "KMGT".contains(c) {
            switch c {
            case "T": n = 1_000_000_000_000
            case "G": n = 1_000_000_000
            case "M": n = 1_000_000
            default: n = 1_000
            }
            rest = rest.dropFirst()
        }
        guard rest == "bps" || rest == "Bps" else { return 0 }
        let (m, overflow) = n.multipliedReportingOverflow(by: v)
        guard !overflow else { return 0 }
        n = m
        if rest == "bps" { n /= 8 }
        return n
    }

    static func clientHello(sendBPS: UInt64, recvBPS: UInt64, auth: Data) -> Data {
        var d = Data([3])
        d.appendBE64(sendBPS)
        d.appendBE64(recvBPS)
        d.appendBE16(UInt16(auth.count))
        d.append(auth)
        return d
    }

    /// (ok, message, consumed) or nil while incomplete. ServerHello: ok(1) sendBPS(8) recvBPS(8) len(2) msg.
    static func serverHello(_ b: Data) -> (Bool, String, Int)? {
        guard b.count >= 19 else { return nil }
        let s = b.startIndex
        let n = Int(b[s + 17]) << 8 | Int(b[s + 18])
        guard b.count >= 19 + n else { return nil }
        return (b[s] == 1, String(decoding: b[(s + 19)..<(s + 19 + n)], as: UTF8.self), 19 + n)
    }

    static func tcpRequest(host: String, port: Int) -> Data {
        let h = Data(host.utf8)
        var d = Data([0])
        d.appendBE16(UInt16(h.count))
        d.append(h)
        d.appendBE16(UInt16(clamping: port))
        return d
    }

    /// ServerResponse: ok(1) udpSessionID(4) len(2) msg.
    static func tcpResponse(_ b: Data) -> (Bool, String, Int)? {
        guard b.count >= 7 else { return nil }
        let s = b.startIndex
        let n = Int(b[s + 5]) << 8 | Int(b[s + 6])
        guard b.count >= 7 + n else { return nil }
        return (b[s] == 1, String(decoding: b[(s + 7)..<(s + 7 + n)], as: UTF8.self), 7 + n)
    }

}

final class NCHysteria1Connection {
    enum State { case idle, connecting, ready, failed, closed }

    private let server: String, port: Int
    private let auth: Data
    private let sendBPS: UInt64, recvBPS: UInt64
    private let sni: String, alpn: [String], allowInsecure: Bool
    let queue: DispatchQueue
    private(set) var state: State = .idle
    private(set) var group: NWConnectionGroup?
    // Packet layer (feat/nc-proto2): obfs / wechat-video / port hopping run in a loopback shim.
    private let ports: [UInt16]
    private let hopInterval: TimeInterval
    private let obfsKey: Data?
    private let wechat: Bool
    private var shim: NCHy1PacketShim?
    // UDP relay state (NCHysteria1UDP.swift).
    var udpSessions: [UInt32: (handler: (Data) -> Void, stream: NCHy2StreamChannel)] = [:]
    var datagramFlow: NWConnection?
    private var defragger = NCHy1UDP.Defragger()
    func defragFeed(_ m: NCHy1UDP.Message) -> NCHy1UDP.Message? { defragger.feed(m) }
    private var control: NCHy2StreamChannel?
    private var controlBuffer = Data()
    private var startCompletion: ((Error?) -> Void)?

    init?(proxy: NCProxy, queue: DispatchQueue) {
        let portList = NCHy1Obfs.parsePorts(proxy.fields["ports"]?.string)
        guard let server = proxy.server, let port = proxy.port ?? portList?.first.map(Int.init) else { return nil }
        self.server = server
        self.port = port
        ports = portList ?? []
        hopInterval = TimeInterval(proxy.fields["hop-interval"]?.int ?? 10)
        if let o = proxy.fields["obfs"]?.string, !o.isEmpty { obfsKey = Data(o.utf8) } else { obfsKey = nil }
        let proto = (proxy.fields["obfs-protocol"]?.string ?? proxy.fields["protocol"]?.string ?? "udp").lowercased()
        wechat = proto == "wechat-video"
        if let a = proxy.fields["auth"]?.string, !a.isEmpty {
            guard let d = Data(base64Encoded: a) else { return nil }
            auth = d
        } else {
            auth = Data((proxy.fields["auth-str"]?.string ?? "").utf8)
        }
        var up = NCHy1.bps(proxy.fields["up"]?.string ?? proxy.fields["up"]?.int.map { String($0) })
        var down = NCHy1.bps(proxy.fields["down"]?.string ?? proxy.fields["down"]?.int.map { String($0) })
        if let u = proxy.fields["up-speed"]?.int, u > 0 { up = UInt64(u) * 125_000 }
        if let d = proxy.fields["down-speed"]?.int, d > 0 { down = UInt64(d) * 125_000 }
        guard up > 0, down > 0 else { return nil }
        sendBPS = up; recvBPS = down
        sni = proxy.fields["sni"]?.string ?? server
        alpn = proxy.fields["alpn"]?.array?.compactMap { $0.string } ?? ["hysteria"]
        allowInsecure = proxy.fields["skip-cert-verify"]?.bool ?? false
        self.queue = queue
    }

    func start(completion: @escaping (Error?) -> Void) {
        guard state == .idle else {
            queue.async { completion(NCConnector.Failure.handshake("hysteria already started")) }
            return
        }
        state = .connecting
        startCompletion = completion
        let quic = NWProtocolQUIC.Options(alpn: alpn)
        let tls = quic.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        if !sni.isEmpty { sec_protocol_options_set_tls_server_name(tls, sni) }
        if allowInsecure { sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, queue) }
        quic.idleTimeout = 30_000
        quic.maxDatagramFrameSize = 1400 // EnableDatagrams (UDP relay)
        let shimmed = obfsKey != nil || wechat || ports.count > 1
        if shimmed { quic.maxUDPPayloadSize = 1200 } // room for the XPlus salt + wechat header on the wire
        let params = NWParameters(quic: quic)
        var endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        if shimmed {
            // QUIC → 127.0.0.1:<shim> → obfuscated / hopping UDP → server. Leave room for salt + wechat header.
            guard let sh = NCHy1PacketShim(server: server, ports: ports.isEmpty ? [UInt16(clamping: port)] : ports,
                                           hopInterval: hopInterval, xplusKey: obfsKey, wechat: wechat, queue: queue),
                  let lp = NWEndpoint.Port(rawValue: sh.localPort) else {
                finish(NCConnector.Failure.handshake("hysteria: packet shim failed"))
                return
            }
            shim = sh
            endpoint = .hostPort(host: "127.0.0.1", port: lp)
        } else {
            NCOutboundBinding.apply(params, host: server)
        }
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
        group.newConnectionHandler = { [weak self] incoming in
            // A server-side flow can only be the datagram flow (v1 servers open no streams).
            guard let self else { incoming.cancel(); return }
            incoming.stateUpdateHandler = { [weak self] st in
                if case .ready = st { self?.readDatagrams(incoming) }
                if case .failed = st { incoming.cancel() }
                if case .cancelled = st { incoming.stateUpdateHandler = nil }
            }
            incoming.start(queue: self.queue)
        }
        group.start(queue: queue)
        guard let conn = group.extract(connectionTo: nil, using: nil) else {
            finish(NCConnector.Failure.handshake("hysteria: cannot open control stream"))
            return
        }
        let ch = NCHy2StreamChannel(conn: conn)
        control = ch
        ch.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.finish(err); return }
            ch.send(NCHy1.clientHello(sendBPS: self.sendBPS, recvBPS: self.recvBPS, auth: self.auth))
            self.readServerHello()
        }
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.finish(NCConnector.Failure.handshake("hysteria handshake timeout"))
        }
    }

    private func readServerHello() {
        control?.receive { [weak self] data, error in
            guard let self, self.state == .connecting else { return }
            guard let data else {
                self.finish(error ?? NCConnector.Failure.handshake("hysteria control stream closed"))
                return
            }
            self.controlBuffer.append(data)
            guard let (ok, msg, _) = NCHy1.serverHello(self.controlBuffer) else {
                self.readServerHello()
                return
            }
            self.controlBuffer = Data()
            if ok {
                self.state = .ready
                self.finish(nil)
                self.drainControl()
            } else {
                self.finish(NCConnector.Failure.handshake("hysteria auth error: \(msg)"))
            }
        }
    }

    /// The control stream stays open for the session; nothing more is expected on it.
    private func drainControl() {
        control?.receive { [weak self] data, _ in
            guard let self else { return }
            if data == nil {
                if self.state == .ready { self.state = .failed; self.close(keepState: true) }
                return
            }
            self.drainControl()
        }
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
        for (_, s) in udpSessions { s.stream.cancel() }
        udpSessions.removeAll()
        datagramFlow?.cancel(); datagramFlow = nil
        shim?.close(); shim = nil
        control?.cancel(); control = nil
        group?.cancel(); group = nil
    }

    func openTCP(target: NCTarget) -> NCRelayStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        let s = NCHysteria1TCPStream(channel: NCHy2StreamChannel(conn: conn), target: target, queue: queue)
        s.begin()
        return s
    }
}

/// One hysteria v1 TCP flow: request header out, ServerResponse in, then raw bytes. Sends before the server
/// accepts are buffered (mihomo's non-fast-open path waits the same way before returning the conn).
final class NCHysteria1TCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let target: NCTarget
    private let queue: DispatchQueue
    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking
    private var head = Data()
    private var outbox = Data()
    private var inbox: [Data] = []
    private var pending: ((Data?, Error?) -> Void)?
    private var failure: Error?

    init(channel: NCHy2StreamChannel, target: NCTarget, queue: DispatchQueue) {
        self.channel = channel
        self.target = target
        self.queue = queue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.fail(err); return }
            self.channel.send(NCHy1.tcpRequest(host: self.target.host, port: self.target.port))
            self.loop()
        }
    }

    func send(_ data: Data) {
        switch phase {
        case .handshaking: outbox.append(data)
        case .open: channel.send(data)
        default: break
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !inbox.isEmpty { handler(inbox.removeFirst(), nil); return }
        if phase == .failed { handler(nil, failure); return }
        if phase == .closed { handler(nil, nil); return }
        pending = handler
    }

    func cancel() {
        phase = .closed
        channel.cancel()
    }

    private func loop() {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.phase == .handshaking || self.phase == .open {
                    self.phase = .closed
                    if let h = self.pending { self.pending = nil; h(nil, error) }
                }
                return
            }
            if self.phase == .handshaking {
                self.head.append(data)
                guard let (ok, msg, used) = NCHy1.tcpResponse(self.head) else {
                    if self.head.count > 65536 { self.fail(NCConnector.Failure.handshake("hysteria response overflow")); return }
                    self.loop()
                    return
                }
                guard ok else { self.fail(NCConnector.Failure.handshake("hysteria connection rejected: \(msg)")); return }
                let rest = Data(self.head.dropFirst(used))
                self.head = Data()
                self.phase = .open
                if !self.outbox.isEmpty { self.channel.send(self.outbox); self.outbox = Data() }
                if !rest.isEmpty { self.deliver(rest) }
            } else if self.phase == .open {
                self.deliver(data)
            } else {
                return
            }
            self.loop()
        }
    }

    private func deliver(_ d: Data) {
        if let h = pending { pending = nil; h(d, nil) } else { inbox.append(d) }
    }

    private func fail(_ e: Error) {
        phase = .failed
        failure = e
        channel.cancel()
        if let h = pending { pending = nil; h(nil, e) }
    }
}

extension NCConnector {
    private static var hy1Registry: [String: NCHysteria1Connection] = [:]
    private static let hy1Lock = NSLock()

    /// One shared QUIC session per proxy, reconnected when it failed or closed (openStreamWithReconnect).
    static func hysteria1Stream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let why = NCSupport.hysteriaUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported(why)) }
            return
        }
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        hy1Lock.lock()
        if let c = hy1Registry[key], c.state == .ready || c.state == .connecting {
            hy1Lock.unlock()
            waitHy1(c, target: target, queue: queue, attempts: 60, completion: completion)
            return
        }
        guard let c = NCHysteria1Connection(proxy: proxy, queue: queue) else {
            hy1Lock.unlock()
            queue.async { completion(nil, Failure.handshake("hysteria bad config (auth / up / down)")) }
            return
        }
        hy1Registry[key] = c
        hy1Lock.unlock()
        c.start { err in
            if let err {
                hy1Lock.lock()
                if hy1Registry[key] === c { hy1Registry.removeValue(forKey: key) }
                hy1Lock.unlock()
                completion(nil, err)
                return
            }
            if let s = c.openTCP(target: target) { completion(s, nil) }
            else { completion(nil, Failure.handshake("hysteria open stream failed")) }
        }
    }

    /// The shared, authenticated session for a proxy (UDP sessions; feat/nc-proto2). nil on failure.
    static func hysteria1Shared(proxy: NCProxy, queue: DispatchQueue, completion: @escaping (NCHysteria1Connection?) -> Void) {
        if NCSupport.hysteriaUnsupported(proxy) != nil { queue.async { completion(nil) }; return }
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        hy1Lock.lock()
        if let c = hy1Registry[key], c.state == .ready || c.state == .connecting {
            hy1Lock.unlock()
            waitHy1Ready(c, queue: queue, attempts: 60, completion: completion)
            return
        }
        guard let c = NCHysteria1Connection(proxy: proxy, queue: queue) else {
            hy1Lock.unlock()
            queue.async { completion(nil) }
            return
        }
        hy1Registry[key] = c
        hy1Lock.unlock()
        c.start { err in
            if err != nil {
                hy1Lock.lock()
                if hy1Registry[key] === c { hy1Registry.removeValue(forKey: key) }
                hy1Lock.unlock()
                completion(nil)
                return
            }
            completion(c)
        }
    }

    private static func waitHy1Ready(_ c: NCHysteria1Connection, queue: DispatchQueue, attempts: Int,
                                     completion: @escaping (NCHysteria1Connection?) -> Void) {
        switch c.state {
        case .ready: completion(c)
        case .connecting where attempts > 0:
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitHy1Ready(c, queue: queue, attempts: attempts - 1, completion: completion)
            }
        default: completion(nil)
        }
    }

    private static func waitHy1(_ c: NCHysteria1Connection, target: NCTarget, queue: DispatchQueue, attempts: Int,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        switch c.state {
        case .ready:
            if let s = c.openTCP(target: target) { completion(s, nil) }
            else { completion(nil, Failure.handshake("hysteria open stream failed")) }
        case .connecting where attempts > 0:
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitHy1(c, target: target, queue: queue, attempts: attempts - 1, completion: completion)
            }
        default:
            completion(nil, Failure.handshake("hysteria connection failed"))
        }
    }
}
