import Foundation
import Network
import os

/// Hysteria v1 client (protocol version 3, Clash.Meta v1.19.33 transport/hysteria/core) over Network.framework QUIC
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

    /// `up-speed` / `down-speed` (Mbps) as bytes per second; 0 when non-positive or it would overflow UInt64.
    static func mbpsToBytes(_ mbps: Int) -> UInt64 {
        guard mbps > 0 else { return 0 }
        let (v, o) = UInt64(mbps).multipliedReportingOverflow(by: 125_000)
        return o ? 0 : v
    }

    static func clientHello(sendBPS: UInt64, recvBPS: UInt64, auth: Data) -> Data {
        var d = Data([3])
        d.appendBE64(sendBPS)
        d.appendBE64(recvBPS)
        let a = auth.prefix(0xffff) // u16 length; init rejects longer, never trap here
        d.appendBE16(UInt16(a.count))
        d.append(a)
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
    /// nc-hy1-queue: the connection's own session queue (the #116 pattern, converged for hy2/tuic in #127):
    /// every piece of connection and stream state — the NW group, the streams registry, the control-stream
    /// parser, the UDP session table — is touched only here, no matter which caller (connector, data plane,
    /// UDP session) drives the connection. The queue passed to init is kept as `callbackQueue`: the start
    /// completion is delivered on it, exactly where callers used to get it when the group ran on their queue.
    let queue: DispatchQueue
    private let callbackQueue: DispatchQueue

    /// Lock-protected snapshot for cross-thread readers (the connector registry, UDP sessions): the state
    /// and the readiness waiters. State changes are driven from the session queue (close() also writes the
    /// snapshot directly, so registry readers see .closed at once); waiters are drained under the lock and
    /// fired outside it, each on its own caller queue — no polling.
    private struct Snapshot {
        var state: State = .idle
        var waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready } }

    private func setSnapshotState(_ state: State) {
        snapshot.withLock { $0.state = state }
    }

    /// Registers interest in readiness (the connector registry): ready → nil at once on `callerQueue`,
    /// failed/closed → the failure, connecting → queued until start resolves either way. Replaces the
    /// registry's old 0.25 s × 60 poll of `state` (nc-hy1-queue, mirroring NCHysteria2Connection.whenReady).
    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        enum Action { case now(Error?), wait }
        let action: Action = snapshot.withLock { snap in
            switch snap.state {
            case .ready:
                return .now(nil)
            case .failed, .closed:
                return .now(NCConnector.Failure.handshake("hysteria connection failed"))
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
    /// Vended TCP streams (session queue only), cancelled wholesale when the connection goes away.
    private var streams: [ObjectIdentifier: NCHysteria1TCPStream] = [:]
    // Packet layer (feat/nc-proto2): obfs / wechat-video / port hopping run in a loopback shim.
    private let ports: [UInt16]
    private let hopInterval: TimeInterval
    private let obfsKey: Data?
    private let wechat: Bool
    private var shim: NCHy1PacketShim?
    // UDP relay state (NCHysteria1UDP.swift), session queue only. Already a per-session-ID table —
    // readDatagrams dispatches by session ID, so concurrent UDP sessions never overwrite each other's
    // handler (no single-slot problem like the pre-#127 hy2 binding had).
    var udpSessions: [UInt32: (handler: (Data) -> Void, stream: NCHy2StreamChannel)] = [:]
    var datagramFlow: NWConnection?
    private var defragger = NCHy1UDP.Defragger()
    /// Session queue only (called from readDatagrams).
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
        let authData: Data
        if let a = proxy.fields["auth"]?.string, !a.isEmpty {
            guard let d = Data(base64Encoded: a) else { return nil }
            authData = d
        } else {
            authData = Data((proxy.fields["auth-str"]?.string ?? "").utf8)
        }
        // The client hello carries the auth with a u16 length (UInt16(count) trapped past 65535).
        guard authData.count <= 0xffff else { return nil }
        auth = authData
        var up = NCHy1.bps(proxy.fields["up"]?.string ?? proxy.fields["up"]?.int.map { String($0) })
        var down = NCHy1.bps(proxy.fields["down"]?.string ?? proxy.fields["down"]?.int.map { String($0) })
        // Mbps → bytes/s; an overflowing value is invalid (0 → node rejected below), like bps() does.
        if let u = proxy.fields["up-speed"]?.int, u > 0 { up = NCHy1.mbpsToBytes(u) }
        if let d = proxy.fields["down-speed"]?.int, d > 0 { down = NCHy1.mbpsToBytes(d) }
        guard up > 0, down > 0 else { return nil }
        sendBPS = up; recvBPS = down
        sni = proxy.fields["sni"]?.string ?? server
        alpn = proxy.fields["alpn"]?.array?.compactMap { $0.string } ?? ["hysteria"]
        allowInsecure = proxy.skipCertVerify
        self.callbackQueue = queue
        self.queue = NCSessionQueues.make("nc.hy1.\(server):\(port)")
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
            callbackQueue.async { completion(NCConnector.Failure.handshake("hysteria already started")) }
            return
        }
        startCompletion = completion
        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    /// Session queue only: build the QUIC group and run the ClientHello/ServerHello exchange on its
    /// first stream.
    private func startOnQueue() {
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
                    self.setSnapshotState(.failed)
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
                self.setSnapshotState(.ready)
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
                if self.state == .ready { self.setSnapshotState(.failed); self.close(keepState: true) }
                return
            }
            self.drainControl()
        }
    }

    private func finish(_ error: Error?) {
        if error != nil, state != .ready { setSnapshotState(.failed) }
        let c = startCompletion
        startCompletion = nil
        if let c {
            callbackQueue.async { c(error) }
        }
        notifyWaiters(error)
        if error != nil { close(keepState: true) }
    }

    func close(keepState: Bool = false) {
        if !keepState {
            // The snapshot flips synchronously so registry readers stop vending this connection at
            // once; the NW teardown itself is confined to the session queue like all other state.
            setSnapshotState(.closed)
            notifyWaiters(NCConnector.Failure.handshake("hysteria connection closed"))
        }
        ncOnSessionQueue(queue) {
            for stream in self.streams.values { stream.cancelFromConnection() }
            self.streams.removeAll()
            for (_, s) in self.udpSessions { s.stream.cancel() }
            self.udpSessions.removeAll()
            self.datagramFlow?.cancel()
            self.datagramFlow = nil
            self.shim?.close()
            self.shim = nil
            self.control?.cancel()
            self.control = nil
            self.group?.cancel()
            self.group = nil
        }
    }

    /// Open a proxied TCP flow. Returns nil unless the connection is ready; the returned stream
    /// performs the hysteria TCP request/response handshake internally and buffers sends until the
    /// server accepts. `callerQueue` is where the stream delivers receive handlers (the mux-session
    /// pattern: the caller's state stays on its own queue). Synchronous return via the session
    /// queue, like NCHysteria2Connection.openTCP.
    func openTCP(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        if NCSessionQueues.isCurrent(queue) { return openTCPOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openTCPOnQueue(target: target, callerQueue: callerQueue) }
    }

    private func openTCPOnQueue(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        let stream = NCHysteria1TCPStream(channel: NCHy2StreamChannel(conn: conn), target: target,
                                          queue: queue, callerQueue: callerQueue)
        streams[ObjectIdentifier(stream)] = stream
        stream.onFinished = { [weak self] in
            guard let self else { return }
            ncOnSessionQueue(self.queue) { self.streams.removeValue(forKey: ObjectIdentifier(stream)) }
        }
        stream.begin()
        return stream
    }
}

/// One hysteria v1 TCP flow: request header out, ServerResponse in, then raw bytes. Sends before the server
/// accepts are buffered (Clash.Meta's non-fast-open path waits the same way before returning the conn).
/// All stream state lives on the owning connection's session queue; the registered receive handler is
/// delivered on the caller queue recorded at openTCP (nc-hy1-queue, the NCHysteria2TCPStream shape).
final class NCHysteria1TCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let target: NCTarget
    /// The owning connection's session queue: all stream state lives here.
    private let queue: DispatchQueue
    /// Where the registered receive handler is delivered (recorded at openTCP, as in NCMuxStream).
    private let callerQueue: DispatchQueue
    var onFinished: () -> Void = {}

    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking
    private var head = Data()
    private var outbox = Data()
    private var inbox: NCDeque<Data> = [] // F13
    private var inboxBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?
    /// Completions of sends buffered in `outbox` until the server accepts; fired on flush/fail/cancel.
    private var outboxWaiters: [NCCallOnce] = []

    /// nc-memory: handshake outbox / reader-ahead inbox caps (see NCHysteria2TCPStream.maxQueuedBytes).
    static let maxQueuedBytes = 256 * 1024

    init(channel: NCHy2StreamChannel, target: NCTarget, queue: DispatchQueue, callerQueue: DispatchQueue) {
        self.channel = channel
        self.target = target
        self.queue = queue
        self.callerQueue = callerQueue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.fail(err); return }
            self.channel.send(NCHy1.tcpRequest(host: self.target.host, port: self.target.port))
            self.loop()
        }
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            switch self.phase {
            case .handshaking:
                guard self.outbox.count + data.count <= Self.maxQueuedBytes else {
                    once.call()
                    self.fail(NSError(domain: "NativeCore", code: 4,
                                      userInfo: [NSLocalizedDescriptionKey: "hysteria1 tcp send buffer overflow"]))
                    return
                }
                self.outbox.append(data); self.outboxWaiters.append(once)
            case .open:
                self.channel.send(data, completion: once.call)
            case .failed, .closed:
                once.call()
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
            if self.phase == .failed {
                let failure = self.failure
                self.callerQueue.async { handler(nil, failure) }
                return
            }
            if self.phase == .closed {
                self.callerQueue.async { handler(nil, nil) }
                return
            }
            self.pendingReceive = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            self.phase = .closed
            self.drainOutboxWaiters()
            self.channel.cancel()
            self.onFinished()
        }
    }

    /// Connection is going away: tear down without the onFinished callback
    /// (the connection clears its own registry).
    func cancelFromConnection() {
        ncOnSessionQueue(queue) {
            self.phase = .closed
            self.drainOutboxWaiters()
            self.channel.cancel()
            if let handler = self.pendingReceive {
                self.pendingReceive = nil
                self.callerQueue.async { handler(nil, nil) }
            }
        }
    }

    private func loop() {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.phase == .handshaking || self.phase == .open {
                    self.phase = .closed
                    if let handler = self.pendingReceive {
                        self.pendingReceive = nil
                        self.callerQueue.async { handler(nil, error) }
                    }
                    self.onFinished()
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
                if !self.outbox.isEmpty {
                    let waiters = self.outboxWaiters; self.outboxWaiters = []
                    self.channel.send(self.outbox) { waiters.forEach { $0.call() } }
                    self.outbox = Data()
                }
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
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(d, nil) }
        } else if inboxBytes + d.count <= Self.maxQueuedBytes {
            inboxBytes += d.count
            inbox.append(d)
        } else {
            fail(NSError(domain: "NativeCore", code: 4,
                         userInfo: [NSLocalizedDescriptionKey: "hysteria1 tcp receive buffer overflow"]))
        }
    }

    private func fail(_ e: Error) {
        phase = .failed
        failure = e
        drainOutboxWaiters()
        channel.cancel()
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(nil, e) }
        }
        onFinished()
    }
}

extension NCConnector {
    private static var hy1Registry: [String: NCHysteria1Connection] = [:]
    private static let hy1Lock = NSLock()

    /// nc-lifecycle: see NCConnector.closeAllSharedSessions.
    static var hy1SessionCount: Int {
        hy1Lock.lock(); defer { hy1Lock.unlock() }
        return hy1Registry.count
    }

    /// nc-lifecycle: drain the registry and close every connection it held
    /// (close() flips the state snapshot synchronously and notifies waiters).
    @discardableResult
    static func closeAllHy1Sessions() -> Int {
        hy1Lock.lock()
        let all = Array(hy1Registry.values)
        hy1Registry.removeAll()
        hy1Lock.unlock()
        for c in all { c.close() }
        return all.count
    }

    /// One shared QUIC session per proxy, reconnected when it failed or closed (openStreamWithReconnect).
    static func hysteria1Stream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        sharedHysteria1(proxy: proxy, queue: queue) { conn, err in
            guard let conn, let stream = conn.openTCP(target: target, callerQueue: queue) else {
                completion(nil, err ?? Failure.handshake("hysteria open stream failed"))
                return
            }
            completion(stream, nil)
        }
    }

    /// The shared, authenticated session for a proxy (UDP sessions; feat/nc-proto2). nil on failure.
    static func hysteria1Shared(proxy: NCProxy, queue: DispatchQueue, completion: @escaping (NCHysteria1Connection?) -> Void) {
        sharedHysteria1(proxy: proxy, queue: queue) { conn, _ in completion(conn) }
    }

    /// nc-hy1-queue: the sharedHysteria2 registry shape — a live connection is vended at once, a
    /// connecting one is awaited through its one-shot whenReady (no 0.25 s polling), and a failed or
    /// closed one is evicted (identity-checked) and redialed.
    private static func sharedHysteria1(proxy: NCProxy, queue: DispatchQueue,
                                        completion: @escaping (NCHysteria1Connection?, Error?) -> Void) {
        if let why = NCSupport.hysteriaUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported(why)) }
            return
        }
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        hy1Lock.lock()
        if let existing = hy1Registry[key] {
            hy1Lock.unlock()
            if existing.isAlive {
                completion(existing, nil)
            } else if existing.state == .connecting {
                existing.whenReady(callerQueue: queue) { err in
                    if let err {
                        hy1Lock.lock()
                        if hy1Registry[key] === existing { hy1Registry.removeValue(forKey: key) }
                        hy1Lock.unlock()
                        completion(nil, err)
                    } else {
                        completion(existing, nil)
                    }
                }
            } else {
                hy1Lock.lock()
                hy1Registry.removeValue(forKey: key)
                hy1Lock.unlock()
                sharedHysteria1(proxy: proxy, queue: queue, completion: completion)
            }
            return
        }
        guard let conn = NCHysteria1Connection(proxy: proxy, queue: queue) else {
            hy1Lock.unlock()
            queue.async { completion(nil, Failure.handshake("hysteria bad config (auth / up / down)")) }
            return
        }
        hy1Registry[key] = conn
        hy1Lock.unlock()
        conn.start { err in
            if err == nil {
                completion(conn, nil)
            } else {
                hy1Lock.lock()
                if hy1Registry[key] === conn { hy1Registry.removeValue(forKey: key) }
                hy1Lock.unlock()
                completion(nil, err)
            }
        }
    }
}
