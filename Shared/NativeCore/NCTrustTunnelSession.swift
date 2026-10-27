import Foundation
import Network
import Security
import os

/// TrustTunnel session layer: HTTP/2 over TLS (Track A) and HTTP/3 over QUIC (Track B), TCP + UDP.
///
/// Specification:
/// - TrustTunnel Protocol Specification v1.0 (AdGuard, Apache 2.0): CONNECT host:port per TCP flow,
///   CONNECT `_udp2` carrying length-prefixed UDP packets (§6), Basic proxy-authorization.
/// - Track A: HTTP/2 (RFC 9113) on the shared NCH2MuxCore.
/// - Track B (fix/nc-trusttunnel-h3): HTTP/3 (RFC 9114) on the NativeCore H3 CONNECT stack
///   (NCH3ProxyConnection: control stream + SETTINGS, DATA framing, static-only QPACK) — the same code the
///   naive / Shadowrocket HTTP3 outbound runs. Optional H2 fallback when the QUIC connection cannot be
///   established (`h2-fallback`, default true; spec §3.3), with a short back-off so a UDP-blocked network
///   does not pay the QUIC timeout on every flow.
/// - Threading: conforms to #116 pattern; all session/stream state is touched only on serial session queues.
/// 需同步 feat/nc-kernel.
public enum NCTrustTunnelSessionManager {

    private static var h2Sessions: [String: NCTrustTunnelH2Session] = [:]
    private static var h3Conns: [String: NCH3ProxyConnection] = [:]
    /// sessionKey → time until which H3 is skipped (H2 fallback in use after a failed QUIC dial).
    private static var h3BackoffUntil: [String: Date] = [:]
    private static let lock = NSLock()
    static var h3Backoff: TimeInterval = 60

    /// Clear all active sessions (for tests and network state resets).
    @discardableResult
    public static func reset() -> Int {
        lock.lock()
        let h2All = Array(h2Sessions.values)
        let h3All = Array(h3Conns.values)
        h2Sessions.removeAll()
        h3Conns.removeAll()
        h3BackoffUntil.removeAll()
        lock.unlock()
        for s in h2All { s.close() }
        for c in h3All { c.close() }
        return h2All.count + h3All.count
    }

    struct Params {
        var name: String
        var server: String
        var port: Int
        var username: String
        var password: String
        var sni: String
        var skipCert: Bool
        var maxStreams: Int
        var quic: Bool
        var fallbackH2: Bool
        var baseKey: String { "\(name)|\(server)|\(port)" }
    }

    static func params(_ proxy: NCProxy) -> Params? {
        guard let server = proxy.server, !server.isEmpty else { return nil }
        let f = proxy.fields
        let net = (f["network"]?.string ?? "").lowercased()
        let quic = f["quic"]?.bool ?? (net == "h3" || net == "quic")
        let fallback = f["h2-fallback"]?.bool ?? f["fallback-h2"]?.bool ?? f["h2_fallback"]?.bool ?? true
        return Params(
            name: proxy.name,
            server: server,
            port: proxy.port ?? NCTrustTunnel.defaultPort,
            username: f["username"]?.string ?? "",
            password: proxy.password ?? f["password"]?.string ?? "",
            sni: f["sni"]?.string ?? f["servername"]?.string ?? server,
            skipCert: f["skip-cert-verify"]?.bool ?? false,
            maxStreams: Int(f["max-streams"]?.number ?? 12),
            quic: quic,
            fallbackH2: fallback
        )
    }

    /// `:authority` per spec §11.3: host:port, [v6]:port, or a bare reserved pseudo-host (`_udp2` …).
    static func authority(for target: NCTarget) -> String {
        let h = target.host
        if h == NCTrustTunnelWire.udpPseudoHost || h == NCTrustTunnelWire.icmpPseudoHost
            || h == NCTrustTunnelWire.checkPseudoHost {
            return h
        }
        let bare = h.hasPrefix("[") && h.hasSuffix("]") ? String(h.dropFirst().dropLast()) : h
        if case .v6? = NCIP(bare) { return "[\(bare)]:\(target.port)" }
        return "\(bare):\(target.port)"
    }

    /// Primary entry point for NCConnector dispatch (TCP flows and the `_udp2` multiplexer stream).
    static func connect(
        proxy: NCProxy,
        target: NCTarget,
        queue: DispatchQueue,
        completion: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        guard let p = params(proxy) else {
            queue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel missing server")) }
            return
        }
        guard p.quic else {
            connectH2(p, target: target, queue: queue, completion: completion)
            return
        }
        if p.fallbackH2 {
            lock.lock()
            let until = h3BackoffUntil[p.baseKey]
            lock.unlock()
            if let until, until > Date() {
                connectH2(p, target: target, queue: queue, completion: completion)
                return
            }
        }
        connectH3(p, target: target, queue: queue) { stream, err, connectionFailed in
            if let stream { completion(stream, nil); return }
            guard connectionFailed, p.fallbackH2 else { completion(nil, err); return }
            lock.lock()
            h3BackoffUntil[p.baseKey] = Date().addingTimeInterval(h3Backoff)
            lock.unlock()
            connectH2(p, target: target, queue: queue, completion: completion)
        }
    }

    /// UDP through the `_udp2` multiplexer stream (spec §6), one stream per tunnel UDP flow bound to `target`.
    /// The stream is message oriented: one send = one datagram to `target`, one receive = one reply payload.
    /// Domain targets are resolved here (the wire carries only IP addresses).
    static func udpStream(
        proxy: NCProxy,
        target: NCTarget,
        queue: DispatchQueue,
        completion: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        guard let port = UInt16(exactly: target.port), port != 0 else {
            queue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel udp: bad port")) }
            return
        }
        func open(_ ip: NCIP) {
            connect(proxy: proxy, target: NCTarget(host: NCTrustTunnelWire.udpPseudoHost, port: 0), queue: queue) { s, e in
                guard let s else { completion(nil, e); return }
                completion(NCTrustTunnelUDPStream(inner: s, dst: ip, dstPort: port), nil)
            }
        }
        if let ip = NCIP(target.host) { open(ip); return }
        DispatchQueue.global(qos: .userInitiated).async {
            let ip = resolve(target.host)
            queue.async {
                guard let ip else {
                    completion(nil, NCConnector.Failure.handshake("trusttunnel udp: cannot resolve \(target.host)"))
                    return
                }
                open(ip)
            }
        }
    }

    private static func resolve(_ host: String) -> NCIP? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(first) }
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                          nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return NCIP(String(cString: buf))
    }

    // MARK: Track A dispatch

    private static func connectH2(_ p: Params, target: NCTarget, queue: DispatchQueue,
                                  completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let sessionKey = p.baseKey + "|h2"
        lock.lock()
        let existing = h2Sessions[sessionKey]
        if let existing, existing.isAlive && existing.activeStreamCount < p.maxStreams {
            lock.unlock()
            existing.openStream(target: target, callerQueue: queue, completion: completion)
            return
        }
        if let existing, existing.state == .connecting {
            lock.unlock()
            existing.whenReady(callerQueue: queue) { err in
                if let err {
                    lock.lock()
                    if h2Sessions[sessionKey] === existing { h2Sessions.removeValue(forKey: sessionKey) }
                    lock.unlock()
                    completion(nil, err)
                } else {
                    existing.openStream(target: target, callerQueue: queue, completion: completion)
                }
            }
            return
        }
        let session = NCTrustTunnelH2Session(
            key: sessionKey,
            server: p.server,
            port: p.port,
            username: p.username,
            password: p.password,
            sni: p.sni,
            skipCert: p.skipCert,
            maxStreams: p.maxStreams
        )
        h2Sessions[sessionKey] = session
        lock.unlock()

        session.start { err in
            if let err {
                lock.lock()
                if h2Sessions[sessionKey] === session { h2Sessions.removeValue(forKey: sessionKey) }
                lock.unlock()
                completion(nil, err)
                return
            }
            session.openStream(target: target, callerQueue: queue, completion: completion)
        }
    }

    // MARK: Track B dispatch

    /// QUIC connection options for the shared H3 CONNECT stack (NCH2H3ProxyOptions has no memberwise init:
    /// built through its own parser from an equivalent `http3` node). Credentials stay out of it: the
    /// TrustTunnel CONNECT headers are built here (spec §5.1 user-agent + proxy-authorization).
    static func h3Options(_ p: Params) -> NCH2H3ProxyOptions? {
        NCH2H3ProxyOptions(proxy: NCProxy(name: p.name, type: "http3", fields: [
            "server": .string(p.server), "port": .number(Double(p.port)),
            "sni": .string(p.sni), "skip-cert-verify": .bool(p.skipCert),
        ]))
    }

    /// completion(stream, error, connectionFailed): connectionFailed = the QUIC/H3 connection itself never
    /// became ready (the only case H2 fallback applies to; a CONNECT rejection such as 407 is final).
    private static func connectH3(_ p: Params, target: NCTarget, queue: DispatchQueue,
                                  completion: @escaping (NCRelayStream?, Error?, Bool) -> Void) {
        let key = p.baseKey + "|h3"
        guard let options = h3Options(p) else {
            queue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel h3: bad server / port"), true) }
            return
        }
        lock.lock()
        let conn: NCH3ProxyConnection
        var dial = false
        if let e = h3Conns[key], e.state == .ready || e.state == .connecting || e.state == .idle,
           e.state != .ready || e.load < NCH3ProxyConnection.maxStreams {
            conn = e
        } else {
            conn = NCH3ProxyConnection(key: "tt.\(key)", options: options)
            h3Conns[key] = conn
            dial = true
        }
        lock.unlock()
        if dial {
            conn.onClosed = { [weak conn] in
                lock.lock()
                if let conn, h3Conns[key] === conn { h3Conns[key] = nil }
                lock.unlock()
            }
            conn.start()
        }
        conn.whenReady(callerQueue: queue) { err in
            if let err { completion(nil, err, true); return }
            let headers = NCTrustTunnelWire.connectHeaders(authority: authority(for: target),
                                                           username: p.username, password: p.password)
            let box = NCTrustTunnelStreamBox()
            let stream = conn.openStream(headers: headers, naive: false, callerQueue: queue) { err in
                completion(err == nil ? box.get() : nil, err, false)
            }
            guard let stream else {
                queue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel h3: cannot open request stream"), false) }
                return
            }
            box.set(stream)
        }
    }
}

/// Hands a stream created synchronously to its own (asynchronous) ready callback.
private final class NCTrustTunnelStreamBox {
    private let lock = NSLock()
    private var stream: NCRelayStream?
    func set(_ s: NCRelayStream) { lock.lock(); stream = s; lock.unlock() }
    func get() -> NCRelayStream? { lock.lock(); defer { lock.unlock() }; return stream }
}

/// One tunnel UDP flow over a `_udp2` CONNECT stream (H2 or H3): datagrams are framed per spec §6.3 on the
/// way out and §6.4 frames are reassembled from the byte stream on the way in. Memory: one reassembly
/// buffer (bounded by one maximal frame) plus decoded payloads waiting for receive (bounded count).
final class NCTrustTunnelUDPStream: NCRelayStream {
    private let inner: NCRelayStream
    private let dstIP: Data
    private let dstPort: UInt16
    private let srcIP = Data(count: 16)
    private let srcPort: UInt16
    private let lock = NSLock()
    private var buffer = Data()
    private var ready: NCDeque<Data> = []

    static let maxFrame = 4 + 36 + 65535
    static let maxQueued = 64

    init(inner: NCRelayStream, dst: NCIP, dstPort: UInt16) {
        self.inner = inner
        self.dstIP = NCTrustTunnelWire.padIPAddress(dst.string) ?? Data(count: 16)
        self.dstPort = dstPort
        self.srcPort = UInt16.random(in: 1024...65535)
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !data.isEmpty, data.count <= 65507 else { completion(); return }
        inner.send(NCTrustTunnelWire.encodeClientPacket(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
                                                        dstPort: dstPort, payload: data),
                   completion: completion)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        let first = ready.popFirst()
        lock.unlock()
        if let first { handler(first, nil); return }
        inner.receive { [weak self] data, err in
            guard let self else { handler(nil, err); return }
            guard let data else { handler(nil, err); return }
            if let bad = self.ingest(data) { self.inner.cancel(); handler(nil, bad); return }
            self.receive(handler)
        }
    }

    /// Appends stream bytes and decodes every complete frame; returns an error for a malformed length.
    func ingest(_ data: Data) -> Error? {
        lock.lock()
        defer { lock.unlock() }
        buffer.append(data)
        var off = 0
        while let pkt = NCTrustTunnelWire.decodeServerPacket(data: buffer, offset: &off) {
            if ready.count < Self.maxQueued, !pkt.payload.isEmpty { ready.append(pkt.payload) }
        }
        buffer = off >= buffer.count ? Data() : Data(buffer[(buffer.startIndex + off)...])
        if buffer.count >= 4 {
            let b = buffer.startIndex
            let len = Int(buffer[b]) << 24 | Int(buffer[b + 1]) << 16 | Int(buffer[b + 2]) << 8 | Int(buffer[b + 3])
            if len < 36 || len + 4 > Self.maxFrame {
                buffer = Data()
                return NCConnector.Failure.handshake("trusttunnel udp: bad frame length \(len)")
            }
        }
        return nil
    }

    /// Decoded payloads waiting for receive (tests).
    var queued: Int { lock.lock(); defer { lock.unlock() }; return ready.count }

    func cancel() { inner.cancel() }
}

// MARK: - Track A: HTTP/2 over TLS

final class NCTrustTunnelH2Session {
    enum State { case connecting, ready, failed, closed }

    let key: String
    let server: String
    let port: Int
    let username: String
    let password: String
    let sni: String
    let skipCert: Bool
    let maxStreams: Int

    let queue: DispatchQueue
    private let snapshot = OSAllocatedUnfairLock(initialState: (state: State.connecting, tornDown: false))
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready && !$0.tornDown } }

    private let core = NCH2MuxCore()
    private var base: NCStream?
    private var streams: [Int: NCTrustTunnelH2Stream] = [:]
    private var readyWaiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []

    var activeStreamCount: Int {
        if NCSessionQueues.isCurrent(queue) { return streams.count }
        return queue.sync { streams.count }
    }

    init(
        key: String,
        server: String,
        port: Int,
        username: String,
        password: String,
        sni: String,
        skipCert: Bool,
        maxStreams: Int
    ) {
        self.key = key
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.sni = sni
        self.skipCert = skipCert
        self.maxStreams = maxStreams
        self.queue = NCSessionQueues.make("nc.tt.h2.\(key)")
    }

    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready:
                callerQueue.async { completion(nil) }
            case .failed, .closed:
                callerQueue.async { completion(NCConnector.Failure.handshake("trusttunnel h2 session not ready")) }
            case .connecting:
                self.readyWaiters.append((callerQueue, completion))
            }
        }
    }

    func start(completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            let raw = NCStream(
                to: self.server,
                port: self.port,
                tlsServerName: self.sni,
                allowInsecure: self.skipCert,
                alpn: ["h2"],
                queue: self.queue
            )
            self.base = raw
            raw.start { [weak self] err in
                guard let self else { return }
                ncOnSessionQueue(self.queue) {
                    if let err {
                        self.snapshot.withLock { $0.state = .failed; $0.tornDown = true }
                        let waiters = self.readyWaiters
                        self.readyWaiters = []
                        completion(err)
                        for w in waiters { w.queue.async { w.completion(err) } }
                        return
                    }
                    self.snapshot.withLock { $0.state = .ready }
                    raw.send(self.core.start())
                    self.startPump()
                    let waiters = self.readyWaiters
                    self.readyWaiters = []
                    completion(nil)
                    for w in waiters { w.queue.async { w.completion(nil) } }
                }
            }
        }
    }

    private func startPump() {
        guard let base, state == .ready else { return }
        base.conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                if let content, !content.isEmpty {
                    let result = self.core.feed(content)
                    if !result.outbound.isEmpty {
                        self.base?.send(result.outbound)
                    }
                    for event in result.events {
                        switch event {
                        case .responseHeaders(let streamID, let headers):
                            self.streams[streamID]?.handleHeaders(headers)
                        case .payload(let streamID, let data):
                            self.streams[streamID]?.handlePayload(data)
                        case .reset(let streamID):
                            self.streams[streamID]?.handleReset()
                        case .ended(let streamID):
                            self.streams[streamID]?.handleEnded()
                        case .windowIncreased:
                            for s in self.streams.values { s.flushSend() }
                        case .goaway:
                            self.close()
                            return
                        }
                    }
                }
                if isComplete || error != nil {
                    self.close()
                    return
                }
                if self.isAlive {
                    self.startPump()
                }
            }
        }
    }

    func openStream(
        target: NCTarget,
        callerQueue: DispatchQueue,
        completion: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        ncOnSessionQueue(queue) {
            guard self.isAlive, let base = self.base else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel h2 session closed")) }
                return
            }
            guard self.streams.count < self.maxStreams else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel max-streams exceeded")) }
                return
            }
            let authority = NCTrustTunnelSessionManager.authority(for: target)
            let headers = NCTrustTunnelWire.connectHeaders(
                authority: authority,
                username: self.username,
                password: self.password
            )
            let (streamID, frame) = self.core.openStream(headers: headers)
            base.send(frame)

            let stream = NCTrustTunnelH2Stream(
                session: self,
                streamID: streamID,
                target: target,
                queue: self.queue,
                callerQueue: callerQueue,
                onConnect: completion
            )
            self.streams[streamID] = stream
        }
    }

    func streamSend(_ streamID: Int, data: Data, completion: @escaping () -> Void) {
        guard let base else { completion(); return }
        let (frames, consumed) = core.makeData(streamID: streamID, data: data)
        if consumed > 0 {
            base.send(frames, completion: completion)
        } else {
            completion()
        }
    }

    func streamMakeData(_ streamID: Int, data: Data) -> (frames: Data, consumed: Int) {
        core.makeData(streamID: streamID, data: data)
    }

    func sendRaw(_ data: Data, completion: (() -> Void)? = nil) {
        if let completion {
            base?.send(data, completion: completion)
        } else {
            base?.send(data)
        }
    }

    func windowUpdate(streamID: Int, consumed: Int) {
        guard consumed > 0 else { return }
        let f = core.windowUpdate(streamID: streamID, consumed)
        if !f.isEmpty {
            base?.send(f)
        }
    }

    func forgetStream(_ streamID: Int) {
        core.forgetStream(streamID)
        streams.removeValue(forKey: streamID)
    }

    func rstStream(_ streamID: Int) {
        let f = core.rstStream(streamID)
        base?.send(f)
        forgetStream(streamID)
    }

    func close() {
        snapshot.withLock { $0.state = .closed; $0.tornDown = true }
        ncOnSessionQueue(queue) {
            let active = Array(self.streams.values)
            self.streams.removeAll()
            for s in active { s.handleReset() }
            self.base?.cancel()
            self.base = nil
        }
    }
}

final class NCTrustTunnelH2Stream: NCRelayStream {
    private weak var session: NCTrustTunnelH2Session?
    let streamID: Int
    let target: NCTarget
    let queue: DispatchQueue
    let callerQueue: DispatchQueue
    private var onConnect: ((NCRelayStream?, Error?) -> Void)?

    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking

    private var pendingSend = Data()
    private var sendWaiters: [(end: Int, once: NCCallOnce)] = []
    private var sendAppended = 0
    private var sendConsumed = 0

    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?

    static let maxPendingSend = 256 * 1024
    static let maxQueuedInbound = 256 * 1024

    init(
        session: NCTrustTunnelH2Session,
        streamID: Int,
        target: NCTarget,
        queue: DispatchQueue,
        callerQueue: DispatchQueue,
        onConnect: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        self.session = session
        self.streamID = streamID
        self.target = target
        self.queue = queue
        self.callerQueue = callerQueue
        self.onConnect = onConnect
    }

    func handleHeaders(_ headers: [(String, String)]) {
        guard phase == .handshaking else { return }
        let status = headers.first { $0.0 == ":status" }?.1 ?? ""
        if status == "200" {
            phase = .open
            if let cb = onConnect {
                onConnect = nil
                callerQueue.async { cb(self, nil) }
            }
            flushSend()
        } else if status == "407" {
            fail(NCConnector.Failure.handshake("trusttunnel: 407 Proxy Authentication Required"))
        } else {
            fail(NCConnector.Failure.handshake("trusttunnel: HTTP \(status)"))
        }
    }

    func handlePayload(_ data: Data) {
        guard phase == .open || phase == .handshaking else { return }
        guard inboxBytes + data.count <= Self.maxQueuedInbound else {
            fail(NCConnector.Failure.handshake("trusttunnel h2 stream inbound overflow"))
            return
        }
        if let handler = pendingReceive {
            pendingReceive = nil
            session?.windowUpdate(streamID: streamID, consumed: data.count)
            callerQueue.async { handler(data, nil) }
        } else {
            inbox.append(data)
            inboxBytes += data.count
        }
    }

    func handleEnded() {
        if phase == .open || phase == .handshaking {
            phase = .closed
            drainSendWaiters()
            if let cb = onConnect {
                onConnect = nil
                callerQueue.async { cb(nil, NCConnector.Failure.handshake("trusttunnel h2 stream closed")) }
            }
            if let handler = pendingReceive {
                pendingReceive = nil
                callerQueue.async { handler(nil, nil) }
            }
            session?.forgetStream(streamID)
        }
    }

    func handleReset() {
        if phase != .closed {
            fail(NCConnector.Failure.handshake("trusttunnel h2 stream reset"))
        }
    }

    func flushSend() {
        guard phase == .open, !pendingSend.isEmpty, let session else { return }
        let (frames, consumed) = session.streamMakeData(streamID, data: pendingSend)
        if consumed > 0 {
            pendingSend = Data(pendingSend.dropFirst(consumed))
            session.sendRaw(frames) { [weak self] in
                guard let self else { return }
                ncOnSessionQueue(self.queue) {
                    self.noteConsumed(consumed)
                }
            }
        }
    }

    private func noteConsumed(_ n: Int) {
        sendConsumed += n
        let due = sendWaiters.filter { $0.end <= sendConsumed }
        sendWaiters.removeAll { $0.end <= sendConsumed }
        due.forEach { $0.once.call() }
    }

    private func drainSendWaiters() {
        let all = sendWaiters
        sendWaiters = []
        all.forEach { $0.once.call() }
    }

    private func fail(_ error: Error) {
        guard phase != .closed && phase != .failed else { return }
        phase = .failed
        failure = error
        drainSendWaiters()
        if let cb = onConnect {
            onConnect = nil
            callerQueue.async { cb(nil, error) }
        }
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(nil, error) }
        }
        session?.rstStream(streamID)
    }

    // MARK: - NCRelayStream

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard self.phase == .open || self.phase == .handshaking else {
                once.call()
                return
            }
            guard self.pendingSend.count + data.count <= Self.maxPendingSend else {
                once.call()
                self.fail(NCConnector.Failure.handshake("trusttunnel h2 stream send overflow"))
                return
            }
            self.pendingSend.append(data)
            self.sendAppended += data.count
            self.sendWaiters.append((self.sendAppended, once))
            if self.phase == .open {
                self.flushSend()
            }
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.inbox.isEmpty {
                let data = self.inbox.removeFirst()
                self.inboxBytes -= data.count
                self.session?.windowUpdate(streamID: self.streamID, consumed: data.count)
                self.callerQueue.async { handler(data, nil) }
                return
            }
            if self.phase == .failed {
                let err = self.failure
                self.callerQueue.async { handler(nil, err) }
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
            if self.phase != .closed {
                self.phase = .closed
                self.drainSendWaiters()
                if let handler = self.pendingReceive {
                    self.pendingReceive = nil
                    self.callerQueue.async { handler(nil, nil) }
                }
                self.session?.rstStream(self.streamID)
            }
        }
    }
}

