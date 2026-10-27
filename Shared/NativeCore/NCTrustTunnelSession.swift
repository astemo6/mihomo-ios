import Foundation
import Network
import Security
import os

/// TrustTunnel session layer: HTTP/2 over TLS (Track A) and HTTP/3 over QUIC (Track B).
///
/// Specification:
/// - TrustTunnel Protocol Specification v1.0 (AdGuard VPN, Apache 2.0)
/// - HTTP/2 (RFC 7540 / RFC 9113) with CONNECT method & Basic Auth
/// - HTTP/3 (RFC 9114 / RFC 9220) with CONNECT method, QPACK (RFC 9204) & Basic Auth
/// - Threading: conforms to #116 pattern; all session/stream state is touched only on serial session queues.
public enum NCTrustTunnelSessionManager {

    private static var h2Sessions: [String: NCTrustTunnelH2Session] = [:]
    private static var h3Sessions: [String: NCTrustTunnelH3Session] = [:]
    private static let lock = NSLock()

    /// Clear all active sessions (for tests and network state resets).
    @discardableResult
    public static func reset() -> Int {
        lock.lock()
        let h2All = Array(h2Sessions.values)
        let h3All = Array(h3Sessions.values)
        h2Sessions.removeAll()
        h3Sessions.removeAll()
        lock.unlock()
        for s in h2All { s.close() }
        for s in h3All { s.close() }
        return h2All.count + h3All.count
    }

    /// Primary entry point for NCConnector dispatch.
    static func connect(
        proxy: NCProxy,
        target: NCTarget,
        queue: DispatchQueue,
        completion: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        guard let server = proxy.server, !server.isEmpty else {
            queue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel missing server")) }
            return
        }
        let port = proxy.port ?? NCTrustTunnel.defaultPort
        let username = proxy.fields["username"]?.string ?? ""
        let password = proxy.fields["password"]?.string ?? ""
        let isQUIC = proxy.fields["quic"]?.bool ?? (proxy.fields["network"]?.string == "h3")
        let sni = proxy.fields["sni"]?.string ?? proxy.fields["servername"]?.string ?? server
        let skipCert = proxy.fields["skip-cert-verify"]?.bool ?? false
        let maxStreams = Int(proxy.fields["max-streams"]?.number ?? 12)

        let sessionKey = "\(proxy.name)|\(server)|\(port)|\(isQUIC ? "h3" : "h2")"

        if isQUIC {
            lock.lock()
            let existing = h3Sessions[sessionKey]
            if let existing, existing.isAlive {
                lock.unlock()
                existing.openStream(target: target, callerQueue: queue, completion: completion)
                return
            }
            if let existing, existing.state == .connecting {
                lock.unlock()
                existing.whenReady(callerQueue: queue) { err in
                    if let err {
                        lock.lock()
                        if h3Sessions[sessionKey] === existing { h3Sessions.removeValue(forKey: sessionKey) }
                        lock.unlock()
                        completion(nil, err)
                    } else {
                        existing.openStream(target: target, callerQueue: queue, completion: completion)
                    }
                }
                return
            }
            let session = NCTrustTunnelH3Session(
                key: sessionKey,
                server: server,
                port: port,
                username: username,
                password: password,
                sni: sni,
                skipCert: skipCert
            )
            h3Sessions[sessionKey] = session
            lock.unlock()

            session.start { err in
                if let err {
                    lock.lock()
                    if h3Sessions[sessionKey] === session { h3Sessions.removeValue(forKey: sessionKey) }
                    lock.unlock()
                    completion(nil, err)
                    return
                }
                session.openStream(target: target, callerQueue: queue, completion: completion)
            }
        } else {
            lock.lock()
            let existing = h2Sessions[sessionKey]
            if let existing, existing.isAlive && existing.activeStreamCount < maxStreams {
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
                server: server,
                port: port,
                username: username,
                password: password,
                sni: sni,
                skipCert: skipCert,
                maxStreams: maxStreams
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
    }
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
            let authority: String
            if target.host == NCTrustTunnelWire.udpPseudoHost {
                authority = NCTrustTunnelWire.udpPseudoHost
            } else {
                authority = "\(target.host):\(target.port)"
            }
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

// MARK: - Track B: HTTP/3 over QUIC

final class NCTrustTunnelH3Session {
    enum State { case connecting, ready, failed, closed }

    let key: String
    let server: String
    let port: Int
    let username: String
    let password: String
    let sni: String
    let skipCert: Bool

    let queue: DispatchQueue
    private let snapshot = OSAllocatedUnfairLock(initialState: (state: State.connecting, tornDown: false))
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready && !$0.tornDown } }

    private var group: NWConnectionGroup?
    private var readyWaiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []

    init(
        key: String,
        server: String,
        port: Int,
        username: String,
        password: String,
        sni: String,
        skipCert: Bool
    ) {
        self.key = key
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.sni = sni
        self.skipCert = skipCert
        self.queue = NCSessionQueues.make("nc.tt.h3.\(key)")
    }

    private func makeQUICOptions() -> NWProtocolQUIC.Options {
        let quicOptions = NWProtocolQUIC.Options(alpn: ["h3"])
        let tlsOptions = quicOptions.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tlsOptions, .tlsProtocol13)
        if !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions, sni)
        }
        if skipCert {
            sec_protocol_options_set_verify_block(tlsOptions, { _, _, complete in complete(true) }, queue)
        }
        quicOptions.maxDatagramFrameSize = 1400
        return quicOptions
    }

    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready:
                callerQueue.async { completion(nil) }
            case .failed, .closed:
                callerQueue.async { completion(NCConnector.Failure.handshake("trusttunnel h3 session not ready")) }
            case .connecting:
                self.readyWaiters.append((callerQueue, completion))
            }
        }
    }

    func start(completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            let parameters = NWParameters(quic: self.makeQUICOptions())
            parameters.allowLocalEndpointReuse = true
            NCOutboundBinding.apply(parameters, host: self.server)

            let endpoint = NWEndpoint.hostPort(
                host: NWEndpoint.Host(self.server),
                port: NWEndpoint.Port(rawValue: UInt16(clamping: self.port)) ?? .any
            )
            let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
            self.group = group

            group.stateUpdateHandler = { [weak self] groupState in
                guard let self else { return }
                ncOnSessionQueue(self.queue) {
                    switch groupState {
                    case .ready:
                        if self.state == .connecting {
                            self.snapshot.withLock { $0.state = .ready }
                            let waiters = self.readyWaiters
                            self.readyWaiters = []
                            completion(nil)
                            for w in waiters { w.queue.async { w.completion(nil) } }
                        }
                    case .failed(let error):
                        if self.state == .connecting {
                            self.snapshot.withLock { $0.state = .failed; $0.tornDown = true }
                            let waiters = self.readyWaiters
                            self.readyWaiters = []
                            completion(error)
                            for w in waiters { w.queue.async { w.completion(error) } }
                        } else {
                            self.close()
                        }
                    default:
                        break
                    }
                }
            }
            group.start(queue: self.queue)
        }
    }

    func openStream(
        target: NCTarget,
        callerQueue: DispatchQueue,
        completion: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        ncOnSessionQueue(queue) {
            guard self.isAlive, let group = self.group else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel h3 session closed")) }
                return
            }
            guard let conn = group.extract(connectionTo: nil, using: nil) else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("trusttunnel h3 stream extract failed")) }
                return
            }
            let stream = NCTrustTunnelH3Stream(
                conn: conn,
                target: target,
                username: self.username,
                password: self.password,
                queue: self.queue,
                callerQueue: callerQueue,
                onConnect: completion
            )
            stream.begin()
        }
    }

    func close() {
        snapshot.withLock { $0.state = .closed; $0.tornDown = true }
        ncOnSessionQueue(queue) {
            self.group?.cancel()
            self.group = nil
        }
    }
}

final class NCTrustTunnelH3Stream: NCRelayStream {
    let conn: NWConnection
    let target: NCTarget
    let username: String
    let password: String
    let queue: DispatchQueue
    let callerQueue: DispatchQueue
    private var onConnect: ((NCRelayStream?, Error?) -> Void)?

    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking

    private var responseBuffer = Data()
    private var outbox = Data()
    private var outboxWaiters: [NCCallOnce] = []
    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?

    static let maxQueuedBytes = 256 * 1024

    init(
        conn: NWConnection,
        target: NCTarget,
        username: String,
        password: String,
        queue: DispatchQueue,
        callerQueue: DispatchQueue,
        onConnect: @escaping (NCRelayStream?, Error?) -> Void
    ) {
        self.conn = conn
        self.target = target
        self.username = username
        self.password = password
        self.queue = queue
        self.callerQueue = callerQueue
        self.onConnect = onConnect
    }

    func begin() {
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                switch state {
                case .ready:
                    let authority: String
                    if self.target.host == NCTrustTunnelWire.udpPseudoHost {
                        authority = NCTrustTunnelWire.udpPseudoHost
                    } else {
                        authority = "\(self.target.host):\(self.target.port)"
                    }
                    let qpack = NCTrustTunnelWire.qpackConnectHeaders(
                        authority: authority,
                        username: self.username,
                        password: self.password
                    )
                    let frame = NCHy2.http3HeadersFrame(fieldSection: qpack)
                    self.conn.send(content: frame, completion: .contentProcessed { [weak self] err in
                        guard let self else { return }
                        ncOnSessionQueue(self.queue) {
                            if let err { self.fail(err); return }
                            self.receiveHandshake()
                        }
                    })
                case .failed(let err):
                    self.fail(err)
                default:
                    break
                }
            }
        }
        conn.start(queue: queue)
    }

    private func receiveHandshake() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, err in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                if let content, !content.isEmpty {
                    self.responseBuffer.append(content)
                    if let parsed = self.tryParseH3Response() {
                        if parsed.status == "200" {
                            self.phase = .open
                            if let cb = self.onConnect {
                                self.onConnect = nil
                                self.callerQueue.async { cb(self, nil) }
                            }
                            if !self.outbox.isEmpty {
                                let w = self.outboxWaiters
                                self.outboxWaiters = []
                                let data = self.outbox
                                self.outbox = Data()
                                self.conn.send(content: data, completion: .contentProcessed { _ in
                                    w.forEach { $0.call() }
                                })
                            }
                            if !parsed.trailing.isEmpty {
                                self.deliver(parsed.trailing)
                            }
                            self.receiveLoop()
                            return
                        } else if parsed.status == "407" {
                            self.fail(NCConnector.Failure.handshake("trusttunnel: 407 Proxy Authentication Required"))
                            return
                        } else {
                            self.fail(NCConnector.Failure.handshake("trusttunnel: HTTP \(parsed.status)"))
                            return
                        }
                    } else if self.responseBuffer.count > Self.maxQueuedBytes {
                        self.fail(NCConnector.Failure.handshake("trusttunnel h3 response overflow"))
                        return
                    }
                }
                if isComplete || err != nil {
                    self.fail(err ?? NCConnector.Failure.handshake("trusttunnel h3 stream EOF during handshake"))
                    return
                }
                self.receiveHandshake()
            }
        }
    }

    private func tryParseH3Response() -> (status: String, trailing: Data)? {
        var off = 0
        guard let (frameType, tLen) = NCHy2.varintDecode(responseBuffer, at: off) else { return nil }
        off += tLen
        guard let (frameLen, lLen) = NCHy2.varintDecode(responseBuffer, at: off) else { return nil }
        off += lLen
        guard responseBuffer.count >= off + Int(frameLen) else { return nil }

        let payload = responseBuffer.subdata(in: (responseBuffer.startIndex + off)..<(responseBuffer.startIndex + off + Int(frameLen)))
        let trailing = Data(responseBuffer.dropFirst(off + Int(frameLen)))

        if frameType == 0x01 { // HEADERS
            if let headers = NCHy2.qpackDecodeFieldSection(payload) {
                let status = headers.first { $0.name == ":status" }?.value ?? ""
                return (status, trailing)
            }
        }
        return nil
    }

    private func receiveLoop() {
        guard phase == .open else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, err in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                if let content, !content.isEmpty {
                    self.deliver(content)
                }
                if isComplete || err != nil {
                    self.phase = .closed
                    self.drainWaiters()
                    if let handler = self.pendingReceive {
                        self.pendingReceive = nil
                        self.callerQueue.async { handler(nil, err) }
                    }
                    return
                }
                if self.phase == .open {
                    self.receiveLoop()
                }
            }
        }
    }

    private func deliver(_ data: Data) {
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(data, nil) }
        } else {
            inbox.append(data)
            inboxBytes += data.count
        }
    }

    private func drainWaiters() {
        let w = outboxWaiters
        outboxWaiters = []
        w.forEach { $0.call() }
    }

    private func fail(_ error: Error) {
        guard phase != .closed && phase != .failed else { return }
        phase = .failed
        failure = error
        drainWaiters()
        if let cb = onConnect {
            onConnect = nil
            callerQueue.async { cb(nil, error) }
        }
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(nil, error) }
        }
        conn.cancel()
    }

    // MARK: - NCRelayStream

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            switch self.phase {
            case .handshaking:
                guard self.outbox.count + data.count <= Self.maxQueuedBytes else {
                    once.call()
                    self.fail(NCConnector.Failure.handshake("trusttunnel h3 outbox overflow"))
                    return
                }
                self.outbox.append(data)
                self.outboxWaiters.append(once)
            case .open:
                self.conn.send(content: data, completion: .contentProcessed { _ in once.call() })
            case .failed, .closed:
                once.call()
            }
        }
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
                self.drainWaiters()
                if let handler = self.pendingReceive {
                    self.pendingReceive = nil
                    self.callerQueue.async { handler(nil, nil) }
                }
                self.conn.cancel()
            }
        }
    }
}
