import Foundation
import Network
import Security
import os

/// MASQUE (RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP) session and data plane connector.
///
/// Implements:
/// - RFC 9298: Proxying UDP in HTTP over HTTP/3 (Extended CONNECT, :protocol = connect-udp)
/// - RFC 9297: HTTP Datagrams over QUIC DATAGRAM frames (Quarter Stream ID + Context ID 0)
/// - Capsule Protocol fallback / streaming inside request stream DATA frames
/// - Multi-session registry & lifecycle on the session queue

// MARK: - Stream Channel Wrapper

final class NCMASQUEStreamChannel {
    private let conn: NWConnection
    private let lock = NSLock()
    private var started = false

    init(conn: NWConnection) {
        self.conn = conn
    }

    func start(queue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        let once = NCCallOnce {
            // Unset handler so state changes after ready do not double-fire
            self.conn.stateUpdateHandler = nil
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                once.call()
                completion(nil)
            case .failed(let err):
                once.call()
                completion(err)
            case .cancelled:
                once.call()
                completion(NCConnector.Failure.handshake("MASQUE stream channel cancelled"))
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    /// The stream's real QUIC id once ready (fix/nc-proto-masque-int: a local counter drifts as soon as two
    /// CONNECT-UDP streams open concurrently or one fails, and datagrams then land on the wrong flow).
    var quicStreamID: UInt64? {
        (conn.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata)?.streamIdentifier
    }

    func send(_ data: Data, completion: (() -> Void)? = nil) {
        conn.send(content: data, completion: .contentProcessed { _ in
            completion?()
        })
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let error {
                completion(nil, error)
            } else if isComplete, data == nil || data?.isEmpty == true {
                completion(nil, nil)
            } else {
                completion(data, nil)
            }
        }
    }

    func receiveMessage(completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void) {
        conn.receiveMessage(completion: completion)
    }

    func cancel() {
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}

// MARK: - UDP Relay Stream (NCRelayStream Conformer)

final class NCMASQUEUDPStream: NCRelayStream {
    let quarterStreamID: UInt64
    let target: NCTarget
    let callerQueue: DispatchQueue
    let channel: NCMASQUEStreamChannel
    private weak var connection: NCMASQUEConnection?

    private let lock = NSLock()
    private var receiveHandler: ((Data?, Error?) -> Void)?
    private var pendingReceives: [Data] = []
    private var closed = false
    private var capsuleParser = NCMASQUE.CapsuleParser()
    /// Unparsed tail of the request stream (an HTTP/3 frame split across receives).
    private var frameBuffer = Data()

    init(quarterStreamID: UInt64, target: NCTarget, callerQueue: DispatchQueue,
         channel: NCMASQUEStreamChannel, connection: NCMASQUEConnection) {
        self.quarterStreamID = quarterStreamID
        self.target = target
        self.callerQueue = callerQueue
        self.channel = channel
        self.connection = connection
    }

    // MARK: NCRelayStream

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        lock.lock()
        if closed || data.isEmpty {
            lock.unlock()
            once.call()
            return
        }
        lock.unlock()

        if let conn = connection {
            conn.sendDatagram(quarterStreamID: quarterStreamID, contextID: 0, payload: data) {
                once.call()
            }
        } else {
            once.call()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            callerQueue.async {
                handler(nil, NSError(domain: "NativeCore", code: 1,
                                    userInfo: [NSLocalizedDescriptionKey: "MASQUE stream closed"]))
            }
            return
        }
        if !pendingReceives.isEmpty {
            let chunk = pendingReceives.removeFirst()
            lock.unlock()
            callerQueue.async { handler(chunk, nil) }
            return
        }
        receiveHandler = handler
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let handler = receiveHandler
        receiveHandler = nil
        pendingReceives.removeAll()
        lock.unlock()

        channel.cancel()
        connection?.removeStream(quarterStreamID: quarterStreamID)
        if let handler {
            callerQueue.async {
                handler(nil, NSError(domain: "NativeCore", code: 2,
                                    userInfo: [NSLocalizedDescriptionKey: "MASQUE stream cancelled"]))
            }
        }
    }

    // MARK: Delivery from Connection

    func deliverPacket(_ packet: Data) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        if let handler = receiveHandler {
            receiveHandler = nil
            lock.unlock()
            callerQueue.async { handler(packet, nil) }
        } else {
            if pendingReceives.count < 32 {
                pendingReceives.append(packet)
            }
            lock.unlock()
        }
    }

    func deliverError(_ error: Error) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let handler = receiveHandler
        receiveHandler = nil
        pendingReceives.removeAll()
        lock.unlock()

        if let handler {
            callerQueue.async { handler(nil, error) }
        }
    }

    /// Background receive loop on the bidirectional request stream to accept
    /// DATAGRAM capsules (RFC 9297 §3.5) carried inside HTTP/3 DATA frames.
    func startCapsuleReceiveLoop() {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            if let error {
                self.deliverError(error)
                return
            }
            guard let data, !data.isEmpty else { return }
            self.frameBuffer.append(data)
            guard self.frameBuffer.count <= 256 * 1024 else {
                self.deliverError(NCConnector.Failure.handshake("MASQUE request stream frame too large"))
                return
            }
            // Walk complete HTTP/3 frames; DATA frames (type 0x00) carry capsules. A partial frame stays buffered.
            let buf = self.frameBuffer
            var offset = 0
            while offset < buf.count {
                guard let (type, tLen) = NCMASQUE.varintDecode(buf, at: offset),
                      let (len, lLen) = NCMASQUE.varintDecode(buf, at: offset + tLen) else { break }
                let hLen = tLen + lLen
                let payloadLen = Int(len)
                guard offset + hLen + payloadLen <= buf.count else { break }
                let s0 = buf.startIndex + offset + hLen
                offset += hLen + payloadLen
                guard type == 0x00 else { continue }
                let capsules = self.capsuleParser.feed(Data(buf[s0..<(s0 + payloadLen)]))
                for cap in capsules where cap.type == NCMASQUE.capsuleTypeDatagram {
                    // Capsule payload: Context ID (varint) + UDP payload
                    if let (ctxID, cLen) = NCMASQUE.varintDecode(cap.value, at: 0), ctxID == 0 {
                        self.deliverPacket(Data(cap.value[(cap.value.startIndex + cLen)...]))
                    }
                }
            }
            self.frameBuffer = offset >= buf.count ? Data() : Data(buf[(buf.startIndex + offset)...])
            self.startCapsuleReceiveLoop()
        }
    }

}

// MARK: - MASQUE Connection (QUIC Group + H3 Handshake)

final class NCMASQUEConnection {
    enum State: Equatable {
        case idle
        case connecting
        case ready
        case failed
        case closed
    }

    let config: NCMASQUE.Config
    let server: String
    let port: Int
    let queue: DispatchQueue
    let callbackQueue: DispatchQueue

    private(set) var state: State = .idle
    private var group: NWConnectionGroup?
    private var controlChannel: NCMASQUEStreamChannel?
    private var serverControlChannel: NCMASQUEStreamChannel?
    private var datagramChannel: NCMASQUEStreamChannel?

    private var nextStreamID: UInt64 = 0
    private var streams: [UInt64: NCMASQUEUDPStream] = [:]
    /// fix/nc-masque-ip: CONNECT-IP request streams (quarter stream id -> packet sink, called on `queue`).
    private var ipSinks: [UInt64: (Data) -> Void] = [:]
    private var waiters: [(Error?) -> Void] = []
    private var startCompletion: ((Error?) -> Void)?
    private var handshakeOpened = false
    /// WARP: set by the TLS verify block when the server key did not match `public-key` (read under `lock`).
    private var pinMismatch = false
    /// WARP: the server key matched; a QUIC failure before `.ready` after this is the server refusing our client
    /// certificate (key not enrolled) — reported as NCMASQUEWarp.warpRejected.
    private var pinMatched = false
    private let lock = NSLock()

    var isAlive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .ready
    }

    init(config: NCMASQUE.Config, queue: DispatchQueue) {
        self.config = config
        self.server = config.server
        self.port = config.port
        self.callbackQueue = queue
        self.queue = NCSessionQueues.make("nc.masque.\(config.server):\(config.port)")
    }

    func whenReady(callerQueue: DispatchQueue, _ completion: @escaping (Error?) -> Void) {
        lock.lock()
        if state == .ready {
            lock.unlock()
            callerQueue.async { completion(nil) }
            return
        }
        if state == .failed || state == .closed {
            lock.unlock()
            callerQueue.async { completion(NCConnector.Failure.handshake("MASQUE connection not available")) }
            return
        }
        waiters.append { err in
            callerQueue.async { completion(err) }
        }
        lock.unlock()
    }

    func start(completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard state == .idle else {
            lock.unlock()
            callbackQueue.async { completion(NCConnector.Failure.handshake("MASQUE already started")) }
            return
        }
        state = .connecting
        startCompletion = completion
        lock.unlock()

        // WARP: build (or reuse) the mTLS identity before dialing, so a bad key fails here with its own message.
        if config.isWarp, NCMASQUEWarp.cachedIdentity(config: config) == nil {
            finishStart(NCMASQUEWarp.WarpError.warpIdentityFailed(NCMASQUEWarp.warpIdentityFailed))
            return
        }

        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    private func makeQUICOptions() -> NWProtocolQUIC.Options {
        let alpn = config.alpn.isEmpty ? ["h3"] : config.alpn
        let quicOptions = NWProtocolQUIC.Options(alpn: alpn)
        let tlsOptions = quicOptions.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tlsOptions, .tlsProtocol13)
        let effectiveSNI = (config.sni != nil && !config.sni!.isEmpty)
            ? config.sni
            : (config.isWarp ? NCMASQUE.defaultWarpSNI : nil)
        if let effectiveSNI, !effectiveSNI.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions, effectiveSNI)
        }
        if config.isWarp {
            if let identity = NCMASQUEWarp.cachedIdentity(config: config) {
                if let sid = sec_identity_create(identity) {
                    sec_protocol_options_set_local_identity(tlsOptions, sid)
                }
            }
            // Server SPKI pinning: overrides skipCertVerify (pinning is always enforced for WARP)
            let configuredPoint = config.publicKey.flatMap { NCMASQUEWarp.publicPoint(fromConfiguredKey: $0) }
            sec_protocol_options_set_verify_block(tlsOptions, { [weak self] _, trustRef, complete in
                guard let expectedPoint = configuredPoint else {
                    complete(false)
                    return
                }
                let secTrust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                let chain = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? []
                guard let leaf = chain.first else {
                    complete(false)
                    return
                }
                let leafDER = SecCertificateCopyData(leaf) as Data
                let matched = NCMASQUEWarp.peerPointMatches(leafCertDER: leafDER, configuredPoint: expectedPoint)
                if let self {
                    self.lock.lock()
                    if matched { self.pinMatched = true } else { self.pinMismatch = true }
                    self.lock.unlock()
                }
                complete(matched)
            }, queue)
        } else if config.skipCertVerify {
            sec_protocol_options_set_verify_block(tlsOptions, { _, _, complete in complete(true) }, queue)
        }
        quicOptions.maxDatagramFrameSize = 1400
        return quicOptions
    }

    private func startOnQueue() {
        let parameters = NWParameters(quic: makeQUICOptions())
        parameters.allowLocalEndpointReuse = true
        NCOutboundBinding.apply(parameters, host: server)

        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
        self.group = group

        group.stateUpdateHandler = { [weak self] (groupState: NWConnectionGroup.State) in
            guard let self else { return }
            switch groupState {
            case .ready:
                self.openHandshakeStreams()
            case .failed(let err):
                self.finishStart(err)
            case .cancelled:
                self.finishStart(NCConnector.Failure.handshake("MASQUE connection group cancelled"))
            default:
                break
            }
        }

        group.newConnectionHandler = { [weak self] (incoming: NWConnection) in
            // Adopt server's unidirectional control stream (RFC 9114)
            guard let self else { incoming.cancel(); return }
            self.acceptServerControlStream(incoming)
        }

        group.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let pending = (self.state == .connecting)
            self.lock.unlock()
            if pending {
                self.finishStart(NCConnector.Failure.handshake("MASQUE connection timeout"))
            }
        }
    }

    private func openHandshakeStreams() {
        guard !handshakeOpened else { return }
        handshakeOpened = true

        guard let group,
              let controlConn = group.extract(connectionTo: nil,
                                              using: NCQUICStreamOptions.unidirectional(from: group,
                                                                                        fallback: makeQUICOptions)) else {
            finishStart(NCConnector.Failure.handshake("MASQUE cannot open control stream"))
            return
        }
        let ch = NCMASQUEStreamChannel(conn: controlConn)
        controlChannel = ch

        ch.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.finishStart(err); return }

            // RFC 9114: send Stream Type 0x00 (control stream) followed by SETTINGS frame
            var flight = NCMASQUE.varintEncode(0x00)
            flight.append(NCMASQUE.http3SettingsFrame())
            ch.send(flight) { [weak self] in
                guard let self else { return }
                self.ensureDatagramChannel()
                self.finishStart(nil)
            }
        }
    }

    private func acceptServerControlStream(_ conn: NWConnection) {
        guard serverControlChannel == nil else { conn.cancel(); return }
        let ch = NCMASQUEStreamChannel(conn: conn)
        serverControlChannel = ch
        ch.start(queue: queue) { [weak self] err in
            guard let self, err == nil else { return }
            self.drainServerControl()
        }
    }

    private func drainServerControl() {
        serverControlChannel?.receive { [weak self] data, _ in
            guard let self else { return }
            guard data != nil else { return }
            self.drainServerControl()
        }
    }

    private func finishStart(_ failure: Error?) {
        lock.lock()
        // WARP: a handshake that died in the pinning check reports that, not Network.framework's generic TLS error.
        var error = failure
        if failure != nil, config.isWarp, state == .connecting {
            if pinMismatch {
                error = NCMASQUEWarp.WarpError.warpPinMismatch(NCMASQUEWarp.warpPinMismatch)
            } else if pinMatched, failure is NWError {
                error = NCMASQUEWarp.WarpError.warpRejected(NCMASQUEWarp.warpRejected)
            }
        }
        if let error {
            state = .failed
        } else {
            state = .ready
        }
        let comp = startCompletion
        startCompletion = nil
        let waiting = waiters
        waiters.removeAll()
        lock.unlock()

        if let comp {
            callbackQueue.async { comp(error) }
        }
        for w in waiting {
            w(error)
        }
    }

    // MARK: Datagram Management

    @discardableResult
    func ensureDatagramChannel() -> NCMASQUEStreamChannel? {
        if let datagramChannel { return datagramChannel }
        guard let group,
              let conn = group.extract(connectionTo: nil,
                                       using: NCQUICStreamOptions.datagram(from: group,
                                                                           fallback: makeQUICOptions)) else {
            return nil
        }
        let ch = NCMASQUEStreamChannel(conn: conn)
        datagramChannel = ch
        ch.start(queue: queue) { [weak self] err in
            guard let self, err == nil else { return }
            self.datagramReceiveLoop()
        }
        return ch
    }

    private func datagramReceiveLoop() {
        datagramChannel?.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            self.lock.lock()
            let closed = (self.state == .closed || self.state == .failed)
            self.lock.unlock()
            if closed { return }

            if let data, !data.isEmpty {
                self.handleIncomingDatagram(data)
            }
            if error == nil {
                self.datagramReceiveLoop()
            }
        }
    }

    private func handleIncomingDatagram(_ packet: Data) {
        guard let (streamID, contextID, payload) = NCMASQUE.decodeH3Datagram(packet) else { return }
        guard contextID == 0 else { return } // Context ID 0 is raw UDP payload (RFC 9298 §5)
        let qid = streamID / 4
        lock.lock()
        let stream = streams[qid]
        let ipSink = stream == nil ? ipSinks[qid] : nil
        lock.unlock()
        if let stream { stream.deliverPacket(payload) } else { ipSink?(payload) }
    }

    // MARK: CONNECT-IP hooks (fix/nc-masque-ip, NCMASQUEIP.swift)

    /// A new client bidirectional request stream on the QUIC connection (call on `queue`).
    func extractRequestStream() -> NWConnection? {
        guard isAlive, let group else { return nil }
        return group.extract(connectionTo: nil, using: nil)
    }

    func registerIPSink(quarterStreamID: UInt64, _ sink: @escaping (Data) -> Void) {
        lock.lock()
        ipSinks[quarterStreamID] = sink
        lock.unlock()
    }

    func removeIPSink(quarterStreamID: UInt64) {
        lock.lock()
        ipSinks.removeValue(forKey: quarterStreamID)
        lock.unlock()
    }

    /// A ready-made HTTP/3 datagram (quarter stream id + context id + payload) on the DATAGRAM channel.
    func sendRawDatagram(_ wire: Data, completion: @escaping () -> Void) {
        ncOnSessionQueue(queue) {
            guard self.isAlive, let channel = self.ensureDatagramChannel() else {
                completion()
                return
            }
            channel.send(wire, completion: completion)
        }
    }

    func sendDatagram(quarterStreamID: UInt64, contextID: UInt64 = 0, payload: Data,
                      completion: (() -> Void)? = nil) {
        let wire = NCMASQUE.encodeH3Datagram(streamID: quarterStreamID * 4, contextID: contextID, payload: payload)
        ncOnSessionQueue(queue) {
            guard self.isAlive, let channel = self.ensureDatagramChannel() else {
                completion?()
                return
            }
            channel.send(wire, completion: completion)
        }
    }

    // MARK: Open UDP Stream (Extended CONNECT)

    func openUDPStream(target: NCTarget, callerQueue: DispatchQueue,
                       completion: @escaping (NCRelayStream?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            guard self.isAlive, let group = self.group else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE 连接尚未就绪"))
                }
                return
            }

            guard let bidiConn = group.extract(connectionTo: nil, using: nil) else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE 无法提取双向请求流"))
                }
                return
            }

            let streamID = self.nextStreamID
            self.nextStreamID += 4
            let quarterStreamID = streamID / 4

            let ch = NCMASQUEStreamChannel(conn: bidiConn)
            ch.start(queue: self.queue) { [weak self] err in
                guard let self else { return }
                if let err {
                    callerQueue.async { completion(nil, err) }
                    return
                }

                // Expand URI template (RFC 9298 §3)
                let resolvedPath = NCMASQUE.expandURITemplate(self.config.uri, target: target)
                let authority = "\(self.config.server):\(self.config.port)"

                var extraHeaders: [(String, String)] = []
                if let u = self.config.username, let p = self.config.password {
                    let cred = Data("\(u):\(p)".utf8).base64EncodedString()
                    extraHeaders.append(("authorization", "Basic \(cred)"))
                }

                let qpackPayload = NCMASQUE.qpackEncodeExtendedConnect(
                    protocolValue: "connect-udp",
                    authority: authority,
                    path: resolvedPath,
                    extraHeaders: extraHeaders
                )

                // HTTP/3 HEADERS frame: Type 0x01
                var headersFrame = NCMASQUE.varintEncode(0x01)
                headersFrame.append(NCMASQUE.varintEncode(UInt64(qpackPayload.count)))
                headersFrame.append(qpackPayload)

                ch.send(headersFrame) { [weak self] in
                    guard let self else { return }
                    self.readExtendedConnectResponse(channel: ch, quarterStreamID: ch.quicStreamID.map { $0 / 4 } ?? quarterStreamID,
                                                     target: target, callerQueue: callerQueue,
                                                     completion: completion)
                }
            }
        }
    }

    private func readExtendedConnectResponse(channel: NCMASQUEStreamChannel,
                                             quarterStreamID: UInt64,
                                             target: NCTarget,
                                             callerQueue: DispatchQueue,
                                             completion: @escaping (NCRelayStream?, Error?) -> Void) {
        channel.receive { [weak self] data, err in
            guard let self else { return }
            if let err {
                callerQueue.async { completion(nil, err) }
                return
            }
            guard let data, !data.isEmpty else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE 服务端未返回握手响应"))
                }
                return
            }

            // Parse HTTP/3 HEADERS frame
            guard let (type, tLen) = NCMASQUE.varintDecode(data, at: 0),
                  let (len, lLen) = NCMASQUE.varintDecode(data, at: tLen) else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE 响应头帧格式无效"))
                }
                return
            }
            let hLen = tLen + lLen
            let payloadLen = Int(len)
            guard type == 0x01, data.count >= hLen + payloadLen else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE 预期 HEADERS 帧，实际收到类型 \(type)"))
                }
                return
            }

            let fieldSection = Data(data[(data.startIndex + hLen)..<(data.startIndex + hLen + payloadLen)])
            guard let fields = NCMASQUE.qpackDecodeFieldSection(fieldSection) else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE QPACK 头部解码失败"))
                }
                return
            }

            var statusStr: String?
            for (name, val) in fields where name.lowercased() == ":status" {
                statusStr = val
                break
            }

            guard let status = statusStr, status.hasPrefix("2") else {
                callerQueue.async {
                    completion(nil, NCConnector.Failure.handshake("MASQUE Extended CONNECT 被拒绝 (HTTP \(statusStr ?? "unknown"))"))
                }
                channel.cancel()
                return
            }

            // Extended CONNECT handshake succeeded!
            let stream = NCMASQUEUDPStream(quarterStreamID: quarterStreamID,
                                           target: target,
                                           callerQueue: callerQueue,
                                           channel: channel,
                                           connection: self)
            self.lock.lock()
            self.streams[quarterStreamID] = stream
            self.lock.unlock()

            stream.startCapsuleReceiveLoop()
            callerQueue.async {
                completion(stream, nil)
            }
        }
    }

    func removeStream(quarterStreamID: UInt64) {
        lock.lock()
        streams.removeValue(forKey: quarterStreamID)
        lock.unlock()
    }

    func close() {
        lock.lock()
        guard state != .closed else { lock.unlock(); return }
        state = .closed
        let allStreams = Array(streams.values)
        streams.removeAll()
        ipSinks.removeAll()
        lock.unlock()

        for s in allStreams {
            s.cancel()
        }

        ncOnSessionQueue(queue) {
            self.controlChannel?.cancel()
            self.controlChannel = nil
            self.serverControlChannel?.cancel()
            self.serverControlChannel = nil
            self.datagramChannel?.cancel()
            self.datagramChannel = nil
            self.group?.cancel()
            self.group = nil
        }
    }
}

// MARK: - Global Registry & Connector Entry Points

enum NCMASQUERegistry {
    private static let lock = NSLock()
    private static var registry: [String: NCMASQUEConnection] = [:]

    static func masqueStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                             completion: @escaping (NCRelayStream?, Error?) -> Void) {
        // 1. Check unsupported field markers
        if let unsupported = NCSupport.unsupportedReason(proxy) {
            queue.async { completion(nil, NCConnector.Failure.unsupported(unsupported)) }
            return
        }

        // 2. Validate configuration mapping
        guard let cfg = NCMASQUE.Config(proxy: proxy) else {
            queue.async { completion(nil, NCConnector.Failure.handshake("MASQUE 无效或缺少核心配置")) }
            return
        }

        // 3. Check mode: CONNECT-IP requires L3 VPN tun interface (PacketTunnel lwip)
        if cfg.mode == .connectIP {
            queue.async {
                completion(nil, NCConnector.Failure.unsupported("MASQUE CONNECT-IP 模式仅支持在 PacketTunnel VPN 隧道内作为 L3 虚拟网卡运行，当前应用层仅支持 CONNECT-UDP 代理"))
            }
            return
        }

        let key = "\(proxy.name)|\(cfg.server):\(cfg.port)"
        lock.lock()
        if let conn = registry[key] {
            lock.unlock()
            if conn.isAlive {
                conn.openUDPStream(target: target, callerQueue: queue, completion: completion)
            } else {
                conn.whenReady(callerQueue: queue) { err in
                    if let err {
                        lock.lock()
                        if registry[key] === conn { registry.removeValue(forKey: key) }
                        lock.unlock()
                        completion(nil, err)
                    } else {
                        conn.openUDPStream(target: target, callerQueue: queue, completion: completion)
                    }
                }
            }
            return
        }

        let newConn = NCMASQUEConnection(config: cfg, queue: queue)
        registry[key] = newConn
        lock.unlock()

        newConn.start { err in
            if let err {
                lock.lock()
                if registry[key] === newConn { registry.removeValue(forKey: key) }
                lock.unlock()
                completion(nil, err)
                return
            }
            newConn.openUDPStream(target: target, callerQueue: queue, completion: completion)
        }
    }
}
