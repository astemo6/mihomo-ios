import Foundation
import Network
import Security
import os

/// Juicity pure Swift client implementation: QUIC transport, TLS 1.3 exporter authentication,
/// TCP relay, and UDP over stream relay.
///
/// Specification references:
///  - Juicity Protocol Spec: https://github.com/juicity/juicity/blob/main/docs/spec.md
///  - Juicity Client/Server implementation: daeuniverse/outbound protocol/juicity
///    (client.go, dialer.go, stream_conn.go, stream_packet_conn.go)
///  - Address and command framing: trojanc.Metadata (addr.go)
///
/// Wire format:
///  - ALPN: "h3" (default), TLS 1.3+
///  - Authentication: unidirectional client-initiated QUIC stream sending:
///      [version: 0x00][cmd_type: 0x00][uuid: 16 bytes][token: 32 bytes]
///    where token is derived via RFC 5705 TLS 1.3 Keying Material Exporter:
///      label = 16 bytes raw UUID, context = password, length = 32 bytes.
///  - TCP stream: bidirectional QUIC stream.
///    Request header: [network: 0x01][target.atypEncoded] (SOCKS5/trojanc ATYP: 1=IPv4, 3=Domain, 4=IPv6).
///    Followed by raw TCP payload. Server returns raw TCP payload.
///  - UDP stream: bidirectional QUIC stream per UDP flow (triplet <sip, sport, UDP>).
///    Request header: [network: 0x03][target.atypEncoded].
///    Each datagram frame (both client->server and server->client):
///      [target.atypEncoded][payload length: uint16 BE][payload].
enum NCJuicityWire {

    /// SOCKS5 / trojanc ATYP target encoding matching NCTarget.atypEncoded:
    ///  - IPv4: 0x01 + 4 bytes IPv4 + 2 bytes port (BE)
    ///  - Domain: 0x03 + 1 byte len + domain UTF8 + 2 bytes port (BE)
    ///  - IPv6: 0x04 + 16 bytes IPv6 + 2 bytes port (BE)
    static func address(_ t: NCTarget) -> Data {
        t.atypEncoded
    }

    /// Parse a 32-char or 36-char (with hyphens) UUID string into 16 raw bytes.
    static func uuidBytes(_ s: String) -> Data? {
        let hex = s.replacingOccurrences(of: "-", with: "")
        guard hex.count == 32 else { return nil }
        var out = Data(capacity: 16)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }

    /// Header sent on opening a TCP stream: [network=0x01][target.atypEncoded].
    static func tcpRequestHeader(target: NCTarget) -> Data {
        var d = Data([0x01])
        d.append(target.atypEncoded)
        return d
    }

    /// Header sent on opening a UDP stream: [network=0x03][target.atypEncoded].
    static func udpRequestHeader(target: NCTarget) -> Data {
        var d = Data([0x03])
        d.append(target.atypEncoded)
        return d
    }

    /// Frame one UDP datagram: [target.atypEncoded][length: uint16 BE][payload].
    static func sealUDPPacket(target: NCTarget, payload: Data) -> Data {
        var d = target.atypEncoded
        let len = UInt16(clamping: payload.count)
        d.append(UInt8((len >> 8) & 0xff))
        d.append(UInt8(len & 0xff))
        d.append(payload)
        return d
    }

    /// Parse one UDP datagram from stream buffer:
    /// [addrType: 1/3/4][addr][port: 2B BE][len: 2B BE][payload].
    static func unsealUDPPacket(_ data: Data, at off: Int = 0) -> (payload: Data, consumed: Int)? {
        let count = data.count - off
        guard count >= 1 else { return nil }
        var headerLen: Int
        switch data[off] {
        case 0x01: // IPv4: 1 + 4 + 2
            headerLen = 1 + 4 + 2
        case 0x04: // IPv6: 1 + 16 + 2
            headerLen = 1 + 16 + 2
        case 0x03: // Domain: 1 + 1 + len + 2
            guard count >= 2 else { return nil }
            headerLen = 1 + 1 + Int(data[off + 1]) + 2
        default:
            return nil
        }
        guard count >= headerLen + 2 else { return nil }
        let len = Int(data[off + headerLen]) << 8 | Int(data[off + headerLen + 1])
        guard count >= headerLen + 2 + len else { return nil }
        let payload = data.subdata(in: (off + headerLen + 2)..<(off + headerLen + 2 + len))
        return (payload, headerLen + 2 + len)
    }

    /// 50-byte Juicity authentication message on the unidirectional stream:
    /// [version: 0x00][cmd_type: 0x00][uuid: 16B][token: 32B].
    static func authMessage(uuid: Data, token: Data) -> Data {
        var d = Data(capacity: 50)
        d.append(0x00) // Version 0
        d.append(0x00) // Authenticate CmdType
        d.append(uuid)
        d.append(token)
        return d
    }

    /// Chained SHA-256 cert chain hash matching juicity common.GenerateCertChainHash:
    ///  chainHash = sha256(cert0)
    ///  chainHash = sha256(chainHash + sha256(cert_i)) for i in 1..<count
    static func generateCertChainHash(rawCerts: [Data]) -> Data? {
        guard !rawCerts.isEmpty else { return nil }
        var chainHash: Data?
        for cert in rawCerts {
            let certHash = NCSHA256.hash(cert)
            if let current = chainHash {
                var combined = current
                combined.append(certHash)
                chainHash = NCSHA256.hash(combined)
            } else {
                chainHash = certHash
            }
        }
        return chainHash
    }

    /// Parse a pinned cert hash string from configuration. juicity's client tries URL Base64, then std Base64,
    /// then hex; a 64-char hex string is also valid Base64 (48 bytes) there and so never matches. Here a decoding
    /// that yields a 32-byte SHA-256 wins, falling back to the first successful decoding.
    static func parseHash(_ s: String) -> Data? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        var candidates: [Data] = []
        var unpadded = trimmed.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = unpadded.count % 4
        if rem > 0 { unpadded += String(repeating: "=", count: 4 - rem) }
        if let d = Data(base64Encoded: unpadded), !d.isEmpty { candidates.append(d) }
        if let d = hexDecode(trimmed.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "")) {
            candidates.append(d)
        }
        return candidates.first(where: { $0.count == 32 }) ?? candidates.first
    }

    private static func hexDecode(_ hex: String) -> Data? {
        guard !hex.isEmpty, hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        return out
    }
}

final class NCJuicityConnection {
    enum State { case idle, connecting, ready, failed, closed }

    private let server: String, port: Int
    private let uuid: Data, password: Data
    private let sni: String?, alpn: [String], allowInsecure: Bool
    private let pinnedCertHash: Data?
    let queue: DispatchQueue
    private let callbackQueue: DispatchQueue

    private struct Snapshot {
        var state: State = .idle
        var waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready } }
    private func setState(_ state: State) { snapshot.withLock { $0.state = state } }

    /// Tracks stream open count for stream retirement (spec: 30 streams per QUIC connection).
    private(set) var streamCount: Int = 0
    private(set) var isExhausted: Bool = false
    /// Spec: a client that cannot read the peer's available stream count opens a new connection after 30 streams.
    static let maxStreamsPerConnection = 30

    private(set) var group: NWConnectionGroup?
    private var authOpened = false
    private var authStream: NWConnection?
    private var startCompletion: ((Error?) -> Void)?

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let server = proxy.server, let port = proxy.port else { return nil }
        self.server = server
        self.port = port
        let uStr = proxy.uuid ?? proxy.fields["uuid"]?.string ?? proxy.fields["user"]?.string ?? ""
        guard let ub = NCJuicityWire.uuidBytes(uStr) else { return nil }
        self.uuid = ub
        self.password = Data((proxy.password ?? proxy.fields["password"]?.string ?? "").utf8)

        let disableSNI = proxy.fields["disable-sni"]?.bool ?? proxy.fields["disable_sni"]?.bool ?? false
        self.sni = disableSNI ? nil : (proxy.fields["sni"]?.string ?? proxy.fields["peer"]?.string ?? server)
        self.alpn = proxy.fields["alpn"]?.array?.compactMap { $0.string } ?? ["h3"]
        self.allowInsecure = proxy.fields["skip-cert-verify"]?.bool
            ?? proxy.fields["allow-insecure"]?.bool
            ?? proxy.fields["allowInsecure"]?.bool
            ?? false

        let pinStr = proxy.fields["pinned-certchain-sha256"]?.string
            ?? proxy.fields["pinned_certchain_sha256"]?.string
            ?? proxy.fields["pinned-peer-cert-sha256"]?.string
            ?? ""
        self.pinnedCertHash = pinStr.isEmpty ? nil : NCJuicityWire.parseHash(pinStr)

        self.callbackQueue = queue
        self.queue = NCSessionQueues.make("nc.juicity.\(server):\(port)")
    }

    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        enum Action { case now(Error?), wait }
        let action: Action = snapshot.withLock { snap in
            switch snap.state {
            case .ready:
                return .now(nil)
            case .failed, .closed:
                return .now(NCConnector.Failure.handshake("juicity connection failed"))
            case .idle, .connecting:
                snap.waiters.append((callerQueue, completion))
                return .wait
            }
        }
        if case .now(let error) = action {
            callerQueue.async { completion(error) }
        }
    }

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

    func start(completion: @escaping (Error?) -> Void) {
        let first: Bool = snapshot.withLock { snap in
            guard snap.state == .idle else { return false }
            snap.state = .connecting
            return true
        }
        guard first else {
            callbackQueue.async { completion(NCConnector.Failure.handshake("juicity already started")) }
            return
        }
        startCompletion = completion
        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    func quicStreamOptions() -> NWProtocolQUIC.Options {
        let options = NWProtocolQUIC.Options(alpn: alpn)
        let tls = options.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        if let sni, !sni.isEmpty { sec_protocol_options_set_tls_server_name(tls, sni) }
        if let expectedHash = pinnedCertHash {
            let allowInsecure = self.allowInsecure
            sec_protocol_options_set_verify_block(tls, { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                let chain = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? []
                let certs = chain.map { SecCertificateCopyData($0) as Data }
                if let hash = NCJuicityWire.generateCertChainHash(rawCerts: certs), hash == expectedHash {
                    complete(true)
                    return
                }
                complete(allowInsecure)
            }, queue)
        } else if allowInsecure {
            sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, queue)
        }
        options.idleTimeout = 30_000
        return options
    }

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
        group.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.finish(NCConnector.Failure.handshake("juicity handshake timeout"))
        }
    }

    private func openAuthStream() {
        guard !authOpened, state == .connecting, let group else { return }
        authOpened = true
        let uniOptions = NCQUICStreamOptions.unidirectional(from: group, fallback: quicStreamOptions)
        guard let auth = group.extract(connectionTo: nil, using: uniOptions) else {
            finish(NCConnector.Failure.handshake("juicity: cannot open auth stream"))
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
                self.finish(NCConnector.Failure.handshake("juicity auth stream cancelled"))
            default:
                break
            }
        }
        auth.start(queue: queue)
    }

    private func sendAuth(on conn: NWConnection) {
        guard let tk = exportToken(conn) else {
            finish(NCConnector.Failure.handshake("juicity: TLS exporter unavailable"))
            return
        }
        let cmd = NCJuicityWire.authMessage(uuid: uuid, token: tk)
        conn.send(content: cmd, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] err in
            guard let self else { return }
            if let err { self.finish(err); return }
            self.setState(.ready)
            self.finish(nil)
        })
    }

    /// TLS 1.3 exporter, label = UUID bytes, context = password, 32 bytes.
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
        NCConnector.juicityForgetRetired(self)
        notifyWaiters(NCConnector.Failure.handshake("juicity connection closed"))
        ncOnSessionQueue(queue) {
            self.authStream?.cancel(); self.authStream = nil
            self.group?.cancel(); self.group = nil
        }
    }

    /// Open a proxied TCP flow on this QUIC connection.
    func openTCP(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        if NCSessionQueues.isCurrent(queue) { return openTCPOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openTCPOnQueue(target: target, callerQueue: callerQueue) }
    }

    private func openTCPOnQueue(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        streamCount += 1
        if streamCount >= Self.maxStreamsPerConnection {
            isExhausted = true
        }
        let s = NCJuicityTCPStream(channel: NCHy2StreamChannel(conn: conn),
                                   head: NCJuicityWire.tcpRequestHeader(target: target),
                                   queue: queue, callerQueue: callerQueue)
        s.begin()
        return s
    }

    /// Open a proxied UDP stream on this QUIC connection.
    func openUDP(firstTarget: NCTarget, callerQueue: DispatchQueue) -> NCJuicityUDPStream? {
        if NCSessionQueues.isCurrent(queue) { return openUDPOnQueue(firstTarget: firstTarget, callerQueue: callerQueue) }
        return queue.sync { openUDPOnQueue(firstTarget: firstTarget, callerQueue: callerQueue) }
    }

    private func openUDPOnQueue(firstTarget: NCTarget, callerQueue: DispatchQueue) -> NCJuicityUDPStream? {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { return nil }
        streamCount += 1
        if streamCount >= Self.maxStreamsPerConnection {
            isExhausted = true
        }
        let s = NCJuicityUDPStream(channel: NCHy2StreamChannel(conn: conn),
                                   initialTarget: firstTarget,
                                   queue: queue, callerQueue: callerQueue)
        s.begin()
        return s
    }
}

/// One Juicity TCP flow: sends [network=0x01][target.atypEncoded] once on open, then raw bytes.
final class NCJuicityTCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let head: Data
    private let queue: DispatchQueue
    private let callerQueue: DispatchQueue
    private var open = false, closed = false
    private var failure: Error?
    private var outbox = Data()
    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var pending: ((Data?, Error?) -> Void)?
    private var outboxWaiters: [NCCallOnce] = []

    static let maxQueuedBytes = 256 * 1024

    init(channel: NCHy2StreamChannel, head: Data, queue: DispatchQueue, callerQueue: DispatchQueue) {
        self.channel = channel
        self.head = head
        self.queue = queue
        self.callerQueue = callerQueue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if let err { self.fail(err); return }
            self.open = true
            let waiters = self.outboxWaiters; self.outboxWaiters = []
            // Send proxy header immediately (with buffered outbox payload if present) to avoid server-first deadlock.
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
                self.fail(NCConnector.Failure.handshake("juicity tcp send buffer overflow"))
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
            guard let data else {
                self.closed = true
                self.drainOutboxWaiters()
                if let h = self.pending {
                    self.pending = nil
                    self.callerQueue.async { h(nil, error) }
                }
                return
            }
            if let h = self.pending {
                self.pending = nil
                self.callerQueue.async { h(data, nil) }
            } else if self.inboxBytes + data.count <= Self.maxQueuedBytes {
                self.inboxBytes += data.count
                self.inbox.append(data)
            } else {
                self.fail(NCConnector.Failure.handshake("juicity tcp receive buffer overflow"))
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

/// One Juicity UDP stream: multiplexes UDP datagrams over a QUIC stream for a source triplet.
/// Packets are framed as: [target.atypEncoded][length: uint16 BE][payload].
final class NCJuicityUDPStream {
    private let channel: NCHy2StreamChannel
    private let initialTarget: NCTarget
    private let queue: DispatchQueue
    private let callerQueue: DispatchQueue
    private var open = false, closed = false
    private var outbox: [(data: Data, target: NCTarget, once: NCCallOnce)] = []
    private var buffer = Data()
    private var bufferOffset = 0
    private var buffered: Int { buffer.count - bufferOffset }

    var onReply: (Data) -> Void = { _ in }
    /// Fired once on callerQueue when the stream ends on its own (peer FIN / reset / open failure), so the owning
    /// session can open a fresh stream instead of silently dropping every later datagram.
    var onClosed: () -> Void = {}

    init(channel: NCHy2StreamChannel, initialTarget: NCTarget, queue: DispatchQueue, callerQueue: DispatchQueue) {
        self.channel = channel
        self.initialTarget = initialTarget
        self.queue = queue
        self.callerQueue = callerQueue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] err in
            guard let self else { return }
            if err != nil {
                self.closed = true
                self.drainOutboxWaiters()
                self.notifyClosed()
                return
            }
            self.open = true
            var initialData = NCJuicityWire.udpRequestHeader(target: self.initialTarget)
            let pending = self.outbox
            self.outbox = []
            for (data, target, once) in pending {
                initialData.append(NCJuicityWire.sealUDPPacket(target: target, payload: data))
                once.call()
            }
            self.channel.send(initialData)
            self.receiveLoop()
        }
    }

    func send(_ data: Data, to target: NCTarget, completion: @escaping () -> Void = {}) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard !self.closed else { once.call(); return }
            if self.open {
                let packet = NCJuicityWire.sealUDPPacket(target: target, payload: data)
                self.channel.send(packet, completion: once.call)
            } else if self.outbox.count < 64 {
                self.outbox.append((data, target, once))
            } else {
                once.call()
            }
        }
    }

    private func receiveLoop() {
        channel.receive { [weak self] data, error in
            guard let self, !self.closed else { return }
            guard let data else {
                self.closed = true
                self.notifyClosed()
                return
            }
            self.buffer.append(data)
            self.parseFrames()
            if self.buffered > 128 * 1024 { self.cancel(); return }
            if error == nil { self.receiveLoop() }
        }
    }

    private func parseFrames() {
        defer { compactBuffer() }
        while let (payload, consumed) = NCJuicityWire.unsealUDPPacket(buffer, at: bufferOffset) {
            bufferOffset += consumed
            let p = payload
            callerQueue.async { [weak self] in
                guard let self, !self.closed else { return }
                self.onReply(p)
            }
        }
    }

    private func notifyClosed() {
        let cb = onClosed
        onClosed = {}
        callerQueue.async { cb() }
    }

    private func compactBuffer() {
        if bufferOffset == 0 { return }
        if bufferOffset >= buffer.count {
            buffer = Data()
            bufferOffset = 0
        } else if bufferOffset > buffer.count / 2 {
            buffer = Data(buffer.dropFirst(bufferOffset))
            bufferOffset = 0
        }
    }

    private func drainOutboxWaiters() {
        let w = outbox; outbox = []
        w.forEach { $0.once.call() }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            self.closed = true
            self.drainOutboxWaiters()
            self.channel.cancel()
        }
    }
}

extension NCConnector {
    private static var juicityRegistry: [String: NCJuicityConnection] = [:]
    /// Connections retired after `maxStreamsPerConnection` streams. Their open streams keep running; the QUIC
    /// idle timeout (or tunnel stop) ends them. Held here so the group is always cancelled (a dropped, uncancelled
    /// NWConnectionGroup is never released by Network.framework) and so teardown sees and closes them.
    private static var juicityRetired: [ObjectIdentifier: NCJuicityConnection] = [:]
    private static let juicityLock = NSLock()

    static var juicitySessionCount: Int {
        juicityLock.lock(); defer { juicityLock.unlock() }
        return juicityRegistry.count + juicityRetired.count
    }

    /// Caller holds juicityLock.
    private static func juicityRetireLocked(_ key: String, _ c: NCJuicityConnection) {
        juicityRegistry.removeValue(forKey: key)
        // A dead one has already cancelled its group (finish / state handler); never call close() here (lock held).
        if c.isAlive { juicityRetired[ObjectIdentifier(c)] = c }
    }

    static func juicityForgetRetired(_ c: NCJuicityConnection) {
        juicityLock.lock()
        juicityRetired.removeValue(forKey: ObjectIdentifier(c))
        juicityLock.unlock()
    }

    @discardableResult
    static func closeAllJuicitySessions() -> Int {
        juicityLock.lock()
        let all = Array(juicityRegistry.values) + Array(juicityRetired.values)
        juicityRegistry.removeAll()
        juicityRetired.removeAll()
        juicityLock.unlock()
        for c in all { c.close() }
        return all.count
    }

    static func juicityStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                              completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        juicityLock.lock()
        if let c = juicityRegistry[key] {
            if c.isExhausted {
                juicityRetireLocked(key, c)
                // Fall through to open a fresh connection when streams are exhausted.
            } else {
                juicityLock.unlock()
                if c.isAlive {
                    openJuicityStream(c, proxy: proxy, target: target, queue: queue, completion: completion)
                } else if c.state == .connecting {
                    c.whenReady(callerQueue: queue) { err in
                        if let err {
                            juicityLock.lock()
                            if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                            juicityLock.unlock()
                            completion(nil, err)
                        } else {
                            openJuicityStream(c, proxy: proxy, target: target, queue: queue, completion: completion)
                        }
                    }
                } else {
                    juicityLock.lock()
                    if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                    juicityLock.unlock()
                    juicityStream(proxy: proxy, target: target, queue: queue, completion: completion)
                }
                return
            }
        }
        guard let c = NCJuicityConnection(proxy: proxy, queue: queue) else {
            juicityLock.unlock()
            queue.async { completion(nil, Failure.handshake("juicity bad config (uuid / password)")) }
            return
        }
        juicityRegistry[key] = c
        juicityLock.unlock()
        c.start { err in
            if let err {
                juicityLock.lock()
                if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                juicityLock.unlock()
                completion(nil, err)
                return
            }
            openJuicityStream(c, proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    private static func openJuicityStream(_ c: NCJuicityConnection, proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                          completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        if let s = c.openTCP(target: target, callerQueue: queue) {
            completion(s, nil)
        } else {
            // Stream extraction failed (e.g. limit reached), cycle the connection.
            juicityLock.lock()
            if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
            juicityLock.unlock()
            juicityStream(proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    static func juicityShared(proxy: NCProxy, queue: DispatchQueue, completion: @escaping (NCJuicityConnection?) -> Void) {
        let key = "\(proxy.name)|\(proxy.server ?? "")|\(proxy.port ?? 0)"
        juicityLock.lock()
        if let c = juicityRegistry[key] {
            if c.isExhausted {
                juicityRetireLocked(key, c)
            } else {
                juicityLock.unlock()
                if c.isAlive {
                    completion(c)
                } else if c.state == .connecting {
                    c.whenReady(callerQueue: queue) { err in
                        if err != nil {
                            juicityLock.lock()
                            if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                            juicityLock.unlock()
                            completion(nil)
                        } else {
                            completion(c)
                        }
                    }
                } else {
                    juicityLock.lock()
                    if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                    juicityLock.unlock()
                    juicityShared(proxy: proxy, queue: queue, completion: completion)
                }
                return
            }
        }
        guard let c = NCJuicityConnection(proxy: proxy, queue: queue) else {
            juicityLock.unlock()
            queue.async { completion(nil) }
            return
        }
        juicityRegistry[key] = c
        juicityLock.unlock()
        c.start { err in
            if err != nil {
                juicityLock.lock()
                if juicityRegistry[key] === c { juicityRegistry.removeValue(forKey: key) }
                juicityLock.unlock()
                completion(nil)
                return
            }
            completion(c)
        }
    }
}
