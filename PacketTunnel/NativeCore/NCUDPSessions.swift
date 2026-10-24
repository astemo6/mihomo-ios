import Foundation
import Network

/// A proxied/direct UDP association for one stack session. `send` carries the
/// per-datagram target because SOCKS5-style relays are target-agnostic.
protocol NCUDPSession: AnyObject {
    var onReply: (Data) -> Void { get set }
    func send(_ data: Data, to target: NCTarget)
    func cancel()
}

/// DIRECT UDP via NWConnection to the (single) first target; later datagrams
/// to other targets on the same stack session spawn their own association in
/// the data plane, so this stays one-to-one.
final class NCUDPDirectSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let conn: NWConnection
    private var cancelled = false

    init(target: NCTarget, queue: DispatchQueue) {
        let port = NWEndpoint.Port(rawValue: UInt16(clamping: target.port)) ?? .any
        conn = NWConnection(host: NWEndpoint.Host(target.host), port: port, using: .udp)
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, !data.isEmpty { self.onReply(data) }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        conn.send(content: data, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}

/// SOCKS5 UDP associate (RFC 1928): a TCP control connection performs the
/// greeting/auth and the UDP ASSOCIATE request; datagrams then go to the
/// relay address the server returns, wrapped in the SOCKS UDP header.
final class NCUDPSocks5Session: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    var onReady: (Bool) -> Void = { _ in }

    private let control: NCStream
    private let serverHost: String
    private var udp: NWConnection?
    private var ready = false
    private var queued: [(Data, NCTarget)] = []
    private var cancelled = false

    init(proxy: NCProxy, queue: DispatchQueue) {
        serverHost = proxy.server ?? ""
        control = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        control.start { [weak self] err in
            guard let self, err == nil else {
                self?.onReady(false)
                return
            }
            self.handshake(proxy: proxy, queue: queue)
        }
    }

    private func handshake(proxy: NCProxy, queue: DispatchQueue) {
        let username = proxy.fields["username"]?.string
        let password = proxy.fields["password"]?.string
        let buf = NCByteBuffer()
        control.send(NCSOCKS5.greeting(username: username, password: password))
        readAtLeast(buf, 2, queue: queue) { [weak self] ok in
            guard let self, ok else { self?.onReady(false); return }
            let head = buf.take(2)
            guard head[0] == 0x05 else { self.onReady(false); return }
            if head[1] == 0x02 {
                guard let u = username else { self.onReady(false); return }
                self.control.send(NCSOCKS5.authRequest(username: u, password: password ?? ""))
                self.readAtLeast(buf, 2, queue: queue) { [weak self] ok in
                    guard let self, ok, buf.take(2)[1] == 0x00 else { self?.onReady(false); return }
                    self.associate(buf: buf, queue: queue)
                }
            } else if head[1] == 0x00 {
                self.associate(buf: buf, queue: queue)
            } else {
                self.onReady(false)
            }
        }
    }

    private func associate(buf: NCByteBuffer, queue: DispatchQueue) {
        // UDP ASSOCIATE with a zero bind address.
        control.send(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        func step() {
            if buf.count >= 4 {
                let atyp = buf.data[3]
                let need = 4 + (atyp == 0x01 ? 4 : atyp == 0x04 ? 16 : atyp == 0x03 ? 1 + Int(buf.count > 4 ? buf.data[4] : 0) : 0) + 2
                if buf.count >= need {
                    let resp = buf.take(need)
                    guard resp[1] == 0x00 else { onReady(false); return }
                    openRelay(resp: resp, atyp: atyp, queue: queue)
                    return
                }
            }
            control.receive { [weak self] data, error in
                guard let self, let data else { self?.onReady(false); return }
                buf.append(data)
                step()
            }
        }
        step()
    }

    private func openRelay(resp: Data, atyp: UInt8, queue: DispatchQueue) {
        let host: String
        let port: Int
        switch atyp {
        case 0x01:
            host = "\(resp[4]).\(resp[5]).\(resp[6]).\(resp[7])"
            port = Int(resp[8]) << 8 | Int(resp[9])
        case 0x03:
            let len = Int(resp[4])
            host = String(decoding: resp[5..<(5 + len)], as: UTF8.self)
            port = Int(resp[5 + len]) << 8 | Int(resp[6 + len])
        default:
            onReady(false)
            return
        }
        // A 0.0.0.0 bind address means "same host as the control connection".
        let relayHost = host == "0.0.0.0" ? serverHost : host
        let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(relayHost),
                                     port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let conn = NWConnection(to: ep, using: .udp)
        udp = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                self.ready = true
                self.onReady(true)
                for (data, target) in self.queued { self.send(data, to: target) }
                self.queued = []
                self.receiveLoop()
            }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        udp?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, let payload = Self.unwrap(data) {
                self.onReply(payload)
            }
            if error == nil { self.receiveLoop() }
        }
    }

    /// SOCKS UDP header: RSV(2) FRAG(1) ATYP + addr + port, then payload.
    private static func unwrap(_ data: Data) -> Data? {
        guard data.count >= 4, data[0] == 0, data[1] == 0, data[2] == 0 else { return nil }
        var offset = 4
        switch data[3] {
        case 0x01: offset += 4
        case 0x04: offset += 16
        case 0x03:
            guard data.count > 4 else { return nil }
            offset += 1 + Int(data[4])
        default: return nil
        }
        offset += 2
        guard data.count > offset else { return nil }
        return Data(data[offset...])
    }

    func send(_ data: Data, to target: NCTarget) {
        guard ready, let udp else {
            if queued.count < 64 { queued.append((data, target)) }
            return
        }
        var packet = Data([0x00, 0x00, 0x00])
        packet.append(target.atypEncoded)
        packet.append(data)
        udp.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        udp?.cancel()
        control.cancel()
    }

    private func readAtLeast(_ buf: NCByteBuffer, _ n: Int, queue: DispatchQueue, done: @escaping (Bool) -> Void) {
        if buf.count >= n { done(true); return }
        control.receive { [weak self] data, _ in
            guard let self, let data else { done(false); return }
            buf.append(data)
            self.readAtLeast(buf, n, queue: queue, done: done)
        }
    }
}

/// One-shot upstream DNS forwarding over UDP, with TCP retry on truncation.
/// Used for queries the fake-IP responder declines (filter hosts, non-A types).
final class NCDNSForwarder {
    private let queue: DispatchQueue

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func forward(_ query: Data, server: String, completion: @escaping (Data?) -> Void) {
        let port = NWEndpoint.Port(rawValue: 53) ?? .any
        let conn = NWConnection(host: NWEndpoint.Host(server), port: port, using: .udp)
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
                            Self.forwardTCP(query, server: server, queue: self.queue) { finish($0 ?? data) }
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
    }

    private static func forwardTCP(_ query: Data, server: String, queue: DispatchQueue, completion: @escaping (Data?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: 53) ?? .any, using: .tcp)
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
    }
}

/// Shadowsocks UDP: every datagram is an independent SIP022 AEAD packet
/// (fresh salt, target header inside), so the stream encoder/decoder are
/// re-created per packet.
final class NCUDPSSSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let conn: NWConnection
    private let cipher: String
    private let password: String
    private var cancelled = false

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let cipher = proxy.cipher, let password = proxy.password,
              let server = proxy.server, let port = proxy.port,
              NCShadowsocks.spec(for: cipher) != nil else { return nil }
        self.cipher = cipher
        self.password = password
        conn = NWConnection(host: NWEndpoint.Host(server),
                            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any,
                            using: .udp)
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, let dec = NCSSDecoder(cipher: cipher, password: password),
               let plain = dec.feed(data), let payload = Self.stripTargetHeader(plain) {
                self.onReply(payload)
            }
            if error == nil { self.receiveLoop() }
        }
    }

    /// Parse a SOCKS-style ATYP header off the front of a decrypted packet.
    static func stripTargetHeader(_ data: Data) -> Data? {
        guard let first = data.first else { return nil }
        var offset: Int
        switch first {
        case 0x01: offset = 1 + 4 + 2
        case 0x04: offset = 1 + 16 + 2
        case 0x03:
            guard data.count >= 2 else { return nil }
            offset = 1 + 1 + Int(data[1]) + 2
        default: return nil
        }
        guard data.count > offset else { return nil }
        return Data(data[offset...])
    }

    func send(_ data: Data, to target: NCTarget) {
        guard let enc = NCSSEncoder(cipher: cipher, password: password) else { return }
        var plain = target.atypEncoded
        plain.append(data)
        guard plain.count <= 0x3fff, let packet = enc.encode(plain) else { return }
        conn.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}

/// Trojan UDP: packets ride the TLS stream (UDP command in the request head),
/// framed as ATYP + length + CRLF + payload.
final class NCUDPTrojanSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private var buffer = Data()
    private var cancelled = false

    init(proxy: NCProxy, firstTarget: NCTarget, queue: DispatchQueue) {
        raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                       tlsServerName: proxy.fields["sni"]?.string ?? proxy.server ?? "",
                       allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                       queue: queue)
        raw.start { [weak self] err in
            guard let self, err == nil, let password = proxy.password else { return }
            self.raw.send(NCTrojan.requestHead(password: password, target: firstTarget, udp: true))
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            self.buffer.append(data)
            self.parseFrames()
            if error == nil { self.receiveLoop() }
        }
    }

    private func parseFrames() {
        while let (payload, consumed) = Self.parseFrame(buffer) {
            buffer = Data(buffer.dropFirst(consumed))
            onReply(payload)
        }
    }

    /// One frame: ATYP header + len(2) + CRLF + payload. nil = need more bytes
    /// (or a malformed frame, which also just waits — the stream is trusted
    /// past the TLS layer in practice; a bad frame resyncs never, matching
    /// other clients' simple parsers).
    static func parseFrame(_ data: Data) -> (payload: Data, consumed: Int)? {
        guard let first = data.first else { return nil }
        var headerLen: Int
        switch first {
        case 0x01: headerLen = 1 + 4 + 2
        case 0x04: headerLen = 1 + 16 + 2
        case 0x03:
            guard data.count >= 2 else { return nil }
            headerLen = 1 + 1 + Int(data[1]) + 2
        default: return nil
        }
        guard data.count >= headerLen + 2 + 2 else { return nil }
        let len = Int(data[headerLen]) << 8 | Int(data[headerLen + 1])
        guard data[headerLen + 2] == 0x0d, data[headerLen + 3] == 0x0a else { return nil }
        let total = headerLen + 2 + 2 + len
        guard data.count >= total else { return nil }
        return (Data(data[(headerLen + 4)..<total]), total)
    }

    func send(_ data: Data, to target: NCTarget) {
        raw.send(NCTrojan.udpPacket(target: target, payload: data))
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}
