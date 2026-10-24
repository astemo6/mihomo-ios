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

    func forward(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any
        let conn = NWConnection(host: NWEndpoint.Host(server), port: nwPort, using: .udp)
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
                            Self.forwardTCP(query, server: server, port: port, queue: self.queue) { finish($0 ?? data) }
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

    static func forwardTCP(_ query: Data, server: String, port: Int = 53, queue: DispatchQueue, completion: @escaping (Data?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any, using: .tcp)
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
    /// Set for 2022-blake3-* ciphers: per-session packet crypto (one UDP
    /// session per app flow, matching the session model of the spec).
    private let ss2022: NCSS2022UDPCrypto?

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let cipherName = proxy.cipher, let pw = proxy.password,
              let server = proxy.server, let port = proxy.port,
              NCShadowsocks.spec(for: cipherName) != nil || NCSS2022.isMethod2022(cipherName)
        else { return nil }
        self.cipher = cipherName
        self.password = pw
        if NCSS2022.isMethod2022(cipherName) {
            guard let crypto = NCSS2022UDPCrypto(method: cipherName, password: pw) else { return nil }
            ss2022 = crypto
        } else {
            ss2022 = nil
        }
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
            if let data {
                if let ss2022 {
                    if let decoded = ss2022.decodePacket(data) { self.onReply(decoded.1) }
                } else if let dec = NCSSDecoder(cipher: cipher, password: password),
                          let plain = dec.feed(data), let payload = Self.stripTargetHeader(plain) {
                    self.onReply(payload)
                }
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
        if let ss2022 {
            guard let packet = ss2022.encodePacket(target: target, payload: data,
                                                   timestamp: UInt64(Date().timeIntervalSince1970))
            else { return }
            conn.send(content: packet, completion: .idempotent)
            return
        }
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

/// Snell UDP (v3+): packets ride a dedicated TCP connection that begins
/// with the UDP command header. v3 carries each packet as one AEAD stream
/// chunk; v4 as one frame. Responses use Snell's response address format.
final class NCUDPSnellSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private let version: Int
    private let encoder: NCSnellStreamEncoder?
    private let decoder: NCSnellStreamDecoder?
    private let v4Writer: NCSnellV4Writer?
    private let v4Reader: NCSnellV4Reader?
    private var cancelled = false

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let password = proxy.password, let server = proxy.server, let port = proxy.port
        else { return nil }
        let version = proxy.fields["version"]?.int ?? 1
        guard version >= 3 else { return nil }
        self.version = version
        let psk = Data(password.utf8)
        if version >= 4 {
            v4Writer = NCSnellV4Writer(psk: psk)
            v4Reader = NCSnellV4Reader(psk: psk)
            encoder = nil
            decoder = nil
        } else {
            v4Writer = nil
            v4Reader = nil
            encoder = NCSnellStreamEncoder(psk: psk, version: version)
            decoder = NCSnellStreamDecoder(psk: psk, version: version)
        }
        raw = NCStream(to: server, port: port, queue: queue)
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            if let v4Writer {
                if let wire = v4Writer.write(NCSnell.udpHeader()) { self.raw.send(wire) }
            } else if let encoder {
                if let wire = encoder.encode(NCSnell.udpHeader()) { self.raw.send(wire) }
            }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            if let v4Reader {
                if let pieces = v4Reader.feed(data) {
                    for piece in pieces {
                        if case .data(let plain) = piece,
                           let parsed = NCSnell.parseUDPResponse(plain) {
                            self.onReply(parsed.1)
                        }
                    }
                }
            } else if let decoder, let pieces = decoder.feed(data) {
                for plain in pieces {
                    if let parsed = NCSnell.parseUDPResponse(plain) {
                        self.onReply(parsed.1)
                    }
                }
            }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        let frame = NCSnell.udpFrame(target: target, payload: data)
        if let v4Writer {
            if let wire = v4Writer.frame(frame) { raw.send(wire) }
        } else if let encoder {
            if let wire = encoder.encode(frame) { raw.send(wire) }
        }
    }

    func cancel() {
        cancelled = true
        raw.cancel()
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

/// Parsed nameserver entry: plain UDP/TCP, DoT, DoH, or DoQ (RFC 9250) —
/// the full encrypted-DNS set Surge/Loon/QX all support.
enum NCDNSUpstream: Equatable {
    case udp(host: String, port: Int)
    case tcp(host: String, port: Int)
    case dot(host: String, port: Int)
    case doh(url: String)
    case doq(host: String, port: Int)

    static func parse(_ raw0: String) -> NCDNSUpstream? {
        var raw = raw0
        if let hash = raw.firstIndex(of: "#") { raw = String(raw[..<hash]) }
        func hostPort(_ rest: String, _ def: Int) -> (String, Int)? {
            let parts = rest.split(separator: ":", maxSplits: 1)
            guard let host = parts.first, !host.isEmpty else { return nil }
            return (String(host), parts.count > 1 ? Int(parts[1]) ?? def : def)
        }
        if raw.hasPrefix("tls://"), let hp = hostPort(String(raw.dropFirst(6)), 853) {
            return .dot(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("quic://"), let hp = hostPort(String(raw.dropFirst(7)), 853) {
            return .doq(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("tcp://"), let hp = hostPort(String(raw.dropFirst(6)), 53) {
            return .tcp(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("https://") {
            return .doh(url: raw)
        }
        if raw.hasPrefix("udp://"), let hp = hostPort(String(raw.dropFirst(6)), 53) {
            return .udp(host: hp.0, port: hp.1)
        }
        if raw.contains("://") || raw == "system" { return nil }
        guard let hp = hostPort(raw, 53) else { return nil }
        return .udp(host: hp.0, port: hp.1)
    }

    /// Map a canonical DNS server reference onto a forwardable upstream.
    init?(_ ref: NCDNSServerRef) {
        switch ref.scheme {
        case .udp: self = .udp(host: ref.host, port: ref.port)
        case .tcp: self = .tcp(host: ref.host, port: ref.port)
        case .dot: self = .dot(host: ref.host, port: ref.port)
        case .doq: self = .doq(host: ref.host, port: ref.port)
        case .doh:
            var url = "https://\(ref.host)"
            if ref.port != 443 { url += ":\(ref.port)" }
            url += ref.path ?? "/dns-query"
            self = .doh(url: url)
        case .dhcp, .system: return nil
        }
    }
}

extension NCDNSForwarder {
    /// Forward via any upstream kind.
    func forward(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) {
        switch upstream {
        case .udp(let host, let port):
            forward(query, server: host, port: port, completion: completion)
        case .tcp(let host, let port):
            Self.forwardTCP(query, server: host, port: port, queue: queue, completion: completion)
        case .dot(let host, let port):
            Self.forwardDoT(query, host: host, port: port, queue: queue, completion: completion)
        case .doh(let url):
            Self.forwardDoH(query, urlString: url, queue: queue, completion: completion)
        case .doq(let host, let port):
            Self.forwardDoQ(query, host: host, port: port, queue: queue, completion: completion)
        }
    }

    /// DoQ (RFC 9250): one bidirectional QUIC stream per query inside a
    /// throwaway connection group; the message is length-prefixed exactly
    /// like DNS-over-TCP, and the send side is closed after the query.
    private static func forwardDoQ(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let quicOptions = NWProtocolQUIC.Options(alpn: ["doq"])
        if let sec = quicOptions.securityProtocolOptions {
            sec_protocol_options_set_min_tls_protocol_version(sec, .tlsProtocol13)
        }
        let params = NWParameters(quic: quicOptions)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            group.cancel()
            completion(data)
        }
        group.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let conn = group.extract(connectionTo: nil, using: nil) else {
                    finish(nil)
                    return
                }
                conn.stateUpdateHandler = { cstate in
                    if case .failed = cstate { finish(nil) }
                }
                conn.start(queue: queue)
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, contentContext: .defaultMessage, isComplete: true,
                          completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
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
        group.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    /// DoT (RFC 7858): TLS stream, 2-byte length framing both ways.
    private static func forwardDoT(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        let stream = NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            stream.cancel()
            completion(data)
        }
        stream.start { err in
            guard err == nil else { finish(nil); return }
            var framed = Data()
            framed.appendBE16(UInt16(query.count))
            framed.append(query)
            stream.send(framed)
            var buffer = Data()
            func pump() {
                stream.receive { data, _ in
                    guard let data else { finish(nil); return }
                    buffer.append(data)
                    if buffer.count >= 2 {
                        let len = Int(buffer[0]) << 8 | Int(buffer[1])
                        if buffer.count >= 2 + len {
                            finish(Data(buffer[2..<(2 + len)]))
                            return
                        }
                    }
                    pump()
                }
            }
            pump()
        }
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    /// DoH (RFC 8484): POST the wire query to the HTTPS endpoint, read the
    /// wire answer (Content-Length or chunked body).
    private static func forwardDoH(_ query: Data, urlString: String, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: urlString), let host = url.host else {
            completion(nil)
            return
        }
        let port = url.port ?? 443
        let path = url.path.isEmpty ? "/dns-query" : url.path
        let stream = NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            stream.cancel()
            completion(data)
        }
        stream.start { err in
            guard err == nil else { finish(nil); return }
            var head = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: \(query.count)\r\nConnection: close\r\n\r\n"
            var request = Data(head.utf8)
            head = ""
            request.append(query)
            stream.send(request)
            var buffer = Data()
            func pump() {
                stream.receive { data, error in
                    if let data { buffer.append(data) }
                    if let body = Self.dohBody(buffer) {
                        finish(body)
                        return
                    }
                    if data == nil {
                        finish(nil)
                        return
                    }
                    if error == nil { pump() }
                }
            }
            pump()
        }
        queue.asyncAfter(deadline: .now() + 6) { finish(nil) }
    }

    /// Extract the body once the full HTTP response has arrived.
    private static func dohBody(_ data: Data) -> Data? {
        guard let headEnd = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[data.startIndex..<headEnd.lowerBound], as: UTF8.self).lowercased()
        let body = Data(data[headEnd.upperBound...])
        if head.contains("transfer-encoding: chunked") {
            var out = Data()
            var rest = body
            while true {
                guard let lineEnd = rest.range(of: Data("\r\n".utf8)) else { return nil }
                let sizeText = String(decoding: rest[rest.startIndex..<lineEnd.lowerBound], as: UTF8.self)
                guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else { return nil }
                if size == 0 { return out }
                let chunkStart = lineEnd.upperBound
                guard rest.count - chunkStart >= size + 2 else { return nil }
                out.append(Data(rest[chunkStart..<(chunkStart + size)]))
                rest = Data(rest[(chunkStart + size + 2)...])
            }
        }
        if let match = head.range(of: "content-length:"),
           let end = head[match.upperBound...].range(of: "\r\n") {
            let lenText = head[match.upperBound..<end.lowerBound].trimmingCharacters(in: .whitespaces)
            if let len = Int(lenText), body.count >= len {
                return Data(body.prefix(len))
            }
            return nil
        }
        return nil
    }
}

/// VMess UDP: a dedicated VMess connection (command 0x02) per destination —
/// the sing-vmess packet connection: the body is the AEAD chunk stream, one
/// record per datagram, target only in the request header.
final class NCUDPVMessSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private let encoder: NCVMessChunkEncoder?
    private let respReader: NCVMessResponseReader
    private let respKeys: (key: Data, nonce: Data)
    private let security: UInt8
    private var decoder: NCVMessChunkDecoder?
    private var responseStarted = false
    private var cancelled = false

    init?(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        let uuidBytesOpt: Data? = proxy.uuid.flatMap { uuidString in
            NCVLESS.uuidBytes(uuidString).map { Data($0) } ?? NCSHA1.uuidV5NilNamespace(uuidString)
        }
        let sec: UInt8
        switch (proxy.fields["cipher"]?.string ?? "auto").lowercased() {
        case "auto", "aes-128-gcm": sec = NCVMess.securityAESGCM
        case "chacha20-poly1305": sec = NCVMess.securityChaCha
        case "none": sec = NCVMess.securityNone
        default: return nil
        }
        guard (proxy.fields["alterId"]?.int ?? 0) == 0, let uuidBytes = uuidBytesOpt else { return nil }
        security = sec
        if proxy.fields["tls"]?.bool ?? false {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                           tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? proxy.server ?? "",
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        } else {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        }
        let reqKey = NCConnector.randomData(16)
        let reqNonce = NCConnector.randomData(16)
        let respV = NCConnector.randomData(1)[0]
        encoder = sec == NCVMess.securityNone ? nil
            : NCVMessChunkEncoder(bodyKey: reqKey, nonceBase: reqNonce, security: sec)
        respKeys = NCVMess.responseKeys(reqKey: reqKey, reqNonce: reqNonce)
        respReader = NCVMessResponseReader(respKey: respKeys.key, respNonce: respKeys.nonce, expectedV: respV)
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            let option: UInt8 = sec == NCVMess.securityNone ? 0
                : NCVMess.optionChunkStream | NCVMess.optionChunkMasking
            let plain = NCVMess.plainHeader(reqNonce: reqNonce, reqKey: reqKey, respV: respV,
                                            option: option, security: sec,
                                            padding: NCConnector.randomData(Int(NCConnector.randomData(1)[0]) % 16),
                                            target: target, command: 0x02)
            let sealed = NCVMess.sealHeader(cmdKey: NCVMess.cmdKey(uuidBytes: uuidBytes),
                                            plainHeader: plain,
                                            time: Int64(Date().timeIntervalSince1970),
                                            authRandom4: NCConnector.randomData(4),
                                            connNonce: NCConnector.randomData(8))
            self.raw.send(sealed)
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            if !responseStarted {
                respReader.feed(data)
                switch respReader.state {
                case .failed:
                    return
                case .reading:
                    break
                case .done:
                    responseStarted = true
                    if security != NCVMess.securityNone {
                        decoder = NCVMessChunkDecoder(bodyKey: respKeys.key, nonceBase: respKeys.nonce, security: security)
                    }
                    let rest = respReader.bodyRemainder
                    if !rest.isEmpty { deliver(rest) }
                }
            } else {
                deliver(data)
            }
            if error == nil { self.receiveLoop() }
        }
    }

    private func deliver(_ data: Data) {
        guard let decoder else {
            onReply(data) // security none: the datagram stream is raw (rare)
            return
        }
        guard let messages = decoder.feedMessages(data) else { return }
        for m in messages { onReply(m) }
    }

    func send(_ data: Data, to target: NCTarget) {
        if let encoder {
            raw.send(encoder.encode(data))
        } else {
            raw.send(data)
        }
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}

/// VLESS UDP: dedicated connection per destination (command 0x02); datagrams
/// are framed as BE16 length + payload in both directions after the response
/// head (version + addon length).
final class NCUDPVLESSSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private var buffer = Data()
    private var responseHeadConsumed = false
    private var cancelled = false

    init?(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        let headOpt: Data? = proxy.uuid.flatMap { NCVLESS.requestHead(uuid: $0, target: target, command: 0x02) }
        guard let head = headOpt else { return nil }
        if proxy.fields["tls"]?.bool ?? false {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                           tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? proxy.server ?? "",
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        } else {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        }
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            self.raw.send(head)
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
        if !responseHeadConsumed {
            guard buffer.count >= 2 else { return }
            let addonLen = Int(buffer[1])
            guard buffer.count >= 2 + addonLen else { return }
            buffer = Data(buffer.dropFirst(2 + addonLen))
            responseHeadConsumed = true
        }
        while buffer.count >= 2 {
            let len = Int(buffer[0]) << 8 | Int(buffer[1])
            guard buffer.count >= 2 + len else { return }
            let payload = Data(buffer[2..<(2 + len)])
            buffer = Data(buffer.dropFirst(2 + len))
            onReply(payload)
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        var framed = Data()
        framed.appendBE16(UInt16(clamping: data.count))
        framed.append(data)
        raw.send(framed)
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}
