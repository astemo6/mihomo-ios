import CryptoKit
import Foundation
import Network
import Security

// feat/nc-brook: Brook outbound (txthinking/brook), pure Swift.
//
// Wire format, ported from brook's own sources (streamclient, packetclient, simplestreamclient,
// simplepacketclient, websocket, brooklink, quic — protocol/*.md):
//
//  * KEY = HKDF-SHA256(IKM = password, salt = 12-byte nonce, info = "brook"), 32 bytes, AES-256-GCM.
//    The two infos can be overridden per link (clientHKDFInfo / serverHKDFInfo).
//  * Stream (brook server TCP, wsserver / wssserver after the HTTP upgrade, quicserver stream):
//      client → server: client nonce (12) | frame* ; server → client: server nonce (12) | frame*
//      frame = GCM(BE16 len) [18 bytes] | GCM(payload) [len + 16]; the nonce is a little-endian u64
//      counter in its first 8 bytes, bumped after EVERY seal / open (so twice per frame).
//      The first client frame is BE32 unix time + DST (SOCKS5 ATYP | addr | port); the time is even for a
//      TCP request and odd for a UDP-over-stream one (the server picks the network from the parity, and
//      rejects anything older than 60 s). The server's TCP read buffer is 2048 bytes: a TCP frame carries
//      at most 2048 - 2 - 16 - 16 = 2014 payload bytes. A UDP-over-stream frame is one whole datagram.
//  * Packet (brook server UDP, quicserver datagram): nonce (12) | GCM(BE32 time | DST | payload);
//    replies are nonce (12) | GCM(SRC address | payload), each with a fresh nonce and its own key.
//  * withoutBrookProtocol (ws / wss / quic): the password becomes SHA-256(password) and is sent in clear —
//      stream head = sha256 (32) | BE16 (4 + len DST) | BE32 time | DST, then the raw TCP stream, or
//      BE16 len | datagram frames for UDP; packet = sha256 | BE32 time | DST | payload, reply DST | payload.
//  * wsserver: an ordinary RFC 6455 upgrade request — but after the 101 the socket carries the brook stream
//    raw, with NO websocket framing (the server takes conn.UnderlyingConn()). wssserver is the same over TLS
//    (ALPN http/1.1). quicserver: ALPN h3, one bidirectional stream per TCP flow (the server accepts any
//    number of streams per connection, so the client shares one QUIC connection per node), UDP as QUIC
//    datagrams (≤ 1197 bytes) or, with udpoverstream, a stream.
//
// Memory: the codecs keep one rebased input buffer each and no per-frame allocations beyond the output.

// MARK: - Crypto + wire primitives

enum NCBrook {
    static let defaultHKDFInfo = Data("brook".utf8)
    /// Server-side TCP buffer (x.BP2048) minus BE16 length, its tag and the payload tag.
    static let maxTCPPayload = 2048 - 2 - 16 - 16
    /// Server-side UDP buffer (x.BP65507) minus the same overhead.
    static let maxUDPPayload = 65507 - 2 - 16 - 16
    /// brook quicserver: quic-go's max datagram payload.
    static let maxQUICDatagram = 1197
    /// NewStreamClient: `len(dst) > 2048-2-16-4-16` is rejected.
    static let maxDstLength = 2048 - 2 - 16 - 4 - 16

    static func key(password: Data, nonce: Data, info: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: password), salt: nonce, info: info,
                               outputByteCount: 32)
    }

    /// brook NextNonce: little-endian u64 increment of the first 8 bytes (bytes 8…11 never change).
    static func nextNonce(_ nonce: inout Data) {
        let base = nonce.startIndex
        for i in 0..<8 {
            let idx = base + i
            let (v, overflow) = nonce[idx].addingReportingOverflow(1)
            nonce[idx] = v
            if !overflow { return }
        }
    }

    /// NewStreamClient: even unix time for TCP, odd for UDP (bumped by one when the parity is wrong).
    static func requestTime(udp: Bool, now: UInt32) -> UInt32 {
        let odd = now % 2 == 1
        return odd == udp ? now : now &+ 1
    }

    static func nowUnix() -> UInt32 { UInt32(truncatingIfNeeded: Int64(Date().timeIntervalSince1970)) }

    static func seal(_ plain: Data, key: SymmetricKey, nonce: Data) -> Data? {
        guard let n = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.seal(plain, using: key, nonce: n) else { return nil }
        var out = Data(capacity: plain.count + 16)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    static func open(_ sealed: Data, key: SymmetricKey, nonce: Data) -> Data? {
        guard sealed.count >= 16, let n = try? AES.GCM.Nonce(data: nonce) else { return nil }
        let split = sealed.endIndex - 16
        guard let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: sealed[sealed.startIndex..<split],
                                               tag: sealed[split...]),
              let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return plain
    }

    static func be16(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }

    static func be32(_ v: UInt32) -> Data {
        Data([UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }

    /// Length of the SOCKS5-style address at `offset` (ATYP + addr + port), nil when malformed / short.
    static func addressLength(_ d: Data, at offset: Int = 0) -> Int? {
        let base = d.startIndex + offset
        guard d.endIndex > base else { return nil }
        let n: Int
        switch d[base] {
        case 0x01: n = 1 + 4 + 2
        case 0x04: n = 1 + 16 + 2
        case 0x03:
            guard d.endIndex > base + 1 else { return nil }
            n = 1 + 1 + Int(d[base + 1]) + 2
        default: return nil
        }
        return d.endIndex - base >= n ? n : nil
    }

    // MARK: Packet (brook server UDP / quicserver datagram)

    /// nonce | GCM_k(nonce)(BE32 time | DST | payload), k = HKDF(password, nonce, clientInfo).
    static func packetEncode(password: Data, clientInfo: Data = defaultHKDFInfo, dst: Data, payload: Data,
                             nonce: Data? = nil, now: UInt32 = nowUnix()) -> Data? {
        let n = nonce ?? randomBytes(12)
        guard n.count == 12 else { return nil }
        var plain = Data(capacity: 4 + dst.count + payload.count)
        plain.append(be32(now))
        plain.append(dst)
        plain.append(payload)
        guard let sealed = seal(plain, key: key(password: password, nonce: n, info: clientInfo), nonce: n) else { return nil }
        return n + sealed
    }

    /// Server reply: nonce | GCM(SRC | payload) under HKDF(password, nonce, serverInfo).
    static func packetDecode(password: Data, serverInfo: Data = defaultHKDFInfo, packet: Data) -> (address: Data, payload: Data)? {
        guard packet.count >= 12 + 16 else { return nil }
        let n = Data(packet.prefix(12))
        guard let plain = open(Data(packet.dropFirst(12)), key: key(password: password, nonce: n, info: serverInfo), nonce: n),
              let alen = addressLength(plain) else { return nil }
        return (Data(plain.prefix(alen)), Data(plain.dropFirst(alen)))
    }

    /// withoutBrookProtocol packet: SHA256(password) | BE32 time | DST | payload.
    static func simplePacketEncode(passwordHash: Data, dst: Data, payload: Data, now: UInt32 = nowUnix()) -> Data {
        var out = Data(capacity: 32 + 4 + dst.count + payload.count)
        out.append(passwordHash)
        out.append(be32(now))
        out.append(dst)
        out.append(payload)
        return out
    }

    /// withoutBrookProtocol reply: SRC | payload.
    static func simplePacketDecode(_ packet: Data) -> (address: Data, payload: Data)? {
        guard let alen = addressLength(packet) else { return nil }
        return (Data(packet.prefix(alen)), Data(packet.dropFirst(alen)))
    }

    static func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        if ok != errSecSuccess { for i in 0..<n { d[i] = UInt8.random(in: 0...255) } }
        return d
    }

    static func sha256(_ s: String) -> Data { Data(SHA256.hash(data: Data(s.utf8))) }
}

// MARK: - Stream codecs

/// One direction pair of a brook stream (client side): `head` goes out first, `encode` frames outbound
/// plaintext, `feed` returns the inbound plaintext pieces (one per frame; a datagram each in UDP mode).
/// nil from encode / feed = fatal (oversized datagram, authentication failure, malformed frame).
protocol NCBrookCodec: AnyObject {
    var head: Data { get }
    func encode(_ data: Data) -> Data?
    func feed(_ data: Data) -> [Data]?
}

/// brook StreamClient (AES-256-GCM frames).
final class NCBrookStreamCodec: NCBrookCodec {
    let udp: Bool
    let head: Data
    private let clientKey: SymmetricKey
    private var clientNonce: Data
    private let password: Data
    private let serverInfo: Data
    private var serverKey: SymmetricKey?
    private var serverNonce = Data()
    private var inbuf = Data()
    private var inOff = 0
    private var pendingLen: Int?
    private var failed = false

    init?(password: Data, udp: Bool, dst: Data, clientInfo: Data = NCBrook.defaultHKDFInfo,
          serverInfo: Data = NCBrook.defaultHKDFInfo, nonce: Data? = nil, now: UInt32 = NCBrook.nowUnix()) {
        guard dst.count <= NCBrook.maxDstLength, NCBrook.addressLength(dst) == dst.count else { return nil }
        let n = nonce ?? NCBrook.randomBytes(12)
        guard n.count == 12 else { return nil }
        self.udp = udp
        self.password = password
        self.serverInfo = serverInfo
        let k = NCBrook.key(password: password, nonce: n, info: clientInfo)
        var counter = n
        var first = NCBrook.be32(NCBrook.requestTime(udp: udp, now: now))
        first.append(dst)
        guard let frame = Self.sealFrame(first, key: k, nonce: &counter) else { return nil }
        clientKey = k
        clientNonce = counter
        head = n + frame
    }

    private static func sealFrame(_ payload: Data, key: SymmetricKey, nonce: inout Data) -> Data? {
        guard let l = NCBrook.seal(NCBrook.be16(payload.count), key: key, nonce: nonce) else { return nil }
        NCBrook.nextNonce(&nonce)
        guard let p = NCBrook.seal(payload, key: key, nonce: nonce) else { return nil }
        NCBrook.nextNonce(&nonce)
        return l + p
    }

    func encode(_ data: Data) -> Data? {
        if udp {
            guard data.count <= NCBrook.maxUDPPayload else { return nil }
            return Self.sealFrame(data, key: clientKey, nonce: &clientNonce)
        }
        var out = Data(capacity: data.count + (data.count / NCBrook.maxTCPPayload + 1) * 34)
        var i = data.startIndex
        repeat {
            let end = min(i + NCBrook.maxTCPPayload, data.endIndex)
            guard let f = Self.sealFrame(Data(data[i..<end]), key: clientKey, nonce: &clientNonce) else { return nil }
            out.append(f)
            i = end
        } while i < data.endIndex
        return out
    }

    func feed(_ data: Data) -> [Data]? {
        guard !failed else { return nil }
        inbuf.append(data)
        var out: [Data] = []
        while true {
            let avail = inbuf.count - inOff
            if serverKey == nil {
                guard avail >= 12 else { break }
                serverNonce = Data(inbuf[inOff..<(inOff + 12)])
                serverKey = NCBrook.key(password: password, nonce: serverNonce, info: serverInfo)
                inOff += 12
                continue
            }
            guard let key = serverKey else { break }
            if let len = pendingLen {
                guard avail >= len + 16 else { break }
                guard let plain = NCBrook.open(Data(inbuf[inOff..<(inOff + len + 16)]), key: key, nonce: serverNonce) else {
                    failed = true
                    return nil
                }
                NCBrook.nextNonce(&serverNonce)
                inOff += len + 16
                pendingLen = nil
                out.append(plain)
            } else {
                guard avail >= 18 else { break }
                guard let lb = NCBrook.open(Data(inbuf[inOff..<(inOff + 18)]), key: key, nonce: serverNonce), lb.count == 2 else {
                    failed = true
                    return nil
                }
                NCBrook.nextNonce(&serverNonce)
                inOff += 18
                pendingLen = Int(lb[lb.startIndex]) << 8 | Int(lb[lb.startIndex + 1])
            }
        }
        if inOff >= inbuf.count {
            inbuf = Data(); inOff = 0
        } else if inOff > 4096 && inOff > inbuf.count / 2 {
            inbuf = Data(inbuf[inOff...]); inOff = 0
        }
        return out
    }
}

/// brook SimpleStreamClient (withoutBrookProtocol): cleartext SHA-256(password) head, then the raw TCP stream,
/// or BE16-length-framed datagrams for UDP.
final class NCBrookSimpleCodec: NCBrookCodec {
    let udp: Bool
    let head: Data
    private var inbuf = Data()
    private var inOff = 0

    init?(passwordHash: Data, udp: Bool, dst: Data, now: UInt32 = NCBrook.nowUnix()) {
        guard passwordHash.count == 32, dst.count <= 2048 - 32 - 2 - 4, NCBrook.addressLength(dst) == dst.count else { return nil }
        self.udp = udp
        var h = passwordHash
        h.append(NCBrook.be16(4 + dst.count))
        h.append(NCBrook.be32(NCBrook.requestTime(udp: udp, now: now)))
        h.append(dst)
        head = h
    }

    func encode(_ data: Data) -> Data? {
        guard udp else { return data }
        guard data.count <= 65507 - 2 else { return nil }
        return NCBrook.be16(data.count) + data
    }

    func feed(_ data: Data) -> [Data]? {
        guard udp else { return [data] }
        inbuf.append(data)
        var out: [Data] = []
        while inbuf.count - inOff >= 2 {
            let len = Int(inbuf[inOff]) << 8 | Int(inbuf[inOff + 1])
            guard inbuf.count - inOff >= 2 + len else { break }
            out.append(Data(inbuf[(inOff + 2)..<(inOff + 2 + len)]))
            inOff += 2 + len
        }
        if inOff >= inbuf.count { inbuf = Data(); inOff = 0 }
        else if inOff > inbuf.count / 2 { inbuf = Data(inbuf[inOff...]); inOff = 0 }
        return out
    }
}

/// TCP relay over a brook codec: the head goes out at once, inbound pieces are concatenated per receive.
final class NCBrookRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private let codec: NCBrookCodec

    init(raw: NCRelayStream, codec: NCBrookCodec) {
        self.raw = raw
        self.codec = codec
        raw.send(codec.head)
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        guard let wire = codec.encode(data) else { raw.cancel(); once.call(); return }
        raw.send(wire, completion: once.call)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            guard let pieces = self.codec.feed(data) else {
                handler(nil, NSError(domain: "NativeCore", code: 3, userInfo: [NSLocalizedDescriptionKey: "brook decode failed"]))
                return
            }
            if pieces.isEmpty { self.receive(handler); return }
            if pieces.count == 1 { handler(pieces[0], nil); return }
            var joined = Data(capacity: pieces.reduce(0) { $0 + $1.count })
            for p in pieces { joined.append(p) }
            handler(joined, nil)
        }
    }

    func cancel() { raw.cancel() }
}

// MARK: - Options

/// A brook node, from the NCProxy field bag (YAML `type: brook`, or a converted brook:// link).
///
///     - name: b1
///       type: brook
///       server: 1.2.3.4            # dial address (brook link `address` when it overrides the URL host)
///       port: 9999
///       password: hello
///       transport: server          # server | wsserver | wssserver | quicserver (default server)
///       host: example.com          # ws/wss/quic URL host: Host header + SNI (default: server); may be host:port
///       path: /ws                  # ws/wss path (default /ws)
///       udp-over-tcp: false        # server: UDP over the TCP stream instead of UDP packets
///       udp-over-stream: false     # quicserver: UDP over a QUIC stream instead of datagrams
///       without-brook-protocol: false   # ws/wss/quic: SHA-256(password) in clear, no brook crypto
///       skip-cert-verify: false    # wss/quic (link: insecure=true)
///       ca: "-----BEGIN CERTIFICATE-----…"   # wss/quic extra root (link: ca)
///       client-fingerprint: chrome # wss uTLS-style ClientHello (link: tlsfingerprint)
///       client-hkdf-info / server-hkdf-info: brook
///       fragment: "50:100:10:50"   # wss ClientHello fragmentation — accepted, not applied
///       udp: true
struct NCBrookOptions {
    enum Kind: String { case server, wsserver, wssserver, quicserver }

    var kind: Kind
    var server: String
    var port: Int
    /// SNI / certificate name (host part of `host`).
    var hostName: String
    /// HTTP Host header for ws / wss (brook sends the URL's host:port verbatim).
    var hostHeader: String
    var path: String
    /// Key material: the password, or SHA-256(password) with withoutBrookProtocol.
    var password: Data
    var withoutBrook: Bool
    var udpOverTCP: Bool
    var udpOverStream: Bool
    var insecure: Bool
    var caPEM: String?
    var fingerprint: String?
    var clientInfo: Data
    var serverInfo: Data
    var token: String?

    static func string(_ p: NCProxy, _ keys: String...) -> String? {
        for k in keys {
            guard let v = p.fields[k] else { continue }
            if let s = v.string, !s.isEmpty { return s }
            if let i = v.int { return String(i) }
        }
        return nil
    }

    static func bool(_ p: NCProxy, _ keys: String...) -> Bool {
        for k in keys {
            guard let v = p.fields[k] else { continue }
            if let b = v.bool { return b }
            if let s = v.string?.lowercased() { return s == "true" || s == "1" }
            if let i = v.int { return i != 0 }
        }
        return false
    }

    /// The configured transport word mapped to a kind; nil when unrecognised.
    static func kind(_ p: NCProxy) -> Kind? {
        let raw = (string(p, "transport", "brook-transport", "kind", "mode") ?? "server").lowercased()
        switch raw {
        case "server", "tcp", "brook": return .server
        case "wsserver", "ws", "websocket": return .wsserver
        case "wssserver", "wss": return .wssserver
        case "quicserver", "quic": return .quicserver
        default: return nil
        }
    }

    init?(proxy p: NCProxy) {
        guard let kind = Self.kind(p), let server = p.server, !server.isEmpty, let port = p.port, port > 0 else { return nil }
        let pw = Self.string(p, "password") ?? ""
        self.kind = kind
        self.server = server
        self.port = port
        let host = Self.string(p, "host", "sni", "servername") ?? server
        let (hn, hp) = Self.splitHostPort(host)
        hostName = hn
        let headerPort = hp ?? port
        hostHeader = (hn.contains(":") ? "[\(hn)]" : hn) + ":\(headerPort)"
        var path = Self.string(p, "path", "ws-path") ?? (p.fields["ws-opts"]?.object?["path"]?.string ?? "/ws")
        if path.isEmpty { path = "/ws" }
        if !path.hasPrefix("/") { path = "/" + path }
        self.path = path
        withoutBrook = kind != .server && Self.bool(p, "without-brook-protocol", "withoutBrookProtocol")
        password = withoutBrook ? NCBrook.sha256(pw) : Data(pw.utf8)
        udpOverTCP = Self.bool(p, "udp-over-tcp", "udpovertcp")
        udpOverStream = Self.bool(p, "udp-over-stream", "udpoverstream")
        insecure = Self.bool(p, "skip-cert-verify", "insecure")
        caPEM = Self.string(p, "ca", "ca-str")
        fingerprint = Self.string(p, "client-fingerprint", "tlsfingerprint", "fingerprint")
        clientInfo = Self.string(p, "client-hkdf-info", "clientHKDFInfo").map { Data($0.utf8) } ?? NCBrook.defaultHKDFInfo
        serverInfo = Self.string(p, "server-hkdf-info", "serverHKDFInfo").map { Data($0.utf8) } ?? NCBrook.defaultHKDFInfo
        token = Self.string(p, "token")
    }

    /// "h", "h:443", "[v6]:443", "v6" → (host, port?).
    static func splitHostPort(_ s: String) -> (String, Int?) {
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let h = String(s[s.index(after: s.startIndex)..<close])
            let tail = s[s.index(after: close)...]
            return (h, tail.hasPrefix(":") ? Int(tail.dropFirst()) : nil)
        }
        let colons = s.filter { $0 == ":" }.count
        if colons == 1, let c = s.lastIndex(of: ":"), let p = Int(s[s.index(after: c)...]) {
            return (String(s[..<c]), p)
        }
        return (s, nil)
    }

    /// The UDP path brook's CreateExchanger takes for this kind.
    var udpUsesPackets: Bool {
        switch kind {
        case .server: return !udpOverTCP
        case .quicserver: return !udpOverStream
        case .wsserver, .wssserver: return false
        }
    }

    func makeCodec(udp: Bool, dst: Data) -> NCBrookCodec? {
        if withoutBrook { return NCBrookSimpleCodec(passwordHash: password, udp: udp, dst: dst) }
        return NCBrookStreamCodec(password: password, udp: udp, dst: dst, clientInfo: clientInfo, serverInfo: serverInfo)
    }

    /// One outbound datagram (packet path).
    func encodePacket(dst: Data, payload: Data) -> Data? {
        if withoutBrook { return NCBrook.simplePacketEncode(passwordHash: password, dst: dst, payload: payload) }
        return NCBrook.packetEncode(password: password, clientInfo: clientInfo, dst: dst, payload: payload)
    }

    func decodePacket(_ packet: Data) -> Data? {
        if withoutBrook { return NCBrook.simplePacketDecode(packet)?.payload }
        return NCBrook.packetDecode(password: password, serverInfo: serverInfo, packet: packet)?.payload
    }

    /// DER certificates from the `ca` PEM (several blocks allowed).
    var caCertificates: [SecCertificate] {
        guard let pem = caPEM else { return [] }
        var out: [SecCertificate] = []
        var rest = Substring(pem)
        while let b = rest.range(of: "-----BEGIN CERTIFICATE-----"),
              let e = rest.range(of: "-----END CERTIFICATE-----", range: b.upperBound..<rest.endIndex) {
            let b64 = rest[b.upperBound..<e.lowerBound].filter { !$0.isWhitespace }
            if let der = Data(base64Encoded: String(b64)), let c = SecCertificateCreateWithData(nil, der as CFData) {
                out.append(c)
            }
            rest = rest[e.upperBound...]
        }
        return out
    }

    /// TLS knobs shared by wss (NWConnection) and quic: SNI, skip-cert-verify, a `ca` anchor (the old core RootCAs: only
    /// the given roots are trusted, hostname still checked).
    func applyTLS(_ sec: sec_protocol_options_t, queue: DispatchQueue) {
        if !hostName.isEmpty, IPv4Address(hostName) == nil, IPv6Address(hostName) == nil {
            sec_protocol_options_set_tls_server_name(sec, hostName)
        }
        if insecure {
            sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, queue)
            return
        }
        let anchors = caCertificates
        guard !anchors.isEmpty else { return }
        let name = hostName
        sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, name as CFString))
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var err: CFError?
            complete(SecTrustEvaluateWithError(trust, &err))
        }, queue)
    }
}

// MARK: - WebSocket upgrade (raw stream after the 101)

enum NCBrookWebSocket {
    static func request(path: String, hostHeader: String, key: String) -> Data {
        Data(("GET \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\n\r\n").utf8)
    }

    static func acceptValue(key: String) -> String {
        Data(Insecure.SHA1.hash(data: Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))).base64EncodedString()
    }

    /// brook WebSocketDial: the status line must contain 101; a Sec-WebSocket-Accept, when present, must match.
    static func validate(head: String, key: String) -> Bool {
        let lines = head.components(separatedBy: "\r\n")
        guard let status = lines.first, status.hasPrefix("HTTP/1.1 "), status.contains("101") else { return false }
        let want = acceptValue(key: key)
        for l in lines.dropFirst() {
            let lower = l.lowercased()
            if lower.hasPrefix("sec-websocket-accept:") {
                let v = l.dropFirst("sec-websocket-accept:".count).trimmingCharacters(in: .whitespaces)
                if v != want { return false }
            }
        }
        return true
    }

    static func upgrade(raw: NCRelayStream, hostHeader: String, path: String, queue: DispatchQueue,
                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let key = NCBrook.randomBytes(16).base64EncodedString()
        let deadline = NCHandshakeDeadline(queue: queue, seconds: 15, raw: raw, what: "brook websocket", completion: completion)
        raw.send(request(path: path, hostHeader: hostHeader, key: key))
        var head = Data()
        func pump() {
            raw.receive { data, error in
                guard !deadline.isDone else { return }
                guard let data else {
                    raw.cancel()
                    deadline.finish(nil, error ?? NCConnector.Failure.handshake("brook websocket upgrade"))
                    return
                }
                head.append(data)
                if let end = head.range(of: Data("\r\n\r\n".utf8)) {
                    let text = String(decoding: head[head.startIndex..<end.lowerBound], as: UTF8.self)
                    guard validate(head: text, key: key) else {
                        raw.cancel()
                        deadline.finish(nil, NCConnector.Failure.handshake("brook websocket upgrade refused: \(text.prefix(64))"))
                        return
                    }
                    let rest = Data(head[end.upperBound...])
                    deadline.finish(rest.isEmpty ? raw : NCBufferedStream(inner: raw, prefix: rest), nil)
                    return
                }
                if head.count > 16384 {
                    raw.cancel()
                    deadline.finish(nil, NCConnector.Failure.handshake("brook websocket upgrade overflow"))
                    return
                }
                pump()
            }
        }
        pump()
    }
}

// MARK: - QUIC (quicserver)

/// One bidirectional QUIC stream extracted from a brook QUIC connection, as a relay byte pipe.
final class NCBrookQUICStream: NCRelayStream {
    private let conn: NWConnection
    private var cancelled = false

    init(conn: NWConnection) { self.conn = conn }

    func start(queue: DispatchQueue, ready: @escaping (Error?) -> Void) {
        var fired = false
        let c = conn
        conn.stateUpdateHandler = { state in
            guard !fired else { return }
            let result: Error?
            switch state {
            case .ready: result = nil
            case .failed(let e): result = e
            case .cancelled: result = NCConnector.Failure.handshake("brook quic stream cancelled")
            default: return
            }
            fired = true
            c.stateUpdateHandler = nil // one-shot: drop the closure (and what it captured)
            ready(result)
        }
        conn.start(queue: queue)
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !cancelled, !data.isEmpty else { completion(); return }
        conn.send(content: data, completion: .contentProcessed { _ in completion() })
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let data, !data.isEmpty { handler(data, nil) }
            else if isComplete { handler(nil, nil) }
            else { handler(nil, error) }
        }
    }

    func cancel() {
        cancelled = true
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}

/// A brook QUIC connection (NWConnectionGroup over a multiplex QUIC group, ALPN h3). TCP flows share one per
/// node (NCBrookQUICPool); each datagram-mode UDP association gets its own, like brook's QUICDialUDP.
/// The connection closes itself after the QUIC idle timeout once no stream is open.
final class NCBrookQUICConnection {
    let options: NCBrookOptions
    let datagram: Bool
    private let queue = DispatchQueue(label: "nc.brook.quic")
    private var group: NWConnectionGroup?
    private enum State { case idle, connecting, ready, dead }
    private var state = State.idle
    /// Mirror of `state == .dead` readable from any thread without touching `queue` (the pool checks it under
    /// its own lock, and `onDead` takes that lock from `queue` — a queue.sync here would deadlock).
    private let deadLock = NSLock()
    private var deadFlag = false
    private var deathError: Error?
    private var waiters: [(NWConnectionGroup?, Error?) -> Void] = []
    var onDead: (() -> Void)?

    init(options: NCBrookOptions, datagram: Bool) {
        self.options = options
        self.datagram = datagram
    }

    var isDead: Bool {
        deadLock.lock(); defer { deadLock.unlock() }
        return deadFlag
    }

    func quicOptions() -> NWProtocolQUIC.Options {
        let o = NWProtocolQUIC.Options(alpn: ["h3"])
        options.applyTLS(o.securityProtocolOptions, queue: queue)
        o.idleTimeout = 30_000
        if datagram { o.maxDatagramFrameSize = 1400 }
        return o
    }

    /// Delivers the ready group (or the error) on the connection queue.
    func withGroup(_ body: @escaping (NWConnectionGroup?, Error?) -> Void) {
        queue.async {
            switch self.state {
            case .ready: body(self.group, nil)
            case .dead: body(nil, self.deathError ?? NCConnector.Failure.handshake("brook quic connection closed"))
            case .connecting: self.waiters.append(body)
            case .idle:
                self.waiters.append(body)
                self.startOnQueue()
            }
        }
    }

    private func startOnQueue() {
        state = .connecting
        let params = NWParameters(quic: quicOptions())
        NCOutboundBinding.apply(params, host: options.server)
        let endpoint = NCStream.endpoint(options.server, port: options.port)
        let g = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        group = g
        g.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                guard self.state == .connecting else { return }
                self.state = .ready
                let w = self.waiters; self.waiters = []
                for f in w { f(g, nil) }
            case .failed(let e):
                self.die(e)
            case .cancelled:
                self.die(NCConnector.Failure.handshake("brook quic connection cancelled"))
            default:
                break
            }
        }
        // brook servers never open streams toward the client.
        g.newConnectionHandler = { incoming in incoming.cancel() }
        g.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.die(NCConnector.Failure.handshake("brook quic handshake timeout"))
        }
    }

    private func die(_ error: Error) {
        guard state != .dead else { return }
        state = .dead
        deathError = error
        deadLock.lock(); deadFlag = true; deadLock.unlock()
        let w = waiters; waiters = []
        for f in w { f(nil, error) }
        group?.stateUpdateHandler = nil
        group?.cancel()
        group = nil
        let cb = onDead; onDead = nil
        cb?()
    }

    func cancel() {
        queue.async { self.die(NCConnector.Failure.handshake("brook quic connection closed")) }
    }

    /// A new bidirectional stream; `completion` fires on `callerQueue` (the stream's own callbacks too).
    func openStream(callerQueue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        withGroup { g, err in
            guard let g else { callerQueue.async { completion(nil, err) }; return }
            guard let c = g.extract(connectionTo: nil, using: nil) else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("brook quic: cannot open stream")) }
                return
            }
            let s = NCBrookQUICStream(conn: c)
            s.start(queue: callerQueue) { e in completion(e == nil ? s : nil, e) }
        }
    }

    /// The RFC 9221 datagram flow (options derived from the group's own — NCQUICStreamOptions). `completion`
    /// fires on `callerQueue` once the flow is ready; the flow's callbacks run there too.
    func openDatagramFlow(callerQueue: DispatchQueue, completion: @escaping (NWConnection?, Error?) -> Void) {
        withGroup { [weak self] g, err in
            guard let self, let g else { callerQueue.async { completion(nil, err) }; return }
            let opts = NCQUICStreamOptions.datagram(from: g, fallback: self.quicOptions)
            guard let c = g.extract(connectionTo: nil, using: opts) else {
                callerQueue.async { completion(nil, NCConnector.Failure.handshake("brook quic: cannot open datagram flow")) }
                return
            }
            var fired = false
            // Strong capture until the first terminal state, then dropped (one-shot).
            c.stateUpdateHandler = { st in
                guard !fired else { return }
                switch st {
                case .ready: fired = true; c.stateUpdateHandler = nil; completion(c, nil)
                case .failed(let e): fired = true; c.stateUpdateHandler = nil; completion(nil, e)
                case .cancelled:
                    fired = true; c.stateUpdateHandler = nil
                    completion(nil, NCConnector.Failure.handshake("brook quic datagram flow cancelled"))
                default: break
                }
            }
            c.start(queue: callerQueue)
        }
    }
}

/// Shared quicserver connections for TCP flows, one per (server, port, TLS identity).
final class NCBrookQUICPool {
    static let shared = NCBrookQUICPool()
    private let lock = NSLock()
    private var conns: [String: NCBrookQUICConnection] = [:]

    static func key(_ o: NCBrookOptions) -> String {
        "\(o.server)|\(o.port)|\(o.hostName)|\(o.insecure)|\(o.caPEM?.hashValue ?? 0)"
    }

    func connection(for o: NCBrookOptions) -> NCBrookQUICConnection {
        let k = Self.key(o)
        lock.lock()
        defer { lock.unlock() }
        if let c = conns[k], !c.isDead { return c }
        let c = NCBrookQUICConnection(options: o, datagram: false)
        c.onDead = { [weak self, weak c] in
            guard let self else { return }
            self.lock.lock()
            if let c, self.conns[k] === c { self.conns[k] = nil }
            self.lock.unlock()
        }
        conns[k] = c
        return c
    }

    /// Tunnel stop (NCConnector.closeAllSharedSessions): drops and closes every pooled connection.
    @discardableResult
    func closeAll() -> Int {
        lock.lock()
        let all = Array(conns.values)
        conns = [:]
        lock.unlock()
        for c in all { c.cancel() }
        return all.count
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return conns.count
    }
}

// MARK: - Dialing

extension NCConnector {
    /// The byte pipe a brook stream rides on: TCP (server / wsserver), TLS (wssserver) — both upgraded to the raw
    /// post-101 stream for ws / wss — or a QUIC stream (quicserver). Over a chain `transport` the TCP kinds dial
    /// through it (wss with the hand-rolled TLS client); quicserver cannot ride a chain.
    static func brookPipe(_ o: NCBrookOptions, queue: DispatchQueue, transport: NCRelayStream?,
                          completion: @escaping (NCRelayStream?, Error?) -> Void) {
        func tcp(_ next: @escaping (NCRelayStream) -> Void) {
            if let transport { next(transport); return }
            let s = NCStream(to: o.server, port: o.port, queue: queue)
            s.start { err in
                if let err { completion(nil, err) } else { next(s) }
            }
        }
        func ws(_ base: NCRelayStream) {
            NCBrookWebSocket.upgrade(raw: base, hostHeader: o.hostHeader, path: o.path, queue: queue, completion: completion)
        }
        switch o.kind {
        case .server:
            tcp { completion($0, nil) }
        case .wsserver:
            tcp(ws)
        case .wssserver:
            let wantsHello = transport != nil || ((o.fingerprint ?? "").isEmpty == false && o.caPEM == nil)
            if wantsHello {
                tcp { base in
                    var cfg = NCTLSClientStream.Config(serverName: o.hostName)
                    cfg.alpn = ["http/1.1"]
                    cfg.allowInsecure = o.insecure
                    cfg.profile = NCClientHelloProfile.named(o.fingerprint)
                    let tls = NCTLSClientStream(raw: base, config: cfg, queue: queue)
                    tls.startHandshake { err in
                        if let err { base.cancel(); completion(nil, err) } else { ws(tls) }
                    }
                }
                return
            }
            let tlsOptions = NWProtocolTLS.Options()
            sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, "http/1.1")
            o.applyTLS(tlsOptions.securityProtocolOptions, queue: queue)
            let s = NCStream(to: o.server, port: o.port, parameters: NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options()),
                             queue: queue)
            s.start { err in
                if let err { completion(nil, err) } else { ws(s) }
            }
        case .quicserver:
            guard transport == nil else {
                queue.async { completion(nil, Failure.unsupported("brook quicserver over a chain transport")) }
                return
            }
            NCBrookQUICPool.shared.connection(for: o).openStream(callerQueue: queue, completion: completion)
        }
    }

    /// A brook TCP flow to `target`.
    static func brookStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue, transport: NCRelayStream?,
                            completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let o = NCBrookOptions(proxy: proxy) else {
            queue.async { completion(nil, Failure.handshake("brook: invalid node (server / port / transport)")) }
            return
        }
        guard let codec = o.makeCodec(udp: false, dst: target.atypEncoded) else {
            queue.async { completion(nil, Failure.handshake("brook: target cannot be encoded")) }
            return
        }
        brookPipe(o, queue: queue, transport: transport) { pipe, err in
            guard let pipe else { completion(nil, err); return }
            completion(NCBrookRelayStream(raw: pipe, codec: codec), nil)
        }
    }
}

// MARK: - brook:// links

/// brook link (brook link / brooklink): `brook://KIND?KIND=<server>&password=…&name=…[&…]` with the
/// query in the old core url.Values form (sorted keys, QueryEscape, `+` for space). KIND = server | wsserver | wssserver |
/// quicserver | socks5; the server is `host:port`, `ws://host:port/path`, `wss://host:port/path`,
/// `quic://host:port`, `socks5://host:port`.
enum NCBrookLink {
    /// the old core url.QueryUnescape semantics (`+` → space).
    static func queryUnescape(_ s: Substring) -> String {
        let plus = s.replacingOccurrences(of: "+", with: " ")
        return plus.removingPercentEncoding ?? plus
    }

    static func parseQuery(_ qs: Substring) -> [String: String] {
        var out: [String: String] = [:]
        for pair in qs.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let k = queryUnescape(kv[0])
            if out[k] == nil { out[k] = kv.count > 1 ? queryUnescape(kv[1]) : "" }
        }
        return out
    }

    /// `rest` = everything after `brook://`.
    static func parse(_ rest: String) -> NCProxy? {
        var s = Substring(rest)
        var fragName: String?
        if let h = s.firstIndex(of: "#") {
            fragName = String(s[s.index(after: h)...]).removingPercentEncoding
            s = s[..<h]
        }
        guard let qm = s.firstIndex(of: "?") else { return nil }
        var kind = String(s[..<qm]).lowercased()
        while kind.hasSuffix("/") { kind.removeLast() }
        let q = parseQuery(s[s.index(after: qm)...])
        guard let serverStr = q[kind], !serverStr.isEmpty else { return nil }
        let password = q["password"] ?? ""
        var f: [String: NCJSONValue] = [:]
        var urlHost = "", urlPort = 0, path = ""
        switch kind {
        case "server":
            let (h, p) = NCBrookOptions.splitHostPort(serverStr)
            guard !h.isEmpty, let p, p > 0 else { return nil }
            urlHost = h; urlPort = p
        case "wsserver", "wssserver", "quicserver", "socks5":
            guard let u = URLComponents(string: serverStr), let h = u.host, !h.isEmpty else { return nil }
            urlHost = h.hasPrefix("[") ? String(h.dropFirst().dropLast()) : h
            urlPort = u.port ?? (kind == "wsserver" ? 80 : kind == "socks5" ? 1080 : 443)
            path = u.percentEncodedPath
        default:
            return nil
        }
        let display = urlHost.contains(":") ? "[\(urlHost)]" : urlHost
        let name = q["name"].flatMap { $0.isEmpty ? nil : $0 } ?? fragName.flatMap { $0.isEmpty ? nil : $0 }
            ?? "Brook \(display)"
        if kind == "socks5" {
            // A brook link to a plain socks5 server is just a socks5 node.
            f["server"] = .string(urlHost)
            f["port"] = .number(Double(urlPort))
            if let u = q["username"], !u.isEmpty { f["username"] = .string(u) }
            if !password.isEmpty { f["password"] = .string(password) }
            f["udp"] = .bool(true)
            return NCProxy(name: name, type: "socks5", fields: f)
        }
        var dialHost = urlHost, dialPort = urlPort
        if kind != "server", let addr = q["address"], !addr.isEmpty {
            let (ah, ap) = NCBrookOptions.splitHostPort(addr)
            if !ah.isEmpty, let ap, ap > 0 { dialHost = ah; dialPort = ap }
        }
        f["server"] = .string(dialHost)
        f["port"] = .number(Double(dialPort))
        f["password"] = .string(password)
        f["transport"] = .string(kind)
        f["udp"] = .bool(true)
        if kind != "server" {
            if dialHost != urlHost || dialPort != urlPort {
                f["host"] = .string(dialPort == urlPort ? urlHost : "\(display):\(urlPort)")
            }
            if kind != "quicserver" { f["path"] = .string(path.isEmpty ? "/ws" : path) }
        }
        func flag(_ k: String, _ field: String) { if q[k] == "true" { f[field] = .bool(true) } }
        flag("udpovertcp", "udp-over-tcp")
        flag("udpoverstream", "udp-over-stream")
        flag("insecure", "skip-cert-verify")
        flag("withoutBrookProtocol", "without-brook-protocol")
        func copy(_ k: String, _ field: String) { if let v = q[k], !v.isEmpty { f[field] = .string(v) } }
        copy("ca", "ca")
        copy("tlsfingerprint", "client-fingerprint")
        copy("clientHKDFInfo", "client-hkdf-info")
        copy("serverHKDFInfo", "server-hkdf-info")
        copy("fragment", "fragment")
        copy("token", "token")
        return NCProxy(name: name, type: "brook", fields: f)
    }

    /// the old core url.QueryEscape.
    static func queryEscape(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            let unreserved = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                || b == 0x2D || b == 0x5F || b == 0x2E || b == 0x7E
            if unreserved { out.append(Character(UnicodeScalar(b))) }
            else if b == 0x20 { out.append("+") }
            else { out += String(format: "%%%02X", b) }
        }
        return out
    }

    /// brook link for a node field bag (brook.Link: url.Values.Encode → keys sorted).
    static func encode(name: String, fields m: [String: Any]) -> String? {
        func s(_ k: String) -> String {
            guard let any = m[k] else { return "" }
            switch any {
            case let v as String: return v
            case let v as NSNumber: return v.stringValue
            case let v as Int: return String(v)
            default: return ""
            }
        }
        func b(_ k: String) -> Bool {
            guard let any = m[k] else { return false }
            switch any {
            case let v as Bool: return v
            case let v as String: return v == "true" || v == "1"
            case let v as NSNumber: return v.intValue != 0
            default: return false
            }
        }
        let server = s("server"), port = s("port")
        guard !server.isEmpty, !port.isEmpty else { return nil }
        let kindRaw = s("transport").lowercased()
        let kind: String
        switch kindRaw {
        case "", "server", "tcp", "brook": kind = "server"
        case "wsserver", "ws", "websocket": kind = "wsserver"
        case "wssserver", "wss": kind = "wssserver"
        case "quicserver", "quic": kind = "quicserver"
        default: return nil
        }
        func hp(_ h: String, _ p: String) -> String { (h.contains(":") && !h.hasPrefix("[") ? "[\(h)]" : h) + ":" + p }
        var v: [String: String] = [:]
        let dial = hp(server, port)
        if kind == "server" {
            v[kind] = dial
        } else {
            let host = s("host")
            var urlHostPort = dial
            if !host.isEmpty {
                let (hn, hport) = NCBrookOptions.splitHostPort(host)
                urlHostPort = hp(hn, hport.map(String.init) ?? port)
                if urlHostPort != dial { v["address"] = dial }
            }
            var path = s("path")
            if kind == "quicserver" { path = "" }
            else if path.isEmpty { path = "/ws" }
            else if !path.hasPrefix("/") { path = "/" + path }
            let scheme = kind == "wsserver" ? "ws" : kind == "wssserver" ? "wss" : "quic"
            v[kind] = "\(scheme)://\(urlHostPort)\(path)"
        }
        v["password"] = s("password")
        if !name.isEmpty { v["name"] = name }
        if b("udp-over-tcp") && kind == "server" { v["udpovertcp"] = "true" }
        if b("udp-over-stream") && kind == "quicserver" { v["udpoverstream"] = "true" }
        if b("skip-cert-verify") && (kind == "wssserver" || kind == "quicserver") { v["insecure"] = "true" }
        if b("without-brook-protocol") && kind != "server" { v["withoutBrookProtocol"] = "true" }
        let copies = [("ca", "ca"), ("client-fingerprint", "tlsfingerprint"), ("client-hkdf-info", "clientHKDFInfo"),
                      ("server-hkdf-info", "serverHKDFInfo"), ("fragment", "fragment"), ("token", "token")]
        for (field, key) in copies where !s(field).isEmpty { v[key] = s(field) }
        let qs = v.keys.sorted().map { "\(queryEscape($0))=\(queryEscape(v[$0]!))" }.joined(separator: "&")
        return "brook://\(kind)?\(qs)"
    }
}
