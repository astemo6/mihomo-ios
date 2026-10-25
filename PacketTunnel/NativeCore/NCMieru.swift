import CommonCrypto
import CryptoKit
import Foundation

// Mieru (feat/nc-proto3, based on astemo6/Muse NativeCore): pure-Swift client for the mieru v3 stream underlay
// (transport: TCP), ported from github.com/enfein/mieru/v3 v3.38.1 pkg/cipher + pkg/protocol (session.go,
// underlay_stream.go, metadata.go, padding.go) and apis/client (socks5 request inside the session, UDP via
// PacketOverStreamTunnel + UDPAssociateWrapper), as mihomo v1.19.33 adapter/outbound/mieru.go drives it.
//
// Wire (one TCP connection = one underlay; this client opens one session per underlay, i.e. multiplexing off —
// the server accepts any number of sessions per underlay, so this interoperates with every multiplexing level):
//   key   = PBKDF2-SHA256(SHA256(password ‖ 0x00 ‖ username), SHA256(BE64(unix time rounded to 2 min)), 64, 32)
//   AEAD  = XChaCha20-Poly1305, implicit nonce: the first sealed block carries the 24-byte nonce (last 4 bytes =
//           SHA256(username ‖ nonce[:16])[:4], the server's user hint); every later block increments it (BE).
//   segment = seal(32-byte metadata) ‖ [prefix padding] ‖ seal(payload) ‖ suffix padding
// Stream transport has no ACK / retransmission (TCP carries it), so the client is a small framing state machine.
// Memory: one receive buffer (≤ one segment, 32 KB payload max) + the per-direction cipher state.

enum NCMieruCrypto {
    static let keyRefreshInterval: Double = 120

    /// cipher.HashPassword(password, username).
    static func hashedPassword(password: String, user: String) -> Data {
        var p = Data(password.utf8)
        p.append(0)
        p.append(Data(user.utf8))
        return Data(SHA256.hash(data: p))
    }

    /// Key for the time slot `date` falls in (Go time.Round(2m): nearest multiple, halfway up).
    static func key(hashed: Data, date: Date = Date()) -> Data {
        let t = date.timeIntervalSince1970
        let rounded = UInt64(max(0, (floor((t + keyRefreshInterval / 2) / keyRefreshInterval) * keyRefreshInterval)))
        var be = Data(count: 8)
        for i in 0..<8 { be[i] = UInt8((rounded >> (56 - 8 * UInt64(i))) & 0xff) }
        let salt = Data(SHA256.hash(data: be))
        var out = [UInt8](repeating: 0, count: 32)
        _ = hashed.withUnsafeBytes { (pw: UnsafeRawBufferPointer) -> Int32 in
            salt.withUnsafeBytes { (sp: UnsafeRawBufferPointer) -> Int32 in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                     pw.baseAddress!.assumingMemoryBound(to: Int8.self), pw.count,
                                     sp.baseAddress!.assumingMemoryBound(to: UInt8.self), sp.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 64, &out, 32)
            }
        }
        return Data(out)
    }
}

/// One direction of mieru's stateful (implicit-nonce) XChaCha20-Poly1305 block cipher.
final class NCMieruCipher {
    private let key: Data
    private let userName: String
    private var nonce: [UInt8]?

    init(key: Data, userName: String) {
        self.key = key
        self.userName = userName
    }

    static let nonceSize = 24
    static let overhead = 16

    var hasNonce: Bool { nonce != nil }

    private func increment() {
        guard var n = nonce else { return }
        var i = n.count - 1
        while i >= 0 {
            n[i] &+= 1
            if n[i] != 0 { break }
            i -= 1
        }
        nonce = n
    }

    /// Encrypt; the first call returns nonce ‖ ciphertext ‖ tag.
    func seal(_ plain: Data) -> Data {
        var prefix = Data()
        if nonce == nil {
            var n = [UInt8]((0..<Self.nonceSize).map { _ in UInt8.random(in: 0...255) })
            if !userName.isEmpty {
                var input = Data(userName.utf8)
                input.append(contentsOf: n[0..<16])
                let h = [UInt8](Data(SHA256.hash(data: input)))
                for i in 0..<4 { n[Self.nonceSize - 4 + i] = h[i] }
            }
            nonce = n
            prefix = Data(n)
        } else {
            increment()
        }
        let sealed = NCChaCha.xchachaSeal(key: key, nonce24: Data(nonce!), plain: plain) ?? Data()
        return prefix + sealed
    }

    /// Decrypt one block (the first one starts with the 24-byte nonce).
    func open(_ block: Data) -> Data? {
        var body = block
        if nonce == nil {
            guard block.count >= Self.nonceSize + Self.overhead else { return nil }
            nonce = [UInt8](block.prefix(Self.nonceSize))
            body = Data(block.dropFirst(Self.nonceSize))
        } else {
            increment()
        }
        return NCChaCha.xchachaOpen(key: key, nonce24: Data(nonce!), sealed: body)
    }
}

/// A mieru session over one stream underlay, after the in-session SOCKS5 request (CONNECT or UDP ASSOCIATE).
final class NCMieruStream: NCRelayStream {
    // protocolType
    static let openSessionRequest: UInt8 = 2
    static let openSessionResponse: UInt8 = 3
    static let closeSessionRequest: UInt8 = 4
    static let closeSessionResponse: UInt8 = 5
    static let dataClientToServer: UInt8 = 6
    static let dataServerToClient: UInt8 = 7
    static let ackServerToClient: UInt8 = 9
    static let maxPDU = 32 * 1024
    static let maxSessionOpenPayload = 1024
    static let metadataLength = 32

    private let raw: NCRelayStream
    private let sendCipher: NCMieruCipher
    private let recvCipher: NCMieruCipher
    private let sessionID: UInt32
    private var nextSend: UInt32 = 0
    private var request: Data?          // pending SOCKS5 request (handshake-mode no-wait: rides the first send)
    private var awaitingReply = true    // the server's SOCKS5 reply is still to be stripped from the stream
    private var replyBuf = Data()
    private var openSent = false

    // receive state
    private var inbuf = [UInt8]()
    private var inOff = 0
    private var pendingMeta: (proto: UInt8, sid: UInt32, prefix: Int, payload: Int, suffix: Int)?
    private var out: [Data] = []
    private var failure: Error?
    private var eof = false
    private var closed = false

    init(raw: NCRelayStream, user: String, hashedPassword: Data, request: Data) {
        self.raw = raw
        let key = NCMieruCrypto.key(hashed: hashedPassword)
        sendCipher = NCMieruCipher(key: key, userName: user)
        recvCipher = NCMieruCipher(key: key, userName: user)
        var sid: UInt32 = 0
        while sid == 0 { sid = UInt32.random(in: 1...UInt32.max) }
        sessionID = sid
        self.request = request
    }

    /// SOCKS5 request as mieru's model.Request.WriteToSocks5: VER CMD RSV ATYP ADDR PORT.
    static func socksRequest(target: NCTarget, udp: Bool) -> Data {
        var d = Data([0x05, udp ? 0x03 : 0x01, 0x00])
        d.append(target.atypEncoded)
        return d
    }

    /// handshake-mode HANDSHAKE_STANDARD (default): send the request in the open-session segment, wait for the
    /// reply, then hand the stream over. HANDSHAKE_NO_WAIT: return at once; the request rides the first write.
    func start(waitReply: Bool, queue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        guard waitReply else { queue.async { completion(nil) }; return }
        flushOpen(with: Data())
        var finished = false
        let timer = DispatchWorkItem { [weak self] in
            guard !finished else { return }
            finished = true
            self?.raw.cancel()
            completion(NCFramedRelay.err("mieru: no SOCKS5 reply within 10 s"))
        }
        queue.asyncAfter(deadline: .now() + 10, execute: timer)
        func pump() {
            pull { [weak self] err in
                guard let self, !finished else { return }
                if let err { finished = true; timer.cancel(); completion(err); return }
                if self.awaitingReply {
                    if self.eof { finished = true; timer.cancel(); completion(NCFramedRelay.err("mieru: closed before SOCKS5 reply")); return }
                    pump()
                } else {
                    finished = true
                    timer.cancel()
                    completion(nil)
                }
            }
        }
        pump()
    }

    // MARK: send

    func send(_ data: Data) {
        guard !closed else { return }
        if !openSent { flushOpen(with: data); return }
        sendData(data)
    }

    /// The first write: openSessionRequest carrying (request ‖ data) when it fits 1024 bytes, else the request
    /// alone (or nothing) and the rest as data segments — Session.Write's rule.
    private func flushOpen(with data: Data) {
        openSent = true
        var first = request ?? Data()
        request = nil
        first.append(data)
        if first.count <= Self.maxSessionOpenPayload {
            writeSession(Self.openSessionRequest, payload: first)
        } else {
            writeSession(Self.openSessionRequest, payload: Data())
            sendData(first)
        }
    }

    private func sendData(_ data: Data) {
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(Self.maxPDU))
            rest = rest.dropFirst(chunk.count)
            writeData(chunk)
        }
    }

    private static func be32(_ v: UInt32, into b: inout [UInt8], at i: Int) {
        b[i] = UInt8(v >> 24); b[i + 1] = UInt8((v >> 16) & 0xff); b[i + 2] = UInt8((v >> 8) & 0xff); b[i + 3] = UInt8(v & 0xff)
    }

    private static func be16(_ v: Int, into b: inout [UInt8], at i: Int) {
        b[i] = UInt8((v >> 8) & 0xff); b[i + 1] = UInt8(v & 0xff)
    }

    private static func minutes() -> UInt32 { UInt32(Date().timeIntervalSince1970 / 60) }

    /// rng.Intn(maxLen) with mieru's scale-down distribution.
    private static func paddingLen(max maxLen: Int, min minLen: Int = 0) -> Int {
        guard maxLen > minLen else { return minLen }
        let u = Double.random(in: 0..<1)
        return minLen + Int(Double(Int.random(in: 0...(maxLen - minLen))) * (u * u * u).squareRoot())
    }

    /// ASCII padding: random bytes with a printable run (asciiPaddingOpts).
    private static func padding(max maxLen: Int, minASCII: Int) -> Data {
        let n = paddingLen(max: maxLen, min: minASCII)
        var p = [UInt8]((0..<n).map { _ in UInt8.random(in: 0...255) })
        if minASCII > 0, n >= minASCII {
            let begin = n > minASCII ? Int.random(in: 0..<(n - minASCII)) : 0
            for i in begin..<(begin + minASCII) { p[i] = UInt8(0x21 + Int(p[i]) % 94) }
        }
        return Data(p)
    }

    private func writeSession(_ proto: UInt8, payload: Data, status: UInt8 = 0) {
        // Recommended padding (session segments): 24–40 printable bytes within ≤ 255.
        let pad = Self.padding(max: 255, minASCII: 24 + Int.random(in: 0..<17))
        var m = [UInt8](repeating: 0, count: Self.metadataLength)
        m[0] = proto
        Self.be32(Self.minutes(), into: &m, at: 2)
        Self.be32(sessionID, into: &m, at: 6)
        Self.be32(nextSend, into: &m, at: 10)
        nextSend &+= 1
        m[14] = status
        Self.be16(payload.count, into: &m, at: 15)
        m[17] = UInt8(pad.count)
        var wire = sendCipher.seal(Data(m))
        if !payload.isEmpty { wire.append(sendCipher.seal(payload)) }
        wire.append(pad)
        raw.send(wire)
    }

    private func writeData(_ payload: Data) {
        let pad1 = Self.padding(max: 255, minASCII: 0)
        let pad2 = Self.padding(max: 255, minASCII: 0) // stream: maxPaddingSize is 255 for both
        var m = [UInt8](repeating: 0, count: Self.metadataLength)
        m[0] = Self.dataClientToServer
        Self.be32(Self.minutes(), into: &m, at: 2)
        Self.be32(sessionID, into: &m, at: 6)
        Self.be32(nextSend, into: &m, at: 10)
        nextSend &+= 1
        Self.be32(0, into: &m, at: 14)           // unAckSeq (stream: unused)
        Self.be16(4096, into: &m, at: 18)        // windowSize = segmentTreeCapacity
        m[20] = 0                                 // fragment: one chunk ≤ maxPDU = one fragment
        m[21] = UInt8(pad1.count)
        Self.be16(payload.count, into: &m, at: 22)
        m[24] = UInt8(pad2.count)
        var wire = sendCipher.seal(Data(m))
        wire.append(pad1)
        wire.append(sendCipher.seal(payload))
        wire.append(pad2)
        raw.send(wire)
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        if openSent { writeSession(Self.closeSessionRequest, payload: Data()) }
        raw.cancel()
    }

    // MARK: receive

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !out.isEmpty { handler(out.removeFirst(), nil); return }
        if let failure { handler(nil, failure); return }
        if eof { handler(nil, nil); return }
        pull { [weak self] err in
            guard let self else { handler(nil, err); return }
            if let err { handler(nil, err); return }
            self.receive(handler)
        }
    }

    /// One raw read, parsed into `out` / state. Calls back once.
    private func pull(_ done: @escaping (Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { done(error); return }
            guard let data else {
                self.eof = true
                if self.out.isEmpty, let error { done(error) } else { done(nil) }
                return
            }
            if self.inOff > 0 && self.inOff >= self.inbuf.count / 2 {
                self.inbuf.removeFirst(self.inOff)
                self.inOff = 0
            }
            self.inbuf.append(contentsOf: data)
            do {
                try self.parse()
                done(nil)
            } catch {
                self.failure = error
                self.raw.cancel()
                done(error)
            }
        }
    }

    private var available: Int { inbuf.count - inOff }

    private func take(_ n: Int) -> Data {
        let d = Data(inbuf[inOff..<(inOff + n)])
        inOff += n
        return d
    }

    private func parse() throws {
        while true {
            if pendingMeta == nil {
                let need = Self.metadataLength + NCMieruCipher.overhead + (recvCipher.hasNonce ? 0 : NCMieruCipher.nonceSize)
                guard available >= need else { return }
                guard let m = recvCipher.open(take(need)).map({ [UInt8]($0) }), m.count == Self.metadataLength else {
                    throw NCFramedRelay.err("mieru: metadata decryption failed (wrong user / password or clock skew)")
                }
                let sid = UInt32(m[6]) << 24 | UInt32(m[7]) << 16 | UInt32(m[8]) << 8 | UInt32(m[9])
                switch m[0] {
                case Self.openSessionRequest...Self.closeSessionResponse:
                    pendingMeta = (m[0], sid, 0, Int(m[15]) << 8 | Int(m[16]), Int(m[17]))
                case Self.dataClientToServer...Self.ackServerToClient:
                    pendingMeta = (m[0], sid, Int(m[21]), Int(m[22]) << 8 | Int(m[23]), Int(m[24]))
                default:
                    throw NCFramedRelay.err("mieru: unexpected protocol \(m[0])")
                }
            }
            guard let meta = pendingMeta else { return }
            let payloadWire = meta.payload > 0 ? meta.payload + NCMieruCipher.overhead : 0
            guard available >= meta.prefix + payloadWire + meta.suffix else { return }
            inOff += meta.prefix
            var payload = Data()
            if payloadWire > 0 {
                guard let p = recvCipher.open(take(payloadWire)) else {
                    throw NCFramedRelay.err("mieru: payload decryption failed")
                }
                payload = p
            }
            inOff += meta.suffix
            pendingMeta = nil
            guard meta.sid == sessionID else { continue }
            switch meta.proto {
            case Self.openSessionResponse, Self.dataServerToClient:
                if !payload.isEmpty { deliver(payload) }
            case Self.closeSessionRequest:
                if !closed { writeSession(Self.closeSessionResponse, payload: Data()) }
                eof = true
                return
            case Self.closeSessionResponse:
                eof = true
                return
            default:
                break // acks: stream transport ignores them
            }
        }
    }

    /// Strip the SOCKS5 reply (VER REP RSV ATYP ADDR PORT) once, then pass the stream through.
    private func deliver(_ payload: Data) {
        guard awaitingReply else { out.append(payload); return }
        replyBuf.append(payload)
        let b = [UInt8](replyBuf)
        guard b.count >= 5 else { return }
        var len: Int
        switch b[3] {
        case 0x01: len = 4 + 4 + 2
        case 0x04: len = 4 + 16 + 2
        case 0x03: len = 4 + 1 + Int(b[4]) + 2
        default:
            failure = NCFramedRelay.err("mieru: bad SOCKS5 reply")
            return
        }
        guard b.count >= len else { return }
        guard b[0] == 0x05, b[1] == 0x00 else {
            failure = NCFramedRelay.err("mieru: server returned SOCKS5 error \(b[1])")
            return
        }
        awaitingReply = false
        if b.count > len { out.append(Data(b[len...])) }
        replyBuf = Data()
    }
}

// MARK: - Connector glue

extension NCConnector {
    /// mihomo MieruOption: server, port | port-range, transport (TCP | UDP), username, password, multiplexing,
    /// handshake-mode, traffic-pattern. TCP transport only (see NCSupport.mieruUnsupported).
    static func mieruStream(proxy: NCProxy, target: NCTarget, udp: Bool, queue: DispatchQueue,
                            transport: NCRelayStream?, completion: @escaping (NCMieruStream?, Error?) -> Void) {
        if let why = NCSupport.mieruUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported(why)) }
            return
        }
        guard let server = proxy.server, let port = mieruPort(proxy) else {
            queue.async { completion(nil, Failure.handshake("mieru \(proxy.name) missing server/port")) }
            return
        }
        let user = proxy.fields["username"]?.string ?? ""
        let hashed = NCMieruCrypto.hashedPassword(password: proxy.password ?? "", user: user)
        let noWait = (proxy.fields["handshake-mode"]?.string ?? "") == "HANDSHAKE_NO_WAIT"
        obtainMieruRaw(transport: transport, server: server, port: port, queue: queue) { raw, err in
            guard let raw else { completion(nil, err); return }
            let s = NCMieruStream(raw: raw, user: user, hashedPassword: hashed,
                                  request: NCMieruStream.socksRequest(target: target, udp: udp))
            s.start(waitReply: !noWait, queue: queue) { err in
                if let err { s.cancel(); completion(nil, err) } else { completion(s, nil) }
            }
        }
    }

    private static func obtainMieruRaw(transport: NCRelayStream?, server: String, port: Int, queue: DispatchQueue,
                                       completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let transport { completion(transport, nil); return }
        let s = NCStream(to: server, port: port, queue: queue)
        s.start { err in completion(err == nil ? s : nil, err) }
    }

    /// `port`, or a random port of `port-range` ("begin-end"), as mieru's client picks one per underlay.
    static func mieruPort(_ proxy: NCProxy) -> Int? {
        if let p = proxy.port, p > 0 { return p }
        guard let range = proxy.fields["port-range"]?.string else { return nil }
        let parts = range.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        guard parts.count == 2, parts[0] >= 1, parts[0] <= parts[1], parts[1] <= 65535 else { return nil }
        return Int.random(in: parts[0]...parts[1])
    }
}

/// UDP over a mieru session (mihomo: UDP ASSOCIATE session → PacketOverStreamTunnel → UDPAssociateWrapper):
/// each datagram = 0x00 ‖ len(2) ‖ [00 00 00 ‖ ATYP ADDR PORT ‖ payload] ‖ 0xFF.
final class NCUDPMieruSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCMieruStream?
    private var pending: [(Data, NCTarget)] = []
    private var buffer = [UInt8]()
    private var cancelled = false

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        NCConnector.mieruStream(proxy: proxy, target: target, udp: true, queue: queue, transport: nil) { [weak self] s, _ in
            guard let self else { s?.cancel(); return }
            guard let s, !self.cancelled else { s?.cancel(); return }
            self.stream = s
            for (d, t) in self.pending { self.sendNow(d, to: t) }
            self.pending = []
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        stream?.receive { [weak self] data, _ in
            guard let self, !self.cancelled, let data else { return }
            self.buffer.append(contentsOf: data)
            self.parse()
            self.receiveLoop()
        }
    }

    private func parse() {
        var off = 0
        while buffer.count - off >= 4 {
            guard buffer[off] == 0x00 else { cancel(); return }
            let len = Int(buffer[off + 1]) << 8 | Int(buffer[off + 2])
            guard buffer.count - off >= 3 + len + 1 else { break }
            guard buffer[off + 3 + len] == 0xff else { cancel(); return }
            let pkt = Array(buffer[(off + 3)..<(off + 3 + len)])
            off += 4 + len
            // UDP associate header: RSV RSV FRAG ATYP ADDR PORT (IP only from the server).
            guard pkt.count > 6, pkt[0] == 0, pkt[1] == 0, pkt[2] == 0 else { continue }
            var h: Int
            switch pkt[3] {
            case 0x01: h = 4 + 4 + 2
            case 0x04: h = 4 + 16 + 2
            default: continue
            }
            guard pkt.count >= h else { continue }
            onReply(Data(pkt[h...]))
        }
        if off > 0 { buffer.removeFirst(off) }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if stream == nil { if pending.count < 32 { pending.append((data, target)) }; return }
        sendNow(data, to: target)
    }

    private func sendNow(_ data: Data, to target: NCTarget) {
        var inner = Data([0, 0, 0])
        inner.append(target.atypEncoded)
        inner.append(data)
        guard inner.count <= 65535 else { return }
        var frame = Data([0x00, UInt8(inner.count >> 8), UInt8(inner.count & 0xff)])
        frame.append(inner)
        frame.append(0xff)
        stream?.send(frame)
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        stream?.cancel()
        stream = nil
        pending = []
    }
}
