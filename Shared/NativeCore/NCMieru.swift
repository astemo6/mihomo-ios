import CommonCrypto
import CryptoKit
import Foundation
import Network

// Mieru (feat/nc-proto3, based on astemo6/Muse NativeCore): pure-Swift client for the mieru v3 stream (TCP)
// and packet (UDP) underlays, ported from github.com/enfein/mieru/v3 v3.38.1 pkg/cipher + pkg/protocol
// and apis/client (socks5
// request inside the session, UDP via PacketOverStreamTunnel + UDPAssociateWrapper), as Clash.Meta v1.19.33
// adapter/outbound/mieru drives it. traffic-pattern (apis/trafficpattern) is decoded and applied.
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

    /// Key for the time slot `date` falls in (the old core time.Round(2m): nearest multiple, halfway up).
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

/// mieru `traffic-pattern` (clientcfg.pb TrafficPattern, protobuf → base64 in the mieru / Clash.Meta
/// config): nonce rewriting, padding caps and TCP fragmentation, with the implicit pattern
/// mieru generates for unset sub-messages. Only the explicitly
/// configured low-entropy codec is out of scope (protocols 10/11 — see NCSupport).
/// The pattern only shapes OUR OWN traffic; the server never sees it, so the implicit values
/// follow mieru's generation ranges without being bit-identical to its hash-based rng.
struct NCMieruTrafficPattern {
    struct Nonce {
        var type: Int = 0 // 0 random, 1 printable, 2 printable-subset, 3 fixed (custom hex)
        var applyToAllUDP: Bool = false
        var minLen: Int = 0
        var maxLen: Int = 0
        var customHex: [Data] = []
    }
    var tcpFragment: Bool = false
    var tcpFragmentMaxSleepMs: Int = 0
    var nonce = Nonce()
    var maxMiddlePadding: Int = 255
    var maxEndPadding: Int = 255
    /// Explicit lowEntropy mode from the config (0 = off); non-zero is unsupported.
    var lowEntropyMode: Int = 0

    /// Deterministic pick in [0, bound), keyed like mieru's rng.FixedInt seed strings.
    private static func fixedInt(_ bound: Int, _ key: String) -> Int {
        guard bound > 0 else { return 0 }
        let h = [UInt8](Data(SHA256.hash(data: Data(key.utf8))))
        var v: UInt64 = 0
        for i in 0..<8 { v = v << 8 | UInt64(h[i]) }
        return Int(v % UInt64(bound))
    }

    /// Decode + validate (mieru trafficpattern.Decode / Validate). nil = malformed.
    static func decode(_ base64: String) -> NCMieruTrafficPattern? {
        guard let raw = Data(base64Encoded: base64) else { return nil }
        var r = NCProtoReader(raw)
        var seed: Int32?
        var unlockAll = false
        var tcpMsg: [UInt8]?, nonceMsg: [UInt8]?, paddingMsg: [UInt8]?, lowEntropyMsg: [UInt8]?
        while let f = r.next() {
            switch (f.field, f.wire) {
            case (1, 0): seed = Int32(truncatingIfNeeded: f.value)
            case (2, 0): unlockAll = f.value != 0
            case (3, 2): tcpMsg = f.bytes
            case (4, 2): nonceMsg = f.bytes
            case (5, 2): paddingMsg = f.bytes
            case (6, 2): lowEntropyMsg = f.bytes
            default: break // unknown fields are skipped by the reader
            }
        }
        guard r.ok else { return nil }
        var p = NCMieruTrafficPattern()
        let sd = seed ?? Int32.random(in: 1...Int32.max)
        if let tcpMsg {
            var tr = NCProtoReader(Data(tcpMsg))
            while let f = tr.next() {
                if f.field == 1, f.wire == 0 { p.tcpFragment = f.value != 0 }
                if f.field == 2, f.wire == 0 { p.tcpFragmentMaxSleepMs = Int(f.value) }
            }
            guard tr.ok, p.tcpFragmentMaxSleepMs <= 100 else { return nil }
        } else if unlockAll {
            // mieru would derive a fragment pattern from the seed; fragmentation is a pure
            // obfuscation nicety, so an unlockAll config simply sends unfragmented.
            p.tcpFragment = false
        }
        if let nonceMsg {
            var nr = NCProtoReader(Data(nonceMsg))
            while let f = nr.next() {
                switch (f.field, f.wire) {
                case (1, 0): p.nonce.type = Int(f.value)
                case (2, 0): p.nonce.applyToAllUDP = f.value != 0
                case (3, 0): p.nonce.minLen = Int(f.value)
                case (4, 0): p.nonce.maxLen = Int(f.value)
                case (5, 2):
                    let s = String(decoding: f.bytes, as: UTF8.self)
                    guard let d = Self.hexDecode(s), d.count <= 12 else { return nil }
                    p.nonce.customHex.append(d)
                default: break
                }
            }
            guard nr.ok else { return nil }
            guard (0...3).contains(p.nonce.type), p.nonce.minLen <= 12, p.nonce.maxLen <= 12,
                  p.nonce.minLen <= p.nonce.maxLen else { return nil }
        } else {
            p.nonce.applyToAllUDP = fixedInt(2, "\(sd):nonce.applyToAllUDPPacket") == 1
            if !unlockAll {
                p.nonce.type = fixedInt(2, "\(sd):nonce.type") + 1
                p.nonce.minLen = fixedInt(7, "\(sd):nonce.minLen") + 6
                p.nonce.maxLen = p.nonce.minLen + fixedInt(13 - p.nonce.minLen, "\(sd):nonce.maxLen")
            }
        }
        if let paddingMsg {
            var pr = NCProtoReader(Data(paddingMsg))
            p.maxMiddlePadding = 0
            p.maxEndPadding = 0
            while let f = pr.next() {
                if f.field == 1, f.wire == 0 { p.maxMiddlePadding = Int(f.value) }
                if f.field == 2, f.wire == 0 { p.maxEndPadding = Int(f.value) }
            }
            guard pr.ok, p.maxMiddlePadding <= 255, p.maxEndPadding <= 255 else { return nil }
        } else if unlockAll {
            p.maxMiddlePadding = fixedInt(256, "\(sd):padding.maxMiddlePaddingLen")
            p.maxEndPadding = fixedInt(256, "\(sd):padding.maxEndPaddingLen")
        } else {
            p.maxMiddlePadding = max(0, fixedInt(256, "\(sd):padding.maxMiddlePaddingLen") - 128)
            p.maxEndPadding = 255
        }
        if let lowEntropyMsg {
            var lr = NCProtoReader(Data(lowEntropyMsg))
            while let f = lr.next() {
                if f.field == 1, f.wire == 0 { p.lowEntropyMode = Int(f.value) }
            }
            guard lr.ok, p.lowEntropyMode <= 4 else { return nil }
        }
        return p
    }

    private static func hexDecode(_ s: String) -> Data? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard t.count % 2 == 0 else { return nil }
        var out = Data()
        var i = t.startIndex
        while i < t.endIndex {
            let j = t.index(i, offsetBy: 2)
            guard let b = UInt8(t[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }

    /// NoncePattern rewrite (pkg/cipher nonce): printable / printable-subset map the first
    /// minLen...maxLen bytes; fixed copies a random custom hex string over the prefix.
    /// The printable-subset alphabet is mieru's ToCommon64Set (base64 alphabet).
    private static let common64 = [UInt8]("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    static func rewriteNonce(_ nonce: inout [UInt8], pattern: Nonce) {
        switch pattern.type {
        case 1, 2:
            guard pattern.maxLen > 0 else { return }
            let len = min(nonce.count, pattern.minLen >= pattern.maxLen
                ? pattern.minLen : Int.random(in: pattern.minLen...pattern.maxLen))
            for i in 0..<len {
                if pattern.type == 1 {
                    nonce[i] = 0x20 + nonce[i] % 95
                } else {
                    nonce[i] = common64[Int(nonce[i]) % 64]
                }
            }
        case 3:
            guard let pick = pattern.customHex.randomElement() else { return }
            for i in 0..<min(pick.count, nonce.count) { nonce[i] = pick[i] }
        default:
            break
        }
    }
}

/// Minimal protobuf wire reader for the traffic-pattern messages.
private struct NCProtoReader {
    private let buf: [UInt8]
    private var off = 0
    private(set) var ok = true

    init(_ data: Data) { buf = [UInt8](data) }

    private mutating func varint() -> UInt64? {
        var v: UInt64 = 0
        var shift: UInt64 = 0
        while off < buf.count, shift < 64 {
            let b = buf[off]
            off += 1
            v |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { return v }
            shift += 7
        }
        return nil
    }

    /// Next field, or nil at the end / on malformed input (`ok` flips false).
    mutating func next() -> (field: Int, wire: Int, value: UInt64, bytes: [UInt8])? {
        guard ok, off < buf.count else { return nil }
        guard let tag = varint() else { ok = false; return nil }
        let field = Int(tag >> 3), wire = Int(tag & 7)
        guard field > 0 else { ok = false; return nil }
        switch wire {
        case 0:
            guard let v = varint() else { ok = false; return nil }
            return (field, wire, v, [])
        case 2:
            guard let len = varint(), len <= UInt64(buf.count - off) else { ok = false; return nil }
            let bytes = Array(buf[off..<(off + Int(len))])
            off += Int(len)
            return (field, wire, 0, bytes)
        case 1:
            guard buf.count - off >= 8 else { ok = false; return nil }
            off += 8
            return (field, wire, 0, [])
        case 5:
            guard buf.count - off >= 4 else { ok = false; return nil }
            off += 4
            return (field, wire, 0, [])
        default:
            ok = false
            return nil
        }
    }
}

/// One direction of mieru's stateful (implicit-nonce) XChaCha20-Poly1305 block cipher.
final class NCMieruCipher {
    private let key: Data
    private let userName: String
    private let noncePattern: NCMieruTrafficPattern.Nonce?
    private var nonce: [UInt8]?

    init(key: Data, userName: String, noncePattern: NCMieruTrafficPattern.Nonce? = nil) {
        self.key = key
        self.userName = userName
        self.noncePattern = noncePattern
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
            // Traffic pattern rewrites the nonce first; the user hint is applied
            // afterwards and wins the last 4 bytes (cipher Encrypt order).
            if let noncePattern { NCMieruTrafficPattern.rewriteNonce(&n, pattern: noncePattern) }
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

/// mieru's stateless cipher for the packet underlay: every block carries a fresh explicit nonce,
/// and a segment's payload block reuses its metadata block's nonce (underlay_packet writeOneSegment).
final class NCMieruStatelessCipher {
    private let key: Data
    private let userName: String
    private let noncePattern: NCMieruTrafficPattern.Nonce?
    private var patternApplied = false

    init(key: Data, userName: String, noncePattern: NCMieruTrafficPattern.Nonce? = nil) {
        self.key = key
        self.userName = userName
        self.noncePattern = noncePattern
    }

    func newNonce() -> Data {
        var n = [UInt8]((0..<NCMieruCipher.nonceSize).map { _ in UInt8.random(in: 0...255) })
        if let noncePattern, !patternApplied || noncePattern.applyToAllUDP {
            NCMieruTrafficPattern.rewriteNonce(&n, pattern: noncePattern)
            patternApplied = true
        }
        if !userName.isEmpty {
            var input = Data(userName.utf8)
            input.append(contentsOf: n[0..<16])
            let h = [UInt8](Data(SHA256.hash(data: input)))
            for i in 0..<4 { n[NCMieruCipher.nonceSize - 4 + i] = h[i] }
        }
        return Data(n)
    }

    /// Seal with a fresh nonce; returns nonce ‖ ciphertext ‖ tag.
    func seal(_ plain: Data) -> Data {
        let nonce = newNonce()
        return nonce + seal(plain, nonce: nonce)
    }

    func seal(_ plain: Data, nonce: Data) -> Data {
        NCChaCha.xchachaSeal(key: key, nonce24: nonce, plain: plain) ?? Data()
    }

    /// Open a nonce ‖ ciphertext ‖ tag block.
    func open(_ block: Data) -> (nonce: Data, plain: Data)? {
        guard block.count >= NCMieruCipher.nonceSize + NCMieruCipher.overhead else { return nil }
        let nonce = Data(block.prefix(NCMieruCipher.nonceSize))
        guard let plain = open(Data(block.dropFirst(NCMieruCipher.nonceSize)), nonce: nonce) else { return nil }
        return (nonce, plain)
    }

    func open(_ sealed: Data, nonce: Data) -> Data? {
        NCChaCha.xchachaOpen(key: key, nonce24: nonce, sealed: sealed)
    }
}

/// Padding helpers shared by both underlays: rng.Intn with mieru's
/// scale-down distribution, and ASCII padding with a printable run.
private func ncmieruPaddingLen(max maxLen: Int, min minLen: Int = 0) -> Int {
    guard maxLen > minLen else { return minLen }
    let u = Double.random(in: 0..<1)
    return minLen + Int(Double(Int.random(in: 0...(maxLen - minLen))) * (u * u * u).squareRoot())
}

private func ncmieruPadding(max maxLen: Int, minASCII: Int) -> Data {
    let n = ncmieruPaddingLen(max: maxLen, min: minASCII)
    var p = [UInt8]((0..<n).map { _ in UInt8.random(in: 0...255) })
    if minASCII > 0, n >= minASCII {
        let begin = n > minASCII ? Int.random(in: 0..<(n - minASCII)) : 0
        for i in begin..<(begin + minASCII) { p[i] = UInt8(0x21 + Int(p[i]) % 94) }
    }
    return Data(p)
}

private func ncmieruBE32(_ v: UInt32, into b: inout [UInt8], at i: Int) {
    b[i] = UInt8(v >> 24); b[i + 1] = UInt8((v >> 16) & 0xff); b[i + 2] = UInt8((v >> 8) & 0xff); b[i + 3] = UInt8(v & 0xff)
}

private func ncmieruBE16(_ v: Int, into b: inout [UInt8], at i: Int) {
    b[i] = UInt8((v >> 8) & 0xff); b[i + 1] = UInt8(v & 0xff)
}

private func ncmieruMinutes() -> UInt32 { UInt32(Date().timeIntervalSince1970 / 60) }

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
    private let pattern: NCMieruTrafficPattern?
    private var fragQueue: DispatchQueue?
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

    init(raw: NCRelayStream, user: String, hashedPassword: Data, request: Data,
         pattern: NCMieruTrafficPattern? = nil) {
        self.raw = raw
        self.pattern = pattern
        let key = NCMieruCrypto.key(hashed: hashedPassword)
        sendCipher = NCMieruCipher(key: key, userName: user, noncePattern: pattern?.nonce)
        recvCipher = NCMieruCipher(key: key, userName: user)
        var sid: UInt32 = 0
        while sid == 0 { sid = UInt32.random(in: 1...UInt32.max) }
        sessionID = sid
        self.request = request
    }

    /// SOCKS5 request as mieru's model.Request.WriteToSocks5: VER CMD RSV ATYP ADDR PORT.
    static func socksRequest(target: NCTarget, udp: Bool) -> Data {
        let cmd: UInt8 = udp ? 0x03 : 0x01
        var d = Data([0x05, cmd, 0x00])
        d.append(target.atypEncoded)
        return d
    }

    /// handshake-mode HANDSHAKE_STANDARD (default): send the request in the open-session segment, wait for the
    /// reply, then hand the stream over. HANDSHAKE_NO_WAIT: return at once; the request rides the first write.
    func start(waitReply: Bool, queue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        fragQueue = queue
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
                if let err = err ?? self.failure { finished = true; timer.cancel(); completion(err); return }
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

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !closed else { once.call(); return }
        if !openSent { flushOpen(with: data, completion: once.call); return }
        sendData(data, completion: once.call)
    }

    /// The first write: openSessionRequest carrying (request ‖ data) when it fits 1024 bytes, else the request
    /// alone (or nothing) and the rest as data segments — Session.Write's rule.
    private func flushOpen(with data: Data, completion: @escaping () -> Void = {}) {
        openSent = true
        var first = request ?? Data()
        request = nil
        first.append(data)
        if first.count <= Self.maxSessionOpenPayload {
            writeSession(Self.openSessionRequest, payload: first, completion: completion)
        } else {
            writeSession(Self.openSessionRequest, payload: Data())
            sendData(first, completion: completion)
        }
    }

    private func sendData(_ data: Data) { sendData(data, completion: {}) }

    private func sendData(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(Self.maxPDU))
            rest = rest.dropFirst(chunk.count)
            if rest.isEmpty {
                writeData(chunk, completion: once.call)
            } else {
                writeData(chunk)
            }
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

    /// All stream-underlay writes go through here so a traffic-pattern TCP
    /// fragmentation (underlay_stream writeWithPossibleFragment) applies:
    /// each segment is split into chunks of random length in
    /// [sqrt(remaining)+1, max(that, remaining/2)] with a random sleep of
    /// 0...maxSleepMs between chunks.
    private func sendWire(_ data: Data, completion: @escaping () -> Void) {
        guard let pattern, pattern.tcpFragment, let fragQueue, data.count > 8 else {
            raw.send(data, completion: completion)
            return
        }
        let total = data.count
        var sent = 0
        func step() {
            if sent >= total { completion(); return }
            let remaining = total - sent
            let lo = Int(Double(remaining).squareRoot()) + 1
            let hi = max(lo, remaining / 2)
            let n = remaining <= hi ? remaining : Int.random(in: lo...hi)
            let chunk = Data(data[sent..<(sent + n)])
            sent += n
            self.raw.send(chunk) {
                if sent >= total {
                    completion()
                } else if pattern.tcpFragmentMaxSleepMs > 0 {
                    fragQueue.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0...pattern.tcpFragmentMaxSleepMs))) { step() }
                } else {
                    step()
                }
            }
        }
        step()
    }

    private func writeSession(_ proto: UInt8, payload: Data, status: UInt8 = 0, completion: @escaping () -> Void = {}) {
        // Recommended padding (session segments): 24–40 printable bytes within the
        // pattern's end-padding cap (255 without a pattern).
        let cap = pattern?.maxEndPadding ?? 255
        let pad = Self.padding(max: cap, minASCII: min(24 + Int.random(in: 0..<17), cap))
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
        sendWire(wire, completion: completion)
    }

    private func writeData(_ payload: Data, completion: @escaping () -> Void = {}) {
        // Pattern padding caps replace the flat 255 maxes (packetPadding in trafficpattern).
        let pad1 = Self.padding(max: pattern?.maxMiddlePadding ?? 255, minASCII: 0)
        let pad2 = Self.padding(max: pattern?.maxEndPadding ?? 255, minASCII: 0)
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
        sendWire(wire, completion: completion)
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
        let len: Int
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

/// One UDP datagram pipe to the mieru server (packet underlay transport).
final class NCMieruUDPConn {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private var cancelled = false

    init(host: String, port: Int, queue: DispatchQueue) {
        self.queue = queue
        conn = NWConnection(to: NCStream.endpoint(host, port: port),
                            using: NCOutboundBinding.params(.udp, host: host))
    }

    func start(ready: @escaping (Error?) -> Void) {
        var fired = false
        conn.stateUpdateHandler = { state in
            guard !fired else { return }
            switch state {
            case .ready:
                fired = true
                ready(nil)
            case .failed(let e):
                fired = true
                ready(e)
            case .cancelled:
                fired = true
                ready(NSError(domain: "NativeCore", code: 2, userInfo: [NSLocalizedDescriptionKey: "connection cancelled"]))
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    func send(_ data: Data) {
        guard !cancelled, !data.isEmpty else { return }
        conn.send(content: data, completion: .idempotent)
    }

    func receiveDatagram(_ handler: @escaping (Data?) -> Void) {
        conn.receiveMessage { data, _, _, _ in handler(data) }
    }

    func cancel() {
        cancelled = true
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}

/// A mieru session over the packet (UDP) underlay. Unlike the stream underlay, reliability
/// lives here: session + data segments share one sequence space,
/// unacknowledged segments retransmit with an RTO × 1.5^tx backoff, the peer's advertised
/// window bounds in-flight segments, ACKs (protocol 8) piggyback unAckSeq on every segment,
/// and an idle session heartbeats with ACKs — the server drops packet sessions after ~1 min
/// idle. Simplifications vs mieru (documented, wire-compatible): fixed 500 ms initial RTO
/// instead of an RTT estimator, no dup-ACK fast retransmit, datagrams capped at 1400 bytes.
final class NCMieruPacketStream: NCRelayStream {
    static let ackClientToServer: UInt8 = 8
    static let maxDatagramPayload = 1200
    static let maxDatagram = 1400
    static let maxRetransmit = 10

    private let conn: NCMieruUDPConn
    private let sendCipher: NCMieruStatelessCipher
    private let recvCipher: NCMieruStatelessCipher
    private let pattern: NCMieruTrafficPattern?
    private let queue: DispatchQueue
    private let sessionID: UInt32
    private var request: Data?
    private var openSent = false
    private var established = false
    private var awaitingReply = true
    private var replyBuf = Data()

    private var nextSend: UInt32 = 0
    private var nextRecv: UInt32 = 0
    private var remoteWindow = 16
    private var sendBuf: [UInt32: Pending] = [:]
    private var sendQueue: [(proto: UInt8, payload: Data, once: NCCallOnce?)] = []
    private var recvBuf: [UInt32: (proto: UInt8, payload: Data)] = [:]
    private var lastTxAt = Date()

    private var out: [Data] = []
    private var waiters: [(Data?, Error?) -> Void] = []
    private var failure: Error?
    private var eof = false
    private var closed = false
    private var started = false

    private struct Pending {
        var proto: UInt8
        var payload: Data
        var txCount: Int
        var lastTx: Date
    }

    init(server: String, port: Int, user: String, hashedPassword: Data, request: Data,
         pattern: NCMieruTrafficPattern?, queue: DispatchQueue) {
        self.queue = queue
        self.pattern = pattern
        conn = NCMieruUDPConn(host: server, port: port, queue: queue)
        let key = NCMieruCrypto.key(hashed: hashedPassword)
        sendCipher = NCMieruStatelessCipher(key: key, userName: user, noncePattern: pattern?.nonce)
        recvCipher = NCMieruStatelessCipher(key: key, userName: user)
        var sid: UInt32 = 0
        while sid == 0 { sid = UInt32.random(in: 1...UInt32.max) }
        sessionID = sid
        self.request = request
    }

    /// Same handshake modes as the stream underlay (see NCMieruStream.start).
    func start(waitReply: Bool, queue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        guard !started else { queue.async { completion(self.failure) }; return }
        started = true
        conn.start { [weak self] err in
            guard let self else { completion(err); return }
            if let err { completion(err); return }
            self.receiveLoop()
            self.scheduleTick()
            self.flushOpen(with: Data())
            guard waitReply else { completion(nil); return }
            var finished = false
            let timer = DispatchWorkItem { [weak self] in
                guard !finished else { return }
                finished = true
                self?.conn.cancel()
                completion(NCFramedRelay.err("mieru: no SOCKS5 reply within 10 s"))
            }
            queue.asyncAfter(deadline: .now() + 10, execute: timer)
            func pump() {
                guard !finished else { return }
                if let err = self.failure {
                    finished = true
                    timer.cancel()
                    completion(err)
                    return
                }
                if !self.awaitingReply {
                    finished = true
                    timer.cancel()
                    completion(nil)
                    return
                }
                if self.eof {
                    finished = true
                    timer.cancel()
                    completion(NCFramedRelay.err("mieru: closed before SOCKS5 reply"))
                    return
                }
                queue.asyncAfter(deadline: .now() + 0.01) { pump() }
            }
            pump()
        }
    }

    // MARK: send

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !closed, failure == nil else { once.call(); return }
        if !openSent { flushOpen(with: data, once: once); return }
        sendData(data, once: once)
    }

    private func flushOpen(with data: Data, once: NCCallOnce? = nil) {
        openSent = true
        var first = request ?? Data()
        request = nil
        first.append(data)
        if first.count <= NCMieruStream.maxSessionOpenPayload {
            enqueue(proto: NCMieruStream.openSessionRequest, payload: first, once: once)
        } else {
            enqueue(proto: NCMieruStream.openSessionRequest, payload: Data(), once: nil)
            sendData(first, once: once)
        }
    }

    private func sendData(_ data: Data, once: NCCallOnce? = nil) {
        guard !data.isEmpty else { once?.call(); return }
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(Self.maxDatagramPayload))
            rest = rest.dropFirst(chunk.count)
            // The send completion rides the last chunk only.
            enqueue(proto: NCMieruStream.dataClientToServer, payload: chunk, once: rest.isEmpty ? once : nil)
        }
    }

    /// Queue a reliable segment; its completion fires on first transmission.
    /// Segments beyond the peer's window wait in `sendQueue`.
    private func enqueue(proto: UInt8, payload: Data, once: NCCallOnce?) {
        if sendBuf.count >= remoteWindow {
            sendQueue.append((proto, payload, once))
            return
        }
        let seq = nextSend
        nextSend &+= 1
        sendBuf[seq] = Pending(proto: proto, payload: payload, txCount: 0, lastTx: Date())
        transmit(seq)
        once?.call()
    }

    private func pumpSendQueue() {
        while sendBuf.count < remoteWindow, !sendQueue.isEmpty {
            let next = sendQueue.removeFirst()
            let seq = nextSend
            nextSend &+= 1
            sendBuf[seq] = Pending(proto: next.proto, payload: next.payload, txCount: 0, lastTx: Date())
            transmit(seq)
            next.once?.call()
        }
    }

    private func transmit(_ seq: UInt32) {
        guard let seg = sendBuf[seq] else { return }
        conn.send(buildDatagram(proto: seg.proto, seq: seq, payload: seg.payload))
        lastTxAt = Date()
    }

    private func sendAck() {
        guard openSent, !closed, failure == nil else { return }
        var m = [UInt8](repeating: 0, count: NCMieruStream.metadataLength)
        m[0] = Self.ackClientToServer
        ncmieruBE32(ncmieruMinutes(), into: &m, at: 2)
        ncmieruBE32(sessionID, into: &m, at: 6)
        ncmieruBE32(nextSend == 0 ? 0 : nextSend - 1, into: &m, at: 10)
        ncmieruBE32(nextRecv, into: &m, at: 14)
        ncmieruBE16(advertisedWindow(), into: &m, at: 18)
        conn.send(sendCipher.seal(Data(m)))
        lastTxAt = Date()
    }

    private func advertisedWindow() -> Int {
        min(4096, max(16, 4096 - recvBuf.count))
    }

    /// Serialize one segment into a datagram: nonce ‖ seal(metadata) ‖ [prefix
    /// padding] ‖ seal(payload, same nonce) ‖ suffix padding. Session segments
    /// carry suffix padding only and the session metadata layout.
    private func buildDatagram(proto: UInt8, seq: UInt32, payload: Data) -> Data {
        let isSession = proto <= NCMieruStream.closeSessionResponse
        var m = [UInt8](repeating: 0, count: NCMieruStream.metadataLength)
        m[0] = proto
        ncmieruBE32(ncmieruMinutes(), into: &m, at: 2)
        ncmieruBE32(sessionID, into: &m, at: 6)
        ncmieruBE32(seq, into: &m, at: 10)
        let sealedPayloadLen = payload.isEmpty ? 0 : payload.count + NCMieruCipher.overhead
        let fixed = NCMieruCipher.nonceSize + NCMieruStream.metadataLength + NCMieruCipher.overhead + sealedPayloadLen
        let budget = max(0, Self.maxDatagram - fixed)
        var pad1 = Data()
        var pad2: Data
        if isSession {
            ncmieruBE16(payload.count, into: &m, at: 15)
            let cap = min(pattern?.maxEndPadding ?? 255, budget)
            pad2 = ncmieruPadding(max: cap, minASCII: min(24 + Int.random(in: 0..<17), cap))
            m[17] = UInt8(pad2.count)
        } else {
            ncmieruBE32(nextRecv, into: &m, at: 14) // unAckSeq
            ncmieruBE16(advertisedWindow(), into: &m, at: 18)
            let cap1 = min(pattern?.maxMiddlePadding ?? 255, budget)
            pad1 = ncmieruPadding(max: cap1, minASCII: 0)
            let cap2 = min(pattern?.maxEndPadding ?? 255, budget - pad1.count)
            pad2 = ncmieruPadding(max: cap2, minASCII: 0)
            m[21] = UInt8(pad1.count)
            ncmieruBE16(payload.count, into: &m, at: 22)
            m[24] = UInt8(pad2.count)
        }
        let head = sendCipher.seal(Data(m))
        var wire = head
        wire.append(pad1)
        if !payload.isEmpty {
            wire.append(sendCipher.seal(payload, nonce: Data(head.prefix(NCMieruCipher.nonceSize))))
        }
        wire.append(pad2)
        return wire
    }

    // MARK: timers

    private func scheduleTick() {
        queue.asyncAfter(deadline: .now() + 0.025) { [weak self] in
            guard let self, !self.closed else { return }
            self.tick()
            self.scheduleTick()
        }
    }

    private func tick() {
        guard failure == nil else { return }
        let now = Date()
        for seq in sendBuf.keys.sorted() {
            guard var seg = sendBuf[seq] else { continue }
            let timeout = min(10.0, 0.5 * pow(1.5, Double(seg.txCount)))
            guard now.timeIntervalSince(seg.lastTx) >= timeout else { continue }
            guard seg.txCount < Self.maxRetransmit else { failSession(); return }
            seg.txCount += 1
            seg.lastTx = now
            sendBuf[seq] = seg
            transmit(seq)
        }
        if established, now.timeIntervalSince(lastTxAt) >= 5 { sendAck() }
    }

    private func failSession() {
        guard failure == nil else { return }
        failure = NCFramedRelay.err("mieru: session retransmission limit reached")
        let pending = waiters
        waiters = []
        for w in pending { w(nil, failure) }
        conn.cancel()
    }

    // MARK: receive

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !out.isEmpty { handler(out.removeFirst(), nil); return }
        if let failure { handler(nil, failure); return }
        if eof { handler(nil, nil); return }
        waiters.append(handler)
    }

    private func serveWaiters() {
        while !waiters.isEmpty {
            if !out.isEmpty {
                let w = waiters.removeFirst()
                w(out.removeFirst(), nil)
            } else if let failure {
                let w = waiters.removeFirst()
                w(nil, failure)
            } else if eof {
                let w = waiters.removeFirst()
                w(nil, nil)
            } else {
                return
            }
        }
    }

    private func receiveLoop() {
        conn.receiveDatagram { [weak self] data in
            guard let self, !self.closed else { return }
            if let data { self.handleDatagram(data) }
            if !self.closed { self.receiveLoop() }
        }
    }

    private func handleDatagram(_ d: Data) {
        let headLen = NCMieruCipher.nonceSize + NCMieruStream.metadataLength + NCMieruCipher.overhead
        guard d.count >= headLen, let (nonce, metaData) = recvCipher.open(Data(d.prefix(headLen))) else { return }
        let m = [UInt8](metaData)
        guard m.count == NCMieruStream.metadataLength else { return }
        let sid = UInt32(m[6]) << 24 | UInt32(m[7]) << 16 | UInt32(m[8]) << 8 | UInt32(m[9])
        guard sid == sessionID else { return }
        let proto = m[0]
        let seq = UInt32(m[10]) << 24 | UInt32(m[11]) << 16 | UInt32(m[12]) << 8 | UInt32(m[13])
        let prefix: Int, payloadLen: Int, suffix: Int
        switch proto {
        case NCMieruStream.openSessionRequest...NCMieruStream.closeSessionResponse:
            prefix = 0
            payloadLen = Int(m[15]) << 8 | Int(m[16])
            suffix = Int(m[17])
        case NCMieruStream.dataClientToServer...NCMieruStream.ackServerToClient:
            prefix = Int(m[21])
            payloadLen = Int(m[22]) << 8 | Int(m[23])
            suffix = Int(m[24])
        default:
            return
        }
        let total = headLen + prefix + (payloadLen > 0 ? payloadLen + NCMieruCipher.overhead : 0) + suffix
        guard d.count >= total else { return }
        var payload = Data()
        if payloadLen > 0 {
            let sealed = Data(d[(headLen + prefix)..<(headLen + prefix + payloadLen + NCMieruCipher.overhead)])
            guard let p = recvCipher.open(sealed, nonce: nonce) else { return }
            payload = p
        }
        // ACK bookkeeping rides the data-layout segments (data / ack from the server).
        if proto == NCMieruStream.dataServerToClient || proto == NCMieruStream.ackServerToClient {
            let unAck = UInt32(m[14]) << 24 | UInt32(m[15]) << 16 | UInt32(m[16]) << 8 | UInt32(m[17])
            pruneSendBuf(unAck: unAck)
            let window = Int(m[18]) << 8 | Int(m[19])
            if window > 0 { remoteWindow = window }
            pumpSendQueue()
        }
        switch proto {
        case NCMieruStream.ackServerToClient:
            return // pure ACK
        case NCMieruStream.closeSessionRequest:
            enqueue(proto: NCMieruStream.closeSessionResponse, payload: Data(), once: nil)
            eof = true
            serveWaiters()
        case NCMieruStream.openSessionResponse, NCMieruStream.dataServerToClient, NCMieruStream.closeSessionResponse:
            if seq < nextRecv {
                sendAck() // duplicate: re-ACK and drop
                return
            }
            if seq == nextRecv {
                process(proto: proto, payload: payload)
                advanceRecv()
            } else if recvBuf.count < 512 {
                recvBuf[seq] = (proto, payload)
            }
            sendAck()
        default:
            return
        }
    }

    private func pruneSendBuf(unAck: UInt32) {
        for seq in Array(sendBuf.keys) where seq < unAck { sendBuf.removeValue(forKey: seq) }
    }

    private func process(proto: UInt8, payload: Data) {
        switch proto {
        case NCMieruStream.openSessionResponse:
            established = true
            for seq in Array(sendBuf.keys) where sendBuf[seq]?.proto == NCMieruStream.openSessionRequest {
                sendBuf.removeValue(forKey: seq)
            }
            if !payload.isEmpty { deliver(payload) }
        case NCMieruStream.dataServerToClient:
            if !payload.isEmpty { deliver(payload) }
        case NCMieruStream.closeSessionResponse:
            eof = true
            serveWaiters()
        default:
            break
        }
    }

    private func advanceRecv() {
        nextRecv &+= 1
        while let seg = recvBuf.removeValue(forKey: nextRecv) {
            process(proto: seg.proto, payload: seg.payload)
            nextRecv &+= 1
        }
    }

    /// Strip the SOCKS5 reply once, then pass the stream through (same as NCMieruStream.deliver).
    private func deliver(_ payload: Data) {
        guard awaitingReply else { out.append(payload); serveWaiters(); return }
        replyBuf.append(payload)
        let b = [UInt8](replyBuf)
        guard b.count >= 5 else { return }
        let len: Int
        switch b[3] {
        case 0x01: len = 4 + 4 + 2
        case 0x04: len = 4 + 16 + 2
        case 0x03: len = 4 + 1 + Int(b[4]) + 2
        default:
            failure = NCFramedRelay.err("mieru: bad SOCKS5 reply")
            serveWaiters()
            return
        }
        guard b.count >= len else { return }
        guard b[0] == 0x05, b[1] == 0x00 else {
            failure = NCFramedRelay.err("mieru: server returned SOCKS5 error \(b[1])")
            serveWaiters()
            return
        }
        awaitingReply = false
        if b.count > len { out.append(Data(b[len...])) }
        replyBuf = Data()
        serveWaiters()
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        if openSent, !eof {
            // Best-effort close, retransmitted briefly by the tick before teardown.
            enqueue(proto: NCMieruStream.closeSessionRequest, payload: Data(), once: nil)
            queue.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.conn.cancel() }
        } else {
            conn.cancel()
        }
        let pending = waiters
        waiters = []
        for w in pending { w(nil, nil) }
    }
}

// MARK: - Connector glue

extension NCConnector {
    /// Clash.Meta MieruOption: server, port | port-range, transport (TCP | UDP), username, password,
    /// multiplexing, handshake-mode, traffic-pattern (decoded + applied; see NCMieruTrafficPattern).
    static func mieruStream(proxy: NCProxy, target: NCTarget, udp: Bool, queue: DispatchQueue,
                            transport: NCRelayStream?, completion: @escaping (NCRelayStream?, Error?) -> Void) {
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
        var pattern: NCMieruTrafficPattern?
        if let tp = proxy.fields["traffic-pattern"]?.string, !tp.isEmpty {
            guard let decoded = NCMieruTrafficPattern.decode(tp) else {
                queue.async { completion(nil, Failure.unsupported("Mieru traffic-pattern 无效")) }
                return
            }
            pattern = decoded
        }
        if (proxy.fields["transport"]?.string ?? "").uppercased() == "UDP" {
            // Packet underlay dials UDP directly; a chained byte-stream transport cannot carry it.
            guard transport == nil else {
                queue.async { completion(nil, Failure.unsupported("mieru UDP underlay 不支持链式 transport")) }
                return
            }
            let s = NCMieruPacketStream(server: server, port: port, user: user, hashedPassword: hashed,
                                        request: NCMieruStream.socksRequest(target: target, udp: udp),
                                        pattern: pattern, queue: queue)
            s.start(waitReply: !noWait, queue: queue) { err in
                if let err { s.cancel(); completion(nil, err) } else { completion(s, nil) }
            }
            return
        }
        obtainMieruRaw(transport: transport, server: server, port: port, queue: queue) { raw, err in
            guard let raw else { completion(nil, err); return }
            let s = NCMieruStream(raw: raw, user: user, hashedPassword: hashed,
                                  request: NCMieruStream.socksRequest(target: target, udp: udp),
                                  pattern: pattern)
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
