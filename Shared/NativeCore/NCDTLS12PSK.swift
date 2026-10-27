import Foundation
import CryptoKit

// fix/nc-oc-dtls: a minimal DTLS 1.2 PSK client (RFC 6347 + RFC 4279 + RFC 5487 / RFC 7905) for the OpenConnect
// "PSK-NEGOTIATE" data channel (ocserv ≥ 0.11, openconnect ≥ 7.08):
//
//   • the PSK is the 32-byte TLS exporter "EXPORTER-openconnect-psk" (no context) of the CSTP TLS session,
//   • PSK identity "psk",
//   • the ClientHello session_id is X-DTLS-App-ID (hex) — ocserv's main process routes the UDP flow to the
//     user's worker by it. Network.framework cannot set that session id, hence this pure-Swift client.
//
// Scope (memory first, no general-purpose TLS): full handshake only (no resumption / renegotiation), cipher suites
// TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00A8), TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00A9) and
// TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAB); HelloVerifyRequest cookies; reassembly of fragmented handshake
// messages; flight retransmission is driven by the owner (`retransmit()`); a 64-record anti-replay window.
// The object is a pure state machine (datagrams in / out), so the owner picks the socket and the queue.

final class NCDTLS12PSK {
    enum State: Equatable { case idle, handshaking, established, failed(String) }

    static let identity = Data("psk".utf8)
    static let exporterLabel = "EXPORTER-openconnect-psk"
    static let suiteAES128 = UInt16(0x00A8), suiteAES256 = UInt16(0x00A9), suiteChaCha = UInt16(0xCCAB)

    private(set) var state: State = .idle
    private(set) var suite: UInt16 = 0
    private let psk: Data
    private let sessionID: Data
    private var clientRandom = Data()
    private var serverRandom = Data()
    private var cookie = Data()
    private var transcript = Data()
    private var master = Data()
    private var lastFlight: [Data] = []
    private var sendSeq: UInt64 = 0         // per-epoch record sequence (48 bits)
    private var sendEpoch: UInt16 = 0
    private var msgSeq: UInt16 = 0          // next handshake message_seq to send
    private var recvMsgSeq: UInt16 = 0      // next handshake message_seq expected
    private var frag: [UInt16: (type: UInt8, total: Int, buf: Data, have: IndexSet)] = [:]
    private var serverCCS = false
    private var gotServerHelloDone = false
    private var writeKey: SymmetricKey?
    private var readKey: SymmetricKey?
    private var writeIV = Data()
    private var readIV = Data()
    private var replayTop: UInt64 = 0
    private var replayBits: UInt64 = 0
    private var replayAny = false

    /// - psk: 32-byte exporter; sessionID: X-DTLS-App-ID bytes (≤ 32).
    init(psk: Data, sessionID: Data) {
        self.psk = psk
        self.sessionID = sessionID.prefix(32)
    }

    static func hexBytes(_ s: String) -> Data? {
        let h = s.trimmingCharacters(in: .whitespaces)
        guard h.count % 2 == 0, h.count <= 64, !h.isEmpty else { return nil }
        var out = Data(capacity: h.count / 2)
        var i = h.startIndex
        while i < h.endIndex {
            let j = h.index(i, offsetBy: 2)
            guard let b = UInt8(h[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }

    // MARK: Handshake

    /// The first flight (ClientHello). Returns datagrams to send.
    func start() -> [Data] {
        state = .handshaking
        var r = Data(count: 32)
        r.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        clientRandom = r
        return sendClientHello()
    }

    private func sendClientHello() -> [Data] {
        var b = Data()
        b.append(contentsOf: [0xFE, 0xFD])
        b.append(clientRandom)
        b.append(UInt8(sessionID.count)); b.append(sessionID)
        b.append(UInt8(cookie.count)); b.append(cookie)
        let suites: [UInt16] = [Self.suiteAES128, Self.suiteAES256, Self.suiteChaCha]
        b.append(u16(suites.count * 2)); for s in suites { b.append(u16(Int(s))) }
        b.append(contentsOf: [0x01, 0x00]) // compression: null
        // extensions: renegotiation_info (empty) — safe renegotiation signalling, nothing else.
        let ext = Data([0xff, 0x01, 0x00, 0x01, 0x00])
        b.append(u16(ext.count)); b.append(ext)
        let msg = handshake(1, b)
        // RFC 6347 §4.2.1: the handshake hash covers only the ClientHello that is answered without a cookie
        // exchange, i.e. the last one sent.
        transcript = msg
        lastFlight = [record(22, msg)]
        return lastFlight
    }

    /// The last flight again (owner's retransmission timer while handshaking).
    func retransmit() -> [Data] {
        guard state == .handshaking else { return [] }
        return lastFlight
    }

    /// Feeds one datagram. Returns (datagrams to send, decrypted application payloads).
    func receive(_ datagram: Data) -> (out: [Data], app: [Data]) {
        var out: [Data] = []
        var app: [Data] = []
        var off = datagram.startIndex
        while datagram.endIndex - off >= 13 {
            let type = datagram[off]
            let epoch = UInt16(datagram[off + 3]) << 8 | UInt16(datagram[off + 4])
            var seq: UInt64 = 0
            for i in 5..<11 { seq = seq << 8 | UInt64(datagram[off + i]) }
            let len = Int(datagram[off + 11]) << 8 | Int(datagram[off + 12])
            let start = off + 13
            guard datagram.endIndex - start >= len else { break }
            let body = datagram.subdata(in: start..<(start + len))
            off = start + len
            var plain = body
            if epoch == 1 {
                guard let rk = readKey, let p = open(type: type, epoch: epoch, seq: seq, body, key: rk) else { continue }
                if state == .established {
                    guard replayOK(seq) else { continue }
                }
                plain = p
            } else if epoch != 0 {
                continue
            }
            switch type {
            case 22: // handshake
                out += handleHandshakeRecord(plain, encrypted: epoch == 1)
            case 20: // change_cipher_spec
                if epoch == 0, state == .handshaking { serverCCS = true }
            case 21: // alert
                if plain.count >= 2, plain[plain.startIndex] == 2 {
                    state = .failed("DTLS alert \(plain[plain.startIndex + 1])")
                } else if plain.count >= 2, plain[plain.startIndex + 1] == 0 {
                    state = .failed("DTLS close_notify")
                }
            case 23: // application_data
                if state == .established, epoch == 1 { app.append(plain) }
            default:
                break
            }
            if case .failed = state { return (out, app) }
        }
        return (out, app)
    }

    private func handleHandshakeRecord(_ p: Data, encrypted: Bool) -> [Data] {
        var out: [Data] = []
        var off = p.startIndex
        while p.endIndex - off >= 12 {
            let t = p[off]
            let total = Int(p[off + 1]) << 16 | Int(p[off + 2]) << 8 | Int(p[off + 3])
            let mseq = UInt16(p[off + 4]) << 8 | UInt16(p[off + 5])
            let foff = Int(p[off + 6]) << 16 | Int(p[off + 7]) << 8 | Int(p[off + 8])
            let flen = Int(p[off + 9]) << 16 | Int(p[off + 10]) << 8 | Int(p[off + 11])
            let s = off + 12
            guard p.endIndex - s >= flen, foff + flen <= total, total <= 16384 else { return out }
            let chunk = p.subdata(in: s..<(s + flen))
            off = s + flen
            guard mseq >= recvMsgSeq else { continue } // a retransmitted, already-processed message
            var entry = frag[mseq] ?? (t, total, Data(count: total), IndexSet())
            if entry.total != total { continue }
            entry.buf.replaceSubrange(foff..<(foff + flen), with: chunk)
            entry.have.insert(integersIn: foff..<(foff + flen))
            frag[mseq] = entry
            // Process complete messages in order.
            while let e = frag[recvMsgSeq], e.have.count == e.total || e.total == 0 {
                frag.removeValue(forKey: recvMsgSeq)
                let seqNo = recvMsgSeq
                recvMsgSeq &+= 1
                out += handleMessage(e.type, e.buf, seq: seqNo)
                if case .failed = state { return out }
            }
        }
        return out
    }

    private func handleMessage(_ t: UInt8, _ body: Data, seq: UInt16) -> [Data] {
        let full = rawHandshake(t, body, seq: seq)
        switch t {
        case 3: // HelloVerifyRequest: retry ClientHello with the cookie (message_seq 1, transcript restarts).
            guard body.count >= 3 else { return fail("bad HelloVerifyRequest") }
            let cl = Int(body[body.startIndex + 2])
            guard body.count >= 3 + cl, cl <= 255 else { return fail("bad HelloVerifyRequest cookie") }
            cookie = body.subdata(in: (body.startIndex + 3)..<(body.startIndex + 3 + cl))
            return sendClientHello()
        case 2: // ServerHello
            transcript.append(full)
            let b = [UInt8](body)
            guard b.count >= 38 else { return fail("bad ServerHello") }
            guard b[0] == 0xFE, b[1] == 0xFD else { return fail("server chose DTLS version \(b[0]).\(b[1])") }
            serverRandom = Data(b[2..<34])
            let sl = Int(b[34])
            guard b.count >= 35 + sl + 3 else { return fail("bad ServerHello") }
            suite = UInt16(b[35 + sl]) << 8 | UInt16(b[36 + sl])
            guard [Self.suiteAES128, Self.suiteAES256, Self.suiteChaCha].contains(suite) else {
                return fail(String(format: "server chose cipher 0x%04x", suite))
            }
            return []
        case 12: // ServerKeyExchange (PSK identity hint) — only hashed.
            transcript.append(full)
            return []
        case 14: // ServerHelloDone → ClientKeyExchange, CCS, Finished
            transcript.append(full)
            gotServerHelloDone = true
            return clientFinishFlight()
        case 20: // server Finished
            guard serverCCS, !master.isEmpty else { return fail("Finished before ChangeCipherSpec") }
            let want = prf(master, "server finished", hash(transcript), 12)
            guard body == want else { return fail("server Finished mismatch (wrong PSK?)") }
            transcript.append(full)
            state = .established
            lastFlight = []
            return []
        default:
            transcript.append(full)
            return []
        }
    }

    private func clientFinishFlight() -> [Data] {
        guard !serverRandom.isEmpty else { return fail("ServerHelloDone before ServerHello") }
        var cke = Data()
        cke.append(u16(Self.identity.count)); cke.append(Self.identity)
        let ckeMsg = handshake(16, cke)
        transcript.append(ckeMsg)
        var pms = Data()
        pms.append(u16(psk.count)); pms.append(Data(count: psk.count))
        pms.append(u16(psk.count)); pms.append(psk)
        master = prf(pms, "master secret", clientRandom + serverRandom, 48)
        let (kl, ivl) = keyLengths(suite)
        let kb = prf(master, "key expansion", serverRandom + clientRandom, 2 * kl + 2 * ivl)
        var o = kb.startIndex
        let cwk = kb.subdata(in: o..<(o + kl)); o += kl
        let swk = kb.subdata(in: o..<(o + kl)); o += kl
        writeIV = kb.subdata(in: o..<(o + ivl)); o += ivl
        readIV = kb.subdata(in: o..<(o + ivl))
        writeKey = SymmetricKey(data: cwk)
        readKey = SymmetricKey(data: swk)

        let r1 = record(22, ckeMsg)
        let r2 = record(20, Data([1]))
        sendEpoch = 1
        sendSeq = 0
        let verify = prf(master, "client finished", hash(transcript), 12)
        let finMsg = handshake(20, verify)
        transcript.append(finMsg)
        let r3 = record(22, finMsg)
        lastFlight = [r1 + r2 + r3]
        return lastFlight
    }

    private func fail(_ why: String) -> [Data] {
        state = .failed(why)
        return []
    }

    // MARK: Application data

    /// One application_data record (epoch 1). nil before the handshake finished.
    func seal(_ payload: Data) -> Data? {
        guard state == .established else { return nil }
        return record(23, payload)
    }

    /// A close_notify alert (best effort on teardown).
    func closeNotify() -> Data? {
        guard state == .established else { return nil }
        return record(21, Data([1, 0]))
    }

    // MARK: Records

    private func record(_ type: UInt8, _ plain: Data) -> Data {
        let seq = sendSeq
        sendSeq += 1
        var body = plain
        if sendEpoch == 1, let k = writeKey {
            body = sealAEAD(type: type, epoch: 1, seq: seq, plain, key: k)
        }
        var r = Data(capacity: 13 + body.count)
        r.append(type)
        r.append(contentsOf: [0xFE, 0xFD])
        r.append(u16(Int(sendEpoch)))
        for i in stride(from: 40, through: 0, by: -8) { r.append(UInt8(truncatingIfNeeded: seq >> UInt64(i))) }
        r.append(u16(body.count))
        r.append(body)
        return r
    }

    private func seqBytes(_ epoch: UInt16, _ seq: UInt64) -> Data {
        let v = UInt64(epoch) << 48 | (seq & 0xffff_ffff_ffff)
        var d = Data(count: 8)
        for i in 0..<8 { d[i] = UInt8(truncatingIfNeeded: v >> UInt64(56 - 8 * i)) }
        return d
    }

    private func aad(_ type: UInt8, _ epoch: UInt16, _ seq: UInt64, _ len: Int) -> Data {
        var a = seqBytes(epoch, seq)
        a.append(type)
        a.append(contentsOf: [0xFE, 0xFD])
        a.append(u16(len))
        return a
    }

    private func sealAEAD(type: UInt8, epoch: UInt16, seq: UInt64, _ plain: Data, key: SymmetricKey) -> Data {
        let explicit = seqBytes(epoch, seq)
        let ad = aad(type, epoch, seq, plain.count)
        if suite == Self.suiteChaCha {
            let nonce = xorNonce(writeIV, explicit)
            guard let n = try? ChaChaPoly.Nonce(data: nonce),
                  let box = try? ChaChaPoly.seal(plain, using: key, nonce: n, authenticating: ad) else { return Data() }
            return box.ciphertext + box.tag
        }
        guard let n = try? AES.GCM.Nonce(data: writeIV + explicit),
              let box = try? AES.GCM.seal(plain, using: key, nonce: n, authenticating: ad) else { return Data() }
        return explicit + box.ciphertext + box.tag
    }

    private func open(type: UInt8, epoch: UInt16, seq: UInt64, _ body: Data, key: SymmetricKey) -> Data? {
        if suite == Self.suiteChaCha {
            guard body.count >= 16 else { return nil }
            let ct = body.prefix(body.count - 16), tag = body.suffix(16)
            let nonce = xorNonce(readIV, seqBytes(epoch, seq))
            guard let n = try? ChaChaPoly.Nonce(data: nonce),
                  let box = try? ChaChaPoly.SealedBox(nonce: n, ciphertext: ct, tag: tag) else { return nil }
            return try? ChaChaPoly.open(box, using: key, authenticating: aad(type, epoch, seq, ct.count))
        }
        guard body.count >= 24 else { return nil }
        let explicit = body.prefix(8)
        let ct = body.dropFirst(8).dropLast(16), tag = body.suffix(16)
        guard let n = try? AES.GCM.Nonce(data: readIV + explicit),
              let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: ct, tag: tag) else { return nil }
        return try? AES.GCM.open(box, using: key, authenticating: aad(type, epoch, seq, ct.count))
    }

    private func xorNonce(_ iv: Data, _ seq8: Data) -> Data {
        var n = [UInt8](iv)
        let s = [UInt8](seq8)
        for i in 0..<8 { n[4 + i] ^= s[i] }
        return Data(n)
    }

    private func replayOK(_ seq: UInt64) -> Bool {
        if !replayAny { replayAny = true; replayTop = seq; replayBits = 1; return true }
        if seq > replayTop {
            let shift = seq - replayTop
            replayBits = shift >= 64 ? 1 : (replayBits << shift) | 1
            replayTop = seq
            return true
        }
        let back = replayTop - seq
        guard back < 64 else { return false }
        let bit = UInt64(1) << back
        if replayBits & bit != 0 { return false }
        replayBits |= bit
        return true
    }

    // MARK: Handshake framing

    private func handshake(_ t: UInt8, _ body: Data) -> Data {
        let m = rawHandshake(t, body, seq: msgSeq)
        msgSeq &+= 1
        return m
    }

    private func rawHandshake(_ t: UInt8, _ body: Data, seq: UInt16) -> Data {
        var m = Data(capacity: 12 + body.count)
        m.append(t)
        m.append(u24(body.count))
        m.append(u16(Int(seq)))
        m.append(u24(0))
        m.append(u24(body.count))
        m.append(body)
        return m
    }

    private func u16(_ v: Int) -> Data { Data([UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)]) }
    private func u24(_ v: Int) -> Data {
        Data([UInt8(truncatingIfNeeded: v >> 16), UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    private func keyLengths(_ s: UInt16) -> (Int, Int) {
        switch s {
        case Self.suiteAES256: return (32, 4)
        case Self.suiteChaCha: return (32, 12)
        default: return (16, 4)
        }
    }

    private var sha384: Bool { suite == Self.suiteAES256 }

    private func hash(_ d: Data) -> Data {
        sha384 ? Data(SHA384.hash(data: d)) : Data(SHA256.hash(data: d))
    }

    private func prf(_ secret: Data, _ label: String, _ seed: Data, _ n: Int) -> Data {
        sha384 ? Self.prf384(secret, label, seed, n) : Self.prf256(secret, label, seed, n)
    }

    /// TLS 1.2 PRF (RFC 5246 §5) with HMAC-SHA256.
    static func prf256(_ secret: Data, _ label: String, _ seed: Data, _ n: Int) -> Data {
        pHash(HMAC<SHA256>.self, secret, Data(label.utf8) + seed, n)
    }

    static func prf384(_ secret: Data, _ label: String, _ seed: Data, _ n: Int) -> Data {
        pHash(HMAC<SHA384>.self, secret, Data(label.utf8) + seed, n)
    }

    private static func pHash<H: HashFunction>(_: HMAC<H>.Type, _ secret: Data, _ seed: Data, _ n: Int) -> Data {
        let key = SymmetricKey(data: secret)
        var out = Data(capacity: n + 64)
        var a = Data(HMAC<H>.authenticationCode(for: seed, using: key))
        while out.count < n {
            out.append(Data(HMAC<H>.authenticationCode(for: a + seed, using: key)))
            a = Data(HMAC<H>.authenticationCode(for: a, using: key))
        }
        return out.prefix(n)
    }
}
