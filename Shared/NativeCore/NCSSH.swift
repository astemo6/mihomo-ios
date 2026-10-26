import Foundation
import CryptoKit
import Security
import os

/// SSH outbound (mihomo v1.19.33 adapter/outbound/ssh.go: one shared client per proxy, a direct-tcpip channel per
/// flow) as a pure-Swift SSH-2 client (feat/nc-proto A3, based on astemo6/Muse NativeCore).
/// Transport: curve25519-sha256 / ecdh-sha2-nistp256, host keys ssh-ed25519 / ecdsa-sha2-nistp256 /
/// rsa-sha2-256/512 (signature always verified; `host-key` pins the blob like mihomo; without a pin the first-seen
/// key is remembered per server:port and a changed key is refused — TOFU, NCSSHKnownHosts, rv2-proto), ciphers
/// aes128/256-gcm@openssh.com and aes128/256-ctr + hmac-sha2-256, server-initiated re-keying.
/// Auth: password; private keys inline (OpenSSH unencrypted ed25519 / ecdsa-p256, PEM EC P-256, PEM/PKCS#8 RSA,
/// PKCS#8 Ed25519). Channel windows are 512 KB per flow (memory-bounded; Go uses 2 MB).
enum NCSSHWire {
    static func string(_ d: Data) -> Data { var o = Data(); o.appendBE32(UInt32(d.count)); o.append(d); return o }
    static func string(_ s: String) -> Data { string(Data(s.utf8)) }
    static func mpint(_ raw: Data) -> Data {
        var b = [UInt8](raw)
        while let f = b.first, f == 0 { b.removeFirst() }
        if let f = b.first, f & 0x80 != 0 { b.insert(0, at: 0) }
        return string(Data(b))
    }
    static func u32(_ v: UInt32) -> Data { var o = Data(); o.appendBE32(v); return o }

    struct Reader {
        let d: [UInt8]
        var i = 0
        init(_ data: Data) { d = [UInt8](data) }
        var atEnd: Bool { i >= d.count }
        mutating func byte() -> UInt8? { guard i < d.count else { return nil }; defer { i += 1 }; return d[i] }
        mutating func u32() -> UInt32? {
            guard i + 4 <= d.count else { return nil }
            defer { i += 4 }
            return UInt32(d[i]) << 24 | UInt32(d[i + 1]) << 16 | UInt32(d[i + 2]) << 8 | UInt32(d[i + 3])
        }
        mutating func bytes() -> Data? {
            guard let n = u32(), i + Int(n) <= d.count else { return nil }
            defer { i += Int(n) }
            return Data(d[i..<(i + Int(n))])
        }
        mutating func str() -> String? { bytes().map { String(decoding: $0, as: UTF8.self) } }
        mutating func bool() -> Bool? { byte().map { $0 != 0 } }
    }

    /// PKCS#1 RSAPublicKey DER from (n, e) magnitudes.
    static func rsaPublicDER(n: Data, e: Data) -> Data {
        func int(_ v: Data) -> Data {
            var b = [UInt8](v)
            while b.count > 1, b[0] == 0 { b.removeFirst() }
            if let f = b.first, f & 0x80 != 0 { b.insert(0, at: 0) }
            return der(0x02, Data(b))
        }
        return der(0x30, int(n) + int(e))
    }
    static func der(_ tag: UInt8, _ v: Data) -> Data {
        var o = Data([tag])
        if v.count < 128 { o.append(UInt8(v.count)) }
        else if v.count < 256 { o.append(contentsOf: [0x81, UInt8(v.count)]) }
        else { o.append(contentsOf: [0x82, UInt8(v.count >> 8), UInt8(v.count & 0xff)]) }
        o.append(v)
        return o
    }
}

/// A client signing key for publickey auth.
enum NCSSHKey {
    case ed25519(Curve25519.Signing.PrivateKey)
    case p256(P256.Signing.PrivateKey)
    case rsa(SecKey, pubBlob: Data)

    var algorithm: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case .p256: return "ecdsa-sha2-nistp256"
        case .rsa: return "rsa-sha2-256"
        }
    }

    var publicBlob: Data {
        switch self {
        case .ed25519(let k): return NCSSHWire.string("ssh-ed25519") + NCSSHWire.string(k.publicKey.rawRepresentation)
        case .p256(let k):
            return NCSSHWire.string("ecdsa-sha2-nistp256") + NCSSHWire.string("nistp256")
                + NCSSHWire.string(k.publicKey.x963Representation)
        case .rsa(_, let blob): return blob
        }
    }

    func sign(_ data: Data) -> Data? {
        switch self {
        case .ed25519(let k):
            guard let s = try? k.signature(for: data) else { return nil }
            return NCSSHWire.string("ssh-ed25519") + NCSSHWire.string(s)
        case .p256(let k):
            guard let s = try? k.signature(for: data) else { return nil }
            let raw = s.rawRepresentation
            let inner = NCSSHWire.mpint(raw.prefix(32)) + NCSSHWire.mpint(raw.suffix(32))
            return NCSSHWire.string("ecdsa-sha2-nistp256") + NCSSHWire.string(inner)
        case .rsa(let key, _):
            var err: Unmanaged<CFError>?
            guard let s = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &err) else {
                return nil
            }
            return NCSSHWire.string("rsa-sha2-256") + NCSSHWire.string(s as Data)
        }
    }

    /// nil with a reason when the key format is not supported.
    static func parse(_ text: String, passphrase: String? = nil) -> (NCSSHKey?, String?) {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let begin = lines.first(where: { $0.hasPrefix("-----BEGIN ") }) else { return (nil, "private-key 不是 PEM") }
        let body = lines.filter { !$0.hasPrefix("-----") && !$0.contains(":") }.joined()
        guard let der = Data(base64Encoded: body) else { return (nil, "private-key base64 无效") }
        if begin.contains("OPENSSH PRIVATE KEY") { return parseOpenSSH(der, passphrase: passphrase) }
        if begin.contains("EC PRIVATE KEY") {
            if let k = try? P256.Signing.PrivateKey(derRepresentation: der) { return (.p256(k), nil) }
            return (nil, "仅支持 P-256 EC 私钥")
        }
        if begin.contains("RSA PRIVATE KEY") { return rsa(pkcs1: der) }
        if begin.contains("BEGIN PRIVATE KEY") {
            if let k = try? P256.Signing.PrivateKey(derRepresentation: der) { return (.p256(k), nil) }
            let b = [UInt8](der)
            let edOID: [UInt8] = [0x06, 0x03, 0x2b, 0x65, 0x70]
            let hasEd = b.count >= 48 && (0...(b.count - edOID.count)).contains { Array(b[$0..<($0 + edOID.count)]) == edOID }
            if hasEd, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: Data(b.suffix(32))) {
                return (.ed25519(k), nil)
            }
            // PKCS#8 RSA: SEQ { INTEGER 0, SEQ { rsaEncryption, NULL }, OCTET STRING pkcs1 }
            var r = NCDERReader(data: der)
            if let seq = r.readTLV(), seq.tag == 0x30 {
                var inner = NCDERReader(data: seq.value)
                _ = inner.readTLV(); _ = inner.readTLV()
                if let oct = inner.readTLV(), oct.tag == 0x04 { return rsa(pkcs1: oct.value) }
            }
            return (nil, "PKCS#8 私钥类型不支持")
        }
        if begin.contains("ENCRYPTED") { return (nil, "加密私钥尚未接入") }
        return (nil, "私钥格式不支持")
    }

    private static func rsa(pkcs1: Data) -> (NCSSHKey?, String?) {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, nil),
              let pub = SecKeyCopyPublicKey(key),
              let pubDER = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return (nil, "RSA 私钥无效") }
        var r = NCDERReader(data: pubDER)
        guard let seq = r.readTLV(), seq.tag == 0x30 else { return (nil, "RSA 公钥无效") }
        var inner = NCDERReader(data: seq.value)
        guard let n = inner.readTLV(), let e = inner.readTLV() else { return (nil, "RSA 公钥无效") }
        let blob = NCSSHWire.string("ssh-rsa") + NCSSHWire.mpint(e.value) + NCSSHWire.mpint(n.value)
        return (.rsa(key, pubBlob: blob), nil)
    }

    private static func parseOpenSSH(_ der: Data, passphrase: String?) -> (NCSSHKey?, String?) {
        let magic = Data("openssh-key-v1".utf8) + Data([0])
        guard der.prefix(magic.count) == magic else { return (nil, "OpenSSH 私钥头无效") }
        var r = NCSSHWire.Reader(Data(der.dropFirst(magic.count)))
        guard let cipher = r.str(), let kdf = r.str(), let kdfOpts = r.bytes(), let n = r.u32(), n >= 1,
              let _ = r.bytes(), var priv = r.bytes() else { return (nil, "OpenSSH 私钥无效") }
        if cipher != "none" || kdf != "none" {
            // feat/nc-proto3: passphrase-protected keys, as metacubex/ssh passphraseProtectedOpenSSHKey:
            // bcrypt_pbkdf(passphrase, salt, rounds, 48) → AES-256 key ‖ IV; aes256-ctr or aes256-cbc.
            guard let passphrase, !passphrase.isEmpty else { return (nil, "OpenSSH 私钥已加密，缺少 private-key-passphrase") }
            guard kdf == "bcrypt" else { return (nil, "OpenSSH 私钥 KDF \(kdf) 不支持（仅 bcrypt）") }
            var o = NCSSHWire.Reader(kdfOpts)
            guard let salt = o.bytes(), let rounds = o.u32(),
                  let k = NCBcryptPBKDF.key(password: [UInt8](passphrase.utf8), salt: [UInt8](salt),
                                            rounds: Int(rounds), keyLen: 48) else { return (nil, "OpenSSH 私钥 KDF 参数无效") }
            let key = Data(k.prefix(32)), iv = Data(k.suffix(16))
            switch cipher {
            case "aes256-ctr":
                guard let c = NCSSStreamCipher(method: "aes-256-ctr", key: key) else { return (nil, "AES 初始化失败") }
                c.setIV(iv)
                priv = c.process(priv)
            case "aes256-cbc":
                guard priv.count % 16 == 0, let aes = NCAES(key: key) else { return (nil, "OpenSSH 私钥长度无效") }
                var prev = [UInt8](iv)
                var out = Data(capacity: priv.count)
                let bytes = [UInt8](priv)
                var i = 0
                while i < bytes.count {
                    let blk = Array(bytes[i..<(i + 16)])
                    let dec = [UInt8](aes.decryptBlock(Data(blk)))
                    out.append(contentsOf: (0..<16).map { dec[$0] ^ prev[$0] })
                    prev = blk
                    i += 16
                }
                priv = out
            default:
                return (nil, "OpenSSH 私钥加密 \(cipher) 不支持（仅 aes256-ctr / aes256-cbc）")
            }
        }
        var p = NCSSHWire.Reader(priv)
        // Compare the checkints before reading anything else: with a wrong passphrase the rest is
        // random bytes, so the key-type string's length prefix is garbage and would fail first,
        // reporting "私钥无效" instead of the passphrase error.
        guard let c1 = p.u32(), let c2 = p.u32() else { return (nil, "OpenSSH 私钥无效") }
        guard c1 == c2 else { return (nil, cipher == "none" ? "OpenSSH 私钥无效" : "OpenSSH 私钥口令错误") }
        guard let type = p.str() else { return (nil, "OpenSSH 私钥无效") }
        switch type {
        case "ssh-ed25519":
            guard let _ = p.bytes(), let sk = p.bytes(), sk.count == 64,
                  let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: sk.prefix(32)) else {
                return (nil, "ed25519 私钥无效")
            }
            return (.ed25519(k), nil)
        case "ecdsa-sha2-nistp256":
            guard let _ = p.str(), let _ = p.bytes(), let d = p.bytes() else { return (nil, "ECDSA 私钥无效") }
            var raw = [UInt8](d)
            while raw.count > 32, raw.first == 0 { raw.removeFirst() }
            while raw.count < 32 { raw.insert(0, at: 0) }
            guard let k = try? P256.Signing.PrivateKey(rawRepresentation: Data(raw)) else { return (nil, "ECDSA 私钥无效") }
            return (.p256(k), nil)
        default:
            return (nil, "OpenSSH 私钥类型 \(type) 尚未接入（RSA 请用 PEM 格式）")
        }
    }
}

/// One direction's packet protection.
private final class NCSSHCipher {
    enum Mode { case none, gcm(SymmetricKey, iv: [UInt8]), ctr(NCSSStreamCipher, mac: SymmetricKey) }
    var mode: Mode = .none
    var blockSize: Int {
        switch mode { case .none: return 8; default: return 16 }
    }

    private func nextNonce() -> AES.GCM.Nonce? {
        guard case .gcm(let k, var iv) = mode else { return nil }
        let nonce = try? AES.GCM.Nonce(data: Data(iv))
        var i = 11
        while i >= 4 { iv[i] &+= 1; if iv[i] != 0 { break }; i -= 1 }
        mode = .gcm(k, iv: iv)
        return nonce
    }

    func seal(payload: Data, seq: UInt32) -> Data? {
        let bs = blockSize
        var aead = false
        if case .gcm = mode { aead = true }
        // GCM: the length field is not encrypted and not part of the padding computation.
        let base = aead ? 1 + payload.count : 4 + 1 + payload.count
        var pad = bs - base % bs
        if pad < 4 { pad += bs }
        var plain = Data()
        plain.appendBE32(UInt32(1 + payload.count + pad))
        plain.append(UInt8(pad))
        plain.append(payload)
        plain.append(NCConnector.randomData(pad))
        switch mode {
        case .none:
            return plain
        case .gcm(let key, _):
            let lenField = plain.prefix(4)
            guard let nonce = nextNonce(),
                  let box = try? AES.GCM.seal(plain.dropFirst(4), using: key, nonce: nonce, authenticating: lenField) else {
                return nil
            }
            return Data(lenField) + box.ciphertext + box.tag
        case .ctr(let c, let macKey):
            let mac = HMAC<SHA256>.authenticationCode(for: NCSSHWire.u32(seq) + plain, using: macKey)
            return c.process(plain) + Data(mac)
        }
    }

    // Incremental open: CTR needs the first block decrypted to learn the length.
    private var head: Data?

    /// Returns (payload, bytes consumed) or nil when more input is needed; throws on a bad packet.
    func open(_ buf: Data, seq: UInt32) throws -> (Data, Int)? {
        switch mode {
        case .none:
            guard buf.count >= 4 else { return nil }
            let len = Int(Self.be32(buf, 0))
            guard len >= 5, len < 256 * 1024 else { throw NCSSHClient.err("bad packet length") }
            guard buf.count >= 4 + len else { return nil }
            let pad = Int(buf[buf.startIndex + 4])
            guard pad + 1 <= len else { throw NCSSHClient.err("bad padding") }
            return (Data(buf[(buf.startIndex + 5)..<(buf.startIndex + 4 + len - pad)]), 4 + len)
        case .gcm(let key, _):
            guard buf.count >= 4 else { return nil }
            let len = Int(Self.be32(buf, 0))
            guard len >= 16, len % 16 == 0, len < 256 * 1024 else { throw NCSSHClient.err("bad packet length") }
            guard buf.count >= 4 + len + 16 else { return nil }
            let s = buf.startIndex
            guard let nonce = nextNonce(),
                  let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: buf[(s + 4)..<(s + 4 + len)],
                                                   tag: buf[(s + 4 + len)..<(s + 4 + len + 16)]),
                  let plain = try? AES.GCM.open(box, using: key, authenticating: buf[s..<(s + 4)]) else {
                throw NCSSHClient.err("packet authentication failed")
            }
            let pad = Int(plain[plain.startIndex])
            guard pad + 1 <= plain.count else { throw NCSSHClient.err("bad padding") }
            return (Data(plain.dropFirst().dropLast(pad)), 4 + len + 16)
        case .ctr(let c, let macKey):
            if head == nil {
                guard buf.count >= 16 else { return nil }
                head = c.process(Data(buf.prefix(16)))
            }
            guard let h = head else { return nil }
            let len = Int(Self.be32(h, 0))
            guard len >= 12, (len + 4) % 16 == 0, len < 256 * 1024 else { throw NCSSHClient.err("bad packet length") }
            guard buf.count >= 4 + len + 32 else { return nil }
            let s = buf.startIndex
            let rest = c.process(Data(buf[(s + 16)..<(s + 4 + len)]))
            let plain = h + rest
            head = nil
            let mac = HMAC<SHA256>.authenticationCode(for: NCSSHWire.u32(seq) + plain, using: macKey)
            guard Data(mac) == buf[(s + 4 + len)..<(s + 4 + len + 32)] else { throw NCSSHClient.err("bad MAC") }
            let pad = Int(plain[4])
            guard pad + 1 <= len else { throw NCSSHClient.err("bad padding") }
            return (Data(plain[5..<(4 + len - pad)]), 4 + len + 32)
        }
    }

    static func be32(_ d: Data, _ o: Int) -> UInt32 {
        let s = d.startIndex + o
        return UInt32(d[s]) << 24 | UInt32(d[s + 1]) << 16 | UInt32(d[s + 2]) << 8 | UInt32(d[s + 3])
    }
}

final class NCSSHClient {
    enum State { case connecting, ready, failed, closed }
    static func err(_ s: String) -> NSError {
        NSError(domain: "NativeCore.SSH", code: 1, userInfo: [NSLocalizedDescriptionKey: "ssh: " + s])
    }

    static let windowSize: UInt32 = 512 * 1024
    static let maxPacket: UInt32 = 32 * 1024

    /// The transport; set at init for a chained transport, or right after via attachRaw when the raw stream
    /// first had to be dialed on this client's own queue (which only exists once the client does).
    private var raw: NCRelayStream?
    /// The client's own serial queue (nc-sessions): every piece of client and channel state is touched only
    /// here. Callers' queues are never used for the transport any more.
    let queue: DispatchQueue
    private let user: String
    private let password: String?
    private let key: NCSSHKey?
    private let hostKeys: [Data]
    private let hostKeyAlgs: [String]
    /// "server:port" for trust-on-first-use when no `host-key` pin is configured (nil = no TOFU, e.g. tests).
    private let knownHostID: String?
    /// Lock-protected snapshot for cross-thread readers (the registry in NCConnector); all other state is
    /// confined to `queue`.
    private let stateLock = OSAllocatedUnfairLock(initialState: State.connecting)
    var state: State { stateLock.withLock { $0 } }
    private func setState(_ newState: State) { stateLock.withLock { $0 = newState } }
    private var readyHandlers: [(Error?) -> Void] = [] // queue-confined

    private let clientVersion = "SSH-2.0-Go"
    private var serverVersion: String?
    private var inbuf = Data()
    /// nc-perf: read offset into `inbuf` — packets are consumed by advancing it instead of a
    /// Data(dropFirst) copy of the remainder per packet (O(n^2)); rebased once past halfway.
    /// `dec.open` reads startIndex-relative, so it takes the un-consumed slice as-is.
    private var inbufOffset = 0
    private func compactInbuf() {
        if inbufOffset == 0 { return }
        if inbufOffset >= inbuf.count { inbuf = Data(); inbufOffset = 0 }
        else if inbufOffset > inbuf.count / 2 { inbuf = Data(inbuf.dropFirst(inbufOffset)); inbufOffset = 0 }
    }
    private var sendSeq: UInt32 = 0, recvSeq: UInt32 = 0
    private let enc = NCSSHCipher(), dec = NCSSHCipher()

    // Key exchange
    private var clientKexInit = Data(), serverKexInit = Data()
    private var kexInProgress = false
    private var kexAlg = "", hostAlg = "", cipherC2S = "", cipherS2C = "", macC2S = "", macS2C = ""
    private var x25519: Curve25519.KeyAgreement.PrivateKey?
    private var p256: P256.KeyAgreement.PrivateKey?
    private var sessionID: Data?
    private var pendingKeys: (cipherIn: NCSSHCipher.Mode, cipherOut: NCSSHCipher.Mode)?
    private var heldDuringKex: [(payload: Data, completion: (() -> Void)?)] = []
    private var heldDuringKexBytes = 0
    /// nc-memory: cap on packets held during a (re-)key exchange; a peer that stalls kex
    /// would otherwise pin everything sent for its whole duration.
    static let maxHeldDuringKex = 256 * 1024
    private var authTried: [String] = []

    // Channels
    private var nextChannel: UInt32 = 0
    private var channels: [UInt32: NCSSHChannel] = [:]

    init(raw: NCRelayStream?, user: String, password: String?, key: NCSSHKey?, hostKeys: [Data],
         hostKeyAlgs: [String], label: String, knownHostID: String? = nil) {
        self.raw = raw
        self.knownHostID = knownHostID
        self.user = user
        self.password = password
        self.key = key
        self.hostKeys = hostKeys
        self.hostKeyAlgs = hostKeyAlgs
        self.queue = NCSessionQueues.make("nc.ssh.\(label)")
    }

    /// Supplies the transport dialed on `queue` (NCConnector.obtainSSHRaw) when it could not exist before
    /// the client. Called once, before start().
    func attachRaw(_ raw: NCRelayStream) { self.raw = raw }

    /// The transport could not be obtained at all: fail like a handshake error.
    func transportFailed(_ e: Error) { fail(e) }

    func start(_ done: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            self.readyHandlers.append(done)
            self.raw?.send(Data((self.clientVersion + "\r\n").utf8))
            self.sendKexInit()
            self.pump()
            self.queue.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard let self, self.state == .connecting else { return }
                self.fail(Self.err("handshake timeout"))
            }
        }
    }

    /// Readiness is delivered on the client's queue; channel opens hand results back on the channel's
    /// caller queue from there.
    func whenReady(_ h: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) {
            switch self.state {
            case .ready: h(nil)
            case .connecting: self.readyHandlers.append(h)
            default: h(Self.err("connection closed"))
            }
        }
    }

    private func pump() {
        raw?.receive { [weak self] data, error in
            guard let self else { return }
            // The raw stream was dialed on this client's queue, so this normally runs inline; the hop also
            // covers a chained transport whose callbacks live on its own session queue.
            ncOnSessionQueue(self.queue) {
                guard self.state == .connecting || self.state == .ready else { return }
                guard let data else { self.fail(error ?? Self.err("connection closed")); return }
                self.inbuf.append(data)
                do { try self.process() } catch { self.fail(error); return }
                if self.state == .connecting || self.state == .ready { self.pump() }
            }
        }
    }

    private func process() throws {
        defer { compactInbuf() }
        if serverVersion == nil {
            while serverVersion == nil {
                guard let nl = inbuf[inbufOffset...].firstIndex(of: 0x0a) else {
                    if inbuf.count - inbufOffset > 8192 { throw Self.err("no version line") }
                    return
                }
                var line = String(decoding: inbuf[inbufOffset..<nl], as: UTF8.self)
                inbufOffset = nl + 1
                if line.hasSuffix("\r") { line.removeLast() }
                if line.hasPrefix("SSH-") {
                    guard line.hasPrefix("SSH-2.0-") || line.hasPrefix("SSH-1.99-") else { throw Self.err("unsupported version \(line)") }
                    serverVersion = line
                }
            }
        }
        while state == .connecting || state == .ready {
            guard let (payload, used) = try dec.open(inbuf[inbufOffset...], seq: recvSeq) else { return }
            inbufOffset += used
            recvSeq &+= 1
            try handle(payload)
        }
    }

    // MARK: Packets out

    /// Queue-confined. `completion` (channel data) fires once the transport has taken the sealed packet —
    /// the channel's back-pressure signal; packets held during a re-key carry theirs along.
    private func sendPacket(_ payload: Data, kex: Bool = false, completion: (() -> Void)? = nil) {
        if kexInProgress && !kex {
            guard heldDuringKexBytes + payload.count <= Self.maxHeldDuringKex else {
                completion?()
                fail(Self.err("ssh kex hold buffer overflow"))
                return
            }
            heldDuringKexBytes += payload.count
            heldDuringKex.append((payload, completion))
            return
        }
        guard let wire = enc.seal(payload: payload, seq: sendSeq) else {
            completion?()
            fail(Self.err("encrypt failed"))
            return
        }
        sendSeq &+= 1
        if let completion {
            raw?.ncSend(wire, completion: completion)
        } else {
            raw?.send(wire)
        }
    }

    private static let kexAlgs = ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"]
    private static let defaultHostAlgs = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
    private static let ciphers = ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes256-ctr"]
    private static let macs = ["hmac-sha2-256"]

    private func sendKexInit() {
        kexInProgress = true
        var p = Data([20])
        p.append(NCConnector.randomData(16))
        let hostAlgs = hostKeyAlgs.isEmpty ? Self.defaultHostAlgs
            : hostKeyAlgs.filter { Self.defaultHostAlgs.contains($0) || $0 == "ssh-rsa" }
        for list in [Self.kexAlgs, hostAlgs, Self.ciphers, Self.ciphers, Self.macs, Self.macs,
                     ["none"], ["none"], [], []] {
            p.append(NCSSHWire.string(list.joined(separator: ",")))
        }
        p.append(0) // first_kex_packet_follows
        p.append(NCSSHWire.u32(0))
        clientKexInit = p
        sendPacket(p, kex: true)
    }

    // MARK: Packets in

    private func handle(_ p: Data) throws {
        guard let type = p.first else { return }
        switch type {
        case 1: // DISCONNECT
            var r = NCSSHWire.Reader(p.dropFirst())
            _ = r.u32()
            throw Self.err("disconnected: \(r.str() ?? "")")
        case 2, 4, 7: // IGNORE, DEBUG, EXT_INFO
            return
        case 3: // UNIMPLEMENTED
            return
        case 20:
            serverKexInit = p
            if !kexInProgress { sendKexInit() }
            try negotiate()
            sendKexECDHInit()
        case 31:
            try handleKexReply(p)
        case 21: // NEWKEYS from server: incoming keys switch now
            guard let keys = pendingKeys else { throw Self.err("unexpected NEWKEYS") }
            dec.mode = keys.cipherIn
            pendingKeys = nil
            kexInProgress = false
            let held = heldDuringKex
            heldDuringKex = []
            heldDuringKexBytes = 0
            if state == .connecting && authTried.isEmpty {
                sendPacket(Data([5]) + NCSSHWire.string("ssh-userauth"))
            }
            for h in held { sendPacket(h.payload, completion: h.completion) }
        case 6: // SERVICE_ACCEPT
            tryNextAuth()
        case 51: // USERAUTH_FAILURE
            tryNextAuth()
        case 52: // USERAUTH_SUCCESS
            setState(.ready)
            let hs = readyHandlers
            readyHandlers = []
            for h in hs { h(nil) }
        case 53: // banner
            return
        case 60:
            throw Self.err("password change requested")
        case 80: // GLOBAL_REQUEST
            var r = NCSSHWire.Reader(p.dropFirst())
            _ = r.str()
            if r.bool() == true { sendPacket(Data([82])) }
        case 91, 92, 93, 94, 95, 96, 97, 98, 99, 100:
            var r = NCSSHWire.Reader(p.dropFirst())
            guard let id = r.u32() else { return }
            if let ch = channels[id] { ch.handle(type: type, reader: &r) }
            else if type == 98 {
                _ = r.str()
                if r.bool() == true { sendPacket(Data([100]) + NCSSHWire.u32(id)) }
            }
        default:
            sendPacket(Data([3]) + NCSSHWire.u32(recvSeq &- 1))
        }
    }

    private func negotiate() throws {
        var c = NCSSHWire.Reader(clientKexInit.dropFirst(17))
        var s = NCSSHWire.Reader(serverKexInit.dropFirst(17))
        var picked: [String] = []
        for i in 0..<6 {
            let cl = (c.str() ?? "").split(separator: ",").map(String.init)
            let sl = Set((s.str() ?? "").split(separator: ",").map(String.init))
            guard let alg = cl.first(where: { sl.contains($0) }) else {
                throw Self.err("no common algorithm (\(["kex", "host key", "cipher", "cipher", "mac", "mac"][i]))")
            }
            picked.append(alg)
        }
        kexAlg = picked[0]; hostAlg = picked[1]; cipherC2S = picked[2]; cipherS2C = picked[3]
        macC2S = picked[4]; macS2C = picked[5]
    }

    private func sendKexECDHInit() {
        let q: Data
        if kexAlg == "ecdh-sha2-nistp256" {
            let k = P256.KeyAgreement.PrivateKey()
            p256 = k
            q = k.publicKey.x963Representation
        } else {
            let k = Curve25519.KeyAgreement.PrivateKey()
            x25519 = k
            q = k.publicKey.rawRepresentation
        }
        sendPacket(Data([30]) + NCSSHWire.string(q), kex: true)
    }

    private func handleKexReply(_ p: Data) throws {
        var r = NCSSHWire.Reader(p.dropFirst())
        guard let ks = r.bytes(), let qs = r.bytes(), let sig = r.bytes() else { throw Self.err("bad KEX reply") }
        let qc: Data
        let secret: Data
        if kexAlg == "ecdh-sha2-nistp256" {
            guard let k = p256, let pub = try? P256.KeyAgreement.PublicKey(x963Representation: qs),
                  let s = try? k.sharedSecretFromKeyAgreement(with: pub) else { throw Self.err("ECDH failed") }
            qc = k.publicKey.x963Representation
            secret = s.withUnsafeBytes { Data($0) }
        } else {
            guard let k = x25519, let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: qs),
                  let s = try? k.sharedSecretFromKeyAgreement(with: pub) else { throw Self.err("X25519 failed") }
            qc = k.publicKey.rawRepresentation
            secret = s.withUnsafeBytes { Data($0) }
        }
        let kMP = NCSSHWire.mpint(secret)
        var hin = NCSSHWire.string(clientVersion) + NCSSHWire.string(serverVersion ?? "")
        hin += NCSSHWire.string(clientKexInit) + NCSSHWire.string(serverKexInit)
        hin += NCSSHWire.string(ks) + NCSSHWire.string(qc) + NCSSHWire.string(qs) + kMP
        let h = Data(SHA256.hash(data: hin))
        guard Self.verifyHostSignature(alg: hostAlg, keyBlob: ks, sig: sig, data: h) else {
            throw Self.err("host key signature invalid")
        }
        if !hostKeys.isEmpty {
            if !hostKeys.contains(ks) {
                throw Self.err("host key mismatch, server send: \(ks.base64EncodedString())")
            }
        } else if let id = knownHostID {
            // No pin: trust on first use. The first verified key for this server:port is stored; a different key
            // later (MITM or a re-keyed server) is refused until the user pins the new key with `host-key`.
            switch NCSSHKnownHosts.shared.check(id: id, keyBlob: ks) {
            case .trusted, .learned:
                break
            case .mismatch(let expected, let got):
                throw Self.err("host key for \(id) changed (known \(expected), server sent \(got)); "
                               + "if the server key really changed, set host-key: [\"\(Self.keyTypeName(ks)) \(ks.base64EncodedString())\"]")
            }
        }
        if sessionID == nil { sessionID = h }
        let sid = sessionID!
        func derive(_ x: String, _ n: Int) -> Data {
            var out = Data(SHA256.hash(data: kMP + h + Data(x.utf8) + sid))
            while out.count < n { out += Data(SHA256.hash(data: kMP + h + out)) }
            return Data(out.prefix(n))
        }
        func mode(_ cipher: String, _ mac: String, iv: String, key: String, macKey: String, encrypt: Bool) throws -> NCSSHCipher.Mode {
            switch cipher {
            case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
                let kl = cipher.hasPrefix("aes128") ? 16 : 32
                return .gcm(SymmetricKey(data: derive(key, kl)), iv: [UInt8](derive(iv, 12)))
            case "aes128-ctr", "aes256-ctr":
                let kl = cipher.hasPrefix("aes128") ? 16 : 32
                let ssName = cipher.hasPrefix("aes128") ? "aes-128-ctr" : "aes-256-ctr"
                guard let c = NCSSStreamCipher(method: ssName, key: derive(key, kl)) else { throw Self.err("cipher init") }
                c.forEncryption = encrypt
                c.setIV(derive(iv, 16))
                return .ctr(c, mac: SymmetricKey(data: derive(macKey, 32)))
            default:
                throw Self.err("cipher \(cipher)")
            }
        }
        let outMode = try mode(cipherC2S, macC2S, iv: "A", key: "C", macKey: "E", encrypt: true)
        let inMode = try mode(cipherS2C, macS2C, iv: "B", key: "D", macKey: "F", encrypt: false)
        pendingKeys = (inMode, outMode)
        x25519 = nil; p256 = nil
        sendPacket(Data([21]), kex: true)
        enc.mode = outMode
    }

    static func keyTypeName(_ blob: Data) -> String {
        var r = NCSSHWire.Reader(blob)
        return r.str() ?? "ssh-unknown"
    }

    static func verifyHostSignature(alg: String, keyBlob: Data, sig: Data, data: Data) -> Bool {
        var k = NCSSHWire.Reader(keyBlob)
        var s = NCSSHWire.Reader(sig)
        guard let keyType = k.str(), let sigType = s.str(), let sigBytes = s.bytes() else { return false }
        switch keyType {
        case "ssh-ed25519":
            guard sigType == "ssh-ed25519", let pk = k.bytes(),
                  let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: pk) else { return false }
            return pub.isValidSignature(sigBytes, for: data)
        case "ecdsa-sha2-nistp256":
            guard sigType == keyType, let _ = k.str(), let q = k.bytes(),
                  let pub = try? P256.Signing.PublicKey(x963Representation: q) else { return false }
            var rs = NCSSHWire.Reader(sigBytes)
            guard let r0 = rs.bytes(), let s0 = rs.bytes() else { return false }
            func fix(_ v: Data) -> Data {
                var b = [UInt8](v)
                while b.count > 32, b.first == 0 { b.removeFirst() }
                while b.count < 32 { b.insert(0, at: 0) }
                return Data(b)
            }
            guard let esig = try? P256.Signing.ECDSASignature(rawRepresentation: fix(r0) + fix(s0)) else { return false }
            return pub.isValidSignature(esig, for: data) // hashes with SHA-256 as the signature requires
        case "ssh-rsa":
            guard let e = k.bytes(), let n = k.bytes() else { return false }
            let alg: SecKeyAlgorithm
            switch sigType {
            case "rsa-sha2-256": alg = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512": alg = .rsaSignatureMessagePKCS1v15SHA512
            case "ssh-rsa": alg = .rsaSignatureMessagePKCS1v15SHA1
            default: return false
            }
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
            guard let key = SecKeyCreateWithData(NCSSHWire.rsaPublicDER(n: n, e: e) as CFData,
                                                 attrs as CFDictionary, nil) else { return false }
            return SecKeyVerifySignature(key, alg, data as CFData, sigBytes as CFData, nil)
        default:
            return false
        }
    }

    // MARK: Auth

    private func tryNextAuth() {
        let base = Data([50]) + NCSSHWire.string(user) + NCSSHWire.string("ssh-connection")
        if let key, !authTried.contains("publickey"), let sid = sessionID {
            authTried.append("publickey")
            var msg = base + NCSSHWire.string("publickey") + Data([1])
            msg += NCSSHWire.string(key.algorithm) + NCSSHWire.string(key.publicBlob)
            if let sig = key.sign(NCSSHWire.string(sid) + msg) {
                sendPacket(msg + NCSSHWire.string(sig))
                return
            }
        }
        if let password, !authTried.contains("password") {
            authTried.append("password")
            sendPacket(base + NCSSHWire.string("password") + Data([0]) + NCSSHWire.string(password))
            return
        }
        if authTried.isEmpty {
            authTried.append("none")
            sendPacket(base + NCSSHWire.string("none"))
            return
        }
        fail(Self.err("authentication failed"))
    }

    // MARK: Channels

    func openDirectTCPIP(target: NCTarget, callerQueue: DispatchQueue) -> NCSSHChannel {
        if NCSessionQueues.isCurrent(queue) { return openChannelOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openChannelOnQueue(target: target, callerQueue: callerQueue) }
    }

    /// Legacy entry point: results land on the client's queue (see NCMuxSession.openStream).
    func openDirectTCPIP(target: NCTarget) -> NCSSHChannel {
        openDirectTCPIP(target: target, callerQueue: queue)
    }

    private func openChannelOnQueue(target: NCTarget, callerQueue: DispatchQueue) -> NCSSHChannel {
        let id = nextChannel
        nextChannel &+= 1
        let ch = NCSSHChannel(client: self, localID: id, callerQueue: callerQueue)
        channels[id] = ch
        var p = Data([90]) + NCSSHWire.string("direct-tcpip")
        p += NCSSHWire.u32(id) + NCSSHWire.u32(Self.windowSize) + NCSSHWire.u32(Self.maxPacket)
        p += NCSSHWire.string(target.host) + NCSSHWire.u32(UInt32(clamping: target.port))
        p += NCSSHWire.string("127.0.0.1") + NCSSHWire.u32(0)
        sendPacket(p)
        return ch
    }

    /// Queue-confined (channels hop onto the client queue before flushing).
    fileprivate func channelSend(_ payload: Data, completion: (() -> Void)? = nil) {
        sendPacket(payload, completion: completion)
    }
    fileprivate func channelGone(_ id: UInt32) { channels.removeValue(forKey: id) }

    private func fail(_ e: Error) {
        ncOnSessionQueue(queue) {
            guard self.state == .connecting || self.state == .ready else { return }
            self.setState(.failed)
            let hs = self.readyHandlers
            self.readyHandlers = []
            for h in hs { h(e) }
            for ch in self.channels.values { ch.connectionLost(e) }
            self.channels.removeAll()
            self.raw?.cancel()
        }
    }

    func close() {
        ncOnSessionQueue(queue) {
            guard self.state != .closed else { return }
            self.setState(.closed)
            // nc-lifecycle: a client closed while still connecting left its
            // whenReady waiters hanging forever (fail() fires them, close()
            // did not) — their callers wait on a completion that never comes.
            let hs = self.readyHandlers
            self.readyHandlers = []
            for h in hs { h(Self.err("connection closed")) }
            for ch in self.channels.values { ch.connectionLost(nil) }
            self.channels.removeAll()
            self.raw?.cancel()
        }
    }
}

/// One direct-tcpip channel as a relay stream. Sends respect the peer's window (queued otherwise); received data
/// is acknowledged with WINDOW_ADJUST as the consumer reads it, so at most one window is buffered per flow.
final class NCSSHChannel: NCRelayStream {
    private var client: NCSSHClient? // strong: a chain-transport client lives as long as its channels
    /// All channel state is confined to the client queue (nc-sessions): entry points hop onto it, and the
    /// receive/open callbacks are handed back on `callerQueue`.
    let callerQueue: DispatchQueue
    let localID: UInt32
    private var remoteID: UInt32 = 0
    private var remoteWindow: UInt32 = 0
    private var remoteMaxPacket: Int = 32768
    private var open = false, eof = false, closed = false
    private var failure: Error?
    private var outbox = Data()
    /// nc-perf: read offset into `outbox` — flush() advances it per window chunk instead of a
    /// Data(dropFirst) copy of the remainder per chunk; rebased once past halfway.
    private var outboxOffset = 0
    private var outboxRemaining: Int { outbox.count - outboxOffset }
    private func compactOutbox() {
        if outboxOffset == 0 { return }
        if outboxOffset >= outbox.count { outbox = Data(); outboxOffset = 0 }
        else if outboxOffset > outbox.count / 2 { outbox = Data(outbox.dropFirst(outboxOffset)); outboxOffset = 0 }
    }
    private var outboxEntries: [NCPendingSendEntry] = []
    private var inbox: [Data] = []
    /// nc-perf: head offset for inbox — receive() pops by advancing instead of removeFirst per
    /// piece (compacted past the halfway point, same pattern as NCVisionStream's outQueue).
    private var inboxHead = 0
    private var inboxBytes = 0
    private var inboxIsEmpty: Bool { inboxHead >= inbox.count }
    private func popInbox() -> Data {
        let d = inbox[inboxHead]
        inboxBytes -= d.count
        inboxHead += 1
        if inboxHead == inbox.count { inbox.removeAll(); inboxHead = 0 }
        else if inboxHead > inbox.count / 2 { inbox.removeFirst(inboxHead); inboxHead = 0 }
        return d
    }

    /// nc-memory: channel queue caps. Inbox is window-paced (we only ack on consumption),
    /// but a peer ignoring the window could still pin it — cap at the advertised window.
    static let maxOutbox = 256 * 1024
    static let maxInbox = 512 * 1024
    private var pending: ((Data?, Error?) -> Void)?
    private var consumed: UInt32 = 0
    var onOpen: ((Error?) -> Void)?

    fileprivate init(client: NCSSHClient, localID: UInt32, callerQueue: DispatchQueue) {
        self.client = client
        self.localID = localID
        self.callerQueue = callerQueue
    }

    private var clientQueue: DispatchQueue { client?.queue ?? callerQueue }

    fileprivate func handle(type: UInt8, reader r: inout NCSSHWire.Reader) {
        switch type {
        case 91: // OPEN_CONFIRMATION
            guard let rid = r.u32(), let win = r.u32(), let maxp = r.u32() else { return }
            remoteID = rid; remoteWindow = win; remoteMaxPacket = max(1024, min(Int(maxp), 32768))
            open = true
            let cb = onOpen; onOpen = nil
            if let cb { callerQueue.async { cb(nil) } }
            flush()
        case 92: // OPEN_FAILURE
            _ = r.u32()
            let msg = r.str() ?? ""
            let e = NCSSHClient.err("channel open failed: \(msg)")
            failure = e
            closed = true
            client?.channelGone(localID)
            let cb = onOpen; onOpen = nil
            if let cb { callerQueue.async { cb(e) } }
            if let h = pending { pending = nil; callerQueue.async { h(nil, e) } }
        case 93: // WINDOW_ADJUST
            if let add = r.u32() { remoteWindow &+= add; flush() }
        case 94: // DATA
            if let d = r.bytes(), !d.isEmpty { deliver(d) }
        case 95: // EXTENDED_DATA: ignore (stderr)
            _ = r.u32()
            if let d = r.bytes() { ack(UInt32(d.count)) }
        case 96: // EOF
            eof = true
            if inboxIsEmpty, let h = pending { pending = nil; callerQueue.async { h(nil, nil) } }
        case 97: // CLOSE
            if !closed { client?.channelSend(Data([97]) + NCSSHWire.u32(remoteID)) }
            closed = true
            eof = true
            client?.channelGone(localID)
            fireOutboxCompletions()
            if inboxIsEmpty, let h = pending { pending = nil; callerQueue.async { h(nil, nil) } }
        case 98: // CHANNEL_REQUEST
            _ = r.str()
            if r.bool() == true { client?.channelSend(Data([100]) + NCSSHWire.u32(remoteID)) }
        default:
            return
        }
    }

    private func deliver(_ d: Data) {
        if let h = pending { pending = nil; ack(UInt32(d.count)); callerQueue.async { h(d, nil) } }
        else if inboxBytes + d.count <= Self.maxInbox {
            inboxBytes += d.count
            inbox.append(d)
        } else {
            connectionLost(NCSSHClient.err("ssh channel receive buffer overflow"))
        }
    }

    private func ack(_ n: UInt32) {
        consumed &+= n
        if consumed >= NCSSHClient.windowSize / 2, open, !closed {
            client?.channelSend(Data([93]) + NCSSHWire.u32(remoteID) + NCSSHWire.u32(consumed))
            consumed = 0
        }
    }

    private func flush() {
        guard open, !closed else { return }
        defer { compactOutbox() }
        while outboxRemaining > 0 && remoteWindow > 0 {
            let n = min(outboxRemaining, remoteMaxPacket, Int(remoteWindow))
            let chunk = Data(outbox[outboxOffset..<(outboxOffset + n)])
            outboxOffset += n
            let (done, rest) = NCPendingSends.split(outboxEntries, consumed: n)
            outboxEntries = rest
            remoteWindow -= UInt32(n)
            let packet = Data([94]) + NCSSHWire.u32(remoteID) + NCSSHWire.string(chunk)
            if let client {
                client.channelSend(packet) { done.forEach { $0.call() } }
            } else {
                done.forEach { $0.call() }
            }
        }
    }

    private func fireOutboxCompletions() {
        NCPendingSends.fireAll(outboxEntries)
        outboxEntries = []
        outbox = Data()
        outboxOffset = 0
    }

    func send(_ data: Data) {
        send(data, completion: {})
    }

    /// Send with back-pressure: `completion` fires exactly once — after these bytes were flushed within the
    /// peer's window and the client's transport took the packet, or when the channel/connection dies trying.
    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCOnceCompletion(completion)
        ncOnSessionQueue(clientQueue) {
            guard !self.closed, self.failure == nil else { once.call(); return }
            // nc-memory: the outbox is window-paced, but a peer that never opens its window
            // would pin everything the app sends; cap it (mux pending-send shape, larger
            // because SSH packets in flight are already window-accounted once flushed).
            guard self.outboxRemaining + data.count <= Self.maxOutbox else {
                once.call()
                self.connectionLost(NCSSHClient.err("ssh channel send buffer overflow"))
                return
            }
            self.outbox.append(data)
            self.outboxEntries.append(NCPendingSendEntry(count: data.count, once: once))
            self.flush()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(clientQueue) {
            if !self.inboxIsEmpty {
                let d = self.popInbox()
                self.ack(UInt32(d.count))
                self.callerQueue.async { handler(d, nil) }
                return
            }
            if let failure = self.failure { self.callerQueue.async { handler(nil, failure) }; return }
            if self.eof || self.closed { self.callerQueue.async { handler(nil, nil) }; return }
            self.pending = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(clientQueue) {
            guard !self.closed else { return }
            self.closed = true
            self.fireOutboxCompletions()
            if self.open {
                self.client?.channelSend(Data([96]) + NCSSHWire.u32(self.remoteID))
                self.client?.channelSend(Data([97]) + NCSSHWire.u32(self.remoteID))
            }
            self.client?.channelGone(self.localID)
        }
    }

    /// Client queue only (called from the client's fail/close).
    fileprivate func connectionLost(_ e: Error?) {
        closed = true
        failure = failure ?? e
        fireOutboxCompletions()
        let cb = onOpen; onOpen = nil
        if let cb { callerQueue.async { cb(e ?? NCSSHClient.err("connection closed")) } }
        if let h = pending { pending = nil; callerQueue.async { h(nil, e) } }
    }
}

extension NCConnector {
    private static var sshRegistry: [String: NCSSHClient] = [:]
    private static let sshLock = NSLock()

    /// nc-lifecycle: see NCConnector.closeAllSharedSessions.
    static var sshSessionCount: Int {
        sshLock.lock(); defer { sshLock.unlock() }
        return sshRegistry.count
    }

    /// nc-lifecycle: drain the registry and close every client it held
    /// (close() fails its channels and, since the lifecycle fix, its
    /// readiness waiters).
    @discardableResult
    static func closeAllSSHSessions() -> Int {
        sshLock.lock()
        let all = Array(sshRegistry.values)
        sshRegistry.removeAll()
        sshLock.unlock()
        for c in all { c.close() }
        return all.count
    }

    static func sshStream(proxy: NCProxy, server: String, port: Int, target: NCTarget, queue: DispatchQueue,
                          transport: NCRelayStream?, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let why = NCSupport.sshUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported(why)) }
            return
        }
        func openOn(_ c: NCSSHClient) {
            c.whenReady { err in
                if let err { completion(nil, err); return }
                // The channel hands its open result back on the caller's queue (recorded here).
                let ch = c.openDirectTCPIP(target: target, callerQueue: queue)
                ch.onOpen = { e in completion(e == nil ? ch : nil, e) }
            }
        }
        let key = "\(proxy.name)|\(server)|\(port)"
        sshLock.lock()
        if transport == nil, let c = sshRegistry[key], c.state == .ready || c.state == .connecting {
            sshLock.unlock()
            openOn(c)
            return
        }
        sshLock.unlock()
        var signer: NCSSHKey?
        if let pk = proxy.fields["private-key"]?.string, !pk.isEmpty {
            // nc-perf: `private-key` is either inline PEM or a file path — absolute, ~, or
            // relative to the profile home (AppShared.homeURL, the same base the known-hosts
            // file uses). An encrypted OpenSSH key in the file is decrypted via
            // private-key-passphrase (bcrypt + aes256-ctr/cbc, NCSSHKey.parseOpenSSH).
            let pemText: String
            if pk.contains("PRIVATE KEY") {
                pemText = pk
            } else {
                let expanded = (pk as NSString).expandingTildeInPath
                let url = expanded.hasPrefix("/") ? URL(fileURLWithPath: expanded)
                                                  : AppShared.homeURL.appendingPathComponent(pk)
                guard let text = try? String(contentsOf: url, encoding: .utf8) else {
                    queue.async { completion(nil, Failure.unsupported("SSH 私钥文件读取失败（\(pk)）")) }
                    return
                }
                pemText = text
            }
            let (k, why) = sshKeyCached(pemText, passphrase: proxy.fields["private-key-passphrase"]?.string)
            guard let k else {
                queue.async { completion(nil, Failure.unsupported(why ?? "ssh private-key")) }
                return
            }
            signer = k
        }
        let pins: [Data] = (proxy.fields["host-key"]?.array ?? []).compactMap { v in
            guard let s = v.string else { return nil }
            let parts = s.split(separator: " ")
            return parts.count >= 2 ? Data(base64Encoded: String(parts[1])) : nil
        }
        let algs = proxy.fields["host-key-algorithms"]?.array?.compactMap { $0.string } ?? []
        let user = proxy.fields["username"]?.string ?? ""
        let pw = proxy.fields["password"]?.string
        // nc-sessions: the client owns its queue, so it is created first and the raw stream is dialed on
        // *its* queue (obtainSSHRaw's queue argument), never on the caller's.
        let c = NCSSHClient(raw: transport, user: user, password: (pw?.isEmpty ?? true) ? nil : pw, key: signer,
                            hostKeys: pins, hostKeyAlgs: algs, label: "\(server):\(port)",
                            knownHostID: "\(server):\(port)")
        if transport == nil {
            sshLock.lock(); sshRegistry[key] = c; sshLock.unlock()
        }
        func begin() {
            c.start { e in
                if e != nil, transport == nil {
                    sshLock.lock()
                    if sshRegistry[key] === c { sshRegistry.removeValue(forKey: key) }
                    sshLock.unlock()
                }
            }
            openOn(c)
        }
        if transport != nil {
            begin()
        } else {
            obtainSSHRaw(transport: nil, server: server, port: port, queue: c.queue) { raw, err in
                guard let raw else {
                    sshLock.lock()
                    if sshRegistry[key] === c { sshRegistry.removeValue(forKey: key) }
                    sshLock.unlock()
                    c.transportFailed(err ?? Failure.handshake("ssh dial failed"))
                    queue.async { completion(nil, err) }
                    return
                }
                c.attachRaw(raw)
                begin()
            }
        }
    }

    /// Parsed keys by (PEM, passphrase): bcrypt_pbkdf costs ~0.1–1 s, so an encrypted key is derived once.
    private static var sshKeyCache: [String: NCSSHKey] = [:]

    private static func sshKeyCached(_ pem: String, passphrase: String?) -> (NCSSHKey?, String?) {
        let cacheKey = Data(SHA256.hash(data: Data((pem + "\u{0}" + (passphrase ?? "")).utf8))).base64EncodedString()
        sshLock.lock()
        if let k = sshKeyCache[cacheKey] { sshLock.unlock(); return (k, nil) }
        sshLock.unlock()
        let (k, why) = NCSSHKey.parse(pem, passphrase: passphrase)
        if let k {
            sshLock.lock()
            if sshKeyCache.count > 16 { sshKeyCache.removeAll() }
            sshKeyCache[cacheKey] = k
            sshLock.unlock()
        }
        return (k, why)
    }

    private static func obtainSSHRaw(transport: NCRelayStream?, server: String, port: Int, queue: DispatchQueue,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let transport { completion(transport, nil); return }
        let s = NCStream(to: server, port: port, queue: queue)
        s.start { err in completion(err == nil ? s : nil, err) }
    }
}

/// Trust-on-first-use store for SSH host keys (rv2-proto): `<home>/engine/ssh_known_hosts.json`, a JSON object
/// "server:port" → "SHA256:<base64>" (OpenSSH fingerprint format) in the app group, shared by app and tunnel.
/// Only consulted when the proxy has no `host-key` pin; an explicit pin always wins.
final class NCSSHKnownHosts {
    static let shared = NCSSHKnownHosts()
    /// Test hook / alternate location.
    static var fileURLOverride: URL?
    /// Bounded: the oldest-inserted entries are dropped past this many servers (memory/file size).
    static let maxEntries = 512

    enum Verdict: Equatable {
        case trusted
        case learned
        case mismatch(expected: String, got: String)
    }

    private let lock = NSLock()
    private var cache: [String: String]?
    private var cacheMTime: Date?

    private var fileURL: URL {
        Self.fileURLOverride ?? AppShared.homeURL.appendingPathComponent("engine/ssh_known_hosts.json")
    }

    static func fingerprint(_ blob: Data) -> String {
        var b64 = Data(SHA256.hash(data: blob)).base64EncodedString()
        while b64.hasSuffix("=") { b64.removeLast() }
        return "SHA256:" + b64
    }

    func check(id: String, keyBlob: Data) -> Verdict {
        let fp = Self.fingerprint(keyBlob)
        lock.lock()
        defer { lock.unlock() }
        var map = loadLocked()
        if let known = map[id] {
            return known == fp ? .trusted : .mismatch(expected: known, got: fp)
        }
        if map.count >= Self.maxEntries, let drop = map.keys.sorted().first { map.removeValue(forKey: drop) }
        map[id] = fp
        cache = map
        saveLocked(map)
        return .learned
    }

    /// Forget a server's stored key (e.g. from a settings action after the user confirmed a key change).
    func forget(id: String) {
        lock.lock()
        defer { lock.unlock() }
        var map = loadLocked()
        guard map.removeValue(forKey: id) != nil else { return }
        cache = map
        saveLocked(map)
    }

    private func modDate() -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate]) as? Date
    }

    private func loadLocked() -> [String: String] {
        // The other process (app ↔ tunnel) may have changed or removed the file: re-read when its mtime moved.
        let mt = modDate()
        if let cache, mt == cacheMTime { return cache }
        cacheMTime = mt
        guard mt != nil, let raw = try? Data(contentsOf: fileURL),
              let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: String] else {
            cache = [:]
            return [:]
        }
        cache = obj
        return obj
    }

    private func saveLocked(_ map: [String: String]) {
        let url = fileURL
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let data = try? JSONSerialization.data(withJSONObject: map, options: [.sortedKeys]) {
            try? data.write(to: url, options: .atomic)
        }
        cacheMTime = modDate()
    }
}
