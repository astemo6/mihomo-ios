import Foundation
import CryptoKit
import Security

/// SSH outbound (mihomo v1.19.33 adapter/outbound/ssh.go: one shared client per proxy, a direct-tcpip channel per
/// flow) as a pure-Swift SSH-2 client (feat/nc-proto A3, based on astemo6/Muse NativeCore).
/// Transport: curve25519-sha256 / ecdh-sha2-nistp256, host keys ssh-ed25519 / ecdsa-sha2-nistp256 /
/// rsa-sha2-256/512 (signature always verified; `host-key` pins the blob like mihomo), ciphers
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
                return (nil, "OpenSSH 私钥加密 \(cipher) 不支持（仅 aes256-ctr / aes256-cbc，与 mihomo 一致）")
            }
        }
        var p = NCSSHWire.Reader(priv)
        guard let c1 = p.u32(), let c2 = p.u32(), let type = p.str() else { return (nil, "OpenSSH 私钥无效") }
        guard c1 == c2 else { return (nil, cipher == "none" ? "OpenSSH 私钥无效" : "OpenSSH 私钥口令错误") }
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
    var macLength: Int {
        switch mode { case .none: return 0; case .gcm: return 16; case .ctr: return 32 }
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

    private let raw: NCRelayStream
    private let queue: DispatchQueue
    private let user: String
    private let password: String?
    private let key: NCSSHKey?
    private let hostKeys: [Data]
    private let hostKeyAlgs: [String]
    private(set) var state: State = .connecting
    private var readyHandlers: [(Error?) -> Void] = []

    private let clientVersion = "SSH-2.0-Go"
    private var serverVersion: String?
    private var inbuf = Data()
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
    private var heldDuringKex: [Data] = []
    private var authTried: [String] = []

    // Channels
    private var nextChannel: UInt32 = 0
    private var channels: [UInt32: NCSSHChannel] = [:]

    init(raw: NCRelayStream, user: String, password: String?, key: NCSSHKey?, hostKeys: [Data],
         hostKeyAlgs: [String], queue: DispatchQueue) {
        self.raw = raw
        self.user = user
        self.password = password
        self.key = key
        self.hostKeys = hostKeys
        self.hostKeyAlgs = hostKeyAlgs
        self.queue = queue
    }

    func start(_ done: @escaping (Error?) -> Void) {
        readyHandlers.append(done)
        raw.send(Data((clientVersion + "\r\n").utf8))
        sendKexInit()
        pump()
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.fail(Self.err("handshake timeout"))
        }
    }

    func whenReady(_ h: @escaping (Error?) -> Void) {
        switch state {
        case .ready: h(nil)
        case .connecting: readyHandlers.append(h)
        default: h(Self.err("connection closed"))
        }
    }

    private func pump() {
        raw.receive { [weak self] data, error in
            guard let self, self.state == .connecting || self.state == .ready else { return }
            guard let data else { self.fail(error ?? Self.err("connection closed")); return }
            self.inbuf.append(data)
            do { try self.process() } catch { self.fail(error); return }
            if self.state == .connecting || self.state == .ready { self.pump() }
        }
    }

    private func process() throws {
        if serverVersion == nil {
            while serverVersion == nil {
                guard let nl = inbuf.firstIndex(of: 0x0a) else {
                    if inbuf.count > 8192 { throw Self.err("no version line") }
                    return
                }
                var line = String(decoding: inbuf[inbuf.startIndex..<nl], as: UTF8.self)
                inbuf = Data(inbuf[(nl + 1)...])
                if line.hasSuffix("\r") { line.removeLast() }
                if line.hasPrefix("SSH-") {
                    guard line.hasPrefix("SSH-2.0-") || line.hasPrefix("SSH-1.99-") else { throw Self.err("unsupported version \(line)") }
                    serverVersion = line
                }
            }
        }
        while state == .connecting || state == .ready {
            guard let (payload, used) = try dec.open(inbuf, seq: recvSeq) else { return }
            inbuf = Data(inbuf.dropFirst(used))
            recvSeq &+= 1
            try handle(payload)
        }
    }

    // MARK: Packets out

    private func sendPacket(_ payload: Data, kex: Bool = false) {
        if kexInProgress && !kex {
            heldDuringKex.append(payload)
            return
        }
        guard let wire = enc.seal(payload: payload, seq: sendSeq) else { fail(Self.err("encrypt failed")); return }
        sendSeq &+= 1
        raw.send(wire)
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
            if state == .connecting && authTried.isEmpty {
                sendPacket(Data([5]) + NCSSHWire.string("ssh-userauth"))
            }
            for h in held { sendPacket(h) }
        case 6: // SERVICE_ACCEPT
            tryNextAuth()
        case 51: // USERAUTH_FAILURE
            tryNextAuth()
        case 52: // USERAUTH_SUCCESS
            state = .ready
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
        if !hostKeys.isEmpty && !hostKeys.contains(ks) {
            throw Self.err("host key mismatch, server send: \(ks.base64EncodedString())")
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

    func openDirectTCPIP(target: NCTarget) -> NCSSHChannel {
        let id = nextChannel
        nextChannel &+= 1
        let ch = NCSSHChannel(client: self, localID: id)
        channels[id] = ch
        var p = Data([90]) + NCSSHWire.string("direct-tcpip")
        p += NCSSHWire.u32(id) + NCSSHWire.u32(Self.windowSize) + NCSSHWire.u32(Self.maxPacket)
        p += NCSSHWire.string(target.host) + NCSSHWire.u32(UInt32(clamping: target.port))
        p += NCSSHWire.string("127.0.0.1") + NCSSHWire.u32(0)
        sendPacket(p)
        return ch
    }

    fileprivate func channelSend(_ payload: Data) { sendPacket(payload) }
    fileprivate func channelGone(_ id: UInt32) { channels.removeValue(forKey: id) }

    private func fail(_ e: Error) {
        guard state == .connecting || state == .ready else { return }
        state = .failed
        let hs = readyHandlers
        readyHandlers = []
        for h in hs { h(e) }
        for ch in channels.values { ch.connectionLost(e) }
        channels.removeAll()
        raw.cancel()
    }

    func close() {
        guard state != .closed else { return }
        state = .closed
        for ch in channels.values { ch.connectionLost(nil) }
        channels.removeAll()
        raw.cancel()
    }
}

/// One direct-tcpip channel as a relay stream. Sends respect the peer's window (queued otherwise); received data
/// is acknowledged with WINDOW_ADJUST as the consumer reads it, so at most one window is buffered per flow.
final class NCSSHChannel: NCRelayStream {
    private var client: NCSSHClient? // strong: a chain-transport client lives as long as its channels
    let localID: UInt32
    private var remoteID: UInt32 = 0
    private var remoteWindow: UInt32 = 0
    private var remoteMaxPacket: Int = 32768
    private var open = false, eof = false, closed = false
    private var failure: Error?
    private var outbox = Data()
    private var inbox: [Data] = []
    private var pending: ((Data?, Error?) -> Void)?
    private var consumed: UInt32 = 0
    var onOpen: ((Error?) -> Void)?

    fileprivate init(client: NCSSHClient, localID: UInt32) {
        self.client = client
        self.localID = localID
    }

    fileprivate func handle(type: UInt8, reader r: inout NCSSHWire.Reader) {
        switch type {
        case 91: // OPEN_CONFIRMATION
            guard let rid = r.u32(), let win = r.u32(), let maxp = r.u32() else { return }
            remoteID = rid; remoteWindow = win; remoteMaxPacket = max(1024, min(Int(maxp), 32768))
            open = true
            let cb = onOpen; onOpen = nil; cb?(nil)
            flush()
        case 92: // OPEN_FAILURE
            _ = r.u32()
            let msg = r.str() ?? ""
            let e = NCSSHClient.err("channel open failed: \(msg)")
            failure = e
            closed = true
            client?.channelGone(localID)
            let cb = onOpen; onOpen = nil; cb?(e)
            if let h = pending { pending = nil; h(nil, e) }
        case 93: // WINDOW_ADJUST
            if let add = r.u32() { remoteWindow &+= add; flush() }
        case 94: // DATA
            if let d = r.bytes(), !d.isEmpty { deliver(d) }
        case 95: // EXTENDED_DATA: ignore (stderr)
            _ = r.u32()
            if let d = r.bytes() { ack(UInt32(d.count)) }
        case 96: // EOF
            eof = true
            if inbox.isEmpty, let h = pending { pending = nil; h(nil, nil) }
        case 97: // CLOSE
            if !closed { client?.channelSend(Data([97]) + NCSSHWire.u32(remoteID)) }
            closed = true
            eof = true
            client?.channelGone(localID)
            if inbox.isEmpty, let h = pending { pending = nil; h(nil, nil) }
        case 98: // CHANNEL_REQUEST
            _ = r.str()
            if r.bool() == true { client?.channelSend(Data([100]) + NCSSHWire.u32(remoteID)) }
        default:
            return
        }
    }

    private func deliver(_ d: Data) {
        if let h = pending { pending = nil; ack(UInt32(d.count)); h(d, nil) }
        else { inbox.append(d) }
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
        while !outbox.isEmpty && remoteWindow > 0 {
            let n = min(outbox.count, remoteMaxPacket, Int(remoteWindow))
            let chunk = Data(outbox.prefix(n))
            outbox = Data(outbox.dropFirst(n))
            remoteWindow -= UInt32(n)
            client?.channelSend(Data([94]) + NCSSHWire.u32(remoteID) + NCSSHWire.string(chunk))
        }
    }

    func send(_ data: Data) {
        guard !closed, failure == nil else { return }
        outbox.append(data)
        flush()
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !inbox.isEmpty {
            let d = inbox.removeFirst()
            ack(UInt32(d.count))
            handler(d, nil)
            return
        }
        if let failure { handler(nil, failure); return }
        if eof || closed { handler(nil, nil); return }
        pending = handler
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        if open {
            client?.channelSend(Data([96]) + NCSSHWire.u32(remoteID))
            client?.channelSend(Data([97]) + NCSSHWire.u32(remoteID))
        }
        client?.channelGone(localID)
    }

    fileprivate func connectionLost(_ e: Error?) {
        closed = true
        failure = failure ?? e
        let cb = onOpen; onOpen = nil; cb?(e ?? NCSSHClient.err("connection closed"))
        if let h = pending { pending = nil; h(nil, e) }
    }
}

extension NCConnector {
    private static var sshRegistry: [String: NCSSHClient] = [:]
    private static let sshLock = NSLock()

    static func sshStream(proxy: NCProxy, server: String, port: Int, target: NCTarget, queue: DispatchQueue,
                          transport: NCRelayStream?, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let why = NCSupport.sshUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported(why)) }
            return
        }
        func openOn(_ c: NCSSHClient) {
            c.whenReady { err in
                if let err { completion(nil, err); return }
                let ch = c.openDirectTCPIP(target: target)
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
            let (k, why) = sshKeyCached(pk, passphrase: proxy.fields["private-key-passphrase"]?.string)
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
        obtainSSHRaw(transport: transport, server: server, port: port, queue: queue) { raw, err in
            guard let raw else { completion(nil, err); return }
            let c = NCSSHClient(raw: raw, user: user, password: (pw?.isEmpty ?? true) ? nil : pw, key: signer,
                                hostKeys: pins, hostKeyAlgs: algs, queue: queue)
            if transport == nil {
                sshLock.lock(); sshRegistry[key] = c; sshLock.unlock()
            }
            c.start { e in
                if e != nil, transport == nil {
                    sshLock.lock()
                    if sshRegistry[key] === c { sshRegistry.removeValue(forKey: key) }
                    sshLock.unlock()
                }
            }
            openOn(c)
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
