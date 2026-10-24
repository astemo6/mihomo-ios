import Foundation
import CryptoKit

/// VMess AEAD (alterId 0), ported from mihomo's sing-vmess client:
/// - cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
/// - header sealed with AuthID + AES-GCM under nested-HMAC KDF keys
/// - body: AEAD records of at most 15000 plaintext bytes, framed by a
///   SHAKE128-masked length, nonce = counter || nonce[2..<12]
/// Randomness is injectable so unit tests can pin the Go library's vectors.
enum NCVMess {
    static let securityAESGCM: UInt8 = 3
    static let securityChaCha: UInt8 = 4
    static let securityNone: UInt8 = 5
    static let optionChunkStream: UInt8 = 1
    static let optionChunkMasking: UInt8 = 4

    static func cat(_ parts: Data...) -> Data {
        var out = Data()
        for p in parts { out.append(p) }
        return out
    }

    static func cmdKey(uuidBytes: Data) -> Data {
        NCMD5.hash(cat(uuidBytes, Data("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8)))
    }

    /// VMess's nested-HMAC KDF: the innermost HMAC is keyed "VMess AEAD KDF",
    /// each subsequent value wraps it as the next HMAC's key.
    static func kdf(key: Data, values: [Data]) -> Data {
        func hmac(_ hash: @escaping (Data) -> Data, _ k: Data, _ msg: Data) -> Data {
            var key = k
            if key.count > 64 { key = hash(key) }
            if key.count < 64 { key.append(Data(repeating: 0, count: 64 - key.count)) }
            let ipad = Data(key.map { $0 ^ 0x36 })
            let opad = Data(key.map { $0 ^ 0x5c })
            return hash(cat(opad, hash(cat(ipad, msg))))
        }
        var level: (Data) -> Data = { msg in
            hmac({ NCSHA256.hash($0) }, Data("VMess AEAD KDF".utf8), msg)
        }
        for v in values {
            let inner = level
            level = { msg in hmac(inner, v, msg) }
        }
        return level(key)
    }

    /// AuthID: AES-128-ECB over time(8 BE) || random(4) || crc32(first 12, BE),
    /// keyed by KDF(cmdKey, "AES Auth ID Encryption")[..16].
    static func authID(cmdKey: Data, time: Int64, random4: Data) -> Data {
        var plain = Data()
        plain.appendBE64(UInt64(bitPattern: time))
        plain.append(random4)
        plain.appendBE32(NCCRC32.checksum(plain))
        let key = kdf(key: cmdKey, values: [Data("AES Auth ID Encryption".utf8)]).prefix(16)
        let aes = NCAES(key: Data(key))!
        return aes.encryptBlock(plain)
    }

    /// The sealed request header:
    /// authID(16) || sealedLen(18) || connNonce(8) || sealedHeader(len + 16).
    static func sealHeader(cmdKey: Data, plainHeader: Data, time: Int64, authRandom4: Data, connNonce: Data) -> Data {
        let auth = authID(cmdKey: cmdKey, time: time, random4: authRandom4)
        let lenKey = kdf(key: cmdKey, values: [Data("VMess Header AEAD Key_Length".utf8), auth, connNonce]).prefix(16)
        let lenNonce = kdf(key: cmdKey, values: [Data("VMess Header AEAD Nonce_Length".utf8), auth, connNonce]).prefix(12)
        var lenPlain = Data()
        lenPlain.appendBE16(UInt16(plainHeader.count))
        let sealedLen = gcmSeal(key: Data(lenKey), nonce: Data(lenNonce), plain: lenPlain, aad: auth)!
        let payKey = kdf(key: cmdKey, values: [Data("VMess Header AEAD Key".utf8), auth, connNonce]).prefix(16)
        let payNonce = kdf(key: cmdKey, values: [Data("VMess Header AEAD Nonce".utf8), auth, connNonce]).prefix(12)
        let sealedPay = gcmSeal(key: Data(payKey), nonce: Data(payNonce), plain: plainHeader, aad: auth)!
        return cat(auth, sealedLen, connNonce, sealedPay)
    }

    /// The plain request header (before sealing). `reqNonce` precedes `reqKey`
    /// on the wire, matching sing-vmess's encodeHeader.
    static func plainHeader(reqNonce: Data, reqKey: Data, respV: UInt8, option: UInt8,
                            security: UInt8, padding: Data, target: NCTarget, command: UInt8 = 1) -> Data {
        var out = Data()
        out.append(0x01) // version
        out.append(reqNonce)
        out.append(reqKey)
        out.append(respV)
        out.append(option)
        out.append(UInt8(padding.count) << 4 | security)
        out.append(0) // reserved
        out.append(command)
        out.appendBE16(UInt16(target.port))
        out.append(NCVLESS.addressEncoded(target)) // VMess uses the same atyp numbering
        out.append(padding)
        out.appendBE32(NCFNV1a.hash32(out))
        return out
    }

    /// AES-128-GCM seal returning ciphertext||tag (Go's Seal layout).
    static func gcmSeal(key: Data, nonce: Data, plain: Data, aad: Data? = nil) -> Data? {
        guard let n = try? AES.GCM.Nonce(data: nonce) else { return nil }
        let box: AES.GCM.SealedBox
        if let aad {
            guard let b = try? AES.GCM.seal(plain, using: SymmetricKey(data: key), nonce: n, authenticating: aad) else { return nil }
            box = b
        } else {
            guard let b = try? AES.GCM.seal(plain, using: SymmetricKey(data: key), nonce: n) else { return nil }
            box = b
        }
        return cat(Data(box.ciphertext), Data(box.tag))
    }

    static func gcmOpen(key: Data, nonce: Data, sealed: Data, aad: Data? = nil) -> Data? {
        guard sealed.count >= 16, let n = try? AES.GCM.Nonce(data: nonce) else { return nil }
        guard let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: sealed.prefix(sealed.count - 16), tag: sealed.suffix(16)) else { return nil }
        if let aad {
            return try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
        }
        return try? AES.GCM.open(box, using: SymmetricKey(data: key))
    }

    static func chaChaSeal(key: Data, nonce: Data, plain: Data) -> Data? {
        guard let n = try? ChaChaPoly.Nonce(data: nonce) else { return nil }
        guard let box = try? ChaChaPoly.seal(plain, using: SymmetricKey(data: key), nonce: n) else { return nil }
        return cat(Data(box.ciphertext), Data(box.tag))
    }

    static func chaChaOpen(key: Data, nonce: Data, sealed: Data) -> Data? {
        guard sealed.count >= 16, let n = try? ChaChaPoly.Nonce(data: nonce) else { return nil }
        guard let box = try? ChaChaPoly.SealedBox(nonce: n, ciphertext: sealed.prefix(sealed.count - 16), tag: sealed.suffix(16)) else { return nil }
        return try? ChaChaPoly.open(box, using: SymmetricKey(data: key))
    }

    /// ChaCha body key: MD5(b) || MD5(that[..16]) stretched to 32 bytes.
    static func chaChaKey(from bodyKey: Data) -> Data {
        let first = NCMD5.hash(bodyKey)
        let second = NCMD5.hash(Data(first.prefix(16)))
        return cat(first, second)
    }

    /// Response body keys for the AEAD path: SHA-256 halves of the request
    /// key/nonce.
    static func responseKeys(reqKey: Data, reqNonce: Data) -> (key: Data, nonce: Data) {
        (key: Data(NCSHA256.hash(reqKey).prefix(16)),
         nonce: Data(NCSHA256.hash(reqNonce).prefix(16)))
    }
}

/// VMess body chunk encoder (AES-GCM or ChaCha20-Poly1305 security).
final class NCVMessChunkEncoder {
    private let bodyKey: Data
    private let nonceBase: Data // 16-byte request/response nonce
    private let shake: NCShake128
    private let security: UInt8
    private var count: UInt16 = 0

    init(bodyKey: Data, nonceBase: Data, security: UInt8) {
        self.bodyKey = bodyKey
        self.nonceBase = nonceBase
        self.security = security
        self.shake = NCShake128(seed: nonceBase)
    }

    func encode(_ data: Data) -> Data {
        var out = Data()
        var offset = 0
        while offset < data.count {
            let end = offset + min(15000, data.count - offset)
            let chunk = Data(data[offset..<end])
            offset = end
            var nonce = Data()
            nonce.appendBE16(count)
            nonce.append(nonceBase[2..<12])
            count &+= 1
            let sealed: Data?
            if security == NCVMess.securityChaCha {
                sealed = NCVMess.chaChaSeal(key: NCVMess.chaChaKey(from: bodyKey), nonce: nonce, plain: chunk)
            } else {
                sealed = NCVMess.gcmSeal(key: bodyKey, nonce: nonce, plain: chunk)
            }
            guard let sealed else { return Data() }
            out.appendBE16(UInt16(sealed.count) ^ shake.nextUInt16())
            out.append(sealed)
        }
        return out
    }
}

/// VMess body chunk decoder; feed returns plaintext or nil on auth failure.
final class NCVMessChunkDecoder {
    private let bodyKey: Data
    private let nonceBase: Data
    private var shake: NCShake128
    private let security: UInt8
    private var count: UInt16 = 0
    private var buffer = Data()
    private(set) var finished = false

    init(bodyKey: Data, nonceBase: Data, security: UInt8) {
        self.bodyKey = bodyKey
        self.nonceBase = nonceBase
        self.security = security
        self.shake = NCShake128(seed: nonceBase)
    }

    /// Per-record plaintexts from the most recent feed call (VMess UDP maps
    /// one AEAD record to one datagram).
    private(set) var lastMessages: [Data] = []

    func feedMessages(_ data: Data) -> [Data]? {
        guard feed(data) != nil else { return nil }
        return lastMessages
    }

    func feed(_ data: Data) -> Data? {
        lastMessages = []
        if finished { return Data() }
        buffer.append(data)
        var out = Data()
        while buffer.count >= 2 {
            // Peek the mask on a clone; commit only when the record is whole.
            let probe = shake.clone()
            let mask = probe.nextUInt16()
            let len = Int((UInt16(buffer[0]) << 8 | UInt16(buffer[1])) ^ mask)
            if len == 0 {
                shake = probe
                buffer = Data(buffer.dropFirst(2))
                finished = true
                return out
            }
            guard buffer.count >= 2 + len else { break }
            shake = probe
            let record = Data(buffer[2..<(2 + len)])
            buffer = Data(buffer.dropFirst(2 + len))
            var nonce = Data()
            nonce.appendBE16(count)
            nonce.append(nonceBase[2..<12])
            count &+= 1
            let plain: Data?
            if security == NCVMess.securityChaCha {
                plain = NCVMess.chaChaOpen(key: NCVMess.chaChaKey(from: bodyKey), nonce: nonce, sealed: record)
            } else {
                plain = NCVMess.gcmOpen(key: bodyKey, nonce: nonce, sealed: record)
            }
            guard let plain else { return nil }
            out.append(plain)
            lastMessages.append(plain)
        }
        return out
    }
}

/// Streaming parser for the VMess AEAD response header (length block, then
/// payload block). Feed bytes; when `state` becomes .done, `bodyRemainder`
/// holds any bytes that already belong to the body stream.
final class NCVMessResponseReader {
    enum State { case reading, done, failed }
    private(set) var state: State = .reading
    private(set) var bodyRemainder = Data()

    private let respKey: Data
    private let respNonce: Data
    private let expectedV: UInt8
    private var buffer = Data()
    private var payloadLen: Int?

    init(respKey: Data, respNonce: Data, expectedV: UInt8) {
        self.respKey = respKey
        self.respNonce = respNonce
        self.expectedV = expectedV
    }

    func feed(_ data: Data) {
        guard state == .reading else { return }
        buffer.append(data)
        if payloadLen == nil {
            guard buffer.count >= 18 else { return }
            let key = NCVMess.kdf(key: respKey, values: [Data("AEAD Resp Header Len Key".utf8)]).prefix(16)
            let nonce = NCVMess.kdf(key: respNonce, values: [Data("AEAD Resp Header Len IV".utf8)]).prefix(12)
            guard let opened = NCVMess.gcmOpen(key: Data(key), nonce: Data(nonce), sealed: Data(buffer.prefix(18))) else {
                state = .failed
                return
            }
            payloadLen = Int(UInt16(opened[0]) << 8 | UInt16(opened[1]))
            buffer = Data(buffer.dropFirst(18))
        }
        guard let payloadLen else { return }
        guard buffer.count >= payloadLen + 16 else { return }
        let key = NCVMess.kdf(key: respKey, values: [Data("AEAD Resp Header Key".utf8)]).prefix(16)
        let nonce = NCVMess.kdf(key: respNonce, values: [Data("AEAD Resp Header IV".utf8)]).prefix(12)
        guard let opened = NCVMess.gcmOpen(key: Data(key), nonce: Data(nonce), sealed: Data(buffer.prefix(payloadLen + 16))) else {
            state = .failed
            return
        }
        guard opened.count >= 1, opened[0] == expectedV else {
            state = .failed
            return
        }
        bodyRemainder = Data(buffer.dropFirst(payloadLen + 16))
        buffer = Data()
        state = .done
    }
}

extension Data {
    mutating func appendBE16(_ v: UInt16) {
        append(UInt8(v >> 8))
        append(UInt8(v & 0xff))
    }
    mutating func appendBE32(_ v: UInt32) {
        append(UInt8((v >> 24) & 0xff))
        append(UInt8((v >> 16) & 0xff))
        append(UInt8((v >> 8) & 0xff))
        append(UInt8(v & 0xff))
    }
    mutating func appendBE64(_ v: UInt64) {
        for i in stride(from: 56, through: 0, by: -8) {
            append(UInt8((v >> UInt64(i)) & 0xff))
        }
    }
}
