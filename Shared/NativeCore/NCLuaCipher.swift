import Foundation
import CommonCrypto
import CryptoKit

/// feat/nc-lua S2: cipher objects behind the Lua `crypto` module.
///
/// Streaming contract mirrors Shadowrocket's CipherObject: `update` may be
/// called any number of times, `final` flushes. Stream ciphers (AES-CFB,
/// CFB8, RC4, ChaCha20) emit byte-for-byte on every update. AEAD ciphers
/// (AES-GCM, ChaCha20-Poly1305) are message-oriented by construction, so
/// `update` buffers and returns empty data and `final` seals/opens the one
/// message, using the IV given at construction as the nonce; the wire form
/// is `ciphertext || tag` (16-byte tag).
class NCLuaCipher {
    func update(_ data: Data) -> Data? { nil }
    func final() -> Data? { nil }

    static func make(algorithm: String, key: Data, iv: Data, decrypt: Bool) -> NCLuaCipher? {
        switch algorithm {
        case "aes-128-cfb", "aes-256-cfb":
            guard (algorithm.hasPrefix("aes-128") ? key.count == 16 : key.count == 32), iv.count == 16 else { return nil }
            return NCAESCFBCipher(key: key, iv: iv, decrypt: decrypt, segment8: false)
        case "aes-128-cfb8", "aes-256-cfb8":
            guard (algorithm.hasPrefix("aes-128") ? key.count == 16 : key.count == 32), iv.count == 16 else { return nil }
            return NCAESCFBCipher(key: key, iv: iv, decrypt: decrypt, segment8: true)
        case "rc4":
            guard !key.isEmpty else { return nil }
            return NCRC4Cipher(key: key)
        case "rc4-md5":
            guard !key.isEmpty else { return nil }
            let derived = Insecure.MD5.hash(data: key + iv)
            return NCRC4Cipher(key: Data(derived))
        case "chacha20":
            guard key.count == 32, iv.count == 8 || iv.count == 12 else { return nil }
            return NCChaCha20Cipher(key: key, nonce: iv)
        case "aes-128-gcm", "aes-256-gcm":
            guard (algorithm.hasPrefix("aes-128") ? key.count == 16 : key.count == 32), iv.count == 12 else { return nil }
            return NCAEADCipher(kind: .aesGCM, key: key, nonce: iv, decrypt: decrypt)
        case "chacha20-poly1305", "chacha20-ietf-poly1305":
            guard key.count == 32, iv.count == 12 else { return nil }
            return NCAEADCipher(kind: .chaChaPoly, key: key, nonce: iv, decrypt: decrypt)
        default:
            return nil
        }
    }
}

/// AES in CFB128 (or CFB8) built on one-shot ECB block encryptions — the
/// CommonCrypto CCCrypt one-shot API only, no CCCryptor state to leak.
/// Arbitrary update chunking is handled by carrying the keystream block
/// offset and the in-flight ciphertext block across calls.
private final class NCAESCFBCipher: NCLuaCipher {
    private let key: Data
    private let decrypt: Bool
    private let segment8: Bool
    private var state: Data // 16-byte shift register (starts as the IV)
    private var keystream = Data()
    private var keystreamPos = 16 // force regeneration on first byte
    private var blockCT = [UInt8](repeating: 0, count: 16)
    private var finished = false

    init(key: Data, iv: Data, decrypt: Bool, segment8: Bool) {
        self.key = key
        self.decrypt = decrypt
        self.segment8 = segment8
        self.state = iv
    }

    private func aesBlock(_ block: Data) -> Data? {
        var out = Data(count: 16)
        var moved = 0
        let rc = out.withUnsafeMutableBytes { outRaw in
            key.withUnsafeBytes { keyRaw in
                block.withUnsafeBytes { blockRaw in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode),
                            keyRaw.baseAddress, key.count, nil,
                            blockRaw.baseAddress, 16,
                            outRaw.baseAddress, 16, &moved)
                }
            }
        }
        return rc == CCCryptorStatus(kCCSuccess) && moved == 16 ? out : nil
    }

    override func update(_ data: Data) -> Data? {
        guard !finished else { return nil }
        var out = Data()
        out.reserveCapacity(data.count)
        if segment8 {
            for byte in data {
                guard let ks = aesBlock(state) else { return nil }
                let ksByte = ks[ks.startIndex]
                let produced = byte ^ ksByte
                let ctByte = decrypt ? byte : produced
                out.append(produced)
                state = Data(state.dropFirst() + [ctByte])
            }
            return out
        }
        for byte in data {
            if keystreamPos == 16 {
                guard let ks = aesBlock(state) else { return nil }
                keystream = ks
                keystreamPos = 0
            }
            let produced = byte ^ keystream[keystream.startIndex + keystreamPos]
            let ctByte = decrypt ? byte : produced
            blockCT[keystreamPos] = ctByte
            out.append(produced)
            keystreamPos += 1
            if keystreamPos == 16 { state = Data(blockCT) }
        }
        return out
    }

    override func final() -> Data? {
        finished = true
        return Data()
    }
}

/// RC4 (also the engine behind rc4-md5, whose key is MD5(key || iv)).
private final class NCRC4Cipher: NCLuaCipher {
    private var s = [UInt8](0...255)
    private var i = 0
    private var j = 0
    private var finished = false

    init(key: Data) {
        var jj = 0
        let keyBytes = [UInt8](key)
        for ii in 0...255 {
            jj = (jj + Int(s[ii]) + Int(keyBytes[ii % keyBytes.count])) & 0xff
            s.swapAt(ii, jj)
        }
    }

    override func update(_ data: Data) -> Data? {
        guard !finished else { return nil }
        var out = Data()
        out.reserveCapacity(data.count)
        for byte in data {
            i = (i + 1) & 0xff
            j = (j + Int(s[i])) & 0xff
            s.swapAt(i, j)
            out.append(byte ^ s[(Int(s[i]) + Int(s[j])) & 0xff])
        }
        return out
    }

    override func final() -> Data? {
        finished = true
        return Data()
    }
}

/// ChaCha20 stream (RFC 8439 for a 12-byte nonce; the original DJB layout
/// for an 8-byte nonce), pure Swift — CryptoKit exposes no raw ChaCha20.
private final class NCChaCha20Cipher: NCLuaCipher {
    private let key: [UInt32]
    private let nonce: [UInt8]
    private var counter: UInt64 = 0
    private var keystream = [UInt8]()
    private var keystreamPos = 64
    private var finished = false

    init(key data: Data, nonce: Data) {
        let bytes = [UInt8](data)
        key = (0..<8).map { o in
            UInt32(bytes[o * 4]) | UInt32(bytes[o * 4 + 1]) << 8 | UInt32(bytes[o * 4 + 2]) << 16 | UInt32(bytes[o * 4 + 3]) << 24
        }
        self.nonce = [UInt8](nonce)
    }

    private static func quarterRound(_ x: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        x[a] &+= x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >> 16)
        x[c] &+= x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >> 20)
        x[a] &+= x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >> 24)
        x[c] &+= x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >> 25)
    }

    private func block() -> [UInt8] {
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for i in 0..<8 { state[4 + i] = key[i] }
        if nonce.count == 12 {
            state[12] = UInt32(truncatingIfNeeded: counter)
            for i in 0..<3 {
                state[13 + i] = UInt32(nonce[i * 4]) | UInt32(nonce[i * 4 + 1]) << 8 | UInt32(nonce[i * 4 + 2]) << 16 | UInt32(nonce[i * 4 + 3]) << 24
            }
        } else {
            state[12] = UInt32(truncatingIfNeeded: counter)
            state[13] = UInt32(truncatingIfNeeded: counter >> 32)
            state[14] = UInt32(nonce[0]) | UInt32(nonce[1]) << 8 | UInt32(nonce[2]) << 16 | UInt32(nonce[3]) << 24
            state[15] = UInt32(nonce[4]) | UInt32(nonce[5]) << 8 | UInt32(nonce[6]) << 16 | UInt32(nonce[7]) << 24
        }
        var work = state
        for _ in 0..<10 {
            Self.quarterRound(&work, 0, 4, 8, 12)
            Self.quarterRound(&work, 1, 5, 9, 13)
            Self.quarterRound(&work, 2, 6, 10, 14)
            Self.quarterRound(&work, 3, 7, 11, 15)
            Self.quarterRound(&work, 0, 5, 10, 15)
            Self.quarterRound(&work, 1, 6, 11, 12)
            Self.quarterRound(&work, 2, 7, 8, 13)
            Self.quarterRound(&work, 3, 4, 9, 14)
        }
        var out = [UInt8]()
        out.reserveCapacity(64)
        for i in 0..<16 {
            let v = work[i] &+ state[i]
            out.append(UInt8(v & 0xff)); out.append(UInt8((v >> 8) & 0xff))
            out.append(UInt8((v >> 16) & 0xff)); out.append(UInt8((v >> 24) & 0xff))
        }
        counter &+= 1
        return out
    }

    override func update(_ data: Data) -> Data? {
        guard !finished else { return nil }
        var out = Data()
        out.reserveCapacity(data.count)
        for byte in data {
            if keystreamPos == 64 {
                keystream = block()
                keystreamPos = 0
            }
            out.append(byte ^ keystream[keystreamPos])
            keystreamPos += 1
        }
        return out
    }

    override func final() -> Data? {
        finished = true
        return Data()
    }
}

/// AEAD ciphers (AES-GCM, ChaCha20-Poly1305) via CryptoKit: update buffers,
/// final seals/opens the single message. Wire form: ciphertext || tag.
private final class NCAEADCipher: NCLuaCipher {
    enum Kind { case aesGCM, chaChaPoly }
    private let kind: Kind
    private let key: Data
    private let nonce: Data
    private let decrypt: Bool
    private var buffer = Data()
    private var finished = false

    init(kind: Kind, key: Data, nonce: Data, decrypt: Bool) {
        self.kind = kind
        self.key = key
        self.nonce = nonce
        self.decrypt = decrypt
    }

    override func update(_ data: Data) -> Data? {
        guard !finished else { return nil }
        buffer.append(data)
        return Data()
    }

    override func final() -> Data? {
        guard !finished else { return nil }
        finished = true
        let symmetricKey = SymmetricKey(data: key)
        do {
            switch (kind, decrypt) {
            case (.aesGCM, false):
                let box = try AES.GCM.seal(buffer, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
                return box.ciphertext + box.tag
            case (.aesGCM, true):
                guard buffer.count >= 16 else { return nil }
                let ct = Data(buffer.dropLast(16))
                let tag = Data(buffer.suffix(16))
                let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
                return try AES.GCM.open(box, using: symmetricKey)
            case (.chaChaPoly, false):
                let box = try ChaChaPoly.seal(buffer, using: symmetricKey, nonce: ChaChaPoly.Nonce(data: nonce))
                return box.ciphertext + box.tag
            case (.chaChaPoly, true):
                guard buffer.count >= 16 else { return nil }
                let ct = Data(buffer.dropLast(16))
                let tag = Data(buffer.suffix(16))
                let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ct, tag: tag)
                return try ChaChaPoly.open(box, using: symmetricKey)
            }
        } catch {
            return nil
        }
    }
}

/// crypto.digest objects (fix/nc-proto-lua-int): `update` buffers, `final` returns the lowercase hex digest
/// as bytes — the shape trojan-backend.lua relies on (hex(SHA224(password)) is the Trojan auth token).
final class NCLuaDigest: NCLuaCipher {
    private let algorithm: String
    private var buffer = Data()
    private var finished = false

    init?(algorithm: String) {
        switch algorithm {
        case "md5", "sha1", "sha224", "sha256", "sha384", "sha512": self.algorithm = algorithm
        default: return nil
        }
    }

    override func update(_ data: Data) -> Data? {
        guard !finished else { return nil }
        buffer.append(data)
        return Data()
    }

    override func final() -> Data? {
        guard !finished else { return nil }
        finished = true
        let raw: [UInt8]
        switch algorithm {
        case "md5": raw = Array(Insecure.MD5.hash(data: buffer))
        case "sha1": raw = Array(Insecure.SHA1.hash(data: buffer))
        case "sha224":
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            buffer.withUnsafeBytes { p in _ = CC_SHA224(p.baseAddress, CC_LONG(buffer.count), &out) }
            raw = out
        case "sha256": raw = Array(SHA256.hash(data: buffer))
        case "sha384": raw = Array(SHA384.hash(data: buffer))
        default: raw = Array(SHA512.hash(data: buffer))
        }
        buffer = Data()
        return Data(raw.map { String(format: "%02x", $0) }.joined().utf8)
    }
}
