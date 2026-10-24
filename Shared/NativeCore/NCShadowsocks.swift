import Foundation
import CryptoKit

/// Shadowsocks AEAD (SIP022) stream crypto, per the shadowsocks spec as mihomo
/// implements it: master key = EVP_BytesToKey(password); per-connection subkey =
/// HKDF-SHA1(master, salt, "ss-subkey"); data moves in chunks of at most 0x3FFF
/// bytes, each chunk = sealed 2-byte big-endian length + sealed payload, with a
/// 96-bit little-endian nonce counter starting at zero.
enum NCShadowsocks {
    struct CipherSpec {
        let keyLen: Int
        let saltLen: Int
        let isAES: Bool
    }

    static func spec(for cipher: String) -> CipherSpec? {
        switch cipher.lowercased() {
        case "aes-128-gcm": return CipherSpec(keyLen: 16, saltLen: 16, isAES: true)
        case "aes-192-gcm": return CipherSpec(keyLen: 24, saltLen: 24, isAES: true)
        case "aes-256-gcm": return CipherSpec(keyLen: 32, saltLen: 32, isAES: true)
        case "chacha20-ietf-poly1305": return CipherSpec(keyLen: 32, saltLen: 32, isAES: false)
        default: return nil
        }
    }

    /// EVP_BytesToKey with MD5, no salt (the original KDF Shadowsocks still uses).
    static func masterKey(password: String, keyLen: Int) -> Data {
        let pw = Data(password.utf8)
        var out = Data()
        var prev = Data()
        while out.count < keyLen {
            var block = prev
            block.append(pw)
            prev = Data(Insecure.MD5.hash(data: block))
            out.append(prev)
        }
        return Data(out.prefix(keyLen))
    }

    static func subkey(master: Data, salt: Data, keyLen: Int) -> Data {
        let derived = HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: master),
            salt: salt,
            info: Data("ss-subkey".utf8),
            outputByteCount: keyLen)
        return derived.withUnsafeBytes { Data($0) }
    }

    static func incrementNonce(_ nonce: inout [UInt8]) {
        var i = 0
        while i < nonce.count {
            nonce[i] &+= 1
            if nonce[i] != 0 { break }
            i += 1
        }
    }
}

final class NCSSEncoder {
    let spec: NCShadowsocks.CipherSpec
    private let key: SymmetricKey
    private var nonce = [UInt8](repeating: 0, count: 12)
    private(set) var salt: Data

    init?(cipher: String, password: String, salt: Data? = nil) {
        guard let spec = NCShadowsocks.spec(for: cipher) else { return nil }
        self.spec = spec
        self.salt = salt ?? Data((0..<spec.saltLen).map { _ in UInt8.random(in: 0...255) })
        let master = NCShadowsocks.masterKey(password: password, keyLen: spec.keyLen)
        let sub = NCShadowsocks.subkey(master: master, salt: self.salt, keyLen: spec.keyLen)
        self.key = SymmetricKey(data: sub)
    }

    private func seal(_ plain: Data) -> Data? {
        defer { NCShadowsocks.incrementNonce(&nonce) }
        // SealedBox.combined = nonce(12) + ciphertext + tag(16); the wire keeps
        // only ciphertext + tag, the nonce is the shared chunk counter.
        if spec.isAES {
            guard let n = try? AES.GCM.Nonce(data: Data(nonce)),
                  let box = try? AES.GCM.seal(plain, using: key, nonce: n),
                  let combined = box.combined else { return nil }
            return Data(combined.dropFirst(12))
        } else {
            guard let n = try? ChaChaPoly.Nonce(data: Data(nonce)),
                  let box = try? ChaChaPoly.seal(plain, using: key, nonce: n) else { return nil }
            return Data(box.combined.dropFirst(12))
        }
    }

    /// Encode one stream chunk: salt is prepended to the very first output only
    /// (the caller tracks whether this encoder already emitted it).
    private var emittedSalt = false
    func encode(_ data: Data) -> Data? {
        var out = Data()
        if !emittedSalt { out.append(salt); emittedSalt = true }
        var rest = data
        while !rest.isEmpty {
            let chunk = rest.prefix(0x3fff)
            rest = rest.dropFirst(chunk.count)
            var lenBytes = Data(count: 2)
            lenBytes[0] = UInt8((chunk.count >> 8) & 0xff)
            lenBytes[1] = UInt8(chunk.count & 0xff)
            guard let sealedLen = seal(lenBytes), let sealedBody = seal(Data(chunk)) else { return nil }
            out.append(sealedLen)
            out.append(sealedBody)
        }
        return out
    }
}

final class NCSSDecoder {
    let spec: NCShadowsocks.CipherSpec
    private let password: String
    private var key: SymmetricKey?
    private var nonce = [UInt8](repeating: 0, count: 12)
    private var buffer = Data()
    private var pendingBodyLen: Int?

    init?(cipher: String, password: String) {
        guard let spec = NCShadowsocks.spec(for: cipher) else { return nil }
        self.spec = spec
        self.password = password
    }

    private func open(_ sealed: Data) -> Data? {
        defer { NCShadowsocks.incrementNonce(&nonce) }
        guard let key else { return nil }
        if spec.isAES {
            var combined = Data(nonce)
            combined.append(sealed)
            guard let box = try? AES.GCM.SealedBox(combined: combined),
                  let plain = try? AES.GCM.open(box, using: key) else { return nil }
            return plain
        } else {
            var combined = Data(nonce)
            combined.append(sealed)
            guard let box = try? ChaChaPoly.SealedBox(combined: combined),
                  let plain = try? ChaChaPoly.open(box, using: key) else { return nil }
            return plain
        }
    }

    /// Feed received bytes; returns whatever plaintext became available.
    func feed(_ data: Data) -> Data? {
        buffer.append(data)
        if key == nil {
            guard buffer.count >= spec.saltLen else { return Data() }
            let salt = Data(buffer.prefix(spec.saltLen))
            buffer = buffer.dropFirst(spec.saltLen)
            let master = NCShadowsocks.masterKey(password: password, keyLen: spec.keyLen)
            key = SymmetricKey(data: NCShadowsocks.subkey(master: master, salt: salt, keyLen: spec.keyLen))
        }
        var out = Data()
        while true {
            if let bodyLen = pendingBodyLen {
                guard buffer.count >= bodyLen + 16 else { break }
                let sealed = Data(buffer.prefix(bodyLen + 16))
                buffer = buffer.dropFirst(bodyLen + 16)
                guard let plain = open(sealed) else { return nil }
                out.append(plain)
                pendingBodyLen = nil
            } else {
                guard buffer.count >= 2 + 16 else { break }
                let sealed = Data(buffer.prefix(2 + 16))
                buffer = buffer.dropFirst(2 + 16)
                guard let lenData = open(sealed), lenData.count == 2 else { return nil }
                pendingBodyLen = (Int(lenData[0]) << 8) | Int(lenData[1])
            }
        }
        return out
    }
}
