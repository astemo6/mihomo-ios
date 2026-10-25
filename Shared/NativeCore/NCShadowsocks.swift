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

    // MARK: - AEAD over UDP (SIP022 packet format)
    //
    // UDP datagrams are independent of each other: packet = salt ‖ a single
    // AEAD seal, nonce all zero, over target-header ‖ payload, keyed by the
    // per-packet subkey. There is no sealed length chunk and no nonce
    // counter — that framing is TCP-only (NCSSEncoder / NCSSDecoder above).
    // Reusing the stream codec for UDP (as NCUDPSSSession once did) emits
    // salt ‖ seal(len) ‖ seal(body), which fails AEAD verification at the
    // server and is dropped silently — no reply ever comes back
    // (fix/nc-ss-udp; cross-checked in tools/loopback/ss-aead-udp-check.py).

    /// Largest legal UDP payload; the whole sealed datagram must fit in it.
    static let maxUDPPacketBytes = 65507

    private static func sealZeroNonce(spec: CipherSpec, key: SymmetricKey, plain: Data) -> Data? {
        // SealedBox.combined = nonce(12) + ciphertext + tag(16); the wire
        // keeps only ciphertext + tag, the nonce is implicitly zero.
        let zeroNonce = Data(count: 12)
        if spec.isAES {
            guard let n = try? AES.GCM.Nonce(data: zeroNonce),
                  let box = try? AES.GCM.seal(plain, using: key, nonce: n),
                  let combined = box.combined else { return nil }
            return Data(combined.dropFirst(12))
        }
        guard let n = try? ChaChaPoly.Nonce(data: zeroNonce),
              let box = try? ChaChaPoly.seal(plain, using: key, nonce: n) else { return nil }
        return Data(box.combined.dropFirst(12))
    }

    private static func openZeroNonce(spec: CipherSpec, key: SymmetricKey, sealed: Data) -> Data? {
        var combined = Data(count: 12)
        combined.append(sealed)
        if spec.isAES {
            guard let box = try? AES.GCM.SealedBox(combined: combined),
                  let plain = try? AES.GCM.open(box, using: key) else { return nil }
            return plain
        }
        guard let box = try? ChaChaPoly.SealedBox(combined: combined),
              let plain = try? ChaChaPoly.open(box, using: key) else { return nil }
        return plain
    }

    /// Seal one UDP datagram's plaintext (target header ‖ payload) into a
    /// wire packet with a fresh salt (or `salt` when given, for tests).
    /// Returns nil for an unknown cipher or a datagram that cannot fit.
    static func udpPacketEncode(cipher: String, password: String, plain: Data, salt: Data? = nil) -> Data? {
        guard let spec = spec(for: cipher) else { return nil }
        return udpPacketEncode(spec: spec, master: masterKey(password: password, keyLen: spec.keyLen),
                               plain: plain, salt: salt)
    }

    /// Same as above with the EVP_BytesToKey master key precomputed (one per
    /// UDP session instead of one MD5 chain per datagram).
    static func udpPacketEncode(spec: CipherSpec, master: Data, plain: Data, salt: Data? = nil) -> Data? {
        let salt = salt ?? Data((0..<spec.saltLen).map { _ in UInt8.random(in: 0...255) })
        guard salt.count == spec.saltLen,
              plain.count + spec.saltLen + 16 <= maxUDPPacketBytes else { return nil }
        let key = SymmetricKey(data: subkey(master: master, salt: salt, keyLen: spec.keyLen))
        guard let sealed = sealZeroNonce(spec: spec, key: key, plain: plain) else { return nil }
        var packet = salt
        packet.append(sealed)
        return packet
    }

    /// Open one received UDP datagram; returns target header ‖ payload, or
    /// nil when the packet is truncated or fails AEAD verification.
    static func udpPacketDecode(cipher: String, password: String, packet: Data) -> Data? {
        guard let spec = spec(for: cipher) else { return nil }
        return udpPacketDecode(spec: spec, master: masterKey(password: password, keyLen: spec.keyLen), packet: packet)
    }

    /// Same as above with the master key precomputed.
    static func udpPacketDecode(spec: CipherSpec, master: Data, packet: Data) -> Data? {
        guard packet.count >= spec.saltLen + 16 else { return nil }
        let salt = Data(packet.prefix(spec.saltLen))
        let key = SymmetricKey(data: subkey(master: master, salt: salt, keyLen: spec.keyLen))
        return openZeroNonce(spec: spec, key: key, sealed: Data(packet.dropFirst(spec.saltLen)))
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

    // nc-perf: read-offset consumption of `buffer` (was a dropFirst copy of the remainder per
    // chunk — O(n^2) over a long stream). Peek copies only the chunk being opened; the offset
    // advances on success, and the buffer is rebased once, past the halfway point.
    private var bufferOffset = 0
    private var buffered: Int { buffer.count - bufferOffset }
    private func peekBuffered(_ n: Int) -> Data { Data(buffer[bufferOffset..<(bufferOffset + n)]) }
    private func compactBuffer() {
        if bufferOffset == 0 { return }
        if bufferOffset >= buffer.count { buffer = Data(); bufferOffset = 0 }
        else if bufferOffset > buffer.count / 2 { buffer = Data(buffer.dropFirst(bufferOffset)); bufferOffset = 0 }
    }

    /// Feed received bytes; returns whatever plaintext became available.
    func feed(_ data: Data) -> Data? {
        defer { compactBuffer() }
        buffer.append(data)
        if key == nil {
            guard buffered >= spec.saltLen else { return Data() }
            let salt = peekBuffered(spec.saltLen)
            bufferOffset += spec.saltLen
            let master = NCShadowsocks.masterKey(password: password, keyLen: spec.keyLen)
            key = SymmetricKey(data: NCShadowsocks.subkey(master: master, salt: salt, keyLen: spec.keyLen))
        }
        var out = Data()
        while true {
            if let bodyLen = pendingBodyLen {
                guard buffered >= bodyLen + 16 else { break }
                let sealed = peekBuffered(bodyLen + 16)
                guard let plain = open(sealed) else { return nil }
                bufferOffset += bodyLen + 16
                out.append(plain)
                pendingBodyLen = nil
            } else {
                guard buffered >= 2 + 16 else { break }
                let sealed = peekBuffered(2 + 16)
                guard let lenData = open(sealed), lenData.count == 2 else { return nil }
                bufferOffset += 2 + 16
                pendingBodyLen = (Int(lenData[0]) << 8) | Int(lenData[1])
            }
        }
        return out
    }
}
