import Foundation
import CryptoKit

/// Shadowsocks 2022 (SIP022, "2022-blake3-*") — single-PSK, no EIH.
/// Implemented against sing-shadowsocks2 (the library mihomo ships):
///
/// - PSK: the password is the base64'd raw key (16 or 32 bytes).
/// - Session key: BLAKE3 derive-key, context "shadowsocks 2022 session
///   subkey", material = PSK ‖ salt.
/// - TCP: salt ‖ seal(fixed header) ‖ seal(variable header) ‖ stream
///   chunks identical in shape to legacy AEAD chunking, one nonce counter
///   across all seals. Request fixed = [0x00][unix ts u64][varLen u16];
///   variable = [target atyp][paddingLen u16][padding][payload…].
///   Response fixed = [0x01][ts][request salt][varLen].
/// - UDP (AES): no salt — a 16-byte separate header [sessionID][packetID]
///   doubles as the session-key "salt" (key = SessionKey(psk, sessionID
///   bytes)) and its bytes [4..<16] are the AEAD nonce; the header itself
///   is AES-block-encrypted with the PSK after sealing.
/// - UDP (ChaCha): XChaCha20-Poly1305 keyed by the PSK directly; random
///   24-byte nonce prefix; [sessionID][packetID] sit inside the plaintext.
enum NCSS2022 {
    struct Spec {
        let keyLen: Int
        let saltLen: Int
        let isAES: Bool
    }

    static func spec(for method: String) -> Spec? {
        switch method.lowercased() {
        case "2022-blake3-aes-128-gcm": return Spec(keyLen: 16, saltLen: 16, isAES: true)
        case "2022-blake3-aes-256-gcm": return Spec(keyLen: 32, saltLen: 32, isAES: true)
        case "2022-blake3-chacha20-poly1305": return Spec(keyLen: 32, saltLen: 32, isAES: false)
        default: return nil
        }
    }

    static func isMethod2022(_ method: String?) -> Bool {
        method.map { spec(for: $0) != nil } ?? false
    }

    static func psk(from password: String, keyLen: Int) -> Data? {
        var b64 = password.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespaces)
        while b64.count % 4 != 0 { b64.append("=") }
        guard let data = Data(base64Encoded: b64), data.count == keyLen else { return nil }
        return data
    }

    static func sessionKey(psk: Data, salt: Data, keyLen: Int) -> Data {
        let derived = NCBlake3.deriveKey(context: "shadowsocks 2022 session subkey",
                                         material: [UInt8](psk) + [UInt8](salt))
        return Data(derived.prefix(keyLen))
    }

    static let maxPadding = 900

    /// Parse a SOCKS-atyp target at the start of `data`; returns the target
    /// and the consumed byte count.
    static func parseTarget(_ data: Data) -> (NCTarget, Int)? {
        guard let atyp = data.first else { return nil }
        switch atyp {
        case 0x01:
            guard data.count >= 7 else { return nil }
            let host = data[1..<5].map { String($0) }.joined(separator: ".")
            return (NCTarget(host: host, port: Int(data[5]) << 8 | Int(data[6])), 7)
        case 0x03:
            guard data.count >= 2 else { return nil }
            let len = Int(data[1])
            guard data.count >= 2 + len + 2 else { return nil }
            let host = String(decoding: data[2..<(2 + len)], as: UTF8.self)
            let port = Int(data[2 + len]) << 8 | Int(data[3 + len])
            return (NCTarget(host: host, port: port), 2 + len + 2)
        case 0x04:
            guard data.count >= 19, let ip = NCIP(bytes: [UInt8](data[1..<17])) else { return nil }
            return (NCTarget(host: ip.string, port: Int(data[17]) << 8 | Int(data[18])), 19)
        default:
            return nil
        }
    }
}

/// One direction of the 2022 AEAD stream: counter nonce starting at zero,
/// incremented per seal/open (same construction as legacy SS).
final class NCSS2022StreamCrypto {
    private let key: SymmetricKey
    private let isAES: Bool
    private var nonce = [UInt8](repeating: 0, count: 12)

    init(sessionKey: Data, isAES: Bool) {
        self.key = SymmetricKey(data: sessionKey)
        self.isAES = isAES
    }

    func seal(_ plain: Data) -> Data? {
        defer { NCShadowsocks.incrementNonce(&nonce) }
        if isAES {
            guard let n = try? AES.GCM.Nonce(data: Data(nonce)),
                  let box = try? AES.GCM.seal(plain, using: key, nonce: n),
                  let combined = box.combined else { return nil }
            return Data(combined.dropFirst(12))
        }
        guard let n = try? ChaChaPoly.Nonce(data: Data(nonce)),
              let box = try? ChaChaPoly.seal(plain, using: key, nonce: n) else { return nil }
        return Data(box.combined.dropFirst(12))
    }

    func open(_ sealed: Data) -> Data? {
        defer { NCShadowsocks.incrementNonce(&nonce) }
        var combined = Data(nonce)
        combined.append(sealed)
        if isAES {
            guard let box = try? AES.GCM.SealedBox(combined: combined),
                  let plain = try? AES.GCM.open(box, using: key) else { return nil }
            return plain
        }
        guard let box = try? ChaChaPoly.SealedBox(combined: combined),
              let plain = try? ChaChaPoly.open(box, using: key) else { return nil }
        return plain
    }
}

/// TCP client → server direction.
final class NCSS2022Encoder {
    let spec: NCSS2022.Spec
    let salt: Data
    private let crypto: NCSS2022StreamCrypto
    private let paddingLen: Int

    init?(method: String, password: String, salt: Data? = nil, paddingLen: Int? = nil) {
        guard let spec = NCSS2022.spec(for: method),
              let psk = NCSS2022.psk(from: password, keyLen: spec.keyLen) else { return nil }
        self.spec = spec
        self.salt = salt ?? Data((0..<spec.saltLen).map { _ in UInt8.random(in: 0...255) })
        self.paddingLen = paddingLen ?? Int.random(in: 1...NCSS2022.maxPadding)
        let key = NCSS2022.sessionKey(psk: psk, salt: self.salt, keyLen: spec.keyLen)
        self.crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: spec.isAES)
    }

    /// salt ‖ sealed fixed header ‖ sealed variable header (target+padding).
    func requestHead(target: NCTarget, timestamp: UInt64) -> Data? {
        var variable = Data()
        variable.append(target.atypEncoded)
        variable.appendBE16(UInt16(paddingLen))
        variable.append(Data(count: paddingLen))
        var fixed = Data()
        fixed.append(0x00)
        fixed.appendBE64(timestamp)
        fixed.appendBE16(UInt16(variable.count))
        guard let sealedFixed = crypto.seal(fixed), let sealedVariable = crypto.seal(variable) else { return nil }
        var out = salt
        out.append(sealedFixed)
        out.append(sealedVariable)
        return out
    }

    /// Stream chunks after the request head: sealed length + sealed payload
    /// per ≤0x3FFF chunk, continuing the header's nonce counter.
    func encode(_ data: Data) -> Data? {
        var out = Data()
        var rest = data
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(0x3fff))
            rest = Data(rest.dropFirst(chunk.count))
            var lenBytes = Data(count: 2)
            lenBytes[0] = UInt8((chunk.count >> 8) & 0xff)
            lenBytes[1] = UInt8(chunk.count & 0xff)
            guard let sealedLen = crypto.seal(lenBytes), let sealedBody = crypto.seal(chunk) else { return nil }
            out.append(sealedLen)
            out.append(sealedBody)
        }
        return out
    }
}

/// TCP server → client direction: validates the response header (type,
/// request salt echo) before settling into chunk mode.
final class NCSS2022Decoder {
    private enum State {
        case salt, fixed, variable(Int), chunkLength, chunkBody(Int)
    }

    let spec: NCSS2022.Spec
    private let psk: Data
    private let requestSalt: Data
    private var state: State = .salt
    private var buffer = Data()
    private var crypto: NCSS2022StreamCrypto?

    init?(method: String, password: String, requestSalt: Data) {
        guard let spec = NCSS2022.spec(for: method),
              let psk = NCSS2022.psk(from: password, keyLen: spec.keyLen) else { return nil }
        self.spec = spec
        self.psk = psk
        self.requestSalt = requestSalt
    }

    var headerDone: Bool {
        switch state { case .chunkLength, .chunkBody: return true; default: return false }
    }

    /// Feed wire bytes; returns plaintext pieces (possibly empty while the
    /// header is still arriving), or nil on any validation/decrypt failure.
    func feed(_ data: Data) -> [Data]? {
        buffer.append(data)
        var out: [Data] = []
        while true {
            switch state {
            case .salt:
                guard buffer.count >= spec.saltLen else { return out }
                let salt = Data(buffer.prefix(spec.saltLen))
                buffer = Data(buffer.dropFirst(spec.saltLen))
                let key = NCSS2022.sessionKey(psk: psk, salt: salt, keyLen: spec.keyLen)
                crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: spec.isAES)
                state = .fixed
            case .fixed:
                let plainLen = 1 + 8 + spec.saltLen + 2
                guard buffer.count >= plainLen + 16 else { return out }
                guard let crypto, let fixed = crypto.open(Data(buffer.prefix(plainLen + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(plainLen + 16))
                guard fixed[0] == 0x01 else { return nil }
                guard Data(fixed[9..<(9 + spec.saltLen)]) == requestSalt else { return nil }
                let varLen = Int(fixed[plainLen - 2]) << 8 | Int(fixed[plainLen - 1])
                state = .variable(varLen)
            case .variable(let len):
                guard buffer.count >= len + 16 else { return out }
                guard let crypto, let plain = crypto.open(Data(buffer.prefix(len + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(len + 16))
                if !plain.isEmpty { out.append(plain) }
                state = .chunkLength
            case .chunkLength:
                guard buffer.count >= 2 + 16 else { return out }
                guard let crypto, let lenData = crypto.open(Data(buffer.prefix(2 + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(2 + 16))
                state = .chunkBody(Int(lenData[0]) << 8 | Int(lenData[1]))
            case .chunkBody(let len):
                guard buffer.count >= len + 16 else { return out }
                guard let crypto, let plain = crypto.open(Data(buffer.prefix(len + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(len + 16))
                if !plain.isEmpty { out.append(plain) }
                state = .chunkLength
            }
        }
    }
}

// MARK: - HChaCha20 / XChaCha20-Poly1305 (for the ChaCha UDP flavor)

enum NCChaCha {
    /// HChaCha20: the ChaCha core over key + 16-byte nonce, outputting the
    /// middle 16 state words (draft-arciszewski-xchacha §2.2).
    static func hchacha20(key: Data, nonce: Data) -> Data {
        precondition(key.count == 32 && nonce.count == 16)
        let constants: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        func words(_ d: Data) -> [UInt32] {
            (0..<d.count / 4).map { i in
                UInt32(d[i * 4]) | UInt32(d[i * 4 + 1]) << 8 | UInt32(d[i * 4 + 2]) << 16 | UInt32(d[i * 4 + 3]) << 24
            }
        }
        var state = constants + words(key) + words(nonce)
        func rotl(_ v: UInt32, _ c: UInt32) -> UInt32 { (v << c) | (v >> (32 - c)) }
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            state[a] = state[a] &+ state[b]; state[d] = rotl(state[d] ^ state[a], 16)
            state[c] = state[c] &+ state[d]; state[b] = rotl(state[b] ^ state[c], 12)
            state[a] = state[a] &+ state[b]; state[d] = rotl(state[d] ^ state[a], 8)
            state[c] = state[c] &+ state[d]; state[b] = rotl(state[b] ^ state[c], 7)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        let outWords = [state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15]]
        var out = Data()
        for w in outWords {
            out.append(UInt8(w & 0xff)); out.append(UInt8((w >> 8) & 0xff))
            out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
        }
        return out
    }

    static func xchachaSeal(key: Data, nonce24: Data, plain: Data) -> Data? {
        guard nonce24.count == 24 else { return nil }
        let subkey = hchacha20(key: key, nonce: Data(nonce24.prefix(16)))
        var nonce12 = Data(count: 4)
        nonce12.append(nonce24.suffix(8))
        guard let n = try? ChaChaPoly.Nonce(data: nonce12),
              let box = try? ChaChaPoly.seal(plain, using: SymmetricKey(data: subkey), nonce: n) else { return nil }
        return Data(box.combined.dropFirst(12))
    }

    static func xchachaOpen(key: Data, nonce24: Data, sealed: Data) -> Data? {
        guard nonce24.count == 24 else { return nil }
        let subkey = hchacha20(key: key, nonce: Data(nonce24.prefix(16)))
        var nonce12 = Data(count: 4)
        nonce12.append(nonce24.suffix(8))
        var combined = nonce12
        combined.append(sealed)
        guard let box = try? ChaChaPoly.SealedBox(combined: combined),
              let plain = try? ChaChaPoly.open(box, using: SymmetricKey(data: subkey)) else { return nil }
        return plain
    }
}

private extension UInt32 {
    func rotated(right n: UInt32) -> UInt32 { (self >> n) | (self << (32 - n)) }
}

// MARK: - UDP

/// SS2022 UDP packet crypto for one session (see the enum docs above).
final class NCSS2022UDPCrypto {
    let spec: NCSS2022.Spec
    private let psk: Data
    let sessionID: UInt64
    private var packetID: UInt64 = 0
    // AES flavor state
    private var aesSessionKey: SymmetricKey?
    private var remoteSessionID: UInt64?
    private var remoteKey: SymmetricKey?
    private var prevRemoteKey: SymmetricKey?

    init?(method: String, password: String, sessionID: UInt64? = nil) {
        guard let spec = NCSS2022.spec(for: method),
              let psk = NCSS2022.psk(from: password, keyLen: spec.keyLen) else { return nil }
        self.spec = spec
        self.psk = psk
        self.sessionID = sessionID ?? UInt64.random(in: 0...UInt64.max)
        if spec.isAES {
            var sid = Data(count: 8)
            for i in 0..<8 { sid[i] = UInt8((self.sessionID >> (56 - 8 * i)) & 0xff) }
            aesSessionKey = SymmetricKey(data: NCSS2022.sessionKey(psk: psk, salt: sid, keyLen: spec.keyLen))
        }
    }

    private func headerPlaintext(type: UInt8, timestamp: UInt64, padding: Int,
                                 target: NCTarget, payload: Data) -> Data {
        var out = Data()
        out.append(type)
        out.appendBE64(timestamp)
        out.appendBE16(UInt16(padding))
        out.append(Data(count: padding))
        out.append(target.atypEncoded)
        out.append(payload)
        return out
    }

    func encodePacket(target: NCTarget, payload: Data, timestamp: UInt64, padding: Int = 0) -> Data? {
        let body = headerPlaintext(type: 0x00, timestamp: timestamp, padding: padding,
                                   target: target, payload: payload)
        if spec.isAES {
            guard let aesSessionKey else { return nil }
            var header = Data(count: 16)
            for i in 0..<8 { header[i] = UInt8((sessionID >> (56 - 8 * i)) & 0xff) }
            for i in 0..<8 { header[8 + i] = UInt8((packetID >> (56 - 8 * i)) & 0xff) }
            packetID += 1
            let nonce = Data(header[4..<16])
            guard let n = try? AES.GCM.Nonce(data: nonce),
                  let box = try? AES.GCM.seal(body, using: aesSessionKey, nonce: n),
                  let combined = box.combined,
                  let block = NCAES(key: psk) else { return nil }
            let sealedHeader = block.encryptBlock(header)
            var out = sealedHeader
            out.append(Data(combined.dropFirst(12)))
            return out
        }
        // ChaCha: random 24-byte nonce prefix; session/packet IDs inside.
        var plain = Data(count: 16)
        for i in 0..<8 { plain[i] = UInt8((sessionID >> (56 - 8 * i)) & 0xff) }
        for i in 0..<8 { plain[8 + i] = UInt8((packetID >> (56 - 8 * i)) & 0xff) }
        packetID += 1
        plain.append(body)
        let nonce = Data((0..<24).map { _ in UInt8.random(in: 0...255) })
        guard let sealed = NCChaCha.xchachaSeal(key: psk, nonce24: nonce, plain: plain) else { return nil }
        var out = nonce
        out.append(sealed)
        return out
    }

    /// Decode one server packet; returns (source target, payload).
    func decodePacket(_ packet: Data) -> (NCTarget, Data)? {
        if spec.isAES {
            guard packet.count >= 16 + 16, let block = NCAES(key: psk) else { return nil }
            let header = block.decryptBlock(Data(packet.prefix(16)))
            var sid: UInt64 = 0
            for i in 0..<8 { sid = sid << 8 | UInt64(header[i]) }
            let nonce = Data(header[4..<16])
            var combined = nonce
            combined.append(Data(packet.dropFirst(16)))
            func openWith(_ key: SymmetricKey) -> Data? {
                guard let box = try? AES.GCM.SealedBox(combined: combined) else { return nil }
                return try? AES.GCM.open(box, using: key)
            }
            let plain = openWith(remoteKey(for: sid)) ?? prevRemoteKey.flatMap(openWith)
            guard let plain else { return nil }
            return parseBody(plain)
        }
        guard packet.count >= 24 + 16 else { return nil }
        let nonce = Data(packet.prefix(24))
        guard let plain = NCChaCha.xchachaOpen(key: psk, nonce24: nonce, sealed: Data(packet.dropFirst(24))),
              plain.count >= 16 else { return nil }
        return parseBody(Data(plain.dropFirst(16)))
    }

    private func remoteKey(for sid: UInt64) -> SymmetricKey {
        if sid == remoteSessionID, let remoteKey { return remoteKey }
        var sidData = Data(count: 8)
        for i in 0..<8 { sidData[i] = UInt8((sid >> (56 - 8 * i)) & 0xff) }
        let key = SymmetricKey(data: NCSS2022.sessionKey(psk: psk, salt: sidData, keyLen: spec.keyLen))
        prevRemoteKey = remoteKey
        remoteSessionID = sid
        remoteKey = key
        return key
    }

    private func parseBody(_ plain: Data) -> (NCTarget, Data)? {
        guard plain.count >= 1 + 8 + 2, plain[0] == 0x01 else { return nil }
        let padLen = Int(plain[9]) << 8 | Int(plain[10])
        let rest = Data(plain.dropFirst(11 + padLen))
        guard let (target, used) = NCSS2022.parseTarget(rest) else { return nil }
        return (target, Data(rest.dropFirst(used)))
    }
}
