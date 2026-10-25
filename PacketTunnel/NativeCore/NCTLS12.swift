import Foundation
import CryptoKit
import Security

/// TLS 1.2 pieces for NCTLSClientStream's fallback path (feat/nc-proto, A8; based on astemo6/Muse NativeCore).
/// Scope: ECDHE (X25519 / P-256 / P-384) with AES-128/256-GCM and ChaCha20-Poly1305 — what Go's crypto/tls
/// client offers by default for TLS 1.2 — extended master secret when the server echoes it, no renegotiation,
/// no resumption, no client certificates (an empty Certificate answers a CertificateRequest).
/// Direct TLS sockets keep using Network.framework (NCStream tls:) which negotiates 1.2 by itself; this path is
/// for TLS run over an arbitrary NCRelayStream (MitM upstream through a proxy, chain hops).
enum NCTLS12 {
    enum Suite: UInt16 {
        case ecdheECDSAAES128GCM = 0xc02b
        case ecdheRSAAES128GCM = 0xc02f
        case ecdheECDSAAES256GCM = 0xc02c
        case ecdheRSAAES256GCM = 0xc030
        case ecdheECDSAChaCha = 0xcca9
        case ecdheRSAChaCha = 0xcca8

        var hashKind: NCTLS13.HashKind {
            switch self {
            case .ecdheECDSAAES256GCM, .ecdheRSAAES256GCM: return .sha384
            default: return .sha256
            }
        }
        var keyLength: Int {
            switch self {
            case .ecdheECDSAAES128GCM, .ecdheRSAAES128GCM: return 16
            default: return 32
            }
        }
        var isChaCha: Bool { self == .ecdheECDSAChaCha || self == .ecdheRSAChaCha }
        /// GCM: 4-byte implicit salt (+ 8-byte explicit nonce per record); ChaCha: 12-byte IV.
        var fixedIVLength: Int { isChaCha ? 12 : 4 }
    }

    /// RFC 5246 §5 P_hash PRF.
    static func prf(_ kind: NCTLS13.HashKind, secret: Data, label: String, seed: Data, length: Int) -> Data {
        var labelSeed = Data(label.utf8)
        labelSeed.append(seed)
        var out = Data()
        out.reserveCapacity(length + kind.length)
        var a = labelSeed
        while out.count < length {
            a = kind.hmac(key: secret, a)
            out.append(kind.hmac(key: secret, a + labelSeed))
        }
        return Data(out.prefix(length))
    }

    struct Keys {
        var clientKey: Data, serverKey: Data, clientIV: Data, serverIV: Data
    }

    static func keyBlock(suite: Suite, master: Data, clientRandom: Data, serverRandom: Data) -> Keys {
        let k = suite.keyLength, iv = suite.fixedIVLength
        let block = prf(suite.hashKind, secret: master, label: "key expansion",
                        seed: serverRandom + clientRandom, length: 2 * k + 2 * iv)
        var i = block.startIndex
        func take(_ n: Int) -> Data { defer { i += n }; return Data(block[i..<(i + n)]) }
        let ck = take(k), sk = take(k), civ = take(iv), siv = take(iv)
        return Keys(clientKey: ck, serverKey: sk, clientIV: civ, serverIV: siv)
    }

    private static func aad(seq: UInt64, type: UInt8, length: Int) -> Data {
        var d = Data(capacity: 13)
        d.appendBE64(seq)
        d.append(type)
        d.appendBE16(0x0303)
        d.appendBE16(UInt16(length))
        return d
    }

    private static func chachaNonce(iv: Data, seq: UInt64) -> Data {
        var nonce = [UInt8](iv)
        for i in 0..<8 { nonce[4 + i] ^= UInt8(truncatingIfNeeded: seq >> (56 - 8 * UInt64(i))) }
        return Data(nonce)
    }

    /// Record payload (what follows the 5-byte header) for one plaintext fragment.
    static func seal(suite: Suite, key: Data, iv: Data, seq: UInt64, type: UInt8, plaintext: Data) -> Data? {
        let ad = aad(seq: seq, type: type, length: plaintext.count)
        if suite.isChaCha {
            guard let nonce = try? ChaChaPoly.Nonce(data: chachaNonce(iv: iv, seq: seq)),
                  let box = try? ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce,
                                                 authenticating: ad) else { return nil }
            return box.ciphertext + box.tag
        }
        var explicit = Data(capacity: 8)
        explicit.appendBE64(seq)
        guard let nonce = try? AES.GCM.Nonce(data: iv + explicit),
              let box = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce,
                                          authenticating: ad) else { return nil }
        return explicit + box.ciphertext + box.tag
    }

    static func open(suite: Suite, key: Data, iv: Data, seq: UInt64, type: UInt8, payload: Data) -> Data? {
        if suite.isChaCha {
            guard payload.count >= 16 else { return nil }
            let ct = payload.prefix(payload.count - 16), tag = payload.suffix(16)
            guard let nonce = try? ChaChaPoly.Nonce(data: chachaNonce(iv: iv, seq: seq)),
                  let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag) else { return nil }
            return try? ChaChaPoly.open(box, using: SymmetricKey(data: key),
                                        authenticating: aad(seq: seq, type: type, length: ct.count))
        }
        guard payload.count >= 24 else { return nil }
        let explicit = payload.prefix(8)
        let ct = payload.dropFirst(8).prefix(payload.count - 24), tag = payload.suffix(16)
        guard let nonce = try? AES.GCM.Nonce(data: iv + explicit),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag) else { return nil }
        return try? AES.GCM.open(box, using: SymmetricKey(data: key),
                                 authenticating: aad(seq: seq, type: type, length: ct.count))
    }

    /// Client half of the ECDHE exchange for the server's named curve: (public key bytes, shared secret).
    static func ecdhe(group: UInt16, serverPublic: Data) -> (Data, Data)? {
        switch group {
        case 0x001d:
            let priv = Curve25519.KeyAgreement.PrivateKey()
            guard let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.rawRepresentation, s.withUnsafeBytes { Data($0) })
        case 0x0017:
            let priv = P256.KeyAgreement.PrivateKey()
            guard let pub = try? P256.KeyAgreement.PublicKey(x963Representation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.x963Representation, s.withUnsafeBytes { Data($0) })
        case 0x0018:
            let priv = P384.KeyAgreement.PrivateKey()
            guard let pub = try? P384.KeyAgreement.PublicKey(x963Representation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.x963Representation, s.withUnsafeBytes { Data($0) })
        default:
            return nil
        }
    }

    /// TLS 1.2 certificate list: 3-byte total length, then 3-byte length + DER per certificate (no extensions).
    static func parseCertificates(_ body: Data) -> [Data] {
        let b = [UInt8](body)
        guard b.count >= 3 else { return [] }
        let total = Int(b[0]) << 16 | Int(b[1]) << 8 | Int(b[2])
        var idx = 3
        let end = min(b.count, 3 + total)
        var out: [Data] = []
        while idx + 3 <= end {
            let n = Int(b[idx]) << 16 | Int(b[idx + 1]) << 8 | Int(b[idx + 2]); idx += 3
            guard idx + n <= end else { break }
            out.append(Data(b[idx..<(idx + n)]))
            idx += n
        }
        return out
    }

    struct ServerKeyExchange {
        var group: UInt16
        var publicKey: Data
        var params: Data // curve_type .. public key, the signed part after the randoms
        var scheme: UInt16
        var signature: Data
    }

    static func parseServerKeyExchange(_ body: Data) -> ServerKeyExchange? {
        let b = [UInt8](body)
        guard b.count >= 4, b[0] == 3 else { return nil } // named_curve only
        let group = UInt16(b[1]) << 8 | UInt16(b[2])
        let pkLen = Int(b[3])
        guard b.count >= 4 + pkLen + 4 else { return nil }
        let pk = Data(b[4..<(4 + pkLen)])
        let params = Data(b[0..<(4 + pkLen)])
        var idx = 4 + pkLen
        let scheme = UInt16(b[idx]) << 8 | UInt16(b[idx + 1]); idx += 2
        let sigLen = Int(b[idx]) << 8 | Int(b[idx + 1]); idx += 2
        guard b.count >= idx + sigLen else { return nil }
        return ServerKeyExchange(group: group, publicKey: pk, params: params, scheme: scheme,
                                 signature: Data(b[idx..<(idx + sigLen)]))
    }

    /// ServerKeyExchange signature (RFC 5246 §7.4.3 + RFC 8422): ECDSA with any hash on the leaf's curve,
    /// RSA PKCS#1 v1.5, RSA-PSS (shared with the TLS 1.3 verifier).
    static func verifySignature(scheme: UInt16, cert: NCX509Certificate, content: Data, signature: Data) -> Bool {
        switch scheme {
        case 0x0804, 0x0805, 0x0806, 0x0807:
            return NCTLSVerify.certificateVerify(scheme: scheme, cert: cert, signedContent: content, signature: signature)
        case 0x0203, 0x0403, 0x0503, 0x0603:
            return verifyECDSA(scheme: scheme, cert: cert, content: content, signature: signature)
        case 0x0201, 0x0401, 0x0501, 0x0601:
            guard cert.publicKeyAlgorithm == .rsa else { return false }
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            ]
            guard let key = SecKeyCreateWithData(cert.publicKeyBytes as CFData, attributes as CFDictionary, nil) else {
                return false
            }
            let alg: SecKeyAlgorithm
            switch scheme {
            case 0x0201: alg = .rsaSignatureMessagePKCS1v15SHA1
            case 0x0401: alg = .rsaSignatureMessagePKCS1v15SHA256
            case 0x0501: alg = .rsaSignatureMessagePKCS1v15SHA384
            default: alg = .rsaSignatureMessagePKCS1v15SHA512
            }
            var error: Unmanaged<CFError>?
            return SecKeyVerifySignature(key, alg, content as CFData, signature as CFData, &error)
        default:
            return false
        }
    }

    private static func verifyECDSA(scheme: UInt16, cert: NCX509Certificate, content: Data, signature: Data) -> Bool {
        switch cert.publicKeyAlgorithm {
        case .ecP256:
            guard let pub = try? P256.Signing.PublicKey(x963Representation: cert.publicKeyBytes),
                  let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch scheme {
            case 0x0203: return pub.isValidSignature(sig, for: Insecure.SHA1.hash(data: content))
            case 0x0403: return pub.isValidSignature(sig, for: SHA256.hash(data: content))
            case 0x0503: return pub.isValidSignature(sig, for: SHA384.hash(data: content))
            default: return pub.isValidSignature(sig, for: SHA512.hash(data: content))
            }
        case .ecP384:
            guard let pub = try? P384.Signing.PublicKey(x963Representation: cert.publicKeyBytes),
                  let sig = try? P384.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch scheme {
            case 0x0203: return pub.isValidSignature(sig, for: Insecure.SHA1.hash(data: content))
            case 0x0403: return pub.isValidSignature(sig, for: SHA256.hash(data: content))
            case 0x0503: return pub.isValidSignature(sig, for: SHA384.hash(data: content))
            default: return pub.isValidSignature(sig, for: SHA512.hash(data: content))
            }
        default:
            return false
        }
    }
}

