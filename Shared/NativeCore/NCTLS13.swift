import Foundation
import CryptoKit
import Security

/// TLS 1.3 (RFC 8446) key schedule and primitives, plus the REALITY client
/// authentication math (aligned with Clash.Meta component/tls/reality, which
/// itself follows XTLS/REALITY). Pure value logic — the record/handshake
/// state machine lives in NCTLSClient.swift.
enum NCTLS13 {
    enum HashKind {
        case sha256, sha384

        var length: Int { self == .sha256 ? 32 : 48 }

        func hash(_ data: Data) -> Data {
            switch self {
            case .sha256: return Data(SHA256.hash(data: data))
            case .sha384: return Data(SHA384.hash(data: data))
            }
        }

        func hmac(key: Data, _ data: Data) -> Data {
            switch self {
            case .sha256:
                return HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)).withUnsafeBytes { Data($0) }
            case .sha384:
                return HMAC<SHA384>.authenticationCode(for: data, using: SymmetricKey(data: key)).withUnsafeBytes { Data($0) }
            }
        }
    }

    enum Suite: UInt16 {
        case aes128GCM = 0x1301
        case aes256GCM = 0x1302
        case chacha20 = 0x1303

        var hashKind: HashKind { self == .aes256GCM ? .sha384 : .sha256 }
        var keyLength: Int {
            switch self {
            case .aes128GCM: return 16
            case .aes256GCM, .chacha20: return 32
            }
        }
    }

    // MARK: HKDF (RFC 5869) over the suite hash

    static func hkdfExtract(_ kind: HashKind, salt: Data, ikm: Data) -> Data {
        kind.hmac(key: salt, ikm)
    }

    static func hkdfExpand(_ kind: HashKind, prk: Data, info: Data, length: Int) -> Data {
        var out = Data()
        var previous = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var input = previous
            input.append(info)
            input.append(counter)
            previous = kind.hmac(key: prk, input)
            out.append(previous)
            counter &+= 1
        }
        return Data(out.prefix(length))
    }

    static func expandLabel(_ kind: HashKind, secret: Data, label: String, context: Data, length: Int) -> Data {
        let fullLabel = Data("tls13 ".utf8) + Data(label.utf8)
        var info = Data()
        info.appendBE16(UInt16(length))
        info.append(UInt8(fullLabel.count))
        info.append(fullLabel)
        info.append(UInt8(context.count))
        info.append(context)
        return hkdfExpand(kind, prk: secret, info: info, length: length)
    }

    static func deriveSecret(_ kind: HashKind, secret: Data, label: String, transcriptHash: Data) -> Data {
        expandLabel(kind, secret: secret, label: label, context: transcriptHash, length: kind.length)
    }

    /// The full client-side schedule from the ECDHE shared secret and the two
    /// transcript checkpoints (ClientHello..ServerHello and ..server Finished).
    struct Schedule {
        let clientHandshakeSecret: Data
        let serverHandshakeSecret: Data
        let clientAppSecret: Data
        let serverAppSecret: Data

        init(kind: HashKind, ecdhe: Data, hashCHtoSH: Data, hashCHtoServerFinished: Data) {
            let zero = Data(repeating: 0, count: kind.length)
            let emptyHash = kind.hash(Data())
            let early = hkdfExtract(kind, salt: zero, ikm: zero)
            let derived1 = deriveSecret(kind, secret: early, label: "derived", transcriptHash: emptyHash)
            let handshake = hkdfExtract(kind, salt: derived1, ikm: ecdhe)
            clientHandshakeSecret = deriveSecret(kind, secret: handshake, label: "c hs traffic", transcriptHash: hashCHtoSH)
            serverHandshakeSecret = deriveSecret(kind, secret: handshake, label: "s hs traffic", transcriptHash: hashCHtoSH)
            let derived2 = deriveSecret(kind, secret: handshake, label: "derived", transcriptHash: emptyHash)
            let master = hkdfExtract(kind, salt: derived2, ikm: zero)
            clientAppSecret = deriveSecret(kind, secret: master, label: "c ap traffic", transcriptHash: hashCHtoServerFinished)
            serverAppSecret = deriveSecret(kind, secret: master, label: "s ap traffic", transcriptHash: hashCHtoServerFinished)
        }
    }

    static func trafficKeyIV(_ kind: HashKind, suite: Suite, secret: Data) -> (key: Data, iv: Data) {
        (expandLabel(kind, secret: secret, label: "key", context: Data(), length: suite.keyLength),
         expandLabel(kind, secret: secret, label: "iv", context: Data(), length: 12))
    }

    static func finishedVerifyData(_ kind: HashKind, trafficSecret: Data, transcriptHash: Data) -> Data {
        let key = expandLabel(kind, secret: trafficSecret, label: "finished", context: Data(), length: kind.length)
        return kind.hmac(key: key, transcriptHash)
    }

    static func updateTrafficSecret(_ kind: HashKind, secret: Data) -> Data {
        expandLabel(kind, secret: secret, label: "traffic upd", context: Data(), length: kind.length)
    }

    /// AEAD seal/open for one TLS record (nonce = IV XOR sequence).
    static func sealRecord(suite: Suite, key: Data, iv: Data, seq: UInt64, header: Data, plaintext: Data) -> Data? {
        let nonce = recordNonce(iv: iv, seq: seq)
        switch suite {
        case .aes128GCM, .aes256GCM:
            guard let n = try? AES.GCM.Nonce(data: nonce),
                  let box = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: header),
                  let combined = box.combined else { return nil }
            return Data(combined.dropFirst(12))
        case .chacha20:
            guard let n = try? ChaChaPoly.Nonce(data: nonce),
                  let box = try? ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: header) else { return nil }
            return Data(box.combined.dropFirst(12))
        }
    }

    static func openRecord(suite: Suite, key: Data, iv: Data, seq: UInt64, header: Data, sealed: Data) -> Data? {
        let nonce = recordNonce(iv: iv, seq: seq)
        var combined = nonce
        combined.append(sealed)
        switch suite {
        case .aes128GCM, .aes256GCM:
            guard let box = try? AES.GCM.SealedBox(combined: combined) else { return nil }
            return try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: header)
        case .chacha20:
            guard let box = try? ChaChaPoly.SealedBox(combined: combined) else { return nil }
            return try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: header)
        }
    }

    private static func recordNonce(iv: Data, seq: UInt64) -> Data {
        var nonce = iv
        for i in 0..<8 {
            nonce[nonce.count - 1 - i] ^= UInt8((seq >> UInt64(i * 8)) & 0xff)
        }
        return nonce
    }

    // MARK: REALITY

    struct RealityParams {
        let publicKey: Data // 32-byte X25519
        let shortID: Data // 0...8 bytes
    }

    /// authKey = HKDF-SHA256(ikm: X25519(clientPriv, serverPub),
    /// salt: clientRandom[0..<20], info: "REALITY"), 32 bytes out.
    static func realityAuthKey(clientPrivate: Curve25519.KeyAgreement.PrivateKey, serverPublic: Data, clientRandom: Data) -> Data? {
        guard let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublic),
              let shared = try? clientPrivate.sharedSecretFromKeyAgreement(with: pub) else { return nil }
        let sharedData = shared.withUnsafeBytes { Data($0) }
        let prk = hkdfExtract(.sha256, salt: Data(clientRandom.prefix(20)), ikm: sharedData)
        return hkdfExpand(.sha256, prk: prk, info: Data("REALITY".utf8), length: 32)
    }

    /// The 16 plaintext session-ID bytes REALITY seals into the hello:
    /// [1, 8, 2, 0] || BE32 unix time || shortID (zero-padded to 8).
    static func realitySessionIDPlain(shortID: Data, unixTime: UInt32) -> Data {
        var sid = Data([1, 8, 2, 0])
        sid.appendBE32(unixTime)
        var sidTail = Data(shortID.prefix(8))
        while sidTail.count < 8 { sidTail.append(0) }
        sid.append(sidTail)
        return sid
    }

    /// Seal the session ID exactly as the old core client does: AES-256-GCM with
    /// authKey, nonce = clientRandom[20..<32], AAD = the whole ClientHello
    /// handshake message with the session-ID field still zeroed.
    static func realitySealSessionID(authKey: Data, plain: Data, clientRandom: Data, aad: Data) -> Data? {
        let nonce = Data(clientRandom.suffix(12))
        guard let n = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.seal(plain, using: SymmetricKey(data: authKey), nonce: n, authenticating: aad),
              let combined = box.combined else { return nil }
        return Data(combined.dropFirst(12))
    }

    /// REALITY server proof: the leaf certificate's signature field equals
    /// HMAC-SHA512(authKey, leaf Ed25519 public key).
    static func realityVerifyLeaf(authKey: Data, leafDER: Data) -> Bool {
        guard let cert = NCX509Certificate(der: leafDER),
              cert.publicKeyAlgorithm == .ed25519,
              let signature = cert.signatureValue else { return false }
        let mac = HMAC<SHA512>.authenticationCode(for: cert.publicKeyBytes, using: SymmetricKey(data: authKey))
        return Data(mac) == signature
    }
}

/// A deliberately small X.509 reader: just enough to find the subject public
/// key info and the signature value of a certificate (no chain building —
/// that is SecTrust's job in the plain-TLS path).
struct NCX509Certificate {
    enum PublicKeyAlgorithm {
        case ed25519, rsa, ecP256, ecP384, unknown
    }

    let publicKeyAlgorithm: PublicKeyAlgorithm
    /// Raw public key bytes (Ed25519: 32 bytes; RSA: PKCS#1 DER; EC: x9.63 point).
    let publicKeyBytes: Data
    /// The certificate's signatureValue, without the BIT STRING header byte.
    let signatureValue: Data?

    init?(der: Data) {
        var reader = NCDERReader(data: der)
        guard let cert = reader.readTLV(), cert.tag == 0x30 else { return nil }
        var certReader = NCDERReader(data: cert.value)
        guard let tbs = certReader.readTLV(), tbs.tag == 0x30,
              let _ = certReader.readTLV(), // signature algorithm
              let sig = certReader.readTLV(), sig.tag == 0x03, sig.value.count > 1 else { return nil }
        signatureValue = Data(sig.value.dropFirst())
        var tbsReader = NCDERReader(data: tbs.value)
        // [0] version (optional), serial, alg, issuer, validity, subject, SPKI
        var fields: [(tag: UInt8, value: Data)] = []
        while let field = tbsReader.readTLV() { fields.append(field) }
        let spkiIndex = fields.first?.tag == 0xa0 ? 6 : 5
        guard fields.count > spkiIndex, fields[spkiIndex].tag == 0x30 else { return nil }
        var spkiReader = NCDERReader(data: fields[spkiIndex].value)
        guard let alg = spkiReader.readTLV(), alg.tag == 0x30,
              let keyBits = spkiReader.readTLV(), keyBits.tag == 0x03, keyBits.value.count > 1 else { return nil }
        var algReader = NCDERReader(data: alg.value)
        guard let oid = algReader.readTLV(), oid.tag == 0x06 else { return nil }
        let oidBytes = [UInt8](oid.value)
        publicKeyBytes = Data(keyBits.value.dropFirst())
        switch oidBytes {
        case [0x2b, 0x65, 0x70]: // 1.3.101.112 Ed25519
            publicKeyAlgorithm = .ed25519
        case [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]: // rsaEncryption
            publicKeyAlgorithm = .rsa
        case [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]: // ecPublicKey
            // params carry the curve OID
            if let curve = algReader.readTLV(), curve.tag == 0x06 {
                switch [UInt8](curve.value) {
                case [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]:
                    publicKeyAlgorithm = .ecP256
                case [0x2b, 0x81, 0x04, 0x00, 0x22]:
                    publicKeyAlgorithm = .ecP384
                default:
                    publicKeyAlgorithm = .unknown
                }
            } else {
                publicKeyAlgorithm = .unknown
            }
        default:
            publicKeyAlgorithm = .unknown
        }
    }
}

/// Minimal DER TLV walker.
struct NCDERReader {
    let data: Data
    var offset = 0

    mutating func readTLV() -> (tag: UInt8, value: Data)? {
        guard offset + 2 <= data.count else { return nil }
        let tag = data[offset]
        var idx = offset + 1
        var length = Int(data[idx])
        idx += 1
        if length & 0x80 != 0 {
            let count = length & 0x7f
            guard count >= 1, count <= 4, idx + count <= data.count else { return nil }
            length = 0
            for _ in 0..<count {
                length = length << 8 | Int(data[idx])
                idx += 1
            }
        }
        guard idx + length <= data.count else { return nil }
        let value = Data(data[idx..<(idx + length)])
        offset = idx + length
        return (tag, value)
    }
}

/// CertificateVerify signature checks (RFC 8446 §4.4.3): Ed25519 and ECDSA
/// through CryptoKit; RSA-PSS by hand (raw RSA public operation via
/// Security, then EMSA-PSS verification with MGF1) to control the exact PSS
/// parameters TLS mandates.
enum NCTLSVerify {
    static func certificateVerify(scheme: UInt16, cert: NCX509Certificate, signedContent: Data, signature: Data) -> Bool {
        switch scheme {
        case 0x0807: // ed25519
            guard cert.publicKeyAlgorithm == .ed25519,
                  let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: cert.publicKeyBytes) else { return false }
            return pub.isValidSignature(signature, for: signedContent)
        case 0x0403: // ecdsa_secp256r1_sha256
            guard cert.publicKeyAlgorithm == .ecP256,
                  let pub = try? P256.Signing.PublicKey(x963Representation: cert.publicKeyBytes),
                  let raw = derToRaw(signature, partLength: 32),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return pub.isValidSignature(sig, for: SHA256.hash(data: signedContent)) // digest overload (Data would hash again)
        case 0x0503: // ecdsa_secp384r1_sha384
            guard cert.publicKeyAlgorithm == .ecP384,
                  let pub = try? P384.Signing.PublicKey(x963Representation: cert.publicKeyBytes),
                  let raw = derToRaw(signature, partLength: 48),
                  let sig = try? P384.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return pub.isValidSignature(sig, for: SHA384.hash(data: signedContent))
        case 0x0804, 0x0805, 0x0806: // rsa_pss_rsae_sha256/384/512
            guard cert.publicKeyAlgorithm == .rsa else { return false }
            let kind: NCTLS13.HashKind = scheme == 0x0804 ? .sha256 : .sha384
            let digest: Data
            let saltLength: Int
            switch scheme {
            case 0x0804: digest = Data(SHA256.hash(data: signedContent)); saltLength = 32
            case 0x0805: digest = Data(SHA384.hash(data: signedContent)); saltLength = 48
            default:
                digest = Data(SHA512.hash(data: signedContent)); saltLength = 64
                return verifyPSS(cert: cert, digest: digest, signature: signature, hashKind: nil, saltLength: saltLength)
            }
            _ = kind
            return verifyPSS(cert: cert, digest: digest, signature: signature, hashKind: kind, saltLength: saltLength)
        default:
            return false
        }
    }

    private static func derToRaw(_ der: Data, partLength: Int) -> Data? {
        var reader = NCDERReader(data: der)
        guard let seq = reader.readTLV(), seq.tag == 0x30 else { return nil }
        var inner = NCDERReader(data: seq.value)
        guard let r = inner.readTLV(), r.tag == 0x02, let s = inner.readTLV(), s.tag == 0x02 else { return nil }
        func padded(_ value: Data) -> Data {
            var v = value
            while v.count > 1, v.first == 0, v.count > partLength { v = Data(v.dropFirst()) }
            while v.count < partLength { v = Data([0]) + v }
            return v
        }
        let out = padded(r.value) + padded(s.value)
        return out.count == partLength * 2 ? out : nil
    }

    /// EMSA-PSS verification: EM = RSA public op(signature); unmask with
    /// MGF1(hash), then H' must equal hash(00*8 || digest || salt).
    private static func verifyPSS(cert: NCX509Certificate, digest: Data, signature: Data, hashKind: NCTLS13.HashKind?, saltLength: Int) -> Bool {
        guard let em = rsaPublicOperation(publicKeyDER: cert.publicKeyBytes, input: signature) else { return false }
        let hashLength = digest.count
        let emBits = rsaModulusBits(publicKeyDER: cert.publicKeyBytes) - 1
        let emLen = (emBits + 7) / 8
        guard em.count >= emLen, em.suffix(emLen).last == 0xbc else { return false }
        let emBlock = Data(em.suffix(emLen))
        let maskedDB = emBlock.prefix(emLen - hashLength - 1)
        let h = emBlock[emLen - hashLength - 1..<emLen - 1]
        var dbMask = mgf1(seed: Data(h), length: maskedDB.count, hashLength: hashLength)
        var db = Data()
        for i in 0..<maskedDB.count { db.append(maskedDB[i] ^ dbMask[i]) }
        let unusedBits = 8 * emLen - emBits
        if unusedBits > 0 {
            db[0] &= UInt8(0xff >> unusedBits)
        }
        // DB must be 00...00 || 01 || salt
        var idx = 0
        while idx < db.count, db[idx] == 0 { idx += 1 }
        guard idx < db.count, db[idx] == 0x01 else { return false }
        let salt = Data(db[(idx + 1)...])
        guard salt.count == saltLength else { return false }
        var mPrime = Data(repeating: 0, count: 8)
        mPrime.append(digest)
        mPrime.append(salt)
        let hPrime: Data
        switch digest.count {
        case 32: hPrime = Data(SHA256.hash(data: mPrime))
        case 48: hPrime = Data(SHA384.hash(data: mPrime))
        case 64: hPrime = Data(SHA512.hash(data: mPrime))
        default: return false
        }
        return hPrime == Data(h)
    }

    private static func mgf1(seed: Data, length: Int, hashLength: Int) -> Data {
        var out = Data()
        var counter: UInt32 = 0
        while out.count < length {
            var input = seed
            input.appendBE32(counter)
            switch hashLength {
            case 32: out.append(Data(SHA256.hash(data: input)))
            case 48: out.append(Data(SHA384.hash(data: input)))
            default: out.append(Data(SHA512.hash(data: input)))
            }
            counter += 1
        }
        return Data(out.prefix(length))
    }

    /// Raw RSA public-key operation through Security (m^e mod n).
    private static func rsaPublicOperation(publicKeyDER: Data, input: Data) -> Data? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(publicKeyDER as CFData, attributes as CFDictionary, nil) else { return nil }
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateEncryptedData(key, .rsaEncryptionRaw, input as CFData, &error) else { return nil }
        return result as Data
    }

    private static func rsaModulusBits(publicKeyDER: Data) -> Int {
        var reader = NCDERReader(data: publicKeyDER)
        guard let seq = reader.readTLV(), seq.tag == 0x30 else { return 0 }
        var inner = NCDERReader(data: seq.value)
        guard let modulus = inner.readTLV(), modulus.tag == 0x02 else { return 0 }
        var bytes = modulus.value
        while bytes.count > 1, bytes.first == 0 { bytes = Data(bytes.dropFirst()) }
        var bits = bytes.count * 8
        if let first = bytes.first {
            var b = first
            while b & 0x80 == 0, b != 0 { bits -= 1; b <<= 1 }
        }
        return bits
    }
}

/// ClientHello shape variants for the `fingerprint` config key. These are
/// recognizable browser shapes (cipher/group/signature lists and a few
/// extension toggles), not byte-exact uTLS clones. The key share stays
/// X25519-only — that's the only group our handshake can actually use —
/// and the REALITY header layout (session ID at offset 39) is kept.
struct NCClientHelloProfile {
    let cipherSuites: [UInt16]
    let groups: [UInt16]
    let sigAlgs: [UInt16]
    let sct: Bool
    let sessionTicket: Bool
    let paddingTo512: Bool

    static let chrome = NCClientHelloProfile(
        cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
        groups: [0x001d, 0x0017, 0x0018],
        sigAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
        sct: true, sessionTicket: true, paddingTo512: true)
    static let firefox = NCClientHelloProfile(
        cipherSuites: [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
        groups: [0x001d, 0x0017, 0x0019, 0x0018, 0x0100, 0x0101],
        sigAlgs: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302],
        sct: true, sessionTicket: true, paddingTo512: false)
    static let safari = NCClientHelloProfile(
        cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc014, 0xc013, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a],
        groups: [0x001d, 0x0017, 0x0018],
        sigAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0203, 0x0201],
        sct: true, sessionTicket: false, paddingTo512: false)
    static let ios = NCClientHelloProfile(
        cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xc014, 0xc013],
        groups: [0x001d, 0x0017, 0x0018],
        sigAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
        sct: true, sessionTicket: false, paddingTo512: false)

    static func named(_ name: String?) -> NCClientHelloProfile {
        switch (name ?? "chrome").lowercased() {
        case "firefox": return .firefox
        case "safari": return .safari
        case "ios": return .ios
        case "random": return [.chrome, .firefox, .safari].randomElement() ?? .chrome
        default: return .chrome
        }
    }
}

extension NCTLS13 {
    /// Build the ClientHello handshake message (TLS 1.3 with an X25519
    /// key share). The session ID field starts at byte offset 39 —
    /// REALITY sealing depends on that exact layout.
    static func buildClientHello(random: Data, sessionID: Data, serverName: String, alpn: [String], keyShare: Data) -> Data {
        buildClientHello(random: random, sessionID: sessionID, serverName: serverName,
                         alpn: alpn, keyShare: keyShare, profile: .chrome)
    }

    static func buildClientHello(random: Data, sessionID: Data, serverName: String, alpn: [String],
                                 keyShare: Data, profile: NCClientHelloProfile) -> Data {
        buildClientHello(random: random, sessionID: sessionID, serverName: serverName,
                         alpn: alpn, keyShare: keyShare, profile: profile,
                         tls13Only: false, cookie: nil, extraExtensions: [])
    }

    static func buildClientHello(random: Data, sessionID: Data, serverName: String, alpn: [String],
                                 keyShare: Data, profile: NCClientHelloProfile,
                                 tls13Only: Bool = false, cookie: Data? = nil,
                                 extraExtensions: [(type: UInt16, data: Data)] = []) -> Data {
        var body = Data()
        body.appendBE16(0x0303) // legacy version
        body.append(random)
        body.append(UInt8(sessionID.count))
        body.append(sessionID)
        var suites = Data()
        for s in profile.cipherSuites {
            suites.appendBE16(s)
        }
        body.appendBE16(UInt16(suites.count))
        body.append(suites)
        body.append(contentsOf: [0x01, 0x00]) // compression: null only

        var exts = Data()
        func ext(_ type: UInt16, _ payload: Data) {
            exts.appendBE16(type)
            exts.appendBE16(UInt16(payload.count))
            exts.append(payload)
        }
        var sni = Data()
        // u16 lengths on the wire: NCTLSClient rejects a server name past 255 bytes (DNS max 253) before building;
        // the prefix only keeps this builder trap-free for any caller.
        let name = Data(serverName.utf8.prefix(255))
        sni.appendBE16(UInt16(name.count + 3))
        sni.append(0x00)
        sni.appendBE16(UInt16(name.count))
        sni.append(name)
        ext(0, sni)
        var groups = Data()
        groups.appendBE16(UInt16(profile.groups.count * 2))
        for g in profile.groups { groups.appendBE16(g) }
        ext(10, groups)
        ext(11, Data([0x03, 0x00, 0x01, 0x02]))
        var sigs = Data()
        sigs.appendBE16(UInt16(profile.sigAlgs.count * 2))
        for s in profile.sigAlgs { sigs.appendBE16(s) }
        ext(13, sigs)
        var alpnData = Data()
        var protocols = Data()
        for p in alpn {
            let name = Array(p.utf8.prefix(255)) // u8 length on the wire (config value; never trap)
            guard !name.isEmpty else { continue }
            // The ALPN list has a u16 length and the whole hello must stay well under 64 KB: a config with
            // hundreds of long entries would trap in UInt16(protocols.count) / UInt16(body.count). Extra
            // entries past 1 KB are dropped (real lists are a few bytes).
            guard protocols.count + 1 + name.count <= 1024 else { break }
            protocols.append(UInt8(name.count))
            protocols.append(contentsOf: name)
        }
        // An empty ALPN list is illegal on the wire (RFC 7301 §3.1): no protocols → no extension
        // (nc-tls-parity: vmess/vless over plain tcp offer none, like Clash.Meta / the system TLS path).
        if !protocols.isEmpty {
            alpnData.appendBE16(UInt16(protocols.count))
            alpnData.append(protocols)
            ext(16, alpnData)
        }
        if let cookie, !cookie.isEmpty {
            ext(extensionCookie, cookie)
        }
        ext(5, Data([0x01, 0x00, 0x00, 0x00, 0x00]))
        if profile.sct { ext(18, Data()) }
        ext(23, Data())
        if profile.sessionTicket { ext(35, Data()) }
        if tls13Only {
            ext(43, Data([0x02, 0x03, 0x04]))
        } else {
            // supported_versions: u8 list length 4 = TLS 1.3, TLS 1.2. Was 0x03 (odd length) since 6bcf716: the old core
            // crypto/tls answers decode_error (alert 50) — every non-ECH native-TLS hello was malformed. Fixed twice
            // independently (feat/nc-naive-h2h3 15a5f62, fix/nc-ech-rest b805b96); this is the single implementation.
            ext(43, Data([0x04, 0x03, 0x04, 0x03, 0x03]))
        }
        ext(45, Data([0x01, 0x01]))
        var share = Data()
        share.appendBE16(UInt16(keyShare.count + 4))
        share.appendBE16(0x001d)
        share.appendBE16(UInt16(keyShare.count))
        share.append(keyShare)
        ext(51, share)
        for (extType, extPayload) in extraExtensions {
            ext(extType, extPayload)
        }

        body.appendBE16(UInt16(exts.count))
        body.append(exts)

        var message = Data()
        message.append(0x01) // client_hello
        message.append(0x00)
        message.appendBE16(UInt16(body.count))
        message.append(body)

        // Chrome-style padding to at least 512 bytes of handshake message.
        if profile.paddingTo512 && message.count < 512 {
            let padLen = 512 - message.count - 4
            if padLen > 0 {
                var exts2 = exts
                exts2.appendBE16(21)
                exts2.appendBE16(UInt16(padLen))
                exts2.append(Data(repeating: 0, count: padLen))
                var body2 = Data()
                let extStart = body.count - exts.count - 2
                body2.append(body.prefix(extStart))
                body2.appendBE16(UInt16(exts2.count))
                body2.append(exts2)
                var message2 = Data()
                message2.append(0x01)
                message2.append(0x00)
                message2.appendBE16(UInt16(body2.count))
                message2.append(body2)
                return message2
            }
        }
        return message
    }

    // MARK: - RFC 9849 Encrypted Client Hello (ECH)

    /// RFC 8446 §4.1.3: Special HelloRetryRequest random value.
    static let helloRetryRequestRandom = Data([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ])

    /// RFC 9849 §5: Extension type for encrypted_client_hello (0xfe0d).
    static let extensionECH: UInt16 = 0xfe0d
    /// RFC 8446 §4.2.2: Extension type for cookie (44).
    static let extensionCookie: UInt16 = 44
    /// RFC 9849 §10.5: Alert description for ech_required (121).
    static let alertECHRequired: UInt8 = 121

    /// RFC 9849 §6.1: Build ClientHelloInner handshake message.
    /// - Real serverName (SNI) and real ALPN.
    /// - TLS 1.3 only (MUST NOT offer TLS 1.2 or below, RFC 9849 §6.1 rule 1).
    /// - Inner encrypted_client_hello extension (type 0xfe0d, payload 0x01, RFC 9849 §5).
    static func buildClientHelloInner(
        random: Data,
        sessionID: Data,
        serverName: String,
        alpn: [String],
        keyShare: Data,
        profile: NCClientHelloProfile = .chrome,
        cookie: Data? = nil
    ) -> Data {
        let innerECHPayload = Data([0x01])
        return buildClientHello(
            random: random,
            sessionID: sessionID,
            serverName: serverName,
            alpn: alpn,
            keyShare: keyShare,
            profile: profile,
            tls13Only: true,
            cookie: cookie,
            extraExtensions: [(extensionECH, innerECHPayload)]
        )
    }

    /// RFC 9849 §5.1 & §6.1.3: Constructs EncodedClientHelloInner from ClientHelloInner.
    ///
    /// Steps:
    /// 1. Strip the 4-byte Handshake header (RFC 9849 §5.1).
    /// 2. Set legacy_session_id to empty (length 0, RFC 9849 §5.1).
    /// 3. Add deterministic padding based on maximum_name_length and SNI (RFC 9849 §6.1.3):
    ///    - If SNI present: padSNI = max(0, M - len(SNI))
    ///    - If SNI absent: padSNI = M + 9
    ///    - Total length L = len(client_hello) + padSNI
    ///    - N = 31 - ((L - 1) % 32)
    ///    - Total zeros = padSNI + N (rounds EncodedClientHelloInner up to a multiple of 32 bytes).
    static func encodeInnerClientHello(
        innerHello: Data,
        serverName: String,
        maximumNameLength: UInt8
    ) -> Data {
        guard innerHello.count >= 4 else { return innerHello }
        let body = innerHello.dropFirst(4) // Strip Handshake header
        guard body.count >= 35 else { return Data(body) }

        // Body starts with: legacy_version (2) + random (32) + legacy_session_id (1 + sidLen)
        let sidLen = Int(body[body.startIndex + 34])
        guard body.count >= 35 + sidLen else { return Data(body) }

        var unpaddedInner = Data()
        unpaddedInner.append(body[body.startIndex..<body.startIndex + 34])
        unpaddedInner.append(0x00) // Empty legacy_session_id (1 byte of length = 0)
        unpaddedInner.append(body[(body.startIndex + 35 + sidLen)...])

        // RFC 9849 §6.1.3 Recommended Padding Scheme:
        let m = Int(maximumNameLength)
        let padSNI: Int
        if !serverName.isEmpty {
            padSNI = max(0, m - serverName.utf8.count)
        } else {
            padSNI = m + 9
        }
        let l = unpaddedInner.count + padSNI
        let n = l > 0 ? (31 - ((l - 1) % 32)) : 0
        let totalPadding = padSNI + n

        var encoded = unpaddedInner
        encoded.append(Data(repeating: 0, count: totalPadding))
        return encoded
    }

    /// RFC 9849 §5: Builds outer encrypted_client_hello extension payload.
    ///
    /// Layout:
    /// - type: uint8 = 0 (outer)
    /// - cipher_suite: uint16 kdf_id, uint16 aead_id
    /// - config_id: uint8
    /// - enc: opaque<0..2^16-1> (uint16 length + bytes; empty on HRR)
    /// - payload: opaque<1..2^16-1> (uint16 length + bytes)
    static func buildOuterECHExtensionData(
        configID: UInt8,
        kdfID: UInt16,
        aeadID: UInt16,
        enc: Data,
        payload: Data
    ) -> Data {
        var d = Data()
        d.append(0x00) // outer(0)
        d.appendBE16(kdfID)
        d.appendBE16(aeadID)
        d.append(configID)
        d.appendBE16(UInt16(enc.count))
        d.append(enc)
        d.appendBE16(UInt16(payload.count))
        d.append(payload)
        return d
    }

    /// RFC 9849 §6.1.1: Constructs ClientHelloOuter encrypting EncodedClientHelloInner.
    ///
    /// 1. Determines ciphertext length L = encodedInner.count + 16 (tag length).
    /// 2. Assembles ClientHelloOuter with placeholder outer ECH extension (payload of L zeros).
    /// 3. Extracts ClientHelloOuterAAD = outerHello[4:] (without 4-byte Handshake header, RFC 9849 §5.2).
    /// 4. Computes final_payload = context.seal(aad: outerAAD, plaintext: encodedInner).
    /// 5. Substitutes placeholder ECH extension with final ECH extension.
    static func buildClientHelloOuter(
        outerRandom: Data,
        sessionID: Data,
        publicName: String,
        alpn: [String],
        keyShare: Data,
        profile: NCClientHelloProfile = .chrome,
        cookie: Data? = nil,
        selectedConfig: NCECHSelectedConfig,
        enc: Data,
        hpkeContext: NCHPKEContextS,
        encodedInner: Data
    ) throws -> Data {
        let ciphertextLen = encodedInner.count + 16 // AEAD tag length is 16 bytes for AES-GCM / ChaChaPoly
        let placeholderExtData = buildOuterECHExtensionData(
            configID: selectedConfig.config.configID,
            kdfID: selectedConfig.cipherSuite.kdfID,
            aeadID: selectedConfig.cipherSuite.aeadID,
            enc: enc,
            payload: Data(repeating: 0, count: ciphertextLen)
        )

        let outerWithPlaceholder = buildClientHello(
            random: outerRandom,
            sessionID: sessionID,
            serverName: publicName,
            alpn: alpn,
            keyShare: keyShare,
            profile: profile,
            tls13Only: true,
            cookie: cookie,
            extraExtensions: [(extensionECH, placeholderExtData)]
        )

        guard outerWithPlaceholder.count >= 4 else {
            throw NCHPKEError.validationError("Malformed outer ClientHello")
        }
        // RFC 9849 §5.2: ClientHelloOuterAAD is the serialized ClientHello without the 4-byte Handshake header
        let outerAAD = Data(outerWithPlaceholder.dropFirst(4))
        let ciphertext = try hpkeContext.seal(aad: outerAAD, plaintext: encodedInner)

        let finalExtData = buildOuterECHExtensionData(
            configID: selectedConfig.config.configID,
            kdfID: selectedConfig.cipherSuite.kdfID,
            aeadID: selectedConfig.cipherSuite.aeadID,
            enc: enc,
            payload: ciphertext
        )

        guard let range = outerWithPlaceholder.range(of: placeholderExtData) else {
            throw NCHPKEError.validationError("Failed to locate ECH placeholder in ClientHelloOuter")
        }

        var finalOuter = outerWithPlaceholder
        finalOuter.replaceSubrange(range, with: finalExtData)
        return finalOuter
    }

    /// RFC 9849 §7.2: Computes accept_confirmation for ServerHello.
    ///
    /// 1. Replace last 8 bytes of ServerHello.random with 8 zeros.
    /// 2. Compute transcript hash of innerTranscript + modifiedServerHello.
    /// 3. prk = HKDF-Extract(0, ClientHelloInner.random)
    /// 4. accept_confirmation = HKDF-Expand-Label(prk, "ech accept confirmation", transcriptHash, 8)
    static func computeAcceptConfirmation(
        kind: HashKind,
        innerTranscript: Data,
        serverHello: Data,
        innerRandom: Data
    ) -> Data? {
        guard serverHello.count >= 38 else { return nil }
        var modified = serverHello
        // In ServerHello handshake message: 4 header + 2 version + 24 random prefix = offset 30
        modified.replaceSubrange(30..<38, with: [UInt8](repeating: 0, count: 8))

        var confTranscript = innerTranscript
        confTranscript.append(modified)
        let transcriptConf = kind.hash(confTranscript)

        let zeroSalt = Data(repeating: 0, count: kind.length)
        let prk = hkdfExtract(kind, salt: zeroSalt, ikm: innerRandom)
        return expandLabel(kind, secret: prk, label: "ech accept confirmation", context: transcriptConf, length: 8)
    }

    /// RFC 9849 §7.2.1: Computes hrr_accept_confirmation for HelloRetryRequest.
    ///
    /// 1. Replace 8-byte payload of encrypted_client_hello extension in HRR with 8 zeros.
    /// 2. Compute transcript hash of innerTranscript + modifiedHRR.
    /// 3. prk = HKDF-Extract(0, ClientHelloInner1.random)
    /// 4. hrr_accept_confirmation = HKDF-Expand-Label(prk, "hrr ech accept confirmation", transcriptHash, 8)
    static func computeHRRAcceptConfirmation(
        kind: HashKind,
        innerTranscript: Data,
        hrrMessage: Data,
        hrrECHPayload: Data,
        innerRandom: Data
    ) -> Data? {
        guard hrrECHPayload.count == 8 else { return nil }
        let range: Range<Data.Index>
        // Review #152 item 6: only the parsed extension offset — a byte search could hit random/cookie first.
        if let found = locateECHExtensionPayload(inHRR: hrrMessage) {
            range = found
        } else {
            return nil
        }
        var modified = hrrMessage
        modified.replaceSubrange(range, with: [UInt8](repeating: 0, count: 8))

        var confTranscript = innerTranscript
        confTranscript.append(modified)
        let transcriptConf = kind.hash(confTranscript)

        let zeroSalt = Data(repeating: 0, count: kind.length)
        let prk = hkdfExtract(kind, salt: zeroSalt, ikm: innerRandom)
        return expandLabel(kind, secret: prk, label: "hrr ech accept confirmation", context: transcriptConf, length: 8)
    }

    /// Locates the 8-byte payload range of the ECH extension (0xfe0d) in a HelloRetryRequest message.
    static func locateECHExtensionPayload(inHRR message: Data) -> Range<Data.Index>? {
        guard message.count >= 4 else { return nil }
        let body = message.dropFirst(4)
        guard body.count >= 34 else { return nil }
        var idx = body.startIndex + 34
        guard body.count > (idx - body.startIndex) else { return nil }
        let sidLen = Int(body[idx]); idx += 1 + sidLen
        guard body.count >= (idx - body.startIndex) + 3 else { return nil }
        idx += 2 // cipher suite
        idx += 1 // compression
        guard body.count >= (idx - body.startIndex) + 2 else { return nil }
        let extLen = Int(body[idx]) << 8 | Int(body[idx + 1]); idx += 2
        let extEnd = min(body.endIndex, idx + extLen)
        while idx + 4 <= extEnd {
            let extType = UInt16(body[idx]) << 8 | UInt16(body[idx + 1])
            let extSize = Int(body[idx + 2]) << 8 | Int(body[idx + 3])
            idx += 4
            guard idx + extSize <= extEnd else { return nil }
            if extType == extensionECH, extSize == 8 {
                return idx..<(idx + 8)
            }
            idx += extSize
        }
        return nil
    }

    /// RFC 8446 §4.3.1 & RFC 9849 §5: Parses retry_configs (extension 0xfe0d) from an EncryptedExtensions message.
    static func parseRetryConfigs(fromEncryptedExtensions message: Data) -> Data? {
        guard message.count >= 6 else { return nil }
        guard message[message.startIndex] == 8 else { return nil } // Handshake type 8 = EncryptedExtensions
        // 4 header bytes + 2 extensions length bytes
        let extsLen = Int(message[message.startIndex + 4]) << 8 | Int(message[message.startIndex + 5])
        guard message.count >= 6 + extsLen else { return nil }
        let extsData = message.subdata(in: (message.startIndex + 6)..<(message.startIndex + 6 + extsLen))
        return parseExtension(type: extensionECH, fromExtensionsData: extsData)
    }

    /// RFC 8446 §4.4.1: Synthetic message_hash handshake message for HelloRetryRequest transcript.
    /// Type: 254 (0xfe), length: uint24 = kind.length, payload: Hash(ClientHello1).
    static func syntheticMessageHash(for clientHello: Data, kind: HashKind) -> Data {
        let h = kind.hash(clientHello)
        var msg = Data([0xfe, 0x00, 0x00, UInt8(h.count)])
        msg.append(h)
        return msg
    }

    /// Locates an extension by type in a handshake message body or extension block.
    static func parseExtension(type: UInt16, fromExtensionsData exts: Data) -> Data? {
        var idx = 0
        while idx + 4 <= exts.count {
            let extType = UInt16(exts[idx]) << 8 | UInt16(exts[idx + 1])
            let extLen = Int(exts[idx + 2]) << 8 | Int(exts[idx + 3])
            idx += 4
            guard idx + extLen <= exts.count else { return nil }
            if extType == type {
                return exts.subdata(in: idx..<idx + extLen)
            }
            idx += extLen
        }
        return nil
    }

    // MARK: - ClientHello Parsing and Derivation (RFC 8446 §4.1.4 & RFC 9849 §6.1.5)

    struct ParsedClientHello {
        var prefix: Data // bytes from legacy_version up to before extensions length
        var extensions: [(type: UInt16, data: Data)]
    }

    /// Parses a complete ClientHello handshake message into prefix and extensions list.
    static func parseClientHello(_ hello: Data) -> ParsedClientHello? {
        guard hello.count >= 4 else { return nil }
        let body = Data(hello.dropFirst(4))
        // legacy_version (2) + random (32) = 34 bytes
        guard body.count >= 34 else { return nil }
        var idx = 34
        guard body.count > idx else { return nil }
        let sidLen = Int(body[idx]); idx += 1 + sidLen
        guard body.count >= idx + 2 else { return nil }
        let csLen = Int(body[idx]) << 8 | Int(body[idx + 1]); idx += 2 + csLen
        guard body.count >= idx + 1 else { return nil }
        let compLen = Int(body[idx]); idx += 1 + compLen
        guard body.count >= idx + 2 else { return nil }
        let prefix = body.subdata(in: 0..<idx)
        let extsLen = Int(body[idx]) << 8 | Int(body[idx + 1]); idx += 2
        let extsEnd = idx + extsLen
        guard body.count >= extsEnd else { return nil }

        var exts: [(type: UInt16, data: Data)] = []
        while idx + 4 <= extsEnd {
            let extType = UInt16(body[idx]) << 8 | UInt16(body[idx + 1])
            let extSize = Int(body[idx + 2]) << 8 | Int(body[idx + 3])
            idx += 4
            guard idx + extSize <= extsEnd else { return nil }
            let extData = body.subdata(in: idx..<idx + extSize)
            exts.append((type: extType, data: extData))
            idx += extSize
        }
        return ParsedClientHello(prefix: prefix, extensions: exts)
    }

    /// Assembles a complete ClientHello handshake message from prefix and extensions list.
    static func assembleClientHello(prefix: Data, extensions: [(type: UInt16, data: Data)]) -> Data {
        var extsData = Data()
        for ext in extensions {
            extsData.appendBE16(ext.type)
            extsData.appendBE16(UInt16(ext.data.count))
            extsData.append(ext.data)
        }
        var body = prefix
        body.appendBE16(UInt16(extsData.count))
        body.append(extsData)

        var msg = Data()
        msg.append(0x01) // Handshake type: ClientHello
        let bodyCount = body.count
        msg.append(UInt8((bodyCount >> 16) & 0xff))
        msg.append(UInt8((bodyCount >> 8) & 0xff))
        msg.append(UInt8(bodyCount & 0xff))
        msg.append(body)
        return msg
    }

    /// RFC 8446 §4.1.4 & RFC 9849 §6.1.5: Derives ClientHelloInner2 from ClientHelloInner1 on HRR.
    /// Only RFC-allowed modifications are applied:
    /// - Adds cookie extension if provided by HRR.
    /// - Updates key_share extension if keyShare is provided (for HRR selected_group).
    /// - All other extensions, random, session_id, and cipher suites remain byte-identical to CH1.
    static func deriveClientHelloInner2(
        from inner1: Data,
        cookie: Data?,
        keyShare: Data? = nil
    ) -> Data? {
        guard let parsed = parseClientHello(inner1) else { return nil }
        var updatedExts = parsed.extensions

        if let keyShare {
            var shareData = Data()
            shareData.appendBE16(UInt16(keyShare.count + 4))
            shareData.appendBE16(0x001d) // X25519
            shareData.appendBE16(UInt16(keyShare.count))
            shareData.append(keyShare)
            if let idx = updatedExts.firstIndex(where: { $0.type == 51 }) {
                updatedExts[idx] = (type: 51, data: shareData)
            } else {
                updatedExts.append((type: 51, data: shareData))
            }
        }

        if let cookie, !cookie.isEmpty {
            if let idx = updatedExts.firstIndex(where: { $0.type == extensionCookie }) {
                updatedExts[idx] = (type: extensionCookie, data: cookie)
            } else {
                if let ksIdx = updatedExts.firstIndex(where: { $0.type == 51 }) {
                    updatedExts.insert((type: extensionCookie, data: cookie), at: ksIdx)
                } else {
                    updatedExts.append((type: extensionCookie, data: cookie))
                }
            }
        }

        return assembleClientHello(prefix: parsed.prefix, extensions: updatedExts)
    }

    /// RFC 9849 §6.1.5 & RFC 8446 §4.1.4: Derives ClientHelloOuter2 from ClientHelloOuter1 on HRR.
    /// - Encrypts encodedInner2 with empty enc and next HPKE sequence number.
    /// - Adds cookie if provided.
    /// - Updates key_share if provided.
    /// - Preserves outerRandom, session_id, cipher suites, and other extensions byte-identical to CH1.
    static func deriveClientHelloOuter2(
        from outer1: Data,
        cookie: Data?,
        keyShare: Data? = nil,
        selectedConfig: NCECHSelectedConfig,
        hpkeContext: NCHPKEContextS,
        encodedInner2: Data
    ) throws -> Data {
        guard let parsed = parseClientHello(outer1) else {
            throw NCHPKEError.validationError("Failed to parse ClientHelloOuter1")
        }
        var updatedExts = parsed.extensions

        if let keyShare {
            var shareData = Data()
            shareData.appendBE16(UInt16(keyShare.count + 4))
            shareData.appendBE16(0x001d)
            shareData.appendBE16(UInt16(keyShare.count))
            shareData.append(keyShare)
            if let idx = updatedExts.firstIndex(where: { $0.type == 51 }) {
                updatedExts[idx] = (type: 51, data: shareData)
            } else {
                updatedExts.append((type: 51, data: shareData))
            }
        }

        if let cookie, !cookie.isEmpty {
            if let idx = updatedExts.firstIndex(where: { $0.type == extensionCookie }) {
                updatedExts[idx] = (type: extensionCookie, data: cookie)
            } else {
                if let ksIdx = updatedExts.firstIndex(where: { $0.type == 51 }) {
                    updatedExts.insert((type: extensionCookie, data: cookie), at: ksIdx)
                } else {
                    updatedExts.append((type: extensionCookie, data: cookie))
                }
            }
        }

        // RFC 9849 §6.1.5: Outer ECH extension with empty enc and placeholder ciphertext
        let ciphertextLen = encodedInner2.count + 16
        let placeholderExtData = buildOuterECHExtensionData(
            configID: selectedConfig.config.configID,
            kdfID: selectedConfig.cipherSuite.kdfID,
            aeadID: selectedConfig.cipherSuite.aeadID,
            enc: Data(), // RFC 9849 §6.1.5: empty enc on HRR
            payload: Data(repeating: 0, count: ciphertextLen)
        )

        guard let echIdx = updatedExts.firstIndex(where: { $0.type == extensionECH }) else {
            throw NCHPKEError.validationError("Outer ECH extension not found in ClientHelloOuter1")
        }
        updatedExts[echIdx] = (type: extensionECH, data: placeholderExtData)

        let outerWithPlaceholder = assembleClientHello(prefix: parsed.prefix, extensions: updatedExts)
        guard outerWithPlaceholder.count >= 4 else {
            throw NCHPKEError.validationError("Malformed outer ClientHello2")
        }
        let outerAAD = Data(outerWithPlaceholder.dropFirst(4))
        let ciphertext = try hpkeContext.seal(aad: outerAAD, plaintext: encodedInner2)

        let finalExtData = buildOuterECHExtensionData(
            configID: selectedConfig.config.configID,
            kdfID: selectedConfig.cipherSuite.kdfID,
            aeadID: selectedConfig.cipherSuite.aeadID,
            enc: Data(),
            payload: ciphertext
        )
        updatedExts[echIdx] = (type: extensionECH, data: finalExtData)

        return assembleClientHello(prefix: parsed.prefix, extensions: updatedExts)
    }
}
