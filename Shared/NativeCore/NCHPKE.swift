import Foundation
import CryptoKit

/// RFC 9180: Hybrid Public Key Encryption (HPKE) Base Mode (mode_base = 0x00).
///
/// Implemented entirely using CryptoKit primitives (Curve25519, HKDF, HMAC, SHA256,
/// AES.GCM, ChaChaPoly) without calling CryptoKit HPKE APIs (which require iOS 17+),
/// maintaining compatibility with the iOS 16.0 deployment target.
///
/// Supported Algorithms:
/// - KEM:  0x0020 DHKEM(X25519, HKDF-SHA256)
/// - KDF:  0x0001 HKDF-SHA256
/// - AEAD: 0x0001 AES-128-GCM, 0x0002 AES-256-GCM, 0x0003 ChaCha20Poly1305, 0xFFFF Export-Only

public enum NCHPKEError: Error, LocalizedError, Equatable {
    case validationError(String)
    case deserializeError(String)
    case encapError(String)
    case decapError(String)
    case openError(String)
    case messageLimitReached
    case unsupportedKEM(UInt16)
    case unsupportedKDF(UInt16)
    case unsupportedAEAD(UInt16)
    case invalidCiphertext

    public var errorDescription: String? {
        switch self {
        case .validationError(let msg): return "HPKE validation error: \(msg)"
        case .deserializeError(let msg): return "HPKE deserialize error: \(msg)"
        case .encapError(let msg): return "HPKE encap error: \(msg)"
        case .decapError(let msg): return "HPKE decap error: \(msg)"
        case .openError(let msg): return "HPKE open error: \(msg)"
        case .messageLimitReached: return "HPKE message sequence limit reached"
        case .unsupportedKEM(let id): return "Unsupported HPKE KEM id: 0x\(String(id, radix: 16))"
        case .unsupportedKDF(let id): return "Unsupported HPKE KDF id: 0x\(String(id, radix: 16))"
        case .unsupportedAEAD(let id): return "Unsupported HPKE AEAD id: 0x\(String(id, radix: 16))"
        case .invalidCiphertext: return "HPKE invalid ciphertext"
        }
    }
}

public enum NCHPKESuite {
    /// RFC 9180 §7.1 Table 2
    public enum KEM: UInt16, CaseIterable, Equatable, Sendable {
        case dhkemX25519HKDFSHA256 = 0x0020

        public var nSecret: Int { 32 }
        public var nEnc: Int { 32 }
        public var nPk: Int { 32 }
        public var nSk: Int { 32 }
        public var nDh: Int { 32 }

        public var kemSuiteID: Data {
            var d = Data("KEM".utf8)
            d.append(UInt8((rawValue >> 8) & 0xff))
            d.append(UInt8(rawValue & 0xff))
            return d
        }
    }

    /// RFC 9180 §7.2 Table 3
    public enum KDF: UInt16, CaseIterable, Equatable, Sendable {
        case hkdfSHA256 = 0x0001

        public var nH: Int { 32 }
    }

    /// RFC 9180 §7.3 Table 5
    public enum AEAD: UInt16, CaseIterable, Equatable, Sendable {
        case aes128GCM = 0x0001
        case aes256GCM = 0x0002
        case chaCha20Poly1305 = 0x0003
        case exportOnly = 0xFFFF

        public var keyLength: Int {
            switch self {
            case .aes128GCM: return 16
            case .aes256GCM: return 32
            case .chaCha20Poly1305: return 32
            case .exportOnly: return 0
            }
        }

        public var nonceLength: Int {
            switch self {
            case .aes128GCM, .aes256GCM, .chaCha20Poly1305: return 12
            case .exportOnly: return 0
            }
        }

        public var tagLength: Int {
            switch self {
            case .aes128GCM, .aes256GCM, .chaCha20Poly1305: return 16
            case .exportOnly: return 0
            }
        }
    }
}

/// An HPKE cipher suite combining KEM, KDF, and AEAD identifiers.
public struct NCHPKECipherSuite: Equatable, Sendable {
    public let kem: NCHPKESuite.KEM
    public let kdf: NCHPKESuite.KDF
    public let aead: NCHPKESuite.AEAD

    public init(kem: NCHPKESuite.KEM = .dhkemX25519HKDFSHA256, kdf: NCHPKESuite.KDF = .hkdfSHA256, aead: NCHPKESuite.AEAD) {
        self.kem = kem
        self.kdf = kdf
        self.aead = aead
    }

    /// RFC 9180 §5.1: suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
    public var hpkeSuiteID: Data {
        var d = Data("HPKE".utf8)
        d.append(UInt8((kem.rawValue >> 8) & 0xff))
        d.append(UInt8(kem.rawValue & 0xff))
        d.append(UInt8((kdf.rawValue >> 8) & 0xff))
        d.append(UInt8(kdf.rawValue & 0xff))
        d.append(UInt8((aead.rawValue >> 8) & 0xff))
        d.append(UInt8(aead.rawValue & 0xff))
        return d
    }
}

/// Context for sender encryption (ContextS).
public final class NCHPKEContextS {
    public let suite: NCHPKECipherSuite
    public let key: Data
    public let baseNonce: Data
    public let exporterSecret: Data
    public var seq: UInt64

    public init(suite: NCHPKECipherSuite, key: Data, baseNonce: Data, exporterSecret: Data, seq: UInt64 = 0) {
        self.suite = suite
        self.key = key
        self.baseNonce = baseNonce
        self.exporterSecret = exporterSecret
        self.seq = seq
    }

    /// RFC 9180 §5.2: ContextS.Seal(aad, pt)
    public func seal(aad: Data = Data(), plaintext: Data, seq explicitSeq: UInt64? = nil) throws -> Data {
        guard suite.aead != .exportOnly else {
            throw NCHPKEError.unsupportedAEAD(suite.aead.rawValue)
        }
        let currentSeq = explicitSeq ?? seq
        let nonce = NCHPKE.computeNonce(baseNonce: baseNonce, seq: currentSeq)

        if explicitSeq == nil {
            if seq == UInt64.max { throw NCHPKEError.messageLimitReached }
            seq += 1
        } else {
            seq = max(seq, currentSeq + 1)
        }

        switch suite.aead {
        case .aes128GCM, .aes256GCM:
            let symKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(plaintext, using: symKey, nonce: gcmNonce, authenticating: aad)
            var ct = sealed.ciphertext
            ct.append(sealed.tag)
            return ct
        case .chaCha20Poly1305:
            let symKey = SymmetricKey(data: key)
            let chaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.seal(plaintext, using: symKey, nonce: chaNonce, authenticating: aad)
            var ct = sealed.ciphertext
            ct.append(sealed.tag)
            return ct
        case .exportOnly:
            throw NCHPKEError.unsupportedAEAD(suite.aead.rawValue)
        }
    }

    /// RFC 9180 §5.3: Context.Export(exporter_context, L)
    public func export(exporterContext: Data, length: Int) throws -> Data {
        try NCHPKE.exportSecret(exporterSecret: exporterSecret, suite: suite, exporterContext: exporterContext, length: length)
    }
}

/// Context for recipient decryption (ContextR).
public final class NCHPKEContextR {
    public let suite: NCHPKECipherSuite
    public let key: Data
    public let baseNonce: Data
    public let exporterSecret: Data
    public var seq: UInt64

    public init(suite: NCHPKECipherSuite, key: Data, baseNonce: Data, exporterSecret: Data, seq: UInt64 = 0) {
        self.suite = suite
        self.key = key
        self.baseNonce = baseNonce
        self.exporterSecret = exporterSecret
        self.seq = seq
    }

    /// RFC 9180 §5.2: ContextR.Open(aad, ct)
    public func open(aad: Data = Data(), ciphertext: Data, seq explicitSeq: UInt64? = nil) throws -> Data {
        guard suite.aead != .exportOnly else {
            throw NCHPKEError.unsupportedAEAD(suite.aead.rawValue)
        }
        guard ciphertext.count >= suite.aead.tagLength else {
            throw NCHPKEError.openError("Ciphertext length (\(ciphertext.count)) is less than tag length (\(suite.aead.tagLength))")
        }
        let currentSeq = explicitSeq ?? seq
        let nonce = NCHPKE.computeNonce(baseNonce: baseNonce, seq: currentSeq)

        if explicitSeq == nil {
            if seq == UInt64.max { throw NCHPKEError.messageLimitReached }
            seq += 1
        } else {
            seq = max(seq, currentSeq + 1)
        }

        let ctLen = ciphertext.count - 16
        let ct = ciphertext.prefix(ctLen)
        let tag = ciphertext.suffix(16)

        switch suite.aead {
        case .aes128GCM, .aes256GCM:
            let symKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
            do {
                return try AES.GCM.open(box, using: symKey, authenticating: aad)
            } catch {
                throw NCHPKEError.openError("AES-GCM decryption failed: \(error)")
            }
        case .chaCha20Poly1305:
            let symKey = SymmetricKey(data: key)
            let chaNonce = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: chaNonce, ciphertext: ct, tag: tag)
            do {
                return try ChaChaPoly.open(box, using: symKey, authenticating: aad)
            } catch {
                throw NCHPKEError.openError("ChaChaPoly decryption failed: \(error)")
            }
        case .exportOnly:
            throw NCHPKEError.unsupportedAEAD(suite.aead.rawValue)
        }
    }

    /// RFC 9180 §5.3: Context.Export(exporter_context, L)
    public func export(exporterContext: Data, length: Int) throws -> Data {
        try NCHPKE.exportSecret(exporterSecret: exporterSecret, suite: suite, exporterContext: exporterContext, length: length)
    }
}

// MARK: - Core HPKE Operations

public enum NCHPKE {
    private static let modeBase: UInt8 = 0x00

    // MARK: HKDF primitives (RFC 5869) with SHA-256

    /// RFC 5869 §2.2: HKDF-Extract(salt, IKM). Empty salt defaults to HashLen zeros.
    public static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let actualSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        let code = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: actualSalt))
        return Data(code)
    }

    /// RFC 5869 §2.3: HKDF-Expand(PRK, info, L)
    public static func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        var out = Data()
        var previous = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var input = previous
            input.append(info)
            input.append(counter)
            let block = HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: prk))
            previous = Data(block)
            out.append(previous)
            counter &+= 1
        }
        return Data(out.prefix(length))
    }

    // MARK: Labeled KDF (RFC 9180 §4)

    /// RFC 9180 §4:
    /// LabeledExtract(salt, label, ikm) = Extract(salt, concat("HPKE-v1", suite_id, label, ikm))
    public static func labeledExtract(salt: Data, label: String, ikm: Data, suiteID: Data) -> Data {
        var labeledIKM = Data("HPKE-v1".utf8)
        labeledIKM.append(suiteID)
        labeledIKM.append(contentsOf: label.utf8)
        labeledIKM.append(ikm)
        return hkdfExtract(salt: salt, ikm: labeledIKM)
    }

    /// RFC 9180 §4:
    /// LabeledExpand(prk, label, info, L) = Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)
    public static func labeledExpand(prk: Data, label: String, info: Data, length: Int, suiteID: Data) -> Data {
        var labeledInfo = Data()
        labeledInfo.append(UInt8((length >> 8) & 0xff))
        labeledInfo.append(UInt8(length & 0xff))
        labeledInfo.append(contentsOf: "HPKE-v1".utf8)
        labeledInfo.append(suiteID)
        labeledInfo.append(contentsOf: label.utf8)
        labeledInfo.append(info)
        return hkdfExpand(prk: prk, info: labeledInfo, length: length)
    }

    // MARK: DHKEM(X25519, HKDF-SHA256) (RFC 9180 §4.1, §7.1.3)

    /// RFC 9180 §7.1.3: DeriveKeyPair(ikm) for X25519
    public static func deriveKeyPair(ikm: Data) throws -> (privateKey: Curve25519.KeyAgreement.PrivateKey, publicKey: Data) {
        let kemSuiteID = NCHPKESuite.KEM.dhkemX25519HKDFSHA256.kemSuiteID
        let dkpPrk = labeledExtract(salt: Data(), label: "dkp_prk", ikm: ikm, suiteID: kemSuiteID)
        let sk = labeledExpand(prk: dkpPrk, label: "sk", info: Data(), length: 32, suiteID: kemSuiteID)
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk)
            return (priv, priv.publicKey.rawRepresentation)
        } catch {
            throw NCHPKEError.deserializeError("Failed to deserialize X25519 private key: \(error)")
        }
    }

    /// RFC 9180 §4.1: Encap(pkR)
    /// Accepts an optional ephemeral private key for deterministic test vector execution.
    public static func encap(
        recipientPublicKey: Data,
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey? = nil
    ) throws -> (sharedSecret: Data, enc: Data) {
        guard recipientPublicKey.count == 32 else {
            throw NCHPKEError.deserializeError("Recipient public key must be 32 bytes for X25519")
        }
        guard let pkR = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey) else {
            throw NCHPKEError.deserializeError("Invalid X25519 public key bytes")
        }
        let skE = ephemeralPrivateKey ?? Curve25519.KeyAgreement.PrivateKey()
        let enc = skE.publicKey.rawRepresentation

        guard let shared = try? skE.sharedSecretFromKeyAgreement(with: pkR) else {
            throw NCHPKEError.encapError("X25519 shared secret agreement failed")
        }
        let dh = shared.withUnsafeBytes { Data($0) }
        if dh.allSatisfy({ $0 == 0 }) {
            throw NCHPKEError.validationError("Diffie-Hellman output is all-zero")
        }

        var kemContext = Data()
        kemContext.append(enc)
        kemContext.append(recipientPublicKey)

        let kemSuiteID = NCHPKESuite.KEM.dhkemX25519HKDFSHA256.kemSuiteID
        let eaePrk = labeledExtract(salt: Data(), label: "eae_prk", ikm: dh, suiteID: kemSuiteID)
        let sharedSecret = labeledExpand(prk: eaePrk, label: "shared_secret", info: kemContext, length: 32, suiteID: kemSuiteID)
        return (sharedSecret, enc)
    }

    /// RFC 9180 §4.1: Decap(enc, skR)
    public static func decap(
        enc: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey
    ) throws -> Data {
        guard enc.count == 32 else {
            throw NCHPKEError.deserializeError("Encapsulated key enc must be 32 bytes for X25519")
        }
        guard let pkE = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: enc) else {
            throw NCHPKEError.deserializeError("Invalid ephemeral public key bytes in enc")
        }
        guard let shared = try? recipientPrivateKey.sharedSecretFromKeyAgreement(with: pkE) else {
            throw NCHPKEError.decapError("X25519 shared secret agreement failed")
        }
        let dh = shared.withUnsafeBytes { Data($0) }
        if dh.allSatisfy({ $0 == 0 }) {
            throw NCHPKEError.validationError("Diffie-Hellman output is all-zero")
        }

        var kemContext = Data()
        kemContext.append(enc)
        kemContext.append(recipientPrivateKey.publicKey.rawRepresentation)

        let kemSuiteID = NCHPKESuite.KEM.dhkemX25519HKDFSHA256.kemSuiteID
        let eaePrk = labeledExtract(salt: Data(), label: "eae_prk", ikm: dh, suiteID: kemSuiteID)
        let sharedSecret = labeledExpand(prk: eaePrk, label: "shared_secret", info: kemContext, length: 32, suiteID: kemSuiteID)
        return sharedSecret
    }

    // MARK: Key Schedule & Setup (RFC 9180 §5.1)

    /// RFC 9180 §5.1: KeySchedule
    public static func keyScheduleBase(
        sharedSecret: Data,
        info: Data,
        suite: NCHPKECipherSuite
    ) -> (key: Data, baseNonce: Data, exporterSecret: Data) {
        let suiteID = suite.hpkeSuiteID
        let pskIDHash = labeledExtract(salt: Data(), label: "psk_id_hash", ikm: Data(), suiteID: suiteID)
        let infoHash = labeledExtract(salt: Data(), label: "info_hash", ikm: info, suiteID: suiteID)

        var keyScheduleContext = Data([modeBase])
        keyScheduleContext.append(pskIDHash)
        keyScheduleContext.append(infoHash)

        let secret = labeledExtract(salt: sharedSecret, label: "secret", ikm: Data(), suiteID: suiteID)

        let key: Data
        let baseNonce: Data
        if suite.aead == .exportOnly {
            key = Data()
            baseNonce = Data()
        } else {
            key = labeledExpand(prk: secret, label: "key", info: keyScheduleContext, length: suite.aead.keyLength, suiteID: suiteID)
            baseNonce = labeledExpand(prk: secret, label: "base_nonce", info: keyScheduleContext, length: suite.aead.nonceLength, suiteID: suiteID)
        }
        let exporterSecret = labeledExpand(prk: secret, label: "exp", info: keyScheduleContext, length: 32, suiteID: suiteID)

        return (key, baseNonce, exporterSecret)
    }

    /// RFC 9180 §5.1.1: SetupBaseS(pkR, info)
    public static func setupBaseS(
        recipientPublicKey: Data,
        info: Data,
        suite: NCHPKECipherSuite,
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey? = nil
    ) throws -> (enc: Data, context: NCHPKEContextS) {
        let (sharedSecret, enc) = try encap(recipientPublicKey: recipientPublicKey, ephemeralPrivateKey: ephemeralPrivateKey)
        let (key, baseNonce, exporterSecret) = keyScheduleBase(sharedSecret: sharedSecret, info: info, suite: suite)
        let ctx = NCHPKEContextS(suite: suite, key: key, baseNonce: baseNonce, exporterSecret: exporterSecret)
        return (enc, ctx)
    }

    /// RFC 9180 §5.1.1: SetupBaseR(enc, skR, info)
    public static func setupBaseR(
        enc: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        info: Data,
        suite: NCHPKECipherSuite
    ) throws -> NCHPKEContextR {
        let sharedSecret = try decap(enc: enc, recipientPrivateKey: recipientPrivateKey)
        let (key, baseNonce, exporterSecret) = keyScheduleBase(sharedSecret: sharedSecret, info: info, suite: suite)
        return NCHPKEContextR(suite: suite, key: key, baseNonce: baseNonce, exporterSecret: exporterSecret)
    }

    // MARK: Nonce Computation & Secret Export

    /// RFC 9180 §5.2: ComputeNonce(seq) = xor(base_nonce, I2OSP(seq, Nn))
    public static func computeNonce(baseNonce: Data, seq: UInt64) -> Data {
        var seqBytes = [UInt8](repeating: 0, count: baseNonce.count)
        var s = seq
        for i in stride(from: baseNonce.count - 1, through: 0, by: -1) {
            seqBytes[i] = UInt8(s & 0xff)
            s >>= 8
        }
        var nonce = Data(count: baseNonce.count)
        for i in 0..<baseNonce.count {
            nonce[i] = baseNonce[i] ^ seqBytes[i]
        }
        return nonce
    }

    /// RFC 9180 §5.3: Context.Export(exporter_context, L)
    public static func exportSecret(
        exporterSecret: Data,
        suite: NCHPKECipherSuite,
        exporterContext: Data,
        length: Int
    ) throws -> Data {
        guard length >= 0 && length <= 255 * 32 else {
            throw NCHPKEError.validationError("Export length \(length) exceeds bound 255 * Nh (8160)")
        }
        return labeledExpand(
            prk: exporterSecret,
            label: "sec",
            info: exporterContext,
            length: length,
            suiteID: suite.hpkeSuiteID
        )
    }

    // MARK: Single-Shot APIs (RFC 9180 §6.1)

    /// RFC 9180 §6.1: SealBase(pkR, info, aad, pt)
    public static func sealBase(
        recipientPublicKey: Data,
        info: Data,
        aad: Data = Data(),
        plaintext: Data,
        suite: NCHPKECipherSuite
    ) throws -> (enc: Data, ciphertext: Data) {
        let (enc, ctx) = try setupBaseS(recipientPublicKey: recipientPublicKey, info: info, suite: suite)
        let ct = try ctx.seal(aad: aad, plaintext: plaintext)
        return (enc, ct)
    }

    /// RFC 9180 §6.1: OpenBase(enc, skR, info, aad, ct)
    public static func openBase(
        enc: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        info: Data,
        aad: Data = Data(),
        ciphertext: Data,
        suite: NCHPKECipherSuite
    ) throws -> Data {
        let ctx = try setupBaseR(enc: enc, recipientPrivateKey: recipientPrivateKey, info: info, suite: suite)
        return try ctx.open(aad: aad, ciphertext: ciphertext)
    }
}
