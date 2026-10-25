import CryptoKit
import Foundation

// MARK: - Noise_IK_25519_ChaChaPoly_BLAKE2s Handshake Engine (ts2021)
//
// Pure Swift implementation of the Noise IK handshake pattern used by Tailscale's
// ts2021 control protocol (tailscale.com/control/controlhttp/ts2021.go).
//
// Differences from WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s):
// 1. Suite Identifier: WireGuard specifies "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
//    ts2021 uses standard "Noise_IK_25519_ChaChaPoly_BLAKE2s".
// 2. No Pre-Shared Key (PSK): WireGuard mixes a 32-byte PSK after message 2; ts2021 does not.
// 3. No Mac1/Mac2 Cookie Mechanism: WireGuard employs 16-byte mac1/mac2 fields and TAI64N timestamps
//    for DoS mitigation; ts2021 is negotiated over a reliable stream (HTTP POST /ts2021 Upgrade).
// 4. Transport Framing: WireGuard wraps fixed UDP packet structures; ts2021 exports symmetric
//    transport keys where each direction encrypts/decrypts contiguous application chunks (HTTP/2 frames)
//    with an incrementing 64-bit nonce ("whole Data in, whole Data out").
//
// Hash Primitive: Reuses `NCBlake2s` from `NCWireGuardCrypto.swift` (same target).

enum NCNoiseError: Error, LocalizedError {
    case invalidMessageLength(expectedAtLeast: Int, actual: Int)
    case invalidPublicKeyLength(expected: Int, actual: Int)
    case weakSharedSecretAllZero
    case decryptionFailed
    case handshakeAlreadyCompleted
    case handshakeNotReadyForMessage2
    case nonceOverflow

    var errorDescription: String? {
        switch self {
        case .invalidMessageLength(let exp, let act):
            return "Noise message too short (expected at least \(exp) bytes, got \(act))"
        case .invalidPublicKeyLength(let exp, let act):
            return "Invalid public key length (expected \(exp), got \(act))"
        case .weakSharedSecretAllZero:
            return "ECDH returned all-zero shared secret (refusing low-order point)"
        case .decryptionFailed:
            return "Noise authentication or decryption failed"
        case .handshakeAlreadyCompleted:
            return "Noise handshake is already completed"
        case .handshakeNotReadyForMessage2:
            return "Cannot process message 2 before message 1 has been generated"
        case .nonceOverflow:
            return "Transport cipher nonce overflow (max 2^64-1)"
        }
    }
}

// MARK: - Transport Cipher (Post-Handshake Bidirectional Stream)

/// Symmetric transport cipher holding independent TX and RX channels.
/// Used to encrypt and decrypt HTTP/2 frames directly over the ts2021 stream.
final class NCTransportCipher {
    private let txKey: SymmetricKey
    private let rxKey: SymmetricKey
    private var txNonce: UInt64 = 0
    private var rxNonce: UInt64 = 0
    private let lock = NSLock()

    init(txKeyBytes: [UInt8], rxKeyBytes: [UInt8]) {
        self.txKey = SymmetricKey(data: txKeyBytes)
        self.rxKey = SymmetricKey(data: rxKeyBytes)
    }

    /// Encrypts an outgoing chunk of application data.
    /// Format: ChaCha20-Poly1305 ciphertext + 16-byte authentication tag.
    func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }

        guard txNonce < UInt64.max else { throw NCNoiseError.nonceOverflow }
        let nonce = Self.makeNonce(txNonce)
        txNonce &+= 1

        guard let box = try? ChaChaPoly.seal(plaintext, using: txKey, nonce: nonce, authenticating: [UInt8]()) else {
            throw NCNoiseError.decryptionFailed
        }
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    /// Decrypts an incoming chunk of data.
    /// Expects at least 16 bytes (ciphertext + authentication tag).
    func decrypt(_ ciphertextAndTag: [UInt8]) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }

        guard ciphertextAndTag.count >= 16 else {
            throw NCNoiseError.invalidMessageLength(expectedAtLeast: 16, actual: ciphertextAndTag.count)
        }
        guard rxNonce < UInt64.max else { throw NCNoiseError.nonceOverflow }
        let nonce = Self.makeNonce(rxNonce)
        rxNonce &+= 1

        let ct = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)
        guard let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag),
              let plain = try? ChaChaPoly.open(box, using: rxKey, authenticating: [UInt8]()) else {
            throw NCNoiseError.decryptionFailed
        }
        return [UInt8](plain)
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        let res = try encrypt([UInt8](plaintext))
        return Data(res)
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        let res = try decrypt([UInt8](ciphertext))
        return Data(res)
    }

    /// RFC 8439 / Noise 12-byte nonce: 4 zero bytes followed by 8 little-endian bytes.
    static func makeNonce(_ counter: UInt64) -> ChaChaPoly.Nonce {
        var n = [UInt8](repeating: 0, count: 12)
        for i in 0..<8 {
            n[4 + i] = UInt8((counter >> (8 * UInt64(i))) & 0xff)
        }
        return try! ChaChaPoly.Nonce(data: n)
    }
}

// MARK: - Noise IK Initiator Handshake Engine

/// State machine implementing Noise_IK_25519_ChaChaPoly_BLAKE2s from the initiator's perspective.
final class NCNoiseIKInitiator {

    // Handshake state
    private var h: [UInt8]
    private var ck: [UInt8]
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private let staticPrivateKey: Curve25519.KeyAgreement.PrivateKey
    private let responderStaticPublicKey: [UInt8]

    private var message1Sent = false
    private var handshakeDone = false

    /// Initializes a new Noise IK initiator session.
    /// - Parameters:
    ///   - staticPrivateKey: The initiator's long-term Curve25519 private key (machine or node key).
    ///   - responderStaticPublicKey: The control plane's known 32-byte Curve25519 public key.
    ///   - prologue: Protocol prologue bytes. Default matches `NCTailscaleConsts.noisePrologueLiteral`.
    ///   - ephemeralPrivateKey: Optional pre-configured ephemeral key (for deterministic testing).
    init(
        staticPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        responderStaticPublicKey: [UInt8],
        prologue: [UInt8] = Array(NCTailscaleConsts.noisePrologueLiteral.utf8),
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey? = nil
    ) throws {
        guard responderStaticPublicKey.count == 32 else {
            throw NCNoiseError.invalidPublicKeyLength(expected: 32, actual: responderStaticPublicKey.count)
        }

        self.staticPrivateKey = staticPrivateKey
        self.responderStaticPublicKey = responderStaticPublicKey
        self.ephemeralPrivateKey = ephemeralPrivateKey

        // Protocol name: "Noise_IK_25519_ChaChaPoly_BLAKE2s" (35 bytes > 32 bytes -> hash)
        let protoBytes = Array(NCTailscaleConsts.noiseProtocolName.utf8)
        let initialH = NCBlake2s.hash(protoBytes)
        self.h = initialH
        self.ck = initialH

        // MixHash(prologue)
        mixHash(prologue)

        // MixHash(rs): Responder static public key is pre-known
        mixHash(responderStaticPublicKey)
    }

    /// Generates Message 1 to send to the responder.
    /// Handshake pattern: `-> e, es, s, ss, [payload]`
    /// Output layout: `e (32B) || c_s (48B) || c_payload (payload.count + 16B)`
    func writeMessage1(payload: [UInt8] = []) throws -> [UInt8] {
        guard !message1Sent else { throw NCNoiseError.handshakeAlreadyCompleted }

        // Generate ephemeral key pair
        let ePriv = ephemeralPrivateKey ?? Curve25519.KeyAgreement.PrivateKey()
        self.ephemeralPrivateKey = ePriv
        let ePub = [UInt8](ePriv.publicKey.rawRepresentation)

        // -> e
        mixHash(ePub)

        // -> es: DH(e, rs)
        guard let esSecret = Self.dh(ePriv, responderStaticPublicKey) else {
            throw NCNoiseError.weakSharedSecretAllZero
        }
        let (ckAfterES, kES) = Self.kdf2(key: ck, input: esSecret)
        self.ck = ckAfterES

        // -> s: EncryptAndHash(s)
        let sPub = [UInt8](staticPrivateKey.publicKey.rawRepresentation)
        let sBox = try encryptWithKey(kES, nonce: 0, plaintext: sPub, aad: h)
        mixHash(sBox)

        // -> ss: DH(s, rs)
        guard let ssSecret = Self.dh(staticPrivateKey, responderStaticPublicKey) else {
            throw NCNoiseError.weakSharedSecretAllZero
        }
        let (ckAfterSS, kSS) = Self.kdf2(key: ck, input: ssSecret)
        self.ck = ckAfterSS

        // -> payload: EncryptAndHash(payload)
        let payloadBox = try encryptWithKey(kSS, nonce: 0, plaintext: payload, aad: h)
        mixHash(payloadBox)

        message1Sent = true

        // Assemble Message 1: e (32) + encrypted static (32+16=48) + encrypted payload (len+16)
        return ePub + sBox + payloadBox
    }

    /// Processes Message 2 received from the responder and completes the handshake.
    /// Handshake pattern: `<- e, ee, se, [payload]`
    /// Input layout: `re (32B) || c_payload (remaining bytes, at least 16B)`
    /// Returns the decrypted response payload and the active `NCTransportCipher`.
    func readMessage2(_ message2Bytes: [UInt8]) throws -> (payload: [UInt8], transport: NCTransportCipher) {
        guard message1Sent else { throw NCNoiseError.handshakeNotReadyForMessage2 }
        guard !handshakeDone else { throw NCNoiseError.handshakeAlreadyCompleted }
        guard message2Bytes.count >= 48 else {
            // Must contain at least 32-byte ephemeral key + 16-byte tag
            throw NCNoiseError.invalidMessageLength(expectedAtLeast: 48, actual: message2Bytes.count)
        }
        guard let ePriv = self.ephemeralPrivateKey else {
            throw NCNoiseError.handshakeNotReadyForMessage2
        }

        let rePub = Array(message2Bytes.prefix(32))
        let payloadBox = Array(message2Bytes.suffix(from: 32))

        // <- e
        mixHash(rePub)

        // <- ee: DH(e, re)
        guard let eeSecret = Self.dh(ePriv, rePub) else {
            throw NCNoiseError.weakSharedSecretAllZero
        }
        let (ckAfterEE, kEE) = Self.kdf2(key: ck, input: eeSecret)
        self.ck = ckAfterEE

        // <- se: DH(s, re)
        guard let seSecret = Self.dh(staticPrivateKey, rePub) else {
            throw NCNoiseError.weakSharedSecretAllZero
        }
        let (ckAfterSE, kSE) = Self.kdf2(key: ck, input: seSecret)
        self.ck = ckAfterSE

        // <- payload: DecryptAndHash(payload)
        let payload = try decryptWithKey(kSE, nonce: 0, ciphertextAndTag: payloadBox, aad: h)
        mixHash(payloadBox)

        // Split: KDF2(ck, zero-length input) -> (txKey, rxKey)
        let (txKeyBytes, rxKeyBytes) = Self.kdf2(key: ck, input: [])
        let transport = NCTransportCipher(txKeyBytes: txKeyBytes, rxKeyBytes: rxKeyBytes)

        handshakeDone = true
        return (payload, transport)
    }

    // MARK: - Data Overloads

    func writeMessage1(payload: Data) throws -> Data {
        let res = try writeMessage1(payload: [UInt8](payload))
        return Data(res)
    }

    func readMessage2(_ message2: Data) throws -> (payload: Data, transport: NCTransportCipher) {
        let (pl, tr) = try readMessage2([UInt8](message2))
        return (Data(pl), tr)
    }

    // MARK: - Handshake State Evolution Helpers

    private func mixHash(_ data: [UInt8]) {
        self.h = NCBlake2s.hash(self.h, data)
    }

    private func encryptWithKey(_ keyBytes: [UInt8], nonce: UInt64, plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let key = SymmetricKey(data: keyBytes)
        let nonceObj = NCTransportCipher.makeNonce(nonce)
        guard let box = try? ChaChaPoly.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad) else {
            throw NCNoiseError.decryptionFailed
        }
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    private func decryptWithKey(
        _ keyBytes: [UInt8],
        nonce: UInt64,
        ciphertextAndTag: [UInt8],
        aad: [UInt8]
    ) throws -> [UInt8] {
        guard ciphertextAndTag.count >= 16 else {
            throw NCNoiseError.invalidMessageLength(expectedAtLeast: 16, actual: ciphertextAndTag.count)
        }
        let key = SymmetricKey(data: keyBytes)
        let nonceObj = NCTransportCipher.makeNonce(nonce)
        let ct = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)
        guard let box = try? ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag),
              let plain = try? ChaChaPoly.open(box, using: key, authenticating: aad) else {
            throw NCNoiseError.decryptionFailed
        }
        return [UInt8](plain)
    }

    /// Noise KDF2 using HMAC-BLAKE2s-256 (via NCBlake2s).
    private static func kdf2(key: [UInt8], input: [UInt8]) -> (key1: [UInt8], key2: [UInt8]) {
        let prk = NCBlake2s.hmac(key: key, input)
        let out1 = NCBlake2s.hmac(key: prk, [0x01])
        let out2 = NCBlake2s.hmac(key: prk, out1 + [0x02])
        return (out1, out2)
    }

    /// Curve25519 DH exchange with low-order point (all-zero) refusal.
    private static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: [UInt8]) -> [UInt8]? {
        guard let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub),
              let s = try? priv.sharedSecretFromKeyAgreement(with: p) else { return nil }
        let out = s.withUnsafeBytes { [UInt8]($0) }
        return out.allSatisfy({ $0 == 0 }) ? nil : out
    }

    // MARK: - Self-Test Loopback Simulation

    /// Simulates a full initiator-responder handshake and transport exchange.
    @discardableResult
    static func selfTest() -> Bool {
        do {
            let initiatorStatic = Curve25519.KeyAgreement.PrivateKey()
            let responderStatic = Curve25519.KeyAgreement.PrivateKey()
            let responderStaticPub = [UInt8](responderStatic.publicKey.rawRepresentation)

            let initiator = try NCNoiseIKInitiator(
                staticPrivateKey: initiatorStatic,
                responderStaticPublicKey: responderStaticPub
            )

            let clientPayload = Array("ts2021 Client Hello".utf8)
            let msg1 = try initiator.writeMessage1(payload: clientPayload)
            guard msg1.count >= 32 + 48 + 16 else { return false }

            // Simulate Responder processing msg1 and creating msg2
            // Protocol: Noise_IK_25519_ChaChaPoly_BLAKE2s
            var respH = NCBlake2s.hash(Array(NCTailscaleConsts.noiseProtocolName.utf8))
            var respCK = respH
            respH = NCBlake2s.hash(respH, Array(NCTailscaleConsts.noisePrologueLiteral.utf8))
            respH = NCBlake2s.hash(respH, responderStaticPub)

            // Read e from msg1
            let eClient = Array(msg1.prefix(32))
            respH = NCBlake2s.hash(respH, eClient)

            // es = DH(responderStatic, eClient)
            guard let esResp = dh(responderStatic, eClient) else { return false }
            let (ckESResp, kESResp) = kdf2(key: respCK, input: esResp)
            respCK = ckESResp

            // Decrypt s
            let sBox = Array(msg1[32..<80])
            let nonce0 = NCTransportCipher.makeNonce(0)
            guard let sSealed = try? ChaChaPoly.SealedBox(
                nonce: nonce0,
                ciphertext: sBox.prefix(32),
                tag: sBox.suffix(16)
            ),
            let sClient = try? ChaChaPoly.open(sSealed, using: SymmetricKey(data: kESResp), authenticating: respH) else {
                return false
            }
            respH = NCBlake2s.hash(respH, sBox)

            // ss = DH(responderStatic, sClient)
            guard let ssResp = dh(responderStatic, [UInt8](sClient)) else { return false }
            let (ckSSResp, kSSResp) = kdf2(key: respCK, input: ssResp)
            respCK = ckSSResp

            // Decrypt payload
            let pBox = Array(msg1[80...])
            guard let pSealed = try? ChaChaPoly.SealedBox(
                nonce: nonce0,
                ciphertext: pBox.prefix(pBox.count - 16),
                tag: pBox.suffix(16)
            ),
            let decryptedClientPayload = try? ChaChaPoly.open(pSealed, using: SymmetricKey(data: kSSResp), authenticating: respH) else {
                return false
            }
            guard [UInt8](decryptedClientPayload) == clientPayload else { return false }
            respH = NCBlake2s.hash(respH, pBox)

            // Responder creates msg2: -> e, ee, se, [payload]
            let respEphemeral = Curve25519.KeyAgreement.PrivateKey()
            let respEphemeralPub = [UInt8](respEphemeral.publicKey.rawRepresentation)
            respH = NCBlake2s.hash(respH, respEphemeralPub)

            guard let eeResp = dh(respEphemeral, eClient) else { return false }
            let (ckEEResp, kEEResp) = kdf2(key: respCK, input: eeResp)
            respCK = ckEEResp

            guard let seResp = dh(respEphemeral, [UInt8](sClient)) else { return false }
            let (ckSEResp, kSEResp) = kdf2(key: respCK, input: seResp)
            respCK = ckSEResp

            let serverPayload = Array("ts2021 Server Handshake OK".utf8)
            guard let serverPBox = try? ChaChaPoly.seal(
                serverPayload,
                using: SymmetricKey(data: kSEResp),
                nonce: nonce0,
                authenticating: respH
            ) else {
                return false
            }
            let serverPayloadSealed = [UInt8](serverPBox.ciphertext) + [UInt8](serverPBox.tag)
            respH = NCBlake2s.hash(respH, serverPayloadSealed)
            let msg2 = respEphemeralPub + serverPayloadSealed

            // Responder split
            let (respRxKey, respTxKey) = kdf2(key: respCK, input: [])
            let responderTransport = NCTransportCipher(txKeyBytes: respTxKey, rxKeyBytes: respRxKey)

            // Initiator reads msg2
            let (receivedServerPayload, initiatorTransport) = try initiator.readMessage2(msg2)
            guard receivedServerPayload == serverPayload else { return false }

            // Test transport bidirectional encryption
            let clientData = Array("GET / HTTP/1.1\r\nHost: example\r\n\r\n".utf8)
            let clientEncrypted = try initiatorTransport.encrypt(clientData)
            let serverDecrypted = try responderTransport.decrypt(clientEncrypted)
            guard serverDecrypted == clientData else { return false }

            let serverData = Array("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)
            let serverEncrypted = try responderTransport.encrypt(serverData)
            let clientDecrypted = try initiatorTransport.decrypt(serverEncrypted)
            guard clientDecrypted == serverData else { return false }

            return true
        } catch {
            return false
        }
    }
}
