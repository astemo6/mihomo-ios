import Foundation
import CryptoKit
import Security

/// A hand-rolled TLS 1.3 client over an NCStream, built for REALITY (which
/// needs byte-exact control of the ClientHello) and usable as plain TLS too.
/// Scope: TLS 1.3 only, X25519 key share, suites 1301/1302/1303, no client
/// certs, no resumption. Certificate policy: REALITY mode verifies the leaf
/// by its HMAC proof (falling back to "not verified" → handshake failure,
/// exactly like the Go client); plain mode uses SecTrust against the system
/// roots for the configured server name.
final class NCTLSClientStream: NCRelayStream {
    struct Config {
        var serverName: String
        var alpn: [String] = ["h2", "http/1.1"]
        var reality: NCTLS13.RealityParams? = nil
        var allowInsecure: Bool = false // plain mode only: skip SecTrust result
    }

    enum TLSError: Error {
        case handshake(String)
        case closed
    }

    private let raw: NCStream
    private let config: Config
    private let queue: DispatchQueue

    // Record layer state
    private var readBuffer = Data()
    private var writeBuffer = Data() // plaintext queued before handshake completes
    private var handshakeDone = false
    private var failed: Error?
    private var closed = false

    private var suite: NCTLS13.Suite = .aes128GCM
    private var kind: NCTLS13.HashKind = .sha256
    private var readKey: Data?, readIV: Data?, readSeq: UInt64 = 0
    private var writeKey: Data?, writeIV: Data?, writeSeq: UInt64 = 0
    private var readSecret: Data? // for KeyUpdate progression
    private var writeSecret: Data?

    // Handshake state
    private var transcript = Data() // concatenated handshake messages
    private var clientPrivate: Curve25519.KeyAgreement.PrivateKey?
    private var clientRandom = Data()
    private var serverFinishedHash: Data?
    private var certsDER: [Data] = []
    private var certVerify: (scheme: UInt16, signature: Data)?
    private var handshakeHandler: ((Error?) -> Void)?
    private var plaintextOut: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?

    init(raw: NCStream, config: Config, queue: DispatchQueue) {
        self.raw = raw
        self.config = config
        self.queue = queue
    }

    // MARK: Handshake

    func startHandshake(completion: @escaping (Error?) -> Void) {
        handshakeHandler = completion
        do {
            try sendClientHello()
        } catch {
            completion(error)
            return
        }
        pumpRaw()
    }

    private func sendClientHello() throws {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        clientPrivate = priv
        clientRandom = NCConnector.randomData(32)
        let clientShare = Data(priv.publicKey.rawRepresentation)

        // REALITY session ID: plaintext built now, sealed after the hello is
        // marshaled (the AAD is the hello with the ID zeroed).
        var authKey: Data?
        var sidPlain: Data?
        if let reality = config.reality {
            authKey = NCTLS13.realityAuthKey(clientPrivate: priv, serverPublic: reality.publicKey, clientRandom: clientRandom)
            guard authKey != nil else { throw TLSError.handshake("reality key agreement") }
            sidPlain = NCTLS13.realitySessionIDPlain(shortID: reality.shortID,
                                                     unixTime: UInt32(Date().timeIntervalSince1970))
        }
        let hello = NCTLS13.buildClientHello(random: clientRandom, sessionID: Data(repeating: 0, count: 32),
                                          serverName: config.serverName, alpn: config.alpn,
                                          keyShare: clientShare)
        var wireHello = hello
        if let reality = config.reality, let authKey, let sidPlain {
            guard let sealed = NCTLS13.realitySealSessionID(authKey: authKey, plain: sidPlain,
                                                            clientRandom: clientRandom, aad: hello),
                  sealed.count == 32 else { throw TLSError.handshake("reality seal") }
            // Session ID sits at offset 39 in the handshake message:
            // 4 header + 2 version + 32 random + 1 length byte, then the ID.
            wireHello.replaceSubrange(39..<(39 + 32), with: sealed)
            self.realityAuthKey = authKey
            _ = reality
        }
        transcript.append(wireHello)
        sendRecord(type: 22, payload: wireHello)
    }

    private var realityAuthKey: Data?

    // MARK: Record pump

    private func pumpRaw() {
        raw.receive { [weak self] data, error in
            guard let self else { return }
            if let data { self.readBuffer.append(data) }
            self.processRecords()
            if data == nil {
                self.closed = true
                self.deliverEOFOrError(error)
                return
            }
            if !self.closed { self.pumpRaw() }
        }
    }

    private func processRecords() {
        while readBuffer.count >= 5 {
            let type = readBuffer[0]
            let len = Int(readBuffer[3]) << 8 | Int(readBuffer[4])
            guard readBuffer.count >= 5 + len else { return }
            let header = Data(readBuffer.prefix(5))
            let payload = Data(readBuffer[5..<(5 + len)])
            readBuffer = Data(readBuffer.dropFirst(5 + len))
            handleRecord(type: type, header: header, payload: payload)
            if failed != nil { return }
        }
    }

    private func handleRecord(type: UInt8, header: Data, payload: Data) {
        switch type {
        case 20: // ChangeCipherSpec: ignore
            return
        case 21: // Alert
            if payload.count >= 2, payload[0] == 2 {
                fail(TLSError.handshake("fatal alert \(payload[1])"))
            }
            closed = true
            return
        case 22, 23:
            if readKey != nil {
                guard let plain = NCTLS13.openRecord(suite: suite, key: readKey!, iv: readIV!, seq: readSeq,
                                                     header: header, sealed: payload) else {
                    fail(TLSError.handshake("record decrypt failed"))
                    return
                }
                readSeq += 1
                guard let innerType = plain.last else { return }
                let content = Data(plain.dropLast())
                switch innerType {
                case 22: handleHandshakeBytes(content)
                case 23: deliverAppData(content)
                case 21: closed = true; deliverEOFOrError(nil)
                default: break
                }
            } else {
                // Plaintext handshake (ServerHello flight)
                handleHandshakeBytes(payload)
            }
        default:
            return
        }
    }

    // MARK: Handshake messages

    private var handshakeBuffer = Data()

    private func handleHandshakeBytes(_ data: Data) {
        handshakeBuffer.append(data)
        while handshakeBuffer.count >= 4 {
            let msgType = handshakeBuffer[0]
            let len = Int(handshakeBuffer[1]) << 16 | Int(handshakeBuffer[2]) << 8 | Int(handshakeBuffer[3])
            guard handshakeBuffer.count >= 4 + len else { return }
            let message = Data(handshakeBuffer.prefix(4 + len))
            handshakeBuffer = Data(handshakeBuffer.dropFirst(4 + len))
            processHandshakeMessage(type: msgType, message: message)
            if failed != nil { return }
        }
    }

    private func processHandshakeMessage(type: UInt8, message: Data) {
        switch type {
        case 2: // ServerHello
            handleServerHello(message)
        case 8: // EncryptedExtensions
            transcript.append(message)
        case 11: // Certificate
            transcript.append(message)
            parseCertificates(message)
        case 15: // CertificateVerify: its signed hash covers CH..Certificate,
            // so verify first and append to the transcript afterwards.
            parseCertificateVerify(message)
            if failed == nil { transcript.append(message) }
        case 20: // Finished
            handleServerFinished(message)
        case 4: // NewSessionTicket (post-handshake): ignore, not in transcript
            return
        case 24: // KeyUpdate
            handleKeyUpdate(message)
        default:
            if handshakeDone { return }
            transcript.append(message)
        }
    }

    private func handleServerHello(_ message: Data) {
        let body = Data(message.dropFirst(4))
        guard body.count >= 34 else { fail(TLSError.handshake("short ServerHello")); return }
        // version(2) random(32) session_id(1+..) cipher(2) compression(1) exts(2..)
        var idx = 34
        guard body.count > idx else { fail(TLSError.handshake("bad ServerHello")); return }
        let sidLen = Int(body[idx]); idx += 1 + sidLen
        guard body.count >= idx + 3 else { fail(TLSError.handshake("bad ServerHello")); return }
        let suiteValue = UInt16(body[idx]) << 8 | UInt16(body[idx + 1]); idx += 2
        guard let chosen = NCTLS13.Suite(rawValue: suiteValue) else {
            fail(TLSError.handshake("suite \(String(suiteValue, radix: 16)) not offered"))
            return
        }
        suite = chosen
        kind = chosen.hashKind
        idx += 1 // compression
        guard body.count >= idx + 2 else { fail(TLSError.handshake("bad ServerHello ext")); return }
        let extLen = Int(body[idx]) << 8 | Int(body[idx + 1]); idx += 2
        let extEnd = min(body.count, idx + extLen)
        var serverShare: Data?
        var supportedVersion: UInt16 = 0
        while idx + 4 <= extEnd {
            let extType = UInt16(body[idx]) << 8 | UInt16(body[idx + 1])
            let extSize = Int(body[idx + 2]) << 8 | Int(body[idx + 3])
            let extBody = Data(body[(idx + 4)..<min(extEnd, idx + 4 + extSize)])
            switch extType {
            case 43: supportedVersion = extBody.count >= 2 ? UInt16(extBody[0]) << 8 | UInt16(extBody[1]) : 0
            case 51: // key_share: group(2) + len(2) + key
                if extBody.count >= 4 {
                    serverShare = Data(extBody.dropFirst(4))
                }
            default: break
            }
            idx += 4 + extSize
        }
        guard supportedVersion == 0x0304 else { fail(TLSError.handshake("not TLS 1.3")); return }
        guard let serverShare, let clientPrivate,
              let serverPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverShare),
              let shared = try? clientPrivate.sharedSecretFromKeyAgreement(with: serverPub) else {
            fail(TLSError.handshake("key agreement failed"))
            return
        }
        transcript.append(message)
        let sharedData = shared.withUnsafeBytes { Data($0) }
        let hashCHSH = kind.hash(transcript)
        // Partial schedule now (handshake secrets); app secrets after Finished.
        let zero = Data(repeating: 0, count: kind.length)
        let early = NCTLS13.hkdfExtract(kind, salt: zero, ikm: zero)
        let derived = NCTLS13.deriveSecret(kind, secret: early, label: "derived", transcriptHash: kind.hash(Data()))
        let handshakeSecret = NCTLS13.hkdfExtract(kind, salt: derived, ikm: sharedData)
        handshakeSecretStored = handshakeSecret
        let cHS = NCTLS13.deriveSecret(kind, secret: handshakeSecret, label: "c hs traffic", transcriptHash: hashCHSH)
        let sHS = NCTLS13.deriveSecret(kind, secret: handshakeSecret, label: "s hs traffic", transcriptHash: hashCHSH)
        let ck = NCTLS13.trafficKeyIV(kind, suite: suite, secret: cHS)
        let sk = NCTLS13.trafficKeyIV(kind, suite: suite, secret: sHS)
        writeKey = ck.key; writeIV = ck.iv; writeSeq = 0; writeSecret = cHS
        readKey = sk.key; readIV = sk.iv; readSeq = 0; readSecret = sHS
    }

    private var handshakeSecretStored: Data?

    private func parseCertificates(_ message: Data) {
        let body = Data(message.dropFirst(4))
        var idx = 0
        guard body.count >= 1 else { return }
        let ctxLen = Int(body[idx]); idx += 1 + ctxLen
        guard body.count >= idx + 3 else { return }
        let listLen = Int(body[idx]) << 16 | Int(body[idx + 1]) << 8 | Int(body[idx + 2]); idx += 3
        let end = min(body.count, idx + listLen)
        while idx + 3 <= end {
            let certLen = Int(body[idx]) << 16 | Int(body[idx + 1]) << 8 | Int(body[idx + 2]); idx += 3
            guard idx + certLen <= end else { return }
            certsDER.append(Data(body[idx..<(idx + certLen)]))
            idx += certLen
            guard idx + 2 <= end else { return }
            let extLen = Int(body[idx]) << 8 | Int(body[idx + 1]); idx += 2 + extLen
        }
    }

    private func parseCertificateVerify(_ message: Data) {
        let body = Data(message.dropFirst(4))
        guard body.count >= 4 else { fail(TLSError.handshake("bad CertificateVerify")); return }
        let scheme = UInt16(body[0]) << 8 | UInt16(body[1])
        let sigLen = Int(body[2]) << 8 | Int(body[3])
        guard body.count >= 4 + sigLen else { fail(TLSError.handshake("bad CertificateVerify sig")); return }
        certVerify = (scheme, Data(body[4..<(4 + sigLen)]))
        verifyCertificate()
    }

    private func verifyCertificate() {
        guard let leaf = certsDER.first, let cert = NCX509Certificate(der: leaf),
              let (scheme, signature) = certVerify else {
            fail(TLSError.handshake("certificate parse failed"))
            return
        }
        // Content: 64 spaces || context string || 0x00 || transcript hash
        // (transcript covers ClientHello..Certificate at this point).
        var content = Data(repeating: 0x20, count: 64)
        content.append(Data("TLS 1.3, server CertificateVerify".utf8))
        content.append(0x00)
        content.append(kind.hash(transcript))
        guard NCTLSVerify.certificateVerify(scheme: scheme, cert: cert, signedContent: content, signature: signature) else {
            fail(TLSError.handshake("CertificateVerify signature invalid"))
            return
        }
        // REALITY: the leaf HMAC proof is the authentication.
        if config.reality != nil {
            guard let authKey = realityAuthKey, NCTLS13.realityVerifyLeaf(authKey: authKey, leafDER: leaf) else {
                fail(TLSError.handshake("REALITY authentication failed"))
                return
            }
        } else if !config.allowInsecure {
            guard secTrustValid() else {
                fail(TLSError.handshake("certificate not trusted"))
                return
            }
        }
    }

    private func secTrustValid() -> Bool {
        let certs = certsDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certs.count == certsDER.count, !certs.isEmpty else { return false }
        let policy = SecPolicyCreateSSL(true, config.serverName as CFString)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }

    private func handleServerFinished(_ message: Data) {
        let body = Data(message.dropFirst(4))
        guard let hsReadSecret = readSecret else { fail(TLSError.handshake("Finished before keys")); return }
        let expected = NCTLS13.finishedVerifyData(kind, trafficSecret: hsReadSecret, transcriptHash: kind.hash(transcript))
        guard body == expected else {
            fail(TLSError.handshake("server Finished verify failed"))
            return
        }
        transcript.append(message)
        let hashThroughServerFinished = kind.hash(transcript)
        // Application secrets
        guard let handshakeSecret = handshakeSecretStored else { return }
        let derived = NCTLS13.deriveSecret(kind, secret: handshakeSecret, label: "derived", transcriptHash: kind.hash(Data()))
        let master = NCTLS13.hkdfExtract(kind, salt: derived, ikm: Data(repeating: 0, count: kind.length))
        let cAP = NCTLS13.deriveSecret(kind, secret: master, label: "c ap traffic", transcriptHash: hashThroughServerFinished)
        let sAP = NCTLS13.deriveSecret(kind, secret: master, label: "s ap traffic", transcriptHash: hashThroughServerFinished)
        // Send client Finished under the handshake write keys first.
        guard let hsWriteSecret = writeSecret else { return }
        let verifyData = NCTLS13.finishedVerifyData(kind, trafficSecret: hsWriteSecret, transcriptHash: hashThroughServerFinished)
        var finished = Data()
        finished.append(0x14)
        finished.append(0x00)
        finished.appendBE16(UInt16(verifyData.count))
        finished.append(verifyData)
        sendEncryptedHandshake(finished)
        // Switch to application keys.
        let ck = NCTLS13.trafficKeyIV(kind, suite: suite, secret: cAP)
        let sk = NCTLS13.trafficKeyIV(kind, suite: suite, secret: sAP)
        writeKey = ck.key; writeIV = ck.iv; writeSeq = 0; writeSecret = cAP
        readKey = sk.key; readIV = sk.iv; readSeq = 0; readSecret = sAP
        handshakeDone = true
        let handler = handshakeHandler
        handshakeHandler = nil
        handler?(nil)
        // Flush queued plaintext.
        let queued = writeBuffer
        writeBuffer = Data()
        if !queued.isEmpty { send(queued) }
    }

    private func handleKeyUpdate(_ message: Data) {
        // body: update_requested (1 byte). Peer's sending secret progresses,
        // so our read secret progresses; if requested, answer with our own
        // KeyUpdate (unrequested) under current write keys, then progress
        // our write secret.
        let body = Data(message.dropFirst(4))
        if let secret = readSecret {
            readSecret = NCTLS13.updateTrafficSecret(kind, secret: secret)
            let sk = NCTLS13.trafficKeyIV(kind, suite: suite, secret: readSecret!)
            readKey = sk.key; readIV = sk.iv; readSeq = 0
        }
        if body.first == 1 {
            var ku = Data([0x18, 0x00, 0x00, 0x01, 0x00])
            sendEncryptedHandshake(ku)
            if let secret = writeSecret {
                writeSecret = NCTLS13.updateTrafficSecret(kind, secret: secret)
                let ck = NCTLS13.trafficKeyIV(kind, suite: suite, secret: writeSecret!)
                writeKey = ck.key; writeIV = ck.iv; writeSeq = 0
            }
            ku = Data()
        }
    }

    // MARK: Record writing

    private func sendRecord(type: UInt8, payload: Data) {
        var record = Data()
        record.append(type)
        record.appendBE16(0x0303)
        record.appendBE16(UInt16(payload.count))
        record.append(payload)
        raw.send(record)
    }

    private func sendEncryptedHandshake(_ message: Data) {
        guard let writeKey, let writeIV else { return }
        var plain = message
        plain.append(0x16) // inner content type: handshake
        var header = Data()
        header.append(0x17)
        header.appendBE16(0x0303)
        header.appendBE16(UInt16(plain.count + 16))
        guard let sealed = NCTLS13.sealRecord(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                              header: header, plaintext: plain) else { return }
        writeSeq += 1
        header.append(sealed)
        raw.send(header)
    }

    // MARK: NCRelayStream

    func send(_ data: Data) {
        guard handshakeDone, failed == nil else {
            writeBuffer.append(data)
            return
        }
        // Split into <=16K records.
        var rest = data
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(16384))
            rest = Data(rest.dropFirst(chunk.count))
            guard let writeKey, let writeIV else { return }
            var plain = chunk
            plain.append(0x17) // inner content type: application data
            var header = Data()
            header.append(0x17)
            header.appendBE16(0x0303)
            header.appendBE16(UInt16(plain.count + 16))
            guard let sealed = NCTLS13.sealRecord(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                                  header: header, plaintext: plain) else { return }
            writeSeq += 1
            header.append(sealed)
            raw.send(header)
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !plaintextOut.isEmpty {
            handler(plaintextOut.removeFirst(), nil)
            return
        }
        if let failed {
            handler(nil, failed)
            return
        }
        if closed {
            handler(nil, nil)
            return
        }
        pendingReceive = handler
    }

    private func deliverAppData(_ data: Data) {
        if data.isEmpty { return }
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(data, nil)
        } else {
            plaintextOut.append(data)
        }
    }

    private func deliverEOFOrError(_ error: Error?) {
        if let handler = handshakeHandler {
            handshakeHandler = nil
            handler(error ?? TLSError.closed)
        }
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(nil, error)
        }
    }

    private func fail(_ error: Error) {
        guard failed == nil else { return }
        failed = error
        if let handler = handshakeHandler {
            handshakeHandler = nil
            handler(error)
        }
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(nil, error)
        }
        raw.cancel()
    }

    func cancel() {
        closed = true
        raw.cancel()
    }
}
