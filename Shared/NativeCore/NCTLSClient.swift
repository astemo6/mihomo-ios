import Foundation
import CryptoKit
import Security

/// A hand-rolled TLS 1.3 client over an NCStream, built for REALITY (which
/// needs byte-exact control of the ClientHello) and usable as plain TLS too.
/// Plain (non-REALITY) mode falls back to TLS 1.2 when the server picks it
/// (ECDHE + AES-GCM / ChaCha20-Poly1305, see NCTLS12; feat/nc-proto A8).
/// Scope: X25519 key share, suites 1301/1302/1303, no client
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
        /// Hostname the certificate chain is verified against when it differs from the SNI
        /// (`serverName`) — restls / plugin `name-cert-verify` (mihomo SetNameCertVerify).
        var certVerifyName: String? = nil
        /// SHA-256 fingerprint pinning (restls `fingerprint`, mihomo ca.NewFingerprintVerifier): the
        /// handshake only proceeds when one of the presented certificates hashes to this value.
        /// Overrides `allowInsecure`, exactly like mihomo (SetFingerprint forces InsecureSkipVerify
        /// and does the check in VerifyConnection).
        var pinnedCertSHA256: Data? = nil
        /// ClientHello shape from the proxy's `fingerprint` field.
        var profile: NCClientHelloProfile = .chrome
        /// Plain mode only: session ID computed from the marshaled hello (zero ID in place) — shadow-tls v3.
        var sessionIDGenerator: ((Data) -> Data?)? = nil
        /// Offer TLS 1.2 only (no supported_versions) — shadow-tls v1 (feat/nc-proto3).
        var maxTLS12: Bool = false
        /// SS restls plugin (NCRestls.swift): session ID, server auth, restls application records.
        var restls: NCRestlsSession? = nil

        /// RFC 9849: Raw ECHConfigList bytes to offer Encrypted Client Hello.
        /// When nil or empty, ECH is disabled and standard TLS handshake is used.
        var echConfigList: Data? = nil
        /// Optional public name override for ClientHelloOuter SNI (defaults to selected ECHConfig.publicName).
        var outerServerName: String? = nil
        /// Optional factory to dial a new transport stream for single ECH retry on server retry_configs.
        var rawDialer: ((@escaping (NCRelayStream?, Error?) -> Void) -> Void)? = nil
    }

    enum TLSError: Error, LocalizedError, Equatable {
        case handshake(String)
        case closed
        case echRejected(retryConfigs: Data?)
        case echRetryFailed(String)

        // fix/nc-delay-test: readable in logs / the delay API instead of "NCTLSClientStream.TLSError 0".
        var errorDescription: String? {
            switch self {
            case .handshake(let why): return "TLS handshake failed: \(why)"
            case .closed: return "TLS connection closed by the peer"
            case .echRejected(let configs):
                return "TLS ECH rejected by server (retry_configs: \(configs.map { "\($0.count) bytes" } ?? "none"))"
            case .echRetryFailed(let msg):
                return "TLS ECH retry failed: \(msg)"
            }
        }
    }

    private var raw: NCRelayStream
    private var config: Config
    private let queue: DispatchQueue

    // Record layer state
    private var readBuffer = Data()
    /// Bytes of `readBuffer` already parsed into records (compacted once per batch, not per record).
    private var readOffset = 0
    private var writeBuffer = Data() // plaintext queued before handshake completes
    /// Completions of sends queued in `writeBuffer`: fired when the buffer is flushed after the
    /// handshake (or drained by fail()/cancel(), so no sender ever waits forever).
    private var bufferedCompletions: [NCCallOnce] = []
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
    private var certsDER: [Data] = []
    private var certVerify: (scheme: UInt16, signature: Data)?
    private var handshakeHandler: ((Error?) -> Void)?
    private var plaintextOut: [Data] = []
    private var plaintextBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?

    /// nc-memory: cap on decrypted plaintext queued ahead of the reader (and on the
    /// post-splice overflow queue below). The record pump is decoupled from receive(),
    /// so without this a fast peer pins unbounded plaintext while the reader is stalled;
    /// overflow fails the stream, the mux failLocal shape. 256 KB aligns with the mux
    /// stream inbound cap.
    static let maxQueuedPlaintext = 256 * 1024

    // TLS 1.3 handshake state machine (rv2-proto): ServerHello → EncryptedExtensions → Certificate →
    // CertificateVerify (signature + chain/REALITY check) → Finished. No PSK/resumption is offered, so a server
    // Finished without a verified CertificateVerify is always an authentication bypass and fails the handshake.
    private var gotEncryptedExtensions = false
    private var gotCertificate = false
    private var serverAuthenticated = false
    private var handshakeTimer: DispatchWorkItem?

    /// Limits (rv2-proto): TLS ciphertext records are at most 2^14 + 2048 bytes (RFC 5246 §6.2.3; 1.3 is tighter),
    /// a single handshake message we accept is capped (certificate chains are a few KB), and the whole handshake
    /// must finish within `handshakeTimeout`.
    static let maxRecordLength = 16384 + 2048
    static let maxHandshakeMessage = 64 * 1024
    static var handshakeTimeout: TimeInterval = 15

    // Vision direct-splice state: after spliceOut(), the record layer is
    // detached and raw socket bytes are forwarded verbatim.
    private var spliced = false
    private var splicePending: ((Data?, Error?) -> Void)?
    private var spliceOverflow: [Data] = []
    private var spliceBytes = 0

    /// ALPN the server selected (EncryptedExtensions in 1.3, ServerHello in 1.2); nil when it sent none.
    /// Valid once the handshake completion fired (feat/nc-proto2, based on astemo6/Muse NativeCore).
    private(set) var negotiatedALPN: String?

    /// application_layer_protocol_negotiation extension body: u16 list length, u8 name length, name.
    fileprivate static func parseALPN(_ ext: ArraySlice<UInt8>) -> String? {
        let e = Array(ext)
        guard e.count >= 3 else { return nil }
        let n = Int(e[2])
        guard n > 0, 3 + n <= e.count else { return nil }
        return String(bytes: e[3..<(3 + n)], encoding: .utf8)
    }

    init(raw: NCRelayStream, config: Config, queue: DispatchQueue) {
        self.raw = raw
        self.config = config
        self.queue = queue
    }

    // MARK: Handshake

    func startHandshake(completion: @escaping (Error?) -> Void) {
        handshakeHandler = completion

        // RFC 9849 / REALITY mutual exclusion: fail hard on conflict
        if config.reality != nil && config.echConfigList != nil && !config.echConfigList!.isEmpty {
            let err = TLSError.handshake("REALITY and ECH are mutually exclusive: cannot enable both on the same stream")
            handshakeHandler = nil
            completion(err)
            return
        }

        // Setup ECH if raw ECHConfigList bytes were configured
        if let echBytes = config.echConfigList, !echBytes.isEmpty {
            do {
                let selected = try NCECHConfigParser.select(fromECHConfigList: echBytes)
                echSelected = selected
                let (enc, ctx) = try selected.setupSender()
                echSenderContext = ctx
                echEnc = enc
            } catch {
                handshakeHandler = nil
                completion(TLSError.handshake("ECH config setup failed: \(error)"))
                return
            }
        }

        do {
            try sendClientHello()
        } catch {
            handshakeHandler = nil
            completion(error)
            return
        }
        armHandshakeTimer()
        pumpRaw()
    }

    private func armHandshakeTimer() {
        handshakeTimer?.cancel()
        // Slowloris guard: a server that never finishes the handshake is cut off.
        let timer = DispatchWorkItem { [weak self] in
            guard let self, !self.handshakeDone, self.handshakeHandler != nil else { return }
            self.fail(TLSError.handshake("handshake timeout"))
        }
        handshakeTimer = timer
        queue.asyncAfter(deadline: .now() + Self.handshakeTimeout, execute: timer)
    }

    /// Handshake finished successfully: stop the timer and hand the completion out once.
    private func completeHandshake() {
        handshakeTimer?.cancel()
        handshakeTimer = nil
        handshakeDone = true
        let handler = handshakeHandler
        handshakeHandler = nil
        handler?(nil)
    }

    private func sendClientHello() throws {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        clientPrivate = priv
        let clientShare = Data(priv.publicKey.rawRepresentation)

        // RFC 9849: ECH ClientHelloOuter + ClientHelloInner
        if let selected = echSelected, let ctx = echSenderContext {
            guard config.serverName.utf8.count <= 255 else { throw TLSError.handshake("server name too long") }
            clientHelloInnerRandom = NCConnector.randomData(32)
            let sessionID = Data(repeating: 0, count: 32)

            let innerHello = NCTLS13.buildClientHelloInner(
                random: clientHelloInnerRandom,
                sessionID: sessionID,
                serverName: config.serverName,
                alpn: config.alpn,
                keyShare: clientShare,
                profile: config.profile
            )
            clientHelloInner1 = innerHello

            let encodedInner = NCTLS13.encodeInnerClientHello(
                innerHello: innerHello,
                serverName: config.serverName,
                maximumNameLength: selected.config.maximumNameLength
            )

            clientRandom = NCConnector.randomData(32) // Outer random
            let publicName = config.outerServerName ?? selected.config.publicName
            guard publicName.utf8.count <= 255 else { throw TLSError.handshake("outer public_name too long") }

            let outerHello = try NCTLS13.buildClientHelloOuter(
                outerRandom: clientRandom,
                sessionID: sessionID,
                publicName: publicName,
                alpn: config.alpn,
                keyShare: clientShare,
                profile: config.profile,
                selectedConfig: selected,
                enc: echEnc,
                hpkeContext: ctx,
                encodedInner: encodedInner
            )
            clientHelloOuter1 = outerHello

            innerTranscript = innerHello
            outerTranscript = outerHello
            transcript = outerHello

            sendRecord(type: 22, payload: outerHello)
            return
        }

        clientRandom = NCConnector.randomData(32)

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
        // A server name past 255 bytes is no DNS name (max 253) and no u16-framed SNI either: fail the handshake
        // instead of sending a truncated name.
        guard config.serverName.utf8.count <= 255 else { throw TLSError.handshake("server name too long") }
        var hello = NCTLS13.buildClientHello(random: clientRandom, sessionID: Data(repeating: 0, count: 32),
                                          serverName: config.serverName, alpn: config.alpn,
                                          keyShare: clientShare, profile: config.profile)
        if config.maxTLS12, let h12 = NCShadowTLS.removingExtension(43, from: hello) { hello = h12 }
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
        } else if let gen = config.sessionIDGenerator {
            guard let sid = gen(hello), sid.count == 32 else { throw TLSError.handshake("session ID generator") }
            wireHello.replaceSubrange(39..<(39 + 32), with: sid)
        } else if let restls = config.restls {
            wireHello.replaceSubrange(39..<(39 + 32), with: restls.sessionID(hello: hello))
        }
        transcript.append(wireHello)
        sendRecord(type: 22, payload: wireHello)
    }

    private var realityAuthKey: Data?

    // ECH State (RFC 9849)
    private var echSelected: NCECHSelectedConfig?
    private var echSenderContext: NCHPKEContextS?
    private var echEnc = Data()
    private var clientHelloInner1 = Data()
    private var clientHelloOuter1 = Data()
    private var clientHelloInnerRandom = Data()
    private var innerTranscript = Data()
    private var outerTranscript = Data()
    private var innerTranscriptBeforeSH = Data()
    private var lastServerHelloMessage: Data?
    private(set) var echAccepted: Bool? = nil
    private var echRetryConfigs: Data?
    private var echRetried = false
    private var hrrReceived = false

    // TLS 1.2 fallback state (nil suite = TLS 1.3).
    private var tls12: NCTLS12.Suite?
    private var serverRandom = Data()
    private var tls12EMS = false
    private var tls12SKE: NCTLS12.ServerKeyExchange?
    private var tls12Master = Data()
    private var tls12NeedClientCert = false
    private var tls12ReadOn = false
    private var tls12ServerKey = Data(), tls12ServerIV = Data()
    /// Client flight (CKE/CCS/Finished) sent: master secret and server keys exist (rv2-proto state checks).
    private var tls12FlightSent = false

    // MARK: Record pump

    private func pumpRaw() {
        raw.receive { [weak self] data, error in
            guard let self else { return }
            if self.spliced {
                // Vision direct splice: socket bytes are inner plaintext now.
                if let data {
                    if let h = self.splicePending { self.splicePending = nil; h(data, nil) }
                    else if self.spliceBytes + data.count <= Self.maxQueuedPlaintext {
                        self.spliceBytes += data.count
                        self.spliceOverflow.append(data)
                    } else {
                        // nc-memory: splice overflow cap (see maxQueuedPlaintext).
                        self.closed = true
                        self.raw.cancel()
                        return
                    }
                    self.pumpRaw()
                } else {
                    self.closed = true
                    if let h = self.splicePending { self.splicePending = nil; h(nil, error) }
                }
                return
            }
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

    /// Index-based record parsing (rv2-proto): `readBuffer` may be a slice (non-zero startIndex), so every read is
    /// startIndex-relative, and consumed bytes are dropped once per batch instead of copying the tail per record.
    /// `readOffset` stays exact after every record because a Vision splice (spliceOut) can happen inside
    /// handleRecord and must see only the unparsed tail.
    private func processRecords() {
        defer { compactReadBuffer() }
        while !spliced, failed == nil {
            let base = readBuffer.startIndex + readOffset
            guard readBuffer.endIndex - base >= 5 else { return }
            let type = readBuffer[base]
            let len = Int(readBuffer[base + 3]) << 8 | Int(readBuffer[base + 4])
            guard len <= Self.maxRecordLength else {
                fail(TLSError.handshake("record too long (\(len))"))
                return
            }
            guard readBuffer.endIndex - base >= 5 + len else { return }
            let header = Data(readBuffer[base..<(base + 5)])
            let payload = Data(readBuffer[(base + 5)..<(base + 5 + len)])
            readOffset += 5 + len
            handleRecord(type: type, header: header, payload: payload)
        }
    }

    private func compactReadBuffer() {
        guard readOffset > 0 else { return }
        if readOffset >= readBuffer.count {
            readBuffer = Data()
        } else {
            readBuffer = Data(readBuffer[(readBuffer.startIndex + readOffset)...])
        }
        readOffset = 0
    }

    private func handleRecord(type: UInt8, header: Data, payload: Data) {
        if let suite12 = tls12 {
            handleRecord12(suite: suite12, type: type, header: header, payload: payload)
            return
        }
        if let restls = config.restls, handshakeDone, restls.authed {
            handleRestlsRecord13(restls, type: type, header: header, payload: payload)
            return
        }
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
                var opened: Data?
                if let restls = config.restls, restls.authPending {
                    // restls server auth: the first encrypted server record is masked (NCRestls.swift).
                    restls.authPending = false
                    opened = NCTLS13.openRecord(suite: suite, key: readKey!, iv: readIV!, seq: readSeq,
                                                header: header, sealed: restls.maskedAuthPayload(payload))
                    guard opened != nil else {
                        fail(TLSError.handshake("restls: server authentication failed (not a restls server or wrong password)"))
                        return
                    }
                    restls.authed = true
                } else {
                    opened = NCTLS13.openRecord(suite: suite, key: readKey!, iv: readIV!, seq: readSeq,
                                                header: header, sealed: payload)
                }
                guard let plain = opened else {
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
        var off = 0
        defer {
            if off >= handshakeBuffer.count { handshakeBuffer = Data() }
            else if off > 0 { handshakeBuffer = Data(handshakeBuffer[(handshakeBuffer.startIndex + off)...]) }
        }
        while failed == nil {
            let base = handshakeBuffer.startIndex + off
            guard handshakeBuffer.endIndex - base >= 4 else { return }
            let msgType = handshakeBuffer[base]
            let len = Int(handshakeBuffer[base + 1]) << 16 | Int(handshakeBuffer[base + 2]) << 8 | Int(handshakeBuffer[base + 3])
            guard len <= Self.maxHandshakeMessage else {
                fail(TLSError.handshake("handshake message too long (\(len))"))
                return
            }
            guard handshakeBuffer.endIndex - base >= 4 + len else { return }
            let message = Data(handshakeBuffer[base..<(base + 4 + len)])
            off += 4 + len
            processHandshakeMessage(type: msgType, message: message)
        }
    }

    private func processHandshakeMessage(type: UInt8, message: Data) {
        if tls12 != nil {
            processHandshake12(type: type, message: message)
            return
        }
        switch type {
        case 2: // ServerHello (exactly once, in plaintext; HelloRetryRequest is not supported)
            guard readKey == nil, handshakeSecretStored == nil, !handshakeDone else {
                fail(TLSError.handshake("unexpected ServerHello"))
                return
            }
            handleServerHello(message)
        case 8: // EncryptedExtensions: first encrypted handshake message
            guard readKey != nil, !gotEncryptedExtensions, !handshakeDone else {
                fail(TLSError.handshake("unexpected EncryptedExtensions"))
                return
            }
            gotEncryptedExtensions = true
            transcript.append(message)
            parseEncryptedExtensions(message)
        case 11: // Certificate
            guard gotEncryptedExtensions, !gotCertificate, !handshakeDone else {
                fail(TLSError.handshake("unexpected Certificate"))
                return
            }
            gotCertificate = true
            transcript.append(message)
            parseCertificates(message)
            if failed == nil, certsDER.isEmpty { fail(TLSError.handshake("empty server Certificate")) }
        case 15: // CertificateVerify: its signed hash covers CH..Certificate,
            // so verify first and append to the transcript afterwards.
            guard gotCertificate, !serverAuthenticated, !handshakeDone else {
                fail(TLSError.handshake("unexpected CertificateVerify"))
                return
            }
            parseCertificateVerify(message)
            if failed == nil {
                serverAuthenticated = true
                transcript.append(message)
            }
        case 20: // Finished: only after a verified Certificate + CertificateVerify (no PSK mode is offered).
            guard !handshakeDone else { fail(TLSError.handshake("unexpected Finished")); return }
            guard serverAuthenticated else {
                fail(TLSError.handshake("server Finished without a verified CertificateVerify"))
                return
            }
            handleServerFinished(message)
        case 4: // NewSessionTicket (post-handshake): ignore, not in transcript
            guard handshakeDone else { fail(TLSError.handshake("NewSessionTicket before Finished")); return }
            return
        case 24: // KeyUpdate
            guard handshakeDone else { fail(TLSError.handshake("KeyUpdate before Finished")); return }
            handleKeyUpdate(message)
        case 13: // CertificateRequest: client certificates are not supported (we would answer nothing → server aborts)
            guard gotEncryptedExtensions, !gotCertificate, !handshakeDone else {
                fail(TLSError.handshake("unexpected CertificateRequest"))
                return
            }
            transcript.append(message)
        default:
            if handshakeDone { return }
            transcript.append(message)
        }
    }

    /// EncryptedExtensions: u16 length, then type/len/body entries; we read ALPN (16) and ECH (0xfe0d).
    private func parseEncryptedExtensions(_ message: Data) {
        let b = [UInt8](message)
        guard b.count >= 6 else { return }
        var idx = 6
        let end = min(b.count, 6 + (Int(b[4]) << 8 | Int(b[5])))
        while idx + 4 <= end {
            let t = UInt16(b[idx]) << 8 | UInt16(b[idx + 1])
            let n = Int(b[idx + 2]) << 8 | Int(b[idx + 3])
            guard idx + 4 + n <= end else { break }
            if t == 16 { negotiatedALPN = Self.parseALPN(b[(idx + 4)..<(idx + 4 + n)]) }
            if t == NCTLS13.extensionECH {
                let payload = Data(b[(idx + 4)..<(idx + 4 + n)])
                if echAccepted == false {
                    echRetryConfigs = payload
                } else if echAccepted == true {
                    if payload.count == 8, let lastSH = lastServerHelloMessage,
                       let expected = NCTLS13.computeAcceptConfirmation(kind: kind, innerTranscript: innerTranscriptBeforeSH, serverHello: lastSH, innerRandom: clientHelloInnerRandom),
                       payload != expected {
                        echAccepted = false
                    }
                }
            }
            idx += 4 + n
        }
    }

    private func handleServerHello(_ message: Data) {
        let body = Data(message.dropFirst(4))
        guard body.count >= 34 else { fail(TLSError.handshake("short ServerHello")); return }
        serverRandom = Data(body[body.startIndex + 2..<body.startIndex + 34])
        // version(2) random(32) session_id(1+..) cipher(2) compression(1) exts(2..)
        var idx = 34
        guard body.count > idx else { fail(TLSError.handshake("bad ServerHello")); return }
        let sidLen = Int(body[idx]); idx += 1 + sidLen
        guard body.count >= idx + 3 else { fail(TLSError.handshake("bad ServerHello")); return }
        let suiteValue = UInt16(body[idx]) << 8 | UInt16(body[idx + 1]); idx += 2
        if config.reality == nil, NCTLS13.Suite(rawValue: suiteValue) == nil {
            handleServerHello12(message: message, body: body, suiteValue: suiteValue, extStart: idx + 1)
            return
        }
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

        // RFC 9849 §6.1.5 / RFC 8446 §4.1.3:
        // ECH-specific HRR is only intercepted when ECH was active and offered.
        // For non-ECH connections, fallback to baseline RFC 8446 handling (unchanged byte-for-byte).
        if echSelected != nil, serverRandom == NCTLS13.helloRetryRequestRandom {
            guard !hrrReceived else {
                fail(TLSError.handshake("multiple HelloRetryRequest messages received"))
                return
            }
            hrrReceived = true
            handleECHHelloRetryRequest(message: message, body: body, extStart: idx, extEnd: extEnd)
            return
        }

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

        // RFC 9849 §6.1.4 & §7.2: Verify accept_confirmation when ECH was offered
        if echSelected != nil {
            lastServerHelloMessage = message
            innerTranscriptBeforeSH = innerTranscript
            if let expectedConf = NCTLS13.computeAcceptConfirmation(
                kind: kind,
                innerTranscript: innerTranscript,
                serverHello: message,
                innerRandom: clientHelloInnerRandom
            ) {
                if serverRandom.suffix(8) == expectedConf {
                    echAccepted = true
                    transcript = innerTranscript
                } else {
                    echAccepted = false
                    transcript = outerTranscript
                }
            } else {
                echAccepted = false
                transcript = outerTranscript
            }
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
        if let restls = config.restls {
            restls.serverRandom = [UInt8](serverRandom)
            restls.authPending = true
        }
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
        } else if !certificatePolicyValid() {
            fail(TLSError.handshake("certificate not trusted"))
            return
        }
    }

    /// The certificate decision for plain mode (both TLS versions): fingerprint pinning when
    /// configured, else SecTrust against the system roots — always under `certVerifyName`
    /// when set (name-cert-verify), else the SNI name. A pin overrides allowInsecure (mihomo
    /// semantics); without a pin, allowInsecure waives the SecTrust result.
    private func certificatePolicyValid() -> Bool {
        // RFC 9849 §6.1.6: When server rejects ECH, the certificate presented in the
        // outer handshake authenticates the outer publicName, not the inner destination.
        // pinnedCertSHA256 pins the inner service certificate and must only be evaluated
        // on the final accepted connection (echAccepted != false).
        // For outer verification during ECH rejection, validate the outer certificate
        // against system roots for publicName.
        if echAccepted == false {
            return config.allowInsecure || secTrustValid(anchoredAt: nil)
        }

        if let pin = config.pinnedCertSHA256 {
            for (i, der) in certsDER.enumerated() where Data(SHA256.hash(data: der)) == pin {
                // Leaf match: accepted as-is (mihomo's verifier does no hostname check here).
                // Non-leaf match: that certificate becomes the trust anchor and the leaf chain
                // (plus hostname) must verify up to it.
                return i == 0 || secTrustValid(anchoredAt: i)
            }
            return false
        }
        return config.allowInsecure || secTrustValid(anchoredAt: nil)
    }

    /// SecTrust evaluation of the presented chain; with `anchoredAt` the chain is truncated at
    /// that certificate, which also becomes the only trust anchor (fingerprint pinning).
    private func secTrustValid(anchoredAt anchor: Int?) -> Bool {
        let presented = anchor.map { Array(certsDER[...$0]) } ?? certsDER
        let certs = presented.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certs.count == presented.count, !certs.isEmpty else { return false }
        let name: String
        if echAccepted == false {
            name = config.outerServerName ?? echSelected?.config.publicName ?? config.serverName
        } else {
            name = config.certVerifyName ?? config.serverName
        }
        let policy = SecPolicyCreateSSL(true, name as CFString)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return false }
        if let anchor {
            guard SecTrustSetAnchorCertificates(trust, [certs[anchor]] as CFArray) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        }
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
        guard let handshakeSecret = handshakeSecretStored else { fail(TLSError.handshake("Finished before keys")); return }
        let derived = NCTLS13.deriveSecret(kind, secret: handshakeSecret, label: "derived", transcriptHash: kind.hash(Data()))
        let master = NCTLS13.hkdfExtract(kind, salt: derived, ikm: Data(repeating: 0, count: kind.length))
        let cAP = NCTLS13.deriveSecret(kind, secret: master, label: "c ap traffic", transcriptHash: hashThroughServerFinished)
        let sAP = NCTLS13.deriveSecret(kind, secret: master, label: "s ap traffic", transcriptHash: hashThroughServerFinished)
        // Send client Finished under the handshake write keys first.
        guard let hsWriteSecret = writeSecret else { fail(TLSError.handshake("Finished before keys")); return }
        let verifyData = NCTLS13.finishedVerifyData(kind, trafficSecret: hsWriteSecret, transcriptHash: hashThroughServerFinished)
        var finished = Data()
        finished.append(0x14)
        finished.append(0x00)
        finished.appendBE16(UInt16(verifyData.count))
        finished.append(verifyData)
        let finishedRecord = sendEncryptedHandshake(finished)
        if let restls = config.restls, restls.authed { restls.clientFinished = finishedRecord.map { [UInt8]($0) } }

        // RFC 9849 §6.1.6: If server rejected ECH, evaluate retry_configs or abort connection
        if echAccepted == false {
            if let retryConfigs = echRetryConfigs, !echRetried, let dialer = config.rawDialer {
                echRetried = true
                let savedHandler = handshakeHandler
                handshakeHandler = nil
                raw.cancel()
                resetForRetry()

                do {
                    let selected = try NCECHConfigParser.select(fromECHConfigList: retryConfigs)
                    echSelected = selected
                    let (enc, ctx) = try selected.setupSender()
                    echSenderContext = ctx
                    echEnc = enc
                    config.echConfigList = retryConfigs
                } catch {
                    handshakeHandler = savedHandler
                    sendAlert(description: NCTLS13.alertECHRequired)
                    fail(TLSError.echRetryFailed("Failed to parse server retry_configs: \(error)"))
                    return
                }

                dialer { [weak self] newRaw, dialErr in
                    guard let self else { return }
                    self.handshakeHandler = savedHandler
                    if let dialErr {
                        self.fail(TLSError.echRetryFailed("Reconnection failed: \(dialErr)"))
                        return
                    }
                    guard let newRaw else {
                        self.fail(TLSError.echRetryFailed("Reconnection returned nil stream"))
                        return
                    }
                    self.raw = newRaw
                    do {
                        try self.sendClientHello()
                        self.armHandshakeTimer()
                        self.pumpRaw()
                    } catch {
                        self.fail(TLSError.echRetryFailed("Send ClientHello failed on retry: \(error)"))
                    }
                }
                return
            } else if echRetried {
                sendAlert(description: NCTLS13.alertECHRequired)
                fail(TLSError.echRetryFailed("Server rejected ECH after retry"))
                return
            } else {
                sendAlert(description: NCTLS13.alertECHRequired)
                fail(TLSError.echRejected(retryConfigs: echRetryConfigs))
                return
            }
        }

        // Switch to application keys.
        let ck = NCTLS13.trafficKeyIV(kind, suite: suite, secret: cAP)
        let sk = NCTLS13.trafficKeyIV(kind, suite: suite, secret: sAP)
        writeKey = ck.key; writeIV = ck.iv; writeSeq = 0; writeSecret = cAP
        readKey = sk.key; readIV = sk.iv; readSeq = 0; readSecret = sAP
        transcript = Data() // not needed any more (memory)
        completeHandshake()
        // Flush queued plaintext.
        let queued = writeBuffer
        writeBuffer = Data()
        let queuedCompletions = bufferedCompletions
        bufferedCompletions = []
        if !queued.isEmpty {
            send(queued) { queuedCompletions.forEach { $0.call() } }
        } else {
            queuedCompletions.forEach { $0.call() }
        }
    }

    private func handleECHHelloRetryRequest(message: Data, body: Data, extStart: Int, extEnd: Int) {
        let extsData = body.subdata(in: extStart..<extEnd)

        // RFC 8446 §4.1.4: Verify selected_version (supported_versions extension must be 0x0304)
        guard let versionData = NCTLS13.parseExtension(type: 43, fromExtensionsData: extsData),
              versionData.count >= 2, (UInt16(versionData[0]) << 8 | UInt16(versionData[1])) == 0x0304 else {
            fail(TLSError.handshake("HRR missing or invalid supported_versions"))
            return
        }

        // RFC 8446 §4.1.4 & §4.2.8: Key share selected group
        var hrrKeyShareGroup: UInt16? = nil
        if let ksData = NCTLS13.parseExtension(type: 51, fromExtensionsData: extsData) {
            guard ksData.count >= 2 else {
                fail(TLSError.handshake("HRR malformed key_share extension"))
                return
            }
            let group = UInt16(ksData[0]) << 8 | UInt16(ksData[1])
            guard group == 0x001d else {
                fail(TLSError.handshake("HRR requested unsupported key share group \(group)"))
                return
            }
            hrrKeyShareGroup = group
        }

        let cookie = NCTLS13.parseExtension(type: NCTLS13.extensionCookie, fromExtensionsData: extsData)

        // RFC 9849 §6.1.5 & §7.2.1: Verify HRR accept confirmation
        if let hrrECHExt = NCTLS13.parseExtension(type: NCTLS13.extensionECH, fromExtensionsData: extsData) {
            guard hrrECHExt.count == 8 else {
                fail(TLSError.handshake("HRR ECH extension length must be 8"))
                return
            }
            if let expectedHRRConf = NCTLS13.computeHRRAcceptConfirmation(
                kind: kind,
                innerTranscript: innerTranscript,
                hrrMessage: message,
                hrrECHPayload: hrrECHExt,
                innerRandom: clientHelloInnerRandom
            ), expectedHRRConf == hrrECHExt {
                echAccepted = true
            } else {
                echAccepted = false
            }
        } else {
            echAccepted = false
        }

        // RFC 8446 §4.4.1 & RFC 9849 §6.1.5: Synthetic message_hash replacement in transcripts
        innerTranscript = NCTLS13.syntheticMessageHash(for: clientHelloInner1, kind: kind)
        innerTranscript.append(message)
        outerTranscript = NCTLS13.syntheticMessageHash(for: clientHelloOuter1, kind: kind)
        outerTranscript.append(message)

        guard let priv = clientPrivate else {
            fail(TLSError.handshake("missing client key share"))
            return
        }
        let clientShare = Data(priv.publicKey.rawRepresentation)

        // Derive ClientHelloInner2 from ClientHelloInner1
        guard let innerHello2 = NCTLS13.deriveClientHelloInner2(
            from: clientHelloInner1,
            cookie: cookie,
            keyShare: hrrKeyShareGroup != nil ? clientShare : nil
        ) else {
            fail(TLSError.handshake("failed to derive ClientHelloInner2"))
            return
        }
        innerTranscript.append(innerHello2)

        let encodedInner2 = NCTLS13.encodeInnerClientHello(
            innerHello: innerHello2,
            serverName: config.serverName,
            maximumNameLength: echSelected!.config.maximumNameLength
        )

        // Derive ClientHelloOuter2 from ClientHelloOuter1
        do {
            let outerHello2 = try NCTLS13.deriveClientHelloOuter2(
                from: clientHelloOuter1,
                cookie: cookie,
                keyShare: hrrKeyShareGroup != nil ? clientShare : nil,
                selectedConfig: echSelected!,
                hpkeContext: echSenderContext!,
                encodedInner2: encodedInner2
            )
            outerTranscript.append(outerHello2)
            transcript = outerTranscript
            sendRecord(type: 22, payload: outerHello2)
        } catch {
            fail(TLSError.handshake("HRR derive ClientHelloOuter2 failed: \(error)"))
        }
    }

    private func resetForRetry() {
        handshakeTimer?.cancel()
        handshakeTimer = nil
        handshakeDone = false
        failed = nil
        closed = false
        readBuffer = Data()
        readOffset = 0
        writeBuffer = Data()
        bufferedCompletions = []
        readKey = nil; readIV = nil; readSeq = 0; readSecret = nil
        writeKey = nil; writeIV = nil; writeSeq = 0; writeSecret = nil
        handshakeSecretStored = nil
        transcript = Data()
        clientPrivate = nil
        clientRandom = Data()
        serverFinishedHash = nil
        certsDER = []
        certVerify = nil
        handshakeBuffer = Data()
        gotEncryptedExtensions = false
        gotCertificate = false
        serverAuthenticated = false
        hrrReceived = false
        echRetryConfigs = nil
        echAccepted = nil
        innerTranscript = Data()
        outerTranscript = Data()
        innerTranscriptBeforeSH = Data()
        lastServerHelloMessage = nil
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

    /// RFC 8446 §6 & RFC 9849 §10.5: Sends TLS alert.
    /// In TLS 1.3, if handshake keys are active, the alert is sent as an encrypted record
    /// (content type 23, inner content type 21); otherwise sent as plaintext record (content type 21).
    private func sendAlert(description: UInt8, fatal: Bool = true) {
        let level: UInt8 = fatal ? 2 : 1
        let alertPayload = Data([level, description])
        if let writeKey, let writeIV {
            var plain = alertPayload
            plain.append(0x15) // inner content type: alert (21)
            var header = Data()
            header.append(0x17) // application_data (23) for encrypted record in TLS 1.3
            header.appendBE16(0x0303)
            header.appendBE16(UInt16(plain.count + 16))
            if let sealed = NCTLS13.sealRecord(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                               header: header, plaintext: plain) {
                writeSeq += 1
                header.append(sealed)
                raw.send(header)
            }
        } else {
            sendRecord(type: 21, payload: alertPayload)
        }
    }

    private func sendRecord(type: UInt8, payload: Data) {
        var record = Data()
        record.append(type)
        record.appendBE16(0x0303)
        record.appendBE16(UInt16(payload.count))
        record.append(payload)
        raw.send(record)
    }

    @discardableResult
    private func sendEncryptedHandshake(_ message: Data) -> Data? {
        guard let writeKey, let writeIV else { return nil }
        var plain = message
        plain.append(0x16) // inner content type: handshake
        var header = Data()
        header.append(0x17)
        header.appendBE16(0x0303)
        header.appendBE16(UInt16(plain.count + 16))
        guard let sealed = NCTLS13.sealRecord(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                              header: header, plaintext: plain) else { return nil }
        writeSeq += 1
        header.append(sealed)
        raw.send(header)
        return header
    }

    // MARK: NCRelayStream

    /// Plaintext queued before the handshake completes is capped (memory first); past it the stream fails.
    static let maxQueuedBeforeHandshake = 256 * 1024

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        if failed != nil { once.call(); return }
        guard handshakeDone else {
            guard writeBuffer.count + data.count <= Self.maxQueuedBeforeHandshake else {
                fail(TLSError.handshake("too much data queued before the handshake completed"))
                once.call()
                return
            }
            writeBuffer.append(data)
            bufferedCompletions.append(once)
            return
        }
        if let restls = config.restls, restls.authed {
            let recs = restls.records(for: data)
            if restls.sendOverflowed {
                // nc-memory: restls sendBuf cap hit (see NCRestlsSession.maxSendBuf).
                fail(TLSError.handshake("restls send buffer overflow"))
                once.call()
                return
            }
            raw.ncSendSequentially(recs, completion: once.call)
            return
        }
        if let suite12 = tls12 {
            var wires: [Data] = []
            var rest = data[...]
            while !rest.isEmpty {
                let chunk = Data(rest.prefix(16384))
                rest = rest.dropFirst(chunk.count)
                guard let rec = record12(suite: suite12, type: 23, plaintext: chunk) else {
                    raw.cancel(); once.call(); return
                }
                wires.append(rec)
            }
            raw.ncSendSequentially(wires, completion: once.call)
            return
        }
        // Split into <=16K records (slice walk, no tail copy per record).
        var wires: [Data] = []
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(16384))
            rest = rest.dropFirst(chunk.count)
            guard let writeKey, let writeIV else { raw.cancel(); once.call(); return }
            var plain = chunk
            plain.append(0x17) // inner content type: application data
            var header = Data()
            header.append(0x17)
            header.appendBE16(0x0303)
            header.appendBE16(UInt16(plain.count + 16))
            guard let sealed = NCTLS13.sealRecord(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                                  header: header, plaintext: plain) else {
                raw.cancel(); once.call(); return
            }
            writeSeq += 1
            header.append(sealed)
            wires.append(header)
        }
        raw.ncSendSequentially(wires, completion: once.call)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !plaintextOut.isEmpty {
            let data = plaintextOut.removeFirst()
            plaintextBytes -= data.count
            handler(data, nil)
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
        if failed != nil { return }
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(data, nil)
        } else if plaintextBytes + data.count <= Self.maxQueuedPlaintext {
            plaintextBytes += data.count
            plaintextOut.append(data)
        } else {
            // nc-memory: queued-plaintext cap (see maxQueuedPlaintext).
            fail(TLSError.handshake("plaintext queue overflow"))
            raw.cancel()
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
        handshakeTimer?.cancel()
        handshakeTimer = nil
        writeBuffer = Data()
        let bc = bufferedCompletions; bufferedCompletions = []; bc.forEach { $0.call() }
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
        handshakeTimer?.cancel()
        handshakeTimer = nil
        writeBuffer = Data()
        let bc = bufferedCompletions; bufferedCompletions = []; bc.forEach { $0.call() }
        raw.cancel()
    }

    // MARK: Vision direct splice

    /// The raw socket under this TLS session.
    var rawStream: NCRelayStream { raw }

    /// Detach from the record layer (XTLS Vision commandDirect): returns the
    /// decrypted-but-unconsumed plaintext chunks and the unparsed raw tail —
    /// bytes past the last complete record, which after a splice are inner
    /// plaintext (mirrors Go tls.Conn's rawInput drain). From now on, raw
    /// socket bytes are delivered verbatim through `receiveSpliced`.
    func spliceOut() -> (plaintext: [Data], rawTail: Data) {
        spliced = true
        let plain = plaintextOut
        plaintextOut = []
        plaintextBytes = 0
        let tail = readOffset >= readBuffer.count ? Data() : Data(readBuffer[(readBuffer.startIndex + readOffset)...])
        readBuffer = Data()
        readOffset = 0
        return (plain, tail)
    }

    /// One-shot verbatim receive for post-splice raw bytes.
    func receiveSpliced(_ handler: @escaping (Data?, Error?) -> Void) {
        if !spliceOverflow.isEmpty {
            let data = spliceOverflow.removeFirst()
            spliceBytes -= data.count
            handler(data, nil)
            return
        }
        if closed {
            handler(nil, nil)
            return
        }
        splicePending = handler
    }
}

// MARK: - TLS 1.2 fallback (feat/nc-proto A8, based on astemo6/Muse NativeCore)

extension NCTLSClientStream {
    fileprivate static let downgradeTLS12 = Data("DOWNGRD".utf8) + Data([0x01])

    fileprivate func handleServerHello12(message: Data, body: Data, suiteValue: UInt16, extStart: Int) {
        guard let suite = NCTLS12.Suite(rawValue: suiteValue) else {
            fail(TLSError.handshake("suite \(String(suiteValue, radix: 16)) not offered"))
            return
        }
        let b = [UInt8](body)
        guard b.count >= 2, b[0] == 3, b[1] == 3 else { fail(TLSError.handshake("server version not TLS 1.2")); return }
        // We offered 1.3: a 1.2 answer carrying the RFC 8446 §4.1.3 sentinel means an active downgrade.
        if !config.maxTLS12, serverRandom.suffix(8) == Self.downgradeTLS12 { fail(TLSError.handshake("TLS downgrade detected")); return }
        var idx = extStart
        if idx + 2 <= b.count {
            let extLen = Int(b[idx]) << 8 | Int(b[idx + 1]); idx += 2
            let end = min(b.count, idx + extLen)
            while idx + 4 <= end {
                let t = UInt16(b[idx]) << 8 | UInt16(b[idx + 1])
                let n = Int(b[idx + 2]) << 8 | Int(b[idx + 3])
                if t == 23 { tls12EMS = true }
                if t == 16, idx + 4 + n <= end { negotiatedALPN = Self.parseALPN(b[(idx + 4)..<(idx + 4 + n)]) }
                if t == 43 { fail(TLSError.handshake("TLS 1.2 suite with supported_versions")); return }
                idx += 4 + n
            }
        }
        tls12 = suite
        kind = suite.hashKind
        transcript.append(message)
        if let restls = config.restls {
            restls.serverRandom = [UInt8](serverRandom)
            restls.gcm12 = !suite.isChaCha // restls tls12GCMCiphers = c02f c02b c030 c02c
        }
    }

    fileprivate func processHandshake12(type: UInt8, message: Data) {
        let body = Data(message.dropFirst(4))
        // State machine (rv2-proto): ServerHello → Certificate → ServerKeyExchange (signature over the randoms +
        // params verified against the leaf, always — skip-cert-verify only waives the chain/SecTrust check) →
        // [CertificateRequest] → ServerHelloDone → (our flight) → CCS → Finished. Only ECDHE suites are offered, so
        // a ServerKeyExchange is mandatory and the handshake cannot finish without that signature.
        if handshakeDone, type != 0, type != 4 { return } // post-handshake: renegotiation unsupported
        switch type {
        case 11: // Certificate
            guard certsDER.isEmpty, tls12SKE == nil, !tls12FlightSent else {
                fail(TLSError.handshake("unexpected Certificate"))
                return
            }
            certsDER = NCTLS12.parseCertificates(body)
            guard !certsDER.isEmpty else { fail(TLSError.handshake("empty server Certificate")); return }
            transcript.append(message)
        case 12: // ServerKeyExchange
            guard tls12SKE == nil, !tls12FlightSent else {
                fail(TLSError.handshake("unexpected ServerKeyExchange"))
                return
            }
            guard let ske = NCTLS12.parseServerKeyExchange(body),
                  let leaf = certsDER.first, let cert = NCX509Certificate(der: leaf) else {
                fail(TLSError.handshake("bad ServerKeyExchange"))
                return
            }
            let signed = clientRandom + serverRandom + ske.params
            guard NCTLS12.verifySignature(scheme: ske.scheme, cert: cert, content: signed, signature: ske.signature) else {
                fail(TLSError.handshake("ServerKeyExchange signature invalid"))
                return
            }
            if !certificatePolicyValid() {
                fail(TLSError.handshake("certificate not trusted"))
                return
            }
            tls12SKE = ske
            transcript.append(message)
        case 13: // CertificateRequest: answered with an empty Certificate
            tls12NeedClientCert = true
            transcript.append(message)
        case 14: // ServerHelloDone
            guard tls12SKE != nil, !tls12FlightSent else {
                fail(TLSError.handshake("ServerHelloDone without a verified ServerKeyExchange"))
                return
            }
            transcript.append(message)
            sendClientFlight12()
        case 4: // NewSessionTicket (before the server's CCS): part of the Finished transcript
            if !handshakeDone { transcript.append(message) }
        case 20: // server Finished
            guard tls12ReadOn, tls12FlightSent, tls12SKE != nil else {
                fail(TLSError.handshake("Finished before ChangeCipherSpec"))
                return
            }
            let expected = NCTLS12.prf(kind, secret: tls12Master, label: "server finished",
                                       seed: kind.hash(transcript), length: 12)
            guard body == expected else { fail(TLSError.handshake("server Finished verify failed")); return }
            transcript = Data() // not needed any more
            completeHandshake()
            let queued = writeBuffer
            writeBuffer = Data()
            let queuedCompletions = bufferedCompletions
            bufferedCompletions = []
            if !queued.isEmpty {
                send(queued) { queuedCompletions.forEach { $0.call() } }
            } else {
                queuedCompletions.forEach { $0.call() }
            }
        case 0: // HelloRequest: renegotiation is not supported, ignore (RFC 5246 allows it)
            return
        default:
            if !handshakeDone { transcript.append(message) } // CertificateStatus etc.
        }
    }

    private func sendClientFlight12() {
        // restls (tls12 hint): the eager key whose public half the session ID committed to.
        let eager = config.restls.flatMap { r in tls12SKE.flatMap { r.eagerECDHE(group: $0.group, serverPublic: $0.publicKey) } }
        guard let suite = tls12, let ske = tls12SKE,
              let (pub, pms) = eager ?? NCTLS12.ecdhe(group: ske.group, serverPublic: ske.publicKey) else {
            fail(TLSError.handshake("ECDHE failed (curve not supported)"))
            return
        }
        if tls12NeedClientCert {
            let empty = Data([0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00])
            transcript.append(empty)
            sendRecord(type: 22, payload: empty)
        }
        var cke = Data([0x10, 0x00])
        cke.appendBE16(UInt16(pub.count + 1))
        cke.append(UInt8(pub.count))
        cke.append(pub)
        transcript.append(cke)
        sendRecord(type: 22, payload: cke)
        if tls12EMS {
            tls12Master = NCTLS12.prf(kind, secret: pms, label: "extended master secret",
                                      seed: kind.hash(transcript), length: 48)
        } else {
            tls12Master = NCTLS12.prf(kind, secret: pms, label: "master secret",
                                      seed: clientRandom + serverRandom, length: 48)
        }
        let keys = NCTLS12.keyBlock(suite: suite, master: tls12Master, clientRandom: clientRandom,
                                    serverRandom: serverRandom)
        writeKey = keys.clientKey; writeIV = keys.clientIV; writeSeq = 0
        tls12ServerKey = keys.serverKey; tls12ServerIV = keys.serverIV
        sendRecord(type: 20, payload: Data([0x01]))
        let verify = NCTLS12.prf(kind, secret: tls12Master, label: "client finished",
                                 seed: kind.hash(transcript), length: 12)
        var fin = Data([0x14, 0x00, 0x00, 0x0c])
        fin.append(verify)
        transcript.append(fin)
        sendRecord12(suite: suite, type: 22, plaintext: fin)
        tls12FlightSent = true
    }

    /// One sealed TLS 1.2 record as wire bytes (sendRecord12 without the send), for completion sends.
    fileprivate func record12(suite: NCTLS12.Suite, type: UInt8, plaintext: Data) -> Data? {
        guard let writeKey, let writeIV,
              let sealed = NCTLS12.seal(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                        type: type, plaintext: plaintext) else { return nil }
        writeSeq += 1
        var record = Data(capacity: 5 + sealed.count)
        record.append(type)
        record.appendBE16(0x0303)
        record.appendBE16(UInt16(sealed.count))
        record.append(sealed)
        return record
    }

    fileprivate func sendRecord12(suite: NCTLS12.Suite, type: UInt8, plaintext: Data) {
        guard let writeKey, let writeIV,
              let sealed = NCTLS12.seal(suite: suite, key: writeKey, iv: writeIV, seq: writeSeq,
                                        type: type, plaintext: plaintext) else { return }
        writeSeq += 1
        var record = Data(capacity: 5 + sealed.count)
        record.append(type)
        record.appendBE16(0x0303)
        record.appendBE16(UInt16(sealed.count))
        record.append(sealed)
        raw.send(record)
    }

    fileprivate func handleRecord12(suite: NCTLS12.Suite, type: UInt8, header: Data, payload: Data) {
        if type == 20 { // ChangeCipherSpec: server switches to the negotiated keys
            if handshakeDone, config.restls != nil { return } // restls post-handshake path ignores CCS
            guard tls12FlightSent, !tls12ReadOn else { fail(TLSError.handshake("unexpected ChangeCipherSpec")); return }
            tls12ReadOn = true
            readSeq = 0
            if let restls = config.restls, !restls.authed { restls.authPending = true }
            return
        }
        if let restls = config.restls, handshakeDone, restls.authed {
            handleRestlsRecord12(restls, suite: suite, type: type, header: header, payload: payload)
            return
        }
        var content = payload
        if tls12ReadOn {
            var opened: Data?
            if let restls = config.restls, restls.authPending {
                // restls server auth: the server Finished record is masked (NCRestls.swift).
                restls.authPending = false
                opened = NCTLS12.open(suite: suite, key: tls12ServerKey, iv: tls12ServerIV, seq: readSeq,
                                      type: type, payload: restls.maskedAuthPayload(payload))
                guard opened != nil else {
                    fail(TLSError.handshake("restls: server authentication failed (not a restls server or wrong password)"))
                    return
                }
                restls.authed = true
            } else {
                opened = NCTLS12.open(suite: suite, key: tls12ServerKey, iv: tls12ServerIV, seq: readSeq,
                                      type: type, payload: payload)
            }
            guard let plain = opened else {
                fail(TLSError.handshake("record decrypt failed"))
                return
            }
            readSeq += 1
            content = plain
        }
        switch type {
        case 21:
            if content.count >= 2, content[content.startIndex] == 2 {
                fail(TLSError.handshake("fatal alert \(content[content.startIndex + 1])"))
                return
            }
            if content.count >= 2, content[content.startIndex + 1] == 0 { // close_notify
                closed = true
                deliverEOFOrError(nil)
            }
        case 22:
            handleHandshakeBytes(content)
        case 23:
            guard handshakeDone else { fail(TLSError.handshake("application data before Finished")); return }
            deliverAppData(content)
        default:
            return
        }
    }
}

// MARK: - restls application records (NCRestls.swift)

extension NCTLSClientStream {
    /// After a restls handshake: a server record is either a restls record (data + command) or a real TLS record
    /// relayed from the camouflage server (decrypted with the real keys, application data dropped).
    fileprivate func restlsAccept(_ restls: NCRestlsSession, header: Data, payload: Data, realOpen: () -> Bool) {
        if header.first == 21 { // Go: an outer alert after auth is treated as fatal bad_record_mac
            fail(TLSError.handshake("restls: alert from server"))
            return
        }
        guard let (data, command) = restls.extract(header: header, payload: payload) else {
            let ok = realOpen()
            restls.toClientCounter &+= 1
            if !ok { fail(TLSError.handshake("restls: record authentication failed")) }
            return
        }
        if restls.writePending {
            restls.writePending = false
            for record in restls.records(for: Data()) { raw.send(record) }
        }
        restls.toClientCounter &+= 1
        if case .response(let k) = command {
            for _ in 0..<Int(k) {
                for record in restls.records(for: Data(), fakeResponse: true) { raw.send(record) }
            }
        }
        deliverAppData(data)
    }

    fileprivate func handleRestlsRecord13(_ restls: NCRestlsSession, type: UInt8, header: Data, payload: Data) {
        if type == 20 { return }
        restlsAccept(restls, header: header, payload: payload) {
            guard let readKey, let readIV,
                  let plain = NCTLS13.openRecord(suite: suite, key: readKey, iv: readIV, seq: readSeq,
                                                 header: header, sealed: payload) else { return false }
            readSeq += 1
            guard let innerType = plain.last else { return true }
            let content = Data(plain.dropLast())
            switch innerType {
            case 22: handleHandshakeBytes(content) // NewSessionTicket / KeyUpdate
            case 21: closed = true; deliverEOFOrError(nil)
            default: break                         // camouflage application data: dropped
            }
            return true
        }
    }

    fileprivate func handleRestlsRecord12(_ restls: NCRestlsSession, suite: NCTLS12.Suite, type: UInt8,
                                          header: Data, payload: Data) {
        if type == 20 { return }
        restlsAccept(restls, header: header, payload: payload) {
            var p = payload
            if restls.gcm12 && !restls.gcmServerDisableCtr && p.count >= 8 {
                // The real records' explicit nonces were rewritten by the restls server: restore the real sequence.
                restls.toClientRealRecordCounter &+= 1
                let c = NCRestls.be64(restls.toClientRealRecordCounter)
                var b = [UInt8](p)
                for i in 0..<8 { b[i] = c[i] }
                p = Data(b)
            }
            guard let plain = NCTLS12.open(suite: suite, key: tls12ServerKey, iv: tls12ServerIV, seq: readSeq,
                                           type: type, payload: p) else { return false }
            readSeq += 1
            switch type {
            case 22: handleHandshakeBytes(plain)
            case 21:
                if plain.count >= 2, plain[plain.startIndex] == 2 || plain[plain.startIndex + 1] == 0 {
                    closed = true
                    deliverEOFOrError(nil)
                }
            default: break
            }
            return true
        }
    }
}
