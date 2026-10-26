import Foundation
import CryptoKit

// Cloak SS plugin (cbeuw/Cloak v2 client protocol), aligning with mihomo plugin: cloak / Shadowrocket.
// Wire format:
// 1. ECIES handshake disguised as TLS 1.3 ClientHello:
//    - Ephemeral X25519 public key in ClientHello.random (32 bytes)
//    - AES-256-GCM auth ciphertext (64 bytes = 48 bytes payload + 16 bytes tag) split across
//      ClientHello.sessionId (first 32 bytes) and X25519 key_share extension data (last 32 bytes)
//    - Shared secret = ECDH(ephPriv, serverStaticPub)
//    - Auth payload (48 bytes): UID(16) || "shadowsocks\0"(12) || encMethod(1) || timestampBE(8) || sessionIdBE(4) || flags(1) || reserved(6)
// 2. ServerHello response:
//    - 64 bytes extracted from ServerHello: random[0..<32] + keyShare[0..<32]
//    - Decrypted with AES-256-GCM using sharedSecret to yield 32-byte sessionKey
// 3. Framing layer:
//    - All data wrapped in TLS ApplicationData records (type 23, version 0x0303)
//    - Cloak frame: 14-byte header (streamID:4 BE, seq:8 BE, closing:1, extraLen:1)
//    - Header encrypted with Salsa20 (key = sessionKey, nonce = last 8 bytes of frame)
//    - Payload optionally encrypted with AEAD (plain / aes-gcm / chacha20-poly1305)
//    - Stream multiplexing: stream ID 1 for Shadowsocks TCP connection.

// MARK: - Options

struct NCCloakPluginOptions: Equatable {
    var uid: Data
    var publicKey: Data
    var serverName: String
    var alternativeNames: [String]
    var browserSig: String
    var encryptionMethod: String
    var transport: String
    var numConn: Int
    var streamTimeout: Int
    var cdnOriginHost: String?
    var cdnWsUrlPath: String?

    var encryptionMethodByte: UInt8 {
        switch encryptionMethod.lowercased() {
        case "aes-gcm", "aes-256-gcm": return 1
        case "chacha20-poly1305": return 2
        case "aes-128-gcm": return 3
        default: return 0 // plain
        }
    }

    /// Parses plugin-opts dictionary into NCCloakPluginOptions.
    /// Supports both Shadowrocket / Cloak upstream keys (PascalCase / camelCase: UID, PublicKey, ServerName,
    /// AlternativeNames, BrowserSig, EncryptionMethod, Transport, NumConn, StreamTimeout) and mihomo kebab-case
    /// (uid, public-key, server-name, alternative-names, browser-signature, encryption-method, transport, num-conn, stream-timeout).
    static func parse(_ opts: [String: NCJSONValue], fallbackHost: String? = nil) -> (NCCloakPluginOptions?, String?) {
        func lookup(_ key: String) -> NCJSONValue? {
            let target = key.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
            for (k, v) in opts {
                let norm = k.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
                if norm == target { return v }
            }
            return nil
        }

        func decodeBytes(_ val: NCJSONValue?) -> Data? {
            guard let s = val?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
            // Try standard base64 / URL-safe base64
            var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            while b64.count % 4 != 0 { b64.append("=") }
            if let d = Data(base64Encoded: b64) { return d }
            // Try hex
            if s.count % 2 == 0 {
                var out = Data(capacity: s.count / 2)
                var idx = s.startIndex
                while idx < s.endIndex {
                    let next = s.index(idx, offsetBy: 2)
                    if let byte = UInt8(s[idx..<next], radix: 16) {
                        out.append(byte)
                    } else {
                        return nil
                    }
                    idx = next
                }
                return out
            }
            return nil
        }

        guard let uidData = decodeBytes(lookup("uid")), uidData.count == 16 else {
            return (nil, "cloak 缺少有效 UID（需 16 字节 base64）")
        }

        guard let pubKeyData = decodeBytes(lookup("publickey") ?? lookup("public-key")), pubKeyData.count == 32 else {
            return (nil, "cloak 缺少有效 PublicKey（需 32 字节 X25519 公钥 base64）")
        }

        let sName = lookup("servername")?.string ?? lookup("host")?.string ?? fallbackHost ?? "www.bing.com"
        let browser = lookup("browsersig")?.string ?? lookup("browsersignature")?.string ?? lookup("clientfingerprint")?.string ?? "chrome"
        let encMethod = lookup("encryptionmethod")?.string ?? "plain"
        let transport = lookup("transport")?.string ?? "direct"
        let numConn = lookup("numconn")?.int ?? 1
        let timeout = lookup("streamtimeout")?.int ?? 300

        var altNames: [String] = []
        if let alt = lookup("alternativenames") {
            if let arr = alt.array {
                altNames = arr.compactMap { $0.string?.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            } else if let s = alt.string {
                altNames = s.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            }
        }

        // Cloak Transport=CDN is a different handshake (real uTLS to the CDN, auth in a WebSocket "hidden"
        // header, 60-byte session-key reply, frames as WS messages without TLS records); not ported.
        if transport.lowercased() == "cdn" {
            return (nil, "cloak Transport=CDN（WebSocket 鉴权模式）暂不支持")
        }

        let cdnHost = lookup("cdnoriginhost")?.string
        let cdnPath = lookup("cdnwsurlpath")?.string ?? lookup("path")?.string

        let options = NCCloakPluginOptions(
            uid: uidData,
            publicKey: pubKeyData,
            serverName: sName,
            alternativeNames: altNames,
            browserSig: browser,
            encryptionMethod: encMethod,
            transport: transport,
            numConn: max(1, numConn),
            streamTimeout: timeout,
            cdnOriginHost: cdnHost,
            cdnWsUrlPath: cdnPath
        )
        return (options, nil)
    }
}

// MARK: - Salsa20 (RFC 7539 / Bernstein 2005)

enum NCSalsa20 {
    /// Encrypts or decrypts `data` in-place using Salsa20 with 32-byte key and 8-byte nonce.
    /// Cloak uses Salsa20 to encrypt and decrypt the 14-byte frame header using the last 8 bytes of the frame as nonce.
    static func xorKeyStream(data: inout [UInt8], key: Data, nonce: Data, counter: UInt64 = 0) {
        guard key.count >= 32, nonce.count >= 8, !data.isEmpty else { return }

        func le32(_ d: Data, _ offset: Int) -> UInt32 {
            let o = d.startIndex + offset
            return UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
        }

        let k = (0..<8).map { le32(key, $0 * 4) }
        let n0 = le32(nonce, 0)
        let n1 = le32(nonce, 4)

        var blockIndex = counter
        var offset = 0
        while offset < data.count {
            let c0 = UInt32(truncatingIfNeeded: blockIndex)
            let c1 = UInt32(truncatingIfNeeded: blockIndex >> 32)

            var x: [UInt32] = [
                0x61707865, k[0],       k[1],       k[2],
                k[3],       0x3320646e, n0,         n1,
                c0,         c1,         0x79622d32, k[4],
                k[5],       k[6],       k[7],       0x6b206574
            ]
            var z = x

            func rotl(_ v: UInt32, _ c: UInt32) -> UInt32 { (v << c) | (v >> (32 - c)) }
            func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
                z[b] ^= rotl(z[a] &+ z[d], 7)
                z[c] ^= rotl(z[b] &+ z[a], 9)
                z[d] ^= rotl(z[c] &+ z[b], 13)
                z[a] ^= rotl(z[d] &+ z[c], 18)
            }

            for _ in 0..<10 {
                // Column round
                qr(0, 4, 8, 12)
                qr(5, 9, 13, 1)
                qr(10, 14, 2, 6)
                qr(15, 3, 7, 11)
                // Row round
                qr(0, 1, 2, 3)
                qr(5, 6, 7, 4)
                qr(10, 11, 8, 9)
                qr(15, 12, 13, 14)
            }

            var keyStream = [UInt8]()
            keyStream.reserveCapacity(64)
            for i in 0..<16 {
                let out = z[i] &+ x[i]
                keyStream.append(UInt8(out & 0xff))
                keyStream.append(UInt8((out >> 8) & 0xff))
                keyStream.append(UInt8((out >> 16) & 0xff))
                keyStream.append(UInt8((out >> 24) & 0xff))
            }

            let take = min(64, data.count - offset)
            for i in 0..<take {
                data[offset + i] ^= keyStream[i]
            }
            offset += take
            blockIndex += 1
        }
    }
}

// MARK: - Handshake & Stream

enum NCCloak {
    private static let topLevelDomains = ["com", "net", "org", "it", "fr", "me", "ru", "cn", "es", "tr", "top", "xyz", "info"]

    static func randomServerName() -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyz".utf8)
        let size = 3 + Int.random(in: 0..<10)
        var s = ""
        for _ in 0..<size {
            s.append(Character(UnicodeScalar(chars.randomElement()!)))
        }
        return s + "." + (topLevelDomains.randomElement() ?? "com")
    }

    /// Performs the Cloak TLS 1.3 disguise handshake over `raw`.
    /// Sends ClientHello carrying the auth payload, reads ServerHello, parses session key, and eats the handshake trail.
    static func handshake(raw: NCRelayStream, options: NCCloakPluginOptions,
                          completion: @escaping (Result<(sessionKey: Data, tail: Data), Error>) -> Void) {
        do {
            let ephPriv = Curve25519.KeyAgreement.PrivateKey()
            let ephPub = ephPriv.publicKey.rawRepresentation // 32 bytes

            guard let serverPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: options.publicKey) else {
                completion(.failure(NCFramedRelay.err("cloak: invalid server public key")))
                return
            }

            let sharedSecret = try ephPriv.sharedSecretFromKeyAgreement(with: serverPub)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            // 1. Auth payload (48 bytes plaintext)
            var plain = Data(capacity: 48)
            plain.append(options.uid) // 16 bytes
            var methodData = Data("shadowsocks".utf8)
            if methodData.count < 12 { methodData.append(Data(repeating: 0, count: 12 - methodData.count)) }
            plain.append(methodData.prefix(12)) // 12 bytes (total 28)
            plain.append(options.encryptionMethodByte) // 1 byte (total 29)
            let nowSec = UInt64(Date().timeIntervalSince1970)
            plain.appendBE64(nowSec) // 8 bytes (total 37)
            let sessID = UInt32.random(in: 0...UInt32.max)
            plain.appendBE32(sessID) // 4 bytes (total 41)
            plain.append(0x00) // 1 byte flag (ordered / TCP)
            plain.append(contentsOf: [0, 0, 0, 0, 0, 0]) // 6 bytes reserved (total 48)

            // AES-256-GCM encrypt auth payload
            let authNonce = try AES.GCM.Nonce(data: ephPub.prefix(12))
            let sealed = try AES.GCM.seal(plain, using: SymmetricKey(data: sharedSecretData), nonce: authNonce)
            let ciphertextWithTag = sealed.ciphertext + sealed.tag // 48 + 16 = 64 bytes

            let clientRandom = ephPub
            let tlsSessionId = ciphertextWithTag.prefix(32)
            let x25519KeyShare = ciphertextWithTag.suffix(32)

            let sni: String
            if options.serverName.lowercased() == "random" {
                sni = randomServerName()
            } else if !options.alternativeNames.isEmpty {
                let list = [options.serverName] + options.alternativeNames
                sni = list.randomElement() ?? options.serverName
            } else {
                sni = options.serverName
            }

            let profile = NCClientHelloProfile.named(options.browserSig)
            let ch = NCTLS13.buildClientHello(random: clientRandom, sessionID: tlsSessionId, serverName: sni,
                                              alpn: ["h2", "http/1.1"], keyShare: x25519KeyShare, profile: profile)
            var rec = Data([0x16, 0x03, 0x01])
            rec.appendBE16(UInt16(ch.count))
            rec.append(ch)

            raw.send(rec)

            // 2. Read ServerHello and handshake reply
            var buf = Data()
            var state = 0 // 0: waiting for ServerHello, 1: ChangeCipherSpec & EncryptedCert
            var sessionKey: Data?

            func pump() {
                raw.receive { data, err in
                    if let err { completion(.failure(err)); return }
                    guard let data else {
                        completion(.failure(NCFramedRelay.err("cloak: remote closed during handshake")))
                        return
                    }
                    buf.append(data)
                    parseHandshake()
                }
            }

            func parseHandshake() {
                while true {
                    guard buf.count >= 5 else { pump(); return }
                    let s = buf.startIndex
                    let recType = buf[s]
                    let recLen = Int(buf[s + 3]) << 8 | Int(buf[s + 4])
                    guard buf.count >= 5 + recLen else { pump(); return }

                    let recBody = Data(buf[(s + 5)..<(s + 5 + recLen)])
                    buf = Data(buf.dropFirst(5 + recLen))

                    if state == 0 {
                        // Expect ServerHello (record type 22, body length >= 116)
                        guard recType == 22, recBody.count >= 116, recBody[0] == 2 else {
                            completion(.failure(NCFramedRelay.err("cloak: unexpected ServerHello record (type \(recType), len \(recBody.count))")))
                            return
                        }
                        // Encrypted session key slice from ServerHello:
                        // encrypted := append(buf[6:38], buf[84:116]...)
                        let part1 = recBody.subdata(in: 6..<38)
                        let part2 = recBody.subdata(in: 84..<116)
                        let encrypted = part1 + part2 // 64 bytes
                        let nonce = encrypted.prefix(12)
                        let ctextAndTag = encrypted.subdata(in: 12..<60) // 48 bytes: 32 bytes cipher + 16 bytes tag
                        let cipherPart = ctextAndTag.prefix(32)
                        let tagPart = ctextAndTag.suffix(16)

                        do {
                            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: cipherPart, tag: tagPart)
                            let key = try AES.GCM.open(box, using: SymmetricKey(data: sharedSecretData))
                            sessionKey = key
                            state = 1
                        } catch {
                            completion(.failure(NCFramedRelay.err("cloak: failed to decrypt session key: \(error)")))
                            return
                        }
                    } else if state == 1 {
                        // Consuming ChangeCipherSpec (type 20/0x14) and EncryptedCert (type 23/0x17 ApplicationData)
                        // Once we see type 23 (or another type > 20), handshake exchange is done.
                        if recType == 23 || recType == 20 {
                            if recType == 23 {
                                // Handshake finished! Trailing records/bytes belong to data conn.
                                guard let sk = sessionKey else {
                                    completion(.failure(NCFramedRelay.err("cloak: missing session key")))
                                    return
                                }
                                completion(.success((sessionKey: sk, tail: buf)))
                                return
                            }
                            // Got ChangeCipherSpec, next will be ApplicationData (EncryptedCert)
                            continue
                        }
                    }
                }
            }

            pump()
        } catch {
            completion(.failure(error))
        }
    }
}

// MARK: - Cloak Framed Relay

final class NCCloakFramedStream: NCFramedRelay {
    private let sessionKey: Data
    private let encMethodByte: UInt8
    private var seq: UInt64 = 0
    private var closingSent = false

    init(raw: NCRelayStream, sessionKey: Data, encMethodByte: UInt8) {
        self.sessionKey = sessionKey
        self.encMethodByte = encMethodByte
        super.init(raw: raw)
    }

    override func send(_ data: Data) {
        for frame in makeFrames(for: data) { raw.send(frame) }
    }

    override func send(_ data: Data, completion: @escaping () -> Void) {
        raw.ncSendSequentially(makeFrames(for: data), completion: completion)
    }

    override func cancel() {
        if !closingSent {
            closingSent = true
            let closeFrame = makeFrame(payload: Data(), closing: 1)
            raw.send(closeFrame)
        }
        raw.cancel()
    }

    private func makeFrames(for data: Data) -> [Data] {
        var out: [Data] = []
        var rest = data[...]
        let maxUnit = 16384 - 14 - 256
        repeat {
            let chunk = Data(rest.prefix(maxUnit))
            rest = rest.dropFirst(chunk.count)
            out.append(makeFrame(payload: chunk, closing: 0))
        } while !rest.isEmpty
        return out
    }

    private func makeFrame(payload: Data, closing: UInt8) -> Data {
        let padLen = seq < 5 ? Int.random(in: 0...64) : 0
        let tagLen = encMethodByte == 0 ? 8 : 16
        let extraLen = padLen + tagLen

        var header = [UInt8](repeating: 0, count: 14)
        // StreamID: 1 (uint32 BE)
        header[0] = 0; header[1] = 0; header[2] = 0; header[3] = 1
        // Seq: uint64 BE
        header[4] = UInt8((seq >> 56) & 0xff); header[5] = UInt8((seq >> 48) & 0xff)
        header[6] = UInt8((seq >> 40) & 0xff); header[7] = UInt8((seq >> 32) & 0xff)
        header[8] = UInt8((seq >> 24) & 0xff); header[9] = UInt8((seq >> 16) & 0xff)
        header[10] = UInt8((seq >> 8) & 0xff); header[11] = UInt8(seq & 0xff)
        header[12] = closing
        header[13] = UInt8(extraLen)
        seq += 1

        var fullPayload = payload
        if padLen > 0 {
            fullPayload.append(NCConnector.randomData(padLen))
        }

        var encPayload = Data()
        if encMethodByte == 0 {
            // Plain: random 8 bytes as tag / salsa20 nonce
            encPayload = fullPayload + NCConnector.randomData(8)
        } else if encMethodByte == 1 || encMethodByte == 3 {
            // AES-GCM (256 or 128)
            let keyData = encMethodByte == 3 ? sessionKey.prefix(16) : sessionKey
            if let nonce = try? AES.GCM.Nonce(data: Data(header.prefix(12))),
               let sealed = try? AES.GCM.seal(fullPayload, using: SymmetricKey(data: keyData), nonce: nonce) {
                encPayload = sealed.ciphertext + sealed.tag
            } else {
                encPayload = fullPayload + NCConnector.randomData(16)
            }
        } else if encMethodByte == 2 {
            // ChaCha20-Poly1305
            if let nonce = try? ChaChaPoly.Nonce(data: Data(header.prefix(12))),
               let sealed = try? ChaChaPoly.seal(fullPayload, using: SymmetricKey(data: sessionKey), nonce: nonce) {
                encPayload = sealed.ciphertext + sealed.tag
            } else {
                encPayload = fullPayload + NCConnector.randomData(16)
            }
        }

        // Salsa20 encrypt header using last 8 bytes of frame as nonce
        let salsaNonce = encPayload.suffix(8)
        NCSalsa20.xorKeyStream(data: &header, key: sessionKey, nonce: salsaNonce)

        var frame = Data(header)
        frame.append(encPayload)

        // Wrap in TLS ApplicationData record (0x17, 0x03, 0x03)
        var rec = Data([0x17, 0x03, 0x03])
        rec.appendBE16(UInt16(frame.count))
        rec.append(frame)
        return rec
    }

    override func consume() throws -> [Data] {
        var out: [Data] = []
        while inbuf.count >= 5 {
            let s = inbuf.startIndex
            guard inbuf[s] == 23 else {
                throw Self.err("cloak: unexpected TLS record type \(inbuf[s])")
            }
            let len = Int(inbuf[s + 3]) << 8 | Int(inbuf[s + 4])
            guard inbuf.count >= 5 + len else { break }

            let frame = inbuf.subdata(in: (s + 5)..<(s + 5 + len))
            inbuf = Data(inbuf.dropFirst(5 + len))

            guard frame.count >= 14 + 8 else {
                throw Self.err("cloak: frame too short (\(frame.count) bytes)")
            }

            var header = [UInt8](frame.prefix(14))
            let salsaNonce = frame.suffix(8)
            NCSalsa20.xorKeyStream(data: &header, key: sessionKey, nonce: salsaNonce)

            let streamID = UInt32(header[0]) << 24 | UInt32(header[1]) << 16 | UInt32(header[2]) << 8 | UInt32(header[3])
            let closing = header[12]
            let extraLen = Int(header[13])

            if closing == 1 || closing == 2 {
                peerClosed = true
                return out
            }

            guard streamID == 1 else { continue } // ignore frames for other streams

            let pldWithOverhead = frame.dropFirst(14)
            guard pldWithOverhead.count >= extraLen else {
                throw Self.err("cloak: extra length \(extraLen) exceeds payload \(pldWithOverhead.count)")
            }
            let usefulLen = pldWithOverhead.count - extraLen

            if encMethodByte == 0 {
                // Plain
                let plain = pldWithOverhead.prefix(usefulLen)
                if !plain.isEmpty { out.append(Data(plain)) }
            } else if encMethodByte == 1 || encMethodByte == 3 {
                // AES-GCM
                let keyData = encMethodByte == 3 ? sessionKey.prefix(16) : sessionKey
                let tag = pldWithOverhead.suffix(16)
                let ctext = pldWithOverhead.dropLast(16)
                guard let nonce = try? AES.GCM.Nonce(data: Data(header.prefix(12))),
                      let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: Data(ctext), tag: Data(tag)),
                      let dec = try? AES.GCM.open(box, using: SymmetricKey(data: keyData)) else {
                    throw Self.err("cloak: payload AES-GCM decryption failed")
                }
                let plain = dec.prefix(usefulLen)
                if !plain.isEmpty { out.append(Data(plain)) }
            } else if encMethodByte == 2 {
                // ChaCha20-Poly1305
                let tag = pldWithOverhead.suffix(16)
                let ctext = pldWithOverhead.dropLast(16)
                guard let nonce = try? ChaChaPoly.Nonce(data: Data(header.prefix(12))),
                      let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: Data(ctext), tag: Data(tag)),
                      let dec = try? ChaChaPoly.open(box, using: SymmetricKey(data: sessionKey)) else {
                    throw Self.err("cloak: payload ChaCha20-Poly1305 decryption failed")
                }
                let plain = dec.prefix(usefulLen)
                if !plain.isEmpty { out.append(Data(plain)) }
            }
        }
        return out
    }
}
