import CryptoKit
import Foundation

// SS restls plugin (feat/native-core-eval, based on astemo6/Muse NativeCore): pure-Swift client side of restls,
// ported from github.com/metacubex/restls-client-go v0.1.9 (the version mihomo v1.19.33 pins; restls_utils.go,
// conn.go readRecordOrCCS / writeRestlsApplicationRecord, handshake_client.go generateSessionID*, u_conn.go,
// key_agreement.go eager ECDHE) as mihomo transport/restls + adapter/outbound/shadowsocks.go drive it.
//
// It rides on NCTLSClientStream (the hand-rolled TLS 1.3 / 1.2 client): the TLS handshake is a real one with the
// camouflage server (`host`), relayed by the restls server, which proves itself inside it:
//   ClientHello session ID
//     tls13 hint: BLAKE3-keyed(secret; for each key_share: group BE16 ‖ key)[:16] ‖ 16 random bytes
//     tls12 hint: three eager ECDHE keys (X25519, P-256, P-384) generated up front; session ID segments
//                 [0,11) [11,22) [22,32) = BLAKE3-keyed(secret; public key)[..]; the ClientKeyExchange then uses
//                 the eager key of the curve the server picked, so the restls server can check it.
//   Server auth: the first server record under the new read keys (1.3: first encrypted handshake record;
//     1.2: Finished after CCS) has its first 16 ciphertext bytes (1.2 AES-GCM with explicit nonce 0: after the
//     nonce) XORed with BLAKE3-keyed(secret; ServerHello.random)[:16]. Unmasking + decrypting succeeds only for a
//     restls server. mihomo falls back to plain TLS when it fails; here the handshake fails instead, so Shadowsocks
//     bytes never go to the camouflage site.
//   Application records (both directions), after the handshake:
//     header(5) [‖ 8-byte counter, TLS 1.2 AES-GCM only] ‖ mac(8) ‖ masked(len(2) ‖ cmd(2)) ‖ data ‖ padding
//     mask = BLAKE3-keyed(secret; serverRandom ‖ dir ‖ BE64(counter) ‖ first ≤32 bytes after the 12-byte header)[:4]
//     mac  = BLAKE3-keyed(secret; serverRandom ‖ dir ‖ BE64(counter) ‖ [client Finished record, first c→s record,
//            TLS 1.3] ‖ header ‖ masked len/cmd ‖ data ‖ padding)[:8]
//     dir = "client-to-server" / "server-to-client". Server records that fail the restls check are real TLS
//     records from the camouflage server: decrypted with the real keys and dropped (application data).
//   restls-script ("250?100<1,350~100<1,600~100,300~200,300~100" by default) shapes the first client records:
//     N = length, N~R = N + random(0..<R) per record, N?R = fixed random once, <K = ask the server for K
//     responses and hold further writes until a server record arrives. The server's commands ask the client for
//     K empty (padding-only) records.
// Not ported: TLS 1.2 session-ticket resumption (layout-4 session IDs; the server accepts full handshakes).
// `fingerprint` (SHA-256 certificate pinning, mihomo ca.NewFingerprintVerifier semantics) and
// `name-cert-verify` (verify the chain against a name other than the SNI host) are implemented in
// NCTLSClientStream's certificate policy (Config.pinnedCertSHA256 / certVerifyName).

enum NCRestls {
    enum VersionHint { case tls12, tls13 }

    /// One restls-script line.
    struct Line {
        var target: Int
        var range: Int
        /// nil = no command; else ActResponse(n).
        var response: UInt8?

        func length() -> Int { range > 0 ? target + Int.random(in: 0..<range) : target }
    }

    static let defaultScript = "250?100<1,350~100<1,600~100,300~200,300~100"

    enum ScriptError: Error { case invalid(String) }

    /// parseRecordScript (restls_utils.go).
    static func parseScript(_ script: String) throws -> [Line] {
        var lines: [Line] = []
        for rawLine in script.replacingOccurrences(of: " ", with: "").split(separator: ",", omittingEmptySubsequences: true) {
            var bytes = [UInt8](rawLine.utf8)[...]
            func integer() throws -> Int {
                var v = 0
                while let b = bytes.first, b >= 0x30, b <= 0x39 {
                    v = v * 10 + Int(b - 0x30)
                    if v > 32768 { throw ScriptError.invalid("\(rawLine): target len > 32768") }
                    bytes = bytes.dropFirst()
                }
                return v
            }
            let target = try integer()
            guard target <= 32767 else { throw ScriptError.invalid("\(rawLine): target len > 32767") }
            var line = Line(target: target, range: 0, response: nil)
            if let b = bytes.first, b == UInt8(ascii: "~") || b == UInt8(ascii: "?") {
                bytes = bytes.dropFirst()
                let r = try integer()
                guard r <= 32767, r + target <= 32768 else { throw ScriptError.invalid("\(rawLine): random range") }
                line.range = r
                if b == UInt8(ascii: "?") {
                    line.target = line.length()
                    line.range = 0
                }
            }
            if let b = bytes.first {
                guard b == UInt8(ascii: "<") else { throw ScriptError.invalid("\(rawLine): unexpected content") }
                bytes = bytes.dropFirst()
                let n = try integer()
                guard bytes.isEmpty else { throw ScriptError.invalid("\(rawLine): unexpected content") }
                guard n < 255 else { throw ScriptError.invalid("\(rawLine): too many responses") }
                line.response = UInt8(n)
            }
            lines.append(line)
        }
        return lines
    }

    /// Parsed scripts per proxy: `N?R` is randomised once per client config in mihomo, not per connection.
    private static var scriptCache: [String: [Line]] = [:]
    private static let cacheLock = NSLock()

    static func script(proxyName: String, _ text: String) throws -> [Line] {
        let key = proxyName + "\u{0}" + text
        cacheLock.lock(); defer { cacheLock.unlock() }
        if let s = scriptCache[key] { return s }
        let s = try parseScript(text.isEmpty ? defaultScript : text)
        if scriptCache.count > 64 { scriptCache.removeAll() }
        scriptCache[key] = s
        return s
    }

    /// blake3.DeriveKey(key, "restls-traffic-key", password).
    static func secret(password: String) -> [UInt8] {
        NCBlake3.deriveKey(context: "restls-traffic-key", material: [UInt8](password.utf8))
    }

    static func mac(_ secret: [UInt8], _ parts: [[UInt8]]) -> [UInt8] {
        var input: [UInt8] = []
        input.reserveCapacity(parts.reduce(0) { $0 + $1.count })
        for p in parts { input.append(contentsOf: p) }
        return NCBlake3.keyedHash(key: secret, input)
    }

    static func be64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (56 - 8 * UInt64($0))) & 0xff) } }

    /// key_share entries of a marshaled ClientHello handshake message: (group, key exchange) in wire order.
    static func keyShares(inHello hello: Data) -> [(UInt16, [UInt8])] {
        let b = [UInt8](hello)
        var i = 4 + 2 + 32
        guard b.count > i else { return [] }
        i += 1 + Int(b[i])                                         // session id
        guard b.count >= i + 2 else { return [] }
        i += 2 + (Int(b[i]) << 8 | Int(b[i + 1]))                  // cipher suites
        guard b.count >= i + 1 else { return [] }
        i += 1 + Int(b[i])                                         // compression
        guard b.count >= i + 2 else { return [] }
        let end = min(b.count, i + 2 + (Int(b[i]) << 8 | Int(b[i + 1])))
        i += 2
        while i + 4 <= end {
            let t = UInt16(b[i]) << 8 | UInt16(b[i + 1])
            let n = Int(b[i + 2]) << 8 | Int(b[i + 3])
            let body = i + 4
            guard body + n <= end else { break }
            if t == 51, n >= 2 {
                var out: [(UInt16, [UInt8])] = []
                var j = body + 2
                let listEnd = min(body + n, body + 2 + (Int(b[body]) << 8 | Int(b[body + 1])))
                while j + 4 <= listEnd {
                    let g = UInt16(b[j]) << 8 | UInt16(b[j + 1])
                    let l = Int(b[j + 2]) << 8 | Int(b[j + 3])
                    guard j + 4 + l <= listEnd else { break }
                    out.append((g, Array(b[(j + 4)..<(j + 4 + l)])))
                    j += 4 + l
                }
                return out
            }
            i = body + n
        }
        return []
    }

    /// Whether the marshaled ClientHello offers TLS 1.3 (supported_versions contains 0x0304).
    static func helloOffersTLS13(_ hello: Data) -> Bool {
        let b = [UInt8](hello)
        var i = 4 + 2 + 32
        guard b.count > i else { return false }
        i += 1 + Int(b[i])
        guard b.count >= i + 2 else { return false }
        i += 2 + (Int(b[i]) << 8 | Int(b[i + 1]))
        guard b.count >= i + 1 else { return false }
        i += 1 + Int(b[i])
        guard b.count >= i + 2 else { return false }
        let end = min(b.count, i + 2 + (Int(b[i]) << 8 | Int(b[i + 1])))
        i += 2
        while i + 4 <= end {
            let t = UInt16(b[i]) << 8 | UInt16(b[i + 1])
            let n = Int(b[i + 2]) << 8 | Int(b[i + 3])
            guard i + 4 + n <= end else { break }
            if t == 43, n >= 1 {
                var j = i + 5
                while j + 1 < i + 4 + n {
                    if b[j] == 0x03 && b[j + 1] == 0x04 { return true }
                    j += 2
                }
                return false
            }
            i += 4 + n
        }
        return false
    }
}

/// Per-connection restls state, shared by NCTLSClientStream through its Config. All access on the stream's queue.
final class NCRestlsSession {
    let secret: [UInt8]
    let hint: NCRestls.VersionHint
    let script: [NCRestls.Line]

    // TLS 1.2 eager ECDHE keys (tls12 hint).
    private(set) var eagerX25519: Curve25519.KeyAgreement.PrivateKey?
    private(set) var eagerP256: P256.KeyAgreement.PrivateKey?
    private(set) var eagerP384: P384.KeyAgreement.PrivateKey?

    var serverRandom: [UInt8] = []
    /// Set when the server's first record under new read keys is due (1.3 handshake keys / 1.2 CCS).
    var authPending = false
    var authed = false
    var gcm12 = false                 // restls12WithGCM
    var gcmServerDisableCtr = false   // restls12GCMServerDisableCtr
    var toClientCounter: UInt64 = 0
    var toServerCounter: UInt64 = 0
    var toClientRealRecordCounter: UInt64 = 0
    var clientFinished: [UInt8]?
    var writePending = false
    var sendBuf: [UInt8] = []

    init(secret: [UInt8], hint: NCRestls.VersionHint, script: [NCRestls.Line]) {
        self.secret = secret
        self.hint = hint
        self.script = script
    }

    // MARK: ClientHello session ID

    /// The 32-byte session ID for this hello (zero ID in place). Go: generateSessionIDForTLS13 / ForTLS12.
    func sessionID(hello: Data) -> Data {
        var sid = [UInt8](NCConnector.randomData(32))
        if hint == .tls13 && NCRestls.helloOffersTLS13(hello) {
            var parts: [[UInt8]] = []
            for (g, key) in NCRestls.keyShares(inHello: hello) {
                parts.append([UInt8(g >> 8), UInt8(g & 0xff)])
                parts.append(key)
            }
            let m = NCRestls.mac(secret, parts)
            for i in 0..<16 { sid[i] = m[i] }
            return Data(sid)
        }
        let x = Curve25519.KeyAgreement.PrivateKey()
        let p256 = P256.KeyAgreement.PrivateKey()
        let p384 = P384.KeyAgreement.PrivateKey()
        eagerX25519 = x; eagerP256 = p256; eagerP384 = p384
        let materials: [[UInt8]] = [[UInt8](x.publicKey.rawRepresentation),
                                    [UInt8](p256.publicKey.x963Representation),
                                    [UInt8](p384.publicKey.x963Representation)]
        let layout = [0, 11, 22, 32]
        for (i, m) in materials.enumerated() {
            let h = NCRestls.mac(secret, [m])
            for j in layout[i]..<layout[i + 1] { sid[j] = h[j - layout[i]] }
        }
        return Data(sid)
    }

    /// ClientKeyExchange with the eager key for the server's curve (nil: not eager → caller generates one;
    /// mihomo does the same for P-521, which then fails restls auth).
    func eagerECDHE(group: UInt16, serverPublic: Data) -> (Data, Data)? {
        switch group {
        case 0x001d:
            guard let priv = eagerX25519,
                  let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.rawRepresentation, s.withUnsafeBytes { Data($0) })
        case 0x0017:
            guard let priv = eagerP256,
                  let pub = try? P256.KeyAgreement.PublicKey(x963Representation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.x963Representation, s.withUnsafeBytes { Data($0) })
        case 0x0018:
            guard let priv = eagerP384,
                  let pub = try? P384.KeyAgreement.PublicKey(x963Representation: serverPublic),
                  let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
            return (priv.publicKey.x963Representation, s.withUnsafeBytes { Data($0) })
        default:
            return nil
        }
    }

    // MARK: Server auth

    /// The masked copy of the server's auth record payload (after the 5-byte header) to try first.
    func maskedAuthPayload(_ payload: Data) -> Data {
        let m = NCRestls.mac(secret, [serverRandom])
        var p = [UInt8](payload)
        var start = 0
        if gcm12 && p.count >= 8 && p[0..<8].allSatisfy({ $0 == 0 }) {
            start = 8
        } else {
            gcmServerDisableCtr = true
        }
        var i = 0
        while i < 16 && start + i < p.count { p[start + i] ^= m[i]; i += 1 }
        return Data(p)
    }

    // MARK: Application records

    private func authHash(toClient: Bool, counter: UInt64, _ rest: [[UInt8]]) -> [UInt8] {
        var parts: [[UInt8]] = [serverRandom, Array((toClient ? "server-to-client" : "client-to-server").utf8),
                                NCRestls.be64(counter)]
        parts.append(contentsOf: rest)
        return NCRestls.mac(secret, parts)
    }

    enum Command { case noop, response(UInt8) }

    /// extractRestlsAppData: nil when the record is not a valid restls record (a real TLS record).
    func extract(header: Data, payload: Data) -> (data: Data, command: Command)? {
        guard header.first == 23 else { return nil }
        var hdr = [UInt8](header)
        var body = [UInt8](payload)
        if gcm12 && !gcmServerDisableCtr {
            guard body.count >= 8 + 12 else { return nil }
            var nonce: UInt64 = 0
            for i in 0..<8 { nonce = nonce << 8 | UInt64(body[i]) }
            guard nonce == toClientCounter &+ 1 else { return nil }
            hdr.append(contentsOf: body[0..<8])
            body = Array(body[8...])
        }
        guard body.count >= 12 else { return nil }
        let auth = authHash(toClient: true, counter: toClientCounter, [hdr, Array(body[8...])])
        guard Array(auth[0..<8]) == Array(body[0..<8]) else { return nil }
        let sample = Array(body[12..<min(body.count, 12 + 32)])
        let mask = authHash(toClient: true, counter: toClientCounter, [sample])
        for i in 0..<4 { body[8 + i] ^= mask[i] }
        let dataLen = Int(body[8]) << 8 | Int(body[9])
        let command: Command
        switch body[10] {
        case 0: command = .noop
        case 1: command = .response(body[11])
        default: return nil
        }
        guard dataLen <= body.count - 12 else { return nil }
        return (Data(body[12..<(12 + dataLen)]), command)
    }

    /// writeRestlsApplicationRecord: wire records for `dataNew` (empty + fakeResponse = one padding-only record).
    /// Data past a `<K` line is held in sendBuf until the server answers.
    func records(for dataNew: Data, fakeResponse fake: Bool = false) -> [Data] {
        var fakeResponse = fake
        if fakeResponse { writePending = false }
        if writePending {
            sendBuf.append(contentsOf: dataNew)
            return []
        }
        var data = sendBuf
        data.append(contentsOf: dataNew)
        sendBuf = []
        var off = 0
        var out: [Data] = []
        while off < data.count || fakeResponse {
            let (payloadLen, dataLen, paddingLen, response) = actAccordingToScript(remaining: data.count - off)
            if payloadLen == 0 { break }
            let headerLen = 5 + (gcm12 ? 8 : 0)
            var rec = [UInt8](repeating: 0, count: headerLen + 12)
            rec[0] = 23; rec[1] = 3; rec[2] = 3
            rec[3] = UInt8(payloadLen >> 8); rec[4] = UInt8(payloadLen & 0xff)
            if gcm12 {
                let c = NCRestls.be64(toServerCounter &+ 1)
                for i in 0..<8 { rec[5 + i] = c[i] }
            }
            rec.append(contentsOf: data[off..<(off + dataLen)])
            rec.append(contentsOf: [UInt8](NCConnector.randomData(paddingLen)))
            // write0x17AuthHeader
            let b = headerLen
            let sample = Array(rec[(b + 12)..<min(rec.count, b + 12 + 32)])
            let mask = authHash(toClient: false, counter: toServerCounter, [sample])
            rec[b + 8] = UInt8((dataLen >> 8) & 0xff); rec[b + 9] = UInt8(dataLen & 0xff)
            if let r = response { rec[b + 10] = 1; rec[b + 11] = r } else { rec[b + 10] = 0; rec[b + 11] = 0 }
            for i in 0..<4 { rec[b + 8 + i] ^= mask[i] }
            var authParts: [[UInt8]] = []
            if let cf = clientFinished { authParts.append(cf); clientFinished = nil }
            authParts.append(Array(rec[0..<b]))
            authParts.append(Array(rec[(b + 8)...]))
            let auth = authHash(toClient: false, counter: toServerCounter, authParts)
            for i in 0..<8 { rec[b + i] = auth[i] }
            let interrupt = response != nil && !fakeResponse
            if interrupt { writePending = true }
            out.append(Data(rec))
            toServerCounter &+= 1
            off += dataLen
            if interrupt { break }
            fakeResponse = false
        }
        if off < data.count { sendBuf = Array(data[off...]) }
        return out
    }

    /// actAccordingToScript → (payloadLen, dataLen, paddingLen, response command).
    private func actAccordingToScript(remaining: Int) -> (Int, Int, Int, UInt8?) {
        var paddingLen = 0
        var dataLen = remaining
        var response: UInt8?
        if toServerCounter < UInt64(script.count) {
            let line = script[Int(toServerCounter)]
            dataLen = line.length()
            response = line.response
        }
        if dataLen == 0 { paddingLen = 19 + Int.random(in: 0..<100) }
        if remaining < dataLen {
            paddingLen = dataLen - remaining
            dataLen = remaining
        }
        let headerLen = 12 + (gcm12 ? 8 : 0)
        let maxPlaintext = 16384
        paddingLen = min(paddingLen, maxPlaintext - headerLen) // Go would panic past this; clamp instead
        var payloadLen = dataLen + paddingLen + headerLen
        if payloadLen > maxPlaintext { payloadLen = maxPlaintext }
        dataLen = max(0, payloadLen - headerLen - paddingLen)
        return (payloadLen, dataLen, paddingLen, response)
    }
}

// MARK: - Connector glue

extension NCConnector {
    private static func hexBytes(_ hex: String) -> Data? {
        var out = Data()
        out.reserveCapacity(hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard j <= hex.endIndex, let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }

    /// mihomo restlsOption (plugin-opts): host, password, version-hint (tls12 | tls13 — anything else,
    /// including an empty hint, is an explicit error, exactly like restls-client-go's NewRestlsConfig),
    /// restls-script, skip-cert-verify, fingerprint, name-cert-verify, force-tls12; the proxy's
    /// client-fingerprint picks the ClientHello shape.
    static func restlsStream(raw: NCRelayStream, proxy: NCProxy, queue: DispatchQueue,
                             completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let opts = proxy.fields["plugin-opts"]?.object ?? [:]
        let host = opts["host"]?.string ?? ""
        let hint: NCRestls.VersionHint
        switch (opts["version-hint"]?.string ?? "").lowercased() {
        case "tls12": hint = .tls12
        case "tls13": hint = .tls13
        default:
            raw.cancel()
            queue.async { completion(nil, Failure.handshake("restls: invalid version hint: should be either tls12 or tls13")) }
            return
        }
        let script: [NCRestls.Line]
        do {
            script = try NCRestls.script(proxyName: proxy.name, opts["restls-script"]?.string ?? "")
        } catch {
            raw.cancel()
            queue.async { completion(nil, Failure.handshake("restls: \(error)")) }
            return
        }
        // fingerprint: hex SHA-256 of a presented certificate (colons tolerated), mihomo
        // ca.NewFingerprintVerifier — browser names here are a config error there, and so here.
        var pin: Data?
        if let fp = opts["fingerprint"]?.string, !fp.isEmpty {
            if ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"]
                .contains(fp.lowercased()) {
                raw.cancel()
                queue.async { completion(nil, Failure.handshake("restls: `fingerprint` is used for TLS certificate pinning; use `client-fingerprint` for the browser fingerprint")) }
                return
            }
            let hex = fp.replacingOccurrences(of: ":", with: "").trimmingCharacters(in: .whitespaces)
            guard hex.count == 64, let bytes = Self.hexBytes(hex) else {
                raw.cancel()
                queue.async { completion(nil, Failure.handshake("restls: fingerprint string decode error: need sha256 fingerprint")) }
                return
            }
            pin = bytes
        }
        let session = NCRestlsSession(secret: NCRestls.secret(password: opts["password"]?.string ?? ""),
                                      hint: hint, script: script)
        var cfg = NCTLSClientStream.Config(serverName: host)
        cfg.allowInsecure = opts["skip-cert-verify"]?.bool ?? false
        cfg.pinnedCertSHA256 = pin
        if let ncv = opts["name-cert-verify"]?.string, !ncv.isEmpty { cfg.certVerifyName = ncv }
        // restls clientIDMap: chrome / firefox / safari / ios, anything else → Chrome.
        let fp = proxy.fields["client-fingerprint"]?.string ?? ""
        cfg.profile = ["chrome", "firefox", "safari", "ios"].contains(fp) ? NCClientHelloProfile.named(fp) : .chrome
        cfg.maxTLS12 = opts["force-tls12"]?.bool ?? false
        cfg.restls = session
        let tls = NCTLSClientStream(raw: raw, config: cfg, queue: queue)
        tls.startHandshake { err in
            if let err { tls.cancel(); completion(nil, err) } else { completion(tls, nil) }
        }
    }
}
