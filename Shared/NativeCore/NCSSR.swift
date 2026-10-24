import CryptoKit
import Foundation

/// CRC-32 (IEEE) and Adler-32 — the checksums SSR's auth protocols use.
enum NCChecksum {
    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xffff_ffff
        for b in data {
            crc = table[Int((crc ^ UInt32(b)) & 0xff)] ^ (crc >> 8)
        }
        return crc ^ 0xffff_ffff
    }

    static func adler32(_ data: Data) -> UInt32 {
        var a: UInt32 = 1
        var b: UInt32 = 0
        for byte in data {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return (b << 16) | a
    }

    private static let table: [UInt32] = (0..<256).map { n in
        var c = UInt32(n)
        for _ in 0..<8 {
            c = c & 1 != 0 ? 0xedb8_8320 ^ (c >> 1) : c >> 1
        }
        return c
    }
}

/// The ChaCha stream core (block function) shared by the three SS stream
/// variants: original (8-byte nonce, 64-bit counter), IETF (12-byte
/// nonce, 32-bit counter), XChaCha (24-byte nonce via HChaCha20).
enum NCChaChaStream {
    static func block(key: Data, tail: [UInt32]) -> [UInt8] {
        let constants: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        func words(_ d: Data) -> [UInt32] {
            (0..<d.count / 4).map { i in
                UInt32(d[i * 4]) | UInt32(d[i * 4 + 1]) << 8 | UInt32(d[i * 4 + 2]) << 16 | UInt32(d[i * 4 + 3]) << 24
            }
        }
        let state = constants + words(key) + tail
        var w = state
        func rotr(_ v: UInt32, _ c: Int) -> UInt32 { (v >> c) | (v << (32 - c)) }
        func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            w[a] = w[a] &+ w[b]; w[d] = rotr(w[d] ^ w[a], 16)
            w[c] = w[c] &+ w[d]; w[b] = rotr(w[b] ^ w[c], 12)
            w[a] = w[a] &+ w[b]; w[d] = rotr(w[d] ^ w[a], 8)
            w[c] = w[c] &+ w[d]; w[b] = rotr(w[b] ^ w[c], 7)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        var out = [UInt8]()
        for i in 0..<16 {
            let v = w[i] &+ state[i]
            out.append(UInt8(v & 0xff)); out.append(UInt8((v >> 8) & 0xff))
            out.append(UInt8((v >> 16) & 0xff)); out.append(UInt8((v >> 24) & 0xff))
        }
        return out
    }
}

/// A symmetric stream cipher state (encryption and decryption are the
/// same operation for CTR/CFB/ChaCha/RC4 as used here — CFB decrypt uses
/// the cipher in encrypt direction on the IV chain, handled internally).
final class NCSSStreamCipher {
    enum Kind {
        case aesCTR(key: Data)
        case aesCFB(key: Data)
        case chachaOriginal(key: Data) // 8-byte nonce
        case chachaIETF(key: Data) // 12-byte nonce
        case xchacha(key: Data) // 24-byte nonce
        case rc4md5(key: Data)
    }

    let kind: Kind
    let ivSize: Int
    private var iv: Data?
    // CTR/CFB state
    private var counterBlock = [UInt8]()
    private var keystream = [UInt8]()
    private var keystreamPos = 64
    // ChaCha state
    private var chachaTail: [UInt32] = []
    private var blockCounter: UInt64 = 0
    // RC4 state
    private var rc4S = [UInt8](0...255)
    private var rc4I = 0
    private var rc4J = 0

    init?(method: String, key: Data) {
        switch method.lowercased() {
        case "aes-128-ctr", "aes-192-ctr", "aes-256-ctr":
            kind = .aesCTR(key: key); ivSize = 16
        case "aes-128-cfb", "aes-192-cfb", "aes-256-cfb":
            kind = .aesCFB(key: key); ivSize = 16
        case "chacha20":
            kind = .chachaOriginal(key: key); ivSize = 8
        case "chacha20-ietf":
            kind = .chachaIETF(key: key); ivSize = 12
        case "xchacha20":
            kind = .xchacha(key: key); ivSize = 24
        case "rc4-md5":
            kind = .rc4md5(key: key); ivSize = 16
        default:
            return nil
        }
    }

    static func isStreamMethod(_ method: String?) -> Bool {
        guard let method else { return false }
        return ["aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
                "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
                "chacha20", "chacha20-ietf", "xchacha20", "rc4-md5"].contains(method.lowercased())
    }

    static func keyLength(for method: String) -> Int {
        switch method.lowercased() {
        case "aes-128-ctr", "aes-128-cfb", "rc4-md5": return 16
        case "aes-192-ctr", "aes-192-cfb": return 24
        default: return 32
        }
    }

    /// True when this instance encrypts (CFB needs direction awareness).
    var forEncryption = true

    func setIV(_ iv: Data) {
        self.iv = iv
        switch kind {
        case .aesCTR:
            counterBlock = [UInt8](iv)
            keystream = []
            keystreamPos = 64
        case .aesCFB:
            counterBlock = [UInt8](iv) // holds the previous ciphertext block
            keystream = []
            keystreamPos = 64
        case .chachaOriginal(let key):
            let n = Self.leWords(iv) // 2 words
            chachaTail = [0, 0, n[0], n[1]]
            blockCounter = 0
            keystream = []
            keystreamPos = 64
            _ = key
        case .chachaIETF(let key):
            let n = Self.leWords(iv) // 3 words
            chachaTail = [0, n[0], n[1], n[2]]
            blockCounter = 0
            keystream = []
            keystreamPos = 64
            _ = key
        case .xchacha(let key):
            let subkey = NCChaCha.hchacha20(key: key, nonce: Data(iv.prefix(16)))
            let n = Self.leWords(Data(iv.suffix(8))) // 2 words, first tail word 0
            chachaTail = [0, 0, n[0], n[1]]
            // Stash the derived key by rewriting the kind.
            self.derivedKey = subkey
            blockCounter = 0
            keystream = []
            keystreamPos = 64
        case .rc4md5(let key):
            var material = [UInt8](key)
            material.append(contentsOf: iv)
            let rc4Key = [UInt8](Insecure.MD5.hash(data: Data(material)))
            rc4S = [UInt8](0...255)
            var j = 0
            for i in 0..<256 {
                j = (j + Int(rc4S[i]) + Int(rc4Key[i % rc4Key.count])) & 0xff
                rc4S.swapAt(i, j)
            }
            rc4I = 0
            rc4J = 0
        }
    }

    private var derivedKey: Data?

    private static func leWords(_ d: Data) -> [UInt32] {
        (0..<d.count / 4).map { i in
            UInt32(d[i * 4]) | UInt32(d[i * 4 + 1]) << 8 | UInt32(d[i * 4 + 2]) << 16 | UInt32(d[i * 4 + 3]) << 24
        }
    }

    private func nextKeystreamByte() -> UInt8 {
        if keystreamPos >= keystream.count { refillKeystream() }
        defer { keystreamPos += 1 }
        return keystream[keystreamPos]
    }

    private func refillKeystream() {
        switch kind {
        case .aesCTR(let key):
            guard let aes = NCAES(key: key) else { keystream = []; return }
            keystream = [UInt8](aes.encryptBlock(Data(counterBlock)))
            // Increment the 128-bit counter big-endian.
            var i = 15
            while i >= 0 {
                counterBlock[i] &+= 1
                if counterBlock[i] != 0 { break }
                i -= 1
            }
        case .aesCFB:
            // Keystream comes from encrypting the feedback block; the
            // feedback itself is updated in process() per output block.
            guard case .aesCFB(let key) = kind, let aes = NCAES(key: key) else { keystream = []; return }
            keystream = [UInt8](aes.encryptBlock(Data(counterBlock)))
        case .chachaOriginal(let key), .chachaIETF(let key):
            var tail = chachaTail
            tail[0] = UInt32(blockCounter & 0xffff_ffff)
            if case .chachaOriginal = kind { tail[1] = UInt32((blockCounter >> 32) & 0xffff_ffff) }
            keystream = NCChaChaStream.block(key: key, tail: tail)
            blockCounter += 1
        case .xchacha:
            var tail = chachaTail
            tail[0] = UInt32(blockCounter & 0xffff_ffff)
            keystream = NCChaChaStream.block(key: derivedKey ?? Data(), tail: tail)
            blockCounter += 1
        case .rc4md5:
            keystream = (0..<256).map { _ in rc4Byte() }
            keystreamPos = 0
            return
        }
        keystreamPos = 0
    }

    private func rc4Byte() -> UInt8 {
        rc4I = (rc4I + 1) & 0xff
        rc4J = (rc4J + Int(rc4S[rc4I])) & 0xff
        rc4S.swapAt(rc4I, rc4J)
        return rc4S[(Int(rc4S[rc4I]) + Int(rc4S[rc4J])) & 0xff]
    }

    /// XOR-process data through the stream. For CFB the feedback register
    /// follows the CIPHERTEXT (output when encrypting, input when
    /// decrypting), so process blocks at a time.
    func process(_ data: Data) -> Data {
        if case .aesCFB = kind {
            return processCFB(data)
        }
        var out = Data()
        out.reserveCapacity(data.count)
        for b in data { out.append(b ^ nextKeystreamByte()) }
        return out
    }

    private func processCFB(_ data: Data) -> Data {
        var out = Data()
        out.reserveCapacity(data.count)
        var offset = 0
        let bytes = [UInt8](data)
        while offset < bytes.count {
            if keystreamPos >= keystream.count { refillKeystream() }
            let take = min(16 - (0), keystream.count - keystreamPos, bytes.count - offset)
            // CFB segment: after 16 bytes the feedback becomes the last
            // ciphertext block. keystreamPos tracks position in segment.
            for k in 0..<take {
                let inByte = bytes[offset + k]
                let outByte = inByte ^ keystream[keystreamPos + k]
                out.append(outByte)
                let feedbackByte = forEncryption ? outByte : inByte
                // Write feedback into the register at the segment offset;
                // when the segment completes it IS the register.
                if feedbackPos < 16 {
                    feedbackRegister[feedbackPos] = feedbackByte
                    feedbackPos += 1
                    if feedbackPos == 16 {
                        counterBlock = feedbackRegister
                        feedbackPos = 0
                    }
                }
            }
            keystreamPos += take
            offset += take
        }
        return out
    }

    private var feedbackRegister = [UInt8](repeating: 0, count: 16)
    private var feedbackPos = 0
}

/// HMAC-SHA1 (RFC 2104) over the pure-Swift SHA-1.
enum NCHMACSHA1 {
    static func mac(key: Data, message: Data) -> Data {
        var k = [UInt8](key)
        if k.count > 64 { k = [UInt8](NCSHA1.hash(Data(k))) }
        k += [UInt8](repeating: 0, count: 64 - k.count)
        let inner = Data(k.map { $0 ^ 0x36 }) + message
        let outer = Data(k.map { $0 ^ 0x5c }) + NCSHA1.hash(inner)
        return NCSHA1.hash(outer)
    }
}

/// Per-proxy auth state: SSR's authData.next() — a random clientID that
/// persists across connections, with a connection counter that resets it
/// when it grows too large.
final class NCSSRAuthState {
    private var clientID = Data()
    private var connectionID: UInt32 = 0
    private let lock = NSLock()
    var randomUInt32: () -> UInt32 = { UInt32.random(in: 0...UInt32.max) }
    var randomBytes: (Int) -> Data = { n in Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

    func next() -> (clientID: Data, connectionID: UInt32) {
        lock.lock()
        defer { lock.unlock() }
        if connectionID > 0xff00_0000 || connectionID == 0 {
            clientID = randomBytes(4)
            connectionID = randomUInt32() & 0xff_ffff
        }
        connectionID += 1
        return (clientID, connectionID)
    }
}

/// SSR `auth_sha1_v4` protocol framing — byte layout from mihomo's
/// transport/ssr/protocol/auth_sha1_v4.go.
final class NCSSRAuthSHA1V4 {
    let key: Data
    let iv: Data
    private let clientID: Data
    private let connectionID: UInt32
    private var sentHeader = false
    private var inBuffer = Data()
    var now: () -> UInt32 = { UInt32(Date().timeIntervalSince1970) }
    var randomBelow: (Int) -> Int = { n in n > 0 ? Int.random(in: 0..<n) : 0 }
    var randomBytes: (Int) -> Data = { n in Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

    init(key: Data, iv: Data, auth: (clientID: Data, connectionID: UInt32)) {
        self.key = key
        self.iv = iv
        clientID = auth.clientID
        connectionID = auth.connectionID
    }

    private func randDataLength(for size: Int) -> Int {
        if size > 1200 { return 0 }
        if size > 400 { return randomBelow(256) }
        return randomBelow(512)
    }

    private func packRand(into out: inout Data, size: Int) {
        if size < 128 {
            out.append(UInt8(size + 1))
        } else {
            out.append(255)
            out.appendBE16(UInt16(size + 3))
        }
        out.append(randomBytes(size))
    }

    func encode(_ data: Data) -> Data {
        var out = Data()
        var rest = data
        if !sentHeader {
            let headLen = Self.headLength(of: rest)
            let take = min(rest.count, headLen + randomBelow(32))
            packAuth(into: &out, piece: Data(rest.prefix(take)))
            rest = Data(rest.dropFirst(take))
            sentHeader = true
        }
        while rest.count > 8100 {
            packData(into: &out, piece: Data(rest.prefix(8100)))
            rest = Data(rest.dropFirst(8100))
        }
        if !rest.isEmpty { packData(into: &out, piece: rest) }
        return out
    }

    private static func headLength(of data: Data) -> Int {
        guard data.count >= 2 else { return 30 }
        switch data[0] & 7 {
        case 1: return 7
        case 4: return 19
        case 3: return 4 + Int(data[1])
        default: return 30
        }
    }

    private func packAuth(into out: inout Data, piece: Data) {
        let randLen = randDataLength(for: 12 + piece.count)
        let prefixLen = randLen < 128 ? 1 : 3
        let packedLen = 2 + 4 + prefixLen + randLen + 12 + piece.count + 10
        var pack = Data()
        pack.appendBE16(UInt16(packedLen))
        var crcInput = Data()
        crcInput.appendBE16(UInt16(packedLen))
        crcInput.append("auth_sha1_v4".data(using: .utf8)!)
        crcInput.append(key)
        pack.appendLE32(NCChecksum.crc32(crcInput))
        packRand(into: &pack, size: randLen)
        pack.appendLE32(now())
        pack.append(clientID)
        pack.appendLE32(connectionID)
        pack.append(piece)
        let macKey = iv + key
        pack.append(NCHMACSHA1.mac(key: macKey, message: pack).prefix(10))
        out.append(pack)
    }

    private func packData(into out: inout Data, piece: Data) {
        let randLen = randDataLength(for: piece.count)
        let prefixLen = randLen < 128 ? 1 : 3
        let packedLen = 2 + 2 + prefixLen + randLen + piece.count + 4
        var pack = Data()
        pack.appendBE16(UInt16(packedLen))
        pack.appendLE16(UInt16(NCChecksum.crc32(Data(pack)) & 0xffff))
        packRand(into: &pack, size: randLen)
        pack.append(piece)
        pack.appendLE32(NCChecksum.adler32(pack))
        out.append(pack)
    }

    /// Feed decrypted bytes; returns the framed payloads (may throw off
    /// the connection on checksum/length errors, like the reference).
    func decode(_ data: Data) throws -> Data {
        inBuffer.append(data)
        var out = Data()
        while inBuffer.count > 4 {
            let length = Int(Self.be16(inBuffer, 0))
            if length >= 8192 || length < 7 { throw NCSSR.error("auth_sha1_v4 bad length") }
            if inBuffer.count < length { break }
            let frame = Data(inBuffer.prefix(length))
            guard NCChecksum.crc32(Data(frame.prefix(2))) & 0xffff == Self.le16(frame, 2) else {
                throw NCSSR.error("auth_sha1_v4 bad crc")
            }
            guard NCChecksum.adler32(Data(frame.prefix(length - 4))) == Self.le32(frame, length - 4) else {
                throw NCSSR.error("auth_sha1_v4 bad adler")
            }
            let first = Int(frame[4])
            let dataStart = first < 255 ? first + 4 : Int(Self.be16(frame, 5)) + 4
            out.append(frame[dataStart..<(length - 4)])
            inBuffer.removeFirst(length)
        }
        return out
    }

    private static func be16(_ d: Data, _ o: Int) -> UInt16 {
        UInt16(d[o]) << 8 | UInt16(d[o + 1])
    }
    private static func le16(_ d: Data, _ o: Int) -> UInt16 {
        UInt16(d[o]) | UInt16(d[o + 1]) << 8
    }
    private static func le32(_ d: Data, _ o: Int) -> UInt32 {
        UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
    }
}

/// SSR obfs `http_simple`: wraps the first chunk in a fake GET request
/// (every head byte %XX-encoded) and strips the response's HTTP header.
/// Layout from mihomo's transport/ssr/obfs/http_simple.go.
final class NCSSRHTTPSimple {
    let host: String
    let port: Int
    let ivSize: Int
    private var sentHeader = false
    private var recvHeader = false
    private var inBuffer = Data()
    var randomBelow: (Int) -> Int = { n in n > 0 ? Int.random(in: 0..<n) : 0 }
    var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36"

    init(server: String, port: Int, param: String?, ivSize: Int) {
        self.port = port
        self.ivSize = ivSize
        var hostValue = server
        var body: String?
        if let param, !param.isEmpty {
            if let hash = param.firstIndex(of: "#") {
                hostValue = String(param[..<hash])
                body = String(param[param.index(after: hash)...])
                    .replacingOccurrences(of: "\\n", with: "\r\n")
                    .replacingOccurrences(of: "\n", with: "\r\n")
            } else {
                hostValue = param
            }
        }
        let hosts = hostValue.split(separator: ",").map(String.init)
        host = hosts.isEmpty ? server : hosts[0]
        customBody = body
    }

    private let customBody: String?

    func encode(_ data: Data) -> Data {
        if sentHeader { return data }
        sentHeader = true
        let headLength = ivSize + 30
        var headLen = data.count
        if data.count - headLength > 64 { headLen = headLength + randomBelow(65) }
        let head = data.prefix(headLen)
        let rest = data.dropFirst(headLen)
        var out = Data()
        out.append("GET /".data(using: .utf8)!)
        let hex = "0123456789abcdef"
        for b in head {
            out.append("%".data(using: .utf8)!)
            out.append(String(hex[hex.index(hex.startIndex, offsetBy: Int(b >> 4))]).data(using: .utf8)!)
            out.append(String(hex[hex.index(hex.startIndex, offsetBy: Int(b & 0xf))]).data(using: .utf8)!)
        }
        out.append(" HTTP/1.1\r\nHost: \(host)".data(using: .utf8)!)
        if port != 80 { out.append(":\(port)".data(using: .utf8)!) }
        out.append("\r\n".data(using: .utf8)!)
        if let customBody {
            out.append((customBody + "\r\n\r\n").data(using: .utf8)!)
        } else {
            out.append(("User-Agent: \(userAgent)\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                "Accept-Language: en-US,en;q=0.8\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "DNT: 1\r\nConnection: keep-alive\r\n\r\n").data(using: .utf8)!)
        }
        out.append(rest)
        return out
    }

    /// Strip the response HTTP header once; returns payload bytes ready
    /// for the cipher, or nil while the header is incomplete.
    func decode(_ data: Data) -> Data? {
        if recvHeader { return data }
        inBuffer.append(data)
        guard let range = inBuffer.range(of: Data([13, 10, 13, 10])) else { return nil }
        let payload = Data(inBuffer[range.upperBound...])
        inBuffer = Data()
        recvHeader = true
        return payload
    }
}

enum NCSSR {
    static func error(_ message: String) -> NSError {
        NSError(domain: "NCSSR", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

extension Data {
    mutating func appendLE16(_ v: UInt16) {
        append(UInt8(v & 0xff))
        append(UInt8((v >> 8) & 0xff))
    }

    mutating func appendLE32(_ v: UInt32) {
        append(UInt8(v & 0xff))
        append(UInt8((v >> 8) & 0xff))
        append(UInt8((v >> 16) & 0xff))
        append(UInt8((v >> 24) & 0xff))
    }
}
