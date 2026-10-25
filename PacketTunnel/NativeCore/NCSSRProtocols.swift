import Foundation
import CryptoKit

// ShadowsocksR protocols and obfs beyond origin / auth_sha1_v4 / http_simple (feat/nc-proto A5, based on
// astemo6/Muse NativeCore). Byte layouts ported from mihomo v1.19.33 transport/ssr/protocol (auth_aes128_md5,
// auth_aes128_sha1, auth_chain_a, auth_chain_b) and transport/ssr/obfs (http_simple/http_post, random_head,
// tls1.2_ticket_auth). Per-connection buffers hold at most one frame.

protocol NCSSRProtocolCodec: AnyObject {
    func encode(_ data: Data) -> Data
    func decode(_ data: Data) throws -> Data
}

/// Obfs layer: `encode` may hold bytes back (returns empty) until the server's first answer; `decode` returns
/// payload for the cipher plus bytes to send back (the held-back flush).
protocol NCSSRObfsCodec: AnyObject {
    func encode(_ data: Data) -> Data
    func decode(_ data: Data) throws -> (payload: Data, reply: Data)
}

extension NCSSRAuthSHA1V4: NCSSRProtocolCodec {}

enum NCSSRKit {
    static func hmacMD5(_ key: Data, _ data: Data) -> Data {
        Data(HMAC<Insecure.MD5>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
    static func hmacSHA1(_ key: Data, _ data: Data) -> Data {
        Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
    static func le32(_ v: UInt32) -> Data { var d = Data(); d.appendLE32(v); return d }
    static func readLE16(_ d: Data, _ o: Int) -> Int { Int(d[d.startIndex + o]) | Int(d[d.startIndex + o + 1]) << 8 }
    static func readLE32(_ d: Data, _ o: Int) -> UInt32 {
        let s = d.startIndex + o
        return UInt32(d[s]) | UInt32(d[s + 1]) << 8 | UInt32(d[s + 2]) << 16 | UInt32(d[s + 3]) << 24
    }
    static func rand(_ n: Int) -> Int { n > 0 ? Int.random(in: 0..<n) : 0 }
    static func randBytes(_ n: Int) -> Data { n > 0 ? NCConnector.randomData(n) : Data() }

    /// getHeadSize(b, 30) + rand(32), capped at the data length (protocol.go getDataLength).
    static func dataLength(_ b: Data) -> Int {
        var head = 30
        if b.count >= 2 {
            let s = b.startIndex
            switch b[s] & 7 {
            case 1: head = 7
            case 4: head = 19
            case 3: head = 4 + Int(b[s + 1])
            default: break
            }
        }
        return min(b.count, head + rand(32))
    }

    /// authData.putEncryptedData: AES-128-CBC (zero IV, one block) under Kdf(base64(userKey)+salt, 16).
    static func encryptedAuth(clientID: Data, connectionID: UInt32, userKey: Data, p0: Int, p1: Int,
                              salt: String) -> Data? {
        var block = Data()
        block.appendLE32(UInt32(Date().timeIntervalSince1970))
        block.append(clientID.prefix(4))
        block.appendLE32(connectionID)
        block.appendLE16(UInt16(truncatingIfNeeded: p0))
        block.appendLE16(UInt16(truncatingIfNeeded: p1))
        let key = NCShadowsocks.masterKey(password: userKey.base64EncodedString() + salt, keyLen: 16)
        guard let aes = NCAES(key: key) else { return nil }
        return aes.encryptBlock(block)
    }
}

/// Per-proxy user data (userID / userKey): random userID when protocol-param carries none — fixed for the
/// proxy's lifetime like mihomo's newAuthAES128* / newAuthChain*.
final class NCSSRUserData {
    let userID: Data
    let userKey: Data
    init(param: String?, key: Data, hashKey: (Data) -> Data) {
        let parts = (param ?? "").split(separator: ":", maxSplits: 1).map(String.init)
        if parts.count > 1, let uid = UInt32(parts[0]) {
            var d = Data(); d.appendLE32(uid)
            userID = d
            userKey = hashKey(Data(parts[1].utf8))
        } else {
            userID = NCConnector.randomData(4)
            userKey = key
        }
    }
}

// MARK: - auth_aes128_md5 / auth_aes128_sha1

final class NCSSRAuthAES128: NCSSRProtocolCodec {
    private let key: Data, iv: Data, salt: String, overhead: Int
    private let user: NCSSRUserData
    private let clientID: Data, connectionID: UInt32
    private let mac: (Data, Data) -> Data
    private var sentHeader = false
    private var rawTrans = false
    private var packID: UInt32 = 1, recvID: UInt32 = 1
    private var inbuf = Data()

    init(sha1: Bool, key: Data, iv: Data, overhead: Int, user: NCSSRUserData,
         auth: (clientID: Data, connectionID: UInt32)) {
        self.key = key; self.iv = iv
        salt = sha1 ? "auth_aes128_sha1" : "auth_aes128_md5"
        mac = sha1 ? NCSSRKit.hmacSHA1 : NCSSRKit.hmacMD5
        self.overhead = overhead
        self.user = user
        clientID = auth.clientID; connectionID = auth.connectionID
    }

    func encode(_ data: Data) -> Data {
        var out = Data()
        var b = data[...]
        let full = data.count
        if !sentHeader {
            let n = NCSSRKit.dataLength(data)
            packAuth(&out, Data(b.prefix(n)))
            b = b.dropFirst(n)
            sentHeader = true
        }
        while b.count > 8100 {
            packData(&out, Data(b.prefix(8100)), full: full)
            b = b.dropFirst(8100)
        }
        if !b.isEmpty { packData(&out, Data(b), full: full) }
        return out
    }

    private func packRand(_ p: inout Data, _ size: Int) {
        if size < 128 {
            p.append(UInt8(size + 1))
        } else {
            p.append(255)
            p.appendLE16(UInt16(size + 3))
        }
        p.append(NCSSRKit.randBytes(size))
    }

    private func randLenPackData(_ len: Int, full: Int) -> Int {
        if full >= 32 * 1024 - overhead { return 0 }
        let rev = 1460 - len - 9
        if rev == 0 { return 0 }
        if rev < 0 {
            if rev > -1460 { return NCSSRKit.rand(rev + 1460) } // trapezoidRandom(_, -0.3) is uniform
            return NCSSRKit.rand(32)
        }
        return NCSSRKit.rand(rev)
    }

    private func packData(_ out: inout Data, _ data: Data, full: Int) {
        let r = randLenPackData(data.count, full: full)
        var packed = 2 + 2 + 3 + r + data.count + 4
        if r < 128 { packed -= 2 }
        let macKey = user.userKey + NCSSRKit.le32(packID)
        packID &+= 1
        var p = Data(capacity: packed)
        p.appendLE16(UInt16(packed))
        p.append(mac(macKey, p).prefix(2))
        packRand(&p, r)
        p.append(data)
        p.append(mac(macKey, p).prefix(4))
        out.append(p)
    }

    private func packAuth(_ out: inout Data, _ data: Data) {
        guard !data.isEmpty else { return }
        let r = data.count > 400 ? NCSSRKit.rand(512) : NCSSRKit.rand(1024)
        let packed = 7 + 4 + 16 + 4 + r + data.count + 4
        let macKey = iv + key
        var p = Data([UInt8.random(in: 0...255)])
        p.append(mac(macKey, p).prefix(6))
        p.append(user.userID)
        guard let enc = NCSSRKit.encryptedAuth(clientID: clientID, connectionID: connectionID,
                                               userKey: user.userKey, p0: packed, p1: r, salt: salt) else { return }
        p.append(enc)
        p.append(mac(macKey, Data(p.dropFirst(7))).prefix(4))
        p.append(NCSSRKit.randBytes(r))
        p.append(data)
        p.append(mac(user.userKey, p).prefix(4))
        out.append(p)
    }

    func decode(_ data: Data) throws -> Data {
        if rawTrans { return data }
        inbuf.append(data)
        var out = Data()
        while inbuf.count > 4 {
            let macKey = user.userKey + NCSSRKit.le32(recvID)
            let s = inbuf.startIndex
            guard mac(macKey, Data(inbuf[s..<(s + 2)])).prefix(2) == inbuf[(s + 2)..<(s + 4)] else {
                inbuf = Data()
                throw NCSSR.error("auth_aes128 decode data wrong mac")
            }
            let length = NCSSRKit.readLE16(inbuf, 0)
            if length >= 8192 || length < 7 {
                rawTrans = true
                inbuf = Data()
                throw NCSSR.error("auth_aes128 decode data wrong length")
            }
            if length > inbuf.count { break }
            guard mac(macKey, Data(inbuf[s..<(s + length - 4)])).prefix(4) == inbuf[(s + length - 4)..<(s + length)] else {
                rawTrans = true
                inbuf = Data()
                throw NCSSR.error("auth_aes128 decode data wrong checksum")
            }
            recvID &+= 1
            var pos = Int(inbuf[s + 4])
            pos = pos < 255 ? pos + 4 : NCSSRKit.readLE16(inbuf, 5) + 4
            if pos < length - 4 { out.append(inbuf[(s + pos)..<(s + length - 4)]) }
            inbuf = Data(inbuf.dropFirst(length))
        }
        return out
    }
}

// MARK: - auth_chain_a / auth_chain_b

struct NCXorShift128Plus {
    var s0: UInt64 = 0, s1: UInt64 = 0

    mutating func next() -> UInt64 {
        var x = s0
        let y = s1
        s0 = y
        x ^= x << 23
        x ^= y ^ (x >> 17) ^ (y >> 26)
        s1 = x
        return x &+ y
    }

    private static func le64(_ b: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[o + i]) << (8 * UInt64(i)) }
        return v
    }

    mutating func initFromBin(_ bin: Data) {
        var full = [UInt8](bin.prefix(16))
        while full.count < 16 { full.append(0) }
        s0 = Self.le64(full, 0); s1 = Self.le64(full, 8)
    }

    /// Go writes the length over the hash's first two bytes in place; same seed here without the aliasing.
    mutating func initFromBinAndLength(_ bin: Data, _ length: Int) {
        var full = [UInt8](bin.prefix(16))
        while full.count < 16 { full.append(0) }
        full[0] = UInt8(truncatingIfNeeded: length)
        full[1] = UInt8(truncatingIfNeeded: length >> 8)
        s0 = Self.le64(full, 0); s1 = Self.le64(full, 8)
        for _ in 0..<4 { _ = next() }
    }
}

final class NCRC4 {
    private var s = [UInt8](0...255)
    private var i = 0, j = 0
    init(key: Data) {
        let k = [UInt8](key)
        var j = 0
        for i in 0..<256 {
            j = (j + Int(s[i]) + Int(k[i % k.count])) & 0xff
            s.swapAt(i, j)
        }
    }
    func process(_ data: Data) -> Data {
        var out = [UInt8](data)
        for n in 0..<out.count {
            i = (i + 1) & 0xff
            j = (j + Int(s[i])) & 0xff
            s.swapAt(i, j)
            out[n] ^= s[(Int(s[i]) + Int(s[j])) & 0xff]
        }
        return Data(out)
    }
}

final class NCSSRAuthChain: NCSSRProtocolCodec {
    private let variantB: Bool
    private let key: Data, iv: Data, salt: String, overhead: Int
    private let user: NCSSRUserData
    private let clientID: Data, connectionID: UInt32
    private var sentHeader = false
    private var rawTrans = false
    private var lastClientHash = Data(), lastServerHash = Data()
    private var encrypter: NCRC4?, decrypter: NCRC4?
    private var randomClient = NCXorShift128Plus(), randomServer = NCXorShift128Plus()
    private var packID: UInt32 = 1, recvID: UInt32 = 1
    private var inbuf = Data()
    private var sizes1: [Int] = [], sizes2: [Int] = []

    init(variantB: Bool, key: Data, iv: Data, overhead: Int, user: NCSSRUserData,
         auth: (clientID: Data, connectionID: UInt32)) {
        self.variantB = variantB
        self.key = key; self.iv = iv
        salt = variantB ? "auth_chain_b" : "auth_chain_a"
        self.overhead = overhead
        self.user = user
        clientID = auth.clientID; connectionID = auth.connectionID
        if variantB { initDataSize() }
    }

    private func initDataSize() {
        var r = NCXorShift128Plus()
        r.initFromBin(key)
        var n = r.next() % 8 + 4
        while n > 0 { sizes1.append(Int(r.next() % 2340 % 2040 % 1440)); n -= 1 }
        sizes1.sort()
        n = r.next() % 16 + 8
        while n > 0 { sizes2.append(Int(r.next() % 2340 % 2040 % 1440)); n -= 1 }
        sizes2.sort()
        randomServer = r
    }

    private func randLength(_ length: Int, _ lastHash: Data, _ random: inout NCXorShift128Plus) -> Int {
        if variantB {
            if length >= 1440 { return 0 }
            random.initFromBinAndLength(lastHash, length)
            let need = length + overhead
            let pos = sizes1.firstIndex(where: { $0 >= need }) ?? sizes1.count
            let fin = pos + Int(random.next() % UInt64(sizes1.count))
            if fin < sizes1.count { return sizes1[fin] - length - overhead }
            let pos2 = sizes2.firstIndex(where: { $0 >= need }) ?? sizes2.count
            let fin2 = pos2 + Int(random.next() % UInt64(sizes2.count))
            if fin2 < sizes2.count { return sizes2[fin2] - length - overhead }
            if fin2 < pos2 + sizes2.count - 1 { return 0 }
        } else {
            if length > 1440 { return 0 }
            random.initFromBinAndLength(lastHash, length)
        }
        if length > 1300 { return Int(random.next() % 31) }
        if length > 900 { return Int(random.next() % 127) }
        if length > 400 { return Int(random.next() % 521) }
        return Int(random.next() % 1021)
    }

    private static func randStartPos(_ length: Int, _ random: inout NCXorShift128Plus) -> Int {
        if length == 0 { return 0 }
        return Int(Int64(bitPattern: random.next() % 8589934609) % Int64(length))
    }

    func encode(_ data: Data) -> Data {
        var out = Data()
        var b = data[...]
        if !sentHeader {
            let n = NCSSRKit.dataLength(data)
            packAuth(&out, Data(b.prefix(n)))
            b = b.dropFirst(n)
            sentHeader = true
        }
        while b.count > 2800 {
            packData(&out, Data(b.prefix(2800)))
            b = b.dropFirst(2800)
        }
        if !b.isEmpty { packData(&out, Data(b)) }
        return out
    }

    private func packAuth(_ out: inout Data, _ data: Data) {
        let macKey = iv + key
        var p = NCSSRKit.randBytes(4)
        lastClientHash = NCSSRKit.hmacMD5(macKey, p)
        let rc4Key = NCShadowsocks.masterKey(password: user.userKey.base64EncodedString()
                                             + lastClientHash.base64EncodedString(), keyLen: 16)
        encrypter = NCRC4(key: rc4Key)
        decrypter = NCRC4(key: rc4Key)
        p.append(lastClientHash.prefix(8))
        p.appendLE32(NCSSRKit.readLE32(user.userID, 0) ^ NCSSRKit.readLE32(lastClientHash, 8))
        guard let enc = NCSSRKit.encryptedAuth(clientID: clientID, connectionID: connectionID,
                                               userKey: user.userKey, p0: overhead, p1: 0, salt: salt) else { return }
        p.append(enc)
        lastServerHash = NCSSRKit.hmacMD5(user.userKey, Data(p.dropFirst(12)))
        p.append(lastServerHash.prefix(4))
        out.append(p)
        packData(&out, data)
    }

    private func packData(_ out: inout Data, _ plain: Data) {
        let data = encrypter?.process(plain) ?? plain
        let macKey = user.userKey + NCSSRKit.le32(packID)
        packID &+= 1
        let length = UInt16(truncatingIfNeeded: data.count) ^ UInt16(NCSSRKit.readLE16(lastClientHash, 14))
        var p = Data()
        p.appendLE16(length)
        let r = randLength(data.count, lastClientHash, &randomClient)
        if data.isEmpty {
            p.append(NCSSRKit.randBytes(r))
        } else if r > 0 {
            let start = Self.randStartPos(r, &randomClient)
            p.append(NCSSRKit.randBytes(start))
            p.append(data)
            p.append(NCSSRKit.randBytes(r - start))
        } else {
            p.append(data)
        }
        lastClientHash = NCSSRKit.hmacMD5(macKey, p)
        p.append(lastClientHash.prefix(2))
        out.append(p)
    }

    func decode(_ data: Data) throws -> Data {
        if rawTrans { return data }
        inbuf.append(data)
        var out = Data()
        while inbuf.count > 4 {
            let macKey = user.userKey + NCSSRKit.le32(recvID)
            let dataLength = NCSSRKit.readLE16(inbuf, 0) ^ NCSSRKit.readLE16(lastServerHash, 14)
            let r = randLength(dataLength, lastServerHash, &randomServer)
            let length = dataLength + r
            if length >= 4096 {
                rawTrans = true
                inbuf = Data()
                throw NCSSR.error("auth_chain decode data wrong length")
            }
            if 4 + length > inbuf.count { break }
            let s = inbuf.startIndex
            let serverHash = NCSSRKit.hmacMD5(macKey, Data(inbuf[s..<(s + length + 2)]))
            guard serverHash.prefix(2) == inbuf[(s + length + 2)..<(s + length + 4)] else {
                rawTrans = true
                inbuf = Data()
                throw NCSSR.error("auth_chain decode data wrong checksum")
            }
            lastServerHash = serverHash
            var pos = 2
            if dataLength > 0 && r > 0 { pos += Self.randStartPos(r, &randomServer) }
            guard pos + dataLength <= length + 2 else { throw NCSSR.error("ssr crashing blocked") }
            let wanted = Data(inbuf[(s + pos)..<(s + pos + dataLength)])
            let plain = decrypter?.process(wanted) ?? wanted
            out.append(recvID == 1 ? Data(plain.dropFirst(2)) : plain)
            recvID &+= 1
            inbuf = Data(inbuf.dropFirst(length + 4))
        }
        return out
    }
}

// MARK: - obfs: http_simple / http_post

final class NCSSRHTTPObfs: NCSSRObfsCodec {
    private let post: Bool
    private let host: String, port: Int, ivSize: Int, param: String
    private var sentHeader = false, recvHeader = false
    private var inbuf = Data()
    private static let userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 7.0; Moto C Build/NRD90M.059) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
    ]

    init(post: Bool, host: String, port: Int, ivSize: Int, param: String?) {
        self.post = post; self.host = host; self.port = port; self.ivSize = ivSize; self.param = param ?? ""
    }

    func encode(_ data: Data) -> Data {
        if sentHeader { return data }
        sentHeader = true
        let headLength = ivSize + 30
        var headLen = data.count
        if data.count - headLength > 64 { headLen = headLength + NCSSRKit.rand(65) }
        let head = data.prefix(headLen), rest = data.dropFirst(headLen)
        var body = ""
        var hostValue = host
        if !param.isEmpty {
            if let hash = param.firstIndex(of: "#") {
                body = String(param[param.index(after: hash)...])
                    .replacingOccurrences(of: "\n", with: "\r\n").replacingOccurrences(of: "\\n", with: "\r\n")
                hostValue = String(param[..<hash])
            } else {
                hostValue = param
            }
        }
        let hosts = hostValue.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let chosen = hosts.isEmpty ? hostValue : hosts[NCSSRKit.rand(hosts.count)]
        var s = post ? "POST /" : "GET /"
        for b in head { s += String(format: "%%%02x", b) }
        s += " HTTP/1.1\r\nHost: " + chosen
        if port != 80 { s += ":\(port)" }
        s += "\r\n"
        if !body.isEmpty {
            s += body + "\r\n\r\n"
        } else {
            s += "User-Agent: " + Self.userAgents[NCSSRKit.rand(Self.userAgents.count)]
            s += "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n"
            if post {
                let set = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                s += "Content-Type: multipart/form-data; boundary=" + String((0..<32).map { _ in set[NCSSRKit.rand(62)] }) + "\r\n"
            }
            s += "DNT: 1\r\nConnection: keep-alive\r\n\r\n"
        }
        var out = Data(s.utf8)
        out.append(rest)
        return out
    }

    func decode(_ data: Data) throws -> (payload: Data, reply: Data) {
        if recvHeader { return (data, Data()) }
        inbuf.append(data)
        guard let r = inbuf.range(of: Data([13, 10, 13, 10])) else {
            if inbuf.count > 65536 { throw NCSSR.error("http obfs: no header end") }
            return (Data(), Data())
        }
        recvHeader = true
        let payload = Data(inbuf[r.upperBound...])
        inbuf = Data()
        return (payload, Data())
    }
}

// MARK: - obfs: random_head

final class NCSSRRandomHead: NCSSRObfsCodec {
    private var sentHeader = false, rawRecv = false, rawSent = false
    private var held = Data()

    func encode(_ data: Data) -> Data {
        if rawSent { return data }
        held.append(data)
        if !sentHeader {
            sentHeader = true
            var head = NCSSRKit.randBytes(NCSSRKit.rand(96) + 4)
            head.appendLE32(0xffff_ffff &- NCChecksum.crc32(head))
            return head
        }
        return Data()
    }

    func decode(_ data: Data) throws -> (payload: Data, reply: Data) {
        if rawRecv { return (data, Data()) }
        rawRecv = true // the server's first chunk is discarded
        let flush = held
        held = Data()
        rawSent = true
        return (Data(), flush)
    }
}

// MARK: - obfs: tls1.2_ticket_auth (and _fastauth)

final class NCSSRTLSTicketAuth: NCSSRObfsCodec {
    private let key: Data, clientID: Data, host: String
    private var status = 0
    private var held = Data()
    private var inbuf = Data()

    init(key: Data, clientID: Data, server: String, param: String?) {
        self.key = key
        self.clientID = clientID
        var h = (param?.isEmpty == false ? param! : server)
        if let last = h.last, last.isNumber { h = "" }
        let hosts = h.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        host = hosts.isEmpty ? h : hosts[NCSSRKit.rand(hosts.count)]
    }

    private func mac(_ d: Data) -> Data { NCSSRKit.hmacSHA1(key + clientID, d).prefix(10) }

    private static func pack(_ out: inout Data, _ d: Data) {
        out.append(contentsOf: [0x17, 3, 3] as [UInt8])
        out.appendBE16(UInt16(d.count))
        out.append(d)
    }

    func encode(_ data: Data) -> Data {
        if status == 8 {
            var out = Data()
            var b = data[...]
            while b.count > 2048 {
                let size = min(b.count, NCSSRKit.rand(4096) + 100)
                Self.pack(&out, Data(b.prefix(size)))
                b = b.dropFirst(size)
            }
            if !b.isEmpty { Self.pack(&out, Data(b)) }
            return out
        }
        if !data.isEmpty { Self.pack(&held, data) }
        guard status == 0 else { return Data() }
        status = 1
        var d = Data([3, 3])
        var auth = Data()
        auth.appendBE32(UInt32(Date().timeIntervalSince1970))
        auth.append(NCSSRKit.randBytes(18))
        auth.append(mac(auth))
        d.append(auth)
        d.append(0x20)
        d.append(clientID)
        d.append(contentsOf: [0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a,
                              0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a] as [UInt8])
        d.append(contentsOf: [0x1, 0x0] as [UInt8])
        var ext = Data([0xff, 0x01, 0x00, 0x01, 0x00])
        let sn = Data(host.utf8)
        ext.append(contentsOf: [0, 0] as [UInt8])
        ext.appendBE16(UInt16(sn.count + 5))
        ext.appendBE16(UInt16(sn.count + 3))
        ext.append(0)
        ext.appendBE16(UInt16(sn.count))
        ext.append(sn)
        ext.append(contentsOf: [0, 0x17, 0, 0] as [UInt8])
        let ticketLen = 16 * (NCSSRKit.rand(17) + 8)
        ext.append(contentsOf: [0, 0x23] as [UInt8])
        ext.appendBE16(UInt16(ticketLen))
        ext.append(NCSSRKit.randBytes(ticketLen))
        ext.append(contentsOf: [0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04,
                                0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03] as [UInt8])
        ext.append(contentsOf: [0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00] as [UInt8])
        ext.append(contentsOf: [0x00, 0x12, 0x00, 0x00] as [UInt8])
        ext.append(contentsOf: [0x75, 0x50, 0x00, 0x00] as [UInt8])
        ext.append(contentsOf: [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00] as [UInt8])
        ext.append(contentsOf: [0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18] as [UInt8])
        d.appendBE16(UInt16(ext.count))
        d.append(ext)
        var ret = Data([0x16, 3, 1])
        ret.appendBE16(UInt16(d.count + 4))
        ret.append(contentsOf: [1, 0] as [UInt8])
        ret.appendBE16(UInt16(d.count))
        ret.append(d)
        return ret
    }

    func decode(_ data: Data) throws -> (payload: Data, reply: Data) {
        inbuf.append(data)
        var reply = Data()
        if status != 8 {
            // Server flight: ServerHello record(s), ChangeCipherSpec, then a 32-byte "Finished" handshake record.
            var off = 0, sawCCS = false, end = -1
            let b = [UInt8](inbuf)
            while off + 5 <= b.count {
                let len = Int(b[off + 3]) << 8 | Int(b[off + 4])
                guard off + 5 + len <= b.count else { break }
                if b[off] == 0x14 { sawCCS = true } else if sawCCS && b[off] == 0x16 { end = off + 5 + len; break }
                off += 5 + len
            }
            guard end > 0 else {
                if inbuf.count > 16384 { throw NCSSR.error("tls1.2_ticket_auth too short data") }
                return (Data(), Data())
            }
            let hello = Data(b[0..<end])
            guard hello.count >= 11 + 32 + 1 + 32,
                  hello[33..<43] == mac(Data(hello[11..<33])),
                  hello.suffix(10) == mac(Data(hello.prefix(hello.count - 10))) else {
                throw NCSSR.error("tls1.2_ticket_auth hmac verifying failed")
            }
            inbuf = Data(b[end...])
            var fin = Data([0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20])
            fin.append(NCSSRKit.randBytes(22))
            fin.append(mac(fin))
            fin.append(held)
            held = Data()
            status = 8
            reply = fin
        }
        var out = Data()
        while inbuf.count > 5 {
            let s = inbuf.startIndex
            guard inbuf[s] == 0x17, inbuf[s + 1] == 3, inbuf[s + 2] == 3 else {
                inbuf = Data()
                throw NCSSR.error("tls1.2_ticket_auth incorrect magic number")
            }
            let size = Int(inbuf[s + 3]) << 8 | Int(inbuf[s + 4])
            guard inbuf.count >= 5 + size else { break }
            out.append(inbuf[(s + 5)..<(s + 5 + size)])
            inbuf = Data(inbuf.dropFirst(5 + size))
        }
        return (out, reply)
    }
}

// MARK: - SSR relay over the generic codecs

final class NCSSRCodecRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private let encryptor: NCSSStreamCipher?
    private let decryptor: NCSSStreamCipher?
    private let clientIV: Data
    private let ivSize: Int
    private var ivSent = false, ivReceived = false
    private var ivBuffer = Data()
    private let proto: NCSSRProtocolCodec?
    private let obfs: NCSSRObfsCodec?

    /// `method` nil = "none"/"dummy" (no cipher, no IV).
    init(raw: NCRelayStream, method: String?, key: Data, clientIV: Data,
         proto: NCSSRProtocolCodec?, obfs: NCSSRObfsCodec?, target: NCTarget) {
        self.raw = raw
        self.clientIV = clientIV
        if let method {
            let e = NCSSStreamCipher(method: method, key: key)
            e?.forEncryption = true
            e?.setIV(clientIV)
            let d = NCSSStreamCipher(method: method, key: key)
            d?.forEncryption = false
            encryptor = e; decryptor = d
            ivSize = d?.ivSize ?? 0
        } else {
            encryptor = nil; decryptor = nil; ivSize = 0
        }
        self.proto = proto
        self.obfs = obfs
        send(target.atypEncoded)
    }

    func send(_ data: Data) {
        let framed = proto?.encode(data) ?? data
        var out = Data()
        if !ivSent {
            out.append(clientIV)
            ivSent = true
        }
        out.append(encryptor?.process(framed) ?? framed)
        let wire = obfs?.encode(out) ?? out
        if !wire.isEmpty { raw.send(wire) }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            do {
                let plain = try self.unwrap(data)
                if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
            } catch {
                self.raw.cancel()
                handler(nil, error)
            }
        }
    }

    private func unwrap(_ data: Data) throws -> Data {
        var chunk = data
        if let obfs {
            let r = try obfs.decode(chunk)
            if !r.reply.isEmpty { raw.send(r.reply) }
            chunk = r.payload
            if chunk.isEmpty { return Data() }
        }
        if !ivReceived && ivSize > 0 {
            ivBuffer.append(chunk)
            guard ivBuffer.count >= ivSize else { return Data() }
            decryptor?.setIV(Data(ivBuffer.prefix(ivSize)))
            chunk = Data(ivBuffer.dropFirst(ivSize))
            ivBuffer = Data()
            ivReceived = true
            if chunk.isEmpty { return Data() }
        }
        let plain = decryptor?.process(chunk) ?? chunk
        if let proto { return try proto.decode(plain) }
        return plain
    }

    func cancel() { raw.cancel() }
}

// MARK: - Connector glue

extension NCConnector {
    private static var ssrUserRegistry: [String: NCSSRUserData] = [:]
    private static var ssrTicketIDs: [String: Data] = [:]
    private static let ssrExtraLock = NSLock()

    static func ssrUserData(proxy: NCProxy, key: Data, sha1: Bool?) -> NCSSRUserData {
        let param = proxy.fields["protocol-param"]?.string
        let id = "\(proxy.name)|\(proxy.fields["protocol"]?.string ?? "")|\(param ?? "")"
        ssrExtraLock.lock(); defer { ssrExtraLock.unlock() }
        if let u = ssrUserRegistry[id] { return u }
        let u = NCSSRUserData(param: param, key: key, hashKey: { pass in
            switch sha1 {
            case .some(true): return Data(Insecure.SHA1.hash(data: pass))
            case .some(false): return Data(Insecure.MD5.hash(data: pass))
            case .none: return pass // auth_chain: raw password bytes
            }
        })
        ssrUserRegistry[id] = u
        return u
    }

    static func ssrTicketClientID(proxy: NCProxy) -> Data {
        ssrExtraLock.lock(); defer { ssrExtraLock.unlock() }
        if let d = ssrTicketIDs[proxy.name] { return d }
        let d = randomData(32)
        ssrTicketIDs[proxy.name] = d
        return d
    }
}
