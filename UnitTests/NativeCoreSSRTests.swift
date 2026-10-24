import XCTest
@testable import Mihomo

/// SSR primitives — stream cipher vectors from reference implementations
/// (Go stdlib AES modes, x/crypto-style ChaCha per RFC 8439, RC4-MD5),
/// auth_sha1_v4 framing verified structurally (CRC/HMAC per spec) plus a
/// self-decoding round trip.
final class NativeCoreSSRTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return d
    }

    private let plain = Data("hello shadowsocksr world".utf8)
    private let key16 = Data((0..<16).map { UInt8($0) })
    private let key32 = Data((0..<32).map { UInt8($0) })
    private let iv16 = Data((0..<16).map { UInt8(0x20 + $0) })

    func testCipherVectors() {
        var c = NCSSStreamCipher(method: "aes-128-ctr", key: key16)!
        c.setIV(iv16)
        XCTAssertEqual(c.process(plain), hex("338d124234640ffc2a45a6d80439a3b338d63c554dfc54cc"))

        c = NCSSStreamCipher(method: "aes-128-cfb", key: key16)!
        c.forEncryption = true
        c.setIV(iv16)
        let cfbOut = c.process(plain)
        XCTAssertEqual(cfbOut, hex("338d124234640ffc2a45a6d80439a3b30dc4650e2ed97596"))
        // CFB decrypt direction reverses it.
        let d = NCSSStreamCipher(method: "aes-128-cfb", key: key16)!
        d.forEncryption = false
        d.setIV(iv16)
        XCTAssertEqual(d.process(cfbOut), plain)

        // Split writes must produce identical streams (state machine).
        let split = NCSSStreamCipher(method: "aes-128-cfb", key: key16)!
        split.setIV(iv16)
        var acc = split.process(Data(plain.prefix(5)))
        acc.append(split.process(Data(plain.dropFirst(5))))
        XCTAssertEqual(acc, cfbOut)

        var ch = NCSSStreamCipher(method: "chacha20", key: key32)!
        ch.setIV(hex("0102030405060708"))
        XCTAssertEqual(ch.process(plain), hex("e48f3453a8a8195eaacb95d2e682b188d3a549214e0115a9"))

        ch = NCSSStreamCipher(method: "chacha20-ietf", key: key32)!
        ch.setIV(hex("0102030405060708090a0b0c"))
        XCTAssertEqual(ch.process(plain), hex("190c1a6cbce4604cce802b43b89f1359ef47713526ddb7be"))

        // XChaCha: encrypt/decrypt round trip (no external vector at hand;
        // the HChaCha core is vector-verified in the SS2022 suite).
        let xe = NCSSStreamCipher(method: "xchacha20", key: key32)!
        xe.setIV(Data((0..<24).map { UInt8($0) }))
        let xd = NCSSStreamCipher(method: "xchacha20", key: key32)!
        xd.setIV(Data((0..<24).map { UInt8($0) }))
        XCTAssertEqual(xd.process(xe.process(plain)), plain)

        let rc = NCSSStreamCipher(method: "rc4-md5", key: key16)!
        rc.setIV(iv16)
        XCTAssertEqual(rc.process(plain), hex("b6e95814e9aabcde76ae1b934bd8d4481bbc7c34240c579f"))

        XCTAssertNil(NCSSStreamCipher(method: "aes-256-gcm", key: key32))
    }

    func testChecksums() {
        XCTAssertEqual(NCChecksum.crc32(Data("123456789".utf8)), 0xcbf4_3926)
        XCTAssertEqual(NCChecksum.adler32(Data("Wikipedia".utf8)), 0x11e6_0398)
    }

    func testAuthSHA1V4() throws {
        let key = Data((0..<32).map { UInt8($0xa0 + $0) })
        let iv = Data((0..<16).map { UInt8($0x50 + $0) })
        let proto = NCSSRAuthSHA1V4(key: key, iv: iv, auth: (clientID: hex("11223344"), connectionID: 0x010203))
        proto.now = { 1_700_000_000 }
        proto.randomBelow = { _ in 0 } // deterministic: no extra head, randLen 0… see below
        proto.randomBytes = { n in Data(repeating: 0xab, count: n) }
        // randomBelow 0 → getDataLength adds 0, randDataLength returns 0.
        let head = hex("01020304050607") // atyp v4 head, 7 bytes
        var payload = head
        payload.append(Data("PAYLOAD".utf8))
        let wire = proto.encode(payload)
        // Parse the auth pack: [len BE][crc LE][rand prefix][authdata][head piece][hmac 10]
        let packedLen = Int(wire[0]) << 8 | Int(wire[1])
        // randLen 0 → prefix byte 1, packed = 2+4+1+0+12+piece+10
        XCTAssertEqual(packedLen, 2 + 4 + 1 + 0 + 12 + 7 + 10)
        // CRC covers BE len + salt + key.
        var crcInput = Data(wire.prefix(2))
        crcInput.append("auth_sha1_v4".data(using: .utf8)!)
        crcInput.append(key)
        let storedCRC = UInt32(wire[2]) | UInt32(wire[3]) << 8 | UInt32(wire[4]) << 16 | UInt32(wire[5]) << 24
        XCTAssertEqual(NCChecksum.crc32(crcInput), storedCRC)
        // Auth data: time LE, clientID, connID LE at offset 2+4+1 = 7.
        XCTAssertEqual([UInt8](wire[7..<11]), [0x00, 0xf1, 0x53, 0x65]) // 1700000000 LE
        XCTAssertEqual([UInt8](wire[11..<15]), [0x11, 0x22, 0x33, 0x44])
        XCTAssertEqual([UInt8](wire[15..<19]), [0x03, 0x02, 0x01, 0x00])
        // HMAC tail = HMAC-SHA1(iv+key, everything before it)[..10].
        let pack = Data(wire.prefix(packedLen))
        let mac = NCHMACSHA1.mac(key: iv + key, message: Data(pack.prefix(packedLen - 10)))
        XCTAssertEqual(Data(pack.suffix(10)), Data(mac.prefix(10)))

        // The rest of the payload went through packData (auth packs are
        // client→server only; the client decoder only ever sees packData
        // frames, like the reference). Feed the remainder and expect the
        // payload tail back.
        let decoder = NCSSRAuthSHA1V4(key: key, iv: iv, auth: (clientID: hex("11223344"), connectionID: 1))
        let decoded = try decoder.decode(Data(wire.dropFirst(packedLen)))
        XCTAssertEqual(decoded, Data("PAYLOAD".utf8))

        // Second encode (no header) decodes cleanly too.
        let more = proto.encode(Data("second".utf8))
        let decoded2 = try decoder.decode(more)
        XCTAssertEqual(decoded2, Data("second".utf8))
    }

    func testHTTPSimple() {
        let obfs = NCSSRHTTPSimple(server: "example.com", port: 8388, param: nil, ivSize: 16)
        obfs.randomBelow = { _ in 0 }
        let data = Data((0..<100).map { UInt8($0) })
        let out = obfs.encode(data)
        let text = String(decoding: out.prefix(200), as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("GET /"))
        XCTAssertTrue(text.contains(" HTTP/1.1\r\nHost: example.com:8388\r\n"))
        XCTAssertTrue(text.contains("User-Agent: Mozilla/5.0"))
        // Head portion is %xx for ivSize+30 bytes (randomBelow 0 → +0).
        // Everything after the header block is the raw tail.
        let headerEnd = out.range(of: Data([13, 10, 13, 10]))!.upperBound
        XCTAssertEqual(Data(out[headerEnd...]), Data(data.dropFirst(46)))
        // Passthrough after the first write.
        XCTAssertEqual(obfs.encode(Data([1, 2, 3])), Data([1, 2, 3]))
        // Response header strip.
        XCTAssertNil(obfs.decode(Data("HTTP/1.1 200 OK\r\n".utf8)))
        XCTAssertEqual(obfs.decode(Data("Content-Length: 3\r\n\r\nabc".utf8)), Data("abc".utf8))
        XCTAssertEqual(obfs.decode(Data("raw".utf8)), Data("raw".utf8))
    }
}
