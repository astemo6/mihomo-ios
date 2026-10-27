import XCTest
import CryptoKit
@testable import Tern

/// Vectors for the hand-rolled TLS 1.3 key schedule and the REALITY
/// handshake math. Sources: RFC 8448 §3, RFC 5869 test case 1, and vectors
/// generated locally with an independent reference implementation (the same crypto
/// the old core uses) — never from the Swift implementation under test.
final class NativeCoreTLS13Tests: XCTestCase {
    private func unhex(_ s: String) -> Data {
        let clean = s.filter { !$0.isWhitespace }
        var out = Data()
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            out.append(UInt8(clean[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    // MARK: RFC 8448 §3 key schedule (AES-128-GCM-SHA256 suite)

    func testKeyScheduleRFC8448() {
        // Full 32-octet ECDHE shared secret from RFC 8448 §3 (ends 0f 89 49 2d).
        let ecdhe = unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
        let hashCHSH = unhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
        let hashCHFin = unhex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
        let schedule = NCTLS13.Schedule(kind: .sha256, ecdhe: ecdhe,
                                        hashCHtoSH: hashCHSH, hashCHtoServerFinished: hashCHFin)
        XCTAssertEqual(hex(schedule.clientHandshakeSecret),
                       "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        XCTAssertEqual(hex(schedule.serverHandshakeSecret),
                       "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        XCTAssertEqual(hex(schedule.clientAppSecret),
                       "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        XCTAssertEqual(hex(schedule.serverAppSecret),
                       "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    }

    // MARK: RFC 5869 test case 1 (HKDF-SHA256 plumbing)

    func testHKDFRFC5869() {
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = unhex("000102030405060708090a0b0c") // RFC 5869 TC1 salt is 13 bytes
        let info = unhex("f0f1f2f3f4f5f6f7f8f9")
        let prk = NCTLS13.hkdfExtract(.sha256, salt: salt, ikm: ikm)
        XCTAssertEqual(hex(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        let okm = NCTLS13.hkdfExpand(.sha256, prk: prk, info: info, length: 42)
        XCTAssertEqual(hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }

    // MARK: REALITY

    func testRealitySessionIDPlain() {
        let plain = NCTLS13.realitySessionIDPlain(shortID: unhex("1122334455667788"), unixTime: 0x65000000)
        XCTAssertEqual(hex(plain), "01080200" + "65000000" + "1122334455667788")
        XCTAssertEqual(plain.count, 16)
        // Short IDs are zero-padded to 8 bytes.
        let short = NCTLS13.realitySessionIDPlain(shortID: unhex("abcd"), unixTime: 0)
        XCTAssertEqual(hex(short), "01080200" + "00000000" + "abcd000000000000")
    }

    func testRealityAuthKeyVector() {
        // an independent ECDH + HKDF: client private = bytes 0x20...0x3f,
        // server public below, clientRandom = bytes 0x00...0x1f.
        let clientPriv = try! Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x20..<0x40).map { UInt8($0) }))
        let serverPub = unhex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
        let random = Data((0..<32).map { UInt8($0) })
        let authKey = NCTLS13.realityAuthKey(clientPrivate: clientPriv, serverPublic: serverPub, clientRandom: random)
        XCTAssertEqual(authKey.map(hex), "dae4cc47afdbf002878ac2265fcaa119c47ea232dd8d98cb8f09889cf48a53fa")
    }

    func testRealitySealSessionIDVector() {
        // the old core crypto/aes+cipher GCM: key = bytes 0x00...0x1f, nonce = a0...ab,
        // plain = the session-id block, AAD = bytes 0x00...0x3f.
        // NCTLS13 takes the nonce from clientRandom[20..<32], so the random
        // below ends with a0...ab.
        let authKey = Data((0..<32).map { UInt8($0) })
        var random = Data((0..<20).map { UInt8($0) })
        random.append(Data((0xa0...0xab).map { UInt8($0) }))
        let plain = unhex("01080200650000001122334455667788")
        let aad = Data((0..<64).map { UInt8($0) })
        let sealed = NCTLS13.realitySealSessionID(authKey: authKey, plain: plain, clientRandom: random, aad: aad)
        XCTAssertEqual(sealed.map(hex), "e7107e2d20cb02bf7347b497521cb756ecab27648faeea208899825f85781837")
    }

    func testRealitySealSessionIDGoStdlibVector() {
        // Also generated with the old core's standard library (crypto/aes +
        // cipher.NewGCM Seal) in a throwaway program: key = bytes 0x00...0x1f,
        // nonce = bytes 0x00...0x0b, plain = the session-id block above,
        // AAD = bytes 0x00...0x3f. The clientRandom passed to NCTLS13 ends
        // with that nonce because the nonce is taken from its last 12 bytes.
        let authKey = Data((0..<32).map { UInt8($0) })
        var random = Data((0xa0...0xb3).map { UInt8($0) })
        random.append(Data((0..<12).map { UInt8($0) }))
        let plain = unhex("01080200650000001122334455667788")
        let aad = Data((0..<64).map { UInt8($0) })
        let sealed = NCTLS13.realitySealSessionID(authKey: authKey, plain: plain, clientRandom: random, aad: aad)
        XCTAssertEqual(sealed.map(hex), "460ad41ba0e5c21b9c63a4cfe48f0fe5069a30297a4937753420f2f14c282e25")
    }

    // MARK: ClientHello structure (session ID offset, padding, extensions)

    func testClientHelloStructure() {
        let random = Data((0..<32).map { UInt8($0) })
        let uuid: [UInt8] = [0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
                             0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11]
        // Any 32-byte value works as the X25519 public share placeholder.
        let share = Data(uuid + uuid)
        let sid = Data(repeating: 0xaa, count: 32)
        let hello = NCTLS13.buildClientHello(random: random, sessionID: sid,
                                                       serverName: "www.example.com",
                                                       alpn: ["h2", "http/1.1"], keyShare: share)
        XCTAssertEqual(hello[0], 0x01) // client_hello
        // Session ID begins at offset 39: 4 (header) + 2 (version) + 32 (random) + 1 (length).
        XCTAssertEqual(hello[38], 32) // session ID length byte
        XCTAssertEqual(Data(hello[39..<71]), sid)
        XCTAssertGreaterThanOrEqual(hello.count, 512) // Chrome-style padding
        // key_share (51) and supported_versions (43) present as extensions.
        let types = Self.extensionTypes(in: hello)
        XCTAssertNotNil(types)
        XCTAssertTrue(types?.contains(51) ?? false, "missing key_share: \(String(describing: types))")
        XCTAssertTrue(types?.contains(43) ?? false, "missing supported_versions: \(String(describing: types))")
    }

    /// Walk the ClientHello structure and list its extension types, so the
    /// check cannot false-positive on extension bytes inside other fields.
    private static func extensionTypes(in hello: Data) -> [UInt16]? {
        var idx = 4 // handshake header
        idx += 2 // legacy version
        idx += 32 // random
        guard idx < hello.count else { return nil }
        idx += 1 + Int(hello[idx]) // session ID
        guard idx + 2 <= hello.count else { return nil }
        let suitesLen = Int(hello[idx]) << 8 | Int(hello[idx + 1])
        idx += 2 + suitesLen
        guard idx < hello.count else { return nil }
        idx += 1 + Int(hello[idx]) // compression methods
        guard idx + 2 <= hello.count else { return nil }
        let extLen = Int(hello[idx]) << 8 | Int(hello[idx + 1])
        idx += 2
        let extEnd = min(hello.count, idx + extLen)
        var types: [UInt16] = []
        while idx + 4 <= extEnd {
            types.append(UInt16(hello[idx]) << 8 | UInt16(hello[idx + 1]))
            let len = Int(hello[idx + 2]) << 8 | Int(hello[idx + 3])
            idx += 4 + len
        }
        return types
    }
}
