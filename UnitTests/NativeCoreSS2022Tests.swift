import XCTest
import CryptoKit
@testable import Mihomo

/// SS2022 (SIP022): session-key vectors generated with
/// sing-shadowsocks2's own SessionKey (the library mihomo ships);
/// HChaCha20 against the published XChaCha draft vector; headers and
/// packets validated by independent CryptoKit operations in the test.
final class NativeCoreSS2022Tests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func data(_ hex: String) -> Data {
        var out = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    private let psk32 = Data((0..<32).map { UInt8($0) })
    private var password32: String { psk32.base64EncodedString() }

    func testSessionKeyVectors() {
        // Ground truth from sing-shadowsocks2 shadowaead_2022.SessionKey
        // (re-verified 2026-10-24 against the module source + a clean Go
        // run; an earlier generation of this vector was wrong).
        let salt32 = Data((0..<32).map { UInt8(0x20 + $0) })
        XCTAssertEqual(hex(NCSS2022.sessionKey(psk: psk32, salt: salt32, keyLen: 32)),
                       "374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda")
        let salt16 = Data((0..<16).map { UInt8(0x20 + $0) })
        XCTAssertEqual(hex(NCSS2022.sessionKey(psk: Data(psk32.prefix(16)), salt: salt16, keyLen: 16)),
                       "8180421f8f56092ca7544a64ff852536")
    }

    func testPSKParsing() {
        XCTAssertEqual(NCSS2022.psk(from: password32, keyLen: 32), psk32)
        XCTAssertNil(NCSS2022.psk(from: password32, keyLen: 16))
        XCTAssertNil(NCSS2022.psk(from: "not-base64!!!", keyLen: 32))
        XCTAssertNil(NCSS2022.spec(for: "2022-blake3-chacha8-poly1305"))
        XCTAssertNotNil(NCSS2022.spec(for: "2022-blake3-aes-128-gcm"))
    }

    func testHChaCha20Vector() {
        let key = data("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = data("000000090000004a0000000031415927")
        // Byte 18 is 0xe4 (x/crypto HChaCha20 cross-checked 2026-10-25;
        // an earlier transcription of the draft vector had 0xa4).
        XCTAssertEqual(hex(NCChaCha.hchacha20(key: key, nonce: nonce)),
                       "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    func testTCPRequestHeadLayout() throws {
        let salt = Data((0..<32).map { UInt8(0x20 + $0) })
        let enc = try XCTUnwrap(NCSS2022Encoder(method: "2022-blake3-aes-256-gcm",
                                                password: password32, salt: salt, paddingLen: 7))
        let head = try XCTUnwrap(enc.requestHead(target: NCTarget(host: "example.com", port: 443),
                                                 timestamp: 1735689600))
        XCTAssertEqual(Data(head.prefix(32)), salt)
        // Open the fixed + variable headers by hand with the vector-anchored key.
        let key = SymmetricKey(data: NCSS2022.sessionKey(psk: psk32, salt: salt, keyLen: 32))
        var nonce = [UInt8](repeating: 0, count: 12)
        func open(_ sealed: Data) throws -> Data {
            defer { NCShadowsocks.incrementNonce(&nonce) }
            var combined = Data(nonce)
            combined.append(sealed)
            return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key)
        }
        let fixedLen = 1 + 8 + 2
        let fixed = try open(Data(head[32..<(32 + fixedLen + 16)]))
        XCTAssertEqual(fixed[0], 0x00)
        var ts: UInt64 = 0
        for i in 0..<8 { ts = ts << 8 | UInt64(fixed[1 + i]) }
        XCTAssertEqual(ts, 1735689600)
        let varLen = Int(fixed[9]) << 8 | Int(fixed[10])
        let variable = try open(Data(head[(32 + fixedLen + 16)...]))
        XCTAssertEqual(variable.count, varLen)
        XCTAssertEqual(variable[0], 0x03) // domain atyp
        XCTAssertEqual(variable[1], 11)
        XCTAssertEqual(String(decoding: variable[2..<13], as: UTF8.self), "example.com")
        XCTAssertEqual(Int(variable[13]) << 8 | Int(variable[14]), 443)
        XCTAssertEqual(Int(variable[15]) << 8 | Int(variable[16]), 7) // padding length
    }

    func testTCPResponseDecodeAndChunks() throws {
        let requestSalt = Data((0..<32).map { UInt8(0xa0 + $0) })
        let responseSalt = Data((0..<32).map { UInt8(0x40 + $0) })
        let dec = try XCTUnwrap(NCSS2022Decoder(method: "2022-blake3-aes-256-gcm",
                                                password: password32, requestSalt: requestSalt))
        // Build the server's bytes with an independent stream crypto.
        let key = NCSS2022.sessionKey(psk: psk32, salt: responseSalt, keyLen: 32)
        let server = NCSS2022StreamCrypto(sessionKey: key, isAES: true)
        var fixed = Data()
        fixed.append(0x01)
        fixed.appendBE64(1735689600)
        fixed.append(requestSalt)
        let payload = Data("hello-2022".utf8)
        fixed.appendBE16(UInt16(payload.count))
        var wire = responseSalt
        wire.append(try XCTUnwrap(server.seal(fixed)))
        wire.append(try XCTUnwrap(server.seal(payload)))
        // A stream chunk after the header: sealed len + sealed body.
        let chunk = Data("chunk-two".utf8)
        var lenBytes = Data(count: 2)
        lenBytes[0] = UInt8(chunk.count >> 8); lenBytes[1] = UInt8(chunk.count & 0xff)
        wire.append(try XCTUnwrap(server.seal(lenBytes)))
        wire.append(try XCTUnwrap(server.seal(chunk)))

        // Feed in awkward slices: header validation must hold back output.
        var got: [Data] = []
        for slice in [wire.prefix(10), wire.dropFirst(10).prefix(40), wire.dropFirst(50)] {
            let pieces = try XCTUnwrap(dec.feed(Data(slice)))
            got.append(contentsOf: pieces)
        }
        XCTAssertEqual(got, [payload, chunk])
        XCTAssertTrue(dec.headerDone)
    }

    func testTCPResponseRejectsWrongRequestSalt() throws {
        let dec = try XCTUnwrap(NCSS2022Decoder(method: "2022-blake3-aes-256-gcm",
                                                password: password32,
                                                requestSalt: Data(count: 32)))
        let responseSalt = Data((0..<32).map { UInt8(0x40 + $0) })
        let key = NCSS2022.sessionKey(psk: psk32, salt: responseSalt, keyLen: 32)
        let server = NCSS2022StreamCrypto(sessionKey: key, isAES: true)
        var fixed = Data()
        fixed.append(0x01)
        fixed.appendBE64(1735689600)
        fixed.append(Data((0..<32).map { _ in UInt8(0x99) })) // not our salt
        fixed.appendBE16(0)
        var wire = responseSalt
        wire.append(try XCTUnwrap(server.seal(fixed)))
        XCTAssertNil(dec.feed(wire))
    }

    func testUDPAESPacketLayout() throws {
        let crypto = try XCTUnwrap(NCSS2022UDPCrypto(method: "2022-blake3-aes-256-gcm",
                                                     password: password32, sessionID: 0x0102030405060708))
        let wire = try XCTUnwrap(crypto.encodePacket(target: NCTarget(host: "8.8.8.8", port: 53),
                                                     payload: Data("dns".utf8), timestamp: 1735689600))
        // Header: ECB-decrypt with the PSK and compare session/packet IDs.
        let block = try XCTUnwrap(NCAES(key: psk32))
        let header = block.decryptBlock(Data(wire.prefix(16)))
        XCTAssertEqual([UInt8](header.prefix(8)), [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual([UInt8](header.suffix(8)), [0, 0, 0, 0, 0, 0, 0, 0]) // first packetID = 0
        // AEAD body with the session key, nonce = header[4..<16].
        let sessionKey = NCSS2022.sessionKey(psk: psk32, salt: Data(header.prefix(8)), keyLen: 32)
        var combined = Data(header[4..<16])
        combined.append(Data(wire.dropFirst(16)))
        let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: combined),
                                     using: SymmetricKey(data: sessionKey))
        XCTAssertEqual(plain[0], 0x00)
        XCTAssertEqual(Int(plain[9]) << 8 | Int(plain[10]), 0) // padding
        XCTAssertEqual(plain[11], 0x01) // atyp v4
        XCTAssertEqual(Data(plain.suffix(3)), Data("dns".utf8))
    }

    func testUDPAESServerPacketDecode() throws {
        let crypto = try XCTUnwrap(NCSS2022UDPCrypto(method: "2022-blake3-aes-256-gcm",
                                                     password: password32, sessionID: 7))
        // Craft a server packet with remote session id 99.
        var header = Data(count: 16)
        header[7] = 99
        header[15] = 3 // packet id 3
        let sessionKey = NCSS2022.sessionKey(psk: psk32, salt: Data(header.prefix(8)), keyLen: 32)
        var body = Data()
        body.append(0x01)
        body.appendBE64(1735689600)
        body.appendBE16(0)
        body.append(NCTarget(host: "1.1.1.1", port: 53).atypEncoded)
        body.append(Data("reply".utf8))
        let nonce = try AES.GCM.Nonce(data: Data(header[4..<16]))
        let box = try AES.GCM.seal(body, using: SymmetricKey(data: sessionKey), nonce: nonce)
        let block = try XCTUnwrap(NCAES(key: psk32))
        var wire = block.encryptBlock(header)
        wire.append(Data(box.combined!.dropFirst(12)))
        let decoded = try XCTUnwrap(crypto.decodePacket(wire))
        XCTAssertEqual(decoded.0, NCTarget(host: "1.1.1.1", port: 53))
        XCTAssertEqual(decoded.1, Data("reply".utf8))
    }

    func testUDPChaChaRoundTripLayout() throws {
        let crypto = try XCTUnwrap(NCSS2022UDPCrypto(method: "2022-blake3-chacha20-poly1305",
                                                     password: password32, sessionID: 5))
        let wire = try XCTUnwrap(crypto.encodePacket(target: NCTarget(host: "example.com", port: 853),
                                                     payload: Data("x".utf8), timestamp: 1735689600))
        let plain = try XCTUnwrap(NCChaCha.xchachaOpen(key: psk32, nonce24: Data(wire.prefix(24)),
                                                       sealed: Data(wire.dropFirst(24))))
        XCTAssertEqual(plain[7], 5) // session id low byte
        XCTAssertEqual(plain[16], 0x00) // client header type
        XCTAssertEqual(plain[27], 0x03) // atyp domain after ts(8)+padlen(2)=offset 16+1+8+2
    }
}
