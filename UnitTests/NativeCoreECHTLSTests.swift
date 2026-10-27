import XCTest
import CryptoKit
@testable import Tern

/// Offline unit tests for RFC 9849 TLS Encrypted Client Hello (ECH) and RFC 8446 HelloRetryRequest.
/// Covers:
/// - ECH padding length rules (RFC 9849 §6.1.3: SNI present vs absent, and 32-byte multiple alignment).
/// - ServerHello accept_confirmation derivation (RFC 9849 §7.2: fixed HKDF test vectors).
/// - EncryptedExtensions retry_configs parsing (RFC 9849 §5 & RFC 8446 §4.3.1).
/// - HelloRetryRequest accept_confirmation verification (RFC 9849 §7.2.1: positive and negative cases).
/// - ClientHello2 derivation from ClientHello1 (RFC 8446 §4.1.4, §4.4.1 & RFC 9849 §6.1.5).
final class NativeCoreECHTLSTests: XCTestCase {

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

    private func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - 1. ECH Padding Length Rules (RFC 9849 §6.1.3)

    func testECHPaddingLengthRules() {
        let dummyInnerRandom = Data(repeating: 0xaa, count: 32)
        let dummySessionID = Data(repeating: 0x00, count: 32)
        let dummyShare = Data(repeating: 0x55, count: 32)

        // Branch 1a: SNI present and len(SNI) < maximumNameLength (e.g. 15 < 32)
        let sniShort = "foo.example.com" // 15 bytes
        let innerHelloShort = NCTLS13.buildClientHelloInner(
            random: dummyInnerRandom,
            sessionID: dummySessionID,
            serverName: sniShort,
            alpn: ["h2", "http/1.1"],
            keyShare: dummyShare
        )
        let maxLenShort: UInt8 = 32
        let encodedShort = NCTLS13.encodeInnerClientHello(
            innerHello: innerHelloShort,
            serverName: sniShort,
            maximumNameLength: maxLenShort
        )
        // §6.1.3: EncodedClientHelloInner MUST be a multiple of 32 bytes
        XCTAssertEqual(encodedShort.count % 32, 0, "Encoded inner hello must be aligned to 32 bytes")

        // Validate formula: padSNI = max(0, 32 - 15) = 17
        let expectedPadSNIShort = max(0, Int(maxLenShort) - sniShort.utf8.count)
        XCTAssertEqual(expectedPadSNIShort, 17)

        // Compute unpadded length (inner hello minus 4-byte header and session_id stripped to 0)
        let unpaddedInnerLenShort = innerHelloShort.count - 4 - dummySessionID.count
        let lShort = unpaddedInnerLenShort + expectedPadSNIShort
        let nShort = lShort > 0 ? (31 - ((lShort - 1) % 32)) : 0
        let totalPadShort = expectedPadSNIShort + nShort
        XCTAssertEqual(encodedShort.count, unpaddedInnerLenShort + totalPadShort)

        // Verify trailing bytes are all zeros
        let trailingZerosShort = encodedShort.suffix(totalPadShort)
        XCTAssertEqual(trailingZerosShort, Data(repeating: 0x00, count: totalPadShort))

        // Branch 1b: SNI present and len(SNI) >= maximumNameLength (e.g. 48 >= 32)
        let sniLong = "verylonghostnameexceedingmaximumlength.example.com" // 50 bytes
        let innerHelloLong = NCTLS13.buildClientHelloInner(
            random: dummyInnerRandom,
            sessionID: dummySessionID,
            serverName: sniLong,
            alpn: ["h2"],
            keyShare: dummyShare
        )
        let maxLenLong: UInt8 = 32
        let encodedLong = NCTLS13.encodeInnerClientHello(
            innerHello: innerHelloLong,
            serverName: sniLong,
            maximumNameLength: maxLenLong
        )
        XCTAssertEqual(encodedLong.count % 32, 0, "Encoded inner hello must be aligned to 32 bytes")

        let expectedPadSNILong = max(0, Int(maxLenLong) - sniLong.utf8.count)
        XCTAssertEqual(expectedPadSNILong, 0)
        let unpaddedInnerLenLong = innerHelloLong.count - 4 - dummySessionID.count
        let lLong = unpaddedInnerLenLong + expectedPadSNILong
        let nLong = lLong > 0 ? (31 - ((lLong - 1) % 32)) : 0
        let totalPadLong = expectedPadSNILong + nLong
        XCTAssertEqual(encodedLong.count, unpaddedInnerLenLong + totalPadLong)
        XCTAssertEqual(encodedLong.suffix(totalPadLong), Data(repeating: 0x00, count: totalPadLong))

        // Branch 2: SNI is absent (empty string) -> padSNI = maximumNameLength + 9
        let innerHelloEmpty = NCTLS13.buildClientHelloInner(
            random: dummyInnerRandom,
            sessionID: dummySessionID,
            serverName: "",
            alpn: ["h2"],
            keyShare: dummyShare
        )
        let maxLenEmpty: UInt8 = 32
        let encodedEmpty = NCTLS13.encodeInnerClientHello(
            innerHello: innerHelloEmpty,
            serverName: "",
            maximumNameLength: maxLenEmpty
        )
        XCTAssertEqual(encodedEmpty.count % 32, 0, "Encoded inner hello must be aligned to 32 bytes")

        let expectedPadSNIEmpty = Int(maxLenEmpty) + 9 // 41 bytes
        XCTAssertEqual(expectedPadSNIEmpty, 41)
        let unpaddedInnerLenEmpty = innerHelloEmpty.count - 4 - dummySessionID.count
        let lEmpty = unpaddedInnerLenEmpty + expectedPadSNIEmpty
        let nEmpty = lEmpty > 0 ? (31 - ((lEmpty - 1) % 32)) : 0
        let totalPadEmpty = expectedPadSNIEmpty + nEmpty
        XCTAssertEqual(encodedEmpty.count, unpaddedInnerLenEmpty + totalPadEmpty)
        XCTAssertEqual(encodedEmpty.suffix(totalPadEmpty), Data(repeating: 0x00, count: totalPadEmpty))

        // Comprehensive boundary sweep: test multiple maximumNameLength values across various ALPNs
        for maxLen in [UInt8(0), UInt8(16), UInt8(32), UInt8(64), UInt8(128)] {
            for sni in ["", "a.org", "sub.domain.example.net", "really.deep.hierarchy.of.subdomains.example.com"] {
                let hello = NCTLS13.buildClientHelloInner(
                    random: dummyInnerRandom,
                    sessionID: dummySessionID,
                    serverName: sni,
                    alpn: ["h2", "http/1.1"],
                    keyShare: dummyShare
                )
                let enc = NCTLS13.encodeInnerClientHello(innerHello: hello, serverName: sni, maximumNameLength: maxLen)
                XCTAssertEqual(enc.count % 32, 0, "Failed 32-byte alignment for maxLen=\(maxLen), sni=\(sni)")
            }
        }
    }

    // MARK: - 2. ServerHello accept_confirmation Derivation (RFC 9849 §7.2)

    func testAcceptConfirmationDerivation() {
        // Deterministic fixed inputs:
        let innerRandom = unhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        let innerTranscript = unhex(String(repeating: "aa", count: 64))

        // ServerHello wire format:
        // Header: 02 00 00 28 (Handshake type 2, length 40)
        // legacy_version: 03 03
        // random: 24 bytes prefix + 8 bytes candidate accept_confirmation
        // legacy_session_id: 00 (empty)
        // cipher_suite: 13 01 (TLS_AES_128_GCM_SHA256)
        // compression_method: 00
        let shPrefix = unhex("020000280303")
        let shRandomPrefix = unhex(String(repeating: "11", count: 24))
        let shRandomSuffix = unhex(String(repeating: "ff", count: 8)) // bytes 30..<38 in ServerHello
        let shRest = unhex("0000130100")
        let serverHello = shPrefix + shRandomPrefix + shRandomSuffix + shRest

        // Step-by-step HKDF validation:
        // RFC 9849 §7.2: last 8 bytes of ServerHello.random replaced with 8 zeros
        let expectedConfirmationHex = "7ea0f853afd48142"

        guard let conf = NCTLS13.computeAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            serverHello: serverHello,
            innerRandom: innerRandom
        ) else {
            XCTFail("computeAcceptConfirmation returned nil")
            return
        }
        XCTAssertEqual(hex(conf), expectedConfirmationHex)

        // RFC 9849 §7.2 invariance test:
        // Any value in the last 8 bytes of ServerHello.random MUST produce the exact same confirmation,
        // because those 8 bytes are zeroed out before computing the transcript hash.
        let serverHelloWithZeros = shPrefix + shRandomPrefix + Data(repeating: 0x00, count: 8) + shRest
        let confFromZeros = NCTLS13.computeAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            serverHello: serverHelloWithZeros,
            innerRandom: innerRandom
        )
        XCTAssertEqual(confFromZeros, conf, "Zeroed suffix must yield identical confirmation")

        let serverHelloWithArbitrary = shPrefix + shRandomPrefix + unhex("4255778899aabbcc") + shRest
        let confFromArbitrary = NCTLS13.computeAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            serverHello: serverHelloWithArbitrary,
            innerRandom: innerRandom
        )
        XCTAssertEqual(confFromArbitrary, conf, "Arbitrary suffix must yield identical confirmation")

        // Changing any byte in the first 24 bytes of random MUST change the confirmation
        let corruptedRandomPrefix = unhex(String(repeating: "22", count: 24))
        let corruptedSH = shPrefix + corruptedRandomPrefix + shRandomSuffix + shRest
        let corruptedConf = NCTLS13.computeAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            serverHello: corruptedSH,
            innerRandom: innerRandom
        )
        XCTAssertNotEqual(corruptedConf, conf, "Corrupted random prefix must alter confirmation")

        // Truncated ServerHello (< 38 bytes) returns nil
        let truncatedSH = serverHello.prefix(37)
        XCTAssertNil(NCTLS13.computeAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            serverHello: truncatedSH,
            innerRandom: innerRandom
        ))
    }

    // MARK: - 3. EncryptedExtensions retry_configs Parsing (RFC 8446 §4.3.1 & RFC 9849 §5)

    func testEncryptedExtensionsRetryConfigsParsing() throws {
        // Real-world DNS HTTPS record from crypto.cloudflare.com
        let echListBytes = unhex("0045fe0d0041f200200020261e68cdb7e70947d4e87743635c72a5d0e14c487cdbb0093d252a4addf766410004000100010012636c6f7564666c6172652d6563682e636f6d0000")

        // Positive case: EncryptedExtensions with ALPN (type 16) + ECH retry_configs (type 0xfe0d)
        var extsPayload = Data()
        // ALPN extension: type 16, len 5, protocols: [0x02, "h2"]
        extsPayload.appendBE16(16)
        extsPayload.appendBE16(5)
        extsPayload.appendBE16(3) // alpn list length
        extsPayload.append(0x02) // "h2" len
        extsPayload.append(Data("h2".utf8))

        // ECH retry_configs extension: type 0xfe0d, length echListBytes.count, payload echListBytes
        extsPayload.appendBE16(NCTLS13.extensionECH)
        extsPayload.appendBE16(UInt16(echListBytes.count))
        extsPayload.append(echListBytes)

        var encExtsMessage = Data()
        encExtsMessage.append(0x08) // Handshake type: EncryptedExtensions (8)
        let bodyLen = extsPayload.count + 2
        encExtsMessage.append(UInt8((bodyLen >> 16) & 0xff))
        encExtsMessage.append(UInt8((bodyLen >> 8) & 0xff))
        encExtsMessage.append(UInt8(bodyLen & 0xff))
        encExtsMessage.appendBE16(UInt16(extsPayload.count))
        encExtsMessage.append(extsPayload)

        // Parse retry_configs
        guard let parsedRetryConfigs = NCTLS13.parseRetryConfigs(fromEncryptedExtensions: encExtsMessage) else {
            XCTFail("parseRetryConfigs returned nil for valid EncryptedExtensions")
            return
        }
        XCTAssertEqual(parsedRetryConfigs, echListBytes)

        // Verify that the parsed retry_configs can be successfully decoded into an ECHConfig
        let configs = try NCECHConfigParser.parseList(parsedRetryConfigs)
        XCTAssertEqual(configs.count, 1)
        XCTAssertEqual(configs[0].configID, 242)
        XCTAssertEqual(configs[0].publicName, "cloudflare-ech.com")

        // Negative case 1: EncryptedExtensions containing ALPN only (no ECH)
        var alpnOnlyExts = Data()
        alpnOnlyExts.appendBE16(16)
        alpnOnlyExts.appendBE16(5)
        alpnOnlyExts.appendBE16(3)
        alpnOnlyExts.append(0x02)
        alpnOnlyExts.append(Data("h2".utf8))

        var alpnOnlyMsg = Data([0x08, 0x00, 0x00, UInt8(alpnOnlyExts.count + 2)])
        alpnOnlyMsg.appendBE16(UInt16(alpnOnlyExts.count))
        alpnOnlyMsg.append(alpnOnlyExts)

        XCTAssertNil(NCTLS13.parseRetryConfigs(fromEncryptedExtensions: alpnOnlyMsg),
                     "Should return nil when ECH extension is absent")

        // Negative case 2: Truncated message
        let truncatedMsg = encExtsMessage.prefix(encExtsMessage.count - 10)
        XCTAssertNil(NCTLS13.parseRetryConfigs(fromEncryptedExtensions: truncatedMsg),
                     "Should return nil for truncated EncryptedExtensions")

        // Negative case 3: Wrong handshake type (e.g. 2 for ServerHello instead of 8)
        var wrongTypeMsg = encExtsMessage
        wrongTypeMsg[0] = 0x02
        XCTAssertNil(NCTLS13.parseRetryConfigs(fromEncryptedExtensions: wrongTypeMsg),
                     "Should return nil when handshake type is not EncryptedExtensions (8)")

        // Negative case 4: Empty data
        XCTAssertNil(NCTLS13.parseRetryConfigs(fromEncryptedExtensions: Data()))
    }

    // MARK: - 4. HRR accept_confirmation Verification (RFC 9849 §7.2.1)

    func testHRRAcceptConfirmationVerification() {
        let innerRandom = unhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        let innerTranscript = unhex(String(repeating: "bb", count: 64))

        // Fixed HRR message with 8-byte confirmation: "2027150f32eef9b4"
        let hrrHeader = unhex("0200003c0303")
        let hrrRandom = NCTLS13.helloRetryRequestRandom
        let hrrMid = unhex("001301000012") // sidLen(0), cipher(1301), comp(00), extsLen(18)
        let extVersion = unhex("002b00020304") // supported_versions: 0x0304
        let expectedConf = unhex("2027150f32eef9b4")
        let extECH = unhex("fe0d0008") + expectedConf
        let hrrMessage = hrrHeader + hrrRandom + hrrMid + extVersion + extECH

        // Positive test: compute confirmation against HRR containing the expected payload
        guard let computedConf = NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: hrrMessage,
            hrrECHPayload: expectedConf,
            innerRandom: innerRandom
        ) else {
            XCTFail("computeHRRAcceptConfirmation returned nil")
            return
        }
        XCTAssertEqual(computedConf, expectedConf, "Positive test: computed HRR confirmation must match payload")

        // Negative test 1: Mismatched confirmation payload in HRR (1 bit flipped)
        var corruptedPayload = expectedConf
        corruptedPayload[7] ^= 0x01
        let corruptedECH = unhex("fe0d0008") + corruptedPayload
        let corruptedHRR = hrrHeader + hrrRandom + hrrMid + extVersion + corruptedECH
        let computedForCorrupted = NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: corruptedHRR,
            hrrECHPayload: corruptedPayload,
            innerRandom: innerRandom
        )
        // The computation zeroes the payload location and recomputes the expected value ("2027150f32eef9b4"),
        // which must NOT match the corrupted payload ("2027150f32eef9b5").
        XCTAssertNotEqual(computedForCorrupted, corruptedPayload, "Negative test: corrupted payload must not match")

        // Negative test 2: Invalid HRR ECH payload length (e.g. 7 or 9 bytes != 8)
        let shortPayload = expectedConf.prefix(7)
        XCTAssertNil(NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: hrrMessage,
            hrrECHPayload: shortPayload,
            innerRandom: innerRandom
        ), "Payload length != 8 must return nil")

        let longPayload = expectedConf + Data([0x00])
        XCTAssertNil(NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: hrrMessage,
            hrrECHPayload: longPayload,
            innerRandom: innerRandom
        ), "Payload length != 8 must return nil")

        // Negative test 3: HRR without ECH extension
        let hrrNoECH = hrrHeader + hrrRandom + unhex("001301000006") + extVersion
        XCTAssertNil(NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: hrrNoECH,
            hrrECHPayload: expectedConf,
            innerRandom: innerRandom
        ), "HRR without ECH extension must return nil")

        // Negative test 4: Changed innerRandom yields different confirmation
        let alteredRandom = unhex("9902030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        let alteredConf = NCTLS13.computeHRRAcceptConfirmation(
            kind: .sha256,
            innerTranscript: innerTranscript,
            hrrMessage: hrrMessage,
            hrrECHPayload: expectedConf,
            innerRandom: alteredRandom
        )
        XCTAssertNotEqual(alteredConf, expectedConf, "Altered innerRandom must not match original confirmation")
    }

    // MARK: - 5. ClientHello2 Derivation from ClientHello1 (RFC 8446 §4.1.4 & RFC 9849 §6.1.5)

    func testClientHello2DerivationFromClientHello1() throws {
        let echListBytes = unhex("0045fe0d0041f200200020261e68cdb7e70947d4e87743635c72a5d0e14c487cdbb0093d252a4addf766410004000100010012636c6f7564666c6172652d6563682e636f6d0000")
        let selected = try NCECHConfigParser.select(fromECHConfigList: echListBytes)
        let (enc, ctx) = try selected.setupSender()

        let priv1 = Curve25519.KeyAgreement.PrivateKey()
        let share1 = Data(priv1.publicKey.rawRepresentation)
        let innerRandom1 = Data(repeating: 0x42, count: 32)
        let outerRandom1 = Data(repeating: 0x84, count: 32)
        let sessionID1 = Data(repeating: 0x00, count: 32)

        // Build CH1
        let inner1 = NCTLS13.buildClientHelloInner(
            random: innerRandom1,
            sessionID: sessionID1,
            serverName: "inner.target.com",
            alpn: ["h2"],
            keyShare: share1
        )
        let encodedInner1 = NCTLS13.encodeInnerClientHello(
            innerHello: inner1,
            serverName: "inner.target.com",
            maximumNameLength: selected.config.maximumNameLength
        )
        let outer1 = try NCTLS13.buildClientHelloOuter(
            outerRandom: outerRandom1,
            sessionID: sessionID1,
            publicName: selected.config.publicName,
            alpn: ["h2"],
            keyShare: share1,
            selectedConfig: selected,
            enc: enc,
            hpkeContext: ctx,
            encodedInner: encodedInner1
        )

        // Parse CH1 prefixes
        guard let parsedInner1 = NCTLS13.parseClientHello(inner1),
              let parsedOuter1 = NCTLS13.parseClientHello(outer1) else {
            XCTFail("Failed to parse CH1")
            return
        }

        // Derive CHInner2 with cookie from HRR
        let cookieData = unhex("c0011e445566778899")
        let priv2 = Curve25519.KeyAgreement.PrivateKey()
        let share2 = Data(priv2.publicKey.rawRepresentation)

        guard let inner2 = NCTLS13.deriveClientHelloInner2(from: inner1, cookie: cookieData, keyShare: share2),
              let parsedInner2 = NCTLS13.parseClientHello(inner2) else {
            XCTFail("Failed to derive or parse inner2")
            return
        }

        // §4.1.4: random, sessionID, cipherSuites in inner2 MUST be identical to inner1
        XCTAssertEqual(parsedInner2.prefix, parsedInner1.prefix,
                       "Inner prefix (random, session_id, suites, compression) must be byte-exact to inner1")
        // Verify cookie extension is added
        let parsedCookieInner = parsedInner2.extensions.first(where: { $0.type == NCTLS13.extensionCookie })
        XCTAssertNotNil(parsedCookieInner)
        XCTAssertEqual(parsedCookieInner?.data, cookieData)
        // Verify key_share updated
        let parsedKeyShareInner = parsedInner2.extensions.first(where: { $0.type == 51 })
        XCTAssertNotNil(parsedKeyShareInner)
        XCTAssertTrue(parsedKeyShareInner!.data.contains(share2))

        // Derive CHOuter2 with cookie and empty enc
        let encodedInner2 = NCTLS13.encodeInnerClientHello(
            innerHello: inner2,
            serverName: "inner.target.com",
            maximumNameLength: selected.config.maximumNameLength
        )
        let outer2 = try NCTLS13.deriveClientHelloOuter2(
            from: outer1,
            cookie: cookieData,
            keyShare: share2,
            selectedConfig: selected,
            hpkeContext: ctx,
            encodedInner2: encodedInner2
        )
        guard let parsedOuter2 = NCTLS13.parseClientHello(outer2) else {
            XCTFail("Failed to parse outer2")
            return
        }

        // §4.1.4: random, sessionID, cipherSuites in outer2 MUST be identical to outer1
        XCTAssertEqual(parsedOuter2.prefix, parsedOuter1.prefix,
                       "Outer prefix (random, session_id, suites, compression) must be byte-exact to outer1")
        // Verify cookie extension added to outer2
        let parsedCookieOuter = parsedOuter2.extensions.first(where: { $0.type == NCTLS13.extensionCookie })
        XCTAssertEqual(parsedCookieOuter?.data, cookieData)
        // Verify key_share updated in outer2
        let parsedKeyShareOuter = parsedOuter2.extensions.first(where: { $0.type == 51 })
        XCTAssertTrue(parsedKeyShareOuter!.data.contains(share2))

        // RFC 9849 §6.1.5: ECH extension in outer2 MUST have enc length = 0
        guard let echOuter2Ext = parsedOuter2.extensions.first(where: { $0.type == NCTLS13.extensionECH }) else {
            XCTFail("Outer2 missing ECH extension")
            return
        }
        let echData = echOuter2Ext.data
        // Layout: type(1: 0x00) + kdf(2) + aead(2) + config_id(1) + enc_len(2)
        XCTAssertGreaterThanOrEqual(echData.count, 8)
        let encLen = Int(echData[6]) << 8 | Int(echData[7])
        XCTAssertEqual(encLen, 0, "RFC 9849 §6.1.5: enc in ClientHelloOuter2 MUST have length 0 on HRR")
    }
}
