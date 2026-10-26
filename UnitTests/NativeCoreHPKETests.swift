import XCTest
import CryptoKit
@testable import Mihomo

/// RFC 9180 test vectors for HPKE Base Mode (mode_base = 0x00) and RFC 9849 ECHConfigList parsing.
///
/// Sources:
/// - RFC 9180 Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
/// - RFC 9180 Appendix A.2: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
/// - RFC 9180 Appendix A [TestVectors] (test-vectors.json mode 0, kem 32, kdf 1, aead 2):
///   DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
/// - RFC 9849 §4: TLS Encrypted Client Hello configuration format and selection
final class NativeCoreHPKETests: XCTestCase {

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

    // MARK: - RFC 9180 Appendix A.1: AES-128-GCM

    func testRFC9180Suite1_AES128GCM() throws {
        let suite = NCHPKECipherSuite(kem: .dhkemX25519HKDFSHA256, kdf: .hkdfSHA256, aead: .aes128GCM)

        let info = unhex("4f6465206f6e2061204772656369616e2055726e")
        let ikmE = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234")
        let pkEmExpected = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
        let skEmExpected = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"

        let ikmR = unhex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037")
        let pkRmExpected = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
        let skRmExpected = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"

        // 1. DeriveKeyPair verification
        let (skE, pkE) = try NCHPKE.deriveKeyPair(ikm: ikmE)
        XCTAssertEqual(hex(skE.rawRepresentation), skEmExpected)
        XCTAssertEqual(hex(pkE), pkEmExpected)

        let (skR, pkR) = try NCHPKE.deriveKeyPair(ikm: ikmR)
        XCTAssertEqual(hex(skR.rawRepresentation), skRmExpected)
        XCTAssertEqual(hex(pkR), pkRmExpected)

        // 2. Encap & Decap verification
        let expectedEnc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
        let expectedSharedSecret = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"

        let (sharedSecretSender, enc) = try NCHPKE.encap(recipientPublicKey: pkR, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(enc), expectedEnc)
        XCTAssertEqual(hex(sharedSecretSender), expectedSharedSecret)

        let sharedSecretRecipient = try NCHPKE.decap(enc: enc, recipientPrivateKey: skR)
        XCTAssertEqual(hex(sharedSecretRecipient), expectedSharedSecret)

        // 3. Key schedule verification
        let (key, baseNonce, exporterSecret) = NCHPKE.keyScheduleBase(sharedSecret: sharedSecretSender, info: info, suite: suite)
        XCTAssertEqual(hex(key), "4531685d41d65f03dc48f6b8302c05b0")
        XCTAssertEqual(hex(baseNonce), "56d890e5accaaf011cff4b7d")
        XCTAssertEqual(hex(exporterSecret), "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")

        // 4. SetupBaseS & SetupBaseR context operations
        let (encOut, ctxS) = try NCHPKE.setupBaseS(recipientPublicKey: pkR, info: info, suite: suite, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(encOut), expectedEnc)
        let ctxR = try NCHPKE.setupBaseR(enc: encOut, recipientPrivateKey: skR, info: info, suite: suite)

        // Encryption sequence 0
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479")
        let aad0 = unhex("436f756e742d30")
        let expectedNonce0 = "56d890e5accaaf011cff4b7d"
        let expectedCt0 = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 0)), expectedNonce0)
        let ct0 = try ctxS.seal(aad: aad0, plaintext: pt)
        XCTAssertEqual(hex(ct0), expectedCt0)
        let opened0 = try ctxR.open(aad: aad0, ciphertext: ct0)
        XCTAssertEqual(hex(opened0), hex(pt))

        // Encryption sequence 1
        let aad1 = unhex("436f756e742d31")
        let expectedNonce1 = "56d890e5accaaf011cff4b7c"
        let expectedCt1 = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 1)), expectedNonce1)
        let ct1 = try ctxS.seal(aad: aad1, plaintext: pt)
        XCTAssertEqual(hex(ct1), expectedCt1)
        let opened1 = try ctxR.open(aad: aad1, ciphertext: ct1)
        XCTAssertEqual(hex(opened1), hex(pt))

        // Encryption sequence 2
        let aad2 = unhex("436f756e742d32")
        let expectedNonce2 = "56d890e5accaaf011cff4b7f"
        let expectedCt2 = "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 2)), expectedNonce2)
        let ct2 = try ctxS.seal(aad: aad2, plaintext: pt)
        XCTAssertEqual(hex(ct2), expectedCt2)
        let opened2 = try ctxR.open(aad: aad2, ciphertext: ct2)
        XCTAssertEqual(hex(opened2), hex(pt))

        // 5. Secret Export verification
        let exp0 = try ctxS.export(exporterContext: Data(), length: 32)
        XCTAssertEqual(hex(exp0), "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee")

        let exp1 = try ctxS.export(exporterContext: unhex("00"), length: 32)
        XCTAssertEqual(hex(exp1), "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5")

        let exp2 = try ctxS.export(exporterContext: unhex("54657374436f6e74657874"), length: 32)
        XCTAssertEqual(hex(exp2), "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931")

        // 6. Single-shot roundtrip
        let (singleEnc, singleCt) = try NCHPKE.sealBase(recipientPublicKey: pkR, info: info, aad: aad0, plaintext: pt, suite: suite)
        let singlePt = try NCHPKE.openBase(enc: singleEnc, recipientPrivateKey: skR, info: info, aad: aad0, ciphertext: singleCt, suite: suite)
        XCTAssertEqual(hex(singlePt), hex(pt))
    }

    // MARK: - RFC 9180 Appendix A.2: ChaCha20Poly1305

    func testRFC9180Suite2_ChaCha20Poly1305() throws {
        let suite = NCHPKECipherSuite(kem: .dhkemX25519HKDFSHA256, kdf: .hkdfSHA256, aead: .chaCha20Poly1305)

        let info = unhex("4f6465206f6e2061204772656369616e2055726e")
        let ikmE = unhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b")
        let pkEmExpected = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        let skEmExpected = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"

        let ikmR = unhex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df")
        let pkRmExpected = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
        let skRmExpected = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"

        // 1. DeriveKeyPair verification
        let (skE, pkE) = try NCHPKE.deriveKeyPair(ikm: ikmE)
        XCTAssertEqual(hex(skE.rawRepresentation), skEmExpected)
        XCTAssertEqual(hex(pkE), pkEmExpected)

        let (skR, pkR) = try NCHPKE.deriveKeyPair(ikm: ikmR)
        XCTAssertEqual(hex(skR.rawRepresentation), skRmExpected)
        XCTAssertEqual(hex(pkR), pkRmExpected)

        // 2. Encap & Decap verification
        let expectedEnc = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        let expectedSharedSecret = "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"

        let (sharedSecretSender, enc) = try NCHPKE.encap(recipientPublicKey: pkR, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(enc), expectedEnc)
        XCTAssertEqual(hex(sharedSecretSender), expectedSharedSecret)

        let sharedSecretRecipient = try NCHPKE.decap(enc: enc, recipientPrivateKey: skR)
        XCTAssertEqual(hex(sharedSecretRecipient), expectedSharedSecret)

        // 3. Key schedule verification
        let (key, baseNonce, exporterSecret) = NCHPKE.keyScheduleBase(sharedSecret: sharedSecretSender, info: info, suite: suite)
        XCTAssertEqual(hex(key), "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
        XCTAssertEqual(hex(baseNonce), "5c4d98150661b848853b547f")
        XCTAssertEqual(hex(exporterSecret), "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922")

        // 4. SetupBaseS & SetupBaseR context operations
        let (encOut, ctxS) = try NCHPKE.setupBaseS(recipientPublicKey: pkR, info: info, suite: suite, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(encOut), expectedEnc)
        let ctxR = try NCHPKE.setupBaseR(enc: encOut, recipientPrivateKey: skR, info: info, suite: suite)

        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479")

        // Seq 0
        let aad0 = unhex("436f756e742d30")
        let expectedNonce0 = "5c4d98150661b848853b547f"
        let expectedCt0 = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 0)), expectedNonce0)
        let ct0 = try ctxS.seal(aad: aad0, plaintext: pt)
        XCTAssertEqual(hex(ct0), expectedCt0)
        let opened0 = try ctxR.open(aad: aad0, ciphertext: ct0)
        XCTAssertEqual(hex(opened0), hex(pt))

        // Seq 1
        let aad1 = unhex("436f756e742d31")
        let expectedNonce1 = "5c4d98150661b848853b547e"
        let expectedCt1 = "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 1)), expectedNonce1)
        let ct1 = try ctxS.seal(aad: aad1, plaintext: pt)
        XCTAssertEqual(hex(ct1), expectedCt1)
        let opened1 = try ctxR.open(aad: aad1, ciphertext: ct1)
        XCTAssertEqual(hex(opened1), hex(pt))

        // Seq 2
        let aad2 = unhex("436f756e742d32")
        let expectedNonce2 = "5c4d98150661b848853b547d"
        let expectedCt2 = "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 2)), expectedNonce2)
        let ct2 = try ctxS.seal(aad: aad2, plaintext: pt)
        XCTAssertEqual(hex(ct2), expectedCt2)
        let opened2 = try ctxR.open(aad: aad2, ciphertext: ct2)
        XCTAssertEqual(hex(opened2), hex(pt))

        // 5. Secret Export verification
        let exp0 = try ctxS.export(exporterContext: Data(), length: 32)
        XCTAssertEqual(hex(exp0), "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e")

        let exp1 = try ctxS.export(exporterContext: unhex("00"), length: 32)
        XCTAssertEqual(hex(exp1), "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69")

        let exp2 = try ctxS.export(exporterContext: unhex("54657374436f6e74657874"), length: 32)
        XCTAssertEqual(hex(exp2), "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53")
    }

    // MARK: - RFC 9180 TestVectors JSON: AES-256-GCM

    func testRFC9180Suite3_AES256GCM() throws {
        let suite = NCHPKECipherSuite(kem: .dhkemX25519HKDFSHA256, kdf: .hkdfSHA256, aead: .aes256GCM)

        let info = unhex("4f6465206f6e2061204772656369616e2055726e")
        let ikmE = unhex("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9")
        let pkEmExpected = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"
        let skEmExpected = "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11"

        let ikmR = unhex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee")
        let pkRmExpected = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"
        let skRmExpected = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"

        // 1. DeriveKeyPair verification
        let (skE, pkE) = try NCHPKE.deriveKeyPair(ikm: ikmE)
        XCTAssertEqual(hex(skE.rawRepresentation), skEmExpected)
        XCTAssertEqual(hex(pkE), pkEmExpected)

        let (skR, pkR) = try NCHPKE.deriveKeyPair(ikm: ikmR)
        XCTAssertEqual(hex(skR.rawRepresentation), skRmExpected)
        XCTAssertEqual(hex(pkR), pkRmExpected)

        // 2. Encap & Decap verification
        let expectedEnc = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"
        let expectedSharedSecret = "3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b"

        let (sharedSecretSender, enc) = try NCHPKE.encap(recipientPublicKey: pkR, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(enc), expectedEnc)
        XCTAssertEqual(hex(sharedSecretSender), expectedSharedSecret)

        let sharedSecretRecipient = try NCHPKE.decap(enc: enc, recipientPrivateKey: skR)
        XCTAssertEqual(hex(sharedSecretRecipient), expectedSharedSecret)

        // 3. Key schedule verification
        let (key, baseNonce, exporterSecret) = NCHPKE.keyScheduleBase(sharedSecret: sharedSecretSender, info: info, suite: suite)
        XCTAssertEqual(hex(key), "f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f")
        XCTAssertEqual(hex(baseNonce), "151d9929e2449747889bc923")
        XCTAssertEqual(hex(exporterSecret), "86017151bbff6a1940e8abae2ac9e0e7032e33df1eaaecc02ca6259b130d62df")

        // 4. SetupBaseS & SetupBaseR context operations
        let (encOut, ctxS) = try NCHPKE.setupBaseS(recipientPublicKey: pkR, info: info, suite: suite, ephemeralPrivateKey: skE)
        XCTAssertEqual(hex(encOut), expectedEnc)
        let ctxR = try NCHPKE.setupBaseR(enc: encOut, recipientPrivateKey: skR, info: info, suite: suite)

        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479")

        // Seq 0
        let aad0 = unhex("436f756e742d30")
        let expectedNonce0 = "151d9929e2449747889bc923"
        let expectedCt0 = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 0)), expectedNonce0)
        let ct0 = try ctxS.seal(aad: aad0, plaintext: pt)
        XCTAssertEqual(hex(ct0), expectedCt0)
        let opened0 = try ctxR.open(aad: aad0, ciphertext: ct0)
        XCTAssertEqual(hex(opened0), hex(pt))

        // Seq 1
        let aad1 = unhex("436f756e742d31")
        let expectedNonce1 = "151d9929e2449747889bc922"
        let expectedCt1 = "2c43aff25343fdbff864506f0818b9d87df84ea01b1a2144d23b4d40c26bf655fdf197fe40297a8aebeed5cc2d"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 1)), expectedNonce1)
        let ct1 = try ctxS.seal(aad: aad1, plaintext: pt)
        XCTAssertEqual(hex(ct1), expectedCt1)
        let opened1 = try ctxR.open(aad: aad1, ciphertext: ct1)
        XCTAssertEqual(hex(opened1), hex(pt))

        // Seq 2
        let aad2 = unhex("436f756e742d32")
        let expectedNonce2 = "151d9929e2449747889bc921"
        let expectedCt2 = "e0a8f2cf92ff61215edbb8c55dc31fe9e2eb42a5685867bb6854211542099f9e940c4b41c192bc390835b1a5f7"

        XCTAssertEqual(hex(NCHPKE.computeNonce(baseNonce: ctxS.baseNonce, seq: 2)), expectedNonce2)
        let ct2 = try ctxS.seal(aad: aad2, plaintext: pt)
        XCTAssertEqual(hex(ct2), expectedCt2)
        let opened2 = try ctxR.open(aad: aad2, ciphertext: ct2)
        XCTAssertEqual(hex(opened2), hex(pt))

        // 5. Secret Export verification
        let exp0 = try ctxS.export(exporterContext: Data(), length: 32)
        XCTAssertEqual(hex(exp0), "ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a")

        let exp1 = try ctxS.export(exporterContext: unhex("00"), length: 32)
        XCTAssertEqual(hex(exp1), "04d3cb6cc116b28ffd22ad5bc276c60d31fec71ceb87ae24db811c64b7507339")

        let exp2 = try ctxS.export(exporterContext: unhex("54657374436f6e74657874"), length: 32)
        XCTAssertEqual(hex(exp2), "7c5ded445732c14fe09727d29b4251c0fd38455fe8440571e687f0886aac94d2")
    }

    // MARK: - RFC 9849: ECHConfigList Parsing & Selection

    func testECHConfigListRealWorldCloudflare() throws {
        // Real-world DNS HTTPS record from crypto.cloudflare.com
        // Base64: AEX+DQBB8gAgACAmHmjNt+cJR9Tod0NjXHKl0OFMSHzbsAk9JSpK3fdmQQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=
        let echListBytes = unhex("0045fe0d0041f200200020261e68cdb7e70947d4e87743635c72a5d0e14c487cdbb0093d252a4addf766410004000100010012636c6f7564666c6172652d6563682e636f6d0000")

        let configs = try NCECHConfigParser.parseList(echListBytes)
        XCTAssertEqual(configs.count, 1)

        let cfg = configs[0]
        XCTAssertEqual(cfg.version, 0xfe0d)
        XCTAssertEqual(cfg.length, 65)
        XCTAssertEqual(cfg.configID, 242)
        XCTAssertEqual(cfg.kemID, 0x0020)
        XCTAssertEqual(hex(cfg.publicKey), "261e68cdb7e70947d4e87743635c72a5d0e14c487cdbb0093d252a4addf76641")
        XCTAssertEqual(cfg.cipherSuites.count, 1)
        XCTAssertEqual(cfg.cipherSuites[0].kdfID, 0x0001)
        XCTAssertEqual(cfg.cipherSuites[0].aeadID, 0x0001)
        XCTAssertEqual(cfg.maximumNameLength, 0)
        XCTAssertEqual(cfg.publicName, "cloudflare-ech.com")
        XCTAssertEqual(cfg.extensions.count, 0)

        // Test selection
        let selected = try NCECHConfigParser.selectSupported(from: configs)
        XCTAssertEqual(selected.config.configID, 242)
        XCTAssertEqual(selected.hpkeSuite.aead, .aes128GCM)
        XCTAssertEqual(selected.hpkeSuite.kem, .dhkemX25519HKDFSHA256)
        XCTAssertEqual(selected.hpkeSuite.kdf, .hkdfSHA256)

        // Test HPKE context creation with selected ECH config
        let (enc, ctxS) = try selected.setupSender()
        XCTAssertEqual(enc.count, 32)
        let ct = try ctxS.seal(plaintext: Data("GET / HTTP/1.1\r\n\r\n".utf8))
        XCTAssertGreaterThan(ct.count, 16)
    }

    func testECHConfigListMultiEntryFallback() throws {
        // Build an ECHConfigList with 2 entries:
        // Entry 1: unsupported version 0xfe0c (or unsupported KEM 0x0010 P-256)
        // Entry 2: supported version 0xfe0d, kem 0x0020, ChaCha20Poly1305 (aead 0x0003)

        // Entry 1: version=0xfe0c, length=10, 10 bytes dummy
        var entry1 = Data()
        entry1.append(contentsOf: [0xfe, 0x0c]) // unsupported version
        entry1.append(contentsOf: [0x00, 0x0a]) // length 10
        entry1.append(contentsOf: [UInt8](repeating: 0xaa, count: 10))

        // Entry 2: valid ECHConfig with ChaCha20Poly1305
        let pk = unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
        var contents2 = Data()
        contents2.append(0x42) // config_id
        contents2.append(contentsOf: [0x00, 0x20]) // kem_id = X25519
        contents2.append(contentsOf: [0x00, 0x20]) // pk_len = 32
        contents2.append(pk)
        contents2.append(contentsOf: [0x00, 0x04]) // cs_len = 4
        contents2.append(contentsOf: [0x00, 0x01, 0x00, 0x03]) // kdf=0x0001, aead=0x0003 (ChaChaPoly)
        contents2.append(0x00) // max_name_len
        contents2.append(0x0a) // name_len = 10
        contents2.append(contentsOf: "server.com".utf8)
        contents2.append(contentsOf: [0x00, 0x00]) // ext_len = 0

        var entry2 = Data()
        entry2.append(contentsOf: [0xfe, 0x0d])
        let len2 = contents2.count
        entry2.append(UInt8((len2 >> 8) & 0xff))
        entry2.append(UInt8(len2 & 0xff))
        entry2.append(contents2)

        var listData = Data()
        let totalPayloadLen = entry1.count + entry2.count
        listData.append(UInt8((totalPayloadLen >> 8) & 0xff))
        listData.append(UInt8(totalPayloadLen & 0xff))
        listData.append(entry1)
        listData.append(entry2)

        let selected = try NCECHConfigParser.select(fromECHConfigList: listData)
        XCTAssertEqual(selected.config.configID, 0x42)
        XCTAssertEqual(selected.config.publicName, "server.com")
        XCTAssertEqual(selected.hpkeSuite.aead, .chaCha20Poly1305)
    }

    func testECHConfigMalformedErrors() {
        // Truncated list
        XCTAssertThrowsError(try NCECHConfigParser.parseList(Data([0x00]))) { err in
            guard case NCECHConfigError.truncatedData = err else {
                XCTFail("Expected truncatedData but got \(err)")
                return
            }
        }

        // Invalid cipher suite length (odd number of bytes)
        var badConfig = Data()
        badConfig.append(contentsOf: [0xfe, 0x0d])
        let badContents = Data([
            0x01, // config_id
            0x00, 0x20, // kem_id
            0x00, 0x04, 0x01, 0x02, 0x03, 0x04, // pk_len=4
            0x00, 0x03, 0x01, 0x02, 0x03, // cs_len=3 (not multiple of 4!)
        ])
        badConfig.append(UInt8((badContents.count >> 8) & 0xff))
        badConfig.append(UInt8(badContents.count & 0xff))
        badConfig.append(badContents)

        var badList = Data()
        badList.append(UInt8((badConfig.count >> 8) & 0xff))
        badList.append(UInt8(badConfig.count & 0xff))
        badList.append(badConfig)

        XCTAssertThrowsError(try NCECHConfigParser.parseList(badList)) { err in
            guard case NCECHConfigError.invalidCipherSuiteLength = err else {
                XCTFail("Expected invalidCipherSuiteLength but got \(err)")
                return
            }
        }
    }

    // MARK: - RFC 9849: Mandatory Extension Handling & Data Slice Parsing

    private func buildTestECHConfig(
        configID: UInt8,
        aeadID: UInt16,
        publicName: String = "test.example",
        extensions: [(type: UInt16, data: Data)] = []
    ) -> Data {
        let pk = Data(repeating: 0x22, count: 32)
        var contents = Data()
        contents.append(configID) // config_id
        contents.append(contentsOf: [0x00, 0x20]) // kem_id = X25519
        contents.append(contentsOf: [0x00, 0x20]) // pk_len = 32
        contents.append(pk)
        contents.append(contentsOf: [0x00, 0x04]) // cs_len = 4
        contents.append(contentsOf: [0x00, 0x01, UInt8((aeadID >> 8) & 0xff), UInt8(aeadID & 0xff)]) // kdf=0x0001, aead
        contents.append(0x00) // max_name_len
        let nameBytes = Array(publicName.utf8)
        contents.append(UInt8(nameBytes.count))
        contents.append(contentsOf: nameBytes)

        var extPayload = Data()
        for ext in extensions {
            extPayload.append(UInt8((ext.type >> 8) & 0xff))
            extPayload.append(UInt8(ext.type & 0xff))
            extPayload.append(UInt8((ext.data.count >> 8) & 0xff))
            extPayload.append(UInt8(ext.data.count & 0xff))
            extPayload.append(ext.data)
        }
        contents.append(UInt8((extPayload.count >> 8) & 0xff))
        contents.append(UInt8(extPayload.count & 0xff))
        contents.append(extPayload)

        var config = Data()
        config.append(contentsOf: [0xfe, 0x0d]) // version
        let len = contents.count
        config.append(UInt8((len >> 8) & 0xff))
        config.append(UInt8(len & 0xff))
        config.append(contents)
        return config
    }

    private func buildTestECHList(configs: [Data]) -> Data {
        let totalLen = configs.reduce(0) { $0 + $1.count }
        var list = Data()
        list.append(UInt8((totalLen >> 8) & 0xff))
        list.append(UInt8(totalLen & 0xff))
        for c in configs {
            list.append(c)
        }
        return list
    }

    func testECHConfigMandatoryExtensionHandling() throws {
        // Config 1: High-bit set mandatory extension (0x8001), unsupported -> must be skipped
        let c1 = buildTestECHConfig(
            configID: 10,
            aeadID: 0x0001, // AES-128-GCM
            publicName: "server1.com",
            extensions: [(type: 0x8001, data: Data([0x01, 0x02]))]
        )

        // Config 2: Mandatory extension (0x0020) requiring unsupported type 0x1234 -> must be skipped
        let c2 = buildTestECHConfig(
            configID: 20,
            aeadID: 0x0002, // AES-256-GCM
            publicName: "server2.com",
            extensions: [(type: 0x0020, data: Data([0x00, 0x02, 0x12, 0x34]))]
        )

        // Config 3: Optional extension 0x0005 (high bit 0) + valid AEAD ChaChaPoly -> must be selected
        let c3 = buildTestECHConfig(
            configID: 30,
            aeadID: 0x0003, // ChaCha20Poly1305
            publicName: "server3.com",
            extensions: [(type: 0x0005, data: Data([0xde, 0xad]))]
        )

        // Config 4: Mandatory extension 0x0020 requiring only supported type 0x0020 -> supported
        let c4 = buildTestECHConfig(
            configID: 40,
            aeadID: 0x0001, // AES-128-GCM
            publicName: "server4.com",
            extensions: [(type: 0x0020, data: Data([0x00, 0x02, 0x00, 0x20]))]
        )

        let listData = buildTestECHList(configs: [c1, c2, c3])
        let parsedConfigs = try NCECHConfigParser.parseList(listData)
        XCTAssertEqual(parsedConfigs.count, 3)

        // Verify individual configs
        XCTAssertTrue(parsedConfigs[0].hasUnsupportedMandatoryExtension)
        XCTAssertTrue(parsedConfigs[1].hasUnsupportedMandatoryExtension)
        XCTAssertFalse(parsedConfigs[2].hasUnsupportedMandatoryExtension)

        // Selection should skip config 1 & 2, and select config 3
        let selected = try NCECHConfigParser.selectSupported(from: parsedConfigs)
        XCTAssertEqual(selected.config.configID, 30)
        XCTAssertEqual(selected.config.publicName, "server3.com")
        XCTAssertEqual(selected.hpkeSuite.aead, .chaCha20Poly1305)

        // Also verify selection directly from ECHConfigList bytes
        let selectedFromList = try NCECHConfigParser.select(fromECHConfigList: listData)
        XCTAssertEqual(selectedFromList.config.configID, 30)

        // Verify list where all configs are unsupported
        let allUnsupportedData = buildTestECHList(configs: [c1, c2])
        let unsupportedConfigs = try NCECHConfigParser.parseList(allUnsupportedData)
        XCTAssertEqual(unsupportedConfigs.count, 2)
        XCTAssertThrowsError(try NCECHConfigParser.selectSupported(from: unsupportedConfigs)) { err in
            guard case NCECHConfigError.noSupportedConfig = err else {
                XCTFail("Expected noSupportedConfig error but got \(err)")
                return
            }
        }
        XCTAssertNil(try? NCECHConfigParser.selectSupported(from: unsupportedConfigs))
        XCTAssertNil(NCECHConfigParser.selectOptional(from: unsupportedConfigs))
        XCTAssertNil(try? NCECHConfigParser.select(fromECHConfigList: allUnsupportedData))
        XCTAssertNil(NCECHConfigParser.selectOptional(fromECHConfigList: allUnsupportedData))

        // Verify config with supported mandatory extension (c4) is selected over skipped (c1)
        let listWithSupportedMandatory = buildTestECHList(configs: [c1, c4])
        let selectedC4 = try NCECHConfigParser.select(fromECHConfigList: listWithSupportedMandatory)
        XCTAssertEqual(selectedC4.config.configID, 40)
        XCTAssertEqual(selectedC4.config.publicName, "server4.com")
    }

    func testECHConfigListParsingFromDataSlice() throws {
        // Real-world DNS HTTPS record from crypto.cloudflare.com
        let echListBytes = unhex("0045fe0d0041f200200020261e68cdb7e70947d4e87743635c72a5d0e14c487cdbb0093d252a4addf766410004000100010012636c6f7564666c6172652d6563682e636f6d0000")

        // Parse directly as baseline
        let directConfigs = try NCECHConfigParser.parseList(echListBytes)
        XCTAssertEqual(directConfigs.count, 1)
        let directSelected = try NCECHConfigParser.select(fromECHConfigList: echListBytes)

        // Wrap echListBytes inside a larger buffer with non-zero start offset
        let prefix = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05])
        let suffix = Data([0xCA, 0xFE, 0xBA, 0xBE, 0x99])
        let fullBuffer = prefix + echListBytes + suffix

        // 1. Slice using subdata(in:)
        let subdataSlice = fullBuffer.subdata(in: prefix.count..<(prefix.count + echListBytes.count))
        let subdataConfigs = try NCECHConfigParser.parseList(subdataSlice)
        XCTAssertEqual(subdataConfigs, directConfigs)

        // 2. Slice using SubSequence (data[range]) with guaranteed startIndex != 0
        let subseqSlice = fullBuffer[prefix.count..<(prefix.count + echListBytes.count)]
        XCTAssertEqual(subseqSlice.startIndex, prefix.count)
        XCTAssertGreaterThan(subseqSlice.startIndex, 0)

        // Verify parseList handles non-zero startIndex slice without crash or misaligned offsets
        let subseqConfigs = try NCECHConfigParser.parseList(subseqSlice)
        XCTAssertEqual(subseqConfigs, directConfigs)

        // Verify select(fromECHConfigList:) handles slice
        let selectedFromSlice = try NCECHConfigParser.select(fromECHConfigList: subseqSlice)
        XCTAssertEqual(selectedFromSlice.config, directSelected.config)
        XCTAssertEqual(selectedFromSlice.cipherSuite, directSelected.cipherSuite)
        XCTAssertEqual(selectedFromSlice.hpkeSuite, directSelected.hpkeSuite)

        // 3. Raw ECHConfig slice (omitting the 2-byte outer list length) with non-zero startIndex
        let rawConfigBytes = directConfigs[0].rawBytes
        let rawBuffer = prefix + rawConfigBytes + suffix
        let rawSlice = rawBuffer[prefix.count..<(prefix.count + rawConfigBytes.count)]
        XCTAssertEqual(rawSlice.startIndex, prefix.count)

        let parsedRawSlice = try NCECHConfigParser.parseList(rawSlice)
        XCTAssertEqual(parsedRawSlice.count, 1)
        XCTAssertEqual(parsedRawSlice[0], directConfigs[0])
    }
}
