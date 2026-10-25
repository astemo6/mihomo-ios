import CryptoKit
import Foundation

// MARK: - NaCl Box Suite (Curve25519 + XSalsa20 + Poly1305)
//
// Pure Swift implementation of Daniel J. Bernstein's NaCl crypto_box and crypto_secretbox
// specifications, used by Tailscale for DERP ClientInfo/ServerInfo handshakes and disco messages.
//
// Test Vector References:
// 1. HSalsa20: libsodium `crypto_core_hsalsa20` test vectors and RFC-draft-strombergson-hsalsa20
// 2. Salsa20/20: RFC 4506 / Bernstein Salsa20 specification test vectors
// 3. Poly1305: RFC 7539 / RFC 8439 Section 2.5.2 official test vectors
// 4. crypto_secretbox (XSalsa20-Poly1305): libsodium `tests/default/secretbox.c` test vector
//    - key: 0xdc908dda0b9344a95362d884aae5b76109c16b75a170a00a8462664f60a0db3c
//    - nonce: 0x69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37
//    - tag: 0x93e52c67f728f3147100f7659913cb86
// 5. Curve25519 low-order point refusal: RFC 7748 and wireguard/libsodium all-zero output check.

enum NCNaClBox {

    // MARK: - Constants ("expand 32-byte k")

    private static let sigma: [UInt32] = [
        0x6170_7865, // "expa"
        0x3320_646e, // "nd 3"
        0x7962_2d32, // "2-by"
        0x6b20_6574, // "te k"
    ]

    // MARK: - 1. HSalsa20

    /// HSalsa20 core: takes a 32-byte key and 16-byte input, outputs a 32-byte subkey.
    /// Does not add initial state to final state (unlike Salsa20).
    struct HSalsa20 {
        static func hash(key: [UInt8], input: [UInt8]) -> [UInt8]? {
            guard key.count == 32, input.count == 16 else { return nil }

            var kw = [UInt32](repeating: 0, count: 8)
            for i in 0..<8 {
                kw[i] = UInt32(key[i * 4]) |
                    (UInt32(key[i * 4 + 1]) << 8) |
                    (UInt32(key[i * 4 + 2]) << 16) |
                    (UInt32(key[i * 4 + 3]) << 24)
            }

            var inw = [UInt32](repeating: 0, count: 4)
            for i in 0..<4 {
                inw[i] = UInt32(input[i * 4]) |
                    (UInt32(input[i * 4 + 1]) << 8) |
                    (UInt32(input[i * 4 + 2]) << 16) |
                    (UInt32(input[i * 4 + 3]) << 24)
            }

            var x: [UInt32] = [
                NCNaClBox.sigma[0], kw[0], kw[1], kw[2],
                kw[3], NCNaClBox.sigma[1], inw[0], inw[1],
                inw[2], inw[3], NCNaClBox.sigma[2], kw[4],
                kw[5], kw[6], kw[7], NCNaClBox.sigma[3],
            ]

            NCNaClBox.salsa20Rounds(&x)

            let outWords: [UInt32] = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]]
            var out = [UInt8](repeating: 0, count: 32)
            for i in 0..<8 {
                let w = outWords[i]
                out[i * 4] = UInt8(w & 0xff)
                out[i * 4 + 1] = UInt8((w >> 8) & 0xff)
                out[i * 4 + 2] = UInt8((w >> 16) & 0xff)
                out[i * 4 + 3] = UInt8((w >> 24) & 0xff)
            }
            return out
        }
    }

    // MARK: - 2. Salsa20 (20 rounds)

    struct Salsa20 {
        /// Generates a single 64-byte block for a 32-byte key, 8-byte nonce, and 64-bit counter.
        static func block(key: [UInt8], nonce8: [UInt8], counter: UInt64) -> [UInt8]? {
            guard key.count == 32, nonce8.count == 8 else { return nil }

            var kw = [UInt32](repeating: 0, count: 8)
            for i in 0..<8 {
                kw[i] = UInt32(key[i * 4]) |
                    (UInt32(key[i * 4 + 1]) << 8) |
                    (UInt32(key[i * 4 + 2]) << 16) |
                    (UInt32(key[i * 4 + 3]) << 24)
            }

            let n0 = UInt32(nonce8[0]) | (UInt32(nonce8[1]) << 8) | (UInt32(nonce8[2]) << 16) | (UInt32(nonce8[3]) << 24)
            let n1 = UInt32(nonce8[4]) | (UInt32(nonce8[5]) << 8) | (UInt32(nonce8[6]) << 16) | (UInt32(nonce8[7]) << 24)
            let c0 = UInt32(truncatingIfNeeded: counter)
            let c1 = UInt32(truncatingIfNeeded: counter >> 32)

            let initial: [UInt32] = [
                NCNaClBox.sigma[0], kw[0], kw[1], kw[2],
                kw[3], NCNaClBox.sigma[1], n0, n1,
                c0, c1, NCNaClBox.sigma[2], kw[4],
                kw[5], kw[6], kw[7], NCNaClBox.sigma[3],
            ]

            var x = initial
            NCNaClBox.salsa20Rounds(&x)

            var out = [UInt8](repeating: 0, count: 64)
            for i in 0..<16 {
                let sum = x[i] &+ initial[i]
                out[i * 4] = UInt8(sum & 0xff)
                out[i * 4 + 1] = UInt8((sum >> 8) & 0xff)
                out[i * 4 + 2] = UInt8((sum >> 16) & 0xff)
                out[i * 4 + 3] = UInt8((sum >> 24) & 0xff)
            }
            return out
        }

        /// XOR-encrypts/decrypts `message` using Salsa20 starting at `counter`.
        static func xor(message: [UInt8], key: [UInt8], nonce8: [UInt8], counter: UInt64 = 0) -> [UInt8]? {
            guard key.count == 32, nonce8.count == 8 else { return nil }
            if message.isEmpty { return [] }

            var out = [UInt8](repeating: 0, count: message.count)
            var currentCounter = counter
            var offset = 0

            while offset < message.count {
                guard let blk = block(key: key, nonce8: nonce8, counter: currentCounter) else { return nil }
                let chunk = min(64, message.count - offset)
                for i in 0..<chunk {
                    out[offset + i] = message[offset + i] ^ blk[i]
                }
                offset += chunk
                currentCounter &+= 1
            }
            return out
        }
    }

    // MARK: - 3. XSalsa20

    struct XSalsa20 {
        /// XOR-encrypts/decrypts `message` with a 32-byte key and 24-byte nonce.
        static func xor(message: [UInt8], key: [UInt8], nonce24: [UInt8]) -> [UInt8]? {
            guard key.count == 32, nonce24.count == 24 else { return nil }
            guard let subkey = HSalsa20.hash(key: key, input: Array(nonce24.prefix(16))) else { return nil }
            let subnonce = Array(nonce24.suffix(8))
            return Salsa20.xor(message: message, key: subkey, nonce8: subnonce, counter: 0)
        }
    }

    // MARK: - 4. Poly1305 MAC

    /// Pure Swift constant-time Poly1305 one-time authenticator (Bernstein 2005 / RFC 7539 / RFC 8439).
    /// Uses 5 limbs of 26-bit radix to avoid 64-bit integer overflow during multiplication.
    struct Poly1305 {
        static func mac(message: [UInt8], key32: [UInt8]) -> [UInt8]? {
            guard key32.count == 32 else { return nil }

            var rBytes = Array(key32.prefix(16))
            rBytes[3] &= 15
            rBytes[7] &= 15
            rBytes[11] &= 15
            rBytes[15] &= 15
            rBytes[4] &= 252
            rBytes[8] &= 252
            rBytes[12] &= 252

            let rVal = UInt64(rBytes[0]) |
                (UInt64(rBytes[1]) << 8) |
                (UInt64(rBytes[2]) << 16) |
                (UInt64(rBytes[3]) << 24) |
                (UInt64(rBytes[4]) << 32) |
                (UInt64(rBytes[5]) << 40) |
                (UInt64(rBytes[6]) << 48) |
                (UInt64(rBytes[7]) << 56)
            let rValHi = UInt64(rBytes[8]) |
                (UInt64(rBytes[9]) << 8) |
                (UInt64(rBytes[10]) << 16) |
                (UInt64(rBytes[11]) << 24) |
                (UInt64(rBytes[12]) << 32) |
                (UInt64(rBytes[13]) << 40) |
                (UInt64(rBytes[14]) << 48) |
                (UInt64(rBytes[15]) << 56)

            let r0 = rVal & 0x03ff_ffff
            let r1 = (rVal >> 26) & 0x03ff_ffff
            let r2 = ((rVal >> 52) | (rValHi << 12)) & 0x03ff_ffff
            let r3 = (rValHi >> 14) & 0x03ff_ffff
            let r4 = (rValHi >> 40) & 0x03ff_ffff

            let s1 = r1 &* 5
            let s2 = r2 &* 5
            let s3 = r3 &* 5
            let s4 = r4 &* 5

            var h0: UInt64 = 0
            var h1: UInt64 = 0
            var h2: UInt64 = 0
            var h3: UInt64 = 0
            var h4: UInt64 = 0

            var offset = 0
            while offset < message.count {
                let chunkLen = min(16, message.count - offset)
                var mBuf = [UInt8](repeating: 0, count: 17)
                for i in 0..<chunkLen {
                    mBuf[i] = message[offset + i]
                }
                mBuf[chunkLen] = 0x01

                let mValLo = UInt64(mBuf[0]) |
                    (UInt64(mBuf[1]) << 8) |
                    (UInt64(mBuf[2]) << 16) |
                    (UInt64(mBuf[3]) << 24) |
                    (UInt64(mBuf[4]) << 32) |
                    (UInt64(mBuf[5]) << 40) |
                    (UInt64(mBuf[6]) << 48) |
                    (UInt64(mBuf[7]) << 56)
                let mValHi = UInt64(mBuf[8]) |
                    (UInt64(mBuf[9]) << 8) |
                    (UInt64(mBuf[10]) << 16) |
                    (UInt64(mBuf[11]) << 24) |
                    (UInt64(mBuf[12]) << 32) |
                    (UInt64(mBuf[13]) << 40) |
                    (UInt64(mBuf[14]) << 48) |
                    (UInt64(mBuf[15]) << 56)
                let mValTop = UInt64(mBuf[16])

                h0 &+= mValLo & 0x03ff_ffff
                h1 &+= (mValLo >> 26) & 0x03ff_ffff
                h2 &+= ((mValLo >> 52) | (mValHi << 12)) & 0x03ff_ffff
                h3 &+= (mValHi >> 14) & 0x03ff_ffff
                h4 &+= ((mValHi >> 40) | (mValTop << 24)) & 0x03ff_ffff

                let d0 = h0 &* r0 &+ h1 &* s4 &+ h2 &* s3 &+ h3 &* s2 &+ h4 &* s1
                var d1 = h0 &* r1 &+ h1 &* r0 &+ h2 &* s4 &+ h3 &* s3 &+ h4 &* s2
                var d2 = h0 &* r2 &+ h1 &* r1 &+ h2 &* r0 &+ h3 &* s4 &+ h4 &* s3
                var d3 = h0 &* r3 &+ h1 &* r2 &+ h2 &* r1 &+ h3 &* r0 &+ h4 &* s4
                var d4 = h0 &* r4 &+ h1 &* r3 &+ h2 &* r2 &+ h3 &* r1 &+ h4 &* r0

                var c = d0 >> 26
                h0 = d0 & 0x03ff_ffff
                d1 &+= c
                c = d1 >> 26
                h1 = d1 & 0x03ff_ffff
                d2 &+= c
                c = d2 >> 26
                h2 = d2 & 0x03ff_ffff
                d3 &+= c
                c = d3 >> 26
                h3 = d3 & 0x03ff_ffff
                d4 &+= c
                c = d4 >> 26
                h4 = d4 & 0x03ff_ffff
                h0 &+= c &* 5
                c = h0 >> 26
                h0 &= 0x03ff_ffff
                h1 &+= c

                offset += chunkLen
            }

            var c = h1 >> 26
            h1 &= 0x03ff_ffff
            h2 &+= c
            c = h2 >> 26
            h2 &= 0x03ff_ffff
            h3 &+= c
            c = h3 >> 26
            h3 &= 0x03ff_ffff
            h4 &+= c
            c = h4 >> 26
            h4 &= 0x03ff_ffff
            h0 &+= c &* 5
            c = h0 >> 26
            h0 &= 0x03ff_ffff
            h1 &+= c

            // Compute h - (2^130 - 5)
            var g0 = h0 &+ 5
            c = g0 >> 26
            g0 &= 0x03ff_ffff
            var g1 = h1 &+ c
            c = g1 >> 26
            g1 &= 0x03ff_ffff
            var g2 = h2 &+ c
            c = g2 >> 26
            g2 &= 0x03ff_ffff
            var g3 = h3 &+ c
            c = g3 >> 26
            g3 &= 0x03ff_ffff
            let g4 = Int64(bitPattern: h4 &+ c) - (1 << 26)

            let mask = UInt64(bitPattern: g4 >> 63)
            let notMask = ~mask

            let f0 = (h0 & mask) | (g0 & notMask)
            let f1 = (h1 & mask) | (g1 & notMask)
            let f2 = (h2 & mask) | (g2 & notMask)
            let f3 = (h3 & mask) | (g3 & notMask)
            let f4 = (h4 & mask) | (UInt64(bitPattern: g4) & notMask)

            let w0 = f0 | (f1 << 26) | ((f2 & 0x0fff) << 52)
            let w1 = (f2 >> 12) | (f3 << 14) | (f4 << 40)

            let s0 = UInt64(key32[16]) |
                (UInt64(key32[17]) << 8) |
                (UInt64(key32[18]) << 16) |
                (UInt64(key32[19]) << 24) |
                (UInt64(key32[20]) << 32) |
                (UInt64(key32[21]) << 40) |
                (UInt64(key32[22]) << 48) |
                (UInt64(key32[23]) << 56)
            let s1 = UInt64(key32[24]) |
                (UInt64(key32[25]) << 8) |
                (UInt64(key32[26]) << 16) |
                (UInt64(key32[27]) << 24) |
                (UInt64(key32[28]) << 32) |
                (UInt64(key32[29]) << 40) |
                (UInt64(key32[30]) << 48) |
                (UInt64(key32[31]) << 56)

            let (out0, carry0) = w0.addingReportingOverflow(s0)
            let out1 = w1 &+ s1 &+ (carry0 ? 1 : 0)

            var out = [UInt8](repeating: 0, count: 16)
            for i in 0..<8 {
                out[i] = UInt8((out0 >> (i * 8)) & 0xff)
                out[8 + i] = UInt8((out1 >> (i * 8)) & 0xff)
            }
            return out
        }

        /// Constant-time tag verification to resist timing side-channels.
        static func verify(tag: [UInt8], message: [UInt8], key32: [UInt8]) -> Bool {
            guard tag.count == 16, let computed = mac(message: message, key32: key32) else { return false }
            var diff: UInt8 = 0
            for i in 0..<16 {
                diff |= tag[i] ^ computed[i]
            }
            return diff == 0
        }
    }

    // MARK: - 5. SecretBox (XSalsa20-Poly1305)

    /// Symmetric authenticated encryption matching NaCl `crypto_secretbox_easy`.
    /// Output layout: 16-byte Poly1305 tag followed by ciphertext.
    struct SecretBox {
        static func seal(message: [UInt8], nonce24: [UInt8], key32: [UInt8]) -> [UInt8]? {
            guard key32.count == 32, nonce24.count == 24 else { return nil }
            guard let subkey = HSalsa20.hash(key: key32, input: Array(nonce24.prefix(16))) else { return nil }
            let subnonce = Array(nonce24.suffix(8))

            // Block 0: first 32 bytes for Poly1305 key; remaining 32 bytes for message encryption
            guard let block0 = Salsa20.block(key: subkey, nonce8: subnonce, counter: 0) else { return nil }
            let polyKey = Array(block0.prefix(32))

            var ciphertext = [UInt8](repeating: 0, count: message.count)
            let firstChunk = min(32, message.count)
            for i in 0..<firstChunk {
                ciphertext[i] = message[i] ^ block0[32 + i]
            }

            if message.count > 32 {
                let rest = Array(message[32...])
                guard let restEnc = Salsa20.xor(message: rest, key: subkey, nonce8: subnonce, counter: 1) else {
                    return nil
                }
                for i in 0..<restEnc.count {
                    ciphertext[32 + i] = restEnc[i]
                }
            }

            guard let tag = Poly1305.mac(message: ciphertext, key32: polyKey) else { return nil }
            return tag + ciphertext
        }

        static func open(box: [UInt8], nonce24: [UInt8], key32: [UInt8]) -> [UInt8]? {
            guard box.count >= 16, key32.count == 32, nonce24.count == 24 else { return nil }
            guard let subkey = HSalsa20.hash(key: key32, input: Array(nonce24.prefix(16))) else { return nil }
            let subnonce = Array(nonce24.suffix(8))

            guard let block0 = Salsa20.block(key: subkey, nonce8: subnonce, counter: 0) else { return nil }
            let polyKey = Array(block0.prefix(32))

            let tag = Array(box.prefix(16))
            let ciphertext = Array(box[16...])

            guard Poly1305.verify(tag: tag, message: ciphertext, key32: polyKey) else {
                return nil
            }

            var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
            let firstChunk = min(32, ciphertext.count)
            for i in 0..<firstChunk {
                plaintext[i] = ciphertext[i] ^ block0[32 + i]
            }

            if ciphertext.count > 32 {
                let rest = Array(ciphertext[32...])
                guard let restDec = Salsa20.xor(message: rest, key: subkey, nonce8: subnonce, counter: 1) else {
                    return nil
                }
                for i in 0..<restDec.count {
                    plaintext[32 + i] = restDec[i]
                }
            }
            return plaintext
        }
    }

    // MARK: - 6. Box (Curve25519 + XSalsa20-Poly1305)

    /// Public-key authenticated encryption matching NaCl `crypto_box_easy`.
    struct Box {
        /// Computes the shared symmetric key (crypto_box_beforenm) using Curve25519 DH + HSalsa20.
        /// Refuses all-zero ECDH output to protect against low-order point attacks.
        static func beforeNM(
            recipientPublicKey: [UInt8],
            senderPrivateKey: Curve25519.KeyAgreement.PrivateKey
        ) -> [UInt8]? {
            guard recipientPublicKey.count == 32 else { return nil }
            guard let peerKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey),
                  let sharedSecret = try? senderPrivateKey.sharedSecretFromKeyAgreement(with: peerKey) else {
                return nil
            }

            let secretBytes = sharedSecret.withUnsafeBytes { [UInt8]($0) }
            // Low-order point check: refuse all-zero shared secret
            if secretBytes.allSatisfy({ $0 == 0 }) {
                return nil
            }

            let zero16 = [UInt8](repeating: 0, count: 16)
            return HSalsa20.hash(key: secretBytes, input: zero16)
        }

        static func seal(
            message: [UInt8],
            nonce24: [UInt8],
            recipientPublicKey: [UInt8],
            senderPrivateKey: Curve25519.KeyAgreement.PrivateKey
        ) -> [UInt8]? {
            guard let sharedKey = beforeNM(recipientPublicKey: recipientPublicKey, senderPrivateKey: senderPrivateKey) else {
                return nil
            }
            return SecretBox.seal(message: message, nonce24: nonce24, key32: sharedKey)
        }

        static func open(
            box: [UInt8],
            nonce24: [UInt8],
            senderPublicKey: [UInt8],
            recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey
        ) -> [UInt8]? {
            guard let sharedKey = beforeNM(recipientPublicKey: senderPublicKey, senderPrivateKey: recipientPrivateKey) else {
                return nil
            }
            return SecretBox.open(box: box, nonce24: nonce24, key32: sharedKey)
        }

        static func sealAfterNM(message: [UInt8], nonce24: [UInt8], sharedKey32: [UInt8]) -> [UInt8]? {
            SecretBox.seal(message: message, nonce24: nonce24, key32: sharedKey32)
        }

        static func openAfterNM(box: [UInt8], nonce24: [UInt8], sharedKey32: [UInt8]) -> [UInt8]? {
            SecretBox.open(box: box, nonce24: nonce24, key32: sharedKey32)
        }
    }

    // MARK: - Internal Salsa20 Quarter-Round Core

    @inline(__always)
    private static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x << n) | (x >> (32 - n))
    }

    private static func salsa20Rounds(_ x: inout [UInt32]) {
        for _ in 0..<10 {
            // Column round
            x[4] ^= rotl(x[0] &+ x[12], 7)
            x[8] ^= rotl(x[4] &+ x[0], 9)
            x[12] ^= rotl(x[8] &+ x[4], 13)
            x[0] ^= rotl(x[12] &+ x[8], 18)

            x[9] ^= rotl(x[5] &+ x[1], 7)
            x[13] ^= rotl(x[9] &+ x[5], 9)
            x[1] ^= rotl(x[13] &+ x[9], 13)
            x[5] ^= rotl(x[1] &+ x[13], 18)

            x[14] ^= rotl(x[10] &+ x[6], 7)
            x[2] ^= rotl(x[14] &+ x[10], 9)
            x[6] ^= rotl(x[2] &+ x[14], 13)
            x[10] ^= rotl(x[6] &+ x[2], 18)

            x[3] ^= rotl(x[15] &+ x[11], 7)
            x[7] ^= rotl(x[3] &+ x[15], 9)
            x[11] ^= rotl(x[7] &+ x[3], 13)
            x[15] ^= rotl(x[11] &+ x[7], 18)

            // Row round
            x[1] ^= rotl(x[0] &+ x[3], 7)
            x[2] ^= rotl(x[1] &+ x[0], 9)
            x[3] ^= rotl(x[2] &+ x[1], 13)
            x[0] ^= rotl(x[3] &+ x[2], 18)

            x[6] ^= rotl(x[5] &+ x[4], 7)
            x[7] ^= rotl(x[6] &+ x[5], 9)
            x[4] ^= rotl(x[7] &+ x[6], 13)
            x[5] ^= rotl(x[4] &+ x[7], 18)

            x[11] ^= rotl(x[10] &+ x[9], 7)
            x[8] ^= rotl(x[11] &+ x[10], 9)
            x[9] ^= rotl(x[8] &+ x[11], 13)
            x[10] ^= rotl(x[9] &+ x[8], 18)

            x[12] ^= rotl(x[15] &+ x[14], 7)
            x[13] ^= rotl(x[12] &+ x[15], 9)
            x[14] ^= rotl(x[13] &+ x[12], 13)
            x[15] ^= rotl(x[14] &+ x[13], 18)
        }
    }

    // MARK: - Debug Self-Test Verification (RFC & Libsodium Vectors)

    /// Verifies the implementation against official RFC and libsodium test vectors.
    /// Can be called during debug / diagnostics without external test dependencies.
    @discardableResult
    static func selfTest() -> Bool {
        // 1. Poly1305 test vector from RFC 7539 / RFC 8439 §2.5.2
        let polyKey: [UInt8] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ]
        let polyMsg = Array("Cryptographic Forum Research Group".utf8)
        let expectedTag: [UInt8] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ]
        guard let computedTag = Poly1305.mac(message: polyMsg, key32: polyKey),
              computedTag == expectedTag else {
            return false
        }

        // 2. SecretBox test vector from libsodium tests/default/secretbox.c
        let sbKey: [UInt8] = [
            0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
            0x53, 0x62, 0xd8, 0x84, 0xaa, 0xe5, 0xb7, 0x61,
            0x09, 0xc1, 0x6b, 0x75, 0xa1, 0x70, 0xa0, 0x0a,
            0x84, 0x62, 0x66, 0x4f, 0x60, 0xa0, 0xdb, 0x3c,
        ]
        let sbNonce: [UInt8] = [
            0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
            0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
            0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
        ]
        let sbMsg: [UInt8] = [
            0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x1f, 0xfc, 0x00,
            0x27, 0xa3, 0x5f, 0x7e, 0xab, 0x62, 0xec, 0x62,
            0xee, 0x38, 0x60, 0x4f, 0x30, 0x43, 0x49, 0x46,
            0x24, 0x4e, 0x65, 0xb2, 0x68, 0xee, 0xf5, 0x1e,
            0x42, 0x66, 0x81, 0x37, 0x64, 0x2a, 0x84, 0x92,
            0x0d, 0x40, 0x68, 0x46, 0x55, 0xeb, 0x06, 0x15,
            0xa2, 0x64, 0x22, 0x2f, 0x6d, 0x60, 0x56, 0x85,
            0x06, 0xa3, 0x8a, 0xd5, 0x25, 0x18, 0x16, 0x5d,
        ]
        let expectedTagPrefix: [UInt8] = [
            0x93, 0xe5, 0x2c, 0x67, 0xf7, 0x28, 0xf3, 0x14,
            0x71, 0x00, 0xf7, 0x65, 0x99, 0x13, 0xcb, 0x86,
        ]
        guard let sealed = SecretBox.seal(message: sbMsg, nonce24: sbNonce, key32: sbKey),
              Array(sealed.prefix(16)) == expectedTagPrefix else {
            return false
        }
        guard let opened = SecretBox.open(box: sealed, nonce24: sbNonce, key32: sbKey),
              opened == sbMsg else {
            return false
        }

        // 3. Curve25519 Box round-trip
        let alicePriv = Curve25519.KeyAgreement.PrivateKey()
        let bobPriv = Curve25519.KeyAgreement.PrivateKey()
        let alicePub = [UInt8](alicePriv.publicKey.rawRepresentation)
        let bobPub = [UInt8](bobPriv.publicKey.rawRepresentation)

        let testNonce = [UInt8](repeating: 0x42, count: 24)
        let testPlain = Array("Hello Tailscale NaCl Box!".utf8)
        guard let boxed = Box.seal(message: testPlain, nonce24: testNonce, recipientPublicKey: bobPub, senderPrivateKey: alicePriv),
              let unboxed = Box.open(box: boxed, nonce24: testNonce, senderPublicKey: alicePub, recipientPrivateKey: bobPriv),
              unboxed == testPlain else {
            return false
        }

        return true
    }
}

// MARK: - Data Convenience Extensions

extension NCNaClBox.SecretBox {
    static func seal(message: Data, nonce24: Data, key32: Data) -> Data? {
        guard let res = seal(message: [UInt8](message), nonce24: [UInt8](nonce24), key32: [UInt8](key32)) else {
            return nil
        }
        return Data(res)
    }

    static func open(box: Data, nonce24: Data, key32: Data) -> Data? {
        guard let res = open(box: [UInt8](box), nonce24: [UInt8](nonce24), key32: [UInt8](key32)) else {
            return nil
        }
        return Data(res)
    }
}

extension NCNaClBox.Box {
    static func beforeNM(
        recipientPublicKey: Data,
        senderPrivateKey: Curve25519.KeyAgreement.PrivateKey
    ) -> Data? {
        guard let res = beforeNM(recipientPublicKey: [UInt8](recipientPublicKey), senderPrivateKey: senderPrivateKey) else {
            return nil
        }
        return Data(res)
    }

    static func seal(
        message: Data,
        nonce24: Data,
        recipientPublicKey: Data,
        senderPrivateKey: Curve25519.KeyAgreement.PrivateKey
    ) -> Data? {
        guard let res = seal(
            message: [UInt8](message),
            nonce24: [UInt8](nonce24),
            recipientPublicKey: [UInt8](recipientPublicKey),
            senderPrivateKey: senderPrivateKey
        ) else {
            return nil
        }
        return Data(res)
    }

    static func open(
        box: Data,
        nonce24: Data,
        senderPublicKey: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey
    ) -> Data? {
        guard let res = open(
            box: [UInt8](box),
            nonce24: [UInt8](nonce24),
            senderPublicKey: [UInt8](senderPublicKey),
            recipientPrivateKey: recipientPrivateKey
        ) else {
            return nil
        }
        return Data(res)
    }

    static func sealAfterNM(message: Data, nonce24: Data, sharedKey32: Data) -> Data? {
        guard let res = sealAfterNM(message: [UInt8](message), nonce24: [UInt8](nonce24), sharedKey32: [UInt8](sharedKey32)) else {
            return nil
        }
        return Data(res)
    }

    static func openAfterNM(box: Data, nonce24: Data, sharedKey32: Data) -> Data? {
        guard let res = openAfterNM(box: [UInt8](box), nonce24: [UInt8](nonce24), sharedKey32: [UInt8](sharedKey32)) else {
            return nil
        }
        return Data(res)
    }
}
