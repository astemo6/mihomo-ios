import CommonCrypto
import Foundation
import Security

/// Swift implementation of PKCS#12 export (RFC 7292) for native MitM and the CA export.
///
/// fix/nc-ut-export: the PFX is the classic, universally readable layout — the one `openssl pkcs12 -export -legacy`,
/// macOS Keychain and Go's `pkcs12.Legacy` write:
///   - private key: PKCS8ShroudedKeyBag, pbeWithSHAAnd3-KeyTripleDES-CBC (PKCS#12 KDF, SHA-1, 2048 iterations);
///   - certificates: CertBags in a plain `data` ContentInfo;
///   - integrity: MacData = HMAC-SHA1 with a PKCS#12-KDF key (ID 3).
/// The previous writer used PBES2 (PBKDF2-SHA256 + AES-256-CBC) and no MacData at all; `SecPKCS12Import` rejected
/// that with errSecDecode (-26275) on the iOS simulator, so neither the full export's CA (`[mitm] p12`) nor the CA
/// p12 export could be read back.
public final class NCPKCS12Exporter: PKCS12Exporting {
    public static let shared = NCPKCS12Exporter()
    public init() {}

    static let iterations = 2048

    public func export(leafDER: Data, leafKey: SecKey, caDER: Data, password: String) throws -> Data {
        let pkcs8KeyDER = try extractPKCS8(from: leafKey)
        let iterations = Self.iterations
        let iterDER = DER.integer(bigEndian: Data([UInt8((iterations >> 8) & 0xFF), UInt8(iterations & 0xFF)]))

        let keySalt = try Self.random(8)
        let desKey = Self.pkcs12KDF(password: password, salt: keySalt, id: 1, iterations: iterations, length: 24)
        let desIV = Self.pkcs12KDF(password: password, salt: keySalt, id: 2, iterations: iterations, length: 8)
        let encryptedKey = try encrypt3DESCBC(data: pkcs8KeyDER, key: Data(desKey), iv: Data(desIV))

        // OIDs
        let oidPbeSHA3DES = [1, 2, 840, 113549, 1, 12, 1, 3]
        let oidSHA1 = [1, 3, 14, 3, 2, 26]
        let oidData = [1, 2, 840, 113549, 1, 7, 1]
        let oidShroudedKeyBag = [1, 2, 840, 113549, 1, 12, 10, 1, 2]
        let oidCertBag = [1, 2, 840, 113549, 1, 12, 10, 1, 3]
        let oidX509Cert = [1, 2, 840, 113549, 1, 9, 22, 1]
        let oidLocalKeyID = [1, 2, 840, 113549, 1, 9, 21]

        // EncryptedPrivateKeyInfo { AlgorithmIdentifier { pbeWithSHAAnd3-KeyTripleDES-CBC, pkcs-12PbeParams }, data }
        let encPKInfo = DER.seq(
            DER.seq(DER.oid(oidPbeSHA3DES), DER.seq(DER.octetString(Data(keySalt)), iterDER)),
            DER.octetString(encryptedKey)
        )

        // LocalKeyID: SHA-1 of leaf cert DER
        var localKeyID = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        leafDER.withUnsafeBytes { b in
            _ = CC_SHA1(b.baseAddress, CC_LONG(leafDER.count), &localKeyID)
        }
        let localKeyIDAttr = DER.set(
            DER.seq(DER.oid(oidLocalKeyID), DER.set(DER.octetString(Data(localKeyID))))
        )

        let keyBag = DER.seq(
            DER.oid(oidShroudedKeyBag),
            DER.explicit(0, encPKInfo),
            localKeyIDAttr
        )

        let leafCertVal = DER.seq(DER.oid(oidX509Cert), DER.explicit(0, DER.octetString(leafDER)))
        var certBags = DER.seq(
            DER.oid(oidCertBag),
            DER.explicit(0, leafCertVal),
            localKeyIDAttr
        )
        if !caDER.isEmpty {
            let caCertVal = DER.seq(DER.oid(oidX509Cert), DER.explicit(0, DER.octetString(caDER)))
            certBags.append(DER.seq(DER.oid(oidCertBag), DER.explicit(0, caCertVal)))
        }

        func dataContentInfo(_ content: Data) -> Data {
            DER.seq(DER.oid(oidData), DER.explicit(0, DER.octetString(content)))
        }
        // AuthenticatedSafe: certificates, then the shrouded key (each SafeContents in its own data ContentInfo).
        let authSafe = DER.seq(
            dataContentInfo(DER.tlv(0x30, certBags)),
            dataContentInfo(DER.tlv(0x30, keyBag))
        )

        // MacData { DigestInfo { sha1, HMAC-SHA1(authSafe) }, macSalt, iterations }
        let macSalt = try Self.random(8)
        let macKey = Self.pkcs12KDF(password: password, salt: macSalt, id: 3, iterations: iterations, length: 20)
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        authSafe.withUnsafeBytes { b in
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), macKey, macKey.count, b.baseAddress, authSafe.count, &mac)
        }
        let macData = DER.seq(
            DER.seq(DER.seq(DER.oid(oidSHA1), DER.tlv(0x05, Data())), DER.octetString(Data(mac))),
            DER.octetString(Data(macSalt)),
            iterDER
        )

        // PFX: version 3, authSafe (data ContentInfo), macData
        return DER.seq(
            DER.integer(bigEndian: Data([0x03])),
            dataContentInfo(authSafe),
            macData
        )
    }

    private static func random(_ n: Int) throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &b) == errSecSuccess else {
            throw LeafCertError.keyGenerationFailed
        }
        return b
    }

    /// RFC 7292 Appendix B.2 key derivation with SHA-1 (u = 20, v = 64). The password is a BMPString:
    /// UTF-16 big-endian plus a two-byte NUL terminator. id: 1 = key, 2 = IV, 3 = MAC key.
    static func pkcs12KDF(password: String, salt: [UInt8], id: UInt8, iterations: Int, length n: Int) -> [UInt8] {
        let u = Int(CC_SHA1_DIGEST_LENGTH), v = 64
        var pw: [UInt8] = []
        for cu in password.utf16 { pw.append(UInt8(cu >> 8)); pw.append(UInt8(cu & 0xFF)) }
        pw.append(contentsOf: [0, 0])
        func fill(_ x: [UInt8]) -> [UInt8] {
            guard !x.isEmpty else { return [] }
            let len = v * ((x.count + v - 1) / v)
            return (0..<len).map { x[$0 % x.count] }
        }
        let d = [UInt8](repeating: id, count: v)
        var i = fill(salt) + fill(pw)
        var out: [UInt8] = []
        while true {
            var a = d + i
            for _ in 0..<max(1, iterations) {
                var h = [UInt8](repeating: 0, count: u)
                let input = a
                _ = CC_SHA1(input, CC_LONG(input.count), &h)
                a = h
            }
            out.append(contentsOf: a)
            if out.count >= n { return Array(out.prefix(n)) }
            let b = (0..<v).map { a[$0 % u] }
            var j = 0
            while j < i.count {
                var carry = 1
                for k in stride(from: v - 1, through: 0, by: -1) {
                    let s = Int(i[j + k]) + Int(b[k]) + carry
                    i[j + k] = UInt8(s & 0xFF)
                    carry = s >> 8
                }
                j += v
            }
        }
    }

    private func extractPKCS8(from key: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }
        // fix/nc-rsa-ca: an RSA key exports PKCS#1 RSAPrivateKey — the shrouded key bag wants PKCS#8.
        if DER.isRSAKey(key) {
            return DER.pkcs8RSA(pkcs1: ext)
        }
        // If already a DER sequence (starts with 0x30), return directly
        if ext.first == 0x30 {
            return ext
        }
        // If it is raw EC private key scalar (32 bytes) or ANSI X9.63 (scalar + pub):
        guard let pub = SecKeyCopyPublicKey(key),
              let pubPoint = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }
        let privScalar: Data
        if ext.count >= 32 {
            privScalar = Data(ext.suffix(32))
        } else {
            privScalar = Data(repeating: 0, count: 32 - ext.count) + ext
        }
        // ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING (32), [1] BIT STRING (pubPoint) }
        let ecPrivKey = DER.seq(
            DER.integer(bigEndian: Data([0x01])),
            DER.octetString(privScalar),
            DER.explicit(1, DER.bitString(pubPoint))
        )
        // PKCS#8 PrivateKeyInfo ::= SEQUENCE { version (0), algId (id-ecPublicKey, prime256v1), privateKey (ecPrivKey) }
        let pkcs8 = DER.seq(
            DER.integer(bigEndian: Data([0x00])),
            DER.seq(DER.oid([1, 2, 840, 10045, 2, 1]), DER.oid([1, 2, 840, 10045, 3, 1, 7])),
            DER.octetString(ecPrivKey)
        )
        return pkcs8
    }

    private func encrypt3DESCBC(data: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSize3DES
        var outData = Data(count: bufferSize)
        var numBytesEncrypted: Int = 0
        let outCapacity = outData.count

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    outData.withUnsafeMutableBytes { outBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithm3DES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            outBytes.baseAddress, outCapacity,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw LeafCertError.signingFailed(nil)
        }
        outData.count = numBytesEncrypted
        return outData
    }
}
