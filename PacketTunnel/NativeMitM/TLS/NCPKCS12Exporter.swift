import CommonCrypto
import Foundation
import Security

/// Swift implementation of PKCS#12 export (RFC 7292 / RFC 8018) for native MitM.
/// Encrypts the leaf private key using PBES2 (PBKDF2 + AES-256-CBC) with HMAC-SHA256,
/// packages leaf and CA certificates into CertBags, and bundles them into an AuthenticatedSafe.
/// This matches what `SecPKCS12Import` in iOS Security framework expects.
public final class NCPKCS12Exporter: PKCS12Exporting {
    public static let shared = NCPKCS12Exporter()
    public init() {}

    public func export(leafDER: Data, leafKey: SecKey, caDER: Data, password: String) throws -> Data {
        let pkcs8KeyDER = try extractPKCS8(from: leafKey)

        var salt = [UInt8](repeating: 0, count: 8)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw LeafCertError.keyGenerationFailed
        }
        var iv = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv) == errSecSuccess else {
            throw LeafCertError.keyGenerationFailed
        }

        let iterations: UInt32 = 2048
        let passwordData = Data(password.utf8)
        var aesKey = [UInt8](repeating: 0, count: 32) // AES-256

        let pbkdfStatus = passwordData.withUnsafeBytes { passBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passBytes.bindMemory(to: Int8.self).baseAddress, passwordData.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &aesKey, aesKey.count
                )
            }
        }
        guard pbkdfStatus == kCCSuccess else {
            throw LeafCertError.signingFailed(nil)
        }

        // AES-256-CBC encryption of PKCS#8 private key
        let encryptedKey = try encryptAES256CBC(data: pkcs8KeyDER, key: Data(aesKey), iv: Data(iv))

        // OIDs
        let oidPBES2 = [1, 2, 840, 113549, 1, 5, 13]
        let oidPBKDF2 = [1, 2, 840, 113549, 1, 5, 12]
        let oidHMACWithSHA256 = [1, 2, 840, 113549, 2, 9]
        let oidAES256CBC = [2, 16, 840, 1, 101, 3, 4, 1, 42]
        let oidData = [1, 2, 840, 113549, 1, 7, 1]
        let oidShroudedKeyBag = [1, 2, 840, 113549, 1, 12, 10, 1, 2]
        let oidCertBag = [1, 2, 840, 113549, 1, 12, 10, 1, 3]
        let oidX509Cert = [1, 2, 840, 113549, 1, 9, 22, 1]
        let oidLocalKeyID = [1, 2, 840, 113549, 1, 9, 21]

        // PBES2 algorithm parameters
        let pbkdf2Params = DER.seq(
            DER.octetString(Data(salt)),
            DER.integer(bigEndian: Data([UInt8(iterations >> 8), UInt8(iterations & 0xFF)])),
            DER.seq(DER.oid(oidHMACWithSHA256), DER.tlv(0x05, Data())) // NULL
        )
        let pbes2Params = DER.seq(
            DER.seq(DER.oid(oidPBKDF2), pbkdf2Params),
            DER.seq(DER.oid(oidAES256CBC), DER.octetString(Data(iv)))
        )
        let encPKInfo = DER.seq(
            DER.seq(DER.oid(oidPBES2), pbes2Params),
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
        let leafCertBag = DER.seq(
            DER.oid(oidCertBag),
            DER.explicit(0, leafCertVal),
            localKeyIDAttr
        )

        var bags = [keyBag, leafCertBag]
        if !caDER.isEmpty {
            let caCertVal = DER.seq(DER.oid(oidX509Cert), DER.explicit(0, DER.octetString(caDER)))
            let caCertBag = DER.seq(DER.oid(oidCertBag), DER.explicit(0, caCertVal))
            bags.append(caCertBag)
        }

        let safeContents = DER.tlv(0x30, bags.reduce(Data(), +))
        let contentInfo = DER.seq(DER.oid(oidData), DER.explicit(0, DER.octetString(safeContents)))
        let authSafe = DER.seq(contentInfo)
        let authSafeContent = DER.octetString(authSafe)
        let authSafeContentInfo = DER.seq(DER.oid(oidData), DER.explicit(0, authSafeContent))

        // PFX: version 3, authSafeContentInfo
        let pfx = DER.seq(
            DER.integer(bigEndian: Data([0x03])),
            authSafeContentInfo
        )
        return pfx
    }

    private func extractPKCS8(from key: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
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
        let privScalar = ext.prefix(32)
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

    private func encryptAES256CBC(data: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = data.count + kCCBlockSizeAES128
        var outData = Data(count: bufferSize)
        var numBytesEncrypted: Int = 0
        let outCapacity = outData.count

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    outData.withUnsafeMutableBytes { outBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
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
