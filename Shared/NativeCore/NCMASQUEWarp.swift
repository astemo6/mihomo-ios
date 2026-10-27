import CryptoKit
import Foundation
import Security

/// Cloudflare WARP (cf-connect-ip) mTLS client identity construction and server certificate pinning.
enum NCMASQUEWarp {

    // MARK: - Constants & Error Messages

    static let warpKeyInvalid = "MASQUE WARP 私钥无效（需 PKCS#8 或 SEC 1 P-256 私钥）"
    static let warpPublicKeyInvalid = "MASQUE WARP 公钥无效（需 P-256 SPKI 或 65 字节未压缩点）"
    static let warpPinMismatch = "MASQUE WARP 服务端证书公钥不匹配（固定校验失败）"
    static let warpIdentityFailed = "MASQUE WARP 客户端证书或身份构造失败"

    // MARK: - Error Types

    enum WarpError: LocalizedError, Equatable {
        case warpKeyInvalid(String = NCMASQUEWarp.warpKeyInvalid)
        case warpPublicKeyInvalid(String = NCMASQUEWarp.warpPublicKeyInvalid)
        case warpPinMismatch(String = NCMASQUEWarp.warpPinMismatch)
        case warpIdentityFailed(String = NCMASQUEWarp.warpIdentityFailed)

        var errorDescription: String? {
            switch self {
            case .warpKeyInvalid(let s),
                 .warpPublicKeyInvalid(let s),
                 .warpPinMismatch(let s),
                 .warpIdentityFailed(let s):
                return s
            }
        }
    }

    typealias Error = WarpError

    // MARK: - Private Key Parsing

    /// Parse ECDSA P-256 private key from PKCS#8 DER, SEC 1 DER, or PEM format (standard or URL-safe base64).
    /// Extracts the 32-byte scalar, derives the public point via CryptoKit, and constructs a SecKey using ANSI X9.63 (04||X||Y||K).
    static func parsePrivateKey(_ raw: String) -> SecKey? {
        guard let der = decodeBase64Flexible(raw),
              let scalar = extractECScalar(from: der),
              scalar.count == 32 else {
            return nil
        }
        guard let p256 = try? P256.Signing.PrivateKey(rawRepresentation: scalar) else {
            return nil
        }
        let pubX963 = p256.publicKey.x963Representation
        guard pubX963.count == 65, pubX963.first == 0x04 else { return nil }
        var x963Data = pubX963
        x963Data.append(scalar) // 65-byte point + 32-byte scalar = 97 bytes (scalar at suffix)
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var err: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(x963Data as CFData, keyAttrs as CFDictionary, &err) else {
            return nil
        }
        return secKey
    }

    // MARK: - Public Point Normalization

    /// Normalize configured public key (SPKI base64, bare 65B point, or PEM) to a 65-byte uncompressed EC point (04||X||Y).
    static func publicPoint(fromConfiguredKey raw: String) -> Data? {
        guard let der = decodeBase64Flexible(raw) else { return nil }
        let point: Data
        if der.count == 65, der.first == 0x04 {
            point = der
        } else {
            let bytes = [UInt8](der)
            var i = 0
            if let (t0, outer) = derTLV(bytes, &i), t0 == 0x30 {
                let o = Array(outer)
                var j = 0
                if let (tAlg, _) = derTLV(o, &j), tAlg == 0x30,
                   let (tBits, bits) = derTLV(o, &j), tBits == 0x03,
                   bits.count == 66, bits[bits.startIndex] == 0x00, bits[bits.startIndex + 1] == 0x04 {
                    point = Data(bits.dropFirst())
                } else if der.count >= 65, der.suffix(65).first == 0x04 {
                    point = Data(der.suffix(65))
                } else {
                    return nil
                }
            } else if der.count >= 65, der.suffix(65).first == 0x04 {
                point = Data(der.suffix(65))
            } else {
                return nil
            }
        }
        guard point.count == 65, point.first == 0x04 else { return nil }
        guard (try? P256.Signing.PublicKey(x963Representation: point)) != nil else { return nil }
        return point
    }

    // MARK: - Peer Certificate Pinning

    /// Compare server leaf certificate public key against configured 65-byte uncompressed point.
    static func peerPointMatches(leafCertDER: Data, configuredPoint: Data) -> Bool {
        guard configuredPoint.count == 65, configuredPoint.first == 0x04 else { return false }
        guard let cert = SecCertificateCreateWithData(nil, leafCertDER as CFData) else { return false }
        guard let key = SecCertificateCopyKey(cert) else { return false }
        var err: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(key, &err) as Data? else { return false }
        guard ext.count == 65, ext.first == 0x04 else { return false }
        return ext == configuredPoint
    }

    // MARK: - Client Certificate Generation

    /// Generate a minimal self-signed X.509 client certificate for Cloudflare WARP mTLS authentication.
    /// - Version 3 (0x02)
    /// - Serial: 0
    /// - Signature Algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    /// - Issuer: empty Name (SEQUENCE {})
    /// - Validity: notBefore to notBefore + 24 h
    /// - Subject: empty Name (SEQUENCE {})
    /// - SubjectPublicKeyInfo: EC P-256 SPKI with client public key
    /// - No extensions
    static func makeClientCertificateDER(privateKey: SecKey, notBefore: Date = Date()) -> Data? {
        guard let pubKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        var err: Unmanaged<CFError>?
        guard let pubPoint = SecKeyCopyExternalRepresentation(pubKey, &err) as Data?,
              pubPoint.count == 65, pubPoint.first == 0x04 else { return nil }

        // SPKI for EC P-256 (91 bytes)
        let algIdEC = derSeq([
            derOID([1, 2, 840, 10045, 2, 1]),   // id-ecPublicKey
            derOID([1, 2, 840, 10045, 3, 1, 7]) // prime256v1
        ])
        let spkiBitString = derBitString(pubPoint, unusedBits: 0)
        let spkiDER = derSeq([algIdEC, spkiBitString])

        // Signature algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        let sigAlg = derSeq([derOID([1, 2, 840, 10045, 4, 3, 2])])

        // Serial number: 0
        let serial = derInteger(bigEndian: Data([0x00]))

        // Empty issuer & subject
        let emptyName = derSeq([])

        // Validity: notBefore to notBefore + 24 h
        let notAfter = notBefore.addingTimeInterval(24 * 3600)
        let validity = derSeq([derUTCTime(notBefore), derUTCTime(notAfter)])

        // Version 3: [0] EXPLICIT INTEGER 2
        let versionV3 = derExplicit(0, derInteger(bigEndian: Data([0x02])))

        let tbs = derSeq([
            versionV3,
            serial,
            sigAlg,
            emptyName,
            validity,
            emptyName,
            spkiDER
        ])

        var signErr: Unmanaged<CFError>?
        guard let sigRaw = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbs as CFData,
            &signErr
        ) as Data? else {
            return nil
        }

        // Encode signature as DER SEQUENCE { INTEGER r, INTEGER s } if not already DER
        let sigDER: Data
        let sigBytes = [UInt8](sigRaw)
        if sigBytes.count > 2 && sigBytes[0] == 0x30 && Int(sigBytes[1]) == sigBytes.count - 2 {
            sigDER = sigRaw
        } else {
            let half = sigRaw.count / 2
            let r = Data(sigRaw.prefix(half))
            let s = Data(sigRaw.suffix(half))
            sigDER = derSeq([derInteger(bigEndian: r), derInteger(bigEndian: s)])
        }

        let sigBitString = derBitString(sigDER, unusedBits: 0)
        return derSeq([tbs, sigAlg, sigBitString])
    }

    // MARK: - Local Identity

    /// Construct SecIdentity wrapping the self-signed client certificate and private key via PKCS#12 export/import.
    static func makeLocalIdentity(privateKey: SecKey, certDER: Data) -> SecIdentity? {
        let password = "tern-warp-identity"
        guard let p12Data = try? NCPKCS12Exporter.shared.export(
            leafDER: certDER,
            leafKey: privateKey,
            caDER: Data(),
            password: password
        ) else {
            return nil
        }
        let options: [String: Any] = [kSecImportExportPassphrase as String: password]
        var rawItems: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &rawItems)
        guard status == errSecSuccess,
              let list = rawItems as? [[String: Any]],
              let first = list.first,
              let identityRef = first[kSecImportItemIdentity as String] else {
            return nil
        }
        return (identityRef as! SecIdentity)
    }

    /// Construct SecIdentity from a validated NCMASQUE.Config.
    static func makeLocalIdentity(config: NCMASQUE.Config) -> SecIdentity? {
        guard let privStr = config.privateKey,
              let privKey = parsePrivateKey(privStr) else {
            return nil
        }
        guard let certDER = makeClientCertificateDER(privateKey: privKey) else {
            return nil
        }
        return makeLocalIdentity(privateKey: privKey, certDER: certDER)
    }

    // MARK: - Configuration Validation

    /// Validate WARP private and public keys for NCSupport.
    static func validate(privateKey: String, publicKey: String) -> String? {
        guard parsePrivateKey(privateKey) != nil else {
            return warpKeyInvalid
        }
        guard publicPoint(fromConfiguredKey: publicKey) != nil else {
            return warpPublicKeyInvalid
        }
        return nil
    }

    // MARK: - Base64 & DER Helpers

    /// Decode base64 string, handling PEM wrappers, whitespace, URL-safe characters, and missing padding.
    static func decodeBase64Flexible(_ raw: String) -> Data? {
        var cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.isEmpty { return nil }
        if cleaned.contains("-----") {
            let lines = cleaned.components(separatedBy: .newlines)
            let filtered = lines.filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.hasPrefix("-----") && !trimmed.isEmpty
            }
            cleaned = filtered.joined()
        }
        cleaned = cleaned.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        cleaned = cleaned.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let mod = cleaned.count % 4
        if mod == 2 {
            cleaned.append("==")
        } else if mod == 3 {
            cleaned.append("=")
        } else if mod == 1 {
            return nil
        }
        return Data(base64Encoded: cleaned)
    }

    /// Extract 32-byte EC private key scalar from PKCS#8 or SEC 1 DER data.
    static func extractECScalar(from der: Data) -> Data? {
        if der.count == 32 {
            return der
        }
        let d = [UInt8](der)
        var i = 0
        guard let (t0, outer) = derTLV(d, &i), t0 == 0x30 else { return nil }
        let o = Array(outer)
        var j = 0
        guard let (tv, _) = derTLV(o, &j), tv == 0x02 else { return nil }
        guard let (t2, second) = derTLV(o, &j) else { return nil }
        var sec1: [UInt8]
        if t2 == 0x30 {
            // PKCS#8: version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey }
            guard let (t3, inner) = derTLV(o, &j), t3 == 0x04 else { return nil }
            sec1 = Array(inner)
        } else if t2 == 0x04 {
            // SEC 1 already: version, privateKey OCTET STRING, ...
            sec1 = d
            _ = second
        } else {
            return nil
        }
        var k = 0
        guard let (s0, ecpk) = derTLV(sec1, &k), s0 == 0x30 else { return nil }
        let e = Array(ecpk)
        var m = 0
        guard let (ev, _) = derTLV(e, &m), ev == 0x02,
              let (ep, priv) = derTLV(e, &m), ep == 0x04 else { return nil }
        var scalar = Array(priv)
        if scalar.count > 32 {
            scalar = Array(scalar.suffix(32))
        }
        while scalar.count < 32 {
            scalar.insert(0, at: 0)
        }
        return Data(scalar)
    }

    /// Read (tag, content) TLV tuple from DER bytes at index `i`, advancing `i`.
    static func derTLV(_ d: [UInt8], _ i: inout Int) -> (UInt8, ArraySlice<UInt8>)? {
        guard i + 2 <= d.count else { return nil }
        let tag = d[i]; i += 1
        var len = Int(d[i]); i += 1
        if len & 0x80 != 0 {
            let n = len & 0x7f
            guard n > 0, n <= 4, i + n <= d.count else { return nil }
            len = 0
            for _ in 0..<n { len = len << 8 | Int(d[i]); i += 1 }
        }
        guard len >= 0, i + len <= d.count else { return nil }
        defer { i += len }
        return (tag, d[i..<(i + len)])
    }

    // MARK: - DER Construction Primitives

    static func derLength(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func derTLVTag(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(derLength(content.count))
        out.append(content)
        return out
    }

    static func derSeq(_ parts: [Data]) -> Data {
        derTLVTag(0x30, parts.reduce(Data(), +))
    }

    static func derInteger(bigEndian raw: Data) -> Data {
        var b = raw
        if b.isEmpty { b = Data([0x00]) }
        while b.count > 1, b.first == 0, (b[b.startIndex + 1] & 0x80) == 0 {
            b.removeFirst()
        }
        if let f = b.first, (f & 0x80) != 0 {
            b.insert(0, at: 0)
        }
        return derTLVTag(0x02, b)
    }

    static func derOID(_ arcs: [Int]) -> Data {
        guard arcs.count >= 2 else { return Data() }
        var content = Data([UInt8(arcs[0] * 40 + arcs[1])])
        for arc in arcs.dropFirst(2) {
            var stack: [UInt8] = [UInt8(arc & 0x7F)]
            var v = arc >> 7
            while v > 0 {
                stack.insert(UInt8(v & 0x7F) | 0x80, at: 0)
                v >>= 7
            }
            content.append(contentsOf: stack)
        }
        return derTLVTag(0x06, content)
    }

    static func derUTCTime(_ date: Date) -> Data {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(secondsFromGMT: 0)!
        let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let s = String(format: "%02d%02d%02d%02d%02d%02dZ",
                       (c.year ?? 1970) % 100, c.month ?? 1, c.day ?? 1,
                       c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
        return derTLVTag(0x17, Data(s.utf8))
    }

    static func derBitString(_ bytes: Data, unusedBits: UInt8 = 0) -> Data {
        derTLVTag(0x03, Data([unusedBits]) + bytes)
    }

    static func derExplicit(_ n: UInt8, _ content: Data) -> Data {
        derTLVTag(0xA0 + n, content)
    }
}
