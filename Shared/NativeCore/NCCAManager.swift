import Foundation
import Security

/// Swift CA and Leaf Certificate Manager for Native MitM.
/// Replaces Go's CA management (`bridge/mitm/ca.go`) and leaf certificate issuance (`LibmihomoMitmLeafIdentity`).
/// Loads or generates the CA in `<home>/engine/ca` and signs per-host leaf certificates.
public final class NCCAManager {
    public static let shared = NCCAManager()

    private let lock = NSLock()
    private var issuer: LeafCertIssuer?
    private var caCert: SecCertificate?
    private var caKey: SecKey?

    public init() {}

    /// Root directory for CA files (<home>/engine/ca).
    public static func caDir(home: String) -> URL {
        URL(fileURLWithPath: home).appendingPathComponent("engine/ca", isDirectory: true)
    }

    /// Load existing CA or generate a new one if missing.
    public func ensureCA(home: String) -> (caCert: SecCertificate, caKey: SecKey)? {
        lock.lock()
        defer { lock.unlock() }
        if let cert = caCert, let key = caKey {
            return (cert, key)
        }
        if let loaded = Self.loadCA(home: home) {
            caCert = loaded.caCert
            caKey = loaded.caKey
            initIssuerLocked(cert: loaded.caCert, key: loaded.caKey)
            return loaded
        }
        // Never replace a CA that exists but could not be read: the user trusts that certificate (installed profile).
        // feat/native-core-eval: Go's CA (bridge/mitm/ca.go) is PKCS#8 — read by loadCA below, EC P-256 or (gap C7)
        // RSA, e.g. a p12 exported by another app and imported; anything else keeps MitM off with a log line.
        let dir = Self.caDir(home: home)
        if FileManager.default.fileExists(atPath: dir.appendingPathComponent("ca.pem").path)
            || FileManager.default.fileExists(atPath: dir.appendingPathComponent("ca.key").path) {
            StartupLog.write("native MitM: CA in engine/ca could not be read (neither EC P-256 nor RSA?) — MitM off, CA left untouched")
            return nil
        }
        do {
            let generated = try Self.generateCA(home: home)
            caCert = generated.caCert
            caKey = generated.caKey
            initIssuerLocked(cert: generated.caCert, key: generated.caKey)
            return generated
        } catch {
            return nil
        }
    }

    private func initIssuerLocked(cert: SecCertificate, key: SecKey) {
        do {
            issuer = try LeafCertIssuer(caCertificate: cert, caPrivateKey: key)
        } catch {
            issuer = nil
        }
    }

    /// Issues a PKCS#12 bundle for `host`, cached by `LeafIdentityCache`.
    public func leafP12(for host: String, extraDNSNames: [String] = []) -> Data? {
        let h = AppShared.homeURL.path
        lock.lock()
        var currentIssuer = issuer
        if currentIssuer == nil {
            lock.unlock()
            _ = ensureCA(home: h)
            lock.lock()
            currentIssuer = issuer
        }
        lock.unlock()

        guard let currentIssuer else { return nil }
        do {
            let res = try currentIssuer.issueLeafCertificate(for: host, extraDNSNames: extraDNSNames)
            return res.pkcs12Data
        } catch {
            return nil
        }
    }

    // MARK: - CA Loading and Generation

    /// Loads CA from <home>/engine/ca/ca.pem and ca.key.
    public static func loadCA(home: String) -> (caCert: SecCertificate, caKey: SecKey)? {
        let dir = caDir(home: home)
        let pemURL = dir.appendingPathComponent("ca.pem")
        let keyURL = dir.appendingPathComponent("ca.key")

        guard let pemData = try? Data(contentsOf: pemURL),
              let keyData = try? Data(contentsOf: keyURL),
              let certDER = extractPEMContent(pemData, label: "CERTIFICATE"),
              let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return nil
        }
        // gap C7 (astemo6/Muse NativeCore): an RSA CA — PKCS#8 with rsaEncryption (Go's ImportP12 writes that for a
        // p12 from another app) or a PKCS#1 "RSA PRIVATE KEY" block. Security takes the PKCS#1 RSAPrivateKey DER.
        if let pkcs1 = extractPEMContent(keyData, label: "RSA PRIVATE KEY")
            ?? extractPEMContent(keyData, label: "PRIVATE KEY").flatMap({ Self.rsaPKCS1(fromPKCS8: $0) }) {
            let rsaAttrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            ]
            var rerr: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(pkcs1 as CFData, rsaAttrs as CFDictionary, &rerr) else { return nil }
            return (cert, key)
        }
        guard let keyDER = extractPEMContent(keyData, label: "PRIVATE KEY") ?? extractPEMContent(keyData, label: "EC PRIVATE KEY") else {
            return nil
        }

        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var err: Unmanaged<CFError>?
        // Security wants X9.63 (04 || X || Y || K); Go writes PKCS#8 (RFC 5208) wrapping an RFC 5915 ECPrivateKey.
        guard let x963 = Self.x963(fromPKCS8OrSEC1: keyDER, certDER: certDER),
              let key = SecKeyCreateWithData(x963 as CFData, keyAttrs as CFDictionary, &err) else {
            return nil
        }
        return (cert, key)
    }

    // MARK: - Minimal DER reading (PKCS#8 / SEC 1 EC private keys)

    /// (tag, contents) of the TLV at `i`, advancing `i` past it.
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

    /// The PKCS#1 RSAPrivateKey inside a PKCS#8 PrivateKeyInfo whose algorithm is rsaEncryption (1.2.840.113549.1.1.1);
    /// nil for any other key (gap C7).
    static func rsaPKCS1(fromPKCS8 der: Data) -> Data? {
        let d = [UInt8](der)
        var i = 0
        guard let (t0, outer) = derTLV(d, &i), t0 == 0x30 else { return nil }
        let o = Array(outer)
        var j = 0
        guard let (tv, _) = derTLV(o, &j), tv == 0x02,
              let (ta, alg) = derTLV(o, &j), ta == 0x30 else { return nil }
        let a = Array(alg)
        var k = 0
        guard let (toid, oid) = derTLV(a, &k), toid == 0x06,
              Array(oid) == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] else { return nil }
        guard let (tk, inner) = derTLV(o, &j), tk == 0x04 else { return nil }
        return Data(inner)
    }

    /// X9.63 private key from PKCS#8 or a bare SEC 1 ECPrivateKey (P-256). The public point comes from the key
    /// structure, else from the CA certificate's SubjectPublicKeyInfo (the CA's own key).
    static func x963(fromPKCS8OrSEC1 der: Data, certDER: Data) -> Data? {
        let d = [UInt8](der)
        var i = 0
        guard let (t0, outer) = derTLV(d, &i), t0 == 0x30 else { return nil }
        var j = 0
        let o = Array(outer)
        guard let (tv, _) = derTLV(o, &j), tv == 0x02 else { return nil }
        guard let (t2, second) = derTLV(o, &j) else { return nil }
        var sec1: [UInt8]
        if t2 == 0x30 {
            // PKCS#8: version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey }
            guard let (t3, inner) = derTLV(o, &j), t3 == 0x04 else { return nil }
            sec1 = Array(inner)
        } else if t2 == 0x04 {
            sec1 = d // SEC 1 already: version, privateKey OCTET STRING, …
            _ = second
        } else {
            return nil
        }
        var k = 0
        guard let (s0, ecpk) = derTLV(sec1, &k), s0 == 0x30 else { return nil }
        let e = Array(ecpk)
        var m = 0
        guard let (ev, _) = derTLV(e, &m), ev == 0x02, let (ep, priv) = derTLV(e, &m), ep == 0x04 else { return nil }
        var scalar = Array(priv)
        if scalar.count > 32 { scalar = Array(scalar.suffix(32)) }
        while scalar.count < 32 { scalar.insert(0, at: 0) }
        var point: [UInt8]?
        while m < e.count, let (tag, val) = derTLV(e, &m) {
            if tag == 0xa1 { // [1] publicKey BIT STRING
                var n = 0
                let v = Array(val)
                if let (bt, bits) = derTLV(v, &n), bt == 0x03, bits.count == 66 { point = Array(bits.dropFirst()) }
            }
        }
        if point == nil, let cert = SecCertificateCreateWithData(nil, certDER as CFData), let pub = SecCertificateCopyKey(cert),
           let ext = SecKeyCopyExternalRepresentation(pub, nil) as Data?, ext.count == 65 {
            point = [UInt8](ext)
        }
        guard let p = point, p.count == 65, p[0] == 0x04 else { return nil }
        return Data(p + scalar)
    }

    /// Generates a new 10-year ECDSA P-256 root CA in Swift and writes to disk.
    public static func generateCA(home: String) throws -> (caCert: SecCertificate, caKey: SecKey) {
        let dir = caDir(home: home)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])

        // 1. Generate EC P-256 private key
        var err: Unmanaged<CFError>?
        guard let caKey = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ] as CFDictionary, &err) else {
            throw LeafCertError.keyGenerationFailed
        }
        guard let pub = SecKeyCopyPublicKey(caKey),
              let pubPoint = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }

        // 2. Generate random serial & common name
        var serialBytes = [UInt8](repeating: 0, count: 15)
        _ = SecRandomCopyBytes(kSecRandomDefault, serialBytes.count, &serialBytes)
        serialBytes[0] &= 0x7F
        let serial = Data(serialBytes)
        let suffix = serial.prefix(3).map { String(format: "%02X", $0) }.joined()
        let cn = "Tern MitM CA " + suffix

        let now = Date()
        let notBefore = now.addingTimeInterval(-48 * 3600)
        let notAfter = Calendar.current.date(byAdding: .year, value: 10, to: now) ?? now.addingTimeInterval(3650 * 86400)

        // 3. CA Extensions: BasicConstraints CA=true (critical), KeyUsage certSign | cRLSign | digitalSignature (critical)
        // BasicConstraints: SEQUENCE { cA BOOLEAN TRUE, pathLenConstraint INTEGER 0 }
        let bcContent = DER.seq(DER.boolean(true), DER.integer(bigEndian: Data([0x00])))
        let bcExt = DER.extn(DER.oidBasicConstraints, critical: true, valueDER: bcContent)
        // KeyUsage: digitalSignature(bit 0), keyCertSign(bit 5), cRLSign(bit 6) -> bits 0, 5, 6 set -> 0x86, 0x00 (1 unused bit)
        let kuContent = DER.bitString(Data([0x86]), unusedBits: 1)
        let kuExt = DER.extn(DER.oidKeyUsage, critical: true, valueDER: kuContent)
        let extensions = DER.explicit(3, DER.seq(bcExt, kuExt))

        let subjectName = DER.name(cn: cn)
        let spki = DER.spkiECP256(point: pubPoint)

        let tbs = DER.seq(
            DER.explicit(0, DER.integer(bigEndian: Data([2]))), // v3
            DER.integer(bigEndian: serial),
            DER.algIdECDSA(),
            subjectName, // issuer = subject
            DER.seq(DER.utcTime(notBefore), DER.utcTime(notAfter)),
            subjectName,
            spki,
            extensions
        )

        guard let x962 = SecKeyCreateSignature(caKey, .ecdsaSignatureMessageX962SHA256, tbs as CFData, &err) as Data? else {
            throw LeafCertError.signingFailed(err?.takeRetainedValue())
        }
        let certDER = DER.certificate(tbs: tbs, signatureX962: x962)
        guard let caCert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            throw LeafCertError.invalidCACertificate
        }

        // 4. Save to files
        guard let keyExt = SecKeyCopyExternalRepresentation(caKey, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }
        let pkcs8: Data
        if keyExt.first == 0x30 {
            pkcs8 = keyExt
        } else {
            let privScalar = keyExt.prefix(32)
            let ecPrivKey = DER.seq(
                DER.integer(bigEndian: Data([0x01])),
                DER.octetString(privScalar),
                DER.explicit(1, DER.bitString(pubPoint))
            )
            pkcs8 = DER.seq(
                DER.integer(bigEndian: Data([0x00])),
                DER.seq(DER.oid([1, 2, 840, 10045, 2, 1]), DER.oid([1, 2, 840, 10045, 3, 1, 7])),
                DER.octetString(ecPrivKey)
            )
        }

        let pemKey = formatPEM(pkcs8, label: "PRIVATE KEY")
        let pemCert = formatPEM(certDER, label: "CERTIFICATE")

        let keyURL = dir.appendingPathComponent("ca.key")
        let pemURL = dir.appendingPathComponent("ca.pem")

        try pemKey.write(to: keyURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

        try pemCert.write(to: pemURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pemURL.path)

        return (caCert, caKey)
    }

    // MARK: - PEM Helpers

    private static func extractPEMContent(_ data: Data, label: String) -> Data? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        let startTag = "-----BEGIN \(label)-----"
        let endTag = "-----END \(label)-----"
        guard let startRange = s.range(of: startTag),
              let endRange = s.range(of: endTag) else { return nil }
        let base64 = s[startRange.upperBound..<endRange.lowerBound]
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        return Data(base64Encoded: base64)
    }

    private static func formatPEM(_ der: Data, label: String) -> Data {
        let b64 = der.base64EncodedString(options: .lineLength64Characters)
        let s = "-----BEGIN \(label)-----\n\(b64)\n-----END \(label)-----\n"
        return Data(s.utf8)
    }
}
