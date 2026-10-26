import CommonCrypto
import Foundation
import Security

public struct CAInfoModel: Codable, Equatable, Sendable {
    public var exists: Bool
    public var subject: String?
    public var fingerprint: String?
    public var sha1: String?
    public var notBefore: String?
    public var notAfter: String?
    public var algorithm: String?

    public init(exists: Bool,
                subject: String? = nil,
                fingerprint: String? = nil,
                sha1: String? = nil,
                notBefore: String? = nil,
                notAfter: String? = nil,
                algorithm: String? = nil) {
        self.exists = exists
        self.subject = subject
        self.fingerprint = fingerprint
        self.sha1 = sha1
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.algorithm = algorithm
    }
}

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

    /// fix/nc-e2e-real: GET /mitm/status caLoaded — a CA is in memory and can sign leaves.
    public var hasIssuer: Bool {
        lock.lock(); defer { lock.unlock() }
        return issuer != nil
    }

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
            // feat/nc-e2e: no reload here — generateCA's reloadCA takes `lock`, which this function already holds
            // (NSLock is not recursive): ensureCA on a home without a CA deadlocked forever (E2E replay run
            // 40264987994: stage 1 hung 600 s in ensureCA; in the tunnel, leafP12 → ensureCA would hang the MitM flow).
            let generated = try Self.generateCA(home: home, reload: false)
            caCert = generated.caCert
            caKey = generated.caKey
            initIssuerLocked(cert: generated.caCert, key: generated.caKey)
            return generated
        } catch {
            return nil
        }
    }

    /// Reload in-memory cached CA certificate and private key.
    public func reloadCA(home: String) {
        lock.lock()
        defer { lock.unlock() }
        caCert = nil
        caKey = nil
        issuer = nil
        if let loaded = Self.loadCA(home: home) {
            caCert = loaded.caCert
            caKey = loaded.caKey
            initIssuerLocked(cert: loaded.caCert, key: loaded.caKey)
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

    /// Returns the root certificate (DER, .cer).
    public static func caCertDER(home: String) -> Data? {
        let pemURL = caDir(home: home).appendingPathComponent("ca.pem")
        guard let pemData = try? Data(contentsOf: pemURL),
              let certDER = extractPEMContent(pemData, label: "CERTIFICATE") else {
            return nil
        }
        return certDER
    }

    /// Returns CA info for UI display.
    public static func caInfo(home: String) -> CAInfoModel {
        guard let certDER = caCertDER(home: home),
              let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return CAInfoModel(exists: false)
        }
        return extractCAInfo(certDER: certDER, cert: cert)
    }

    /// Builds an unsigned configuration profile carrying the root (.mobileconfig).
    public static func mobileConfig(home: String) -> Data? {
        guard let certDER = caCertDER(home: home),
              let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return nil
        }
        var sha256Bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        certDER.withUnsafeBytes { b in
            _ = CC_SHA256(b.baseAddress, CC_LONG(certDER.count), &sha256Bytes)
        }
        let sum = Data(sha256Bytes)
        let u1 = uuidFrom(sum.prefix(16))
        let u2 = uuidFrom(sum.suffix(16))
        let u1_8 = String(u1.prefix(8))
        let u2_8 = String(u2.prefix(8))
        let b64 = certDER.base64EncodedString()

        var name = "Tern MitM CA"
        if let cn = extractCAInfo(certDER: certDER, cert: cert).subject, !cn.isEmpty {
            name = cn
        }
        let escapedName = xmlEscape(name)

        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \t<key>PayloadContent</key>
        \t<array>
        \t\t<dict>
        \t\t\t<key>PayloadCertificateFileName</key>
        \t\t\t<string>tern-ca.cer</string>
        \t\t\t<key>PayloadContent</key>
        \t\t\t<data>\(b64)</data>
        \t\t\t<key>PayloadDescription</key>
        \t\t\t<string>Tern MitM 根证书</string>
        \t\t\t<key>PayloadDisplayName</key>
        \t\t\t<string>\(escapedName)</string>
        \t\t\t<key>PayloadIdentifier</key>
        \t\t\t<string>com.astemo6.mihomo.ca.\(u2_8)</string>
        \t\t\t<key>PayloadType</key>
        \t\t\t<string>com.apple.security.root</string>
        \t\t\t<key>PayloadUUID</key>
        \t\t\t<string>\(u2)</string>
        \t\t\t<key>PayloadVersion</key>
        \t\t\t<integer>1</integer>
        \t\t</dict>
        \t</array>
        \t<key>PayloadDescription</key>
        \t<string>安装后请到 设置 → 通用 → 关于本机 → 证书信任设置 中为该证书开启完全信任。</string>
        \t<key>PayloadDisplayName</key>
        \t<string>\(escapedName)</string>
        \t<key>PayloadIdentifier</key>
        \t<string>com.astemo6.mihomo.ca-profile.\(u1_8)</string>
        \t<key>PayloadRemovalDisallowed</key>
        \t<false/>
        \t<key>PayloadType</key>
        \t<string>Configuration</string>
        \t<key>PayloadUUID</key>
        \t<string>\(u1)</string>
        \t<key>PayloadVersion</key>
        \t<integer>1</integer>
        </dict>
        </plist>

        """
        return Data(xml.utf8)
    }

    /// Exports cert + private key as password protected PKCS#12 (.p12).
    public static func exportP12(home: String, password: String) throws -> Data {
        guard !password.isEmpty else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "请设置导出密码"])
        }
        guard let (caCert, caKey) = loadCA(home: home) else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "请先生成 CA 证书"])
        }
        let caDER = SecCertificateCopyData(caCert) as Data
        return try NCPKCS12Exporter.shared.export(leafDER: caDER, leafKey: caKey, caDER: Data(), password: password)
    }

    /// feat/nc-full-export: decodes + validates a PKCS#12 CA (cert + private key) without touching the CA files.
    /// Returns the PEM bytes `importP12` writes (ca.pem, ca.key). The full export (.conf) validates its p12 with this
    /// before anything is written, then writes the files in one staged step.
    public static func pemPair(fromP12 data: Data, password: String) throws -> (pemCert: Data, pemKey: Data) {
        var rawItems: CFArray?
        let options: [String: Any] = [kSecImportExportPassphrase as String: password]
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &rawItems)
        guard status == errSecSuccess else {
            if status == errSecAuthFailed {
                throw NSError(domain: "TernCA", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "密码错误"])
            }
            throw NSError(domain: "TernCA", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "p12 解析失败：\(status)"])
        }
        guard let list = rawItems as? [[String: Any]],
              let first = list.first,
              let identityRef = first[kSecImportItemIdentity as String] else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "p12 解析失败：未找到有效证书"])
        }
        let identity = identityRef as! SecIdentity
        var certRef: SecCertificate?
        var keyRef: SecKey?
        guard SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess, let cert = certRef,
              SecIdentityCopyPrivateKey(identity, &keyRef) == errSecSuccess, let key = keyRef else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "无法提取证书或私钥"])
        }
        let certDER = SecCertificateCopyData(cert) as Data

        try validateCAPair(cert: cert, certDER: certDER, key: key)

        let pkcs8 = try exportPKCS8(from: key)
        return (formatPEM(certDER, label: "CERTIFICATE"), formatPEM(pkcs8, label: "PRIVATE KEY"))
    }

    /// Imports CA cert + private key from PKCS#12, replacing current CA files.
    public static func importP12(home: String, data: Data, password: String) throws {
        let (pemCert, pemKey) = try pemPair(fromP12: data, password: password)

        let dir = caDir(home: home)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let keyURL = dir.appendingPathComponent("ca.key")
        let pemURL = dir.appendingPathComponent("ca.pem")

        try writeAtomic(url: keyURL, data: pemKey, posixPermissions: 0o600)
        try writeAtomic(url: pemURL, data: pemCert, posixPermissions: 0o644)

        shared.reloadCA(home: home)
    }

    /// Returns test chain (leaf DER, CA DER, hostname) for SecTrust evaluation.
    public static func trustChain(home: String) -> (leafDER: Data, caDER: Data, hostname: String)? {
        guard let (caCert, caKey) = loadCA(home: home) else { return nil }
        let caDER = SecCertificateCopyData(caCert) as Data
        let host = "mitm-trust-check.tern.local"
        do {
            let issuer = try LeafCertIssuer(caCertificate: caCert, caPrivateKey: caKey)
            let leaf = try issuer.issueLeafCertificate(for: host)
            return (leaf.leafCertificateDER, caDER, host)
        } catch {
            return nil
        }
    }

    /// Evaluates CA trust in system store with a signed leaf.
    public static func checkTrust(home: String) -> Bool {
        guard let chain = trustChain(home: home),
              let leaf = SecCertificateCreateWithData(nil, chain.leafDER as CFData),
              let ca = SecCertificateCreateWithData(nil, chain.caDER as CFData) else {
            return false
        }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, chain.hostname as CFString)
        guard SecTrustCreateWithCertificates([leaf, ca] as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            return false
        }
        var cfErr: CFError?
        return SecTrustEvaluateWithError(trust, &cfErr)
    }

    /// Serves profile on ephemeral loopback port for ~3 minutes.
    public static func serveProfile(home: String) throws -> Int {
        try NCCAProfileServer.shared.start(home: home)
    }

    /// Generates a new 10-year ECDSA P-256 root CA in Swift and writes to disk.
    @discardableResult
    /// `reload: false` only from `ensureCA`, which holds `lock` and installs the result itself.
    public static func generateCA(home: String, reload: Bool = true) throws -> (caCert: SecCertificate, caKey: SecKey) {
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

        // 4. Save to files (taking last 32 bytes for private key scalar)
        let pkcs8 = try exportPKCS8(from: caKey)
        let pemKey = formatPEM(pkcs8, label: "PRIVATE KEY")
        let pemCert = formatPEM(certDER, label: "CERTIFICATE")

        let keyURL = dir.appendingPathComponent("ca.key")
        let pemURL = dir.appendingPathComponent("ca.pem")

        try writeAtomic(url: keyURL, data: pemKey, posixPermissions: 0o600)
        try writeAtomic(url: pemURL, data: pemCert, posixPermissions: 0o644)

        if reload { shared.reloadCA(home: home) }

        return (caCert, caKey)
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

    // MARK: - Validation & Export Helpers

    private static func validateCAPair(cert: SecCertificate, certDER: Data, key: SecKey) throws {
        // fix/nc-rsa-ca: EC P-256 (Tern / Go CA) or RSA 2048/3072/4096 (QuanX [mitm] passphrase + p12, other apps).
        guard let attrs = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "CA 私钥类型不支持"])
        }
        let keyType = attrs[kSecAttrKeyType] as? String
        let bits = (attrs[kSecAttrKeySizeInBits] as? Int) ?? (attrs[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
        let isEC = keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && bits == 256
        let isRSA = keyType == (kSecAttrKeyTypeRSA as String) && [2048, 3072, 4096].contains(bits)
        guard isEC || isRSA else {
            throw NSError(domain: "TernCA", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "CA 私钥类型不支持（仅支持 EC P-256 或 RSA 2048/3072/4096）"])
        }
        guard let certPub = SecCertificateCopyKey(cert),
              let keyPub = SecKeyCopyPublicKey(key),
              let certPubExt = SecKeyCopyExternalRepresentation(certPub, nil) as Data?,
              let keyPubExt = SecKeyCopyExternalRepresentation(keyPub, nil) as Data?,
              certPubExt == keyPubExt else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "私钥与证书不匹配"])
        }
        let (isCA, hasKeyUsage, hasCertSign) = inspectCertificateExtensions(certDER: certDER)
        if !isCA {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "该证书不是 CA 证书"])
        }
        if hasKeyUsage && !hasCertSign {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "该 CA 证书不允许签发证书（缺少 keyCertSign）"])
        }
    }

    private static func inspectCertificateExtensions(certDER: Data) -> (isCA: Bool, hasKeyUsage: Bool, hasCertSign: Bool) {
        var i = 0
        let d = [UInt8](certDER)
        guard let (t0, certContent) = derTLV(d, &i), t0 == 0x30 else { return (false, false, false) }
        var j = 0
        let c = Array(certContent)
        guard let (t1, tbsContent) = derTLV(c, &j), t1 == 0x30 else { return (false, false, false) }
        var k = 0
        let t = Array(tbsContent)
        if let (tv, _) = derTLV(t, &k), tv == 0xA0 { /* version */ } else { k = 0 }
        _ = derTLV(t, &k) // serial
        _ = derTLV(t, &k) // sigAlg
        _ = derTLV(t, &k) // issuer
        _ = derTLV(t, &k) // validity
        _ = derTLV(t, &k) // subject
        _ = derTLV(t, &k) // spki

        var isCA = false
        var hasKeyUsage = false
        var hasCertSign = false

        while k < t.count {
            guard let (tTag, tVal) = derTLV(t, &k) else { break }
            if tTag == 0xA3 { // [3] Extensions
                var ei = 0
                let ec = Array(tVal)
                guard let (tSeq, extsSeq) = derTLV(ec, &ei), tSeq == 0x30 else { break }
                var xi = 0
                let xc = Array(extsSeq)
                while xi < xc.count {
                    guard let (txSeq, extSeq) = derTLV(xc, &xi), txSeq == 0x30 else { break }
                    var mi = 0
                    let mc = Array(extSeq)
                    guard let (tOid, oidVal) = derTLV(mc, &mi), tOid == 0x06 else { continue }
                    guard let (tNext, nextVal) = derTLV(mc, &mi) else { continue }
                    let valBytes: [UInt8]
                    if tNext == 0x01 { // critical BOOLEAN
                        guard let (tOct, octVal) = derTLV(mc, &mi), tOct == 0x04 else { continue }
                        valBytes = Array(octVal)
                    } else if tNext == 0x04 {
                        valBytes = Array(nextVal)
                    } else {
                        continue
                    }
                    // basicConstraints: 2.5.29.19 (55 1D 13)
                    if Array(oidVal) == [0x55, 0x1D, 0x13] {
                        var bi = 0
                        if let (tbSeq, bSeq) = derTLV(valBytes, &bi), tbSeq == 0x30 {
                            var ci = 0
                            let bcArray = Array(bSeq)
                            if let (tBool, boolVal) = derTLV(bcArray, &ci), tBool == 0x01 {
                                if let first = boolVal.first, first != 0 {
                                    isCA = true
                                }
                            }
                        }
                    }
                    // keyUsage: 2.5.29.15 (55 1D 0F)
                    if Array(oidVal) == [0x55, 0x1D, 0x0F] {
                        hasKeyUsage = true
                        var ki = 0
                        if let (tBit, bitVal) = derTLV(valBytes, &ki), tBit == 0x03 {
                            let bc = Array(bitVal)
                            if bc.count >= 2 {
                                let bits = bc[1]
                                if (bits & 0x04) != 0 {
                                    hasCertSign = true
                                }
                            }
                        }
                    }
                }
            }
        }
        return (isCA, hasKeyUsage, hasCertSign)
    }

    private static func exportPKCS8(from key: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }
        // fix/nc-rsa-ca: an RSA key exports PKCS#1 — wrap it as PKCS#8 (what loadCA's rsaPKCS1(fromPKCS8:) and Go read).
        if DER.isRSAKey(key) {
            return DER.pkcs8RSA(pkcs1: ext)
        }
        if ext.first == 0x30 {
            return ext
        }
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
        let ecPrivKey = DER.seq(
            DER.integer(bigEndian: Data([0x01])),
            DER.octetString(privScalar),
            DER.explicit(1, DER.bitString(pubPoint))
        )
        let pkcs8 = DER.seq(
            DER.integer(bigEndian: Data([0x00])),
            DER.seq(DER.oid([1, 2, 840, 10045, 2, 1]), DER.oid([1, 2, 840, 10045, 3, 1, 7])),
            DER.octetString(ecPrivKey)
        )
        return pkcs8
    }

    private static func extractCAInfo(certDER: Data, cert: SecCertificate) -> CAInfoModel {
        var sha256Bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        certDER.withUnsafeBytes { b in
            _ = CC_SHA256(b.baseAddress, CC_LONG(certDER.count), &sha256Bytes)
        }
        let fingerprint = colonHex(sha256Bytes)

        var sha1Bytes = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        certDER.withUnsafeBytes { b in
            _ = CC_SHA1(b.baseAddress, CC_LONG(certDER.count), &sha1Bytes)
        }
        let sha1Str = colonHex(sha1Bytes)

        var i = 0
        let d = [UInt8](certDER)
        guard let (t0, certContent) = derTLV(d, &i), t0 == 0x30 else {
            return CAInfoModel(exists: true, fingerprint: fingerprint, sha1: sha1Str)
        }
        var j = 0
        let c = Array(certContent)
        guard let (t1, tbsContent) = derTLV(c, &j), t1 == 0x30 else {
            return CAInfoModel(exists: true, fingerprint: fingerprint, sha1: sha1Str)
        }
        var k = 0
        let t = Array(tbsContent)
        if let (tv, _) = derTLV(t, &k), tv == 0xA0 { /* version */ } else { k = 0 }
        _ = derTLV(t, &k) // serial
        _ = derTLV(t, &k) // sigAlg
        _ = derTLV(t, &k) // issuer

        var notBeforeStr: String?
        var notAfterStr: String?
        if let (tvld, vldContent) = derTLV(t, &k), tvld == 0x30 {
            var vi = 0
            let vc = Array(vldContent)
            if let (tnb, nbContent) = derTLV(vc, &vi),
               let nbDate = parseX509Date(tag: tnb, content: Array(nbContent)) {
                notBeforeStr = formatDateYMD(nbDate)
            }
            if let (tna, naContent) = derTLV(vc, &vi),
               let naDate = parseX509Date(tag: tna, content: Array(naContent)) {
                notAfterStr = formatDateYMD(naDate)
            }
        }

        var subjectCN: String?
        if let (tsubj, subjContent) = derTLV(t, &k), tsubj == 0x30 {
            subjectCN = extractCN(fromSubject: Array(subjContent))
        }
        if subjectCN == nil || subjectCN?.isEmpty == true {
            if let summary = SecCertificateCopySubjectSummary(cert) as String? {
                subjectCN = summary
            }
        }

        var algorithm = "ECDSA P-256"
        if let (tspki, spkiContent) = derTLV(t, &k), tspki == 0x30 {
            var si = 0
            let sc = Array(spkiContent)
            if let (talg, algContent) = derTLV(sc, &si), talg == 0x30 {
                var ai = 0
                let ac = Array(algContent)
                if let (toid, oidContent) = derTLV(ac, &ai), toid == 0x06 {
                    let rsaOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] // 1.2.840.113549.1.1.1
                    if Array(oidContent) == rsaOID {
                        algorithm = "RSA"
                    }
                }
            }
        }

        return CAInfoModel(exists: true,
                           subject: subjectCN,
                           fingerprint: fingerprint,
                           sha1: sha1Str,
                           notBefore: notBeforeStr,
                           notAfter: notAfterStr,
                           algorithm: algorithm)
    }

    private static func parseX509Date(tag: UInt8, content: [UInt8]) -> Date? {
        guard let s = String(bytes: content, encoding: .ascii) else { return nil }
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone(secondsFromGMT: 0)
        if tag == 0x17 { // UTCTime: YYMMDDHHMMSSZ
            df.dateFormat = "yyMMddHHmmss'Z'"
            return df.date(from: s)
        } else if tag == 0x18 { // GeneralizedTime: YYYYMMDDHHMMSSZ
            df.dateFormat = "yyyyMMddHHmmss'Z'"
            return df.date(from: s)
        }
        return nil
    }

    private static func formatDateYMD(_ date: Date) -> String {
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone(secondsFromGMT: 0)
        df.dateFormat = "yyyy-MM-dd"
        return df.string(from: date)
    }

    private static func extractCN(fromSubject bytes: [UInt8]) -> String? {
        var i = 0
        while i < bytes.count {
            guard let (tSet, setContent) = derTLV(bytes, &i) else { break }
            if tSet == 0x31 { // SET
                var j = 0
                let sc = Array(setContent)
                while j < sc.count {
                    guard let (tSeq, seqContent) = derTLV(sc, &j) else { break }
                    if tSeq == 0x30 { // SEQUENCE
                        var m = 0
                        let sqc = Array(seqContent)
                        guard let (tOid, oidContent) = derTLV(sqc, &m), tOid == 0x06 else { continue }
                        guard let (tVal, valContent) = derTLV(sqc, &m) else { continue }
                        // OID 2.5.4.3: 55 04 03
                        if Array(oidContent) == [0x55, 0x04, 0x03] {
                            if tVal == 0x0C || tVal == 0x13 || tVal == 0x16 { // UTF8, Printable, IA5
                                return String(bytes: valContent, encoding: .utf8)
                            }
                        }
                    }
                }
            }
        }
        return nil
    }

    private static func colonHex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    private static func uuidFrom(_ bytes: Data) -> String {
        let hex = bytes.prefix(16).map { String(format: "%02X", $0) }.joined()
        guard hex.count == 32 else { return UUID().uuidString }
        let p1 = hex.prefix(8)
        let p2 = hex.dropFirst(8).prefix(4)
        let p3 = hex.dropFirst(12).prefix(4)
        let p4 = hex.dropFirst(16).prefix(4)
        let p5 = hex.dropFirst(20).prefix(12)
        return "\(p1)-\(p2)-\(p3)-\(p4)-\(p5)"
    }

    private static func xmlEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
    }

    private static func writeAtomic(url: URL, data: Data, posixPermissions: Int) throws {
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: posixPermissions], ofItemAtPath: url.path)
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
