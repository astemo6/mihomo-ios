import Foundation
import Security

/// B7 draft — leaf certificate issuance for native MitM TLS termination.
/// Builds the TBSCertificate as hand-rolled DER, signs it with
/// `SecKeyCreateSignature`, and assembles the Certificate structure.
///
/// Semantics mirror Go (`bridge/mitm/ca.go`, `CA.LeafWithNames`):
///   - ECDSA P-256; ONE shared leaf keypair signs nothing — it is
///     the subject key of every leaf cert; the CA key is the issuer key.
///   - Serial: uniform random in [0, 2^120).
///   - Validity: NotBefore = now - 48 h, NotAfter = +1 year (365 days).
///   - Subject: CN = host, O = "Tern MitM". Issuer name is copied byte-exact
///     from the CA certificate's subject.
///   - Extensions: BasicConstraints CA=false (critical), KeyUsage
///     digitalSignature (critical), ExtKeyUsage serverAuth, SAN with the
///     host (DNS or IP), a wildcard for sibling subdomains when the host
///     has >= 2 dots, plus extra names (dedup, cap 64).
///   - Signature algorithm: ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2) for an EC P-256 CA; for an RSA CA
///     (gap C7, a p12 imported from another app — astemo6/Muse NativeCore) sha256WithRSAEncryption
///     (1.2.840.113549.1.1.11, PKCS#1 v1.5). The leaf's own key stays EC P-256 either way (a valid chain; ECDHE-ECDSA
///     handshakes stay cheap), like Go's shared leaf key.

public enum LeafCertError: Error, LocalizedError {
    case invalidCAPrivateKey
    case invalidCACertificate
    case keyGenerationFailed
    case signingFailed(CFError?)
    case malformedCACertificate
    case invalidHostname

    public var errorDescription: String? {
        switch self {
        case .invalidCAPrivateKey: return "CA private key is neither EC P-256 nor RSA (≥ 2048 bits)"
        case .invalidCACertificate: return "CA certificate cannot sign certificates"
        case .keyGenerationFailed: return "Failed to generate the shared leaf key"
        case .signingFailed(let e): return "SecKeyCreateSignature failed: \(e?.localizedDescription ?? "unknown")"
        case .malformedCACertificate: return "CA certificate DER could not be walked"
        case .invalidHostname: return "Hostname is empty"
        }
    }
}

public protocol PKCS12Exporting {
    func export(leafDER: Data, leafKey: SecKey, caDER: Data, password: String) throws -> Data
}

public struct LeafCertResult {
    public let leafCertificateDER: Data
    public let chainDER: [Data]            // [leaf, CA]
    public let leafPrivateKey: SecKey       // the shared leaf key (Go: ca.leafKey)
    public let pkcs12Data: Data?            // exported PKCS#12
    public let hostname: String
    public let notBefore: Date
    public let notAfter: Date
}

public struct LeafCertConfig {
    public var validityDays: Int = 365          // 1 year
    public var notBeforeOffset: TimeInterval = -48 * 3600
    public var addWildcardSAN: Bool = true
    public var maxExtraDNSNames: Int = 64
    public init() {}
}

public final class LeafCertIssuer {
    private let caCertificateDER: Data
    private let caPrivateKey: SecKey
    /// gap C7: the CA key is RSA (sha256WithRSAEncryption signatures)
    private let caIsRSA: Bool
    private let issuerNameDER: Data             // CA subject, raw TLV from the CA cert
    /// fix/nc-rsa-ca: the CA's SubjectKeyIdentifier, carried as the leaf's AuthorityKeyIdentifier — RSA CA only
    /// (an EC CA leaf stays byte-identical: no AKI, as before).
    private let authorityKeyID: Data?
    private let leafPrivateKey: SecKey          // shared across all hosts (Go semantics)
    private let leafPublicKeyDER: Data          // SubjectPublicKeyInfo, prebuilt once
    private let config: LeafCertConfig
    private let pkcs12Exporter: PKCS12Exporting?
    private let pkcs12Password: String?

    public init(caCertificate: SecCertificate,
                caPrivateKey: SecKey,
                config: LeafCertConfig = LeafCertConfig(),
                pkcs12Exporter: PKCS12Exporting? = NCPKCS12Exporter.shared,
                pkcs12Password: String? = "tern") throws {
        let caDER = SecCertificateCopyData(caCertificate) as Data
        guard let issuerName = try? Self.extractSubjectName(fromCertificateDER: caDER) else {
            throw LeafCertError.malformedCACertificate
        }
        guard let attrs = SecKeyCopyAttributes(caPrivateKey) as? [CFString: Any] else { throw LeafCertError.invalidCAPrivateKey }
        let keyType = attrs[kSecAttrKeyType] as? String
        let bits = (attrs[kSecAttrKeySizeInBits] as? Int) ?? (attrs[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
        let isEC = keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && bits == 256
        let isRSA = keyType == (kSecAttrKeyTypeRSA as String) && bits >= 2048
        guard isEC || isRSA,
              SecKeyIsAlgorithmSupported(caPrivateKey, .sign, isRSA ? .rsaSignatureMessagePKCS1v15SHA256 : .ecdsaSignatureMessageX962SHA256) else {
            throw LeafCertError.invalidCAPrivateKey
        }
        // One shared leaf keypair, generated once (Go: ca.leafKey).
        var err: Unmanaged<CFError>?
        guard let leafKey = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ] as CFDictionary, &err) else { throw LeafCertError.keyGenerationFailed }
        guard let leafPub = SecKeyCopyPublicKey(leafKey),
              let point = SecKeyCopyExternalRepresentation(leafPub, &err) as Data? else {
            throw LeafCertError.keyGenerationFailed
        }
        self.caCertificateDER = caDER
        self.caPrivateKey = caPrivateKey
        self.caIsRSA = isRSA
        self.issuerNameDER = issuerName
        self.authorityKeyID = isRSA ? Self.extractSubjectKeyIdentifier(fromCertificateDER: caDER) : nil
        self.leafPrivateKey = leafKey
        self.leafPublicKeyDER = DER.spkiECP256(point: point)
        self.config = config
        self.pkcs12Exporter = pkcs12Exporter
        self.pkcs12Password = pkcs12Password
    }

    public func issueLeafCertificate(for hostname: String,
                                     extraDNSNames: [String] = []) throws -> LeafCertResult {
        let host = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !host.isEmpty else { throw LeafCertError.invalidHostname }

        let now = Date()
        let notBefore = now.addingTimeInterval(config.notBeforeOffset)
        let notAfter = now.addingTimeInterval(TimeInterval(config.validityDays) * 24 * 3600)

        var dnsNames: [String] = []
        var ips: [Data] = []
        if let ip = Self.parseIP(host) {
            ips.append(ip)
        } else {
            dnsNames.append(host)
            if config.addWildcardSAN,
               let firstDot = host.firstIndex(of: "."),
               host.filter({ $0 == "." }).count >= 2 {
                dnsNames.append("*" + host[firstDot...])
            }
        }
        var seen = Set(dnsNames)
        for raw in extraDNSNames {
            let n = raw.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            if n != host, !seen.contains(n), seen.count < config.maxExtraDNSNames {
                dnsNames.append(n); seen.insert(n)
            }
        }

        let tbs = DER.tbsCertificate(
            serial: try Self.randomSerial(),
            issuerNameDER: issuerNameDER,
            subjectCN: host,
            notBefore: notBefore, notAfter: notAfter,
            spkiDER: leafPublicKeyDER,
            dnsNames: dnsNames, ips: ips,
            signatureAlgorithm: caIsRSA ? DER.algIdRSASHA256() : DER.algIdECDSA(),
            authorityKeyID: authorityKeyID)

        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            caPrivateKey, caIsRSA ? .rsaSignatureMessagePKCS1v15SHA256 : .ecdsaSignatureMessageX962SHA256, tbs as CFData, &err) as Data? else {
            throw LeafCertError.signingFailed(err?.takeRetainedValue())
        }
        let certDER = caIsRSA ? DER.certificate(tbs: tbs, rsaSignature: sig) : DER.certificate(tbs: tbs, signatureX962: sig)

        var p12: Data? = nil
        if let exporter = pkcs12Exporter, let pw = pkcs12Password {
            p12 = try exporter.export(leafDER: certDER, leafKey: leafPrivateKey,
                                      caDER: caCertificateDER, password: pw)
        }
        return LeafCertResult(leafCertificateDER: certDER,
                              chainDER: [certDER, caCertificateDER],
                              leafPrivateKey: leafPrivateKey,
                              pkcs12Data: p12,
                              hostname: host,
                              notBefore: notBefore, notAfter: notAfter)
    }

    // MARK: - Helpers

    private static func randomSerial() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 15)   // < 2^120 once top bit cleared
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw LeafCertError.keyGenerationFailed
        }
        bytes[0] &= 0x7F   // positive, minimal-length DER INTEGER
        return Data(bytes)
    }

    private static func parseIP(_ host: String) -> Data? {
        var a4 = in_addr()
        if inet_pton(AF_INET, host, &a4) == 1 { return Data(bytes: &a4, count: 4) }
        var a6 = in6_addr()
        if inet_pton(AF_INET6, host, &a6) == 1 { return Data(bytes: &a6, count: 16) }
        return nil
    }

    /// Walk a DER certificate far enough to copy out the issuer Name TLV:
    /// Certificate SEQ → TBS SEQ → [0] version?, serial, signature, issuer.
    private static func extractSubjectName(fromCertificateDER der: Data) throws -> Data {
        var r = DERReader(data: der)
        guard let certBody = try? r.readTLV(tag: 0x30) else { throw LeafCertError.malformedCACertificate }
        var t = DERReader(data: certBody)
        guard let tbsBody = try? t.readTLV(tag: 0x30) else { throw LeafCertError.malformedCACertificate }
        var b = DERReader(data: tbsBody)
        if b.peekTag() == 0xA0 { _ = try? b.readAnyTLV() }        // version [0]
        _ = try? b.readAnyTLV()                                    // serial
        _ = try? b.readAnyTLV()                                    // signature alg
        guard let name = try? b.readRawTLV() else { throw LeafCertError.malformedCACertificate }
        return name
    }

    /// fix/nc-rsa-ca: the keyIdentifier of the CA's SubjectKeyIdentifier extension (2.5.29.14), nil when absent.
    static func extractSubjectKeyIdentifier(fromCertificateDER der: Data) -> Data? {
        var r = DERReader(data: der)
        guard let certBody = try? r.readTLV(tag: 0x30) else { return nil }
        var t = DERReader(data: certBody)
        guard let tbsBody = try? t.readTLV(tag: 0x30) else { return nil }
        var b = DERReader(data: tbsBody)
        if b.peekTag() == 0xA0 { _ = try? b.readAnyTLV() }       // version [0]
        for _ in 0..<6 {                                          // serial, sigAlg, issuer, validity, subject, spki
            guard (try? b.readAnyTLV()) != nil else { return nil }
        }
        while let tag = b.peekTag() {
            guard tag == 0xA3 else {
                guard (try? b.readAnyTLV()) != nil else { return nil }
                continue
            }
            guard let wrap = try? b.readTLV(tag: 0xA3) else { return nil }
            var w = DERReader(data: wrap)
            guard let exts = try? w.readTLV(tag: 0x30) else { return nil }
            var e = DERReader(data: exts)
            while e.peekTag() == 0x30 {
                guard let ext = try? e.readTLV(tag: 0x30) else { return nil }
                var x = DERReader(data: ext)
                guard let oid = try? x.readTLV(tag: 0x06) else { continue }
                if x.peekTag() == 0x01 { _ = try? x.readAnyTLV() }  // critical
                guard let val = try? x.readTLV(tag: 0x04) else { continue }
                if oid == Data([0x55, 0x1D, 0x0E]) {
                    var v = DERReader(data: val)
                    guard let ski = try? v.readTLV(tag: 0x04), !ski.isEmpty else { return nil }
                    return ski
                }
            }
            return nil
        }
        return nil
    }
}

// MARK: - Minimal DER writer (just what an ECDSA certificate needs)

public enum DER {
    public static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    public static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    public static func seq(_ parts: Data...) -> Data { tlv(0x30, parts.reduce(Data(), +)) }
    public static func set(_ parts: Data...) -> Data { tlv(0x31, parts.reduce(Data(), +)) }
    public static func octetString(_ d: Data) -> Data { tlv(0x04, d) }
    public static func utf8(_ s: String) -> Data { tlv(0x0C, Data(s.utf8)) }
    public static func ia5(_ s: String) -> Data { tlv(0x16, Data(s.utf8)) }
    public static func boolean(_ v: Bool) -> Data { tlv(0x01, Data([v ? 0xFF : 0x00])) }

    public static func integer(bigEndian raw: Data) -> Data {
        var b = raw
        while b.count > 1, b.first == 0, (b[b.startIndex + 1] & 0x80) == 0 { b.removeFirst() }
        if let f = b.first, (f & 0x80) != 0 { b.insert(0, at: 0) }
        return tlv(0x02, b)
    }

    public static func oid(_ arcs: [Int]) -> Data {
        var content = Data([UInt8(arcs[0] * 40 + arcs[1])])
        for arc in arcs.dropFirst(2) {
            var stack: [UInt8] = [UInt8(arc & 0x7F)]
            var v = arc >> 7
            while v > 0 { stack.insert(UInt8(v & 0x7F) | 0x80, at: 0); v >>= 7 }
            content.append(contentsOf: stack)
        }
        return tlv(0x06, content)
    }

    public static func utcTime(_ date: Date) -> Data {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(secondsFromGMT: 0)!
        let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let s = String(format: "%02d%02d%02d%02d%02d%02dZ",
                       (c.year ?? 1970) % 100, c.month ?? 1, c.day ?? 1,
                       c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
        return tlv(0x17, Data(s.utf8))
    }

    public static func bitString(_ bytes: Data, unusedBits: UInt8 = 0) -> Data {
        tlv(0x03, Data([unusedBits]) + bytes)
    }

    public static func explicit(_ n: UInt8, _ content: Data) -> Data { tlv(0xA0 + n, content) }

    // OIDs
    public static let oidECDSAWithSHA256: [Int] = [1, 2, 840, 10045, 4, 3, 2]
    public static let oidECPublicKey: [Int] = [1, 2, 840, 10045, 2, 1]
    public static let oidPrime256v1: [Int] = [1, 2, 840, 10045, 3, 1, 7]
    public static let oidCN: [Int] = [2, 5, 4, 3]
    public static let oidO: [Int] = [2, 5, 4, 10]
    public static let oidBasicConstraints: [Int] = [2, 5, 29, 19]
    public static let oidKeyUsage: [Int] = [2, 5, 29, 15]
    public static let oidExtKeyUsage: [Int] = [2, 5, 29, 37]
    public static let oidSAN: [Int] = [2, 5, 29, 17]
    public static let oidServerAuth: [Int] = [1, 3, 6, 1, 5, 5, 7, 3, 1]

    public static func algIdECDSA() -> Data { seq(oid(oidECDSAWithSHA256)) }
    /// sha256WithRSAEncryption with its NULL parameters (RFC 4055)
    public static let oidSHA256WithRSA: [Int] = [1, 2, 840, 113549, 1, 1, 11]
    public static func algIdRSASHA256() -> Data { seq(oid(oidSHA256WithRSA), Data([0x05, 0x00])) }
    public static let oidRSAEncryption: [Int] = [1, 2, 840, 113549, 1, 1, 1]
    public static let oidAuthorityKeyIdentifier: [Int] = [2, 5, 29, 35]
    public static let oidSubjectKeyIdentifier: [Int] = [2, 5, 29, 14]

    /// fix/nc-rsa-ca: true for an RSA SecKey (its external representation is PKCS#1, not X9.63).
    public static func isRSAKey(_ key: SecKey) -> Bool {
        guard let attrs = SecKeyCopyAttributes(key) as? [CFString: Any] else { return false }
        return (attrs[kSecAttrKeyType] as? String) == (kSecAttrKeyTypeRSA as String)
    }

    /// fix/nc-rsa-ca: PKCS#8 PrivateKeyInfo { 0, { rsaEncryption, NULL }, OCTET STRING { RSAPrivateKey } } around the
    /// PKCS#1 DER SecKeyCopyExternalRepresentation returns for an RSA private key.
    public static func pkcs8RSA(pkcs1: Data) -> Data {
        seq(integer(bigEndian: Data([0x00])), seq(oid(oidRSAEncryption), Data([0x05, 0x00])), octetString(pkcs1))
    }

    public static func spkiECP256(point: Data) -> Data {
        seq(seq(oid(oidECPublicKey), oid(oidPrime256v1)), bitString(point))
    }

    public static func name(cn: String) -> Data {
        seq(set(seq(oid(oidCN), utf8(cn))),
            set(seq(oid(oidO), utf8("Tern MitM"))))
    }

    public static func extn(_ oidArcs: [Int], critical: Bool, valueDER: Data) -> Data {
        if critical { return seq(oid(oidArcs), boolean(true), octetString(valueDER)) }
        return seq(oid(oidArcs), octetString(valueDER))
    }

    public static func tbsCertificate(serial: Data, issuerNameDER: Data, subjectCN: String,
                                      notBefore: Date, notAfter: Date, spkiDER: Data,
                                      dnsNames: [String], ips: [Data], signatureAlgorithm: Data = algIdECDSA(),
                                      authorityKeyID: Data? = nil) -> Data {
        var exts: [Data] = []
        exts.append(extn(oidBasicConstraints, critical: true, valueDER: seq()))
        // KeyUsage digitalSignature: bit 0 set → first byte 0x80, 7 unused bits.
        exts.append(extn(oidKeyUsage, critical: true, valueDER: bitString(Data([0x80]), unusedBits: 7)))
        exts.append(extn(oidExtKeyUsage, critical: false, valueDER: seq(oid(oidServerAuth))))
        if !dnsNames.isEmpty || !ips.isEmpty {
            var names = Data()
            for d in dnsNames { names.append(tlv(0x82, Data(d.utf8))) }        // dNSName [2] IA5
            for ip in ips { names.append(tlv(0x87, ip)) }                      // iPAddress [7]
            exts.append(extn(oidSAN, critical: false, valueDER: seq(names)))
        }
        // AuthorityKeyIdentifier { [0] keyIdentifier } = the CA's SKI (RSA CA leaves only; nil keeps EC leaves as before).
        if let aki = authorityKeyID {
            exts.append(extn(oidAuthorityKeyIdentifier, critical: false, valueDER: seq(tlv(0x80, aki))))
        }
        let extensions = explicit(3, seq(exts.reduce(Data(), +)))
        return seq(
            explicit(0, integer(bigEndian: Data([2]))),                        // version v3
            integer(bigEndian: serial),
            signatureAlgorithm,
            issuerNameDER,
            seq(utcTime(notBefore), utcTime(notAfter)),
            name(cn: subjectCN),
            spkiDER,
            extensions)
    }

    public static func certificate(tbs: Data, signatureX962 x962: Data) -> Data {
        // fix/nc-rsa-ca: SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256) already returns the DER
        // ECDSA-Sig-Value SEQUENCE { r, s }. Splitting that blob in half as if it were raw r||s produced a signature that
        // never verifies (every Swift-generated EC CA self-signature and EC-signed leaf; NativeCoreRSACATests run
        // 40277857806: caSelfSigVerifies=false, SecTrust "Unable to build chain"). Use it as-is; raw r||s keeps the old path.
        var probe = DERReader(data: x962)
        if (try? probe.readTLV(tag: 0x30)) != nil, probe.offset == x962.count {
            return seq(tbs, algIdECDSA(), bitString(x962))
        }
        let half = x962.count / 2
        let sig = seq(integer(bigEndian: Data(x962.prefix(half))),
                      integer(bigEndian: Data(x962.suffix(half))))
        return seq(tbs, algIdECDSA(), bitString(sig))
    }

    /// gap C7: a certificate signed by an RSA CA (PKCS#1 v1.5 signature bytes as SecKeyCreateSignature returns them).
    public static func certificate(tbs: Data, rsaSignature: Data) -> Data {
        seq(tbs, algIdRSASHA256(), bitString(rsaSignature))
    }
}

// MARK: - Minimal DER reader (only for walking the CA cert)

public struct DERReader {
    public let data: Data
    public var offset: Int = 0

    public init(data: Data) { self.data = data }

    public func peekTag() -> UInt8? {
        offset < data.count ? data[data.startIndex + offset] : nil
    }

    private mutating func readLength() throws -> Int {
        guard offset < data.count else { throw LeafCertError.malformedCACertificate }
        let first = data[data.startIndex + offset]; offset += 1
        if first < 0x80 { return Int(first) }
        let n = Int(first & 0x7F)
        guard n >= 1, n <= 4, offset + n <= data.count else { throw LeafCertError.malformedCACertificate }
        var v = 0
        for _ in 0..<n { v = (v << 8) | Int(data[data.startIndex + offset]); offset += 1 }
        return v
    }

    public mutating func readTLV(tag: UInt8) throws -> Data {
        guard peekTag() == tag else { throw LeafCertError.malformedCACertificate }
        offset += 1
        let len = try readLength()
        guard offset + len <= data.count else { throw LeafCertError.malformedCACertificate }
        defer { offset += len }
        return data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + len))
    }

    public mutating func readRawTLV() throws -> Data {
        let start = offset
        guard peekTag() != nil else { throw LeafCertError.malformedCACertificate }
        offset += 1
        let len = try readLength()
        guard offset + len <= data.count else { throw LeafCertError.malformedCACertificate }
        offset += len
        return data.subdata(in: (data.startIndex + start)..<(data.startIndex + offset))
    }

    public mutating func readAnyTLV() throws {
        _ = try readRawTLV()
    }
}
