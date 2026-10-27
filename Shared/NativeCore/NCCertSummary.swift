import Foundation
import Security

/// fix/nc-tls-scripts (fix-tls-c): a short, secret-free description of a server certificate chain and of why SecTrust
/// rejected it. Used by NCStream when a verification-on TLS connect fails (the `[delay]` / connect error then says
/// "verify on: <reason> · chain …" instead of a bare `-9808: bad certificate format`) and by the E2E node-tls row.
///
/// Why: E2E 40543432526 showed 17/33 SelfBuild nodes failing with `tls · -9808` while the runner log had boringssl
/// `CERTIFICATE_VERIFY_FAILED` (ssl/handshake.cc:397, the custom verify callback said no) for each of them — a trust
/// decision, not a parse error — but nothing in our own output said whether verification was on or what the chain was.
/// No host names, subjects or addresses are printed: quoted names in SecTrust's text are replaced by “<cert>”.
/// 需同步 feat/nc-kernel.
enum NCCertSummary {
    struct Leaf: Equatable {
        /// "RSA-2048", "EC-256", "other" (SecCertificateCopyKey gives nil for Ed25519 / unknown algorithms).
        var key: String
        var selfSigned: Bool
        var notBefore: Date?
        var notAfter: Date?
    }

    static func leaf(_ cert: SecCertificate) -> Leaf {
        var key = "other"
        if let k = SecCertificateCopyKey(cert), let a = SecKeyCopyAttributes(k) as? [String: Any] {
            let type = a[kSecAttrKeyType as String] as? String ?? ""
            let bits = (a[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue ?? 0
            if type == (kSecAttrKeyTypeRSA as String) { key = "RSA-\(bits)" }
            else if type == (kSecAttrKeyTypeECSECPrimeRandom as String) { key = "EC-\(bits)" }
        }
        let subj = SecCertificateCopyNormalizedSubjectSequence(cert) as Data?
        let iss = SecCertificateCopyNormalizedIssuerSequence(cert) as Data?
        let v = validity(der: SecCertificateCopyData(cert) as Data)
        return Leaf(key: key, selfSigned: subj != nil && subj == iss, notBefore: v?.notBefore, notAfter: v?.notAfter)
    }

    /// "chain 1, leaf RSA-2048 self-signed, valid 2025-03-01…2026-03-01, expired".
    static func describe(chain: [SecCertificate], now: Date = Date()) -> String {
        guard let first = chain.first else { return "chain 0, no certificate" }
        let l = leaf(first)
        var s = "chain \(chain.count), leaf \(l.key)\(l.selfSigned ? " self-signed" : "")"
        if let a = l.notBefore, let b = l.notAfter {
            s += ", valid \(day(a))…\(day(b))"
            if now > b { s += ", expired" } else if now < a { s += ", not yet valid" }
        }
        return s
    }

    /// The SecTrust error text with quoted certificate / host names replaced (“x.example.com” → “<cert>”).
    static func maskTrustError(_ s: String) -> String {
        var out = s
        for (open, close) in [("\u{201C}", "\u{201D}"), ("\"", "\""), ("\u{300C}", "\u{300D}")] {
            var result = ""
            var rest = Substring(out)
            while let a = rest.range(of: open) {
                result += rest[..<a.upperBound]
                let after = rest[a.upperBound...]
                guard let b = after.range(of: close) else { rest = after; break }
                result += "<cert>" + close
                rest = after[b.upperBound...]
            }
            out = result + rest
        }
        return String(out.prefix(160))
    }

    /// One line for a rejected chain: SecTrust's reason (masked) and the chain summary.
    static func trustFailure(trust: SecTrust, error: CFError?) -> String {
        let reason = error.map { maskTrustError(($0 as Error).localizedDescription) } ?? "not trusted"
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        return "\(reason) · \(describe(chain: chain))"
    }

    // MARK: - X.509 validity (TBSCertificate.validity)

    /// notBefore / notAfter of a DER certificate: Certificate ::= SEQ { tbs SEQ { [0] version?, serial, sigAlg, issuer,
    /// validity SEQ { time, time }, … } }. nil when the encoding is not what X.509 says.
    static func validity(der: Data) -> (notBefore: Date, notAfter: Date)? {
        let b = [UInt8](der)
        var i = 0
        guard let cert = tlv(b, &i), cert.tag == 0x30 else { return nil }
        var j = cert.start
        guard let tbs = tlv(b, &j), tbs.tag == 0x30 else { return nil }
        var k = tbs.start
        guard var el = tlv(b, &k) else { return nil }
        if el.tag == 0xA0 { guard let n = tlv(b, &k) else { return nil }; el = n } // explicit version
        guard el.tag == 0x02 else { return nil }                                   // serial
        guard let alg = tlv(b, &k), alg.tag == 0x30 else { return nil }    // signature algorithm
        guard let iss = tlv(b, &k), iss.tag == 0x30 else { return nil }    // issuer
        guard let val = tlv(b, &k), val.tag == 0x30 else { return nil }
        var m = val.start
        guard let t1 = tlv(b, &m), let t2 = tlv(b, &m),
              let a = x509Time(tag: t1.tag, b[t1.start..<t1.end]), let z = x509Time(tag: t2.tag, b[t2.start..<t2.end]) else { return nil }
        return (a, z)
    }

    private struct TLV { var tag: UInt8; var start: Int; var end: Int }

    /// Reads one TLV at `i` (advancing `i` past it); content is b[start..<end].
    private static func tlv(_ b: [UInt8], _ i: inout Int) -> TLV? {
        guard i + 2 <= b.count else { return nil }
        let tag = b[i]
        var len = Int(b[i + 1])
        var p = i + 2
        if len & 0x80 != 0 {
            let n = len & 0x7F
            guard n >= 1, n <= 4, p + n <= b.count else { return nil }
            len = 0
            for _ in 0..<n { len = (len << 8) | Int(b[p]); p += 1 }
        }
        guard p + len <= b.count else { return nil }
        i = p + len
        return TLV(tag: tag, start: p, end: p + len)
    }

    private static func x509Time(tag: UInt8, _ c: ArraySlice<UInt8>) -> Date? {
        guard let s = String(bytes: c, encoding: .ascii) else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case 0x17: f.dateFormat = s.count == 13 ? "yyMMddHHmmss'Z'" : "yyMMddHHmm'Z'"   // UTCTime
        case 0x18: f.dateFormat = "yyyyMMddHHmmss'Z'"                                  // GeneralizedTime
        default: return nil
        }
        guard let d = f.date(from: s) else { return nil }
        // RFC 5280 §4.1.2.5.1: UTCTime YY ≥ 50 is 19YY. DateFormatter's two-digit pivot is not that rule.
        if tag == 0x17, let yy = Int(s.prefix(2)) {
            let year = Calendar(identifier: .gregorian).dateComponents(in: TimeZone(identifier: "UTC")!, from: d).year ?? 0
            let want = yy >= 50 ? 1900 + yy : 2000 + yy
            if year != want {
                return Calendar(identifier: .gregorian).date(byAdding: .year, value: want - year, to: d)
            }
        }
        return d
    }

    private static func day(_ d: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: d)
    }
}
