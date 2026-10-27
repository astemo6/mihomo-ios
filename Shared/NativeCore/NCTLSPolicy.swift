import Foundation

/// fix/nc-tls-scripts: one reading of a node's "skip certificate verification" switch for every TLS layer
/// (Network.framework sec_protocol verify block, the Swift TLS 1.3 / 1.2 client, QUIC transports).
///
/// Before, every dial read `fields["skip-cert-verify"]?.bool`, which is true only for a JSON boolean. A provider
/// whose cached body carries the switch as a string ("true", quoted YAML), a number (1) or under its share-link /
/// Loon / v2rayN spellings (`allow-insecure`, `allowInsecure`) verified the certificate anyway — device build506:
/// self-built nodes with self-signed / expired certificates failed with `tls · -9808` / `-9814`. 需同步 feat/nc-kernel.
extension NCProxy {
    /// skip-cert-verify in any of its accepted spellings and value types. `insecure` is NOT read here: hysteria2 /
    /// tuic parsers already map their `insecure` to skip-cert-verify, and for other types it can mean something else.
    var skipCertVerify: Bool {
        for key in ["skip-cert-verify", "allow-insecure", "allowInsecure", "skip_cert_verify"] {
            if let v = fields[key], let b = Self.truthy(v) { return b }
        }
        return false
    }

    static func truthy(_ v: NCJSONValue) -> Bool? {
        switch v {
        case .bool(let b): return b
        case .number(let n): return n != 0
        case .string(let s):
            switch s.trimmingCharacters(in: .whitespaces).lowercased() {
            case "true", "1", "yes", "on": return true
            case "false", "0", "no", "off", "": return false
            default: return nil
            }
        default: return nil
        }
    }
}
