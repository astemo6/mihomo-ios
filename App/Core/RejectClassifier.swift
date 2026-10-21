import Foundation

/// Device report 2026-10-21 (「为什么有好多dns被拦截了」): the DNS 日志 拦截 tab tallies REJECT *connections*, and most
/// of them were the QUIC fallback rule `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT` — HTTP/3 refused so the app
/// retries over TCP, nothing is actually blocked. This tells those apart from real ad / privacy blocks and turns the
/// core's rule text into something a person can read.
///
/// Forms recognised (mihomo logs a matched rule as `RuleType(payload)`, see rules/logic/logic.go Payload()):
///   AND(((Network,udp) && (DstPort,443)))                                   memtune.go UDPFallbackRule
///   AND(((Network,udp) && (DstPort,443) && (NOT,(!(InType,INNER)))))        mitm.QUICBlockAllRule (阻止 QUIC: 始终)
///   AND(((Network,udp) && (DstPort,443/8443) && (RuleSet,__mitm_hosts)…))  MitM hosts' QUIC
/// and the config spellings users import: AND,((NETWORK,UDP),(DST-PORT,443)), Surge AND,((PROTOCOL,UDP),(DEST-PORT,443)),
/// PROTOCOL,QUIC, and a bare Network(udp) rule hit by a UDP connection to port 443.
enum RejectClassifier {
    /// True when a REJECT hit is a QUIC (HTTP/3) refusal: apps fall back to TCP, access is not affected.
    /// - rule: the matched rule as logged (`AND(((Network,udp) && (DstPort,443)))`) or as written in a profile.
    /// - network: "TCP" / "UDP" from the log line prefix, when known.
    /// - port: destination port of the connection, when known.
    static func isQUIC(rule: String, network: String = "", port: Int? = nil) -> Bool {
        let n = normalise(rule)
        if n.contains("PROTOCOL,QUIC") || n.contains("PROTOCOL(QUIC)") { return true }
        let udp = network.uppercased() == "UDP"
        // A bare UDP rule only counts when the connection itself was UDP to 443 (otherwise it blocks all UDP).
        if n == "NETWORK(UDP)" || n == "NETWORK,UDP" { return udp && port == 443 }
        guard n.hasPrefix("AND") else { return false }
        guard n.contains("(NETWORK,UDP)"), !n.contains("!(NETWORK,UDP)"), !n.contains("NOT,((NETWORK,UDP)") else { return false }
        guard let ports = dstPorts(n) else { return false }
        return covers(ports, 443)
    }

    /// The MitM-hosts variant (QUIC to hosts whose HTTPS is decrypted), for a slightly more specific subtitle.
    static func isMitMQUIC(rule: String) -> Bool {
        normalise(rule).contains("RULESET,__MITM_HOSTS")
    }

    /// Short readable label for a REJECT hit's rule: 「UDP 443（QUIC）」 for QUIC refusals, 「域名后缀 · ads.example.com」
    /// / 「规则集 · ads」 for the common rule types, the raw text otherwise.
    static func friendlyRule(_ rule: String, network: String = "", port: Int? = nil) -> String {
        if isQUIC(rule: rule, network: network, port: port) {
            return isMitMQUIC(rule: rule) ? String(localized: "UDP 443（QUIC）· MitM 主机") : String(localized: "UDP 443（QUIC）")
        }
        let r = rule.trimmingCharacters(in: .whitespaces)
        guard let open = r.firstIndex(of: "("), r.hasSuffix(")") else {
            if r.uppercased() == "MATCH" { return String(localized: "兜底规则") }
            return r
        }
        let type = String(r[..<open])
        let payload = String(r[r.index(after: open)..<r.index(before: r.endIndex)])
        guard !payload.isEmpty, let label = label(type, payload) else { return r }
        return label
    }

    private static func label(_ type: String, _ p: String) -> String? {
        switch type.uppercased().replacingOccurrences(of: "-", with: "") {
        case "DOMAIN": return String(localized: "域名 · \(p)")
        case "DOMAINSUFFIX": return String(localized: "域名后缀 · \(p)")
        case "DOMAINKEYWORD": return String(localized: "域名关键词 · \(p)")
        case "DOMAINREGEX", "DOMAINWILDCARD": return String(localized: "域名匹配 · \(p)")
        case "RULESET": return String(localized: "规则集 · \(p)")
        case "GEOSITE": return "GeoSite · \(p)"
        case "GEOIP": return "GeoIP · \(p)"
        case "IPCIDR", "IPCIDR6", "IPSUFFIX": return String(localized: "IP 段 · \(p)")
        case "IPASN": return "ASN · \(p)"
        default: return nil
        }
    }

    // MARK: helpers

    /// Upper-case, no spaces, one spelling per condition (DST-PORT / DEST-PORT → DSTPORT, PROTOCOL,UDP → NETWORK,UDP).
    static func normalise(_ rule: String) -> String {
        var n = rule.uppercased().replacingOccurrences(of: " ", with: "")
        for (a, b) in [("DST-PORT", "DSTPORT"), ("DEST-PORT", "DSTPORT"), ("RULE-SET", "RULESET"), ("IN-TYPE", "INTYPE"),
                       ("(PROTOCOL,UDP)", "(NETWORK,UDP)"), ("(PROTOCOL,TCP)", "(NETWORK,TCP)")] {
            n = n.replacingOccurrences(of: a, with: b)
        }
        return n
    }

    private static let portRE = try! NSRegularExpression(pattern: #"\(DSTPORT,([0-9/,\-]+)\)"#)

    /// Port ranges from every (DSTPORT,…) condition: "443", "443/8443", "400-500".
    private static func dstPorts(_ n: String) -> [ClosedRange<Int>]? {
        let ns = n as NSString
        var out: [ClosedRange<Int>] = []
        for m in portRE.matches(in: n, range: NSRange(location: 0, length: ns.length)) {
            for part in ns.substring(with: m.range(at: 1)).split(whereSeparator: { $0 == "/" || $0 == "," }) {
                let b = part.split(separator: "-").compactMap { Int($0) }
                if b.count == 1 { out.append(b[0]...b[0]) } else if b.count == 2, b[0] <= b[1] { out.append(b[0]...b[1]) }
            }
        }
        return out.isEmpty ? nil : out
    }

    private static func covers(_ ranges: [ClosedRange<Int>], _ p: Int) -> Bool { ranges.contains { $0.contains(p) } }
}
