import Foundation

// feat/native-core-eval: moved from PacketTunnel/NativeCore/NCUDPSessions.swift so the app target (unit tests:
// NativeCoreDNSPolicyTests.testUpstreamMapping) builds it too.

/// Parsed nameserver entry: plain UDP/TCP, DoT, DoH, or DoQ (RFC 9250) —
/// the full encrypted-DNS set Surge/Loon/QX all support.
enum NCDNSUpstream: Equatable {
    case udp(host: String, port: Int)
    case tcp(host: String, port: Int)
    case dot(host: String, port: Int)
    case doh(url: String)
    case doq(host: String, port: Int)

    static func parse(_ raw0: String) -> NCDNSUpstream? {
        var raw = raw0
        if let hash = raw.firstIndex(of: "#") { raw = String(raw[..<hash]) }
        func hostPort(_ rest: String, _ def: Int) -> (String, Int)? {
            let parts = rest.split(separator: ":", maxSplits: 1)
            guard let host = parts.first, !host.isEmpty else { return nil }
            return (String(host), parts.count > 1 ? Int(parts[1]) ?? def : def)
        }
        if raw.hasPrefix("tls://"), let hp = hostPort(String(raw.dropFirst(6)), 853) {
            return .dot(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("quic://"), let hp = hostPort(String(raw.dropFirst(7)), 853) {
            return .doq(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("tcp://"), let hp = hostPort(String(raw.dropFirst(6)), 53) {
            return .tcp(host: hp.0, port: hp.1)
        }
        if raw.hasPrefix("https://") {
            return .doh(url: raw)
        }
        if raw.hasPrefix("udp://"), let hp = hostPort(String(raw.dropFirst(6)), 53) {
            return .udp(host: hp.0, port: hp.1)
        }
        if raw.contains("://") || raw == "system" { return nil }
        guard let hp = hostPort(raw, 53) else { return nil }
        return .udp(host: hp.0, port: hp.1)
    }

    /// Map a canonical DNS server reference onto a forwardable upstream.
    init?(_ ref: NCDNSServerRef) {
        switch ref.scheme {
        case .udp: self = .udp(host: ref.host, port: ref.port)
        case .tcp: self = .tcp(host: ref.host, port: ref.port)
        case .dot: self = .dot(host: ref.host, port: ref.port)
        case .doq: self = .doq(host: ref.host, port: ref.port)
        case .doh:
            var url = "https://\(ref.host)"
            if ref.port != 443 { url += ":\(ref.port)" }
            url += ref.path ?? "/dns-query"
            self = .doh(url: url)
        case .dhcp, .system: return nil
        }
    }
}
