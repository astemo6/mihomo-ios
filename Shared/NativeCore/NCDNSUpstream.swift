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
    /// Ordered server list tried sequentially (short per-server timeout,
    /// the last server that answered goes first next time) — Clash.Meta /
    /// Surge use every configured nameserver, not just the first.
    indirect case group([NCDNSUpstream])

    /// Wrap several upstreams as one (a single one stays itself).
    static func of(_ list: [NCDNSUpstream]) -> NCDNSUpstream? {
        var flat: [NCDNSUpstream] = []
        for u in list {
            if case .group(let inner) = u { flat.append(contentsOf: inner) } else { flat.append(u) }
        }
        var seen: [NCDNSUpstream] = []
        for u in flat where !seen.contains(u) { seen.append(u) }
        if seen.isEmpty { return nil }
        return seen.count == 1 ? seen[0] : .group(seen)
    }

    /// Members in preference order (a plain upstream is a group of one).
    var members: [NCDNSUpstream] {
        if case .group(let list) = self { return list }
        return [self]
    }

    /// `host[:port]` with bracketed IPv6 (`[2001:db8::1]:853`) and bare
    /// IPv6 literals (`2001:db8::1`, no port) handled; a path / query tail
    /// is ignored. nil for an empty host or a non-numeric port.
    static func splitHostPort(_ rest0: String, defaultPort def: Int) -> (String, Int)? {
        var rest = rest0
        if let cut = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) { rest = String(rest[..<cut]) }
        if rest.hasPrefix("[") {
            guard let close = rest.firstIndex(of: "]") else { return nil }
            let host = String(rest[rest.index(after: rest.startIndex)..<close])
            guard !host.isEmpty else { return nil }
            let tail = rest[rest.index(after: close)...]
            if tail.isEmpty { return (host, def) }
            guard tail.hasPrefix(":"), let p = Int(tail.dropFirst()), (1...65535).contains(p) else { return nil }
            return (host, p)
        }
        let colons = rest.filter { $0 == ":" }.count
        if colons > 1 { // bare IPv6 literal: no port possible without brackets
            return NCIP(rest) != nil ? (rest, def) : nil
        }
        if colons == 1, let c = rest.firstIndex(of: ":") {
            let host = String(rest[..<c])
            guard !host.isEmpty, let p = Int(rest[rest.index(after: c)...]), (1...65535).contains(p) else { return nil }
            return (host, p)
        }
        return rest.isEmpty ? nil : (rest, def)
    }

    static func parse(_ raw0: String) -> NCDNSUpstream? {
        var raw = raw0.trimmingCharacters(in: .whitespaces)
        if let hash = raw.firstIndex(of: "#") { raw = String(raw[..<hash]) }
        func hostPort(_ rest: String, _ def: Int) -> (String, Int)? {
            splitHostPort(rest, defaultPort: def)
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

    /// fix/nc-start-empty: the first list (in priority order) that yields a forwardable upstream. A runtime whose
    /// `nameserver` holds only `system` / `dhcp://…` (QX profiles that rely on the system resolver) used to give
    /// no upstream at all, and in redir-host mode every TUN DNS query was dropped — "connected, nothing loads".
    /// Callers pass nameserver, then default-nameserver, then proxy-server-nameserver.
    static func firstUsable(_ lists: [[String]]) -> NCDNSUpstream? {
        for list in lists {
            if let u = of(list.compactMap { parse($0) }) { return u }
        }
        return nil
    }

    /// Map a canonical DNS server reference onto a forwardable upstream.
    init?(_ ref: NCDNSServerRef) {
        switch ref.scheme {
        case .udp: self = .udp(host: ref.host, port: ref.port)
        case .tcp: self = .tcp(host: ref.host, port: ref.port)
        case .dot: self = .dot(host: ref.host, port: ref.port)
        case .doq: self = .doq(host: ref.host, port: ref.port)
        case .doh:
            var url = ref.host.contains(":") ? "https://[\(ref.host)]" : "https://\(ref.host)"
            if ref.port != 443 { url += ":\(ref.port)" }
            url += ref.path ?? "/dns-query"
            self = .doh(url: url)
        case .dhcp, .system: return nil
        }
    }
}
