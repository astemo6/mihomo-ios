import Foundation

/// fix/nc-mitm-live (build 404 device report: 「重写脚本一个都用不了」): the TUN data plane's MitM decision, kept pure so
/// the unit tests run it (NCDataPlane itself lives in the tunnel target only).
///
/// Root cause it replaces: NCDataPlane consulted the MitM host list only inside its *sniffer* path, which runs for a
/// flow only when the destination is a bare IP AND `sniffer.parse-pure-ip` is on (or a force-domain matches). Every
/// flow whose domain was already known — fake-ip mapping, or the redir-host real-IP → host map — was connected
/// straight away in accept(), so no connection ever reached the native MitM front and no rewrite / script ran.
///
/// Now: whenever MitM is active, a TCP flow is held for its first bytes (the ClientHello) when
///   - its known domain is a MitM host for that port, or
///   - its domain is unknown (bare IP / fake-ip without mapping) and the port is one MitM hosts use (443 or a port
///     named in the host list) — the SNI decides.
/// The verdict on the first bytes is independent of the sniffer configuration.
enum NCMitmGate {
    enum Verdict: Equatable {
        /// The first TLS record is not complete yet: wait for more bytes (bounded by the caller's timeout / cap).
        case needMore
        /// Hand the flow to the native front for `host` (SNI, else the known domain); `alpn` as offered.
        case mitm(host: String, alpn: [String])
        /// Relay without decrypting; `reason` is for the [MITM] diagnostics line.
        case passthrough(reason: String)
    }

    /// Largest first flight we wait for before giving up on finding a complete ClientHello.
    static let maxHelloBytes = 16 * 1024

    /// Should accept() hold this flow for its first bytes?
    /// - knownDomain: fake-ip / redir-host mapping (nil: bare IP or unmapped fake-ip).
    /// - mitmPorts: ports the host list names explicitly (443 is always included).
    static func shouldPeek(knownDomain: String?, port: Int, mitmActive: Bool, mitmPorts: Set<Int>,
                           isMitm: (String, Int) -> Bool) -> Bool {
        guard mitmActive else { return false }
        if let d = knownDomain, !d.isEmpty { return isMitm(d, port) }
        return port == 443 || mitmPorts.contains(port)
    }

    /// The first TLS record (record header + length) is fully buffered.
    static func helloComplete(_ d: Data) -> Bool {
        guard d.count >= 5 else { return false }
        let s = d.startIndex
        let len = Int(d[s + 3]) << 8 | Int(d[s + 4])
        return d.count >= 5 + len
    }

    /// Verdict on the client's first bytes.
    /// - knownDomain: the domain from DNS (fake-ip / redir-host), used when the ClientHello has no SNI.
    /// - dstIP: the destination address text, matched last (host lists may name IP literals).
    static func decide(firstBytes d: Data, knownDomain: String?, dstIP: String?, port: Int,
                       isMitm: (String, Int) -> Bool) -> Verdict {
        guard let first = d.first else { return .needMore }
        guard first == 0x16 else { return .passthrough(reason: "not TLS") }
        if !helloComplete(d) {
            return d.count >= maxHelloBytes ? .passthrough(reason: "ClientHello over \(maxHelloBytes >> 10) KB") : .needMore
        }
        guard case .tls(let sni, let alpn) = NCSniffer.parseClientHello(d) else {
            return .passthrough(reason: "unparsable ClientHello")
        }
        // The SNI is authoritative when present: the DNS-derived domain can be wrong for shared CDN addresses
        // (redir-host maps an IP to the last name that resolved to it), and the leaf must name what the client asked.
        if let sni = sni?.lowercased(), !sni.isEmpty {
            return isMitm(sni, port) ? .mitm(host: sni, alpn: alpn) : .passthrough(reason: "SNI \(sni) not in MitM hostname list")
        }
        // No SNI (old clients, IP-literal URLs): the known domain, then the destination IP.
        for h in [knownDomain?.lowercased(), dstIP].compactMap({ $0 }) where !h.isEmpty && isMitm(h, port) {
            return .mitm(host: h, alpn: alpn)
        }
        if knownDomain == nil && dstIP == nil { return .passthrough(reason: "no SNI") }
        return .passthrough(reason: "no SNI, not in MitM hostname list")
    }

    /// Ports a MitM host list names explicitly ("host:8443"); 443 is implied.
    static func ports(fromPatterns pats: [(pat: String, port: Int)]) -> Set<Int> {
        var s: Set<Int> = [443]
        for p in pats where p.port > 0 { s.insert(p.port) }
        return s
    }
}

/// fix/nc-mitm-live: one shared limiter for the per-flow diagnostics lines ([TCP] / [UDP] / [MITM] / [REWRITE] /
/// [SCRIPT]) going into NativeLogRing (400 lines → /logs, 诊断包 core-log.txt). At most `perSecond` lines a second
/// across all of them; the rest are counted and reported as one "suppressed" line when the next window opens.
final class NCDiagLimiter {
    static let shared = NCDiagLimiter()
    static let perSecond = 20

    private let lock = NSLock()
    private var window: UInt64 = 0
    private var count = 0
    private var suppressed = 0
    /// Where admitted lines go (tests replace it). (type, payload)
    var sink: (String, String) -> Void

    init(sink: @escaping (String, String) -> Void = { _, _ in }) { self.sink = sink }

    /// Returns true when the line was admitted.
    @discardableResult
    func line(_ payload: String, level: String = "info", now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> Bool {
        lock.lock()
        var flush = 0
        if now &- window >= 1_000_000_000 {
            flush = suppressed
            window = now
            count = 0
            suppressed = 0
        }
        let admit = count < Self.perSecond
        if admit { count += 1 } else { suppressed += 1 }
        let sink = self.sink
        lock.unlock()
        if flush > 0 { sink("warning", "[diag] \(flush) line(s) suppressed (limit \(Self.perSecond)/s)") }
        if admit { sink(level, payload) }
        return admit
    }
}
