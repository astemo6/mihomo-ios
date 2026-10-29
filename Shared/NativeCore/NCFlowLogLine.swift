import Foundation

/// The canonical connection-outcome log lines — the flow counterpart of NCDNSLogLine.
/// The core composes its [TCP]/[UDP] outcome lines here, in Shared, so the App-side
/// parsers (the DNS log page's 已拦截 tab, SelfCheck) and the unit tests build and read
/// the exact same strings. The shapes are the native core's own (they never were
/// Clash's): "[TCP] <host>:<port> rule <rule> → <via>" plus an outcome word for TCP,
/// one whole line for UDP. The DNS page originally parsed only the old Go core's
/// "[TCP] src --> host match … using REJECT" lines, so its 已拦截 tab silently stayed
/// empty on the native core while the core's rejected counter kept counting
/// (device 2026-10-29) — the same drift as the DNS lines in fix/nc-dns-log-page.
enum NCFlowLogLine {
    /// "[TCP] example.com:443 rule DomainSuffix(example.com) → REJECT" — the head the
    /// outcome words hang off ("connected in … ms", "failed after … ms: …", "rejected").
    static func head(proto: String, host: String, port: Int, rule: String, matchNote: String, via: String) -> String {
        "[\(proto)] \(host):\(port) rule \(rule)\(matchNote) → \(via)"
    }

    /// The full UDP outcome line (at its call site the outcome is part of the same line).
    static func udpOutcome(host: String, port: Int, rule: String, via: String, opened: Bool) -> String {
        "[UDP] \(host):\(port) rule \(rule) → \(via) \(opened ? "opened" : "dropped (no UDP relay for this policy)")"
    }
}
