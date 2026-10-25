import Foundation

/// Execution contract for the two script kinds that are not bound to an
/// HTTP phase: Surge `type=dns` and `type=rule` scripts (and, with the
/// same registration, Egern scriptings with dns / rule triggers).
///
/// STATUS: registration (nc-compat, above) AND kernel execution
/// (nc-script-runtime) are both wired. The tunnel-side runner is
/// PacketTunnel/NativeCore/NCScriptHookRunner.swift — it cannot use
/// this file's types (App target), so it mirrors them there; the
/// semantics below are the shared contract. Two placement decisions
/// differ from the original sketch and are deliberate:
///
/// 1. type=dns — the scripts run AFTER an answer exists (hosts /
///    fake-IP locally, or the assigned upstream's reply, on the
///    `handleDNSQuery(_:)` path in NCDataPlane) and BEFORE it is
///    written back to the client, in declaration order, each script
///    seeing the previous script's answer:
///      - .addresses(ips)  → the reply's answer is rebuilt from those
///        A / AAAA records (filtered to the query's qtype); an empty
///        list is an authoritative empty answer (NODATA). A script
///        may also set an rcode.
///      - .passThrough     → the current answer stands.
///    A rule's `pattern`, when non-empty, is a domain regex filter:
///    the script only runs for matching query names. Errors and
///    timeouts (script timeout from the manifest entry) are
///    .passThrough — a broken dns script must never break resolution.
///
/// 2. type=rule — NativeCoreEngine `route(_:)` / `routeAsync(_:…)`
///    consult the registered rule scripts, in declaration order,
///    BEFORE NCRuleMatcher evaluation (the kernel's rule list and the
///    manifest's rule list come from different sources, so an
///    interleaved "when evaluation reaches them" is not
///    representable):
///      - .policy(name) → the connection takes that policy, exactly
///        as if a rule with that policy had matched; stop.
///      - .noMatch      → continue matching the remaining rules.
///    Errors and timeouts are .noMatch.
///
/// The runner protocol below is what the tunnel's script host
/// (NativeScriptHost, JSC) is expected to implement over the manifest
/// entries whose `type` is "dns" / "rule". On the JS side this maps to
/// the Surge conventions: a dns script receives the query domain (and
/// qtype) and answers with an address list or nothing (pass-through);
/// a rule script receives the connection context and answers with a
/// policy name or nothing (no match). Egern ctx-style scripts of these
/// two kinds use the same contract; their code is adapted by
/// NCScriptManifest.adaptEgern when it is in export-default form, and
/// the ctx fields they read (ctx.request / ctx.env / …) are the ones
/// documented at parseEgernScripting in EngineParser.swift.
///
/// Naming (nc-script-runtime-verify): the value types and the protocol
/// in this file are a spec only — nothing in the App target conforms
/// to or constructs them. They carry the `Hook` infix so they do not
/// collide with the tunnel runner's operational mirrors
/// (NCScriptDNSQuery / NCScriptRuleContext / NCScriptHookRunner in
/// PacketTunnel/NativeCore/NCScriptHookRunner.swift) now that the
/// runner also compiles into the app target for the integration tests
/// (UnitTests/NativeCoreScriptRuntimeVerifyTests.swift).

// MARK: - DNS hook values

/// One DNS query, as handed to a type=dns script.
struct NCScriptHookDNSQuery {
    /// Query name, lowercased, no trailing dot.
    var domain: String
    /// DNS record type code (1 = A, 28 = AAAA, 65 = HTTPS, …).
    var qtype: UInt16
}

enum NCScriptDNSAnswer {
    /// The script does not decide: normal resolution continues.
    case passThrough
    /// Use these addresses (IP literals) as the answer. An empty array
    /// is an authoritative empty answer (NODATA), not pass-through.
    case addresses([String])
}

// MARK: - Rule hook values

/// Connection context for a type=rule script. Field-for-field mirror
/// of the kernel's NCMatchContext (Shared/NativeCore/NCRule.swift),
/// with IPs as literals so this App-side contract does not depend on
/// kernel types; the kernel adapter fills what it has and leaves the
/// rest nil — scripts must treat every field as optional.
struct NCScriptHookRuleContext {
    var domain: String? = nil
    var ip: String? = nil
    var srcIP: String? = nil
    var dstPort: Int? = nil
    var srcPort: Int? = nil
    /// "tcp" | "udp".
    var network: String? = nil
    /// Sniffed application protocol: "http" | "tls" | "quic".
    var protocolHint: String? = nil
    var processName: String? = nil
    var url: String? = nil
    var userAgent: String? = nil
}

enum NCScriptRuleVerdict {
    /// The script does not match: rule matching continues.
    case noMatch
    /// The script decides: route via this policy name.
    case policy(String)
}

// MARK: - Runner (implemented tunnel-side by NCScriptHookRunner.swift)

protocol NCScriptHookExecuting: AnyObject {
    /// Runs one registered type=dns script for a query. Must be
    /// fail-open: any script error or timeout returns .passThrough.
    func runDNSScript(_ script: NCEngineScript, query: NCScriptHookDNSQuery) -> NCScriptDNSAnswer
    /// Runs one registered type=rule script for a connection. Must be
    /// fail-open: any script error or timeout returns .noMatch.
    func runRuleScript(_ script: NCEngineScript, context: NCScriptHookRuleContext) -> NCScriptRuleVerdict
}

// MARK: - Registration view over a parsed ruleset

enum NCScriptHooks {
    static let dnsType = "dns"
    static let ruleType = "rule"

    static func isHookType(_ type: String) -> Bool {
        type == dnsType || type == ruleType
    }

    /// Registered type=dns scripts, in declaration order.
    static func dnsScripts(in rs: NCEngineRuleset) -> [NCEngineScript] {
        rs.rules.compactMap { r in
            guard r.kind == "script", let sc = r.script, sc.type == dnsType else { return nil }
            return sc
        }
    }

    /// Registered type=rule scripts, in declaration order.
    static func ruleScripts(in rs: NCEngineRuleset) -> [NCEngineScript] {
        rs.rules.compactMap { r in
            guard r.kind == "script", let sc = r.script, sc.type == ruleType else { return nil }
            return sc
        }
    }
}
