import Foundation

/// Canonical (source-neutral) config model for the native core.
///
/// Design: docs/native-config-model.md. The user's direction is that the
/// native core is NOT bounded by mihomo: the internal model takes the union
/// of Quantumult X / Loon / Surge semantics, and every source format
/// (mihomo YAML included) is just an importer into this model. Engines
/// consume only this model; adding a format means adding an importer.
///
/// Nodes reuse `NCProxy` (type + parameter bag) and rules stay raw strings
/// for now — both are already source-neutral shapes, and the connector /
/// rule matcher consume them unchanged.

/// One upstream DNS server, parsed from the string forms used across the
/// four ecosystems ("8.8.8.8", "tcp://…", "https://…" DoH, "tls://…" DoT,
/// "quic://…" DoQ, "system", "dhcp://en0", with optional "#params" suffix).
struct NCDNSServerRef: Equatable {
    enum Scheme: Equatable { case udp, tcp, doh, dot, doq, dhcp, system }
    let raw: String
    let scheme: Scheme
    let host: String
    let port: Int
    let path: String? // DoH path ("/dns-query")

    static func parse(_ raw0: String) -> NCDNSServerRef {
        let raw = raw0.trimmingCharacters(in: .whitespaces)
        var body = raw
        if let hash = body.firstIndex(of: "#") { body = String(body[..<hash]) }
        if body.lowercased() == "system" {
            return NCDNSServerRef(raw: raw, scheme: .system, host: "", port: 0, path: nil)
        }
        var scheme: Scheme = .udp
        var rest = body
        for (prefix, s) in [("https://", Scheme.doh), ("quic://", .doq), ("tls://", .dot),
                            ("tcp://", .tcp), ("udp://", .udp), ("dhcp://", .dhcp)] {
            if body.lowercased().hasPrefix(prefix) {
                scheme = s
                rest = String(body.dropFirst(prefix.count))
                break
            }
        }
        // Split host[:port][/path]; bracketed IPv6 keeps its colons.
        var path: String? = nil
        if let slash = rest.firstIndex(of: "/") {
            path = String(rest[slash...])
            rest = String(rest[..<slash])
        }
        var host = rest
        var port: Int? = nil
        if rest.hasPrefix("[") {
            if let close = rest.firstIndex(of: "]") {
                host = String(rest[rest.index(after: rest.startIndex)..<close])
                let tail = rest[rest.index(after: close)...]
                if tail.hasPrefix(":"), let p = Int(tail.dropFirst()) { port = p }
            }
        } else if let colon = rest.lastIndex(of: ":"), let p = Int(rest[rest.index(after: colon)...]) {
            host = String(rest[..<colon])
            port = p
        }
        let defaultPort: Int
        switch scheme {
        case .udp, .tcp: defaultPort = 53
        case .doh: defaultPort = 443
        case .dot, .doq: defaultPort = 853
        case .dhcp, .system: defaultPort = 0
        }
        return NCDNSServerRef(raw: raw, scheme: scheme, host: host,
                              port: port ?? defaultPort, path: path)
    }
}

/// A hosts-table entry: static address, per-domain DNS server ("server:…",
/// Surge/Loon [Host] style) or an alias to another name.
struct NCHostEntry: Equatable {
    enum Kind: Equatable { case address, dnsServer, alias }
    let pattern: String // may contain "*" wildcards
    let value: String
    var kind: Kind {
        if value.lowercased().hasPrefix("server:") { return .dnsServer }
        if NCIP(value) != nil { return .address }
        return .alias
    }
    var dnsServer: NCDNSServerRef? {
        guard kind == .dnsServer else { return nil }
        return NCDNSServerRef.parse(String(value.dropFirst("server:".count)))
    }
}

/// A remote node subscription: QX [server_remote], Loon [Remote Proxy],
/// mihomo proxy-providers, Surge external policy sources — one concept.
struct NCNodeSubscription: Equatable {
    let name: String
    let url: String
    var interval: Int = 86400
    var includeRegex: String? = nil
    var excludeRegex: String? = nil
    var fields: [String: NCJSONValue] = [:] // source-specific extras (health-check, filter, …)
}

/// A remote rule list reference (dialect detection lives in the rule-set
/// engine; this is the config-level reference plus its forced policy).
struct NCRuleSetRef: Equatable {
    let name: String
    let url: String?
    var interval: Int = 86400
    var forcedPolicy: String? = nil // QX force-policy / the RULE-SET line's policy column
    var fields: [String: NCJSONValue] = [:]
}

enum NCGroupKind: Equatable {
    case select, urlTest, fallback, loadBalance, relay, external
}

struct NCGroupModel: Equatable {
    let name: String
    var kind: NCGroupKind
    var members: [String] = []
    var url: String? = nil
    var interval: Int = 300
    var tolerance: Int = 0
    var strategy: String? = nil // load-balance: round-robin | consistent-hashing
    var includeRegex: String? = nil
    var excludeRegex: String? = nil
    var use: [String] = [] // names of NCNodeSubscription feeding this group
    /// SUBNET conditions (Surge SUBNET / QX ssid policies): network key
    /// (a Wi-Fi SSID, or "DEFAULT") → member to route to on that network.
    var subnetConditions: [String: String] = [:]

    /// Adapter back to the legacy group shape the existing group engine
    /// consumes, so the engine needs no changes while importers land.
    func legacy() -> NCProxyGroup {
        let type: String
        switch kind {
        case .select: type = "select"
        case .urlTest: type = "url-test"
        case .fallback: type = "fallback"
        case .loadBalance: type = "load-balance"
        case .relay: type = "relay"
        case .external: type = "select"
        }
        var fields: [String: NCJSONValue] = [:]
        if let url { fields["url"] = .string(url) }
        fields["interval"] = .number(Double(interval))
        fields["tolerance"] = .number(Double(tolerance))
        if let strategy { fields["strategy"] = .string(strategy) }
        if !use.isEmpty { fields["use"] = .array(use.map { .string($0) }) }
        if !subnetConditions.isEmpty {
            fields["subnet"] = .object(subnetConditions.mapValues { .string($0) })
        }
        return NCProxyGroup(name: name, type: type, proxies: members, fields: fields)
    }
}

struct NCFallbackFilter: Equatable {
    var geosite: [String] = []
    var ipcidr: [String] = []
    var domain: [String] = []
}

/// DNS model: union of the three apps' semantics (see design doc §3).
struct NCDNSModel: Equatable {
    enum Mode: Equatable { case fakeIP, redirHost, normal }
    var mode: Mode = .fakeIP
    var fakeIPRange4: String = "198.18.0.1/16"
    var fakeIPRange6: String? = nil
    var alwaysRealIP: [String] = [] // Surge always-real-ip ∪ fake-ip-filter
    var defaultServers: [NCDNSServerRef] = []
    var encryptedServers: [NCDNSServerRef] = [] // doh/dot/doq subset of defaults, split for policy code
    var domainServers: [(key: String, servers: [NCDNSServerRef])] = []
    var fallback: [NCDNSServerRef] = []
    var fallbackFilter = NCFallbackFilter()
    var respectRules: Bool = false

    static func == (a: NCDNSModel, b: NCDNSModel) -> Bool {
        a.mode == b.mode && a.fakeIPRange4 == b.fakeIPRange4 && a.fakeIPRange6 == b.fakeIPRange6
            && a.alwaysRealIP == b.alwaysRealIP && a.defaultServers == b.defaultServers
            && a.encryptedServers == b.encryptedServers && a.fallback == b.fallback
            && a.fallbackFilter == b.fallbackFilter && a.respectRules == b.respectRules
            && a.domainServers.map { $0.key } == b.domainServers.map { $0.key }
            && a.domainServers.map { $0.servers } == b.domainServers.map { $0.servers }
    }
}

/// MitM configuration parsed from canonical sources (Surge / Loon [Mitm], QX [mitm], mihomo mitm:).
struct NCMitmConfig: Equatable {
    var enabled: Bool = false
    var hostnames: [String] = []
    var skipCertVerify: Bool = false
    var h2: Bool = true
    var captureBodies: Bool = false
}

/// Rewrite rule: URL rewrites, header rewrites, map local, body rewrites.
struct NCRewriteRule: Equatable {
    var kind: String       // "url", "header", "body", "maplocal"
    var phase: String      // "request", "response"
    var pattern: String    // URL regex or pattern
    var action: String?    // "reject", "reject-200", "reject-img", "reject-dict", "reject-array", "reject-drop", "302", "307", "header"
    var target: String?    // replacement URL or header value or map-local content
    var extra: [String: String] = [:]
}

/// Script rule: http-request, http-response, cron.
struct NCScriptRule: Equatable {
    var name: String
    var type: String       // "http-request", "http-response", "cron"
    var pattern: String
    var scriptPath: String?
    var requiresBody: Bool = false
    var timeoutMs: Int64 = 10000
    var extra: [String: String] = [:]
}

/// Non-fatal import findings: unmapped parameters and unrecognized sections
/// are reported, never silently dropped.
struct NCImportReport: Equatable {
    var warnings: [String] = []
    var skippedSections: [String] = []
}

struct NCCanonicalConfig: Equatable {
    var sourceFormat: String // "mihomo" | "surge" | "loon" | "quantumultx"
    var mode: String = "rule"
    var logLevel: String = "info"
    var ipv6: Bool = false
    var dns = NCDNSModel()
    var hosts: [NCHostEntry] = []
    var nodes: [NCProxy] = []
    var subscriptions: [NCNodeSubscription] = []
    var groups: [NCGroupModel] = []
    var ruleSets: [NCRuleSetRef] = []
    var rules: [String] = []
    var mitm = NCMitmConfig()
    var rewrites: [NCRewriteRule] = []
    var scripts: [NCScriptRule] = []
    var report = NCImportReport()

    var nodeMap: [String: NCProxy] { Dictionary(nodes.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a }) }
    var groupMap: [String: NCGroupModel] { Dictionary(groups.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a }) }

    /// Bridge to the legacy runtime config while the engine migrates.
    /// DNS fields are reconstructed from the model so enhanced mode,
    /// fake ranges and filters survive the trip.
    func legacyConfig() -> NCConfig {
        var dnsFields: [String: NCJSONValue] = [:]
        switch dns.mode {
        case .fakeIP: dnsFields["enhanced-mode"] = .string("fake-ip")
        case .redirHost: dnsFields["enhanced-mode"] = .string("redir-host")
        case .normal: dnsFields["enhanced-mode"] = .string("normal")
        }
        dnsFields["fake-ip-range"] = .string(dns.fakeIPRange4)
        if let range6 = dns.fakeIPRange6 { dnsFields["fake-ip-range6"] = .string(range6) }
        if !dns.alwaysRealIP.isEmpty {
            dnsFields["fake-ip-filter"] = .array(dns.alwaysRealIP.map { .string($0) })
        }
        let servers = (dns.defaultServers + dns.encryptedServers).map { NCJSONValue.string($0.raw) }
        if !servers.isEmpty { dnsFields["nameserver"] = .array(servers) }
        return NCConfig(mode: mode, logLevel: logLevel, ipv6: ipv6,
                        proxies: nodes, groups: groups.map { $0.legacy() }, rules: rules,
                        dns: NCDNSConfig(fields: dnsFields), raw: [:])
    }
}

// MARK: - mihomo importer (NCConfig → canonical)

extension NCCanonicalConfig {
    static func from(mihomo cfg: NCConfig) -> NCCanonicalConfig {
        var out = NCCanonicalConfig(sourceFormat: "mihomo")
        out.mode = cfg.mode
        out.logLevel = cfg.logLevel
        out.ipv6 = cfg.ipv6
        out.nodes = cfg.proxies
        out.rules = cfg.rules
        out.groups = cfg.groups.map { g in
            let kind: NCGroupKind
            switch g.type {
            case "url-test": kind = .urlTest
            case "fallback": kind = .fallback
            case "load-balance": kind = .loadBalance
            case "relay": kind = .relay
            default: kind = .select
            }
            return NCGroupModel(name: g.name, kind: kind, members: g.proxies,
                                url: g.url, interval: g.interval, tolerance: g.tolerance,
                                strategy: g.fields["strategy"]?.string, use: g.use)
        }

        // DNS
        let d = cfg.dns.fields
        var dns = NCDNSModel()
        switch cfg.dns.enhancedMode {
        case "fake-ip": dns.mode = .fakeIP
        case "redir-host": dns.mode = .redirHost
        default: dns.mode = .normal
        }
        dns.fakeIPRange4 = cfg.dns.fakeIPRange
        dns.fakeIPRange6 = d["fake-ip-range6"]?.string
        dns.alwaysRealIP = cfg.dns.fakeIPFilter
        let allServers = cfg.dns.nameservers.map(NCDNSServerRef.parse)
        dns.defaultServers = allServers
        dns.encryptedServers = allServers.filter { [.doh, .dot, .doq].contains($0.scheme) }
        if let policy = d["nameserver-policy"]?.object {
            dns.domainServers = policy.keys.sorted().map { key in
                let list = policy[key]?.array?.compactMap { $0.string } ?? (policy[key]?.string.map { [$0] } ?? [])
                return (key: key, servers: list.map(NCDNSServerRef.parse))
            }
        }
        dns.fallback = (d["fallback"]?.array?.compactMap { $0.string } ?? []).map(NCDNSServerRef.parse)
        if let ff = d["fallback-filter"]?.object {
            dns.fallbackFilter = NCFallbackFilter(
                geosite: ff["geosite"]?.array?.compactMap { $0.string } ?? [],
                ipcidr: ff["ipcidr"]?.array?.compactMap { $0.string } ?? [],
                domain: ff["domain"]?.array?.compactMap { $0.string } ?? [])
        }
        dns.respectRules = d["respect-rules"]?.bool ?? false
        out.dns = dns

        // hosts: { pattern: ip | [ips] }
        if let hosts = cfg.raw["hosts"]?.object {
            out.hosts = hosts.keys.sorted().map { key in
                let v = hosts[key]
                let value = v?.string ?? v?.array?.compactMap { $0.string }.first ?? ""
                return NCHostEntry(pattern: key, value: value)
            }
        }

        // proxy-providers → node subscriptions
        if let providers = cfg.raw["proxy-providers"]?.object {
            out.subscriptions = providers.keys.sorted().compactMap { name in
                guard let o = providers[name]?.object, let url = o["url"]?.string else { return nil }
                return NCNodeSubscription(
                    name: name, url: url,
                    interval: o["interval"]?.int ?? 86400,
                    fields: o)
            }
        }
        // rule-providers → rule set refs
        if let providers = cfg.raw["rule-providers"]?.object {
            out.ruleSets = providers.keys.sorted().compactMap { name in
                guard let o = providers[name]?.object else { return nil }
                return NCRuleSetRef(name: name, url: o["url"]?.string,
                                    interval: o["interval"]?.int ?? 86400, fields: o)
            }
        }

        // mitm
        if let mitmObj = cfg.raw["mitm"]?.object {
            out.mitm.enabled = mitmObj["enabled"]?.bool ?? (mitmObj["enable"]?.bool ?? true)
            if let hosts = mitmObj["hostnames"]?.array?.compactMap({ $0.string }) ?? mitmObj["hostname"]?.array?.compactMap({ $0.string }) {
                out.mitm.hostnames = hosts
            }
            out.mitm.skipCertVerify = mitmObj["skip-cert-verify"]?.bool ?? (mitmObj["skip-server-cert-verify"]?.bool ?? false)
            out.mitm.h2 = mitmObj["h2"]?.bool ?? true
        }
        return out
    }
}
