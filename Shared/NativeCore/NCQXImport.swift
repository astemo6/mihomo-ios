import Foundation

/// Quantumult X .conf importer into the canonical config model
/// (docs/native-config-model.md §6). Reuses the INI splitter and lexical
/// helpers from NCConfImport (same module).
///
/// QX dialect notes:
/// - Sections are lowercase: [general] [dns] [server_local] [server_remote]
///   [policy] [filter_local] [filter_remote] [host]; everything else
///   ([rewrite_local], [rewrite_remote], [mitm], [task_local], …) is
///   non-kernel and lands in `report.skippedSections`.
/// - Node lines are `type=server:port, k=v…, tag=Name` — the type leads,
///   the name trails in `tag=`.
/// - Credentials differ per protocol: vmess/vless carry the UUID in
///   `password=`; `tls-verification=false` is the inverse spelling of
///   `skip-cert-verify=true`.
/// - [filter_local] uses the lowercase QX rule dialect, translated to the
///   canonical uppercase rule strings here (host→DOMAIN, …, final→MATCH).
///   The built-in policies direct/reject are uppercased to match the
///   canonical spelling; group/node names keep their original case.
enum NCQXImport {

    static func quantumultx(_ text: String) -> NCCanonicalConfig {
        var report = NCImportReport()
        var cfg = NCCanonicalConfig(sourceFormat: "quantumultx")
        let sections = NCConfImport.splitSections(text)
        let map = NCConfImport.sectionMap(sections)
        let handled: Set<String> = ["general", "dns", "server_local", "server_remote",
                                    "policy", "filter_local", "filter_remote", "host",
                                    "mitm", "rewrite_local", "rewrite_remote"]
        for s in sections where !handled.contains(s.key) { report.skippedSections.append(s.name) }

        if let lines = map["mitm"] {
            for line in lines {
                if let (k, v) = NCConfImport.keyValueLine(line) {
                    if k.lowercased() == "hostname" {
                        let hosts = v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                        cfg.mitm.hostnames.append(contentsOf: hosts)
                        cfg.mitm.enabled = true
                    } else if k.lowercased() == "skip_validating_cert" {
                        cfg.mitm.skipCertVerify = (NCConfImport.boolValue(v) ?? false)
                    }
                }
            }
        }
        if let lines = map["rewrite_local"] {
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }
                let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                guard parts.count >= 3, parts[1].lowercased() == "url" else { continue }
                let pattern = parts[0]
                let action = parts[2]
                if action.hasPrefix("reject") {
                    cfg.rewrites.append(NCRewriteRule(kind: "url", phase: "request", pattern: pattern, action: action, target: nil))
                } else if (action == "302" || action == "307"), parts.count >= 4 {
                    cfg.rewrites.append(NCRewriteRule(kind: "url", phase: "request", pattern: pattern, action: action, target: parts[3]))
                } else if action.hasPrefix("script-") || action.hasPrefix("request-") || action.hasPrefix("response-") {
                    let type = action.contains("response") ? "http-response" : "http-request"
                    let path = parts.count >= 4 ? parts[3] : ""
                    cfg.scripts.append(NCScriptRule(name: "qx_script", type: type, pattern: pattern, scriptPath: path))
                }
            }
        }

        // [general]: no kernel mapping; only DNS-relevant keys are reported.
        if let lines = map["general"] {
            for line in lines {
                if let (k, _) = NCConfImport.keyValueLine(line), k.lowercased().hasPrefix("dns") {
                    report.warnings.append("quantumultx [general]: dns-related key '\(k)' has no canonical mapping")
                }
            }
        }
        if let lines = map["dns"] { applyDNS(lines: lines, cfg: &cfg, report: &report) }
        if let lines = map["server_local"] {
            for line in lines {
                if let node = buildQXNode(line: line, report: &report) { cfg.nodes.append(node) }
            }
        }
        if let lines = map["server_remote"] {
            for line in lines { appendServerRemote(line: line, cfg: &cfg, report: &report) }
        }
        if let lines = map["policy"] {
            for line in lines {
                if let group = buildQXPolicy(line: line, report: &report) { cfg.groups.append(group) }
            }
        }
        if let lines = map["filter_local"] {
            for line in lines {
                if let rule = translateQXRule(line) {
                    cfg.rules.append(rule)
                } else {
                    report.warnings.append("quantumultx [filter_local]: unparsable rule skipped: \(line)")
                }
            }
        }
        if let lines = map["filter_remote"] {
            for line in lines { appendFilterRemote(line: line, cfg: &cfg, report: &report) }
        }
        if let lines = map["host"] {
            for line in lines {
                if let (pattern, value) = NCConfImport.keyValueLine(line) {
                    cfg.hosts.append(NCHostEntry(pattern: pattern, value: value))
                }
            }
        }
        cfg.report = report
        return cfg
    }

    // MARK: - [dns]

    /// QX [dns]: `server=` (plain, repeatable), `server=/domain/addr`
    /// (per-domain upstream), `address=/domain/ip` (hosts entry),
    /// `doh-server=` comma list (DoT/DoQ spellings accepted too),
    /// `no-ipv6=`, `no-system=` (reported — no canonical field).
    private static func applyDNS(lines: [String], cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        /// Split "/domain/value" (dnsmasq style) at the LAST slash.
        func splitPath(_ value: String) -> (domain: String, rest: String)? {
            guard value.hasPrefix("/") else { return nil }
            let body = String(value.dropFirst())
            guard let slash = body.lastIndex(of: "/") else { return nil }
            let domain = String(body[..<slash])
            let rest = String(body[body.index(after: slash)...])
            guard !domain.isEmpty, !rest.isEmpty else { return nil }
            return (domain, rest)
        }
        for line in lines {
            guard let (rawKey, value) = NCConfImport.keyValueLine(line) else { continue }
            switch rawKey.lowercased() {
            case "server":
                if let (domain, addr) = splitPath(value) {
                    let ref = NCDNSServerRef.parse(addr)
                    if let idx = cfg.dns.domainServers.firstIndex(where: { $0.key == domain }) {
                        cfg.dns.domainServers[idx].servers.append(ref)
                    } else {
                        cfg.dns.domainServers.append((key: domain, servers: [ref]))
                    }
                } else {
                    cfg.dns.defaultServers.append(NCDNSServerRef.parse(value))
                }
            case "address":
                if let (domain, ip) = splitPath(value) {
                    cfg.hosts.append(NCHostEntry(pattern: domain, value: ip))
                } else {
                    report.warnings.append("quantumultx [dns]: malformed address= line: \(line)")
                }
            case "doh-server":
                cfg.dns.defaultServers.append(contentsOf: NCConfImport.tokens(value).map(NCDNSServerRef.parse))
            case "dot-server":
                cfg.dns.defaultServers.append(contentsOf: NCConfImport.tokens(value).map {
                    NCDNSServerRef.parse($0.contains("://") ? $0 : "tls://" + $0)
                })
            case "doq-server":
                cfg.dns.defaultServers.append(contentsOf: NCConfImport.tokens(value).map {
                    NCDNSServerRef.parse($0.contains("://") ? $0 : "quic://" + $0)
                })
            case "no-ipv6":
                if let b = NCConfImport.boolValue(value) { cfg.ipv6 = !b }
            case "no-system":
                if NCConfImport.boolValue(value) == true {
                    report.warnings.append("quantumultx [dns]: no-system=true noted; the canonical model only uses system DNS when explicitly listed")
                }
            default:
                report.warnings.append("quantumultx [dns]: unmapped key '\(rawKey)' ignored")
            }
        }
        cfg.dns.encryptedServers = cfg.dns.defaultServers.filter { [.doh, .dot, .doq].contains($0.scheme) }
    }

    // MARK: - [server_local] nodes

    /// Parse `type=server:port, k=v…, tag=Name`.
    static func buildQXNode(line: String, report: inout NCImportReport) -> NCProxy? {
        let toks = NCConfImport.tokens(line)
        guard let first = toks.first, let (rawType, address) = NCConfImport.keyValue(first) else {
            report.warnings.append("quantumultx [server_local]: unparsable line skipped: \(line)")
            return nil
        }
        let rawTypeLower = rawType.lowercased()
        if rawTypeLower == "custom" {
            report.warnings.append("quantumultx [server_local]: custom= node skipped (legacy script-defined protocol): \(line)")
            return nil
        }
        if rawTypeLower == "trusttunnel" || rawTypeLower == "trust-tunnel" {
            report.warnings.append("quantumultx [server_local]: trusttunnel has no Quantumult X format specification; explicitly unavailable: \(line)")
            return nil
        }
        // Address: host:port, or [v6]:port.
        var host = address
        var port: Int? = nil
        if address.hasPrefix("["), let close = address.firstIndex(of: "]") {
            host = String(address[address.index(after: address.startIndex)..<close])
            let tail = address[address.index(after: close)...]
            if tail.hasPrefix(":") { port = Int(tail.dropFirst()) }
        } else if let colon = address.lastIndex(of: ":"), let p = Int(address[address.index(after: colon)...]) {
            host = String(address[..<colon])
            port = p
        }
        let (_, kv, order) = NCConfImport.classify(Array(toks.dropFirst()))

        var fields: [String: NCJSONValue] = ["server": .string(host)]
        if let port { fields["port"] = .number(Double(port)) }
        else { report.warnings.append("quantumultx [server_local]: node at \(address) has no parseable port") }
        var consumed: Set<String> = ["tag"]
        func take(_ k: String) -> String? {
            guard let v = kv[k] else { return nil }
            consumed.insert(k)
            return v
        }

        let name = kv["tag"] ?? "\(rawTypeLower)-\(host)-\(port.map { String($0) } ?? "?")"
        if kv["tag"] == nil {
            report.warnings.append("quantumultx [server_local]: node without tag= named '\(name)'")
        }

        var type = rawTypeLower
        switch rawTypeLower {
        case "shadowsocks", "ss":
            type = "ss"
            if let c = take("method") { fields["cipher"] = .string(c) }
            if let p = take("password") { fields["password"] = .string(p) }
            if kv["obfs"] != nil { NCConfImport.applySimpleObfs(kv: kv, consumed: &consumed, fields: &fields) }
        case "vmess", "vless":
            type = rawTypeLower
            // QX carries the UUID in `password=`.
            if let u = take("password") ?? take("uuid") { fields["uuid"] = .string(u) }
            if let c = take("method") { fields["cipher"] = .string(c) }
            applyQXTransport(kv: kv, consumed: &consumed, fields: &fields)
            if let s = take("tls-host") ?? take("tls-name") ?? take("sni") {
                fields["sni"] = .string(s)
                fields["servername"] = .string(s)
            }
            if type == "vless", let f = take("flow") { fields["flow"] = .string(f) }
            // NB: `tls-pseudo-domain` (REALITY camouflage) is deliberately
            // left unconsumed — it is preserved verbatim by finishFields.
        case "trojan":
            if let p = take("password") { fields["password"] = .string(p) }
            if let ot = take("over-tls"), NCConfImport.boolValue(ot) == false {
                report.warnings.append("quantumultx node '\(name)': trojan over-tls=false cannot be honored (trojan is always TLS)")
            }
            if let s = take("tls-host") ?? take("tls-name") ?? take("sni") {
                fields["sni"] = .string(s)
                fields["servername"] = .string(s)
            }
            applyQXTransport(kv: kv, consumed: &consumed, fields: &fields)
        case "http":
            if let u = take("username") { fields["username"] = .string(u) }
            if let p = take("password") { fields["password"] = .string(p) }
            if let ot = take("over-tls"), NCConfImport.boolValue(ot) == true { type = "https" }
        case "socks5":
            if let u = take("username") { fields["username"] = .string(u) }
            if let p = take("password") { fields["password"] = .string(p) }
            if let ot = take("over-tls"), NCConfImport.boolValue(ot) == true { fields["tls"] = .bool(true) }
        case "snell":
            if let p = take("psk") ?? take("password") { fields["password"] = .string(p) }
            if let v = take("version"), let n = Int(v) { fields["version"] = .number(Double(n)) }
        case "tuic":
            // Same mapping as the Surge/Loon tuic spelling (NCConfImport.buildSurgeLikeNode): credentials stay
            // strings (the verbatim pass would coerce an all-digit token / password into a number).
            if let p = take("password") { fields["password"] = .string(p) }
            if let t = take("token") { fields["token"] = .string(t) }
            if let u = take("uuid") { fields["uuid"] = .string(u) }
            if let s = take("sni") ?? take("tls-host") ?? take("tls-name") { fields["sni"] = .string(s) }
        case "juicity":
            if let p = take("password") { fields["password"] = .string(p) }
            if let u = take("uuid") ?? take("user") { fields["uuid"] = .string(u) }
            if let s = take("sni") ?? take("peer") ?? take("tls-host") ?? take("tls-name") { fields["sni"] = .string(s) }
            if let cc = take("congestion-controller") ?? take("congestion-control") ?? take("congestion_control") {
                fields["congestion-controller"] = .string(cc)
            }
            if let pin = take("pinned-certchain-sha256") ?? take("pinned_certchain_sha256") ?? take("pinned-peer-cert-sha256") ?? take("cert-sha256") {
                fields["pinned-certchain-sha256"] = .string(pin)
            }
        case "hysteria2":
            if let p = take("password") ?? take("auth") { fields["password"] = .string(p) }
            if let s = take("sni") ?? take("tls-host") ?? take("tls-name") { fields["sni"] = .string(s) }
        default:
            // wireguard / anytls / …: generic credential
            // mapping; everything else rides along verbatim below.
            if type == "shadowsocksr" || type == "ssr" { type = "ssr" }
            if let p = take("password") { fields["password"] = .string(p) }
            if let p = take("psk"), fields["password"] == nil { fields["password"] = .string(p) }
            if let c = take("method") { fields["cipher"] = .string(c) }
        }

        // Common parameters.
        if let v = take("udp-relay") ?? take("udp"), let b = NCConfImport.boolValue(v) { fields["udp"] = .bool(b) }
        if let v = take("fast-open") ?? take("tfo"), let b = NCConfImport.boolValue(v) { fields["tfo"] = .bool(b) }
        if let v = take("tls-verification"), let b = NCConfImport.boolValue(v) {
            fields["skip-cert-verify"] = .bool(!b) // QX spells verification positively
        }
        if fields["skip-cert-verify"] == nil, let v = take("skip-cert-verify"), let b = NCConfImport.boolValue(v) {
            fields["skip-cert-verify"] = .bool(b)
        }
        NCConfImport.applyECH(kv: kv, consumed: &consumed, fields: &fields)

        NCConfImport.finishFields(&fields, kv: kv, order: order, consumed: consumed)
        return NCProxy(name: name, type: type, fields: fields)
    }

    /// QX transport spelling: `obfs=ws` (+ obfs-host/obfs-uri) or
    /// `obfs=over-tls` (SNI then comes from obfs-host if tls-host is absent).
    private static func applyQXTransport(kv: [String: String], consumed: inout Set<String>,
                                         fields: inout [String: NCJSONValue]) {
        guard let obfs = kv["obfs"] else { return }
        switch obfs.lowercased() {
        case "ws", "wss":
            consumed.insert("obfs")
            fields["network"] = .string("ws")
            var opts: [String: NCJSONValue] = [:]
            if let p = kv["obfs-uri"] { consumed.insert("obfs-uri"); opts["path"] = .string(p) }
            if let h = kv["obfs-host"] {
                consumed.insert("obfs-host")
                opts["headers"] = .object(["Host": .string(h)])
            }
            if !opts.isEmpty { fields["ws-opts"] = .object(opts) }
            if obfs.lowercased() == "wss" {
                fields["tls"] = .bool(true)
                // fix/nc-diag-439 (G): QX uses obfs-host as the TLS SNI of `obfs=wss` when tls-host is absent (as for
                // over-tls). Without it the node had no servername and the SNI fell back to `server` — for CloudFront
                // 优选-IP nodes an IP literal, so no SNI was sent and the edge aborted the handshake (tls -9824).
                // A later tls-host / sni still wins.
                if fields["servername"] == nil, fields["sni"] == nil, let h = kv["obfs-host"], !h.isEmpty {
                    fields["sni"] = .string(h)
                    fields["servername"] = .string(h)
                }
            }
        case "over-tls":
            consumed.insert("obfs")
            fields["tls"] = .bool(true)
            if fields["sni"] == nil, let h = kv["obfs-host"] {
                consumed.insert("obfs-host")
                fields["sni"] = .string(h)
                fields["servername"] = .string(h)
            }
        case "none":
            consumed.insert("obfs")
        default:
            break // unknown obfs: preserved verbatim by finishFields
        }
    }

    // MARK: - [server_remote]

    /// `<url>, k=v, …` for [server_remote] / [filter_remote]: the leading URL (everything before the first comma)
    /// is taken as-is, only the options after it are split as `k=v`. A subscription URL with a query
    /// (`https://x/sub?token=abc`) contains `=`, so classifying it as a token turned it into a key/value pair and
    /// the line was dropped as unparsable. A leading token that is not a URL keeps the generic classification.
    static func remoteLineFields(_ line: String) -> (positional: [String], kv: [String: String], order: [String]) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let head: Substring
        let tail: Substring
        if let comma = trimmed.firstIndex(of: ",") {
            head = trimmed[..<comma]
            tail = trimmed[trimmed.index(after: comma)...]
        } else {
            head = trimmed[...]
            tail = ""
        }
        let url = head.trimmingCharacters(in: .whitespaces)
        guard url.contains("://") else { return NCConfImport.classify(NCConfImport.tokens(line)) }
        let rest = NCConfImport.classify(NCConfImport.tokens(String(tail)))
        return ([url] + rest.positional, rest.kv, rest.order)
    }


    /// `<url>, update-interval=N, opt-parser=…, tag=X, enabled=…`.
    /// Disabled entries are skipped (QX semantics).
    private static func appendServerRemote(line: String, cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        let (positional, kv, order) = remoteLineFields(line)
        guard let url = positional.first else {
            report.warnings.append("quantumultx [server_remote]: unparsable line skipped: \(line)")
            return
        }
        if let e = kv["enabled"], NCConfImport.boolValue(e) == false { return }
        var fields: [String: NCJSONValue] = [:]
        // opt-parser and any other extras are preserved verbatim.
        NCConfImport.finishFields(&fields, kv: kv, order: order,
                                  consumed: ["enabled", "update-interval", "tag"])
        // fix/nc-open-6-10 #10: fetched with the QuanX User-Agent (NCNodeSubscriptionStore.userAgents).
        fields["x-origin"] = .string("qx")
        cfg.subscriptions.append(NCNodeSubscription(
            name: kv["tag"] ?? NCConfImport.hostDerivedName(url), url: url,
            interval: kv["update-interval"].flatMap { Int($0) } ?? 86400,
            fields: fields))
    }

    // MARK: - [policy]

    /// `static=Name, member…` / `url-test=Name, server-tag-regex=…, url=…,
    /// interval=…` / `available=` / `round-robin=` / `load-balance=` /
    /// `ssid=Name, DEFAULT:P, SSID:P`.
    private static func buildQXPolicy(line: String, report: inout NCImportReport) -> NCGroupModel? {
        let toks = NCConfImport.tokens(line)
        guard let first = toks.first, let (rawKind, name) = NCConfImport.keyValue(first), !name.isEmpty else {
            report.warnings.append("quantumultx [policy]: unparsable line skipped: \(line)")
            return nil
        }
        let (positional, kv, order) = NCConfImport.classify(Array(toks.dropFirst()))
        let consumed: Set<String> = ["url", "interval", "tolerance", "server-tag-regex"]
        var group: NCGroupModel
        switch rawKind.lowercased() {
        case "static":
            group = NCGroupModel(name: name, kind: .select, members: positional)
        case "available":
            group = NCGroupModel(name: name, kind: .fallback, members: positional)
        case "url-test":
            group = NCGroupModel(name: name, kind: .urlTest, members: positional)
        case "round-robin":
            group = NCGroupModel(name: name, kind: .loadBalance, members: positional, strategy: "round-robin")
        case "load-balance":
            group = NCGroupModel(name: name, kind: .loadBalance, members: positional)
        case "ssid":
            // Subnet conditions land in the canonical model; members are all
            // targets (DEFAULT first) so the group stays meaningful even
            // when no SSID is known.
            var conditions: [String: String] = [:]
            var members: [String] = []
            for token in positional {
                guard let colon = token.firstIndex(of: ":") else { continue }
                let ssid = String(token[..<colon])
                let target = String(token[token.index(after: colon)...])
                conditions[ssid] = target
                if !members.contains(target) { members.append(target) }
            }
            if let def = conditions["DEFAULT"] {
                members.removeAll { $0 == def }
                members.insert(def, at: 0)
            }
            group = NCGroupModel(name: name, kind: .select, members: members,
                                 subnetConditions: conditions)
        default:
            report.warnings.append("quantumultx [policy]: unrecognized policy kind '\(rawKind)' skipped: \(line)")
            return nil
        }
        if let u = kv["url"] { group.url = u }
        if let i = kv["interval"], let n = Int(i) { group.interval = n }
        if let t = kv["tolerance"], let n = Int(t) { group.tolerance = n }
        if let re = kv["server-tag-regex"] { group.includeRegex = re }
        let unmapped = order.filter { !consumed.contains($0) }
        if !unmapped.isEmpty {
            report.warnings.append("quantumultx group '\(name)': unmapped parameters ignored: \(unmapped.joined(separator: ", "))")
        }
        return group
    }

    // MARK: - [filter_local] dialect translation

    /// QX built-in policies are lowercase; canonical rule strings use the
    /// uppercase built-ins. Named policies keep their original case (group
    /// lookup is case-sensitive).
    static func canonicalPolicy(_ p: String) -> String {
        switch p.lowercased() {
        case "direct": return "DIRECT"
        case "reject": return "REJECT"
        case "proxy": return "PROXY"
        default: return p
        }
    }

    /// Translate one QX filter line to a canonical rule string.
    /// Returns nil for lines too short to carry type+payload+policy.
    static func translateQXRule(_ line: String) -> String? {
        let t = NCConfImport.tokens(line)
        guard let head = t.first else { return nil }
        let type = head.lowercased()
        if type == "final" {
            guard t.count >= 2 else { return nil }
            var s = "MATCH," + canonicalPolicy(t[1])
            if t.count > 2 { s += "," + t.dropFirst(2).joined(separator: ",") }
            return s
        }
        guard t.count >= 3 else { return nil }
        let mapped: String
        switch type {
        case "host": mapped = "DOMAIN"
        case "host-suffix": mapped = "DOMAIN-SUFFIX"
        case "host-keyword": mapped = "DOMAIN-KEYWORD"
        case "host-wildcard": mapped = "DOMAIN-WILDCARD"
        case "ip-cidr", "ip6-cidr": mapped = "IP-CIDR"
        case "geoip": mapped = "GEOIP"
        case "ip-asn": mapped = "IP-ASN"
        case "user-agent": mapped = "USER-AGENT"
        case "dest-port": mapped = "DST-PORT"
        case "src-port": mapped = "SRC-PORT"
        case "src-ip": mapped = "SRC-IP-CIDR"
        case "protocol": mapped = "PROTOCOL"
        case "network": mapped = "NETWORK"
        default: mapped = type.uppercased() // best-effort pass-through for newer QX types
        }
        var s = "\(mapped),\(t[1]),\(canonicalPolicy(t[2]))"
        if t.count > 3 { s += "," + t.dropFirst(3).joined(separator: ",") }
        return s
    }

    // MARK: - [filter_remote]

    /// `<url>, tag=X, force-policy=P, update-interval=N, enabled=…`.
    private static func appendFilterRemote(line: String, cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        let (positional, kv, _) = remoteLineFields(line)
        guard let url = positional.first else {
            report.warnings.append("quantumultx [filter_remote]: unparsable line skipped: \(line)")
            return
        }
        if let e = kv["enabled"], NCConfImport.boolValue(e) == false { return }
        let name = kv["tag"] ?? NCConfImport.ruleSetName(for: url)
        let forced = kv["force-policy"].map(canonicalPolicy)
        cfg.ruleSets.append(NCRuleSetRef(
            name: name, url: url,
            interval: kv["update-interval"].flatMap { Int($0) } ?? 86400,
            forcedPolicy: forced))
        cfg.rules.append("RULE-SET,\(url),\(forced ?? name)")
    }
}
