import Foundation

/// Importers for the INI-style .conf ecosystems (Surge / Loon, and — in
/// NCQXImport.swift — Quantumult X) into the canonical config model
/// (docs/native-config-model.md §6).
///
/// Shared grammar: `[Section]` headers; full-line comments starting with
/// `#`, `;` or `//`; entries are `key = value` lines or bare payload lines
/// depending on the section. There is NO escaping/nesting in these formats,
/// so comma splitting is a plain split + trim — a value that itself contains
/// a comma (a password, a regex) cannot be represented and is a documented
/// limitation of the source formats, not of this parser.
///
/// Mapping policy (design doc §1): parameters with a canonical meaning are
/// translated to the field names the connector actually reads (server, port,
/// password, cipher, uuid, network, ws-opts, tls, servername/sni,
/// skip-cert-verify, flow, reality-opts…); every other parameter is preserved
/// verbatim under its original (lowercased) key — nothing is dropped
/// silently, and sections with no kernel meaning land in
/// `report.skippedSections`.
enum NCConfImport {

    // MARK: - INI splitting

    struct Section {
        let name: String // as written in the file ("Proxy Group", "MITM")
        let key: String  // lowercased lookup key ("proxy group", "mitm")
        var lines: [String]
    }

    /// Split config text into ordered sections. Comment and blank lines are
    /// dropped; content lines keep their original text (trimmed at the ends).
    /// Lines before the first header are ignored.
    static func splitSections(_ text: String) -> [Section] {
        var out: [Section] = []
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                let name = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                out.append(Section(name: name, key: name.lowercased(), lines: []))
                continue
            }
            guard !out.isEmpty else { continue }
            out[out.count - 1].lines.append(line)
        }
        return out
    }

    /// Sections merged by lookup key (a repeated section keeps file order).
    static func sectionMap(_ sections: [Section]) -> [String: [String]] {
        var map: [String: [String]] = [:]
        for s in sections { map[s.key, default: []].append(contentsOf: s.lines) }
        return map
    }

    // MARK: - Lexical helpers

    /// Comma split + trim, empty tokens dropped (these formats have no
    /// nesting, so no quote/paren awareness is needed or possible).
    static func tokens(_ text: String) -> [String] {
        text.components(separatedBy: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Split a token at its FIRST '=' (values may contain '=', e.g. base64
    /// padding). Returns nil when the token is positional (no '=').
    static func keyValue(_ token: String) -> (key: String, value: String)? {
        guard let eq = token.firstIndex(of: "=") else { return nil }
        let k = String(token[..<eq]).trimmingCharacters(in: .whitespaces)
        let v = String(token[token.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
        guard !k.isEmpty else { return nil }
        return (k, v)
    }

    /// Classify payload tokens into positional tokens (in order) and k=v
    /// parameters (keys lowercased; last value wins, first-seen order kept).
    static func classify(_ toks: [String]) -> (positional: [String], kv: [String: String], order: [String]) {
        var positional: [String] = []
        var kv: [String: String] = [:]
        var order: [String] = []
        for tok in toks {
            if let (k, v) = keyValue(tok) {
                let key = k.lowercased()
                if kv[key] == nil { order.append(key) }
                kv[key] = v
            } else {
                positional.append(tok)
            }
        }
        return (positional, kv, order)
    }

    static func boolValue(_ s: String?) -> Bool? {
        guard let s else { return nil }
        switch s.trimmingCharacters(in: .whitespaces).lowercased() {
        case "true", "1", "yes", "on": return true
        case "false", "0", "no", "off": return false
        default: return nil
        }
    }

    /// YAML-flavoured coercion for verbatim-preserved parameters (mirrors how
    /// the same value would be typed had it come through a Clash.Meta YAML file).
    static func coerce(_ s: String) -> NCJSONValue {
        if let b = boolValue(s) { return .bool(b) }
        if let i = Int(s) { return .number(Double(i)) }
        if let d = Double(s) { return .number(d) }
        return .string(s)
    }

    /// Host portion of a URL for name derivation ("https://a.b/c" → "a.b").
    static func hostDerivedName(_ url: String) -> String {
        if let host = URL(string: url)?.host, !host.isEmpty { return host }
        var rest = url
        if let r = rest.range(of: "://") { rest = String(rest[r.upperBound...]) }
        let host = rest.components(separatedBy: "/").first ?? rest
        return host.isEmpty ? "remote" : host
    }

    /// Name for a rule-set reference: last path component minus extension
    /// ("https://x/reject.list" → "reject"), host-derived as fallback.
    static func ruleSetName(for url: String) -> String {
        var tail = url
        if let q = tail.firstIndex(of: "?") { tail = String(tail[..<q]) }
        if let slash = tail.lastIndex(of: "/") { tail = String(tail[tail.index(after: slash)...]) }
        if let dot = tail.lastIndex(of: "."), dot != tail.startIndex { tail = String(tail[..<dot]) }
        return tail.isEmpty ? hostDerivedName(url) : tail
    }

    /// `pattern = value` line (hosts / general / dns sections): split at the
    /// first '=' and keep the value raw (it may contain ':' or ',').
    static func keyValueLine(_ line: String) -> (key: String, value: String)? {
        guard let (k, v) = keyValue(line) else { return nil }
        return (k, v)
    }

    // MARK: - Shared node-parameter mappings

    /// Copy every unconsumed parameter into `fields` verbatim (coerced).
    static func finishFields(_ fields: inout [String: NCJSONValue],
                             kv: [String: String], order: [String], consumed: Set<String>) {
        for key in order where !consumed.contains(key) {
            if let v = kv[key] { fields[key] = coerce(v) }
        }
    }

    /// Surge/Loon/QX simple-obfs (ss `obfs=http|tls` + obfs-host/obfs-uri)
    /// expressed in the Clash.Meta plugin shape the connector ecosystem uses.
    static func applySimpleObfs(kv: [String: String], consumed: inout Set<String>,
                                fields: inout [String: NCJSONValue]) {
        guard let obfs = kv["obfs"] else { return }
        consumed.insert("obfs")
        fields["plugin"] = .string("obfs")
        var opts: [String: NCJSONValue] = ["mode": .string(obfs)]
        if let h = kv["obfs-host"] { consumed.insert("obfs-host"); opts["host"] = .string(h) }
        if let p = kv["obfs-uri"] { consumed.insert("obfs-uri"); opts["path"] = .string(p) }
        fields["plugin-opts"] = .object(opts)
    }

    /// Shadowsocks cloak and kcptun plugin options in conf lines
    static func applySSPlugin(kv: [String: String], consumed: inout Set<String>,
                              fields: inout [String: NCJSONValue]) {
        guard let rawPlugin = kv["plugin"] else { return }
        consumed.insert("plugin")
        let plugin = rawPlugin.lowercased()
        if plugin.contains("cloak") || plugin.contains("ck-client") {
            fields["plugin"] = .string("cloak")
            var opts: [String: NCJSONValue] = [:]
            let cloakKeys: Set<String> = [
                "servername", "publickey", "uid", "browsersig", "encryptionmethod",
                "transport", "numconn", "streamtimeout", "alternativenames",
                "cdnoriginhost", "cdnwsurlpath", "host", "path"
            ]
            for (k, v) in kv {
                let norm = k.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
                if cloakKeys.contains(norm) {
                    consumed.insert(k)
                    opts[k] = coerce(v)
                }
            }
            if !opts.isEmpty { fields["plugin-opts"] = .object(opts) }
        } else if plugin.contains("kcptun") {
            fields["plugin"] = .string("kcptun")
            var opts: [String: NCJSONValue] = [:]
            let kcptunKeys: Set<String> = [
                "key", "crypt", "mode", "conn", "autoexpire", "scavengettl", "mtu",
                "sndwnd", "rcvwnd", "datashard", "parityshard", "dscp", "nocomp",
                "acknodelay", "nodelay", "interval", "resend", "nc", "nocongestion",
                "sockbuf", "smuxver", "smuxbuf", "framesize", "streambuf", "keepalive"
            ]
            for (k, v) in kv {
                let norm = k.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
                if kcptunKeys.contains(norm) {
                    consumed.insert(k)
                    opts[k] = coerce(v)
                }
            }
            if !opts.isEmpty { fields["plugin-opts"] = .object(opts) }
        }
    }

    /// Apply Surge/Loon `ech=...` / `ech-opts=...` / `ech-config=...` options into `fields["ech-opts"]`.
    static func applyECH(kv: [String: String], consumed: inout Set<String>,
                         fields: inout [String: NCJSONValue]) {
        guard kv["ech"] != nil || kv["ech-opts"] != nil || kv["ech-config"] != nil else { return }
        var q: [String: String] = [:]
        if let v = kv["ech"] { consumed.insert("ech"); q["ech"] = v }
        if let v = kv["ech-opts"] { consumed.insert("ech-opts"); q["ech"] = v }
        if let v = kv["ech-config"] { consumed.insert("ech-config"); q["ech-config"] = v }
        if let v = kv["ech-qsn"] { consumed.insert("ech-qsn"); q["ech-qsn"] = v }
        if let v = kv["ech-query-server-name"] { consumed.insert("ech-query-server-name"); q["ech-qsn"] = v }
        if let v = kv["query-server-name"] { consumed.insert("query-server-name"); q["ech-qsn"] = v }
        if let opts = NCECHOpts.parse(query: q) {
            fields["ech-opts"] = .object(opts.toObject())
        }
    }

    /// Parse a Surge `ws-headers` value ("Host:cdn.example.com", several
    /// headers separated by '|') into a header map.
    static func parseWSHeaders(_ value: String) -> [String: String] {
        var out: [String: String] = [:]
        for part in value.components(separatedBy: "|") {
            let p = part.trimmingCharacters(in: .whitespaces)
            if let colon = p.firstIndex(of: ":") {
                let k = String(p[..<colon]).trimmingCharacters(in: .whitespaces)
                let v = String(p[p.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                if !k.isEmpty { out[k] = v }
            } else if !p.isEmpty, out["Host"] == nil {
                out["Host"] = p
            }
        }
        return out
    }

    /// TLS + WebSocket mapping shared by the Surge/Loon vmess/vless/trojan
    /// spellings: `tls=`/`over-tls=`, `tls-name=`/`tls-host=`/`sni=`,
    /// `ws=true` or `transport=ws|wss`, `ws-path=`/`path=`, `ws-headers=`,
    /// Loon's bare `host=` as the WS Host header.
    static func applyTLSAndWS(kv: [String: String], consumed: inout Set<String>,
                              fields: inout [String: NCJSONValue]) {
        func take(_ k: String) -> String? {
            guard let v = kv[k] else { return nil }
            consumed.insert(k)
            return v
        }
        if let t = take("tls") ?? take("over-tls"), let b = boolValue(t) {
            fields["tls"] = .bool(b)
        }
        if let sni = take("tls-name") ?? take("tls-host") ?? take("sni") ?? take("servername") {
            fields["sni"] = .string(sni)
            fields["servername"] = .string(sni)
        }
        var isWS = false
        if let w = take("ws"), boolValue(w) == true { isWS = true }
        if let tr = take("transport") {
            switch tr.lowercased() {
            case "ws": isWS = true
            case "wss": isWS = true; fields["tls"] = .bool(true)
            case "tcp": break
            default: fields["network"] = .string(tr.lowercased()) // grpc/h2/…: preserved; connector rejects until supported
            }
        }
        if isWS {
            fields["network"] = .string("ws")
            var opts: [String: NCJSONValue] = [:]
            if let p = take("ws-path") ?? take("path") { opts["path"] = .string(p) }
            var headers: [String: String] = [:]
            if let wh = take("ws-headers") { headers = parseWSHeaders(wh) }
            if headers["Host"] == nil, let h = take("host") { headers["Host"] = h }
            if !headers.isEmpty { opts["headers"] = .object(headers.mapValues { .string($0) }) }
            if !opts.isEmpty { fields["ws-opts"] = .object(opts) }
        }
    }

    // MARK: - Surge/Loon [Proxy] node lines

    /// Parse `Name = type, server, port, k=v…` (direct/reject have no
    /// server/port). Returns nil for non-node lines.
    static func parseNamedNodeLine(_ line: String) -> (name: String, positional: [String], kv: [String: String], order: [String])? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return nil }
        let rhs = String(line[line.index(after: eq)...])
        let (positional, kv, order) = classify(tokens(rhs))
        guard !positional.isEmpty else { return nil }
        return (name, positional, kv, order)
    }

    /// Build a canonical node from a Surge/Loon [Proxy] line. The type
    /// vocabulary is normalized to the spellings the rest of the native core
    /// already uses (ss / vmess / vless / trojan / socks5 / http / https /
    /// hysteria2 / snell / tuic / wireguard / direct / reject).
    static func buildSurgeLikeNode(name: String, positional: [String],
                                   kv: [String: String], order: [String],
                                   report: inout NCImportReport) -> NCProxy? {
        let rawType = positional[0].lowercased()
        var fields: [String: NCJSONValue] = [:]
        var consumed: Set<String> = []
        func take(_ k: String) -> String? {
            guard let v = kv[k] else { return nil }
            consumed.insert(k)
            return v
        }

        let type: String
        switch rawType {
        case "ss", "shadowsocks": type = "ss"
        case "ssr", "shadowsocksr": type = "ssr"
        case "vmess": type = "vmess"
        case "vless": type = "vless"
        case "trojan": type = "trojan"
        case "socks5": type = "socks5"
        case "socks5-tls": type = "socks5"; fields["tls"] = .bool(true)
        case "http": type = "http"
        case "https": type = "https"
        case "snell": type = "snell"
        case "tuic": type = "tuic"
        case "juicity": type = "juicity"
        case "hysteria2", "hy2": type = "hysteria2"
        case "hysteria":
            type = "hysteria2"
            report.warnings.append("node '\(name)': hysteria v1 approximated as hysteria2")
        case "wireguard": type = "wireguard"
        // feat/nc-gost-relay: Shadowrocket `Name = relay, host, port, user, pass, …` (GOST relay; a [Proxy] node
        // line, unrelated to the `relay` chain group) and the Clash.Meta spelling.
        case "relay", "gost-relay", "gostrelay": type = "gost-relay"
        case "lua": type = "lua"
        case "direct": type = "direct"
        case "reject", "reject-tinygif": type = "reject"
        default:
            type = rawType
            report.warnings.append("node '\(name)': unrecognized proxy type '\(rawType)' kept verbatim")
        }

        // Positional server/port (absent for direct/reject).
        if type != "direct", type != "reject" {
            if positional.count >= 2 { fields["server"] = .string(positional[1]) }
            if positional.count >= 3, let port = Int(positional[2]) {
                fields["port"] = .number(Double(port))
            } else if positional.count >= 2 {
                report.warnings.append("node '\(name)': missing or unparseable port")
            }
        }

        // Common parameters.
        if let v = take("udp-relay") ?? take("udp"), let b = boolValue(v) { fields["udp"] = .bool(b) }
        if let v = take("tfo") ?? take("fast-open"), let b = boolValue(v) { fields["tfo"] = .bool(b) }
        if let v = take("skip-cert-verify") ?? take("allow-insecure") ?? take("allowInsecure"), let b = boolValue(v) { fields["skip-cert-verify"] = .bool(b) }
        applyECH(kv: kv, consumed: &consumed, fields: &fields)

        switch type {
        case "ss":
            if let c = take("encrypt-method") ?? take("method") { fields["cipher"] = .string(c) }
            if let p = take("password") { fields["password"] = .string(p) }
            applySimpleObfs(kv: kv, consumed: &consumed, fields: &fields)
            applySSPlugin(kv: kv, consumed: &consumed, fields: &fields)
        case "vmess":
            // Surge/Loon spell the UUID `username`.
            if let u = take("username") ?? take("uuid") { fields["uuid"] = .string(u) }
            if let a = take("alterid") ?? take("alter-id"), let n = Int(a) { fields["alterId"] = .number(Double(n)) }
            if let c = take("encrypt-method") ?? take("method") { fields["cipher"] = .string(c) }
            applyTLSAndWS(kv: kv, consumed: &consumed, fields: &fields)
        case "vless":
            if let u = take("username") ?? take("uuid") ?? take("password") { fields["uuid"] = .string(u) }
            if let f = take("flow") { fields["flow"] = .string(f) }
            if let pub = take("reality-public-key") {
                var opts: [String: NCJSONValue] = ["public-key": .string(pub)]
                if let sid = take("reality-short-id") { opts["short-id"] = .string(sid) }
                fields["reality-opts"] = .object(opts)
            }
            applyTLSAndWS(kv: kv, consumed: &consumed, fields: &fields)
        case "trojan":
            if let p = take("password") { fields["password"] = .string(p) }
            applyTLSAndWS(kv: kv, consumed: &consumed, fields: &fields)
        case "snell":
            if let p = take("psk") ?? take("password") { fields["password"] = .string(p) }
            if let v = take("version"), let n = Int(v) { fields["version"] = .number(Double(n)) }
            if let o = take("obfs") { fields["obfs"] = .string(o) }
            if let h = take("obfs-host") { fields["obfs-host"] = .string(h) }
        case "tuic":
            if let p = take("password") { fields["password"] = .string(p) }
            // `token` stays under its own name (verbatim pass would coerce
            // it identically, but tuic auth is either password or token).
            if let t = take("token") { fields["token"] = .string(t) }
            if let s = take("sni") { fields["sni"] = .string(s) }
        case "juicity":
            if let u = take("uuid") ?? take("user") ?? take("username") { fields["uuid"] = .string(u) }
            if let p = take("password") { fields["password"] = .string(p) }
            if let s = take("sni") ?? take("peer") ?? take("tls-host") ?? take("tls-name") { fields["sni"] = .string(s) }
            if let cc = take("congestion-controller") ?? take("congestion-control") ?? take("congestion_control") {
                fields["congestion-controller"] = .string(cc)
            }
            if let pin = take("pinned-certchain-sha256") ?? take("pinned_certchain_sha256") ?? take("pinned-peer-cert-sha256") ?? take("cert-sha256") {
                fields["pinned-certchain-sha256"] = .string(pin)
            }
            if let alpn = take("alpn") {
                let parts = alpn.replacingOccurrences(of: "|", with: ",").split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
                fields["alpn"] = .array(parts.map { .string($0) })
            }
        case "hysteria2":
            if let p = take("password") ?? take("auth") { fields["password"] = .string(p) }
            if let s = take("sni") { fields["sni"] = .string(s) }
        case "gost-relay":
            if positional.count >= 4, !positional[3].isEmpty, kv["username"] == nil { fields["username"] = .string(positional[3]) }
            if positional.count >= 5, !positional[4].isEmpty, kv["password"] == nil { fields["password"] = .string(positional[4]) }
            if fields["udp"] == nil { fields["udp"] = .bool(true) }
            consumed.formUnion(NCGostRelay.applyParams(kv, into: &fields))
        case "lua":
            // Shadowrocket Lua custom protocol backend:
            // Node = lua, server, port, file=backend.lua, username=user, password=pass
            if let f = take("file") ?? take("script-path") { fields["file"] = .string(f) }
            if let u = take("username") ?? take("user") { fields["username"] = .string(u) }
            if let p = take("password") { fields["password"] = .string(p) }
            report.warnings.append("node '\(name)': lua proxy backend recognized")
        case "http", "https", "socks5":
            // Surge spells credentials positionally after the port for these
            // types; the k=v form is accepted too.
            if let u = take("username") { fields["username"] = .string(u) }
            else if positional.count >= 4 { fields["username"] = .string(positional[3]) }
            if let p = take("password") { fields["password"] = .string(p) }
            else if positional.count >= 5 { fields["password"] = .string(positional[4]) }
        default:
            break
        }

        finishFields(&fields, kv: kv, order: order, consumed: consumed)
        return NCProxy(name: name, type: type, fields: fields)
    }

    // MARK: - Surge/Loon [Proxy Group] lines

    /// Build a canonical group from `Name = kind, member…, k=v…`. A
    /// `policy-path=` turns the group external and registers a node
    /// subscription under the group's own name (Surge external policies).
    static func buildSurgeLikeGroup(name: String, positional: [String],
                                    kv: [String: String], order: [String],
                                    report: inout NCImportReport) -> (group: NCGroupModel, subscription: NCNodeSubscription?) {
        let rawKind = positional[0].lowercased()
        var kind: NCGroupKind
        switch rawKind {
        case "select": kind = .select
        case "url-test": kind = .urlTest
        case "fallback": kind = .fallback
        case "load-balance": kind = .loadBalance
        case "smart":
            kind = .urlTest
            report.warnings.append("group '\(name)': smart group approximated as url-test")
        case "subnet", "ssid":
            kind = .select // network conditions parsed below into subnetConditions
        default:
            kind = .select
            report.warnings.append("group '\(name)': unrecognized group type '\(rawKind)' treated as select")
        }
        var consumed: Set<String> = []
        func take(_ k: String) -> String? {
            guard let v = kv[k] else { return nil }
            consumed.insert(k)
            return v
        }
        var group = NCGroupModel(name: name, kind: kind, members: Array(positional.dropFirst()))
        if rawKind == "subnet" || rawKind == "ssid" {
            // Surge SUBNET / Loon ssid group: tokens are `SSID:policy`
            // (the SSID may be quoted), plus a DEFAULT entry. Lands in the
            // canonical subnet conditions exactly like the QX ssid policy
            // (NCQXImport); NCGroupEngine evaluates them by current SSID.
            var conditions: [String: String] = [:]
            var members: [String] = []
            for token in positional.dropFirst() {
                guard let colon = token.firstIndex(of: ":") else { continue }
                let ssid = String(token[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
                let target = String(token[token.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                guard !ssid.isEmpty, !target.isEmpty else { continue }
                conditions[ssid] = target
                if !members.contains(target) { members.append(target) }
            }
            if let def = conditions["DEFAULT"] {
                members.removeAll { $0 == def }
                members.insert(def, at: 0)
            }
            group.kind = .select
            group.members = members
            group.subnetConditions = conditions
        }
        if let u = take("url") { group.url = u }
        if let i = take("interval"), let n = Int(i) { group.interval = n }
        if let t = take("tolerance"), let n = Int(t) { group.tolerance = n }
        if take("timeout") != nil {
            report.warnings.append("group '\(name)': timeout has no canonical field and was dropped")
        }
        var subscription: NCNodeSubscription? = nil
        if let path = take("policy-path") {
            group.kind = .external
            var fields: [String: NCJSONValue] = [:]
            if let u = group.url { fields["url"] = .string(u) } // health-check target for the external set
            subscription = NCNodeSubscription(
                name: name, url: path,
                interval: take("update-interval").flatMap { Int($0) } ?? 86400,
                fields: fields)
            group.use = [name]
        } else if take("update-interval") != nil {
            report.warnings.append("group '\(name)': update-interval without policy-path ignored")
        }
        let unmapped = order.filter { !consumed.contains($0) }
        if !unmapped.isEmpty {
            report.warnings.append("group '\(name)': unmapped parameters ignored: \(unmapped.joined(separator: ", "))")
        }
        return (group, subscription)
    }

    // MARK: - Surge/Loon [General]

    /// [General] subset with kernel meaning: DNS servers (plain + encrypted),
    /// ipv6, loglevel, always-real-ip. Other keys are summarized in one
    /// warning (Surge [General] carries many UI/interface settings).
    static func applyGeneral(lines: [String], formatLabel: String,
                             cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        var plain: [NCDNSServerRef] = []
        var encrypted: [NCDNSServerRef] = []
        var unmapped: [String] = []
        let known: Set<String> = ["dns-server", "encrypted-dns-server", "doh-server",
                                  "dot-server", "doq-server", "ipv6", "loglevel", "always-real-ip"]
        for line in lines {
            guard let (rawKey, value) = keyValueLine(line) else { continue }
            let key = rawKey.lowercased()
            switch key {
            case "dns-server":
                plain.append(contentsOf: tokens(value).map(NCDNSServerRef.parse))
            case "encrypted-dns-server", "doh-server":
                encrypted.append(contentsOf: tokens(value).map(NCDNSServerRef.parse))
            case "dot-server":
                encrypted.append(contentsOf: tokens(value).map {
                    NCDNSServerRef.parse($0.contains("://") ? $0 : "tls://" + $0)
                })
            case "doq-server":
                encrypted.append(contentsOf: tokens(value).map {
                    NCDNSServerRef.parse($0.contains("://") ? $0 : "quic://" + $0)
                })
            case "ipv6":
                if let b = boolValue(value) { cfg.ipv6 = b }
            case "loglevel":
                cfg.logLevel = value.lowercased()
            case "always-real-ip":
                cfg.dns.alwaysRealIP.append(contentsOf: tokens(value))
            default:
                if !known.contains(key) { unmapped.append(key) }
            }
        }
        cfg.dns.defaultServers.append(contentsOf: plain + encrypted)
        cfg.dns.encryptedServers = cfg.dns.defaultServers.filter { [.doh, .dot, .doq].contains($0.scheme) }
        if !unmapped.isEmpty {
            report.warnings.append("\(formatLabel) [General]: unmapped keys ignored: \(Array(Set(unmapped)).sorted().joined(separator: ", "))")
        }
    }

    // MARK: - Surge/Loon [Rule]

    /// [Rule] lines are already in the Clash.Meta-style spelling and are kept
    /// verbatim, with two translations: FINAL,x → MATCH,x, and RULE-SET /
    /// DOMAIN-SET lines additionally registering an NCRuleSetRef whose
    /// forced policy is the line's policy column.
    static func processRules(lines: [String], cfg: inout NCCanonicalConfig) {
        for line in lines {
            let t = tokens(line)
            guard let head = t.first else { continue }
            let type = head.uppercased()
            if type == "FINAL", t.count >= 2 {
                var s = "MATCH," + t[1]
                if t.count > 2 { s += "," + t.dropFirst(2).joined(separator: ",") }
                cfg.rules.append(s)
                continue
            }
            if (type == "RULE-SET" || type == "DOMAIN-SET"), t.count >= 3 {
                let ref = t[1], policy = t[2]
                let behavior: NCJSONValue = .string(type == "DOMAIN-SET" ? "domain" : "classical")
                if ref.contains("://") {
                    cfg.ruleSets.append(NCRuleSetRef(name: ruleSetName(for: ref), url: ref,
                                                     forcedPolicy: policy, fields: ["behavior": behavior]))
                } else { // Surge built-in sets (SYSTEM, LAN, …) have no URL
                    cfg.ruleSets.append(NCRuleSetRef(name: ref, url: nil,
                                                     forcedPolicy: policy, fields: ["behavior": behavior]))
                }
            }
            cfg.rules.append(line)
        }
    }

    // MARK: - Surge

    static func surge(_ text: String) -> NCCanonicalConfig {
        var report = NCImportReport()
        var cfg = NCCanonicalConfig(sourceFormat: "surge")
        let sections = splitSections(text)
        let map = sectionMap(sections)
        let handled: Set<String> = ["general", "proxy", "proxy group", "rule", "host",
                                    "mitm", "url rewrite", "header rewrite", "script", "body rewrite", "map local"]
        for s in sections where !handled.contains(s.key) { report.skippedSections.append(s.name) }

        if let lines = map["general"] { applyGeneral(lines: lines, formatLabel: "surge", cfg: &cfg, report: &report) }
        if let lines = map["mitm"] { applyMitm(lines: lines, cfg: &cfg) }
        if let lines = map["url rewrite"] { applyURLRewrite(lines: lines, cfg: &cfg) }
        if let lines = map["header rewrite"] { applyHeaderRewrite(lines: lines, cfg: &cfg) }
        if let lines = map["script"] { applyScript(lines: lines, cfg: &cfg) }
        if let lines = map["proxy"] {
            for line in lines {
                guard let p = parseNamedNodeLine(line) else {
                    report.warnings.append("surge [Proxy]: unparsable line skipped: \(line)")
                    continue
                }
                if let node = buildSurgeLikeNode(name: p.name, positional: p.positional, kv: p.kv, order: p.order, report: &report) {
                    cfg.nodes.append(node)
                }
            }
        }
        if let lines = map["proxy group"] {
            for line in lines {
                guard let parsed = parseNamedNodeLine(line) else {
                    report.warnings.append("surge [Proxy Group]: unparsable line skipped: \(line)")
                    continue
                }
                let (group, sub) = buildSurgeLikeGroup(name: parsed.name, positional: parsed.positional,
                                                       kv: parsed.kv, order: parsed.order, report: &report)
                cfg.groups.append(group)
                if let sub { cfg.subscriptions.append(sub) }
            }
        }
        if let lines = map["rule"] { processRules(lines: lines, cfg: &cfg) }
        if let lines = map["host"] {
            for line in lines {
                if let (pattern, value) = keyValueLine(line) {
                    cfg.hosts.append(NCHostEntry(pattern: pattern, value: value))
                }
            }
        }
        cfg.report = report
        return cfg
    }

    // MARK: - Loon

    static func loon(_ text: String) -> NCCanonicalConfig {
        var report = NCImportReport()
        var cfg = NCCanonicalConfig(sourceFormat: "loon")
        let sections = splitSections(text)
        let map = sectionMap(sections)
        let handled: Set<String> = ["general", "proxy", "proxy group", "rule", "host", "remote proxy", "remote rule",
                                    "mitm", "url rewrite", "header rewrite", "script", "rewrite"]
        for s in sections where !handled.contains(s.key) { report.skippedSections.append(s.name) }

        if let lines = map["general"] { applyGeneral(lines: lines, formatLabel: "loon", cfg: &cfg, report: &report) }
        if let lines = map["mitm"] { applyMitm(lines: lines, cfg: &cfg) }
        if let lines = map["url rewrite"] { applyURLRewrite(lines: lines, cfg: &cfg) }
        if let lines = map["rewrite"] { applyURLRewrite(lines: lines, cfg: &cfg, typeOmittedIsHeader: false) }
        if let lines = map["header rewrite"] { applyHeaderRewrite(lines: lines, cfg: &cfg) }
        if let lines = map["script"] { applyScript(lines: lines, cfg: &cfg) }
        if let lines = map["proxy"] {
            for line in lines {
                guard let p = parseNamedNodeLine(line) else {
                    report.warnings.append("loon [Proxy]: unparsable line skipped: \(line)")
                    continue
                }
                if let node = buildSurgeLikeNode(name: p.name, positional: p.positional, kv: p.kv, order: p.order, report: &report) {
                    cfg.nodes.append(node)
                }
            }
        }
        if let lines = map["proxy group"] {
            for line in lines {
                guard let parsed = parseNamedNodeLine(line) else {
                    report.warnings.append("loon [Proxy Group]: unparsable line skipped: \(line)")
                    continue
                }
                let (group, sub) = buildSurgeLikeGroup(name: parsed.name, positional: parsed.positional,
                                                       kv: parsed.kv, order: parsed.order, report: &report)
                cfg.groups.append(group)
                if let sub { cfg.subscriptions.append(sub) }
            }
        }
        // Local [Rule] first…
        if let lines = map["rule"] { processRules(lines: lines, cfg: &cfg) }
        // …then [Remote Proxy] subscriptions.
        if let lines = map["remote proxy"] {
            for line in lines { appendRemoteProxy(line: line, cfg: &cfg, report: &report) }
        }
        // …then [Remote Rule] references. NOTE: .conf sections carry no
        // interleaving order, so remote-rule RULE-SET lines are appended
        // AFTER the local [Rule] lines even if the section appears earlier
        // in the file (a deliberate, documented deviation from a strict
        // per-file reading of Loon semantics).
        if let lines = map["remote rule"] {
            for line in lines { appendRemoteRule(line: line, cfg: &cfg, report: &report) }
        }
        if let lines = map["host"] {
            for line in lines {
                if let (pattern, value) = keyValueLine(line) {
                    cfg.hosts.append(NCHostEntry(pattern: pattern, value: value))
                }
            }
        }
        cfg.report = report
        return cfg
    }

    /// Loon [Remote Proxy]: a bare subscription URL, or
    /// `Name = <url>, update-interval=…, enabled=…`.
    private static func appendRemoteProxy(line: String, cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        var name: String? = nil
        var payload = line
        // A bare-URL line starts with the URL itself; in the named form the
        // name precedes the first '=' and the remainder starts with the URL
        // (a bare URL's query string may contain '=' and must not be split).
        if !line.lowercased().hasPrefix("http"), let eq = line.firstIndex(of: "=") {
            let lhs = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            let rhs = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if rhs.lowercased().hasPrefix("http") {
                name = lhs
                payload = rhs
            }
        }
        let (positional, kv, order) = classify(tokens(payload))
        guard let url = positional.first else {
            report.warnings.append("loon [Remote Proxy]: unparsable line skipped: \(line)")
            return
        }
        if let e = kv["enabled"], boolValue(e) == false { return } // disabled subscription: skipped by design
        var fields: [String: NCJSONValue] = [:]
        finishFields(&fields, kv: kv, order: order, consumed: ["enabled", "update-interval"])
        cfg.subscriptions.append(NCNodeSubscription(
            name: name ?? hostDerivedName(url), url: url,
            interval: kv["update-interval"].flatMap { Int($0) } ?? 86400,
            fields: fields))
    }

    /// Loon [Remote Rule]: `<url>, policy=<p>, tag=<name>, enabled=…` or a
    /// bare URL. Registers the rule-set ref and appends the RULE-SET rule.
    private static func appendRemoteRule(line: String, cfg: inout NCCanonicalConfig, report: inout NCImportReport) {
        let (positional, kv, _) = classify(tokens(line))
        guard let url = positional.first else {
            report.warnings.append("loon [Remote Rule]: unparsable line skipped: \(line)")
            return
        }
        if let e = kv["enabled"], boolValue(e) == false { return }
        let policy = kv["policy"]
        let name = kv["tag"] ?? ruleSetName(for: url)
        cfg.ruleSets.append(NCRuleSetRef(
            name: name, url: url,
            interval: kv["update-interval"].flatMap { Int($0) } ?? 86400,
            forcedPolicy: policy))
        if let policy {
            cfg.rules.append("RULE-SET,\(url),\(policy)")
        } else {
            // Without a policy column the set's own per-line policies apply;
            // the canonical rule still needs one, so reference the set name.
            cfg.rules.append("RULE-SET,\(url),\(name)")
            report.warnings.append("loon [Remote Rule]: '\(url)' has no policy=; referencing it by name '\(name)'")
        }
    }

    // MARK: - MitM & Rewrite Import Helpers

    static func applyMitm(lines: [String], cfg: inout NCCanonicalConfig) {
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") || trimmed.hasPrefix(";") { continue }
            guard let (k, v) = keyValueLine(trimmed) else { continue }
            let key = k.lowercased()
            switch key {
            case "hostname":
                let hosts = v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                cfg.mitm.hostnames.append(contentsOf: hosts)
                cfg.mitm.enabled = true
            case "skip-server-cert-verify":
                cfg.mitm.skipCertVerify = boolValue(v) ?? false
            case "h2":
                cfg.mitm.h2 = boolValue(v) ?? true
            case "enable":
                cfg.mitm.enabled = boolValue(v) ?? true
            default:
                break
            }
        }
    }

    /// URL actions, normalized the way the App parser does (EngineParser
    /// NCEngineRuleset.urlActions / normURLAction), so the tunnel's .conf path and
    /// the App's module path read the same line the same way (review M1).
    static let urlRewriteActions: Set<String> = ["reject", "reject-200", "reject-img", "reject-dict", "reject-array",
                                                 "reject-drop", "reject-no-drop", "reject-tinygif", "reject-video",
                                                 "302", "307", "301", "header"]

    static func normURLRewriteAction(_ a0: String) -> String {
        switch a0.lowercased() {
        case "reject-tinygif": return "reject-img"
        case "reject-no-drop": return "reject"
        case "reject-video": return "reject-200"
        case "301": return "302"
        default: return a0.lowercased()
        }
    }

    /// [URL Rewrite] / Loon [Rewrite] lines, in the App parser's order:
    ///   Loon   <regex> <action> [target]          (action in the middle)
    ///   Surge  <regex> <replacement> <type>       (type last)
    ///   Surge  <regex> <replacement>              type omitted -> `header`, a transparent
    ///          rewrite of the upstream request (manual.nssurge.com/http/url-rewrite.html:
    ///          "If the type is omitted, header is used") — only in a [URL Rewrite] section
    ///          (`typeOmittedIsHeader`); it used to be read as a 302 to the client.
    /// Anything else is not a URL rewrite and is skipped.
    static func applyURLRewrite(lines: [String], cfg: inout NCCanonicalConfig, typeOmittedIsHeader: Bool = true) {
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") || trimmed.hasPrefix(";") { continue }
            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 2 else { continue }
            let pattern = parts[0]
            let second = parts[1].lowercased()
            if urlRewriteActions.contains(second) {
                let action = normURLRewriteAction(second)
                let target: String? = parts.count >= 3 ? parts[2] : nil
                if (action == "302" || action == "307" || action == "header") && (target ?? "").isEmpty { continue }
                cfg.rewrites.append(NCRewriteRule(kind: "url", phase: "request", pattern: pattern, action: action, target: target))
                continue
            }
            if parts.count >= 3 {
                let last = parts[parts.count - 1].lowercased()
                if urlRewriteActions.contains(last) {
                    cfg.rewrites.append(NCRewriteRule(kind: "url", phase: "request", pattern: pattern,
                                                      action: normURLRewriteAction(last), target: parts[1]))
                }
                continue
            }
            if typeOmittedIsHeader {
                cfg.rewrites.append(NCRewriteRule(kind: "url", phase: "request", pattern: pattern, action: "header", target: parts[1]))
            }
        }
    }

    static func applyHeaderRewrite(lines: [String], cfg: inout NCCanonicalConfig) {
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") || trimmed.hasPrefix(";") { continue }
            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 3 else { continue }
            let pattern = parts[0]
            let op = parts[1]
            let header = parts[2]
            let value = parts.count > 3 ? parts.dropFirst(3).joined(separator: " ") : nil
            cfg.rewrites.append(NCRewriteRule(kind: "header", phase: "request", pattern: pattern, action: op, target: value, extra: ["op": op, "header": header]))
        }
    }

    static func applyScript(lines: [String], cfg: inout NCCanonicalConfig) {
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") || trimmed.hasPrefix(";") { continue }
            if trimmed.hasPrefix("http-request ") || trimmed.hasPrefix("http-response ") {
                let type = trimmed.hasPrefix("http-response ") ? "http-response" : "http-request"
                let rest = String(trimmed.dropFirst(type.count + 1)).trimmingCharacters(in: .whitespaces)
                let tokens = rest.split(separator: ",", omittingEmptySubsequences: true).map { $0.trimmingCharacters(in: .whitespaces) }
                guard !tokens.isEmpty else { continue }
                let pattern = tokens[0]
                var name = "script"
                var path = ""
                var reqBody = false
                var extra: [String: String] = [:]
                for t in tokens.dropFirst() {
                    if let eq = t.firstIndex(of: "=") {
                        let k = String(t[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                        let v = String(t[t.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                        if k == "tag" || k == "name" { name = v }
                        else if k == "script-path" { path = v }
                        else if k == "requires-body" { reqBody = (boolValue(v) ?? false) }
                        else { extra[k] = v }
                    }
                }
                if path.lowercased().hasSuffix(".lua") || type.lowercased() == "lua" || extra["engine"]?.lowercased() == "lua" {
                    extra["engine"] = "lua"
                    extra["status"] = "unsupported"
                    cfg.report.warnings.append("script '\(name)': lua script recognized (unsupported: HTTP-layer Lua scripts are outside the Lua backend engine's scope)")
                }
                cfg.scripts.append(NCScriptRule(name: name, type: type, pattern: pattern, scriptPath: path, requiresBody: reqBody, extra: extra))
            } else if let eq = trimmed.firstIndex(of: "=") {
                let name = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces)
                let params = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                let tokens = params.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                var type = "http-request"
                var pattern = ""
                var path = ""
                var reqBody = false
                var extra: [String: String] = [:]
                for t in tokens {
                    if let peq = t.firstIndex(of: "=") {
                        let k = String(t[..<peq]).trimmingCharacters(in: .whitespaces).lowercased()
                        let v = String(t[t.index(after: peq)...]).trimmingCharacters(in: .whitespaces)
                        if k == "type" { type = v }
                        else if k == "pattern" { pattern = v }
                        else if k == "script-path" { path = v }
                        else if k == "requires-body" { reqBody = (boolValue(v) ?? (v == "1")) }
                        else { extra[k] = v }
                    }
                }
                if path.lowercased().hasSuffix(".lua") || type.lowercased() == "lua" || extra["engine"]?.lowercased() == "lua" {
                    extra["engine"] = "lua"
                    extra["status"] = "unsupported"
                    cfg.report.warnings.append("script '\(name)': lua script recognized (unsupported: HTTP-layer Lua scripts are outside the Lua backend engine's scope)")
                }
                if !pattern.isEmpty {
                    cfg.scripts.append(NCScriptRule(name: name, type: type, pattern: pattern, scriptPath: path, requiresBody: reqBody, extra: extra))
                }
            }
        }
    }
}
