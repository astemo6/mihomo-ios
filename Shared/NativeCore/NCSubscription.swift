import Foundation

/// Node-subscription content parsing + filtering + cached store.
///
/// Every subscription format in the wild reduces to one of:
/// - a Clash/mihomo YAML document with `proxies:`
/// - a base64 blob of newline-separated share URIs (ss/vmess/vless/trojan/
///   hysteria2/tuic) — the "airport" format QX/Loon/Surge all consume
/// - the same URI list in plain text
///
/// Parsed nodes use the canonical parameter-bag shape (NCProxy) with the
/// field names the connector reads. Name collisions get " 2", " 3", …
/// suffixes, like the reference apps do.
enum NCSubscriptionParser {
    static func parse(_ text: String) -> [NCProxy] {
        var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("\u{FEFF}") { trimmed.removeFirst() }
        if trimmed.hasPrefix("proxies:") || trimmed.contains("\nproxies:") {
            if let nodes = parseClashYAML(trimmed) { return dedup(nodes) }
        }
        // bridge nodes.go parseNodeText: JSON is tried on the raw text, then
        // unconditionally on the base64-decoded text (a padded JSON blob used
        // to fall through here because the first branch required no "=").
        if let jsonNodes = parseJSONNodes(trimmed) {
            return dedup(jsonNodes)
        }
        var body = trimmed
        if let decoded = tryB64Text(body), let jsonNodes = parseJSONNodes(decoded) {
            return dedup(jsonNodes)
        }
        if !body.contains("://") && !body.contains("=") {
            if let decoded = tryB64Text(body) { body = decoded }
        } else if let decoded = tryB64Text(body), decoded.contains("://") {
            body = decoded
        }
        // bridge nodes.go parseNodeText order: self-parsed lines (QX / Surge
        // named lines and the wireguard / snell / ssh / socks-http schemes)
        // come first in line order; all other :// URIs are collected and
        // converted afterwards. Member order and dedup numbering follow.
        var selfParsed: [NCProxy] = []
        var uriParsed: [NCProxy] = []
        let selfSchemes: Set<String> = ["wireguard", "wg", "snell", "ssh", "socks", "socks5", "socks5h", "http", "https"]
        for line in body.components(separatedBy: .newlines) {
            let l = line.trimmingCharacters(in: .whitespaces)
            if l.isEmpty || l.hasPrefix("#") || l.hasPrefix("//") || l.hasPrefix(";") || l.hasPrefix("[") {
                continue
            }
            if let sep = l.range(of: "://") {
                let scheme = l[..<sep.lowerBound].lowercased()
                guard let n = parseURI(l) else { continue }
                if selfSchemes.contains(scheme) { selfParsed.append(n) } else { uriParsed.append(n) }
            } else if l.contains("=") {
                var dummy = NCImportReport()
                if let qx = NCQXImport.buildQXNode(line: l, report: &dummy) {
                    selfParsed.append(qx)
                } else if let parsed = NCConfImport.parseNamedNodeLine(l),
                          let surge = NCConfImport.buildSurgeLikeNode(name: parsed.name, positional: parsed.positional, kv: parsed.kv, order: parsed.order, report: &dummy) {
                    selfParsed.append(surge)
                }
            }
        }
        return dedup(selfParsed + uriParsed)
    }

    /// bridge nodes.go tryB64: reject when the trimmed text still contains a
    /// space or tab; strip CR/LF (line-wrapped blobs) before decoding.
    private static func tryB64Text(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty || t.contains(" ") || t.contains("\t") { return nil }
        let stripped = t.replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        guard let data = base64Decode(stripped) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Parse nodes from text directly into dictionary representation.
    static func parseToDictionaries(_ text: String) -> [[String: Any]] {
        parse(text).map { $0.dictionary }
    }

    // MARK: Clash YAML

    static func parseClashYAML(_ text: String) -> [NCProxy]? {
        guard let root = NCYAML.parse(text) else { return nil }
        let cfg = NCConfig.decode(root: root.object ?? [:])
        return cfg.proxies.isEmpty ? nil : cfg.proxies
    }

    // MARK: URI schemes

    static func parseURI(_ uri: String) -> NCProxy? {
        guard let sep = uri.range(of: "://") else { return nil }
        let scheme = uri[..<sep.lowerBound].lowercased()
        let rest = String(uri[sep.upperBound...])
        switch scheme {
        case "ss": return parseSS(rest)
        case "ssr": return parseSSR(rest)
        case "vmess": return parseVMess(rest)
        case "vless": return parseVLESS(rest)
        case "trojan": return parseTrojan(rest)
        case "hysteria2", "hy2": return parseHysteria2(rest)
        case "hysteria": return parseHysteria1(rest)
        case "tuic": return parseTUIC(rest)
        case "wireguard", "wg": return parseWireGuard(rest, scheme: scheme)
        case "snell": return parseSnell(rest)
        case "ssh": return parseSSH(rest)
        case "socks", "socks5", "socks5h", "http", "https": return parseSocksHTTP(rest, scheme: scheme)
        case "anytls": return parseAnyTLS(rest)
        case "mieru", "mierus": return parseMieru(rest)
        default: return nil
        }
    }

    /// Split `userinfo@host:port?query#name` (query/name optional).
    private struct Parts {
        var userinfo: String = ""
        var host: String = ""
        var port: Int = 0
        var query: [String: String] = [:]
        var name: String = ""
    }

    private static func splitParts(_ rest: String) -> Parts {
        var p = Parts()
        var s = rest
        if let hash = s.firstIndex(of: "#") {
            p.name = String(s[s.index(after: hash)...]).removingPercentEncoding ?? ""
            s = String(s[..<hash])
        }
        if let q = s.firstIndex(of: "?") {
            let qs = s[s.index(after: q)...]
            s = String(s[..<q])
            for pair in qs.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 {
                    p.query[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
                }
            }
        }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) } // stray path
        if let at = s.lastIndex(of: "@") {
            p.userinfo = String(s[..<at])
            s = String(s[s.index(after: at)...])
        }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            p.host = String(s[s.index(after: s.startIndex)..<close])
            let tail = s[s.index(after: close)...]
            if tail.hasPrefix(":") { p.port = Int(tail.dropFirst()) ?? 0 }
        } else if let colon = s.lastIndex(of: ":") {
            p.host = String(s[..<colon])
            p.port = Int(s[s.index(after: colon)...]) ?? 0
        } else {
            p.host = s
        }
        return p
    }

    private static func base64Decode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }

    private static func fields(_ pairs: [(String, NCJSONValue?)]) -> [String: NCJSONValue] {
        var out: [String: NCJSONValue] = [:]
        for (k, v) in pairs { if let v { out[k] = v } }
        return out
    }

    private static func str(_ v: String?) -> NCJSONValue? {
        guard let v, !v.isEmpty else { return nil }
        return .string(v)
    }

    // ss://base64(method:password)@host:port#name | ss://method:pass@… | legacy whole-base64
    private static func parseSS(_ rest: String) -> NCProxy? {
        // Legacy: the entire rest (minus #name) is one base64 blob.
        var body = rest
        var frag = ""
        if let hash = body.firstIndex(of: "#") {
            frag = String(body[body.index(after: hash)...]).removingPercentEncoding ?? ""
            body = String(body[..<hash])
        }
        if !body.contains("@"), let decoded = base64Decode(body),
           let s = String(data: decoded, encoding: .utf8), s.contains("@") {
            var p = splitParts(s)
            p.name = frag
            return ssNode(p, userinfo: p.userinfo)
        }
        let p = splitParts(rest)
        return ssNode(p, userinfo: p.userinfo.removingPercentEncoding ?? p.userinfo)
    }

    private static func ssNode(_ p: Parts, userinfo: String) -> NCProxy? {
        var ui = userinfo
        // bridge nodes.go: the base64 userinfo replaces the raw one only when
        // the decoded text actually contains ":" (a bare method name that
        // happens to base64-decode must not clobber the credentials).
        if !ui.contains(":"), let decoded = base64Decode(ui),
           let s = String(data: decoded, encoding: .utf8), s.contains(":") {
            ui = s
        }
        let kv = ui.split(separator: ":", maxSplits: 1)
        guard kv.count == 2, !p.host.isEmpty, p.port > 0 else { return nil }
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("cipher", str(String(kv[0]))), ("password", str(String(kv[1]))),
            ("udp", .bool(true)),
        ])
        // SIP002 plugin query: "<binary>[;arg=value…]" — the binary name
        // picks the plugin, the rest re-parses as a query string. A bare
        // binary without ";" (plugin=obfs-local) is a plugin too. Mirrors
        // mihomo common/convert/converter.go so links from any client land
        // in the same canonical shape as a mihomo YAML node.
        if let plugin = p.query["plugin"], !plugin.isEmpty {
            let parts = plugin.split(separator: ";")
            let binary = String(parts[0])
            var args: [String: String] = [:]
            for part in parts.dropFirst() {
                let kv = part.split(separator: "=", maxSplits: 1).map(String.init)
                if kv.count == 2 {
                    args[kv[0]] = kv[1].removingPercentEncoding ?? kv[1]
                } else if kv.count == 1, !kv[0].isEmpty {
                    args[kv[0]] = "" // bare flag (v2ray-plugin's "tls")
                }
            }
            func arg(_ k: String) -> String? {
                guard let v = args[k], !v.isEmpty else { return nil }
                return v
            }
            if binary.contains("obfs") {
                f["plugin"] = .string("obfs")
                var opts: [String: NCJSONValue] = [:]
                if let m = arg("obfs") { opts["mode"] = .string(m) }
                if let h = arg("obfs-host") { opts["host"] = .string(h) }
                if !opts.isEmpty { f["plugin-opts"] = .object(opts) }
            } else if binary.contains("v2ray-plugin") {
                f["plugin"] = .string("v2ray-plugin")
                var opts: [String: NCJSONValue] = [:]
                opts["mode"] = .string(arg("mode") ?? arg("obfs") ?? "websocket")
                if let h = arg("host") ?? arg("obfs-host") { opts["host"] = .string(h) }
                if let pa = arg("path") { opts["path"] = .string(pa) }
                // mihomo detects the TLS flag with strings.Contains over the
                // whole plugin value — kept for byte-for-byte parity with
                // Libmihome on the same link.
                if plugin.contains("tls") { opts["tls"] = .bool(true) }
                f["plugin-opts"] = .object(opts)
            } else {
                // Unknown binary: keep it verbatim with its parsed args
                // instead of dropping the plugin on the floor.
                f["plugin"] = .string(binary)
                if !args.isEmpty {
                    f["plugin-opts"] = .object(args.mapValues { .string($0) })
                }
            }
        }
        if p.query["uot"] == "1" || p.query["uot"] == "true" {
            f["udp-over-tcp"] = .bool(true)
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "ss", fields: f)
    }

    // vmess://base64(JSON)
    private static func parseVMess(_ rest: String) -> NCProxy? {
        var body = rest
        if let hash = body.firstIndex(of: "#") { body = String(body[..<hash]) }
        guard let data = base64Decode(body),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        func s(_ k: String) -> String {
            if let v = obj[k] as? String { return v }
            if let v = obj[k] as? NSNumber { return v.stringValue }
            return ""
        }
        let port = Int(s("port")) ?? 0
        guard !s("add").isEmpty, port > 0, !s("id").isEmpty else { return nil }
        var f = fields([
            ("server", str(s("add"))), ("port", .number(Double(port))),
            ("uuid", str(s("id"))),
            ("alterId", .number(Double(Int(s("aid")) ?? 0))),
            ("cipher", str(s("scy").isEmpty ? "auto" : s("scy"))),
            ("udp", .bool(true)),
        ])
        let net = s("net")
        if !net.isEmpty, net != "tcp" { f["network"] = .string(net) }
        if s("tls") == "tls" {
            f["tls"] = .bool(true)
            if !s("sni").isEmpty { f["servername"] = .string(s("sni")) }
            // bridge/share.go writes alpn (comma-joined) and fp for vmess —
            // read them back (alpn may also arrive as a JSON array).
            if let arr = obj["alpn"] as? [Any], !arr.isEmpty {
                f["alpn"] = .array(arr.map { .string(jStr($0)) })
            } else if !s("alpn").isEmpty {
                f["alpn"] = .array(s("alpn").split(separator: ",").map { .string(String($0)) })
            }
            if !s("fp").isEmpty { f["client-fingerprint"] = .string(s("fp")) }
        }
        if net == "ws" || net == "httpupgrade" {
            var opts: [String: NCJSONValue] = [:]
            if !s("path").isEmpty { opts["path"] = .string(s("path")) }
            if !s("host").isEmpty { opts["headers"] = .object(["Host": .string(s("host"))]) }
            f["ws-opts"] = .object(opts)
        }
        if net == "h2" {
            var opts: [String: NCJSONValue] = [:]
            if !s("path").isEmpty { opts["path"] = .string(s("path")) }
            if !s("host").isEmpty { opts["host"] = .array([.string(s("host"))]) }
            f["h2-opts"] = .object(opts)
        }
        if net == "http" {
            var opts: [String: NCJSONValue] = [:]
            if !s("path").isEmpty { opts["path"] = .string(s("path")) }
            if !s("host").isEmpty { opts["headers"] = .object(["Host": .string(s("host"))]) }
            f["http-opts"] = .object(opts)
        }
        if net == "grpc", !s("path").isEmpty {
            f["grpc-opts"] = .object(["grpc-service-name": .string(s("path"))])
        }
        let name = s("ps").isEmpty ? "\(s("add")):\(port)" : s("ps")
        return NCProxy(name: name, type: "vmess", fields: f)
    }

    private static func parseVLESS(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0, !p.userinfo.isEmpty else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("uuid", str(p.userinfo)), ("udp", .bool(true)),
        ])
        if let flow = q["flow"] { f["flow"] = .string(flow) }
        if let enc = q["encryption"] { f["encryption"] = .string(enc) }
        if q["allowInsecure"] == "1" || q["allowInsecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        if let fp = q["fp"] { f["client-fingerprint"] = .string(fp) }
        if let alpn = q["alpn"] {
            f["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0)) })
        }
        let security = q["security"] ?? ""
        if security == "tls" || security == "reality" { f["tls"] = .bool(true) }
        if let sni = q["sni"] ?? q["peer"] { f["servername"] = .string(sni) }
        if security == "reality" {
            var opts: [String: NCJSONValue] = [:]
            if let pbk = q["pbk"] { opts["public-key"] = .string(pbk) }
            if let sid = q["sid"] { opts["short-id"] = .string(sid) }
            f["reality-opts"] = .object(opts)
        }
        let net = q["type"] ?? "tcp"
        if net != "tcp" { f["network"] = .string(net) }
        if net == "ws" || net == "httpupgrade" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["headers"] = .object(["Host": .string(host)]) }
            f["ws-opts"] = .object(opts)
        }
        if net == "h2" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["host"] = .array([.string(host)]) }
            f["h2-opts"] = .object(opts)
        }
        if net == "http" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["headers"] = .object(["Host": .string(host)]) }
            f["http-opts"] = .object(opts)
        }
        if net == "grpc", let svc = q["serviceName"] {
            f["grpc-opts"] = .object(["grpc-service-name": .string(svc)])
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "vless", fields: f)
    }

    private static func parseTrojan(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
            ("password", str(p.userinfo.removingPercentEncoding ?? p.userinfo)),
            ("udp", .bool(true)),
        ])
        if let sni = q["sni"] ?? q["peer"] { f["sni"] = .string(sni) }
        if q["allowInsecure"] == "1" || q["allowInsecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        if let fp = q["fp"] { f["client-fingerprint"] = .string(fp) }
        if let alpn = q["alpn"] {
            f["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0)) })
        }
        // bridge/share.go emits security=reality&pbk&sid for trojan too.
        if q["security"] == "reality" {
            var opts: [String: NCJSONValue] = [:]
            if let pbk = q["pbk"] { opts["public-key"] = .string(pbk) }
            if let sid = q["sid"] { opts["short-id"] = .string(sid) }
            f["reality-opts"] = .object(opts)
        }
        let net = q["type"] ?? "tcp"
        if net != "tcp" { f["network"] = .string(net) }
        if net == "ws" || net == "httpupgrade" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["headers"] = .object(["Host": .string(host)]) }
            f["ws-opts"] = .object(opts)
        }
        if net == "h2" {
            var opts: [String: NCJSONValue] = [:]
            if let path = q["path"] { opts["path"] = .string(path) }
            if let host = q["host"] { opts["host"] = .array([.string(host)]) }
            f["h2-opts"] = .object(opts)
        }
        if net == "grpc", let svc = q["serviceName"] {
            f["grpc-opts"] = .object(["grpc-service-name": .string(svc)])
        }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "trojan", fields: f)
    }

    /// The raw port token of a URI authority (splitParts only keeps the Int,
    /// which port-hopping lists like "443,8443-8449" cannot survive).
    private static func rawPortToken(_ rest: String) -> String {
        var s = rest
        if let h = s.firstIndex(of: "#") { s = String(s[..<h]) }
        if let q = s.firstIndex(of: "?") { s = String(s[..<q]) }
        if let sl = s.firstIndex(of: "/") { s = String(s[..<sl]) }
        if let at = s.lastIndex(of: "@") { s = String(s[s.index(after: at)...]) }
        if s.hasPrefix("[") { return "" }
        guard let c = s.lastIndex(of: ":") else { return "" }
        return String(s[s.index(after: c)...])
    }

    private static func parseHysteria2(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        let q = p.query
        // bridge/share.go emits host:<ports> verbatim for hy2 (port hopping);
        // splitParts' Int() drops such nodes entirely. Recover: first port is
        // the dial port, the raw list lands in "ports".
        var port = p.port
        var portsField: String?
        if port == 0 {
            let token = rawPortToken(rest)
            if token.contains(",") || token.contains("-") {
                portsField = token
                let firstSeg = token.split(separator: ",").first.map(String.init) ?? ""
                port = Int(firstSeg.split(separator: "-").first.map(String.init) ?? "") ?? 0
            }
        }
        if let mp = q["mport"] ?? q["ports"] { portsField = mp }
        guard !p.host.isEmpty, port > 0 else { return nil }
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(port))),
            ("password", str(p.userinfo.removingPercentEncoding ?? p.userinfo)),
        ])
        if let portsField { f["ports"] = .string(portsField) }
        if let sni = q["sni"] { f["sni"] = .string(sni) }
        if q["insecure"] == "1" || q["insecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        if let obfs = q["obfs"] { f["obfs"] = .string(obfs) }
        if let obfsPwd = q["obfs-password"] { f["obfs-password"] = .string(obfsPwd) }
        if let alpn = q["alpn"] {
            f["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0)) })
        }
        if let pin = q["pinSHA256"] { f["fingerprint"] = .string(pin) }
        if let up = q["up"] { f["up"] = .string(up) }
        if let down = q["down"] { f["down"] = .string(down) }
        let name = p.name.isEmpty ? "\(p.host):\(port)" : p.name
        return NCProxy(name: name, type: "hysteria2", fields: f)
    }

    private static func parseTUIC(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        let creds = p.userinfo.split(separator: ":", maxSplits: 1)
        guard !p.host.isEmpty, p.port > 0, !creds.isEmpty else { return nil }
        let q = p.query
        var f = fields([
            ("server", str(p.host)), ("port", .number(Double(p.port))),
        ])
        if creds.count == 2 {
            f["uuid"] = str(String(creds[0]))
            f["password"] = str(String(creds[1]).removingPercentEncoding ?? String(creds[1]))
        } else {
            // Token-only form: bridge/share.go emits the token alone as
            // userinfo when uuid is empty — read it back as "token".
            f["token"] = str(p.userinfo.removingPercentEncoding ?? p.userinfo)
        }
        if let sni = q["sni"] { f["sni"] = .string(sni) }
        if let cc = q["congestion_control"] { f["congestion-controller"] = .string(cc) }
        if let alpn = q["alpn"] { f["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0)) }) }
        if let urm = q["udp_relay_mode"] { f["udp-relay-mode"] = .string(urm) }
        if q["disable_sni"] == "1" || q["disable_sni"] == "true" { f["disable-sni"] = .bool(true) }
        if q["allow_insecure"] == "1" || q["allowInsecure"] == "1" { f["skip-cert-verify"] = .bool(true) }
        let name = p.name.isEmpty ? "\(p.host):\(p.port)" : p.name
        return NCProxy(name: name, type: "tuic", fields: f)
    }

    // bridge nativeformats.go strOf/intOf/boolOf over decoded JSON values.
    private static func jStr(_ v: Any?) -> String { v as? String ?? "" }
    private static func jInt(_ v: Any?) -> Int {
        if let n = v as? NSNumber { return n.intValue }
        if let s = v as? String { return Int(s) ?? 0 }
        return 0
    }
    private static func jBool(_ v: Any?) -> Bool {
        if let b = v as? Bool { return b }
        if let n = v as? NSNumber { return n.boolValue }
        return false
    }

    private static func parseJSONNodes(_ text: String) -> [NCProxy]? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix("{") || t.hasPrefix("["),
              let data = t.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) else {
            return nil
        }
        // SIP008: {"servers": [...]}
        if let json = root as? [String: Any], let servers = json["servers"] as? [[String: Any]] {
            let proxies = servers.compactMap { sip008Node($0) }
            return proxies.isEmpty ? nil : proxies
        }
        // sing-box: {"outbounds": [...]} or a bare outbound array.
        var outbounds: [[String: Any]]?
        if let json = root as? [String: Any] { outbounds = json["outbounds"] as? [[String: Any]] }
        if outbounds == nil, let arr = root as? [[String: Any]] { outbounds = arr }
        guard let outbounds else { return nil }
        let proxies = outbounds.compactMap { singBoxNode($0) }
        return proxies.isEmpty ? nil : proxies
    }

    /// bridge nativeformats.go sip008: only an empty server drops the entry;
    /// name falls back remarks → id → server; plugin_opts is a ";" separated
    /// string parsed into opts; the plugin name is normalized (obfs /
    /// v2ray-plugin with default mode, otherwise kept raw).
    private static func sip008Node(_ s: [String: Any]) -> NCProxy? {
        let server = jStr(s["server"])
        guard !server.isEmpty else { return nil }
        let remarks = jStr(s["remarks"]), ident = jStr(s["id"])
        let name = !remarks.isEmpty ? remarks : (!ident.isEmpty ? ident : server)
        var f: [String: NCJSONValue] = [
            "server": .string(server),
            "port": .number(Double(jInt(s["server_port"]))),
            "cipher": .string(jStr(s["method"])),
            "password": .string(jStr(s["password"])),
            "udp": .bool(true),
        ]
        let plugin = jStr(s["plugin"])
        if !plugin.isEmpty {
            var opts: [String: NCJSONValue] = [:]
            for kv in jStr(s["plugin_opts"]).split(separator: ";", omittingEmptySubsequences: false) {
                let pair = kv.split(separator: "=", maxSplits: 1)
                let k = String(pair[0]).trimmingCharacters(in: .whitespaces)
                let v = pair.count > 1 ? String(pair[1]).trimmingCharacters(in: .whitespaces) : ""
                switch k {
                case "obfs": opts["mode"] = .string(v)
                case "obfs-host", "host": opts["host"] = .string(v)
                case "path": opts["path"] = .string(v)
                case "tls": opts["tls"] = .bool(true)
                case "mode": opts["mode"] = .string(v)
                default: break
                }
            }
            if plugin.contains("obfs") {
                f["plugin"] = .string("obfs")
            } else if plugin.contains("v2ray") {
                f["plugin"] = .string("v2ray-plugin")
                if opts["mode"] == nil { opts["mode"] = .string("websocket") }
            } else {
                f["plugin"] = .string(plugin)
            }
            f["plugin-opts"] = .object(opts)
        }
        return NCProxy(name: name, type: "ss", fields: f)
    }

    /// bridge nativeformats.go singBoxOutbound + singBoxTLS + singBoxTransport.
    /// Types outside the mapped set (selector / urltest / direct / …) drop.
    private static func singBoxNode(_ o: [String: Any]) -> NCProxy? {
        let server = jStr(o["server"])
        guard !server.isEmpty else { return nil }
        let tag = jStr(o["tag"])
        let name = tag.isEmpty ? server : tag
        var f: [String: NCJSONValue] = [
            "server": .string(server),
            "port": .number(Double(jInt(o["server_port"]))),
        ]
        let typ: String
        switch jStr(o["type"]) {
        case "shadowsocks":
            typ = "ss"
            f["cipher"] = .string(jStr(o["method"]))
            f["password"] = .string(jStr(o["password"]))
            f["udp"] = .bool(true)
            if !jStr(o["plugin"]).isEmpty,
               let sp = sip008Node(["server": server, "plugin": jStr(o["plugin"]),
                                    "plugin_opts": jStr(o["plugin_opts"])]) {
                if let pl = sp.fields["plugin"] { f["plugin"] = pl }
                if let po = sp.fields["plugin-opts"] { f["plugin-opts"] = po }
            }
        case "vmess":
            typ = "vmess"
            f["uuid"] = .string(jStr(o["uuid"]))
            f["alterId"] = .number(Double(jInt(o["alter_id"])))
            let sec = jStr(o["security"])
            f["cipher"] = .string(sec.isEmpty ? "auto" : sec)
            f["udp"] = .bool(true)
        case "vless":
            typ = "vless"
            f["uuid"] = .string(jStr(o["uuid"]))
            if !jStr(o["flow"]).isEmpty { f["flow"] = .string(jStr(o["flow"])) }
            f["udp"] = .bool(true)
        case "trojan":
            typ = "trojan"
            f["password"] = .string(jStr(o["password"]))
            f["udp"] = .bool(true)
        case "hysteria2":
            typ = "hysteria2"
            f["password"] = .string(jStr(o["password"]))
            if let obfs = o["obfs"] as? [String: Any], !jStr(obfs["type"]).isEmpty {
                f["obfs"] = .string(jStr(obfs["type"]))
                f["obfs-password"] = .string(jStr(obfs["password"]))
            }
            if jInt(o["up_mbps"]) > 0 { f["up"] = .string("\(jInt(o["up_mbps"])) Mbps") }
            if jInt(o["down_mbps"]) > 0 { f["down"] = .string("\(jInt(o["down_mbps"])) Mbps") }
        case "tuic":
            typ = "tuic"
            f["uuid"] = .string(jStr(o["uuid"]))
            f["password"] = .string(jStr(o["password"]))
            if !jStr(o["congestion_control"]).isEmpty { f["congestion-controller"] = .string(jStr(o["congestion_control"])) }
            if !jStr(o["udp_relay_mode"]).isEmpty { f["udp-relay-mode"] = .string(jStr(o["udp_relay_mode"])) }
        case "anytls":
            typ = "anytls"
            f["password"] = .string(jStr(o["password"]))
            f["udp"] = .bool(true)
        case "socks":
            typ = "socks5"
            if !jStr(o["username"]).isEmpty {
                f["username"] = .string(jStr(o["username"]))
                f["password"] = .string(jStr(o["password"]))
            }
            f["udp"] = .bool(true)
        case "http":
            typ = "http"
            if !jStr(o["username"]).isEmpty {
                f["username"] = .string(jStr(o["username"]))
                f["password"] = .string(jStr(o["password"]))
            }
        case "ssh":
            typ = "ssh"
            let user = jStr(o["user"])
            f["username"] = .string(user.isEmpty ? "root" : user)
            if !jStr(o["password"]).isEmpty { f["password"] = .string(jStr(o["password"])) }
            if !jStr(o["private_key"]).isEmpty { f["private-key"] = .string(jStr(o["private_key"])) }
        case "wireguard":
            typ = "wireguard"
            f["private-key"] = .string(jStr(o["private_key"]))
            f["public-key"] = .string(jStr(o["peer_public_key"]))
            if !jStr(o["pre_shared_key"]).isEmpty { f["pre-shared-key"] = .string(jStr(o["pre_shared_key"])) }
            if let addrs = o["local_address"] as? [Any] {
                for a in addrs {
                    let s = jStr(a).split(separator: "/", maxSplits: 1).first.map(String.init) ?? ""
                    if s.contains(":") { f["ipv6"] = .string(s) }
                    else if f["ip"] == nil { f["ip"] = .string(s) }
                }
            }
            if jInt(o["mtu"]) > 0 { f["mtu"] = .number(Double(jInt(o["mtu"]))) }
            f["udp"] = .bool(true)
        default:
            return nil
        }
        applySingBoxTLS(&f, outbound: o, mappedType: typ)
        applySingBoxTransport(&f, outbound: o)
        return NCProxy(name: name, type: typ, fields: f)
    }

    private static func applySingBoxTLS(_ f: inout [String: NCJSONValue], outbound o: [String: Any], mappedType typ: String) {
        guard let tls = o["tls"] as? [String: Any], jBool(tls["enabled"]) else { return }
        if typ == "vmess" || typ == "vless" || typ == "http" || typ == "socks5" {
            f["tls"] = .bool(true)
        }
        let sn = jStr(tls["server_name"])
        if !sn.isEmpty {
            if typ == "vmess" || typ == "vless" { f["servername"] = .string(sn) } else { f["sni"] = .string(sn) }
        }
        if jBool(tls["insecure"]) { f["skip-cert-verify"] = .bool(true) }
        if let alpn = tls["alpn"] as? [Any], !alpn.isEmpty {
            f["alpn"] = .array(alpn.map { .string(jStr($0)) })
        }
        if let utls = tls["utls"] as? [String: Any], jBool(utls["enabled"]), !jStr(utls["fingerprint"]).isEmpty {
            f["client-fingerprint"] = .string(jStr(utls["fingerprint"]))
        }
        if let reality = tls["reality"] as? [String: Any], jBool(reality["enabled"]) {
            f["reality-opts"] = .object([
                "public-key": .string(jStr(reality["public_key"])),
                "short-id": .string(jStr(reality["short_id"])),
            ])
            if f["client-fingerprint"] == nil { f["client-fingerprint"] = .string("chrome") }
        }
    }

    private static func applySingBoxTransport(_ f: inout [String: NCJSONValue], outbound o: [String: Any]) {
        guard let tr = o["transport"] as? [String: Any] else { return }
        let path = jStr(tr["path"]).isEmpty ? "/" : jStr(tr["path"])
        switch jStr(tr["type"]) {
        case "ws":
            f["network"] = .string("ws")
            var ws: [String: NCJSONValue] = ["path": .string(path)]
            if let h = tr["headers"] as? [String: Any], !h.isEmpty {
                ws["headers"] = .object(h.mapValues { NCJSONValue($0) })
            }
            f["ws-opts"] = .object(ws)
        case "grpc":
            f["network"] = .string("grpc")
            f["grpc-opts"] = .object(["grpc-service-name": .string(jStr(tr["service_name"]))])
        case "http":
            f["network"] = .string("h2")
            var h2: [String: NCJSONValue] = ["path": .string(path)]
            if let hosts = tr["host"] as? [Any], !hosts.isEmpty {
                h2["host"] = .array(hosts.map { .string(jStr($0)) })
            }
            f["h2-opts"] = .object(h2)
        case "httpupgrade":
            f["network"] = .string("ws")
            f["ws-opts"] = .object(["path": .string(path), "v2ray-http-upgrade": .bool(true)])
        default:
            break
        }
    }

    private static func parseSSR(_ rest: String) -> NCProxy? {
        guard let data = base64Decode(rest),
              let decoded = String(data: data, encoding: .utf8) else { return nil }
        let mainAndQuery = decoded.components(separatedBy: "/?")
        let mainParts = mainAndQuery[0].components(separatedBy: ":")
        guard mainParts.count >= 6 else { return nil }
        let server = mainParts[0]
        guard let port = Int(mainParts[1]), port > 0 else { return nil }
        let protocolStr = mainParts[2]
        let cipher = mainParts[3]
        let obfs = mainParts[4]
        let passB64 = mainParts[5]
        let pass = base64Decode(passB64).flatMap { String(data: $0, encoding: .utf8) } ?? passB64

        var name = "\(server):\(port)"
        var obfsParam: String? = nil
        var protoParam: String? = nil
        if mainAndQuery.count > 1 {
            for pair in mainAndQuery[1].components(separatedBy: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                guard kv.count == 2 else { continue }
                let k = String(kv[0]).lowercased()
                let vB64 = String(kv[1])
                let v = base64Decode(vB64).flatMap { String(data: $0, encoding: .utf8) } ?? vB64
                if k == "remarks" { name = v }
                else if k == "obfsparam" { obfsParam = v }
                else if k == "protoparam" { protoParam = v }
            }
        }
        var f: [String: NCJSONValue] = [
            "server": .string(server),
            "port": .number(Double(port)),
            "protocol": .string(protocolStr),
            "cipher": .string(cipher),
            "obfs": .string(obfs),
            "password": .string(pass),
            "udp": .bool(true)
        ]
        if let obfsParam, !obfsParam.isEmpty { f["obfs-param"] = .string(obfsParam) }
        if let protoParam, !protoParam.isEmpty { f["protocol-param"] = .string(protoParam) }
        return NCProxy(name: name, type: "ssr", fields: f)
    }

    private static func parseWireGuard(_ rest: String, scheme: String) -> NCProxy? {
        // bridge nodes.go parseWireGuard: both keys are REQUIRED; alias sets
        // and defaults (ip 172.16.0.2, mtu fallback 1408, reserved raw-string
        // fallback) follow the Go parser exactly.
        let p = splitParts(rest)
        let q = p.query
        let server = p.host
        let port = p.port > 0 ? p.port : 51820
        guard !server.isEmpty else { return nil }
        func firstQ(_ keys: [String]) -> String {
            for k in keys { if let v = q[k], !v.isEmpty { return v } }
            return ""
        }
        var privKey = !p.userinfo.isEmpty ? (p.userinfo.removingPercentEncoding ?? p.userinfo) : ""
        if privKey.isEmpty {
            privKey = firstQ(["privatekey", "private_key", "private-key", "secretKey", "pk"])
        }
        let pubKey = firstQ(["publickey", "public_key", "public-key", "peer_public_key", "peer_pk", "peerPublicKey"])
        guard !privKey.isEmpty, !pubKey.isEmpty else { return nil }

        var f: [String: NCJSONValue] = [
            "server": .string(server),
            "port": .number(Double(port)),
            "private-key": .string(privKey),
            "public-key": .string(pubKey),
            "udp": .bool(true)
        ]
        let addr = firstQ(["address", "ip", "local_address", "localAddress", "ips"])
        if !addr.isEmpty {
            for part in addr.components(separatedBy: ",") {
                let trimmed = part.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty { continue }
                let ip = trimmed.components(separatedBy: "/")[0]
                if ip.contains(":") { f["ipv6"] = .string(ip) } else { f["ip"] = .string(ip) }
            }
        }
        if f["ip"] == nil { f["ip"] = .string("172.16.0.2") }
        let psk = firstQ(["presharedkey", "pre_shared_key", "preshared_key", "psk"])
        if !psk.isEmpty { f["pre-shared-key"] = .string(psk) }
        if let reserved = q["reserved"], !reserved.isEmpty {
            let nums = reserved.components(separatedBy: ",").map { Int($0.trimmingCharacters(in: .whitespaces)) ?? 0 }
            if nums.count == 3 {
                f["reserved"] = .array(nums.map { .number(Double($0)) })
            } else {
                f["reserved"] = .string(reserved)
            }
        }
        if let mtuStr = q["mtu"], !mtuStr.isEmpty {
            f["mtu"] = .number(Double(Int(mtuStr) ?? 1408))
        }

        let name = p.name.isEmpty ? "WireGuard \(server)" : p.name
        return NCProxy(name: name, type: "wireguard", fields: f)
    }

    private static func parseSnell(_ rest: String) -> NCProxy? {
        // bridge nodes.go parseSnell: psk required (userinfo username or
        // ?psk=), port defaults 443, version always written (default 4),
        // obfs "none"/absent produces no obfs-opts, host key always present.
        let p = splitParts(rest)
        guard !p.host.isEmpty else { return nil }
        let q = p.query
        var psk = String(p.userinfo.split(separator: ":", maxSplits: 1).first ?? "")
        psk = psk.removingPercentEncoding ?? psk
        if psk.isEmpty { psk = q["psk"] ?? "" }
        guard !psk.isEmpty else { return nil }
        let port = p.port > 0 ? p.port : 443
        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(port)),
            "psk": .string(psk),
            "version": .number(Double((q["version"].flatMap { Int($0) }) ?? 4)),
            "udp": .bool(true)
        ]
        if let mode = q["obfs"], !mode.isEmpty, mode != "none" {
            f["obfs-opts"] = .object([
                "mode": .string(mode),
                "host": .string(q["obfs-host"] ?? q["host"] ?? ""),
            ])
        }

        let name = p.name.isEmpty ? "Snell \(p.host)" : p.name
        return NCProxy(name: name, type: "snell", fields: f)
    }

    private static func parseSSH(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty else { return nil }
        let port = p.port > 0 ? p.port : 22
        let q = p.query
        var username = ""
        var password = ""
        if !p.userinfo.isEmpty {
            let creds = p.userinfo.split(separator: ":", maxSplits: 1)
            username = String(creds[0]).removingPercentEncoding ?? String(creds[0])
            if creds.count > 1 {
                password = String(creds[1]).removingPercentEncoding ?? String(creds[1])
            }
        }
        if username.isEmpty { username = q["user"] ?? q["username"] ?? "" }
        if password.isEmpty { password = q["password"] ?? q["pass"] ?? "" }
        guard !username.isEmpty else { return nil }
        func firstQ(_ keys: [String]) -> String {
            for k in keys { if let v = q[k], !v.isEmpty { return v } }
            return ""
        }

        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(port)),
            "username": .string(username)
        ]
        if !password.isEmpty { f["password"] = .string(password) }
        // bridge nodes.go parseSSH: full alias sets; a private key that does
        // not look like PEM is base64-decoded and used when the decoding is
        // PEM (links often carry the key base64-wrapped).
        var pk = firstQ(["private-key", "privateKey", "private_key", "pk", "key"])
        if !pk.isEmpty {
            if !pk.contains("-----BEGIN"), let decoded = base64Decode(pk),
               let s = String(data: decoded, encoding: .utf8), s.contains("-----BEGIN") {
                pk = s
            }
            f["private-key"] = .string(pk)
        }
        let pp = firstQ(["private-key-passphrase", "passphrase", "privateKeyPassphrase"])
        if !pp.isEmpty { f["private-key-passphrase"] = .string(pp) }
        let hk = firstQ(["host-key", "hostkey", "host_key", "server-key", "serverKey"])
        if !hk.isEmpty {
            let keys = hk.components(separatedBy: "|").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if !keys.isEmpty { f["host-key"] = .array(keys.map { .string($0) }) }
        }
        let alg = firstQ(["host-key-algorithms", "hostKeyAlgorithms"])
        if !alg.isEmpty {
            f["host-key-algorithms"] = .array(alg.components(separatedBy: ",").map { .string($0.trimmingCharacters(in: .whitespaces)) }.filter { !$0.isEmpty })
        }
        // Go: an ssh node with neither password nor private key is an error.
        guard !password.isEmpty || f["private-key"] != nil else { return nil }

        let name = p.name.isEmpty ? "ssh \(p.host)" : p.name
        return NCProxy(name: name, type: "ssh", fields: f)
    }

    private static func parseSocksHTTP(_ rest: String, scheme: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let isSocks = scheme.hasPrefix("socks")
        let isHTTPS = scheme == "https"
        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(p.port))
        ]
        if isSocks { f["udp"] = .bool(true) }
        if isHTTPS {
            f["tls"] = .bool(true)
            if let sni = p.query["sni"] { f["sni"] = .string(sni) }
        }
        if !p.userinfo.isEmpty {
            var ui = p.userinfo
            // Same rule as ssNode (bridge nodes.go): only a decoded value
            // containing ":" may replace the raw userinfo.
            if !ui.contains(":"), let decoded = base64Decode(ui),
               let s = String(data: decoded, encoding: .utf8), s.contains(":") {
                ui = s
            }
            let creds = ui.split(separator: ":", maxSplits: 1)
            f["username"] = .string(String(creds[0]).removingPercentEncoding ?? String(creds[0]))
            if creds.count > 1 {
                f["password"] = .string(String(creds[1]).removingPercentEncoding ?? String(creds[1]))
            }
        }
        let typ = isSocks ? "socks5" : "http"
        let name = p.name.isEmpty ? "\(typ) \(p.host)" : p.name
        return NCProxy(name: name, type: typ, fields: f)
    }

    private static func parseAnyTLS(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let q = p.query
        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(p.port)),
            "password": .string(p.userinfo.removingPercentEncoding ?? p.userinfo)
        ]
        if let sni = q["sni"] { f["sni"] = .string(sni) }
        if q["insecure"] == "1" || q["insecure"] == "true" { f["skip-cert-verify"] = .bool(true) }
        if let fp = q["hpkp"] ?? q["fingerprint"] { f["fingerprint"] = .string(fp) }

        let name = p.name.isEmpty ? "anytls \(p.host)" : p.name
        return NCProxy(name: name, type: "anytls", fields: f)
    }

    private static func parseMieru(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty else { return nil }
        let q = p.query
        let portStr = q["port"] ?? ""
        // bridge/share.go round-trips a mieru port range ("8000-8010"): the
        // first port dials, the range string is kept in "port-range".
        var portRange: String?
        var port = Int(portStr) ?? 0
        if port == 0, portStr.contains("-") {
            portRange = portStr
            port = Int(portStr.split(separator: "-").first.map(String.init) ?? "") ?? 0
        }
        if port == 0 { port = p.port }
        guard port > 0 else { return nil }
        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(port))
        ]
        if let portRange { f["port-range"] = .string(portRange) }
        if !p.userinfo.isEmpty {
            let creds = p.userinfo.split(separator: ":", maxSplits: 1)
            f["username"] = .string(String(creds[0]).removingPercentEncoding ?? String(creds[0]))
            if creds.count > 1 {
                f["password"] = .string(String(creds[1]).removingPercentEncoding ?? String(creds[1]))
            }
        }
        if let proto = q["protocol"] { f["transport"] = .string(proto) }
        if let mux = q["multiplexing"] { f["multiplexing"] = .string(mux) }
        if let hm = q["handshake-mode"] { f["handshake-mode"] = .string(hm) }
        let name = q["profile"] ?? (p.name.isEmpty ? "mieru \(p.host)" : p.name)
        return NCProxy(name: name, type: "mieru", fields: f)
    }

    private static func parseHysteria1(_ rest: String) -> NCProxy? {
        let p = splitParts(rest)
        guard !p.host.isEmpty, p.port > 0 else { return nil }
        let q = p.query
        var f: [String: NCJSONValue] = [
            "server": .string(p.host),
            "port": .number(Double(p.port))
        ]
        if let sni = q["peer"] ?? q["sni"] { f["sni"] = .string(sni) }
        if let auth = q["auth"] { f["auth-str"] = .string(auth) }
        if let obfs = q["obfs"] { f["obfs"] = .string(obfs) }
        if let proto = q["protocol"] { f["protocol"] = .string(proto) }
        if let up = q["upmbps"] { f["up"] = .string(up) }
        if let down = q["downmbps"] { f["down"] = .string(down) }
        if let alpn = q["alpn"] { f["alpn"] = .array(alpn.components(separatedBy: ",").map { .string($0.trimmingCharacters(in: .whitespaces)) }) }
        if q["insecure"] == "1" || q["insecure"] == "true" { f["skip-cert-verify"] = .bool(true) }

        let name = p.name.isEmpty ? "hysteria \(p.host)" : p.name
        return NCProxy(name: name, type: "hysteria", fields: f)
    }

    private static func dedup(_ nodes: [NCProxy]) -> [NCProxy] {
        // bridge nodes.go uniqueNames: an empty name is first filled with
        // "<type> <server>", then collisions get " 2", " 3", … suffixes.
        var seen: [String: Int] = [:]
        return nodes.map { node in
            var node = node
            if node.name.isEmpty {
                let server = node.fields["server"]?.string ?? ""
                node = NCProxy(name: "\(node.type) \(server)", type: node.type, fields: node.fields)
            }
            let count = (seen[node.name] ?? 0) + 1
            seen[node.name] = count
            guard count > 1 else { return node }
            return NCProxy(name: "\(node.name) \(count)", type: node.type, fields: node.fields)
        }
    }
}

/// Regex include/exclude node filtering (QX server_remote filters, Loon
/// remote filters, mihomo group filter/exclude-filter over providers).
enum NCNodeFilter {
    static func matches(_ name: String, include: String?, exclude: String?) -> Bool {
        if let include, !include.isEmpty,
           (try? NSRegularExpression(pattern: include))?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) == nil {
            return false
        }
        if let exclude, !exclude.isEmpty,
           (try? NSRegularExpression(pattern: exclude))?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil {
            return false
        }
        return true
    }

    static func apply(_ nodes: [NCProxy], include: String?, exclude: String?) -> [NCProxy] {
        nodes.filter { matches($0.name, include: include, exclude: exclude) }
    }
}

/// Cached store for node subscriptions, mirroring the rule-provider
/// store's freshness model: cache-first, refresh failures keep old nodes.
final class NCNodeSubscriptionStore {
    private let dir: URL
    private let lock = NSLock()
    private var nodesBySub: [String: [NCProxy]] = [:]
    private var fetchedAt: [String: TimeInterval] = [:]

    var fetcher: (String, @escaping (Data?) -> Void) -> Void = { urlString, done in
        guard let url = URL(string: urlString) else { done(nil); return }
        var req = URLRequest(url: url)
        req.setValue("clash-verge/v2.0", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: req) { data, _, _ in done(data) }.resume()
    }

    init(dir: URL) {
        self.dir = dir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? Data(contentsOf: dir.appendingPathComponent("meta.json")),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Double] {
            fetchedAt = obj
        }
    }

    private func cacheFile(for name: String) -> URL {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in name.utf8 { hash = (hash ^ UInt64(b)) &* 0x100000001b3 }
        return dir.appendingPathComponent(String(format: "sub-%016llx.txt", hash))
    }

    /// Load cached nodes for all subscriptions; returns those needing a
    /// network refresh (stale or never fetched).
    @discardableResult
    func loadCached(_ subs: [NCNodeSubscription]) -> [NCNodeSubscription] {
        var stale: [NCNodeSubscription] = []
        for sub in subs {
            if let text = try? String(contentsOf: cacheFile(for: sub.name), encoding: .utf8) {
                let nodes = NCSubscriptionParser.parse(text)
                if !nodes.isEmpty {
                    lock.lock(); nodesBySub[sub.name] = nodes; lock.unlock()
                }
            }
            lock.lock(); let at = fetchedAt[sub.name]; lock.unlock()
            if at == nil || Date().timeIntervalSince1970 - at! > Double(max(sub.interval, 60)) {
                stale.append(sub)
            }
        }
        return stale
    }

    func refresh(_ sub: NCNodeSubscription, completion: (() -> Void)? = nil) {
        fetcher(sub.url) { [weak self] data in
            guard let self, let data, let text = String(data: data, encoding: .utf8) else {
                completion?()
                return
            }
            let nodes = NCSubscriptionParser.parse(text)
            guard !nodes.isEmpty else { completion?(); return }
            try? data.write(to: self.cacheFile(for: sub.name), options: .atomic)
            self.lock.lock()
            self.nodesBySub[sub.name] = nodes
            self.fetchedAt[sub.name] = Date().timeIntervalSince1970
            let meta = self.fetchedAt
            self.lock.unlock()
            if let mdata = try? JSONSerialization.data(withJSONObject: meta) {
                try? mdata.write(to: self.dir.appendingPathComponent("meta.json"), options: .atomic)
            }
            completion?()
        }
    }

    /// Nodes of one subscription with its own include/exclude filter applied.
    func nodes(for sub: NCNodeSubscription) -> [NCProxy] {
        lock.lock(); let raw = nodesBySub[sub.name] ?? []; lock.unlock()
        return NCNodeFilter.apply(raw, include: sub.includeRegex, exclude: sub.excludeRegex)
    }

    func allNodes() -> [String: [NCProxy]] {
        lock.lock(); defer { lock.unlock() }
        return nodesBySub
    }
}
