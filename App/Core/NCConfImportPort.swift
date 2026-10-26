// DIVERGENCES:
// None. All data structures, JSON keys, dictionary shapes, section translations,
// and warning/error outputs mirror bridge/confimport.go and bridge/qximport.go exactly.

import Foundation

/// Pure Swift port of bridge/confimport.go + bridge/qximport.go.
/// Converts Surge .conf and Quantumult X .conf to mihomo YAML,
/// modules, remote modules, connection settings, and an import report.
enum NCConfImportPort {

    // MARK: - Data Models

    struct ConfReport: Codable {
        var format: String = "" // surge | qx
        var proxies: Int = 0
        var groups: Int = 0
        var rules: Int = 0
        var providers: Int = 0
        var module: Bool = false
        var rewrites: Int = 0
        var scripts: Int = 0
        var tasks: Int = 0
        var hostnames: Int = 0
        var remotes: Int = 0
        var skipped: [String] = []
        var notes: [String] = []
        var disabled: [String]? = nil
        var rulesSkipped: Int? = nil
    }

    struct RemoteModule: Codable, Hashable {
        var url: String
        var name: String
        var enabled: Bool
        var interval: Int
    }

    struct ConfSettings: Codable {
        var excludedRoutes: [String]? = nil
        var trustedSSIDs: [String]? = nil
        var testURL: String? = nil
        var testTimeoutMs: Int? = nil
        var blockQUIC: Bool? = nil
        var modeTrigger: ModeTrigger? = nil
        var geoAPI: String? = nil
        var geoScript: String? = nil
        var geoDisabled: Bool? = nil
        var parserURL: String? = nil

        func isEmpty() -> Bool {
            (excludedRoutes == nil || excludedRoutes!.isEmpty) &&
            (trustedSSIDs == nil || trustedSSIDs!.isEmpty) &&
            (testURL == nil || testURL!.isEmpty) &&
            (testTimeoutMs == nil || testTimeoutMs == 0) &&
            blockQUIC != true &&
            modeTrigger == nil &&
            (geoAPI == nil || geoAPI!.isEmpty) &&
            (geoScript == nil || geoScript!.isEmpty) &&
            geoDisabled != true &&
            (parserURL == nil || parserURL!.isEmpty)
        }
    }

    struct ConfResult: Codable {
        var yaml: String = ""
        var module: String? = nil
        var rewriteRemotes: [RemoteModule]? = nil
        var settings: ConfSettings? = nil
        var report: ConfReport
        var error: String? = nil
    }

    // MARK: - Public API

    /// ImportConf converts a Surge or Quantumult X profile to mihomo. Returns JSON {yaml, module, report, error}.
    static func importConf(_ text: String) -> String {
        let res = importConfResult(text)
        let enc = JSONEncoder()
        if let data = try? enc.encode(res), let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "{\"error\":\"内部编码错误\"}"
    }

    // MARK: - Section Parsing

    private static let confSectionRe = try? NSRegularExpression(pattern: "^\\[([^\\]]+)\\]\\s*$")

    static func splitSections(_ text: String) -> (order: [String], secs: [String: [String]]) {
        var order: [String] = []
        var secs: [String: [String]] = [:]
        var cur = ""
        var t0 = text
        if t0.hasPrefix("\u{FEFF}") { t0.removeFirst() }
        let normalized = t0.replacingOccurrences(of: "\r", with: "")
        for raw in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if let re = confSectionRe,
               let m = re.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)),
               let r1 = Range(m.range(at: 1), in: t) {
                cur = String(t[r1]).trimmingCharacters(in: .whitespaces).lowercased()
                if secs[cur] == nil {
                    order.append(cur)
                    secs[cur] = []
                }
                secs[cur]?.append("")
                continue
            }
            if t.isEmpty || t.hasPrefix("#") || t.hasPrefix(";") || t.hasPrefix("//") {
                continue
            }
            if secs[cur] == nil {
                secs[cur] = []
            }
            secs[cur]?.append(t)
        }
        return (order, secs)
    }

    static func nonEmpty(_ l: [String]?) -> [String] {
        guard let l else { return [] }
        return l.filter { !$0.isEmpty }
    }

    static func builtinPolicy(_ s: String) -> String {
        let up = s.trimmingCharacters(in: .whitespaces).uppercased()
        if up.hasPrefix("REJECT") {
            if up == "REJECT-DROP" { return up }
            return "REJECT"
        }
        return "DIRECT"
    }

    // MARK: - Lexical Helpers

    static func splitParams(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inQ = false
        for ch in s {
            if ch == "\"" {
                inQ = !inQ
            } else if ch == "," && !inQ {
                out.append(cur.trimmingCharacters(in: .whitespaces))
                cur = ""
                continue
            }
            cur.append(ch)
        }
        if !cur.trimmingCharacters(in: .whitespaces).isEmpty {
            out.append(cur.trimmingCharacters(in: .whitespaces))
        }
        return out
    }

    static func kvs(_ parts: [String]) -> (pos: [String], kv: [String: String]) {
        var pos: [String] = []
        var kv: [String: String] = [:]
        for p in parts {
            if let eq = p.firstIndex(of: "="), eq > p.startIndex {
                let k = String(p[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                let v = String(p[p.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                kv[k] = v
            } else {
                pos.append(p.trimmingCharacters(in: CharacterSet(charactersIn: "\"")))
            }
        }
        return (pos, kv)
    }

    static func splitHostPort(_ s: String) -> (host: String, port: Int, ok: Bool) {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
            let h = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let tail = trimmed[trimmed.index(after: close)...]
            if tail.hasPrefix(":"), let p = Int(tail.dropFirst()), p > 0, p <= 65535 {
                return (h, p, true)
            }
            return (h, 0, false)
        }
        if let colon = trimmed.lastIndex(of: ":") {
            let h = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let pStr = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if let p = Int(pStr), p > 0, p <= 65535 {
                return (h, p, true)
            }
        }
        return ("", 0, false)
    }

    static func truthy(_ v: String?) -> Bool {
        guard let v = v?.trimmingCharacters(in: .whitespaces).lowercased() else { return false }
        return v == "true" || v == "1" || v == "yes" || v == "on"
    }

    static func atoi(_ s: String?, _ def: Int) -> Int {
        guard let s = s?.trimmingCharacters(in: .whitespaces), let n = Int(s) else { return def }
        return n
    }

    static func firstNonEmpty(_ list: String?...) -> String {
        for s in list {
            if let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty {
                return s
            }
        }
        return ""
    }

    static func csv(_ s: String) -> [String] {
        s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func strOf(_ v: Any?) -> String {
        if let s = v as? String { return s }
        if let v { return "\(v)" }
        return ""
    }

    private static func applyWS(_ p: inout [String: Any], path: String?, host: String?) {
        p["network"] = "ws"
        var opts: [String: Any] = [:]
        if let path, !path.isEmpty { opts["path"] = path }
        if let host, !host.isEmpty { opts["headers"] = ["Host": host] }
        if !opts.isEmpty { p["ws-opts"] = opts }
    }

    private static func vmessCipher(_ c: String) -> String {
        let trimmed = c.trimmingCharacters(in: .whitespaces).lowercased()
        return trimmed.isEmpty ? "auto" : trimmed
    }

    private static func headerHost(_ h: String) -> String {
        for pair in h.split(separator: "|") {
            if let eq = pair.firstIndex(of: ":") {
                let k = String(pair[..<eq]).trimmingCharacters(in: .whitespaces)
                let v = String(pair[pair.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                if k.caseInsensitiveCompare("host") == .orderedSame {
                    return v
                }
            }
        }
        return ""
    }

    // MARK: - Proxy Line Parsers

    static func parseSurgeLine(_ line: String) throws -> [String: Any] {
        guard let eq = line.firstIndex(of: "=") else {
            throw NSError(domain: "ImportConf", code: 1, userInfo: [NSLocalizedDescriptionKey: "not a surge line"])
        }
        let name = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
        let (pos, kv) = kvs(splitParams(String(line[line.index(after: eq)...])))
        guard pos.count >= 3 else {
            throw NSError(domain: "ImportConf", code: 2, userInfo: [NSLocalizedDescriptionKey: "surge: 参数不足"])
        }
        let typ = pos[0].lowercased()
        let server = pos[1]
        let port = atoi(pos[2], 0)
        guard port > 0 else {
            throw NSError(domain: "ImportConf", code: 3, userInfo: [NSLocalizedDescriptionKey: "surge: 端口无效"])
        }
        var p: [String: Any] = ["name": name, "server": server, "port": port]
        let udp = truthy(kv["udp-relay"]) || truthy(kv["udp"])
        let sni = kv["sni"] ?? ""
        let skip = truthy(kv["skip-cert-verify"])
        func setTLS() {
            p["tls"] = true
            if !sni.isEmpty { p["servername"] = sni }
            if skip { p["skip-cert-verify"] = true }
        }
        func at(_ i: Int) -> String {
            if i < pos.count { return pos[i] }
            return ""
        }
        func loonTransport() {
            switch (kv["transport"] ?? "").lowercased() {
            case "ws":
                applyWS(&p, path: kv["path"], host: kv["host"])
            case "http":
                p["network"] = "http"
                var opts: [String: Any] = [:]
                if let v = kv["path"], !v.isEmpty { opts["path"] = [v] }
                if let v = kv["host"], !v.isEmpty { opts["headers"] = ["Host": [v]] }
                p["http-opts"] = opts
            case "grpc":
                p["network"] = "grpc"
                p["grpc-opts"] = ["grpc-service-name": firstNonEmpty(kv["service-name"], kv["path"])]
            default:
                break
            }
        }
        switch typ {
        case "ss", "shadowsocks":
            p["type"] = "ss"
            p["cipher"] = firstNonEmpty(kv["encrypt-method"], kv["method"], kv["cipher"], at(3))
            p["password"] = firstNonEmpty(kv["password"], at(4))
            p["udp"] = udp
            if let o = kv["obfs"], !o.isEmpty {
                p["plugin"] = "obfs"
                p["plugin-opts"] = ["mode": o, "host": kv["obfs-host"] ?? ""]
            }
            if let v = kv["shadow-tls-password"], !v.isEmpty {
                p["plugin"] = "shadow-tls"
                p["client-fingerprint"] = "chrome"
                p["plugin-opts"] = ["host": kv["shadow-tls-sni"] ?? "", "password": v, "version": atoi(kv["shadow-tls-version"], 3)]
            }
        case "vmess":
            p["type"] = "vmess"
            p["uuid"] = firstNonEmpty(kv["username"], at(4))
            p["alterId"] = atoi(kv["alterid"], 0)
            p["cipher"] = vmessCipher(firstNonEmpty(kv["encrypt-method"], at(3)))
            p["udp"] = true
            if truthy(kv["ws"]) {
                applyWS(&p, path: kv["ws-path"], host: headerHost(kv["ws-headers"] ?? ""))
            }
            loonTransport()
            if truthy(kv["tls"]) || truthy(kv["over-tls"]) {
                setTLS()
            }
        case "vless":
            p["type"] = "vless"
            p["uuid"] = firstNonEmpty(kv["uuid"], kv["username"], at(3))
            p["udp"] = true
            if let v = kv["flow"], !v.isEmpty { p["flow"] = v }
            loonTransport()
            if let pk = kv["public-key"], !pk.isEmpty {
                setTLS()
                var ro: [String: Any] = ["public-key": pk]
                if let sid = kv["short-id"], !sid.isEmpty { ro["short-id"] = sid }
                p["reality-opts"] = ro
                p["client-fingerprint"] = "chrome"
            } else if truthy(kv["over-tls"]) || truthy(kv["tls"]) {
                setTLS()
            }
        case "trojan":
            p["type"] = "trojan"
            p["password"] = firstNonEmpty(kv["password"], at(3))
            p["udp"] = true
            if !sni.isEmpty { p["sni"] = sni }
            if skip { p["skip-cert-verify"] = true }
            if truthy(kv["ws"]) {
                applyWS(&p, path: kv["ws-path"], host: headerHost(kv["ws-headers"] ?? ""))
            }
            loonTransport()
        case "snell":
            p["type"] = "snell"
            p["psk"] = kv["psk"] ?? ""
            p["version"] = atoi(kv["version"], 4)
            p["udp"] = true
            if let o = kv["obfs"], !o.isEmpty {
                p["obfs-opts"] = ["mode": o, "host": kv["obfs-host"] ?? ""]
            }
        case "http", "https":
            p["type"] = "http"
            if pos.count >= 5 {
                p["username"] = pos[3]
                p["password"] = pos[4]
            }
            p["username"] = firstNonEmpty(kv["username"], p["username"] as? String)
            p["password"] = firstNonEmpty(kv["password"], p["password"] as? String)
            if typ == "https" { setTLS() }
        case "socks5", "socks5-tls":
            p["type"] = "socks5"
            if pos.count >= 5 {
                p["username"] = pos[3]
                p["password"] = pos[4]
            }
            p["username"] = firstNonEmpty(kv["username"], p["username"] as? String)
            p["password"] = firstNonEmpty(kv["password"], p["password"] as? String)
            p["udp"] = udp
            if typ == "socks5-tls" { setTLS() }
        case "hysteria2", "hy2":
            p["type"] = "hysteria2"
            p["password"] = firstNonEmpty(kv["password"], at(3))
            if !sni.isEmpty { p["sni"] = sni }
            if skip { p["skip-cert-verify"] = true }
            if let v = kv["download-bandwidth"], !v.isEmpty { p["down"] = v + " Mbps" }
        case "tuic", "tuic-v5":
            p["type"] = "tuic"
            p["uuid"] = kv["uuid"] ?? ""
            p["password"] = firstNonEmpty(kv["password"], kv["token"])
            if !sni.isEmpty { p["sni"] = sni }
            if skip { p["skip-cert-verify"] = true }
            if let v = kv["alpn"], !v.isEmpty {
                p["alpn"] = csv(v.replacingOccurrences(of: "|", with: ","))
            } else {
                p["alpn"] = ["h3"]
            }
            p["congestion-controller"] = "bbr"
            p["udp-relay-mode"] = "native"
        case "anytls":
            p["type"] = "anytls"
            p["password"] = kv["password"] ?? ""
            if !sni.isEmpty { p["sni"] = sni }
            if skip { p["skip-cert-verify"] = true }
            p["udp"] = true
        case "ssh":
            p["type"] = "ssh"
            p["username"] = kv["username"] ?? ""
            p["password"] = kv["password"] ?? ""
            if let v = kv["private-key"], !v.isEmpty { p["private-key"] = v }
            if let v = kv["private-key-passphrase"], !v.isEmpty { p["private-key-passphrase"] = v }
            if let v = kv["server-fingerprint"] ?? kv["host-key"], !v.isEmpty { p["host-key"] = [v] }
        default:
            throw NSError(domain: "ImportConf", code: 4, userInfo: [NSLocalizedDescriptionKey: "surge: 不支持的类型 \(typ)"])
        }
        return p
    }

    static func parseQXLine(_ line: String) throws -> [String: Any] {
        guard let eq = line.firstIndex(of: "=") else {
            throw NSError(domain: "ImportConf", code: 1, userInfo: [NSLocalizedDescriptionKey: "not qx"])
        }
        let typ = String(line[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
        let parts = splitParams(String(line[line.index(after: eq)...]))
        guard let first = parts.first, !first.isEmpty else {
            throw NSError(domain: "ImportConf", code: 2, userInfo: [NSLocalizedDescriptionKey: "qx: 空"])
        }
        let (host, port, ok) = splitHostPort(first)
        guard ok else {
            throw NSError(domain: "ImportConf", code: 3, userInfo: [NSLocalizedDescriptionKey: "qx: 地址无效 \(first)"])
        }
        let (_, kv) = kvs(Array(parts.dropFirst()))
        let name = kv["tag"] ?? (typ + " " + host)
        var p: [String: Any] = ["server": host, "port": port, "name": name]
        let obfs = (kv["obfs"] ?? "").lowercased()
        let obfsHost = kv["obfs-host"] ?? ""
        let obfsURI = kv["obfs-uri"] ?? ""
        let overTLS = truthy(kv["over-tls"]) || obfs == "over-tls" || obfs == "wss"
        let tlsHost = firstNonEmpty(kv["tls-host"], obfsHost)
        let skip = (kv["tls-verification"] ?? "").caseInsensitiveCompare("false") == .orderedSame
        switch typ {
        case "shadowsocks":
            p["type"] = "ss"
            p["cipher"] = kv["method"] ?? ""
            p["password"] = kv["password"] ?? ""
            p["udp"] = truthy(kv["udp-relay"])
            if let proto = kv["ssr-protocol"], !proto.isEmpty {
                p["type"] = "ssr"
                p["protocol"] = proto
                if let pp = kv["ssr-protocol-param"], !pp.isEmpty { p["protocol-param"] = pp }
                p["obfs"] = firstNonEmpty(obfs, "plain")
                if !obfsHost.isEmpty { p["obfs-param"] = obfsHost }
                break
            }
            switch obfs {
            case "http", "tls":
                p["plugin"] = "obfs"
                p["plugin-opts"] = ["mode": obfs, "host": obfsHost]
            case "ws", "wss":
                var opts: [String: Any] = ["mode": "websocket", "host": obfsHost, "path": firstNonEmpty(obfsURI, "/")]
                if obfs == "wss" { opts["tls"] = true }
                p["plugin"] = "v2ray-plugin"
                p["plugin-opts"] = opts
            default:
                break
            }
        case "vmess", "vless":
            p["type"] = typ
            p["uuid"] = kv["password"] ?? ""
            p["udp"] = true
            if typ == "vmess" {
                p["alterId"] = 0
                p["cipher"] = vmessCipher(kv["method"] ?? "")
            } else if let f = kv["vless-flow"], !f.isEmpty {
                p["flow"] = f
            }
            if obfs == "ws" || obfs == "wss" {
                applyWS(&p, path: obfsURI, host: obfsHost)
            }
            if overTLS {
                p["tls"] = true
                if !tlsHost.isEmpty { p["servername"] = tlsHost }
                if skip { p["skip-cert-verify"] = true }
            }
            if let pk = kv["reality-base64-pubkey"], !pk.isEmpty {
                p["tls"] = true
                var ro: [String: Any] = ["public-key": pk]
                if let sid = kv["reality-hex-shortid"], !sid.isEmpty { ro["short-id"] = sid }
                p["reality-opts"] = ro
                p["client-fingerprint"] = "chrome"
            }
        case "trojan":
            p["type"] = "trojan"
            p["password"] = kv["password"] ?? ""
            p["udp"] = truthy(kv["udp-relay"])
            if !tlsHost.isEmpty { p["sni"] = tlsHost }
            if skip { p["skip-cert-verify"] = true }
            if obfs == "wss" || obfs == "ws" {
                applyWS(&p, path: obfsURI, host: obfsHost)
            }
        case "http":
            p["type"] = "http"
            p["username"] = kv["username"] ?? ""
            p["password"] = kv["password"] ?? ""
            if overTLS {
                p["tls"] = true
                if skip { p["skip-cert-verify"] = true }
            }
        case "socks5":
            p["type"] = "socks5"
            p["username"] = kv["username"] ?? ""
            p["password"] = kv["password"] ?? ""
            p["udp"] = truthy(kv["udp-relay"])
            if overTLS {
                p["tls"] = true
                if skip { p["skip-cert-verify"] = true }
            }
        case "anytls":
            p["type"] = "anytls"
            p["password"] = kv["password"] ?? ""
            p["udp"] = true
            if !tlsHost.isEmpty { p["sni"] = tlsHost }
            if skip { p["skip-cert-verify"] = true }
        default:
            throw NSError(domain: "ImportConf", code: 4, userInfo: [NSLocalizedDescriptionKey: "qx: 不支持的类型 \(typ)"])
        }
        qxNodeExtras(&p, kv: kv, typ: typ)
        return p
    }

    private static func qxNodeExtras(_ p: inout [String: Any], kv: [String: String], typ: String) {
        if truthy(kv["fast-open"]) { p["tfo"] = true }
        let hasTLS = (p["tls"] as? Bool == true) || typ == "trojan" || typ == "anytls"
        if let rawFP = kv["tls-cert-sha256"] {
            let fp = rawFP.lowercased().replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "")
            if fp.count == 64 && hasTLS {
                p["fingerprint"] = fp
            }
        }
        if let v = kv["tls-alpn"], !v.isEmpty && hasTLS {
            p["alpn"] = csv(v.replacingOccurrences(of: "|", with: ","))
        }
        if truthy(kv["udp-over-tcp"]) { p["udp-over-tcp"] = true }
        if (typ == "http" || typ == "socks5") && (p["tls"] as? Bool == true) {
            if let h = kv["tls-host"], !h.isEmpty { p["sni"] = h }
        }
    }

    // MARK: - QX Remote and Options

    struct QXServerRemote {
        var url: String
        var tag: String = ""
        var interval: Int = 86400
        var asPolicy: String = ""
    }

    static func parseQXServerRemote(_ line: String) -> (remote: QXServerRemote, ok: Bool) {
        let parts = line.split(separator: ",").map { String($0) }
        guard let first = parts.first else { return (QXServerRemote(url: ""), false) }
        let u = first.trimmingCharacters(in: .whitespaces)
        guard u.hasPrefix("http://") || u.hasPrefix("https://") else {
            return (QXServerRemote(url: ""), false)
        }
        var sp = QXServerRemote(url: u, interval: 86400)
        for p in parts.dropFirst() {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch k {
            case "tag":
                sp.tag = v
            case "as-policy":
                sp.asPolicy = v
            case "update-interval":
                if let n = Int(v), n > 0 { sp.interval = n }
            case "enabled":
                if !truthy(v) { return (QXServerRemote(url: ""), false) }
            default:
                break
            }
        }
        return (sp, true)
    }

    static func parseQXRewriteRemote(_ line: String) -> (RemoteModule, Bool) {
        let parts = line.split(separator: ",").map { String($0) }
        guard let first = parts.first else { return (RemoteModule(url: "", name: "", enabled: false, interval: 0), false) }
        let u = first.trimmingCharacters(in: .whitespaces)
        guard u.hasPrefix("http://") || u.hasPrefix("https://") else {
            return (RemoteModule(url: "", name: "", enabled: false, interval: 0), false)
        }
        var m = RemoteModule(url: u, name: "", enabled: true, interval: 86400)
        for p in parts.dropFirst() {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch k {
            case "tag":
                m.name = v
            case "update-interval":
                if let n = Int(v), n > 0 { m.interval = n }
            case "enabled":
                m.enabled = truthy(v)
            default:
                break
            }
        }
        if m.name.isEmpty {
            m.name = NCRuleValidator.prettyProviderName(u: u, tag: "")
        }
        return (m, true)
    }

    static func qxLineOpts(_ line: String) -> [String: String] {
        var out: [String: String] = [:]
        let parts = line.split(separator: ",").map { String($0) }
        for p in parts.dropFirst() {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            out[k] = v
        }
        return out
    }

    static func qxLineDisabled(_ line: String) -> Bool {
        for p in line.split(separator: ",") {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces)
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if k.caseInsensitiveCompare("enabled") == .orderedSame {
                return !truthy(v)
            }
        }
        return false
    }

    static func qxRemoteLabel(_ line: String) -> String {
        let parts = line.split(separator: ",").map { String($0) }
        var host = parts.first?.trimmingCharacters(in: .whitespaces) ?? ""
        if let u = URL(string: host), let h = u.host {
            host = h + u.path
        }
        for p in parts.dropFirst() {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let k = String(trimmed[..<eq]).trimmingCharacters(in: .whitespaces)
            let v = String(trimmed[trimmed.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if k.caseInsensitiveCompare("tag") == .orderedSame {
                return v + " (" + host + ")"
            }
        }
        return host
    }

    static func hadUnknown(_ members: [String], groups: Set<String>, proxies: Set<String>) -> Bool {
        for m in members {
            let u = m.uppercased()
            if u == "DIRECT" || u.hasPrefix("REJECT") || u == "PROXY" {
                continue
            }
            if !groups.contains(m) && !proxies.contains(m) {
                return true
            }
        }
        return false
    }

    static func importedCheckTimeout(_ n: Int) -> Int {
        max(5000, min(n, 10000))
    }

    static func unquotePolicy(_ s: String) -> String {
        var str = s.trimmingCharacters(in: .whitespaces)
        for q in ["\"", "'", "“", "”"] {
            if str.hasPrefix(q) { str.removeFirst() }
            if str.hasSuffix(q) { str.removeLast() }
        }
        return str.trimmingCharacters(in: .whitespaces)
    }

    static func policyKey(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            if CharacterSet.whitespacesAndNewlines.contains(scalar) { continue }
            let val = scalar.value
            if val == 0x3000 || val == 0x22 || val == 0x27 || val == 0x201C || val == 0x201D
                || val == 0xFE0E || val == 0xFE0F || val == 0x200B || val == 0x200C || val == 0x200D
                || val == 0x2060 || val == 0xFEFF {
                continue
            }
            out.append(Character(scalar))
        }
        return out.lowercased()
    }

    static func loosePolicyMatch(_ pol: String, groups: [String], proxies: [String]) -> (String, Bool) {
        let k = policyKey(pol)
        if k.isEmpty { return ("", false) }
        for list in [groups, proxies] {
            var found = ""
            var n = 0
            for g in list {
                if policyKey(g) == k {
                    found = g
                    n += 1
                }
            }
            if n == 1 { return (found, true) }
            if n > 1 { return ("", false) }
        }
        return ("", false)
    }

    static func stripReservedOutbound(_ proxies: [[String: Any]], _ groups: [[String: Any]], _ rep: inout ConfReport) -> ([[String: Any]], [[String: Any]]) {
        let proxyName = "__MITM__"
        var dropped = false
        var keptP: [[String: Any]] = []
        for p in proxies {
            if (p["name"] as? String) == proxyName {
                dropped = true
                continue
            }
            keptP.append(p)
        }
        var keptG: [[String: Any]] = []
        for var g in groups {
            if let list = g["proxies"] as? [String] {
                var kept: [String] = []
                for x in list {
                    if x == proxyName { dropped = true; continue }
                    kept.append(x)
                }
                g["proxies"] = kept
            } else if let list = g["proxies"] as? [Any] {
                var kept: [Any] = []
                for x in list {
                    if let s = x as? String, s == proxyName { dropped = true; continue }
                    kept.append(x)
                }
                g["proxies"] = kept
            }
            keptG.append(g)
        }
        if dropped {
            rep.notes.append(proxyName + " 是 App 内部保留的出站名称，原配置中的同名节点 / 成员已忽略")
        }
        return (keptP, keptG)
    }

    // MARK: - QX DNS & General Helpers

    private static func qxDomainServer(_ s: String) -> (domain: String, value: String, ok: Bool) {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("/") else { return ("", "", false) }
        let rest = String(trimmed.dropFirst())
        guard let slash = rest.firstIndex(of: "/"), slash > rest.startIndex else { return ("", "", false) }
        let domain = String(rest[..<slash]).trimmingCharacters(in: .whitespaces)
        let value = String(rest[rest.index(after: slash)...]).trimmingCharacters(in: .whitespaces)
        guard !domain.isEmpty, !value.isEmpty else { return ("", "", false) }
        return (domain, value, true)
    }

    private static func qxLeadingStar(_ d: String) -> Bool {
        let rest = d.trimmingCharacters(in: CharacterSet(charactersIn: "*"))
        return rest != d && !rest.isEmpty && !rest.hasPrefix(".") && !rest.contains("*")
    }

    private static func qxPolicyDomain(_ d: String) -> String {
        let lower = d.trimmingCharacters(in: .whitespaces).lowercased()
        if lower.hasPrefix("*.") {
            return "+." + lower.dropFirst(2)
        }
        if qxLeadingStar(lower) {
            return "+." + lower.trimmingCharacters(in: CharacterSet(charactersIn: "*"))
        }
        if lower.hasPrefix("+.") || lower.contains("*") {
            return lower
        }
        return "+." + lower
    }

    private static func qxWildcardOK(_ d: String) -> Bool {
        for l in d.split(separator: ".") {
            if l.contains("*") && l != "*" {
                return false
            }
        }
        return true
    }

    private static func qxHostDomain(_ d: String) -> String {
        let lower = d.trimmingCharacters(in: .whitespaces).lowercased()
        if lower.hasPrefix("*.") {
            return "+." + lower.dropFirst(2)
        }
        if qxLeadingStar(lower) {
            return "+." + lower.trimmingCharacters(in: CharacterSet(charactersIn: "*"))
        }
        return lower
    }

    private static func importQXDNS(_ cfg: inout [String: Any], _ lines: [String], _ rep: inout ConfReport) {
        var plain: [String] = []
        var encrypted: [String] = []
        var policy: [String: [String]] = [:]
        var policyOrder: [String] = []
        var hosts: [String: String] = [:]
        var noSystem = false, preferH3 = false, noIPv6 = false

        func addPolicy(_ d: String, _ v: String) {
            let k = qxPolicyDomain(d)
            guard qxWildcardOK(k) else {
                rep.notes.append("[dns] 通配写法 mihomo 不支持，已跳过：" + d)
                return
            }
            if policy[k] == nil {
                policyOrder.append(k)
                policy[k] = []
            }
            policy[k]?.append(v)
        }

        for l in lines {
            let (key, v, hasEq): (String, String, Bool)
            if let eq = l.firstIndex(of: "=") {
                key = String(l[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                v = String(l[l.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                hasEq = true
            } else {
                key = l.trimmingCharacters(in: .whitespaces).lowercased()
                v = ""
                hasEq = false
            }
            if !hasEq {
                switch key {
                case "no-system":
                    noSystem = true
                case "prefer-doh3":
                    preferH3 = true
                case "no-ipv6":
                    noIPv6 = true
                case "circumvent-ipv4-answer", "circumvent-ipv6-answer":
                    rep.notes.append("[dns] " + key + " 没有对应项，已忽略")
                default:
                    break
                }
                continue
            }
            var val = v
            if let i = val.range(of: "cluded_ssids", options: .caseInsensitive) {
                let sub = String(val[..<i.lowerBound])
                if let c = sub.lastIndex(of: ",") {
                    val = String(sub[..<c]).trimmingCharacters(in: .whitespaces)
                    rep.notes.append("[dns] 按 Wi-Fi 生效的服务器已按全局导入：" + val)
                }
            }
            switch key {
            case "server":
                let (d, vDomain, ok) = qxDomainServer(val)
                if ok {
                    addPolicy(d, vDomain)
                    continue
                }
                if !val.isEmpty { plain.append(val) }
            case "doh-server", "doq-server":
                let (d, vDomain, ok) = qxDomainServer(val)
                if ok {
                    addPolicy(d, vDomain)
                    continue
                }
                for x in val.split(separator: ",") {
                    let trimmed = x.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty && !trimmed.contains("=") {
                        encrypted.append(trimmed)
                    }
                }
            case "address", "alias":
                let (d, vDomain, ok) = qxDomainServer(val)
                if ok {
                    if key == "address" {
                        let ipCandidate = vDomain.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                        if NCIP(ipCandidate) == nil && !vDomain.isEmpty {
                            rep.notes.append("[dns] address 的值不是 IP，已跳过：" + val)
                            continue
                        }
                    }
                    let hd = qxHostDomain(d)
                    if qxWildcardOK(hd) {
                        hosts[hd] = vDomain
                    } else {
                        rep.notes.append("[dns] 通配写法 mihomo 不支持，已跳过：" + d)
                    }
                }
            default:
                break
            }
        }

        var d = (cfg["dns"] as? [String: Any]) ?? [:]
        var ns: [String] = []
        if !encrypted.isEmpty {
            ns = encrypted
        } else {
            ns = plain
            if !noSystem {
                ns.append("system")
            }
        }
        if !encrypted.isEmpty || !plain.isEmpty {
            d["enable"] = true
            d["nameserver"] = ns
            if !plain.isEmpty {
                d["default-nameserver"] = plain
            }
        }
        if !policyOrder.isEmpty {
            d["enable"] = true
            d["nameserver-policy"] = policy
            if d["nameserver"] == nil {
                d["nameserver"] = ["system"]
            }
        }
        if preferH3 { d["prefer-h3"] = true }
        if noIPv6 { d["ipv6"] = false }
        if !d.isEmpty { cfg["dns"] = d }
        if !hosts.isEmpty {
            cfg["hosts"] = hosts
            if var dd = cfg["dns"] as? [String: Any] {
                dd["use-hosts"] = true
                cfg["dns"] = dd
            }
        }
    }

    private static func maskedCIDRString(_ s: String) -> String? {
        guard let cidr = NCCIDR(s) else { return nil }
        switch cidr.network {
        case .v4(let n):
            let mask: UInt32 = cidr.bits == 32 ? 0xffff_ffff : (cidr.bits == 0 ? 0 : (0xffff_ffff << (32 - cidr.bits)))
            let masked = n & mask
            let b0 = (masked >> 24) & 0xff
            let b1 = (masked >> 16) & 0xff
            let b2 = (masked >> 8) & 0xff
            let b3 = masked & 0xff
            return "\(b0).\(b1).\(b2).\(b3)/\(cidr.bits)"
        case .v6:
            return s.trimmingCharacters(in: .whitespaces)
        }
    }

    private static func importQXGeneral(_ cfg: inout [String: Any], _ g: [String: String], _ res: inout ConfResult, _ rep: inout ConfReport) {
        var set = res.settings ?? ConfSettings()
        if let v = g["dns_exclusion_list"], !v.isEmpty {
            var list: [String] = []
            for x in v.split(separator: ",") {
                let trimmed = x.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty { list.append(qxPolicyDomain(trimmed)) }
            }
            if !list.isEmpty {
                var d = (cfg["dns"] as? [String: Any]) ?? [:]
                var fake = (d["fake-ip-filter"] as? [String]) ?? []
                fake.append(contentsOf: list)
                d["fake-ip-filter"] = fake
                cfg["dns"] = d
            }
        }
        if let v = g["excluded_routes"], !v.isEmpty {
            for x in v.split(separator: ",") {
                let trimmed = x.trimmingCharacters(in: .whitespaces)
                if let str = maskedCIDRString(trimmed) {
                    if set.excludedRoutes == nil { set.excludedRoutes = [] }
                    set.excludedRoutes?.append(str)
                }
            }
        }
        if let v = g["ssid_suspended_list"], !v.isEmpty {
            for x in v.split(separator: ",") {
                let trimmed = x.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty {
                    if set.trustedSSIDs == nil { set.trustedSSIDs = [] }
                    set.trustedSSIDs?.append(trimmed)
                }
            }
        }
        if let u = g["server_check_url"], u.hasPrefix("http://") || u.hasPrefix("https://") {
            set.testURL = u
        }
        if let timeoutStr = g["server_check_timeout"], let n = Int(timeoutStr), n > 0 {
            set.testTimeoutMs = importedCheckTimeout(n)
        }
        if let v = g["running_mode_trigger"], !v.isEmpty {
            if let mt = parseQXModeTrigger(v) {
                set.modeTrigger = mt
            } else {
                rep.notes.append("[general] running_mode_trigger 无法识别，已忽略")
            }
        }
        if let v = g["geo_location_checker"]?.trimmingCharacters(in: .whitespaces), !v.isEmpty {
            if v.caseInsensitiveCompare("disabled") == .orderedSame {
                set.geoDisabled = true
            } else {
                let parts = v.split(separator: ",", maxSplits: 1).map { String($0) }
                if let a = parts.first?.trimmingCharacters(in: .whitespaces), a.hasPrefix("http") {
                    set.geoAPI = a
                }
                if parts.count > 1 {
                    let sc = parts[1].trimmingCharacters(in: .whitespaces)
                    if sc.hasPrefix("http") { set.geoScript = sc }
                }
            }
        }
        if let u = g["resource_parser_url"]?.trimmingCharacters(in: .whitespaces), u.hasPrefix("http") {
            set.parserURL = u
        }
        for k in ["enhanced_compatibility_ssid_list", "dns_reject_domain_behavior", "icmp_auto_reply", "server_check_user_agent", "doh_user_agent"] {
            if let val = g[k], !val.isEmpty {
                rep.notes.append("[general] " + k + " 没有对应设置，已忽略")
            }
        }
        if !set.isEmpty() {
            res.settings = set
        }
    }

    private static func parseQXModeTrigger(_ v: String) -> ModeTrigger? {
        var mt = ModeTrigger(enabled: true)
        let parts = v.split(separator: ",").map { String($0) }
        for (i, raw) in parts.enumerated() {
            let x = raw.trimmingCharacters(in: .whitespaces)
            if x.isEmpty { continue }
            if i >= 2, let eq = x.firstIndex(of: ":") {
                let k = String(x[..<eq]).trimmingCharacters(in: .whitespaces)
                let m = String(x[x.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                let mm = qxModeName(m)
                if !mm.isEmpty && !k.isEmpty {
                    if mt.ssids == nil { mt.ssids = [:] }
                    mt.ssids?[k] = mm
                }
                continue
            }
            switch i {
            case 0: mt.cellular = qxModeName(x)
            case 1: mt.wifi = qxModeName(x)
            default: break
            }
        }
        if (mt.cellular == nil || mt.cellular!.isEmpty) &&
            (mt.wifi == nil || mt.wifi!.isEmpty) &&
            (mt.ssids == nil || mt.ssids!.isEmpty) {
            return nil
        }
        return mt
    }

    private static func qxModeName(_ m: String) -> String {
        let norm = m.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "-", with: "_").lowercased()
        switch norm {
        case "filter", "rule": return "rule"
        case "all_proxy", "global": return "global"
        case "all_direct", "direct": return "direct"
        default: return ""
        }
    }

    // MARK: - Core Import Logic

    static func importConfResult(_ text: String) -> ConfResult {
        var res = ConfResult(report: ConfReport(skipped: [], notes: []))
        let (order, secs) = splitSections(text)
        var isQX = secs["server_local"] != nil || secs["policy"] != nil
        for k in ["filter_local", "server_remote", "filter_remote"] {
            if secs[k] != nil { isQX = true }
        }
        if isQX {
            res.report.format = "qx"
        } else if secs["proxy"] != nil || secs["rule"] != nil {
            res.report.format = "surge"
        } else {
            res.error = "未识别为 Surge 或 Quantumult X 配置（缺少 [Proxy]/[Rule] 或 [server_local]/[policy] 段）"
            return res
        }

        var rep = res.report
        var qxGeneral: [String: String] = [:]
        if isQX {
            for l in nonEmpty(secs["general"]) {
                if let eq = l.firstIndex(of: "=") {
                    let k = String(l[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                    let v = String(l[l.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    qxGeneral[k] = v
                }
            }
        }
        var checkURL = "https://www.gstatic.com/generate_204"
        if let u = qxGeneral["server_check_url"], u.hasPrefix("http://") || u.hasPrefix("https://") {
            checkURL = u
        }
        var checkTimeout = 0
        if let n = Int(qxGeneral["server_check_timeout"] ?? ""), n > 0 {
            checkTimeout = importedCheckTimeout(n)
        }

        var proxies: [[String: Any]] = []
        var groups: [[String: Any]] = []
        var groupNames = Set<String>()
        var proxyNames = Set<String>()
        var skippedOver = 0

        func skip(_ sec: String, _ line: String, _ why: String) {
            if rep.skipped.count < 200 {
                rep.skipped.append("[\(sec)] \(line) — \(why)")
            } else {
                skippedOver += 1
            }
        }

        // ---- proxies
        let proxySec = isQX ? "server_local" : "proxy"
        for l in nonEmpty(secs[proxySec]) {
            let p: [String: Any]
            do {
                if isQX {
                    p = try parseQXLine(l)
                } else {
                    let name: String
                    let rhs: String
                    if let eq = l.firstIndex(of: "=") {
                        name = String(l[..<eq]).trimmingCharacters(in: .whitespaces)
                        rhs = String(l[l.index(after: eq)...]).trimmingCharacters(in: .whitespaces).lowercased()
                    } else {
                        name = l.trimmingCharacters(in: .whitespaces)
                        rhs = ""
                    }
                    if rhs.hasPrefix("direct") || rhs.hasPrefix("reject") {
                        let policyName = builtinPolicy(String(rhs.split(separator: ",", maxSplits: 1).first ?? ""))
                        groups.append(["name": name, "type": "select", "proxies": [policyName]])
                        groupNames.insert(name)
                        continue
                    }
                    p = try parseSurgeLine(l)
                }
            } catch {
                skip(proxySec, l, error.localizedDescription)
                continue
            }
            proxies.append(p)
            if let n = p["name"] as? String {
                proxyNames.insert(n)
            }
        }

        // ---- server_remote
        var proxyProviders: [String: Any] = [:]
        var providerTags: [String] = []
        var asPolicy: [(String, String)] = []
        if isQX {
            for l in nonEmpty(secs["server_remote"]) {
                let (sp, ok) = parseQXServerRemote(l)
                if !ok {
                    if qxLineDisabled(l) {
                        if rep.disabled == nil { rep.disabled = [] }
                        rep.disabled?.append("[server_remote] " + qxRemoteLabel(l))
                    } else {
                        skip("server_remote", l, "无效的订阅地址")
                    }
                    continue
                }
                var name = sp.tag
                if name.isEmpty {
                    name = NCRuleValidator.prettyProviderName(u: sp.url, tag: "")
                }
                name = NCRuleValidator.uniqueProviderName(base: name, taken: { proxyProviders[$0] != nil })
                proxyProviders[name] = [
                    "type": "http",
                    "url": sp.url,
                    "x-convert": "nodes",
                    // fix/nc-open-6-10 #10: fetched like QuanX fetched it (the panel picks the format / allows the
                    // client by this UA); mihomo honours `header` the same way.
                    "header": ["User-Agent": [NCNodeSubscriptionStore.qxUserAgent]] as [String: Any],
                    "path": "./proxies/" + NCRuleValidator.providerNameFor(url: sp.url, kind: "nodes") + ".yaml",
                    "interval": sp.interval,
                    "health-check": ["enable": true, "url": checkURL, "interval": 600, "lazy": true] as [String: Any]
                ] as [String: Any]
                providerTags.append(name)
                if !sp.asPolicy.isEmpty {
                    asPolicy.append((name, sp.asPolicy))
                }
            }
        }

        // ---- groups
        struct PendingGroup {
            var name: String
            var typ: String
            var qxType: String = ""
            var members: [String] = []
            var opts: [String: String] = [:]
        }
        var pg: [PendingGroup] = []

        func parseGroup(name: String, typ: String, parts: [String]) -> PendingGroup {
            var g = PendingGroup(name: name.trimmingCharacters(in: .whitespaces), typ: typ)
            for p in parts {
                if let eq = p.firstIndex(of: "=") {
                    let kk = String(p[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                    let vv = String(p[p.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    g.opts[kk] = vv
                    continue
                }
                g.members.append(p.trimmingCharacters(in: .whitespaces))
            }
            return g
        }

        if isQX {
            let qxGroupType = [
                "static": "select", "available": "fallback", "round-robin": "load-balance",
                "url-latency-benchmark": "url-test", "dest-hash": "load-balance", "ssid": "select"
            ]
            for l in nonEmpty(secs["policy"]) {
                guard let eq = l.firstIndex(of: "=") else {
                    skip("policy", l, "无法识别的策略组行（缺少「=」）")
                    continue
                }
                let k = String(l[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                let v = String(l[l.index(after: eq)...])
                guard let typ = qxGroupType[k] else {
                    skip("policy", l, "不支持的策略类型")
                    continue
                }
                let parts = splitParams(v)
                guard let first = parts.first, !first.trimmingCharacters(in: .whitespaces).isEmpty else {
                    skip("policy", l, "策略组没有名称")
                    continue
                }
                var g = parseGroup(name: first, typ: typ, parts: Array(parts.dropFirst()))
                g.qxType = k
                if k.hasPrefix("ssid") {
                    rep.notes.append("SSID 策略组「" + g.name + "」按普通选择组导入（不随 Wi-Fi 切换）")
                }
                pg.append(g)
            }
        } else {
            for l in nonEmpty(secs["proxy group"]) {
                guard let eq = l.firstIndex(of: "=") else { continue }
                let name = String(l[..<eq])
                let v = String(l[l.index(after: eq)...])
                let parts = splitParams(v)
                guard let first = parts.first else { continue }
                let t = first.trimmingCharacters(in: .whitespaces).lowercased()
                let typeMap = ["select": "select", "url-test": "url-test", "fallback": "fallback", "load-balance": "load-balance", "smart": "url-test"]
                guard let typ = typeMap[t] else {
                    skip("Proxy Group", l, "不支持的策略组类型 " + t)
                    continue
                }
                if t == "smart" {
                    rep.notes.append("Surge smart 组「" + name.trimmingCharacters(in: .whitespaces) + "」转为 url-test")
                }
                pg.append(parseGroup(name: name, typ: typ, parts: Array(parts.dropFirst())))
            }
        }

        for a in asPolicy {
            if groupNames.contains(a.0) { continue }
            let policyMap = ["static": "select", "available": "fallback", "round-robin": "load-balance", "url-latency-benchmark": "url-test", "dest-hash": "load-balance"]
            guard let typ = policyMap[a.1.lowercased()] else {
                rep.notes.append("订阅「" + a.0 + "」的 as-policy=" + a.1 + " 不支持，未生成策略组")
                continue
            }
            let g = PendingGroup(
                name: a.0, typ: typ, qxType: a.1.lowercased(),
                opts: ["resource-tag-regex": "^" + NSRegularExpression.escapedPattern(for: a.0) + "$"]
            )
            pg.append(g)
            groupNames.insert(a.0)
        }
        for g in pg { groupNames.insert(g.name) }

        var providers: [String: Any] = [:]
        var qxProxyGroup = ""
        if isQX && !groupNames.contains("proxy") {
            for g in pg {
                for mem in g.members {
                    if mem.caseInsensitiveCompare("proxy") == .orderedSame {
                        qxProxyGroup = "proxy"
                    }
                }
            }
            if !qxProxyGroup.isEmpty {
                var pm: [String: Any] = ["name": qxProxyGroup, "type": "select"]
                var names: [String] = []
                for p in proxies {
                    if let n = p["name"] as? String { names.append(n) }
                }
                if !providerTags.isEmpty {
                    pm["include-all-providers"] = true
                }
                if !names.isEmpty {
                    pm["proxies"] = names
                } else if providerTags.isEmpty {
                    pm["proxies"] = ["DIRECT"]
                }
                groups.append(pm)
                rep.notes.append("QX 内置策略 proxy 已生成为策略组「proxy」（全部本地节点和订阅节点），原来引用 proxy 的策略组改为引用它")
            }
        }

        for g in pg {
            var m: [String: Any] = ["name": g.name, "type": g.typ]
            var members: [String] = []
            var remoteNames: [String] = []
            for mem in g.members {
                let u = mem.uppercased()
                if u == "DIRECT" || u.hasPrefix("REJECT") {
                    members.append(builtinPolicy(u))
                } else if groupNames.contains(mem) || proxyNames.contains(mem) {
                    members.append(mem)
                } else if u == "PROXY" && isQX && !qxProxyGroup.isEmpty {
                    members.append(qxProxyGroup)
                } else if u == "PROXY" && isQX {
                    skip("group " + g.name, mem, "QX 的 proxy 成员没有对应项，已忽略")
                } else if !providerTags.isEmpty {
                    remoteNames.append(mem)
                } else {
                    skip("group " + g.name, mem, "成员不存在（没有节点订阅可以提供它）")
                }
            }

            if let rawOG = g.opts["include-other-group"] {
                let og = rawOG.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
                if !og.isEmpty {
                    var have = Set(members)
                    for rawN in og.split(separator: ",") {
                        let n = String(rawN).trimmingCharacters(in: CharacterSet(charactersIn: "\"' \t"))
                        if n.isEmpty || n == g.name || have.contains(n) {
                            continue
                        } else if groupNames.contains(n) {
                            members.append(n)
                            have.insert(n)
                        } else {
                            skip("group " + g.name, n, "include-other-group 引用的策略组不存在")
                        }
                    }
                }
            }

            if let rawV = g.opts["include-all-proxies"] {
                let v = rawV.trimmingCharacters(in: CharacterSet(charactersIn: "\"' ")).lowercased()
                if v == "true" || v == "1" || v == "yes" {
                    if !providerTags.isEmpty {
                        m["include-all"] = true
                    } else {
                        m["include-all-proxies"] = true
                    }
                }
            }

            if let pp = g.opts["policy-path"], pp.contains("://") {
                rep.notes.append("策略组「" + g.name + "」的 policy-path 远程节点列表未导入，请把该订阅作为单独配置添加")
            }

            let reFilter = firstNonEmpty(g.opts["policy-regex-filter"], g.opts["server-tag-regex"])
            if !reFilter.isEmpty {
                m["filter"] = reFilter
                if !providerTags.isEmpty {
                    m["include-all"] = true
                } else {
                    m["include-all-proxies"] = true
                }
            }

            if let re = g.opts["resource-tag-regex"], !re.isEmpty && !providerTags.isEmpty {
                var use: [String] = []
                if let rx = try? NSRegularExpression(pattern: re) {
                    for t in providerTags {
                        if rx.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil {
                            use.append(t)
                        }
                    }
                }
                if !use.isEmpty {
                    m["use"] = use
                    m.removeValue(forKey: "include-all")
                }
            }

            if !remoteNames.isEmpty && m["filter"] == nil && m["use"] == nil && m["include-all"] == nil {
                var alts: [String] = []
                for n in remoteNames { alts.append(NSRegularExpression.escapedPattern(for: n)) }
                m["use"] = providerTags
                m["filter"] = "^(?:" + alts.joined(separator: "|") + ")$"
                rep.notes.append(String(format: "策略组「%@」的 %d 个成员来自节点订阅，按名称从订阅中选取", g.name, remoteNames.count))
            }

            if members.isEmpty && m["include-all"] == nil && m["include-all-proxies"] == nil && m["use"] == nil &&
                !providerTags.isEmpty && hadUnknown(g.members, groups: groupNames, proxies: proxyNames) {
                m["use"] = providerTags
            }

            let ic = firstNonEmpty(g.opts["img-url"], g.opts["icon-url"])
            if ic.hasPrefix("http://") || ic.hasPrefix("https://") {
                m["icon"] = ic
            }

            if members.isEmpty && m["include-all-proxies"] == nil && m["include-all"] == nil && m["use"] == nil {
                members.append("DIRECT")
            }
            if !members.isEmpty {
                m["proxies"] = members
            }

            if g.typ == "url-test" || g.typ == "fallback" || g.typ == "load-balance" {
                m["url"] = firstNonEmpty(g.opts["url"], g.opts["check-interval-url"], checkURL)
                var defInterval = 300
                if isQX && g.qxType == "available" { defInterval = 600 }
                m["interval"] = atoi(firstNonEmpty(g.opts["interval"], g.opts["check-interval"]), defInterval)
                let tol = atoi(g.opts["tolerance"], 0)
                if tol > 0 { m["tolerance"] = tol }
                if checkTimeout > 0 { m["timeout"] = checkTimeout }
                if let v = g.opts["alive-checking"] {
                    m["lazy"] = !truthy(v)
                }
                switch g.qxType {
                case "round-robin": m["strategy"] = "round-robin"
                case "dest-hash": m["strategy"] = "consistent-hashing"
                default: break
                }
            }
            groups.append(m)
        }

        // ---- rules
        var gl: [String] = []
        var pl: [String] = []
        var firstSelect = ""
        for g in groups {
            let gName = strOf(g["name"])
            let gType = strOf(g["type"])
            if !qxProxyGroup.isEmpty && gName == qxProxyGroup {
                continue
            }
            gl.append(gName)
            if firstSelect.isEmpty && gType == "select" {
                firstSelect = gName
            }
        }
        for n in proxyNames { pl.append(n) }

        var rules: [String] = []
        let ruleSec = isQX ? "filter_local" : "rule"
        var rulesSkipped = 0

        func resolvePol(_ pol0: String) -> (String, Bool) {
            let pol = unquotePolicy(pol0)
            let (p, ok) = NCRuleValidator.resolvePolicy(pol, groups: gl, proxies: pl, firstSelect: firstSelect.isEmpty ? nil : firstSelect)
            if ok { return (p, true) }
            let (lp, lok) = loosePolicyMatch(pol, groups: gl, proxies: pl)
            if lok {
                rep.notes.append("策略「" + pol + "」按近似名称匹配为「" + lp + "」")
                return (lp, true)
            }
            return ("", false)
        }

        func missingPol(_ pol: String) -> String {
            "策略「" + unquotePolicy(pol) + "」不存在（原配置的 [policy] 中没有同名策略组或节点），这一项未导入"
        }

        var byList: [String: String] = [:]
        func addRemote(sec: String, u: String, kind: String, pol: String, line: String, tag: String, interval0: Int) {
            let (p, ok) = resolvePol(pol)
            guard ok else {
                skip(sec, line, "整个规则列表未导入：" + missingPol(pol))
                rulesSkipped += 1
                return
            }
            let interval = interval0 <= 0 ? 86400 : interval0
            let own = (kind == "list-own")
            var effectiveKind = own ? "list" : kind
            let key = effectiveKind + "|" + u
            var name = byList[key] ?? ""
            if name.isEmpty {
                let base = NCRuleValidator.prettyProviderName(u: u, tag: tag)
                name = NCRuleValidator.uniqueProviderName(base: base, taken: { providers[$0] != nil })
                let behavior = (effectiveKind == "domainset") ? "domain" : "classical"
                let pk = own ? "list-own" : effectiveKind
                var pMap: [String: Any] = [
                    "type": "http", "behavior": behavior, "format": "text", "url": u, "x-convert": effectiveKind,
                    "path": "./ruleset/" + NCRuleValidator.providerNameFor(url: u, kind: pk) + ".txt", "interval": interval
                ]
                if own { pMap["x-own-policy"] = true }
                providers[name] = pMap
                byList[key] = name
            }
            rules.append("RULE-SET," + name + "," + p)
        }

        var finalRule: String? = nil
        for l in nonEmpty(secs[ruleSec]) {
            let (c, err) = NCEngineRuleset.convertRuleLine(l)
            if let err {
                skip(ruleSec, l, err)
                continue
            }
            if !c.remoteURL.isEmpty {
                addRemote(sec: ruleSec, u: c.remoteURL, kind: c.remoteKind, pol: c.policy, line: l, tag: "", interval0: 0)
                continue
            }
            if c.rule.isEmpty { continue }
            let (pol, ok) = resolvePol(c.policy)
            guard ok else {
                skip(ruleSec, l, missingPol(c.policy))
                rulesSkipped += 1
                continue
            }
            if c.type == "MATCH" {
                finalRule = c.format(pol)
                continue
            }
            rules.append(c.format(pol))
        }

        if isQX {
            var inserted: [String] = []
            for l in nonEmpty(secs["filter_remote"]) {
                let opts = qxLineOpts(l)
                if let v = opts["enabled"], !truthy(v) {
                    if rep.disabled == nil { rep.disabled = [] }
                    rep.disabled?.append("[filter_remote] " + qxRemoteLabel(l))
                    continue
                }
                let before = rules.count
                let head = String(l.split(separator: ",", maxSplits: 1).first ?? "").trimmingCharacters(in: .whitespaces).uppercased()
                switch head {
                case "FILTER_LAN", "FILTER_REGION":
                    let targetPol = firstNonEmpty(opts["force-policy"], "direct")
                    let (pol, ok) = resolvePol(targetPol)
                    guard ok else {
                        skip("filter_remote", l, missingPol(opts["force-policy"] ?? ""))
                        rulesSkipped += 1
                        continue
                    }
                    if head == "FILTER_LAN" {
                        for c in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16"] {
                            rules.append("IP-CIDR," + c + "," + pol + ",no-resolve")
                        }
                        rules.append("DOMAIN-SUFFIX,local," + pol)
                    } else {
                        rules.append("GEOIP,CN," + pol)
                    }
                default:
                    if let (sp, ok) = NCRuleValidator.parseQXRemote(l), ok {
                        if unquotePolicy(opts["force-policy"] ?? "").isEmpty {
                            rep.notes.append("filter_remote 未指定 force-policy：下载后按列表内每行自己的策略分流（不存在的策略自动创建为手动选择组），下载前整份列表走 proxy：" + sp.tag)
                            addRemote(sec: "filter_remote", u: sp.url, kind: "list-own", pol: sp.policy, line: l, tag: sp.tag, interval0: sp.interval)
                        } else {
                            addRemote(sec: "filter_remote", u: sp.url, kind: "list", pol: sp.policy, line: l, tag: sp.tag, interval0: sp.interval)
                        }
                    } else {
                        if qxLineDisabled(l) {
                            if rep.disabled == nil { rep.disabled = [] }
                            rep.disabled?.append("[filter_remote] " + qxRemoteLabel(l))
                        } else {
                            skip("filter_remote", l, "整个规则列表未导入：无效的规则列表地址（需要 http:// 或 https:// 开头）")
                            rulesSkipped += 1
                        }
                        continue
                    }
                }
                if truthy(opts["inserted-resource"]) && rules.count > before {
                    inserted.append(contentsOf: rules[before...])
                    rules.removeSubrange(before...)
                }
            }
            if !inserted.isEmpty {
                rules.insert(contentsOf: inserted, at: 0)
            }
        }

        if isQX {
            var pre: [String] = []
            if let v = qxGeneral["udp_drop_list"], !v.isEmpty {
                var ports: [String] = []
                for rawX in v.split(separator: ",") {
                    let x = rawX.trimmingCharacters(in: .whitespaces)
                    switch x.uppercased() {
                    case "": break
                    case "QUIC":
                        if res.settings == nil { res.settings = ConfSettings() }
                        res.settings?.blockQUIC = true
                    case "STUN":
                        ports.append(contentsOf: ["3478", "5349", "19302"])
                    default:
                        if atoi(x.replacingOccurrences(of: "-", with: ""), -1) >= 0 {
                            ports.append(x)
                        }
                    }
                }
                if !ports.isEmpty {
                    pre.append("AND,((NETWORK,UDP),(DST-PORT," + ports.joined(separator: "/") + ")),REJECT-DROP")
                }
            }
            if let v = qxGeneral["udp_whitelist"], !v.isEmpty {
                var ports: [String] = []
                for rawX in v.split(separator: ",") {
                    let x = rawX.trimmingCharacters(in: .whitespaces)
                    if !x.isEmpty && atoi(x.replacingOccurrences(of: "-", with: ""), -1) >= 0 {
                        ports.append(x)
                    }
                }
                if !ports.isEmpty {
                    pre.append("AND,((NETWORK,UDP),(NOT,((DST-PORT," + ports.joined(separator: "/") + ")))),REJECT")
                }
            }
            if !pre.isEmpty {
                rules.insert(contentsOf: pre, at: 0)
            }
            if let v = qxGeneral["fallback_udp_policy"], !v.isEmpty && v.caseInsensitiveCompare("reject") != .orderedSame {
                let (pol, ok) = resolvePol(v)
                if ok {
                    rules.append("AND,((NETWORK,UDP))," + pol)
                } else {
                    rep.notes.append("fallback_udp_policy 的策略「" + v + "」不存在，未导入")
                }
            }
        }

        if finalRule == nil {
            let target = firstSelect.isEmpty ? "DIRECT" : firstSelect
            finalRule = "MATCH," + target
            rep.notes.append("原配置没有 FINAL 规则，已追加 MATCH," + target)
        }
        if let finalRule {
            rules.append(finalRule)
        }

        // ---- DNS / General
        let (strippedP, strippedG) = stripReservedOutbound(proxies, groups, &rep)
        proxies = strippedP
        groups = strippedG

        var cfg: [String: Any] = [
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": groups,
            "rules": rules
        ]
        if !providers.isEmpty { cfg["rule-providers"] = providers }
        if !proxyProviders.isEmpty { cfg["proxy-providers"] = proxyProviders }

        func listOf(_ v: String) -> [String] {
            var out: [String] = []
            for s in v.split(separator: ",") {
                let trimmed = s.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty && trimmed != "system" { out.append(trimmed) }
            }
            return out
        }

        for l in nonEmpty(secs["general"]) {
            guard let eq = l.firstIndex(of: "=") else { continue }
            let k = String(l[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let v = String(l[l.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch k {
            case "dns-server":
                let ns = listOf(v)
                if !ns.isEmpty {
                    var d = (cfg["dns"] as? [String: Any]) ?? ["enable": true]
                    d["default-nameserver"] = ns
                    if d["nameserver"] == nil { d["nameserver"] = ns }
                    cfg["dns"] = d
                }
            case "encrypted-dns-server":
                let ns = listOf(v)
                if !ns.isEmpty {
                    var d = (cfg["dns"] as? [String: Any]) ?? ["enable": true]
                    d["nameserver"] = ns
                    cfg["dns"] = d
                }
            case "ipv6":
                cfg["ipv6"] = truthy(v)
            default:
                break
            }
        }

        if isQX {
            importQXDNS(&cfg, nonEmpty(secs["dns"]), &rep)
            importQXGeneral(&cfg, qxGeneral, &res, &rep)
        }

        // ---- rewrite / MitM / scripts → one module text
        let moduleSecs: Set<String> = [
            "url rewrite", "header rewrite", "body rewrite", "map local", "script", "mitm",
            "rewrite_local", "task_local"
        ]
        let knownSecs: Set<String> = [
            "", "general", "proxy", "proxy group", "rule", "server_local", "server_remote",
            "policy", "filter_local", "filter_remote", "dns", "replica", "host", "rewrite_remote"
        ]
        var modText = ""
        for s in order {
            if !moduleSecs.contains(s) {
                if !knownSecs.contains(s) {
                    rep.notes.append("[" + s + "] 段未导入")
                }
                continue
            }
            var lines = nonEmpty(secs[s])
            if lines.isEmpty { continue }
            var title = s
            if s == "mitm" && !isQX { title = "MITM" }
            if s == "mitm" {
                var kept: [String] = []
                for l in lines {
                    let k = (l.split(separator: "=", maxSplits: 1).first ?? "").trimmingCharacters(in: .whitespaces).lowercased()
                    switch k {
                    case "passphrase", "p12", "ca-passphrase", "ca-p12":
                        continue
                    default:
                        kept.append(l)
                    }
                }
                lines = kept
                if lines.isEmpty { continue }
            }
            modText += "[" + title + "]\n" + lines.joined(separator: "\n") + "\n\n"
        }

        if isQX {
            var remotes: [RemoteModule] = []
            for l in nonEmpty(secs["rewrite_remote"]) {
                let (m, ok) = parseQXRewriteRemote(l)
                if ok {
                    remotes.append(m)
                } else {
                    skip("rewrite_remote", l, "不是有效的远程重写链接")
                }
            }
            if !remotes.isEmpty {
                res.rewriteRemotes = remotes
            }
            rep.remotes = remotes.count
        }

        if !modText.isEmpty {
            res.module = modText
            rep.module = true
            let rs = NCEngineRuleset()
            rs.parseText(modText, source: "导入", args: [:])
            for r in rs.rules {
                if r.kind == "script" {
                    rep.scripts += 1
                } else {
                    rep.rewrites += 1
                }
            }
            for tk in rs.tasks {
                let isOff = tk.line.contains("enable=false") || tk.line.contains("enabled=false")
                if !isOff { rep.tasks += 1 }
            }
            for h in rs.hostnames {
                if !h.hasPrefix("-") { rep.hostnames += 1 }
            }
            for l in rs.unsupported {
                skip("重写", l, "不支持")
            }
            for e in rs.errors {
                rep.skipped.append("[重写] " + e)
            }
        }

        rep.proxies = proxies.count
        rep.groups = groups.count
        rep.rules = rules.count
        rep.providers = providers.count + proxyProviders.count

        if rulesSkipped > 0 {
            rep.rulesSkipped = rulesSkipped
            rep.notes.insert(String(format: "注意：原配置中有 %d 条分流规则 / 规则列表没有导入（见「未转换」），相应流量会改走其他规则；修正原配置后重新导入即可找回", rulesSkipped), at: 0)
        }
        if skippedOver > 0 {
            rep.skipped.append(String(format: "…… 另有 %d 项未转换，未逐条列出", skippedOver))
        }
        if !proxyProviders.isEmpty {
            rep.notes.append(String(format: "[server_remote] 的 %d 个节点订阅已转为节点集（连接时下载）", proxyProviders.count))
        }
        if proxies.isEmpty && proxyProviders.isEmpty {
            rep.notes.append("没有导入到节点；可以之后在「手动节点」或订阅中补充")
        }

        res.report = rep
        res.yaml = NCYAML.emit(cfg)
        return res
    }
}
